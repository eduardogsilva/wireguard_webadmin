import ipaddress
import re
from datetime import timedelta

from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Button, Field
from crispy_forms.layout import HTML, Layout, Row, Submit, Div
from django import forms
from django.core.validators import MinValueValidator, MaxValueValidator
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from cluster.models import ClusterSettings, Worker
from scheduler.models import PeerScheduling
from speed_profiles.models import SpeedProfile
from wireguard.models import NETMASK_CHOICES, Peer, PeerAllowedIP
from wireguard_peer.functions import find_network_in_other_instance


class PeerModelForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            *self.Meta.fields,
            FormActions(
                Submit('save', _('Save'), css_class='btn-primary'),
                Button('cancel', _('Back'), css_class='btn-outline-secondary', onclick='window.history.back()')
            )
        )

class PeerNameForm(PeerModelForm):
    name = forms.CharField(label=_('Name'), required=False)

    class Meta:
        model = Peer
        fields = ['name']


class PeerKeepaliveForm(PeerModelForm):
    persistent_keepalive = forms.IntegerField(
        label=_('Persistent Keepalive'),
        required=True,
        validators=[MinValueValidator(1), MaxValueValidator(3600)],
    )

    class Meta:
        model = Peer
        fields = ['persistent_keepalive']


class PeerKeysForm(PeerModelForm):
    public_key = forms.CharField(label=_('Public Key'), required=True)
    private_key = forms.CharField(label=_('Private Key'), required=False)
    pre_shared_key = forms.CharField(label=_('Pre-Shared Key'), required=True)

    class Meta:
        model = Peer
        fields = ['public_key', 'private_key', 'pre_shared_key']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # A remote WireGuard server may not use a pre-shared key
        if self.instance.endpoint:
            self.fields['pre_shared_key'].required = False


HOSTNAME_PATTERN = re.compile(r'^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')


def normalize_endpoint(value):
    """Validate a WireGuard endpoint (host:port, with IPv6 addresses in brackets) and return it normalized."""
    value = (value or '').strip()
    if not value:
        return ''
    host, separator, port = value.rpartition(':')
    if not separator or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise forms.ValidationError(_('Enter the endpoint as host:port, e.g. vpn.example.com:51820'))
    if host.startswith('[') and host.endswith(']'):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise forms.ValidationError(_('Enter a valid IPv6 address between brackets, e.g. [2001:db8::1]:51820'))
        return f'{host.lower()}:{int(port)}'
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if not HOSTNAME_PATTERN.match(host):
            raise forms.ValidationError(_('Enter the endpoint as host:port, e.g. vpn.example.com:51820'))
    return f'{host.lower()}:{int(port)}'


class PeerSpeedProfileForm(PeerModelForm):
    speed_profile = forms.ModelChoiceField(
        queryset=SpeedProfile.objects.order_by('name'), label=_('Speed profile'), required=False,
        empty_label=_('No limit'),
        help_text=_('Download and upload limits of this peer. Speed profiles are managed from the peer list.'),
    )

    class Meta:
        model = Peer
        fields = ['speed_profile']


class PeerEndpointForm(PeerModelForm):
    endpoint = forms.CharField(
        label=_('Endpoint'), required=False,
        help_text=_('Address (host:port) of a remote WireGuard server. This server connects to it, instead of waiting '
                    'for the peer to connect. Leave empty for a regular peer.'),
    )
    active_worker = forms.ModelChoiceField(
        queryset=Worker.objects.none(), label=_('Connected server'), required=False,
        empty_label=_('Primary Server'),
        help_text=_('Cluster server that connects to the endpoint. The networks of this peer are reachable from the '
                    'clients connected to that server.'),
    )

    class Meta:
        model = Peer
        fields = ['endpoint', 'active_worker']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # The node of an endpoint peer is only chosen in the mirror mode; in the distributed mode it is the node of
        # the instance
        if ClusterSettings.cluster_enabled() and not ClusterSettings.is_distributed():
            self.fields['active_worker'].queryset = Worker.objects.order_by('name')
        else:
            del self.fields['active_worker']
            self.helper.layout = Layout(
                'endpoint',
                FormActions(
                    Submit('save', _('Save'), css_class='btn-primary'),
                    Button('cancel', _('Back'), css_class='btn-outline-secondary', onclick='window.history.back()')
                )
            )

    def clean_endpoint(self):
        return normalize_endpoint(self.cleaned_data.get('endpoint'))

    def clean(self):
        cleaned_data = super().clean()
        if 'active_worker' in self.fields and not cleaned_data.get('endpoint'):
            cleaned_data['active_worker'] = None
        return cleaned_data


class PeerAllowedIPForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        current_peer = kwargs.pop('current_peer', None)
        config_file = kwargs.pop('config_file', None)
        super().__init__(*args, **kwargs)
        self.current_peer = current_peer
        self.config_file = config_file
        
    allowed_ip = forms.GenericIPAddressField(label=_('Allowed IP or Network'), required=True)
    netmask = forms.ChoiceField(choices=NETMASK_CHOICES, label=_('Netmask'), initial=24, required=True)
    priority = forms.IntegerField(label=_('Priority'), required=True, initial=1)
    
    def clean(self):
        cleaned_data = super().clean()
        priority = cleaned_data.get('priority')
        allowed_ip = cleaned_data.get('allowed_ip')
        netmask = cleaned_data.get('netmask')
        if allowed_ip is None:
            raise forms.ValidationError(_("Please provide a valid IP address."))

        if self.config_file == 'server':
            wireguard_network = ipaddress.ip_network(f"{self.current_peer.wireguard_instance.address}/{self.current_peer.wireguard_instance.netmask}", strict=False)
            if priority == 0:
                zero_priority_ips_query = PeerAllowedIP.objects.filter(peer=self.current_peer, config_file='server', priority=0)
                if self.instance:
                    zero_priority_ips_query = zero_priority_ips_query.exclude(uuid=self.instance.uuid)
                if zero_priority_ips_query.exists():
                    raise forms.ValidationError(_("A peer can have only one IP with priority zero."))

                duplicated_ip = PeerAllowedIP.objects.filter(config_file='server', allowed_ip=allowed_ip)
                if self.instance:
                    duplicated_ip = duplicated_ip.exclude(uuid=self.instance.uuid)
                if duplicated_ip.exists():
                    raise forms.ValidationError(_("This IP is already in use by another peer."))
                # A peer with an endpoint is a remote server, whose tunnel address may belong to its own network
                if ipaddress.ip_address(allowed_ip) not in wireguard_network and not self.current_peer.endpoint:
                    raise forms.ValidationError(_("The IP address does not belong to the Peer's WireGuard instance network range. Please check the IP address or change the priority."))
                if str(netmask) != str(32):
                    raise forms.ValidationError(_("The netmask for priority 0 IP must be 32."))
                if self.current_peer.wireguard_instance.address == allowed_ip:
                    raise forms.ValidationError(_("The IP address is the same as the Peer's WireGuard instance address."))
            else:
                if ipaddress.ip_address(allowed_ip) in wireguard_network:
                    raise forms.ValidationError(_("The IP address belongs to the Peer's WireGuard instance network range. Please check the IP address or change use priority 0 instead."))
            other_network = find_network_in_other_instance(self.current_peer.wireguard_instance, allowed_ip, netmask)
            if other_network:
                raise forms.ValidationError(
                    _("This network is already used by peer %(peer)s of wg%(instance)s. A network can be routed to only one WireGuard instance.") % {
                        'peer': other_network.peer, 'instance': other_network.peer.wireguard_instance.instance_id
                    }
                )
        elif self.config_file == 'client':
            if self.current_peer.routing_template and not self.current_peer.routing_template.allow_peer_custom_routes:
                raise forms.ValidationError(_("The peer's routing template does not allow custom routes."))
            if priority < 1:
                raise forms.ValidationError(_("Priority must be greater than or equal to 1"))
        else:
            raise forms.ValidationError(_('Invalid config file'))

    class Meta:
        model = PeerAllowedIP
        fields = ['allowed_ip', 'priority', 'netmask']
    

class PeerSuspensionForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        self.peer = kwargs.pop('peer', None)
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'

        if self.peer and self.peer.suspended:
            suspend_toggle_text = _('Reactivate now')
            suspend_toggle_action = 'unsuspend_now'
        else:
            suspend_toggle_text = _('Suspend now')
            suspend_toggle_action = 'suspend_now'

        self.helper.layout = Layout(
            Row(Div(Field('next_manual_suspend_at'), css_class='col-md-12')),
            Row(Div(Field('next_manual_unsuspend_at'), css_class='col-md-12')),
            Row(Div(Field('manual_suspend_reason'), css_class='col-md-12')),
            Row(
                Div(
                    HTML(
                        '<button type="submit" name="action" value="schedule" '
                        'class="btn btn-primary me-2">{}</button> '.format(_("Schedule"))
                    ),
                    HTML(
                        '<button type="submit" name="action" value="clear_schedule" '
                        'class="btn btn-primary me-2">{}</button> '.format(_("Clear Schedule"))
                    ),
                    HTML(
                        '<button type="submit" name="action" value="{}" '
                        'class="btn btn-primary me-2">{}</button> '.format(
                            suspend_toggle_action,
                            suspend_toggle_text
                        )
                    ),
                    HTML(
                        '<a class="btn btn-secondary" href="{}?peer={}">{}</a>'.format(
                            reverse_lazy('wireguard_peer_manage'),
                            self.peer.uuid,
                            _("Back")
                        )
                    ),

                    css_class='col-md-12')
            )
        )

    class Meta:
        model = PeerScheduling
        fields = ['next_manual_suspend_at', 'next_manual_unsuspend_at', 'manual_suspend_reason']
        widgets = {
            'next_manual_suspend_at': forms.DateTimeInput(attrs={'type': 'datetime-local'}, format='%Y-%m-%dT%H:%M'),
            'next_manual_unsuspend_at': forms.DateTimeInput(attrs={'type': 'datetime-local'}, format='%Y-%m-%dT%H:%M'),
            'manual_suspend_reason': forms.Textarea(attrs={'rows': 3}),
        }

    def clean(self):
        cleaned_data = super().clean()
        suspend_at = cleaned_data.get('next_manual_suspend_at')
        unsuspend_at = cleaned_data.get('next_manual_unsuspend_at')

        if suspend_at and unsuspend_at:
            time_diff = abs((unsuspend_at - suspend_at).total_seconds())
            if time_diff < 300:
                raise forms.ValidationError(_('The difference between suspend and unsuspend times must be at least 5 minutes.'))

        min_future_time = timezone.now() + timedelta(minutes=10)
        if suspend_at and suspend_at < min_future_time:
             raise forms.ValidationError(_('Scheduled suspension time must be at least 10 minutes in the future.'))
        
        if unsuspend_at and unsuspend_at < min_future_time:
             raise forms.ValidationError(_('Scheduled unsuspension time must be at least 10 minutes in the future.'))

        return cleaned_data


class PeerScheduleProfileForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        self.peer = kwargs.pop('peer', None)
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        
        self.helper.layout = Layout(
            Row(Div(Field('profile'), css_class='col-md-12')),
            Row(
                Div(
                    FormActions(
                        Submit('save', _('Save'), css_class='btn-primary'),
                        HTML(
                            '<a class="btn btn-secondary" href="{}?peer={}">{}</a>'.format(
                                reverse_lazy('wireguard_peer_manage'),
                                self.peer.uuid,
                                _("Back")
                            )
                        ),
                    ),
                    css_class='col-md-12'
                )
            )
        )

    class Meta:
        model = PeerScheduling
        fields = ['profile']
