import ipaddress

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Column, HTML, Layout, Row, Submit
from django import forms
from django.conf import settings
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _

from wgwadmlibrary.tools import is_valid_ip_or_hostname
from .models import NETMASK_CHOICES, WireGuardInstance


class WireGuardInstanceForm(forms.ModelForm):
    name = forms.CharField(label=_('Display Name'), required=False)
    instance_id = forms.IntegerField(label=_('Instance ID'))
    private_key = forms.CharField(label=_('Private Key'))
    public_key = forms.CharField(label=_('Public Key'))
    hostname = forms.CharField(label=_('Public Address'))
    listen_port = forms.IntegerField(label=_('Listen Port'))
    address = forms.GenericIPAddressField(label=_('Internal IP Address'))
    netmask = forms.ChoiceField(choices=NETMASK_CHOICES, label=_('Netmask'))
    peer_list_refresh_interval = forms.IntegerField(label=_('Web Refresh Interval'), initial=10)
    dns_primary = forms.GenericIPAddressField(label=_('Primary DNS'), initial='1.1.1.1', required=False)
    dns_secondary = forms.GenericIPAddressField(label=_('Secondary DNS'), initial='', required=False)
    enforce_route_policy = forms.BooleanField(label=_('Enforce Route Policy'), required=False)

    class Meta:
        model = WireGuardInstance
        fields = [
            'name', 'instance_id', 'private_key', 'public_key','hostname', 'listen_port', 'address', 
            'netmask', 'peer_list_refresh_interval', 'dns_primary', 'dns_secondary', 'enforce_route_policy'
            ]
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        force_cache_refresh = 0
        if hasattr(settings, 'WIREGUARD_STATUS_CACHE_ENABLED') and settings.WIREGUARD_STATUS_CACHE_ENABLED:
            if hasattr(settings, 'WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL'):
               force_cache_refresh = settings.WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL
        
        if force_cache_refresh > 0:
            self.fields['peer_list_refresh_interval'].initial = force_cache_refresh
            self.fields['peer_list_refresh_interval'].widget.attrs['readonly'] = True
        self.fields['private_key'].widget = forms.PasswordInput(attrs={'class': 'form-control'}, render_value=True)

        self.helper = FormHelper()
        self.helper.form_method = 'post'

        back_label = _("Back")
        delete_label = _("Delete")

        if self.instance.pk and not self.instance._state.adding:
            delete_html = f"<a href='javascript:void(0)' class='btn btn-outline-danger' data-command='delete' onclick='openCommandDialog(this)'>{delete_label}</a>"
        else:
            delete_html = ''


        self.helper.layout = Layout(
            
            Row(
                Column(
                    Row(
                        Column('name', css_class='form-group col-md-6 mb-0'),
                        Column('peer_list_refresh_interval', css_class='form-group col-md-6 mb-0'),
                        css_class='form-row'
                    ),
                    Row(
                        Column('hostname', css_class='form-group col-md-6 mb-0'),
                        Column('listen_port', css_class='form-group col-md-3 mb-0'),
                        Column('instance_id', css_class='form-group col-md-3 mb-0'),
                        css_class='form-row'
                    ),
                    Row(
                        Column('private_key', css_class='form-group col-md-6 mb-0'),
                        Column('public_key', css_class='form-group col-md-6 mb-0'),
                        css_class='form-row'
                    ),
                    Row(
                        Column('address', css_class='form-group col-md-6 mb-0'),
                        Column('netmask', css_class='form-group col-md-6 mb-0'),
                        css_class='form-row'
                    ),
                    Row(
                         Column('dns_primary', css_class='form-group col-md-6 mb-0'),
                         Column('dns_secondary', css_class='form-group col-md-6 mb-0'),
                         css_class='form-row'
                    ),
                    Row(
                        Column('enforce_route_policy', css_class='form-group col-md-12 mb-0'),
                        css_class='form-row'
                    ),
                    css_class='col-lg-12'
                ),
                css_class='row'
            ),
            Row(
                Column(
                    Submit('submit', _('Save'), css_class='btn btn-success'),
                    HTML(f' <a class="btn btn-secondary" href="{reverse_lazy('wireguard_server_list')}">{back_label}</a> '),
                    HTML(delete_html),
                    css_class='col-12'
                ),
                css_class='row'
            ),
        )

    def clean(self):
        cleaned_data = super().clean()
        hostname = cleaned_data.get('hostname')
        address = cleaned_data.get('address')
        netmask = cleaned_data.get('netmask')

        peer_list_refresh_interval = cleaned_data.get('peer_list_refresh_interval')
        if peer_list_refresh_interval and peer_list_refresh_interval < 5:
            raise forms.ValidationError(_('Peer List Refresh Interval must be at least 5 seconds'))

        if hostname and not is_valid_ip_or_hostname(hostname):
            raise forms.ValidationError(_('Invalid hostname or IP Address'))

        if address and netmask:
            current_network = ipaddress.ip_network(f"{address}/{netmask}", strict=False)
            all_other_instances = WireGuardInstance.objects.all()
            if self.instance and self.instance.pk:
                all_other_instances = all_other_instances.exclude(uuid=self.instance.uuid)
            for instance in all_other_instances:
                other_network = ipaddress.ip_network(f"{instance.address}/{instance.netmask}", strict=False)
                if current_network.overlaps(other_network):
                    raise forms.ValidationError(_('The selected network range overlaps with another instance.'))

        return cleaned_data

