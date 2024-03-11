from django import forms
from .models import WireGuardInstance, NETMASK_CHOICES
from wgwadmlibrary.tools import is_valid_ip_or_hostname
import ipaddress

class WireGuardInstanceForm(forms.ModelForm):
    name = forms.CharField(label='Display Name', required=False)
    instance_id = forms.IntegerField(label='Instance ID')
    private_key = forms.CharField(label='Private Key')
    public_key = forms.CharField(label='Public Key')
    hostname = forms.CharField(label='Public Address')
    listen_port = forms.IntegerField(label='Listen Port')
    address = forms.GenericIPAddressField(label='VPN IP Address')
    netmask = forms.ChoiceField(choices=NETMASK_CHOICES, label='Netmask')
    post_up = forms.CharField(label='Post Up', required=False)
    post_down = forms.CharField(label='Post Down', required=False)
    peer_list_refresh_interval = forms.IntegerField(label='Web Refresh Interval', initial=20)
    dns_primary = forms.GenericIPAddressField(label='Primary DNS', initial='1.1.1.1', required=False)
    dns_secondary = forms.GenericIPAddressField(label='Secondary DNS', initial='1.0.0.1', required=False)

    class Meta:
        model = WireGuardInstance
        fields = [
            'name', 'instance_id', 'private_key', 'public_key','hostname', 'listen_port', 'address', 
            'netmask', 'post_up', 'post_down', 'peer_list_refresh_interval', 'dns_primary', 'dns_secondary'
            ]
        
    def clean(self):
        cleaned_data = super().clean()
        hostname = cleaned_data.get('hostname')
        address = cleaned_data.get('address')
        netmask = cleaned_data.get('netmask')
        post_up = cleaned_data.get('post_up')
        post_down = cleaned_data.get('post_down')

        peer_list_refresh_interval = cleaned_data.get('peer_list_refresh_interval')
        if peer_list_refresh_interval < 10:
            raise forms.ValidationError('Peer List Refresh Interval must be at least 10 seconds')

        if not is_valid_ip_or_hostname(hostname):
            raise forms.ValidationError('Invalid hostname or IP Address')

        current_network = ipaddress.ip_network(f"{address}/{netmask}", strict=False)
        all_other_instances = WireGuardInstance.objects.all()
        if self.instance:
            all_other_instances = all_other_instances.exclude(uuid=self.instance.uuid)
        for instance in all_other_instances:
            other_network = ipaddress.ip_network(f"{instance.address}/{instance.netmask}", strict=False)
            if current_network.overlaps(other_network):
                raise forms.ValidationError(f"The network range {current_network} overlaps with another instance's network range {other_network}.")

        #if self.instance:
        #    if post_up or post_down:
        #        if self.instance.post_up != post_up or self.instance.post_down != post_down:
        #            raise forms.ValidationError('Post Up and Post Down cannot be changed, please go to Firewall page to make changes to the firewall.')
        #else:
        #    if post_up or post_down:
        #        raise forms.ValidationError('Post Up and Post Down cannot be set, please go to Firewall page to make changes to the firewall.')
            
        return cleaned_data

