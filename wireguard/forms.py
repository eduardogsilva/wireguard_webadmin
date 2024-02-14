from django import forms
from .models import WireGuardInstance, NETMASK_CHOICES
from wgwadmlibrary.tools import is_valid_ip_or_hostname
import ipaddress

class WireGuardInstanceForm(forms.ModelForm):
    name = forms.CharField(label='Display Name', required=False)
    instance_id = forms.IntegerField(label='Instance ID')
    private_key = forms.CharField(label='Private Key')
    hostname = forms.CharField(label='Public Address')
    listen_port = forms.IntegerField(label='Listen Port')
    address = forms.GenericIPAddressField(label='VPN IP Address')
    netmask = forms.ChoiceField(choices=NETMASK_CHOICES, label='Netmask')
    post_up = forms.CharField(label='Post Up', required=False)
    post_down = forms.CharField(label='Post Down', required=False)
    persistent_keepalive = forms.IntegerField(label='Persistent Keepalive')

    class Meta:
        model = WireGuardInstance
        fields = [
            'name', 'instance_id', 'private_key', 'hostname', 'listen_port', 'address', 'netmask', 'post_up', 'post_down', 'persistent_keepalive'
            ]
        
    def clean(self):
        cleaned_data = super().clean()
        hostname = cleaned_data.get('hostname')
        address = cleaned_data.get('address')
        netmask = cleaned_data.get('netmask')

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

        return cleaned_data

