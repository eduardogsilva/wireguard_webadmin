from firewall.models import RedirectRule
from wireguard.models import Peer, WireGuardInstance
from django import forms


class RedirectRuleForm(forms.ModelForm):
    description = forms.CharField(label='Description', required=False)
    protocol = forms.ChoiceField(label='Protocol', choices=[('tcp', 'TCP'), ('udp', 'UDP')], initial='tcp')
    port = forms.IntegerField(label='Port', initial=8080, min_value=1, max_value=65535)
    add_forward_rule = forms.BooleanField(label='Add Forward Rule', required=False, initial=True)
    masquerade_source = forms.BooleanField(label='Masquerade Source (not recommended)', required=False)
    peer = forms.ModelChoiceField(label='Peer', queryset=Peer.objects.all(), required=False)
    wireguard_instance = forms.ModelChoiceField(label='WireGuard Instance', queryset=WireGuardInstance.objects.all().order_by('instance_id'), required=True)
    ip_address = forms.GenericIPAddressField(label='IP Address', required=False)

    class Meta:
        model = RedirectRule
        fields = ['description', 'protocol', 'port', 'add_forward_rule', 'masquerade_source', 'peer', 'wireguard_instance', 'ip_address']
    
    def __init__(self, *args, **kwargs):
        super(RedirectRuleForm, self).__init__(*args, **kwargs)
        if self.fields['wireguard_instance'].queryset.exists():
            self.fields['wireguard_instance'].initial = self.fields['wireguard_instance'].queryset.first().uuid

    def clean(self):
        cleaned_data = super().clean()
        port = cleaned_data.get('port')
        protocol = cleaned_data.get('protocol')
        peer = cleaned_data.get('peer')
        ip_address = cleaned_data.get('ip_address')
        wireguard_instance = cleaned_data.get('wireguard_instance')

        if port == 8000 and protocol == 'tcp':
            raise forms.ValidationError("Port 8000 (tcp) is reserved for wireguard-webadmin.")
        
        if protocol == 'udp':
            if WireGuardInstance.objects.filter(udp_port=port).exists():
                raise forms.ValidationError("Port " + str(port) + " (udp) is already in use by a WireGuard instance.")

        if peer and ip_address:
            raise forms.ValidationError("Peer and IP Address cannot be selected at the same time.")
        
        if ip_address and not wireguard_instance:
            raise forms.ValidationError("IP Address cannot be used without selecting a WireGuard instance.")
        
        if peer:
            cleaned_data['wireguard_instance'] = peer.wireguard_instance
            cleaned_data['ip_address'] = None
        if ip_address:
            cleaned_data['peer'] = None

        return cleaned_data