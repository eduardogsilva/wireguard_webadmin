from firewall.models import RedirectRule, FirewallRule, FirewallSettings
from wireguard.models import Peer, WireGuardInstance, NETMASK_CHOICES
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
            if WireGuardInstance.objects.filter(listen_port=port).exists():
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
    

class FirewallRuleForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        current_chain = kwargs.pop('current_chain', None)
        super(FirewallRuleForm, self).__init__(*args, **kwargs)

        firewall_settings, firewall_settings_created = FirewallSettings.objects.get_or_create(name='global')
        interface_list = [('', '------'),]
        interface_list.append((firewall_settings.wan_interface, firewall_settings.wan_interface + ' (WAN)'))
        
        for wireguard_instance in WireGuardInstance.objects.all().order_by('instance_id'):
            wireguard_instance_interface = 'wg'+ str(wireguard_instance.instance_id)
            interface_list.append((wireguard_instance_interface, wireguard_instance_interface))
        
        interface_list.append(('wg+', 'wg+ (Any WireGuard Interface)'))
        
        description = forms.CharField(label='Description', required=False)
        firewall_chain = forms.ChoiceField(label='Firewall Chain', choices=[('forward', 'FORWARD'), ('postrouting', 'POSTROUTING (nat)')])
        in_interface = forms.ChoiceField(label='In Interface', required=False)
        out_interface = forms.ChoiceField(label='Out Interface', required=False)
        source_ip = forms.GenericIPAddressField(label='Source IP', required=False)
        source_netmask = forms.IntegerField(label='Source Netmask', initial=32, min_value=0, max_value=32)
        source_peer = forms.ModelMultipleChoiceField(label='Source Peer', queryset=Peer.objects.all(), required=False)
        source_peer_include_networks = forms.BooleanField(label='Source Peer Include Networks', required=False)
        not_source = forms.BooleanField(label='Not Source', required=False)
        destination_ip = forms.GenericIPAddressField(label='Destination IP', required=False)
        destination_netmask = forms.IntegerField(label='Destination Netmask', initial=32, min_value=0, max_value=32)
        destination_peer = forms.ModelMultipleChoiceField(label='Destination Peer', queryset=Peer.objects.all(), required=False)
        destination_peer_include_networks = forms.BooleanField(label='Destination Peer Include Networks', required=False)
        not_destination = forms.BooleanField(label='Not Destination', required=False)
        protocol = forms.ChoiceField(label='Protocol', choices=[('', 'all'), ('tcp', 'TCP'), ('udp', 'UDP'), ('both', 'TCP+UDP'), ('icmp', 'ICMP')], required=False)
        destination_port = forms.CharField(label='Destination Port', required=False)
        state_new = forms.BooleanField(label='State NEW', required=False)
        state_related = forms.BooleanField(label='State RELATED', required=False)
        state_established = forms.BooleanField(label='State ESTABLISHED', required=False)
        state_invalid = forms.BooleanField(label='State INVALID', required=False)
        state_untracked = forms.BooleanField(label='State UNTRACKED', required=False)
        not_state = forms.BooleanField(label='Not State', required=False)
        rule_action = forms.ChoiceField(label='Rule Action', initial='accept', choices=[('accept', 'ACCEPT'), ('reject', 'REJECT'), ('drop', 'DROP'), ('masquerade', 'MASQUERADE')])
        sort_order = forms.IntegerField(label='Sort Order', initial=0, min_value=0)
        self.fields['firewall_chain'].initial = current_chain
        self.fields['in_interface'].choices = interface_list
        self.fields['out_interface'].choices = interface_list

    class Meta:
        model = FirewallRule
        fields = ['description', 'firewall_chain', 'in_interface', 'out_interface', 'source_ip', 'source_netmask', 'source_peer', 'source_peer_include_networks', 'not_source', 'destination_ip', 'destination_netmask', 'destination_peer', 'destination_peer_include_networks', 'not_destination', 'protocol', 'destination_port', 'state_new', 'state_related', 'state_established', 'state_invalid', 'state_untracked', 'not_state', 'rule_action', 'sort_order']

    def clean(self):
        cleaned_data = super().clean()
        firewall_chain = cleaned_data.get('firewall_chain')
        rule_action = cleaned_data.get('rule_action')
        in_interface = cleaned_data.get('in_interface')

        if firewall_chain == 'forward' and rule_action not in ['accept', 'drop', 'reject']:
            raise forms.ValidationError("Invalid rule action for firewall chain 'forward'. Allowed actions are 'accept', 'drop', and 'reject'.")
        
        if firewall_chain == 'postrouting':
            if rule_action not in ['masquerade', 'accept']:
                raise forms.ValidationError("Invalid rule action for firewall chain 'postrouting'. Allowed actions are 'masquerade' and 'accept'.")
            if in_interface:
                raise forms.ValidationError("In Interface cannot be used with firewall chain 'postrouting'.")

        return cleaned_data



