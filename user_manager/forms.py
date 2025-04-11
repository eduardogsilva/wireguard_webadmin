from crispy_forms.helper import FormHelper
from crispy_forms.layout import Column, HTML, Layout, Row, Submit
from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

from wireguard.models import PeerGroup
from .models import UserAcl


class UserAclForm(forms.Form):
    username = forms.CharField(max_length=150)
    password1 = forms.CharField(widget=forms.PasswordInput, required=False, label="Password")
    password2 = forms.CharField(widget=forms.PasswordInput, required=False, label="Password confirmation")
    enable_console = forms.BooleanField(required=False, label="Enable Console")
    enable_reload = forms.BooleanField(required=False, label="Enable Reload")
    enable_restart = forms.BooleanField(required=False, label="Enable Restart")
    enable_enhanced_filter = forms.BooleanField(required=False, label="Enable Enhanced Filter")
    user_level = forms.ChoiceField(choices=UserAcl.user_level.field.choices, required=True, label="User Level")
    peer_groups = forms.ModelMultipleChoiceField(
        queryset=PeerGroup.objects.all(),
        required=False,
    )

    def __init__(self, *args, **kwargs):
        self.instance = kwargs.pop('instance', None)
        self.user_id = kwargs.pop('user_id', None)
        super().__init__(*args, **kwargs)

        if self.instance:
            self.fields['username'].initial = self.instance.username
            self.fields['username'].widget.attrs['readonly'] = True
            self.fields['peer_groups'].initial = self.instance.useracl.peer_groups.all()
            self.fields['enable_console'].initial = self.instance.useracl.enable_console
            self.fields['enable_reload'].initial = self.instance.useracl.enable_reload
            self.fields['enable_restart'].initial = self.instance.useracl.enable_restart
            self.fields['enable_enhanced_filter'].initial = self.instance.useracl.enable_enhanced_filter
        else:
            self.fields['password1'].required = True
            self.fields['password2'].required = True
            self.fields['enable_console'].initial = True
            self.fields['enable_reload'].initial = True
            self.fields['enable_restart'].initial = True
            self.fields['enable_enhanced_filter'].initial = False
        
        self.fields['enable_console'].label = "Console"
        self.fields['enable_reload'].label = "Reload"
        self.fields['enable_restart'].label = "Restart"
        self.fields['enable_enhanced_filter'].label = "Enhanced Filter"

        self.helper = FormHelper()
        self.helper.form_method = 'post'
        
        if self.instance:
            delete_html = "<a href='javascript:void(0)' class='btn btn-outline-danger' data-command='delete' onclick='openCommandDialog(this)'>Delete</a>"
        else:
            delete_html = ''
            
        self.helper.layout = Layout(
            Row(
                Column('username', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('password1', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('password2', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('user_level', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('peer_groups', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('enable_console', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('enable_reload', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('enable_restart', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('enable_enhanced_filter', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column(
                    Submit('submit', 'Save', css_class='btn btn-success'),
                    HTML(' <a class="btn btn-secondary" href="/user/list/">Back</a> '),
                    HTML(delete_html),
                    css_class='col-md-12'),
                css_class='form-row'
            )
        )

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exclude(pk=self.user_id).exists():
            raise ValidationError("A user with that username already exists.")
        return username

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')

        if not self.instance:  
            if not password1:
                raise ValidationError("Password is required for new users.")
            if not password2:
                raise ValidationError("Password confirmation is required for new users.")

        if password1 or password2: 
            if password1 != password2:
                raise ValidationError("The two password fields didn't match.")
            if len(password1) < 8:
                raise ValidationError("Password must be at least 8 characters long.")

        return cleaned_data

    def save(self):
        username = self.cleaned_data['username']
        password = self.cleaned_data.get('password1')
        user_level = self.cleaned_data['user_level']
        peer_groups = self.cleaned_data.get('peer_groups', [])
        enable_console = self.cleaned_data.get('enable_console', False)
        enable_reload = self.cleaned_data.get('enable_reload', False)
        enable_restart = self.cleaned_data.get('enable_restart', False)
        enable_enhanced_filter = self.cleaned_data.get('enable_enhanced_filter', False)

        if self.instance:
            user = self.instance
            if password:
                user.set_password(password)
                user.save()
        else:
            user = User.objects.create_user(
                username=username,
                password=password
            )

        user_acl, created = UserAcl.objects.update_or_create(
            user=user,
            defaults={
                'user_level': user_level,
                'enable_console': enable_console,
                'enable_reload': enable_reload,
                'enable_restart': enable_restart,
                'enable_enhanced_filter': enable_enhanced_filter
            }
        )
        
        user_acl.peer_groups.set(peer_groups)

        return user



class PeerGroupForm(forms.ModelForm):
    class Meta:
        model = PeerGroup
        fields = ['name', 'peer', 'server_instance']

    def __init__(self, *args, **kwargs):
        self.user_id = kwargs.pop('user_id', None)
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        
        if self.instance.pk:
            delete_html = "<a href='javascript:void(0)' class='btn btn-outline-danger' data-command='delete' onclick='openCommandDialog(this)'>Delete</a>"
        else:
            delete_html = ''
            
        self.helper.layout = Layout(
            Row(
                Column('name', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('peer', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('server_instance', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column(
                    Submit('submit', 'Save', css_class='btn btn-success'),
                    HTML(' <a class="btn btn-secondary" href="/user/peer-group/list/">Back</a> '),
                    HTML(delete_html),
                    css_class='col-md-12'),
                css_class='form-row'
            )
        )

    def clean(self):
        cleaned_data = super().clean()
        name = cleaned_data.get('name')
        peers = cleaned_data.get('peer')
        server_instances = cleaned_data.get('server_instance')

        if PeerGroup.objects.filter(name=name).exclude(pk=self.instance.pk if self.instance else None).exists():
            raise ValidationError("A peer group with that name already exists.")

        return cleaned_data
    
    def save(self, commit=True):
        peer_group = super().save(commit=False)
        
        if commit:
            peer_group.save()

        return peer_group

