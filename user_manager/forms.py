from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserAcl
from django.core.exceptions import ValidationError


class UserAclForm(UserCreationForm):
    user_level = forms.ChoiceField(choices=UserAcl.user_level.field.choices, required=True, label="User Level")

    class Meta(UserCreationForm.Meta):
        model = User
        fields = UserCreationForm.Meta.fields + ('user_level',)

    def __init__(self, *args, **kwargs):
        self.user_id = kwargs.pop('user_id', None)
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields['password1'].required = False
            self.fields['password2'].required = False
            self.fields['username'].widget.attrs['readonly'] = True

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exclude(pk=self.user_id).exists():
            raise ValidationError("A user with that username already exists.")
        return username

    def save(self, commit=True):
        user = super().save(commit=False)
        new_password = self.cleaned_data.get("password1")
        
        if new_password:
            user.set_password(new_password)
            user.save()
        else:
            if not user.id:
                user.save()

        if commit:
            user_acl, created = UserAcl.objects.update_or_create(
                user=user, 
                defaults={'user_level': self.cleaned_data.get('user_level')}
            )

        return user
