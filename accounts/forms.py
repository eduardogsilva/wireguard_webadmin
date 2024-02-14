from typing import Any
from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate


class CreateUserForm(forms.Form):
    username = forms.CharField(label='Username')
    password = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm Password', widget=forms.PasswordInput)  # Adicione este campo para a confirmação da senha

    def clean(self):
        cleaned_data = super().clean()

        username = cleaned_data.get("username")
        if username and ' ' in username:
            self.add_error('username', ValidationError("Username cannot contain spaces."))
        cleaned_data['username'] = username.lower()
        password = cleaned_data.get("password")
        password2 = cleaned_data.get("password2")

        if password and password2 and password != password2:
            self.add_error('password2', ValidationError("The two password fields didn't match."))
        return cleaned_data


class LoginForm(forms.Form):
    username = forms.CharField(label='Username')
    password = forms.CharField(label='Password', widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get("username")
        password = cleaned_data.get("password")
        if username and password:
            user = authenticate(username=username, password=password)
            if not user:
                self.add_error(None, ValidationError("Invalid username or password."))
        else:
            self.add_error(None, ValidationError("Both fields are required."))
        return cleaned_data