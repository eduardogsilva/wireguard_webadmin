from django.shortcuts import render, Http404, redirect
from django.contrib.auth.models import User
from django.contrib import auth
from .forms import CreateUserForm, LoginForm
from django.http import HttpResponse


def view_create_first_user(request):
    if User.objects.filter().all():
        raise Http404('Superuser already exists')
    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            User.objects.create_superuser(username=username, password=password)
            return render(request, 'accounts/superuser_created.html')
    else:
        form = CreateUserForm()
    return render(request, 'accounts/create_first_user.html', {'form': form})


def view_login(request):
    if not User.objects.filter().all():
        return redirect('/accounts/create_first_user/')
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            user = User.objects.get(username=username)
            auth.login(request, user)
            return redirect('/')
    else:
        form = LoginForm()
    return render(request, 'accounts/login.html', {'form': form})


def view_logout(request):
    auth.logout(request)
    return render(request, 'accounts/logout.html')