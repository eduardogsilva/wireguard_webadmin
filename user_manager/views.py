from django.shortcuts import render
from django.contrib.auth.decorators import login_required


@login_required
def view_user_list(request):
    page_title = 'User Manager'
    context = {'page_title': page_title}
    return render(request, 'user_manager/list.html', context)