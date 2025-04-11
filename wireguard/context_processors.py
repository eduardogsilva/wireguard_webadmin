from user_manager.models import UserAcl
from .models import WireGuardInstance


def pending_changes_warning(request):
    user_acl = UserAcl.objects.filter(user=request.user).first()
    if request.user.is_authenticated:
        pending = WireGuardInstance.objects.filter(pending_changes=True).exists()
    else:
        pending = False
    return {'pending_changes_warning': pending, 'user_acl': user_acl}
