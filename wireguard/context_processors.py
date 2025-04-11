from user_manager.models import UserAcl
from .models import WireGuardInstance


def pending_changes_warning(request):
    if request.user.is_authenticated:
        user_acl = UserAcl.objects.filter(user=request.user).first()
        pending = WireGuardInstance.objects.filter(pending_changes=True).exists()
    else:
        user_acl = None
        pending = False
    return {'pending_changes_warning': pending, 'user_acl': user_acl}
