from .models import WireGuardInstance


def pending_changes_warning(request):
    if request.user.is_authenticated:
        pending = WireGuardInstance.objects.filter(pending_changes=True).exists()
    else:
        pending = False
    return {'pending_changes_warning': pending}
