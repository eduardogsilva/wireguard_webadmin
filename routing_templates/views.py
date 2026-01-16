from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _

from user_manager.models import UserAcl
from .forms import RoutingTemplateForm
from .models import RoutingTemplate


@login_required
def view_routing_template_list(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})

    page_title = _('Routing Templates')
    routing_templates = RoutingTemplate.objects.all().order_by('name')
    context = {'page_title': page_title, 'routing_templates': routing_templates}
    return render(request, 'routing_templates/list.html', context)


@login_required
def view_manage_routing_template(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})

    routing_template = None
    if 'uuid' in request.GET:
        routing_template = get_object_or_404(RoutingTemplate, uuid=request.GET['uuid'])
        form = RoutingTemplateForm(instance=routing_template, user=request.user)
        page_title = _('Edit Routing Template: ') + routing_template.name

        if request.GET.get('action') == 'delete':
            template_name = routing_template.name
            if request.GET.get('confirmation') == 'delete':
                routing_template.delete()
                messages.success(request, _('Routing Template deleted|Routing Template deleted: ') + template_name)
                return redirect('/routing-templates/list/')
            else:
                messages.warning(request, _('Routing Template not deleted|Invalid confirmation.'))
            return redirect('/routing-templates/list/')
    else:
        form = RoutingTemplateForm(user=request.user)
        page_title = _('Add Routing Template')

    if request.method == 'POST':
        if routing_template:
            form = RoutingTemplateForm(request.POST, instance=routing_template, user=request.user)
        else:
            form = RoutingTemplateForm(request.POST, user=request.user)

        if form.is_valid():
            form.save()
            return redirect('/routing-templates/list/')

    form_description = {
        'size': '',
        'content': _('''
        <h5>Routing Templates</h5>
        <p>Define routing configurations that can be applied to peers.</p>
        
        <h5>Default Template</h5>
        <p>If checked, this template will be the default for the selected WireGuard instance. Only one default template is allowed per instance.</p>

        <h5>Route Type</h5>
        <p>Select the type of routes to push to the client.</p>
        <ul>
            <li><strong>Default Route (0.0.0.0/0)</strong>: Redirects all traffic through the VPN.</li>
            <li><strong>Routes from Peers on same Interface</strong>: Pushes routes for other peers on the same WireGuard interface.</li>
            <li><strong>Routes from All Peers</strong>: Pushes routes for all peers across all interfaces.</li>
            <li><strong>Custom Routes</strong>: Allows you to specify custom CIDR ranges.</li>
        </ul>

        <h5>Custom Routes</h5>
        <p>Enter custom routes in CIDR notation, one per line (e.g., 192.168.1.0/24).</p>
        
        <h5>Allow Peer Custom Routes</h5>
        <p>If checked, allows specific peers to add their own custom routes on top of this template.</p>
        
        <h5>Enforce Route Policy</h5>
        <p>If enabled, firewall rules will be applied to strictly enforce this routing policy.<br>The peer will only be able to access networks explicitly defined by the assigned routing template.<br>Any traffic to destinations outside these routes will be blocked.</p>
        <p>Note: depending on the number of routes and peers, enabling this option may generate a large number of firewall rules.</p>
        ''')
    }
    
    context = {
        'page_title': page_title,
        'form': form,
        'instance': routing_template,
        'form_description': form_description
    }
    return render(request, 'generic_form.html', context)
