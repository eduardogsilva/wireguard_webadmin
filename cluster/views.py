from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _

from dns.functions import compress_dnsmasq_config
from user_manager.models import UserAcl
from .forms import WorkerForm, ClusterSettingsForm
from .models import ClusterSettings, Worker


@login_required
def cluster_main(request):
    """Main cluster page with workers list"""
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})
    
    cluster_settings, created = ClusterSettings.objects.get_or_create(name='cluster_settings')
    page_title = _('Cluster')
    workers = Worker.objects.all().order_by('name')
    context = {
        'page_title': page_title, 
        'workers': workers, 
        'current_worker_version': 10,
        'cluster_settings': cluster_settings
    }
    return render(request, 'cluster/workers_list.html', context)


@login_required
def worker_manage(request):
    """Add/Edit worker view"""
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})
    
    worker = None
    if 'uuid' in request.GET:
        worker = get_object_or_404(Worker, uuid=request.GET['uuid'])
        form = WorkerForm(instance=worker)
        page_title = _('Edit Worker: ') + worker.name
        
        if request.GET.get('action') == 'delete':
            worker_name = worker.name
            if request.GET.get('confirmation') == 'delete':
                worker.delete()
                messages.success(request, _('Worker deleted|Worker deleted: ') + worker_name)
                return redirect('/cluster/')
            else:
                messages.warning(request, _('Worker not deleted|Invalid confirmation.'))
            return redirect('/cluster/')
    else:
        form = WorkerForm()
        page_title = _('Add Worker')

    if request.method == 'POST':
        if worker:
            form = WorkerForm(request.POST, instance=worker)
        else:
            form = WorkerForm(request.POST)

        if form.is_valid():
            worker = form.save()
            if worker.pk:
                messages.success(request, _('Worker updated|Worker updated: ') + worker.name)
            else:
                messages.success(request, _('Worker created|Worker created: ') + worker.name)
            return redirect('/cluster/')

    form_description = {
        'size': 'col-lg-6',
        'content': _('''
        <h5>Worker Configuration</h5>
        <p>Configure a cluster worker node that will synchronize with this primary instance.</p>
        
        <h5>Name</h5>
        <p>A unique name to identify this worker.</p>
        
        <h5>IP Address</h5>
        <p>The IP address of the worker node. Leave empty if IP lock is disabled.</p>
        
        <h5>IP Lock</h5>
        <p>When enabled, the worker can only connect from the specified IP address.</p>
        
        <h5>Location Information</h5>
        <p>Optional location details for this worker (country, city, hostname).</p>
        ''')
    }
    
    context = {
        'page_title': page_title, 
        'form': form, 
        'worker': worker, 
        'instance': worker,
        'form_description': form_description
    }
    return render(request, 'generic_form.html', context)


@login_required
def cluster_settings(request):
    """Cluster settings configuration"""
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})
    
    cluster_settings, created = ClusterSettings.objects.get_or_create(name='cluster_settings')
    page_title = _('Cluster Settings')
    
    if request.method == 'POST':
        form = ClusterSettingsForm(request.POST, instance=cluster_settings)
        if form.is_valid():
            form.save()
            messages.success(request, _('Cluster settings updated successfully.'))
            compress_dnsmasq_config()
            return redirect('/cluster/')
    else:
        form = ClusterSettingsForm(instance=cluster_settings)

    form_description = {
        'size': 'col-lg-6',
        'content': _('''
        <h5>Cluster Mode</h5>
        <p>Configure how the cluster operates and synchronizes configurations between nodes.</p>
        
        <h5>Sync Intervals</h5>
        <p>Configure how frequently statistics and cache data are synchronized between cluster nodes.</p>
        
        <h5>Restart Mode</h5>
        <p>Choose whether WireGuard services should be automatically restarted when configurations change, or if manual intervention is required.</p>
        
        <h5>Worker Display</h5>
        <p>Select how workers should be identified in the interface - by name, server address, location, or a combination.</p>
        ''')
    }
    
    context = {
        'page_title': page_title,
        'form': form,
        'cluster_settings': cluster_settings,
        'instance': cluster_settings,
        'form_description': form_description
    }
    return render(request, 'generic_form.html', context)
