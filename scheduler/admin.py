from django.contrib import admin

from .models import PeerScheduling, ScheduleSlot, ScheduleProfile


class ScheduleProfileAdmin(admin.ModelAdmin):
    list_display = ('name', 'created', 'updated')
    search_fields = ('name',)
    ordering = ('name', 'created')
admin.site.register(ScheduleProfile, ScheduleProfileAdmin)


class ScheduleSlotAdmin(admin.ModelAdmin):
    list_display = ('profile', 'start_weekday', 'end_weekday', 'start_time', 'end_time', 'created', 'updated')
    list_filter = ('profile', 'start_weekday', 'end_weekday', 'created', 'updated')
    search_fields = ('profile__name',)
    ordering = ('profile__name', 'start_weekday', 'start_time')
admin.site.register(ScheduleSlot, ScheduleSlotAdmin)


class PeerSchedulingAdmin(admin.ModelAdmin):
    list_display = ('peer', 'profile', 'next_scheduled_enable_at', 'next_scheduled_disable_at',
                    'next_manual_suspend_at', 'next_manual_unsuspend_at', 'created', 'updated')
    list_filter = ('profile', 'created', 'updated')
    search_fields = ('peer__name', 'manual_suspend_reason')
    ordering = ('created', 'updated')
admin.site.register(PeerScheduling, PeerSchedulingAdmin)

