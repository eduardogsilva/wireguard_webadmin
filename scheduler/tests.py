import datetime

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from scheduler.models import ScheduleProfile, ScheduleSlot
from user_manager.models import UserAcl


class SchedulerAccessControlTests(TestCase):
    def setUp(self):
        self.profile = ScheduleProfile.objects.create(name='Business Hours')
        self.slot = ScheduleSlot.objects.create(
            profile=self.profile, start_weekday=0, end_weekday=0,
            start_time=datetime.time(8, 0), end_time=datetime.time(18, 0),
        )

    def _login_with_level(self, user_level):
        user = User.objects.create_user(username=f'user{user_level}', password='fixture-password')
        UserAcl.objects.create(user=user, user_level=user_level)
        self.client.force_login(user)

    def test_low_levels_cannot_change_profiles_or_slots(self):
        for user_level in (10, 20):
            with self.subTest(user_level=user_level):
                self._login_with_level(user_level)

                requests = (
                    (reverse('manage_scheduler_profile'), {'name': 'Changed', 'active': 'on'}),
                    (f"{reverse('manage_scheduler_profile')}?uuid={self.profile.uuid}", {'name': 'Changed'}),
                    (f"{reverse('delete_scheduler_profile')}?uuid={self.profile.uuid}", {}),
                    (f"{reverse('manage_scheduler_slot')}?profile_uuid={self.profile.uuid}", {
                        'start_weekday': 1, 'end_weekday': 1, 'start_time': '00:00', 'end_time': '23:59',
                    }),
                    (f"{reverse('delete_scheduler_slot')}?uuid={self.slot.uuid}", {}),
                )
                for url, data in requests:
                    response = self.client.post(url, data)
                    self.assertEqual(response.status_code, 200)
                    self.assertTemplateUsed(response, 'access_denied.html')

                self.assertEqual(ScheduleProfile.objects.count(), 1)
                self.assertEqual(ScheduleProfile.objects.get(uuid=self.profile.uuid).name, 'Business Hours')
                self.assertEqual(ScheduleSlot.objects.count(), 1)

    def test_peer_manager_can_delete_slot_and_profile(self):
        self._login_with_level(30)

        response = self.client.post(f"{reverse('delete_scheduler_slot')}?uuid={self.slot.uuid}")
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ScheduleSlot.objects.exists())

        response = self.client.post(f"{reverse('delete_scheduler_profile')}?uuid={self.profile.uuid}")
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ScheduleProfile.objects.exists())

    def test_profile_list_disables_crud_buttons_for_low_levels(self):
        self._login_with_level(20)

        response = self.client.get(reverse('scheduler_profile_list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Business Hours')
        self.assertNotContains(response, f"{reverse('manage_scheduler_profile')}?uuid={self.profile.uuid}")
        self.assertNotContains(response, f"{reverse('delete_scheduler_profile')}?uuid={self.profile.uuid}")
        self.assertContains(response, 'btn btn-primary disabled')
