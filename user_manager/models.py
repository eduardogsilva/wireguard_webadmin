from django.db import models
from django.contrib.auth.models import User
# Create your models here.


class UserAcl(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    user_level = models.PositiveIntegerField(default=0, choices=(
        (10, 'Debugging Analyst'),
        (20, 'View Only User'),
        (30, 'Peer Manager'),
        (40, 'Wireguard Manager'),
        (50, 'Administrator'),

    ))

    def __str__(self):
        return self.user.username
