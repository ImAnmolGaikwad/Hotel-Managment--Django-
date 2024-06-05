from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.


class Hotel(AbstractUser):
    role_choice = (
        ("A", "Admin"),
        ("M", "Manager"),
        ("U", "User"),
    )

    role = models.CharField(max_length=10, choices=role_choice)
    phone = models.BigIntegerField(null=True,unique=True)

    def save(self, *args, **kwargs):
        # Call set_password() to hash the password before saving
        if self.password:
            self.set_password(self.password)
        super().save(*args, **kwargs)


class Rooms(models.Model):
    room_type = (("s", "Single "), ("d", "Double"), ("t", "Triple"))
    type = models.CharField(max_length=10, choices=room_type)
    charges = models.FloatField()
    user=models.OneToOneField(Hotel,on_delete=models.SET_NULL,null=True)

