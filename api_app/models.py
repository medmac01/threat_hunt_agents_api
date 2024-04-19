from django.db import models

from django.db import models
from django.contrib.auth.models import User
from django.utils.crypto import get_random_string

class Token(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    key = models.CharField(max_length=40, unique=True)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = get_random_string(40)
        return super().save(*args, **kwargs)

    def __str__(self):
        return self.key

class ExampleModel(models.Model):
    field1 = models.CharField(max_length=100)
    field2 = models.TextField()
