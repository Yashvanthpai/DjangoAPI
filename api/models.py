from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    uid = models.AutoField(primary_key=True)
    companyid = models.CharField(max_length=50)
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    position = models.CharField(max_length=50)
    imageurl = models.CharField(max_length=50)

    class Meta:
        ordering=['uid']

    def __str__(self):
        return self.email