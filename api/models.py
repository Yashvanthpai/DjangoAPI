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
        return self.user.username


class UserGroups(models.Model):
    gid = models.AutoField(primary_key=True)
    groupName = models.CharField(max_length=50,blank=False,null=False)
    description = models.CharField(max_length=100,blank=True,null=True)
    groupImageUrl = models.CharField(max_length=50,blank=True,null=True)
    owner = models.OneToOneField(User,on_delete=models.SET_NULL,null=True)
    class Meta:
        ordering=['gid']

    def __str__(self):
        return self.groupName+" ("+str(self.gid)+") "

class UserGroupMember(models.Model):
    user_ref = models.ForeignKey(User,on_delete=models.CASCADE,null=True)
    group_ref = models.ForeignKey(UserGroups,on_delete=models.CASCADE,null=True)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return self.group_ref.groupName+"("+self.user_ref.username+")"

class UserPost(models.Model):
    pid = models.AutoField(primary_key=True)
    title = models.CharField(max_length=50,blank=False,null=False)
    description =  models.CharField(max_length=100,blank=True,null=True)
    group_ref = models.ForeignKey(UserGroups,on_delete=models.SET_NULL,null=True)
    user_ref = models.ForeignKey(User,on_delete=models.SET_NULL,null=True)

    class Meta:
        ordering=['pid']

    def __str__(self):
        return self.title+" ("+str(self.pid)+") "