from django.contrib import admin

# Register your models here.
from .models import *


admin.site.register(UserProfile)
admin.site.register(UserGroups)
admin.site.register(UserGroupMember)
admin.site.register(UserPost)