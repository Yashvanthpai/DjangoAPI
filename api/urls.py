from django.conf.urls import url
from .views import *


urlpatterns =[
    url(r"^admin$",UserRegistrationAPIView.as_view(),),
    url(r'^appusers$',LoginRedirectAPIView.as_view(),),
    url(r'^changepassword$',UserPasswordChangeAPIView.as_view(),),
    url(r'^login$',UserLoginAPIView.as_view(),),
    url(r'^logout$',LogoutAPIView.as_view(),),
    url(r'',PageNotFoundAPIViews.as_view())
]

