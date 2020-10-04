from django.conf.urls import url
from .views import *


urlpatterns =[
    url(r"^admin$",UserRegistrationAPIView.as_view(),),
   
    url(r'^grouplists$',LoginRedirectAPIView.as_view(),),
    
    url(r'^group/create$',GroupAPIView.as_view(),),

    url(r'^group/(?P<groupId>[0-9]+)$',GroupAPIView.as_view(),),    
    url(r'^group/(?P<groupId>[0-9]+)$/adduser',GroupAPIView.as_view(),),    
    url(r'^group/(?P<groupId>[0-9]+)/update$',GroupAPIView.as_view(),),

    url(r'^group/(?P<groupId>[0-9]+)/groupposts$',LoginRedirectAPIView.as_view(),),
    
    url(r'^userpost/(?P<postId>[0-9]+)$',LoginRedirectAPIView.as_view(),),
    url(r'^userpost/(?P<postId>[0-9]+)/create$',LoginRedirectAPIView.as_view(),),
    url(r'^userpost/(?P<postId>[0-9]+)/update$',LoginRedirectAPIView.as_view(),),
    
    url(r'^changepassword$',UserPasswordChangeAPIView.as_view(),),
    url(r'^login$',UserLoginAPIView.as_view(),),
    url(r'^logout$',LogoutAPIView.as_view(),),
    url(r'',PageNotFoundAPIViews.as_view())
]

