from django.conf.urls import url
from .views import *


urlpatterns =[
    url(r"^admin$",UserRegistrationAPIView.as_view(),),
   
    #to get list of groups in which logedin user is in and to create new group
    url(r'^grouplists$',GroupAPIView.as_view()),
    url(r'^group/create$',GroupAPIView.as_view(),),

    url(r'^group/(?P<groupId>[0-9]+)$',GroupDetailAPIView.as_view(),name='group_info'),    
    url(r'^group/(?P<groupId>[0-9]+)$/adduser',GroupDetailAPIView.as_view(),),    
    url(r'^group/(?P<groupId>[0-9]+)/update$',GroupDetailAPIView.as_view(),),

    #to get list of posts from perticular user in the group
    url(r'^group/(?P<groupId>[0-9]+)/(?P<userId>[0-9]+)/groupuserposts$',GroupUserPostsAPIView.as_view(),name='group_posts'),
    url(r'^group/userpost_create$',GroupUserPostsAPIView.as_view(),),

    #to get perticular post from user in the group
    url(r'^userpost/(?P<postId>[0-9]+)$',UserPostDetailAPIView.as_view(),),
    url(r'^userpost/(?P<postId>[0-9]+)/update$',UserPostDetailAPIView.as_view(),),
    
    url(r'^changepassword$',UserPasswordChangeAPIView.as_view(),),
    url(r'^login$',UserLoginAPIView.as_view(),),
    url(r'^logout$',LogoutAPIView.as_view(),),
    url(r'',PageNotFoundAPIViews.as_view())
]

