from.serializers import *
from .models import *

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.status import (   
        HTTP_200_OK,
        HTTP_201_CREATED,
        HTTP_205_RESET_CONTENT,
        HTTP_400_BAD_REQUEST,
        HTTP_404_NOT_FOUND
    )
from rest_framework.authentication import TokenAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated,AllowAny,IsAdminUser
from rest_framework.authtoken.models import Token

from django.contrib.auth import authenticate,login,logout,update_session_auth_hash
from django.db.models import Q
from django.contrib.auth.models import User
from django.shortcuts import reverse,redirect
from django.forms.models import model_to_dict


def get_user_serialised_data(user=None):
    user_data = dict()
    remove_list = ['password','groups','user_permissions']
    if user:
        user_data =  model_to_dict(user)
        if not user_data['is_superuser']:
            user_data['companyid'] = user.userprofile.companyid
            user_data['position'] = user.userprofile.position
            user_data['imageurl'] = user.userprofile.imageurl

        for key in remove_list:
            user_data.pop(key)
        return user_data

    return None
    

#Authentication related views

class UserRegistrationAPIView(APIView):
    permission_classes = [IsAdminUser]
    authentication_classes = [TokenAuthentication]
    serializer_class =UserProfileSerialiser

    def get(self,request):
        context = {
        "username": "String field",
        "password": "String field",
        "first_name": "String field",
        "last_name": "String field",
        "email": "Valid Email field",
        "companyid":"String field",
        "position":"String field",
        "imageurl":"String field",
        }
        return Response(context,status=HTTP_200_OK)
    
    def post(self,request):
        serialise_data = UserProfileSerialiser(data=request.data)
        if serialise_data.is_valid():
            serialise_data.save()
            return Response(serialise_data.validated_data,status=HTTP_201_CREATED)
        else:
            return Response(serialise_data.errors,status=HTTP_400_BAD_REQUEST) 

class UserLoginAPIView(APIView):
    serializer_class=UserLoginSerializer
    def get(self,request):
        context = {
        "username": "Username",
        "password": "Users password"        
       }
        return Response(context,status=HTTP_200_OK)
    
    def post(self,request):
        error_messages = {
            'invalid_login': (
                "Please enter a correct usernames and password. Note that both "
                "fields may be case-sensitive."
            ),
            'inactive': "This account is inactive.",
        }
        serialise_data = self.serializer_class(data=request.data)
        if serialise_data.is_valid():
            try:
                user_obj  = authenticate(
                                request=request,
                                username=serialise_data.validated_data.get('username'),
                                password=serialise_data.validated_data.get('password')
                            )
                if user_obj is not None:
                    if user_obj.is_active:
                        token,created = Token.objects.get_or_create(user = user_obj)
                        request.user = user_obj
                        data = get_user_serialised_data(request.user)
                        data['token'] = token.key
                        return Response(data=data,status=HTTP_200_OK)
                    else:
                        raise Exception(error_messages['inactive'])
                else:
                    raise Exception(error_messages['invalid_login'])
            except Exception as e:
                return Response(str(e),status=HTTP_400_BAD_REQUEST)

class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def get(self,request):
        request.user.auth_token.delete()    
        logout(request)
        return Response("Logout Sucessfull")

class UserPasswordChangeAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    serializer_class = UserPasswordChangeSerializer

    def get(self,request):
        context ={
            "oldPassword": "Users Old password",
            "newPassword1": "Users new password",
            "newPassword2": "Users new Confirm password",
            "password contraints":
                    [
                        "Your password can't be too similar to your other personal information.",
                        "Your password must contain at least 8 characters.",
                        "Your password can't be a commonly used password.",
                        "Your password can't be entirely numeric."
                    ]
        }
        return Response(context)
    
    def post(self,request):

        serialized_data = self.serializer_class(instance=request.user, data=request.data)
        if serialized_data.is_valid():
            userinstance = serialized_data.save()
            update_session_auth_hash(request, request.user)
            data = get_user_serialised_data(request.user)
            data['message'] = "password changed sucessfully"
            print(data)
            return Response(data=data,status=HTTP_200_OK)
        else:
            return Response(data=serialized_data.errors,status=HTTP_400_BAD_REQUEST)


#functionality views

# return list of groups in which logedin user is in,getmethod
# create new group, postmethod
class GroupAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]


    def get(self,request):

        data = {
            'grouplist':None,
            'loggeduser_info':None
        }
        group_list = UserGroups.objects.filter(
          usergroupmember__user_ref__id=request.user.id
        )

        search = request.query_params.get('search',None)

        if search:
            group_list = group_list.filter(
                Q(groupName__icontains=search)|
                Q(description__icontains=search)|
                Q(owner__username__icontains=search)|
                Q(owner__first_name__icontains=search)|
                Q(owner__userprofile__companyid__icontains=search)
            )

        serialized_data = GroupDataSerializer(
            group_list,many=True
        )

        data['grouplist']=serialized_data.data
        data['loggeduser_info']=get_user_serialised_data(request.user)
        
        return Response(data=data,status=HTTP_200_OK)

    def post(self,request):
        serialized_data = GroupCreateSerializer(
            data=request.data
        )
        if serialized_data.is_valid():
            serialized_data.save()

            group_list = UserGroups.objects.filter(
             groupName=serialized_data.validated_data.get('groupName')
            )

            serialized_data = GroupDataSerializer(
                group_list,many=True
            )
            return Response(data=serialized_data.data,status=HTTP_200_OK)
   
        else:
            return Response(data=serialized_data.errors,status=HTTP_400_BAD_REQUEST)

# return list of users in group , getmethod
# add new user to group , postmethod
# update group info , updatemethod
class GroupDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def get(self,request,groupId=None):
        if groupId:
            
            data = {
            'userlist':None,
            'group_info':None
            }

            user_list = UserGroupMember.objects.filter(
                group_ref__gid=groupId
            )
            
            search = request.query_params.get('search',None)

            if search:
                if search.lower() in 'admin is_admin isadmin':
                    user_list = user_list.filter(is_admin=True)
                else:
                    user_list = user_list.filter(
                        Q(user_ref__username__icontains=search)|
                        Q(user_ref__first_name__icontains=search)|
                        Q(user_ref__userprofile__companyid__icontains=search)
                    )
            
            user_data = UserGroupMemberSerializer(user_list,many=True)
            
            group_info = UserGroups.objects.get(gid=groupId)
            group_data = GroupDataSerializer(group_info)
            
            data['userlist']= user_data.data
            data['group_info']=group_data.data

            return Response(data=data,status=HTTP_200_OK)
        
        return Response(status=HTTP_400_BAD_REQUEST)

    def post(self,request):
        serialized_data = UserGroupMemberCreateSerializer(
                data=request.data
        )
        if serialized_data.is_valid():
                data = serialized_data.save()
                data = UserGroupMemberSerializer(data)
                return Response(data=data.data,status=HTTP_200_OK)
            
        else:
                return Response(data=serialized_data.errors,status=HTTP_400_BAD_REQUEST)
    
    def put(self,request):
        group_obj = UserGroups.objects.get(gid=request.data.get('gid'))
        serialized_data = GroupCreateSerializer(
            instance=group_obj,data=request.data,partial=True
        )
        if serialized_data.is_valid():
            data = serialized_data.save()
            data = GroupDataSerializer(data)
            return Response(data=data.data,status=HTTP_200_OK)
        
        else:
            return Response(data=serialized_data.errors,status=HTTP_400_BAD_REQUEST)
       

# get list of post posted by user in a group,getmethod
# create new post,postmethod
class GroupUserPostsAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def get(self,request,groupId,userId):
        if groupId and userId:
            data={
                'group_id':groupId,
                'user_id':userId,
                'user_posts':None
            }
            user_posts = UserPost.objects.filter(
                group_ref__gid= groupId,
                user_ref__id = userId
            )
            
            search = request.query_params.get('search',None)

            if search:
                    user_posts = user_posts.filter(
                        Q(title__icontains=search)|
                        Q(description__icontains=search)
                    )


            serialized_data = GroupPostDataSerializer(
                user_posts,many=True
            )
            data['user_posts']=serialized_data.data
            
            return Response(data=data,status=HTTP_200_OK)
        else:
            return Response(status=HTTP_400_BAD_REQUEST)

    def post(self,request):
        serialized_data = GroupPostCreateSerializer(
            data = request.data
        )
        if serialized_data.is_valid():
            data = serialized_data.save()
            data = GroupPostDataSerializer(
                data
            )
            return Response(data=data.data,status=HTTP_200_OK)
        else:
            return Response(data=serialized_data.errors,status=HTTP_400_BAD_REQUEST)


# get specific userpost and update the same
class UserPostDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def get(self,request,postId=None):
        if postId:
            user_post = UserPost.objects.filter(
               pid=postId
            )
            serialized_data = GroupPostDataSerializer(
                user_post,many=True
            )

            return Response(data=serialized_data.data,status=HTTP_200_OK)
        else:
            return Response(status=HTTP_400_BAD_REQUEST)

    def put(self,request,postId=None):
        if postId:
            post_obj = UserPost.objects.get(pid=postId)
            serialized_data = GroupPostCreateSerializer(
               instance=post_obj, data = request.data,partial=True
            )
            if serialized_data.is_valid():
               
                data = serialized_data.save()
                data = GroupPostDataSerializer(
                    data
                )
                return Response(data=data.data,status=HTTP_200_OK)
            
            else:
                return Response(data=serialized_data.errors,status=HTTP_400_BAD_REQUEST)

        else:
            return Response(status=HTTP_400_BAD_REQUEST)      



# handling 404 errors

class PageNotFoundAPIViews(APIView):
    def get(self,request):
        return Response(data="Page Not Found",status=HTTP_404_NOT_FOUND)


