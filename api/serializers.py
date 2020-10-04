from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from rest_framework.serializers import ValidationError
from django.contrib.auth.models import User
from .models import UserGroups,UserPost,UserGroupMember
from .models import UserProfile
import django.contrib.auth.password_validation as validators

class UserSerializer(ModelSerializer):
    class Meta:
        model =User
        fields=('username','password','first_name','last_name','email')
        extra_kwargs = {
            "password": {"write_only": True, 'style':{'input_type':"password"}},
        }
    
    

class UserProfileSerialiser(ModelSerializer):
    user  = UserSerializer()
    class Meta:
        model = UserProfile
        fields=('user','companyid','position','imageurl')
    
    def create(self, validated_data):
        userdata = validated_data.pop('user')
        userobj = User.objects.create_user(**userdata)

        profileobj = UserProfile.objects.create(user=userobj,**validated_data)

        return profileobj


class UserLoginSerializer(serializers.Serializer):
        username = serializers.CharField(max_length=300, required=True)
        password = serializers.CharField(required=True, write_only=True,style={'input_type':"password"})


class UserPasswordChangeSerializer(serializers.Serializer):
        oldPassword = serializers.CharField(required=True, write_only=True,style={'input_type':"password"})
        newPassword1 = serializers.CharField(required=True, write_only=True,style={'input_type':"password"})
        newPassword2 = serializers.CharField(required=True, write_only=True,style={'input_type':"password"})

        class Meta:
            fields=('oldPassword','newPassword1','newPassword2')

        def validate(self, data):
            if data['newPassword1'] != data['newPassword2']:
                 raise  serializers.ValidationError("New passwords are not matching")
            return super().validate(data)
        
        def update(self, instance, validated_data):
             
            if not instance.check_password(validated_data.get('oldPassword')):
                raise  serializers.ValidationError("Old password is incorect try again")
            
            errors = dict()
            try:
                validators.validate_password(password=validated_data['newPassword1'],user=instance)

            except Exception as e:
                errors['password'] = list(e.messages)

            if errors:
                raise serializers.ValidationError(errors)
            
            instance.set_password(validated_data['newPassword1'])
            instance.save()
            return instance



class UserProfileDataSerializer(ModelSerializer):
    class Meta:
        model = UserProfile
        fields=('companyid','position','imageurl')


class UserDataSerializer(ModelSerializer):
    user_profile_info = UserProfileDataSerializer(source='userprofile')
    class Meta:
        model=User
        fields=('id','username','first_name','last_name','email','user_profile_info')
        


class GroupData_CreateSerializer(ModelSerializer):
    group_owner = UserDataSerializer(source='owner')
    class Meta:
        model=UserGroups
        fields=('gid','groupName','description','groupImageUrl','group_owner')
    
    def create(self, validated_data):
        user_id = validated_data.pop('owner')
        user = None
        request = self.context.get('request')
        if request and hasattr(request,'user'):
            user = request.get('user')
        else:
            user = User.objects.get(id=user_id)
        
        group_obj = UserGroups.objects.create(owner=user,**validated_data)

        first_group_member_obj = UserGroupMember.objects.create(
            user_ref = user,
            group_ref=group_obj,
            is_admin=True
        )
        return group_obj


class UserGroupMemberCreateSerializer(ModelSerializer):
    class Meta:
        model = UserGroupMember
        fields = "__all__"
        
    def create(self, validated_data):
        user_id = validated_data.pop('user_ref')
        group_id = validated_data.pop('group_ref')
        user = None
        request = self.context.get('request')
        if request and hasattr(request,'user'):
            user = request.get('user')
        else:
            user = User.objects.get(id=user_id)
        
        group = UserGroups.objects.get(gid=group_id)

        group_member_obj = UserGroupMember.objects.create(
            user_ref = user,
            group_ref=group,
            **validated_data
        )

        return group_member_obj


class UserGroupMemberSerializer(ModelSerializer):
    user_info = UserDataSerializer(source='user_ref')
    class Meta:
        model = UserGroupMember
        fields = ('is_admin','user_info')
        
    

class GroupPostSerializer(ModelSerializer):
    class Meta:
        model = UserPost
        fields="__all__"

    def create(self, validated_data):
        user_id = validated_data.pop('user_ref')
        group_id = validated_data.pop('group_ref')
        user = None
        request = self.context.get('request')
        if request and hasattr(request,'user'):
            user = request.get('user')
        else:
            user = User.objects.get(id=user_id)
        
        group = UserGroups.objects.get(gid=group_id)

        user_post_obj = UserPost.objects.create(
            user_ref = user,
            group_ref=group,
            **validated_data
        )

        return user_post_obj

# def validate(self,data):
#         if data['password'] != data['password1']:
#             raise ValidationError("password not matching")
#         errors = dict() 
#         data.pop('password1')
#         user = None
#         request = self.context.get("request")
#         if request and hasattr(request, "user"):
#                 user = request.user
#         else:
#             user = User(**data)
#         try:
#              validators.validate_password(password=data['password'],user=user)

#         except ValidationError as e:
#              errors['password'] = list(e.messages)

#         if errors:
#              raise serializers.ValidationError(errors)

#         return super(UserSerializer,self).validate(data)