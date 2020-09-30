from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from rest_framework.serializers import ValidationError
from django.contrib.auth.models import User
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



# def validate(self,data):
#         if data['password'] != data['password1']:
#             raise ValidationError("password not matching")
#         errors = dict() 
#         data.pop('password1')
#         user = User(**data)
#         try:
#              validators.validate_password(password=data['password'],user=user)

#         except ValidationError as e:
#              errors['password'] = list(e.messages)

#         if errors:
#              raise serializers.ValidationError(errors)

#         return super(UserSerializer,self).validate(data)