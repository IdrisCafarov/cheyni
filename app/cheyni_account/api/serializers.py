from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.core.mail import send_mail
from django.conf import settings

from django.http import HttpResponse

from django.contrib.auth.password_validation import validate_password


User = get_user_model()

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    
    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError('Invalid credentials')

class RegistrationSerializer(serializers.ModelSerializer):

    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    email = serializers.EmailField()



    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        user = User.objects.filter(email=email).exists()

        if user:
            raise serializers.ValidationError("This email already in use !")

        if len(password) < 6:
            raise serializers.ValidationError("Password must be at least 6 characters !")

        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError("Passwords did not match !")
        
        

        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data['email'],
            name=validated_data['name'],
            surname=validated_data['surname'],
        )


        user.set_password(validated_data['password'])
        user.is_active = False
        user.is_user = True
        user.save()

        return user



    class Meta:
        model = User
        fields = ("id","name","surname","email","password", "password2",)
        extra_kwargs = {
            "password": {"write_only": True},
            "password2": {"write_only": True},
        }



class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'surname']  # Add other fields as needed

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.surname = validated_data.get('surname', instance.surname)
        instance.save()
        return instance
