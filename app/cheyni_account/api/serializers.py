from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.core.mail import send_mail
from django.conf import settings

from django.http import HttpResponse

from django.contrib.auth.password_validation import validate_password
from django.utils.encoding import force_bytes, force_text
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.template.loader import get_template
from django.core.mail import EmailMessage
from django.core.exceptions import ValidationError



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
    



class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, data):
        email = data.get('email')
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError("No user with this email address.")
        return data

    def save(self):
        email = self.validated_data['email']
        user = User.objects.get(email=email)
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        
        mail_subject = 'Reset Password !'
        ctx = {
            'uid': uid,
            'token': token,
        }
        message = get_template('password-reset.html').render(ctx)
        to_email = user.email
        to_list = [to_email]
        from_mail = settings.DEFAULT_FROM_EMAIL
        msg = EmailMessage(mail_subject, message, from_mail, to_list)
        msg.content_subtype = 'html'
        msg.mixed_subtype = 'related'


        msg.send()
        

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField()

    def validate(self, data):
        uid = force_text(urlsafe_base64_decode(data['uid']))
        token = data['token']
        new_password = data['new_password']
        try:
            user = User.objects.get(pk=uid)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid user.")
        if not default_token_generator.check_token(user, token):
            raise serializers.ValidationError("Invalid or expired token.")
        
        try:
            validate_password(new_password, user)
        except ValidationError as e:
            raise serializers.ValidationError({"new_password": e.messages})
        
        return data

        return data

    def save(self):
        uid = force_text(urlsafe_base64_decode(self.validated_data['uid']))
        new_password = self.validated_data['new_password']
        user = User.objects.get(pk=uid)
        user.set_password(new_password)
        user.save()
        return user
    

