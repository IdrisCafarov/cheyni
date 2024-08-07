from django.shortcuts import render,redirect, get_object_or_404, get_list_or_404
from django.contrib.auth import login,logout, authenticate
from django.contrib.sites.shortcuts import get_current_site
from rest_framework import generics, serializers, viewsets
from rest_framework.response import Response
from .serializers import *
from django.contrib.auth import get_user_model, login, authenticate
from rest_framework_simplejwt.tokens import RefreshToken

from django.utils.encoding import force_bytes
from django.template.loader import get_template
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes, force_str
from rest_framework.permissions import IsAuthenticated
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .tokens import *
from rest_framework.authtoken.models import Token
from django.views import View
from rest_framework import status
from rest_framework.views import APIView







User = get_user_model()

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })







class RegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()


        # Prepare activation email
        current_site = get_current_site(request)
        print(current_site)
        mail_subject = 'Account Activation !'
        ctx = {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': account_activation_token.make_token(user),
        }
        message = get_template('activation.html').render(ctx)
        to_email = user.email
        to_list = [to_email]
        from_mail = settings.DEFAULT_FROM_EMAIL
        msg = EmailMessage(mail_subject, message, from_mail, to_list)
        msg.content_subtype = 'html'
        msg.mixed_subtype = 'related'


        msg.send()
        
        login(request, user)
        return Response(serializer.data, status=201)




class AccountActivationView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            token, created = Token.objects.get_or_create(user=user)
            message_type = "success"  # Or "success" based on the type of message
            custom_message = "Your Account Succesfully Activated !"
            redirect_url = f'http://localhost:5173/login/?message_type={message_type}&message={custom_message}'
            return redirect(redirect_url)
            
        else:
            message_type = "error"  # Or "success" based on the type of message
            custom_message = "The session time for the link has expired. Please make a new request."
            redirect_url = f'http://localhost:5173/login/?message_type={message_type}&message={custom_message}'
            return redirect(redirect_url)


class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)
    


class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Password has been reset."}, status=status.HTTP_200_OK)



class UserUpdateView(generics.UpdateAPIView):
    serializer_class = UserUpdateSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
    


class ValidateResetTokenView(APIView):

    def get(self, request, *args, **kwargs):
        uid = request.query_params.get('uid')
        token = request.query_params.get('token')

        if not uid or not token:
            return Response({"detail": "UID and token are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uid = force_text(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"detail": "Invalid UID."}, status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token):
            return Response({"message": "Token is valid."}, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)