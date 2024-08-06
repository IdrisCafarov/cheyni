from django.urls import path
from .api.views import *

urlpatterns = [
    path('register/', RegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('update/', UserUpdateView.as_view(), name='user-update'),  # New endpoint for updating user details
    path('activate/<str:uidb64>/<str:token>/', AccountActivationView.as_view(), name='activate'),

]