from django.urls import path
from .views import crypto_login_api, home_view, research_chatbot_api

urlpatterns = [
    path('', home_view, name='home'),
    path('api/login-test/', crypto_login_api, name='crypto_login_api'),
    path('api/chatbot/', research_chatbot_api, name='research_chatbot_api'),
]