"""v2 URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path

from . import views
from rest_framework.authtoken import views as auth_views

urlpatterns = [
    # POST: requires valid `username` and `password` parameters. Returns
    # { 'token' : '<token>' }
    path('api_token_auth/', auth_views.obtain_auth_token),
    path('google_auth/', views.google_oauth),
    path('link_google_account/', views.link_google_account),
    path('send_alert/', views.send_alert),
    path('register_device/', views.register_device),
    path('unregister_device/', views.unregister_device),
    path('register_user/', views.register_user),
    path('add_friend/', views.add_friend),
    path('get_name/', views.get_friend_name),
    path('delete_friend/<str:username>/', views.delete_friend),
    path('edit/', views.edit_user),
    path('photo/', views.edit_photo),
    path('get_info/', views.get_user_info),
    path('delete_user_data/', views.delete_user_data),
    path('alert_read/', views.alert_read),
    path('edit_friend_name/', views.edit_friend_name),
    path('alert_delivered/', views.alert_delivered),
    path('set_csrf/', views.set_csrf_token, name='Set-CSRF'),
    path('login/', views.login_session, name='Login'),
    path('test_auth/', views.test_auth)
]
