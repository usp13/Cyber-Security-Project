from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('scan/', views.scan_url, name='scan_url'),
    path('scan-text/', views.scan_text, name='scan_text'),
    path('scan/<int:scan_id>/', views.scan_result, name='scan_result'),
    path('ip/', views.check_ip, name='check_ip'),
    path('qr/', views.check_qr, name='check_qr'),
    path('password/', views.generate_password, name='generate_password'),
    path('breach-check/', views.check_breach, name='check_breach'),
    path('scan-file/', views.scan_file, name='scan_file'),
    path('recon/', views.network_recon, name='network_recon'),
    path('contact/', views.contact, name='contact'),
    path('history/', views.history, name='history'),
    path('community/', views.community_list, name='community_list'),
    path('community/new/', views.community_create, name='community_create'),
    path('community/<int:post_id>/', views.community_detail, name='community_detail'),
    
    # Auth URLs
    path('login/', auth_views.LoginView.as_view(template_name='scanner/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('register/', views.register, name='register'),
]