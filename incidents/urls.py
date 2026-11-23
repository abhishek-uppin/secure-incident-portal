from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name='incident-home'),
    path('incidents/', views.incident_list, name='incident-list'),
    path('incidents/<int:pk>/', views.incident_detail, name='incident-detail'),
]