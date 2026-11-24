from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name='incident-home'),
    path('incidents/', views.incident_list, name='incident-list'),
    path('incidents/new/', views.incident_create, name='incident-create'),
    path('incidents/<int:pk>/', views.incident_detail, name='incident-detail'),
    path('incidents/<int:pk>/edit/', views.incident_edit, name='incident-edit'),
]