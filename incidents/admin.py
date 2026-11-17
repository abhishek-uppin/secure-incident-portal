from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group
from .models import Incident, Note, AuditLog

User = get_user_model()
admin.site.unregister(User)


@admin.register(User)
class PortalUserAdmin(BaseUserAdmin):
    def get_readonly_fields(self, request, obj=None):
        fields = list(super().get_readonly_fields(request, obj))
        if not request.user.is_superuser:
            fields += ["is_superuser", "is_staff", "user_permissions", "last_login", "date_joined"]
        return fields

    def has_change_permission(self, request, obj=None):
        if obj is not None and (obj.is_superuser or obj.is_staff or obj == request.user) and not request.user.is_superuser:
            return False                      
        return super().has_change_permission(request, obj)

    def formfield_for_manytomany(self, db_field, request, **kwargs):
        if db_field.name == "groups" and not request.user.is_superuser:
            kwargs["queryset"] = Group.objects.filter(name__in=["Employee", "Analyst"])
        return super().formfield_for_manytomany(db_field, request, **kwargs)


admin.site.register(Incident)
admin.site.register(Note)
admin.site.register(AuditLog)
