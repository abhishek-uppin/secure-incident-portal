from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group
from django.contrib.auth.forms import UserChangeForm
from .models import Incident, Note, AuditLog
from .roles import ADMIN_ASSIGNABLE_ROLES, ALL_ROLES


User = get_user_model()
admin.site.unregister(User)


class PortalUserChangeForm(UserChangeForm):
    def clean(self):
        cleaned_data = super().clean()

        is_superuser_account = cleaned_data.get("is_superuser", self.instance.is_superuser)

        if not is_superuser_account:
            groups = cleaned_data.get("groups")
            if groups is not None:
                if groups.count() != 1 or groups.first().name not in ALL_ROLES:
                    self.add_error("groups", "Each user must have exactly one role.")

        return cleaned_data


@admin.register(User)
class PortalUserAdmin(BaseUserAdmin):
    form = PortalUserChangeForm
    def get_readonly_fields(self, request, obj=None):
        fields = list(super().get_readonly_fields(request, obj))
        if not request.user.is_superuser:
            fields += ["is_superuser", "is_staff", "user_permissions", "last_login", "date_joined"]
        return fields

    def has_change_permission(self, request, obj=None):
        if (obj is not None 
        and (obj.is_superuser or obj.is_staff or obj == request.user)
        and not request.user.is_superuser):
            return False
        return super().has_change_permission(request, obj)

    def formfield_for_manytomany(self, db_field, request, **kwargs):
        if db_field.name == "groups" and not request.user.is_superuser:
            kwargs["queryset"] = Group.objects.filter(name__in=ADMIN_ASSIGNABLE_ROLES)
        return super().formfield_for_manytomany(db_field, request, **kwargs)


admin.site.register(Incident)
admin.site.register(Note)
admin.site.register(AuditLog)
