from django.contrib import admin
from .models import Incident, Note, AuditLog

admin.site.register(Incident)
admin.site.register(Note)
admin.site.register(AuditLog)
