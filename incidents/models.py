from django.conf import settings
from django.db import models

class Category(models.TextChoices):
    PHISHING = "phishing", "Phishing"
    MALWARE = "malware", "Malware"
    UNAUTHORISED_ACCESS = "unauthorised_access", "Unauthorised Access"
    DOS = "dos", "Denial of Service/DDoS"
    DATA_LEAK = "data_leak", "Data Leak"
    LOST_STOLEN_DEVICE = "lost_stolen_device", "Lost/Stolen Device"
    OTHER = "other", "Other"

class Severity(models.TextChoices):
    LOW = "low", "Low (P4)"
    MEDIUM = "medium", "Medium (P3)"
    HIGH = "high", "High (P2)"
    CRITICAL = "critical", "Critical (P1)"

class Status(models.TextChoices):
    OPEN = "open", "Open"
    INVESTIGATING = "investigating", "Investigating"
    CLOSED = "closed", "Closed"

class Incident(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    category = models.CharField(choices=Category.choices, max_length=30)
    severity = models.CharField(choices=Severity.choices, max_length=15)
    status = models.CharField(choices=Status.choices, default=Status.OPEN, max_length=20)
    reporter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="incidents")
    occurred_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class Note(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.PROTECT, related_name="notes")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="authored_notes")
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.incident} by {self.author}"

class AuditLog(models.Model):
    class Action(models.TextChoices):
        INCIDENT_CREATED = "incident_created", "Incident created"
        INCIDENT_EDITED = "incident_edited", "Incident edited"
        INCIDENT_DELETED = "incident_deleted", "Incident deleted"
        STATUS_CHANGED = "status_changed", "Status changed"
        SEVERITY_CHANGED = "severity_changed", "Severity changed"
        NOTE_ADDED = "note_added", "Note added"
        ACCESS_DENIED = "access_denied", "Access denied"
        LOGIN = "login", "Login"
        LOGOUT = "logout", "Logout"
        LOGIN_FAILED = "login_failed", "Login failed"

    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True)
    action = models.CharField(max_length=30, choices=Action.choices)
    incident = models.ForeignKey(Incident, on_delete=models.SET_NULL, null=True, blank=True, related_name="audit_logs")
    incident_ref = models.PositiveIntegerField(null=True, blank=True)
    details = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"At {self.timestamp}, {self.actor} has {self.action}" 