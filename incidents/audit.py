from .models import AuditLog

INCIDENT_CREATED = "incident_created"
INCIDENT_EDITED = "incident_edited"
INCIDENT_DELETED = "incident_deleted"
STATUS_CHANGED = "status_changed"
SEVERITY_CHANGED = "severity_changed"
NOTE_ADDED = "note_added"
ACCESS_DENIED = "access_denied"


def log_event(request, action, incident=None, details=""):
    valid_actions = {value for value, _label in AuditLog._meta.get_field("action").choices}
    if action not in valid_actions:
        raise ValueError("Unknown audit action")

    user = request.user
    actor = user if user.is_authenticated else None
    incident_ref = incident.pk if incident is not None else None

    AuditLog.objects.create(
        actor=actor,
        action=action,
        incident=incident,
        incident_ref=incident_ref,
        details=details,
    )