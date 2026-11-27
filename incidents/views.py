from django.contrib import messages
from django.contrib.auth.decorators import login_not_required
from django.core.exceptions import PermissionDenied
from django.db.models import ProtectedError
from django.db import transaction
from django.http import Http404
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods, require_safe

from . import audit
from .forms import IncidentForm, IncidentTriageForm, NoteForm
from .models import Incident
from .roles import ROLE_ADMIN, ROLE_ANALYST, ROLE_EMPLOYEE, get_role


@login_not_required
def home(request):
    context = {'title': 'Home'}
    return render(request, 'incidents/home.html', context)


STATUS_OPEN = "open"


def can_create_incident(role):
    return role == ROLE_EMPLOYEE


def can_edit_incident(user, role, incident):
    return (
        role == ROLE_EMPLOYEE
        and incident.reporter_id == user.id
        and incident.status == STATUS_OPEN
    )

def can_delete_incident(role):
    return role == ROLE_ADMIN

def can_triage_incident(role):
    return role == ROLE_ANALYST

def can_add_note(role):
    return role == ROLE_ANALYST

NO_ROLE_MESSAGE = "Your account has no role yet. Contact an administrator."


def no_role_response(request):
    messages.error(request, NO_ROLE_MESSAGE)
    return redirect("incident-home")


def visible_incidents(user, role):
    if role in (ROLE_ANALYST, ROLE_ADMIN):
        return Incident.objects.all()
    if role == ROLE_EMPLOYEE:
        return Incident.objects.filter(reporter=user)
    return Incident.objects.none()


def get_visible_incident(request, role, pk):
    incident = (
        visible_incidents(request.user, role)
        .select_related("reporter")
        .filter(pk=pk)
        .first()
    )
    if incident is not None:
        return incident

    existing = Incident.objects.filter(pk=pk).first()
    if existing is not None:
        audit.log_event(
            request,
            audit.ACCESS_DENIED,
            incident=existing,
            details="Incident not visible to this user",
        )
    raise Http404


def deny(request, incident, attempted):
    audit.log_event(
        request,
        audit.ACCESS_DENIED,
        incident=incident,
        details=f"Not allowed: {attempted}",
    )
    raise PermissionDenied


@require_safe
def incident_list(request):
    role = get_role(request.user)
    if role is None:
        return no_role_response(request)

    incidents = (
        visible_incidents(request.user, role)
        .select_related("reporter")
        .order_by("-created_at")
    )
    context = {
        "incidents": incidents,
        "show_reporter": role in (ROLE_ANALYST, ROLE_ADMIN),
        "can_create": can_create_incident(role),
    }
    return render(request, "incidents/incident_list.html", context)


@require_safe
def incident_detail(request, pk):
    role = get_role(request.user)
    if role is None:
        return no_role_response(request)

    incident = get_visible_incident(request, role, pk)
    notes = incident.notes.select_related("author").order_by("created_at")
    context = {
        "incident": incident,
        "notes": notes,
        "can_edit": can_edit_incident(request.user, role, incident),
        "can_triage": can_triage_incident(role),
        "can_add_note": can_add_note(role),
        "can_delete": can_delete_incident(role),
    }
    return render(request, "incidents/incident_detail.html", context)


@require_http_methods(["GET", "POST"])
def incident_create(request):
    role = get_role(request.user)
    if role is None:
        return no_role_response(request)
    if not can_create_incident(role):
        deny(request, None, "create incident")

    if request.method == "POST":
        form = IncidentForm(request.POST)
        if form.is_valid():
            incident = form.save(commit=False)
            incident.reporter = request.user
            with transaction.atomic():
                incident.save()
                audit.log_event(request, audit.INCIDENT_CREATED, incident=incident)
            messages.success(request, "Incident reported.")
            return redirect("incident-detail", pk=incident.pk)
    else:
        form = IncidentForm()

    return render(
        request,
        "incidents/incident_form.html",
        {"form": form, "heading": "Report an incident"},
    )


@require_http_methods(["GET", "POST"])
def incident_edit(request, pk):
    role = get_role(request.user)
    if role is None:
        return no_role_response(request)

    incident = get_visible_incident(request, role, pk)
    if not can_edit_incident(request.user, role, incident):
        deny(request, incident, "edit incident")

    if request.method == "POST":
        form = IncidentForm(request.POST, instance=incident)
        if form.is_valid():
            with transaction.atomic():
                form.save()
                if form.changed_data:
                    audit.log_event(
                        request,
                        audit.INCIDENT_EDITED,
                        incident=incident,
                        details="Fields changed: " + ", ".join(form.changed_data),
                    )
            messages.success(request, "Incident updated.")
            return redirect("incident-detail", pk=incident.pk)
    else:
        form = IncidentForm(instance=incident)

    return render(
        request,
        "incidents/incident_form.html",
        {"form": form, "heading": f"Edit incident {incident.pk}"},
    )


@require_http_methods(["GET", "POST"])
def incident_triage(request, pk):
    role = get_role(request.user)
    if role is None:
        return no_role_response(request)

    incident = get_visible_incident(request, role, pk)
    if not can_triage_incident(role):
        deny(request, incident, "change status or severity")

    if request.method == "POST":
        form = IncidentTriageForm(request.POST, instance=incident)
        if form.is_valid():
            old_status = form.initial["status"]
            old_severity = form.initial["severity"]
            with transaction.atomic():
                form.save()
                if "status" in form.changed_data:
                    audit.log_event(
                        request,
                        audit.STATUS_CHANGED,
                        incident=incident,
                        details=f"{old_status} -> {incident.status}",
                    )
                if "severity" in form.changed_data:
                    audit.log_event(
                        request,
                        audit.SEVERITY_CHANGED,
                        incident=incident,
                        details=f"{old_severity} -> {incident.severity}",
                    )
            messages.success(request, "Incident updated.")
            return redirect("incident-detail", pk=incident.pk)
    else:
        form = IncidentTriageForm(instance=incident)

    return render(
        request,
        "incidents/incident_form.html",
        {"form": form, "heading": "Update status and severity"},
    )


@require_http_methods(["GET", "POST"])
def incident_note_add(request, pk):
    role = get_role(request.user)
    if role is None:
        return no_role_response(request)

    incident = get_visible_incident(request, role, pk)
    if not can_add_note(role):
        deny(request, incident, "add note")

    if request.method == "POST":
        form = NoteForm(request.POST)
        if form.is_valid():
            note = form.save(commit=False)
            note.incident = incident
            note.author = request.user
            with transaction.atomic():
                note.save()
                audit.log_event(
                    request,
                    audit.NOTE_ADDED,
                    incident=incident,
                    details=f"Note {note.pk}",
                )
            messages.success(request, "Note added.")
            return redirect("incident-detail", pk=incident.pk)
    else:
        form = NoteForm()

    return render(
        request,
        "incidents/incident_form.html",
        {"form": form, "heading": "Add a note"},
    )


@require_http_methods(["GET", "POST"])
def incident_delete(request, pk):
    role = get_role(request.user)
    if role is None:
        return no_role_response(request)

    incident = get_visible_incident(request, role, pk)
    if not can_delete_incident(role):
        deny(request, incident, "delete incident")

    if request.method == "POST":
        try:
            with transaction.atomic():
                audit.log_event(request, audit.INCIDENT_DELETED, incident=incident)
                incident.delete()
        except ProtectedError:
            messages.error(
                request,
                "This incident has notes and cannot be deleted. Close it instead.",
            )
            return redirect("incident-detail", pk=pk)
        messages.success(request, "Incident deleted.")
        return redirect("incident-list")

    return render(
        request,
        "incidents/incident_confirm_delete.html",
        {"incident": incident},
    )