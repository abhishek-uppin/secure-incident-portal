from django.shortcuts import render
from django.contrib.auth.decorators import login_not_required
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_safe

from .models import Incident
from .roles import ROLE_ADMIN, ROLE_ANALYST, ROLE_EMPLOYEE, get_role

@login_not_required
def home(request):
    context = {'title': 'Home'}
    return render(request, 'incidents/home.html', context)


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
    }
    return render(request, "incidents/incident_list.html", context)


@require_safe
def incident_detail(request, pk):
    role = get_role(request.user)
    if role is None:
        return no_role_response(request)

    incident = get_object_or_404(
        visible_incidents(request.user, role).select_related("reporter"),
        pk=pk,
    )
    notes = incident.notes.select_related("author").order_by("created_at")
    context = {"incident": incident, "notes": notes}
    return render(request, "incidents/incident_detail.html", context)