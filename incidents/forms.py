from django import forms
from django.utils import timezone

from .models import Incident, Note


class IncidentForm(forms.ModelForm):
    occurred_at = forms.DateTimeField(
        required=False,
        input_formats=["%Y-%m-%dT%H:%M"],
        widget=forms.DateTimeInput(
            attrs={"type": "datetime-local"},
            format="%Y-%m-%dT%H:%M",
        ),
    )

    class Meta:
        model = Incident
        fields = ("title", "description", "category", "severity", "occurred_at")

    def clean_occurred_at(self):
        value = self.cleaned_data.get("occurred_at")
        if value is not None and value > timezone.now():
            raise forms.ValidationError("The time cannot be in the future.")
        return value

    from .models import Incident, Note


class IncidentTriageForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = ("status", "severity")


class NoteForm(forms.ModelForm):
    class Meta:
        model = Note
        fields = ("text",)

