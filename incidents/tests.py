from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from .models import Incident, Note
from .roles import ROLE_ANALYST, ROLE_EMPLOYEE, ROLE_ADMIN
from .views import STATUS_OPEN


User = get_user_model()


def make_user(username, role_name=None):
    user = User.objects.create_user(username=username)
    if role_name is not None:
        group, _ = Group.objects.get_or_create(name=role_name)
        user.groups.add(group)
    return user


def make_incident(title, reporter):
    return Incident.objects.create(
        title=title,
        description="Test description",
        category=Incident._meta.get_field("category").choices[0][0],
        severity=Incident._meta.get_field("severity").choices[0][0],
        reporter=reporter,
    )


class IncidentVisibilityTests(TestCase):
    def setUp(self):
        self.alice = make_user("alice", ROLE_EMPLOYEE)
        self.bob = make_user("bob", ROLE_EMPLOYEE)
        self.analyst = make_user("ana", ROLE_ANALYST)
        self.no_role = make_user("nora")
        self.alice_incident = make_incident("Alice phishing report", self.alice)
        self.bob_incident = make_incident("Bob malware report", self.bob)

    def test_anonymous_is_redirected_to_login(self):
        url = reverse("incident-list")
        response = self.client.get(url)
        self.assertRedirects(response, f"{reverse('login')}?next={url}")

    def test_employee_list_shows_only_own(self):
        self.client.force_login(self.alice)
        response = self.client.get(reverse("incident-list"))
        self.assertContains(response, "Alice phishing report")
        self.assertNotContains(response, "Bob malware report")

    def test_analyst_list_shows_all(self):
        self.client.force_login(self.analyst)
        response = self.client.get(reverse("incident-list"))
        self.assertContains(response, "Alice phishing report")
        self.assertContains(response, "Bob malware report")

    def test_employee_can_open_own_detail(self):
        self.client.force_login(self.alice)
        response = self.client.get(reverse("incident-detail", args=[self.alice_incident.pk]))
        self.assertEqual(response.status_code, 200)

    def test_employee_cannot_open_other_detail(self):
        self.client.force_login(self.alice)
        response = self.client.get(reverse("incident-detail", args=[self.bob_incident.pk]))
        self.assertEqual(response.status_code, 404)

    def test_analyst_can_open_any_detail(self):
        self.client.force_login(self.analyst)
        response = self.client.get(reverse("incident-detail", args=[self.bob_incident.pk]))
        self.assertEqual(response.status_code, 200)

    def test_missing_incident_is_404(self):
        self.client.force_login(self.analyst)
        response = self.client.get(reverse("incident-detail", args=[999999]))
        self.assertEqual(response.status_code, 404)

    def test_user_without_role_is_sent_home(self):
        self.client.force_login(self.no_role)
        response = self.client.get(reverse("incident-list"))
        self.assertRedirects(response, reverse("incident-home"))

    def test_post_is_rejected(self):
        self.client.force_login(self.analyst)
        response = self.client.post(reverse("incident-list"))
        self.assertEqual(response.status_code, 405)


CATEGORY = Incident._meta.get_field("category").choices[0][0]
SEVERITY = Incident._meta.get_field("severity").choices[0][0]


def form_data(**overrides):
    data = {
        "title": "New report",
        "description": "Something happened",
        "category": CATEGORY,
        "severity": SEVERITY,
        "occurred_at": "",
    }
    data.update(overrides)
    return data


class IncidentCreateTests(TestCase):
    def setUp(self):
        self.alice = make_user("alice", ROLE_EMPLOYEE)
        self.bob = make_user("bob", ROLE_EMPLOYEE)
        self.analyst = make_user("ana", ROLE_ANALYST)
        self.no_role = make_user("nora")
        self.url = reverse("incident-create")

    def test_anonymous_is_redirected_to_login(self):
        response = self.client.get(self.url)
        self.assertRedirects(response, f"{reverse('login')}?next={self.url}")

    def test_employee_sees_form(self):
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(self.url).status_code, 200)

    def test_analyst_is_forbidden(self):
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.client.post(self.url, form_data()).status_code, 403)
        self.assertEqual(Incident.objects.count(), 0)

    def test_no_role_is_sent_home(self):
        self.client.force_login(self.no_role)
        self.assertRedirects(self.client.get(self.url), reverse("incident-home"))

    def test_create_sets_reporter_and_status_on_server(self):
        self.client.force_login(self.alice)
        data = form_data(reporter=self.bob.pk, status="closed")
        response = self.client.post(self.url, data)
        incident = Incident.objects.get()
        self.assertRedirects(response, reverse("incident-detail", args=[incident.pk]))
        self.assertEqual(incident.reporter, self.alice)
        self.assertEqual(incident.status, STATUS_OPEN)

    def test_future_occurred_at_is_rejected(self):
        self.client.force_login(self.alice)
        future = (timezone.now() + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
        response = self.client.post(self.url, form_data(occurred_at=future))
        self.assertEqual(response.status_code, 200)
        self.assertFormError(
            response.context["form"], "occurred_at", "The time cannot be in the future."
        )
        self.assertEqual(Incident.objects.count(), 0)

    def test_missing_title_is_rejected(self):
        self.client.force_login(self.alice)
        response = self.client.post(self.url, form_data(title=""))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Incident.objects.count(), 0)

    def test_post_without_csrf_token_is_rejected(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.alice)
        response = client.post(self.url, form_data())
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Incident.objects.count(), 0)


class IncidentEditTests(TestCase):
    def setUp(self):
        self.alice = make_user("alice", ROLE_EMPLOYEE)
        self.bob = make_user("bob", ROLE_EMPLOYEE)
        self.analyst = make_user("ana", ROLE_ANALYST)
        self.mine = make_incident("Original title", self.alice)
        self.theirs = make_incident("Bob original", self.bob)

    def url(self, incident):
        return reverse("incident-edit", args=[incident.pk])

    def test_owner_can_open_edit_page(self):
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(self.url(self.mine)).status_code, 200)

    def test_owner_can_edit_while_open(self):
        self.client.force_login(self.alice)
        response = self.client.post(self.url(self.mine), form_data(title="Changed title"))
        self.assertRedirects(response, reverse("incident-detail", args=[self.mine.pk]))
        self.mine.refresh_from_db()
        self.assertEqual(self.mine.title, "Changed title")

    def test_edit_cannot_change_reporter_or_status(self):
        self.client.force_login(self.alice)
        data = form_data(reporter=self.bob.pk, status="closed")
        self.client.post(self.url(self.mine), data)
        self.mine.refresh_from_db()
        self.assertEqual(self.mine.reporter, self.alice)
        self.assertEqual(self.mine.status, STATUS_OPEN)

    def test_other_users_incident_is_404(self):
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(self.url(self.theirs)).status_code, 404)
        response = self.client.post(self.url(self.theirs), form_data(title="Hacked"))
        self.assertEqual(response.status_code, 404)
        self.theirs.refresh_from_db()
        self.assertEqual(self.theirs.title, "Bob original")

    def test_closed_incident_cannot_be_edited(self):
        self.mine.status = "closed"
        self.mine.save()
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(self.url(self.mine)).status_code, 403)
        response = self.client.post(self.url(self.mine), form_data(title="Late change"))
        self.assertEqual(response.status_code, 403)
        self.mine.refresh_from_db()
        self.assertEqual(self.mine.title, "Original title")

    def test_analyst_cannot_use_employee_edit(self):
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.get(self.url(self.mine)).status_code, 403)
        response = self.client.post(self.url(self.mine), form_data(title="Analyst edit"))
        self.assertEqual(response.status_code, 403)
        self.mine.refresh_from_db()
        self.assertEqual(self.mine.title, "Original title")

    def test_edit_link_only_shown_while_open(self):
        self.client.force_login(self.alice)
        detail = reverse("incident-detail", args=[self.mine.pk])
        self.assertContains(self.client.get(detail), self.url(self.mine))
        self.mine.status = "closed"
        self.mine.save()
        self.assertNotContains(self.client.get(detail), self.url(self.mine))

class IncidentTriageTests(TestCase):
    def setUp(self):
        self.owner = make_user("owner", ROLE_EMPLOYEE)
        self.other = make_user("other", ROLE_EMPLOYEE)
        self.analyst = make_user("analyst", ROLE_ANALYST)
        self.incident = make_incident("Phish", self.owner)
        self.url = reverse("incident-triage", args=[self.incident.pk])
        self.new_severity = Incident._meta.get_field("severity").choices[-1][0]

    def test_anonymous_redirected(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)

    def test_analyst_changes_status_and_severity(self):
        self.client.force_login(self.analyst)
        self.client.post(self.url, {"status": "investigating", "severity": self.new_severity})
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, "investigating")
        self.assertEqual(self.incident.severity, self.new_severity)

    def test_analyst_can_reopen_closed_incident(self):
        self.incident.status = "closed"
        self.incident.save()
        self.client.force_login(self.analyst)
        self.client.post(self.url, {"status": STATUS_OPEN, "severity": self.incident.severity})
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, STATUS_OPEN)

    def test_invalid_status_rejected(self):
        self.client.force_login(self.analyst)
        response = self.client.post(self.url, {"status": "banana", "severity": self.incident.severity})
        self.assertEqual(response.status_code, 200)
        self.assertIn("status", response.context["form"].errors)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, STATUS_OPEN)

    def test_forged_reporter_ignored(self):
        self.client.force_login(self.analyst)
        self.client.post(
            self.url,
            {"status": "investigating", "severity": self.incident.severity, "reporter": self.analyst.pk},
        )
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.reporter, self.owner)

    def test_owner_gets_403_and_nothing_changes(self):
        self.client.force_login(self.owner)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        response = self.client.post(self.url, {"status": "closed", "severity": self.incident.severity})
        self.assertEqual(response.status_code, 403)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, STATUS_OPEN)

    def test_other_employee_gets_404(self):
        self.client.force_login(self.other)
        self.assertEqual(self.client.get(self.url).status_code, 404)
        response = self.client.post(self.url, {"status": "closed", "severity": self.incident.severity})
        self.assertEqual(response.status_code, 404)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, STATUS_OPEN)

    def test_no_role_redirected_home(self):
        self.client.force_login(make_user("norole"))
        response = self.client.get(self.url)
        self.assertRedirects(response, reverse("incident-home"))


class NoteTests(TestCase):
    def setUp(self):
        self.owner = make_user("owner", ROLE_EMPLOYEE)
        self.other = make_user("other", ROLE_EMPLOYEE)
        self.analyst = make_user("analyst", ROLE_ANALYST)
        self.incident = make_incident("Phish", self.owner)
        self.url = reverse("incident-note-add", args=[self.incident.pk])

    def test_analyst_adds_note_with_server_set_fields(self):
        self.client.force_login(self.analyst)
        self.client.post(self.url, {"text": "Checked mail logs", "author": self.owner.pk})
        note = Note.objects.get()
        self.assertEqual(note.author, self.analyst)
        self.assertEqual(note.incident, self.incident)

    def test_empty_note_rejected(self):
        self.client.force_login(self.analyst)
        response = self.client.post(self.url, {"text": ""})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Note.objects.count(), 0)

    def test_owner_gets_403_and_no_note_created(self):
        self.client.force_login(self.owner)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.client.post(self.url, {"text": "x"}).status_code, 403)
        self.assertEqual(Note.objects.count(), 0)

    def test_other_employee_gets_404_and_no_note_created(self):
        self.client.force_login(self.other)
        self.assertEqual(self.client.post(self.url, {"text": "x"}).status_code, 404)
        self.assertEqual(Note.objects.count(), 0)

    def test_owner_sees_note_on_detail(self):
        Note.objects.create(incident=self.incident, author=self.analyst, text="Visible note")
        self.client.force_login(self.owner)
        response = self.client.get(reverse("incident-detail", args=[self.incident.pk]))
        self.assertContains(response, "Visible note")

    def test_other_employee_cannot_see_note(self):
        Note.objects.create(incident=self.incident, author=self.analyst, text="Hidden note")
        self.client.force_login(self.other)
        response = self.client.get(reverse("incident-detail", args=[self.incident.pk]))
        self.assertEqual(response.status_code, 404)

class IncidentDeleteTests(TestCase):
    def setUp(self):
        self.owner = make_user("owner", ROLE_EMPLOYEE)
        self.other = make_user("other", ROLE_EMPLOYEE)
        self.analyst = make_user("analyst", ROLE_ANALYST)
        self.admin = make_user("admin_user", ROLE_ADMIN)
        self.incident = make_incident("Phish", self.owner)
        self.url = reverse("incident-delete", args=[self.incident.pk])

    def test_anonymous_redirected_and_incident_kept(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Incident.objects.filter(pk=self.incident.pk).exists())

    def test_admin_get_shows_confirmation_and_deletes_nothing(self):
        self.client.force_login(self.admin)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Incident.objects.filter(pk=self.incident.pk).exists())

    def test_admin_post_deletes(self):
        self.client.force_login(self.admin)
        response = self.client.post(self.url)
        self.assertRedirects(response, reverse("incident-list"))
        self.assertFalse(Incident.objects.filter(pk=self.incident.pk).exists())

    def test_incident_with_notes_is_kept_with_friendly_message(self):
        Note.objects.create(incident=self.incident, author=self.analyst, text="Evidence")
        self.client.force_login(self.admin)
        response = self.client.post(self.url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "cannot be deleted")
        self.assertTrue(Incident.objects.filter(pk=self.incident.pk).exists())
        self.assertEqual(Note.objects.count(), 1)

    def test_analyst_gets_403_and_incident_kept(self):
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.client.post(self.url).status_code, 403)
        self.assertTrue(Incident.objects.filter(pk=self.incident.pk).exists())

    def test_owner_gets_403_and_incident_kept(self):
        self.client.force_login(self.owner)
        self.assertEqual(self.client.post(self.url).status_code, 403)
        self.assertTrue(Incident.objects.filter(pk=self.incident.pk).exists())

    def test_other_employee_gets_404_and_incident_kept(self):
        self.client.force_login(self.other)
        self.assertEqual(self.client.post(self.url).status_code, 404)
        self.assertTrue(Incident.objects.filter(pk=self.incident.pk).exists())

    def test_missing_incident_gives_404(self):
        self.client.force_login(self.admin)
        response = self.client.post(reverse("incident-delete", args=[999999]))
        self.assertEqual(response.status_code, 404)

    def test_post_without_csrf_token_is_rejected(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        response = client.post(self.url)
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Incident.objects.filter(pk=self.incident.pk).exists())

    def test_no_role_redirected_and_incident_kept(self):
        self.client.force_login(make_user("norole"))
        response = self.client.post(self.url)
        self.assertRedirects(response, reverse("incident-home"))
        self.assertTrue(Incident.objects.filter(pk=self.incident.pk).exists())