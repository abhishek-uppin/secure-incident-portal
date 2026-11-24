from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from .models import Incident
from .roles import ROLE_ANALYST, ROLE_EMPLOYEE


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
