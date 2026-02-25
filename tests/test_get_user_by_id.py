from django.contrib.auth import get_user_model
from django.test import TestCase

from oidc_auth.authentication import get_user_by_id


class TestGetUserById(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
        )

    def test_valid_email_sub_returns_user(self):
        result = get_user_by_id(None, {'sub': 'testuser@example.com'})
        self.assertEqual(result, self.user)

    def test_missing_sub_returns_none(self):
        result = get_user_by_id(None, {})
        self.assertIsNone(result)

    def test_non_email_sub_returns_none(self):
        result = get_user_by_id(None, {'sub': 'notanemail'})
        self.assertIsNone(result)

    def test_nonexistent_user_returns_none(self):
        result = get_user_by_id(None, {'sub': 'nobody@example.com'})
        self.assertIsNone(result)
