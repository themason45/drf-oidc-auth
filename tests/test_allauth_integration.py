import base64
import time
from unittest import TestCase
from unittest.mock import MagicMock, patch

from django.test import TestCase as DjangoTestCase

from oidc_auth.settings import api_settings
from oidc_auth.test import AuthenticationTestCaseMixin
from oidc_auth.utils.allauth import get_allauth_app, get_allauth_issuer


class TestGetAllauthApp(TestCase):
    def test_returns_none_when_provider_not_configured(self):
        """Returns None (and skips all allauth imports) when OIDC_ALLAUTH_PROVIDER is unset."""
        self.assertIsNone(get_allauth_app(None))

    @patch.object(api_settings, 'OIDC_ALLAUTH_PROVIDER', 'my-provider')
    def test_returns_none_when_allauth_not_installed(self):
        """Returns None gracefully when django-allauth is not installed."""
        with patch.dict('sys.modules', {'allauth.socialaccount.models': None}):
            self.assertIsNone(get_allauth_app(MagicMock()))

    @patch.object(api_settings, 'OIDC_ALLAUTH_PROVIDER', 'my-provider')
    def test_returns_social_app_for_current_site(self):
        """Returns the SocialApp matched to the current site."""
        mock_app = MagicMock(client_id='allauth-client-id', secret='allauth-secret')
        mock_site = MagicMock()

        MockSocialApp = MagicMock()
        MockSocialApp.objects.filter.return_value.first.return_value = mock_app

        mock_models = MagicMock()
        mock_models.SocialApp = MockSocialApp

        with patch.dict('sys.modules', {
            'allauth': MagicMock(),
            'allauth.socialaccount': MagicMock(),
            'allauth.socialaccount.models': mock_models,
        }), patch('django.contrib.sites.shortcuts.get_current_site', return_value=mock_site):
            result = get_allauth_app(MagicMock())

        self.assertEqual(result, mock_app)
        MockSocialApp.objects.filter.assert_called_once_with(
            provider='my-provider', sites=mock_site)

    @patch.object(api_settings, 'OIDC_ALLAUTH_PROVIDER', 'my-provider')
    def test_returns_none_when_no_app_for_site(self):
        """Returns None when no SocialApp is registered for the current site."""
        mock_site = MagicMock()

        MockSocialApp = MagicMock()
        MockSocialApp.objects.filter.return_value.first.return_value = None

        mock_models = MagicMock()
        mock_models.SocialApp = MockSocialApp

        with patch.dict('sys.modules', {
            'allauth': MagicMock(),
            'allauth.socialaccount': MagicMock(),
            'allauth.socialaccount.models': mock_models,
        }), patch('django.contrib.sites.shortcuts.get_current_site', return_value=mock_site):
            result = get_allauth_app(MagicMock())

        self.assertIsNone(result)


class TestGetAllauthIssuer(TestCase):
    def test_returns_none_when_key_not_configured(self):
        """Returns None when OIDC_ALLAUTH_ISSUER_KEY is unset."""
        self.assertIsNone(get_allauth_issuer(MagicMock()))

    def test_returns_none_when_social_app_is_none(self):
        """Returns None when no SocialApp was resolved."""
        with patch.object(api_settings, 'OIDC_ALLAUTH_ISSUER_KEY', 'oidc_endpoint'):
            self.assertIsNone(get_allauth_issuer(None))

    @patch.object(api_settings, 'OIDC_ALLAUTH_ISSUER_KEY', 'oidc_endpoint')
    def test_returns_issuer_from_social_app_settings(self):
        """Returns the value at the configured key from SocialApp.settings."""
        mock_app = MagicMock()
        mock_app.settings = {'oidc_endpoint': 'https://sso.example.com/realms/myrealm'}
        result = get_allauth_issuer(mock_app)
        self.assertEqual(result, 'https://sso.example.com/realms/myrealm')

    @patch.object(api_settings, 'OIDC_ALLAUTH_ISSUER_KEY', 'oidc_endpoint')
    def test_returns_none_when_key_absent_from_settings(self):
        """Returns None when the key is missing from SocialApp.settings."""
        mock_app = MagicMock()
        mock_app.settings = {'other_key': 'something'}
        self.assertIsNone(get_allauth_issuer(mock_app))

    @patch.object(api_settings, 'OIDC_ALLAUTH_ISSUER_KEY', 'oidc_endpoint')
    def test_returns_none_when_settings_is_empty(self):
        """Returns None when SocialApp.settings is an empty dict."""
        mock_app = MagicMock()
        mock_app.settings = {}
        self.assertIsNone(get_allauth_issuer(mock_app))


class TestBearerAuthenticationWithAllauth(AuthenticationTestCaseMixin, DjangoTestCase):
    """Integration tests verifying that bearer auth picks up allauth credentials."""

    def setUp(self):
        self.set_up()

    def test_uses_allauth_credentials_when_configured(self):
        """Introspection uses client_id/secret from SocialApp, not from settings."""
        mock_app = MagicMock()
        mock_app.client_id = 'allauth-client-id'
        mock_app.secret = 'allauth-secret'

        self.responder.set_response(
            'http://example.com/introspect',
            {'username': self.user.username, 'active': True, 'exp': int(time.time()) + 300})

        with patch('oidc_auth.authentication.bearer.get_allauth_app', return_value=mock_app):
            resp = self.client.get('/test/', HTTP_AUTHORIZATION='Bearer sometoken')

        self.assertEqual(resp.status_code, 200)

        expected_auth = base64.b64encode(b'allauth-client-id:allauth-secret').decode('ascii')
        actual_auth = self.mock_post.call_args.kwargs['headers']['Authorization']
        self.assertEqual(actual_auth, f'Basic {expected_auth}')

    def test_uses_allauth_issuer_for_oidc_config(self):
        """oidc_config_for is called with the per-site issuer from SocialApp.settings."""
        from oidc_auth.authentication.bearer import BearerTokenAuthentication

        allauth_issuer = 'https://sso.example.com/realms/myrealm'
        mock_app = MagicMock(client_id='allauth-client-id', secret='allauth-secret')
        mock_oidc_conf = {'introspection_endpoint': 'http://example.com/introspect'}

        self.responder.set_response(
            'http://example.com/introspect',
            {'username': self.user.username, 'active': True, 'exp': int(time.time()) + 300})

        with patch('oidc_auth.authentication.bearer.get_allauth_app', return_value=mock_app), \
             patch('oidc_auth.authentication.bearer.get_allauth_issuer',
                   return_value=allauth_issuer), \
             patch.object(BearerTokenAuthentication, 'oidc_config_for',
                          return_value=mock_oidc_conf) as mock_config_for:
            resp = self.client.get('/test/', HTTP_AUTHORIZATION='Bearer issuertoken')

        self.assertEqual(resp.status_code, 200)
        mock_config_for.assert_called_once_with(allauth_issuer)

    def test_falls_back_to_settings_credentials_when_allauth_returns_none(self):
        """Introspection uses settings credentials when get_allauth_app returns None."""
        self.responder.set_response(
            'http://example.com/introspect',
            {'username': self.user.username, 'active': True, 'exp': int(time.time()) + 300})

        with patch('oidc_auth.authentication.bearer.get_allauth_app', return_value=None):
            resp = self.client.get('/test/', HTTP_AUTHORIZATION='Bearer sometoken')

        self.assertEqual(resp.status_code, 200)

        # Settings credentials are 'test-client-id' / 'test-client-secret' (from tests/settings.py)
        expected_auth = base64.b64encode(b'test-client-id:test-client-secret').decode('ascii')
        actual_auth = self.mock_post.call_args.kwargs['headers']['Authorization']
        self.assertEqual(actual_auth, f'Basic {expected_auth}')
