import time
from unittest.mock import Mock, PropertyMock, patch

import requests
from django.test import TestCase
from rest_framework.exceptions import AuthenticationFailed

from oidc_auth.test import AuthenticationTestCaseMixin


class TestBearerAuthentication(AuthenticationTestCaseMixin, TestCase):
    urls = __name__

    def setUp(self):
        self.set_up()
        self.openid_configuration = {
            'issuer': 'http://accounts.example.com/dex',
            'authorization_endpoint': 'http://accounts.example.com/dex/auth',
            'token_endpoint': 'http://accounts.example.com/dex/token',
            'jwks_uri': 'http://accounts.example.com/dex/keys',
            'response_types_supported': ['code'],
            'subject_types_supported': ['public'],
            'id_token_signing_alg_values_supported': ['RS256'],
            'scopes_supported': ['openid', 'email', 'groups', 'profile', 'offline_access'],
            'token_endpoint_auth_methods_supported': ['client_secret_basic'],
            'claims_supported': [
                'aud', 'email', 'email_verified', 'exp', 'iat', 'iss', 'locale',
                'name', 'sub'
            ],
            'userinfo_endpoint': 'http://sellers.example.com/v1/sellers/'
        }

    def test_using_valid_bearer_token(self):
        self.responder.set_response(
            'http://example.com/introspect',
            {'username': self.user.username, 'active': True, 'exp': int(time.time()) + 300})
        auth = 'Bearer abcdefg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.content.decode(), 'a')
        self.assertEqual(resp.status_code, 200)

    def test_cache_of_valid_bearer_token(self):
        cache_ttl = 2
        token_exp = int(time.time()) + cache_ttl
        self.responder.set_response(
            'http://example.com/introspect',
            {'username': self.user.username, 'active': True, 'exp': token_exp})
        auth = 'Bearer egergerg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

        # Token expires at the server, but our local cache still considers it valid
        self.responder.set_response('http://example.com/introspect', "", 401)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

        time.sleep(cache_ttl + 1)

        # Cache has expired; re-validates against introspection endpoint which now rejects it
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_using_invalid_bearer_token(self):
        self.responder.set_response('http://example.com/introspect', "", 401)
        auth = 'Bearer hjikasdf'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_cache_of_invalid_bearer_token(self):
        self.responder.set_response('http://example.com/introspect', "", 401)
        auth = 'Bearer feegrgeregreg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

        # Token becomes valid
        self.responder.set_response(
            'http://example.com/introspect', {'username': self.user.username, 'active': True}, 200)

        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_using_inactive_bearer_token(self):
        """A 200 introspection response with active=false is rejected."""
        self.responder.set_response(
            'http://example.com/introspect', {'active': False}, 200)
        auth = 'Bearer inactivetoken'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_introspection_network_error(self):
        """A network error during the introspection POST returns 401."""
        self.mock_post.side_effect = requests.RequestException("Connection failed")
        auth = 'Bearer sometoken'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_introspection_missing_username(self):
        """An introspection response without a username claim returns 401 rather than crashing."""
        self.responder.set_response(
            'http://example.com/introspect', {'active': True}, 200)
        auth = 'Bearer tokenwithoutusr'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_missing_introspection_endpoint(self):
        """AuthenticationFailed is raised when no introspection endpoint is discoverable."""
        with patch('oidc_auth.authentication.BaseOidcAuthentication.oidc_config',
                   new_callable=PropertyMock) as mock_config:
            mock_config.return_value = {
                'issuer': 'http://example.com',
                'jwks_uri': 'http://example.com/jwks',
                # No introspection_endpoint
            }
            auth = 'Bearer sometoken'
            resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
            self.assertEqual(resp.status_code, 401)

    def test_using_malformed_bearer_token(self):
        auth = 'Bearer abc def'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_using_missing_bearer_token(self):
        auth = 'Bearer'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_using_inaccessible_userinfo_endpoint(self):
        self.mock_get.side_effect = ConnectionError
        auth = 'Bearer'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_get_user_info_endpoint(self):
        with patch('oidc_auth.authentication.BaseOidcAuthentication.oidc_config',
                   new_callable=PropertyMock) as oidc_config_mock:
            oidc_config_mock.return_value = self.openid_configuration
            from oidc_auth.authentication import BearerTokenAuthentication

            authentication = BearerTokenAuthentication()
            response_mock = Mock(return_value=Mock(status_code=200,
                                                   json=Mock(return_value={}),
                                                   raise_for_status=Mock(return_value=None)))
            with patch('oidc_auth.authentication.requests.get', response_mock):
                result = authentication.get_userinfo(b'token')
                assert result == {}

    def test_get_user_info_endpoint_with_missing_field(self):
        self.openid_configuration.pop('userinfo_endpoint')
        with patch('oidc_auth.authentication.BaseOidcAuthentication.oidc_config',
                   new_callable=PropertyMock) as oidc_config_mock:
            oidc_config_mock.return_value = self.openid_configuration
            from oidc_auth.authentication import BearerTokenAuthentication
            authentication = BearerTokenAuthentication()

            with self.assertRaisesMessage(AuthenticationFailed, 'userinfo_endpoint'):
                authentication.get_userinfo(b'faketoken')
