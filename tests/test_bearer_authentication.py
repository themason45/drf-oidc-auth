import sys
import time

from django.test import TestCase
from rest_framework.exceptions import AuthenticationFailed

from oidc_auth.test import AuthenticationTestCaseMixin

if sys.version_info > (3,):
    long = int
else:
    # noinspection PyShadowingBuiltins
    class ConnectionError(OSError):
        """
        Wrapper for ConnectionError to be compatible with Python 2.7.
        """
        pass

try:
    from unittest.mock import Mock, PropertyMock, patch
except ImportError:
    # Supress warnings since this is dependent on the Python version
    # noinspection PyUnresolvedReferences,PyPackageRequirements
    from mock import Mock, PropertyMock, patch


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
            'http://example.com/introspect', {'username': self.user.username, 'active': True, 'exp': 30})
        auth = 'Bearer abcdefg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.content.decode(), 'a')
        self.assertEqual(resp.status_code, 200)

    def test_cache_of_valid_bearer_token(self):
        token_expiry = 1
        self.responder.set_response(
            'http://example.com/introspect', {'username': self.user.username, 'active': True, 'exp': token_expiry})
        auth = 'Bearer egergerg'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

        # Token expires, but validity is cached
        self.responder.set_response('http://example.com/introspect', "", 401)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

        time.sleep(token_expiry)

        # The cached value should have expired as the introspection endpoint specified the lifetime of the token
        # The caching backend should invalidate the cached value after `token_expiry` has passed.
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
            # Import BearerTokenAuthentication here.
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
            # Import BearerTokenAuthentication here.
            from oidc_auth.authentication import BearerTokenAuthentication
            authentication = BearerTokenAuthentication()

            with self.assertRaisesMessage(AuthenticationFailed, 'userinfo_endpoint'):
                authentication.get_userinfo(b'faketoken')
