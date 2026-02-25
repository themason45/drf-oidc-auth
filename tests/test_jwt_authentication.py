import time
from unittest.mock import patch

import requests
from django.test import TestCase

from oidc_auth.test import AuthenticationTestCaseMixin, make_id_token


class TestJWTAuthentication(AuthenticationTestCaseMixin, TestCase):
    urls = __name__

    def setUp(self):
        self.set_up()

    def test_using_valid_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username, iat=time.time())
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content.decode(), 'a')

    def test_without_jwt(self):
        resp = self.client.get('/test/')
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_jwt(self):
        auth = 'JWT e30='
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_auth_header(self):
        # This will end up trying to authenticate with a Bearer token, so best make sure
        # that token will be seen as invalid.
        self.responder.set_response('http://example.com/introspect', "", 401)
        auth = 'Bearer 12345'
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)

        self.assertEqual(resp.status_code, 401)

    def test_with_expired_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username, exp=13151351)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_old_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username, iat=13151351)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_issuer(self):
        auth = 'JWT ' + \
               make_id_token(self.user.username, iss='http://something.com')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_invalid_audience(self):
        auth = 'JWT ' + make_id_token(self.user.username, aud='somebody')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_too_new_jwt(self):
        auth = 'JWT ' + make_id_token(self.user.username, nbf=999999999999)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_unknown_subject(self):
        auth = 'JWT ' + make_id_token(self.user.username + 'x')
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_multiple_audiences(self):
        auth = 'JWT ' + make_id_token(self.user.username, aud=['you', 'me'], iat=time.time())
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_with_invalid_multiple_audiences(self):
        # If at least one audience is valid, then the JWT is valid.
        auth = 'JWT ' + make_id_token(self.user.username, aud=['we', 'me'], iat=time.time())
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

        # If none of the audiences are valid, then the JWT is invalid.
        auth = 'JWT ' + make_id_token(self.user.username, aud=['we', 'woo'], iat=time.time())
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_with_multiple_audiences_and_authorized_party(self):
        auth = 'JWT ' + \
               make_id_token(self.user.username, aud=['you', 'me'], azp='you', iat=time.time())
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 200)

    def test_with_invalid_signature(self):
        auth = 'JWT ' + make_id_token(self.user.username, iat=time.time())
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth + 'x')
        self.assertEqual(resp.status_code, 401)
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth + 'x')
        self.assertEqual(resp.status_code, 401)

    @patch('oidc_auth.authentication.jwt.logger')
    def test_decode_jwt_logs_exception_message_when_decode_throws_exception(
            self,
            logger_mock
    ):
        # Append some rubbish to the end of the JWT to make sure the signature is invalid.
        # If the signature is invalid, then we should get the exception message logged.
        auth = 'JWT ' + make_id_token(self.user.username, iat=time.time()) + "MAKEMEINVALID"
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)

        self.assertEqual(resp.status_code, 401)
        logger_mock.exception.assert_called_once_with(
            'Invalid Authorization header. JWT Signature verification failed.')

    def test_oidc_config_fetch_failure(self):
        """A network error fetching the OIDC discovery document returns 401."""
        self.mock_get.side_effect = requests.RequestException("Connection failed")
        auth = 'JWT ' + make_id_token(self.user.username, iat=time.time())
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)

    def test_jwks_fetch_failure(self):
        """A network error fetching the JWKS returns 401."""
        def selective_failure(url, *args, **kwargs):
            if 'jwks' in url:
                raise requests.RequestException("JWKS fetch failed")
            return self.responder.get(url, *args, **kwargs)

        self.mock_get.side_effect = selective_failure
        auth = 'JWT ' + make_id_token(self.user.username, iat=time.time())
        resp = self.client.get('/test/', HTTP_AUTHORIZATION=auth)
        self.assertEqual(resp.status_code, 401)
