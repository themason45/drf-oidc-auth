import json
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from requests.models import Response
from authlib.jose import JsonWebToken, KeySet, RSAKey

try:
    from unittest.mock import patch, Mock, MagicMock, AsyncMock
except ImportError:
    from mock import patch, Mock, MagicMock, AsyncMock

key = RSAKey.generate_key(is_private=True)

def make_id_token(sub,
                  iss='http://example.com',
                  aud='you',
                  exp=999999999999,  # tests will start failing in September 33658
                  iat=999999999999,
                  **kwargs):
    return make_jwt(
        dict(
            iss=iss,
            aud=aud,
            exp=exp,
            iat=iat,
            sub=str(sub),
            **kwargs
        )
    ).decode('ascii')


def make_jwt(payload):
    jwt = JsonWebToken(['RS256'])
    jws = jwt.encode(
        {'alg': 'RS256', 'kid': key.as_dict(add_kid=True).get('kid')}, payload, key=key)
    return jws


class FakeRequests:
    """
    A fake requests object that can be used to mock `requests.get` in tests.

    :usage: ```python
    responder = FakeRequests()
    responder.set_response("http://example.com/...",
                           {"abc": "xyz"})

    self.mock_get = [PATCH PATH TO requests.get]
    self.mock_get.side_effect = self.responder.get
    ```
    """

    def __init__(self):
        self.responses = {}

    def set_response(self, url, content, status_code=200):
        self.responses[url] = (status_code, json.dumps(content))

    def get(self, url, *args, **kwargs):
        wanted_response = self.responses.get(url)
        if not wanted_response:
            status_code, content = 404, ''
        else:
            status_code, content = wanted_response

        response = Response()
        response._content = content.encode('utf-8')
        response.status_code = status_code

        return response

    def post(self, url, *args, **kwargs):
        wanted_response = self.responses.get(url)
        if not wanted_response:
            status_code, content = 404, ''
        else:
            status_code, content = wanted_response

        response = Response()
        response._content = content.encode('utf-8')
        response.status_code = status_code

        return response


class AuthenticationTestCaseMixin:
    username = 'demouser'
    user: User
    responder: FakeRequests
    mock_get: MagicMock | AsyncMock
    mock_post: MagicMock | AsyncMock

    @staticmethod
    def patch(thing_to_mock, **kwargs) -> MagicMock | AsyncMock:
        """
        Wrap the unittest patch decorator to make it easier to use in tests.
        """
        patcher = patch(thing_to_mock, **kwargs)
        patched = patcher.start()
        return patched

    def set_up(self):
        """
        Set up the test case with a user and a responder that will return the
        """
        self.user, _ = get_user_model().objects.get_or_create(username=self.username)
        self.responder = FakeRequests()
        self.responder.set_response("http://example.com/.well-known/openid-configuration",
                                    {"jwks_uri": "http://example.com/jwks",
                                     "issuer": "http://example.com",
                                     "userinfo_endpoint": "http://example.com/userinfo",
                                     "introspection_endpoint": "http://example.com/introspect"})
        keys = KeySet(keys=[key])

        self.responder.set_response("http://example.com/jwks", keys.as_dict())
        self.responder.set_response("http://example.com/introspect", {"active": True, "username": self.username})
        self.mock_get = AuthenticationTestCaseMixin.patch('requests.get')
        self.mock_get.side_effect = self.responder.get
        self.mock_post = AuthenticationTestCaseMixin.patch('requests.post')
        self.mock_post.side_effect = self.responder.post
