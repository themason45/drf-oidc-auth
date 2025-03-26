import base64
import logging

import requests
from django.utils.translation import gettext as _
from rest_framework.exceptions import AuthenticationFailed

from oidc_auth.authentication.base import BaseOidcAuthentication
from oidc_auth.settings import api_settings
from oidc_auth.utils import cache

logging.basicConfig()
logger = logging.getLogger(__name__)


class BearerTokenAuthentication(BaseOidcAuthentication):
    """
    Bearer token authentication using the OpenID Connect introspection endpoint.
    """
    www_authenticate_realm = 'api'

    def __init__(self):
        super().__init__()

    def authenticate_header(self, request):
        return "Bearer"

    def authenticate(self, request):
        bearer_token = BearerTokenAuthentication.get_token(request, api_settings.BEARER_AUTH_HEADER_PREFIX)

        introspection_endpoint = self.oidc_config.get('introspection_endpoint', api_settings.INTROSPECTION_ENDPOINT)
        if not introspection_endpoint:
            raise AuthenticationFailed(_('Invalid introspection_endpoint URL. Did not find a URL from OpenID connect '
                                         'discovery metadata nor settings.OIDC_AUTH.INTROSPECTION_ENDPOINT.'))

        client_id = api_settings.OIDC_CLIENT_ID
        client_secret = api_settings.OIDC_CLIENT_SECRET
        auth_header = base64.b64encode(f'{client_id}:{client_secret}'.encode('ascii')).decode('ascii')

        introspection_response = requests.post(introspection_endpoint, headers={
            'Authorization': f'Basic {auth_header}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }, data={
            'token': bearer_token
        })

        introspection_response.raise_for_status()

        introspection_result = introspection_response.json()
        # TODO: Add token caching using the expiry date as a maximum
        if not introspection_result.get('active'):
            raise AuthenticationFailed(_('Token is not active'))
        # Set the `sub` claim to the `username`. The default implementation of `OIDC_RESOLVE_USER_FUNCTION` uses the
        # `sub` claim to resolve the user, however, OIDC introspection endpoints don't return this by default.
        introspection_result["sub"] = introspection_result["username"]

        user = api_settings.OIDC_RESOLVE_USER_FUNCTION(request, introspection_result)

        return user, introspection_result

    @cache(ttl=api_settings.OIDC_BEARER_TOKEN_EXPIRATION_TIME)
    def get_userinfo(self, token):
        userinfo_endpoint = self.oidc_config.get('userinfo_endpoint', api_settings.USERINFO_ENDPOINT)
        if not userinfo_endpoint:
            raise AuthenticationFailed(_('Invalid userinfo_endpoint URL. Did not find a URL from OpenID connect '
                                         'discovery metadata nor settings.OIDC_AUTH.USERINFO_ENDPOINT.'))

        response = requests.get(userinfo_endpoint, headers={
            'Authorization': 'Bearer {0}'.format(token.decode('ascii'))})
        response.raise_for_status()

        return response.json()
