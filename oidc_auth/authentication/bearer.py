import base64
import hashlib
import logging
from typing import Optional

import requests
from django.contrib.auth.models import User
from django.utils.translation import gettext as _
from rest_framework.exceptions import AuthenticationFailed

from oidc_auth.authentication.base import BaseOidcAuthentication
from oidc_auth.settings import api_settings
from oidc_auth.utils import cache
from oidc_auth.utils.caching import get_cache_key, get_cached_value, set_cache_value

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
        return api_settings.BEARER_AUTH_HEADER_PREFIX

    def authenticate(self, request) -> Optional[tuple[User, dict]]:
        bearer_token: Optional[bytes] = BearerTokenAuthentication.get_token(request,
                                                                            api_settings.BEARER_AUTH_HEADER_PREFIX)

        # Return None here instead of raising an error so that other Authentication classes can be tried.
        if not bearer_token:
            return None

        # Use SHA512.
        # While not as secure as bcrypt or Argon, it is faster, and it is likely that by the
        # time the hash is cracked, the token will have expired.
        token_hash = hashlib.sha512(bearer_token).hexdigest()
        cache_key = get_cache_key("Bearer", token_hash)

        # Early return if the token is cached
        if cached_introspection_result := get_cached_value(cache_key):
            print("Found cached value")
            user = api_settings.OIDC_RESOLVE_USER_FUNCTION(request, cached_introspection_result)
            return user, cached_introspection_result

        # Resolve the introspection endpoint
        introspection_endpoint = self.oidc_config.get('introspection_endpoint', api_settings.INTROSPECTION_ENDPOINT)
        if not introspection_endpoint:
            raise AuthenticationFailed(_('Invalid introspection_endpoint URL. Did not find a URL from OpenID connect '
                                         'discovery metadata nor settings.OIDC_AUTH.INTROSPECTION_ENDPOINT.'))

        client_id = api_settings.OIDC_CLIENT_ID
        client_secret = api_settings.OIDC_CLIENT_SECRET
        auth_header = base64.b64encode(f'{client_id}:{client_secret}'.encode('ascii')).decode('ascii')

        try:
            introspection_response = requests.post(
                introspection_endpoint,
                headers={
                    'Authorization': f'Basic {auth_header}',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data={
                    'token': bearer_token
                },
                timeout=10,
                verify=True
            )
        except requests.RequestException as e:
            logger.error(f"Error calling introspection endpoint: {str(e)}")
            raise AuthenticationFailed(_("Error calling introspection endpoint"))

        if not introspection_response.ok:
            raise AuthenticationFailed(_('Non 200 response from introspection endpoint'))

        introspection_result = introspection_response.json()

        if not introspection_result.get('active'):
            raise AuthenticationFailed(_('Token is not active'))

        # Set the `sub` claim to the `username`. The default implementation of `OIDC_RESOLVE_USER_FUNCTION` uses the
        # `sub` claim to resolve the user; however, OIDC introspection endpoints don't return this by default.
        introspection_result["sub"] = introspection_result["username"]

        # Calculate cache value expiry time.
        # The introspection result will contain an `exp` claim, which is the expiry time of the token, we also
        # have the `OIDC_BEARER_TOKEN_EXPIRATION_TIME` setting which acts as a default. We will use the earliest.
        token_expiry = introspection_result.get('exp', 0)
        cache_expiry = min(token_expiry, api_settings.OIDC_BEARER_TOKEN_EXPIRATION_TIME)

        # Cache the introspection result
        set_cache_value(cache_key, introspection_result, ttl=cache_expiry)

        user = api_settings.OIDC_RESOLVE_USER_FUNCTION(request, introspection_result)

        return user, introspection_result

    @cache(ttl=api_settings.OIDC_BEARER_TOKEN_EXPIRATION_TIME, has_secret_args=True)
    def get_userinfo(self, token: bytes) -> dict:
        userinfo_endpoint = self.oidc_config.get('userinfo_endpoint', api_settings.USERINFO_ENDPOINT)
        if not userinfo_endpoint:
            raise AuthenticationFailed(_('Invalid userinfo_endpoint URL. Did not find a URL from OpenID connect '
                                         'discovery metadata nor settings.OIDC_AUTH.USERINFO_ENDPOINT.'))

        response = requests.get(
            userinfo_endpoint,
            headers={
                'Authorization': 'Bearer {0}'.format(token.decode('ascii'))
            },
            timeout=10,
            verify=True
        )

        # We don't want to hide the true HTTP status, as we do in other parts of the library.
        response.raise_for_status()
        return response.json()
