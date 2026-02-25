import json
import logging
from typing import Optional

import requests
from authlib.oidc.discovery import get_well_known_url
from django.utils.encoding import smart_str
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from django.utils.translation import gettext as _

from oidc_auth.settings import api_settings
from oidc_auth.utils import cache

logger = logging.getLogger(__name__)


class BaseOidcAuthentication(BaseAuthentication):
    """
    A base class to provide common methods for OIDC authentication classes.
    """

    @property
    def oidc_config(self):
        """
        Fetch the OpenID Connect discovery metadata using the global OIDC_ENDPOINT
        setting. Results are cached per endpoint via oidc_config_for().
        """
        return self.oidc_config_for(api_settings.OIDC_ENDPOINT)

    @cache(ttl=api_settings.OIDC_CONFIG_CACHE_EXPIRATION_TIME)
    def oidc_config_for(self, endpoint: str) -> dict:
        """
        Fetch the OpenID Connect discovery metadata for a specific issuer URL.
        Results are cached per endpoint, so multiple sites with different issuers
        each get their own cache entry.
        """
        try:
            response = requests.get(
                get_well_known_url(endpoint, external=True),
                timeout=10,
                verify=True
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Error fetching OIDC configuration: {str(e)}")
            raise AuthenticationFailed(_("Error fetching OIDC configuration"))

    @staticmethod
    def get_token(request, prefix: str = api_settings.JWT_AUTH_HEADER_PREFIX) -> Optional[bytes]:
        """
        Get the token from the request authorisation header.
        """
        auth = get_authorization_header(request).split()
        auth_header_prefix = prefix.lower()

        if not auth or smart_str(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided')
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _(
                'Invalid Authorization header. Credentials string should not contain spaces.')
            raise AuthenticationFailed(msg)
        return auth[1]
