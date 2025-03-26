import json

import requests
from authlib.oidc.discovery import get_well_known_url
from django.utils.encoding import smart_str
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from django.utils.translation import gettext as _

from oidc_auth.settings import api_settings
from oidc_auth.utils import cache


class BaseOidcAuthentication(BaseAuthentication):
    """
    A base class to provide common methods for OIDC authentication classes.
    """

    @property
    @cache(ttl=api_settings.OIDC_BEARER_TOKEN_EXPIRATION_TIME)
    def oidc_config(self):
        """
        Fetch the OpenID Connect discovery metadata from the well-known endpoint.
        The well-known endpoint is derived from the OIDC_ENDPOINT setting.
        """
        config = requests.get(
            get_well_known_url(
                api_settings.OIDC_ENDPOINT,
                external=True
            )
        ).json()

        return config

    @staticmethod
    def get_token(request, prefix: str = api_settings.JWT_AUTH_HEADER_PREFIX):
        """

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

        print("Found auth token: ", auth[1])
        return auth[1]
