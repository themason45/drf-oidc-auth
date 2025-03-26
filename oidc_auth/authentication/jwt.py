import logging
import time

import requests
from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import (BadSignatureError, DecodeError,
                                 ExpiredTokenError, JoseError)
from authlib.oidc.core import IDToken
from django.utils.functional import cached_property
from django.utils.translation import gettext as _
from rest_framework.exceptions import AuthenticationFailed

from oidc_auth.authentication.base import BaseOidcAuthentication
from oidc_auth.settings import api_settings
from oidc_auth.utils import cache

logging.basicConfig()
logger = logging.getLogger(__name__)


class DRFIDToken(IDToken):
    """
    Custom IDToken class that checks for expiration and iat claims.
    """

    def validate_exp(self, now, leeway):
        super(DRFIDToken, self).validate_exp(now, leeway)
        if now > self['exp']:
            msg = _('Invalid Authorization header. JWT has expired.')
            raise AuthenticationFailed(msg)

    def validate_iat(self, now, leeway):
        super(DRFIDToken, self).validate_iat(now, leeway)
        if self['iat'] < leeway:
            msg = _('Invalid Authorization header. JWT too old.')
            raise AuthenticationFailed(msg)


class JSONWebTokenAuthentication(BaseOidcAuthentication):
    """
    Token based authentication using the JSON Web Token standard.
    Behind the scenes it makes use of the Authlib library ([Authlib](https://docs.authlib.org/en/latest/)).
    """

    www_authenticate_realm = 'api'

    def authenticate_header(self, request):
        return "JWT"

    @property
    def claims_options(self):
        _claims_options = {
            'iss': {
                'essential': True,
                'values': [self.issuer]
            }
        }
        for key, value in api_settings.OIDC_CLAIMS_OPTIONS.items():
            _claims_options[key] = value
        return _claims_options

    def authenticate(self, request):
        jwt_value = JSONWebTokenAuthentication.get_token(request)
        if jwt_value is None:
            return None
        payload = self.decode_jwt(jwt_value)
        self.validate_claims(payload)

        user = api_settings.OIDC_RESOLVE_USER_FUNCTION(request, payload)

        return user, payload

    def jwks(self):
        return JsonWebKey.import_key_set(self.jwks_data())

    @cache(ttl=api_settings.OIDC_JWKS_EXPIRATION_TIME)
    def jwks_data(self):
        r = requests.get(self.oidc_config['jwks_uri'], allow_redirects=True)
        r.raise_for_status()
        return r.json()

    @cached_property
    def issuer(self):
        return self.oidc_config['issuer']

    def decode_jwt(self, jwt_value):
        try:
            id_token = jwt.decode(
                jwt_value.decode('ascii'),
                self.jwks(),
                claims_cls=DRFIDToken,
                claims_options=self.claims_options
            )
        except (BadSignatureError, DecodeError):
            msg = _(
                'Invalid Authorization header. JWT Signature verification failed.')
            logger.exception(msg)
            raise AuthenticationFailed(msg)
        except AssertionError:
            msg = _(
                'Invalid Authorization header. Please provide base64 encoded ID Token'
            )
            raise AuthenticationFailed(msg)

        return id_token

    def validate_claims(self, id_token):
        try:
            id_token.validate(
                now=int(time.time()),
                leeway=int(time.time() - api_settings.OIDC_LEEWAY)
            )
        except ExpiredTokenError:
            msg = _('Invalid Authorization header. JWT has expired.')
            raise AuthenticationFailed(msg)
        except JoseError as e:
            msg = _(str(type(e)) + str(e))
            raise AuthenticationFailed(msg)

    def authenticate_header(self, request):
        return 'JWT realm="{0}"'.format(self.www_authenticate_realm)
