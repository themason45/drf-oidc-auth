from django.conf import settings
from rest_framework.settings import APISettings

USER_SETTINGS = getattr(settings, 'OIDC_AUTH', None)

DEFAULTS = {
    # OIDC Client credentials
    ## The following is related to OAuth2 Token Introspection
    ## https://datatracker.ietf.org/doc/html/rfc7662
    ## They are only required for use with Bearer tokens.

    # The Client ID of this application for use with
    # token introspection.
    'OIDC_CLIENT_ID': None,
    # The Client Secret of this application for use with
    # token introspection.
    'OIDC_CLIENT_SECRET': None,
    # The endpoint to use for token introspection.
    'INTROSPECTION_ENDPOINT': None,

    ## OIDC Provider configuration

    # The Issuer URL of the OpenID Provider
    # Should match the `iss` claim in the JWT
    'OIDC_ENDPOINT': None,

    # The Claims Options can now be defined by a static string.
    # ref: https://docs.authlib.org/en/latest/jose/jwt.html#jwt-payload-claims-validation
    'OIDC_CLAIMS_OPTIONS': {
        'aud': {
            'essential': True,
        }
    },

    # The time for which to keep the current OIDC configuration in cache
    'OIDC_CONFIG_CACHE_EXPIRATION_TIME': 24 * 60 * 60,

    # The time for which to keep the current JWKs (JSON Web Keys) in cache for validating JWTs.
    'OIDC_JWKS_EXPIRATION_TIME': 24 * 60 * 60,

    # Number of seconds in the past valid tokens can be issued
    'OIDC_LEEWAY': 600,

    # Function to resolve user from request and token or userinfo
    'OIDC_RESOLVE_USER_FUNCTION': 'oidc_auth.authentication.get_user_by_id',

    # Time before bearer token validity is verified again
    'OIDC_BEARER_TOKEN_EXPIRATION_TIME': 600,

    ## Prefixes for Authorization headers (likely won't need to change)
    # The prefix for the JWT Authorization header
    'JWT_AUTH_HEADER_PREFIX': 'JWT',
    # The prefix for the Bearer Authorization header
    'BEARER_AUTH_HEADER_PREFIX': 'Bearer',

    # The Django cache to use
    # This should be the name of a cache defined in the CACHES setting (defaults to 'default')
    # If you have a Redis cache, then you could use that.
    'OIDC_CACHE_NAME': 'default',
    # The prefix to use for cache keys (excluding trailing '.')
    'OIDC_CACHE_PREFIX': 'oidc_auth',
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'OIDC_RESOLVE_USER_FUNCTION',
)

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
