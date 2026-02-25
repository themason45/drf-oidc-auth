# OpenID Connect authentication for Django Rest Framework

This package contains an authentication mechanism for authenticating
users of a REST API using tokens obtained from OpenID Connect.

It supports authentication via:
- JSON Web Tokens (JWT) ID Tokens
- Bearer Tokens

In the case of JWTs, validation is done using the public keys made available by the OpenID
Connect provider. Read more about JWT validation in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519).
The provider's public keys are fetched from its JWKS endpoint and cached for a configurable time.

In the case of Bearer tokens, the token is introspected using the provider's introspection
endpoint. Read more about token introspection in [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662).

---

## Installation

```sh
pip install drf-oidc-auth
```

If you intend to use the [django-allauth integration](#django-allauth-integration), install the
optional extra instead:

```sh
pip install drf-oidc-auth[allauth]
```

---

## Configuration

Configure the authentication classes in `settings.py`:

```python
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'oidc_auth.authentication.JSONWebTokenAuthentication',
        'oidc_auth.authentication.BearerTokenAuthentication',
    ),
}
```

Then add an `OIDC_AUTH` block to configure the module:

```python
OIDC_AUTH = {
    # --- OIDC provider ---

    # Issuer URL of the OpenID Provider.
    # Used to construct the well-known discovery endpoint and must match
    # the `iss` claim in received JWTs.
    'OIDC_ENDPOINT': 'https://sso.example.com/realms/myrealm',

    # Claims validation options passed to authlib.
    # ref: https://docs.authlib.org/en/latest/jose/jwt.html#jwt-payload-claims-validation
    'OIDC_CLAIMS_OPTIONS': {
        'aud': {
            'essential': True,
            'values': ['my-client-id'],
        }
    },

    # --- Bearer token / introspection (RFC 7662) ---

    # Client ID and secret used for Basic auth on the introspection endpoint.
    'OIDC_CLIENT_ID': 'my-client-id',
    'OIDC_CLIENT_SECRET': 'my-client-secret',

    # Override the introspection endpoint if it is not published in the
    # provider's discovery document.
    'INTROSPECTION_ENDPOINT': None,

    # Override the userinfo endpoint if it is not published in the
    # provider's discovery document.
    'USERINFO_ENDPOINT': None,

    # How long (seconds) a validated bearer token result is cached locally
    # before the introspection endpoint is called again.
    'OIDC_BEARER_TOKEN_EXPIRATION_TIME': 300,

    # --- Caching ---

    # How long (seconds) to cache the OIDC discovery document.
    'OIDC_CONFIG_CACHE_EXPIRATION_TIME': 24 * 60 * 60,

    # How long (seconds) to cache the provider's public JWKS.
    'OIDC_JWKS_EXPIRATION_TIME': 24 * 60 * 60,

    # Django cache backend to use (must be defined in settings.CACHES).
    'OIDC_CACHE_NAME': 'default',

    # Prefix applied to all cache keys.
    'OIDC_CACHE_PREFIX': 'oidc_auth',

    # --- Misc ---

    # Maximum age (seconds) of a token's `iat` claim relative to now.
    'OIDC_LEEWAY': 600,

    # Dotted-path to a function that resolves a Django user from the
    # request and the token payload / introspection result.
    # Default implementation looks up a user by email using the `sub` claim.
    'OIDC_RESOLVE_USER_FUNCTION': 'oidc_auth.authentication.get_user_by_id',

    # Authorization header prefixes (change only if your provider is non-standard).
    'JWT_AUTH_HEADER_PREFIX': 'JWT',
    'BEARER_AUTH_HEADER_PREFIX': 'Bearer',
}
```

---

## django-allauth Integration

When your application has [django-allauth](https://docs.allauth.org/) installed you can source
OIDC credentials and the issuer URL directly from a `SocialApp`, resolved per Django site.
This allows different sites in a multi-site project to authenticate against different OIDC
providers without any code changes.

### Requirements

- `django-allauth>=64.0` with `allauth.socialaccount` in `INSTALLED_APPS`
- `django.contrib.sites` in `INSTALLED_APPS` with `SITE_ID` configured

### Settings

```python
OIDC_AUTH = {
    # Allauth provider ID to look up (e.g. the value of SocialApp.provider).
    # When set, client_id and secret are taken from the matching SocialApp
    # for the current Django site instead of from OIDC_CLIENT_ID / OIDC_CLIENT_SECRET.
    'OIDC_ALLAUTH_PROVIDER': 'keycloak',

    # Key inside SocialApp.settings (a JSON field) that holds the OIDC issuer URL.
    # When set, overrides OIDC_ENDPOINT on a per-site basis.
    # Example: if SocialApp.settings == {"oidc_endpoint": "https://…"}, set this to 'oidc_endpoint'.
    'OIDC_ALLAUTH_ISSUER_KEY': 'oidc_endpoint',

    # OIDC_ENDPOINT is still used as a fallback when no SocialApp is found.
    'OIDC_ENDPOINT': 'https://sso.example.com/realms/default',
}
```

### How it works

On each bearer token request the library:

1. Queries `SocialApp.objects.filter(provider=OIDC_ALLAUTH_PROVIDER, sites=current_site).first()`
2. If a `SocialApp` is found:
   - Uses `social_app.client_id` and `social_app.secret` for introspection auth
   - Reads `social_app.settings[OIDC_ALLAUTH_ISSUER_KEY]` as the issuer URL (if configured)
   - Fetches and caches the OIDC discovery document for that issuer independently
3. If no `SocialApp` is found, falls back to `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and `OIDC_ENDPOINT` from settings

The discovery document cache is keyed per issuer URL, so different sites using different
providers do not interfere with each other.

---

## Running tests

```sh
pip install tox
tox
```

---

## Mocking authentication in tests

An `AuthenticationTestCaseMixin` is provided in `oidc_auth.test` to simplify writing tests
for views that use OIDC authentication:

```python
from django.test import TestCase
from oidc_auth.test import AuthenticationTestCaseMixin

class MyViewTests(AuthenticationTestCaseMixin, TestCase):
    def setUp(self):
        self.set_up()

    def test_valid_bearer_token(self):
        self.responder.set_response(
            'http://example.com/introspect',
            {'username': self.user.username, 'active': True})
        resp = self.client.get('/my-endpoint/', HTTP_AUTHORIZATION='Bearer mytoken')
        self.assertEqual(resp.status_code, 200)

    def test_invalid_bearer_token(self):
        self.responder.set_response('http://example.com/introspect', '', 401)
        resp = self.client.get('/my-endpoint/', HTTP_AUTHORIZATION='Bearer badtoken')
        self.assertEqual(resp.status_code, 401)
```

The mixin patches `requests.get` and `requests.post` with a `FakeRequests` responder so no
real HTTP calls are made. Call `self.responder.set_response(url, body, status_code)` to
configure what each endpoint returns.

---

## Compatibility matrix

| Python | Django | DRF    | Authlib | Requests |
|--------|--------|--------|---------|----------|
| 3.10   | 4.2.*  | 3.14.* / 3.15.* | 1.*  | 2.31.* |
| 3.11   | 4.2.*  | 3.14.* / 3.15.* | 1.*  | 2.31.* |
| 3.11   | 5.1.*  | 3.15.* | 1.*     | 2.31.* |
| 3.12   | 4.2.*  | 3.14.* / 3.15.* | 1.*  | 2.31.* |
| 3.12   | 5.1.*  | 3.15.* | 1.*     | 2.31.* |
| 3.12   | 5.2.*  | 3.15.* | 1.*     | 2.31.* |
| 3.13   | 5.1.*  | 3.15.* | 1.*     | 2.31.* |
| 3.13   | 5.2.*  | 3.15.* | 1.*     | 2.31.* |

---

## References

- [Django REST Framework](https://www.django-rest-framework.org/)
- [Django](https://www.djangoproject.com/)
- [Authlib](https://docs.authlib.org/)
- Inspired by [REST framework JWT Auth](https://github.com/GetBlimp/django-rest-framework-jwt)
