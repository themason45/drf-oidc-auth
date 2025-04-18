SECRET_KEY = 'secret'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }
}
INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
)
ROOT_URLCONF = 'tests.urls'
OIDC_AUTH = {
    'OIDC_ENDPOINT': 'http://example.com',
    'OIDC_CLAIMS_OPTIONS': {
        'aud': {
            'values': ['you', 'me'],
            'essential': True,
        }
    },
    'OIDC_CLIENT_ID': 'test-client-id',
    'OIDC_CLIENT_SECRET': 'test-client-secret',
    'OIDC_RESOLVE_USER_FUNCTION': 'tests.utils.get_user_by_id',
}
