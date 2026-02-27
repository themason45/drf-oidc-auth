from typing import Optional
from oidc_auth.settings import api_settings


def get_allauth_issuer(social_app) -> Optional[str]:
    """
    Read the OIDC issuer URL from a SocialApp's settings JSON field.

    The key to look up is configured via OIDC_AUTH['OIDC_ALLAUTH_ISSUER_KEY'].
    Returns None when the setting is unset, when social_app is None, or when
    the key is absent from social_app.settings, causing the caller to fall back
    to the global OIDC_ENDPOINT setting.
    """
    key = api_settings.OIDC_ALLAUTH_ISSUER_KEY
    if not key or not social_app:
        return None
    settings_data = getattr(social_app, 'settings', None) or {}
    return settings_data.get(key) or None


def get_allauth_app(request):
    """
    Retrieve the allauth SocialApp for the current Django site, when allauth
    integration is configured via OIDC_AUTH['OIDC_ALLAUTH_PROVIDER'].

    Returns the SocialApp instance if one is found for the current site, or
    None to fall back to OIDC_CLIENT_ID / OIDC_CLIENT_SECRET from settings.

    Requirements when this feature is in use:
    - django-allauth installed with 'allauth.socialaccount' in INSTALLED_APPS
    - 'django.contrib.sites' in INSTALLED_APPS and SITE_ID configured
    """
    provider = api_settings.OIDC_ALLAUTH_PROVIDER
    if not provider:
        return None

    try:
        from allauth.socialaccount.models import SocialApp
        from django.contrib.sites.shortcuts import get_current_site
    except ImportError:
        return None

    site = get_current_site(request)
    app: Optional[SocialApp] = SocialApp.objects.filter(provider=provider, sites=site).first()

    return app
