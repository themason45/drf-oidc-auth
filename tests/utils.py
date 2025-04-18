from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed
from django.utils.translation import gettext as _


def get_user_by_id(_request, id_token):
    """
    A stub used by the tests to mock the `oidc_auth.authentication.get_user_by_id` function.

    This is specified in the test's settings.py using the `OIDC_AUTH_RESOLVE_USER_FUNCTION` setting.
    """
    User = get_user_model()
    try:
        user = User.objects.get_by_natural_key(id_token.get('sub'))
    except User.DoesNotExist:
        msg = _('Invalid Authorization header. User not found.')
        raise AuthenticationFailed(msg)
    return user
