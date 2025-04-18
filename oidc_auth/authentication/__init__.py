import logging

from rest_framework.request import Request

from .bearer import BearerTokenAuthentication
from .jwt import JSONWebTokenAuthentication
from .base import BaseOidcAuthentication

# Leave in place as the tests need to mock this
# noinspection PyUnresolvedReferences
import requests

logging.basicConfig()
logger = logging.getLogger(__name__)

def get_user_by_id(_request: Request, userinfo: dict):
    """
    Default function to resolve user from userinfo.
    It simply matches sub to the user's email.

    Returns None if the user does not exist to avoid information leakage.
    Your implementation may want to handle this differently.
    """
    from django.contrib.auth import get_user_model
    from django.core.exceptions import ObjectDoesNotExist
    import re

    subject = userinfo.get('sub')

    if not subject:
        logger.warning("No subject claim found in token")
        return None

    # Basic validation of the subject claim to prevent injection attacks
    if not isinstance(subject, str) or not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', subject):
        logger.warning(f"Invalid subject claim format: {subject}")
        return None

    try:
        user = get_user_model().objects.get(email=subject)
        return user
    except ObjectDoesNotExist:
        logger.warning(f"User with email {subject} not found")
        return None
