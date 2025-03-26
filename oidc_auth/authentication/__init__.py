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

    Will 404 if the user does not exist. Your implementation
    may want to handle this differently.
    """
    from django.contrib.auth import get_user_model
    from django.shortcuts import get_object_or_404

    subject = userinfo.get('sub')
    print(subject)
    if not subject:
        return None

    user = get_object_or_404(get_user_model(), email=userinfo['sub'])
    return user