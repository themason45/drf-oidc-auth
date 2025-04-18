import sys

from django.http import HttpResponse
from django.urls import re_path as url
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from oidc_auth.authentication import (BearerTokenAuthentication,
                                      JSONWebTokenAuthentication)

class MockView(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (
        JSONWebTokenAuthentication,
        BearerTokenAuthentication
    )

    def get(self, request):
        return HttpResponse('a')


urlpatterns = [
    url(r'^test/$', MockView.as_view(), name="testview")
]
