from authlib.integrations.django_oauth2 import BearerTokenValidator, ResourceProtector
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from my_auth.models import OAuth2Token

from .server import server
from .models import DeviceCredential


@csrf_exempt
@login_required
def authorize(request):
    if request.method == "GET":
        grant = server.get_consent_grant(request, end_user=request.user)
        client = grant.client
        scope = client.get_allowed_scope(grant.request.scope)
        context = dict(grant=grant, client=client, scope=scope, user=request.user)
        return render(request, "authorize.html", context)

    # if is_user_confirmed(request):
    if True:
        # granted by resource owner
        return server.create_authorization_response(request, grant_user=request.user)

    # denied by resource owner
    return server.create_authorization_response(request, grant_user=None)


# use ``server.create_token_response`` to handle token endpoint


@csrf_exempt
@require_http_methods(["POST"])  # we only allow POST for token endpoint
def issue_token(request):
    return server.create_token_response(request)


require_oauth = ResourceProtector()
require_oauth.register_token_validator(BearerTokenValidator(OAuth2Token))


@csrf_exempt
@require_http_methods(["POST"])  # we only allow POST for token endpoint
def device_authorization(request):
    return server.create_endpoint_response("device_authorization", request)


@require_oauth("profile")
def user_profile(request):
    user = request.oauth_token.user
    return JsonResponse(dict(sub=user.pk, username=user.username))


@csrf_exempt
@login_required
def verify_device_code(request):
    if request.method == "GET":
        return render(request, "verification.html", {"user_code": request.GET["user_code"]})

    credential = DeviceCredential.objects.get(user_code=request.POST["user_code"])

    credential.verified = True
    credential.save()

    return render(request, "verified.html")
