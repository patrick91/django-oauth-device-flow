from django.views.decorators.csrf import csrf_exempt

from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from authlib.integrations.django_oauth2 import BearerTokenValidator, ResourceProtector
from django.http import JsonResponse

from my_auth.models import OAuth2Token

from .server import server


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
    breakpoint()
    return server.create_token_response(request)


require_oauth = ResourceProtector()
require_oauth.register_token_validator(BearerTokenValidator(OAuth2Token))


@require_oauth("profile")
def user_profile(request):
    user = request.oauth_token.user
    return JsonResponse(dict(sub=user.pk, username=user.username))
