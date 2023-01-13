from authlib.common.security import generate_token
from authlib.integrations.django_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import grants
from django.contrib.auth import get_user_model

from .models import AuthorizationCode, OAuth2Client, OAuth2Token

User = get_user_model()

server = AuthorizationServer(OAuth2Client, OAuth2Token)


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        client = request.client
        auth_code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            response_type=request.response_type,
            scope=request.scope,
            user=request.user,
        )
        auth_code.save()
        return auth_code

    def query_authorization_code(self, code, client):
        try:
            item = AuthorizationCode.objects.get(code=code, client_id=client.client_id)
        except AuthorizationCode.DoesNotExist:
            return None

        if not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        authorization_code.delete()

    def authenticate_user(self, authorization_code):
        return authorization_code.user


# register it to grant endpoint
server.register_grant(AuthorizationCodeGrant)


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def authenticate_user(self, username, password):
        try:
            user = User.objects.get(username=username)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None


# register it to grant endpoint
server.register_grant(PasswordGrant)
