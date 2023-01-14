# from authlib.common.security import generate_token
from authlib.integrations.django_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc8628 import DeviceAuthorizationEndpoint, DeviceCodeGrant
from django.contrib.auth import get_user_model


from .models import AuthorizationCode, OAuth2Client, OAuth2Token, DeviceCredential

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


class MyDeviceAuthorizationEndpoint(DeviceAuthorizationEndpoint):
    def get_verification_uri(self):
        return "http://localhost:8000/active"

    def save_device_credential(self, client_id, scope, data):
        DeviceCredential.objects.create(
            client_id=client_id,
            scope=scope,
            **data
        )


server.register_endpoint(MyDeviceAuthorizationEndpoint)




class MyDeviceCodeGrant(DeviceCodeGrant):
    def query_device_credential(self, device_code: str):
        return DeviceCredential.objects.filter(device_code=device_code).first()

    def query_user_grant(self, user_code: str):
        credential = DeviceCredential.objects.filter(user_code=user_code).first()

        if not credential:
            return None

        if credential.verified:
            return credential.user, True


    def should_slow_down(self, credential):
        # developers can return True/False based on credential and now
        return False


server.register_grant(MyDeviceCodeGrant)
