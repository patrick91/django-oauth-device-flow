from django.urls import path
from . import views

urlpatterns = [
    path("token", views.issue_token, name="issue_token"),
    path("authorize", views.authorize, name="authorize"),
    path("profile", views.user_profile, name="profile"),
    path(
        "device_authorization", views.device_authorization, name="device_authorization"
    ),
    path("active", views.verify_device_code, name="verify_device_code"),
    # path('introspection', views.introspect_token, name="introspect_token")
]
