from django.urls import path
from . import views

urlpatterns = [
    path('token', views.issue_token, name='issue_token'),
    path("authorize", views.authorize, name="authorize"),
    # path('introspection', views.introspect_token, name="introspect_token")
]