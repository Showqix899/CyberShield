from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views

from .views import home

urlpatterns = [
    path("", home, name="home"),

    path("admin/", admin.site.urls),

    path("accounts/", include("accounts.urls")),

    path(
        "login/",
        auth_views.LoginView.as_view(
            template_name="accounts/login.html"
        ),
        name="login",
    ),

    path(
        "logout/",
        auth_views.LogoutView.as_view(),
        name="logout",
    ),

    path("dashboard/", include("dashboard.urls")),
    path("scanner/", include("scanner.urls")),
]