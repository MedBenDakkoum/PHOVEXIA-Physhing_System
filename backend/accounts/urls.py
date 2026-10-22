from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    ChangePasswordView,
    LoginView,
    LogoutView,
    MeView,
    PasswordResetConfirmView,
    PasswordResetView,
    RegisterView,
    ThrottledTokenRefreshView,
    UserAdminViewSet,
)

router = DefaultRouter()
router.register("users", UserAdminViewSet, basename="user")

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("refresh/", ThrottledTokenRefreshView.as_view(), name="token_refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("me/", MeView.as_view(), name="me"),
    path("change-password/", ChangePasswordView.as_view(), name="change_password"),
    # Step 13 (US5): password reset - request + confirm.
    path(
        "password-reset/",
        PasswordResetView.as_view(),
        name="password_reset",
    ),
    path(
        "password-reset/confirm/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path("", include(router.urls)),
]
