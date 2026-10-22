from typing import ClassVar

from django.contrib.auth import get_user_model
from django.db import transaction
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import filters, generics, mixins, status, viewsets
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from audit.models import AuditLog
from audit.services import record
from emails.services import send_templated_email

from .permissions import IsAdmin, IsEndUser
from .serializers import (
    AdminUserSerializer,
    ChangePasswordSerializer,
    LogoutSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    RegisterSerializer,
    UserSerializer,
)
from .services import (
    EmailThrottleExceeded,
    InvalidResetToken,
    confirm_password_reset,
    email_throttle_response,
    hit_email_throttle,
)
from .tasks import send_password_reset_email

User = get_user_model()


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes: ClassVar[list] = [AllowAny]
    # Step 8d: THROTTLE_REGISTER per IP (rate in settings.DEFAULT_THROTTLE_RATES).
    throttle_classes: ClassVar[list] = [ScopedRateThrottle]
    throttle_scope = "register"

    @transaction.atomic
    def perform_create(self, serializer):
        user = serializer.save()
        record(AuditLog.Action.REGISTER, request=self.request, user=user, target=user)
        # Step 13 (US56): welcome email queued AFTER the commit (on_commit).
        send_templated_email(
            user.email,
            "welcome",
            {"first_name": user.first_name or user.email},
            user_id=user.pk,
        )


class LoginView(TokenObtainPairView):
    """Connexion JWT + journalisation des succès et des échecs."""

    # Step 8d: THROTTLE_LOGIN per IP, applied BEFORE the credentials are read,
    # so a throttled attempt writes no audit entry and reveals nothing.
    throttle_classes: ClassVar[list] = [ScopedRateThrottle]
    throttle_scope = "login"

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except AuthenticationFailed:
            # Identifiants refusés : message identique pour mauvais mot de passe
            # ou email inconnu, conformément au cahier des charges.
            record(AuditLog.Action.LOGIN_FAILED, request=request, user=None, email="")
            raise AuthenticationFailed("Identifiants incorrects.")
        except TokenError as e:
            raise InvalidToken(e.args[0])

        record(AuditLog.Action.LOGIN_SUCCESS, request=request, user=serializer.user)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class ThrottledTokenRefreshView(TokenRefreshView):
    """Takes a refresh type JSON web token and returns an access type JSON web
    token if the refresh token is valid.

    Step 8d: throttled, THROTTLE_REFRESH per IP (default 60/min), rate read
    from settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"].
    """

    throttle_classes: ClassVar[list] = [ScopedRateThrottle]
    throttle_scope = "refresh"


class MeView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes: ClassVar[list] = [IsEndUser]

    def get_object(self):
        return self.request.user


class ChangePasswordView(APIView):
    permission_classes: ClassVar[list] = [IsEndUser]
    # Step 8d: THROTTLE_CHANGE_PASSWORD per USER (authenticated -> key = pk).
    throttle_classes: ClassVar[list] = [ScopedRateThrottle]
    throttle_scope = "change_password"

    @extend_schema(
        request=ChangePasswordSerializer,
        responses={
            204: None,
            400: OpenApiResponse(
                description="Mot de passe actuel incorrect ou nouveau mot de passe trop faible."
            ),
        },
    )
    def post(self, request):
        s = ChangePasswordSerializer(data=request.data, context={"request": request})
        s.is_valid(raise_exception=True)
        request.user.set_password(s.validated_data["new_password"])
        request.user.save()
        # Step 13 (US56): security email, ALWAYS sent (not gated by
        # email_notifications).
        send_templated_email(
            request.user.email,
            "password_changed",
            {"first_name": request.user.first_name or request.user.email},
            user_id=request.user.pk,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class LogoutView(APIView):
    permission_classes: ClassVar[list] = [IsEndUser]

    @extend_schema(
        request=LogoutSerializer,
        responses={
            204: None,
            400: OpenApiResponse(description="Token invalide ou expiré."),
        },
    )
    def post(self, request):
        s = LogoutSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        try:
            RefreshToken(s.validated_data["refresh"]).blacklist()
        except TokenError:
            return Response({"detail": "Token invalide ou expiré."},
                            status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_204_NO_CONTENT)


RESET_202_BODY = {
    "detail": (
        "Si un compte actif correspond à cette adresse, un lien de "
        "réinitialisation vient d'être envoyé."
    )
}


class PasswordResetView(APIView):
    """US5 - request a reset link. NEVER reveals whether the account exists.

    Always the same 202 + body (existing, unknown or suspended email); the
    lookup, the token and the email are done in the Celery task, so the
    response time does not leak the answer either.
    """

    permission_classes: ClassVar[list] = [AllowAny]
    throttle_classes: ClassVar[list] = [ScopedRateThrottle]
    throttle_scope = "password_reset"

    @extend_schema(
        request=PasswordResetRequestSerializer,
        responses={
            202: OpenApiResponse(
                description="Toujours 202, que l'email existe ou non."
            ),
        },
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        # 3/hour per HASHED email address, on top of the 5/hour per IP.
        try:
            hit_email_throttle(email)
        except EmailThrottleExceeded as exc:
            return email_throttle_response(exc)
        transaction.on_commit(lambda: send_password_reset_email.delay(email))
        return Response(RESET_202_BODY, status=status.HTTP_202_ACCEPTED)


class PasswordResetConfirmView(APIView):
    """US5 - set the new password with the emailed uid + token."""

    permission_classes: ClassVar[list] = [AllowAny]
    throttle_classes: ClassVar[list] = [ScopedRateThrottle]
    throttle_scope = "password_reset_confirm"

    @extend_schema(
        request=PasswordResetConfirmSerializer,
        responses={
            200: OpenApiResponse(description="Mot de passe réinitialisé."),
            400: OpenApiResponse(
                description="Lien invalide ou expiré, ou mot de passe trop faible."
            ),
        },
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            confirm_password_reset(
                uid=serializer.validated_data["uid"],
                token=serializer.validated_data["token"],
                new_password=serializer.validated_data["new_password"],
                request=request,
            )
        except InvalidResetToken:
            # Same 400 for an invalid, expired or already-used token (and
            # for a suspended account): never says which.
            return Response(
                {"code": "invalid_or_expired_token",
                 "detail": "Lien de réinitialisation invalide ou expiré."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(
            {"detail": "Mot de passe réinitialisé avec succès."},
            status=status.HTTP_200_OK,
        )


class UserAdminViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin,
                       mixins.UpdateModelMixin, mixins.DestroyModelMixin,
                       viewsets.GenericViewSet):
    """Gestion des utilisateurs (admin uniquement). DELETE = suspension du compte."""
    queryset: ClassVar = User.objects.all().order_by("-date_joined")
    serializer_class = AdminUserSerializer
    permission_classes: ClassVar[list] = [IsAdmin]
    filter_backends: ClassVar[list] = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields: ClassVar[list[str]] = ["role", "is_active"]
    search_fields: ClassVar[list[str]] = ["email", "first_name", "last_name"]

    def _notify_account_state(self, user) -> None:
        """Step 13 (US56): security email, ALWAYS sent (suspend/reactivate)."""
        template = "account_reactivated" if user.is_active else "account_suspended"
        send_templated_email(
            user.email,
            template,
            {"first_name": user.first_name or user.email},
            user_id=user.pk,
        )

    # La modification et son entrée d'audit réussissent ou échouent ensemble.
    @transaction.atomic
    def perform_update(self, serializer):
        old_role = serializer.instance.role
        old_active = serializer.instance.is_active
        user = serializer.save()

        # BR-06 : Admin ne peut pas retirer son propre rôle admin
        if user == self.request.user and old_role == "admin" and user.role != "admin":
            raise ValidationError("Un administrateur ne peut pas retirer son propre rôle d'administrateur.")

        # BR-06 : Admin ne peut pas se désactiver lui-même
        if user == self.request.user and old_active and not user.is_active:
            raise ValidationError("Un administrateur ne peut pas désactiver son propre compte.")

        if user.role != old_role:
            record(AuditLog.Action.ROLE_CHANGE, request=self.request, target=user,
                   metadata={"old": old_role, "new": user.role})
        if user.is_active != old_active:
            action = (AuditLog.Action.USER_REACTIVATE if user.is_active
                      else AuditLog.Action.USER_SUSPEND)
            record(action, request=self.request, target=user)
            self._notify_account_state(user)

    @transaction.atomic
    def perform_destroy(self, instance):
        if instance.is_active:
            instance.is_active = False
            instance.save(update_fields=["is_active"])
            record(AuditLog.Action.USER_SUSPEND, request=self.request, target=instance)
            self._notify_account_state(instance)
