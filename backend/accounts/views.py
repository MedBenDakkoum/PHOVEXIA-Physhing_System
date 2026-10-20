from typing import ClassVar

from django.contrib.auth import get_user_model
from django.db import transaction
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, generics, mixins, status, viewsets
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from audit.models import AuditLog
from audit.services import record

from .permissions import IsEndUser, IsAdmin
from .serializers import (AdminUserSerializer, ChangePasswordSerializer,
                          LogoutSerializer, RegisterSerializer, UserSerializer)

User = get_user_model()


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    # Step 8d: THROTTLE_REGISTER per IP (rate in settings.DEFAULT_THROTTLE_RATES).
    throttle_classes: ClassVar[list] = [ScopedRateThrottle]
    throttle_scope = "register"

    def perform_create(self, serializer):
        user = serializer.save()
        record(AuditLog.Action.REGISTER, request=self.request, user=user, target=user)


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
    permission_classes = [IsEndUser]

    def get_object(self):
        return self.request.user


class ChangePasswordView(APIView):
    permission_classes = [IsEndUser]
    # Step 8d: THROTTLE_CHANGE_PASSWORD per USER (authenticated -> key = pk).
    throttle_classes: ClassVar[list] = [ScopedRateThrottle]
    throttle_scope = "change_password"

    def post(self, request):
        s = ChangePasswordSerializer(data=request.data, context={"request": request})
        s.is_valid(raise_exception=True)
        request.user.set_password(s.validated_data["new_password"])
        request.user.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class LogoutView(APIView):
    permission_classes = [IsEndUser]

    def post(self, request):
        s = LogoutSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        try:
            RefreshToken(s.validated_data["refresh"]).blacklist()
        except TokenError:
            return Response({"detail": "Token invalide ou expiré."},
                            status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserAdminViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin,
                       mixins.UpdateModelMixin, mixins.DestroyModelMixin,
                       viewsets.GenericViewSet):
    """Gestion des utilisateurs (admin uniquement). DELETE = suspension du compte."""
    queryset = User.objects.all().order_by("-date_joined")
    serializer_class = AdminUserSerializer
    permission_classes = [IsAdmin]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["role", "is_active"]
    search_fields = ["email", "first_name", "last_name"]

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

    @transaction.atomic
    def perform_destroy(self, instance):
        if instance.is_active:
            instance.is_active = False
            instance.save(update_fields=["is_active"])
            record(AuditLog.Action.USER_SUSPEND, request=self.request, target=instance)