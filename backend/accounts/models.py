from typing import ClassVar

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra):
        if not email:
            raise ValueError("L'email est obligatoire")
        user = self.model(email=self.normalize_email(email).lower(), **extra)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra):
        extra.setdefault("is_staff", False)
        extra.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra)

    def create_superuser(self, email, password=None, **extra):
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        extra.setdefault("role", "admin")
        return self._create_user(email, password, **extra)


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = "admin", "Administrateur"
        ANALYST = "analyst", "Analyste"
        END_USER = "end_user", "Utilisateur"

    username = None
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.END_USER)
    # Step 13 (US6/US57): opt-out of NON-security notification emails
    # (report decisions). Security emails (reset, password changed,
    # suspension) are always sent, whatever this flag says.
    email_notifications = models.BooleanField(default=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list] = []

    objects = UserManager()

    def __str__(self):
        return self.email
