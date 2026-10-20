from django.apps import AppConfig


class ReviewsConfig(AppConfig):
    """Human review workflow (US31, US33-US36, US57)."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "reviews"
    verbose_name = "Human review"
