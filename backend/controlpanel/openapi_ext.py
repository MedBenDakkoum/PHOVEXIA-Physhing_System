"""drf-spectacular extension for the Api-Key scheme (US54).

Imported by `controlpanel.apps` at startup so the extension is registered
before schema generation: without it every operation emits
"could not resolve authenticator ... ApiKeyAuthentication" (Warnings must
stay at 0).
"""
from drf_spectacular.extensions import OpenApiAuthenticationExtension


class ApiKeyAuthenticationExtension(OpenApiAuthenticationExtension):
    """Document `Authorization: Api-Key <secret>` in the OpenAPI schema."""

    target_class = "controlpanel.authentication.ApiKeyAuthentication"
    name = "ApiKeyAuth"
    priority = -1  # JWT stays the first/primary scheme

    def get_security_definition(self, auto_schema):
        return {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": (
                "Clé API : en-tête `Authorization` avec le préfixe `Api-Key `, "
                "puis le secret. Accepté uniquement sur `POST /api/scans/` et "
                "`GET /api/scans/{public_id}/` (le secret n'est montré qu'une "
                "fois, à la création)."
            ),
        }
