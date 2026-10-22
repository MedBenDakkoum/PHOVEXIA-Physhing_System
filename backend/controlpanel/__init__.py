"""Admin control panel app (US45, US48, US49, US52, US53, US54 / BR-11).

Models:
- DetectionSettings: singleton thresholds + quotas (US52).
- ModelVersion: model registry, ONE active at a time (BR-11, US48/US49).
- ApiKey: hashed API keys for machine clients (US54).
"""
