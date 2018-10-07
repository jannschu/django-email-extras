from django.conf import settings

GNUPG_HOME = getattr(settings, "EMAIL_EXTRAS_GNUPG_HOME", None)
ALWAYS_TRUST = getattr(settings, "EMAIL_EXTRAS_ALWAYS_TRUST_KEYS", False)
SIGN = getattr(settings, "EMAIL_EXTRAS_SIGN", False)
