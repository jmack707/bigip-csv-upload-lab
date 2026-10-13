"""Validator configuration. Every limit is explicit and comes from the environment."""
import os


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def _float(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


class Settings:
    # Sizes (bytes). 1 MiB file inside a 1.25 MiB request.
    MAX_FILE_BYTES = _int("MAX_FILE_BYTES", 1_048_576)
    MAX_REQUEST_BYTES = _int("MAX_REQUEST_BYTES", 1_310_720)

    # Multipart
    FILE_FIELD = os.environ.get("FILE_FIELD", "file")
    ALLOWED_CONTENT_TYPES = tuple(
        x.strip().lower()
        for x in os.environ.get(
            "ALLOWED_CONTENT_TYPES", "text/csv,application/csv,application/vnd.ms-excel"
        ).split(",")
        if x.strip()
    )
    # Compatibility mode (documented, off by default): also accept a part with
    # no Content-Type or application/octet-stream, because some browsers send that.
    CONTENT_TYPE_COMPAT = _bool("CONTENT_TYPE_COMPAT", False)

    # CSV grammar
    DELIMITERS = os.environ.get("DELIMITERS", ",;\t")
    IGNORE_TRAILING_BLANK_LINES = _bool("IGNORE_TRAILING_BLANK_LINES", False)
    MIN_COLUMNS = _int("MIN_COLUMNS", 2)
    MIN_RECORDS = _int("MIN_RECORDS", 2)  # header + at least one data record

    # Formula policy
    ALLOW_SIGNED_NUMBERS = _bool("ALLOW_SIGNED_NUMBERS", True)

    # ICAP listener for BIG-IP request-adapt
    ICAP_ENABLED = _bool("ICAP_ENABLED", True)
    ICAP_PORT = _int("ICAP_PORT", 1344)
    ICAP_READ_TIMEOUT = _float("ICAP_READ_TIMEOUT", 20.0)
    UPLOAD_PATH = os.environ.get("UPLOAD_PATH", "/upload")

    # Shared secret for the approval signature the upload application verifies.
    VALIDATION_SECRET = os.environ.get("VALIDATION_SECRET", "")

    UPLOAD_ID_PREFIX = os.environ.get("UPLOAD_ID_PREFIX", "lab-")


settings = Settings()
