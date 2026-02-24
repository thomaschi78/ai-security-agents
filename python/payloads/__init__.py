"""Payload loading and encoding utilities."""

from .payload_loader import (
    PayloadLoader,
    get_default_payloads,
    DEFAULT_SQLI_PAYLOADS,
    DEFAULT_XSS_PAYLOADS,
    DEFAULT_CMDI_PAYLOADS,
)
from .payload_encoder import (
    encode_payload,
    generate_encoded_variants,
    get_bypass_variants,
    ENCODERS,
    url_encode,
    double_url_encode,
    html_encode,
    unicode_encode,
    base64_encode,
)

__all__ = [
    "PayloadLoader",
    "get_default_payloads",
    "DEFAULT_SQLI_PAYLOADS",
    "DEFAULT_XSS_PAYLOADS",
    "DEFAULT_CMDI_PAYLOADS",
    "encode_payload",
    "generate_encoded_variants",
    "get_bypass_variants",
    "ENCODERS",
    "url_encode",
    "double_url_encode",
    "html_encode",
    "unicode_encode",
    "base64_encode",
]
