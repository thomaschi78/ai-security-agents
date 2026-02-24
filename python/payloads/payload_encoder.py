"""Payload encoding utilities for bypass techniques."""

import base64
import html
import urllib.parse
from typing import List, Callable


def url_encode(payload: str) -> str:
    """URL encode payload."""
    return urllib.parse.quote(payload, safe='')


def double_url_encode(payload: str) -> str:
    """Double URL encode payload."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')


def html_encode(payload: str) -> str:
    """HTML entity encode payload."""
    return html.escape(payload)


def html_encode_decimal(payload: str) -> str:
    """HTML decimal entity encode payload."""
    return ''.join(f'&#{ord(c)};' for c in payload)


def html_encode_hex(payload: str) -> str:
    """HTML hex entity encode payload."""
    return ''.join(f'&#x{ord(c):x};' for c in payload)


def unicode_encode(payload: str) -> str:
    """Unicode escape encode payload."""
    return ''.join(f'\\u{ord(c):04x}' for c in payload)


def hex_encode(payload: str) -> str:
    """Hex encode payload."""
    return ''.join(f'%{ord(c):02x}' for c in payload)


def base64_encode(payload: str) -> str:
    """Base64 encode payload."""
    return base64.b64encode(payload.encode()).decode()


def utf7_encode(payload: str) -> str:
    """UTF-7 encode payload (for some XSS bypasses)."""
    return payload.encode('utf-7').decode('ascii')


def mixed_case(payload: str) -> str:
    """Apply mixed case to payload."""
    result = []
    for i, c in enumerate(payload):
        if c.isalpha():
            result.append(c.upper() if i % 2 == 0 else c.lower())
        else:
            result.append(c)
    return ''.join(result)


def null_byte_inject(payload: str) -> str:
    """Add null byte to payload."""
    return payload + "%00"


def newline_inject(payload: str) -> str:
    """Add newline to payload."""
    return payload + "%0a"


def crlf_inject(payload: str) -> str:
    """Add CRLF to payload."""
    return payload + "%0d%0a"


def space_to_comment(payload: str) -> str:
    """Replace spaces with SQL comments."""
    return payload.replace(" ", "/**/")


def space_to_plus(payload: str) -> str:
    """Replace spaces with plus signs."""
    return payload.replace(" ", "+")


def space_to_tab(payload: str) -> str:
    """Replace spaces with tabs."""
    return payload.replace(" ", "\t")


# Encoder registry
ENCODERS = {
    "url": url_encode,
    "double_url": double_url_encode,
    "html": html_encode,
    "html_decimal": html_encode_decimal,
    "html_hex": html_encode_hex,
    "unicode": unicode_encode,
    "hex": hex_encode,
    "base64": base64_encode,
    "utf7": utf7_encode,
    "mixed_case": mixed_case,
    "null_byte": null_byte_inject,
    "newline": newline_inject,
    "crlf": crlf_inject,
    "space_comment": space_to_comment,
    "space_plus": space_to_plus,
    "space_tab": space_to_tab,
}


def encode_payload(payload: str, encodings: List[str]) -> str:
    """
    Apply multiple encodings to a payload.

    Args:
        payload: Original payload
        encodings: List of encoding names to apply in order

    Returns:
        Encoded payload
    """
    result = payload
    for encoding in encodings:
        if encoding in ENCODERS:
            result = ENCODERS[encoding](result)
    return result


def generate_encoded_variants(payload: str, encodings: List[str] = None) -> List[str]:
    """
    Generate multiple encoded variants of a payload.

    Args:
        payload: Original payload
        encodings: List of encodings to try (default: common bypass encodings)

    Returns:
        List of encoded variants
    """
    if encodings is None:
        encodings = ["url", "double_url", "html", "unicode", "mixed_case"]

    variants = [payload]  # Include original

    for encoding in encodings:
        if encoding in ENCODERS:
            encoded = ENCODERS[encoding](payload)
            if encoded not in variants:
                variants.append(encoded)

    return variants


def get_bypass_variants(payload: str, vuln_type: str) -> List[str]:
    """
    Get bypass variants specific to a vulnerability type.

    Args:
        payload: Original payload
        vuln_type: Vulnerability type

    Returns:
        List of bypass variants
    """
    variants = [payload]

    if vuln_type == "sqli":
        # SQL injection bypasses
        variants.extend([
            space_to_comment(payload),
            mixed_case(payload),
            payload.replace("'", "''"),
            payload.replace("OR", "||"),
        ])

    elif vuln_type == "xss":
        # XSS bypasses
        variants.extend([
            mixed_case(payload),
            html_encode(payload),
            unicode_encode(payload),
            payload.replace("<", "&lt;").replace(">", "&gt;"),
        ])

    elif vuln_type == "cmdi":
        # Command injection bypasses
        variants.extend([
            payload.replace(" ", "${IFS}"),
            payload.replace(" ", "\t"),
            payload + "%00",
        ])

    elif vuln_type in ("lfi", "path_traversal"):
        # Path traversal bypasses
        variants.extend([
            double_url_encode(payload),
            payload.replace("../", "....//"),
            payload.replace("../", "..%00/"),
        ])

    return list(set(variants))
