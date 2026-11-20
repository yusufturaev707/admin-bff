"""Masking of personal data (section 9).

Masks:
    PINFL     31201234560045    -> 3120*****0045
    phone     +998 90 123 45 45 -> +998 90 *** ** 45
    passport  AB1234567         -> AB*****67

`scrub_text` finds these patterns inside arbitrary text and is used by the log
processor, so personal data never reaches the logs even if a message or an
exception text contains it.
"""

import re

PINFL_RE = re.compile(r"(?<!\d)(\d{4})\d{6}(\d{4})(?!\d)")
PHONE_RE = re.compile(
    r"(?<![\d+])\+?998[\s-]?\(?(\d{2})\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?(\d{2})(?!\d)"
)
PASSPORT_RE = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2})\d{5}(\d{2})(?!\d)")


def mask_pinfl(value: str) -> str:
    digits = value.strip()
    if len(digits) != 14 or not digits.isdigit():
        return "*" * 5
    return f"{digits[:4]}*****{digits[-4:]}"


def mask_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 9:
        digits = "998" + digits
    if len(digits) != 12 or not digits.startswith("998"):
        return "*" * 5
    return f"+998 {digits[3:5]} *** ** {digits[-2:]}"


def mask_passport(value: str) -> str:
    compact = value.strip().upper()
    if len(compact) != 9 or not compact[:2].isalpha() or not compact[2:].isdigit():
        return "*" * 5
    return f"{compact[:2]}*****{compact[-2:]}"


def scrub_text(text: str) -> str:
    """Masks every PINFL, phone number and passport number found in `text`."""
    text = PHONE_RE.sub(lambda m: f"+998 {m.group(1)} *** ** {m.group(2)}", text)
    text = PINFL_RE.sub(lambda m: f"{m.group(1)}*****{m.group(2)}", text)
    return PASSPORT_RE.sub(lambda m: f"{m.group(1)}*****{m.group(2)}", text)
