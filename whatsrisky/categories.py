"""Normalized finding categories.

`category` on a finding is whatever its scanner called it - `SAST/security`,
`Dependency/pip`, `AI/Injection`. Useless for grouping. This module derives a
closed vocabulary from the strongest signal available, in order:

1. CWE, when the finding carries one. This is the reliable signal and it is
   already in the data.
2. The scanner's own class - a Trivy vulnerability is a dependency finding
   whatever its CWE says, a gitleaks hit is a secret.
3. Keywords in the rule id, as a last resort.
4. `other` - and `other` staying large is a bug in this mapping, not a category.
"""

from __future__ import annotations

import re

# --- the vocabulary ---------------------------------------------------
SECRET = "secret"
INJECTION = "injection"
INJECTION_SQL = "injection.sql"
INJECTION_COMMAND = "injection.command"
INJECTION_CODE = "injection.code"
XSS = "xss"
PATH_TRAVERSAL = "path-traversal"
DESERIALIZATION = "deserialization"
SSRF = "ssrf"
XXE = "xxe"
ACCESS_CONTROL = "access-control"
AUTHENTICATION = "authentication"
CRYPTO = "crypto"
DEPENDENCY = "dependency"
MISCONFIGURATION = "misconfiguration"
SUPPLY_CHAIN = "supply-chain"
DOS = "dos"
INFO_DISCLOSURE = "info-disclosure"
INPUT_VALIDATION = "input-validation"
RACE = "race"
MEMORY = "memory"
LOGGING = "logging"
OTHER = "other"

LABELS = {
    SECRET: "Leaked secret",
    INJECTION: "Injection",
    INJECTION_SQL: "SQL injection",
    INJECTION_COMMAND: "Command injection",
    INJECTION_CODE: "Code injection",
    XSS: "Cross-site scripting",
    PATH_TRAVERSAL: "Path traversal",
    DESERIALIZATION: "Unsafe deserialization",
    SSRF: "Server-side request forgery",
    XXE: "XML external entities",
    ACCESS_CONTROL: "Broken access control",
    AUTHENTICATION: "Authentication",
    CRYPTO: "Cryptography",
    DEPENDENCY: "Vulnerable dependency",
    MISCONFIGURATION: "Misconfiguration",
    SUPPLY_CHAIN: "Supply chain",
    DOS: "Denial of service",
    INFO_DISCLOSURE: "Information disclosure",
    INPUT_VALIDATION: "Input validation",
    RACE: "Race condition",
    MEMORY: "Memory safety",
    LOGGING: "Logging",
    OTHER: "Other",
}

VOCABULARY = tuple(LABELS)

# --- CWE -> category --------------------------------------------------
_CWE_GROUPS: dict[str, tuple[int, ...]] = {
    SECRET: (256, 259, 260, 312, 315, 316, 321, 522, 798),
    INJECTION_SQL: (89, 564, 943),
    INJECTION_COMMAND: (77, 78, 88, 624),
    INJECTION_CODE: (94, 95, 96, 470, 917, 1336),
    INJECTION: (74, 75, 76, 91, 93, 1236),
    XSS: (79, 80, 83, 87),
    PATH_TRAVERSAL: (22, 23, 24, 36, 73, 98),
    DESERIALIZATION: (502, 915),
    SSRF: (918),
    XXE: (611, 776, 827),
    ACCESS_CONTROL: (284, 285, 306, 425, 552, 566, 639, 862, 863),
    AUTHENTICATION: (287, 288, 290, 294, 297, 303, 304, 307, 384, 521, 613, 620, 640),
    CRYPTO: (295, 296, 310, 311, 326, 327, 328, 329, 330, 331, 335, 338, 347, 759, 760, 780, 916, 1240),
    DEPENDENCY: (937, 1035, 1104),
    MISCONFIGURATION: (16, 276, 614, 693, 732, 942, 1004, 1021, 1275),
    SUPPLY_CHAIN: (494, 506, 829, 1357),
    DOS: (400, 405, 409, 674, 770, 834, 1333),
    INFO_DISCLOSURE: (200, 201, 209, 213, 215, 359, 497, 532, 538, 540, 548, 668),
    INPUT_VALIDATION: (20, 116, 129, 138, 172, 179, 1284),
    RACE: (362, 366, 367, 421),
    MEMORY: (119, 120, 121, 122, 125, 126, 131, 190, 191, 401, 415, 416, 476, 787, 788, 805),
    LOGGING: (117, 223, 778),
}

CWE_TO_CATEGORY: dict[int, str] = {}
for _category, _numbers in _CWE_GROUPS.items():
    for _number in (_numbers if isinstance(_numbers, tuple) else (_numbers,)):
        CWE_TO_CATEGORY[_number] = _category

# --- rule-id keywords, the last resort --------------------------------
_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("sql-injection", INJECTION_SQL),
    ("sqli", INJECTION_SQL),
    ("tainted-sql", INJECTION_SQL),
    ("command-injection", INJECTION_COMMAND),
    ("shell-injection", INJECTION_COMMAND),
    ("subprocess", INJECTION_COMMAND),
    ("os-system", INJECTION_COMMAND),
    ("eval", INJECTION_CODE),
    ("exec-use", INJECTION_CODE),
    ("code-injection", INJECTION_CODE),
    ("template-injection", INJECTION_CODE),
    ("xss", XSS),
    ("cross-site-scripting", XSS),
    ("autoescape", XSS),
    ("path-traversal", PATH_TRAVERSAL),
    ("zip-slip", PATH_TRAVERSAL),
    ("directory-traversal", PATH_TRAVERSAL),
    ("pickle", DESERIALIZATION),
    ("marshal", DESERIALIZATION),
    ("yaml-load", DESERIALIZATION),
    ("deserial", DESERIALIZATION),
    ("ssrf", SSRF),
    ("xxe", XXE),
    ("xml-external", XXE),
    ("csrf", ACCESS_CONTROL),
    ("authz", ACCESS_CONTROL),
    ("authorization", ACCESS_CONTROL),
    ("permission", MISCONFIGURATION),
    ("chmod", MISCONFIGURATION),
    ("auth", AUTHENTICATION),
    ("jwt", AUTHENTICATION),
    ("password", AUTHENTICATION),
    ("session", AUTHENTICATION),
    ("crypto", CRYPTO),
    ("cipher", CRYPTO),
    ("hash", CRYPTO),
    ("md5", CRYPTO),
    ("sha1", CRYPTO),
    ("tls", CRYPTO),
    ("ssl", CRYPTO),
    ("certificate", CRYPTO),
    ("random", CRYPTO),
    ("secret", SECRET),
    ("token", SECRET),
    ("api-key", SECRET),
    ("credential", SECRET),
    ("private-key", SECRET),
    ("debug", MISCONFIGURATION),
    ("cors", MISCONFIGURATION),
    ("header", MISCONFIGURATION),
    ("mutable-action", SUPPLY_CHAIN),
    ("unpinned", SUPPLY_CHAIN),
    ("curl-pipe", SUPPLY_CHAIN),
    ("dos", DOS),
    ("redos", DOS),
    ("logging", LOGGING),
    ("log-injection", LOGGING),
    ("traceback", INFO_DISCLOSURE),
    ("stacktrace", INFO_DISCLOSURE),
    ("verbose-error", INFO_DISCLOSURE),
)

# --- scanner class -> category ----------------------------------------
_NATIVE: tuple[tuple[str, str], ...] = (
    ("secret", SECRET),
    ("dependency", DEPENDENCY),
    ("misconfiguration", MISCONFIGURATION),
)

_CWE_NUMBER = re.compile(r"(\d+)")


def parse_cwe(values) -> list[int]:
    """Accept 'CWE-89', 'cwe89', 89 - scanners write all three."""
    numbers: list[int] = []
    for value in values or []:
        match = _CWE_NUMBER.search(str(value))
        if match:
            numbers.append(int(match.group(1)))
    return numbers


def classify(cwe=None, native_category: str = "", rule_id: str = "", title: str = "") -> str:
    """Best category for a finding, from the strongest signal available."""
    native = (native_category or "").lower()

    # A dependency CVE keeps its own category whatever its CWE says: the action is
    # "upgrade this package", not "review your crypto".
    for needle, category in _NATIVE:
        if native.startswith(needle):
            return category

    for number in parse_cwe(cwe):
        if number in CWE_TO_CATEGORY:
            return CWE_TO_CATEGORY[number]

    haystack = f"{rule_id} {title}".lower().replace("_", "-").replace(" ", "-")
    for needle, category in _KEYWORDS:
        if needle in haystack:
            return category

    if native.startswith("ai/") or native.startswith("sast"):
        return OTHER
    return OTHER


def label(category: str) -> str:
    return LABELS.get(category, LABELS[OTHER])
