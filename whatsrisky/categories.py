"""Normalized finding categories.

`category` on a finding is whatever its scanner called it - `SAST/security`,
`Dependency/pip`, `AI/Injection`. Useless for grouping. This module derives a
closed vocabulary from the strongest signal available, in order:

1. The scanner's own class - a Trivy vulnerability is a dependency finding
   whatever its CWE says, and a gitleaks hit is a secret.
2. Unambiguous tokens in the rule id. Scanner authors name rules after the
   vulnerability class (`...injection.tainted-sql-string`), and that name is a
   *stronger* signal than the CWE: semgrep tags that very rule with CWE-915
   (object-attribute modification), which would file a SQL injection under
   deserialization. Only tokens that can mean one thing belong here.
3. The artifact: a finding in a Dockerfile, a Terraform file or a CI workflow is
   a misconfiguration unless step 2 already said otherwise.
4. CWE.
5. Fuzzy keywords - `auth`, `hash`, `header` - which are too weak to outrank a CWE.
6. `other` - and `other` staying large is a bug in this mapping, not a category.
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
    # 269 is privilege management: as a Dockerfile finding it is a
    # misconfiguration, which the artifact rule above already decides.
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

# --- rule-id tokens that can only mean one thing ----------------------
# These outrank the CWE. Longest first, so `sql-injection` is not shadowed by a
# shorter token that happens to be a substring of it.
_STRONG: tuple[tuple[str, str], ...] = (
    ("sql-injection", INJECTION_SQL),
    ("tainted-sql", INJECTION_SQL),
    ("sqli", INJECTION_SQL),
    ("command-injection", INJECTION_COMMAND),
    ("shell-injection", INJECTION_COMMAND),
    ("subprocess", INJECTION_COMMAND),
    ("os-system", INJECTION_COMMAND),
    ("shell-true", INJECTION_COMMAND),
    ("code-injection", INJECTION_CODE),
    ("template-injection", INJECTION_CODE),
    ("eval", INJECTION_CODE),
    ("exec-use", INJECTION_CODE),
    ("cross-site-scripting", XSS),
    ("xss", XSS),
    ("autoescape", XSS),
    ("directory-traversal", PATH_TRAVERSAL),
    ("path-traversal", PATH_TRAVERSAL),
    ("zip-slip", PATH_TRAVERSAL),
    ("deserial", DESERIALIZATION),
    ("pickle", DESERIALIZATION),
    ("marshal", DESERIALIZATION),
    ("yaml-load", DESERIALIZATION),
    ("ssrf", SSRF),
    ("xml-external", XXE),
    ("xxe", XXE),
    ("hardcoded", SECRET),
    ("private-key", SECRET),
    ("api-key", SECRET),
    ("credential", SECRET),
    ("secret", SECRET),
    ("-token", SECRET),
    ("token-", SECRET),
    ("mutable-action", SUPPLY_CHAIN),
    ("unpinned", SUPPLY_CHAIN),
    ("curl-pipe", SUPPLY_CHAIN),
    ("pipe-shell", SUPPLY_CHAIN),
    ("csrf", ACCESS_CONTROL),
    ("authz", ACCESS_CONTROL),
    ("authorization", ACCESS_CONTROL),
    ("log-injection", LOGGING),
    ("redos", DOS),
)

# --- fuzzy keywords, too weak to outrank a CWE ------------------------
_WEAK: tuple[tuple[str, str], ...] = (
    ("password", AUTHENTICATION),
    ("session", AUTHENTICATION),
    ("jwt", AUTHENTICATION),
    ("auth", AUTHENTICATION),
    ("certificate", CRYPTO),
    ("cipher", CRYPTO),
    ("crypto", CRYPTO),
    ("md5", CRYPTO),
    ("sha1", CRYPTO),
    ("random", CRYPTO),
    ("tls", CRYPTO),
    ("ssl", CRYPTO),
    ("hash", CRYPTO),
    ("permission", MISCONFIGURATION),
    ("chmod", MISCONFIGURATION),
    ("debug", MISCONFIGURATION),
    ("cors", MISCONFIGURATION),
    ("header", MISCONFIGURATION),
    ("traceback", INFO_DISCLOSURE),
    ("stacktrace", INFO_DISCLOSURE),
    ("verbose-error", INFO_DISCLOSURE),
    ("logging", LOGGING),
    ("dos", DOS),
)

# A finding in one of these artifacts is a misconfiguration when nothing more
# specific applies - that is what those files are.
_CONFIG_SOURCES = frozenset({"container", "iac", "ci-config"})

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


def _normalize(*parts: str) -> str:
    return "-" + "-".join(str(p or "").lower().replace("_", "-").replace(" ", "-").replace(".", "-") for p in parts) + "-"


def classify(
    cwe=None,
    native_category: str = "",
    rule_id: str = "",
    title: str = "",
    source: str = "",
) -> str:
    """Best category for a finding, from the strongest signal available."""
    native = (native_category or "").lower()

    # A dependency CVE keeps its own category whatever its CWE says: the action is
    # "upgrade this package", not "review your crypto".
    for needle, category in _NATIVE:
        if native.startswith(needle):
            return category

    rule_text = _normalize(rule_id)
    for needle, category in _STRONG:
        if needle in rule_text:
            return category

    title_text = _normalize(title)
    for needle, category in _STRONG:
        if needle in title_text:
            return category

    if source in _CONFIG_SOURCES:
        return MISCONFIGURATION

    for number in parse_cwe(cwe):
        if number in CWE_TO_CATEGORY:
            return CWE_TO_CATEGORY[number]

    for needle, category in _WEAK:
        if needle in rule_text or needle in title_text:
            return category

    return OTHER


def label(category: str) -> str:
    return LABELS.get(category, LABELS[OTHER])
