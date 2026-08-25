package model

import (
	"regexp"
	"strconv"
	"strings"
)

// The category vocabulary. A finding's own scanner calls it whatever it likes -
// "SAST/security", "Dependency/pip", "AI/Injection" - which is useless for
// grouping, so every finding is mapped onto this closed set.
const (
	CatSecret           = "secret"
	CatInjection        = "injection"
	CatInjectionSQL     = "injection.sql"
	CatInjectionCommand = "injection.command"
	CatInjectionCode    = "injection.code"
	CatXSS              = "xss"
	CatPathTraversal    = "path-traversal"
	CatDeserialization  = "deserialization"
	CatSSRF             = "ssrf"
	CatXXE              = "xxe"
	CatAccessControl    = "access-control"
	CatAuthentication   = "authentication"
	CatCrypto           = "crypto"
	CatDependency       = "dependency"
	CatMisconfiguration = "misconfiguration"
	CatSupplyChain      = "supply-chain"
	CatDoS              = "dos"
	CatInfoDisclosure   = "info-disclosure"
	CatInputValidation  = "input-validation"
	CatRace             = "race"
	CatMemory           = "memory"
	CatLogging          = "logging"
	CatOther            = "other"
)

// CategoryLabels is the display name for each entry; Vocabulary is the order the
// entries were defined in.
var (
	CategoryLabels = map[string]string{
		CatSecret: "Leaked secret", CatInjection: "Injection",
		CatInjectionSQL: "SQL injection", CatInjectionCommand: "Command injection",
		CatInjectionCode: "Code injection", CatXSS: "Cross-site scripting",
		CatPathTraversal: "Path traversal", CatDeserialization: "Unsafe deserialization",
		CatSSRF: "Server-side request forgery", CatXXE: "XML external entities",
		CatAccessControl: "Broken access control", CatAuthentication: "Authentication",
		CatCrypto: "Cryptography", CatDependency: "Vulnerable dependency",
		CatMisconfiguration: "Misconfiguration", CatSupplyChain: "Supply chain",
		CatDoS: "Denial of service", CatInfoDisclosure: "Information disclosure",
		CatInputValidation: "Input validation", CatRace: "Race condition",
		CatMemory: "Memory safety", CatLogging: "Logging", CatOther: "Other",
	}

	Vocabulary = []string{
		CatSecret, CatInjection, CatInjectionSQL, CatInjectionCommand, CatInjectionCode,
		CatXSS, CatPathTraversal, CatDeserialization, CatSSRF, CatXXE, CatAccessControl,
		CatAuthentication, CatCrypto, CatDependency, CatMisconfiguration, CatSupplyChain,
		CatDoS, CatInfoDisclosure, CatInputValidation, CatRace, CatMemory, CatLogging, CatOther,
	}
)

// cweGroups maps CWE numbers onto the vocabulary.
var cweGroups = map[string][]int{
	CatSecret:           {256, 259, 260, 312, 315, 316, 321, 522, 798},
	CatInjectionSQL:     {89, 564, 943},
	CatInjectionCommand: {77, 78, 88, 624},
	CatInjectionCode:    {94, 95, 96, 470, 917, 1336},
	CatInjection:        {74, 75, 76, 91, 93, 1236},
	CatXSS:              {79, 80, 83, 87},
	CatPathTraversal:    {22, 23, 24, 36, 73, 98},
	CatDeserialization:  {502, 915},
	CatSSRF:             {918},
	CatXXE:              {611, 776, 827},
	CatAccessControl:    {284, 285, 306, 425, 552, 566, 639, 862, 863},
	CatAuthentication:   {287, 288, 290, 294, 297, 303, 304, 307, 384, 521, 613, 620, 640},
	CatCrypto:           {295, 296, 310, 311, 326, 327, 328, 329, 330, 331, 335, 338, 347, 759, 760, 780, 916, 1240},
	CatDependency:       {937, 1035, 1104},
	CatMisconfiguration: {16, 276, 614, 693, 732, 942, 1004, 1021, 1275},
	CatSupplyChain:      {494, 506, 829, 1357},
	CatDoS:              {400, 405, 409, 674, 770, 834, 1333},
	CatInfoDisclosure:   {200, 201, 209, 213, 215, 359, 497, 532, 538, 540, 548, 668},
	CatInputValidation:  {20, 116, 129, 138, 172, 179, 1284},
	CatRace:             {362, 366, 367, 421},
	CatMemory:           {119, 120, 121, 122, 125, 126, 131, 190, 191, 401, 415, 416, 476, 787, 788, 805},
	CatLogging:          {117, 223, 778},
}

// CWEToCategory is the flattened lookup.
var CWEToCategory = func() map[int]string {
	out := make(map[int]string, 160)
	for category, numbers := range cweGroups {
		for _, number := range numbers {
			out[number] = category
		}
	}
	return out
}()

type token struct {
	needle   string
	category string
}

// strongTokens are rule-id fragments that can only mean one thing, and they
// outrank the CWE: scanner authors name rules after the vulnerability class,
// while CWE tagging is unreliable. Semgrep tags its own
// injection.tainted-sql-string rule with CWE-915, which would file a SQL
// injection under deserialization. Longest first so a shorter token cannot
// shadow a longer one.
var strongTokens = []token{
	{"sql-injection", CatInjectionSQL}, {"tainted-sql", CatInjectionSQL}, {"sqli", CatInjectionSQL},
	{"command-injection", CatInjectionCommand}, {"shell-injection", CatInjectionCommand},
	{"subprocess", CatInjectionCommand}, {"os-system", CatInjectionCommand},
	{"shell-true", CatInjectionCommand},
	{"code-injection", CatInjectionCode}, {"template-injection", CatInjectionCode},
	{"eval", CatInjectionCode}, {"exec-use", CatInjectionCode},
	{"cross-site-scripting", CatXSS}, {"xss", CatXSS}, {"autoescape", CatXSS},
	{"directory-traversal", CatPathTraversal}, {"path-traversal", CatPathTraversal},
	{"zip-slip", CatPathTraversal},
	{"deserial", CatDeserialization}, {"pickle", CatDeserialization},
	{"marshal", CatDeserialization}, {"yaml-load", CatDeserialization},
	{"ssrf", CatSSRF}, {"dynamic-urllib", CatSSRF}, {"urlopen", CatSSRF}, {"open-redirect", CatSSRF},
	{"xml-external", CatXXE}, {"xxe", CatXXE},
	{"hardcoded", CatSecret}, {"private-key", CatSecret}, {"api-key", CatSecret},
	{"credential", CatSecret}, {"secret", CatSecret}, {"-token", CatSecret}, {"token-", CatSecret},
	{"mutable-action", CatSupplyChain}, {"unpinned", CatSupplyChain},
	{"curl-pipe", CatSupplyChain}, {"pipe-shell", CatSupplyChain},
	{"csrf", CatAccessControl}, {"authz", CatAccessControl}, {"authorization", CatAccessControl},
	{"log-injection", CatLogging}, {"redos", CatDoS},
}

// weakTokens are fuzzy and must not outrank a CWE.
var weakTokens = []token{
	{"password", CatAuthentication}, {"session", CatAuthentication},
	{"jwt", CatAuthentication}, {"auth", CatAuthentication},
	{"certificate", CatCrypto}, {"cipher", CatCrypto}, {"crypto", CatCrypto},
	{"md5", CatCrypto}, {"sha1", CatCrypto}, {"random", CatCrypto},
	{"tls", CatCrypto}, {"ssl", CatCrypto}, {"hash", CatCrypto},
	{"permission", CatMisconfiguration}, {"chmod", CatMisconfiguration},
	{"debug", CatMisconfiguration}, {"cors", CatMisconfiguration}, {"header", CatMisconfiguration},
	{"traceback", CatInfoDisclosure}, {"stacktrace", CatInfoDisclosure},
	{"verbose-error", CatInfoDisclosure},
	{"logging", CatLogging}, {"dos", CatDoS},
}

// nativeClasses: a scanner's own class wins outright. A dependency CVE stays a
// dependency finding whatever its CWE says - the action is "upgrade this
// package", not "review your crypto".
var nativeClasses = []token{
	{"secret", CatSecret},
	{"dependency", CatDependency},
	{"misconfiguration", CatMisconfiguration},
}

// configSources: a finding in one of these artifacts is a misconfiguration when
// nothing more specific applies. That is what those files are.
var configSources = map[string]bool{SourceContainer: true, SourceIaC: true, SourceCI: true}

var cweNumber = regexp.MustCompile(`(\d+)`)

// ParseCWE accepts "CWE-89", "cwe89" and "89" - scanners write all three.
func ParseCWE(values []string) []int {
	var out []int
	for _, value := range values {
		if match := cweNumber.FindString(value); match != "" {
			if number, err := strconv.Atoi(match); err == nil {
				out = append(out, number)
			}
		}
	}
	return out
}

func normalizeTokens(parts ...string) string {
	joined := strings.ToLower(strings.Join(parts, "-"))
	for _, pair := range []string{"_", "-", " ", "-", ".", "-"} {
		_ = pair
	}
	joined = strings.NewReplacer("_", "-", " ", "-", ".", "-").Replace(joined)
	return "-" + joined + "-"
}

// Classify picks the best category from the strongest signal available:
// the scanner's own class, then an unambiguous rule-id token, then the artifact,
// then CWE, then a fuzzy keyword. `other` staying large is a bug in this mapping,
// not a category.
func Classify(cwe []string, nativeCategory, ruleID, title, source string) string {
	native := strings.ToLower(nativeCategory)
	for _, entry := range nativeClasses {
		if strings.HasPrefix(native, entry.needle) {
			return entry.category
		}
	}

	ruleText := normalizeTokens(ruleID)
	for _, entry := range strongTokens {
		if strings.Contains(ruleText, entry.needle) {
			return entry.category
		}
	}
	titleText := normalizeTokens(title)
	for _, entry := range strongTokens {
		if strings.Contains(titleText, entry.needle) {
			return entry.category
		}
	}

	if configSources[source] {
		return CatMisconfiguration
	}

	for _, number := range ParseCWE(cwe) {
		if category, ok := CWEToCategory[number]; ok {
			return category
		}
	}

	for _, entry := range weakTokens {
		if strings.Contains(ruleText, entry.needle) || strings.Contains(titleText, entry.needle) {
			return entry.category
		}
	}
	return CatOther
}

// CategoryLabel is the display name, falling back to Other's.
func CategoryLabel(category string) string {
	if label, ok := CategoryLabels[category]; ok {
		return label
	}
	return CategoryLabels[CatOther]
}
