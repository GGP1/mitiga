package llm

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/GGP1/mitiga/pkg/protocol"
)

// sensitiveRule pairs a compiled regex with the token category to produce and
// the submatch index that holds the sensitive value.  valueGroup=0 means the
// whole match is sensitive; valueGroup>0 means only that capture group is (used
// for key=value patterns where we want to keep the key name visible).
type sensitiveRule struct {
	re         *regexp.Regexp
	category   string
	valueGroup int
}

// defaultRules is the ordered list of patterns applied by every new Sanitizer.
// Order matters: more specific patterns (AWS keys) should come before broad
// credential patterns to avoid double-tokenization.
var defaultRules = []*sensitiveRule{
	// AWS access key IDs (AKIA… / ASIA… / AROA… prefixes).
	{
		re:         regexp.MustCompile(`\b(?:AKIA|ASIA|AROA|AIDA|APKA)[0-9A-Z]{16}\b`),
		category:   "AWS_KEY",
		valueGroup: 0,
	},
	// SSH / PGP / generic private key PEM blocks.
	{
		re:         regexp.MustCompile(`(?s)-----BEGIN\s+(?:[A-Z ]+\s+)?PRIVATE KEY-----.*?-----END\s+(?:[A-Z ]+\s+)?PRIVATE KEY-----`),
		category:   "PRIVKEY",
		valueGroup: 0,
	},
	// GCP service-account JSON field.
	{
		re:         regexp.MustCompile(`"private_key"\s*:\s*"(-----BEGIN[^"]+)"`),
		category:   "PRIVKEY",
		valueGroup: 1,
	},
	// Generic key=value / key: value credential patterns.
	// Group 1 = key name (kept visible), Group 2 = value (tokenized).
	{
		re: regexp.MustCompile(
			`(?i)\b(password|passwd|secret|token|api[_-]?key|apikey|` +
				`credential|auth[_-]?token|access[_-]?key|client[_-]?secret|` +
				`db[_-]?pass|db[_-]?password)\s*[=:]\s*(\S+)`),
		category:   "CRED",
		valueGroup: 2,
	},
	// IPv4 addresses.  Placed after credential patterns so that an IP that
	// appears in a URL inside a credential value is already tokenized.
	{
		re: regexp.MustCompile(
			`\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)` +
				`\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)` +
				`\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)` +
				`\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b`),
		category:   "IP",
		valueGroup: 0,
	},
	// IPv6 addresses — full form and common compressed forms.
	{
		re:         regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`),
		category:   "IPV6",
		valueGroup: 0,
	},
	// IPv6 compressed (e.g. fe80::1, ::1, 2001:db8::1).
	{
		re:         regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{0,4}\b`),
		category:   "IPV6",
		valueGroup: 0,
	},
	// Email addresses.
	{
		re:         regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
		category:   "EMAIL",
		valueGroup: 0,
	},
	// Usernames appearing in /etc/passwd-style lines.
	// Group 1 = username (tokenized); the colon-delimited suffix is kept.
	{
		re:         regexp.MustCompile(`(?m)^([a-zA-Z_][a-zA-Z0-9_.\-]{0,31})(:[^:]*:\d+:\d+:)`),
		category:   "USER",
		valueGroup: 1,
	},
}

// Sanitizer replaces sensitive values in raw text with stable opaque tokens.
//
// A fresh Sanitizer is created per LLM request.  All substitutions are
// consistent within a single request: the same sensitive value always maps to
// the same token, so the LLM can reason about relationships (e.g. "<IP_1>
// appears in two rules") without seeing the real data.
//
// Tokens are PERMANENT in findings that pass through the LLM pipeline — they
// are not restored automatically because those findings continue to the
// advisory LLM.  Call RestoreFindings / RestoreInsights only when producing
// a final human-readable report for an operator, never earlier.
type Sanitizer struct {
	mu       sync.Mutex
	forward  map[string]string // original value → token
	reverse  map[string]string // token → original value
	counters map[string]int    // category → next index
	rules    []*sensitiveRule
}

// NewSanitizer creates a Sanitizer loaded with the default sensitive-pattern
// rules.  It is inexpensive to create and should be instantiated per request.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{
		forward:  make(map[string]string),
		reverse:  make(map[string]string),
		counters: make(map[string]int),
		rules:    defaultRules,
	}
}

// Sanitize processes input through all sensitive-data rules and returns a
// copy with sensitive values replaced by tokens.  Repeated calls on the same
// Sanitizer accumulate all seen values so tokens are consistent across
// multiple pieces of related text (e.g. raw output split into chunks).
func (s *Sanitizer) Sanitize(input string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, rule := range s.rules {
		input = s.applyRule(input, rule)
	}
	return input
}

// Restore replaces all tokens in text with their original values.
func (s *Sanitizer) Restore(text string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, original := range s.reverse {
		text = strings.ReplaceAll(text, token, original)
	}
	return text
}

// RestoreFindings re-hydrates tokens in every text field of each finding.
// Call this after mapLLMFindings so reports contain real values.
func (s *Sanitizer) RestoreFindings(findings []protocol.Finding) []protocol.Finding {
	restored := make([]protocol.Finding, len(findings))
	for i, f := range findings {
		f.Description = s.Restore(f.Description)
		f.Impact = s.Restore(f.Impact)
		f.Recommendation = s.Restore(f.Recommendation)
		for j, ev := range f.Evidence {
			f.Evidence[j] = s.Restore(ev)
		}
		restored[i] = f
	}
	return restored
}

// RestoreInsights re-hydrates tokens in every insight string.
func (s *Sanitizer) RestoreInsights(insights []string) []string {
	restored := make([]string, len(insights))
	for i, ins := range insights {
		restored[i] = s.Restore(ins)
	}
	return restored
}

// HasSubstitutions returns true if any sensitive values were found and
// tokenized during Sanitize calls.  Useful for conditional logging.
func (s *Sanitizer) HasSubstitutions() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.forward) > 0
}

// SubstitutionCount returns the total number of unique sensitive values
// tokenized so far.  Intended for metrics / debug logging (never log the
// values themselves).
func (s *Sanitizer) SubstitutionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.forward)
}

// applyRule applies a single sensitive rule to input.  Must be called with
// s.mu held.
func (s *Sanitizer) applyRule(input string, rule *sensitiveRule) string {
	if rule.valueGroup == 0 {
		// The whole match is sensitive — simple ReplaceAllStringFunc.
		return rule.re.ReplaceAllStringFunc(input, func(match string) string {
			return s.tokenFor(rule.category, match)
		})
	}

	// Only the captured group at valueGroup is sensitive (key=value style).
	// We rebuild the string, replacing only the bytes of that group.
	var sb strings.Builder
	last := 0
	for _, locs := range rule.re.FindAllStringSubmatchIndex(input, -1) {
		// locs[2*n], locs[2*n+1] are the byte range of group n.
		start := locs[2*rule.valueGroup]
		end := locs[2*rule.valueGroup+1]
		if start < 0 {
			// Group didn't participate (optional group).
			continue
		}
		value := input[start:end]
		token := s.tokenFor(rule.category, value)

		sb.WriteString(input[last:start])
		sb.WriteString(token)
		last = end
	}
	sb.WriteString(input[last:])
	return sb.String()
}

// tokenFor returns the stable token for value under category, creating a new
// one if this value hasn't been seen before.  Must be called with s.mu held.
func (s *Sanitizer) tokenFor(category, value string) string {
	if tok, ok := s.forward[value]; ok {
		return tok
	}
	s.counters[category]++
	tok := fmt.Sprintf("<%s_%d>", category, s.counters[category])
	s.forward[value] = tok
	s.reverse[tok] = value
	return tok
}

// ── Prompt injection defense ─────────────────────────────────────────────────

// injectionSignature describes a known prompt-injection pattern.
// label is used in log messages only — it is never surfaced in LLM output.
type injectionSignature struct {
	re    *regexp.Regexp
	label string
}

// injectionSignatures is the ordered list of prompt injection patterns.
// These are matched case-insensitively against raw tool output BEFORE it is
// sent to any LLM.  A match does NOT block analysis — it is logged as HIGH and
// the matching text is redacted so the LLM never sees it.
var injectionSignatures = []*injectionSignature{
	// Classic instruction-override phrases.
	{re: regexp.MustCompile(`(?i)\bignore\s+(previous|all|the\s+above|prior|your)\s+(instructions?|prompt|rules?|directions?)\b`), label: "ignore-instructions"},
	{re: regexp.MustCompile(`(?i)\bdisregard\s+(all|the|previous|prior)?\s*(instructions?|prompt|rules?|above)\b`), label: "disregard-instructions"},
	{re: regexp.MustCompile(`(?i)\bforget\s+(everything|all|your|the)\s*(instructions?|above|previous|training)?\b`), label: "forget-instructions"},
	// Role-switching / persona hijacking.
	{re: regexp.MustCompile(`(?i)\byou\s+are\s+now\b`), label: "you-are-now"},
	{re: regexp.MustCompile(`(?i)\bnew\s+(persona|role|identity|system\s+prompt)\b`), label: "new-persona"},
	{re: regexp.MustCompile(`(?i)\bpretend\s+to\s+be\b`), label: "pretend-to-be"},
	{re: regexp.MustCompile(`(?i)\bact\s+as\s+(if\s+you\s+(are|were)|a\b)`), label: "act-as"},
	{re: regexp.MustCompile(`(?i)\byour\s+(new\s+)?(role|purpose|goal|task|mission)\s+is\b`), label: "role-override"},
	// Jailbreak keywords.
	{re: regexp.MustCompile(`(?i)\b(jailbreak|DAN\b|do\s+anything\s+now)\b`), label: "jailbreak"},
	// Delimiter injection — trying to close or open system/user/assistant tags.
	{re: regexp.MustCompile(`(?i)<\/?\s*(system|user|assistant|prompt|instruction)[^>]*>`), label: "tag-injection"},
	// "From now on" instruction override.
	{re: regexp.MustCompile(`(?i)\bfrom\s+now\s+on\s+(you|your|always|never|do|don'?t)\b`), label: "from-now-on"},
	// Explicit override / bypass keywords.
	{re: regexp.MustCompile(`(?i)\b(override|bypass|circumvent|disable)\s+(the\s+)?(system\s+)?(prompt|instructions?|rules?|filters?|restrictions?)\b`), label: "override-instructions"},
	// "New instructions" insertion.
	{re: regexp.MustCompile(`(?i)\b(new|updated?|revised?)\s+instructions?\s*:`), label: "new-instructions"},
}

// invisibleCharRe matches zero-width, soft-hyphen, and other invisible Unicode
// code points commonly used to obfuscate injection attempts.
var invisibleCharRe = regexp.MustCompile(
	`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F` + // C0 controls except tab/LF/CR
		`\x{00AD}` + // soft hyphen
		`\x{200B}-\x{200F}` + // zero-width space / joiners / direction marks
		`\x{2028}\x{2029}` + // line/paragraph separator
		`\x{202A}-\x{202E}` + // bi-directional overrides
		`\x{2060}-\x{2064}` + // word joiner, invisible operators
		`\x{FEFF}` + // BOM / zero-width no-break space
		`\x{FFF9}-\x{FFFB}` + // interlinear annotation anchors
		`]`,
)

// ansiEscapeRe matches ANSI terminal escape sequences that could confuse
// token boundaries or hide content from human reviewers.
var ansiEscapeRe = regexp.MustCompile(`\x1B\[[0-9;]*[A-Za-z]|\x1B[()][A-B0-2]`)

// InjectionMatch records one detected injection pattern in the input.
type InjectionMatch struct {
	Label   string
	Excerpt string // up to 80 chars around the match, for logging only
}

// DefendPromptInjection sanitizes raw tool output against prompt injection
// attacks before the text is included in any LLM prompt.  It:
//
//  1. Strips invisible/control Unicode characters — a common obfuscation vector.
//  2. Strips ANSI escape sequences.
//  3. Scans for known injection phrases and redacts each match with the literal
//     text "[REDACTED:injection]", preserving surrounding context so analysis
//     can still proceed.
//
// It returns the cleaned text and a slice of matches (non-nil and non-empty
// when injection was detected).  Callers MUST log every match at HIGH severity
// before passing the cleaned text to an LLM.
//
// This function does NOT block analysis.  Even a compromised input produces
// scrubbed text that the LLM can reason about.  The caller's logging creates the
// audit trail required for forensic review.
func DefendPromptInjection(input string) (cleaned string, matches []InjectionMatch) {
	// 1. Strip invisible characters.
	cleaned = invisibleCharRe.ReplaceAllString(input, "")

	// 2. Strip ANSI escapes.
	cleaned = ansiEscapeRe.ReplaceAllString(cleaned, "")

	// 3. Normalize non-printable characters that survived step 1 (paranoia pass).
	cleaned = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return r // keep whitespace that appears in normal tool output
		}
		if !unicode.IsPrint(r) {
			return -1 // drop
		}
		return r
	}, cleaned)

	// 4. Detect and redact injection patterns.
	for _, sig := range injectionSignatures {
		var found bool
		cleaned = sig.re.ReplaceAllStringFunc(cleaned, func(match string) string {
			found = true
			excerpt := match
			if len(excerpt) > 80 {
				excerpt = excerpt[:80] + "…"
			}
			matches = append(matches, InjectionMatch{Label: sig.label, Excerpt: excerpt})
			return "[REDACTED:injection]"
		})
		_ = found
	}

	return cleaned, matches
}

// WrapDataSection wraps sanitized tool output in explicit XML-like boundaries.
// The LLM's system prompt instructs it to treat everything inside <data> tags
// as untrusted raw output that can never override instructions.
func WrapDataSection(sanitizedOutput string) string {
	return "<data>\n" + sanitizedOutput + "\n</data>"
}
