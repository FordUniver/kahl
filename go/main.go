// kahl: Filter stdin for secrets, redact with labels
// Build: go build -ldflags="-s -w" -o kahl kahl.go patterns_gen.go
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	gomath "math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Read version from VERSION file at startup
var version = func() string {
	exePath, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	exeDir := filepath.Dir(exePath)
	versionPath := filepath.Join(exeDir, "..", "VERSION")
	data, err := os.ReadFile(versionPath)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}()

// Filter configuration
type FilterConfig struct {
	ValuesEnabled   bool
	PatternsEnabled bool
	EntropyEnabled  bool
}

const (
	StateNormal = iota
	StateInPrivateKey
	StateInPrivateKeyOverflow
)

// classifySegment returns N for digits, A for letters, X for mixed
func classifySegment(s string) string {
	if s == "" {
		return ""
	}
	allDigits := true
	allLetters := true
	for _, r := range s {
		if !unicode.IsDigit(r) {
			allDigits = false
		}
		if !unicode.IsLetter(r) {
			allLetters = false
		}
	}
	lenStr := strconv.Itoa(len(s))
	if allDigits {
		return lenStr + "N"
	}
	if allLetters {
		return lenStr + "A"
	}
	return lenStr + "X"
}

// describeStructure returns a description of the token structure
func describeStructure(s string) string {
	if s == "" {
		return ""
	}

	// Very long tokens
	if len(s) >= LongThreshold {
		for _, sep := range []string{"-", "_", "."} {
			if strings.Contains(s, sep) {
				parts := strings.Split(s, sep)
				first := parts[0]
				isAlpha := true
				for _, r := range first {
					if !unicode.IsLetter(r) {
						isAlpha = false
						break
					}
				}
				knownPrefixes := map[string]bool{"ghp": true, "gho": true, "ghs": true, "ghr": true, "npm": true, "sk": true}
				if isAlpha || knownPrefixes[first] {
					return first + sep + "...:" + strconv.Itoa(len(s)) + "chars"
				}
			}
		}
		return strconv.Itoa(len(s)) + "chars"
	}

	// Check for structured tokens
	for _, sep := range []string{"-", ".", "_"} {
		if strings.Contains(s, sep) {
			parts := strings.Split(s, sep)
			if len(parts) >= 2 {
				first := parts[0]
				isAlpha := true
				for _, r := range first {
					if !unicode.IsLetter(r) {
						isAlpha = false
						break
					}
				}
				if isAlpha && len(first) <= 12 {
					segments := make([]string, len(parts)-1)
					for i, p := range parts[1:] {
						segments[i] = classifySegment(p)
					}
					return first + sep + strings.Join(segments, sep)
				}
				segments := make([]string, len(parts))
				for i, p := range parts {
					segments[i] = classifySegment(p)
				}
				return strings.Join(segments, sep)
			}
		}
	}

	return classifySegment(s)
}

// loadSecrets loads secret values from environment variables
func loadSecrets() map[string]string {
	secrets := make(map[string]string)

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name, value := parts[0], parts[1]

		// Skip empty values and values shorter than 8 characters
		if len(value) < 8 {
			continue
		}

		// Check explicit names (from patterns_gen.go)
		if explicitEnvVars[name] {
			secrets[name] = value
			continue
		}

		// Check suffix patterns (from patterns_gen.go)
		for _, suffix := range envSuffixes {
			if strings.HasSuffix(name, suffix) {
				secrets[name] = value
				break
			}
		}
	}

	return secrets
}

// isFalsy checks if a string represents a falsy boolean value
func isFalsy(val string) bool {
	lower := strings.ToLower(strings.TrimSpace(val))
	return lower == "0" || lower == "false" || lower == "no"
}

// isTruthy checks if a string represents a truthy boolean value
func isTruthy(val string) bool {
	lower := strings.ToLower(strings.TrimSpace(val))
	return lower == "1" || lower == "true" || lower == "yes"
}

// parseFilterConfig parses filter configuration from CLI args and environment
func parseFilterConfig() FilterConfig {
	config := FilterConfig{
		ValuesEnabled:   true,
		PatternsEnabled: true,
		EntropyEnabled:  false, // Entropy is off by default
	}

	// Check for --version or -v
	args := os.Args[1:]
	for _, arg := range args {
		if arg == "--version" || arg == "-v" {
			fmt.Print(version)
			os.Exit(0)
		}
	}

	// Check for --filter or -f in args
	var filterArg string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--filter=") {
			filterArg = strings.TrimPrefix(arg, "--filter=")
			break
		} else if strings.HasPrefix(arg, "-f=") {
			filterArg = strings.TrimPrefix(arg, "-f=")
			break
		} else if (arg == "--filter" || arg == "-f") && i+1 < len(args) {
			filterArg = args[i+1]
			break
		}
	}

	if filterArg != "" {
		// CLI flag overrides environment entirely
		config.ValuesEnabled = false
		config.PatternsEnabled = false
		config.EntropyEnabled = false

		var validFound bool
		var invalidFilters []string

		parts := strings.Split(filterArg, ",")
		for _, part := range parts {
			filter := strings.ToLower(strings.TrimSpace(part))
			switch filter {
			case "values":
				config.ValuesEnabled = true
				validFound = true
			case "patterns":
				config.PatternsEnabled = true
				validFound = true
			case "entropy":
				config.EntropyEnabled = true
				validFound = true
			case "all":
				config.ValuesEnabled = true
				config.PatternsEnabled = true
				config.EntropyEnabled = true
				validFound = true
			default:
				if filter != "" {
					invalidFilters = append(invalidFilters, part)
				}
			}
		}

		// Warn about invalid filters
		for _, invalid := range invalidFilters {
			fmt.Fprintf(os.Stderr, "kahl: unknown filter '%s', ignoring\n", strings.TrimSpace(invalid))
		}

		// Error if no valid filters found
		if !validFound {
			fmt.Fprintln(os.Stderr, "kahl: no valid filters specified")
			os.Exit(1)
		}
	} else {
		// Check environment variables
		if val := os.Getenv("SECRETS_FILTER_VALUES"); val != "" && isFalsy(val) {
			config.ValuesEnabled = false
		}
		if val := os.Getenv("SECRETS_FILTER_PATTERNS"); val != "" && isFalsy(val) {
			config.PatternsEnabled = false
		}
		// Entropy: enabled by ENTROPY_ENABLED_DEFAULT or SECRETS_FILTER_ENTROPY=1
		if val := os.Getenv("SECRETS_FILTER_ENTROPY"); val != "" && isTruthy(val) {
			config.EntropyEnabled = true
		} else if EntropyEnabledDefault {
			config.EntropyEnabled = true
		}
	}

	return config
}

// redactEnvValues replaces known secret values with [REDACTED:VAR_NAME:structure]
func redactEnvValues(text string, secrets map[string]string) string {
	if secrets == nil {
		return text
	}

	// Sort by value length descending
	type kv struct {
		key string
		val string
	}
	var sorted []kv
	for k, v := range secrets {
		if v != "" {
			sorted = append(sorted, kv{k, v})
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i].val) > len(sorted[j].val)
	})

	for _, s := range sorted {
		structure := describeStructure(s.val)
		replacement := "[REDACTED:" + s.key + ":" + structure + "]"
		text = strings.ReplaceAll(text, s.val, replacement)
	}

	return text
}

// redactPatterns replaces known token patterns
func redactPatterns(text string) string {
	// Direct patterns
	for _, p := range patterns {
		text = p.Regex.ReplaceAllStringFunc(text, func(match string) string {
			structure := describeStructure(match)
			return "[REDACTED:" + p.Label + ":" + structure + "]"
		})
	}

	// Context patterns (simulate lookbehind)
	for _, cp := range contextPatterns {
		text = cp.Regex.ReplaceAllStringFunc(text, func(match string) string {
			submatches := cp.Regex.FindStringSubmatch(match)
			if len(submatches) > cp.Group {
				secret := submatches[cp.Group]
				structure := describeStructure(secret)
				return submatches[1] + "[REDACTED:" + cp.Label + ":" + structure + "]"
			}
			return match
		})
	}

	// Git credential URLs
	text = gitCredentialPattern.ReplaceAllStringFunc(text, func(match string) string {
		submatches := gitCredentialPattern.FindStringSubmatch(match)
		if len(submatches) >= 4 {
			structure := describeStructure(submatches[2])
			return submatches[1] + "[REDACTED:GIT_CREDENTIAL:" + structure + "]" + submatches[3]
		}
		return match
	})

	// Docker config auth
	text = dockerAuthPattern.ReplaceAllStringFunc(text, func(match string) string {
		submatches := dockerAuthPattern.FindStringSubmatch(match)
		if len(submatches) >= 4 {
			structure := describeStructure(submatches[2])
			return submatches[1] + "[REDACTED:DOCKER_AUTH:" + structure + "]" + submatches[3]
		}
		return match
	})

	return text
}

// ============================================================================
// Entropy-based detection
// ============================================================================

// EntropyConfig holds runtime entropy configuration (with env var overrides)
type EntropyConfig struct {
	Thresholds map[string]float64
	MinLength  int
	MaxLength  int
}

// Token represents a potential secret token with its position
type Token struct {
	Value string
	Start int
	End   int
}

// shannonEntropy calculates Shannon entropy of a string in bits
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * log2(p)
	}
	return entropy
}

// log2 returns log base 2 of x
func log2(x float64) float64 {
	return ln(x) / ln(2)
}

// ln returns natural logarithm of x
func ln(x float64) float64 {
	// Use Go's math package
	return gomath.Log(x)
}

// Hex character set (lowercase)
var hexChars = map[rune]bool{
	'0': true, '1': true, '2': true, '3': true, '4': true,
	'5': true, '6': true, '7': true, '8': true, '9': true,
	'a': true, 'b': true, 'c': true, 'd': true, 'e': true, 'f': true,
}

// Base64 character set
var base64Chars = map[rune]bool{}

// Alphanumeric character set (A-Za-z0-9_-)
var alnumChars = map[rune]bool{}

func init() {
	// Initialize base64 charset
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" {
		base64Chars[c] = true
	}
	// Initialize alphanumeric charset
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" {
		alnumChars[c] = true
	}
}

// classifyCharset determines the character set of a string
func classifyCharset(s string) string {
	lower := strings.ToLower(s)

	// Check hex first (most restrictive)
	isHex := true
	for _, r := range lower {
		if !hexChars[r] {
			isHex = false
			break
		}
	}
	if isHex {
		return "hex"
	}

	// Check alphanumeric
	isAlnum := true
	for _, r := range s {
		if !alnumChars[r] {
			isAlnum = false
			break
		}
	}
	if isAlnum {
		return "alphanumeric"
	}

	// Check base64
	isBase64 := true
	for _, r := range s {
		if !base64Chars[r] {
			isBase64 = false
			break
		}
	}
	if isBase64 {
		return "base64"
	}

	return "mixed"
}

// Token delimiter regex
var tokenDelimRe = regexp.MustCompile(`[\s"'` + "`" + `()\[\]{},:;<>=@#]+`)

// extractTokens splits text into potential secret tokens
func extractTokens(text string, minLen, maxLen int) []Token {
	var tokens []Token

	// Split by delimiters
	parts := tokenDelimRe.Split(text, -1)
	pos := 0

	for _, part := range parts {
		if part == "" {
			continue
		}

		// Find actual position in text
		start := strings.Index(text[pos:], part)
		if start == -1 {
			continue
		}
		start += pos
		end := start + len(part)
		pos = end

		// Filter by length
		if len(part) < minLen || len(part) > maxLen {
			continue
		}

		// Skip if all alphabetic (variable names)
		allAlpha := true
		for _, r := range part {
			if !unicode.IsLetter(r) {
				allAlpha = false
				break
			}
		}
		if allAlpha {
			continue
		}

		// Skip if all numeric (IDs, line numbers)
		allDigit := true
		for _, r := range part {
			if !unicode.IsDigit(r) {
				allDigit = false
				break
			}
		}
		if allDigit {
			continue
		}

		// Skip if contains whitespace
		hasWhitespace := false
		for _, r := range part {
			if unicode.IsSpace(r) {
				hasWhitespace = true
				break
			}
		}
		if hasWhitespace {
			continue
		}

		tokens = append(tokens, Token{Value: part, Start: start, End: end})
	}

	return tokens
}

// hasContextKeyword checks if a position in text is preceded by a context keyword
func hasContextKeyword(text string, pos int, keywords []string) bool {
	if len(keywords) == 0 {
		return false
	}

	// Look back up to 50 chars
	start := pos - 50
	if start < 0 {
		start = 0
	}
	prefix := strings.ToLower(text[start:pos])

	for _, kw := range keywords {
		if strings.Contains(prefix, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// Compiled exclusion patterns (lazy initialized)
var compiledExclusions []struct {
	regex           *regexp.Regexp
	label           string
	contextKeywords []string
}
var exclusionsCompiled bool

func getCompiledExclusions() []struct {
	regex           *regexp.Regexp
	label           string
	contextKeywords []string
} {
	if !exclusionsCompiled {
		for _, excl := range EntropyExclusions {
			pattern := excl.Pattern
			if excl.CaseInsensitive {
				pattern = "(?i)" + pattern
			}
			re, err := regexp.Compile("^" + pattern + "$")
			if err != nil {
				continue
			}
			compiledExclusions = append(compiledExclusions, struct {
				regex           *regexp.Regexp
				label           string
				contextKeywords []string
			}{
				regex:           re,
				label:           excl.Label,
				contextKeywords: excl.ContextKeywords,
			})
		}
		exclusionsCompiled = true
	}
	return compiledExclusions
}

// matchesExclusion checks if a token matches an exclusion pattern
// Returns the label if excluded, empty string otherwise
func matchesExclusion(token, text string, pos int) string {
	for _, excl := range getCompiledExclusions() {
		if excl.regex.MatchString(token) {
			// Check context keywords if present
			if len(excl.contextKeywords) > 0 {
				if hasContextKeyword(text, pos, excl.contextKeywords) {
					return excl.label
				}
				// Has context keywords but none found - not excluded
				continue
			}
			// No context keywords required - excluded
			return excl.label
		}
	}

	// Check global context keywords
	var globalKeywords []string
	for kw := range EntropyContextKeywords {
		globalKeywords = append(globalKeywords, kw)
	}
	if hasContextKeyword(text, pos, globalKeywords) {
		return "CONTEXT"
	}

	return ""
}

// describeEntropyStructure creates structure description for entropy redaction
func describeEntropyStructure(token string, entropy float64, charset string) string {
	charsetAbbrev := map[string]string{
		"hex":          "hex",
		"base64":       "b64",
		"alphanumeric": "alnum",
		"mixed":        "mix",
	}
	abbrev := charsetAbbrev[charset]
	if abbrev == "" {
		abbrev = charset
	}
	return abbrev + ":" + strconv.Itoa(len(token)) + ":" + strconv.FormatFloat(entropy, 'f', 1, 64)
}

// getEntropyConfig gets entropy configuration with environment variable overrides
func getEntropyConfig() EntropyConfig {
	config := EntropyConfig{
		Thresholds: make(map[string]float64),
		MinLength:  EntropyMinLength,
		MaxLength:  EntropyMaxLength,
	}

	// Copy default thresholds
	for k, v := range EntropyThresholds {
		config.Thresholds[k] = v
	}

	// Check for global threshold override
	if val := os.Getenv("SECRETS_FILTER_ENTROPY_THRESHOLD"); val != "" {
		var t float64
		if _, err := fmt.Sscanf(val, "%f", &t); err == nil {
			config.Thresholds["hex"] = t
			config.Thresholds["base64"] = t
			config.Thresholds["alphanumeric"] = t
		}
	}

	// Check for per-charset overrides
	if val := os.Getenv("SECRETS_FILTER_ENTROPY_HEX"); val != "" {
		var t float64
		if _, err := fmt.Sscanf(val, "%f", &t); err == nil {
			config.Thresholds["hex"] = t
		}
	}
	if val := os.Getenv("SECRETS_FILTER_ENTROPY_BASE64"); val != "" {
		var t float64
		if _, err := fmt.Sscanf(val, "%f", &t); err == nil {
			config.Thresholds["base64"] = t
		}
	}

	// Length overrides
	if val := os.Getenv("SECRETS_FILTER_ENTROPY_MIN_LEN"); val != "" {
		var n int
		if _, err := fmt.Sscanf(val, "%d", &n); err == nil {
			config.MinLength = n
		}
	}
	if val := os.Getenv("SECRETS_FILTER_ENTROPY_MAX_LEN"); val != "" {
		var n int
		if _, err := fmt.Sscanf(val, "%d", &n); err == nil {
			config.MaxLength = n
		}
	}

	return config
}

// redactEntropy detects and redacts high-entropy strings
func redactEntropy(text string, config EntropyConfig) string {
	tokens := extractTokens(text, config.MinLength, config.MaxLength)

	// Process in reverse order to preserve positions when replacing
	type replacement struct {
		start int
		end   int
		text  string
	}
	var replacements []replacement

	for i := len(tokens) - 1; i >= 0; i-- {
		token := tokens[i]

		// Check exclusions
		if excluded := matchesExclusion(token.Value, text, token.Start); excluded != "" {
			continue
		}

		// Classify character set and get threshold
		charset := classifyCharset(token.Value)
		var threshold float64
		if charset == "mixed" {
			// Mixed character sets - use alphanumeric threshold
			threshold = config.Thresholds["alphanumeric"]
			if threshold == 0 {
				threshold = 4.5
			}
		} else {
			threshold = config.Thresholds[charset]
			if threshold == 0 {
				threshold = 4.5
			}
		}

		// Calculate entropy
		entropy := shannonEntropy(token.Value)

		if entropy >= threshold {
			structure := describeEntropyStructure(token.Value, entropy, charset)
			repl := "[REDACTED:HIGH_ENTROPY:" + structure + "]"
			replacements = append(replacements, replacement{
				start: token.Start,
				end:   token.End,
				text:  repl,
			})
		}
	}

	// Apply replacements (already in reverse order)
	for _, r := range replacements {
		text = text[:r.start] + r.text + text[r.end:]
	}

	return text
}

// redactLine applies all redaction to a single line based on config
func redactLine(line string, secrets map[string]string, config FilterConfig, entropyConfig EntropyConfig) string {
	if config.ValuesEnabled && secrets != nil {
		line = redactEnvValues(line, secrets)
	}
	if config.PatternsEnabled {
		line = redactPatterns(line)
	}
	if config.EntropyEnabled {
		line = redactEntropy(line, entropyConfig)
	}
	return line
}

func main() {
	config := parseFilterConfig()

	// Only load secrets if values filter is enabled
	var secrets map[string]string
	if config.ValuesEnabled {
		secrets = loadSecrets()
	}

	// Only load entropy config if entropy filter is enabled
	var entropyConfig EntropyConfig
	if config.EntropyEnabled {
		entropyConfig = getEntropyConfig()
	}

	state := StateNormal
	var buffer []string

	reader := bufio.NewReader(os.Stdin)

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			break
		}
		if err == io.EOF && line == "" {
			break
		}

		// Handle line without newline at EOF
		hasNewline := strings.HasSuffix(line, "\n")

		// Binary detection: null byte
		if bytes.Contains([]byte(line), []byte{0}) {
			// Flush buffer
			for _, l := range buffer {
				fmt.Print(redactLine(l, secrets, config, entropyConfig))
			}
			buffer = nil
			// Passthrough this line and rest
			fmt.Print(line)
			io.Copy(os.Stdout, reader)
			return
		}

		switch state {
		case StateNormal:
			if config.PatternsEnabled && privateKeyBegin.MatchString(line) {
				state = StateInPrivateKey
				buffer = []string{line}
			} else {
				fmt.Print(redactLine(line, secrets, config, entropyConfig))
			}

		case StateInPrivateKey:
			buffer = append(buffer, line)

			if privateKeyEnd.MatchString(line) {
				fmt.Println("[REDACTED:PRIVATE_KEY:multiline]")
				buffer = nil
				state = StateNormal
			} else if len(buffer) > MaxPrivateKeyBuffer {
				// Buffer overflow - redact entirely (fail closed, don't leak)
				fmt.Println("[REDACTED:PRIVATE_KEY:multiline]")
				buffer = nil
				// Transition to overflow state - consume remaining lines silently until END
				state = StateInPrivateKeyOverflow
			}

		case StateInPrivateKeyOverflow:
			// Consume lines silently until END marker
			if privateKeyEnd.MatchString(line) {
				state = StateNormal
			}
			// No buffering, no output - just wait for END
		}

		if err == io.EOF {
			break
		}
		_ = hasNewline // suppress unused warning
	}

	// EOF: handle remaining state
	if state == StateInPrivateKey {
		// Incomplete private key block - redact entirely (fail closed, don't leak)
		fmt.Println("[REDACTED:PRIVATE_KEY:multiline]")
	} else if state == StateInPrivateKeyOverflow {
		// Already emitted overflow redaction, nothing to do
	} else if len(buffer) > 0 {
		// Flush any remaining buffered content
		for _, l := range buffer {
			fmt.Print(redactLine(l, secrets, config, entropyConfig))
		}
	}
}
