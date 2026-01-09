// secrets-filter: Filter stdin for secrets, redact with labels
// Build: go build -o secrets-filter secrets-filter.go
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	StateNormal = iota
	StateInPrivateKey
)

const (
	MaxPrivateKeyBuffer = 100
	LongThreshold       = 50
)

var (
	privateKeyBegin = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	privateKeyEnd   = regexp.MustCompile(`-----END [A-Z ]*PRIVATE KEY-----`)
)

// Pattern holds a compiled regex and its label
type Pattern struct {
	Regex *regexp.Regexp
	Label string
}

// Patterns that can be matched directly
var patterns = []Pattern{
	// GitHub
	{regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), "GITHUB_PAT"},
	{regexp.MustCompile(`gho_[A-Za-z0-9]{36}`), "GITHUB_OAUTH"},
	{regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`), "GITHUB_SERVER"},
	{regexp.MustCompile(`ghr_[A-Za-z0-9]{36}`), "GITHUB_REFRESH"},
	{regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`), "GITHUB_PAT"},

	// GitLab
	{regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`), "GITLAB_PAT"},

	// Slack
	{regexp.MustCompile(`xoxb-[0-9]+-[0-9A-Za-z-]+`), "SLACK_BOT"},
	{regexp.MustCompile(`xoxp-[0-9]+-[0-9A-Za-z-]+`), "SLACK_USER"},
	{regexp.MustCompile(`xoxa-[0-9]+-[0-9A-Za-z-]+`), "SLACK_APP"},
	{regexp.MustCompile(`xoxs-[0-9]+-[0-9A-Za-z-]+`), "SLACK_SESSION"},

	// OpenAI / Anthropic
	{regexp.MustCompile(`sk-[A-Za-z0-9]{48}`), "OPENAI_KEY"},
	{regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{20,}`), "OPENAI_PROJECT_KEY"},
	{regexp.MustCompile(`sk-ant-[A-Za-z0-9-]{90,}`), "ANTHROPIC_KEY"},

	// AWS
	{regexp.MustCompile(`AKIA[A-Z0-9]{16}`), "AWS_ACCESS_KEY"},

	// Google Cloud
	{regexp.MustCompile(`AIza[A-Za-z0-9_-]{35}`), "GOOGLE_API_KEY"},

	// age encryption
	{regexp.MustCompile(`AGE-SECRET-KEY-[A-Z0-9]{59}`), "AGE_SECRET_KEY"},

	// Stripe
	{regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`), "STRIPE_SECRET"},
	{regexp.MustCompile(`sk_test_[A-Za-z0-9]{24,}`), "STRIPE_TEST"},
	{regexp.MustCompile(`pk_live_[A-Za-z0-9]{24,}`), "STRIPE_PUBLISHABLE"},

	// Twilio
	{regexp.MustCompile(`SK[a-f0-9]{32}`), "TWILIO_KEY"},

	// SendGrid
	{regexp.MustCompile(`SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), "SENDGRID_KEY"},

	// npm / PyPI
	{regexp.MustCompile(`npm_[A-Za-z0-9]{36}`), "NPM_TOKEN"},
	{regexp.MustCompile(`pypi-[A-Za-z0-9_-]{100,}`), "PYPI_TOKEN"},

	// JWT tokens
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), "JWT_TOKEN"},
}

// Context patterns (need capture groups since Go doesn't support lookbehind)
var contextPatterns = []struct {
	Regex *regexp.Regexp
	Label string
	Group int // which capture group contains the secret
}{
	// netrc/authinfo: password <value> or passwd <value>
	{regexp.MustCompile(`(password |passwd )([^\s]+)`), "NETRC_PASSWORD", 2},

	// Generic key=value patterns
	{regexp.MustCompile(`(password=)([^\s,;"'\}\[\]]+)`), "PASSWORD_VALUE", 2},
	{regexp.MustCompile(`(password:)(\s*[^\s,;"'\}\[\]]+)`), "PASSWORD_VALUE", 2},
	{regexp.MustCompile(`(Password=)([^\s,;"'\}\[\]]+)`), "PASSWORD_VALUE", 2},
	{regexp.MustCompile(`(Password:)(\s*[^\s,;"'\}\[\]]+)`), "PASSWORD_VALUE", 2},
	{regexp.MustCompile(`(secret=)([^\s,;"'\}\[\]]+)`), "SECRET_VALUE", 2},
	{regexp.MustCompile(`(secret:)(\s*[^\s,;"'\}\[\]]+)`), "SECRET_VALUE", 2},
	{regexp.MustCompile(`(Secret=)([^\s,;"'\}\[\]]+)`), "SECRET_VALUE", 2},
	{regexp.MustCompile(`(Secret:)(\s*[^\s,;"'\}\[\]]+)`), "SECRET_VALUE", 2},
	{regexp.MustCompile(`(token=)([^\s,;"'\}\[\]]+)`), "TOKEN_VALUE", 2},
	{regexp.MustCompile(`(token:)(\s*[^\s,;"'\}\[\]]+)`), "TOKEN_VALUE", 2},
	{regexp.MustCompile(`(Token=)([^\s,;"'\}\[\]]+)`), "TOKEN_VALUE", 2},
	{regexp.MustCompile(`(Token:)(\s*[^\s,;"'\}\[\]]+)`), "TOKEN_VALUE", 2},
}

// Special patterns with context preservation
var (
	gitCredentialPattern = regexp.MustCompile(`(://[^:]+:)([^@]+)(@)`)
	dockerAuthPattern    = regexp.MustCompile(`("auth":\s*")([A-Za-z0-9+/=]{20,})(")`)
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
	if allDigits {
		return fmt.Sprintf("%dN", len(s))
	}
	if allLetters {
		return fmt.Sprintf("%dA", len(s))
	}
	return fmt.Sprintf("%dX", len(s))
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
					return fmt.Sprintf("%s%s...:%dchars", first, sep, len(s))
				}
			}
		}
		return fmt.Sprintf("%dchars", len(s))
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

// loadSecretsFromDotfiles loads secret variable names and values from dotfiles
func loadSecretsFromDotfiles() map[string]string {
	dotfiles := os.Getenv("DOTFILES")
	if dotfiles == "" {
		home := os.Getenv("HOME")
		dotfiles = filepath.Join(home, ".dotfiles")
	}
	secretsDir := filepath.Join(dotfiles, "secrets")

	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		return nil
	}

	cmd := exec.Command("grep", "-rh", `^[A-Z_][A-Z0-9_]*=`, secretsDir)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	secrets := make(map[string]string)
	varPattern := regexp.MustCompile(`^([A-Z_][A-Z0-9_]*)=`)

	for _, line := range strings.Split(string(output), "\n") {
		matches := varPattern.FindStringSubmatch(line)
		if len(matches) >= 2 {
			varName := matches[1]
			if val := os.Getenv(varName); val != "" {
				secrets[varName] = val
			}
		}
	}

	return secrets
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
		replacement := fmt.Sprintf("[REDACTED:%s:%s]", s.key, structure)
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
			return fmt.Sprintf("[REDACTED:%s:%s]", p.Label, structure)
		})
	}

	// Context patterns (simulate lookbehind)
	for _, cp := range contextPatterns {
		text = cp.Regex.ReplaceAllStringFunc(text, func(match string) string {
			submatches := cp.Regex.FindStringSubmatch(match)
			if len(submatches) > cp.Group {
				secret := submatches[cp.Group]
				structure := describeStructure(strings.TrimSpace(secret))
				return submatches[1] + fmt.Sprintf("[REDACTED:%s:%s]", cp.Label, structure)
			}
			return match
		})
	}

	// Git credential URLs
	text = gitCredentialPattern.ReplaceAllStringFunc(text, func(match string) string {
		submatches := gitCredentialPattern.FindStringSubmatch(match)
		if len(submatches) >= 4 {
			structure := describeStructure(submatches[2])
			return submatches[1] + fmt.Sprintf("[REDACTED:GIT_CREDENTIAL:%s]", structure) + submatches[3]
		}
		return match
	})

	// Docker config auth
	text = dockerAuthPattern.ReplaceAllStringFunc(text, func(match string) string {
		submatches := dockerAuthPattern.FindStringSubmatch(match)
		if len(submatches) >= 4 {
			structure := describeStructure(submatches[2])
			return submatches[1] + fmt.Sprintf("[REDACTED:DOCKER_AUTH:%s]", structure) + submatches[3]
		}
		return match
	})

	return text
}

// redactLine applies all redaction to a single line
func redactLine(line string, secrets map[string]string) string {
	line = redactEnvValues(line, secrets)
	line = redactPatterns(line)
	return line
}

func main() {
	secrets := loadSecretsFromDotfiles()
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
				fmt.Print(redactLine(l, secrets))
			}
			buffer = nil
			// Passthrough this line and rest
			fmt.Print(line)
			io.Copy(os.Stdout, reader)
			return
		}

		switch state {
		case StateNormal:
			if privateKeyBegin.MatchString(line) {
				state = StateInPrivateKey
				buffer = []string{line}
			} else {
				fmt.Print(redactLine(line, secrets))
			}

		case StateInPrivateKey:
			buffer = append(buffer, line)

			if privateKeyEnd.MatchString(line) {
				fmt.Println("[REDACTED:PRIVATE_KEY:multiline]")
				buffer = nil
				state = StateNormal
			} else if len(buffer) > MaxPrivateKeyBuffer {
				for _, l := range buffer {
					fmt.Print(redactLine(l, secrets))
				}
				buffer = nil
				state = StateNormal
			}
		}

		if err == io.EOF {
			break
		}
		_ = hasNewline // suppress unused warning
	}

	// EOF: flush remaining buffer
	for _, l := range buffer {
		fmt.Print(redactLine(l, secrets))
	}
}
