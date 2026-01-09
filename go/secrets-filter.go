// secrets-filter: Filter stdin for secrets, redact with labels
// Build: go build -o secrets-filter secrets-filter.go patterns_gen.go
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"
)

// Filter configuration
type FilterConfig struct {
	ValuesEnabled   bool
	PatternsEnabled bool
}

const (
	StateNormal = iota
	StateInPrivateKey
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

// parseFilterConfig parses filter configuration from CLI args and environment
func parseFilterConfig() FilterConfig {
	config := FilterConfig{
		ValuesEnabled:   true,
		PatternsEnabled: true,
	}

	// Check for --filter or -f in args
	var filterArg string
	args := os.Args[1:]
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
			case "all":
				config.ValuesEnabled = true
				config.PatternsEnabled = true
				validFound = true
			default:
				if filter != "" {
					invalidFilters = append(invalidFilters, part)
				}
			}
		}

		// Warn about invalid filters
		for _, invalid := range invalidFilters {
			fmt.Fprintf(os.Stderr, "secrets-filter: unknown filter '%s', ignoring\n", strings.TrimSpace(invalid))
		}

		// Error if no valid filters found
		if !validFound {
			fmt.Fprintln(os.Stderr, "secrets-filter: no valid filters specified")
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
				structure := describeStructure(secret)
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

// redactLine applies all redaction to a single line based on config
func redactLine(line string, secrets map[string]string, config FilterConfig) string {
	if config.ValuesEnabled && secrets != nil {
		line = redactEnvValues(line, secrets)
	}
	if config.PatternsEnabled {
		line = redactPatterns(line)
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
				fmt.Print(redactLine(l, secrets, config))
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
				fmt.Print(redactLine(line, secrets, config))
			}

		case StateInPrivateKey:
			buffer = append(buffer, line)

			if privateKeyEnd.MatchString(line) {
				fmt.Println("[REDACTED:PRIVATE_KEY:multiline]")
				buffer = nil
				state = StateNormal
			} else if len(buffer) > MaxPrivateKeyBuffer {
				for _, l := range buffer {
					fmt.Print(redactLine(l, secrets, config))
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
		fmt.Print(redactLine(l, secrets, config))
	}
}
