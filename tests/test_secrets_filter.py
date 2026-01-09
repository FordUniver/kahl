#!/usr/bin/env python3
"""Tests for secrets-filter redaction logic.

Run with: pytest .claude/tests/test_secrets_filter.py -v

Test architecture:
- Unit tests: Test redact_patterns(), redact_env_values() directly (single-line)
- Streaming tests: Run filter via subprocess (multiline private keys, binary)
"""
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

# Path to the filter (now in python/ subdirectory)
filter_path = Path(__file__).parent.parent / "python" / "secrets-filter"

# Import functions from secrets-filter (filename has hyphen, use exec)
secrets_filter = ModuleType("secrets_filter")
with open(filter_path) as f:
    code = f.read()
exec(compile(code, filter_path, "exec"), secrets_filter.__dict__)

# Aliases for convenience
redact_patterns = secrets_filter.redact_patterns
redact_env_values = secrets_filter.redact_env_values
describe_structure = secrets_filter.describe_structure
classify_segment = secrets_filter.classify_segment


class TestClassifySegment:
    """Tests for segment classification (N=digits, A=letters, X=mixed)."""

    def test_empty(self):
        assert classify_segment("") == ""

    def test_digits_only(self):
        assert classify_segment("123") == "3N"
        assert classify_segment("1234567890") == "10N"

    def test_letters_only(self):
        assert classify_segment("abc") == "3A"
        assert classify_segment("ABC") == "3A"
        assert classify_segment("AbCdEf") == "6A"

    def test_mixed(self):
        assert classify_segment("abc123") == "6X"
        assert classify_segment("123abc") == "6X"
        assert classify_segment("a1b2c3") == "6X"


class TestDescribeStructure:
    """Tests for token structure description."""

    def test_simple_digits(self):
        assert describe_structure("12345") == "5N"

    def test_simple_letters(self):
        assert describe_structure("abcdef") == "6A"

    def test_dash_separated_with_prefix(self):
        # Slack-style: xoxb-123456789-abcdef
        result = describe_structure("xoxb-123456789-abcdef")
        assert result == "xoxb-9N-6A"

    def test_underscore_separated_with_prefix(self):
        # GitHub PAT style: ghp_abc123def456
        result = describe_structure("ghp_abcdef123456")
        assert result == "ghp_12X"

    def test_long_token_with_prefix(self):
        # Very long tokens show prefix + length
        long_token = "ghp_" + "a" * 60
        result = describe_structure(long_token)
        assert "ghp_" in result
        assert "64chars" in result

    def test_long_token_without_clear_prefix(self):
        # Long token without prefix just shows length
        long_token = "a" * 60
        result = describe_structure(long_token)
        assert result == "60chars"

    def test_dot_separated(self):
        # SendGrid style: SG.xxx.yyy
        result = describe_structure("SG.abcdef.ghijkl")
        assert result == "SG.6A.6A"


class TestPatternMatching:
    """Tests for known token pattern redaction."""

    # --- GitHub ---
    def test_github_pat_classic(self):
        text = "token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
        result = redact_patterns(text)
        assert "[REDACTED:GITHUB_PAT:" in result
        # The actual token value should be replaced (structure may contain prefix)
        assert "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" not in result

    def test_github_pat_fine_grained(self):
        text = "github_pat_11ABCDEFGH0123456789_abcdefghijklmnop"
        result = redact_patterns(text)
        assert "[REDACTED:GITHUB_PAT:" in result

    def test_github_oauth(self):
        text = "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
        result = redact_patterns(text)
        assert "[REDACTED:GITHUB_OAUTH:" in result

    def test_github_server(self):
        text = "ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
        result = redact_patterns(text)
        assert "[REDACTED:GITHUB_SERVER:" in result

    def test_github_refresh(self):
        text = "ghr_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
        result = redact_patterns(text)
        assert "[REDACTED:GITHUB_REFRESH:" in result

    # --- GitLab ---
    def test_gitlab_pat(self):
        text = "glpat-abcdefghij1234567890"
        result = redact_patterns(text)
        assert "[REDACTED:GITLAB_PAT:" in result

    # --- Slack ---
    def test_slack_bot_token(self):
        text = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuv"
        result = redact_patterns(text)
        assert "[REDACTED:SLACK_BOT:" in result

    def test_slack_user_token(self):
        text = "xoxp-123456789012-1234567890123-abcdefghijklmnopqrstuv"
        result = redact_patterns(text)
        assert "[REDACTED:SLACK_USER:" in result

    def test_slack_app_token(self):
        text = "xoxa-123456789012-1234567890123-abcdefghijklmnopqrstuv"
        result = redact_patterns(text)
        assert "[REDACTED:SLACK_APP:" in result

    # --- OpenAI / Anthropic ---
    def test_openai_key(self):
        text = "sk-" + "a" * 48
        result = redact_patterns(text)
        assert "[REDACTED:OPENAI_KEY:" in result

    def test_openai_project_key(self):
        """New OpenAI format: sk-proj-xxxx"""
        text = "sk-proj-abcdefghij1234567890"
        result = redact_patterns(text)
        assert "[REDACTED:OPENAI_PROJECT_KEY:" in result

    def test_anthropic_key(self):
        text = "sk-ant-" + "a" * 90
        result = redact_patterns(text)
        assert "[REDACTED:ANTHROPIC_KEY:" in result

    def test_anthropic_key_realistic_format(self):
        """Real Anthropic keys have hyphens: sk-ant-api03-xxxx... (90+ chars after sk-ant-)"""
        # Pattern requires 90+ chars after "sk-ant-", so total ~97+ chars
        text = "sk-ant-api03-" + "a1b2c3d4e5f6g7h8i9j0" * 5  # 13 + 100 = 113 chars
        result = redact_patterns(text)
        assert "[REDACTED:ANTHROPIC_KEY:" in result
        assert "[REDACTED:OPENAI_KEY:" not in result  # OpenAI pattern shouldn't match

    def test_anthropic_not_matched_as_openai(self):
        """Verify OpenAI pattern sk-[A-Za-z0-9]{48} can't match Anthropic keys with hyphens."""
        # Anthropic keys have hyphens after sk-ant-, OpenAI pattern requires 48 alphanumeric
        text = "sk-ant-api03-abcdef"  # Short key with hyphens
        result = redact_patterns(text)
        # Should not match OpenAI (hyphens prevent match)
        assert "[REDACTED:OPENAI_KEY:" not in result

    # --- AWS ---
    def test_aws_access_key(self):
        text = "AKIAIOSFODNN7EXAMPLE"
        result = redact_patterns(text)
        assert "[REDACTED:AWS_ACCESS_KEY:" in result

    # --- Google Cloud ---
    def test_google_api_key(self):
        text = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"
        result = redact_patterns(text)
        assert "[REDACTED:GOOGLE_API_KEY:" in result

    # --- age ---
    def test_age_secret_key(self):
        text = "AGE-SECRET-KEY-" + "A" * 59
        result = redact_patterns(text)
        assert "[REDACTED:AGE_SECRET_KEY:" in result

    # --- Stripe ---
    def test_stripe_secret_live(self):
        text = "sk_live_abcdefghijklmnopqrstuvwx"
        result = redact_patterns(text)
        assert "[REDACTED:STRIPE_SECRET:" in result

    def test_stripe_secret_test(self):
        text = "sk_test_abcdefghijklmnopqrstuvwx"
        result = redact_patterns(text)
        assert "[REDACTED:STRIPE_TEST:" in result

    # --- Twilio ---
    def test_twilio_key(self):
        text = "SK" + "a" * 32
        result = redact_patterns(text)
        assert "[REDACTED:TWILIO_KEY:" in result

    # --- SendGrid ---
    def test_sendgrid_key(self):
        text = "SG.abcdefghijk.lmnopqrstuvwxyz123456"
        result = redact_patterns(text)
        assert "[REDACTED:SENDGRID_KEY:" in result

    # --- npm / PyPI ---
    def test_npm_token(self):
        text = "npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
        result = redact_patterns(text)
        assert "[REDACTED:NPM_TOKEN:" in result

    def test_pypi_token(self):
        text = "pypi-" + "a" * 100
        result = redact_patterns(text)
        assert "[REDACTED:PYPI_TOKEN:" in result

    # --- JWT ---
    def test_jwt_token(self):
        text = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = redact_patterns(text)
        assert "[REDACTED:JWT_TOKEN:" in result

    # --- netrc/authinfo ---
    def test_netrc_password(self):
        text = "machine github.com login user password supersecret123"
        result = redact_patterns(text)
        assert "[REDACTED:NETRC_PASSWORD:" in result
        assert "supersecret123" not in result

    def test_netrc_passwd(self):
        text = "machine github.com login user passwd anothersecret"
        result = redact_patterns(text)
        assert "[REDACTED:NETRC_PASSWORD:" in result

    # --- Generic key=value ---
    def test_password_equals(self):
        text = "connection password=mysecretpassword"
        result = redact_patterns(text)
        assert "[REDACTED:PASSWORD_VALUE:" in result
        assert "mysecretpassword" not in result

    def test_password_colon(self):
        text = "password: mysecretvalue"
        result = redact_patterns(text)
        assert "[REDACTED:PASSWORD_VALUE:" in result

    def test_token_equals(self):
        text = "config token=abc123xyz"
        result = redact_patterns(text)
        assert "[REDACTED:TOKEN_VALUE:" in result

    def test_secret_colon(self):
        text = "secret: verysecretvalue"
        result = redact_patterns(text)
        assert "[REDACTED:SECRET_VALUE:" in result

    # --- Private keys (batch mode - multiline regex) ---
    def test_rsa_private_key(self):
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
more key content here
-----END RSA PRIVATE KEY-----"""
        result = redact_patterns(text)
        assert "[REDACTED:PRIVATE_KEY:" in result
        assert "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn" not in result

    def test_ec_private_key(self):
        text = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBYr
-----END EC PRIVATE KEY-----"""
        result = redact_patterns(text)
        assert "[REDACTED:PRIVATE_KEY:" in result

    # --- Git credentials ---
    def test_git_credential_url(self):
        text = "https://user:mypassword123@github.com/repo.git"
        result = redact_patterns(text)
        assert "[REDACTED:GIT_CREDENTIAL:" in result
        assert "mypassword123" not in result

    # --- Docker auth ---
    def test_docker_config_auth(self):
        text = '{"auths": {"registry": {"auth": "dXNlcm5hbWU6cGFzc3dvcmQ="}}}'
        result = redact_patterns(text)
        assert "[REDACTED:DOCKER_AUTH:" in result
        assert "dXNlcm5hbWU6cGFzc3dvcmQ" not in result


class TestEnvBasedRedaction:
    """Tests for environment variable value redaction."""

    def test_redact_single_value(self):
        secrets = {"MY_SECRET": "supersecretvalue123"}
        text = "The value is supersecretvalue123 in the output"
        result = redact_env_values(text, secrets)
        assert "[REDACTED:MY_SECRET:" in result
        assert "supersecretvalue123" not in result

    def test_redact_multiple_values(self):
        secrets = {
            "SECRET_A": "valueA",
            "SECRET_B": "valueB",
        }
        text = "First valueA and then valueB appear"
        result = redact_env_values(text, secrets)
        assert "[REDACTED:SECRET_A:" in result
        assert "[REDACTED:SECRET_B:" in result
        assert "valueA" not in result
        assert "valueB" not in result

    def test_longer_values_replaced_first(self):
        # If one value contains another, longer should be replaced first
        secrets = {
            "SHORT": "abc",
            "LONG": "abcdef",
        }
        text = "The value abcdef here"
        result = redact_env_values(text, secrets)
        # Should redact as LONG, not SHORT + "def"
        assert "[REDACTED:LONG:" in result
        assert "abcdef" not in result

    def test_empty_value_skipped(self):
        secrets = {"EMPTY": "", "REAL": "realvalue"}
        text = "Contains realvalue"
        result = redact_env_values(text, secrets)
        assert "[REDACTED:REAL:" in result
        # Empty string should not cause issues
        assert "realvalue" not in result

    def test_multiple_occurrences(self):
        secrets = {"TOKEN": "abc123"}
        text = "First abc123 and second abc123"
        result = redact_env_values(text, secrets)
        assert result.count("[REDACTED:TOKEN:") == 2


class TestFalsePositives:
    """Tests to ensure we don't redact safe content."""

    def test_git_sha_not_redacted(self):
        # 40-char hex git SHA should not be redacted
        text = "commit abc123def456789012345678901234567890"
        result = redact_patterns(text)
        assert text == result

    def test_short_git_sha_not_redacted(self):
        text = "commit abc1234"
        result = redact_patterns(text)
        assert text == result

    def test_container_id_not_redacted(self):
        # Docker container IDs are 64-char hex
        text = "container: " + "a" * 64
        result = redact_patterns(text)
        # Should not be redacted (no matching pattern)
        assert "a" * 64 in result

    def test_uuid_not_redacted(self):
        text = "id: 550e8400-e29b-41d4-a716-446655440000"
        result = redact_patterns(text)
        assert text == result

    def test_base64_content_not_redacted(self):
        # Random base64 that's not in a sensitive context
        text = "data: SGVsbG8gV29ybGQh"
        result = redact_patterns(text)
        assert text == result

    def test_sk_prefix_too_short(self):
        # sk- followed by < 48 chars should not match OpenAI pattern
        text = "sk-shortkey123"
        result = redact_patterns(text)
        assert text == result

    def test_normal_password_word(self):
        # The word "password" alone shouldn't trigger
        text = "Enter your password:"
        result = redact_patterns(text)
        assert text == result

    def test_commented_code(self):
        # Code comments mentioning tokens shouldn't be redacted
        text = "# TODO: add GITHUB_TOKEN support"
        result = redact_patterns(text)
        assert text == result


class TestEdgeCases:
    """Tests for edge cases and robustness."""

    def test_empty_input(self):
        result = redact_patterns("")
        assert result == ""
        result = redact_env_values("", {})
        assert result == ""

    def test_whitespace_only(self):
        text = "   \n\t\n   "
        result = redact_patterns(text)
        assert result == text

    def test_very_long_line(self):
        # 10KB line
        text = "x" * 10000
        result = redact_patterns(text)
        assert result == text

    def test_unicode_content(self):
        text = "Password: secret123 with emoji"
        result = redact_patterns(text)
        assert "" in result

    def test_multiple_secrets_same_line(self):
        text = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 and glpat-abcdefghij1234567890"
        result = redact_patterns(text)
        assert "[REDACTED:GITHUB_PAT:" in result
        assert "[REDACTED:GITLAB_PAT:" in result

    def test_secret_at_line_boundaries(self):
        text = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\nglpat-abcdefghij1234567890"
        result = redact_patterns(text)
        assert "[REDACTED:GITHUB_PAT:" in result
        assert "[REDACTED:GITLAB_PAT:" in result

    def test_nested_redaction_markers(self):
        # Ensure we don't double-redact
        text = "[REDACTED:SOMETHING:structure]"
        result = redact_patterns(text)
        # Should pass through unchanged
        assert result == text


class TestBoundaryLengths:
    """Tests for token length boundaries (exact match behavior)."""

    def test_github_pat_exact_36_matches(self):
        # Exactly 36 chars after prefix should match
        text = "ghp_" + "a" * 36
        result = redact_patterns(text)
        assert "[REDACTED:GITHUB_PAT:" in result

    def test_github_pat_35_chars_no_match(self):
        # 35 chars is too short, should NOT match
        text = "ghp_" + "a" * 35
        result = redact_patterns(text)
        assert "[REDACTED:GITHUB_PAT:" not in result
        assert "ghp_" in result

    def test_github_pat_37_chars_partial_match(self):
        # 37 chars: first 36 should match, 37th char remains
        text = "ghp_" + "a" * 37
        result = redact_patterns(text)
        # The pattern matches exactly 36 chars, so 37th char is not part of match
        # Since all chars are valid, the regex will match the first 36
        # Actually, {36} is exact, so it won't match if there are more valid chars
        # Let me think... the regex is ghp_[A-Za-z0-9]{36}
        # In "ghp_aaa...a" (37 a's), the regex matches "ghp_" + first 36 a's
        # But the 37th 'a' is still valid for the character class...
        # Actually regex {36} means EXACTLY 36, not "at least 36"
        # So ghp_[A-Za-z0-9]{36} on "ghp_" + 37 a's will match ghp_ + 36 a's
        # and leave the 37th 'a' unmatched
        assert "[REDACTED:GITHUB_PAT:" in result

    def test_github_pat_37_with_delimiter(self):
        # 36 chars followed by a non-matching char
        text = "ghp_" + "a" * 36 + "."
        result = redact_patterns(text)
        assert "[REDACTED:GITHUB_PAT:" in result
        assert "." in result  # delimiter preserved

    def test_gitlab_pat_exact_20_matches(self):
        # GitLab PAT: glpat- followed by exactly 20 chars
        text = "glpat-" + "a" * 20
        result = redact_patterns(text)
        assert "[REDACTED:GITLAB_PAT:" in result

    def test_gitlab_pat_19_chars_no_match(self):
        # 19 chars is too short
        text = "glpat-" + "a" * 19
        result = redact_patterns(text)
        assert "[REDACTED:GITLAB_PAT:" not in result


class TestIntegration:
    """Integration tests combining env and pattern redaction."""

    def test_env_takes_precedence(self):
        # If a value matches both env and pattern, env label should be used
        # (env redaction runs first)
        github_token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
        secrets = {"GH_TOKEN": github_token}
        text = f"token: {github_token}"

        # First env redaction
        result = redact_env_values(text, secrets)
        assert "[REDACTED:GH_TOKEN:" in result

        # Then pattern redaction should find nothing new
        result = redact_patterns(result)
        assert "[REDACTED:GH_TOKEN:" in result
        assert "[REDACTED:GITHUB_PAT:" not in result

    def test_combined_redaction(self):
        secrets = {"MY_API_KEY": "custom-api-key-value"}
        text = """
        Custom key: custom-api-key-value
        GitHub: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789
        Slack: xoxb-123456789012-1234567890123-abcdefghij
        """
        result = redact_env_values(text, secrets)
        result = redact_patterns(result)

        assert "[REDACTED:MY_API_KEY:" in result
        assert "[REDACTED:GITHUB_PAT:" in result
        assert "[REDACTED:SLACK_BOT:" in result
        assert "custom-api-key-value" not in result


class TestStreaming:
    """Tests that run the filter via subprocess (streaming state machine).

    These test a different code path than unit tests:
    - Unit tests: call redact_patterns() directly (batch mode)
    - Streaming tests: run filter via subprocess (line-by-line state machine)
    """

    def run_filter(self, input_text: str) -> str:
        """Run the filter via subprocess and return stdout."""
        result = subprocess.run(
            [str(filter_path)],
            input=input_text,
            capture_output=True,
            text=True
        )
        return result.stdout

    def test_streaming_rsa_private_key(self):
        """Private key block → single [REDACTED:PRIVATE_KEY:multiline]."""
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nbase64data\n-----END RSA PRIVATE KEY-----\n"
        result = self.run_filter(text)
        assert result == "[REDACTED:PRIVATE_KEY:multiline]\n"

    def test_streaming_ec_private_key(self):
        """EC private key also handled."""
        text = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBYr\n-----END EC PRIVATE KEY-----\n"
        result = self.run_filter(text)
        assert result == "[REDACTED:PRIVATE_KEY:multiline]\n"

    def test_streaming_generic_private_key(self):
        """Generic PRIVATE KEY (no algorithm specified)."""
        text = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----\n"
        result = self.run_filter(text)
        assert result == "[REDACTED:PRIVATE_KEY:multiline]\n"

    def test_streaming_binary_passthrough(self):
        """Binary data (null byte) triggers passthrough."""
        text = "text\x00binary"
        result = self.run_filter(text)
        assert result == "text\x00binary"

    def test_streaming_binary_after_text(self):
        """Binary appearing after some text lines."""
        text = "line1\nline2\n\x00binary"
        result = self.run_filter(text)
        # First two lines are processed, then binary passthrough
        assert "line1\n" in result
        assert "line2\n" in result
        assert "\x00binary" in result

    def test_streaming_incomplete_key_eof(self):
        """BEGIN without END → lines flushed individually at EOF."""
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n"
        result = self.run_filter(text)
        # Should NOT be collapsed to single multiline redaction
        assert "[REDACTED:PRIVATE_KEY:multiline]" not in result
        # Buffer flushed - content appears (not swallowed)
        assert len(result.strip()) > 0
        # BEGIN line should appear (flushed individually)
        assert "-----BEGIN" in result

    def test_streaming_mixed_content(self):
        """Text before and after private key."""
        text = "before\n-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----\nafter\n"
        result = self.run_filter(text)
        assert "before\n" in result
        assert "[REDACTED:PRIVATE_KEY:multiline]\n" in result
        assert "after\n" in result

    def test_streaming_multiple_keys(self):
        """Multiple private keys in sequence."""
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\nkey1\n-----END RSA PRIVATE KEY-----\n"
            "-----BEGIN EC PRIVATE KEY-----\nkey2\n-----END EC PRIVATE KEY-----\n"
        )
        result = self.run_filter(text)
        assert result.count("[REDACTED:PRIVATE_KEY:multiline]") == 2

    def test_streaming_single_line_patterns(self):
        """Single-line patterns work in streaming mode."""
        text = "token: ghp_" + "a" * 36 + "\n"
        result = self.run_filter(text)
        assert "[REDACTED:GITHUB_PAT:" in result

    def test_streaming_preserves_newlines(self):
        """Newlines are preserved in output."""
        text = "line1\nline2\nline3\n"
        result = self.run_filter(text)
        assert result == "line1\nline2\nline3\n"

    def test_streaming_empty_input(self):
        """Empty input produces empty output."""
        result = self.run_filter("")
        assert result == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
