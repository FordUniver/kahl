#!/usr/bin/env perl
# Generate Patterns.pm from YAML pattern definitions
# Usage: ./generate.pl

use strict;
use warnings;
use File::Basename;
use Cwd 'abs_path';
use Digest::SHA qw(sha256_hex);
use POSIX qw(strftime);

my $script_dir = dirname(abs_path($0));
my $repo_root = dirname($script_dir);
my $patterns_file = "$repo_root/patterns/patterns.yaml";
my $env_file = "$repo_root/patterns/env.yaml";
my $entropy_file = "$repo_root/patterns/entropy.yaml";
my $output_file = "$script_dir/Patterns.pm";

# Verify source files exist
die "patterns.yaml not found: $patterns_file\n" unless -f $patterns_file;
die "env.yaml not found: $env_file\n" unless -f $env_file;
# entropy.yaml is optional

# Compute source hash for reproducibility tracking
sub compute_source_hash {
    my @files = @_;
    my $combined = '';
    for my $file (@files) {
        open my $fh, '<', $file or die "Cannot read $file: $!\n";
        local $/;
        $combined .= <$fh>;
        close $fh;
    }
    return substr(sha256_hex($combined), 0, 12);
}

# Run yq command and return output
sub yq {
    my ($expr, $file) = @_;
    my $cmd = "yq -r '$expr' '$file'";
    my $output = `$cmd`;
    die "yq failed: $cmd\n" if $? != 0;
    chomp $output;
    return $output;
}

# Run yq and return array of lines (filtering nulls)
sub yq_array {
    my ($expr, $file) = @_;
    my $output = yq($expr, $file);
    return grep { $_ ne '' && $_ ne 'null' } split /\n/, $output;
}

# Escape a string for Perl single-quoted context
sub escape_sq {
    my ($s) = @_;
    $s =~ s/\\/\\\\/g;
    $s =~ s/'/\\'/g;
    return $s;
}

# Escape forward slashes in regex pattern (for qr// delimiter)
sub escape_regex_delim {
    my ($s) = @_;
    $s =~ s{/}{\\/}g;
    return $s;
}

# Parse patterns.yaml
sub parse_patterns {
    my $count = yq('.patterns | length', $patterns_file);
    my @patterns;

    for my $i (0 .. $count - 1) {
        my $pattern = yq(".patterns[$i].pattern", $patterns_file);
        my $label = yq(".patterns[$i].label", $patterns_file);
        my $multiline = yq(".patterns[$i].multiline // false", $patterns_file);

        push @patterns, {
            pattern => $pattern,
            label => $label,
            multiline => ($multiline eq 'true' ? 1 : 0),
        };
    }

    return @patterns;
}

# Parse context_patterns from patterns.yaml
sub parse_context_patterns {
    my $count = yq('.context_patterns | length', $patterns_file);
    my @patterns;

    for my $i (0 .. $count - 1) {
        my $prefix = yq(".context_patterns[$i].prefix", $patterns_file);
        my $value = yq(".context_patterns[$i].value", $patterns_file);
        my $label = yq(".context_patterns[$i].label", $patterns_file);

        push @patterns, {
            prefix => $prefix,
            value => $value,
            label => $label,
        };
    }

    return @patterns;
}

# Parse special_patterns from patterns.yaml
sub parse_special_patterns {
    my @keys = yq_array('.special_patterns | keys | .[]', $patterns_file);
    my %patterns;

    for my $key (@keys) {
        my $pattern = yq(".special_patterns.$key.pattern", $patterns_file);
        my $label = yq(".special_patterns.$key.label", $patterns_file);
        my $secret_group = yq(".special_patterns.$key.secret_group", $patterns_file);

        $patterns{$key} = {
            pattern => $pattern,
            label => $label,
            secret_group => $secret_group,
        };
    }

    return %patterns;
}

# Parse constants from patterns.yaml
sub parse_constants {
    my $long_threshold = yq('.constants.long_threshold', $patterns_file);
    my $max_pk_buffer = yq('.constants.max_private_key_buffer', $patterns_file);
    return ($long_threshold, $max_pk_buffer);
}

# Parse private key markers from patterns.yaml
sub parse_private_key_markers {
    my $begin = yq('.private_key.begin', $patterns_file);
    my $end = yq('.private_key.end', $patterns_file);
    return ($begin, $end);
}

# Parse env.yaml
sub parse_env {
    my @explicit = yq_array('.explicit[]', $env_file);
    my @suffixes = yq_array('.suffixes[]', $env_file);
    return (\@explicit, \@suffixes);
}

# Parse entropy.yaml
sub parse_entropy {
    return () unless -f $entropy_file;

    my %config;

    # Enabled by default
    my $enabled = yq('.enabled_by_default // false', $entropy_file);
    $config{enabled_default} = ($enabled eq 'true' ? 1 : 0);

    # Thresholds
    $config{threshold_hex} = yq('.thresholds.hex // 3.0', $entropy_file);
    $config{threshold_base64} = yq('.thresholds.base64 // 4.5', $entropy_file);
    $config{threshold_alphanumeric} = yq('.thresholds.alphanumeric // 4.5', $entropy_file);

    # Token length constraints
    $config{min_length} = yq('.token_length.min // 16', $entropy_file);
    $config{max_length} = yq('.token_length.max // 256', $entropy_file);

    # Exclusion patterns
    my @exclusions;
    my $excl_count = yq('.exclusions | length', $entropy_file);
    for my $i (0 .. $excl_count - 1) {
        my $pattern = yq(".exclusions[$i].pattern", $entropy_file);
        my $label = yq(".exclusions[$i].label", $entropy_file);
        my $case_insensitive = yq(".exclusions[$i].case_insensitive // false", $entropy_file);

        # Check for context keywords
        my $kw_check = yq(".exclusions[$i].context_keywords // null", $entropy_file);
        my @context_keywords;
        if ($kw_check ne 'null') {
            @context_keywords = yq_array(".exclusions[$i].context_keywords[]", $entropy_file);
        }

        push @exclusions, {
            pattern => $pattern,
            label => $label,
            case_insensitive => ($case_insensitive eq 'true' ? 1 : 0),
            context_keywords => \@context_keywords,
        };
    }
    $config{exclusions} = \@exclusions;

    # Global context keywords
    my @context_keywords = yq_array('.context_keywords[]', $entropy_file);
    $config{context_keywords} = \@context_keywords;

    return %config;
}

# Generate Patterns.pm content
sub generate_module {
    my @source_files = ($patterns_file, $env_file);
    push @source_files, $entropy_file if -f $entropy_file;
    my $source_hash = compute_source_hash(@source_files);
    my $timestamp = strftime('%Y-%m-%d %H:%M:%S UTC', gmtime);

    my @patterns = parse_patterns();
    my @context_patterns = parse_context_patterns();
    my %special_patterns = parse_special_patterns();
    my ($long_threshold, $max_pk_buffer) = parse_constants();
    my ($pk_begin, $pk_end) = parse_private_key_markers();
    my ($explicit_ref, $suffixes_ref) = parse_env();
    my %entropy_config = parse_entropy();

    my $output = <<"HEADER";
# Generated by generate.pl - DO NOT EDIT
# Source: patterns/*.yaml (hash: $source_hash)
# Generated: $timestamp
package Patterns;

use strict;
use warnings;
use Exporter 'import';

our \@EXPORT_OK = qw(
    \@PATTERNS
    \@CONTEXT_PATTERNS
    \%SPECIAL_PATTERNS
    \$PRIVATE_KEY_BEGIN
    \$PRIVATE_KEY_END
    \@EXPLICIT_ENV_VARS
    \@ENV_SUFFIXES
    \$LONG_THRESHOLD
    \$MAX_PRIVATE_KEY_BUFFER
    \$ENTROPY_ENABLED_DEFAULT
    \%ENTROPY_THRESHOLDS
    \$ENTROPY_MIN_LENGTH
    \$ENTROPY_MAX_LENGTH
    \@ENTROPY_EXCLUSIONS
    \%ENTROPY_CONTEXT_KEYWORDS
);

our \%EXPORT_TAGS = (
    all => \\\@EXPORT_OK,
);

# Constants
our \$LONG_THRESHOLD = $long_threshold;
our \$MAX_PRIVATE_KEY_BUFFER = $max_pk_buffer;

# Private key markers (for streaming state machine)
our \$PRIVATE_KEY_BEGIN = qr/$pk_begin/;
our \$PRIVATE_KEY_END = qr/$pk_end/;

HEADER

    # Generate @PATTERNS
    $output .= "# Direct token patterns: [regex, label]\n";
    $output .= "# Order: more specific patterns first\n";
    $output .= "our \@PATTERNS = (\n";

    for my $p (@patterns) {
        my $pattern = escape_regex_delim($p->{pattern});
        my $label = $p->{label};
        my $comment = $p->{multiline} ? '  # multiline' : '';
        $output .= "    [qr/$pattern/, '$label'],$comment\n";
    }

    $output .= ");\n\n";

    # Generate @CONTEXT_PATTERNS (using lookbehind)
    $output .= "# Context patterns: [regex with lookbehind, label]\n";
    $output .= "our \@CONTEXT_PATTERNS = (\n";

    for my $p (@context_patterns) {
        my $prefix = escape_regex_delim($p->{prefix});
        my $value = escape_regex_delim($p->{value});
        my $label = $p->{label};
        # Use lookbehind: (?<=prefix)value
        $output .= "    [qr/(?<=$prefix)$value/, '$label'],\n";
    }

    $output .= ");\n\n";

    # Generate %SPECIAL_PATTERNS
    $output .= "# Special patterns with capture groups\n";
    $output .= "our \%SPECIAL_PATTERNS = (\n";

    for my $key (sort keys %special_patterns) {
        my $p = $special_patterns{$key};
        my $pattern = escape_regex_delim($p->{pattern});
        my $label = $p->{label};
        my $group = $p->{secret_group};
        $output .= "    $key => {\n";
        $output .= "        pattern => qr/$pattern/,\n";
        $output .= "        label => '$label',\n";
        $output .= "        secret_group => $group,\n";
        $output .= "    },\n";
    }

    $output .= ");\n\n";

    # Generate @EXPLICIT_ENV_VARS
    $output .= "# Explicit environment variable names to check\n";
    $output .= "our \@EXPLICIT_ENV_VARS = qw(\n";

    for my $var (@$explicit_ref) {
        $output .= "    $var\n";
    }

    $output .= ");\n\n";

    # Generate @ENV_SUFFIXES
    $output .= "# Environment variable name suffixes that indicate secrets\n";
    $output .= "our \@ENV_SUFFIXES = qw(\n";

    for my $suffix (@$suffixes_ref) {
        $output .= "    $suffix\n";
    }

    $output .= ");\n\n";

    # Generate entropy config
    $output .= "# Entropy detection configuration\n";
    if (%entropy_config) {
        my $enabled = $entropy_config{enabled_default} ? 1 : 0;
        $output .= "our \$ENTROPY_ENABLED_DEFAULT = $enabled;\n\n";

        $output .= "our \%ENTROPY_THRESHOLDS = (\n";
        $output .= "    hex => $entropy_config{threshold_hex},\n";
        $output .= "    base64 => $entropy_config{threshold_base64},\n";
        $output .= "    alphanumeric => $entropy_config{threshold_alphanumeric},\n";
        $output .= ");\n\n";

        $output .= "our \$ENTROPY_MIN_LENGTH = $entropy_config{min_length};\n";
        $output .= "our \$ENTROPY_MAX_LENGTH = $entropy_config{max_length};\n\n";

        # Exclusions array
        $output .= "our \@ENTROPY_EXCLUSIONS = (\n";
        for my $excl (@{$entropy_config{exclusions}}) {
            my $pattern = escape_regex_delim($excl->{pattern});
            my $label = $excl->{label};
            my $case_i = $excl->{case_insensitive} ? 'i' : '';
            my @kw = @{$excl->{context_keywords}};

            $output .= "    {\n";
            $output .= "        pattern => qr/$pattern/$case_i,\n";
            $output .= "        label => '$label',\n";
            $output .= "        case_insensitive => $excl->{case_insensitive},\n";
            if (@kw) {
                $output .= "        context_keywords => [qw(" . join(' ', @kw) . ")],\n";
            } else {
                $output .= "        context_keywords => undef,\n";
            }
            $output .= "    },\n";
        }
        $output .= ");\n\n";

        # Context keywords hash/set
        $output .= "our \%ENTROPY_CONTEXT_KEYWORDS = map { \$_ => 1 } qw(\n";
        for my $kw (sort @{$entropy_config{context_keywords}}) {
            $output .= "    $kw\n";
        }
        $output .= ");\n\n";
    } else {
        # Defaults when entropy.yaml is missing
        $output .= "our \$ENTROPY_ENABLED_DEFAULT = 0;\n";
        $output .= "our \%ENTROPY_THRESHOLDS = (hex => 3.0, base64 => 4.5, alphanumeric => 4.5);\n";
        $output .= "our \$ENTROPY_MIN_LENGTH = 16;\n";
        $output .= "our \$ENTROPY_MAX_LENGTH = 256;\n";
        $output .= "our \@ENTROPY_EXCLUSIONS = ();\n";
        $output .= "our \%ENTROPY_CONTEXT_KEYWORDS = ();\n\n";
    }

    $output .= "1;\n";

    return $output;
}

# Main
sub main {
    my $content = generate_module();

    open my $fh, '>', $output_file or die "Cannot write $output_file: $!\n";
    print $fh $content;
    close $fh;

    print "Generated: $output_file\n";
}

main();
