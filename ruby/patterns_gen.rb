# frozen_string_literal: true

# AUTO-GENERATED FILE - DO NOT EDIT
# Generated: 2026-01-09T18:46:56Z
# Source: patterns/patterns.yaml (81fdf7816541)
#         patterns/env.yaml (dfab996443dc)
# Regenerate with: ruby ruby/generate.rb

module PatternsGen
  # Constants
  LONG_THRESHOLD = 50
  MAX_PRIVATE_KEY_BUFFER = 100

  # Private key markers (for streaming state machine)
  PRIVATE_KEY_BEGIN = /-----BEGIN [A-Z ]*PRIVATE KEY-----/
  PRIVATE_KEY_END = /-----END [A-Z ]*PRIVATE KEY-----/

  # Direct patterns: [regex, label]
  # Order: more specific patterns first
  PATTERNS = [
    [/ghp_[A-Za-z0-9]{36}/, 'GITHUB_PAT'],
    [/gho_[A-Za-z0-9]{36}/, 'GITHUB_OAUTH'],
    [/ghs_[A-Za-z0-9]{36}/, 'GITHUB_SERVER'],
    [/ghr_[A-Za-z0-9]{36}/, 'GITHUB_REFRESH'],
    [/github_pat_[A-Za-z0-9_]{22,}/, 'GITHUB_PAT'],
    [/glpat-[A-Za-z0-9_-]{20,}/, 'GITLAB_PAT'],
    [/xoxb-[0-9]+-[0-9A-Za-z-]+/, 'SLACK_BOT'],
    [/xoxp-[0-9]+-[0-9A-Za-z-]+/, 'SLACK_USER'],
    [/xoxa-[0-9]+-[0-9A-Za-z-]+/, 'SLACK_APP'],
    [/xoxs-[0-9]+-[0-9A-Za-z-]+/, 'SLACK_SESSION'],
    [/sk-[A-Za-z0-9]{48}/, 'OPENAI_KEY'],
    [/sk-proj-[A-Za-z0-9_-]{20,}/, 'OPENAI_PROJECT_KEY'],
    [/sk-ant-[A-Za-z0-9-]{90,}/, 'ANTHROPIC_KEY'],
    [/AKIA[A-Z0-9]{16}/, 'AWS_ACCESS_KEY'],
    [/AIza[A-Za-z0-9_-]{35}/, 'GOOGLE_API_KEY'],
    [/AGE-SECRET-KEY-[A-Z0-9]{59}/, 'AGE_SECRET_KEY'],
    [/sk_live_[A-Za-z0-9]{24,}/, 'STRIPE_SECRET'],
    [/sk_test_[A-Za-z0-9]{24,}/, 'STRIPE_TEST'],
    [/pk_live_[A-Za-z0-9]{24,}/, 'STRIPE_PUBLISHABLE'],
    [/SK[a-f0-9]{32}/, 'TWILIO_KEY'],
    [/SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, 'SENDGRID_KEY'],
    [/npm_[A-Za-z0-9]{36}/, 'NPM_TOKEN'],
    [/pypi-[A-Za-z0-9_-]{100,}/, 'PYPI_TOKEN'],
    [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, 'JWT_TOKEN'],
    [/dop_v1_[a-f0-9]{64}/, 'DIGITALOCEAN_PAT'],
    [/doo_v1_[a-f0-9]{64}/, 'DIGITALOCEAN_OAUTH'],
    [/dor_v1_[a-f0-9]{64}/, 'DIGITALOCEAN_REFRESH'],
    [/HRKU-[A-Za-z0-9_]{60}/, 'HEROKU_API_KEY'],
    [/GOCSPX-[A-Za-z0-9_-]{20,}/, 'GCP_OAUTH_SECRET'],
    [/nfp_[A-Za-z0-9_-]{20,}/, 'NETLIFY_PAT'],
    [/sb_publishable_[A-Za-z0-9_-]{20,}/, 'SUPABASE_PUBLISHABLE'],
    [/sb_secret_[A-Za-z0-9_-]{20,}/, 'SUPABASE_SECRET'],
    [/pscale_tkn_[A-Za-z0-9_-]{30,}/, 'PLANETSCALE_TOKEN'],
    [/[A-Za-z0-9]{9}\.atlasv1\.[A-Za-z0-9]{40,}/, 'TERRAFORM_CLOUD_TOKEN'],
    [/hvs\.[A-Za-z0-9]{24,}/, 'VAULT_SERVICE_TOKEN'],
    [/hvb\.[A-Za-z0-9]{24,}/, 'VAULT_BATCH_TOKEN'],
    [/hvr\.[A-Za-z0-9]{24,}/, 'VAULT_RECOVERY_TOKEN'],
    [/rubygems_[a-f0-9]{56}/, 'RUBYGEMS_API_KEY'],
    [/shpat_[A-Za-z0-9]{32,}/, 'SHOPIFY_ADMIN_TOKEN'],
    [/NRAK-[A-Za-z0-9]{27,}/, 'NEWRELIC_USER_KEY'],
    [/key-[A-Za-z0-9]{32,}/, 'MAILGUN_API_KEY'],
    [/lin_api_[A-Za-z0-9]{40,}/, 'LINEAR_API_KEY'],
    [/dp\.pt\.[A-Za-z0-9]{40,}/, 'DOPPLER_TOKEN'],
    [/[0-9]{9,10}:[A-Za-z0-9_-]{35,}/, 'TELEGRAM_BOT_TOKEN'],
    [/[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/, 'DISCORD_BOT_TOKEN'],
    [%r{https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+}, 'DISCORD_WEBHOOK'],
    [/EAA[A-Za-z0-9]{50,}/, 'FACEBOOK_ACCESS_TOKEN'],
  ].freeze

  # Context patterns: [regex_with_lookbehind, label]
  # Ruby supports lookbehind: (?<=prefix)value
  CONTEXT_PATTERNS = [
    [/(?<=password\ )[^\s]+/, 'NETRC_PASSWORD'],
    [/(?<=passwd\ )[^\s]+/, 'NETRC_PASSWORD'],
    [/(?<=password=)[^\s,;"'\}\[\]]+/, 'PASSWORD_VALUE'],
    [/(?<=password:)\s*[^\s,;"'\}\[\]]+/, 'PASSWORD_VALUE'],
    [/(?<=secret=)[^\s,;"'\}\[\]]+/, 'SECRET_VALUE'],
    [/(?<=secret:)\s*[^\s,;"'\}\[\]]+/, 'SECRET_VALUE'],
    [/(?<=token=)[^\s,;"'\}\[\]]+/, 'TOKEN_VALUE'],
    [/(?<=token:)\s*[^\s,;"'\}\[\]]+/, 'TOKEN_VALUE'],
    [%r{(?<=AccountKey=)[A-Za-z0-9+/]{88}==}, 'AZURE_STORAGE_KEY'],
    [/(?<=Password=)[^\s,;"'\}\[\]]+/, 'PASSWORD_VALUE'],
    [/(?<=Password:)\s*[^\s,;"'\}\[\]]+/, 'PASSWORD_VALUE'],
    [/(?<=Secret=)[^\s,;"'\}\[\]]+/, 'SECRET_VALUE'],
    [/(?<=Secret:)\s*[^\s,;"'\}\[\]]+/, 'SECRET_VALUE'],
    [/(?<=Token=)[^\s,;"'\}\[\]]+/, 'TOKEN_VALUE'],
    [/(?<=Token:)\s*[^\s,;"'\}\[\]]+/, 'TOKEN_VALUE'],
  ].freeze

  # Special patterns with capture groups
  # Each entry: { pattern: regex, label: string, secret_group: integer }
  SPECIAL_PATTERNS = {
    git_credential: {
      pattern: %r{(://[^:]+:)([^@]+)(@)},
      label: 'GIT_CREDENTIAL',
      secret_group: 2
    },
    docker_auth: {
      pattern: %r{("auth":\s*")([A-Za-z0-9+/=]{20,})(")},
      label: 'DOCKER_AUTH',
      secret_group: 2
    },
  }.freeze

  # Private key pattern (multiline, for batch mode fallback)
  PRIVATE_KEY_PATTERN = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/

  # Explicit secret variable names
  EXPLICIT_ENV_VARS = Set.new(%w[
    GITHUB_TOKEN GH_TOKEN GITLAB_TOKEN GLAB_TOKEN BITBUCKET_TOKEN
    AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AZURE_CLIENT_SECRET OPENAI_API_KEY ANTHROPIC_API_KEY
    CLAUDE_API_KEY SLACK_TOKEN SLACK_BOT_TOKEN SLACK_WEBHOOK_URL NPM_TOKEN
    PYPI_TOKEN DOCKER_PASSWORD DATABASE_URL REDIS_URL MONGODB_URI
    JWT_SECRET SESSION_SECRET ENCRYPTION_KEY SENDGRID_API_KEY TWILIO_AUTH_TOKEN
    STRIPE_SECRET_KEY DIGITALOCEAN_TOKEN DIGITALOCEAN_ACCESS_TOKEN HEROKU_API_KEY HEROKU_AUTH_TOKEN
    NETLIFY_AUTH_TOKEN VERCEL_TOKEN CLOUDFLARE_API_TOKEN CLOUDFLARE_API_KEY SUPABASE_SERVICE_ROLE_KEY
    SUPABASE_ANON_KEY PLANETSCALE_SERVICE_TOKEN NEON_API_KEY VAULT_TOKEN TF_TOKEN
    TFC_TOKEN TERRAFORM_CLOUD_TOKEN CONSUL_HTTP_TOKEN DISCORD_TOKEN DISCORD_BOT_TOKEN
    TELEGRAM_BOT_TOKEN DATADOG_API_KEY DATADOG_APP_KEY NEW_RELIC_LICENSE_KEY NEWRELIC_API_KEY
    SENTRY_DSN SENTRY_AUTH_TOKEN GRAFANA_API_KEY LINEAR_API_KEY DOPPLER_TOKEN
    SHOPIFY_ACCESS_TOKEN SHOPIFY_API_KEY SHOPIFY_API_SECRET MAILGUN_API_KEY ALGOLIA_API_KEY
    ALGOLIA_ADMIN_KEY FACEBOOK_ACCESS_TOKEN
  ]).freeze

  # Suffixes indicating secret variables
  ENV_SUFFIXES = %w[
    _SECRET _PASSWORD _TOKEN _API_KEY _PRIVATE_KEY _AUTH _CREDENTIAL
  ].freeze
end
