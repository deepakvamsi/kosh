// Package storage is Kosh's persistence layer over SQLite (pure-Go driver
// modernc.org/sqlite, no CGO). It stores only ciphertext and non-secret metadata; it
// never sees or stores plaintext secrets or the master password.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a *sql.DB with Kosh-specific helpers.
type DB struct {
	sql *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path, hardens file
// permissions to the current OS user, enables foreign keys + WAL, and runs migrations.
func Open(path string) (*DB, error) {
	// _pragma options configure the connection on open.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)", path)
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open: %w", err)
	}
	sqldb.SetMaxOpenConns(1) // simplify WAL + write serialization for a desktop app
	if err := sqldb.Ping(); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("storage: ping: %w", err)
	}
	if err := migrate(sqldb); err != nil {
		sqldb.Close()
		return nil, err
	}
	if path != ":memory:" {
		if err := hardenPermissions(path); err != nil {
			sqldb.Close()
			return nil, err
		}
	}
	db := &DB{sql: sqldb}
	if err := db.seedProviders(); err != nil {
		sqldb.Close()
		return nil, err
	}
	return db, nil
}

// OpenMemory opens an in-memory database (used by tests).
func OpenMemory() (*DB, error) { return Open(":memory:") }

// Close closes the underlying database.
func (d *DB) Close() error { return d.sql.Close() }

// SQL exposes the underlying *sql.DB for advanced callers (vault package).
func (d *DB) SQL() *sql.DB { return d.sql }

func now() int64 { return time.Now().Unix() }

func (d *DB) seedProviders() error {
	type p struct {
		key, name, category string
	}
	// Built-in providers span the common surfaces where software teams hold credentials.
	// New rows are additive: INSERT OR IGNORE means an existing vault picks up additions on
	// the next open without disturbing user-added providers. Keys are stable identifiers;
	// never rename one (it is bound into a secret's associated data).
	builtins := []p{
		// Cloud platforms
		{"aws", "Amazon Web Services", "cloud"},
		{"gcp", "Google Cloud Platform", "cloud"},
		{"azure", "Microsoft Azure", "cloud"},
		{"digitalocean", "DigitalOcean", "cloud"},
		{"linode", "Akamai / Linode", "cloud"},
		{"oraclecloud", "Oracle Cloud (OCI)", "cloud"},
		{"ibmcloud", "IBM Cloud", "cloud"},
		{"heroku", "Heroku", "cloud"},
		{"render", "Render", "cloud"},
		{"railway", "Railway", "cloud"},
		{"flyio", "Fly.io", "cloud"},
		{"netlify", "Netlify", "cloud"},
		{"vercel", "Vercel", "cloud"},
		{"supabase", "Supabase", "cloud"},
		{"firebase", "Firebase", "cloud"},

		// Operating systems & endpoints
		{"windows", "Microsoft Windows", "os"},
		{"macos", "Apple macOS", "os"},
		{"linux", "Linux (generic)", "os"},
		{"ubuntu", "Ubuntu", "os"},
		{"debian", "Debian", "os"},
		{"redhat", "Red Hat", "os"},
		{"suse", "SUSE", "os"},
		{"apple", "Apple", "os"},

		// Infrastructure, containers & IaC
		{"docker", "Docker", "infra"},
		{"kubernetes", "Kubernetes", "infra"},
		{"helm", "Helm", "infra"},
		{"terraform", "Terraform", "infra"},
		{"ansible", "Ansible", "infra"},
		{"pulumi", "Pulumi", "infra"},
		{"hashicorpvault", "HashiCorp Vault", "infra"},
		{"consul", "HashiCorp Consul", "infra"},
		{"nomad", "HashiCorp Nomad", "infra"},

		// CI/CD
		{"githubactions", "GitHub Actions", "cicd"},
		{"jenkins", "Jenkins", "cicd"},
		{"circleci", "CircleCI", "cicd"},
		{"travisci", "Travis CI", "cicd"},
		{"argocd", "Argo CD", "cicd"},
		{"teamcity", "TeamCity", "cicd"},
		{"azuredevops", "Azure DevOps", "cicd"},

		// Version control
		{"github", "GitHub", "vcs"},
		{"gitlab", "GitLab", "vcs"},
		{"bitbucket", "Bitbucket", "vcs"},
		{"gitea", "Gitea", "vcs"},

		// Package & artifact registries
		{"npm", "npm", "registry"},
		{"pypi", "PyPI", "registry"},
		{"dockerhub", "Docker Hub", "registry"},
		{"ghcr", "GitHub Container Registry", "registry"},
		{"jfrog", "JFrog Artifactory", "registry"},
		{"nuget", "NuGet", "registry"},
		{"rubygems", "RubyGems", "registry"},
		{"maven", "Maven Central", "registry"},

		// Databases, caches & data warehouses
		{"postgresql", "PostgreSQL", "db"},
		{"mysql", "MySQL", "db"},
		{"mariadb", "MariaDB", "db"},
		{"mongodb", "MongoDB", "db"},
		{"redis", "Redis", "db"},
		{"elasticsearch", "Elasticsearch", "db"},
		{"cassandra", "Apache Cassandra", "db"},
		{"cockroachdb", "CockroachDB", "db"},
		{"clickhouse", "ClickHouse", "db"},
		{"influxdb", "InfluxDB", "db"},
		{"neo4j", "Neo4j", "db"},
		{"snowflake", "Snowflake", "db"},

		// Messaging, streaming & queues
		{"kafka", "Apache Kafka", "messaging"},
		{"rabbitmq", "RabbitMQ", "messaging"},
		{"nats", "NATS", "messaging"},

		// Monitoring & observability
		{"datadog", "Datadog", "monitoring"},
		{"sentry", "Sentry", "monitoring"},
		{"newrelic", "New Relic", "monitoring"},
		{"grafana", "Grafana", "monitoring"},
		{"prometheus", "Prometheus", "monitoring"},
		{"pagerduty", "PagerDuty", "monitoring"},
		{"splunk", "Splunk", "monitoring"},
		{"opsgenie", "Opsgenie", "monitoring"},

		// Communication, email & SMS
		{"slack", "Slack", "comms"},
		{"discord", "Discord", "comms"},
		{"microsoftteams", "Microsoft Teams", "comms"},
		{"twilio", "Twilio", "comms"},
		{"sendgrid", "SendGrid", "comms"},
		{"mailgun", "Mailgun", "comms"},
		{"postmark", "Postmark", "comms"},
		{"telegram", "Telegram", "comms"},

		// Payments & billing
		{"stripe", "Stripe", "payments"},
		{"paypal", "PayPal", "payments"},
		{"square", "Square", "payments"},
		{"razorpay", "Razorpay", "payments"},
		{"braintree", "Braintree", "payments"},
		{"adyen", "Adyen", "payments"},

		// Identity & auth
		{"auth0", "Auth0", "auth"},
		{"okta", "Okta", "auth"},
		{"clerk", "Clerk", "auth"},
		{"keycloak", "Keycloak", "auth"},
		{"onelogin", "OneLogin", "auth"},

		// AI / LLM providers
		{"openai", "OpenAI", "ai"},
		{"anthropic", "Anthropic", "ai"},
		{"gemini", "Google Gemini", "ai"},
		{"xai", "Grok / xAI", "ai"},
		{"mistral", "Mistral", "ai"},
		{"groq", "Groq", "ai"},
		{"deepseek", "DeepSeek", "ai"},
		{"openrouter", "OpenRouter", "ai"},
		{"huggingface", "Hugging Face", "ai"},
		{"cohere", "Cohere", "ai"},
		{"perplexity", "Perplexity", "ai"},
		{"replicate", "Replicate", "ai"},
		{"elevenlabs", "ElevenLabs", "ai"},

		// CDN & edge
		{"cloudflare", "Cloudflare", "cdn"},
		{"fastly", "Fastly", "cdn"},
		{"akamai", "Akamai", "cdn"},

		// Storage & object stores
		{"backblaze", "Backblaze B2", "storage"},
		{"wasabi", "Wasabi", "storage"},
		{"minio", "MinIO", "storage"},

		// Search
		{"algolia", "Algolia", "search"},
		{"meilisearch", "Meilisearch", "search"},

		// Analytics
		{"segment", "Segment", "analytics"},
		{"amplitude", "Amplitude", "analytics"},
		{"mixpanel", "Mixpanel", "analytics"},
		{"posthog", "PostHog", "analytics"},

		// Dev & productivity platforms
		{"cursor", "Cursor", "devtools"},
		{"replit", "Replit", "devtools"},
		{"figma", "Figma", "devtools"},
		{"linear", "Linear", "devtools"},
		{"jira", "Jira", "devtools"},
		{"confluence", "Confluence", "devtools"},
		{"notion", "Notion", "devtools"},

		// Cryptographic material & PKI (for key pairs, certs, tokens)
		{"ssh", "SSH key", "security"},
		{"gpg", "GPG / PGP key", "security"},
		{"tls", "TLS / SSL certificate", "security"},
		{"letsencrypt", "Let's Encrypt", "security"},

		{"custom", "Custom", "custom"},
	}
	ctx := context.Background()
	for _, b := range builtins {
		_, err := d.sql.ExecContext(ctx,
			`INSERT OR IGNORE INTO providers(key,name,category,is_builtin,created_at) VALUES(?,?,?,1,?)`,
			b.key, b.name, b.category, now())
		if err != nil {
			return fmt.Errorf("storage: seed provider %s: %w", b.key, err)
		}
	}
	return nil
}
