#!/usr/bin/env sh
set -eu

OUTPUT_FILE="${1:-.env.prod}"
FORCE="${2:-}"

if [ -f "${OUTPUT_FILE}" ] && [ "${FORCE}" != "--force" ]; then
    echo "Error: ${OUTPUT_FILE} already exists."
    echo "To overwrite, run: $0 ${OUTPUT_FILE} --force"
    exit 1
fi

generate_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "import secrets; print(secrets.token_hex(32))"
    else
        echo "Error: neither openssl nor python3 found to generate secure random secrets." >&2
        exit 1
    fi
}

echo "Generating secrets for ${OUTPUT_FILE}..."

PG_PASSWORD=$(generate_secret)
ADMIN_TOKEN=$(generate_secret)
TASKER_TOKEN=$(generate_secret)
WORKER_TOKEN=$(generate_secret)

cat <<EOF > "${OUTPUT_FILE}"
# Production environment configuration for Falcoria
# Generated on: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Database credentials
POSTGRES_PASSWORD=${PG_PASSWORD}

# Scanledger authentication tokens (seeded on startup)
SCANLEDGER_ADMIN_TOKEN=${ADMIN_TOKEN}
SCANLEDGER_TASKER_TOKEN=${TASKER_TOKEN}
SCANLEDGER_WORKER_TOKEN=${WORKER_TOKEN}

# Service ports and logging
TASKER_PORT=8000
LOG_LEVEL=INFO

# Application concurrency
SCANLEDGER_WORKERS=4
TASKER_WORKERS=4

# Worker execution tuning
WORKER_MAX_CONCURRENT_ACTIVITIES=1
WORKER_WINDOW_SIZE=20
EOF

chmod 600 "${OUTPUT_FILE}"
echo "Successfully created ${OUTPUT_FILE} with restricted permissions (0600)."
