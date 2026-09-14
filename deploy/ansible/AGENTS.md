# AGENTS.md (Deployment & Ansible)

Rules and reference for agents working on deployment automation and multi-node
infrastructure in `deploy/ansible/`.

## Architecture Overview

Falcoria multi-node deployment separates the stack into two tiers:

1. **Control Plane (`control_plane`)**:
   - Runs Caddy, PostgreSQL, Temporal Server, Scanledger, and Tasker via Docker Compose.
   - **Zero-Trust port exposure**: Only Caddy binds to external host ports (`80` and `443`). PostgreSQL (`5432`), Temporal gRPC (`7233`), Scanledger (`8000`), and Tasker (`8000`) MUST NOT publish host ports.
   - Internal inter-service communication (Tasker -> Scanledger, Tasker -> Temporal) happens over the private Docker bridge network (`falcoria-internal`) in cleartext/h2c.
   - External communication (Workers -> Scanledger, Workers -> Temporal, external Web/CLI clients) terminates at Caddy on port `443`.
   - Caddy handles TLS termination (Let's Encrypt / ZeroSSL) and enforces mutual TLS (`client_auth: require_and_verify`) for Temporal gRPC on `temporal.<domain>:443`.

2. **Workers (`workers`)**:
   - Run `falcoria-worker` containers with `network_mode: host` and `cap_add: [NET_RAW, NET_ADMIN]` required for raw SYN/UDP scanning.
   - Connect to Scanledger via HTTPS (`https://ledger.<domain>/api`).
   - Connect to Temporal gRPC via mTLS over HTTPS (`temporal.<domain>:443`) using client certificate and key.

## PKI & Certificate Management

- All TLS certificates are generated declaratively via native `community.crypto` Ansible modules.
- Do NOT use ad-hoc shell scripts (`openssl req ...`) or manual CA tools.
- Control Plane maintains the Root CA (`ca.key`, `ca.crt`) in `/opt/falcoria/pki/ca/`.
- Worker certificates (`client.key`, `client.crt`) are generated and signed by the Root CA on the Control Plane, fetched to the deployment runner in `/tmp/falcoria-pki/`, and distributed to workers with mode `0600`.
- Cert paths on workers: `/etc/falcoria/certs/`.

## Prerequisites & Dependencies

Run all Ansible operations from `deploy/ansible/`:

```bash
ansible-galaxy collection install -r requirements.yml
```

Collections required:
- `community.crypto` (X.509 keys, CSRs, certificates)
- `community.general` (UFW firewall rules)
- `ansible.posix` (sysctl parameter tuning)

## Running Playbooks

Always check syntax and run dry-runs before applying:

```bash
# 1. Syntax check
ansible-playbook --syntax-check playbooks/site.yml

# 2. Dry run
ansible-playbook -i inventory/hosts.ini playbooks/site.yml --check --diff

# 3. Deploy full stack
ansible-playbook -i inventory/hosts.ini playbooks/site.yml --ask-vault-pass

# 4. Target only Control Plane or Workers
ansible-playbook -i inventory/hosts.ini playbooks/control_plane.yml --ask-vault-pass
ansible-playbook -i inventory/hosts.ini playbooks/workers.yml --ask-vault-pass
```

## Invariants & Guardrails

- **Zero-Trust Ports**: Never add `ports:` to PostgreSQL, Temporal, Scanledger, or Tasker in `docker-compose.control-plane.yaml.j2`. Caddy is the sole ingress gateway.
- **Worker Networking**: Worker containers require `network_mode: host` for Nmap raw socket access. Do not place workers on bridge networks.
- **Secrets Management**: Never commit plain passwords or tokens. Use `ansible-vault` for `group_vars/vault.yml`.
- **Idempotence**: All tasks must be safe to re-run. Do not write non-idempotent `command` or `shell` tasks when native Ansible modules exist.
