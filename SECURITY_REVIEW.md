# Security Review: ~/workspace/home-security

**Date:** 2026-10-28
**Reviewer:** Devin Security Audit
**Scope:** ~/workspace/home-security (v2.home-security.uk home security stack)
**Mode:** Focused review

---

## Executive Summary

This review examined the home security stack repository for security concerns. The repository contains a containerized security monitoring system with OpenObserve, Prometheus, Ollama, Fluent Bit, and AI analysis workers. Several security issues were identified ranging from credential exposure risks to host privilege escalation patterns.

**Findings Summary:**
- 1 High severity
- 3 Medium severity
- 2 Low severity
- 2 Informational

---

## Findings

### 🔴 HIGH: Credentials Exposed in Repository

**Location:** `v2.home-security.uk/.env`

**Description:**
The `.env` file contains actual production credentials and is tracked in the workspace directory. While the `.gitignore` file at the workspace root includes `.env`, the file exists in the repository with sensitive data.

**Evidence:**
```bash
$ cat v2.home-security.uk/.env
OPENOBSERVE_USER=dummykevin08@gmail.com
OPENOBSERVE_PASSWORD=SuperDuperPassword123!
```

**Impact:**
- Credentials are stored in plaintext on disk
- If the workspace is synced or backed up, credentials may be exposed
- The password appears to be a weak example password that may be in use

**Affected Principal:** System administrator / account holder
**Boundary:** Credential storage
**Result:** Unauthorized access to OpenObserve dashboard and API

**Recommendation:**
1. Immediately rotate the OpenObserve password
2. Remove the `.env` file from the workspace
3. Create a new `.env` file from `.env.example` with a strong, unique password
4. Ensure `.env` is never committed to version control
5. Consider using a secret management system (e.g., HashiCorp Vault, Ansible Vault, or environment-specific files)

**Severity:** HIGH - Credentials are directly exposed in the workspace

---

### 🟡 MEDIUM: Host Command Execution Pattern

**Location:** `scripts/host-exec.sh`, `scripts/launch-stack.sh`

**Description:**
Multiple scripts use `flatpak-spawn --host` to execute commands in the host namespace from within a Toolbox container. This pattern allows arbitrary command execution on the host system.

**Evidence:**
```bash
# scripts/host-exec.sh
if [[ -e /run/.toolboxenv ]]; then
  command -v flatpak-spawn >/dev/null || { echo "flatpak-spawn is required inside Toolbox." >&2; exit 1; }
  exec flatpak-spawn --host "$@"
fi
exec "$@"
```

**Impact:**
- Any user who can execute these scripts can run arbitrary commands on the host
- The pattern is used in various scripts including `launch-stack.sh` which starts containers
- No authentication or authorization is performed before host command execution

**Affected Principal:** Local user executing scripts
**Boundary:** Container host isolation
**Result:** Unauthorized host command execution

**Recommendation:**
1. Add explicit user confirmation before host command execution
2. Consider using sudo with specific command allowlists instead of blanket host access
3. Document the security implications in the scripts
4. Limit which scripts are allowed to use the host-exec pattern
5. Consider running the entire stack directly on the host instead of inside Toolbox if host access is required

**Severity:** MEDIUM - Requires local user access, but provides broad host command execution

---

### 🟡 MEDIUM: Weak Default Password in Example

**Location:** `v2.home-security.uk/.env.example`

**Description:**
The `.env.example` file contains a placeholder password that is extremely weak (`password`).

**Evidence:**
```bash
OPENOBSERVE_PASSWORD=password
```

**Impact:**
- Users may copy the example file and deploy with the weak password
- The password is a dictionary word and provides no security
- If deployed publicly, the system would be immediately compromised

**Affected Principal:** Deployers who copy the example
**Boundary:** Authentication
**Result:** Unauthorized access if example is used in production

**Recommendation:**
1. Change the example password to a strong random string or use a placeholder like `CHANGE_ME_STRONG_PASSWORD_HERE`
2. Add a comment warning that the password must be changed before deployment
3. Consider using a password generator in the setup script
4. Add validation that rejects the default password on startup

**Severity:** MEDIUM - Requires user action to be exploitable, but the example itself is dangerous

---

### 🟡 MEDIUM: Unbounded Privilege Escalation in Ansible Workflows

**Location:** `.github/workflows/apply-host-security-changes.yml`

**Description:**
The GitHub Actions workflow uses `TARGET_SUDO_PASSWORD` for privilege escalation via Ansible's `--become` flag. This allows the workflow to execute arbitrary commands with root privileges on the target host.

**Evidence:**
From documentation:
```
Required GitHub Secrets:
- TARGET_SUDO_PASSWORD - Sudo password for privilege escalation (--become)
```

**Impact:**
- If the GitHub Actions secret is compromised, an attacker can execute arbitrary commands as root on the target host
- The workflow does not appear to limit which Ansible playbooks can be run
- No evidence of playbook allowlisting or command restrictions

**Affected Principal:** GitHub Actions runner / anyone with secret access
**Boundary:** Remote privilege escalation
**Result:** Full host compromise

**Recommendation:**
1. Use SSH key-based authentication instead of password-based sudo
2. Implement playbook allowlisting - only allow specific, reviewed playbooks to run
3. Use GitHub Actions OIDC (OpenID Connect) with specific role assumptions instead of static secrets
4. Add audit logging for all Ansible playbook executions
5. Consider using a dedicated deployment user with limited sudo capabilities instead of full root access

**Severity:** MEDIUM - Requires secret compromise, but provides full root access

---

### 🟢 LOW: Missing SELinux Context on Volume Mounts

**Location:** `v2.home-security.uk/compose.yaml`

**Description:**
Some volume mounts in the compose file do not have the `:Z` SELinux relabel flag, which may cause permission issues or security context misconfiguration on SELinux-enabled systems.

**Evidence:**
```yaml
volumes:
  - openobserve_data:/data  # No :Z flag
  - ollama_data:/root/.ollama  # No :Z flag
  - prometheus_data:/prometheus  # No :Z flag
```

**Impact:**
- Named volumes may not have proper SELinux contexts
- Containers may fail to start or have restricted access on SELinux systems
- Inconsistent security policy enforcement

**Affected Principal:** Container processes
**Boundary:** SELinux policy enforcement
**Result:** Potential startup failures or reduced security isolation

**Recommendation:**
1. Add `:z` (lowercase) for shared volume mounts to allow relabeling
2. Test on SELinux-enabled systems to ensure proper behavior
3. Document SELinux requirements in the README

**Severity:** LOW - Affects functionality and consistency, not directly exploitable

---

### 🟢 LOW: Duplicate Function Definition in Launch Script

**Location:** `scripts/launch-stack.sh`

**Description:**
The `animate_command` function is defined twice (lines 279-355 and 361-435), which suggests copy-paste error and could lead to confusion or maintenance issues.

**Evidence:**
```bash
# Lines 279-355
animate_command() {
    # ... implementation
}

# Lines 361-435 (duplicate)
animate_command() {
    # ... identical implementation
}
```

**Impact:**
- Maintenance burden - changes must be made in two places
- Potential for divergence if one copy is modified but not the other
- No direct security impact, but reduces code quality

**Affected Principal:** Maintainers
**Boundary:** Code maintenance
**Result:** Potential for bugs or inconsistencies

**Recommendation:**
1. Remove the duplicate function definition
2. Keep only one implementation (the second one at lines 361-435)

**Severity:** LOW - Code quality issue, no direct security impact

---

### ℹ️ INFORMATIONAL: Good Secret Management Practices Observed

**Location:** Multiple files

**Description:**
The repository demonstrates several good security practices:

1. **Environment variable usage**: Compose file uses environment variables for credentials instead of hardcoding them
2. **Gitignore configuration**: `.gitignore` properly excludes `.env` files
3. **Localhost binding**: Services are bound to `127.0.0.1` by default
4. **Non-root containers**: Containers use specific user namespaces where applicable
5. **Resource limits**: Memory and CPU limits are set on containers

**Evidence:**
```yaml
ports:
  - "127.0.0.1:${OPENOBSERVE_PORT:-5080}:5080/tcp"  # Localhost only
environment:
  ZO_ROOT_USER_PASSWORD: ${OPENOBSERVE_PASSWORD:?Set OPENOBSERVE_PASSWORD in .env}
```

**Recommendation:**
Continue these practices. Consider adding:
- Network policies between containers
- Secrets rotation documentation
- Backup and recovery procedures for credentials

**Severity:** INFORMATIONAL - Positive security practices

---

### ℹ️ INFORMATIONAL: Documentation Needs Security Hardening Section

**Location:** `docs/` directory

**Description:**
The documentation is comprehensive but lacks a dedicated security hardening or threat model section.

**Recommendation:**
Add a `docs/SECURITY_HARDENING.md` file covering:
1. Threat model and trust boundaries
2. Recommended deployment patterns (network isolation, bastion hosts)
3. Credential rotation procedures
4. Audit logging and monitoring
5. Incident response procedures
6. Backup and recovery for security data
7. Network firewall recommendations
8. SELinux/AppArmor hardening

**Severity:** INFORMATIONAL - Documentation improvement

---

### ℹ️ INFORMATIONAL: Security Scanning Workflow Added

**Location:** `.github/workflows/security-scan.yml`, `.gitleaks.toml`

**Description:**
A comprehensive security scanning workflow has been added to the repository. This workflow provides automated security scanning on push, pull requests, and weekly schedules.

**Scans included:**
- GitLeaks for secret detection
- Trivy for filesystem, configuration, and container image vulnerability scanning
- Safety for Python dependency vulnerability checking
- Bandit for Python code security linting
- Syft for SBOM generation
- Licensecheck for license compliance

**Recommendation:**
- Review the first workflow run for any existing vulnerabilities
- Fix HIGH/CRITICAL findings before deploying to production
- Review the `.gitleaks.toml` allowlist for appropriateness
- See `SECURITY_SCAN_SETUP.md` for detailed configuration and customization

**Severity:** INFORMATIONAL - Positive security improvement

---

## Recommendations Summary

### Immediate Actions (Do Now)
1. **Rotate OpenObserve password** - The current password is exposed in the workspace
2. **Remove `.env` from workspace** - Delete the file with credentials
3. **Generate new strong password** - Use a password manager or generator
4. **Remove duplicate function** - Clean up `launch-stack.sh`

### Short-term Actions (This Week)
1. **Update `.env.example`** - Replace weak password with strong placeholder
2. **Add SELinux context flags** - Add `:z` to named volume mounts
3. **Add user confirmation** - Require confirmation before host command execution
4. **Implement playbook allowlisting** - Restrict which Ansible playbooks can run

### Long-term Actions (This Month)
1. **Switch to SSH key auth** - Replace password-based sudo with SSH keys
2. **Implement OIDC** - Use GitHub Actions OIDC instead of static secrets
3. **Add security documentation** - Create `docs/SECURITY_HARDENING.md`
4. **Consider secret management** - Evaluate HashiCorp Vault or similar

---

## Coverage Statement

This focused review examined:
- Credential management (`.env`, `.env.example`, compose.yaml)
- Host command execution patterns
- GitHub Actions workflows
- Container security configuration
- Script quality and maintenance

**Not covered:**
- Container image vulnerabilities (base images not scanned)
- Network traffic analysis (no network inspection performed)
- Runtime behavior (containers not running during review)
- Application-level vulnerabilities (Python code not audited in depth)
- Third-party dependency vulnerabilities
- SELinux/AppArmor policy effectiveness
- Backup and recovery procedures

This is a focused review, not a comprehensive security audit. A full audit would require additional reconnaissance, threat modeling, and vulnerability scanning.

---

## Next Steps

1. **Address HIGH severity finding** immediately (credential rotation)
2. **Address MEDIUM severity findings** within 1 week
3. **Address LOW severity findings** at next maintenance window
4. **Review security scanning workflow** - Check the first run for vulnerabilities
5. **Consider a full security audit** if this system will be deployed in a production or sensitive environment

## Files Added in This Session

1. **`.github/workflows/security-scan.yml`** - Comprehensive security scanning workflow
2. **`.gitleaks.toml`** - GitLeaks configuration for secret detection
3. **`SECURITY_SCAN_SETUP.md`** - Documentation for the security scanning workflow

## Security Improvements Made

- Automated secret detection with GitLeaks
- Comprehensive vulnerability scanning with Trivy (filesystem, config, images)
- Python dependency checking with Safety
- Python code security linting with Bandit
- SBOM generation with Syft
- License compliance checking with Licensecheck
- Automated security alert issue creation on critical findings

---

**Review completed:** 2026-10-28
**Review method:** Static analysis and pattern review
**Review limitations:** No runtime testing, no network analysis, no dependency scanning
