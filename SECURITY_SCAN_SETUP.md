# Security Scanning Setup

This document describes the security scanning workflow added to the home-security repository.

## Overview

The `.github/workflows/security-scan.yml` workflow provides comprehensive security scanning including:
- Secret detection (GitLeaks)
- Container image vulnerability scanning (Trivy)
- Configuration file scanning (Trivy)
- Python dependency vulnerability checking (Safety)
- Python code security linting (Bandit)
- Software Bill of Materials (SBOM) generation (Syft)
- License compliance checking (Licensecheck)

## Workflow Triggers

The security scan runs on:
- **Push** to `main` or `dev` branches
- **Pull requests** targeting `main`
- **Weekly schedule** - Every Monday at 2 AM UTC
- **Manual trigger** - Via GitHub Actions UI (`workflow_dispatch`)

## Required Permissions

```yaml
permissions:
  contents: read
  security-events: write  # For uploading SARIF results to Security tab
  issues: write          # For creating security alert issues
```

## Security Scans Performed

### 1. GitLeaks - Secret Detection
Scans the repository for exposed secrets, API keys, passwords, and tokens.

- **Config:** `.gitleaks.toml`
- **Severity:** CRITICAL, HIGH, MEDIUM
- **Output:** Fails workflow if secrets detected
- **Integration:** Results uploaded to GitHub Security tab via SARIF

### 2. Trivy - Filesystem Scan
Scans the entire repository for known vulnerabilities in files and configurations.

- **Scan type:** Filesystem (`fs`)
- **Scope:** Entire repository
- **Severity:** CRITICAL, HIGH, MEDIUM
- **Output:** SARIF format uploaded to GitHub Security tab

### 3. Trivy - Configuration Scan
Scans Docker Compose and Kubernetes configuration files for misconfigurations.

- **Scan type:** Configuration (`config`)
- **Target:** `v2.home-security.uk/compose.yaml`
- **Severity:** CRITICAL, HIGH, MEDIUM
- **Output:** Table format (console output)

### 4. Trivy - Third-Party Image Scans
Scans external Docker images used in the stack for vulnerabilities.

**Images scanned:**
- `docker.io/prom/prometheus:latest`
- `docker.io/ollama/ollama:latest`
- `cr.fluentbit.io/fluent/fluent-bit:3.2`

- **Severity:** CRITICAL, HIGH
- **Output:** Table format (console output)

### 5. Trivy - Custom Image Scans
Builds and scans custom Docker images for vulnerabilities.

**Images built and scanned:**
- `local/openobserve-test` (from `v2.home-security.uk/openobserve/Dockerfile`)
- `local/security-ai-test` (from `v2.home-security.uk/security-ai/Dockerfile`)
- `local/ansible-ai-test` (from `v2.home-security.uk/ansible-ai/Dockerfile`)
- `local/worker-image-test` (from `v2.home-security.uk/worker-image/Dockerfile`)

- **Severity:** CRITICAL, HIGH
- **Note:** Build failures don't fail the workflow (continue-on-error)
- **Output:** Table format (console output)

### 6. Safety - Python Dependency Vulnerability Check
Scans Python `requirements.txt` files for known vulnerable dependencies.

**Targets:**
- `v2.home-security.uk/security-ai/requirements.txt` (if exists)
- `v2.home-security.uk/ansible-ai/requirements.txt` (if exists)

- **Output:** JSON and console formats
- **Note:** Failures don't fail the workflow (continue-on-error)

### 7. Bandit - Python Security Linter
Scans Python source code for common security issues.

**Targets:**
- `v2.home-security.uk/security-ai/`
- `v2.home-security.uk/ansible-ai/`
- `v2.home-security.uk/scripts/`

- **Output:** JSON format
- **Note:** Failures don't fail the workflow (continue-on-error)

### 8. Syft - SBOM Generation
Generates Software Bill of Materials (SBOM) for custom images.

**Targets:**
- `local/openobserve-test:latest`
- `local/security-ai-test:latest`

- **Format:** SPDX JSON
- **Output:** Uploaded as workflow artifacts

### 9. Licensecheck - License Compliance
Checks Python packages for license compliance.

**Targets:**
- `v2.home-security.uk/security-ai/`
- `v2.home-security.uk/ansible-ai/`

- **Output:** JSON format
- **Note:** Failures don't fail the workflow (continue-on-error)

## Workflow Artifacts

The following artifacts are uploaded and retained for 90 days:

- `sbom-*.spdx.json` - SBOM files from Syft
- `trivy-results.sarif` - Trivy SARIF results
- `safety-report.json` - Safety vulnerability report
- `bandit-*.json` - Bandit security linting reports

## Security Alert Issue Creation

If the workflow fails (due to GitLeaks finding secrets or Trivy filesystem scan finding critical vulnerabilities), an issue is automatically created with:

- **Title:** 🚨 Security Alert: Vulnerability or Secret Detected
- **Labels:** `security`, `critical`
- **Body:** Actionable steps and resources
- **Workflow link:** Direct link to the failed run

## GitLeaks Configuration

The `.gitleaks.toml` file configures secret detection with:

### Extended Rules
- Uses default Gitleaks rules (`useDefault = true`)

### Allowlist Paths
- `.gitleaks.toml` - The config file itself
- `.env.example` - Example environment files
- `.env` - Local environment files (should be gitignored)
- Binary files (jpg, gif, png, pdf, bin)
- Test scripts
- Git directory
- Dependency directories (node_modules, vendor)
- Generated artifacts (`v2.home-security.uk/artifacts/generated/`)
- Ansible state (`v2.home-security.uk/ansible-ai/state/`)
- Python cache (`__pycache__/`, `.pyc`)

### Allowlist Regexes
- `REPLACE_WITH_` - Placeholder strings
- `YOUR_.*_HERE` - Generic placeholders
- `CHANGE_ME` - Change placeholders
- `<.*>` - XML/HTML tags
- Common words in comments/docs: `password`, `secret`, `token`, `api_key`

## Customization

### Adding New Image Scans

To scan additional Docker images, add:

```yaml
- name: Scan custom <image-name> image
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: 'image'
    image-ref: 'your-image:tag'
    format: 'table'
    severity: 'CRITICAL,HIGH'
    exit-code: '0'
```

### Changing Severity Levels

Modify the `severity` parameter in Trivy steps:
- `CRITICAL,HIGH,MEDIUM,LOW` - All vulnerabilities
- `CRITICAL,HIGH` - Only critical and high
- `CRITICAL` - Only critical

### Adding Custom GitLeaks Rules

Add custom rules to `.gitleaks.toml`:

```toml
[[rules]]
id = "custom-api-key"
description = "Custom API key pattern"
regex = '''your-regex-pattern'''
secretGroup = 1
entropy = 3.5
keywords = ["api_key", "apikey"]
```

### Disabling Specific Scans

To disable a scan, add `if: false` to the step:

```yaml
- name: Run bandit security linter
  if: false  # Disabled
  run: ...
```

## Viewing Results

### GitHub Security Tab
Navigate to: `https://github.com/<owner>/<repo>/security`

This shows:
- Code scanning alerts (from Trivy SARIF upload)
- Secret scanning alerts (from GitLeaks)

### Workflow Run Logs
Navigate to: `Actions > Security Scan > <run>`

View detailed output from each scan step.

### Workflow Artifacts
After a run completes, download artifacts from the workflow run page.

## Recommendations

### Immediate Actions
1. **Review the first workflow run** - Check for any existing secrets or vulnerabilities
2. **Fix HIGH/CRITICAL findings** - Prioritize these for remediation
3. **Review allowlist** - Ensure `.gitleaks.toml` allowlist is appropriate

### Ongoing Maintenance
1. **Update Trivy database** - Trivy automatically updates its vulnerability database
2. **Review weekly runs** - Check scheduled Monday runs for new vulnerabilities
3. **Update custom images** - Rebuild and scan when base images change
4. **Review dependencies** - Keep Python dependencies updated to avoid known vulnerabilities

### Best Practices
1. **Don't suppress all failures** - Use `continue-on-error` only for non-critical scans
2. **Review SARIF results** - The GitHub Security tab provides a good overview
3. **Keep SBOMs** - Download and retain SBOMs for compliance and auditing
4. **License compliance** - Review license reports for policy violations

## Troubleshooting

### Workflow Fails on Custom Image Build
- Check Dockerfile syntax
- Ensure all build contexts are present
- Review build logs in the workflow run

### GitLeaks False Positives
- Add the pattern to `.gitleaks.toml` allowlist regexes
- Add the file path to allowlist paths
- Review if the finding is actually a secret

### Trivy Scans Timeout
- Reduce scan scope (fewer images)
- Increase GitHub Actions timeout
- Scan images separately in multiple workflows

### Python Scans Fail
- Ensure `requirements.txt` files exist
- Check Python version compatibility
- Review scan logs for specific errors

## References

- [GitLeaks Documentation](https://github.com/gitleaks/gitleaks)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Safety Documentation](https://pyup.io/safety/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Syft Documentation](https://github.com/anchore/syft)
- [GitHub Advanced Security](https://docs.github.com/en/code-security)

## Version History

- **2026-10-28** - Initial security scanning workflow setup
  - Added GitLeaks secret detection
  - Added Trivy filesystem, config, and image scanning
  - Added Safety dependency checking
  - Added Bandit Python security linting
  - Added Syft SBOM generation
  - Added Licensecheck compliance checking
  - Added automated security alert issue creation
