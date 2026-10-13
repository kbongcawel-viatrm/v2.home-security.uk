#!/usr/bin/env bash
# Simulate deployment workflow locally
# This script tests all components of the deployment without actually deploying
#
# Usage: ./scripts/simulate-deployment.sh
#
# What this tests:
# 1. Repository structure and required files
# 2. YAML syntax validation
# 3. Python script syntax
# 4. Ansible playbook validation
# 5. Artifact validation
# 6. SSH configuration script
# 7. Process firewalld blocks script (dry-run)
# 8. Ansible check mode (dry-run) - requires ansible installed

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; WARN=$((WARN+1)); }
section() { echo ""; echo -e "${BLUE}=== $1 ===${NC}"; }

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PROJECT_DIR/.." && pwd)"

cd "$PROJECT_DIR" || exit 1

section "DEPLOYMENT SIMULATION"
info "Project directory: $PROJECT_DIR"
info "Repository root: $REPO_ROOT"
echo ""

# ============================================
# 1. Check Repository Structure
# ============================================
section "1. Repository Structure"

required_files=(
    "compose.yaml"
    ".env.example"
    "containers-policy.json"
    "STACK.md"
    "security-ai/worker.py"
    "security-ai/ansible_agent.py"
    "security-ai/Dockerfile"
    "ansible/playbooks/deploy-suricata-rules.yml"
    "ansible/playbooks/block-ip-firewalld.yml"
    "ansible/playbooks/block-service-firewalld.yml"
    "ansible/playbooks/rollback-firewalld.yml"
    "scripts/validate-local-playbooks.py"
    "scripts/process-firewalld-blocks.py"
    "scripts/setup-ssh.sh"
    "scripts/ssh_config.hardened"
    "artifacts/suricata.rules"
    "artifacts/firewalld-blocks.json"
)

for file in "${required_files[@]}"; do
    if [[ -f "$file" ]]; then
        pass "Found: $file"
    else
        fail "Missing: $file"
    fi
done

# Check workflow files at root
workflow_files=(
    "$REPO_ROOT/.github/workflows/deploy-v2-stack.yml"
    "$REPO_ROOT/.github/workflows/apply-host-security-changes.yml"
    "$REPO_ROOT/.github/workflows/ansible-local.yml"
)

for file in "${workflow_files[@]}"; do
    if [[ -f "$file" ]]; then
        pass "Found workflow: $(basename "$file")"
    else
        fail "Missing workflow: $file"
    fi
done

# ============================================
# 2. YAML Syntax Validation
# ============================================
section "2. YAML Syntax Validation"

if command -v python3 &>/dev/null; then
    for yml in "$REPO_ROOT"/.github/workflows/*.yml compose.yaml; do
        if [[ -f "$yml" ]]; then
            if python3 -c "import yaml; yaml.safe_load(open('$yml'))" 2>/dev/null; then
                pass "YAML valid: $(basename "$yml")"
            else
                fail "YAML invalid: $yml"
            fi
        fi
    done
else
    warn "python3 not found, skipping YAML validation"
fi

# ============================================
# 3. Python Script Syntax
# ============================================
section "3. Python Script Syntax"

python_scripts=(
    "security-ai/worker.py"
    "security-ai/ansible_agent.py"
    "scripts/validate-local-playbooks.py"
    "scripts/process-firewalld-blocks.py"
)

for script in "${python_scripts[@]}"; do
    if [[ -f "$script" ]]; then
        if python3 -c "import ast; ast.parse(open('$script').read())" 2>/dev/null; then
            pass "Python syntax OK: $script"
        else
            fail "Python syntax error: $script"
        fi
    fi
done

# ============================================
# 4. Bash Script Syntax
# ============================================
section "4. Bash Script Syntax"

bash_scripts=(
    "scripts/setup-ssh.sh"
    "scripts/debug-sshd.sh"
    "scripts/host-exec.sh"
)

for script in "${bash_scripts[@]}"; do
    if [[ -f "$script" ]]; then
        if bash -n "$script" 2>/dev/null; then
            pass "Bash syntax OK: $script"
        else
            fail "Bash syntax error: $script"
        fi
        # Check if executable
        if [[ -x "$script" ]]; then
            pass "Executable: $script"
        else
            warn "Not executable: $script (run: chmod +x $script)"
        fi
    fi
done

# ============================================
# 5. Ansible Playbook Validation
# ============================================
section "5. Ansible Playbook Validation"

if command -v ansible-playbook &>/dev/null; then
    info "Ansible version: $(ansible-playbook --version | head -1)"
    
    # Run the validator
    if python3 scripts/validate-local-playbooks.py ansible/playbooks 2>&1; then
        pass "Playbook policy validation passed"
    else
        fail "Playbook policy validation failed"
    fi
    
    # Syntax check all playbooks
    for playbook in ansible/playbooks/*.yml; do
        if [[ -f "$playbook" ]]; then
            if ansible-playbook --inventory 'localhost,' --connection local --syntax-check "$playbook" &>/dev/null; then
                pass "Ansible syntax OK: $(basename "$playbook")"
            else
                fail "Ansible syntax error: $playbook"
            fi
        fi
    done
    
    # Check mode (dry-run) for deploy-suricata-rules
    info "Running check mode (dry-run) for deploy-suricata-rules.yml..."
    if ansible-playbook --inventory 'localhost,' --connection local --check --diff ansible/playbooks/deploy-suricata-rules.yml &>/dev/null; then
        pass "Check mode preview OK: deploy-suricata-rules.yml"
    else
        warn "Check mode had issues (expected if suricata not installed locally)"
    fi
else
    warn "ansible-playbook not found, skipping Ansible validation"
    info "Install with: pip install ansible-core"
fi

# ============================================
# 6. Artifact Validation
# ============================================
section "6. Artifact Validation"

# Validate suricata.rules
if [[ -f artifacts/suricata.rules ]]; then
    pass "suricata.rules exists"
    
    # Check for non-comment, non-empty lines
    rule_count=$(grep -v '^#' artifacts/suricata.rules | grep -v '^$' | wc -l)
    info "Total rules (non-comment): $rule_count"
    
    # Check for alert rules
    alert_count=$(grep -c '^alert' artifacts/suricata.rules || true)
    info "Alert rules: $alert_count"
    
    # Check for multi-line rules (should be single-line)
    if grep -P '^[^#].*[^;]$' artifacts/suricata.rules | grep -v '^$' &>/dev/null; then
        warn "Possible multi-line rules found (all rules should end with ;)"
    else
        pass "All rules appear to be single-line"
    fi
    
    # Check for duplicate SIDs
    duplicate_sids=$(grep -oP 'sid:\K\d+' artifacts/suricata.rules | sort | uniq -d)
    if [[ -n "$duplicate_sids" ]]; then
        fail "Duplicate SIDs found: $duplicate_sids"
    else
        pass "No duplicate SIDs"
    fi
else
    fail "suricata.rules not found"
fi

# Validate firewalld-blocks.json
if [[ -f artifacts/firewalld-blocks.json ]]; then
    pass "firewalld-blocks.json exists"
    
    if python3 -c "import json; json.load(open('artifacts/firewalld-blocks.json'))" 2>/dev/null; then
        pass "Valid JSON format"
        
        # Count blocks
        block_count=$(python3 -c "import json; print(len(json.load(open('artifacts/firewalld-blocks.json')).get('blocks', [])))" 2>/dev/null || echo "0")
        info "Number of blocks: $block_count"
    else
        fail "Invalid JSON format"
    fi
else
    fail "firewalld-blocks.json not found"
fi

# ============================================
# 7. SSH Configuration Script Test
# ============================================
section "7. SSH Configuration Script"

if [[ -f scripts/setup-ssh.sh ]]; then
    pass "setup-ssh.sh exists"
    
    # Test with dummy values (should fail gracefully)
    info "Testing setup-ssh.sh with dummy values (expected to fail at connection)..."
    if SSH_KEY="dummy-key" TARGET_HOST="192.0.2.1" TARGET_USER="test" timeout 5 bash scripts/setup-ssh.sh 2>&1 | grep -q "SSH connection test failed"; then
        pass "Script handles connection failure gracefully"
    else
        warn "Script behavior unclear (may have different error handling)"
    fi
else
    fail "setup-ssh.sh not found"
fi

# ============================================
# 8. Process Firewalld Blocks (Dry-Run)
# ============================================
section "8. Process Firewalld Blocks Script"

if [[ -f scripts/process-firewalld-blocks.py ]]; then
    pass "process-firewalld-blocks.py exists"
    
    # Test --help
    if python3 scripts/process-firewalld-blocks.py --help &>/dev/null; then
        pass "Script --help works"
    else
        fail "Script --help failed"
    fi
    
    # Test with check mode (should fail at ansible but script should run)
    info "Testing process-firewalld-blocks.py in check mode..."
    if python3 scripts/process-firewalld-blocks.py --check 2>&1 | grep -q "CHECK MODE\|No firewalld blocks file\|Processing"; then
        pass "Script runs in check mode"
    else
        warn "Script check mode output unclear"
    fi
else
    fail "process-firewalld-blocks.py not found"
fi

# ============================================
# 9. Environment Check
# ============================================
section "9. Environment Check"

# Check required commands
commands=("python3" "bash" "git")
for cmd in "${commands[@]}"; do
    if command -v "$cmd" &>/dev/null; then
        pass "Found command: $cmd ($(command -v "$cmd"))"
    else
        fail "Missing command: $cmd"
    fi
done

# Check optional commands
optional_commands=("ansible-playbook" "podman" "ssh" "scp")
for cmd in "${optional_commands[@]}"; do
    if command -v "$cmd" &>/dev/null; then
        pass "Found optional command: $cmd"
    else
        warn "Missing optional command: $cmd"
    fi
done

# ============================================
# 10. Git Status
# ============================================
section "10. Git Status"

if command -v git &>/dev/null; then
    cd "$REPO_ROOT" || exit 1
    
    current_branch=$(git branch --show-current 2>/dev/null || echo "unknown")
    info "Current branch: $current_branch"
    
    if [[ "$current_branch" == "v2.0" ]]; then
        pass "On correct branch: v2.0"
    else
        warn "Not on v2.0 branch (current: $current_branch)"
    fi
    
    # Check if clean
    if [[ -z "$(git status --porcelain 2>/dev/null)" ]]; then
        pass "Working tree is clean"
    else
        warn "Working tree has uncommitted changes"
        git status --short | head -5
    fi
    
    # Check if up to date with remote
    git fetch origin v2.0 2>/dev/null || true
    local_commit=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
    remote_commit=$(git rev-parse origin/v2.0 2>/dev/null || echo "unknown")
    
    if [[ "$local_commit" == "$remote_commit" ]]; then
        pass "Up to date with origin/v2.0"
    else
        warn "Local and remote may be out of sync"
        info "Local:  $local_commit"
        info "Remote: $remote_commit"
    fi
    
    cd "$PROJECT_DIR" || exit 1
fi

# ============================================
# Summary
# ============================================
section "SIMULATION SUMMARY"

echo ""
echo -e "${GREEN}Passed:${NC}  $PASS"
echo -e "${RED}Failed:${NC}  $FAIL"
echo -e "${YELLOW}Warnings:${NC} $WARN"
echo ""

TOTAL=$((PASS + FAIL))
if [[ $TOTAL -gt 0 ]]; then
    SCORE=$((PASS * 100 / TOTAL))
    echo "Score: $SCORE% ($PASS/$TOTAL)"
fi

echo ""
if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}✓ All critical checks passed! Ready for deployment.${NC}"
    exit 0
else
    echo -e "${RED}✗ $FAIL check(s) failed. Please fix before deployment.${NC}"
    exit 1
fi
