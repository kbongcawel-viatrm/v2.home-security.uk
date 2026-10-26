watch -n 1 '
echo "=== Container Resource Limits ==="
echo "---------------------------------"
printf "%-20s %12s %15s %16s\n" "NAME" "MEMORY(GB)" "CPU_QUOTA(ms)" "CPU_PERIOD(ms)"
printf "%s\n" "-----------------------------------------------------------------------"

podman inspect --format "{{.Name}} {{.HostConfig.Memory}} {{.HostConfig.CpuQuota}} {{.HostConfig.CpuPeriod}}" \
  openobserve ollama fluent-bit security-ai ansible-ai 2>&1 |
while read -r name memory cpu_quota cpu_period; do
    memory_gb=$(awk -v m="$memory" "BEGIN {printf \"%.2f\", m/1000000000}")
    if [ "$cpu_quota" -lt 0 ]; then
        quota_ms="unlimited"
    else
        quota_ms=$(awk -v q="$cpu_quota" "BEGIN {printf \"%.2f\", q/1000}")
    fi
    period_ms=$(awk -v p="$cpu_period" "BEGIN {printf \"%.2f\", p/1000}")
    printf "%-20s %12s %15s %16s\n" "$name" "$memory_gb" "$quota_ms" "$period_ms"
done

echo
echo "=== Container Resource Usage ==="
echo "--------------------------------"
podman stats --all --no-stream
'

