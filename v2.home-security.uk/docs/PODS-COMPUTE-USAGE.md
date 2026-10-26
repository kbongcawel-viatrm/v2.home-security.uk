# All the pods memory and cpu usage


# commands
 
```bash
podman stats --all --no-stream
```

```bash
ID            NAME            CPU %       MEM USAGE / LIMIT  MEM %       NET IO             BLOCK IO           PIDS        CPU TIME      AVG CPU %
e5daa3617881  rhel-toolbox-9  0.00%       0B / 0B            0.00%       0B / 0B            0B / 0B            0           0s            0.00%
0be2665c63fb  fedora-toolbox  0.30%       5.64MB / 8.021GB   0.07%       0B / 0B            850.2MB / 97.8MB   7           27.486464s    0.30%
2938778f0dc3  rclone          0.00%       0B / 0B            0.00%       0B / 0B            0B / 0B            0           0s            0.00%
da2a09d6641a  fail2ban        0.00%       0B / 0B            0.00%       0B / 0B            0B / 0B            0           0s            0.00%
c87177c6aa6b  aide-container  0.40%       16.11MB / 8.021GB  0.20%       0B / 0B            1.117GB / 3.527GB  6           33.744377s    0.40%
4b313d420f99  ollama          173.60%     2.275GB / 2.953GB  77.05%      52.12kB / 17.05kB  5.551GB / 31.05MB  21          5m18.350986s  173.60%
14c69c9aea1a  openobserve     0.95%       216.3MB / 1.342GB  16.11%      25.15MB / 41.76kB  834.5MB / 55.89MB  19          1.740596s     0.95%
e9e4ab074f98  fluent-bit      0.40%       34.71MB / 134.2MB  25.86%      28.55kB / 25.11MB  243.1MB / 99.52MB  14          738.106ms     0.40%
c644f5763ea4  security-ai     0.18%       12.03MB / 402.7MB  2.99%       9.481kB / 12.83kB  55.99MB / 4.874MB  1           297.515ms     0.18%
```

# commands 
```bash
podman inspect --format '{{.Name}} memory={{.HostConfig.Memory}} cpu_quota={{.HostConfig.CpuQuota}} cpu_period={{.HostConfig.CpuPeriod}}' openobserve ollama fluent-bit security-ai 
```

```bash
openobserve memory=1342177280 cpu_quota=100000 cpu_period=100000
ollama memory=2952790016 cpu_quota=200000 cpu_period=100000
fluent-bit memory=134217728 cpu_quota=25000 cpu_period=100000
security-ai memory=402653184 cpu_quota=50000 cpu_period=100000
```

# combined command

```bash
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
```
