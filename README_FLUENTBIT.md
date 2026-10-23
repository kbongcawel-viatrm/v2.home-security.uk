# Fluent Bit Log Collection Configuration

This configuration sets up Fluent Bit to collect logs from multiple sources including rotated logs, starting immediately when the container/service begins.

## Supported Log Sources

The configuration collects logs from the following sources:

1. **Suricata** - Network intrusion detection logs
   - Path: `/var/log/suricata/*.log`
   - Parser: JSON format

2. **Auditd** - Linux audit logs
   - Path: `/var/log/audit/audit.log`
   - Parser: Custom regex for auditd format

3. **AIDE** - Advanced Intrusion Detection Environment logs
   - Path: `/var/log/aide/*.log`
   - Parser: Custom regex for AIDE format

4. **Kernel logs**
   - Path: `/var/log/kern.log`
   - Parser: Syslog RFC3164 format

5. **Boot logs**
   - Path: `/var/log/boot.log`
   - Parser: Syslog RFC3164 format

6. **Systemd Journal** - Auditd and general system logs
   - Service: `auditd.service` (filtered)
   - General system logs

## Key Features

### Rotated Log Handling
- All file-based inputs are configured with `Rotate_Wait` to handle log rotation
- Database files track file positions for each log source
- `storage.total_limit_size` prevents unbounded storage growth
- `file_rotated_logs` service option enables rotated log processing

### Immediate Start
- Fluent Bit starts collecting logs as soon as it begins
- `Read_From_Tail` is enabled for systemd inputs
- Database tracking ensures no logs are missed on restart

### Configuration Files

1. **fluent-bit.conf** - Main Fluent Bit configuration
   - Service settings
   - Input plugins for all log sources
   - Filter plugins for log processing
   - Output plugins (configured for stdout by default)

2. **parsers.conf** - Parser definitions
   - JSON parser for Suricata
   - Regex parser for auditd
   - Regex parser for AIDE
   - Syslog parser for kernel and boot logs
   - Multiline parser for Suricata

## Usage

### Running Fluent Bit

```bash
# Run Fluent Bit with the configuration
fluent-bit -c /path/to/fluent-bit.conf

# Or using the default config location
fluent-bit -c /var/home/kb/workspace/home-security/fluent-bit.conf
```

### Docker Container

If running in a container, mount the configuration files:

```bash
docker run -d \
  --name fluent-bit \
  -v /var/home/kb/workspace/home-security/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf \
  -v /var/home/kb/workspace/home-security/parsers.conf:/fluent-bit/etc/parsers.conf \
  -v /var/log:/var/log \
  -v /run/log/journal:/run/log/journal \
  fluent/fluent-bit:latest
```

### Environment Variables

The configuration uses the following environment variables:
- `${HOSTNAME}` - Automatically populated with the container/host hostname
- `${FLUENT_BIT_TAG}` - Automatically set by Fluent Bit for each input tag

### Customizing Output

By default, logs are output to stdout in JSON format. To send logs to a different destination:

#### Elasticsearch

Uncomment and configure the Elasticsearch output section:

```ini
[OUTPUT]
    Name          es
    Match         *
    Host          elasticsearch
    Port          9200
    Index         fluent-bit-${FLUENT_BIT_TAG}
    Type          _doc
    Replace_Dots  On
    Retry_Limit   False
    tls           On
    tls.verify    On
```

#### Loki

Uncomment and configure the Loki output section:

```ini
[OUTPUT]
    Name          loki
    Match         *
    Host          loki
    Port          3100
    Labels        job=fluent-bit
    Label_Keys    $HOSTNAME,$FLUENT_BIT_TAG
    Line_Format   json
```

#### Kafka

```ini
[OUTPUT]
    Name          kafka
    Match         *
    Brokers       kafka:9092
    Topic         fluent-bit-logs
    Retry_Limit   False
```

## Storage Configuration

The configuration uses Fluent Bit's storage layer to:
- Track file positions across restarts
- Handle rotated logs properly
- Prevent memory overflow

Storage paths:
- `/var/log/flb_storage/` - Storage chunk directory
- Database files track positions for each log source

## Monitoring

Fluent Bit HTTP server is enabled for monitoring:
- Address: `0.0.0.0:2020`
- Endpoints:
  - `/api/v1/metrics` - Prometheus metrics
  - `/api/v1/health` - Health check

## Troubleshooting

### Logs Not Appearing

1. **Check file paths**: Ensure log files exist at the expected paths
2. **Verify permissions**: Fluent Bit needs read access to log files
3. **Check parser configuration**: Ensure the correct parser is assigned
4. **Review storage**: Check that database files are being created

### Permission Issues

```bash
# Run with appropriate privileges
chmod -R 755 /var/log/flb_storage/
chown -R fluent-bit:fluent-bit /var/log/flb_storage/
```

### Debug Mode

Run Fluent Bit in debug mode for troubleshooting:

```bash
fluent-bit -c fluent-bit.conf -i debug
```

## Customization

### Adding New Log Sources

1. Add a new `[INPUT]` section in `fluent-bit.conf`
2. Create a parser in `parsers.conf` if needed
3. Add appropriate filters if needed
4. Configure the output destination

### Modifying Existing Sources

Edit the relevant `[INPUT]` section and:
- Update the `Path` to point to your log files
- Change the `Tag` for better identification
- Adjust the `Parser` if your log format differs
- Modify `DB` path for position tracking

## Performance Tuning

Adjust these parameters based on your log volume:

```ini
[SERVICE]
    flush        1          # Flush interval in seconds
    log_level    info       # Can be debug for troubleshooting
    
[INPUT]
    Mem_Buf_Limit 5MB       # Increase for high-volume logs
    storage.total_limit_size 100M  # Increase for many log sources
```

## References

- [Fluent Bit Official Documentation](https://docs.fluentbit.io/)
- [Fluent Bit Configuration Guide](https://docs.fluentbit.io/manual/administration/configuring-fluent-bit)
- [Fluent Bit Input Plugins](https://docs.fluentbit.io/manual/pipeline/inputs)
- [Fluent Bit Parser Guide](https://docs.fluentbit.io/manual/pipeline/parsers)
