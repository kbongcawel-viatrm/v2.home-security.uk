#!/usr/bin/env bash
echo "## Watching rsync progress live ##"
echo "---------------------------------"
watch -n 1 'echo "## Source ##" \
	&& echo "---------------------------------" \
        && ls -alt /var/log/suricata/ | head -n 5 \
	&& ls -alt /var/log/aide/ | head -n 5 \
	&& ls -alt /var/log/audit/ | head -n 5 \
	&& echo \
	&& echo "## Destination ##" \
	&& echo "---------------------------------" \
	&& ls -alt /var/log/suricata-export | head -n 10'

