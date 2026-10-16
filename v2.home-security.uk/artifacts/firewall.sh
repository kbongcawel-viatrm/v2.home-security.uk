# Set the default zone to public
firewall-cmd --set-default-zone=public

# Set the default incoming policy to DROP
firewall-cmd --permanent --zone=public --set-target=DROP

# Remove all services from the public zone
firewall-cmd --permanent --zone=public --remove-service=ssh
firewall-cmd --permanent --zone=public --remove-service=cockpit
firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client
firewall-cmd --permanent --zone=public --remove-service=mdns

# Remove all explicitly allowed ports
firewall-cmd --permanent --zone=public --remove-ports=0-65535/tcp
firewall-cmd --permanent --zone=public --remove-ports=0-65535/udp

# Allow HTTPS only
firewall-cmd --permanent --zone=public --add-service=https

##########################################################
#  CUSTOM BLOCKS BASED ON ANALYSIS    ###################
########################################################  
# Incoming traffic to local port 40676
firewall-cmd --permanent --add-rich-rule='rule priority="-100" port port="40676" protocol="tcp" drop'
firewall-cmd --permanent --add-rich-rule='rule priority="-100" port port="40676" protocol="udp" drop'

# Outgoing traffic whose destination port is 40676
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -p tcp --dport 40676 -j DROP
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -p udp --dport 40676 -j DROP

########################################################
#    END ##############################################
########################################################

# Reload firewall rules
firewall-cmd --reload

# Getting the current firewall rules
echo "Allowed ports."
firewall-cmd --list-ports

echo "Allowed services."
firewall-cmd --list-services

echo "list-all"
firewall-cmd --list-all
