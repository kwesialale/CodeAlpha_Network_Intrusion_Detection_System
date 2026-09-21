#!/bin/bash
#
# suricata-block.sh
#
# Purpose:
#   Watches Suricata's fast.log in real time. When a PING FLOOD DETECTION
#   alert is seen, extracts the offending source IP and adds a firewall
#   rule to drop all further traffic from that address. This turns the
#   IDS (detection only) into a basic automated-response system
#   (detection + mitigation), satisfying Task 4, Point 4.
#
# Usage:
#   sudo chmod +x suricata-block.sh
#   sudo nohup ./suricata-block.sh &
#
# Log of every block action is written to /var/log/suricata-block.log

tail -Fn0 /var/log/suricata/fast.log | while read line; do
  if echo "$line" | grep -q "PING FLOOD DETECTION"; then
    SRC_IP=$(echo "$line" | grep -oP '(?<={)[0-9.]+(?=:.*->)')
    if [ -n "$SRC_IP" ]; then
      echo "$(date): Blocking $SRC_IP" >> /var/log/suricata-block.log
      iptables -A INPUT -s "$SRC_IP" -j DROP
    fi
  fi
done
