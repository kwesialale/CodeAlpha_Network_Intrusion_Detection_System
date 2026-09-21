# CodeAlpha_Network_Intrusion_Detection_System

**CodeAlpha Cybersecurity Internship — Task 4: Network Intrusion Detection System**

This project implements a network-based Intrusion Detection System (IDS) using **Suricata**, running inside a **Kali Linux virtual machine**. It covers the setup, custom detection rules, continuous monitoring, and an automated response mechanism for detected attacks.

> **Scope note:** This submission covers Task 4 requirements 1 through 4 (setup, rule configuration, continuous monitoring, and response mechanism). Point 5, dashboard visualization, is optional per the task instructions and is not included in this submission.

---

## Environment

| Component        | Detail                                   |
|-------------------|-------------------------------------------|
| Host OS           | macOS (MacBook Pro)                       |
| Virtualization    | Oracle VirtualBox                         |
| Guest OS          | Kali Linux 2025.4 (VirtualBox amd64)      |
| Network Mode      | NAT Network (`NatNetwork1`)               |
| IDS Tool          | Suricata 8.0.6                            |
| Interface Monitored | `eth0`                                  |
| Guest IP          | `10.0.0.2/24`                             |
| Gateway (test target) | `10.0.0.1`                             |

---

## Task Requirements Covered

### 1. Set up a network-based IDS using Suricata

Suricata was installed directly from the Kali repositories and configured to monitor the VM's active network interface.

```bash
sudo apt update
sudo apt install suricata -y
suricata --version
```

Network details were identified with:

```bash
ip a
ip route | grep default
```

This confirmed the interface (`eth0`), the VM's IP (`10.0.0.2`), and the gateway (`10.0.0.1`).

The core configuration file `/etc/suricata/suricata.yaml` was then edited to:
- Set `HOME_NET` to the actual lab subnet (`10.0.0.0/24`) instead of the broad default ranges, for accurate alert scoping.
- Set the monitoring interface under `af-packet` to `eth0`.
- Enable both `eve-log` (JSON output) and `fast` (plain-text alert log) outputs.

See [`config/suricata.yaml.snippet`](config/suricata.yaml.snippet) for the exact lines changed.

Rule sets were refreshed with:

```bash
sudo suricata-update
```

---

### 2. Configure rules and alerts to detect suspicious activity

A custom rule file was created at `/etc/suricata/rules/local.rules` (included here as [`rules/local.rules`](rules/local.rules)) containing two detection rules for ICMP ping-flood behavior:

```
alert icmp any any -> $HOME_NET any (msg:"PING FLOOD DETECTION - Rapid ICMP"; itype:8; detection_filter: track by_src, count 50, seconds 1; classtype:attempted-dos; sid:1000001; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"PING FLOOD DETECTION - Sustained ICMP"; itype:8; threshold: type limit, track by_src, count 100, seconds 10; classtype:attempted-dos; sid:1000002; rev:1;)
```

- **Rule 1** fires if a single source sends 50+ ICMP echo requests within 1 second.
- **Rule 2** fires if a single source sends 100+ ICMP echo requests within 10 seconds (catches slower, sustained floods that rule 1 might miss).

The rule file was referenced in `suricata.yaml` under `rule-files`, and the configuration was validated before use:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Output confirmed: `Configuration provided was successfully loaded`.

---

### 3. Monitor network traffic continuously for potential threats

Rather than running Suricata manually in the foreground, it was configured to run as a persistent **systemd service**, so monitoring continues in the background and would automatically resume on reboot:

```bash
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

**Evidence:** `systemctl status` confirmed the service was `active (running)`, managed under `suricata.service`, running as PID 5322 with the exact launch command:

```
/usr/bin/suricata -D --af-packet -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata/suricata.pid
```

(See `screenshots/01-suricata-service-active.png`.)

---

### 4. Implement response mechanisms for detected intrusions

To move beyond passive alerting, a bash script (`scripts/suricata-block.sh`) was written to watch the alert log in real time and automatically block any source IP that triggers a ping-flood alert:

```bash
#!/bin/bash
tail -Fn0 /var/log/suricata/fast.log | while read line; do
  if echo "$line" | grep -q "PING FLOOD DETECTION"; then
    SRC_IP=$(echo "$line" | grep -oP '(?<={)[0-9.]+(?=:.*->)')
    if [ -n "$SRC_IP" ]; then
      echo "$(date): Blocking $SRC_IP" >> /var/log/suricata-block.log
      iptables -A INPUT -s "$SRC_IP" -j DROP
    fi
  fi
done
```

It works by:
1. Continuously tailing `fast.log` for new lines.
2. Filtering for lines matching `PING FLOOD DETECTION`.
3. Extracting the source IP from the alert text.
4. Adding an `iptables` `DROP` rule for that IP, and logging the action with a timestamp to `/var/log/suricata-block.log`.

Run with:

```bash
sudo chmod +x scripts/suricata-block.sh
sudo nohup ./scripts/suricata-block.sh &
```

This closes the gap between *detecting* an intrusion and *responding* to one, which a passive IDS alone does not do.

---

## Testing & Evidence

The system was tested by simulating an ICMP flood attack against the Kali VM's gateway:

```bash
sudo ping -c 200 -i 0.01 10.0.0.1
```

This sends 200 ICMP echo requests at ~100 packets/second, well above both rule thresholds.

**Evidence:**
- `screenshots/02-ping-flood-command.png` — the flood command running, showing successful ICMP replies from the gateway.
- `screenshots/03-suricata-alerts-firing.png` — `fast.log` populated with repeated `PING FLOOD DETECTION` alerts for both the "Rapid ICMP" (sid:1000001) and "Sustained ICMP" (sid:1000002) rules, each showing the correct source (`10.0.0.2`) and destination (`10.0.0.1`) with accurate timestamps.

Sample alert line from the log:

```
09/20/2026-14:46:20.616561  [**] [1:1000002:1] PING FLOOD DETECTION - Sustained ICMP [**] [Classification: Attempted Denial of Service] [Priority: 2] {ICMP} 10.0.0.2:8 -> 10.0.0.1:0
```

This confirms detection worked correctly for both the rapid-burst rule and the sustained-flood rule.

---

## Repository Structure

```
CodeAlpha_Network_Intrusion_Detection_System/
├── README.md                       # This file
├── config/
│   └── suricata.yaml.snippet       # Key configuration changes made
├── rules/
│   └── local.rules                 # Custom ICMP flood detection rules
├── scripts/
│   └── suricata-block.sh           # Automated response / auto-block script
└── screenshots/
    ├── 01-suricata-service-active.png
    ├── 02-ping-flood-command.png
    └── 03-suricata-alerts-firing.png
```

> Note: add your three screenshots into the `screenshots/` folder with the filenames referenced above before pushing to GitHub.

---

## How to Reproduce

1. Install Suricata: `sudo apt update && sudo apt install suricata -y`
2. Identify your interface/IP: `ip a` and `ip route | grep default`
3. Edit `/etc/suricata/suricata.yaml` using [`config/suricata.yaml.snippet`](config/suricata.yaml.snippet) as a reference, substituting your own subnet.
4. Update rule sets: `sudo suricata-update`
5. Copy [`rules/local.rules`](rules/local.rules) to `/etc/suricata/rules/local.rules` and confirm it's referenced under `rule-files` in the yaml.
6. Validate the config: `sudo suricata -T -c /etc/suricata/suricata.yaml`
7. Enable and start the service: `sudo systemctl enable suricata && sudo systemctl start suricata`
8. Run the response script: `sudo nohup scripts/suricata-block.sh &`
9. Simulate an attack: `sudo ping -c 200 -i 0.01 <gateway-ip>`
10. Confirm alerts: `sudo tail -f /var/log/suricata/fast.log`

---

## Summary

This project demonstrates a functioning network intrusion detection and basic response pipeline: Suricata detects ICMP flood-style denial-of-service behavior using custom-written rules, runs continuously as a background service, and triggers an automated firewall-based response when an attack is detected — fulfilling Task 4, requirements 1 through 4.
