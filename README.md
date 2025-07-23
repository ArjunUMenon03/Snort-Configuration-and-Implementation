# Snort-IDS-IPS
Snort generally is a most commonly used Intrusion detection and prevention system. In this report, we discuss all the minute elements that are required from installing snort to configuring it as a full-fledged Intrusion detection and prevention system. We also give an overview of functioning of Snort by performing several attacks such as cross-site scripting and SQL injection attack. By whole we present a complete step by step process of deploying a complete package of Snort along with configuration of both the attacker and the victim. 

# Configuring and Implementing Snort as an IDS/IPS System  
(Ubuntu Server 22.04 LTS + Windows 11 Log Source)

**Author:** Arjun U Menon  
**CICSA Batch:** Sunday  
**Date:** July 2025

---

## Table of Contents

- [Introduction](#introduction)
- [Objectives](#objectives)
- [Virtual Environment Setup](#virtual-environment-setup)
- [Snort Installation](#snort-installation)
  - [Ubuntu Server 22.04 LTS](#ubuntu-server-2204-lts)
  - [Windows 11](#windows-11)
- [Snort Configuration](#snort-configuration)
- [Creating and Managing Snort Rules](#creating-and-managing-snort-rules)
- [Running Snort](#running-snort)
  - [As an Intrusion Detection System (IDS)](#as-an-intrusion-detection-system-ids)
  - [As an Intrusion Prevention System (IPS)](#as-an-intrusion-prevention-system-ips)
- [Testing and Validation](#testing-and-validation)
- [Performance Tuning and Optimization](#performance-tuning-and-optimization)
- [Conclusion](#conclusion)
- [References](#references)

---

## Introduction

Organizations today face a growing landscape of cyber threats including malware, ransomware, unauthorized access, and data exfiltration. **Intrusion Detection and Prevention Systems (IDS/IPS)** are crucial tools that monitor network traffic to detect and respond to such threats.  
**Snort**, developed by Cisco, is a leading open-source network IDS/IPS offering real-time traffic analysis, protocol inspection, and a flexible rule-based detection mechanism suitable for a wide variety of threat monitoring and prevention tasks.

---

## Objectives

- Introduce IDS and IPS concepts.
- Provide practical experience deploying Snort as a security tool.
- Demonstrate Snort installation, configuration, and traffic analysis.
- Simulate attacks to validate detection/blocking capabilities.
- Create and manage custom Snort rules.
- Explore integrations to enhance detection and response.

---

## Virtual Environment Setup

**Host Requirements:**
- 64-bit machine, 8+ GB RAM (16 GB recommended), 100+ GB disk, virtualization enabled.

**VM Specifications:**
- **Ubuntu Server 22.04 LTS:** 2 vCPUs, 4 GB RAM, 40 GB disk.
- **Windows 11 Pro:** 2 vCPUs, 4 GB RAM, 40 GB disk.

**Networking:**
- **Host-Only Adapter:** Isolates VMs from the internet.
- **Internal/Bridged Mode:** For realistic traffic flows and centralized monitoring.

---

## Snort Installation

### Ubuntu Server 22.04 LTS

**Update and Upgrade:**
sudo apt update && sudo apt upgrade -y

**DAQ Installation:**
wget https://www.snort.org/downloads/snort/daq-2.X.tar.gz
tar -xvzf daq-2.X.tar.gz
cd daq-2.X
./configure && make && sudo make install

**Install Snort:**
sudo apt-get install snort -y


### Windows 11

1. Download latest Snort binary from the [official website](https://www.snort.org/downloads).
2. Extract to `C:\Snort\`
3. Add `C:\Snort\bin` to the system PATH via Environment Variables.

---

## Snort Configuration

- **Create Directories:**
  - `/etc/snort`
  - `/etc/snort/rules`
  - `/var/log/snort`
  - `/usr/local/lib/snort_dynamicrules`
- **Copy Default Configs:**
  - `snort.conf`
  - `classification.config`
  - `reference.config`
  - `.map` files
- **Edit `snort.conf`:**
  - Set variables:  
    `var HOME_NET 192.168.56.0/24`
  - Define rule path and include custom rules:  
    `var RULE_PATH /etc/snort/rules`  
    `include $RULE_PATH/local.rules`
  - Set output:  
    `output alert_fast: stdout`

---

## Creating and Managing Snort Rules

Rule Syntax: 
`action protocol src_ip src_port -> dest_ip dest_port (options)`

Example Custom Rule:
alert icmp any any -> $HOME_NET any (msg:"ICMP Packet Detected"; sid:1000001; rev:1;)

text
- Place all custom rules in `/etc/snort/rules/local.rules`.  
- Use SIDs above 1,000,000 for custom rules.

Test Rule Syntax:
sudo snort -T -c /etc/snort/snort.conf

---

## Running Snort

### As an Intrusion Detection System (IDS)

- Sniffer Mode:
sudo snort -v -i eth0

- Packet Logger Mode:
sudo snort -dev -i eth0 -l /var/log/snort

- IDS Detection Mode:
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0

### As an Intrusion Prevention System (IPS)

1. Enable IP Forwarding:
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo sysctl -p

2. Configure iptables for NFQUEUE:
sudo iptables -I INPUT -j NFQUEUE --queue-num 0

3. Run Snort in Inline Mode:
sudo snort -Q --daq nfq --daq-var queue=0 -c /etc/snort/snort.conf

4. Use `drop` rules in local.rules to block traffic instead of just alerting:
drop tcp any any -> $HOME_NET 22 (msg:"SSH Blocked"; sid:1000002; rev:1;)

text

---

## Testing and Validation

**Attack Simulation Tools Used:**
- Nmap: Port scanning, e.g. `nmap -sS 192.168.56.101`
- Nikto: Web vulnerability scanning
- Metasploit: Exploit/reverse shell attacks

**Validate:**
- Detection/logging of port scans and malicious activities.
- Use `sudo tail -f /var/log/snort/alert` to quickly view alerts.

---

## Performance Tuning and Optimization

- Disable unused rule sets in `snort.conf` by commenting out unnecessary rules:
#include $RULE_PATH/malware.rules

text
- Focus on custom rules relevant to your network.
- Test configuration and monitor performance:**  
sudo snort -T -c /etc/snort/snort.conf

text

---

## Conclusion

This project demonstrates the end-to-end installation, configuration, and validation of Snort for IDS/IPS functions within a controlled virtual environment. Step-by-step procedures cover environment setup, rule customization, live threat simulation, and performance optimization, enabling robust intrusion detection and prevention capabilities adaptable to various organizational security needs.

---

## References

- [The Snort Project – Official Documentation](https://docs.snort.org)
- [Snort Official Website](https://www.snort.org)
- [Snort Rules Documentation](https://snort.org/documents)
- [Snort Installation Guides on Ubuntu](https://linuxhint.com/install_snort_ubuntu/)
- [Metasploit Framework Documentation](https://docs.rapid7.com/metasploit/)
- [Security Onion Project](https://docs.securityonion.net)
