# Wazuh EDR Endpoint Detection Lab

Deploying Wazuh across a manager and an agent, then generating real attack behaviour on the endpoint and watching the rules fire in the raw alert log. No dashboard.

## At a Glance

| Field | Detail |
| --- | --- |
| Build Type | EDR deployment and endpoint detection |
| Manager | Wazuh 4.x on Ubuntu Server, 192.168.64.12 |
| Endpoint | Kali Linux, agent ID 004 |
| Alert Source | /var/ossec/logs/alerts/alerts.log |
| Detected | Privilege escalation, unauthorised account creation, SSH brute force |
| Outcome | All three detected in real time, mapped to ATT&CK |

## What Happened

A Wazuh manager was stood up on Ubuntu with an agent on a Kali endpoint. Three categories of suspicious behaviour were then generated on that endpoint and watched arriving at the manager live.

Everything was read from the raw alert log rather than a dashboard. That was deliberate. A dashboard tells you a rule fired. The log tells you what the rule actually saw, and the day the dashboard is down or the rule is wrong, the log is the only thing left.

Scope stated plainly: the attack activity is self generated on a lab host, and the SSH brute force runs over loopback. The rules, the rule IDs, and the alerts are real Wazuh output.

## Manager Verification

![Wazuh Manager Running](./screenshots/01_wazuh_manager_running.png)

Service confirmed active and enabled at startup, memory usage consistent with active processing.

Check the manager before trusting anything downstream. A stopped manager does not produce an error, it produces silence, and silence looks exactly like a quiet network.

## Agent Deployment

![Wazuh Agent Running](./screenshots/02_wazuh_agent_running.png)

Agent installed on the Kali endpoint, pointed at the manager, confirmed active, registered as ID 004.

The agent is the visibility. A host without one is not a low risk host, it is an unknown one.

## Agent Connectivity

![Agent Connected](./screenshots/03_agent_connected.png)

Agent 004 confirmed Active on the manager. Stale disconnected agents removed so the inventory reflects reality.

An agent list full of disconnected entries is worse than an empty one. It means nobody knows which endpoints are actually covered, and coverage you cannot state is coverage you do not have.

## Baseline

![Alerts Log Live](./screenshots/04_alerts_log_live.png)

Alert log opened and confirmed streaming. Initial alerts from the manager itself captured. Baseline taken before any attack activity.

Baseline first. Without knowing what the log looks like quiet, there is no way to say what the attack added.

## First Endpoint Telemetry

![Kali Alerts Detected](./screenshots/05_kali_alerts_detected.png)

Endpoint events arriving at the manager.

Rule 5402, level 3, successful sudo to root.

PAM session open and close events captured.

Sudo is legitimate almost every time it fires, which is exactly why it is worth logging. It is the step between having access and being able to use it, and an attacker who lands as a normal user needs it too.

## Detection, Unauthorised Account Creation

![User Creation Alert](./screenshots/06_user_creation_alert.png)

A user account, hacker123, was created on the endpoint.

Wazuh fired immediately:

Rule 5901, level 8, new group added to the system.

Rule 5902, level 8, new user added to the system.

Full detail captured: UID 1003, GID 1004, home /home/hacker123.

This is the alert the lab exists for. Account creation is persistence, and it is persistence that survives the password reset, the reboot, and the incident review. An attacker who gets a shell and leaves has visited. An attacker who gets a shell and creates an account has moved in.

Level 8 is the reason the detail matters. The alert does not just say something happened, it hands the responder the UID and the home directory, which is everything needed to find and remove the account without a forensic pass.

## Detection, SSH Brute Force

![SSH Brute Force Alerts](./screenshots/07_ssh_brute_force_alerts.png)

Repeated SSH attempts using a non existent user, wronguser.

Rule 5503, level 5, PAM user login failed.

Rule 5710, level 5, sshd attempt to login using a non existent user.

Source ::1, loopback, confirming the lab origin.

Rule 5710 is the more interesting of the two. A failed password against a real account is someone guessing a password. Repeated attempts against an account that does not exist is someone guessing who exists, which is enumeration wearing brute force's clothes. Wazuh separates them, and that distinction changes what the attacker is assumed to know.

## Alert Summary

| Rule | Level | Alert | Source |
| --- | --- | --- | --- |
| 5402 | 3 | Successful sudo to root | Attacker-Tier4 |
| 5501 | 3 | PAM login session opened | Attacker-Tier4 |
| 5502 | 3 | PAM login session closed | Attacker-Tier4 |
| 5503 | 5 | PAM user login failed | Attacker-Tier4 |
| 5710 | 5 | sshd attempt to login using a non existent user | Attacker-Tier4 |
| 5901 | 8 | New group added to the system | Attacker-Tier4 |
| 5902 | 8 | New user added to the system, hacker123 | Attacker-Tier4 |

## Observations

| Type | Value | Verdict |
| --- | --- | --- |
| Endpoint | Attacker-Tier4 | Suspicious activity detected |
| Account created | hacker123, UID 1003 | Unauthorised, persistence |
| Failed SSH user | wronguser | Non existent, enumeration attempt |
| Privilege action | sudo to root | Escalation, investigate |
| Source | ::1, loopback | Lab origin, self generated |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Rule |
| --- | --- | --- | --- |
| Persistence | Create account, local account | T1136.001 | 5902 |
| Privilege Escalation | Abuse elevation control mechanism, sudo | T1548.003 | 5402 |
| Credential Access | Brute force, password guessing | T1110.001 | 5710, 5503 |

Mapping note: these are the techniques the rules detected in this lab. T1078 valid accounts is not mapped, because the created account was never used to authenticate.

## Analyst Findings

Wazuh deployed across manager and endpoint, telemetry confirmed flowing end to end.

All three generated behaviours detected in real time.

Unauthorised account hacker123 detected on creation, rule 5902, level 8, with UID and home directory captured.

SSH brute force against a non existent user detected, rule 5710, with the attempt pattern confirming automation.

Privilege escalation via sudo detected, rule 5402.

Every alert carries timestamp, source host, and rule ID, which is what makes them usable rather than just visible.

## Recommended Response

Remove the unauthorised account and check for anything it owns.

Enable Wazuh active response to block brute force sources automatically rather than waiting for an analyst to read the log.

Alert specifically on rule 5902. Account creation has no innocent explanation outside a change window.

Deploy agents to every endpoint. Partial coverage is a map with holes in it that looks complete.

Audit the agent list on a schedule so disconnected agents surface before an incident does.

## What This Lab Demonstrates

Deploying an EDR manager and agent across a multi machine environment and verifying telemetry end to end.

Reading raw alert logs rather than depending on a dashboard.

Establishing a baseline before generating any attack activity.

Recognising account creation as persistence rather than as an administrative event.

Distinguishing password guessing from user enumeration by which rule fires.

Mapping detections to ATT&CK by rule ID, and leaving out the technique that was not observed.

## Repository Structure

```
edr-wazuh-endpoint-detection-lab/
├── README.md
└── screenshots/
    ├── 01_wazuh_manager_running.png
    ├── 02_wazuh_agent_running.png
    ├── 03_agent_connected.png
    ├── 04_alerts_log_live.png
    ├── 05_kali_alerts_detected.png
    ├── 06_user_creation_alert.png
    └── 07_ssh_brute_force_alerts.png
```

---

[![LinkedIn](https://img.shields.io/badge/LinkedIn-WilliamInCyber-blue?style=flat&logo=linkedin)](https://linkedin.com/in/WilliamInCyber)
[![X](https://img.shields.io/badge/X-@WilliamInCyber-black?style=flat&logo=x)](https://x.com/WilliamInCyber)
