# Incident Report — Brute Force Against vm-endpoint

| Field | Value |
|---|---|
| Incident | Sentinel incident #14 (duplicate: #13) |
| Rule | Brute Force - Successful Logon After Failures |
| Severity | High |
| Status | Resolved — Benign Positive (authorized security testing) |
| Date | October 29–30, 2026 (all times UTC; Pacific Time in brackets) |
| Analyst | Janaki Meenakshi Sundaram |
| Environment | Self-built lab: Microsoft Sentinel + Windows Server 2022 VM on Azure |

> This was a planned simulation in my own lab. I generated the "attack" myself by typing wrong passwords against my own VM. No real systems or third parties were involved. The source IP is my own internet connection and is partly redacted below.

## 1. Summary

On October 30, 2026 at 00:11 UTC, Microsoft Sentinel created High-severity incident #14 from the rule "Brute Force - Successful Logon After Failures." The local administrator account `soclabadmin` on `vm-endpoint` had **11 failed RDP logons** (EventID 4625) from a single source IP (104.53.x.x) starting at 23:46:26 UTC. Windows **locked the account** (EventID 4740). After the lockout cleared, the same IP **logged on successfully** at 00:02:16 UTC (EventID 4624).

A burst of failures followed by a success from the same IP is the classic pattern of a password-guessing attack that worked. In a production environment this would be treated as a likely account compromise. Here it was confirmed as authorized testing and closed as a benign positive.

## 2. Detection

- **Source:** Microsoft Sentinel scheduled analytics rules (managed in the Microsoft Defender portal).
- **Log source:** Windows Security Events from `vm-endpoint`, collected by the Azure Monitor Agent through data collection rule `dcr-vm-endpoint` into Log Analytics workspace `law-soc-lab`.
- **MITRE ATT&CK:** T1110 Brute Force (Credential Access).

All three detection rules fired during the test:

| Rule | Severity | What it caught | Incidents |
|---|---|---|---|
| Rule 1 — Multiple failed logons | Medium | 11 × EventID 4625 for `soclabadmin` | #4, #8, #12 |
| Rule 2 — Successful logon after failures | High | 4624 at 00:02:16 after the 4625 burst | #13, #14 |
| Rule 3 — Privileged group membership change | Medium | `testuser` added to local groups (separate test, see §3) | several |

## 3. Analysis

### Timeline (UTC)

| Time | Event | Detail |
|---|---|---|
| 23:37 | 4624 ×3 | Authorized admin sign-in to `vm-endpoint` to set up the test |
| 23:42:47 | 4732 | `testuser` created; Windows added it to the local **Users** group automatically |
| 23:43:37 | 4732 | `testuser` added to the local **Administrators** group (deliberate test for Rule 3) |
| 23:46:26 | 4625 | **First failed logon** to `soclabadmin` from 104.53.x.x |
| 23:46–23:49 | 4625 | 11 failed logons in total, same account, same IP |
| ≈23:49 | 4740 | **Account locked out** — Windows lockout policy stopped the guessing |
| 00:02:16 | 4624 | **Successful logon** to `soclabadmin` from the same IP (two events: LogonType 3 network authentication, then LogonType 10 RDP session) |
| 00:11:53 | — | Sentinel creates incident #14 (High) |
| 00:24 | — | Incident resolved: Benign Positive — security testing |

The `testuser` group change happened **before** the brute-force attempts, as a separate test of Rule 3. It was not an action taken after the "compromise."

### Investigation questions

| Question | Finding |
|---|---|
| Which account was targeted? | `soclabadmin` — the VM's local administrator |
| Which source IP? | One IP: 104.53.x.x |
| How many failures, over what window? | 11 failures, starting 23:46:26 UTC, within about 3 minutes |
| Did any sign-in succeed? | **Yes** — 00:02:16 UTC from the same IP, 13 minutes after the lockout |
| One account or many? | One account → **targeted brute force**, not a password spray |
| Did any control work? | **Yes** — the account lockout policy (EventID 4740) stopped the guessing after about 10 attempts |

### Impact (if this were real)

`soclabadmin` is a local administrator. An attacker with this password would have full control of the server: they could create accounts, add them to Administrators (exactly what Rule 3 watches for), disable security tools, and use the host to move to other systems.

### How the incident looked in Sentinel

- **Attack story:** the incident graph linked the account `soclabadmin` to the source IP.
- **Assets:** one user, `vm-endpoint\soclabadmin`.
- **Evidence:** the source IP, marked **Suspicious**.

## 4. Containment & Eradication (what I would do in production)

1. **Reset the `soclabadmin` password** and sign out all of its active sessions.
2. **Block the source IP** in the VM's network security group (NSG).
3. **Review everything the account did after 00:02:16 UTC:** new processes, new accounts, group changes (4720, 4728, 4732, 4756), scheduled tasks and services.
4. **Remove any unauthorized accounts or group memberships** found in step 3.
5. If anything suspicious is found, **isolate the VM** and escalate.

## 5. Recovery & Lessons Learned

### Security improvements

- **Don't expose RDP (port 3389) to the internet.** Use Azure Bastion, a VPN, or Just-in-Time VM access.
- **Require MFA** for administrative access.
- **Keep the account lockout policy.** It worked here and slowed the attack.
- **Use a unique, strong password** for every local administrator account.

### Detection-engineering findings

1. **The guide's original Rule 2 would never have fired.** Windows recorded the failed logons as `MicrosoftAccount\soclabadmin` but the successful logon as `vm-endpoint\soclabadmin`. Joining on the full `TargetAccount` field fails. I rewrote the rule to match on the lowercased username (`TargetUserName`), and it fired correctly.
2. **Duplicate incidents.** Each rule ran every 5 minutes but looked back 1 hour, so it found the same events up to 12 times and opened a new incident each run. I fixed this with **1-hour alert suppression**.
3. **One RDP sign-in creates two success events** (LogonType 3, then LogonType 10), which produced two High incidents (#13 and #14) for the same sign-in. Grouping alerts by account and IP would merge them.
4. **Rule 3 was too broad.** It also fired when `testuser` was added to the normal Users group, which Windows does automatically when any user is created. The tuned version in `detections/rule3-admin-group.kql` only alerts on privileged groups such as Administrators.

## Closure

Classified as **Benign Positive — authorized security testing**: the detections worked as designed, and the activity was my own planned test. All lab resources were deleted after the investigation.
