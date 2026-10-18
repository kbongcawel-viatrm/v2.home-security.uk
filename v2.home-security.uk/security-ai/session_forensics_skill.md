# Forensic Investigation Skill: Login Session Compromise or Hijacking

## Purpose

Triage whether current or recent interactive login sessions may be unauthorized,
compromised, or hijacked. Correlate systemd journal authentication records with
the live session table and login accounting records. Treat this as read-only
investigation: do not terminate sessions, change accounts, rotate credentials,
or alter host configuration as part of this skill.

## Safety and evidence handling

- Run commands on the host being investigated, with authorization. Use `sudo`
  only when needed to read protected journal records; do not change system state.
- Record the host identity, investigator, collection time and timezone, command,
  and unmodified output. Preserve the original output securely; redact secrets
  and personal data only in copies shared for analysis.
- Prefer collecting evidence before taking containment actions. If compromise
  appears active, follow the organization's incident-response process and
  involve the system owner; avoid actions that could destroy volatile evidence.
- Logs and accounting files may be incomplete, rotated, missing, altered, or
  unavailable to an unprivileged user. A missing event is not proof that an
  event did not happen, and logs are not tamper-proof evidence.

## Initial collection

Run and capture each command separately so errors and output remain attributable:

```bash
journalctl -b --no-pager | grep -Ei \
'sshd|authentication failure|session opened|session closed|sudo|polkit'

who
w
loginctl list-sessions
last -ai | head -20
```

The journal command searches the current boot only. If the event may be older,
check retained boots and the relevant time range, subject to journal retention and
access permissions. Do not infer that an empty result means there were no logins.

## Correlation and follow-up

1. **Establish expected activity.** Identify authorized users, administrators,
   service accounts, expected maintenance windows, known VPN/jump-host addresses,
   and expected local console sessions. Ask the system owner to validate anything
   unfamiliar; do not assume that an unfamiliar address or account is malicious.
2. **Correlate session records.** Compare usernames, TTYs, source addresses,
   login times, and session IDs across `who`, `w`, `loginctl`, `last`, and journal
   entries. Account for timezone, clock skew, host aliases, NAT, and VPN egress.
   Check whether a session shown as active is still present and whether its
   recorded start time and origin are plausible.
3. **Inspect a specific session read-only.** For a session ID reported by
   `loginctl list-sessions`, use:

   ```bash
   loginctl session-status SESSION_ID
   ```

   Replace `SESSION_ID` with the observed ID. Record the session's user, seat,
   TTY, leader process, and processes. Access and details vary by systemd version
   and permissions. Do not kill the session or its processes during triage.
4. **Expand the time window.** Once a relevant time range is known, inspect
   journal entries around it (for example, `journalctl --since '2026-10-17 10:00:00' --until '2026-10-17 11:00:00' --no-pager`).
   Use actual incident dates and the host's timezone; the example dates are not
   defaults. On systems where SSH logs use a separate unit, query the unit that
   exists on that host (commonly `sshd` or `ssh`).
5. **Look for corroboration.** If authorized and available, inspect audit/auth
   logs and process/network evidence for the same user and time window. Examples
   include `sudo`/polkit authorization records, SSH accepted-key/password records,
   source addresses, unexpected privilege transitions, and unfamiliar long-lived
   shells, multiplexers, or remote-control processes. Preserve the outputs and
   correlate timestamps rather than relying on one indicator.

## Assessment guidance

Report findings as **no suspicious evidence observed**, **suspicious activity
requiring validation**, or **probable compromise/hijack**, with a confidence
level and explicit evidence. Do not claim a session is compromised solely because
it is active, a session-open event exists, or a source address is unfamiliar.

Indicators that warrant validation include:

- An account, login time, TTY, session, or origin that the account owner cannot
  explain, especially when corroborated by authentication records.
- Successful authentication followed by an unexpected `sudo`/polkit elevation,
  account change, or other privileged activity.
- A session that remains active after the user says they logged out, or
  concurrent sessions inconsistent with the user's expected activity.
- Evidence of unexpected remote access, shell/multiplexer processes, or network
  connections associated with the session.
- Authentication failures alone indicate attempts, not successful access. A
  session-open message alone indicates a session was opened, not that it was
  unauthorized. A session-close record may be absent due to abrupt disconnect,
  logging gaps, or accounting behavior.

Use stronger language such as **probable compromise/hijack** only when multiple
independent records support unauthorized access or control, or a trusted user
confirms they did not initiate the session. State alternative explanations and
gaps (including missing/rotated logs and whether the host clock is reliable).
This command set cannot conclusively detect a hijacked already-authenticated
session; a hijacker operating within a legitimate session may leave no distinct
login record.

## Output format

Provide a concise report with:

- Host and investigation time range (including timezone).
- Commands run, collection limitations, and evidence references.
- Sessions and authentication events correlated by user, time, TTY/session ID,
  and origin where available.
- Findings, confidence, plausible benign explanations, and unresolved questions.
- Recommended next investigative or incident-response steps. Keep recommendations
  separate from actions performed; this skill does not authorize remediation.
