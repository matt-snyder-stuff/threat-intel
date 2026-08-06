# Environment

This file describes the data sources, indexes, and key fields available for
threat hunting in this deployment. **Update this file when your environment
changes.** The `peak-hunt` agent reads it during PREPARE to scope hypotheses
to telemetry that actually exists — a hypothesis that references a missing
index is marked inconclusive before any query runs.

---

## Splunk Deployment

| Setting | Value |
|---------|-------|
| REST API | Set `SPLUNK_URL` in env — see `.env.example` |
| Auth | `SPLUNK_TOKEN` (preferred) or `SPLUNK_USERNAME` + `SPLUNK_PASSWORD` |
| SSL | Set `SPLUNK_VERIFY_SSL=false` for self-signed certs |

---

## Available Indexes

Update the Status column to reflect your actual deployment.

| Index | Sourcetype(s) | What it contains | Status |
|-------|--------------|-----------------|--------|
| `endpoint` | `WinEventLog:Security`, `WinEventLog:Sysmon`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Windows process creation (4688/Sysmon 1), network connections (Sysmon 3), file create (Sysmon 11), registry (Sysmon 12–14), logon events (4624/4625/4768/4771) | Unknown — update |
| `network` | `stream:dns`, `stream:http`, `stream:tcp`, `bro:conn`, `paloalto:traffic` | DNS queries, HTTP/S connections, firewall traffic logs | Unknown — update |
| `cloud` | `aws:cloudtrail`, `aws:s3:accesslogs`, `azure:activity`, `gcp:audit` | Cloud API calls, storage access, IAM changes, compute operations | Unknown — update |
| `identity` | `WinEventLog:Security`, `azure:activedirectory`, `okta:im2` | Authentication events, MFA, group changes, OAuth token grants | Unknown — update |
| `email` | `ms:o365:email`, `proofpoint:maillog`, `mimecast:email` | Inbound/outbound email, attachment hashes, sender/recipient | Unknown — update |
| `threat_intel` | *(varies by source)* | Imported threat intel reports — fed by this pipeline | Unknown — update |

---

## Key Fields by Category

These field names are used by the `peak-hunt` and `splunk-hunter` agents to
build targeted queries. Update them if your environment uses different field
names (e.g. after Splunk CIM normalization).

### Process / Endpoint

| Field | Typical value | Notes |
|-------|--------------|-------|
| `process` or `Image` | `C:\Windows\System32\cmd.exe` | Sysmon: `Image`; Security 4688: `NewProcessName` |
| `parent_process` or `ParentImage` | `C:\Windows\explorer.exe` | Sysmon: `ParentImage` |
| `CommandLine` or `process_exec` | `powershell -enc ...` | |
| `user` or `SubjectUserName` | `DOMAIN\user` | |
| `host` or `ComputerName` | `WORKSTATION-01` | |
| `dest_ip` or `DestinationIp` | `1.2.3.4` | Sysmon 3 |
| `dest_port` or `DestinationPort` | `443` | |

### Network

| Field | Typical value | Notes |
|-------|--------------|-------|
| `src_ip` | `192.168.1.10` | Source of connection |
| `dest_ip` | `1.2.3.4` | Destination |
| `dest_port` | `443` | |
| `bytes_out` | `524288` | Outbound bytes |
| `query` | `evil.example.com` | DNS query (stream:dns) |
| `answer` | `1.2.3.4` | DNS response |
| `uri_path` | `/upload/file.zip` | HTTP path (stream:http) |
| `url` | `https://evil.example.com/upload` | Full URL |

### Cloud (AWS CloudTrail)

| Field | Typical value | Notes |
|-------|--------------|-------|
| `eventName` | `AssumeRole`, `GetObject`, `CreateUser` | API action |
| `userIdentity.arn` | `arn:aws:iam::123:role/name` | Who performed the action |
| `sourceIPAddress` | `1.2.3.4` | Caller IP |
| `requestParameters.bucketName` | `my-bucket` | S3 target |
| `errorCode` | `AccessDenied` | Non-empty means denied |

### Identity

| Field | Typical value | Notes |
|-------|--------------|-------|
| `src_user` | `user@domain.com` | |
| `action` | `success`, `failure` | Authentication outcome |
| `app` | `Okta`, `AzureAD` | |
| `mfa_method` | `TOTP`, `SMS` | If available |

---

## Known Gaps (update as you close them)

| Gap | Impact on hunting | Owner | Status |
|-----|------------------|-------|--------|
| DNS logs not confirmed in `index=network` | Hunts for DNS-based C2 (T1071.004, T1568) will be inconclusive | — | Unknown |
| S3 access logs may not be enabled | Hunts for T1530 data exfil from cloud storage will be inconclusive | — | Unknown |
| EDR product unknown | Sysmon field names vs EDR product field names may differ | — | Unknown |

---

## OCSF Field Mapping Reference

When building cross-platform queries, the agents use the following OCSF mappings:

| OCSF Class | OCSF Field | Splunk equivalent |
|-----------|-----------|------------------|
| Process Activity | `process.name` | `process`, `Image` |
| Process Activity | `process.cmd_line` | `CommandLine`, `process_exec` |
| Network Activity | `dst_endpoint.ip` | `dest_ip`, `DestinationIp` |
| Network Activity | `dst_endpoint.port` | `dest_port`, `DestinationPort` |
| DNS Activity | `query.hostname` | `query` (stream:dns) |
| File Activity | `file.name` | `file_name`, `TargetFilename` |
| Authentication | `user.name` | `src_user`, `SubjectUserName` |

---

## Notes for the Peak-Hunt Agent

- If an index in the table above shows Status = "Unknown", treat it as potentially absent.
  Run a validation count query (1-event limit, 24h window) before building a hypothesis
  that depends on it.
- If `SPLUNK_URL` is not set, run in offline mode and note all data sources as "unverified."
- Do not assume CIM normalization is complete. Check field names with a sample event before
  building queries that rely on standard CIM field names.
- When in doubt about a field name, run a broad stats query first:
  `index=<target> | fieldsummary | sort -count | head 20`
