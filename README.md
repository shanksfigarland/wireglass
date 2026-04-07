<div align="center">

# Wireglass

### Local-first PCAP triage for fast incident review

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![UI](https://img.shields.io/badge/UI-HTML%20%7C%20CSS%20%7C%20JS-111827?style=for-the-badge)](#)
[![Focus](https://img.shields.io/badge/Focus-Offline%20Triage-0F766E?style=for-the-badge)](#)
[![Defensive](https://img.shields.io/badge/Use-Defensive%20Analysis-B91C1C?style=for-the-badge)](#)

Wireglass is a local PCAP analysis workstation that turns raw captures into a readable case summary with findings, artifacts, important frames, suspicious hosts, and investigation pivots.

</div>

## Why Wireglass

Most packet tools are great for manual deep dives, but slower when you want quick triage.
Wireglass is built for the first pass:

- upload a `.pcap` or `.pcapng`
- summarize the capture automatically
- surface suspicious behavior
- recover visible artifacts when possible
- pivot into malware and reputation research without leaving the case flow

It is designed as a defensive triage tool, not an offensive framework.

## Highlights

| Area | What it does |
| --- | --- |
| Capture support | Reads `.pcap` and `.pcapng` from Ethernet, raw IP, and Linux cooked captures |
| Protocol coverage | Extracts DNS, HTTP, TLS ClientHello, Kerberos, LDAP, SMB, and DCE/RPC metadata |
| Detections | Flags SYN scans, beaconing, suspicious DNS behavior, cleartext HTTP, uncommon ports, and AD-focused abuse indicators |
| Artifact recovery | Reassembles lightweight HTTP streams and computes SHA-256 for recovered files |
| Intel pivots | Builds local intel matches and optional external pivots for VirusTotal, MalwareBazaar, OTX, AbuseIPDB, Shodan, and Censys |
| Reporting | Produces terminal summaries, JSON reports, and browser-based HTML exports |
| UI | Local web dashboard with sticky section nav, dark mode, severity views, and quick pivots |

## What the workflow looks like

1. Ingest a capture locally.
2. Review the case summary and analyst narrative.
3. Check findings, impacted hosts, and important frames.
4. Inspect recovered artifacts and hashes.
5. Pivot to external intel only when you want deeper reputation context.

## Quick Start

### 1. Generate the built-in sample captures

```powershell
python generate_sample_pcap.py
```

### 2. Run the CLI analyzer

```powershell
python analyzer.py .\samples\synthetic_suspicious.pcapng --json .\reports\synthetic_report.json
```

### 3. Launch the local web app

```powershell
python webapp.py
```

Then open [http://127.0.0.1:8765](http://127.0.0.1:8765).

## External Intel

External lookups are optional and disabled by default.

- Web UI: enable providers only for the case you want to enrich
- CLI: use `--external-intel`
- Supported key env vars: `VIRUSTOTAL_API_KEY`, `VT_API_KEY`, `MALWAREBAZAAR_API_KEY`, `ABUSECH_AUTH_KEY`

Example:

```powershell
python analyzer.py .\samples\synthetic_suspicious.pcapng --external-intel --virustotal-key YOUR_VT_KEY --malwarebazaar-key YOUR_MB_KEY
```

## Defensive Detection Coverage

- Suspicious DNS subdomains and possible tunneling patterns
- SYN scan behavior
- Beacon-like periodic traffic
- Cleartext HTTP to external hosts
- Uncommon external port activity
- Kerberos, LDAP, SMB, and RPC patterns related to suspicious AD abuse
- DCSync-like replication interface access
- Delegation-related LDAP reconnaissance
- Recovered file hashing and indicator-based enrichment

## Project Layout

```text
pcap-triage/
|-- analyzer.py
|-- external_intel.py
|-- generate_sample_pcap.py
|-- triage_core.py
|-- webapp.py
|-- intel/
|   `-- known_iocs.json
|-- samples/
|-- reports/
`-- static/
    |-- index.html
    |-- main.js
    `-- glass-workstation.css
```

## Privacy Notes

- Captures stay local by default
- External reputation lookups are opt-in
- Enabling external enrichment shares selected indicators with those providers
- Encrypted payloads are not decrypted

## Limitations

- Detection logic is heuristic and triage-oriented
- Stream reassembly is intentionally lightweight
- Recovered malware depends on cleartext or directly observable delivery
- Local IOC data is sample data unless you replace it with your own approved sources

## Roadmap Ideas

- deeper protocol parsing
- stronger stream reconstruction
- richer host timelines
- better evidence correlation
- local model-assisted analyst narration

## Disclaimer

Wireglass is intended for defensive analysis, lab work, and incident triage.
Use it only on data and environments you are authorized to inspect.
