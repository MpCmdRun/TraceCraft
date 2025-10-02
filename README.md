
# TraceCraft 🚀✨

**ETW-powered Windows telemetry collector & conservative Sigma generator.**  
_Lab-only. Ethical research. No malware. Be smart._

![demo-gif](assets/demo.gif)

---

## TL;DR (read this if you're busy)
TraceCraft grabs deep Windows ETW telemetry (processes, image loads, file/registry ops, PowerShell, .NET, network), writes it as **NDJSON**, and spits out **conservative Sigma rules** you can review and use in a SIEM. Single-file C# (.NET 8.0). Run **elevated** in an **isolated VM**. No malware, no drama.

---

## Why you'll stan this
- Learn Windows internals without getting blocked by noise.  
- Generate reproducible telemetry for writeups or blue-team testing.  
- Ship a single-file C# tool and flex it on GitHub.  
- Ethical by design: outputs defensive artifacts, not exploits.

![fun-gif](https://media.giphy.com/media/3o7aD2saalBwwftBIY/giphy.gif)

---

## Features ✨
- Real-time ETW capture: process, image, FileIO, network (best-effort), PowerShell, CLR where available  
- NDJSON output (one JSON event per line) — easy to pipe into ingestion tools  
- Conservative Sigma generator (manual review required)  
- Single-file C# (.NET 8.0) — minimal deps  
- Example scenarios + lab runbook included

---

## Quickstart (super fast)
```bash
# create project
dotnet new console -n TraceCraft -f net8.0
cd TraceCraft

# add ETW package
dotnet add package Microsoft.Diagnostics.Tracing.TraceEvent

# replace Program.cs with TraceCraft_Program.cs from this repo
dotnet build

# collect telemetry (must be elevated; run in lab VM)
dotnet run -- collect examples/output.ndjson
# press Ctrl+C to stop

# generate Sigma (conservative)
dotnet run -- gen-sigma examples/output.ndjson examples/suspicious.yml
```

![install-gif](assets/install.gif)

---

## Example workflow (TL;DR)
1. Spin up an isolated Windows VM snapshot.  
2. Start TraceCraft collector and run safe scenarios (signed tools used oddly, PS scripts that only echo, network to localhost).  
3. Stop collector and run `gen-sigma`.  
4. Inspect Sigma and tune before feeding to a SIEM.

---

## Output format
- **NDJSON**: `TraceEventRecord` objects with `timestamp`, `provider`, `processName`, `pid`, `commandLine`, `path`, `details`.  
- **Sigma**: conservative YAML that searches `CommandLine|contains`. Always manually review.

---

## Safety & ethics (read this)
- **Do NOT** run on production or systems you don't own/authorize.  
- Run in isolated VMs with snapshots.  
- The tool is conservative by default but **always** review outputs before acting.  
- License: MIT. Use for research and defense only.

---

## Contributing & roadmap
- Add more ETW providers and better normalization.  
- Visual timeline (Blazor) for interactive review.  
- Sequence clustering (process→file→network).  
- Exporters for ELK/OTel/Influx.

---

## Credits & contact
Built by **@MpCmdRun** — red-team curious, blue-team helpful. Open an issue or PR if you want collab.

---

## 1-line repo blurb
TraceCraft — ETW-powered Windows telemetry collector & conservative Sigma generator (lab-only)

