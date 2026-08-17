# rapid7-mcp

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![CI](https://github.com/jmorales-savers/rapid7-mcp/actions/workflows/ci.yml/badge.svg)
![Wiki Publish](https://github.com/jmorales-savers/rapid7-mcp/actions/workflows/wiki-publish.yml/badge.svg)

A unified MCP server for Rapid7's security platform — exposing [InsightVM](https://www.rapid7.com/products/insightvm/) (vulnerability management), [InsightIDR](https://www.rapid7.com/products/insightidr/) (SIEM/investigations), [Automation (InsightConnect)](https://docs.rapid7.com/insightconnect/) (workflow automation), and [Metasploit Pro](https://www.rapid7.com/products/metasploit/) (pentest telemetry) as tools for Claude, Cursor, and any MCP-compatible LLM client.

Ask natural-language questions across your entire Rapid7 environment — vulnerabilities, active incidents, compromised hosts — and get structured answers without writing a single API call.

Built with [fastapi-mcp](https://github.com/tadata-ru/fastapi-mcp), [FastAPI](https://fastapi.tiangolo.com/), and [httpx](https://www.python-httpx.org/).

> **No Rapid7 instance?** Set `DEMO_MODE=true` to explore all 55 tools against realistic fixture data. Clone, run, connect — no credentials required.

---

## What you can do

Once connected to Claude, you can ask things like:

> _"Which of my sites has the highest risk score?"_
> _"What are the critical vulnerabilities on the production web server, and is there already a remediation project for them?"_
> _"Is Log4Shell present anywhere in my environment? Show me the CVSS score and any available exploits."_
> _"Are there any open InsightIDR investigations right now? What's the highest priority one?"_
> _"Search our logs for any connections to this IP address: 185.220.101.1"_
> _"What active Metasploit sessions exist and what hosts were compromised?"_
> _"Give me a full security posture summary across sites, open incidents, and active sessions."_

The server translates these into API calls across InsightVM, InsightIDR, and Metasploit Pro and returns structured data that Claude can reason over, correlate, and summarize.

---

## Architecture

```text
Claude / Cursor / MCP Client
        │  MCP (Streamable HTTP)
        ▼
┌─────────────────────────────────────────────────┐
│  FastAPI + fastapi-mcp  :8000                   │
│                                                 │
│  InsightVM      InsightIDR       InsightConnect │
│  ──────────────  ───────────────  ──────────── │
│  /sites          /idr/invest.     /connect/jobs │
│  /assets         /idr/logs        /connect/wfs  │
│  /asset_groups   /idr/rules                     │
│  /vulnerabilities /idr/entities  MSP            │
│  /scans          /idr/iocs        ───────────── │
│  /remediation                     /workspaces   │
│  /reports                         /sessions     │
│                                   /loot         │
│  /mcp  ← MCP endpoint                           │
└──────┬──────────────┬─────────────┬─────────────┘
       │ Basic Auth   │ X-Api-Key   │ Token
       ▼              ▼             ▼
  InsightVM      Insight Platform  Metasploit
  Console        (IDR + Connect)   Pro Console
  :3780          (regional)        :3790
```

Every FastAPI route is automatically published as an MCP tool via `fastapi-mcp`. Operation IDs become tool names, Pydantic schemas become input/output schemas, and docstrings become tool descriptions.

---

## Quick Start

**Prerequisites:** Python 3.11+, [uv](https://docs.astral.sh/uv/getting-started/installation/)

```bash
# 1. Clone and install
git clone https://github.com/jmorales-savers/rapid7-mcp.git
cd rapid7-mcp
uv sync

# 2. Configure (or skip and use DEMO_MODE)
cp .env.example .env
# edit .env with your console URLs and credentials

# 3. Start the server
DEMO_MODE=true uv run uvicorn rapid7_mcp.main:app --port 8000
```

- MCP endpoint: `http://localhost:8000/mcp`
- Interactive API docs: `http://localhost:8000/docs`

---

## Connect to VS Code

Add `.vscode/mcp.json` to your workspace (already included in this repo):

```json
{
  "servers": {
    "rapid7-mcp": {
      "type": "http",
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

Start the server first (`Ctrl+Shift+P` → **Tasks: Run Task** → **Start MCP Server (Demo Mode)**), then connect in the Claude Code panel.

## Connect to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "rapid7": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

Start the server first, then restart Claude Desktop.

---

## Available MCP Tools

### InsightVM — Vulnerability Management

| Tool | Description |
| --- | --- |
| `list_sites` | List all scan sites — names, asset counts, risk scores, last scan time |
| `get_site` | Full details for a single site |
| `list_asset_groups` | Logical asset groupings (PCI scope, DMZ, dynamic OS groups) |
| `get_asset_group` | Details for a single asset group |
| `get_asset` | Asset details — IP, hostname, OS, vulnerability counts by severity, risk score |
| `search_assets` | Filter assets by IP, hostname, OS family, site ID, or tag |
| `get_asset_vulnerabilities` | All vulnerabilities found on a specific asset |
| `get_asset_tags` | Owner, environment, and compliance tags assigned to an asset |
| `list_vulnerabilities` | Browse the vulnerability library, filter by severity |
| `get_vulnerability` | Full vuln details — CVSS v2/v3, CVEs, exploit count, description |
| `list_scans` | Recent scans with status, duration, and vulnerability summaries |
| `get_scan` | Details for a single scan |
| `start_scan` | Trigger a new scan on a site by site ID |
| `stop_scan` | Stop a running scan |
| `list_scan_engines` | List scan engines — name, address, status, pool membership |
| `get_scan_engine` | Full details for a single scan engine |
| `update_scan_engine_configuration` | Update a scan engine's address or attributes |
| `remove_scan_engine_configuration` | Remove a scan engine from the console |
| `list_remediation_projects` | In-flight fix tracking — owner, due date, affected assets |
| `get_remediation_project` | Details for a single remediation project |
| `list_reports` | All configured reports (executive summaries, PCI exports, CSV) |
| `get_report` | Configuration and status for a single report |
| `execute_report` | Trigger on-demand report generation, returns download URI |

### InsightIDR — SIEM & Investigations

| Tool | Description |
| --- | --- |
| `list_investigations` | Open security incidents — priority, status, assignee, alert summary |
| `get_investigation` | Full alert timeline for a specific investigation |
| `list_investigation_alerts` | All alerts attached to an investigation |
| `search_investigations` | Filter investigations by status, priority, assignee, or date range |
| `assign_investigation` | Assign an investigation to an analyst |
| `set_investigation_disposition` | Set disposition: Benign/Malicious/Not Applicable/Undecided |
| `set_investigation_status` | Set status: Open/Investigating/Waiting/Closed |
| `set_investigation_priority` | Set priority: Critical/High/Medium/Low |
| `bulk_close_investigations` | Close multiple investigations at once with a disposition |
| `add_investigation_comment` | Add a triage note or analyst comment to an investigation |
| `list_investigation_comments` | List all analyst comments on an investigation |
| `query_logs` | LEQL search across firewall, proxy, DNS, and endpoint logs |
| `list_logs` | List all available log sources and their log sets |
| `list_indicators` | Active threat intelligence IOCs — IPs, domains, hashes, URLs |
| `get_health_metrics` | IDR platform health metrics (collector status, ingestion counts) |

### InsightIDR — Detection Rules

| Tool | Description |
| --- | --- |
| `list_detection_rules` | List detection rules with name, MITRE tactics, priority, state, and detection count |
| `get_detection_rule` | Full detail for a single rule — conditions, event types, exceptions, MITRE mapping |

### InsightIDR — Entity Context

| Tool | Description |
| --- | --- |
| `search_idr_accounts` | Search domain-joined accounts (AD, Okta) by username, domain, or UPN |
| `get_idr_account` | Account detail — type, privileged status, lock state, last auth time |
| `search_idr_users` | Search IDR users by name, email, or risk priority |
| `get_idr_user` | User detail — risk score (0–1000), risk priority, last-seen timestamp |
| `search_idr_assets` | Search assets tracked in IDR by hostname or IP |
| `get_idr_asset` | Asset detail by RRN |

### Automation (InsightConnect)

| Tool | Description |
| --- | --- |
| `list_connect_jobs` | List Automation jobs (workflow execution history) |
| `get_connect_job` | Get a single Automation job with step inputs/outputs |
| `list_connect_workflows` | List Automation workflows and active/inactive state |
| `get_connect_workflow` | Get one Automation workflow and version metadata |

### Metasploit Pro — Pentest Telemetry (read-only)

> These tools are intentionally read-only. The LLM can see what Metasploit knows — active sessions, collected credentials, task status — but cannot execute exploits or interact with sessions.

| Tool | Description |
| --- | --- |
| `list_workspaces` | All Metasploit Pro workspaces (pentest projects) |
| `get_workspace` | Details for a single workspace |
| `list_sessions` | Active Meterpreter and shell sessions — host, exploit, platform, username |
| `get_loot` | Credentials, hashes, and files extracted from compromised hosts |
| `list_msp_tasks` | Background tasks — scan imports, report generation, bruteforce jobs |

---

## Demo Mode

`DEMO_MODE=true` replaces all API calls with fixture data across all three products. No console, no credentials, no VPN.

Fixtures in [`tests/fixtures/`](tests/fixtures/):

| Fixture | Contents |
| --- | --- |
| `sites.json` / `site.json` | 3 sites: Production, Development, Cloud |
| `assets.json` / `asset.json` | Ubuntu and RHEL hosts with full vulnerability breakdowns |
| `asset_groups.json` / `asset_group.json` | PCI Scope, DMZ, Critical Infra, All Linux groups |
| `asset_tags.json` | Owner, environment, and compliance tags |
| `vulnerabilities.json` / `vulnerability.json` | Log4Shell, OpenSSL CVE-2022-0778, POODLE |
| `asset_vulnerabilities.json` | Vulnerabilities scoped to a single asset |
| `scans.json` / `scan.json` | One finished scan, one running |
| `scan_engines.json` / `scan_engine.json` | Scan engine list and single engine detail |
| `scan_start.json` / `scan_stop.json` | Start/stop scan response envelopes |
| `scan_engine_update_config.json` / `scan_engine_remove_config.json` | Engine update/remove responses |
| `remediation_projects.json` / `remediation_project.json` | Q1 patching sprint, Log4Shell project |
| `reports.json` / `report.json` / `report_generate.json` | Executive summary, PCI report, CSV export |
| `investigations.json` / `investigation.json` | PowerShell execution alert, SSH brute force |
| `bulk_close.json` | Bulk-close investigation response |
| `comment.json` / `comments.json` | Single comment and comment list for an investigation |
| `detection_rules.json` / `detection_rule.json` | Detection rules list and single rule with MITRE mapping |
| `idr_accounts.json` / `idr_account.json` | Domain account search results and single account detail |
| `idr_users.json` / `idr_user.json` | IDR user search results and single user with risk score |
| `idr_assets.json` / `idr_asset.json` | IDR asset search results and single asset detail |
| `log_search_results.json` | Firewall and proxy hits for a Tor exit node IP |
| `indicators.json` | Tor IP, Cobalt Strike hash, APT28 C2 domain |
| `connect_jobs.json` / `connect_job.json` | InsightConnect job history and single job with step I/O |
| `connect_workflows.json` / `connect_workflow.json` | Workflow list and single workflow with version metadata |
| `workspaces.json` / `workspace.json` | Default workspace + Q1 external pentest |
| `sessions.json` | Meterpreter (SYSTEM) + shell (tomcat) sessions |
| `loot.json` | NTLM hashes + PostgreSQL credentials |
| `msp_tasks.json` | Completed InsightVM import + running report task |

---

## Configuration

All settings via environment variable or `.env` file. Copy `.env.example` to get started.

### InsightVM

| Variable | Default | Description |
| --- | --- | --- |
| `R7_CONSOLE_URL` | `https://localhost:3780` | InsightVM console base URL |
| `R7_USERNAME` | `admin` | InsightVM user (Global Administrator role required) |
| `R7_PASSWORD` | `password` | InsightVM password |
| `R7_VERIFY_SSL` | `false` | Set to `true` if your console has a valid certificate |

### InsightIDR

| Variable | Default | Description |
| --- | --- | --- |
| `IDR_REGION` | `us` | Insight Platform region: `us`, `us2`, `us3`, `eu`, `ca`, `au`, `ap` |
| `IDR_API_KEY` | _(empty)_ | Insight Platform API key |

### Automation (InsightConnect)

| Variable | Default | Description |
| --- | --- | --- |
| `CONNECT_REGION` | _(falls back to `IDR_REGION`)_ | Automation API region |
| `CONNECT_API_KEY` | _(falls back to `IDR_API_KEY`)_ | Automation API key |

### Metasploit Pro

| Variable | Default | Description |
| --- | --- | --- |
| `MSP_URL` | `https://localhost:3790` | Metasploit Pro console base URL |
| `MSP_TOKEN` | _(empty)_ | MSP REST API token |
| `MSP_VERIFY_SSL` | `false` | Set to `true` if your MSP console has a valid certificate |

### General

| Variable | Default | Description |
| --- | --- | --- |
| `DEMO_MODE` | `false` | Return fixture data for all products; skips all live connectivity |

---

## Development

```bash
uv sync                                          # install deps + dev extras
uv run pytest --cov=rapid7_mcp tests/           # run tests with coverage
uv run ruff check . && uv run ruff format .      # lint + format
uv run mypy rapid7_mcp/                          # type check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new tool, extend fixtures, and open a pull request.

## Community & Project Health

- [Security policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Contributing guide](CONTRIBUTING.md)
- [Issue templates](.github/ISSUE_TEMPLATE/)
- [Pull request template](.github/pull_request_template.md)
- [Repository hardening checklist](.github/REPOSITORY_HARDENING.md)
- [Wiki starter docs](docs/wiki/Home.md)
- [Wiki publishing guide](docs/wiki/Publishing.md)

---

## Tech Stack

| Library | Why |
| --- | --- |
| [fastapi-mcp](https://github.com/tadata-ru/fastapi-mcp) | Converts FastAPI routes to MCP tools automatically — auth, deps, and schemas carry through |
| [httpx](https://www.python-httpx.org/) | Async HTTP client, consistent with FastAPI's async model |
| [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) | Type-safe config from env vars and `.env` files |
| [uv](https://docs.astral.sh/uv/) | Fast dependency management, becoming the standard for MCP Python projects |
| [ruff](https://docs.astral.sh/ruff/) | Replaces flake8 + black + isort in one tool |

---

## License

MIT — see [LICENSE](LICENSE).
