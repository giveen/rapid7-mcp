# API Specs

OpenAPI / Swagger 2.0 documents for the Rapid7 surfaces this MCP
server integrates with. Used as a reference for tool design, response
shape mapping, and cloud-vs-local branching.

| File | Product | Mode | Paths | What it covers |
|---|---|---|---|---|
| `insightvm-v3.json` | InsightVM | Local (on-prem console) | 207 | The full v3 console API used by every VM router that exists today, plus most of the ones planned in `../tool_ideas.md`. |
| `insightvm-v4-cloud.json` | InsightVM | Cloud (Insight Platform) | 11 | The slim v4 Integrations API. Covers the cloud branches of `sites`, `assets`, `vulnerabilities`, `scans`, and the `get_vm_health` endpoint. Everything else returns 501 in cloud. |
| `insightidr-v1.json` | InsightIDR | Cloud | 29 | Tenant management surface: accounts, assets, users, comments, custom threats, cloud webhooks, collectors, attachments, and the older `/idr/v1/investigations` form. |
| `insightidr-v2.json` | InsightIDR | Cloud | 11 | The current investigations surface: list/get/search, alert membership, R7-product alerts, and the state-change endpoints that are deliberately excluded by the project's read-only philosophy. |

## Source

- v3 / v4 InsightVM specs: <https://help.rapid7.com/insightvm/en-us/api/>
- v1 / v2 InsightIDR specs: <https://developer.rapid7.com/>

Snapshots captured June 2026. If the vendor ships breaking schema
changes, refresh by re-downloading and replacing these files.
