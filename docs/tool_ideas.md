# Tool Roadmap

> Living backlog of tools to add to the Rapid7 InsightVM and InsightIDR
> surfaces exposed by this MCP server. The wiki
> ([Tool Catalog — InsightVM](../wiki/Tool-Catalog---InsightVM.md),
> [Tool Catalog — InsightIDR](../wiki/Tool-Catalog---InsightIDR.md))
> is the source of truth for **what is currently wired**. This file
> tracks **what we plan to add** and **what we have explicitly ruled
> out**. The upstream OpenAPI specs are checked in at
> [`api-specs/`](./api-specs/) for reference.

---

## Project philosophy: read-only

This MCP server is a **read-only** interface to Rapid7. It exists so an
LLM analyst can query, search, and correlate security state — it is
**not** a remediation or administration console.

Concretely, every tool in scope must satisfy all three rules:

1. **No state mutation.** No `POST`/`PUT`/`PATCH`/`DELETE` that creates,
   updates, or removes a server-side record. Investigation status
   changes, vulnerability-exception create/delete, tag assignment, custom
   threat CRUD, scan engine / template / credential writes, and
   policy-override lifecycle are all out of scope.
2. **No admin-only endpoints.** Anything that requires Console Superuser
   or console-admin role is excluded (user/role management, license
   administration, `policy_overrides/*`, scan-engine shared-secret
   rotation, console-command execution).
3. **No secret material in scope.** No `shared_credentials` (read or
   write) and no attachment uploads. Attachment *downloads* and
   *metadata* are read-only and therefore allowed; credential values
   never enter or leave the MCP.

Soft write operations that an analyst performs in their normal triage
flow (e.g., "open → investigating", "add investigation comment") are
documented in the [Excluded writes](#excluded-writes) section at the
end. They are deliberately deferred to a future, opt-in mode — not
rejected on principle, just not granted by default to an LLM.

---

## Currently wired (31 tools)

| Product | Routers | Tools |
|---|---|---|
| InsightVM | sites, assets, vulnerabilities, scans, asset_groups, remediation, reports, vm_health | 18 |
| InsightIDR | idr (investigations, logs, IOCs, health) | 8 |
| Metasploit Pro | metasploit | 5 |

Full tool list and signatures live in the wiki tool-catalog pages linked
above.

---

## Tier 1 — high value, read-only, unblocks common workflows

These are the next 20-ish tools. Each is read-only; cloud mode (v4
Integrations API) is 501 except where noted.

### InsightIDR — investigation context (v2)

| Tool | Endpoint | Notes |
|---|---|---|
| `list_investigation_rapid7_product_alerts` | `GET /idr/v2/investigations/{id}/rapid7-product-alerts` | R7-product alerts (vs third-party) on an investigation. Distinct from `list_investigation_alerts`. |

### InsightIDR — comments (v1)

| Tool | Endpoint | Notes |
|---|---|---|
| `list_idr_comments` | `GET /idr/v1/comments` | All comments on the tenant, filterable by investigation RRN. |
| `get_idr_comment` | `GET /idr/v1/comments/{rrn}` | Single comment + author + timestamp. |

### InsightIDR — entity context (v1)

The "who/what is this" trio that every investigation pivots through.

| Tool | Endpoint | Notes |
|---|---|---|
| `search_idr_assets` | `POST /idr/v1/assets/_search` | Find an asset by IP, hostname, or MAC. |
| `get_idr_asset` | `GET /idr/v1/assets/{rrn}` | Full asset record incl. agent status, OS, exposure. |
| `search_idr_local_accounts` | `POST /idr/v1/assets/local-accounts/_search` | Endpoints with local accounts. |
| `get_idr_local_account` | `GET /idr/v1/assets/local-accounts/{rrn}` | Local account detail. |
| `search_idr_accounts` | `POST /idr/v1/accounts/_search` | Domain-joined accounts (AD/Okta/etc.). |
| `get_idr_account` | `GET /idr/v1/accounts/{rrn}` | Account detail incl. privileged status. |
| `search_idr_users` | `POST /idr/v1/users/_search` | Find a user by name, email, or UID. |
| `get_idr_user` | `GET /idr/v1/users/{rrn}` | User risk score, role, MFA status. |

### InsightVM — vulnerability exceptions (v3)

Read-only views of the existing risk-acceptance register.

| Tool | Endpoint | Notes |
|---|---|---|
| `list_vulnerability_exceptions` | `GET /api/3/vulnerability_exceptions` | All current exceptions (filter by status, scope). |
| `get_vulnerability_exception` | `GET /api/3/vulnerability_exceptions/{id}` | Rationale, expiry, submitter, scope. |
| `get_vulnerability_exception_expiration` | `GET /api/3/vulnerability_exceptions/{id}/expires` | When does the exception lapse? |

*Excluded:* `POST`, `DELETE`, `PUT /expires`, `POST /{status}` — these
are the risk-acceptance writes.

### InsightVM — tags (v3)

| Tool | Endpoint | Notes |
|---|---|---|
| `list_tags` | `GET /api/3/tags` | Tag taxonomy. |
| `get_tag` | `GET /api/3/tags/{id}` | Single tag definition. |
| `get_tag_assets` | `GET /api/3/tags/{id}/assets` | Assets bearing this tag. |
| `get_tag_sites` | `GET /api/3/tags/{id}/sites` | Sites bearing this tag. |
| `get_tag_asset_groups` | `GET /api/3/tags/{id}/asset_groups` | Asset groups bearing this tag. |
| `get_tag_search_criteria` | `GET /api/3/tags/{id}/search_criteria` | Dynamic-tag query definition. |

*Excluded:* all `POST`/`PUT`/`DELETE` under `/tags/...` and the
asset-group / site / asset membership writes.

### InsightVM — policies & compliance (v3, 20 paths)

The most-asked compliance question — "are we PCI compliant?" — is
unanswerable today. This is the most consequential gap.

| Tool | Endpoint | Notes |
|---|---|---|
| `list_policies` | `GET /api/3/policies` | PCI, CIS, HIPAA, custom. |
| `get_policy` | `GET /api/3/policies/{id}` | Policy metadata. |
| `get_policy_compliance_summary` | `GET /api/3/policy/summary` | **Headline tool** — pass/fail % per policy. |
| `list_policy_assets` | `GET /api/3/policies/{id}/assets` | Which assets fail this policy? |
| `get_policy_asset` | `GET /api/3/policies/{id}/assets/{assetId}` | Per-asset compliance rollup. |
| `list_policy_groups` | `GET /api/3/policies/{id}/groups` | Top-level policy groups. |
| `get_policy_group` | `GET /api/3/policies/{id}/groups/{groupId}` | Group detail. |
| `get_policy_group_children` | `GET /api/3/policies/{id}/groups/{groupId}/children` | Subgroups + rules. |
| `get_policy_group_assets` | `GET /api/3/policies/{id}/groups/{groupId}/assets` | Assets failing this group. |
| `list_policy_rules` | `GET /api/3/policies/{id}/rules` | All rules (incl. disabled). |
| `list_disabled_policy_rules` | `GET /api/3/policies/{id}/rules/disabled` | Tuned-off rules. |
| `get_policy_rule` | `GET /api/3/policies/{id}/rules/{ruleId}` | Single rule. |
| `get_policy_rule_proof` | `GET /api/3/policies/{id}/rules/{ruleId}/assets/{assetId}/proof` | The evidence text. |
| `get_policy_rule_controls` | `GET /api/3/policies/{id}/rules/{ruleId}/controls` | Which controls this rule maps to. |
| `get_policy_rule_rationale` | `GET /api/3/policies/{id}/rules/{ruleId}/rationale` | Why the rule exists. |
| `get_policy_rule_remediation` | `GET /api/3/policies/{id}/rules/{ruleId}/remediation` | How to fix a failing rule. |

*Excluded:* `policy_overrides/*` (admin-only lifecycle of policy
exception grants).

---

## Tier 2 — natural follow-ons, read-only

### InsightVM — solutions & software (v3)

The "how do I fix this CVE?" follow-on to a vulnerability lookup.

| Tool | Endpoint | Notes |
|---|---|---|
| `get_vulnerability_solutions` | `GET /api/3/vulnerabilities/{id}/solutions` | All solutions for a vuln. |
| `list_solutions` | `GET /api/3/solutions` | Paged solution catalog. |
| `get_solution` | `GET /api/3/solutions/{id}` | Solution detail. |
| `get_solution_prerequisites` | `GET /api/3/solutions/{id}/prerequisites` | What must be true first. |
| `get_solution_supersedes` | `GET /api/3/solutions/{id}/supersedes` | Older solutions this replaces. |
| `get_solution_superseding` | `GET /api/3/solutions/{id}/superseding` | Newer solutions that replace this. |
| `list_software` | `GET /api/3/software` | Software inventory across the estate. |
| `get_software` | `GET /api/3/software/{id}` | Assets running this software. |

### InsightVM — threat context (v3)

| Tool | Endpoint | Notes |
|---|---|---|
| `list_exploits` | `GET /api/3/exploits` | Known exploits (Metasploit, Core Impact, Canvas, etc.). |
| `get_exploit` | `GET /api/3/exploits/{id}` | Single exploit. |
| `get_exploitable_vulnerabilities` | `GET /api/3/exploits/{id}/vulnerabilities` | Vulns reachable by this exploit. |
| `list_malware_kits` | `GET /api/3/malware_kits` | Malware kit catalog. |
| `get_malware_kit` | `GET /api/3/malware_kits/{id}` | Single kit. |
| `get_malware_kit_vulnerabilities` | `GET /api/3/malware_kits/{id}/vulnerabilities` | Vulns exploited by this kit. |

### InsightVM — vulnerability taxonomy (v3)

| Tool | Endpoint | Notes |
|---|---|---|
| `list_vulnerability_categories` | `GET /api/3/vulnerability_categories` | Top-level categories. |
| `get_vulnerability_category` | `GET /api/3/vulnerability_categories/{id}` | Category detail. |
| `get_vulnerability_category_vulns` | `GET /api/3/vulnerability_categories/{id}/vulnerabilities` | Vulns in a category. |
| `list_vulnerability_checks` | `GET /api/3/vulnerability_checks` | All vuln checks. |
| `get_vulnerability_check` | `GET /api/3/vulnerability_checks/{id}` | Single check (what it does, how it works). |
| `list_operating_systems` | `GET /api/3/operating_systems` | Known OS fingerprints. |
| `get_operating_system` | `GET /api/3/operating_systems/{id}` | OS detail. |

### InsightVM — scan infrastructure (read-only views)

| Tool | Endpoint | Notes |
|---|---|---|
| `list_scan_engines` | `GET /api/3/scan_engines` | All engines + status. |
| `get_scan_engine` | `GET /api/3/scan_engines/{id}` | Single engine. |
| `get_scan_engine_pools_for_engine` | `GET /api/3/scan_engines/{id}/scan_engine_pools` | Pool memberships. |
| `get_scan_engine_scans` | `GET /api/3/scan_engines/{id}/scans` | Scans run by this engine. |
| `get_scan_engine_sites` | `GET /api/3/scan_engines/{id}/sites` | Sites this engine scans. |
| `list_scan_engine_pools` | `GET /api/3/scan_engine_pools` | All pools. |
| `get_scan_engine_pool` | `GET /api/3/scan_engine_pools/{id}` | Pool detail. |
| `get_scan_engine_pool_engines` | `GET /api/3/scan_engine_pools/{id}/engines` | Engines in this pool. |
| `get_scan_engine_pool_sites` | `GET /api/3/scan_engine_pools/{id}/sites` | Sites assigned to this pool. |
| `list_scan_templates` | `GET /api/3/scan_templates` | Scan templates. |
| `get_scan_template` | `GET /api/3/scan_templates/{id}` | Single template. |
| `list_sonar_queries` | `GET /api/3/sonar_queries` | Project Sonar queries. |
| `search_sonar_queries` | `POST /api/3/sonar_queries/search` | Search by criteria (POST = read semantically). |
| `get_sonar_query` | `GET /api/3/sonar_queries/{id}` | Single Sonar query. |
| `get_sonar_query_assets` | `GET /api/3/sonar_queries/{id}/assets` | Assets matching this Sonar query. |

*Excluded:* all `POST`/`PUT`/`DELETE` under these paths (engine / pool /
template / Sonar writes are admin operations), and the entire
`/scan_engines/shared_secret` group (admin secret rotation).

### InsightVM — discovery & auth (read-only)

| Tool | Endpoint | Notes |
|---|---|---|
| `list_discovery_connections` | `GET /api/3/discovery_connections` | Configured discovery sources. |
| `get_discovery_connection` | `GET /api/3/discovery_connections/{id}` | Single connection. |
| `list_authentication_sources` | `GET /api/3/authentication_sources` | AD / LDAP sources. |
| `get_authentication_source` | `GET /api/3/authentication_sources/{id}` | Single source. |
| `get_authentication_source_users` | `GET /api/3/authentication_sources/{id}/users` | Users in this source. |

*Excluded:* `POST /discovery_connections/{id}/connect` (admin trigger).

### InsightVM — reporting metadata (read-only)

| Tool | Endpoint | Notes |
|---|---|---|
| `list_report_templates` | `GET /api/3/report_templates` | Available report templates. |
| `get_report_template` | `GET /api/3/report_templates/{id}` | Single template (sections, parameters). |
| `list_report_formats` | `GET /api/3/report_formats` | Output formats (PDF, CSV, etc.). |

### InsightVM — administration (read-only, non-admin)

| Tool | Endpoint | Notes |
|---|---|---|
| `get_console_info` | `GET /api/3/administration/info` | Console version, hostname, build. Non-admin. |
| `get_console_properties` | `GET /api/3/administration/properties` | Server-side properties. Informational. |

*Excluded:* `/administration/license`, `/administration/settings`,
`/administration/logs`, and `POST /administration/commands` (admin).

### InsightIDR — attachments & webhooks (read-only)

| Tool | Endpoint | Notes |
|---|---|---|
| `list_idr_attachments` | `GET /idr/v1/attachments` | Attachments on the tenant. |
| `get_idr_attachment_metadata` | `GET /idr/v1/attachments/{rrn}/metadata` | Filename, size, MIME, author. |
| `download_idr_attachment` | `GET /idr/v1/attachments/{rrn}` | Binary download. May be awkward via MCP. |
| `list_idr_cloud_webhooks` | `GET /idr/v1/cloud-webhooks` | Configured webhooks (read-only). |
| `get_idr_cloud_webhook` | `GET /idr/v1/cloud-webhooks/{webhook_rrn}` | Single webhook. |

*Excluded:* all `POST`/`PUT`/`DELETE`/`PATCH` on attachments and
webhooks (uploads, deletions, replays, tests, validations).

---

## Tier 3 — nice-to-have, larger surface

| Product | Area | Why wait |
|---|---|---|
| VM | `policy_overrides/*` reads (current state of overrides) | Even the reads are admin-flavored; defer until a concrete need. |
| VM | `reports/{id}/history` (already partly wired) and `reports/{id}/download` | Already covered; just need to confirm the download path is included. |
| VM | `administration/properties` and `administration/info` (Tier 2) are the only admin reads we permit; anything else is out. |
| IDR | Investigation write ops (status, priority, disposition, assignee, bulk_close, comment create) | See [Excluded writes](#excluded-writes). |
| IDR | Custom threat CRUD (community threats + indicator add/replace) | See [Excluded writes](#excluded-writes). |
| IDR | Webhook create / replay / test | See [Excluded writes](#excluded-writes). |
| IDR | Collector lifecycle | Infra management. |

---

## Excluded writes

These endpoints are **not** part of the MCP, listed here so the omission
is explicit and discoverable. If a future requirement calls for
bounded write capability (e.g., "move investigation from OPEN to
INVESTIGATING"), that would be a separate, opt-in tool group with its
own confirmation flow — not a quiet addition to the default surface.

### InsightIDR

| Excluded | Endpoint | Reason |
|---|---|---|
| `update_investigation_status` | `PUT /idr/v2/investigations/{id}/status/{status}` | Triage state change. |
| `update_investigation_priority` | `PUT /idr/v2/investigations/{id}/priority/{priority}` | Re-prioritization. |
| `update_investigation_disposition` | `PUT /idr/v2/investigations/{id}/disposition/{disposition}` | True/false positive decision. |
| `assign_investigation` | `PUT /idr/v2/investigations/{id}/assignee` | Hands off to a user. |
| `bulk_close_investigations` | `POST /idr/v2/investigations/bulk_close` | Mass mutation. |
| `add_investigation_comment` | `POST /idr/v1/comments` | Append-only mutation. |
| `update_comment_visibility` | `PUT /idr/v1/comments/{rrn}/{visibility}` | Visibility change. |
| `delete_comment` | `DELETE /idr/v1/comments/{rrn}` | Destructive. |
| `remove_alert_from_investigation` | `DELETE /idr/v2/investigations/{id}/alerts/{alertRrn}` | Destructive; affects detection coverage. |
| `create_custom_threat` / `add_indicators` / `replace_indicators` / `delete_custom_threat` | `/idr/v1/customthreats/...` | Threat-intel mutations; high blast radius. |
| `create_idr_cloud_webhook` / `update` / `delete` / `replay` / `test` / `validation` | `/idr/v1/cloud-webhooks/...` | Infra mutations. |
| `upload_attachment` / `delete_attachment` | `/idr/v1/attachments/...` | Attachment upload excluded by project policy. |
| `add_collector` | `POST /idr/v1/collectors` | Infra provision. |

### InsightVM

| Excluded | Endpoint | Reason |
|---|---|---|
| `create_vulnerability_exception` / `delete` / `update_expiration` / `set_status` | `/api/3/vulnerability_exceptions/...` | Risk acceptance is a serious modification. |
| All `tags/...` writes (asset/site/asset_group/search_criteria membership) | `/api/3/tags/...` | Tag assignment mutates asset metadata. |
| All `policy_overrides/...` writes | `/api/3/policy_overrides/...` | Admin-only lifecycle. |
| All `scan_engines/...` writes (incl. `/shared_secret`) | `/api/3/scan_engines/...` | Engine lifecycle + secret rotation. |
| All `scan_engine_pools/...` writes | `/api/3/scan_engine_pools/...` | Pool membership changes. |
| All `scan_templates/...` writes | `/api/3/scan_templates/...` | Template content changes. |
| All `sonar_queries/...` writes (the `POST /_search` is fine) | `/api/3/sonar_queries/...` | Sonar query CRUD. |
| `create_user` / `update_user` / `delete_user` / `set_password` / `set_2FA` / `unlock` / `set_role` / `set_asset_group_access` / `set_site_access` | `/api/3/users/...` | Admin-only user lifecycle. |
| `create_role` / `update_role` / `delete_role` | `/api/3/roles/...` | Admin-only RBAC. |
| `set_license` / `console_command` | `/api/3/administration/...` | Admin. |
| All `shared_credentials/...` endpoints (read AND write) | `/api/3/shared_credentials/...` | Secret material; excluded by project policy. |
| All scan write operations (start / stop / pause / resume / archive) | `/api/3/sites/{id}/scans/...` | Project's read-only philosophy. |
| All site CRUD (create / update / delete site, scan schedule, etc.) | `/api/3/sites/...` | Site lifecycle is admin. |
| `create_asset_group` / `update` / `delete` | `/api/3/asset_groups/...` | Asset-group lifecycle. |
| `create_remediation_project` / update / delete | `/api/3/remediation_projects/...` | Remediation lifecycle. |
| `create_report` / `delete_report` | `/api/3/reports/...` (writes only) | Report lifecycle. `generate` (POST `/reports/{id}/generate`) is already in the read-only catalog as a tool because it returns a generated artifact rather than mutating config. |

---

## Suggested next sprint

The smallest useful chunk: **Tier 1 only**, ~20 new tools across 5 new
routers. Cloud-mode impact: all read tools are local-only (v3) — v4
Integrations API does not cover tags, exceptions, policies, IDR
entities, or comments — so they all 501 in cloud mode. This is the
correct behavior; the docs for each tool should state "501 in cloud".

Recommended slicing for the sprint:

1. `routers/idr_investigations_extras.py` — `list_investigation_rapid7_product_alerts`
2. `routers/idr_comments.py` — `list_idr_comments`, `get_idr_comment`
3. `routers/idr_entities.py` — assets / accounts / users (search + get)
4. `routers/vm_tags.py` — list / get / get-assets / get-sites / get-asset-groups / get-search-criteria
5. `routers/vm_exceptions.py` — list / get / get-expiration
6. `routers/vm_policies.py` — list / get / summary / per-asset / per-group / per-rule endpoints
