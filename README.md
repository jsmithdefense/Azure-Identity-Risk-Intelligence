# Azure RBAC Risk Analyzer

**Enumerate, score, and remediate overprivileged identities across your Azure tenant.**

No third-party platforms. No agents. No connectors. Just the Azure SDK and the Anthropic API running against your control plane.

---

> *"The analysts group can actively manage Microsoft Sentinel incidents and alerts in the production SOC resource group — including dismissing, closing, or modifying incident status — actions that could suppress legitimate detections or obscure attacker activity."*
>
> — AI-generated capability summary produced by this tool against a live Azure environment

---

## What It Does

Azure environments accumulate RBAC assignments over time. Role names are opaque, assignments are scattered across subscriptions, and no native tooling tells you which identities represent the greatest real-world risk — or what to do about it.

This tool:
- **Enumerates** all role assignments across every accessible subscription
- **Classifies** roles by what their permissions actually allow, not just their names
- **Scores** principals by cumulative privilege exposure across all subscriptions
- **Generates** AI-powered capability narratives explaining real-world abuse potential
- **Executes** approved remediations directly against your environment via the Azure SDK

---

## Quick Start

### Prerequisites
- Python 3.12+
- Azure CLI (`az login`)
- `Reader` role at subscription scope
- Microsoft Graph read permissions for principal name resolution
- Anthropic API key (optional — required for AI enrichment only)

### Install
```bash
git clone https://github.com/jsmithdefense/Azure-RBAC-Risk-Analyzer
cd Azure-RBAC-Risk-Analyzer

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
az login
```

### Run
```bash
python -m src.main
```

### With AI Enrichment
```bash
export ANTHROPIC_API_KEY=your_key_here
python -m src.main
```

---

## Sample Output

### Principal Risk Analysis
```
Name = analysts (500 members) | Type = Group | Severity = Critical | Score = 475
  - Medium | 55 | Microsoft Sentinel Responder | resource_control_broad | production-soc-rg
  - Medium | 40 | Alert Rules Admin            | resource_control_narrow | production-soc-rg
  - Medium | 40 | Student NSG User             | resource_control_narrow | network-controls-rg
  - Low    | 30 | Student Subnet Joiner        | resource_control_narrow | core-vnet
```

### AI Capability Summary
```
- The analysts group can create, modify, and delete Sentinel alert rules via the 
  Alert Rules Admin role — meaning they could disable or weaken detection logic 
  within the SOC workspace, directly undermining the integrity of monitoring.

- The combination of alert rule write access and Sentinel Responder permissions 
  creates a realistic defense evasion path: group members could disable detections, 
  suppress active incidents, and cover their tracks — all within their assigned roles.
```

### Remediation Engine
```
REMEDIATION ENGINE
============================================================
  Principal: analysts (Group)
    1. [CRITICAL | Effort: Low]    Remove Alert Rules Admin       (remove_role_assignment)
    2. [CRITICAL | Effort: Medium] Convert Sentinel Responder     (convert_to_pim_eligible)
    3. [HIGH     | Effort: Low]    Remove Student NSG User        (remove_role_assignment)

Select actions to execute (comma-separated, 0=all, S=skip):
```

---

## How It Works

### Role Classification
Roles are classified by what their permissions actually allow — not just their names. A custom role containing `*/write` permissions gets flagged regardless of what it's called.

| Classification | What It Means |
|---|---|
| `privilege_escalation` | Can modify access control |
| `resource_control_broad` | Can create or modify infrastructure |
| `resource_control_narrow` | Controls a specific service domain |
| `data_access` | Can read or extract stored data |
| `security_visibility` | Can view monitoring or security telemetry |
| `read_only` | Limited to metadata inspection |

### Cumulative Risk Scoring
Principal risk is the sum of all assignment scores across all subscriptions — not just the highest single role. This surfaces identities that accumulate significant privilege through multiple lower-severity assignments.

### AI Enrichment
Select which principals to analyze, choose your model, review the estimated cost before confirming. Each enriched principal gets a plain-English capability summary and a prioritized remediation playbook with **Why**, **Steps**, and **Validation** for each action.

### Remediation Engine
AI output is parsed into structured, machine-executable actions. Each action is presented for individual approval, logged to an audit file, executed via the Azure SDK, and validated.

| Action Type | Behavior |
|---|---|
| `remove_role_assignment` | Executes removal via Azure SDK, validates success |
| `convert_to_pim_eligible` | Provides step-by-step PIM instructions |
| `manual_review_required` | Logs description for human execution |

---

## Required Permissions

| Permission | Purpose |
|---|---|
| `Reader` at subscription scope | RBAC enumeration |
| `Microsoft.Graph` read access | Principal name resolution |
| `Microsoft.Authorization/roleAssignments/delete` | Remediation execution |

---

## Project Structure
```
Azure-RBAC-Risk-Analyzer/
├── src/
│   ├── main.py                    # Pipeline orchestration
│   ├── rbac_collector.py          # Azure RBAC enumeration
│   ├── role_taxonomy_generator.py # Capability inference
│   ├── risk_model.py              # Cumulative scoring
│   ├── scope_utils.py             # Scope normalization
│   ├── ai_enrichment.py           # AI analysis and remediation parsing
│   ├── report_writer.py           # JSON report generation
│   ├── pdf_report.py              # PDF report generation
│   ├── remediation_engine.py      # Azure SDK execution engine
│   ├── models.py                  # Data structures
│   └── config_loader.py           # Configuration management
├── config/
│   └── role_taxonomy.json         # Role capability classifications
├── reports/                       # Generated reports (gitignored)
└── requirements.txt
```

---

## Roadmap

- [x] Multi-subscription RBAC enumeration and tenant-level aggregation
- [x] Capability-based role classification with analyst override taxonomy
- [x] Cumulative principal risk scoring across subscriptions
- [x] Subscription risk ranking
- [x] Structured JSON report output
- [x] Interactive AI enrichment with model selection and cost estimation
- [x] AI capability summaries with prioritized remediation playbooks
- [x] PDF report export
- [x] Remediation engine with per-action approval and audit logging
- [ ] Recursive group membership expansion for user-level blast radius analysis
- [ ] Privilege escalation path detection
- [ ] Historical report diffing between runs
- [ ] Terraform lab environment for controlled testing

---

## Authentication

Uses `DefaultAzureCredential`. Resolves to your Azure CLI session in local environments. No credentials are stored.

```bash
az login
```
