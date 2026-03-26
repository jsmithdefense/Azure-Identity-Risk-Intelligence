# Azure RBAC Risk Analyzer

> *"Students can actively manage Microsoft Sentinel incidents and alerts in 
> Cyber-Range-Admin-SOC — including dismissing, closing, or modifying incident 
> status — actions that could suppress legitimate detections or obscure attacker 
> activity during exercises."*
>
> — AI-generated capability summary produced by this tool against a live Azure environment

---

## The Problem

Azure environments accumulate RBAC assignments over time. Role names are often 
opaque, assignments are scattered across subscriptions, and no native tooling tells 
you which identities represent the greatest real-world risk — or what to do about it.

Security teams need to know: **who can do what, across which resources, and what 
happens if that access is abused.**

---

## What This Tool Does

The Azure RBAC Risk Analyzer enumerates role assignments across your entire Azure 
tenant, scores each principal by cumulative privilege exposure, generates AI-powered 
capability narratives explaining the real-world impact of each identity's access, 
and offers to execute approved remediations directly against your environment.

**No third-party platforms. No agents. No connectors.** Just the Azure SDK and the 
Anthropic API running against your control plane.

---

## Who This Is For

| Persona | Use Case |
|---|---|
| Security Engineers | Tenant-wide RBAC risk assessment |
| SOC Analysts | Identity threat investigation |
| Cloud Architects | Privilege accumulation detection |
| Compliance Teams | Audit-ready risk documentation |
| Penetration Testers | Pre-engagement identity reconnaissance |

---

## Features

**Multi-Subscription Tenant Analysis**
Enumerate all accessible subscriptions, select individual targets or analyze all at 
once. Risk is aggregated at the tenant level with per-subscription ranking.

**Capability-Based Role Classification**
Roles are classified by what their permissions actually allow — not just their names. 
A custom role containing `/action` permissions gets flagged regardless of what it's 
called.

| Classification | What It Means |
|---|---|
| `privilege_escalation` | Can modify access control |
| `resource_control_broad` | Can create or modify infrastructure |
| `resource_control_narrow` | Controls a specific service domain |
| `data_access` | Can read or extract stored data |
| `security_visibility` | Can view monitoring or security telemetry |
| `read_only` | Limited to metadata inspection |

**Cumulative Risk Scoring**
Principal risk is the sum of all assignment scores across all subscriptions — not 
just the single highest role. This surfaces identities that accumulate significant 
privilege through multiple lower-severity assignments.

**Interactive AI Enrichment**
Select which principals to analyze, choose your model, review the estimated cost 
before confirming. Each enriched principal receives:
- Plain-English capability summary explaining operational impact and abuse potential
- Prioritized remediation playbook with Why, Steps, and Validation for each action

**PDF Report Export**
Professional security report suitable for stakeholder review. Includes tenant 
summary, subscription rankings, role classifications, principal risk analysis, and 
the full AI enrichment output with formatted remediation playbooks.

**Remediation Engine**
AI output is parsed into structured, machine-executable actions. Each action is 
presented for individual approval, logged to an audit file before execution, 
executed via the Azure SDK, and validated.

| Action Type | Behavior |
|---|---|
| `remove_role_assignment` | Executes removal via Azure SDK, validates success |
| `convert_to_pim_eligible` | Provides step-by-step PIM instructions |
| `manual_review_required` | Logs description for human execution |

---

## Sample Output

### Principal Risk Analysis
```
Name = students (2437 members) | Type = Group | Severity = Critical | Score = 475
  - Medium | 55 | Microsoft Sentinel Responder | resource_control_broad | Cyber-Range-Admin-SOC
  - Medium | 40 | Alert Rules Admin            | resource_control_narrow | Cyber-Range-Admin-SOC  
  - Medium | 40 | Student NSG User             | resource_control_narrow | Cyber-Range-NSGs
  - Low    | 30 | Student Subnet Joiner        | resource_control_narrow | Cyber-Range-VNet
```

### AI Capability Summary
```
- Students can create, modify, and delete Sentinel alert rules via the Alert Rules 
  Admin role — meaning they could disable or weaken detection logic within the SOC 
  workspace, directly undermining the integrity of monitoring.

- The combination of alert rule write access and Sentinel Responder permissions 
  creates a realistic defense evasion path: students could disable detections, 
  suppress active incidents, and cover their tracks — all within their assigned roles.
```

### Remediation Playbook
```
[CRITICAL | Effort: Low] Remove Alert Rules Admin from students group

Why
Students with write access to Sentinel analytics rules can disable detections
that instructors depend on to monitor the range.

Steps
  1. Navigate to Azure Portal → Cyber-Range-Admin-SOC → Access control (IAM)
  2. Filter Role assignments by the students group
  3. Locate Alert Rules Admin → Remove → Confirm

Validation
az role assignment list --assignee <group-id> --resource-group Cyber-Range-Admin-SOC
Confirm no Alert Rules Admin entry is returned.
```

### Remediation Engine
```
REMEDIATION ENGINE
============================================================
  Principal: students (Group)
    1. [CRITICAL | Effort: Low]    Remove Alert Rules Admin       (remove_role_assignment)
    2. [CRITICAL | Effort: Medium] Convert Sentinel Responder     (convert_to_pim_eligible)
    3. [HIGH     | Effort: Low]    Remove Student NSG User        (remove_role_assignment)

Select actions to execute (comma-separated, 0=all, S=skip):
```

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

## Required Permissions

| Permission | Purpose |
|---|---|
| `Reader` at subscription scope | RBAC enumeration |
| `Microsoft.Graph` read access | Principal name resolution |
| `Microsoft.Authorization/roleAssignments/delete` | Remediation execution |

---

## Roadmap

### Completed
- [x] Multi-subscription RBAC enumeration and tenant-level aggregation
- [x] Capability-based role classification with analyst override taxonomy
- [x] Cumulative principal risk scoring across subscriptions
- [x] Subscription risk ranking
- [x] Structured JSON report output
- [x] Interactive AI enrichment with model selection and cost estimation
- [x] AI capability summaries with prioritized remediation playbooks
- [x] PDF report export
- [x] Remediation engine with per-action approval and audit logging

### Planned
- [ ] Remediation execution testing against isolated lab environment
- [ ] Recursive group membership expansion for user-level blast radius analysis
- [ ] Privilege escalation path detection
- [ ] Historical report diffing between runs
- [ ] Terraform lab environment for controlled testing

---

## Authentication

Uses `DefaultAzureCredential` from the Azure SDK. Resolves to your Azure CLI 
session in local environments. No credentials are stored in the repository.
```bash
az login
```