"""MITRE ATLAS mapping enrichment — maps signals to ATLAS techniques."""

from __future__ import annotations

from typing import Any

from threatlens.models import AttackCategory

# Extended ATLAS technique database
ATLAS_TECHNIQUES: dict[str, dict[str, Any]] = {
    "AML.T0001": {
        "id": "AML.T0001",
        "name": "ML Model Access",
        "tactics": ["Initial Access"],
        "description": "Adversary gains access to ML model endpoints",
        "mitigations": ["Rate limiting", "Authentication", "API security"],
    },
    "AML.T0044": {
        "id": "AML.T0044",
        "name": "Resource Discovery",
        "tactics": ["Discovery"],
        "description": "Adversary probes for available resources",
        "mitigations": ["Access control", "Monitoring", "Request filtering"],
    },
    "AML.T0051": {
        "id": "AML.T0051",
        "name": "LLM Prompt Injection",
        "tactics": ["Initial Access"],
        "description": "Adversary injects malicious prompts into LLM",
        "mitigations": ["Input validation", "Prompt filtering", "Rate limiting"],
    },
    "AML.T0051.001": {
        "id": "AML.T0051.001",
        "name": "Direct Prompt Injection",
        "tactics": ["Initial Access"],
        "description": "Direct injection of adversarial prompts",
        "mitigations": ["Input sanitization", "Context isolation"],
    },
    "AML.T0054": {
        "id": "AML.T0054",
        "name": "Jailbreak",
        "tactics": ["Initial Access"],
        "description": "Adversary bypasses model safeguards",
        "mitigations": ["Safety training", "Red teaming", "Behavioral monitoring"],
    },
    "AML.T0054.001": {
        "id": "AML.T0054.001",
        "name": "Adversarial Perturbations",
        "tactics": ["Initial Access"],
        "description": "Subtle input modifications to evade detection",
        "mitigations": ["Adversarial training", "Input perturbation detection"],
    },
    "AML.T0058": {
        "id": "AML.T0058",
        "name": "Steganography",
        "tactics": ["Defense Evasion"],
        "description": "Hidden data within model inputs or outputs",
        "mitigations": ["Content inspection", "Entropy analysis"],
    },
    "AML.T0059": {
        "id": "AML.T0059",
        "name": "Remote Code Execution",
        "tactics": ["Execution"],
        "description": "Execution of arbitrary code through model vectors",
        "mitigations": ["Sandboxing", "Input validation", "Tool restrictions"],
    },
    "AML.T0059.001": {
        "id": "AML.T0059.001",
        "name": "Sandbagged RCE",
        "tactics": ["Execution"],
        "description": "Delayed or disguised RCE execution",
        "mitigations": ["Dynamic analysis", "Behavior monitoring"],
    },
    "AML.T0059.002": {
        "id": "AML.T0059.002",
        "name": "Command Injection",
        "tactics": ["Execution"],
        "description": "Injection of system commands through inputs",
        "mitigations": ["Command sanitization", "Whitelist validation"],
    },
    "AML.T0060": {
        "id": "AML.T0060",
        "name": "Server-Side Request Forgery",
        "tactics": ["Execution"],
        "description": "Forcing server to make unintended requests",
        "mitigations": ["URL validation", "Network segmentation"],
    },
    "AML.T0061": {
        "id": "AML.T0061",
        "name": "SQL Injection",
        "tactics": ["Execution"],
        "description": "Injection of SQL queries through inputs",
        "mitigations": ["Parameterized queries", "Input sanitization"],
    },
    "AML.T0062": {
        "id": "AML.T0062",
        "name": "Malware Generation",
        "tactics": ["Execution"],
        "description": "Using ML to generate malicious code",
        "mitigations": ["Output filtering", "Usage monitoring"],
    },
    "AML.T0065": {
        "id": "AML.T0065",
        "name": "Impersonation",
        "tactics": ["Credential Access"],
        "description": "Adversary impersonates legitimate users or systems",
        "mitigations": ["Authentication", "Behavioral analytics"],
    },
    "AML.T0066": {
        "id": "AML.T0066",
        "name": "Tool Poisoning",
        "tactics": ["Defense Evasion"],
        "description": "Adversary manipulates tool outputs to mislead system",
        "mitigations": ["Tool verification", "Output validation"],
    },
    "AML.T0066.001": {
        "id": "AML.T0066.001",
        "name": "Tool Function Manipulation",
        "tactics": ["Defense Evasion"],
        "description": "Modifying tool function behavior or results",
        "mitigations": ["Integrity checks", "Function monitoring"],
    },
    "AML.T0067": {
        "id": "AML.T0067",
        "name": "Exfiltration via API",
        "tactics": ["Exfiltration"],
        "description": "Exfiltrating data through model API responses",
        "mitigations": ["Output monitoring", "Data loss prevention"],
    },
    "AML.T0067.001": {
        "id": "AML.T0067.001",
        "name": "Model Output Exfiltration",
        "tactics": ["Exfiltration"],
        "description": "Extracting sensitive data through model outputs",
        "mitigations": ["Output filtering", "Rate limiting"],
    },
    "AML.T0068": {
        "id": "AML.T0068",
        "name": "Policy Violation",
        "tactics": ["Impact"],
        "description": "Violation of usage or security policies",
        "mitigations": ["Policy enforcement", "Audit logging"],
    },
}


class AtlasMapper:
    def map_category(self, category: AttackCategory) -> list[dict[str, Any]]:
        mapping = {
            AttackCategory.INJECTION: ["AML.T0051", "AML.T0051.001"],
            AttackCategory.JAILBREAK: ["AML.T0054", "AML.T0054.001"],
            AttackCategory.EXFILTRATION: ["AML.T0067", "AML.T0067.001"],
            AttackCategory.TOOL_POISONING: ["AML.T0066", "AML.T0066.001"],
            AttackCategory.RCE: ["AML.T0059", "AML.T0059.001"],
            AttackCategory.CMD_INJECTION: ["AML.T0059.002"],
            AttackCategory.SQL_INJECTION: ["AML.T0061"],
            AttackCategory.SSRF: ["AML.T0060"],
            AttackCategory.STEGO: ["AML.T0058"],
            AttackCategory.MALWARE: ["AML.T0062"],
            AttackCategory.IMPERSONATION: ["AML.T0065"],
            AttackCategory.POLICY_VIOLATION: ["AML.T0068"],
            AttackCategory.RESOURCE_SCAN: ["AML.T0044"],
        }

        return [
            ATLAS_TECHNIQUES.get(ttp_id, {"id": ttp_id}) for ttp_id in mapping.get(category, [])
        ]

    def get_technique(self, ttp_id: str) -> dict[str, Any] | None:
        return ATLAS_TECHNIQUES.get(ttp_id)

    def search(self, query: str) -> list[dict[str, Any]]:
        query = query.lower()
        results: list[dict[str, Any]] = []
        for ttp_id, technique in ATLAS_TECHNIQUES.items():
            if query in ttp_id.lower() or query in technique["name"].lower():
                results.append({"id": ttp_id, **technique})
        return results
