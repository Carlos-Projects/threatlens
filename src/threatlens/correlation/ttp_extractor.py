"""TTP extraction based on TTPrint methodology (arXiv:2605.25836)."""

from __future__ import annotations

from typing import Any

from threatlens.models import AttackCategory, RawSignal

# Mapping from attack categories to MITRE ATLAS techniques
ATLAS_TTP_MAP: dict[AttackCategory, list[dict[str, str]]] = {
    AttackCategory.INJECTION: [
        {"id": "AML.T0051", "name": "LLM Prompt Injection", "phase": "Initial Access"},
        {"id": "AML.T0051.001", "name": "Direct Prompt Injection", "phase": "Initial Access"},
    ],
    AttackCategory.JAILBREAK: [
        {"id": "AML.T0054", "name": "Jailbreak", "phase": "Initial Access"},
        {"id": "AML.T0054.001", "name": "Adversarial Perturbations", "phase": "Initial Access"},
    ],
    AttackCategory.EXFILTRATION: [
        {"id": "AML.T0067", "name": "Exfiltration via API", "phase": "Exfiltration"},
        {"id": "AML.T0067.001", "name": "Model Output Exfiltration", "phase": "Exfiltration"},
    ],
    AttackCategory.TOOL_POISONING: [
        {"id": "AML.T0066", "name": "Tool Poisoning", "phase": "Defense Evasion"},
        {"id": "AML.T0066.001", "name": "Tool Function Manipulation", "phase": "Defense Evasion"},
    ],
    AttackCategory.RCE: [
        {"id": "AML.T0059", "name": "Remote Code Execution", "phase": "Execution"},
        {"id": "AML.T0059.001", "name": "Sandbagged RCE", "phase": "Execution"},
    ],
    AttackCategory.SSRF: [
        {"id": "AML.T0060", "name": "Server-Side Request Forgery", "phase": "Execution"},
    ],
    AttackCategory.CMD_INJECTION: [
        {"id": "AML.T0059.002", "name": "Command Injection", "phase": "Execution"},
    ],
    AttackCategory.SQL_INJECTION: [
        {"id": "AML.T0061", "name": "SQL Injection", "phase": "Execution"},
    ],
    AttackCategory.STEGO: [
        {"id": "AML.T0058", "name": "Steganography", "phase": "Defense Evasion"},
    ],
    AttackCategory.POLICY_VIOLATION: [
        {"id": "AML.T0068", "name": "Policy Violation", "phase": "Impact"},
    ],
    AttackCategory.RESOURCE_SCAN: [
        {"id": "AML.T0044", "name": "Resource Discovery", "phase": "Discovery"},
        {"id": "T1046", "name": "Network Service Discovery", "phase": "Discovery"},
    ],
    AttackCategory.IMPERSONATION: [
        {"id": "AML.T0065", "name": "Impersonation", "phase": "Credential Access"},
    ],
    AttackCategory.MALWARE: [
        {"id": "AML.T0062", "name": "Malware Generation", "phase": "Execution"},
    ],
}


UNCATEGORIZED_TTP_ID = "AML.T0000"
UNCATEGORIZED_TTP_NAME = "Uncategorized Event"


class TTPExtractor:
    def extract(self, signal: RawSignal) -> list[dict[str, Any]]:
        ttps = ATLAS_TTP_MAP.get(signal.category, [])
        if not ttps:
            return [
                {
                    "id": UNCATEGORIZED_TTP_ID,
                    "name": UNCATEGORIZED_TTP_NAME,
                    "phase": "Unknown",
                    "confidence": signal.confidence.value,
                    "evidence": signal.snippet[:200] if signal.snippet else signal.title,
                }
            ]

        return [
            {
                **ttp,
                "confidence": signal.confidence.value,
                "evidence": signal.snippet[:200] if signal.snippet else signal.title,
                "source": signal.source.value,
                "source_id": signal.source_id,
            }
            for ttp in ttps
        ]

    def extract_batch(self, signals: list[RawSignal]) -> list[dict[str, Any]]:
        all_ttps: list[dict[str, Any]] = []
        for signal in signals:
            all_ttps.extend(self.extract(signal))
        return all_ttps
