"""Curated Suricata update sources and evidence-linked selection policy."""

from __future__ import annotations

from typing import Any


SOURCE_CATALOG = {
    "julioliraup/antiphishing": {
        "summary": "Community anti-phishing Suricata rules for malicious URL/domain indicators.",
        "attack_types": {"phishing", "spear_phishing", "credential_phishing", "brand_impersonation"},
        "minimum_severity": "medium",
        "license": "GPL-3.0",
        "requires_operator_review": True,
    },
}

SEVERITY_RANK = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def recommend_sources(analysis: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map validated phishing findings to a fixed allow-listed source ID.

    Source IDs are never accepted from free-form model output. The model must
    identify a phishing-class finding and cite event_refs from the analyzed
    event batch; this function then maps that taxonomy to the curated source.
    """
    if not isinstance(analysis, dict):
        return []
    severity = str(analysis.get("overall_severity", analysis.get("severity", "low"))).lower()
    confidence = str(analysis.get("confidence", "low")).lower()
    valid_refs = {event.get("event_ref") for event in events if event.get("event_ref")}
    if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["medium"] or confidence not in {"medium", "high"}:
        return []

    recommendations = []
    for finding in analysis.get("findings", [])[:20]:
        if not isinstance(finding, dict):
            continue
        types = finding.get("attack_types", [])
        if isinstance(types, str):
            types = [types]
        if not isinstance(types, list):
            continue
        matched_types = sorted({str(value).strip().lower() for value in types} & SOURCE_CATALOG["julioliraup/antiphishing"]["attack_types"])
        refs = finding.get("event_refs", [])
        if not isinstance(refs, list):
            continue
        refs = sorted({ref for ref in refs if isinstance(ref, str) and ref in valid_refs})
        if not matched_types or not refs:
            continue
        recommendations.append({
            "source_id": "julioliraup/antiphishing",
            "summary": SOURCE_CATALOG["julioliraup/antiphishing"]["summary"],
            "attack_types": matched_types,
            "event_refs": refs[:20],
            "rationale": str(finding.get("recommendation") or finding.get("description") or "Evidence-linked phishing activity warrants anti-phishing coverage.")[:500],
            "status": "proposed_not_enabled",
            "license": SOURCE_CATALOG["julioliraup/antiphishing"]["license"],
        })
    return recommendations[:3]