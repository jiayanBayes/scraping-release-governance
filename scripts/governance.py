#!/usr/bin/env python3
"""Build the independently governed custom predicate for one guardian subject."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Final, NoReturn


DIGEST_RE: Final = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE: Final = re.compile(r"^[0-9a-f]{40}$")
RUN_URI_RE: Final = re.compile(
    r"^https://github\.com/liupeng69/scraping-release-signing/actions/runs/"
    r"[1-9][0-9]*/attempts/[1-9][0-9]*$"
)
PREDICATE_TYPE: Final = (
    "https://scraping-platform.invalid/attestations/"
    "independent-release-signer-governance/v1"
)
MAX_CLOCK_SKEW: Final = timedelta(minutes=5)
GITHUB_ATTESTATION_CERTIFICATE_ISSUER: Final = (
    "CN=sigstore-intermediate,O=sigstore.dev"
)
GITHUB_ACTIONS_OIDC_ISSUER: Final = "https://token.actions.githubusercontent.com"


class GovernanceError(ValueError):
    """The signer or environment evidence is not the pinned authority."""


def _reject(message: str) -> NoReturn:
    raise GovernanceError(message)


def _reject_from(message: str, exc: Exception) -> NoReturn:
    raise GovernanceError(message) from exc


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _reject_from(f"invalid JSON evidence: {path.name}", exc)
    if not isinstance(value, dict):
        _reject(f"invalid JSON evidence: {path.name}")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        _reject(f"{label} invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        _reject_from(f"{label} invalid", exc)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _reject(f"{label} invalid")
    return parsed.astimezone(timezone.utc)


def _policy(path: Path) -> dict[str, Any]:
    policy = _load(path)
    if set(policy) != {
        "schema_version",
        "current_cycle",
        "signer",
        "signer_environment_rules",
    } or policy.get("schema_version") != "scraping_release_governance_policy.v1":
        _reject("governance policy shape invalid")
    signer = policy.get("signer")
    rules = policy.get("signer_environment_rules")
    cycle = policy.get("current_cycle")
    if not all(isinstance(value, dict) for value in (signer, rules, cycle)):
        _reject("governance policy shape invalid")
    if (
        COMMIT_RE.fullmatch(str(signer.get("workflow_commit") or "")) is None
        or DIGEST_RE.fullmatch(str(signer.get("workflow_sha256") or "")) is None
        or DIGEST_RE.fullmatch(str(rules.get("required_reviewers_sha256") or ""))
        is None
        or set(str(signer["workflow_commit"])) == {"0"}
        or set(str(signer["workflow_sha256"])) == {"0"}
        or set(str(rules["required_reviewers_sha256"])) == {"0"}
    ):
        _reject("governance policy remains unconfigured")
    return policy


def reviewer_projection(environment: Mapping[str, Any]) -> list[dict[str, object]]:
    rules = environment.get("protection_rules")
    if not isinstance(rules, list):
        _reject("signer environment protection rules invalid")
    required = [
        item
        for item in rules
        if isinstance(item, dict) and item.get("type") == "required_reviewers"
    ]
    if len(required) != 1 or required[0].get("prevent_self_review") is not True:
        _reject("signer environment reviewer rule invalid")
    reviewers = required[0].get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) != 1:
        _reject("signer environment reviewer set invalid")
    item = reviewers[0]
    reviewer = item.get("reviewer") if isinstance(item, dict) else None
    if (
        not isinstance(item, dict)
        or item.get("type") != "User"
        or not isinstance(reviewer, dict)
        or reviewer.get("login") != "jiayanBayes"
        or reviewer.get("id") != 33_464_549
    ):
        _reject("signer environment reviewer identity invalid")
    return [{"type": "User", "login": "jiayanBayes", "id": 33_464_549}]


def environment_rules(
    environment: Mapping[str, Any], *, expected_reviewers_sha256: str
) -> dict[str, object]:
    if environment.get("name") != "release-signing":
        _reject("signer environment name invalid")
    if environment.get("can_admins_bypass") is not False:
        _reject("signer environment administrator bypass remains enabled")
    branch = environment.get("deployment_branch_policy")
    if branch != {"protected_branches": True, "custom_branch_policies": False}:
        _reject("signer environment branch policy invalid")
    projection = reviewer_projection(environment)
    observed = hashlib.sha256(_canonical(projection)).hexdigest()
    if observed != expected_reviewers_sha256:
        _reject("signer environment reviewer digest mismatch")
    return {
        "environment": "release-signing",
        "protected_branches_only": True,
        "custom_branch_policies": False,
        "prevent_self_review": True,
        "administrator_bypass_disabled": True,
        "required_reviewers_sha256": observed,
    }


def _signer_evidence(
    raw: object,
    *,
    subject_name: str,
    subject_sha256: str,
    signer: Mapping[str, Any],
    issued: datetime,
    expires: datetime,
) -> dict[str, str]:
    if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], dict):
        _reject("signer attestation result is not exact")
    verification = raw[0].get("verificationResult")
    if not isinstance(verification, dict):
        _reject("signer attestation verification invalid")
    statement = verification.get("statement")
    expected_subject = [{"name": subject_name, "digest": {"sha256": subject_sha256}}]
    if (
        not isinstance(statement, dict)
        or statement.get("_type") != "https://in-toto.io/Statement/v1"
        or statement.get("predicateType") != "https://slsa.dev/provenance/v1"
        or statement.get("subject") != expected_subject
    ):
        _reject("signer attestation subject invalid")
    signature = verification.get("signature")
    certificate = signature.get("certificate") if isinstance(signature, dict) else None
    workflow_identity = (
        f"https://github.com/{signer['repository']}/{signer['workflow']}@"
        f"{signer['source_ref']}"
    )
    expected_certificate = {
        "certificateIssuer": GITHUB_ATTESTATION_CERTIFICATE_ISSUER,
        "issuer": GITHUB_ACTIONS_OIDC_ISSUER,
        "subjectAlternativeName": workflow_identity,
        "buildSignerURI": workflow_identity,
        "buildSignerDigest": signer["workflow_commit"],
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": f"https://github.com/{signer['repository']}",
        "sourceRepositoryDigest": signer["workflow_commit"],
        "sourceRepositoryRef": signer["source_ref"],
        "sourceRepositoryIdentifier": str(signer["repository_id"]),
        "sourceRepositoryVisibilityAtSigning": "public",
        "buildConfigURI": workflow_identity,
        "buildConfigDigest": signer["workflow_commit"],
        "buildTrigger": "workflow_dispatch",
    }
    if not isinstance(certificate, dict) or any(
        certificate.get(key) != value for key, value in expected_certificate.items()
    ):
        _reject("signer attestation certificate invalid")
    run_uri = certificate.get("runInvocationURI")
    if not isinstance(run_uri, str) or RUN_URI_RE.fullmatch(run_uri) is None:
        _reject("signer attestation run URI invalid")
    timestamps = verification.get("verifiedTimestamps")
    if not isinstance(timestamps, list):
        _reject("signer attestation timestamps invalid")
    witnessed: list[datetime] = []
    tlog = False
    for item in timestamps:
        if not isinstance(item, dict) or item.get("type") not in {"Tlog", "TSA"}:
            _reject("signer attestation timestamps invalid")
        tlog = tlog or item["type"] == "Tlog"
        witnessed.append(_utc(item.get("timestamp"), "signer timestamp"))
    if not witnessed or not tlog:
        _reject("signer transparency timestamp missing")
    earliest = min(witnessed)
    now = datetime.now(timezone.utc)
    if earliest < issued - MAX_CLOCK_SKEW or earliest > expires or earliest > now + MAX_CLOCK_SKEW:
        _reject("signer timestamp outside guardian validity")
    return {
        "name": subject_name,
        "sha256": subject_sha256,
        "witnessed_at": earliest.isoformat().replace("+00:00", "Z"),
        "run_invocation_uri": run_uri,
    }


def build(arguments: argparse.Namespace) -> dict[str, object]:
    policy = _policy(arguments.policy)
    signer = policy["signer"]
    configured_rules = policy["signer_environment_rules"]
    subject_raw = arguments.subject.read_bytes()
    subject = json.loads(subject_raw)
    if not isinstance(subject, dict):
        _reject("guardian subject invalid")
    subject_name = arguments.subject.name
    subject_sha256 = hashlib.sha256(subject_raw).hexdigest()
    if DIGEST_RE.fullmatch(subject_sha256) is None:
        _reject("guardian digest invalid")
    issued = datetime.fromtimestamp(subject.get("issued_at_unix"), timezone.utc)
    expires = datetime.fromtimestamp(subject.get("expires_at_unix"), timezone.utc)
    if expires <= issued:
        _reject("guardian validity invalid")
    attestation_value = json.loads(arguments.signer_attestation.read_bytes())
    signer_evidence = _signer_evidence(
        attestation_value,
        subject_name=subject_name,
        subject_sha256=subject_sha256,
        signer=signer,
        issued=issued,
        expires=expires,
    )
    live_rules = environment_rules(
        _load(arguments.signer_environment),
        expected_reviewers_sha256=configured_rules["required_reviewers_sha256"],
    )
    if live_rules != configured_rules:
        _reject("signer environment differs from configured governance policy")
    if (
        DIGEST_RE.fullmatch(arguments.admin_bypass_observation_sha256) is None
        or set(arguments.admin_bypass_observation_sha256) == {"0"}
    ):
        _reject("administrator-bypass observation digest invalid")
    observed_at = datetime.now(timezone.utc)
    if observed_at < issued - MAX_CLOCK_SKEW or observed_at > expires:
        _reject("governance observation outside guardian validity")
    binding = {"name": subject_name, "sha256": subject_sha256}
    predicate: dict[str, object] = {
        "schema_version": "independent_release_signer_governance.v1",
        "subject": binding,
        "signer": signer,
        "protected_environment": live_rules,
        "administrator_bypass_observation_sha256": (
            arguments.admin_bypass_observation_sha256
        ),
        "signer_attestation": {
            "subject": binding,
            "predicate_type": signer["predicate_type"],
            "workflow_identity": (
                f"https://github.com/{signer['repository']}/{signer['workflow']}@"
                f"{signer['source_ref']}"
            ),
            "workflow_commit": signer["workflow_commit"],
            "run_invocation_uri": signer_evidence["run_invocation_uri"],
            "witnessed_at": signer_evidence["witnessed_at"],
        },
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
    }
    if arguments.output.exists() or arguments.output.is_symlink():
        _reject("refusing to replace predicate output")
    arguments.output.write_text(
        json.dumps(predicate, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    return predicate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--subject", type=Path, required=True)
    parser.add_argument("--signer-attestation", type=Path, required=True)
    parser.add_argument("--signer-environment", type=Path, required=True)
    parser.add_argument("--admin-bypass-observation-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    result = build(parser.parse_args())
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GovernanceError, OSError, TypeError, ValueError) as exc:
        print(f"release governance rejected: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
