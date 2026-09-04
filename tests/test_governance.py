from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import governance  # noqa: E402


REVIEWERS_SHA256 = "9dfe221bcf0c8dc1f9b2c391a6b8d4d81418fb48b38ddb78d2f78806e638da8e"
SUBJECT_SHA256 = "a" * 64


def _signer() -> dict[str, object]:
    policy = json.loads((ROOT / "authority-policy.json").read_text(encoding="ascii"))
    signer = policy["signer"]
    assert isinstance(signer, dict)
    return signer


def _attestation_certificate() -> dict[str, object]:
    signer = _signer()
    workflow_identity = (
        f"https://github.com/{signer['repository']}/{signer['workflow']}@"
        f"{signer['source_ref']}"
    )
    return {
        "certificateIssuer": governance.GITHUB_ATTESTATION_CERTIFICATE_ISSUER,
        "issuer": governance.GITHUB_ACTIONS_OIDC_ISSUER,
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
        "runInvocationURI": (
            "https://github.com/liupeng69/scraping-release-signing/"
            "actions/runs/33893689852/attempts/1"
        ),
    }


def _attestation(certificate: dict[str, object]) -> tuple[list[object], datetime, datetime]:
    now = datetime.now(timezone.utc)
    issued = now - timedelta(minutes=2)
    expires = now + timedelta(minutes=30)
    payload: list[object] = [
        {
            "verificationResult": {
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "subject": [
                        {
                            "name": "generic-crawl-guardian-receipt.json",
                            "digest": {"sha256": SUBJECT_SHA256},
                        }
                    ],
                },
                "signature": {"certificate": certificate},
                "verifiedTimestamps": [
                    {
                        "type": "Tlog",
                        "timestamp": (now - timedelta(minutes=1))
                        .astimezone(timezone(timedelta(hours=-7)))
                        .isoformat(),
                    }
                ],
            }
        }
    ]
    return payload, issued, expires


def _verify_certificate(certificate: dict[str, object]) -> dict[str, str]:
    payload, issued, expires = _attestation(certificate)
    return governance._signer_evidence(
        payload,
        subject_name="generic-crawl-guardian-receipt.json",
        subject_sha256=SUBJECT_SHA256,
        signer=_signer(),
        issued=issued,
        expires=expires,
    )


def _environment(*, can_admins_bypass: bool) -> dict[str, object]:
    return {
        "name": "release-signing",
        "can_admins_bypass": can_admins_bypass,
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [
                    {
                        "type": "User",
                        "reviewer": {"login": "jiayanBayes", "id": 33_464_549},
                    }
                ],
            }
        ],
    }


class GovernanceEnvironmentTests(unittest.TestCase):
    def test_exact_environment_is_accepted(self) -> None:
        observed = governance.environment_rules(
            _environment(can_admins_bypass=False),
            expected_reviewers_sha256=REVIEWERS_SHA256,
        )

        self.assertTrue(observed["administrator_bypass_disabled"])
        self.assertEqual(observed["required_reviewers_sha256"], REVIEWERS_SHA256)

    def test_administrator_bypass_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            governance.GovernanceError, "administrator bypass remains enabled"
        ):
            governance.environment_rules(
                _environment(can_admins_bypass=True),
                expected_reviewers_sha256=REVIEWERS_SHA256,
            )

    def test_reviewer_projection_digest_is_exact(self) -> None:
        projection = governance.reviewer_projection(
            _environment(can_admins_bypass=False)
        )
        raw = json.dumps(
            projection,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")

        self.assertEqual(hashlib.sha256(raw).hexdigest(), REVIEWERS_SHA256)


class SignerAttestationTests(unittest.TestCase):
    def test_real_github_cli_certificate_field_mapping_is_accepted(self) -> None:
        evidence = _verify_certificate(_attestation_certificate())

        self.assertEqual(evidence["sha256"], SUBJECT_SHA256)
        self.assertRegex(
            evidence["run_invocation_uri"],
            re.compile(r"/actions/runs/33893689852/attempts/1$"),
        )

    def test_certificate_and_oidc_issuers_cannot_be_swapped_or_aliased(self) -> None:
        certificate = _attestation_certificate()
        certificate["certificateIssuer"] = governance.GITHUB_ACTIONS_OIDC_ISSUER
        certificate["issuer"] = governance.GITHUB_ATTESTATION_CERTIFICATE_ISSUER

        with self.assertRaisesRegex(
            governance.GovernanceError, "signer attestation certificate invalid"
        ):
            _verify_certificate(certificate)

        aliased = _attestation_certificate()
        aliased["certificateIssuer"] = governance.GITHUB_ACTIONS_OIDC_ISSUER
        del aliased["issuer"]
        with self.assertRaisesRegex(
            governance.GovernanceError, "signer attestation certificate invalid"
        ):
            _verify_certificate(aliased)

    def test_both_issuer_fields_are_required(self) -> None:
        for field in ("certificateIssuer", "issuer"):
            certificate = _attestation_certificate()
            del certificate[field]
            with self.subTest(field=field), self.assertRaisesRegex(
                governance.GovernanceError, "signer attestation certificate invalid"
            ):
                _verify_certificate(certificate)


class WorkflowContractTests(unittest.TestCase):
    def test_attestation_uses_one_compatible_identity_selector_family(self) -> None:
        workflow = (
            ROOT / ".github/workflows/witness-generic-crawl-release.yml"
        ).read_text(encoding="utf-8")
        identity_flags = re.findall(
            r"^\s+--(cert-identity(?:-regex)?|signer-repo|signer-workflow)\b",
            workflow,
            flags=re.MULTILINE,
        )

        self.assertEqual(identity_flags, ["signer-workflow"])
        self.assertEqual(
            workflow.count(
                "--cert-oidc-issuer https://token.actions.githubusercontent.com"
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
