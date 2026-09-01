from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import governance  # noqa: E402


REVIEWERS_SHA256 = "9dfe221bcf0c8dc1f9b2c391a6b8d4d81418fb48b38ddb78d2f78806e638da8e"


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


if __name__ == "__main__":
    unittest.main()
