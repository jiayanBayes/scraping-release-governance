# Scraping release governance witness

This is the source template for the independently owned public repository
`jiayanBayes/scraping-release-governance`. Jia must create the empty repository
herself, retain its owner-only settings authority, and invite Peng as a write
collaborator. Peng may then publish this exact checked-in template without
receiving Jia's password, token, 2FA code, or recovery credential. Jia must
independently verify the published commit and source-test run and configure the
protected branch and environment. This division keeps the non-programmer
reviewer out of the credential-bearing command line while preserving her
exclusive ownership and approval boundary. Either person can act as operator
in a later candidate while the other reviews.

A browser-only, non-programmer procedure for Jia is maintained in the private
operator repository at
[`docs/JIA_RELEASE_GOVERNANCE_STEP_BY_STEP.zh-CN.md`](https://github.com/scraping-repo/scraping/blob/new-features-jiay/docs/JIA_RELEASE_GOVERNANCE_STEP_BY_STEP.zh-CN.md).

The current cycle uses Peng as operator and Jia as reviewer. Peng dispatches
`Witness Generic Crawl Release`; the `release-governance` environment requires
Jia's approval with self-review prevention. Before approval, Jia independently
checks the signer subject, signer provenance, live `release-signing`
environment, and GitHub's public environment projection showing that
administrator bypass is disabled. The
workflow then creates a custom Sigstore/GitHub attestation over the exact same
guardian receipt.

`authority-policy.json` is pre-bound to signing repository commit
`405dda41290a77429c0dc63a255b49de4f8205e7`, the exact authorization workflow
blob, and the exact one-reviewer environment projection observed on 2026-08-30.
Jia must verify those values before the initial push. After the push, protect `main` with an active no-bypass ruleset, create the
`release-governance` environment with Jia as the sole required reviewer,
enable prevent-self-review, restrict deployments to protected branches, and
disable administrator bypass in the GitHub UI. The governance workflow commit
and workflow-file SHA-256 must then be copied into the private candidate
repository's independent signer policy before candidate capture.

The workflow fails closed unless GitHub's live environment API also reports
`can_admins_bypass=false`. It binds the SHA-256 of Jia's independent public-API
observation into the custom governance predicate.

No private candidate source, AWS credential, AWS secret value, private key, or
private-repository token belongs in this repository.
