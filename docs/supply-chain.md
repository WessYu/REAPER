# Release supply-chain evidence

The CI quality job runs `npm audit --audit-level=high`, builds the npm package, emits a CycloneDX 1.5 SBOM from the lockfile, and creates a SHA-256 manifest covering the package tarball and SBOM. The workflow verifies those hashes before uploading the files as `reaper-supply-chain-evidence`.

For pushes of version tags beginning with `v`, the provenance job uses GitHub Actions OIDC and GitHub artifact attestations to attest the npm tarball, hash manifest, and SBOM. It does not use a repository signing private key. Pull request and branch CI produce the SBOM and hashes but do not issue attestations. Attestation requires the GitHub repository plan and settings to support artifact attestations.

After downloading the evidence, consumers can verify the package provenance and SBOM attestation with GitHub CLI:

```sh
gh attestation verify wess2001-reaper-0.2.0.tgz -R WessYu/REAPER
gh attestation verify reaper.cdx.json -R WessYu/REAPER
```

The SHA-256 manifest detects changes only when compared with a trusted copy. It is not a signature. Prefer the attestation verification above to establish the artifact's repository/workflow provenance. Verify that the tag and workflow identity match the release you intended to install.

The npm registry publication step is not part of this workflow. This project currently publishes only when a maintainer performs the release process; the attestations describe GitHub-built artifacts and do not independently prove that a registry download is byte-for-byte identical unless the downloaded tarball is also verified.
