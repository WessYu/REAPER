# Signed rule packs

`scan` can apply one Ed25519-signed, data-only rule pack. A pack contains a format version, stable pack ID, semantic version, explicit compatible REAPER engine versions, literal-match rules, SHA-256 hash, signing key ID, and signature. The signature covers the key ID, normalized payload, and content hash. Verification rejects unknown fields, altered content, untrusted keys, malformed bounds, and incompatible engine versions.

Rule packs do not contain JavaScript, callbacks, regular expressions, module paths, or shell commands. A rule can match one literal string, optionally case-insensitively and for selected file extensions. Matches create LOW-confidence findings with the pack ID/version and hash in the finding evidence and scan metadata. A literal match is a review candidate, not proof of a vulnerability.

Example application:

```ts
const result = await scan({
  root: "./service",
  rulePack: signedPack,
  trustedRulePackKeys: {
    "security-team-2026": trustedPublicKeyPem,
  },
});
```

Pack signing code can use `createSignedRulePack(payload, keyId, privateKey)`. Keep the Ed25519 private key in a controlled signing environment; distribute trusted public keys through a separate trusted channel. Key rotation, signer identity, pack publication, and revocation remain deployment responsibilities.

Bounds currently enforced are: 1 MiB serialized pack, 100 rules, 500 characters per literal, 20 hits per rule per file, 2,000 findings, 5,000 scanned files, 100 MiB total source bytes, and 2 MiB per source file. Source files resolving through symlinks or outside the configured root are skipped. Packs do not execute source or fetch network content.

The existing `ReaperRule` callback API remains trusted local JavaScript running in-process. Signed data-only packs provide a separate path for externally distributed rules; they do not sandbox custom callbacks.
