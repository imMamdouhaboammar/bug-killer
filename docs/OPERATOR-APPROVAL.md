# Operator approval setup

Privileged remediation is **fail closed** until a separately managed Ed25519 signer and a pinned verification policy are provisioned. A repository's `.aegis/operator_identity.key` never grants approval authority. Merely putting an operator public key in a receipt does not make it trusted.

## Distinct operator and execution principals

Use an operator account or protected signing host that the coding agent cannot access. The operator account owns a raw 32-byte Ed25519 private signing seed at:

`$XDG_CONFIG_HOME/bug-killer/operator_identity.key`, or `$HOME/.config/bug-killer/operator_identity.key` if `XDG_CONFIG_HOME` is not set.

In the operator account, provision this key deliberately. For example, on a trusted host with OpenSSL:

```sh
umask 077
mkdir -p "$HOME/.config/bug-killer"
openssl rand -out "$HOME/.config/bug-killer/operator_identity.key" 32
bug-killer operator-public-key
```

The last command prints the public key as lowercase hex. Transfer **only the public key** through an authenticated channel. Never copy the private key into the project or agent's workspace.

The administrator responsible for the **execution** identity pins allowed operator public keys in its configuration directory:

```json
[
  "<64-character operator public key from trusted enrollment>"
]
```

Save that JSON as `trusted_operator_keys.json` in the same platform-specific config directory. Keep this policy protected against writes by untrusted coding agents. If it is missing, corrupt, empty, or located inside the target workspace, verification fails.

The operator reviews the actual plan and issues a short-lived receipt using `bug-killer approve <finding-id> <workspace>` (or the explicit `all` plan selector). The execution identity then runs `bug-killer apply <finding-id> <workspace> --approval-file <receipt-path>`. The signed payload binds the plan hash, canonical workspace root, declared approver, risk, expiry, and nonce. `heal --apply`, `heal --auto-apply`, `watch --auto-heal`, and unapproved interactive shell healing are rejected.

**Important threat boundary:** putting the signer and verifier under one untrusted operating-system account does not separate human authority. A process able to edit the verifier's trusted-key policy, steal the private signer, or rewrite consumed-nonce history can defeat these checks. Use separate OS principals or an external approval service with independently controlled policies. Signed receipts are necessary for the approval flow, but are not a substitute for access controls.

Old receipts signed using ambiguous colon-delimited payloads are intentionally not accepted. Existing operator keys may still be used after explicit out-of-project provisioning; old receipts must be reissued.
