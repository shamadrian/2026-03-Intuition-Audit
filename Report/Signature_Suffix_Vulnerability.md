## Atom Wallet Signature Suffix Malleability Allows Any Users To Modify ValidAfter/ValidUntil

### Description 
`AtomWallet` is an ERC-4337 account (`BaseAccount`) which validates `PackedUserOperation`s via `_validateSignature()`. When a `UserOperation` is submitted to the `EntryPoint`, the account returns a packed `validationData` value which includes the signature validity window (`validAfter`, `validUntil`). The `EntryPoint` uses this time window to decide whether the operation is allowed to execute “now”.

`AtomWallet` supports an extended signature format where `validUntil` and `validAfter` are appended as a 12-byte suffix:

```solidity
// Signature format:
// - 65 bytes: (r,s,v)
// - optional 12 bytes: uint48 validUntil || uint48 validAfter
(uint48 validUntil, uint48 validAfter, bytes memory rawSig) =
    _extractValidUntilAndValidAfterFromSignature(userOp.signature);
```

However, **this 12-byte time window suffix is not cryptographically bound to what the owner signs**.

In `_validateSignature()`, the wallet:
1) parses `validUntil`/`validAfter` out of `userOp.signature`,
2) computes an EIP-191 hash over `userOpHash`,
3) recovers the signer address using only the *raw 65-byte ECDSA signature*, and
4) returns `_packValidationData(sigFailed, validUntil, validAfter)`.

```solidity
bytes32 hash = keccak256(abi.encodePacked(
    "\x19Ethereum Signed Message:\n32",
    userOpHash
));

(address recovered,,) = ECDSA.tryRecover(hash, rawSig);
return _packValidationData(recovered != owner(), validUntil, validAfter);
```

Critically, in ERC-4337 the `userOpHash` produced by the `EntryPoint` is computed over the operation fields **excluding** `userOp.signature`. This is intentional in the standard: the signature is meant to be verified *against* the hash.

As a result, the wallet owner’s signature only authenticates `userOpHash` (the operation contents), but **does not authenticate the `validAfter`/`validUntil` values extracted from the signature suffix**.

This makes the time window *malleable*: any party who can see the submitted `UserOperation` (for example in the mempool, or after the transaction is executed and reverted due to timeframe constraint), can keep the 65-byte ECDSA signature intact while rewriting the final 12 bytes, changing the returned `validationData` window without breaking
signature recovery.

### Impact
Time-based constraints enforced via `validAfter`/`validUntil` can be bypassed or altered by third parties:
- **Execute earlier than intended** by setting `validAfter = 0`.
- **Execute after expiry / “revive” an operation** by extending `validUntil` (and optionally setting `validAfter = 0`).

This breaks common “scheduled / delayed execution” and “execute only within a specific timeframe” safety expectations,
allowing operations to be executed at times the owner did not authorize.

More importantly, this undermines the integrity and autonomy of signature-based authorization: the wallet returns `validationData` (and the `EntryPoint` enforces) a time window that is not covered by the owner’s signature. 

### Proof of Concept

The PoC is implemented as an end-to-end ERC-4337 flow using a real `EntryPoint.handleOps` call (see [tests/PoCCore.t.sol](tests/PoCCore.t.sol)).

### Real-Life Scenario

**Attack case 1: Execute earlier than Alice intended (bypass `validAfter`)**
- Alice produces a signed `UserOperation` with `validAfter` set in the future (a “scheduled” operation). If submitted as-is, the `EntryPoint` should reject it until that timestamp.
- A third party who observes the submitted `UserOperation` bytes (e.g., bundler/relayer or any observer of the UserOp before inclusion) copies the exact same operation and signature, but mutates only the final 12 bytes of `userOp.signature`, setting `validAfter = 0` (leaving the 65-byte ECDSA signature unchanged).
- Because the ECDSA signature is checked only against `userOpHash` (which excludes `userOp.signature`), signature recovery still succeeds as Alice, but the wallet returns `validationData` with the attacker-chosen time window.
- The `EntryPoint` now considers the operation valid immediately and executes the transfer early.

**Attack case 2: Force execution after the intended window is missed (bypass `validUntil`)**
- Alice produces a signed `UserOperation` intended to be executable only within a limited window (both `validAfter` and `validUntil` set).
- If the window is missed (e.g., due to delayed bundling, reverted submission, or lack of inclusion), submitting the original operation after expiry should fail.
- Any observer can “revive” the operation by mutating only the 12-byte suffix: extend `validUntil` into the future (and optionally set `validAfter = 0`), again without changing the 65-byte ECDSA signature.
- The `EntryPoint` then enforces the attacker-modified window and executes a transfer that Alice expected to be invalid after expiry.

**Both of these cases are demonstrated clearly in the PoC.**


### Mitigation
Bind the time window to the signed payload. For example, have the account verify the signature over a hash that includes
`validAfter`/`validUntil` (e.g., `keccak256(abi.encode(userOpHash, validUntil, validAfter))`), or otherwise ensure the
`EntryPoint`-enforced window values are derived from data that is actually signed by the wallet owner.

### Notes / Clarification
In the publicly known issues, The project notes that the AtomWallet signature format is intentionally strict: only 65-byte raw ECDSA or 77-byte ECDSA+time-window suffix.

This strictness only constrains how `userOp.signature` is parsed. It does not ensure the appended 12-byte time-window suffix (`validUntil`/`validAfter`) is included in (or otherwise bound to) what the owner cryptographically signs, which is the root cause of the above vulnerability.

