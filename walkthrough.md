# CryptoFlow Redesign — Walkthrough

## What Changed

### Design Overhaul (hashexplained.com style)
- **Pure black** `#000` background with dark slate panels (`#020617`)
- **Monospace-only** typography (JetBrains Mono everywhere)
- **Color-coded sections**: green (Sender), amber (Network), purple (Receiver)
- **Flat, minimal panels** with `● SECTION` uppercase headers and dot indicators
- **Single-column vertical layout** instead of 3-column grid — more room for step data
- No gradients, no glassmorphism — clean terminal aesthetic

### Step-by-Step Visualization

**Sender (4 steps revealed after clicking Send):**

| Step | Label | Shows |
|------|-------|-------|
| 1 | Concatenation | `M \|\| S` as readable text |
| 2 | SHA-256 Hash | 64-char hex digest of `H(M \|\| S)` |
| 3 | Build Payload | Hex of `M \|\| H(M\|\|S)` with byte counts |
| 4 | AES Encryption | Base64 ciphertext + normalized key hex |

**Receiver (4 steps revealed after clicking Process):**

| Step | Label | Shows |
|------|-------|-------|
| 1 | AES Decryption | Full decrypted payload in hex |
| 2 | Payload Split | Extracted message + received hash (hex) |
| 3 | Hash Recomputation | Recomputed `H'(M \|\| S)` in hex |
| 4 | Verification | Side-by-side hash comparison table (green=match, red=mismatch) |

### Backend Changes

| File | Change |
|------|--------|
| [CryptoUtils.java](file:///d:/Coding%20Projects/computer_network_security/src/main/java/com/cryptodemo/util/CryptoUtils.java) | Added `toHex(byte[])` method |
| [SenderController.java](file:///d:/Coding%20Projects/computer_network_security/src/main/java/com/cryptodemo/controller/SenderController.java) | Returns `steps` object with all intermediates |
| [ReceiverController.java](file:///d:/Coding%20Projects/computer_network_security/src/main/java/com/cryptodemo/controller/ReceiverController.java) | Returns `steps` object with all intermediates |
| [index.html](file:///d:/Coding%20Projects/computer_network_security/src/main/resources/static/index.html) | Complete rewrite — new design + step visualization |

## Verification

Tested all scenarios in the browser:

| Scenario | Result |
|----------|--------|
| Correct secret + correct key | ✅ Authentication PASSED + all steps shown |
| Wrong secret | ✅ Authentication FAILED + hash comparison shows mismatch |
| All 4 sender steps visualized | ✅ Concatenation, Hash, Payload, Encryption |
| All 4 receiver steps visualized | ✅ Decryption, Split, Recomputation, Comparison |

![Redesigned CryptoFlow page](C:/Users/ricon/.gemini/antigravity/brain/30de65c3-972d-4a76-9ba5-96f95f5dd9e5/.system_generated/click_feedback/click_feedback_1776418727226.png)

## How to Run

```bash
mvn spring-boot:run
# Open http://localhost:8080
```
