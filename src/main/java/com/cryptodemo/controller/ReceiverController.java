package com.cryptodemo.controller;

import com.cryptodemo.util.CryptoUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

/**
 * Receiver endpoint — decrypts, verifies, and reports authenticity.
 *
 * Flow:
 *   1. Decode Base64 ciphertext
 *   2. Decrypt with AES(K)
 *   3. Split payload into M and received hash
 *   4. Independently compute H' = SHA-256(M || S)
 *   5. Compare H' with received hash (constant-time)
 *   6. Return verification result + decrypted message
 */
@RestController
@RequestMapping("/api")
public class ReceiverController {

    @PostMapping("/receive")
    public ResponseEntity<?> receive(@RequestBody Map<String, String> body) {
        try {
            String ciphertextBase64 = body.get("ciphertext");
            String secret = body.get("secret");
            String key = body.get("key");

            if (ciphertextBase64 == null || secret == null || key == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Missing required fields: ciphertext, secret, key"));
            }

            // Step 1: Decode Base64
            byte[] ciphertext;
            try {
                ciphertext = CryptoUtils.fromBase64(ciphertextBase64);
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid Base64 ciphertext"));
            }

            // Step 2: Decrypt with AES
            SecretKeySpec aesKey = CryptoUtils.normalizeKey(key);
            byte[] decryptedPayload;
            try {
                decryptedPayload = CryptoUtils.aesDecrypt(ciphertext, aesKey);
            } catch (Exception e) {
                return ResponseEntity.ok(Map.of(
                        "verified", false,
                        "message", "",
                        "detail", "Decryption failed — wrong key or corrupted ciphertext."
                ));
            }

            // Step 3: Split payload → [M, receivedHash]
            byte[][] parts;
            try {
                parts = CryptoUtils.splitPayload(decryptedPayload);
            } catch (IllegalArgumentException e) {
                return ResponseEntity.ok(Map.of(
                        "verified", false,
                        "message", "",
                        "detail", "Decrypted payload too short to contain a valid hash."
                ));
            }

            byte[] messageBytes = parts[0];
            byte[] receivedHash = parts[1];

            // Step 4: Independently compute SHA-256(M || S)
            byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
            byte[] combined = CryptoUtils.concatenate(messageBytes, secretBytes);
            byte[] computedHash = CryptoUtils.sha256(combined);

            // Step 5: Constant-time comparison
            boolean verified = MessageDigest.isEqual(computedHash, receivedHash);

            // Step 6: Build response
            String decryptedMessage = new String(messageBytes, StandardCharsets.UTF_8);

            return ResponseEntity.ok(Map.of(
                    "verified", verified,
                    "message", decryptedMessage,
                    "detail", verified
                            ? "Authentication PASSED — integrity and authenticity confirmed."
                            : "Authentication FAILED — the message or secret has been tampered with."
            ));

        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Processing failed: " + e.getMessage()));
        }
    }
}
