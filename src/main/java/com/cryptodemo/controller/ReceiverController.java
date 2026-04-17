package com.cryptodemo.controller;

import com.cryptodemo.util.CryptoUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
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
 *   6. Return verification result + all intermediate values
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

            Map<String, Object> steps = new LinkedHashMap<>();
            steps.put("ciphertextBase64", ciphertextBase64);

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
            String normalizedKeyHex = CryptoUtils.toHex(
                    java.util.Arrays.copyOf(CryptoUtils.sha256(key), 16));
            steps.put("normalizedKeyHex", normalizedKeyHex);

            byte[] decryptedPayload;
            try {
                decryptedPayload = CryptoUtils.aesDecrypt(ciphertext, aesKey);
            } catch (Exception e) {
                steps.put("decryptionError", "Decryption failed — wrong key or corrupted ciphertext.");
                Map<String, Object> response = new LinkedHashMap<>();
                response.put("verified", false);
                response.put("message", "");
                response.put("detail", "Decryption failed — wrong key or corrupted ciphertext.");
                response.put("steps", steps);
                return ResponseEntity.ok(response);
            }

            steps.put("decryptedPayloadHex", CryptoUtils.toHex(decryptedPayload));
            steps.put("decryptedPayloadLength", decryptedPayload.length);

            // Step 3: Split payload → [M, receivedHash]
            byte[][] parts;
            try {
                parts = CryptoUtils.splitPayload(decryptedPayload);
            } catch (IllegalArgumentException e) {
                steps.put("splitError", "Decrypted payload too short to contain a valid hash.");
                Map<String, Object> response = new LinkedHashMap<>();
                response.put("verified", false);
                response.put("message", "");
                response.put("detail", "Decrypted payload too short to contain a valid hash.");
                response.put("steps", steps);
                return ResponseEntity.ok(response);
            }

            byte[] messageBytes = parts[0];
            byte[] receivedHash = parts[1];
            String extractedMessage = new String(messageBytes, StandardCharsets.UTF_8);

            steps.put("extractedMessage", extractedMessage);
            steps.put("extractedMessageLength", messageBytes.length);
            steps.put("receivedHashHex", CryptoUtils.toHex(receivedHash));

            // Step 4: Independently compute SHA-256(M || S)
            byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
            byte[] combined = CryptoUtils.concatenate(messageBytes, secretBytes);
            String recomputedConcatenation = new String(combined, StandardCharsets.UTF_8);
            byte[] computedHash = CryptoUtils.sha256(combined);

            steps.put("recomputedConcatenation", recomputedConcatenation);
            steps.put("recomputedHashHex", CryptoUtils.toHex(computedHash));

            // Step 5: Constant-time comparison
            boolean verified = MessageDigest.isEqual(computedHash, receivedHash);
            steps.put("hashMatch", verified);

            // Step 6: Build response
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("verified", verified);
            response.put("message", extractedMessage);
            response.put("detail", verified
                    ? "Authentication PASSED — integrity and authenticity confirmed."
                    : "Authentication FAILED — the message or secret has been tampered with.");
            response.put("steps", steps);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Processing failed: " + e.getMessage()));
        }
    }
}
