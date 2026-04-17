package com.cryptodemo.controller;

import com.cryptodemo.util.CryptoUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Sender endpoint — constructs the authenticated + encrypted payload.
 *
 * Flow:
 *   1. Compute H = SHA-256(M || S)
 *   2. Build payload = M || H
 *   3. Encrypt payload with AES(K)
 *   4. Return Base64-encoded ciphertext + all intermediate values
 */
@RestController
@RequestMapping("/api")
public class SenderController {

    @PostMapping("/send")
    public ResponseEntity<?> send(@RequestBody Map<String, String> body) {
        try {
            String message = body.get("message");
            String secret = body.get("secret");
            String key = body.get("key");

            if (message == null || secret == null || key == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Missing required fields: message, secret, key"));
            }

            // Step 1: Concatenate M || S
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
            byte[] combined = CryptoUtils.concatenate(messageBytes, secretBytes);
            String concatenated = new String(combined, StandardCharsets.UTF_8);

            // Step 2: Compute SHA-256( M || S )
            byte[] hash = CryptoUtils.sha256(combined);
            String hashHex = CryptoUtils.toHex(hash);

            // Step 3: Build payload = M || H(M||S)
            byte[] payload = CryptoUtils.concatenate(messageBytes, hash);
            String payloadDescription = "M (%d bytes) || H (%d bytes) = %d bytes total"
                    .formatted(messageBytes.length, hash.length, payload.length);
            String payloadHex = CryptoUtils.toHex(payload);

            // Step 4: Encrypt with AES
            SecretKeySpec aesKey = CryptoUtils.normalizeKey(key);
            byte[] ciphertext = CryptoUtils.aesEncrypt(payload, aesKey);
            String ciphertextBase64 = CryptoUtils.toBase64(ciphertext);
            String normalizedKeyHex = CryptoUtils.toHex(
                    java.util.Arrays.copyOf(CryptoUtils.sha256(key), 16));

            // Build steps object
            Map<String, Object> steps = new LinkedHashMap<>();
            steps.put("message", message);
            steps.put("secret", secret);
            steps.put("concatenated", concatenated);
            steps.put("hashHex", hashHex);
            steps.put("messageLength", messageBytes.length);
            steps.put("hashLength", hash.length);
            steps.put("payloadDescription", payloadDescription);
            steps.put("payloadHex", payloadHex);
            steps.put("normalizedKeyHex", normalizedKeyHex);
            steps.put("ciphertextBase64", ciphertextBase64);

            // Build response
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("ciphertext", ciphertextBase64);
            response.put("steps", steps);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Encryption failed: " + e.getMessage()));
        }
    }
}
