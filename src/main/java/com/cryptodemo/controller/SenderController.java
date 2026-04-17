package com.cryptodemo.controller;

import com.cryptodemo.util.CryptoUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Sender endpoint — constructs the authenticated + encrypted payload.
 *
 * Flow:
 *   1. Compute H = SHA-256(M || S)
 *   2. Build payload = M || H
 *   3. Encrypt payload with AES(K)
 *   4. Return Base64-encoded ciphertext
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

            // Step 1: Compute SHA-256( M || S )
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
            byte[] combined = CryptoUtils.concatenate(messageBytes, secretBytes);
            byte[] hash = CryptoUtils.sha256(combined);

            // Step 2: Build payload = M || H(M||S)
            byte[] payload = CryptoUtils.concatenate(messageBytes, hash);

            // Step 3: Encrypt with AES
            SecretKeySpec aesKey = CryptoUtils.normalizeKey(key);
            byte[] ciphertext = CryptoUtils.aesEncrypt(payload, aesKey);

            // Step 4: Return Base64-encoded ciphertext
            String ciphertextBase64 = CryptoUtils.toBase64(ciphertext);

            return ResponseEntity.ok(Map.of("ciphertext", ciphertextBase64));

        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Encryption failed: " + e.getMessage()));
        }
    }
}
