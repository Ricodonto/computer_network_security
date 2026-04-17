package com.cryptodemo.util;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Cryptographic utility class providing SHA-256 hashing, AES encryption/decryption,
 * key normalization, and safe byte-array concatenation/splitting.
 */
public final class CryptoUtils {

    /** SHA-256 always produces a 32-byte digest. */
    public static final int SHA256_HASH_LENGTH = 32;

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";

    private CryptoUtils() {
        // Utility class — prevent instantiation
    }

    // ──────────────────────────────────────────────
    //  SHA-256 Hashing
    // ──────────────────────────────────────────────

    /**
     * Computes the SHA-256 hash of the given input bytes.
     *
     * @param input the data to hash
     * @return 32-byte SHA-256 digest
     */
    public static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available in every compliant JVM
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Computes SHA-256 of a UTF-8 string.
     */
    public static byte[] sha256(String input) {
        return sha256(input.getBytes(StandardCharsets.UTF_8));
    }

    // ──────────────────────────────────────────────
    //  AES Key Normalization
    // ──────────────────────────────────────────────

    /**
     * Normalizes an arbitrary user-provided key string into a valid 16-byte
     * AES {@link SecretKeySpec}. The normalization takes the first 16 bytes
     * of the SHA-256 hash of the user's input.
     *
     * @param userKey the raw key string typed by the user
     * @return a 128-bit AES SecretKeySpec
     */
    public static SecretKeySpec normalizeKey(String userKey) {
        byte[] hash = sha256(userKey);
        byte[] keyBytes = Arrays.copyOf(hash, 16); // first 16 bytes → AES-128
        return new SecretKeySpec(keyBytes, AES_ALGORITHM);
    }

    // ──────────────────────────────────────────────
    //  AES Encryption / Decryption
    // ──────────────────────────────────────────────

    /**
     * Encrypts the given plaintext bytes using AES/ECB/PKCS5Padding.
     *
     * @param plaintext the data to encrypt
     * @param key       the AES key
     * @return encrypted ciphertext bytes
     */
    public static byte[] aesEncrypt(byte[] plaintext, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Decrypts the given ciphertext bytes using AES/ECB/PKCS5Padding.
     *
     * @param ciphertext the data to decrypt
     * @param key        the AES key
     * @return decrypted plaintext bytes
     */
    public static byte[] aesDecrypt(byte[] ciphertext, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    // ──────────────────────────────────────────────
    //  Byte-Array Concatenation & Splitting
    // ──────────────────────────────────────────────

    /**
     * Concatenates two byte arrays: {@code [a || b]}.
     *
     * @param a first array
     * @param b second array
     * @return a new array containing a followed by b
     */
    public static byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Splits a decrypted payload into the original message bytes and the
     * trailing 32-byte SHA-256 hash.
     *
     * @param payload the full decrypted payload [M || H]
     * @return a two-element array: [messageBytes, hashBytes]
     * @throws IllegalArgumentException if the payload is too short to contain a hash
     */
    public static byte[][] splitPayload(byte[] payload) {
        if (payload.length < SHA256_HASH_LENGTH) {
            throw new IllegalArgumentException(
                    "Payload too short (%d bytes) to contain a %d-byte SHA-256 hash"
                            .formatted(payload.length, SHA256_HASH_LENGTH));
        }
        int messageLength = payload.length - SHA256_HASH_LENGTH;
        byte[] messageBytes = Arrays.copyOfRange(payload, 0, messageLength);
        byte[] hashBytes = Arrays.copyOfRange(payload, messageLength, payload.length);
        return new byte[][] { messageBytes, hashBytes };
    }

    // ──────────────────────────────────────────────
    //  Base64 Helpers
    // ──────────────────────────────────────────────

    /**
     * Encodes bytes to a Base64 string.
     */
    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Decodes a Base64 string to bytes.
     */
    public static byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }
}
