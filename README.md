# CryptoFlow

**CryptoFlow** is an interactive, educational web application built with Spring Boot and Vanilla JavaScript that visualizes cryptographic message authentication and confidentiality. It demonstrates how to securely transmit a message using a combination of **SHA-256 hashing (for integrity and authentication)** and **AES-128 encryption (for confidentiality)**.

The frontend is heavily inspired by terminal aesthetics (a la *hashexplained.com*), revealing the raw hex and base64 values of the data at every step of the cryptographic pipeline.

---

## 🎯 Features

*   **Step-by-Step Visualization:** The UI breaks down the black box of cryptography, showing the exact byte/hex values during string concatenation, SHA-256 hashing, payload construction, and AES encryption.
*   **Message Authentication:** Uses a shared secret (`S`) appended to a message (`M`) to generate an authentication hash `H(M || S)` that guarantees both integrity and sender identity.
*   **Confidentiality (Encryption):** Encrypts the entire payload `[M || Hash]` using `AES/ECB/PKCS5Padding`.
*   **Man-in-the-Middle Simulation:** Includes a "Network" panel where users can maliciously edit the intercepted ciphertext before it reaches the receiver to see how the mathematical decryption behaves (and fails securely).
*   **Constant-Time Verification:** The receiver independently splits the decrypted payload, recomputes the hash with their own secret, and compares it to the transmitted hash to verify authenticity.

---

## 🛠️ Tech Stack

*   **Backend:** Java 26, Spring Boot 3.5.13+ (REST API)
*   **Security:** `java.security.MessageDigest` (SHA-256), `javax.crypto.Cipher` (AES)
*   **Frontend:** HTML5, Vanilla JavaScript (ES6 `fetch`), pure Vanilla CSS (CSS Variables, Flexbox, JetBrains Mono font)
*   **Architecture:** Stateless REST (`/api/send` and `/api/receive`)

> **⚠️ Java 26 Note:** Due to ASM parsing constraints with Java class file version 70, this project **requires Spring Boot version 3.5.13 or higher**. Using older frameworks like 3.4.x will result in startup crashes.

---

## ⚙️ The Cryptographic Pipeline

1.  **Concatenation:** The user inputs a plaintext Message (`M`) and a Shared Secret (`S`). The strings are concatenated: `M || S`.
2.  **Hashing:** The backend computes a 32-byte digest of the combined string: `H = SHA-256(M || S)`.
3.  **Payload Generation:** The digest `H` is appended to the *original* message `M` to create the final payload: `P = M || H`.
4.  **Key Derivation:** The user's typed Symmetric Key is hashed with SHA-256, and the *first 16 bytes* of that digest form the AES-128 `SecretKeySpec`.
5.  **Encryption:** The payload `P` is encrypted using the AES key to produce the final `Ciphertext`.
6.  **Decryption & Verification:** The receiver decrypts the ciphertext, splits the payload into `M'` and `H'`, re-concatenates `M'` with their local Shared Secret, hashes it to generate `H''`, and does a constant-time comparison of `H'` vs `H''`. If they match, the message is 100% authentic and unaltered.

---

## 🚀 Getting Started

### Prerequisites
*   [Java Development Kit (JDK) 26](https://jdk.java.net/26/)
*   Apache Maven

### Running the Application

1.  Clone this repository.
2.  Open your terminal and navigate to the root directory containing the `pom.xml`.
3.  Start the Spring Boot server using Maven:
    ```bash
    mvn clean spring-boot:run
    ```
4.  Open a web browser and navigate to exactly:
    ```
    http://localhost:8080
    ```

### Usage Instructions

1.  **Sender Flow:** Scroll down to the **Sender** panel. Type a message, a secret (e.g., `secret123`), and a key (e.g., `myKey`). Click **Encrypt & Send**.
2.  **View Pipeline:** Watch the 4-step visualization unpack the math behind the scenes.
3.  **Network MITM:** Scroll down to the **Network** panel. You will see the raw Base64 ciphertext passing over the "wire". Try changing a few characters to simulate a network attack!
4.  **Receiver Flow:** Scroll down to the **Receiver** panel. Input the expected Shared Secret and Key. Click **Process Received Data** to see the 4-step mathematical verification and the final Authentication Pass/Fail assertion.

---

*This project was built for educational purposes to demonstrate secure REST API payload manipulation, byte-level safety, and basic full-stack web architecture.*
