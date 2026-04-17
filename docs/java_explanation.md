# A Beginner's Guide to the CryptoFlow Java Code

If you have never written a line of Java before, looking at the code for this cryptography project might feel intimidating. You will see words like `byte[]`, `Cipher`, `@RestController`, and `ResponseEntity`. 

This document translates the "programmer speak" into plain English so you can understand exactly how our application handles the math, the security, and the communication with the user's web browser, alongside exactly where to find that code!

---

## 1. The Big Picture: How is the Code Organized?

Think of our Java code as a restaurant:
*   **The Waiters (`Controllers`):** They stand at the front, take orders (data) from the web browser, hand it to the kitchen, and bring the final dish back to the customer. 
*   **The Kitchen (`CryptoUtils`):** The chefs who don't care about the internet. They just take raw ingredients (data), chop them up, do complex math, and hand them back.

---

## 2. The Kitchen: `CryptoUtils.java`

*File location: [CryptoUtils.java](../src/main/java/com/cryptodemo/util/CryptoUtils.java)*

Computers don't encrypt English words like "Hello". They encrypt raw numbers. A fundamental concept in Java cryptography is the **Byte Array** (written as `byte[]`). A byte array is just a sequence of raw numbers that represents computer data. Before we do any math, we always translate the user's text into a `byte[]`.

### Hashing ([`sha256()`](../src/main/java/com/cryptodemo/util/CryptoUtils.java#L37-L45))
**The Concept:** A hash is a mathematical fingerprint. No matter how large the input is, SHA-256 will always spit out exactly 32 bytes (64 hex characters) of gibberish. If you change a single letter in the input, the entire fingerprint completely changes.

**The Code:** Our Java code uses a built-in tool called `MessageDigest.getInstance("SHA-256")`. It takes in the raw bytes, runs the fingerprint math, and returns the 32-byte result.
```java
public static byte[] sha256(byte[] input) {
    try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("SHA-256 algorithm not available", e);
    }
}
```

### Slicing and Dicing ([`concatenate()`](../src/main/java/com/cryptodemo/util/CryptoUtils.java#L113-L118) and [`splitPayload()`](../src/main/java/com/cryptodemo/util/CryptoUtils.java#L128-L138))
**The Concept:** To send the message and the fingerprint together, we need to glue them. But how does the receiver know where the message ends and the fingerprint begins without using a comma or a space? Because we know SHA-256 is *always* exactly 32 bytes, our code works like a butcher. 

**The Code:** To cut the string (`splitPayload`), it takes the final chunk of data, counts exactly 32 steps backwards from the end, and cuts it like a knife. The front half is guaranteed to be the message; the back 32 steps are guaranteed to be the fingerprint.
```java
public static byte[][] splitPayload(byte[] payload) {
    // Cut 32 bytes from the absolute end of the array
    int messageLength = payload.length - SHA256_HASH_LENGTH;
    byte[] messageBytes = Arrays.copyOfRange(payload, 0, messageLength);
    byte[] hashBytes = Arrays.copyOfRange(payload, messageLength, payload.length);
    return new byte[][] { messageBytes, hashBytes };
}
```

### Encryption ([`aesEncrypt()`](../src/main/java/com/cryptodemo/util/CryptoUtils.java#L83-L87) and [`normalizeKey()`](../src/main/java/com/cryptodemo/util/CryptoUtils.java#L66-L70))
**The Concept:** AES is like an indestructible lockbox. To lock it (encrypt) or unlock it (decrypt), you need an exact 16-character physical key. Users might type a password like "cat", which isn't 16 characters. 

**The Code:** Our code fixes this by taking their "cat" password, generating a giant hash of it, and chopping off the first 16 bytes to use as the perfect key. Then it uses the Java `Cipher` class to scramble the data.
```java
public static SecretKeySpec normalizeKey(String userKey) {
    byte[] hash = sha256(userKey);
    byte[] keyBytes = Arrays.copyOf(hash, 16); // first 16 bytes → AES-128 key
    return new SecretKeySpec(keyBytes, AES_ALGORITHM);
}
```

---

## 3. The Waiters: The Website Aspect (Controllers)

Whenever you click a button on the website, the browser shouts a message over the network to our Java server. The Controllers are the code listening for those shouts.

### [`SenderController.java`](../src/main/java/com/cryptodemo/controller/SenderController.java#L37-L56)
**The Concept:** The user wants to send a secret message. The `@PostMapping("/api/send")` tells Java: "If the website asks for '/api/send', run this block of code."

**The Code Pipeline:** It gathers the inputs, uses the kitchen (`CryptoUtils`) to hash them together, glues the array, and encrypts it safely.
```java
// Step 1: Concatenate M || S
byte[] combined = CryptoUtils.concatenate(messageBytes, secretBytes);

// Step 2: Compute SHA-256( M || S )
byte[] hash = CryptoUtils.sha,256(combined);

// Step 3: Build payload = M || H(M||S)
byte[] payload = CryptoUtils.concatenate(messageBytes, hash);

// Step 4: Encrypt with AES
SecretKeySpec aesKey = CryptoUtils.normalizeKey(key);
byte[] ciphertext = CryptoUtils.aesEncrypt(payload, aesKey);
```

### [`ReceiverController.java`](../src/main/java/com/cryptodemo/controller/ReceiverController.java#L74-L109)
**The Concept:** The user just received an encrypted box and wants to know if it's authentic. It unlocks the box (`aesDecrypt`) and splits it up.

**The Bouncer Check (The most important check in the code):** The Receiver assumes the text inside might be dangerous. It glues the extracted text to its *own* local `Secret` and runs it through the fingerprint machine.
```java
// Independently compute new hash from the extracted message + correct secret
byte[] combined = CryptoUtils.concatenate(messageBytes, secretBytes);
byte[] computedHash = CryptoUtils.sha256(combined);

// Constant-time mathematical comparison: Does our computed hash match the received hash?
boolean verified = MessageDigest.isEqual(computedHash, receivedHash);
```
We use `MessageDigest.isEqual()`. This compares the fingerprint that just came out of the machine with the fingerprint found inside the box. If they match exactly, we know two things for a fact: The message wasn't manipulated in transit (Integrity), and the sender knows the secret password (Authenticity).

---

## 4. The Foundation: Maven and Spring Boot

If the code files are the restaurant staff, **Maven** and **Spring Boot** are the construction crew and the building manager.

### Maven (`pom.xml`)
**The Concept:** Managing a Java project manually is exhausting. You have to compile your code, download external tools, and tell the computer how to package it all up. Maven automates this entirely.
**The Code:** In our project, Maven looks at the [`pom.xml`](../pom.xml) (Project Object Model) file. This is simply a shopping list. When you type `mvn spring-boot:run` in your terminal, Maven reads the `pom.xml`, downloads all the required Spring Boot libraries, compiles the Java code, and starts the project. It ensures that everyone on the team has the exact same setup.

### Spring Boot (`CryptoFlowApplication.java`)
**The Concept:** Writing a web server from scratch in Java takes thousands of lines of boilerplate code. It involves managing network ports, handling raw HTTP bytes, and configuring server hardware.
**The Code:** Spring Boot does all of this magically in the background so we can just focus on our cryptography app. The `@RestController` and `@PostMapping` annotations we use in our Waiters? Those are Spring Boot features. Spring Boot automatically wires up an embedded web server (Tomcat), listens on port `8080`, and routes the incoming HTTP traffic directly to our specific methods without us having to write any raw networking logic.

---

## Summary

In short, the Java code relies on **Controllers** to talk to the internet and format data nicely for the UI, while offloading all the heavy lifting to the **CryptoUtils** class. By handling data as raw `byte[]` arrays instead of readable text, the application ensures that complex characters, emojis, or malicious tampering won't accidentally break the math.
