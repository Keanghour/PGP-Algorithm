
---
#README
Pretty Good Privacy (PGP) is a widely-used encryption program that provides cryptographic privacy and authentication for data communication. Initially created by Phil Zimmermann in 1991, it uses a combination of asymmetric (public-key) and symmetric (private-key) cryptography to secure sensitive information.
---

---

Here’s a more concise and polished version of your README, keeping it clear and easy to read:

---

# PGP Algorithm - Java Encryption & Decryption

### Overview
This Java project demonstrates how to generate RSA key pairs and encrypt/decrypt messages using the BouncyCastle library. It supports RSA key sizes (2048, 4096, etc.) and saves the keys in ASCII-armored format, with the private key protected by a passphrase.

### Features:
- **Generate RSA Key Pairs**: Customizable key sizes (2048, 4096, etc.).
- **Message Encryption**: Encrypt messages using a public key.
- **Message Decryption**: Decrypt messages using a private key and passphrase.
- **Export Keys**: Save public and private keys in ASCII-armored format.
- **Secure Private Key**: Encrypt the private key with a passphrase.

### Prerequisites:
- Java 8+
- BouncyCastle Library (version 1.76 or 1.80)

### Setup:
1. **Add BouncyCastle Dependency** (via Maven):
   
   For **BouncyCastle 1.76**:
   ```xml
   <dependency>
       <groupId>org.bouncycastle</groupId>
       <artifactId>bcprov-jdk18on</artifactId>
       <version>1.76</version>
   </dependency>
   ```

   For **BouncyCastle 1.80**:
   ```xml
   <dependency>
       <groupId>org.bouncycastle</groupId>
       <artifactId>bcprov-jdk18on</artifactId>
       <version>1.80</version>
   </dependency>
   ```

2. **Import BouncyCastle**:
   ```java
   Security.addProvider(new BouncyCastleProvider());
   ```

### Usage:

#### 1. Generate Key Pair:
```java
PGPAlgorithm.generateKeyPair("Your Name", "email@example.com", "passphrase", "publicKey.asc", "privateKey.asc", 2048);
```

#### 2. Encrypt Message:
```java
String encryptedMessage = PGPAlgorithm.encryptMessage("Your secret message", "publicKey.asc");
System.out.println(encryptedMessage);
```

#### 3. Decrypt Message:
```java
String decryptedMessage = PGPAlgorithm.decryptMessage(encryptedMessage, "privateKey.asc", "passphrase");
System.out.println(decryptedMessage);
```

### Notes:
- Keys are saved in ASCII-armored format.
- RSA encryption and AES-256 are used for key protection.

### License:
MIT License

---

**Contact**:
- Email: phokeanghour12@gmail.com
- Telegram: @phokeanghour | 095 323 346

---

**Credit**: This project was created by **Pho Keanghour**.

---

Let me know if this works!
