
---

# PGPAlgorithm - Java PGP Encryption & Decryption

### Overview:
This Java class allows generating PGP RSA key pairs and encrypting/decrypting messages using BouncyCastle.

### Features:
- **Key Pair Generation**: Create RSA public/private keys with a passphrase.
- **Message Encryption**: Encrypt messages with a public key.
- **Message Decryption**: Decrypt messages with a private key and passphrase.

### Prerequisites:
- Java 8+
- BouncyCastle Library (BC provider)

### Setup:
1. **Add BouncyCastle Dependency** (via Maven | Gradle):
   
   ```xml
   <dependency>
       <groupId>org.bouncycastle</groupId>
       <artifactId>bcprov-jdk18on</artifactId>
       <version>1.76</version>
   </dependency>
   ```


### URL for download the JAR file"

**Referenced Libranries**
```
https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk18on/1.76
https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk18on/1.76
```

----


2. **Import BouncyCastle Provider**:
   - Add `Security.addProvider(new BouncyCastleProvider())` in your code to enable BouncyCastle.

### Usage:

#### 1. Generate Key Pair:

```java
PGPAlgorithm.generateKeyPair("Your Name", "email@example.com", "passphrase", "publicKey.asc", "privateKey.asc", 2048);
```

- **Args**: Name, email, passphrase, public/private key file paths, key size.

#### 2. Encrypt Message:

```java
String encryptedMessage = PGPAlgorithm.encryptMessage("Your secret message", "publicKey.asc");
System.out.println(encryptedMessage);
```

- **Args**: Message to encrypt, public key file.

#### 3. Decrypt Message:

```java
String decryptedMessage = PGPAlgorithm.decryptMessage(encryptedMessage, "privateKey.asc", "passphrase");
System.out.println(decryptedMessage);
```

- **Args**: Encrypted message, private key file, passphrase.

### Notes:
- Keys are saved in ASCII armored format.
- Uses RSA encryption and AES-256 for private key protection.

### License:
MIT License

**Let me know if this works for you!**
---

**Contact:**
- Email: phokeanghour12@gmail.com
- Telegram: 095 323 346 | @phokeanghour

---

**Credit**: This project was created by **Pho Keanghour**.
