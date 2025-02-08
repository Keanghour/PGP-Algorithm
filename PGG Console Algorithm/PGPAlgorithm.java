import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

public class PGPAlgorithm {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Key pair generation
    public static void generateKeyPair(String name, String email, String passphrase, String publicKeyFile, String privateKeyFile, int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());

        PBESecretKeyEncryptor encryptor = new JcePBESecretKeyEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256, sha1Calc)
                .setProvider("BC")
                .build(passphrase.toCharArray());

        PGPSecretKey secretKey = new PGPSecretKey(
                PGPSignature.DEFAULT_CERTIFICATION,
                pgpKeyPair,
                name + " <" + email + ">",
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                encryptor
        );

        // Export public key
        try (OutputStream publicKeyOut = new ArmoredOutputStream(new FileOutputStream(publicKeyFile))) {
            PGPPublicKey publicKey = secretKey.getPublicKey();
            publicKey.encode(publicKeyOut);
        }

        // Export private key
        try (OutputStream privateKeyOut = new ArmoredOutputStream(new FileOutputStream(privateKeyFile))) {
            secretKey.encode(privateKeyOut);
        }
    }

    // Encrypt a message (string)
    public static String encryptMessage(String message, String publicKeyFile) throws Exception {
        PGPPublicKey publicKey = readPublicKey(new FileInputStream(publicKeyFile));

        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        try (OutputStream armoredOut = new ArmoredOutputStream(encryptedOut)) {
            PGPEncryptedDataGenerator encryptor = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                            .setWithIntegrityPacket(true)
                            .setProvider("BC")
            );
            encryptor.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

            try (OutputStream cipherOut = encryptor.open(armoredOut, new byte[4096])) {
                byte[] buffer = message.getBytes();
                cipherOut.write(buffer, 0, buffer.length);
            }
        }

        return new String(encryptedOut.toByteArray());
    }


    // Decrypt a message (string)
    public static String decryptMessage(String encryptedMessage, String privateKeyFile, String passphrase) throws Exception {
        PGPPrivateKey privateKey = readPrivateKey(new FileInputStream(privateKeyFile), passphrase);

        ByteArrayInputStream encryptedIn = new ByteArrayInputStream(encryptedMessage.getBytes());
        InputStream decodedStream = PGPUtil.getDecoderStream(encryptedIn);

        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(decodedStream, new JcaKeyFingerprintCalculator());
        Object object = pgpObjectFactory.nextObject();

        if (object instanceof PGPEncryptedDataList) {
            PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) object;
            Iterator<?> it = encryptedDataList.getEncryptedDataObjects();
            PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData) it.next();

            try (InputStream decryptedData = encryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
                    .setProvider("BC")
                    .build(privateKey))) {
                byte[] buffer = new byte[4096];
                int len;
                ByteArrayOutputStream decryptedOut = new ByteArrayOutputStream();
                while ((len = decryptedData.read(buffer)) > 0) {
                    decryptedOut.write(buffer, 0, len);
                }

                System.out.println(new String(decryptedOut.toByteArray(), StandardCharsets.UTF_8));
                return new String(decryptedOut.toByteArray(), StandardCharsets.UTF_8);
            }
        } else {
            throw new IllegalArgumentException("The input is not a valid PGP encrypted message.");
        }
    }

    // Helper method to read the public key
    private static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
        PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator()
        );

        Iterator<PGPPublicKeyRing> keyRingIterator = keyRingCollection.getKeyRings();
        while (keyRingIterator.hasNext()) {
            PGPPublicKeyRing keyRing = keyRingIterator.next();
            Iterator<PGPPublicKey> keyIterator = keyRing.getPublicKeys();
            while (keyIterator.hasNext()) {
                PGPPublicKey key = keyIterator.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("No encryption key found in the public key file.");
    }

    // Helper method to read the private key
    private static PGPPrivateKey readPrivateKey(InputStream input, String passphrase) throws IOException, PGPException {
        PGPSecretKeyRingCollection keyRingCollection = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator()
        );

        Iterator<PGPSecretKeyRing> keyRingIterator = keyRingCollection.getKeyRings();
        while (keyRingIterator.hasNext()) {
            PGPSecretKeyRing keyRing = keyRingIterator.next();
            Iterator<PGPSecretKey> keyIterator = keyRing.getSecretKeys();
            while (keyIterator.hasNext()) {
                PGPSecretKey secretKey = keyIterator.next();
                if (secretKey.isSigningKey()) {
                    return secretKey.extractPrivateKey(
                            new JcePBESecretKeyDecryptorBuilder()
                                    .setProvider("BC")
                                    .build(passphrase.toCharArray())
                    );
                }
            }
        }

        throw new IllegalArgumentException("No decryption key found in the private key file.");
    }
}