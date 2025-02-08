import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Date;

public class PGPKeyGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Generate a 2048-bit RSA key pair
    public static PGPKeyPair generateKeyPair() throws NoSuchAlgorithmException, PGPException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Key size
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());
    }

    // Export the public key to a file
    public static void exportPublicKey(PGPPublicKey publicKey, String filePath) throws IOException {
        File file = new File(filePath);
        File parentDir = file.getParentFile();

        // Create the directory if it doesn't exist
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs(); // Create all necessary parent directories
        }

        try (OutputStream out = new ArmoredOutputStream(new FileOutputStream(file))) {
            publicKey.encode(out);
        }
    }

    // Export the private key to a file
    public static void exportPrivateKey(PGPSecretKey secretKey, String filePath) throws IOException {
        File file = new File(filePath);
        File parentDir = file.getParentFile();

        // Create the directory if it doesn't exist
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs(); // Create all necessary parent directories
        }

        try (OutputStream out = new ArmoredOutputStream(new FileOutputStream(file))) {
            secretKey.encode(out);
        }
    }

    // Generate and save the PGP key pair
    public static void generateAndSaveKeys(String publicKeyPath, String privateKeyPath, String identity,
            char[] passphrase) throws Exception {
        // Generate the key pair
        PGPKeyPair keyPair = generateKeyPair();

        // Create a digest calculator for the key
        PGPDigestCalculator digestCalculator = new JcaPGPDigestCalculatorProviderBuilder()
                .build()
                .get(HashAlgorithmTags.SHA1);

        // Create a secret key encryptor (to protect the private key)
        PBESecretKeyEncryptor secretKeyEncryptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5,
                digestCalculator)
                .setProvider("BC")
                .build(passphrase);

        // Create the secret key
        PGPSecretKey secretKey = new PGPSecretKey(
                PGPSignature.DEFAULT_CERTIFICATION,
                keyPair,
                identity,
                digestCalculator,
                null,
                null,
                new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                secretKeyEncryptor);

        // Export the keys
        exportPublicKey(keyPair.getPublicKey(), publicKeyPath);
        exportPrivateKey(secretKey, privateKeyPath);

        System.out.println("Keys generated successfully!");
        System.out.println("Public Key: " + publicKeyPath);
        System.out.println("Private Key: " + privateKeyPath);
    }

    public static void main(String[] args) {
        try {
            // Define the folder and file paths for the keys
            String publicKeyPath = "src/v1/publicKey.asc";
            String privateKeyPath = "src/v1/privateKey.asc";

            // Define identity (e.g., email or name) and passphrase
            String identity = "hour@testing.com";
            char[] passphrase = "hour1234".toCharArray();

            // Generate and save the keys
            generateAndSaveKeys(publicKeyPath, privateKeyPath, identity, passphrase);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}