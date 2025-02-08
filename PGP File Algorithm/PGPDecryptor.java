package PGP File Algorithm;

public class PGPDecryptor {
    public static void main(String[] args) {
        String encryptedFile = "Testing.txt.pgp"; 
        String privateKeyFile = "private-key.asc"; 
        String passphrase = "hour1234"; 
        String outputFile = "Testing.txt";

        try {
            PGPAlgorithm.decryptFile(encryptedFile, outputFile, privateKeyFile, passphrase);
            System.out.println("File decrypted successfully!");
            System.out.println("Decrypted file saved to: " + outputFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
