package PGP File Algorithm;

public class PGPEncryptor {
    public static void main(String[] args) {
        String inputFile = "Testing.txt"; 
        String publicKeyFile = "public-key.asc"; 
        String outputFile = "Testing.txt.pgp"; 

        try {
            PGPAlgorithm.encryptFile(inputFile, outputFile, publicKeyFile);
            System.out.println("File encrypted successfully!");
            System.out.println("Encrypted file saved to: " + outputFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
