public class PGPDecryptor {
    public static void main(String[] args) {

        String privateKeyFile = "";
        String passphrase = ""; // passphrase private key

        String encryptMessages = "";

        try {
            PGPAlgorithm.decryptMessage(encryptMessages, privateKeyFile, passphrase);
            // System.out.println("Message decrypted successfully!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
