public class PGPEncryptor {
    public static void main(String[] args) {
        // message
        String data = "";

        // key
        String publicKeyFile = "";

        String Encryption = "";
        try {
            Encryption = PGPAlgorithm.encryptMessage(data, publicKeyFile);

            System.out.println(Encryption);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}