import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.Cipher;

public class Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try {
            System.out.println("[Client] Connecting to server...");
            Socket socket = new Socket(SERVER_ADDRESS, PORT);

            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            // Step 1: Send Alice's identity and a random nonce (nonceA)
            String aliceIdentity = "Alice";
            long nonceA = new SecureRandom().nextLong();
            System.out.println("[Client] Sending Identity and NonceA...");
            oos.writeObject(aliceIdentity);
            oos.writeObject(nonceA);
            oos.flush();
            System.out.println("[Client] Sent Identity: " + aliceIdentity);
            System.out.println("[Client] Sent NonceA: " + nonceA);

            // Step 2: Receive NonceB and Bob’s Public Key
            System.out.println("[Client] Waiting to receive NonceB and Bob’s Public Key...");
            long nonceB = (long) ois.readObject();
            PublicKey bobPublicKey = (PublicKey) ois.readObject();
            System.out.println("[Client] Received NonceB: " + nonceB);
            System.out.println("[Client] Received Bob’s Public Key.");

            // Step 3: Generate Alice’s RSA key pair
            System.out.println("[Client] Generating Alice's RSA key pair...");
            KeyPair keyPair = generateKeyPair();
            PublicKey alicePublicKey = keyPair.getPublic();
            PrivateKey alicePrivateKey = keyPair.getPrivate();

            // Step 4: Encrypt Alice’s identity + nonceB using **Alice’s private key**
            System.out.println("[Client] Encrypting message using Alice’s Private Key...");
            byte[] encryptedMessageToBob = encrypt(aliceIdentity + nonceB, alicePrivateKey);

            // Step 5: Send Alice’s Public Key and Encrypted Message to Bob
            System.out.println("[Client] Sending Alice's Public Key and Encrypted Message...");
            oos.writeObject(alicePublicKey);
            oos.writeObject(encryptedMessageToBob);
            oos.flush();

            // Step 6: Close connection
            System.out.println("[Client] Closing connection.");
            oos.close();
            ois.close();
            socket.close();
        } catch (Exception e) {
            System.err.println("[Client] Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Generates an RSA key pair.
     */
    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Encrypts a string using the provided key (either public or private).
     */
    private static byte[] encrypt(String data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }

    /**
     * Decrypts a byte array using the provided key (either public or private).
     */
    private static String decrypt(byte[] encryptedData, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(encryptedData);
        return new String(decryptedBytes);
    }
}


