import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;

public class Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try {
            System.out.println("[Alice] Connecting to Bob...");
            Socket socket = new Socket(SERVER_ADDRESS, PORT);
            System.out.println("[Alice] Connection established with Bob.");

            try (ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

                // Step 1: Generate RSA key pair (Alice's key pair)
                KeyPair aliceKeyPair = generateKeyPair();
                PublicKey alicePublicKey = aliceKeyPair.getPublic();
                PrivateKey alicePrivateKey = aliceKeyPair.getPrivate();

                // Step 2: Receive Bob’s public key
                PublicKey bobPublicKey = (PublicKey) ois.readObject();
                System.out.println("[Alice] Received Bob’s Public Key.");

                // Step 3: Send Alice’s public key to Bob
                oos.writeObject(alicePublicKey);
                oos.flush();
                System.out.println("[Alice] Sent Public Key to Bob.");

                // Step 4: Create message with timestamp
                String message = "Hello, Bob!";
                long timestamp = System.currentTimeMillis();
                String messageWithTimestamp = message + "|" + timestamp;
                System.out.println("[Alice] Message with timestamp: " + messageWithTimestamp);

                // Step 5: Sign the message using Alice's private key
                byte[] signature = signMessage(messageWithTimestamp, alicePrivateKey);
                System.out.println("[Alice] Generated Digital Signature.");

                // Step 6: Encrypt the message using Bob’s public key
                byte[] encryptedMessage = encrypt(messageWithTimestamp, bobPublicKey);
                System.out.println("[Alice] Encrypted Message: " + Base64.getEncoder().encodeToString(encryptedMessage));

                // Step 7: Send encrypted message and signature to Bob
                oos.writeObject(encryptedMessage);
                oos.writeObject(signature);
                oos.flush();
                System.out.println("[Alice] Sent Encrypted Message and Signature to Bob.");
            }

            // Step 8: Close connection
            System.out.println("[Alice] Closing connection.");
            socket.close();
        } catch (Exception e) {
            System.err.println("[Alice] Error: " + e.getMessage());
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
     * Encrypts a message using the provided public key.
     */
    private static byte[] encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    /**
     * Signs a message using the provided private key.
     */
    private static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }
}

