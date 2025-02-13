import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;

public class Server {
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try {
            System.out.println("[Bob] Waiting for connection...");
            ServerSocket serverSocket = new ServerSocket(PORT);
            Socket socket = serverSocket.accept();
            System.out.println("[Bob] Connection established with Alice.");

            try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                 ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {

                // Step 1: Generate RSA key pair (Bob's key pair)
                KeyPair bobKeyPair = generateKeyPair();
                PublicKey bobPublicKey = bobKeyPair.getPublic();
                PrivateKey bobPrivateKey = bobKeyPair.getPrivate();

                // Step 2: Send Bob’s public key to Alice
                oos.writeObject(bobPublicKey);
                oos.flush();
                System.out.println("[Bob] Sent Public Key to Alice.");

                // Step 3: Receive Alice’s public key
                PublicKey alicePublicKey = (PublicKey) ois.readObject();
                System.out.println("[Bob] Received Alice's Public Key.");

                // Step 4: Receive encrypted message and signature from Alice
                byte[] encryptedMessage = (byte[]) ois.readObject();
                byte[] signatureA = (byte[]) ois.readObject();

                // Step 5: Decrypt Alice's message using Bob’s private key
                String decryptedMessage = decrypt(encryptedMessage, bobPrivateKey);
                System.out.println("[Bob] Decrypted Message from Alice: " + decryptedMessage);

                // Step 6: Verify Alice’s signature using her public key
                if (verifySignature(decryptedMessage, signatureA, alicePublicKey)) {
                    System.out.println("[Bob] Signature Verified. Message is authentic.");
                } else {
                    System.out.println("[Bob] Signature Verification Failed! Possible tampering or replay attack.");
                }
            }

            // Step 7: Close connection
            System.out.println("[Bob] Closing connection...");
            serverSocket.close();
        } catch (Exception e) {
            System.err.println("[Bob] Error: " + e.getMessage());
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
     * Decrypts a message using the provided private key.
     */
    private static String decrypt(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedData);
        return new String(decryptedBytes);
    }

    /**
     * Verifies the digital signature using the sender's public key.
     */
    private static boolean verifySignature(String message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(message.getBytes());
        return verifier.verify(signature);
    }
}

