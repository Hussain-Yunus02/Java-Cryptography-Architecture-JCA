import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;

public class Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try {
            System.out.println("[Client] Connecting to server...");
            Socket socket = new Socket(SERVER_ADDRESS, PORT);

            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            // Step 1: Send Alice's identity and a random nonce (nonceA) to Bob
            String aliceIdentity = "Alice";
            long nonceA = new SecureRandom().nextLong();

            System.out.println("[Client] Sending Identity and NonceA: " + aliceIdentity + ", " + nonceA);
            oos.writeObject(aliceIdentity);
            oos.writeObject(nonceA);
            oos.flush();  // Ensure data is sent immediately

            // Step 2: Receive Bob’s nonce (nonceB) and encrypted message
            System.out.println("[Client] Waiting for response from Server...");
            long nonceB = (long) ois.readObject();
            byte[] encryptedMessageFromBob = (byte[]) ois.readObject();
            System.out.println("[Client] Received NonceB: " + nonceB);
            System.out.println("[Client] Received Encrypted Message from Server.");

            // Step 3: Generate symmetric key
            String sharedKey = generateSharedKey(aliceIdentity, "Bob");
            Key secretKey = generateSecretKey(sharedKey);

            // Step 4: Decrypt Bob’s identity and nonceA
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            System.out.println("[Client] Attempting decryption...");
            byte[] decryptedMessage = cipher.doFinal(encryptedMessageFromBob);
            String decryptedMessageString = new String(decryptedMessage);
            System.out.println("[Client] Decrypted Message from Server: " + decryptedMessageString);

            // Step 5: Encrypt Alice’s identity and Bob’s nonce (nonceB)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedMessageToBob = cipher.doFinal((aliceIdentity + nonceB).getBytes());

            System.out.println("[Client] Sending Encrypted Message to Server.");
            oos.writeObject(encryptedMessageToBob);
            oos.flush();  // Ensure it's sent

            // Step 6: Close connections
            System.out.println("[Client] Closing connection.");
            oos.close();
            ois.close();
            socket.close();
        } catch (Exception e) {
            System.err.println("[Client] Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String generateSharedKey(String aliceIdentity, String bobIdentity) throws Exception {
        String concatenatedIdentities = aliceIdentity + bobIdentity;
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = sha256.digest(concatenatedIdentities.getBytes());
        return Base64.getEncoder().encodeToString(hashedBytes);
    }

    private static Key generateSecretKey(String sharedKey) {
        return new SecretKeySpec(sharedKey.getBytes(), 0, 16, "AES");
    }
}

