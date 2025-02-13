import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;

public class Server {
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try {
            System.out.println("[Server] Waiting for connection...");
            ServerSocket serverSocket = new ServerSocket(PORT);
            Socket socket = serverSocket.accept();
            System.out.println("[Server] Client connected.");

            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            // Step 1: Receive Alice's identity and nonceA
            String aliceIdentity = (String) ois.readObject();
            long nonceA = (long) ois.readObject();
            System.out.println("[Server] Received Identity: " + aliceIdentity + ", NonceA: " + nonceA);

            // Step 2: Generate Bob's nonce
            SecureRandom secureRandom = new SecureRandom();
            long nonceB = secureRandom.nextLong();

            // Step 3: Generate symmetric key
            String sharedKey = generateSharedKey(aliceIdentity, "Bob");
            Key secretKey = generateSecretKey(sharedKey);

            // Step 4: Encrypt Bob's identity and nonceA
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedMessage = cipher.doFinal(("Bob" + nonceA).getBytes());

            // Step 5: Send nonceB and encrypted message to Alice
            System.out.println("[Server] Sending NonceB: " + nonceB);
            oos.writeObject(nonceB);
            oos.writeObject(encryptedMessage);
            oos.flush();

            // Step 6: Receive and decrypt Alice’s response
            System.out.println("[Server] Waiting for response from Client...");
            byte[] encryptedMessageFromAlice = (byte[]) ois.readObject();

            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedMessage = cipher.doFinal(encryptedMessageFromAlice);
            String decryptedMessageString = new String(decryptedMessage);
            System.out.println("[Server] Decrypted Message from Alice: " + decryptedMessageString);

            // Step 7: Close connections
            System.out.println("[Server] Closing connection.");
            ois.close();
            oos.close();
            socket.close();
            serverSocket.close();
        } catch (Exception e) {
            System.err.println("[Server] Error: " + e.getMessage());
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
