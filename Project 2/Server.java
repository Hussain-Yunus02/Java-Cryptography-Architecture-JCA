import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.Cipher;

public class Server {
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try {
            System.out.println("[Server] Waiting for client connection...");
            ServerSocket serverSocket = new ServerSocket(PORT);
            Socket socket = serverSocket.accept();
            System.out.println("[Server] Connection established.");

            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            // Step 1: Receive Alice's identity and nonce
            System.out.println("[Server] Receiving Alice's identity and nonce...");
            String aliceIdentity = (String) ois.readObject();
            long nonceA = (long) ois.readObject();
            System.out.println("[Server] Received Identity: " + aliceIdentity);
            System.out.println("[Server] Received NonceA: " + nonceA);

            // Step 2: Generate Bob's RSA key pair
            System.out.println("[Server] Generating Bob's RSA key pair...");
            KeyPair keyPair = generateKeyPair();
            PublicKey bobPublicKey = keyPair.getPublic();
            PrivateKey bobPrivateKey = keyPair.getPrivate();

            // Step 3: Generate NonceB
            SecureRandom secureRandom = new SecureRandom();
            long nonceB = secureRandom.nextLong();
            System.out.println("[Server] Generated NonceB: " + nonceB);

            // Step 4: Send NonceB, Bob’s public key, and encrypted message to Alice
            System.out.println("[Server] Sending NonceB, Public Key, and Encrypted Message to Alice...");
            oos.writeObject(nonceB);
            oos.writeObject(bobPublicKey);
            oos.flush();

            // Step 5: Receive Alice’s Public Key and Encrypted Message
            System.out.println("[Server] Waiting for Alice's public key and encrypted response...");
            PublicKey alicePublicKey = (PublicKey) ois.readObject();
            byte[] encryptedMessageFromAlice = (byte[]) ois.readObject();
            System.out.println("[Server] Received Alice's Public Key.");
            System.out.println("[Server] Received Encrypted Message from Alice.");

            // Step 6: Decrypt Alice’s message using **Alice’s public key**
            System.out.println("[Server] Decrypting message using Alice’s Public Key...");
            String decryptedMessage = decrypt(encryptedMessageFromAlice, alicePublicKey);
            System.out.println("[Server] Decrypted Message from Alice: " + decryptedMessage);

            // Step 7: Close connection
            System.out.println("[Server] Closing connection...");
            ois.close();
            oos.close();
            socket.close();
            serverSocket.close();
        } catch (Exception e) {
            System.err.println("[Server] Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encrypt(String data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }

    private static String decrypt(byte[] encryptedData, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(encryptedData);
        return new String(decryptedBytes);
    }
}


