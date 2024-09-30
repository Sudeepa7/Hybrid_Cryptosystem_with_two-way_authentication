import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Base64;

public class Server {

    public static void main(String[] args) throws Exception {
        // Create server socket listening on port 1234
        ServerSocket serverSocket = new ServerSocket(1234);
        System.out.println("Server is running....." + "\n");

        // Wait for the client to connect
        Socket socket = serverSocket.accept();
        ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());

        // Generate an RSA key pair for the server (Bob)
        KeyPair serverKeyPair = generateRSAKeyPair();
        System.out.println("Generated Server's RSA Public Key: " + Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded()));
        System.out.println("Generated Server's RSA Private Key: " + Base64.getEncoder().encodeToString(serverKeyPair.getPrivate().getEncoded()) + "\n");

        // Send the server's public RSA key to the client
        outputStream.writeObject(serverKeyPair.getPublic());

        // Receive the encrypted message, encrypted AES key, and signature from the client
        byte[] encryptedMessage = (byte[]) inputStream.readObject();
        byte[] encryptedAESKey = (byte[]) inputStream.readObject();
        byte[] signature = (byte[]) inputStream.readObject();
        PublicKey clientPublicKey = (PublicKey) inputStream.readObject();

        // Print the received encrypted message and keys
        System.out.println("Received Encrypted Message: " + Base64.getEncoder().encodeToString(encryptedMessage));
        System.out.println("Received Encrypted AES Key: " + Base64.getEncoder().encodeToString(encryptedAESKey));
        System.out.println("Received Client's Digital Signature: " + Base64.getEncoder().encodeToString(signature));
        System.out.println("Received Client's Public Key: " + Base64.getEncoder().encodeToString(clientPublicKey.getEncoded()) + "\n");

        // Decrypt the AES key using the server's private RSA key
        byte[] decryptedAESKey = decryptRSA(encryptedAESKey, serverKeyPair.getPrivate());
        SecretKey aesKey = new SecretKeySpec(decryptedAESKey, 0, decryptedAESKey.length, "AES");
        System.out.println("Decrypted AES Key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()) + "\n");

        // Decrypt the message using the decrypted AES key
        String decryptedMessage = decryptAES(encryptedMessage, aesKey);
        System.out.println("Decrypted Message from Client: " + decryptedMessage + "\n");

        // Verify the client's digital signature using the client's public key
        boolean isVerified = verifySignature(decryptedMessage, signature, clientPublicKey);
        System.out.println("Is Client's signature verified? " + isVerified + "\n");

        // Server's acknowledgment message
        String ackMessage = "Acknowledgment from Server";
        System.out.println("Acknowledgment Message: " + ackMessage + "\n");

        // Encrypt the acknowledgment using AES
        byte[] encryptedAckMessage = encryptAES(ackMessage, aesKey);
        System.out.println("Encrypted Acknowledgment: " + Base64.getEncoder().encodeToString(encryptedAckMessage) + "\n");

        // Sign the acknowledgment message using the server's private RSA key
        byte[] serverSignature = signMessage(ackMessage, serverKeyPair.getPrivate());
        System.out.println("Server's Digital Signature on Acknowledgment: " + Base64.getEncoder().encodeToString(serverSignature) + "\n");

        // Send the encrypted acknowledgment message and signature to the client
        outputStream.writeObject(encryptedAckMessage);
        outputStream.writeObject(serverSignature);

        System.out.println("Encrypted acknowledgment and signature sent to the client....." + "\n");

        // Close resources
        outputStream.close();
        inputStream.close();
        socket.close();
        serverSocket.close();
    }

    // Generate RSA key pair for encryption and signing
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);  // RSA key size of 2048 bits
        return keyGen.generateKeyPair();
    }

    // RSA Decryption using private key
    public static byte[] decryptRSA(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);  // Decrypt the AES key
    }

    // AES Encryption
    public static byte[] encryptAES(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);  // Initialize cipher for encryption
        return cipher.doFinal(message.getBytes());  // Encrypt the acknowledgment message
    }

    // AES Decryption
    public static String decryptAES(byte[] cipherText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);  // Initialize cipher for decryption
        byte[] decryptedBytes = cipher.doFinal(cipherText);  // Decrypt the client's message
        return new String(decryptedBytes);  // Convert decrypted bytes to string
    }

    // Generate a digital signature using the private key
    public static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");  // Use SHA-256 with RSA for signing
        signature.initSign(privateKey);  // Initialize signature with private key
        signature.update(message.getBytes());  // Sign the acknowledgment message
        return signature.sign();  // Generate the digital signature
    }

    // Verify the digital signature using the sender's public key
    public static boolean verifySignature(String message, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");  // Use SHA-256 with RSA for verification
        signature.initVerify(publicKey);  // Initialize verification with the public key
        signature.update(message.getBytes());  // Provide the original message data for verification
        return signature.verify(signatureBytes);  // Verify the digital signature
    }
}
