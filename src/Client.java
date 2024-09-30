import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;
import java.util.Base64;

public class Client {

    public static void main(String[] args) throws Exception {
        // Connect to the server on localhost at port 1234
        Socket socket = new Socket("localhost", 1234);
        ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());

        // Generate AES key for message encryption
        SecretKey aesKey = generateAESKey();
        System.out.println("Generated AES Key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()) + "\n");

        // Message to send to the server
        String message = "Hello, Server! This is a secret message.";
        System.out.println("Original Message: " + message + "\n");

        // Encrypt the message using AES
        byte[] encryptedMessage = encryptAES(message, aesKey);
        System.out.println("Encrypted Message (AES): " + Base64.getEncoder().encodeToString(encryptedMessage) + "\n");

        // Receive server's public RSA key from the server
        PublicKey serverPublicKey = (PublicKey) inputStream.readObject();
        System.out.println("Received Server's Public RSA Key: " + Base64.getEncoder().encodeToString(serverPublicKey.getEncoded()) + "\n");

        // Encrypt the AES key using the server's public RSA key
        byte[] encryptedAESKey = encryptRSA(aesKey.getEncoded(), serverPublicKey);
        System.out.println("Encrypted AES Key (RSA): " + Base64.getEncoder().encodeToString(encryptedAESKey) + "\n");

        // Generate RSA key pair for the client (this client, Alice)
        KeyPair clientKeyPair = generateRSAKeyPair();
        System.out.println("Generated Client's RSA Public Key: " + Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded()));
        System.out.println("Generated Client's RSA Private Key: " + Base64.getEncoder().encodeToString(clientKeyPair.getPrivate().getEncoded()) + "\n");

        // Sign the original message using the client's private RSA key
        byte[] signature = signMessage(message, clientKeyPair.getPrivate());
        System.out.println("Digital Signature of Message: " + Base64.getEncoder().encodeToString(signature) + "\n");

        // Send the encrypted message, encrypted AES key, signature, and client's public key to the server
        outputStream.writeObject(encryptedMessage);
        outputStream.writeObject(encryptedAESKey);
        outputStream.writeObject(signature);
        outputStream.writeObject(clientKeyPair.getPublic());

        System.out.println("Message and signature sent to the server....." + "\n");

        // Receive encrypted acknowledgment and the server's digital signature
        byte[] encryptedAckMessage = (byte[]) inputStream.readObject();
        byte[] serverSignature = (byte[]) inputStream.readObject();

        // Print the encrypted acknowledgment in Base64 (as received)
        System.out.println("Encrypted Acknowledgment from Server (Base64): " + Base64.getEncoder().encodeToString(encryptedAckMessage) + "\n");

        // Decrypt the acknowledgment using AES
        String ackMessage = decryptAES(encryptedAckMessage, aesKey);
        System.out.println("Decrypted Acknowledgment from Server: " + ackMessage + "\n");

        // Verify the server's signature on the acknowledgment using the server's public key
        boolean isServerVerified = verifySignature(ackMessage, serverSignature, serverPublicKey);
        System.out.println("Is Server's signature verified? " + isServerVerified + "\n");

        // Close all resources
        outputStream.close();
        inputStream.close();
        socket.close();
    }

    // Generate an RSA key pair for the client
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);  // Use a 2048-bit key for RSA
        return keyGen.generateKeyPair();
    }

    // Generate an AES key for encrypting the message
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // AES key size is 128 bits
        return keyGen.generateKey();
    }

    // Encrypt data using RSA public key encryption
    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // Encrypt the original message using AES symmetric encryption
    public static byte[] encryptAES(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(message.getBytes());
    }

    // Decrypt the cipher text using the provided AES secret key
    public static String decryptAES(byte[] cipherText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(cipherText);
        return new String(decryptedBytes);
    }

    // Generate a digital signature for the message using the client's private key
    public static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA"); // Use SHA-256 with RSA algorithm
        signature.initSign(privateKey);  // Initialize the signing process with the private key
        signature.update(message.getBytes());  // Provide the message data to sign
        return signature.sign();  // Generate the digital signature
    }

    // Verify the digital signature of the received message using the sender's public key
    public static boolean verifySignature(String message, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA"); // Use SHA-256 with RSA for verification
        signature.initVerify(publicKey);  // Initialize the verification with the sender's public key
        signature.update(message.getBytes());  // Provide the original message data for comparison
        return signature.verify(signatureBytes);  // Check if the signature matches the original message
    }
}
