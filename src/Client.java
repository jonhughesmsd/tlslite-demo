import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

public class Client {

    public static void main(String[] args) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        // Socket setup
        Socket cs = new Socket("localhost", 8080);

        ObjectOutputStream objOut = new ObjectOutputStream(cs.getOutputStream());
        ObjectInputStream objIn = new ObjectInputStream(cs.getInputStream());

        // Certificates
        // CA Certificate
        PublicKey CA_Public = functions.getCAPublicKey();
        // CA Signed Client Certificate
        X509Certificate clientCert = functions.getCert("src/CASignedClientCertificate.pem");

        // Random number
        SecureRandom clientRand = new SecureRandom();
        byte[] clientRandArr = new byte[32];
        clientRand.nextBytes(clientRandArr);

        // Diffie Hellman
        BigInteger c_DH_Private = new BigInteger(2048, new SecureRandom());
        byte[] c_DH_Public_Arr = functions.getPublicDHkey(c_DH_Private);

        //Signed DH Public Key
        byte[] c_signed_DH_Public_Arr = functions.getSignedPublicDH("src/clientPrivateKey.der", c_DH_Public_Arr);

        // Handshake
        // Client Hello -- send
        objOut.writeObject(clientRandArr);
        messages.add(clientRandArr);

        // Server Hello -- receive
        X509Certificate serverCert = (X509Certificate) objIn.readObject();
        byte[] s_DH_Public_Arr = (byte[]) objIn.readObject();
        byte[] s_signed_DH_Public_Arr = (byte[]) objIn.readObject();
        messages.add(serverCert.getEncoded());
        messages.add(s_DH_Public_Arr);
        messages.add(s_signed_DH_Public_Arr);

        //Verify Signed DH Public Key
        boolean verified = functions.verifySignedPublicDH(CA_Public, serverCert, s_DH_Public_Arr, s_signed_DH_Public_Arr);
        System.out.println("Verified Signature: " + verified);

        if (verified) {

            // Shared DH Key
            byte[] sharedDHArr = functions.generateSharedDH(c_DH_Private, s_DH_Public_Arr);

            // Client Key Exchange -- send
            objOut.writeObject(clientCert);
            objOut.writeObject(c_DH_Public_Arr);
            objOut.writeObject(c_signed_DH_Public_Arr);
            messages.add(clientCert.getEncoded());
            messages.add(c_DH_Public_Arr);
            messages.add(c_signed_DH_Public_Arr);

            //Make Symmetric Keys
            makeSymmetricKeys(clientRandArr, sharedDHArr);

            // Server Summary -- receive
            byte[] s_summary = (byte[]) objIn.readObject();
            byte[] s_summary_verify = functions.MACsummary(serverMAC, messages);

            boolean handshakeSuccess = false;
            if (Arrays.equals(s_summary, s_summary_verify)) {
                System.out.println("Server Summary: verified\n--Handshake: Complete--\n");
                handshakeSuccess = true;
            } else {
                System.out.println("Server Summary: failed");
            }

            if (handshakeSuccess) {

                // Client Summary -- send
                messages.add(s_summary);
                byte[] c_summary = functions.MACsummary(clientMAC, messages);
                objOut.writeObject(c_summary);

                // Message -- receive
                byte[] cipherText = (byte[]) objIn.readObject();
                String decryptedText = decrypt(cipherText);
                System.out.println("Decrypted message: " + decryptedText);

                // Message ACK -- send
                String message = "ACK";
                cipherText = encrypt(message);
                objOut.writeObject(cipherText);

                // Message -- receive
                cipherText = (byte[]) objIn.readObject();
                decryptedText = decrypt(cipherText);
                System.out.println("Decrypted message: " + decryptedText);

                // Message ACK -- send
                message = "ACK";
                cipherText = encrypt(message);
                objOut.writeObject(cipherText);


//                while (true) {
//                }

            }
        }

        cs.close();
    }

    private static void makeSymmetricKeys(byte[] clientRandArr, byte[] sharedDH_Arr) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] prk = functions.getHMAC(clientRandArr, sharedDH_Arr);
        serverEncrypt = functions.hkdfExpand(prk, "server encypt");
        clientEncrypt = functions.hkdfExpand(serverEncrypt, "client encypt");
        serverMAC = functions.hkdfExpand(clientEncrypt, "server MAC");
        clientMAC = functions.hkdfExpand(serverMAC, "client MAC");
        serverIV = functions.hkdfExpand(clientMAC, "server IV");
        clientIV = functions.hkdfExpand(serverIV, "client IV");
    }

    static byte[] encrypt(String message) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        return functions.encrypt(message, clientMAC, clientEncrypt, clientIV);

    }


    static String decrypt(byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return functions.decrypt(cipherText, serverMAC, serverEncrypt, serverIV);
    }

    static byte[] serverEncrypt;
    static byte[] clientEncrypt;
    static byte[] serverMAC;
    static byte[] clientMAC;
    static byte[] serverIV;
    static byte[] clientIV;
    static ArrayList<byte[]> messages = new ArrayList<>();

}
