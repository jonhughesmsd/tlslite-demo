import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

public class Server {

    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException, ClassNotFoundException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        //Server Setup
        ServerSocket ss = new ServerSocket(8080);
        Socket socket = ss.accept();
        ObjectOutputStream objOut = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream objIn = new ObjectInputStream(socket.getInputStream());

        while(true) {

            // CA Certificate
            PublicKey CA_Public = functions.getCAPublicKey();

            //CA Signed Server Certificate
            X509Certificate serverCert = functions.getCert("src/CASignedServerCertificate.pem");

            // Diffie Hellman
            BigInteger s_DH_Private = new BigInteger(2048, new SecureRandom());
            byte[] s_DH_Public_Arr = functions.getPublicDHkey(s_DH_Private);

            //Signed DH Public Key
            byte[] s_signed_DH_Public_Arr = functions.getSignedPublicDH("src/serverPrivateKey.der", s_DH_Public_Arr);

            //Handshake
            //Client Hello -- receive
            byte[] clientRandArr = (byte[])objIn.readObject();
            messages.add(clientRandArr);

            //Server Hello -- send
            objOut.writeObject(serverCert);
            objOut.writeObject(s_DH_Public_Arr);
            objOut.writeObject(s_signed_DH_Public_Arr);
            messages.add(serverCert.getEncoded());
            messages.add(s_DH_Public_Arr);
            messages.add(s_signed_DH_Public_Arr);

            //Client Key Exchange -- recieve
            X509Certificate clientCert = (X509Certificate) objIn.readObject();
            byte[] c_DH_Public_Arr = (byte[]) objIn.readObject();
            byte[] c_signed_DH_Public_Arr = (byte[]) objIn.readObject();
            messages.add(clientCert.getEncoded());
            messages.add(c_DH_Public_Arr);
            messages.add(c_signed_DH_Public_Arr);

            //Verify Signed DH Public Key
            boolean verified = functions.verifySignedPublicDH(CA_Public, clientCert, c_DH_Public_Arr, c_signed_DH_Public_Arr);
            System.out.println("Signature Verified: " + verified);

            if (verified) {

                //Shared DH Key
                byte[] sharedDH_Arr = functions.generateSharedDH(s_DH_Private, c_DH_Public_Arr);

                //Make Symmetric Keys
                makeSymmetricKeys(clientRandArr, sharedDH_Arr);

                //Server Summary -- send
                byte[] s_summary = functions.MACsummary(serverMAC, messages);
                objOut.writeObject(s_summary);
                messages.add(s_summary);

                //Client Summary -- receive
                byte[] c_summary = (byte[]) objIn.readObject();
                byte[] c_summary_verify = functions.MACsummary(clientMAC, messages);

                boolean handshakeSuccess = false;
                if (Arrays.equals(c_summary, c_summary_verify)) {
                    System.out.println("Client Summary: verified\n--Handshake: Complete--\n");
                    handshakeSuccess = true;
                } else {
                    System.out.println("Client Summary: failed");
                }

                if (handshakeSuccess) {
                    // Message -- send
                    String message = "Hello! This is the first message from the server to the client";
                    byte[] cipherText = encrypt(message);
                    objOut.writeObject(cipherText);

                    // Message -- receive
                    cipherText = (byte[]) objIn.readObject();
                    String decryptedText = decrypt(cipherText);
                    if (decryptedText.equals("ACK")) {
                        System.out.println("ACK received");
                    }

                    // Message -- send
                    message = "Second message sent from server";
                    cipherText = encrypt(message);
                    objOut.writeObject(cipherText);

                    // Message -- receive
                    cipherText = (byte[]) objIn.readObject();
                    decryptedText = decrypt(cipherText);
                    if (decryptedText.equals("ACK")) {
                        System.out.println("ACK received");
                    }
                }
            }

            break;

        }

        ss.close();
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

    private static byte[] encrypt(String message) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        return functions.encrypt(message, serverMAC, serverEncrypt, serverIV);
    }

    private static String decrypt(byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return functions.decrypt(cipherText, clientMAC, clientEncrypt, clientIV);
    }

    static byte[] serverEncrypt;
    static byte[] clientEncrypt;
    static byte[] serverMAC;
    static byte[] clientMAC;
    static byte[] serverIV;
    static byte[] clientIV;
    static ArrayList<byte[]> messages = new ArrayList<>();

}
