import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

public class functions {

    public static BigInteger getN() throws IOException {
        File file = new File("src/N.txt");

        BufferedReader br = new BufferedReader(new FileReader(file));

        String num = "";
        String line;
        while ((line = br.readLine()) != null){
            num += line;
        }

        num = num.replaceAll("\\s", "");
        return new BigInteger(num, 16);
    }

    public static PublicKey getCAPublicKey() throws CertificateException, FileNotFoundException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fileIn = new FileInputStream("src/CACertificate.pem");
        X509Certificate CAcert = (X509Certificate) certificateFactory.generateCertificate(fileIn);
        return CAcert.getPublicKey();
    }

    public static X509Certificate getCert(String path) throws CertificateException, FileNotFoundException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fileIn = new FileInputStream(path);
        return (X509Certificate) certificateFactory.generateCertificate(fileIn);
    }

    public static byte[] getPublicDHkey(BigInteger dhPrivate) throws IOException {
        String g = "2";
        BigInteger N = getN();

        BigInteger bigInt2 = new BigInteger(g);
        BigInteger s_DH_Public = bigInt2.modPow(dhPrivate, N);
        return s_DH_Public.toByteArray();
    }

    public static byte[] getSignedPublicDH(String keyPathStr, byte[] dhPublic) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Path keyPath = Paths.get(keyPathStr);
        byte[] s_RSA_Private_Arr = Files.readAllBytes(keyPath);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(s_RSA_Private_Arr);
        PrivateKey s_RSA_Private = keyFactory.generatePrivate(privateKeySpec);

        Signature s_signed_DH_Public = Signature.getInstance("SHA256withRSA");
        s_signed_DH_Public.initSign(s_RSA_Private);
        s_signed_DH_Public.update(dhPublic);

        return s_signed_DH_Public.sign();
    }

    public static boolean verifySignedPublicDH(PublicKey CA_Public, X509Certificate cert, byte[] dhPublic, byte[] signedDHPublic) throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        // Verify Certificate with Certificate Authority
        cert.verify(CA_Public);

        // Verify Signed DH Public Key
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(cert.getPublicKey());
        signature.update(dhPublic);
        return signature.verify(signedDHPublic);
    }

    public static byte[] generateSharedDH(BigInteger dhPrivate, byte[] dhPublic) throws IOException {
        BigInteger dhPublicInt = new BigInteger(dhPublic);
        BigInteger sharedDH = dhPublicInt.modPow(dhPrivate, getN());
        return sharedDH.toByteArray();
    }

    public static byte[] getHMAC(byte[] keySpec, byte[] input) throws InvalidKeyException, NoSuchAlgorithmException {
        Mac HmacSHA256 = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(keySpec, "HmacSHA256");
        HmacSHA256.init(secretKeySpec);
        HmacSHA256.update(input);
        return HmacSHA256.doFinal();
    }

    public static byte[] hkdfExpand(byte[] input, String tag) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] tagArr = tag.getBytes(StandardCharsets.UTF_8);

        Mac HmacSHA256 = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(input, "HmacSHA256");
        HmacSHA256.init(secretKeySpec);
        HmacSHA256.update(tagArr);
        HmacSHA256.update((byte) 0x1);
        byte[] okm = HmacSHA256.doFinal();

        return Arrays.copyOf(okm, 16);
    }

    public static byte[] MACsummary(byte[] key, ArrayList<byte[]> messages) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
        hmac.init(secretKeySpec);

        for (byte[] arr : messages){
            hmac.update(arr);
        }

        return hmac.doFinal();
    }

    public static byte[] encrypt(String message, byte[] mac, byte[] encrypt, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        //Message MAC
        byte[] messageArr = message.getBytes(StandardCharsets.UTF_8);
        byte[] messageMAC = getHMAC(messageArr, mac);

        //Cipher Setup
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(encrypt, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        //Concatenate Message and MAC
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(messageArr);
        os.write(messageMAC);
        byte[] packet = os.toByteArray();

        //Generate Ciphertext and return
        return cipher.doFinal(packet);
    }

    public static String decrypt(byte[] cipherText, byte[] mac, byte[] encrypt, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //Decipher Setup
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(encrypt, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        //Decrypt Packet
        byte[] decryptedText = cipher.doFinal(cipherText);

        //Separate Message and MAC
        byte[] message = Arrays.copyOf(decryptedText, decryptedText.length - 32);
        byte[] hmac = Arrays.copyOfRange(decryptedText, decryptedText.length - 32, decryptedText.length);

        //Generate MAC from Message and Compare
        byte[] hmac_verify = getHMAC(message, mac);
        if (Arrays.equals(hmac, hmac_verify)){
            return new String(message);
        }
        else {
            return "MESSAGE FAIL -- MAC mismatch";
        }

    }

}
