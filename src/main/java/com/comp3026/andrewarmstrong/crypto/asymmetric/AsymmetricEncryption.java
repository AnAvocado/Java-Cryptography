package com.comp3026.andrewarmstrong.crypto.asymmetric;

import javax.crypto.Cipher;
import java.security.*;

public class AsymmetricEncryption {
    public static KeyPair generateRSAKeyPair() throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }
    public static byte[] MyRSAEncryption(String plainText, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText.getBytes());
    }
    public static String MyRSADecryption(byte[] cipherText, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainTextBytes = cipher.doFinal(cipherText);
        return new String(plainTextBytes);
    }
}
