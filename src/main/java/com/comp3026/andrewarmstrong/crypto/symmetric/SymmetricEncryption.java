package com.comp3026.andrewarmstrong.crypto.symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class SymmetricEncryption {

    //CREATE SYMMETRIC AES KEY
    public static SecretKey generateSymmetricAESKey () throws Exception {

        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256, secureRandom);
        return keyGenerator.generateKey();
    }

    //CREATE AN INITIALIZATION VECTOR FOR THE CBC METHOD
    public static byte[] createInitVector(){

        final byte blockSizeofAES = 16; //define the size of the block (128 bits)
        byte[] initVector = new byte[blockSizeofAES];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initVector);
        return initVector;
    }

    //ENCRYPT PLAINTEXT WITH THE AES CIPHER
    public static byte[] myAESEncryption(String plaintext, SecretKey secretKey, byte[] initVector) throws Exception{

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plaintext.getBytes());
    }

    public static String myAESDecryption(byte[] cipherText, SecretKey secretKey, byte[] initVector) throws Exception{

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] plainTextBytes = cipher.doFinal(cipherText);
        return new String(plainTextBytes);
    }



}
