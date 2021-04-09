package com.comp3026.andrewarmstrong.crypto.symmetric;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricEncryptionTest {

    @org.junit.jupiter.api.Test
    void generateSymmetricAESKey() throws Exception{

        SecretKey key = SymmetricEncryption.generateSymmetricAESKey();

        System.out.println(DatatypeConverter.printHexBinary(key.getEncoded()));


    }

    @Test
    void myAESEncryption() throws Exception{
        String plainText = "The quick brown fox jumped over the lazy dog.";
        SecretKey key = SymmetricEncryption.generateSymmetricAESKey();
        System.out.println("Generating Secret Key..." + "\nKey Generated: "+ DatatypeConverter.printHexBinary(key.getEncoded()));
        TimeUnit.SECONDS.sleep(1);
        byte[] initVector = SymmetricEncryption.createInitVector();
        System.out.println("Generating initialization vector..." + "\nInit Vector Created: " + initVector.toString());
        TimeUnit.SECONDS.sleep(1);
        byte[] cipherText = SymmetricEncryption.myAESEncryption(plainText, key, initVector);
        System.out.println("Encrypting with AES...");
        TimeUnit.SECONDS.sleep(1);
        System.out.println("Encrypting with AES...");
        TimeUnit.SECONDS.sleep(1);
        System.out.println("Encrypting with AES...");
        TimeUnit.SECONDS.sleep(1);
        System.out.println("Encryption Finished!");
        System.out.println("=================================");
        System.out.println("Plain Text = " + plainText);
        System.out.println("Ciphertext (Encrypted) = " + DatatypeConverter.printHexBinary(cipherText));
        System.out.println("=================================");
        TimeUnit.SECONDS.sleep(1);
        String decryptedText = SymmetricEncryption.myAESDecryption(cipherText, key, initVector);
        System.out.println("Decrypting Text...");
        TimeUnit.SECONDS.sleep(1);
        System.out.println("Decrypting Text...");
        TimeUnit.SECONDS.sleep(1);
        System.out.println("Decrypting Text...");
        TimeUnit.SECONDS.sleep(1);
        System.out.println("Text Decrypted!");
        System.out.println("=================================");
        System.out.println("Decrypted Text = " + decryptedText);
        System.out.println("=================================");
    }
}