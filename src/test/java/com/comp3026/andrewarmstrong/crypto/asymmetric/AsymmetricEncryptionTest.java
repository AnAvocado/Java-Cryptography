package com.comp3026.andrewarmstrong.crypto.asymmetric;

import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class AsymmetricEncryptionTest {

    @Test
    void generateRSAKeyPair() {
    }

    @Test
    void myRSAEncryption() throws Exception{
        String plainText = "The roof is on fire";
        KeyPair keyPair = AsymmetricEncryption.generateRSAKeyPair();
        System.out.println("Generating RSA Key Pair...");
        TimeUnit.SECONDS.sleep(1);
        PublicKey publicKey = keyPair.getPublic();
        System.out.println("Getting Public Key...");
        TimeUnit.SECONDS.sleep(1);
        System.out.println("Public Key = " + DatatypeConverter.printHexBinary(publicKey.getEncoded()));
        byte[] cipherText = AsymmetricEncryption.MyRSAEncryption(plainText, publicKey);
        System.out.println("Encrypting with RSA...");
        TimeUnit.SECONDS.sleep(1);
        System.out.println("Encryption Finished!");
        System.out.println("Plaintext = " + plainText);
        System.out.println("Ciphertext (RSA) = " + DatatypeConverter.printHexBinary(cipherText));
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println("Starting Decryption...");
        System.out.println("Getting Private Key...");
        System.out.println("Private Key = " + DatatypeConverter.printHexBinary(privateKey.getEncoded()));
        String decryptedText = AsymmetricEncryption.MyRSADecryption(cipherText, privateKey);
        System.out.println("Decrypting...");
        TimeUnit.SECONDS.sleep(1);
        System.out.println("Decryption Finished!");
        System.out.println("Decrypted Text = " + decryptedText);


    }

    @Test
    void myRSADecryption() {
    }
}