package edu.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;

class RSATest {

    @Test
    public void paddingTest() {
        RSA rsa = new RSA();
        byte[] chunkWithoutPadding = new byte[RSA.N / 8 - 22];
        Arrays.fill(chunkWithoutPadding, (byte) 4);
        chunkWithoutPadding[chunkWithoutPadding.length - 1] = 5;
        byte[] chunkWithPadding = rsa.addPadding(chunkWithoutPadding);
        byte[] chunkWithRemovedPadding = rsa.removePadding(chunkWithPadding);
        Assertions.assertArrayEquals(chunkWithoutPadding, chunkWithRemovedPadding);
    }

    @Test
    void cypherDecipherTextTest() {
        RSA rsa = new RSA();
        BigInteger n = rsa.getN();
        BigInteger e = rsa.getE();
        BigInteger d = rsa.getD();
        String stringText = "test message";
        byte[] byteText = stringText.getBytes();
        ArrayList<BigInteger> M = rsa.cypherText(byteText, e, n);
        byte[] m = rsa.decipherText(M, d, n);
        Assertions.assertArrayEquals(byteText, m);
    }

    @Test
    void cypherDecipherFileTest() throws IOException {
        RSA rsa = new RSA();
        BigInteger n = rsa.getN();
        BigInteger e = rsa.getE();
        BigInteger d = rsa.getD();
        byte[] byteText = Files.readAllBytes(Paths.get("testFiles/inputFile.pdf"));
        ArrayList<BigInteger> cypheredText = rsa.cypherText(byteText, e, n);
        byte[] cypheredDecipheredText = rsa.decipherText(cypheredText, d, n);
        File outputFile = new File("testFiles/outputFile.pdf");
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(cypheredDecipheredText);
        }
        Assertions.assertArrayEquals(byteText, cypheredDecipheredText);
    }

}