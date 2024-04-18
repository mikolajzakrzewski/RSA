package edu.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

class RSATest {

    @Test
    void cypherDecipherTextTest() {
        RSA rsa = new RSA();
        BigInteger n = rsa.getN();
        BigInteger e = rsa.getE();
        BigInteger d = rsa.getD();
        String stringText = "test message";
        byte[] byteText = stringText.getBytes(StandardCharsets.UTF_8);
        BigInteger M = rsa.cypherText(byteText, e, n);
        BigInteger m = rsa.decipherText(M.toByteArray(), d, n);
        byte[] decipheredByteText = m.toByteArray();
        String decipheredText = new String(decipheredByteText, StandardCharsets.UTF_8);
        Assertions.assertEquals(stringText, decipheredText);
    }

//    @Test
//    void cypherDecipherFileTest() throws IOException {
//        RSA rsa = new RSA();
//        BigInteger n = rsa.getN();
//        BigInteger e = rsa.getE();
//        BigInteger d = rsa.getD();
//        byte[] byteText = Files.readAllBytes(Paths.get("testFiles/inputFile.pdf"));
//        byte[] M = rsa.cypherText(byteText, e, n).toByteArray();
//        BigInteger m = rsa.decipherText(M, d, n);
//        byte[] decipheredByteText = m.toByteArray();
//        Assertions.assertArrayEquals(byteText, decipheredByteText);
//        File outputFile = new File("testFiles/outputFile.pdf");
//        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
//            outputStream.write(decipheredByteText);
//        }
//    }
}