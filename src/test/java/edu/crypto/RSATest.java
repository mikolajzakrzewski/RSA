package edu.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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
        String stringText = "testmessage23rewsdfgtestmessage23rewsdfgtestmeage23rewsdfge23rewsdfgtestmessage23rewsdfgtestmessage23rewsdfgmtestmessage23rewsdfgtestmessage23rewsdfgtestmessage23rewsdfgessage23rewsdfgtestmessage23rewsdfgtestmessage23rewsdfgtestmessage23rewsdfg";
        byte[] byteText = stringText.getBytes(StandardCharsets.UTF_8);
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
        Converter converter = new Converter();
        ArrayList<BigInteger> cypheredText = rsa.cypherText(byteText, e, n);
        String cypheredTextHexString = converter.bigIntegerArrayListToHexString(cypheredText);
        File file = new File("testFiles/cipheredTextFile.txt");
        try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file))) {
            bufferedWriter.write(cypheredTextHexString);
        }
        StringBuilder fileContentBuilder = new StringBuilder();
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                fileContentBuilder.append(line);
            }
        }
        String cipheredMessageHex = fileContentBuilder.toString();
        ArrayList<BigInteger> byteTextFromHexString = converter.hexStringToBigIntegerArrayList(cipheredMessageHex);
        byte[] cypheredDecipheredText = rsa.decipherText(byteTextFromHexString, d, n);
        File outputFile = new File("testFiles/outputFile.pdf");
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(cypheredDecipheredText);
        }
        Assertions.assertEquals(new String(byteText, StandardCharsets.US_ASCII), new String(cypheredDecipheredText, StandardCharsets.US_ASCII));
    }

}