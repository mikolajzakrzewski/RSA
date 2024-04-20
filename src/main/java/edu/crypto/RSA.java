package edu.crypto;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

public class RSA {

    public static int N = 2048;
    private BigInteger n;
    private BigInteger e;
    private BigInteger d;

    public RSA() {
        this.generateKeys();
    }

    public void generateKeys() {
        BigInteger p = BigInteger.probablePrime(N / 2, new Random());
        BigInteger q = BigInteger.probablePrime(N / 2, new Random());
        while (p.compareTo(q) == 0) {
            q = BigInteger.probablePrime(N, new Random());
        }
        this.n = p.multiply(q);
        this.e = this.getExponent(p, q);
        this.d = this.getDecodingExponent(this.e, p, q);
    }

    public BigInteger getN() {
        return this.n;
    }

    public BigInteger getE() {
        return this.e;
    }

    public BigInteger getD() {
        return this.d;
    }

    private BigInteger getExponent(BigInteger p, BigInteger q) {
        BigInteger eulerFunction = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e;
        do {
            e = new BigInteger(N, new Random());
        } while (!e.gcd(eulerFunction).equals(BigInteger.ONE));
        return e;
    }

    private BigInteger getDecodingExponent(BigInteger e, BigInteger p, BigInteger q) {
        BigInteger eulerFunction = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        return e.modInverse(eulerFunction);
    }

    private BigInteger cipher(BigInteger m, BigInteger e, BigInteger n) {
        return m.modPow(e, n);
    }

    private BigInteger decipher(BigInteger c, BigInteger d, BigInteger n) {
        return c.modPow(d, n);
    }

    public byte[] addPadding(byte[] bytes) {
        int chunkSize = N / 8;
        if (bytes.length > chunkSize - 11) {
            throw new RuntimeException("Message too long. Given length: " + bytes.length + ", max length: " + (chunkSize - 11));
        }
        int paddingLength = chunkSize - bytes.length;
        byte[] padding = new byte[paddingLength];
        padding[0] = 0x01;
        padding[1] = 0x01;
        padding[paddingLength - 1] = 0x00;
        for (int i = 2; i < padding.length - 1; i++) {
            padding[i] = (byte) 0xff;
        }
        byte[] chunkWithPadding = new byte[chunkSize];
        System.arraycopy(padding, 0, chunkWithPadding, 0, padding.length);
        System.arraycopy(bytes, 0, chunkWithPadding, padding.length, bytes.length);
        return chunkWithPadding;
    }

    public byte[] removePadding(byte[] chunkWithPadding) {
        int chunkSize = N / 8;
        if (chunkWithPadding.length != chunkSize) {
            throw new RuntimeException("Incorrect message length. Given length: " + chunkWithPadding.length + ", expected length: " + chunkSize);
        }
        int paddingLength = 2;
        for (int i = 2; i < chunkWithPadding.length - 1; i++) {
            paddingLength++;
            if (chunkWithPadding[i] == 0x00) {
                break;
            }
        }
        byte[] chunkWithoutPadding = new byte[chunkWithPadding.length - paddingLength];
        System.arraycopy(chunkWithPadding, paddingLength, chunkWithoutPadding, 0, chunkWithPadding.length - paddingLength);
        return chunkWithoutPadding;
    }

    public ArrayList<BigInteger> cypherText(byte[] plainText, BigInteger e, BigInteger n) {
        ArrayList<BigInteger> cypherText = new ArrayList<>();
        int chunkSizeWithoutPadding = ((n.bitLength() - 1) / 8) - 11;
        for (int i = 0; i < plainText.length; i += chunkSizeWithoutPadding) {
            byte[] chunkWithoutPadding = new byte[chunkSizeWithoutPadding];
            if (i + chunkSizeWithoutPadding > plainText.length) {
                chunkWithoutPadding = new byte[plainText.length % chunkSizeWithoutPadding];
                System.arraycopy(plainText, i, chunkWithoutPadding, 0, plainText.length % chunkSizeWithoutPadding);
            }
            else {
                System.arraycopy(plainText, i, chunkWithoutPadding, 0, chunkSizeWithoutPadding);
            }
            byte[] chunkWithPadding = this.addPadding(chunkWithoutPadding);
            BigInteger m = new BigInteger(1, chunkWithPadding);
            BigInteger c = cipher(m, e, n);
            cypherText.add(c);
        }
        return cypherText;
    }

    public byte[] decipherText(ArrayList<BigInteger> cList, BigInteger d, BigInteger n) {
        ArrayList<byte[]> plainTextPaddedChunks = new ArrayList<>();
        for (BigInteger c : cList) {
            BigInteger m = decipher(c, d, n);
            plainTextPaddedChunks.add(m.toByteArray());
        }
        int plainTextLength = 0;
        ArrayList<byte[]> plainTextChunks = new ArrayList<>();
        for (byte[] chunkWithPadding : plainTextPaddedChunks) {
            byte[] chunkWithoutPadding = this.removePadding(chunkWithPadding);
            plainTextChunks.add(chunkWithoutPadding);
            plainTextLength += chunkWithoutPadding.length;
        }
        byte[] plainText = new byte[plainTextLength];
        int currentIndex = 0;
        for (byte[] chunkWithPadding : plainTextChunks) {
            System.arraycopy(chunkWithPadding, 0, plainText, currentIndex, chunkWithPadding.length);
            currentIndex += chunkWithPadding.length;
        }
        return plainText;
    }

}
