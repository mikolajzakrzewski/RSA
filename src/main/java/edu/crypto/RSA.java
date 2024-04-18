package edu.crypto;

import java.math.BigInteger;
import java.util.Random;

public class RSA {

    private final int keyBitLength = 1024;
    private BigInteger n;
    private BigInteger e;
    private BigInteger d;

    public RSA() {
        this.generateKeys();
    }

    public void generateKeys() {
        BigInteger p = BigInteger.probablePrime(keyBitLength, new Random());
        BigInteger q = BigInteger.probablePrime(keyBitLength, new Random());
        this.n = p.multiply(q);
        this.e = this.getExponent(p, q);
        this.d = this.getDecodingExponent(e, p, q);
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
            e = new BigInteger(keyBitLength, new Random()).mod(eulerFunction);
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

    public BigInteger cypherText(byte[] text, BigInteger e, BigInteger n) {
        BigInteger m = new BigInteger(text);
        return cipher(m, e, n);
    }

    public BigInteger decipherText(byte[] cypherText, BigInteger d, BigInteger n) {
        BigInteger c = new BigInteger(cypherText);
        return decipher(c, d, n);
    }

}
