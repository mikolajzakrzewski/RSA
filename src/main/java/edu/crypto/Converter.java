package edu.crypto;

import java.util.ArrayList;
import java.math.BigInteger;

public class Converter {

    public byte[] bigIntegerArrayListToByteArray(ArrayList<BigInteger> bigIntegerArrayList) {
        int bytesNumber = 0;
        ArrayList<byte[]> byteArrayArrayList = new ArrayList<>();
        for (BigInteger i : bigIntegerArrayList) {
            byte[] bigIntegerByteArray = i.toByteArray();
            byteArrayArrayList.add(bigIntegerByteArray);
            bytesNumber += bigIntegerByteArray.length;
        }
        byte[] byteArray = new byte[bytesNumber];
        int currentIndex = 0;
        for (byte[] chunk : byteArrayArrayList) {
            System.arraycopy(chunk, 0, byteArray, currentIndex, chunk.length);
            currentIndex += chunk.length;
        }
        return byteArray;
    }

    public ArrayList<BigInteger> byteArrayToBigIntegerArrayList(byte[] byteArray) {
        ArrayList<BigInteger> bigIntegerArrayList = new ArrayList<>();
        for (int i = 0; i < byteArray.length; i += RSA.N / 8) {
            byte[] chunk = new byte[RSA.N / 8];
            System.arraycopy(byteArray, i, chunk, 0, chunk.length);
            bigIntegerArrayList.add(new BigInteger(chunk));
        }
        return bigIntegerArrayList;
    }

    public byte[] hexStringToByteArray(String hexString) {
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hexString.substring(i, i + 2), 16);
        }
        return bytes;
    }

    public String byteArrayToHexString(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder(bytes.length * 2);
        for(byte b: bytes)
            stringBuilder.append(String.format("%02x", b));
        return stringBuilder.toString();
    }

}
