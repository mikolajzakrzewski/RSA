package edu.crypto;

import java.util.ArrayList;
import java.math.BigInteger;

public class Converter {

    public String bigIntegerArrayListToHexString(ArrayList<BigInteger> bigIntegerArrayList) {
        StringBuilder hexStringBuilder = new StringBuilder();
        for (BigInteger i : bigIntegerArrayList) {
            hexStringBuilder.append(i.toString(16));
            hexStringBuilder.append("  ");
        }
        return String.valueOf(hexStringBuilder);
    }

    public ArrayList<BigInteger> hexStringToBigIntegerArrayList(String hexString) {
        ArrayList<BigInteger> bigIntegerArrayList = new ArrayList<>();
        int hexStringLength = hexString.length();
        int currentIndex = 0;
        while (currentIndex < hexStringLength) {
            int endIndex = hexString.indexOf("  ", currentIndex);
            String hex = hexString.substring(currentIndex, endIndex);
            if (!hex.isEmpty()) {
                bigIntegerArrayList.add(new BigInteger(hex, 16));
            }
            currentIndex = endIndex + 2;
        }
        return bigIntegerArrayList;
    }

}
