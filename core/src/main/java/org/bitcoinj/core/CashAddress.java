/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.core;

import org.bitcoinj.params.BCCMainNetParams;
import org.bitcoinj.params.BCCTestNet3Params;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class CashAddress {
    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final HashMap<String, Integer> CHARSET_INVERSE_INDEX = new HashMap<>();

    static {
        CHARSET_INVERSE_INDEX.put("q", 0);
        CHARSET_INVERSE_INDEX.put("p", 1);
        CHARSET_INVERSE_INDEX.put("z", 2);
        CHARSET_INVERSE_INDEX.put("r", 3);
        CHARSET_INVERSE_INDEX.put("y", 4);
        CHARSET_INVERSE_INDEX.put("9", 5);
        CHARSET_INVERSE_INDEX.put("x", 6);
        CHARSET_INVERSE_INDEX.put("8", 7);
        CHARSET_INVERSE_INDEX.put("g", 8);
        CHARSET_INVERSE_INDEX.put("f", 9);
        CHARSET_INVERSE_INDEX.put("2", 10);
        CHARSET_INVERSE_INDEX.put("t", 11);
        CHARSET_INVERSE_INDEX.put("v", 12);
        CHARSET_INVERSE_INDEX.put("d", 13);
        CHARSET_INVERSE_INDEX.put("w", 14);
        CHARSET_INVERSE_INDEX.put("0", 15);
        CHARSET_INVERSE_INDEX.put("s", 16);
        CHARSET_INVERSE_INDEX.put("3", 17);
        CHARSET_INVERSE_INDEX.put("j", 18);
        CHARSET_INVERSE_INDEX.put("n", 19);
        CHARSET_INVERSE_INDEX.put("5", 20);
        CHARSET_INVERSE_INDEX.put("4", 21);
        CHARSET_INVERSE_INDEX.put("k", 22);
        CHARSET_INVERSE_INDEX.put("h", 23);
        CHARSET_INVERSE_INDEX.put("c", 24);
        CHARSET_INVERSE_INDEX.put("e", 25);
        CHARSET_INVERSE_INDEX.put("6", 26);
        CHARSET_INVERSE_INDEX.put("m", 27);
        CHARSET_INVERSE_INDEX.put("u", 28);
        CHARSET_INVERSE_INDEX.put("a", 29);
        CHARSET_INVERSE_INDEX.put("7", 30);
        CHARSET_INVERSE_INDEX.put("l", 31);

    }

    private NetworkParameters mNetworkParameters;
    private int[] mPayload;
    private int mVersion = 0;


    public CashAddress(Address address) {
        mNetworkParameters = address.getParameters();
        byte[] hash160 = address.getHash160();
        mPayload = new int[hash160.length];
        for (int i = 0; i < hash160.length; i++) {
            mPayload[i] = hash160[i] & 0xFF;
        }
        if (address.isP2SHAddress()) mVersion = 1;
    }

    private int[] checksumToArray(BigInteger checksum) {
        int[] result = new int[8];
        for (int i = 0; i < 8; i++) {
            result[i] = checksum.and(BigInteger.valueOf(31)).intValue();
            checksum = checksum.shiftRight(5);
        }
        reverse(result);
        return result;
    }

    /***
     * Derives an array from the given prefix to be used in the computation
     * of the address' checksum.
     *
     */
    private static int[] prefixToArray(String prefix) {
        int[] result = new int[prefix.length()+1];

        for (int i = 0; i < prefix.length(); i++) {
            result[i] = prefix.charAt(i) & 31;
        }

        result[result.length-1] = 0;

        return result;
    }

    private byte getVersionByte() {
        return (byte) (mVersion << 3);
    }

    /**
     * Converts an array of integers made up of `from` bits into an
     * array of integers made up of `to` bits. The output array is
     * zero-padded if necessary, unless strict mode is true.
     * Original by Pieter Wuille: https://github.com/sipa/bech32.
     *
     * @param {Array} data Array of integers made up of `from` bits.
     * @param {number} from Length in bits of elements in the input array.
     * @param {number} to Length in bits of elements in the output array.
     * @param {bool} strict Require the conversion to be completed without padding.
     */
    private static int[] convertBits(int[] data, int from, int to, boolean strict) throws AddressFormatException {
        int accumulator = 0;
        int bits = 0;
        ArrayList<Integer> result = new ArrayList<>();
        int mask = (1 << to) - 1;

        for (int value : data) {
            if (value < 0 || (value >> from) != 0) {
                throw new AddressFormatException("Invalid value: "+value);
            }

            accumulator = (accumulator << from) | value;
            bits += from;

            while(bits >= to) {
                bits -= to;
                result.add((accumulator >> bits) & mask);
            }
        }

        if (!strict) {
            if (bits > 0) {
                result.add((accumulator << (to - bits)) & mask);
            }
        } else if (bits >= from || ((accumulator << (to - bits)) & mask) != 0) {
            throw new AddressFormatException("Conversion requires padding but strict mode was used.");
        }

        int[] realResult = new int[result.size()];
        for (int i = 0; i < realResult.length; i++) {
            realResult[i] = result.get(i);
        }
        return realResult;
    }

    private static BigInteger polymod(int[] data) {
        BigInteger[] GENERATOR = new BigInteger[] {
                new BigInteger("98f2bc8e61", 16),
                new BigInteger("79b76d99e2", 16),
                new BigInteger("f33e5fb3c4", 16),
                new BigInteger("ae2eabe2a8", 16),
                new BigInteger("1e4f43e470", 16)};
        BigInteger checksum = BigInteger.ONE;
        for (int value : data) {
            BigInteger topBits = checksum.shiftRight(35);
            checksum = checksum.and(new BigInteger("07ffffffff", 16)).shiftLeft(5).xor(BigInteger.valueOf(value));
            for (int i = 0; i < GENERATOR.length; ++i) {
                if (topBits.shiftRight(i).and(BigInteger.ONE).equals(BigInteger.ONE)) {
                    checksum = checksum.xor(GENERATOR[i]);
                }
            }
        }
        return checksum.xor(BigInteger.ONE);
    }

    private static String encodeBase32(int[] data) throws AddressFormatException {
        StringBuilder base32 = new StringBuilder();
        for (int value : data) {
            if (0 <= value && value < 32) {
                base32.append(CHARSET.charAt(value));
            } else {
                throw new AddressFormatException("Invalid value: "+value);
            }
        }
        return base32.toString();
    }

    private static int[] decodeBase32(String base32) throws AddressFormatException {
        int[] data = new int[base32.length()];
        for (int i = 0; i < base32.length(); i++) {
            String value = base32.substring(i, i+1);
            if (!CHARSET_INVERSE_INDEX.containsKey(value)) {
                throw new AddressFormatException("Invalid value: "+value);
            }
            data[i] = CHARSET_INVERSE_INDEX.get(value);
        }
        return data;
    }

    private static <T> T concatenate(T a, T b) {
        if (!a.getClass().isArray() || !b.getClass().isArray()) {
            throw new IllegalArgumentException();
        }

        Class<?> resCompType;
        Class<?> aCompType = a.getClass().getComponentType();
        Class<?> bCompType = b.getClass().getComponentType();

        if (aCompType.isAssignableFrom(bCompType)) {
            resCompType = aCompType;
        } else if (bCompType.isAssignableFrom(aCompType)) {
            resCompType = bCompType;
        } else {
            throw new IllegalArgumentException();
        }

        int aLen = Array.getLength(a);
        int bLen = Array.getLength(b);

        @SuppressWarnings("unchecked")
        T result = (T) Array.newInstance(resCompType, aLen + bLen);
        System.arraycopy(a, 0, result, 0, aLen);
        System.arraycopy(b, 0, result, aLen, bLen);

        return result;
    }

    private static void reverse(int[] data) {
        for (int left = 0, right = data.length - 1; left < right; left++, right--) {
            // swap the values at the left and right indices
            int temp = data[left];
            data[left]  = data[right];
            data[right] = temp;
        }
    }

    private static boolean hasSingleCase(String string) {
        boolean hasLowerCase = false;
        boolean hasUpperCase = false;
        for (int i = 0; i < string.length(); i++) {
            String letter = string.substring(i,i+1);
            hasLowerCase = hasLowerCase || !letter.equals(letter.toUpperCase());
            hasUpperCase = hasUpperCase || !letter.equals(letter.toLowerCase());
            if (hasLowerCase && hasUpperCase) {
                return false;
            }
        }
        return true;
    }

    private static boolean validChecksum(String prefix, int[] payload) {
        int[] prefixData = prefixToArray(prefix);
        int[] data = concatenate(prefixData, payload);
        System.out.println("data = " + Arrays.toString(data));
        BigInteger polymod = polymod(data);
        System.out.println("polymod = " + polymod);
        return polymod.compareTo(BigInteger.ZERO) == 0;
    }

    private static int getHashSize(int versionByte) {
        switch (versionByte & 7) {
            case 0:
                return 160;
            case 1:
                return 192;
            case 2:
                return 224;
            case 3:
                return 256;
            case 4:
                return 320;
            case 5:
                return 384;
            case 6:
                return 448;
            case 7:
                return 512;
            default:
                return 0;
        }
    }

    private static String getType(int versionByte) throws AddressFormatException {
        switch (versionByte & 120) {
            case 0:
                return "P2PKH";
            case 8:
                return "P2SH";
            default:
                throw new AddressFormatException("Invalid address type in version byte: "+versionByte);
        }
    }

    public String encode() throws AddressFormatException {
        String prefix = mNetworkParameters.getUriScheme();
        int[]  prefixData = prefixToArray(prefix);
        int[] versionByte = new int[] {getVersionByte()};
        int[] data = concatenate(versionByte, mPayload);
        int[] payloadData = convertBits(data, 8, 5, false);
        int[] prefAndPayloadData = concatenate(prefixData, payloadData);
        int[] checksumData = concatenate(prefAndPayloadData, new int[]{0,0,0,0,0,0,0,0});
        BigInteger polymodResult = polymod(checksumData);
        int[] polymodArray = checksumToArray(polymodResult);
        int[] payload = concatenate(payloadData, polymodArray);
        System.out.println("payload = " + Arrays.toString(payload));
        String encodedPayload = encodeBase32(payload);
        return prefix+":"+encodedPayload;
    }

    public static Address decode(String bchAddress) throws AddressFormatException {
        String[] pieces = bchAddress.split(":");
        if (pieces.length != 2) {
            throw new AddressFormatException("Missing prefix: "+bchAddress);
        }
        String prefix = pieces[0];
        NetworkParameters networkParameters;
        switch (prefix) {
            case BCCMainNetParams.BITCOIN_CASH_SCHEME:
                networkParameters = BCCMainNetParams.get();
                break;
            case BCCTestNet3Params.BITCOIN_CASH_TESTNET_SCHEME:
                networkParameters = BCCTestNet3Params.get();
                break;
            default:
                throw new AddressFormatException("Invalid prefix: " + prefix);
        }

        String encodedPayload = pieces[1];

        if (!hasSingleCase(encodedPayload)) {
            throw new AddressFormatException("Mixed case in address payload: "+encodedPayload);
        }

        int[] payload = decodeBase32(encodedPayload.toLowerCase());

        if (!validChecksum(prefix, payload)) {
            throw new AddressFormatException("Invalid checksum: "+bchAddress);
        }

        int[] data = Arrays.copyOfRange(payload, 0, payload.length - 8);
        int[] result = convertBits(data, 5, 8, true);
        int versionByte = result[0];
        System.out.println("versionByte = " + versionByte);
        int[] hash = Arrays.copyOfRange(result, 1, result.length);

        System.out.println("hash = " + Arrays.toString(hash));

        if (getHashSize(versionByte) != hash.length * 8) {
            throw new AddressFormatException("Invalid hash size: "+bchAddress);
        }

        byte[] hashByteArray = new byte[hash.length];
        for (int i = 0; i < hash.length; i++) {
            hashByteArray[i] = (byte) hash[i];
        }

        if (versionByte == 1)
            return new Address(networkParameters, networkParameters.p2shHeader, hashByteArray);
        else
            return new Address(networkParameters, networkParameters.addressHeader, hashByteArray);

    }

    public static void main(String[] args) {
        try {
            Address address1 = Address.fromBase58(BCCMainNetParams.get(), "1F18bHRRkTFKrbjDbjY7EwaXesGLQ261n5");
            System.out.println("address1.toCashAddress() = " + address1.toCashAddress());

            Address address2 = CashAddress.decode("bitcoincash:qzvesxgz06gwpg2qg4zhqj2vu2yh9v8dcue88wnxm7");
            System.out.println(address2.toBase58());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
