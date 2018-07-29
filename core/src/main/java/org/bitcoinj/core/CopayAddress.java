package org.bitcoinj.core;

import org.bitcoinj.params.BCCMainNetParams;

public class CopayAddress {
    private Address mAddress;

    public CopayAddress(Address address) {
        mAddress = address;
    }

    public String encode() {
        if (mAddress.getParameters().getId().equals(NetworkParameters.ID_TESTNET)) {
            return mAddress.toBase58();
        } else {
            int version;
            if (mAddress.isP2SHAddress()) {
                version = BCCMainNetParams.COPAY_P2SH_HEADER;
            } else if (mAddress.getVersion() == 0) {
                version = BCCMainNetParams.COPAY_ADDRESS_HEADER;
            } else {
                throw new AddressFormatException("Wrong version");
            }

            return Base58.encodeChecked(version, mAddress.getHash());
        }
    }

    /*public static Address decode(NetworkParameters networkParameters, String address) {
        Address addr = Address.fromString(networkParameters, address);
        if (networkParameters.getId().equals(NetworkParameters.ID_TESTNET)) {
            return addr;
        } else {
            int version;
            if (addr.getVersion() == BCCMainNetParams.COPAY_ADDRESS_HEADER) {
                version = networkParameters.addressHeader;
            } else if (addr.getVersion() == BCCMainNetParams.COPAY_P2SH_HEADER) {
                version = networkParameters.p2shHeader;
            } else {
                throw new AddressFormatException("Wrong version");
            }

            if (version == params.getAddressHeader())
                return new LegacyAddress(params, false, bytes);
            else if (version == params.getP2SHHeader())
                return new LegacyAddress(params, true, bytes);
            throw new AddressFormatException.WrongNetwork(version);

            byte[] bytes = Base58.decodeChecked(address);
            return new LegacyAddress(networkParameters, bytes);
            //return new Address(networkParameters, version, addr.getHash());
        }
    }*/
}
