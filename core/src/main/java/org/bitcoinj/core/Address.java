/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Giannis Dzegoutanis
 * Copyright 2015 Andreas Schildbach
 * Copyright 2018 the bitcoinj-cash developers
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This file has been modified by the bitcoinj-cash developers for the bitcoinj-cash project.
 * The original file was from the bitcoinj project (https://github.com/bitcoinj/bitcoinj).
 */

package org.bitcoinj.core;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bitcoinj.script.Script.ScriptType;

/**
 * <p>
 * Base class for addresses, e.g. native segwit addresses ({@link SegwitAddress}) or legacy addresses ({@link LegacyAddress}).
 * </p>
 * 
 * <p>
 * Use {@link #fromString(NetworkParameters, String)} to conveniently construct any kind of address from its textual
 * form.
 * </p>
 */
public abstract class Address extends PrefixedChecksummedBytes {
    public Address(NetworkParameters params, byte[] bytes) {
        super(params, bytes);
    }

    /**
     * Construct an address from its textual form.
     * 
     * @param params
     *            the expected network this address is valid for, or null if the network should be derived from the
     *            textual form
     * @param str
     *            the textual form of the address, such as "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL" or
     *            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
     * @return constructed address
     * @throws AddressFormatException
     *             if the given string doesn't parse or the checksum is invalid
     * @throws AddressFormatException.WrongNetwork
     *             if the given string is valid but not for the expected network (eg testnet vs mainnet)
     */
    /** @deprecated Use {@link #fromBase58(NetworkParameters, String)} */
    @Deprecated
    /*public Address(@Nullable NetworkParameters params, String address) throws AddressFormatException {
        super(address);
        if (params != null) {
            if (!isAcceptableVersion(params, version)) {
                throw new WrongNetworkException(version, params.getAcceptableAddressCodes());
            }
            this.params = params;
        } else {
            NetworkParameters paramsFound = null;
            for (NetworkParameters p : Networks.get()) {
                if (isAcceptableVersion(p, version)) {
                    paramsFound = p;
                    break;
                }
            }
            if (paramsFound == null)
                throw new AddressFormatException("No network found for " + address);

            this.params = paramsFound;
        }
    */

    public String toCashAddress() {
        try {
            return new CashAddress(this).encode();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String toCopayAddress() {
        try {
            return new CopayAddress(this).encode();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public static Address fromString(@Nullable NetworkParameters params, String str)
            throws AddressFormatException {
        try {
            return LegacyAddress.fromBase58(params, str);
        } catch (AddressFormatException.WrongNetwork x) {
            throw x;
        } catch (AddressFormatException x) {
            try {
                return SegwitAddress.fromBech32(params, str);
            } catch (AddressFormatException.WrongNetwork x2) {
                throw x;
            } catch (AddressFormatException x2) {
                throw new AddressFormatException(str);
            }
        }
    }

    /**
     * Get either the public key hash or script hash that is encoded in the address.
     * 
     * @return hash that is encoded in the address
     */
	/*public static boolean isAcceptableVersion(NetworkParameters params, int version) {
        for (int v : params.getAcceptableAddressCodes()) {
            if (version == v) {
                return true;
            }
        }
        return false;
	}*/

    public abstract byte[] getHash();

    /**
     * Get the type of output script that will be used for sending to the address.
     * 
     * @return type of output script
     */
	/*@Override
    public Address clone() throws CloneNotSupportedException {
        return (Address) super.clone();
    }

    // Java serialization

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeUTF(params.id);
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        params = NetworkParameters.fromID(in.readUTF());
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    @Override
    public String toString() {
        if (getParameters().getUseForkId()) {
            switch (type) {
                case 1:
                    return toCashAddress();
                case 2:
                    return toCopayAddress();
                default:
                    return super.toString();
            }
        } else {
            return super.toString();
        }
	}*/

    public abstract ScriptType getOutputScriptType();
}
