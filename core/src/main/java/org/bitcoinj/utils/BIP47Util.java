/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.utils;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VarInt;
import org.bitcoinj.core.bip47.BIP47PaymentCode;
import org.bitcoinj.crypto.BIP47SecretPoint;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.signers.MissingSigResolutionSigner;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.wallet.CoinSelection;
import org.bitcoinj.wallet.CoinSelector;
import org.bitcoinj.wallet.DecryptingKeyBag;
import org.bitcoinj.wallet.KeyBag;
import org.bitcoinj.wallet.RedeemData;
import org.bitcoinj.wallet.SendRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.LinkedList;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * Created by jimmy on 10/3/17.
 */

public class BIP47Util {
    private static final String TAG = "BIP47Util";
    private static final Logger log = LoggerFactory.getLogger(BIP47Util.class);

    public static class FeeCalculation {
        public CoinSelection bestCoinSelection;
        public TransactionOutput bestChangeOutput;
    }

    public static FeeCalculation calculateFee(org.bitcoinj.wallet.Wallet vWallet, SendRequest req, Coin value, List<TransactionOutput> candidates) throws InsufficientMoneyException {
        CoinSelector selector = vWallet.getCoinSelector();
        // There are 3 possibilities for what adding change might do:
        // 1) No effect
        // 2) Causes increase in fee (change < 0.01 COINS)
        // 3) Causes the transaction to have a dust output or change < fee increase (ie change will be thrown away)
        // If we get either of the last 2, we keep note of what the inputs looked like at the time and try to
        // add inputs as we go up the list (keeping track of minimum inputs for each category).  At the end, we pick
        // the best input set as the one which generates the lowest total fee.
        Coin additionalValueForNextCategory = null;
        CoinSelection selection3 = null;
        CoinSelection selection2 = null;
        TransactionOutput selection2Change = null;
        CoinSelection selection1 = null;
        TransactionOutput selection1Change = null;
        // We keep track of the last size of the transaction we calculated but only if the act of adding inputs and
        // change resulted in the size crossing a 1000 byte boundary. Otherwise it stays at zero.
        int lastCalculatedSize = 0;
        Coin valueNeeded, valueMissing = null;

        Coin referenceDefaultMinTxFee = vWallet.getNetworkParameters().getReferenceDefaultMinTxFee();

        while (true) {
            req.tx.clearInputs();
            Coin fees = req.feePerKb.multiply(lastCalculatedSize).divide(1000);
            if (fees.compareTo(referenceDefaultMinTxFee) < 0)
                fees = referenceDefaultMinTxFee;

            valueNeeded = value.add(fees);
            if (additionalValueForNextCategory != null)
                valueNeeded = valueNeeded.add(additionalValueForNextCategory);
            Coin additionalValueSelected = additionalValueForNextCategory;

            // Of the coins we could spend, pick some that we actually will spend.
            // selector is allowed to modify candidates list.
            CoinSelection selection = selector.select(valueNeeded, new LinkedList<>(candidates));
            // Can we afford this?
            if (selection.valueGathered.compareTo(valueNeeded) < 0) {
                valueMissing = valueNeeded.subtract(selection.valueGathered);
                break;
            }

            // We keep track of an upper bound on transaction size to calculate fees that need to be added.
            // Note that the difference between the upper bound and lower bound is usually small enough that it
            // will be very rare that we pay a fee we do not need to.
            //
            // We can't be sure a selection is valid until we check fee per kb at the end, so we just store
            // them here temporarily.
            boolean eitherCategory2Or3 = false;
            boolean isCategory3 = false;

            Coin change = selection.valueGathered.subtract(valueNeeded);
            if (additionalValueSelected != null)
                change = change.add(additionalValueSelected);

            // If change is < 0.01 BTC, we will need to have at least minfee to be accepted by the network
            if (req.ensureMinRequiredFee && !change.equals(Coin.ZERO) &&
                    change.compareTo(Coin.CENT) < 0 && fees.compareTo(referenceDefaultMinTxFee) < 0) {
                // This solution may fit into category 2, but it may also be category 3, we'll check that later
                eitherCategory2Or3 = true;
                additionalValueForNextCategory = Coin.CENT;
                // If the change is smaller than the fee we want to add, this will be negative
                change = change.subtract(referenceDefaultMinTxFee.subtract(fees));
            }

            int size = 0;
            TransactionOutput changeOutput = null;
            if (change.signum() > 0) {
                // The value of the inputs is greater than what we want to send. Just like in real life then,
                // we need to take back some coins ... this is called "change". Add another output that sends the change
                // back to us. The address comes either from the request or currentChangeAddress() as a default.
                Address changeAddress = req.changeAddress;
                if (changeAddress == null)
                    changeAddress = vWallet.currentChangeAddress();
                changeOutput = new TransactionOutput(vWallet.getNetworkParameters(), req.tx, change, changeAddress);
                // If the change output would result in this transaction being rejected as dust, just drop the change and make it a fee
                if (req.ensureMinRequiredFee && changeOutput.isDust()) {
                    // This solution definitely fits in category 3
                    isCategory3 = true;
                    additionalValueForNextCategory = referenceDefaultMinTxFee.add(
                            changeOutput.getMinNonDustValue().add(Coin.SATOSHI));
                } else {
                    size += changeOutput.unsafeBitcoinSerialize().length + VarInt.sizeOf(req.tx.getOutputs().size()) - VarInt.sizeOf(req.tx.getOutputs().size() - 1);
                    // This solution is either category 1 or 2
                    if (!eitherCategory2Or3) // must be category 1
                        additionalValueForNextCategory = null;
                }
            } else {
                if (eitherCategory2Or3) {
                    // This solution definitely fits in category 3 (we threw away change because it was smaller than MIN_TX_FEE)
                    isCategory3 = true;
                    additionalValueForNextCategory = referenceDefaultMinTxFee.add(Coin.SATOSHI);
                }
            }

            // Now add unsigned inputs for the selected coins.
            for (TransactionOutput output : selection.gathered) {
                TransactionInput input = req.tx.addInput(output);
                // If the scriptBytes don't default to none, our size calculations will be thrown off.
                checkState(input.getScriptBytes().length == 0);
            }

            // Estimate transaction size and loop again if we need more fee per kb. The serialized tx doesn't
            // include things we haven't added yet like input signatures/scripts or the change output.
            size += req.tx.unsafeBitcoinSerialize().length;
            size += estimateBytesForSigning(vWallet, selection);
            if (size > lastCalculatedSize && req.feePerKb.signum() > 0) {
                lastCalculatedSize = size;
                // We need more fees anyway, just try again with the same additional value
                additionalValueForNextCategory = additionalValueSelected;
                continue;
            }

            if (isCategory3) {
                if (selection3 == null)
                    selection3 = selection;
            } else if (eitherCategory2Or3) {
                // If we are in selection2, we will require at least CENT additional. If we do that, there is no way
                // we can end up back here because CENT additional will always get us to 1
                checkState(selection2 == null);
                checkState(additionalValueForNextCategory.equals(Coin.CENT));
                selection2 = selection;
                selection2Change = checkNotNull(changeOutput); // If we get no change in category 2, we are actually in category 3
            } else {
                // Once we get a category 1 (change kept), we should break out of the loop because we can't do better
                checkState(selection1 == null);
                checkState(additionalValueForNextCategory == null);
                selection1 = selection;
                selection1Change = changeOutput;
            }

            if (additionalValueForNextCategory != null) {
                if (additionalValueSelected != null)
                    checkState(additionalValueForNextCategory.compareTo(additionalValueSelected) > 0);
                continue;
            }
            break;
        }

        req.tx.clearInputs();

        if (selection3 == null && selection2 == null && selection1 == null) {
            checkNotNull(valueMissing);
            log.warn("Insufficient value in wallet for send: needed "+valueMissing.toFriendlyString()+" more");
            throw new InsufficientMoneyException(valueMissing);
        }

        Coin lowestFee = null;
        FeeCalculation result = new FeeCalculation();
        if (selection1 != null) {
            if (selection1Change != null)
                lowestFee = selection1.valueGathered.subtract(selection1Change.getValue());
            else
                lowestFee = selection1.valueGathered;
            result.bestCoinSelection = selection1;
            result.bestChangeOutput = selection1Change;
        }

        if (selection2 != null) {
            Coin fee = selection2.valueGathered.subtract(checkNotNull(selection2Change).getValue());
            if (lowestFee == null || fee.compareTo(lowestFee) < 0) {
                lowestFee = fee;
                result.bestCoinSelection = selection2;
                result.bestChangeOutput = selection2Change;
            }
        }

        if (selection3 != null) {
            if (lowestFee == null || selection3.valueGathered.compareTo(lowestFee) < 0) {
                result.bestCoinSelection = selection3;
                result.bestChangeOutput = null;
            }
        }
        return result;
    }

    /**
     * <p>Given a send request containing transaction, attempts to sign it's inputs. This method expects transaction
     * to have all necessary inputs connected or they will be ignored.</p>
     * <p>Actual signing is done by pluggable signers and it's not guaranteed that
     * transaction will be complete in the end.</p>
     */
    static void signTransaction(org.bitcoinj.wallet.Wallet vWallet, SendRequest req, byte[] pubKey, BIP47PaymentCode myBIP47PaymentCode) {
        Transaction tx = req.tx;
        List<TransactionInput> inputs = tx.getInputs();
        List<TransactionOutput> outputs = tx.getOutputs();
        checkState(inputs.size() > 0);
        checkState(outputs.size() > 0);

        KeyBag maybeDecryptingKeyBag = new DecryptingKeyBag(vWallet, req.aesKey);

        int numInputs = tx.getInputs().size();
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = tx.getInput(i);
            if (txIn.getConnectedOutput() == null) {
                // Missing connected output, assuming already signed.
                continue;
            }

            try {
                // We assume if its already signed, its hopefully got a SIGHASH type that will not invalidate when
                // we sign missing pieces (to check this would require either assuming any signatures are signing
                // standard output types or a way to get processed signatures out of script execution)
                if(vWallet.getNetworkParameters().getUseForkId()) {
                    txIn.getScriptSig().correctlySpends(tx, i, txIn.getConnectedOutput().getScriptPubKey(), txIn.getConnectedOutput().getValue());
                } else {
                    txIn.getScriptSig().correctlySpends(tx, i, txIn.getConnectedOutput().getScriptPubKey());
                }
                continue;
            } catch (ScriptException e) {
                log.debug("Input contained an incorrect signature", e);
                // Expected.
            }

            Script scriptPubKey = txIn.getConnectedOutput().getScriptPubKey();
            RedeemData redeemData = txIn.getConnectedRedeemData(maybeDecryptingKeyBag);
            checkNotNull(redeemData, "StashTransaction exists in wallet that we cannot redeem: %s", txIn.getOutpoint().getHash());
            Script scriptSig = scriptPubKey.createEmptyInputScript(redeemData.keys.get(0), redeemData.redeemScript);
            txIn.setScriptSig(scriptSig);
            if (i == 0) {
                log.debug("Keys: "+redeemData.keys.size());
                log.debug("Private key 0?: "+redeemData.keys.get(0).hasPrivKey());
                byte[] privKey = redeemData.getFullKey().getPrivKeyBytes();
                log.debug("Private key: "+ Utils.HEX.encode(privKey));
                log.debug("Public Key: "+Utils.HEX.encode(pubKey));
                byte[] outpoint = txIn.getOutpoint().bitcoinSerialize();

                byte[] mask = null;
                try {
                    BIP47SecretPoint BIP47SecretPoint = new BIP47SecretPoint(privKey, pubKey);
                    log.debug("Secret Point: "+Utils.HEX.encode(BIP47SecretPoint.ECDHSecretAsBytes()));
                    log.debug("Outpoint: "+Utils.HEX.encode(outpoint));
                    mask = BIP47PaymentCode.getMask(BIP47SecretPoint.ECDHSecretAsBytes(), outpoint);
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchProviderException e) {
                    e.printStackTrace();
                } catch (InvalidKeySpecException e) {
                    e.printStackTrace();
                }
                log.debug("My payment code: "+ myBIP47PaymentCode.toString());
                log.debug("Mask: "+Utils.HEX.encode(mask));
                byte[] op_return = BIP47PaymentCode.blind(myBIP47PaymentCode.getPayload(), mask);

                tx.addOutput(Coin.ZERO, ScriptBuilder.createOpReturnScript(op_return));
            }
        }

        tx.shuffleOutputs();

        TransactionSigner.ProposedTransaction proposal = vWallet.getNetworkParameters().getUseForkId() ?
                new TransactionSigner.ProposedTransaction(tx, true) :
                new TransactionSigner.ProposedTransaction(tx);
        for (TransactionSigner signer : vWallet.getTransactionSigners()) {
            if (!signer.signInputs(proposal, maybeDecryptingKeyBag))
                log.debug(signer.getClass().getName()+" returned false for the tx");
        }

        // resolve missing sigs if any
        new MissingSigResolutionSigner(req.missingSigsMode).signInputs(proposal, maybeDecryptingKeyBag);
    }

    private static int estimateBytesForSigning(org.bitcoinj.wallet.Wallet vWallet, CoinSelection selection) {
        int size = 0;
        for (TransactionOutput output : selection.gathered) {
            try {
                Script script = output.getScriptPubKey();
                ECKey key = null;
                Script redeemScript = null;
                if (script.isSentToAddress()) {
                    key = vWallet.findKeyFromPubHash(script.getPubKeyHash());
                    checkNotNull(key, "Coin selection includes unspendable outputs");
                } else if (script.isPayToScriptHash()) {
                    redeemScript = vWallet.findRedeemDataFromScriptHash(script.getPubKeyHash()).redeemScript;
                    checkNotNull(redeemScript, "Coin selection includes unspendable outputs");
                }
                size += script.getNumberOfBytesRequiredToSpend(key, redeemScript);
            } catch (ScriptException e) {
                // If this happens it means an output script in a wallet tx could not be understood. That should never
                // happen, if it does it means the wallet has got into an inconsistent state.
                throw new IllegalStateException(e);
            }
        }
        return size;
    }
}
