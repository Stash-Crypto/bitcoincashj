/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47;


import com.google.common.base.Joiner;
import com.google.common.net.InetAddresses;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.bitcoinj.core.listeners.OnTransactionBroadcastListener;
import org.bitcoinj.wallet.bip47.BIP47Util;
import org.bitcoinj.wallet.bip47.Bip47Address;
import org.bitcoinj.wallet.bip47.Bip47Meta;
import org.bitcoinj.wallet.bip47.NotSecp256k1Exception;
import org.bitcoinj.wallet.bip47.PaymentCode;
import org.bitcoinj.wallet.bip47.SecretPoint;
import org.bitcoinj.wallet.bip47.listeners.BlockchainDownloadProgressTracker;
import org.bitcoinj.wallet.bip47.listeners.TransactionEventListener;
import org.bitcoinj.crypto.bip47.Account;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.CashAddress;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.SPVBlockStore;
import org.bitcoinj.wallet.CoinSelection;
import org.bitcoinj.wallet.KeyChainGroup;
import org.bitcoinj.wallet.Protos;
import org.bitcoinj.wallet.RedeemData;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.WalletProtobufSerializer;
import org.bitcoinj.wallet.bip47.models.StashDeterministicSeed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Created by jimmy on 9/28/17.
 */

public class Wallet {
    private static final String TAG = "Wallet";

    protected final Blockchain blockchain;
    private volatile BlockChain vChain;
    private volatile BlockStore vStore;
    private volatile org.bitcoinj.wallet.Wallet vWallet;
    private volatile PeerGroup vPeerGroup;

    private final File directory;
    private volatile File vWalletFile;

    private StashDeterministicSeed restoreFromSeed;

    private List<Account> mAccounts = new ArrayList<>(1);

    private BlockchainDownloadProgressTracker mBlockchainDownloadProgressTracker;
    private TransactionEventListener mTransactionEventListener = null;

    private boolean mBlockchainDownloadStarted = false;

    private ConcurrentHashMap<String, Bip47Meta> bip47MetaData = new ConcurrentHashMap<>();
    private static final Logger log = LoggerFactory.getLogger(Wallet.class);

    public Wallet(Blockchain blockchain, File walletDirectory, @Nullable StashDeterministicSeed deterministicSeed) throws Exception {
        this.blockchain = blockchain;

        this.directory = new File(walletDirectory, blockchain.getCoin());

        this.restoreFromSeed = deterministicSeed;

        if (!directory.exists()) {
            if (!directory.mkdirs()) {
                throw new IOException("Could not create directory " + directory.getAbsolutePath());
            }
        }

        File chainFile = new File(directory, blockchain.getCoin() + ".spvchain");
        boolean chainFileExists = chainFile.exists();
        vWalletFile = new File(directory, blockchain.getCoin() + ".wallet");
        log.debug("Wallet: "+getCoin());
        boolean shouldReplayWallet = (vWalletFile.exists() && !chainFileExists) || restoreFromSeed != null;

        Context.propagate(new Context(blockchain.getNetworkParameters()));
        vWallet = createOrLoadWallet(shouldReplayWallet);
        setAccount();

        Address notificationAddress = mAccounts.get(0).getNotificationAddress();
        log.debug("Wallet notification address: "+notificationAddress.toString());

        if (!vWallet.isAddressWatched(notificationAddress)) {
            vWallet.addWatchedAddress(notificationAddress);
        }

        vWallet.allowSpendingUnconfirmedTransactions();

        log.debug(vWallet.toString());
    }

    private org.bitcoinj.wallet.Wallet createOrLoadWallet(boolean shouldReplayWallet) throws Exception {
        org.bitcoinj.wallet.Wallet wallet;

        if (vWalletFile.exists()) {
            wallet = loadWallet(shouldReplayWallet);
        } else {
            wallet = createWallet();
            wallet.freshReceiveKey();

            wallet.saveToFile(vWalletFile);
            wallet = loadWallet(false);
        }

        wallet.autosaveToFile(vWalletFile, 5, TimeUnit.SECONDS, null);

        return wallet;
    }

    private org.bitcoinj.wallet.Wallet loadWallet(boolean shouldReplayWallet) throws Exception {
        try (FileInputStream walletStream = new FileInputStream(vWalletFile)) {
            Protos.Wallet proto = WalletProtobufSerializer.parseToProto(walletStream);
            final WalletProtobufSerializer serializer = new WalletProtobufSerializer();
            org.bitcoinj.wallet.Wallet wallet = serializer.readWallet(blockchain.getNetworkParameters(), null, proto);
            if (shouldReplayWallet)
                wallet.reset();
            return wallet;
        }
    }

    private org.bitcoinj.wallet.Wallet createWallet() {
        KeyChainGroup kcg;
        if (restoreFromSeed != null)
            kcg = new KeyChainGroup(blockchain.getNetworkParameters(), restoreFromSeed);
        else
            kcg = new KeyChainGroup(blockchain.getNetworkParameters());
        return new org.bitcoinj.wallet.Wallet(blockchain.getNetworkParameters(), kcg);  // default
    }

    public String getCoin() {
        return blockchain.getCoin();
    }

    public void setAccount() {
        log.debug("Seed: "+vWallet.getKeyChainSeed());

        byte[] hd_seed = vWallet.getKeyChainSeed().getSeedBytes();

        DeterministicKey mKey = HDKeyDerivation.createMasterPrivateKey(hd_seed);
        DeterministicKey purposeKey = HDKeyDerivation.deriveChildKey(mKey, 47 | ChildNumber.HARDENED_BIT);
        DeterministicKey coinKey = HDKeyDerivation.deriveChildKey(purposeKey, ChildNumber.HARDENED_BIT);

        Account account = new Account(blockchain.getNetworkParameters(), coinKey, 0);

        mAccounts.clear();
        mAccounts.add(account);
    }

    public void start(boolean startBlockchainDownload) {
        Context.propagate(new Context(blockchain.getNetworkParameters()));
        File chainFile = new File(directory, blockchain.getCoin() + ".spvchain");
        boolean chainFileExists = chainFile.exists();

        try {
            // Initiate Bitcoin network objects (block store, blockchain and peer group)
            vStore = new SPVBlockStore(blockchain.getNetworkParameters(), chainFile);
            if (restoreFromSeed != null && chainFileExists) {
                log.info( "Deleting the chain file in preparation from restore.");
                vStore.close();
                if (!chainFile.delete())
                    log.warn("start: ", new IOException("Failed to delete chain file in preparation for restore."));
                vStore = new SPVBlockStore(blockchain.getNetworkParameters(), chainFile);
            }
            vChain = new BlockChain(blockchain.getNetworkParameters(), vStore);
            vPeerGroup = new PeerGroup(blockchain.getNetworkParameters(), vChain);

            // Fixes a bug created by a race condition between a filteredBlock and a notification transaction
            // (transaction dependencies are asynchronous (See issue 1029))
            // By rolling the blockstore one block, we will be sure that the generated keys were imported to the wallet.
            vPeerGroup.addOnTransactionBroadcastListener(new OnTransactionBroadcastListener() {
                @Override
                public void onTransaction(Peer peer, Transaction t) {
                    if (isNotificationTransaction(t) && peer.getCurrentFilteredBlock() != null){

                        if (vWallet.getTransaction(t.getHash()) != null) {
                            log.debug("Already seen this notification transaction. ");
                            return;
                        }
                        log.debug("Valid notification transaction found. Replaying a block back .. ");
                        try {
                            vChain.rollbackBlockStore(vWallet.getLastBlockSeenHeight() - 1);
                        } catch(BlockStoreException e){
                            log.error("Could not rollback ... " );
                        }
                    }
                }
            });

            if (blockchain.getCoin().equals("BCH")) {
                vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("158.69.119.35"), 8333));
                vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("144.217.73.86"), 8333));
            } else if (blockchain.getCoin().equals("tBCH")) {
                vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("158.69.119.35"), 8333));
                vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("144.217.73.86"), 18333));
            }

            vPeerGroup.setUseLocalhostPeerWhenPossible(true);
            vPeerGroup.addPeerDiscovery(new DnsDiscovery(blockchain.getNetworkParameters()));

            vChain.addWallet(vWallet);
            vPeerGroup.addWallet(vWallet);

            if (startBlockchainDownload) {
                startBlockchainDownload();
            }
        } catch (BlockStoreException e) {
            log.warn("start: ", e);

        }
    }

    public void startBlockchainDownload() {
        if (isStarted() && !mBlockchainDownloadStarted) {
            log.debug("Starting blockchain download.");
            vPeerGroup.start();
            vPeerGroup.startBlockChainDownload(mBlockchainDownloadProgressTracker);
            mBlockchainDownloadStarted = true;
        }
    }

    public List<Peer> getConnectedPeers() {
        return vPeerGroup.getConnectedPeers();
    }

    public void stop() {
        if (vPeerGroup == null || !isStarted()) {
            return;
        }

        log.debug("Stopping peergroup");
        if (vPeerGroup.isRunning()) vPeerGroup.stopAsync();
        try {
            log.debug("Saving wallet");
            vWallet.saveToFile(vWalletFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
        log.debug("stopWallet: closing store");
        try {
            vStore.close();
        } catch (BlockStoreException e) {
            e.printStackTrace();
        }

        vStore = null;

        mBlockchainDownloadStarted = false;

        log.debug("stopWallet: Done");
    }

    public boolean isStarted() {
        return vStore != null;
    }

    public void setBlockchainDownloadProgressTracker(BlockchainDownloadProgressTracker downloadProgressTracker) {
        mBlockchainDownloadProgressTracker = downloadProgressTracker;
    }

    /**
     *
     */
    public boolean loadBip47MetaData() {
        String jsonString = readBip47MetaDataFile();

        if (StringUtils.isEmpty(jsonString)) {
            return false;
        }

        log.debug("loadBip47MetaData: "+jsonString);

        return importBip47MetaData(jsonString);
    }

    public String readBip47MetaDataFile() {
        File file = new File(directory, getCoin().concat(".bip47"));
        String jsonString;
        try {
            jsonString = FileUtils.readFileToString(file, Charset.defaultCharset());
        } catch (IOException e){
            log.debug("Creating BIP47 wallet file at " + file.getAbsolutePath() + "  ...");
            saveBip47MetaData();
            loadBip47MetaData();
            return null;
        }

        return jsonString;
    }

    public boolean importBip47MetaData(String jsonString) {
        log.debug("loadBip47MetaData: "+jsonString);

        Gson gson = new Gson();
        Type collectionType = new TypeToken<Collection<Bip47Meta>>(){}.getType();
        try {
            List<Bip47Meta> bip47MetaList = gson.fromJson(jsonString, collectionType);
            if (bip47MetaList != null) {
                for (Bip47Meta bip47Meta: bip47MetaList) {
                    bip47MetaData.put(bip47Meta.getPaymentCode(), bip47Meta);
                }
            }
        } catch (JsonSyntaxException e) {
            return true;
        }
        return false;
    }

    public synchronized void saveBip47MetaData() {
        try {
            vWallet.saveToFile(vWalletFile);
        } catch (IOException io){
            log.error("Failed to save wallet file",io);
        }

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(bip47MetaData.values());

        log.debug("saveBip47MetaData: "+json);

        File file = new File(directory, getCoin().concat(".bip47"));

        try {
            FileUtils.writeStringToFile(file, json, Charset.defaultCharset(), false);
            log.debug("saveBip47MetaData: saved");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void addTransactionEventListener(TransactionEventListener coinsReceivedEventListener) {
        if (mTransactionEventListener != null) {
            vWallet.removeCoinsReceivedEventListener(mTransactionEventListener);
            vWallet.removeTransactionConfidenceEventListener(mTransactionEventListener);
        }

        vWallet.removeCoinsReceivedEventListener(coinsReceivedEventListener);
        vWallet.removeTransactionConfidenceEventListener(coinsReceivedEventListener);

        coinsReceivedEventListener.setWallet(this);

        vWallet.addCoinsReceivedEventListener(coinsReceivedEventListener);
        vWallet.addTransactionConfidenceEventListener(coinsReceivedEventListener);

        mTransactionEventListener = coinsReceivedEventListener;
    }

    public boolean isNotificationTransaction(Transaction tx) {
        Address address = getAddressOfReceived(tx);
        Address myNotificationAddress = mAccounts.get(0).getNotificationAddress();

        return address != null && address.toString().equals(myNotificationAddress.toString());
    }

    public boolean isToBIP47Address(Transaction transaction) {
        List<ECKey> keys = vWallet.getImportedKeys();
        for (ECKey key : keys) {
            Address address = key.toAddress(getNetworkParameters());
            if (address == null) {
                continue;
            }
            Address addressOfReceived = getAddressOfReceived(transaction);
            if (addressOfReceived != null && address.toString().equals(addressOfReceived.toString())) {
                return true;
            }
        }
        return false;
    }

    public Address getAddressOfReceived(Transaction tx) {
        for (final TransactionOutput output : tx.getOutputs()) {
            try {
                if (output.isMineOrWatched(vWallet)) {
                    final Script script = output.getScriptPubKey();
                    return script.getToAddress(blockchain.getNetworkParameters(), true);
                }
            } catch (final ScriptException x) {
                // swallow
            }
        }

        return null;
    }

    public Address getAddressOfSent(Transaction tx) {
        for (final TransactionOutput output : tx.getOutputs()) {
            try {
                if (!output.isMineOrWatched(vWallet)) {
                    final Script script = output.getScriptPubKey();
                    return script.getToAddress(blockchain.getNetworkParameters(), true);
                }
            } catch (final ScriptException x) {
                // swallow
            }
        }

        return null;
    }

    public PaymentCode getPaymentCodeInNotificationTransaction(Transaction tx) {
        byte[] privKeyBytes = mAccounts.get(0).getNotificationKey().getPrivKeyBytes();

        return BIP47Util.getPaymentCodeInNotificationTransaction(privKeyBytes, tx);
    }

    public boolean savePaymentCode(PaymentCode paymentCode) {
        if (bip47MetaData.containsKey(paymentCode.toString())) {
            Bip47Meta bip47Meta = bip47MetaData.get(paymentCode.toString());
            if (bip47Meta.getIncomingAddresses().size() != 0) {
                return false;
            } else {
                try {
                    bip47Meta.generateKeys(this);
                    return true;
                } catch (NotSecp256k1Exception | InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
                    e.printStackTrace();
                    return false;
                }
            }
        }

        Bip47Meta bip47Meta = new Bip47Meta(paymentCode.toString());

        try {
            bip47Meta.generateKeys(this);
            bip47MetaData.put(paymentCode.toString(), bip47Meta);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public Account getAccount(int i) {
        return mAccounts.get(i);
    }

    public NetworkParameters getNetworkParameters() {
        return blockchain.getNetworkParameters();
    }

    public Address getAddressOfKey(ECKey key) {
        return key.toAddress(getNetworkParameters());
    }

    public void importKey(ECKey key) {
        vWallet.importKey(key);
    }

    public boolean generateNewBip47IncomingAddress(String address) {
        for (Bip47Meta bip47Meta : bip47MetaData.values()) {
            for (Bip47Address bip47Address : bip47Meta.getIncomingAddresses()) {
                if (!bip47Address.getAddress().equals(address)) {
                    continue;
                }
                if (bip47Address.isSeen()) {
                    return false;
                }

                int nextIndex = bip47Meta.getCurrentIncomingIndex() + 1;
                try {
                    ECKey key = BIP47Util.getReceiveAddress(this, bip47Meta.getPaymentCode(), nextIndex).getReceiveECKey();
                    vWallet.importKey(key);
                    Address newAddress = getAddressOfKey(key);
                    bip47Meta.addNewIncomingAddress(newAddress.toString(), nextIndex);
                    bip47Address.setSeen(true);
                    return true;
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return false;
            }
        }
        return false;
    }

    public Bip47Meta getBip47MetaForAddress(String address) {
        for (Bip47Meta bip47Meta : bip47MetaData.values()) {
            for (Bip47Address bip47Address : bip47Meta.getIncomingAddresses()) {
                if (bip47Address.getAddress().equals(address)) {
                    return bip47Meta;
                }
            }
        }
        return null;
    }

    public String getPaymentCodeForAddress(String address) {
        for (Bip47Meta bip47Meta : bip47MetaData.values()) {
            for (Bip47Address bip47Address : bip47Meta.getIncomingAddresses()) {
                if (bip47Address.getAddress().equals(address)) {
                    return bip47Meta.getPaymentCode();
                }
            }
        }
        return null;
    }

    public Bip47Meta getBip47MetaForOutgoingAddress(String address) {
        for (Bip47Meta bip47Meta : bip47MetaData.values()) {
            for (String outgoingAddress : bip47Meta.getOutgoingAddresses()) {
                if (outgoingAddress.equals(address)) {
                    return bip47Meta;
                }
            }
        }
        return null;
    }

    public Bip47Meta getBip47MetaForPaymentCode(String paymentCode) {
        for (Bip47Meta bip47Meta : bip47MetaData.values()) {
            if (bip47Meta.getPaymentCode().equals(paymentCode)) {
                return bip47Meta;
            }
        }
        return null;
    }

    public Coin getValueOfTransaction(Transaction transaction) {
        return transaction.getValue(vWallet);
    }

    public Coin getValueSentToMe(Transaction transaction) {
        return transaction.getValueSentToMe(vWallet);
    }

    public Coin getValueSentFromMe(Transaction transaction) {
        return transaction.getValueSentFromMe(vWallet);
    }

    public List<Transaction> getTransactions() {
        return vWallet.getTransactionsByTime();
    }

    public long getBalanceValue() {
        return vWallet.getBalance(org.bitcoinj.wallet.Wallet.BalanceType.ESTIMATED_SPENDABLE).getValue();
    }

    public Coin getBalance() {
        return vWallet.getBalance(org.bitcoinj.wallet.Wallet.BalanceType.ESTIMATED_SPENDABLE);
    }

    public boolean isDownloading() {
        return mBlockchainDownloadProgressTracker != null && mBlockchainDownloadProgressTracker.isDownloading();
    }

    public int getBlockchainProgress() {
        return mBlockchainDownloadProgressTracker != null ? mBlockchainDownloadProgressTracker.getProgress() : -1;
    }

    public boolean isTransactionEntirelySelf(Transaction tx) {
        for (final TransactionInput input : tx.getInputs()) {
            final TransactionOutput connectedOutput = input.getConnectedOutput();
            if (connectedOutput == null || !connectedOutput.isMine(vWallet))
                return false;
        }

        for (final TransactionOutput output : tx.getOutputs()) {
            if (!output.isMine(vWallet))
                return false;
        }

        return true;
    }

    public String getPaymentCode() {
        return getAccount(0).getStringPaymentCode();
    }

    public void resetBlockchainSync() {
        File chainFile = new File(directory, getCoin()+".spvchain");
        if (chainFile.exists()) {
            log.debug("deleteSpvFile: exits");
            chainFile.delete();
        }
    }

    public String getMnemonicCode() {
        return Joiner.on(" ").join(vWallet.getKeyChainSeed().getMnemonicCode());
    }

    public Address getCurrentAddress() {
        return vWallet.currentReceiveAddress();
    }

    public Address getAddressFromBase58(String addr) {
        return Address.fromBase58(getNetworkParameters(), addr);
    }

    public boolean isValidAddress(String address) {
        try {
            Address.fromBase58(getNetworkParameters(), address);
            return true;
        } catch (AddressFormatException e) {
            try {
                CashAddress.decode(address);
                return true;
            } catch (AddressFormatException e2) {
                e2.printStackTrace();
                return false;
            }
        }
    }

    public Blockchain getBlockchain() {
        return blockchain;
    }

    public Transaction createSend(String strAddr, long amount) throws InsufficientMoneyException {
        Address address;
        try {
            address = Address.fromBase58(getNetworkParameters(), strAddr);
        } catch (AddressFormatException e1) {
            try {
                address = CashAddress.decode(strAddr);
            } catch (AddressFormatException e2) {
                return null;
            }
        }
        return createSend(address, amount);
    }

    public Transaction createSend(Address address, long amount) throws InsufficientMoneyException {
        SendRequest sendRequest = SendRequest.to(address, Coin.valueOf(amount));
        if (!getNetworkParameters().getUseForkId()) {
            sendRequest.feePerKb = Coin.valueOf(141000);
        }
        vWallet.completeTx(sendRequest);
        return sendRequest.tx;
    }

    public SendRequest makeNotificationTransaction(String paymentCode, boolean complete) throws InsufficientMoneyException {
        Account toAccount = new Account(getNetworkParameters(), paymentCode);
        Coin ntValue =  getNetworkParameters().getMinNonDustOutput();
        Address ntAddress = toAccount.getNotificationAddress();


        log.debug("Balance: " + vWallet.getBalance());
        log.debug("To notification address: "+ntAddress.toString());
        log.debug("Value: "+ntValue.toFriendlyString());

        SendRequest sendRequest = SendRequest.to(ntAddress, ntValue);

        if (!getNetworkParameters().getUseForkId()) {
            sendRequest.feePerKb = Coin.valueOf(141000);
        }

        sendRequest.memo = "notification_transaction";

        FeeCalculation feeCalculation = WalletUtil.calculateFee(vWallet, sendRequest, ntValue, vWallet.calculateAllSpendCandidates());

        for (TransactionOutput output :feeCalculation.bestCoinSelection.gathered) {
            sendRequest.tx.addInput(output);
        }

        if (sendRequest.tx.getInputs().size() > 0) {
            TransactionInput txIn = sendRequest.tx.getInput(0);
            RedeemData redeemData = txIn.getConnectedRedeemData(vWallet);
            checkNotNull(redeemData, "StashTransaction exists in wallet that we cannot redeem: %s", txIn.getOutpoint().getHash());
            log.debug("Keys: "+redeemData.keys.size());
            log.debug("Private key 0?: "+redeemData.keys.get(0).hasPrivKey());
            byte[] privKey = redeemData.getFullKey().getPrivKeyBytes();
            log.debug("Private key: "+ Utils.HEX.encode(privKey));
            byte[] pubKey = toAccount.getNotificationKey().getPubKey();
            log.debug("Public Key: "+Utils.HEX.encode(pubKey));
            byte[] outpoint = txIn.getOutpoint().bitcoinSerialize();

            byte[] mask = null;
            try {
                SecretPoint secretPoint = new SecretPoint(privKey, pubKey);
                log.debug("Secret Point: "+Utils.HEX.encode(secretPoint.ECDHSecretAsBytes()));
                log.debug("Outpoint: "+Utils.HEX.encode(outpoint));
                mask = PaymentCode.getMask(secretPoint.ECDHSecretAsBytes(), outpoint);
            } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
                e.printStackTrace();
            }
            log.debug("My payment code: "+mAccounts.get(0).getPaymentCode().toString());
            log.debug("Mask: "+Utils.HEX.encode(mask));
            byte[] op_return = PaymentCode.blind(mAccounts.get(0).getPaymentCode().getPayload(), mask);

            sendRequest.tx.addOutput(Coin.ZERO, ScriptBuilder.createOpReturnScript(op_return));
        }

        if (complete)
            vWallet.completeTx(sendRequest);

        log.debug("Completed SendRequest");
        log.debug(sendRequest.toString());
        log.debug(sendRequest.tx.toString());

        sendRequest.tx.verify();

        return sendRequest;
    }

    public Transaction getSignedNotificationTransaction(SendRequest sendRequest, String paymentCode) {
        //Account toAccount = new Account(getNetworkParameters(), paymentCode);

        // notification address pub key
        //WalletUtil.signTransaction(vWallet, sendRequest, toAccount.getNotificationKey().getPubKey(), mAccounts.get(0).getPaymentCode());

        vWallet.commitTx(sendRequest.tx);

        return sendRequest.tx;
    }

    public ListenableFuture<Transaction> broadcastTransaction(Transaction transactionToSend) {
        vWallet.commitTx(transactionToSend);
        return vPeerGroup.broadcastTransaction(transactionToSend).future();
    }

    public boolean putBip47Meta(String profileId, String name) {
        if (bip47MetaData.containsKey(profileId)) {
            Bip47Meta bip47Meta = bip47MetaData.get(profileId);
            if (!name.equals(bip47Meta.getLabel())) {
                bip47Meta.setLabel(name);
                return true;
            }
        } else {
            bip47MetaData.put(profileId, new Bip47Meta(profileId, name));
            return true;
        }
        return false;
    }

    public void putPaymenCodeStatusSent(String paymentCode) {
        if (bip47MetaData.containsKey(paymentCode)) {
            Bip47Meta bip47Meta = bip47MetaData.get(paymentCode);
            bip47Meta.setStatusSent();
        } else {
            putBip47Meta(paymentCode, paymentCode);
            putPaymenCodeStatusSent(paymentCode);
        }
    }

    public String getCurrentOutgoingAddress(Bip47Meta bip47Meta) {
        try {
            ECKey key = BIP47Util.getSendAddress(this, new PaymentCode(bip47Meta.getPaymentCode()), bip47Meta.getCurrentOutgoingIndex()).getSendECKey();
            return key.toAddress(getNetworkParameters()).toString();
        } catch (InvalidKeyException | InvalidKeySpecException | NotSecp256k1Exception | NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void commitTx(Transaction tx) {
        vWallet.commitTx(tx);
    }

    public org.bitcoinj.wallet.Wallet.SendResult sendCoins(SendRequest sendRequest) throws InsufficientMoneyException {
        return vWallet.sendCoins(sendRequest);
    }

    static class FeeCalculation {
        CoinSelection bestCoinSelection;
        TransactionOutput bestChangeOutput;
    }
}
