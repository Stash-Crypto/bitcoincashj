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
import org.bitcoinj.net.BlockingClientManager;
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

    // This wallet allows one listener to be invoked when there are coins received and
    private TransactionEventListener mCoinsReceivedEventListener = null;
    // one listener when the transaction confidence changes
    private TransactionEventListener mTransactionConfidenceListener = null;

    private boolean mBlockchainDownloadStarted = false;

    private ConcurrentHashMap<String, Bip47Meta> bip47MetaData = new ConcurrentHashMap<>();
    private static final Logger log = LoggerFactory.getLogger(Wallet.class);

    private int torSocksPort = -1;

    public Wallet(Blockchain blockchain, File walletDirectory, @Nullable StashDeterministicSeed deterministicSeed) throws Exception {
        this(blockchain, walletDirectory, deterministicSeed, -1);
    }

    public Wallet(Blockchain blockchain, File walletDirectory, @Nullable StashDeterministicSeed deterministicSeed, int torSocksPort) throws Exception {
        this.blockchain = blockchain;

        this.directory = new File(walletDirectory, blockchain.getCoin());

        this.restoreFromSeed = deterministicSeed;

        this.torSocksPort = torSocksPort;
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

        // Initiate Bitcoin network objects (block store, blockchain and peer group)
        vStore = new SPVBlockStore(blockchain.getNetworkParameters(), chainFile);
        if (restoreFromSeed != null && chainFileExists) {
            log.info( "Deleting the chain file in preparation from restore.");
            vStore.close();
            if (!chainFile.delete())
                log.warn("start: ", new IOException("Failed to delete chain file in preparation for restore."));
            vStore = new SPVBlockStore(blockchain.getNetworkParameters(), chainFile);
        }

        try {
            vChain = new BlockChain(blockchain.getNetworkParameters(), vStore);
        } catch (BlockStoreException e){

            //  - we can create a new blockstore in case it is corrupted, the wallet should have a last height
            if (chainFile.exists()) {
                log.debug("deleteSpvFile: exits");
                chainFile.delete();
            }

            vStore = new SPVBlockStore(blockchain.getNetworkParameters(), chainFile);
            vChain = new BlockChain(blockchain.getNetworkParameters(), vStore);
        }

        vChain.addWallet(vWallet);
        derivePeerGroup();
        addBip47Listener();
    }

    private void derivePeerGroup() {

        if (torSocksPort>0) {
            System.setProperty("socksProxyHost", "127.0.0.1");
            System.setProperty("socksProxyPort", ((Integer)torSocksPort).toString());
        }

        Context.propagate(new Context(blockchain.getNetworkParameters()));

        if (vPeerGroup == null) {
            if (torSocksPort > 0)
                vPeerGroup = new PeerGroup(blockchain.getNetworkParameters(), vChain, new BlockingClientManager());
            else
                vPeerGroup = new PeerGroup(blockchain.getNetworkParameters(), vChain);
        }

        if (blockchain.getCoin().equals("BCH")) {
            // stash crypto
            vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("158.69.119.35"), 8333));
            vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("144.217.73.86"), 8333));
            // bitcoin abc from shodan.io
            //vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("106.14.105.56"), 8333));
            //vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("52.211.14.233"), 8333));
            //vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("50.39.245.26"), 8333));
            //vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("52.57.14.67"), 8333));
            // bucash
            //vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("5.44.97.110"), 8333));
            //vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("185.69.52.180"), 8333));
        } else if (blockchain.getCoin().equals("tBCH")) {
            // stash crypto
            vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("158.69.119.35"), 18333));
            vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("144.217.73.86"), 18333));
            // bitcoin abc from shodan.io
            //vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("61.100.182.189"), 18333));
            //vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("47.74.186.127"), 18333));
        }

        vPeerGroup.setUseLocalhostPeerWhenPossible(true);
        vPeerGroup.addPeerDiscovery(new DnsDiscovery(blockchain.getNetworkParameters()));

        vPeerGroup.addWallet(vWallet);
    }

    private void addBip47Listener(){
        this.addOnReceiveTransactionListener(new TransactionEventListener() {
            @Override
            public void onTransactionReceived(Wallet bip47Wallet, Transaction transaction) {

                if (isNotificationTransaction(transaction)) {
                    log.debug("Valid notification transaction received");
                    PaymentCode paymentCode = getPaymentCodeInNotificationTransaction(transaction);
                    if (paymentCode == null) {
                        log.warn("Error decoding payment code in tx {}", transaction);
                    } else {
                        log.debug("Payment Code: " + paymentCode);
                        boolean needsSaving = savePaymentCode(paymentCode);
                        if (needsSaving) {
                            saveBip47MetaData();
                        }
                    }
                } else if (isToBIP47Address(transaction)) {
                    log.debug("New BIP47 payment received to address: "+getAddressOfReceived(transaction));
                    boolean needsSaving = generateNewBip47IncomingAddress(getAddressOfReceived(transaction).toString());
                    if (needsSaving) {
                        saveBip47MetaData();
                    }
                    String paymentCode = getPaymentCodeForAddress(getAddressOfReceived(transaction).toString());
                    log.debug("Received tx for Payment Code: " + paymentCode);
                } else {
                    Coin valueSentToMe = getValueSentToMe(transaction);
                    log.debug("Received tx for "+valueSentToMe.toFriendlyString() + ":" + transaction);
                }
            }

            @Override
            public void onTransactionConfidenceEvent(Wallet bip47Wallet, Transaction transaction) {
                return;
            }
        });
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
        byte[] hd_seed = this.restoreFromSeed != null ?
                this.restoreFromSeed.getSeedBytes() :
                vWallet.getKeyChainSeed().getSeedBytes();

        DeterministicKey mKey = HDKeyDerivation.createMasterPrivateKey(hd_seed);
        DeterministicKey purposeKey = HDKeyDerivation.deriveChildKey(mKey, 47 | ChildNumber.HARDENED_BIT);
        DeterministicKey coinKey = HDKeyDerivation.deriveChildKey(purposeKey, ChildNumber.HARDENED_BIT);

        Account account = new Account(blockchain.getNetworkParameters(), coinKey, 0);

        mAccounts.clear();
        mAccounts.add(account);
    }

    public void start(boolean startBlockchainDownload) {
        //Context.propagate(new Context(blockchain.getNetworkParameters()));
        //File chainFile = new File(directory, blockchain.getCoin() + ".spvchain");
        //boolean chainFileExists = chainFile.exists();

        if (startBlockchainDownload) {
            startBlockchainDownload();
        }
    }

    public void startBlockchainDownload() {
        if (!isStarted() && !mBlockchainDownloadStarted) {
            log.debug("Starting blockchain download.");
            vPeerGroup.start();
            vPeerGroup.startBlockChainDownload(mBlockchainDownloadProgressTracker);
            mBlockchainDownloadStarted = true;
        } else {
            log.warn("Attempted to start blockchain download but it is already started.");
        }
    }

    public List<Peer> getConnectedPeers() {
        return vPeerGroup.getConnectedPeers();
    }

    // throws TimeoutException only if tor is enabled
    public void stop() {
        if (!isStarted()) {
            return;
        }

        log.debug("Stopping peergroup");
        vPeerGroup.stop();
        try {
            log.debug("Saving wallet");
            vWallet.saveToFile(vWalletFile);
        } catch (IOException e) {
            e.printStackTrace();
        }

        log.debug("stopWallet: closing store");
        try {
            if (vStore != null)
                vStore.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        vStore = null;
        vPeerGroup = null;
        mBlockchainDownloadStarted = false;
        derivePeerGroup();

        mBlockchainDownloadStarted = false;

        log.debug("stopWallet: Done");
    }

    public boolean isStarted() {
        if (vPeerGroup == null)
            return false;
        return vPeerGroup.isRunning();
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

    /** <p>A listener is added to be invoked when the wallet sees an incoming transaction. </p> */
    public void addOnReceiveTransactionListener(TransactionEventListener transactionEventListener){
        if (this.mCoinsReceivedEventListener != null)
            vWallet.removeCoinsReceivedEventListener(mCoinsReceivedEventListener);

        transactionEventListener.setWallet(this);
        vWallet.addCoinsReceivedEventListener(transactionEventListener);

        mCoinsReceivedEventListener = transactionEventListener;
    }

    /** <p>A listener is added to be invoked when the wallet receives blocks and builds confidence on a transaction </p> */
    public void addTransactionConfidenceEventListener(TransactionEventListener transactionEventListener){
        if (this.mTransactionConfidenceListener != null)
            vWallet.removeTransactionConfidenceEventListener(mTransactionConfidenceListener);

        transactionEventListener.setWallet(this);
        vWallet.addTransactionConfidenceEventListener(transactionEventListener);

        mTransactionConfidenceListener = transactionEventListener;
    }

    public TransactionEventListener getCoinsReceivedEventListener(){
        return this.mCoinsReceivedEventListener;
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

    private static Coin getDefaultFee(NetworkParameters params){
        if (params.getUseForkId()) {
            return Transaction.DEFAULT_TX_FEE;
        } else {
            return Transaction.BCC_DEFAULT_TX_FEE;
        }
    }
    public Transaction createSend(Address address, long amount) throws InsufficientMoneyException {
        SendRequest sendRequest = SendRequest.to(address, Coin.valueOf(amount));

        sendRequest.feePerKb = getDefaultFee(getNetworkParameters());

        vWallet.completeTx(sendRequest);
        return sendRequest.tx;
    }

    public SendRequest makeNotificationTransaction(String paymentCode) throws InsufficientMoneyException {
        Account toAccount = new Account(getNetworkParameters(), paymentCode);
        Coin ntValue =  getNetworkParameters().getMinNonDustOutput();
        Address ntAddress = toAccount.getNotificationAddress();


        log.debug("Balance: " + vWallet.getBalance());
        log.debug("To notification address: "+ntAddress.toString());
        log.debug("Value: "+ntValue.toFriendlyString());

        SendRequest sendRequest = SendRequest.to(ntAddress, ntValue);

        sendRequest.feePerKb = getDefaultFee(getNetworkParameters());

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

    public void rescanTxBlock(Transaction tx) throws BlockStoreException {
        int blockHeight = tx.getConfidence().getAppearedAtChainHeight() - 2;
        this.vChain.rollbackBlockStore(blockHeight);
    }

    public File getDirectory() {
        return directory;
    }

    public File getvWalletFile(){
        return this.vWalletFile;
    }

    public org.bitcoinj.wallet.Wallet getvWallet(){
        return vWallet;
    }

    public void closeBlockStore() throws BlockStoreException, IllegalAccessException {
        if (isStarted())
            throw new IllegalAccessException("Must call stop() before closing block store");

        if (vStore != null) {
            vStore.close();
        }
    }

    public List<String> getAddresses(int size) {
        List<DeterministicKey> deterministicKeys = vWallet.getActiveKeyChain().getLeafKeys();
        List<String> addresses = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            addresses.add(deterministicKeys.get(i).toAddress(getNetworkParameters()).toBase58());
        }
        return addresses;
    }

    public int getExternalAddressCount() {
        return vWallet.getActiveKeyChain().getIssuedReceiveKeys().size();
    }
}
