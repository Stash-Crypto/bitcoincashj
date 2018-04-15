/*
 * Copyright 2013 Google Inc.
 * Copyright 2015 Andreas Schildbach
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
 */

package org.bitcoinj.params;

import com.google.common.base.Preconditions;
import com.google.common.base.Stopwatch;
import org.bitcoinj.core.*;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import static com.google.common.base.Preconditions.*;

/**
 * Parameters for the main production network on which people trade goods and services.
 */
public class BCCMainNetParams extends AbstractBitcoinNetParams {
    public static final int MAINNET_MAJORITY_WINDOW = 1000;
    public static final int MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED = 950;
    public static final int MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 750;

    public static final int COPAY_ADDRESS_HEADER = 28;
    public static final int COPAY_P2SH_HEADER = 40;

    /**
     * Scheme part for Bitcoin Cash URIs.
     */
    public static final String BITCOIN_CASH_SCHEME = "bitcoincash";

    private static final Logger log = LoggerFactory.getLogger(BCCMainNetParams.class);

    // Aug, 1 hard fork
    int uahfHeight = 478559;
    /** Activation time at which the cash HF kicks in. */
    long cashHardForkActivationTime;

    int daaHeight;

    public BCCMainNetParams() {
        super();
        interval = INTERVAL;
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x1d00ffffL);
        dumpedPrivateKeyHeader = 128;
        addressHeader = 0;
        p2shHeader = 5;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader, COPAY_ADDRESS_HEADER, COPAY_P2SH_HEADER };
        port = 8333;
        packetMagic = 0xe3e1f3e8L;
        bip32HeaderPub = 0x0488B21E; //The 4 byte header that serializes in base58 to "xpub".
        bip32HeaderPriv = 0x0488ADE4; //The 4 byte header that serializes in base58 to "xprv"

        majorityEnforceBlockUpgrade = MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = MAINNET_MAJORITY_WINDOW;

        genesisBlock.setDifficultyTarget(0x1d00ffffL);
        genesisBlock.setTime(1231006505L);
        genesisBlock.setNonce(2083236893);
        id = ID_MAINNET;
        subsidyDecreaseBlockCount = 210000;
        spendableCoinbaseDepth = 100;
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
                genesisHash);

        // This contains (at a minimum) the blocks which are not BIP30 compliant. BIP30 changed how duplicate
        // transactions are handled. Duplicated transactions could occur in the case where a coinbase had the same
        // extraNonce and the same outputs but appeared at different heights, and greatly complicated re-org handling.
        // Having these here simplifies block connection logic considerably.
        checkpoints.put(91722, Sha256Hash.wrap("00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"));
        checkpoints.put(91812, Sha256Hash.wrap("00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"));
        checkpoints.put(91842, Sha256Hash.wrap("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"));
        checkpoints.put(91880, Sha256Hash.wrap("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"));
        checkpoints.put(200000, Sha256Hash.wrap("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"));
        checkpoints.put(478559, Sha256Hash.wrap("000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"));

        dnsSeeds = new String[] {
                "seed.bitcoinabc.org",
                "seed-abc.bitcoinforks.org",
                "btccash-seeder.bitcoinunlimited.info",
                "seed.bitprim.org",
                "seed.deadalnix.me",
                "seeder.criptolayer.net"
        };
        httpSeeds = null; /*new HttpDiscovery.Details[] {
                // Andreas Schildbach
                new HttpDiscovery.Details(
                        ECKey.fromPublicOnly(Utils.HEX.decode("0238746c59d46d5408bf8b1d0af5740fe1a6e1703fcb56b2953f0b965c740d256f")),
                        URI.create("http://httpseed.bitcoin.schildbach.de/peers")
                )
        };*/

        addrSeeds = null; /*new int[] {
                0x1ddb1032, 0x6242ce40, 0x52d6a445, 0x2dd7a445, 0x8a53cd47, 0x73263750, 0xda23c257, 0xecd4ed57,
                0x0a40ec59, 0x75dce160, 0x7df76791, 0x89370bad, 0xa4f214ad, 0x767700ae, 0x638b0418, 0x868a1018,
                0xcd9f332e, 0x0129653e, 0xcc92dc3e, 0x96671640, 0x56487e40, 0x5b66f440, 0xb1d01f41, 0xf1dc6041,
                0xc1d12b42, 0x86ba1243, 0x6be4df43, 0x6d4cef43, 0xd18e0644, 0x1ab0b344, 0x6584a345, 0xe7c1a445,
                0x58cea445, 0xc5daa445, 0x21dda445, 0x3d3b5346, 0x13e55347, 0x1080d24a, 0x8e611e4b, 0x81518e4b,
                0x6c839e4b, 0xe2ad0a4c, 0xfbbc0a4c, 0x7f5b6e4c, 0x7244224e, 0x1300554e, 0x20690652, 0x5a48b652,
                0x75c5c752, 0x4335cc54, 0x340fd154, 0x87c07455, 0x087b2b56, 0x8a133a57, 0xac23c257, 0x70374959,
                0xfb63d45b, 0xb9a1685c, 0x180d765c, 0x674f645d, 0x04d3495e, 0x1de44b5e, 0x4ee8a362, 0x0ded1b63,
                0xc1b04b6d, 0x8d921581, 0x97b7ea82, 0x1cf83a8e, 0x91490bad, 0x09dc75ae, 0x9a6d79ae, 0xa26d79ae,
                0x0fd08fae, 0x0f3e3fb2, 0x4f944fb2, 0xcca448b8, 0x3ecd6ab8, 0xa9d5a5bc, 0x8d0119c1, 0x045997d5,
                0xca019dd9, 0x0d526c4d, 0xabf1ba44, 0x66b1ab55, 0x1165f462, 0x3ed7cbad, 0xa38fae6e, 0x3bd2cbad,
                0xd36f0547, 0x20df7840, 0x7a337742, 0x549f8e4b, 0x9062365c, 0xd399f562, 0x2b5274a1, 0x8edfa153,
                0x3bffb347, 0x7074bf58, 0xb74fcbad, 0x5b5a795b, 0x02fa29ce, 0x5a6738d4, 0xe8a1d23e, 0xef98c445,
                0x4b0f494c, 0xa2bc1e56, 0x7694ad63, 0xa4a800c3, 0x05fda6cd, 0x9f22175e, 0x364a795b, 0x536285d5,
                0xac44c9d4, 0x0b06254d, 0x150c2fd4, 0x32a50dcc, 0xfd79ce48, 0xf15cfa53, 0x66c01e60, 0x6bc26661,
                0xc03b47ae, 0x4dda1b81, 0x3285a4c1, 0x883ca96d, 0x35d60a4c, 0xdae09744, 0x2e314d61, 0x84e247cf,
                0x6c814552, 0x3a1cc658, 0x98d8f382, 0xe584cb5b, 0x15e86057, 0x7b01504e, 0xd852dd48, 0x56382f56,
                0x0a5df454, 0xa0d18d18, 0x2e89b148, 0xa79c114c, 0xcbdcd054, 0x5523bc43, 0xa9832640, 0x8a066144,
                0x3894c3bc, 0xab76bf58, 0x6a018ac1, 0xfebf4f43, 0x2f26c658, 0x31102f4e, 0x85e929d5, 0x2a1c175e,
                0xfc6c2cd1, 0x27b04b6d, 0xdf024650, 0x161748b8, 0x28be6580, 0x57be6580, 0x1cee677a, 0xaa6bb742,
                0x9a53964b, 0x0a5a2d4d, 0x2434c658, 0x9a494f57, 0x1ebb0e48, 0xf610b85d, 0x077ecf44, 0x085128bc,
                0x5ba17a18, 0x27ca1b42, 0xf8a00b56, 0xfcd4c257, 0xcf2fc15e, 0xd897e052, 0x4cada04f, 0x2f35f6d5,
                0x382ce8c9, 0xe523984b, 0x3f946846, 0x60c8be43, 0x41da6257, 0xde0be142, 0xae8a544b, 0xeff0c254,
                0x1e0f795b, 0xaeb28890, 0xca16acd9, 0x1e47ddd8, 0x8c8c4829, 0xd27dc747, 0xd53b1663, 0x4096b163,
                0x9c8dd958, 0xcb12f860, 0x9e79305c, 0x40c1a445, 0x4a90c2bc, 0x2c3a464d, 0x2727f23c, 0x30b04b6d,
                0x59024cb8, 0xa091e6ad, 0x31b04b6d, 0xc29d46a6, 0x63934fb2, 0xd9224dbe, 0x9f5910d8, 0x7f530a6b,
                0x752e9c95, 0x65453548, 0xa484be46, 0xce5a1b59, 0x710e0718, 0x46a13d18, 0xdaaf5318, 0xc4a8ff53,
                0x87abaa52, 0xb764cf51, 0xb2025d4a, 0x6d351e41, 0xc035c33e, 0xa432c162, 0x61ef34ae, 0xd16fddbc,
                0x0870e8c1, 0x3070e8c1, 0x9c71e8c1, 0xa4992363, 0x85a1f663, 0x4184e559, 0x18d96ed8, 0x17b8dbd5,
                0x60e7cd18, 0xe5ee104c, 0xab17ac62, 0x1e786e1b, 0x5d23b762, 0xf2388fae, 0x88270360, 0x9e5b3d80,
                0x7da518b2, 0xb5613b45, 0x1ad41f3e, 0xd550854a, 0x8617e9a9, 0x925b229c, 0xf2e92542, 0x47af0544,
                0x73b5a843, 0xb9b7a0ad, 0x03a748d0, 0x0a6ff862, 0x6694df62, 0x3bfac948, 0x8e098f4f, 0x746916c3,
                0x02f38e4f, 0x40bb1243, 0x6a54d162, 0x6008414b, 0xa513794c, 0x514aa343, 0x63781747, 0xdbb6795b,
                0xed065058, 0x42d24b46, 0x1518794c, 0x9b271681, 0x73e4ffad, 0x0654784f, 0x438dc945, 0x641846a6,
                0x2d1b0944, 0x94b59148, 0x8d369558, 0xa5a97662, 0x8b705b42, 0xce9204ae, 0x8d584450, 0x2df61555,
                0xeebff943, 0x2e75fb4d, 0x3ef8fc57, 0x9921135e, 0x8e31042e, 0xb5afad43, 0x89ecedd1, 0x9cfcc047,
                0x8fcd0f4c, 0xbe49f5ad, 0x146a8d45, 0x98669ab8, 0x98d9175e, 0xd1a8e46d, 0x839a3ab8, 0x40a0016c,
                0x6d27c257, 0x977fffad, 0x7baa5d5d, 0x1213be43, 0xb167e5a9, 0x640fe8ca, 0xbc9ea655, 0x0f820a4c,
                0x0f097059, 0x69ac957c, 0x366d8453, 0xb1ba2844, 0x8857f081, 0x70b5be63, 0xc545454b, 0xaf36ded1,
                0xb5a4b052, 0x21f062d1, 0x72ab89b2, 0x74a45318, 0x8312e6bc, 0xb916965f, 0x8aa7c858, 0xfe7effad,
        };*/

        // Aug, 1 hard fork
        uahfHeight = 478559;
        /** Activation time at which the cash HF kicks in. */
        cashHardForkActivationTime = 1510600000;
        daaHeight = 504031+1;
    }

    private static BCCMainNetParams instance;
    public static synchronized BCCMainNetParams get() {
        if (instance == null) {
            instance = new BCCMainNetParams();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_MAINNET;
    }

    @Override
    public int getMaxBlockSize() {
        return Block.BCC_MAX_BLOCK_SIZE;
    }

    @Override
    public int getMaxBlockSigops() {
        return Block.BCC_MAX_BLOCK_SIGOPS;
    }

    @Override
    public Coin getReferenceDefaultMinTxFee() {
        return Transaction.BCC_REFERENCE_DEFAULT_MIN_TX_FEE;
    }

    @Override
    public Coin getDefaultTxFee() {
        return Transaction.BCC_DEFAULT_TX_FEE;
    }

    @Override
    public Coin getMinNonDustOutput() {
        return Transaction.BCC_MIN_NONDUST_OUTPUT;
    }

    @Override
    public int getProtocolVersionNum(final ProtocolVersion version) {
        return version == ProtocolVersion.CURRENT? ProtocolVersion.BCC_CURRENT.getBitcoinProtocolVersion() : version.getBitcoinProtocolVersion();
    }

    @Override
    public boolean getUseForkId() {
        return true;
    }

    @Override
    public String getUriScheme() {
        return BITCOIN_CASH_SCHEME;
    }

    void verifyDifficulty(BigInteger newTarget, Block nextBlock) {
        if (newTarget.compareTo(this.getMaxTarget()) > 0) {
            log.info("Difficulty hit proof of work limit: {}", newTarget.toString(16));
            newTarget = this.getMaxTarget();
        }

        int accuracyBytes = (int) (nextBlock.getDifficultyTarget() >>> 24) - 3;
        long receivedTargetCompact = nextBlock.getDifficultyTarget();

        // The calculated difficulty is to a higher precision than received, so reduce here.
        BigInteger mask = BigInteger.valueOf(0xFFFFFFL).shiftLeft(accuracyBytes * 8);
        newTarget = newTarget.and(mask);
        long newTargetCompact = Utils.encodeCompactBits(newTarget);

        if (newTargetCompact != receivedTargetCompact)
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
                    Long.toHexString(newTargetCompact) + " vs " + Long.toHexString(receivedTargetCompact));
    }

    /**
     * The number that is one greater than the largest representable SHA-256
     * hash.
     */
    private static BigInteger LARGEST_HASH = BigInteger.ONE.shiftLeft(256);

    /**
     * Compute the a target based on the work done between 2 blocks and the time
     * required to produce that work.
     */
    BigInteger ComputeTarget(StoredBlock pindexFirst,
                             StoredBlock pindexLast) {

        Preconditions.checkState(pindexLast.getHeight() > pindexFirst.getHeight());

        /**
         * From the total work done and the time it took to produce that much work,
         * we can deduce how much work we expect to be produced in the targeted time
         * between blocks.
         */
        BigInteger work = pindexLast.getChainWork().subtract(pindexFirst.getChainWork());
        work = work.multiply(BigInteger.valueOf(this.TARGET_SPACING));

        // In order to avoid difficulty cliffs, we bound the amplitude of the
        // adjustement we are going to do.
        //assert(pindexLast->nTime > pindexFirst->nTime);
        long nActualTimespan = pindexLast.getHeader().getTimeSeconds() - pindexFirst.getHeader().getTimeSeconds();
        if (nActualTimespan > 288 * TARGET_SPACING) {
            nActualTimespan = 288 * TARGET_SPACING;
        } else if (nActualTimespan < 72 * TARGET_SPACING) {
            nActualTimespan = 72 * TARGET_SPACING;
        }

        work = work.divide(BigInteger.valueOf(nActualTimespan));

        /**
         * We need to compute T = (2^256 / W) - 1 but 2^256 doesn't fit in 256 bits.
         * By expressing 1 as W / W, we get (2^256 - W) / W, and we can compute
         * 2^256 - W as the complement of W.
         */
        //return (-work) / work;
        //return BigInteger.valueOf(2).pow(256).divide(work).subtract(BigInteger.valueOf(1));

        //return Block.LARGEST_HASH.divide(target.add(BigInteger.ONE))

        return LARGEST_HASH.divide(work).subtract(BigInteger.ONE);//target.add(BigInteger.ONE))
    }

    /**
     * To reduce the impact of timestamp manipulation, we select the block we are
     * basing our computation on via a median of 3.
     */
    StoredBlock GetSuitableBlock(StoredBlock pindex, BlockStore blockStore) throws BlockStoreException{
        //assert(pindex->nHeight >= 3);

        /**
         * In order to avoid a block is a very skewed timestamp to have too much
         * influence, we select the median of the 3 top most blocks as a starting
         * point.
         */
        StoredBlock blocks[] = new StoredBlock[3];
        blocks[2] = pindex;
        blocks[1] = pindex.getPrev(blockStore);
        blocks[0] = blocks[1].getPrev(blockStore);

        // Sorting network.
        if (blocks[0].getHeader().getTimeSeconds() > blocks[2].getHeader().getTimeSeconds()) {
            //std::swap(blocks[0], blocks[2]);
            StoredBlock temp = blocks[0];
            blocks[0] = blocks[2];
            blocks[2] = temp;
        }

        if (blocks[0].getHeader().getTimeSeconds() > blocks[1].getHeader().getTimeSeconds()) {
            //std::swap(blocks[0], blocks[1]);
            StoredBlock temp = blocks[0];
            blocks[0] = blocks[1];
            blocks[1] = temp;
        }

        if (blocks[1].getHeader().getTimeSeconds() > blocks[2].getHeader().getTimeSeconds()) {
            //std::swap(blocks[1], blocks[2]);
            StoredBlock temp = blocks[1];
            blocks[1] = blocks[2];
            blocks[2] = temp;
        }

        // We should have our candidate in the middle now.
        return blocks[1];
    }

    /**
     * Compute the next required proof of work using a weighted average of the
     * estimated hashrate per block.
     *
     * Using a weighted average ensure that the timestamp parameter cancels out in
     * most of the calculation - except for the timestamp of the first and last
     * block. Because timestamps are the least trustworthy information we have as
     * input, this ensures the algorithm is more resistant to malicious inputs.
     */
    protected void checkNextCashWorkRequired(StoredBlock pindexPrev,
                                   Block pblock, BlockStore blockStore) {
        // This cannot handle the genesis block and early blocks in general.
        //assert(pindexPrev);

        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 2* 10 minutes then allow
        // mining of a min-difficulty block.
        /*if (params.fPowAllowMinDifficultyBlocks &&
                (pblock->GetBlockTime() >
                        pindexPrev->GetBlockTime() + 2 * params.nPowTargetSpacing)) {
            return UintToArith256(params.powLimit).GetCompact();
        }*/

        // Compute the difficulty based on the full adjustement interval.
        int nHeight = pindexPrev.getHeight();
        Preconditions.checkState(nHeight >= this.interval);

        // Get the last suitable block of the difficulty interval.
        try {
            StoredBlock pindexLast = GetSuitableBlock(pindexPrev, blockStore);
            //assert (pindexLast);

            // Get the first suitable block of the difficulty interval.
            int nHeightFirst = nHeight - 144;

            StoredBlock pindexFirst = pindexPrev;

            for (int i = 144; i > 0; --i)
            {
                pindexFirst = pindexFirst.getPrev(blockStore);
                if(pindexFirst == null)
                    return;
            }

            pindexFirst = GetSuitableBlock(pindexFirst, blockStore);
            //assert (pindexFirst);

            // Compute the target based on time and work done during the interval.
            BigInteger nextTarget =
                    ComputeTarget(pindexFirst, pindexLast);

            verifyDifficulty(nextTarget, pblock);
        }
        catch (BlockStoreException x)
        {
            //this means we don't have enough blocks, yet.  let it go until we do.
            return;
        }
    }

}
