/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This defines the public blockchains as a service (PBaaS) notarization protocol, VerusLink.
 * VerusLink is a new distributed consensus protocol that enables multiple public blockchains 
 * to operate as a decentralized ecosystem of chains, which can interact and easily engage in cross 
 * chain transactions.
 * 
 * In all notarization services, there is notarizing chain and a chain paying notarization rewards. They are not the same.
 * The notarizing chain earns the right to submit notarizations onto the paying chain, which uses provable Verus chain power 
 * of each chain combined with a confirmation process to validate the correct version of one chain to another and vice versa.
 * Generally, the paying chain will be Verus, and the notarizing chain will be the PBaaS chain started with a root of Verus 
 * notarization.
 * 
 * On each chain, notarizations spend the output of the prior transaction that spent the notarization output, which has some spending
 * rules that create a thread of one attempted notarization per block, each of them properly representing the current chain, whether 
 * the prior transaction represents a valid representation of the other chain or not. In order to move the notarization forward,
 * it must also be accepted onto the paying chain, then referenced to move confirmed notarization forward again on the current chain. 
 * All notarization threads are started with a chain definition on the paying chain, or at block 1 on the PBaaS chain.
 * 
 * Every notarization besides the chain definition is initiated on the PBaaS chain as an effort to create a notarization that is accepted
 * and confirmed on the paying chain by first being accepted by a Verus miner before a more valuable 
 * notarization is completed and available for acceptance, then being confirmed by multiple cross notarizations.
 * 
 * A notarization submission is earned when a block is won by staking or mining on the PBaaS chain. The miner puts a notarization
 * of the paying chain into the block mined, spending the notarization thread. In order for the miner to have a transaction output to spend from,
 * all PBaaS chains have a block 1 output of a small, transferable amount of Verus, which is only used as a notarization thread.
 * 
 * After "n" blocks, currently 8, from the block won, the earned notarization may be submitted, proving the last notarization and 
 * including an MMR root that is 8 blocks after the asserted winning block, which must also be proven along with at least one staked block. 
 * Once accepted and confirmed, the notarization transaction itself may be used to spend from the pool of notarization rewards, 
 * with an output that pays 50% to the notary and 50% to the block miner/staker recipient on the paying chain.
 *
 * A notarizaton must be either the first in the chain or refer to a prior notarization with which it agrees. If it skips existing
 * notarizations, referring to a prior notarization as valid, that is the same as asserting that the skipped notarizations are invalid.
 * In that case, the notarization and 2 after it must prove one additional block since the notarization skipped.
 * 
 * The intent is to make it extremely improbable cryptographically to achieve full confirmation of any notarization unless an alternate 
 * fork actually represents a valid chain with a majority of combined work and stake, even if more than the majority of notarizers are 
 * attempting to notarize an invalid chain.
 * 
 * to accept an earned notarization as valid on the Verus blockchain, it must prove a transaction on the alternate chain, which is 
 * either the original chain definition transaction, which CAN and MUST be proven ONLY in block 1, or the latest notarization transaction 
 * on the alternate chain that represents an accurate MMR for the accepting chain.
 * In addition, any accepted notarization must fullfill the following requirements:
 * 1) Must prove either a PoS block from the alternate chain or a merge mined
 *    block that is owned by the submitter and exactly 8 blocks behind the submitted MMR, which is used for proof.
 * 2) must prove a chain definition tx and be block 1 or contain a notarization tx, which asserts a previous, valid MMR for this
 *    chain and properly proves objects using that MMR, as well as has the proper notarization thread inputs and outputs.
 * 3) must spend the notarization thread to the specified chainID in a fee free transaction with notarization thread input and output
 * 
 * to agree with a previous notarization, we must:
 * 1) agree that at the indicated block height, the MMR root is the root claimed, and is a correct representation of the best chain.
 * 
 */

#ifndef NOTARIZATION_H
#define NOTARIZATION_H

#include "pbaas/pbaas.h"
#include "key_io.h"

// This is the data for a PBaaS notarization transaction, either of a PBaaS chain into the Verus chain, or the Verus
// chain into a PBaaS chain.

// Part of a transaction with an opret that contains only the hashes and proofs, without the source
// headers, transactions, and objects. This type of notarizatoin is mined into a block by the miner, and is created on the PBaaS
// chain.
//
// Notarizations include the following elements in order:
//  Latest block header being notarized, or a header ref for a merge-mined header
//  Proof of the header using the latest MMR root
//  Cross notarization transaction less its op_ret
//  Proof of the cross notarization using the latest MMR root
class CPBaaSNotarization
{
public:
    static const int FINAL_CONFIRMATIONS = 10;
    static const int MIN_BLOCKS_BETWEEN_ACCEPTED = 8;
    static const int CURRENT_VERSION = PBAAS_VERSION;
    uint32_t nVersion;                      // PBAAS version
    uint160 chainID;                        // chain being notarized
    uint160 notaryKeyID;                    // confirmed notary rewards are spent to this address when this notarization is confirmed

    uint32_t notarizationHeight;            // height of the notarization we certify
    uint256 mmrRoot;                        // latest MMR root of the notarization height
    uint256 notarizationPreHash;            // combination of block hash, merkle root, and compact power for the notarization height
    uint256 compactPower;                   // compact power of the block height notarization to compare

    uint256 prevNotarization;               // txid of the prior notarization on this chain that we agree with, even those not accepted yet
    int32_t prevHeight;
    uint256 crossNotarization;              // hash of previous notarization transaction on the other chain, which is the first tx object in the opret input
    int32_t crossHeight;

    COpRetProof opRetProof;                 // hashes and types of all objects in our opret, enabling reconstruction without the opret on notarized chain

    std::vector<CNodeData> nodes;           // network nodes

    CPBaaSNotarization() : nVersion(PBAAS_VERSION_INVALID) { }

    CPBaaSNotarization(uint32_t version,
                       uint160 chainid,
                       uint160 notarykey,
                       int32_t notarizationheight, 
                       uint256 MMRRoot,
                       uint256 preHash,
                       uint256 compactpower,
                       uint256 prevnotarization,
                       int32_t prevheight,
                       uint256 crossnotarization,
                       int32_t crossheight,
                       COpRetProof orp,
                       std::vector<CNodeData> &Nodes) : 
                       nVersion(version),
                       chainID(chainid),
                       notaryKeyID(notarykey),

                       notarizationHeight(notarizationheight),
                       mmrRoot(MMRRoot),
                       notarizationPreHash(preHash),
                       compactPower(compactpower),

                       prevNotarization(prevnotarization),
                       prevHeight(prevheight),
                       crossNotarization(crossnotarization),
                       crossHeight(crossheight),

                       opRetProof(orp),

                       nodes(Nodes)
    { }

    CPBaaSNotarization(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CPBaaSNotarization(const CTransaction &tx, bool validate = false);

    CPBaaSNotarization(const UniValue &obj);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nVersion));
        READWRITE(chainID);
        READWRITE(notaryKeyID);
        READWRITE(notarizationHeight);
        READWRITE(mmrRoot);
        READWRITE(notarizationPreHash);
        READWRITE(compactPower);
        READWRITE(prevNotarization);
        READWRITE(prevHeight);
        READWRITE(crossNotarization);
        READWRITE(crossHeight);
        READWRITE(opRetProof);
        READWRITE(nodes);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        return !mmrRoot.IsNull();
    }

    UniValue ToUniValue() const;
};

class CNotarizationFinalization
{
public:
    int32_t confirmedInput;

    CNotarizationFinalization() : confirmedInput(-1) {}
    CNotarizationFinalization(int32_t nIn) : confirmedInput(nIn) {}
    CNotarizationFinalization(std::vector<unsigned char> vch)
    {
        ::FromVector(vch, *this);
    }
    CNotarizationFinalization(const CTransaction &tx, bool validate=false);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(confirmedInput);
    }

    bool IsValid()
    {
        return confirmedInput != -1;
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    UniValue ToUniValue() const
    {
        UniValue ret(UniValue::VOBJ);
        ret.push_back(Pair("confirmedinput", confirmedInput));
        return ret;
    }
};

class CChainNotarizationData
{
public:
    static const int CURRENT_VERSION = PBAAS_VERSION;
    uint32_t version;

    std::vector<std::pair<uint256, CPBaaSNotarization>> vtx;
    int32_t lastConfirmed;                          // last confirmed notarization
    std::vector<std::vector<int32_t>> forks;        // chains that represent alternate branches from the last confirmed notarization
    int32_t bestChain;                              // index in forks of the chain, beginning with the last confirmed notarization, that has the most power

    CChainNotarizationData() : version(0), lastConfirmed(-1) {}

    CChainNotarizationData(uint32_t ver, int32_t start, int32_t end, 
                           std::vector<std::pair<uint256, CPBaaSNotarization>> txes,
                           int32_t lastConf,
                           std::vector<std::vector<int32_t>> &Forks,
                           int32_t Best) : 
                        version(ver),
                        vtx(txes), lastConfirmed(lastConf), bestChain(Best), forks(Forks) {}

    CChainNotarizationData(std::vector<unsigned char> vch)
    {
        ::FromVector(vch, *this);
    }

    CChainNotarizationData(UniValue &obj);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(vtx);
        READWRITE(bestChain);
        READWRITE(forks);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        // this needs an actual check
        return version != 0;
    }

    bool IsConfirmed()
    {
        return lastConfirmed != -1;
    }

    UniValue ToUniValue() const;
};

class CInputDescriptor
{
public:
    CScript scriptPubKey;
    CAmount nValue;
    CTxIn txIn;
    CInputDescriptor() : nValue(0) {}
    CInputDescriptor(CScript script, CAmount value, CTxIn input) : scriptPubKey(script), nValue(value), txIn(input) {}
};

bool CreateEarnedNotarization(CMutableTransaction &mnewTx, std::vector<CInputDescriptor> &inputs, CTransaction &lastTx, CTransaction &crossTx, int32_t height, int32_t *confirmedInput, CTxDestination *confirmedDest);
uint256 CreateAcceptedNotarization(const CBlock &blk, int32_t txIndex, int32_t height);
std::vector<CInputDescriptor> AddSpendsAndFinalizations(const CChainNotarizationData &cnd, 
                                                        const uint256 &lastNotarizationID, 
                                                        const CTransaction &lastTx, 
                                                        CMutableTransaction &mnewTx, 
                                                        int32_t *pConfirmedInput, 
                                                        int32_t *pConfirmedIdx, 
                                                        CTxDestination *pConfirmedDest);
bool GetNotarizationAndFinalization(int32_t ecode, CMutableTransaction mtx, CPBaaSNotarization &pbn, uint32_t *pNotarizeOutIndex, uint32_t *pFinalizeOutIndex);
bool ValidateEarnedNotarization(CTransaction &ntx, CPBaaSNotarization *notarization = NULL);
bool ValidateEarnedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsEarnedNotarizationInput(const CScript &scriptSig);
bool ValidateAcceptedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsAcceptedNotarizationInput(const CScript &scriptSig);
bool ValidateFinalizeNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsFinalizeNotarizationInput(const CScript &scriptSig);
bool IsServiceRewardInput(const CScript &scriptSig);
bool IsBlockBoundTransaction(const CTransaction &tx);

#endif
