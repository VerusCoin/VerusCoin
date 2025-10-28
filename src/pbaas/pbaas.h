/********************************************************************
 * (C) 2019 Michael Toutonghi
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * This provides support for PBaaS initialization, notarization, and cross-chain token
 * transactions and enabling liquid or non-liquid tokens across the
 * Verus ecosystem.
 *
 *
 */

#ifndef PBAAS_H
#define PBAAS_H

#include <vector>
#include <univalue.h>

#include "cc/CCinclude.h"
#include "streams.h"
#include "script/script.h"
#include "amount.h"
#include "pbaas/crosschainrpc.h"
#include "pbaas/reserves.h"
#include "mmr.h"
#include "lrucache.h"

#include <boost/algorithm/string.hpp>

void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex, bool fIncludeAsm=true);

class CPBaaSNotarization;
class TransactionBuilder;

// these are output cryptoconditions for the Verus reserve liquidity system
// VRSC can be proxied to other PBaaS chains and sent back for use with this system
// The assumption that Verus is either the proxy on the PBaaS chain or the native
// coin on Verus enables us to reduce data requirements systemwide

// this is for transaction outputs with a Verus proxy on a PBaaS chain cryptoconditions with these outputs
// must also be funded with the native chain for fees, unless the chain is a Verus reserve chain, in which
// case the fee will be autoconverted from the Verus proxy through the conversion rules of this chain

static const uint32_t PBAAS_NODESPERNOTARIZATION = 2;       // number of nodes to reference in each notarization
static const int64_t PBAAS_MINNOTARIZATIONOUTPUT = 10000;   // enough for one fee worth to finalization and notarization thread
static const int32_t PBAAS_MINSTARTBLOCKDELTA = 20;         // minimum number of blocks to wait for starting a chain after definition
static const int32_t PBAAS_MAXPRIORBLOCKS = 16;             // maximum prior block commitments to include in prior blocks chain object
static const uint32_t PBAAS_CROSS_CHAIN_PROOF_FIX_HEIGHT = 3143920;
static const uint32_t PBAAS_BLOCK_ONE_ID_UPGRADE_FIX_HEIGHT = 3173198;
static const uint32_t PBAAS_PROMOTE_EXCHANGE_RATE_HEIGHT = 3173568;
static const uint32_t PBAAS_PROMOTE_EXCHANGE_RATE_TEST_HEIGHT = 171274;
static const uint32_t PBAAS_NOTARIZATION_ORDER_HEIGHT = 3227685;
static const uint32_t PBAAS_NOTARIZATION_ORDER_VARRR_HEIGHT = 238210;
static const uint32_t PBAAS_NOTARIZATION_ORDER_VDEX_HEIGHT = 68730;
static const uint32_t PBAAS_SCHEDULED_PROTOCOL_UPGRADE_01 = 1731002400;
static const uint32_t PBAAS_SCHEDULED_PROTOCOL_TESTNET_UPGRADE_01 = 1730228400;
static const uint32_t PBAAS_SCHEDULED_PROTOCOL_UPGRADE_02 = 1732471200; // (GMT): Sunday, November 24, 2024 6:00:00 PM
static const uint32_t PBAAS_SCHEDULED_PROTOCOL_TESTNET_UPGRADE_02 = 1731373200; // (GMT): Tuesday, November 12, 2024 1:00:00 AM
static const uint32_t PBAAS_LAUNCH_REFUND_FIX_UPGRADE = 1740679200; // GMT: Thursday, Feb 27, 2025 6:00:00 PM
static const uint32_t PBAAS_LAUNCH_REFUND_FIX_TESTNET_UPGRADE_02 = 1740679200; // GMT: Thursday, Feb 27, 2025 6:00:00 PM
static const uint32_t PBAAS_CHIPS_NOTARIZATION_FIX_UPGRADE = 1741798800; // GMT: Wednesday, March 12, 2025 5:00:00 PM
static const uint32_t PBAAS_ALLCHAINS_NOTARIZATION_FIX_UPGRADE = 1743440400; // GMT: Monday, March 31, 2025 5:00:00 PM
static const uint32_t PBAAS_ALLCHAINS_NOTARIZATION_FIX_TESTNET_UPGRADE = 1741798800; // GMT: Wednesday, March 12, 2025 5:00:00 PM

class CUpgradeDescriptor
{
public:
    enum EVersions {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = 1,
    };

    uint32_t version;                       // version
    uint32_t minDaemonVersion;              // if we are not at this version or higher, we cannot support this upgrade
    uint160 upgradeID;                      // upgrade identifier for listening client
    uint32_t upgradeBlockHeight;            // block height at which the upgrade should happen
    uint32_t upgradeTargetTime;             // target time for upgrade, depending on specific upgrade activation rules

    CUpgradeDescriptor(uint32_t Version=VERSION_INVALID) : version(Version), upgradeBlockHeight(0) {}
    CUpgradeDescriptor(const uint160 &UpgradeID, uint32_t minDaemonVersion, uint32_t UpgradeHeight, uint32_t upgradeTargetTime, uint32_t Version=VERSION_CURRENT) :
        version(Version), upgradeID(UpgradeID), upgradeBlockHeight(UpgradeHeight) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(version));
        READWRITE(VARINT(minDaemonVersion));
        READWRITE(upgradeID);
        READWRITE(VARINT(upgradeBlockHeight));
        READWRITE(VARINT(upgradeTargetTime));
    }

    CUpgradeDescriptor(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CUpgradeDescriptor(const UniValue &uni);
    UniValue ToUniValue() const;

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return version >= VERSION_FIRST && version <= VERSION_LAST && !upgradeID.IsNull() && (upgradeBlockHeight || upgradeTargetTime);
    }
};

class CInputDescriptor
{
public:
    CScript scriptPubKey;
    CAmount nValue;
    CTxIn txIn;
    CInputDescriptor() : nValue(0) {}
    CInputDescriptor(CScript script, CAmount value, CTxIn input) : scriptPubKey(script), nValue(value), txIn(input) {}
    bool operator<(const CInputDescriptor &op) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(scriptPubKey);
        READWRITE(nValue);
        READWRITE(txIn);
    }
};

class CRPCChainData
{
public:
    CCurrencyDefinition chainDefinition;    // chain information for the specific chain
    std::string     rpcHost;                // host of the chain's daemon
    int32_t         rpcPort;                // port of the chain's daemon
    std::string     rpcUserPass;            // user and password for this daemon
    int64_t         lastConnectTime;        // set whenever we check valid

    CRPCChainData() {}
    CRPCChainData(CCurrencyDefinition &chainDef, std::string host, int32_t port, std::string userPass) :
        chainDefinition(chainDef), rpcHost{host}, rpcPort(port), rpcUserPass(userPass), lastConnectTime(0) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(chainDefinition);
        READWRITE(rpcHost);
        READWRITE(rpcPort);
        READWRITE(rpcUserPass);
        READWRITE(lastConnectTime);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return chainDefinition.IsValid();
    }

    int64_t SetLastConnection(int64_t setTime)
    {
        return (lastConnectTime = setTime);
    }

    int64_t LastConnectionTime() const
    {
        return lastConnectTime;
    }

    uint160 GetID() const
    {
        return chainDefinition.GetID();
    }
};

// Each merge mined chain gets an entry that includes information required to connect to a live daemon
// for that block, cross notarize, and validate notarizations.
class CPBaaSMergeMinedChainData : public CRPCChainData
{
public:
    CBlock          block;                  // full block to submit upon winning header

    CPBaaSMergeMinedChainData() {}
    CPBaaSMergeMinedChainData(CCurrencyDefinition &chainDef, std::string host, int32_t port, std::string userPass, CBlock &blk) :
        CRPCChainData(chainDef, host, port, userPass), block(blk) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(chainDefinition);
        READWRITE(rpcHost);
        READWRITE(rpcPort);
        READWRITE(rpcUserPass);
        READWRITE(block);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }
};

class CGateway
{
public:
    virtual bool ValidateDestination(const std::string &destination) const = 0;
    virtual CTransferDestination ToTransferDestination(const std::string &destination) const = 0;
    virtual std::set<uint160> FeeCurrencies() const = 0;
    virtual uint160 GatewayID() const = 0;
};

class CEthGateway : public CGateway
{
public:
    virtual bool ValidateDestination(const std::string &destination) const;
    virtual CTransferDestination ToTransferDestination(const std::string &destination) const;
    virtual std::set<uint160> FeeCurrencies() const;
    virtual uint160 GatewayID() const;
};

class CObjectFinalization;

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
    enum {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_PBAAS = 1,
        VERSION_PBAAS_MAINNET = 2,
        VERSION_LAST = 2,
        VERSION_CURRENT = 2,
        FINAL_CONFIRMATIONS = 9,
        DEFAULT_NOTARIZATION_FEE = 10000,               // default notarization fee when entering a signature for a notarization
        DEFAULT_ACCEPTED_EVIDENCE_FEE = 100000,         // minimum price of each evidence output when entering a notarization
        MAX_NODES = 2,                                  // only provide 2 nodes per notarization
        MIN_NOTARIZATION_OUTPUT = 0,                    // minimum amount for notarization output

        EXPECT_MIN_HEADER_PROOFS = 1,                   // if header proofs are needed, we need this many or number of blocks
        MIN_EARNED_FOR_SIGNED = 2,                      // minimum earned notarizations to notarize with witnesses
        MIN_EARNED_FOR_AUTO = 4,                        // minimum earned notarizations to auto-notarize at any modulo
        NUM_BLOCKS_BEFORE_EXTENSION = 150,              // if we haven't confirmed a notarization in this long, modulo gets multiplied
        MODULO_EXTENSION_MULTIPLIER = 10,               // notarization rate drops to 1/10 when not confirmed on time
        MIN_BLOCKS_TO_AUTOCONFIRM = 100,                // we cannot autoconfirm (signature-free) a notarization < 200 blocks old
        MIN_BLOCKS_TO_SIGNCONFIRM = 15,                 // we cannot sign confirm a notarization < 15 blocks old
        MAX_NOTARIZATION_DELAY_BEFORE_CROSSCHAIN_PAUSE = 1000, // if we go 1000 minutes with no notarization, cross-chain to that chani is paused

        MAX_HEADER_PROOFS_PER_PROOF = 25,               // don't use more than this many header proofs in an alternate chain proof tx
        MAX_HEADER_PROOFS_SIZE = 200000,                // never require more than 200K of evidence for any reason
        MAX_BLOCKS_PER_COMMITMENT_RANGE = 256,          // up to 256 blocks per commitment range
        MAX_BLOCK_RANGES_PER_PROOF = 5,                 // no more than 5 randomly selected ranges to cover any gap length
        NUM_COMMITMENT_BLOCKS_START_OFFSET = 100,       // commitment blocks start this far before the actual start or at 1
        NUM_BLOCKS_PER_PROOF_RANGE = 100,               // number of blocks in an ideal proof range
        NUM_HEADER_PROOF_RANGE_DIVISOR = 10,            // proofs every this many blocks
        MIN_BLOCKS_PER_CHECKPOINT = 256,                // blocks before we need another checkpoint
        MAX_PROOF_CHECKPOINTS = 100,                    // we do not add more than 100, after that, they are spaced further apart
        BLOCKS_TO_STABLE_PBAAS_ROOT = 5,                // PBaaS tip ahead of considered a "laststableroot", must be proven on challenge
        BLOCKS_ENFORCED_TO_STABLE_NOTARY_ROOT = 100,    // unnotarized notary chain tip blocks ahead of "laststableroot", must be proven on challenge
        BLOCKS_TO_STABLE_NOTARY_ROOT = 102,             // used as last stable root to ensure we can prove statistically almost all the time
        MIN_BLOCKS_FOR_SEMISTABLE_TIP = 2,              // leeway to ensure sticky notarizations
    };

    inline static int32_t MinBlocksToAutoNotarization(uint32_t notarizationBlockModulo)
    {
        return CCurrencyDefinition::MinBlocksToAutoNotarization(notarizationBlockModulo);
    }

    inline static int32_t MinBlocksToSignedNotarization(uint32_t notarizationBlockModulo)
    {
        return CCurrencyDefinition::MinBlocksToSignedNotarization(notarizationBlockModulo);
    }

    inline static int32_t MinBlocksToStartNotarization(uint32_t notarizationBlockModulo)
    {
        return CCurrencyDefinition::MinBlocksToStartNotarization(notarizationBlockModulo);
    }

    inline static int32_t BlocksBeforeAlternateStakeEnforcement()
    {
        return 300;
    }

    inline static int32_t GetBlocksBeforeModuloExtension(uint32_t notarizationBlockModulo)
    {
        uint32_t maxAutoConfirmBlocks = notarizationBlockModulo * MODULO_EXTENSION_MULTIPLIER * (MIN_EARNED_FOR_AUTO * 2);
        return std::max(maxAutoConfirmBlocks, (uint32_t)NUM_BLOCKS_BEFORE_EXTENSION);
    }

    inline static int32_t NotarizationsBeforeModuloExtension()
    {
        return MIN_EARNED_FOR_AUTO << 1 + MIN_EARNED_FOR_AUTO;
    }

    static int32_t GetAdjustedNotarizationModuloExp(int64_t notarizationBlockModulo,
                                                    int64_t fromHeight,
                                                    int64_t untilHeight,
                                                    int64_t notarizationsBeforeModuloExtension,
                                                    int64_t notarizationCount=0);

    inline static int32_t GetAdjustedNotarizationModulo(uint32_t notarizationBlockModulo, uint32_t fromHeight, uint32_t untilHeight, int32_t notarizationCount=0)
    {
        return GetAdjustedNotarizationModuloExp(notarizationBlockModulo, fromHeight, untilHeight, NotarizationsBeforeModuloExtension(), notarizationCount);
    }

    enum FLAGS
    {
        FLAGS_NONE = 0,
        FLAG_DEFINITION_NOTARIZATION = 1,   // initial notarization on definition of currency/system/chain
        FLAG_PRE_LAUNCH = 2,                // pre-launch notarization
        FLAG_START_NOTARIZATION = 4,        // first notarization after pre-launch
        FLAG_LAUNCH_CONFIRMED = 8,
        FLAG_REFUNDING = 0x10,
        FLAG_ACCEPTED_MIRROR = 0x20,        // if this is set, this notarization is a mirror of an earned notarization on another chain
        FLAG_BLOCKONE_NOTARIZATION = 0x40,  // block 1 notarizations are auto-finalized, the blockchain itself will be worthless if it is wrong
        FLAG_SAME_CHAIN = 0x80,             // set if all currency information is verifiable on this chain
        FLAG_LAUNCH_COMPLETE = 0x100,       // set if all currency information is verifiable on this chain
        FLAG_CONTRACT_UPGRADE = 0x200,      // if set, this notarization agrees to the contract ugrade referenced in the first auxdest
        FLAGS_MASK = 0x3ff
    };

    uint32_t nVersion;
    uint32_t flags;                         // notarization options
    CTransferDestination proposer;          // paid when this gets used on import (miner/staker, shares this with 1 notary for each validation)

    uint160 currencyID;                     // the primary currency this notarization represents for the system, may be gateway or external chain
    uint32_t notarizationHeight;            // <= height on the current system as of this notarization (can't be confirmed earlier)
    CCoinbaseCurrencyState currencyState;   // state of the currency being notarized as of this notarization

    CUTXORef prevNotarization;              // reference of the prior notarization on this system with which we agree
    uint256 hashPrevCrossNotarization;      // (this is not the same notarization as the prev notarization or prev height)
                                            //  it is the hash of the prior notarization on the other chain with which we agree, even one not yet confirmed
    uint32_t prevHeight;                    // height of previous notarization we agree with

    std::map<uint160, CCoinbaseCurrencyState> currencyStates; // currency state of other currencies to be co-notarized for gateways
    std::map<uint160, CProofRoot> proofRoots; // if cross-chain notarization, includes valid proof root of systemID at notarizationHeight + others verified

    std::vector<CNodeData> nodes;           // if cross chain notarization, network nodes

    CPBaaSNotarization() : nVersion(PBAAS_VERSION_INVALID), flags(0), notarizationHeight(0), prevHeight(0) {}

    CPBaaSNotarization(const uint160 &currencyid,
                       const CCoinbaseCurrencyState CurrencyState,
                       uint32_t height,
                       const CUTXORef &prevnotarization,
                       uint32_t prevheight,
                       const std::vector<CNodeData> &Nodes=std::vector<CNodeData>(),
                       const std::map<uint160, CCoinbaseCurrencyState> &CurrencyStates=std::map<uint160, CCoinbaseCurrencyState>(),
                       const CTransferDestination &Proposer=CTransferDestination(),
                       const std::map<uint160, CProofRoot> &ProofRoots=std::map<uint160, CProofRoot>(),
                       uint32_t version=VERSION_CURRENT,
                       uint32_t Flags=FLAGS_NONE) :
                       nVersion(version),
                       flags(Flags),
                       proposer(Proposer),
                       currencyID(currencyid),
                       notarizationHeight(height),
                       currencyState(CurrencyState),
                       prevNotarization(prevnotarization),
                       prevHeight(prevheight),
                       currencyStates(CurrencyStates),
                       proofRoots(ProofRoots),
                       nodes(Nodes)
    {
    }

    CPBaaSNotarization(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CPBaaSNotarization(const CTransaction &tx, int32_t *pOutIdx=nullptr);

    CPBaaSNotarization(const CScript &scriptPubKey);

    CPBaaSNotarization(const UniValue &obj);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nVersion));
        READWRITE(VARINT(flags));
        READWRITE(proposer);
        READWRITE(currencyID);
        READWRITE(currencyState);
        READWRITE(notarizationHeight);
        READWRITE(prevNotarization);
        READWRITE(hashPrevCrossNotarization);
        READWRITE(prevHeight);

        if (nVersion == VERSION_PBAAS_MAINNET)
        {
            std::vector<CCoinbaseCurrencyState> vecCurrencyStates;
            if (ser_action.ForRead())
            {
                READWRITE(vecCurrencyStates);
                for (auto &oneState : vecCurrencyStates)
                {
                    currencyStates.insert(std::make_pair(oneState.GetID(), oneState));
                }
            }
            else
            {
                for (auto &oneState : currencyStates)
                {
                    vecCurrencyStates.push_back(oneState.second);
                }
                READWRITE(vecCurrencyStates);
            }
            std::vector<CProofRoot> vecProofRoots;
            if (ser_action.ForRead())
            {
                READWRITE(vecProofRoots);
                for (auto &oneRoot : vecProofRoots)
                {
                    proofRoots.insert(std::make_pair(oneRoot.systemID, oneRoot));
                }
            }
            else
            {
                for (auto &oneRoot : proofRoots)
                {
                    vecProofRoots.push_back(oneRoot.second);
                }
                READWRITE(vecProofRoots);
            }
        }
        else
        {
            std::vector<std::pair<uint160, CCoinbaseCurrencyState>> vecCurrencyStates;
            if (ser_action.ForRead())
            {
                READWRITE(vecCurrencyStates);
                for (auto &oneState : vecCurrencyStates)
                {
                    currencyStates.insert(oneState);
                }
            }
            else
            {
                for (auto &oneState : currencyStates)
                {
                    vecCurrencyStates.push_back(oneState);
                }
                READWRITE(vecCurrencyStates);
            }
            std::vector<std::pair<uint160, CProofRoot>> vecProofRoots;
            if (ser_action.ForRead())
            {
                READWRITE(vecProofRoots);
                for (auto &oneRoot : vecProofRoots)
                {
                    proofRoots.insert(oneRoot);
                }
            }
            else
            {
                for (auto &oneRoot : proofRoots)
                {
                    vecProofRoots.push_back(oneRoot);
                }
                READWRITE(vecProofRoots);
            }
        }

        READWRITE(nodes);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return nVersion >= VERSION_FIRST && nVersion <= VERSION_LAST && !currencyID.IsNull();
    }

    static std::string NotaryNotarizationKeyName()
    {
        return "vrsc::system.notarization.notarization";
    }

    static std::string DefinitionNotarizationKeyName()
    {
        return "vrsc::system.notarization.definitionnotarization";
    }

    static std::string EarnedNotarizationKeyName()
    {
        return "vrsc::system.notarization.earnednotarization";
    }

    static std::string AcceptedNotarizationKeyName()
    {
        return "vrsc::system.notarization.acceptednotarization";
    }

    static std::string PriorNotarizationKeyName()
    {
        return "vrsc::system.notarization.prior";
    }

    static std::string LaunchNotarizationKeyName()
    {
        return "vrsc::system.currency.launch.notarization";
    }

    static std::string LaunchPrelaunchKeyName()
    {
        return "vrsc::system.currency.launch.prelaunch";
    }

    static std::string LaunchRefundKeyName()
    {
        return "vrsc::system.currency.launch.refund";
    }

    static std::string LaunchConfirmKeyName()
    {
        return "vrsc::system.currency.launch.confirm";
    }

    static std::string LaunchCompleteKeyName()
    {
        return "vrsc::system.currency.launch.complete";
    }

    static std::string RangeSelectEntropyKeyName()
    {
        return "vrsc::system.notarization.entropy";
    }

    static uint160 NotaryNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 notaryNotarizationKey = CVDXF::GetDataKey(NotaryNotarizationKeyName(), nameSpace);
        return notaryNotarizationKey;
    }

    static uint160 DefinitionNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 definitionNotarizationKey = CVDXF::GetDataKey(DefinitionNotarizationKeyName(), nameSpace);
        return definitionNotarizationKey;
    }

    static uint160 EarnedNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 earnedNotarizationKey = CVDXF::GetDataKey(EarnedNotarizationKeyName(), nameSpace);
        return earnedNotarizationKey;
    }

    static uint160 AcceptedNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 acceptedNotarizationKey = CVDXF::GetDataKey(AcceptedNotarizationKeyName(), nameSpace);
        return acceptedNotarizationKey;
    }

    static uint160 PriorNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 priorNotarizationKey = CVDXF::GetDataKey(PriorNotarizationKeyName(), nameSpace);
        return priorNotarizationKey;
    }

    static uint160 LaunchNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(LaunchNotarizationKeyName(), nameSpace);
        return signatureKey;
    }

    static uint160 LaunchPrelaunchKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(LaunchPrelaunchKeyName(), nameSpace);
        return signatureKey;
    }

    static uint160 LaunchRefundKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(LaunchRefundKeyName(), nameSpace);
        return signatureKey;
    }

    static uint160 LaunchConfirmKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(LaunchConfirmKeyName(), nameSpace);
        return signatureKey;
    }

    static uint160 LaunchCompleteKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(LaunchCompleteKeyName(), nameSpace);
        return signatureKey;
    }

    static uint160 RangeSelectEntropyKey()
    {
        static uint160 nameSpace;
        static uint160 rangeSelectKey = CVDXF::GetDataKey(RangeSelectEntropyKeyName(), nameSpace);
        return rangeSelectKey;
    }

    // if false, *this is unmodifed, otherwise, it is set to the last valid notarization in the requested range
    bool GetLastNotarization(const uint160 &currencyID,
                             int32_t startHeight=0,
                             int32_t endHeight=0,
                             CAddressIndexDbEntry *txOutIdx=nullptr,
                             CTransaction *txOut=nullptr);

    // if false, no matching, unspent notarization found
    bool GetLastUnspentNotarization(const uint160 &currencyID,
                                    uint256 &txIDOut,
                                    int32_t &txOutNum,
                                    CTransaction *txOut=nullptr);

    bool NextNotarizationInfo(const CCurrencyDefinition &sourceSystem,
                              const CCurrencyDefinition &destCurrency,
                              uint32_t lastExportHeight,
                              uint32_t notaHeight,
                              std::vector<CReserveTransfer> &exportTransfers,
                              uint256 &transferHash,
                              CPBaaSNotarization &newNotarization,
                              std::vector<CTxOut> &importOutputs,
                              CCurrencyValueMap &importedCurrency,
                              CCurrencyValueMap &gatewayDepositsUsed,
                              CCurrencyValueMap &spentCurrencyOut,
                              CTransferDestination feeRecipient=CTransferDestination(),
                              bool lastImportBeforeComplete=false,
                              bool coLaunchCheck=true) const;

    static int GetBlocksPerCheckpoint(int heightChange);
    static int GetNumCheckpoints(int heightChange);

    static bool CreateEarnedNotarization(const CRPCChainData &externalSystem,
                                         const CTransferDestination &Proposer,
                                         bool isStake,
                                         CValidationState &state,
                                         std::vector<CTxOut> &txOutputs,
                                         CPBaaSNotarization &notarization);

    bool FindEarnedNotarization(CObjectFinalization &finalization, CAddressIndexDbEntry *pEarnedNotarizationIndex=nullptr) const;
    bool FindEarnedNotarizations(std::vector<CObjectFinalization> &finalization, std::vector<CAddressIndexDbEntry>  *pEarnedNotarizationIndex=nullptr) const;
    static bool FindFinalizedIndexByVDXFKey(const uint160 &notarizationIdxKey,
                                            CObjectFinalization &confirmedFinalization,
                                            CAddressIndexDbEntry &earnedNotarizationIndex,
                                            bool selectLast=false);
    static bool FindFinalizedIndexesByVDXFKey(const uint160 &notarizationIdxKey,
                                              std::vector<CObjectFinalization> &confirmedFinalizations,
                                              std::vector<CAddressIndexDbEntry> &earnedNotarizationIndex);

    bool CheckCrossNotarizationProgression(const CCurrencyDefinition &curDef,
                                           CPBaaSNotarization &priorNotarization,
                                           uint32_t newHeight,
                                           CValidationState &state) const;

    // accepts enough information to build a local accepted notarization transaction
    // miner fees are deferred until an import that uses this notarization, in which case
    // Proposer will get a share of the fees, if they are large enough. any miner,
    // who is mining the bridge can make such a notarization.
    static bool CreateAcceptedNotarization(const CCurrencyDefinition &externalSystem,
                                           const CPBaaSNotarization &notarization,
                                           const CNotaryEvidence &notaryEvidence,
                                           CValidationState &state,
                                           TransactionBuilder &txBuilder);

    static bool ConfirmOrRejectNotarizations(CWallet *pWallet,
                                             const CRPCChainData &externalSystem,
                                             CValidationState &state,
                                             std::vector<TransactionBuilder> &txBuilders,
                                             uint32_t nHeight);

    static std::vector<uint256> SubmitFinalizedNotarizations(const CRPCChainData &externalSystem,
                                                             CValidationState &state);

    bool CheckProof(const uint160 &systemID, const CMMRProof &transactionBlockProof, uint256 checkHash)
    {
        auto proofRootIt = proofRoots.find(systemID);
        if (proofRootIt == proofRoots.end())
        {
            return false;
        }
        return transactionBlockProof.CheckProof(checkHash) == proofRootIt->second.stateRoot;
    }

    CProofRoot GetProofRoot(const uint160 &systemID) const
    {
        auto proofRootIt = proofRoots.find(systemID);
        if (proofRootIt == proofRoots.end())
        {
            return CProofRoot();
        }
        return proofRootIt->second;
    }

    static bool CheckEntropyHashMatch(const uint256 &entropyHash,
                                      const CHashCommitments &commitments,
                                      const uint160 &currencyID,
                                      uint32_t startingHeight,
                                      uint32_t endHeight);

    static std::vector<std::pair<uint32_t, uint32_t>>
        GetBlockCommitmentRanges(uint32_t lastNotarizationHeight, uint32_t currentNotarizationHeight, uint256 entropy);

    void SetLaunchComplete(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_LAUNCH_COMPLETE;
        }
        else
        {
            flags &= ~FLAG_LAUNCH_COMPLETE;
        }
    }

    bool IsLaunchComplete() const
    {
        return flags & FLAG_LAUNCH_COMPLETE;
    }

    void SetSameChain(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_SAME_CHAIN;
        }
        else
        {
            flags &= ~FLAG_SAME_CHAIN;
        }
    }

    bool IsSameChain() const
    {
        return flags & FLAG_SAME_CHAIN;
    }

    bool IsMirror() const
    {
        return flags & FLAG_ACCEPTED_MIRROR;
    }

    // both sets the mirror flag and also transforms the notarization
    // between mirror states. returns false if could not change state to requested.
    bool SetMirror(bool setTrue=true);
    void SetMirrorFlag(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_ACCEPTED_MIRROR;
        }
        else
        {
            flags &= ~FLAG_ACCEPTED_MIRROR;
        }
    }

    bool IsDefinitionNotarization() const
    {
        return flags & FLAG_DEFINITION_NOTARIZATION;
    }

    void SetDefinitionNotarization(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_DEFINITION_NOTARIZATION;
        }
        else
        {
            flags &= ~FLAG_DEFINITION_NOTARIZATION;
        }
    }

    bool IsBlockOneNotarization() const
    {
        return flags & FLAG_BLOCKONE_NOTARIZATION;
    }

    void SetBlockOneNotarization(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_BLOCKONE_NOTARIZATION;
        }
        else
        {
            flags &= ~FLAG_BLOCKONE_NOTARIZATION;
        }
    }

    bool IsPreLaunch() const
    {
        return flags & FLAG_PRE_LAUNCH;
    }

    void SetPreLaunch(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_PRE_LAUNCH;
        }
        else
        {
            flags &= ~FLAG_PRE_LAUNCH;
        }
    }

    bool IsLaunchCleared() const
    {
        return flags & FLAG_START_NOTARIZATION;
    }

    void SetLaunchCleared(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_START_NOTARIZATION;
        }
        else
        {
            flags &= ~FLAG_START_NOTARIZATION;
        }
    }

    bool IsContractUpgrade() const
    {
        return flags & FLAG_CONTRACT_UPGRADE;
    }

    void SetContractUpgrade(const CTransferDestination &contractAddr, bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_CONTRACT_UPGRADE;
            proposer.SetAuxDest(contractAddr, 0);
        }
        else
        {
            if (IsContractUpgrade())
            {
                proposer.EraseAuxDest(0);
                flags &= ~FLAG_CONTRACT_UPGRADE;
            }
        }
    }

    bool IsLaunchConfirmed() const
    {
        return flags & FLAG_LAUNCH_CONFIRMED;
    }

    void SetLaunchConfirmed(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_LAUNCH_CONFIRMED;
        }
        else
        {
            flags &= ~FLAG_LAUNCH_CONFIRMED;
        }
    }

    bool IsRefunding() const
    {
        return flags & FLAG_REFUNDING;
    }

    void SetRefunding(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_REFUNDING;
        }
        else
        {
            flags &= ~FLAG_REFUNDING;
        }
    }

    UniValue ToUniValue() const;
};

class CNotarySystemInfo
{
public:
    enum EVersions
    {
        VERSION_INVALID = 0,
        VERSION_CURRENT = 1,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
    };

    enum ENotarySystemTypes
    {
        TYPE_INVALID = 0,
        TYPE_PBAAS = 1,
        TYPE_ETH = 2,
        TYPE_KOMODO = 3,
    };

    uint32_t notarySystemVersion;
    uint32_t notarySystemType;
    uint32_t height;                            // height of last notarization
    CRPCChainData notaryChain;                  // notary chain information and connectivity for PBaaS protocol
    CPBaaSNotarization lastConfirmedNotarization;

    CNotarySystemInfo(uint32_t NotarySystemType=TYPE_PBAAS, uint32_t NotaryVersion=VERSION_INVALID) : notarySystemVersion(NotaryVersion), notarySystemType(NotarySystemType), height(0) {}

    CNotarySystemInfo(uint32_t Height,
                      const CRPCChainData &NotaryChain,
                      const CPBaaSNotarization &lastNotarization,
                      uint32_t NotarySystemType=TYPE_PBAAS,
                      uint32_t notaryVersion=VERSION_CURRENT) :
                      notarySystemVersion(notaryVersion),
                      notarySystemType(NotarySystemType),
                      height(Height),
                      notaryChain(NotaryChain),
                      lastConfirmedNotarization(lastNotarization)
    {}
};

class CConnectedChains
{
protected:
    CPBaaSMergeMinedChainData *GetChainInfo(uint160 chainID);

public:
    uint32_t lastBlockHeight;
    CBlock lastBlock;
    std::map<uint160, CPBaaSMergeMinedChainData> mergeMinedChains;
    std::multimap<arith_uint256, CPBaaSMergeMinedChainData *> mergeMinedTargets;

    uint32_t nextBlockTime;
    bool nextBlockTimeUpdateRequired;

    std::map<uint160, CUpgradeDescriptor> activeUpgradesByKey;

    LRUCache<uint160, CCurrencyDefinition> currencyDefCache;        // protected by cs_main, so doesn't need sync
    LRUCache<std::tuple<uint160, uint256, bool>, CCoinbaseCurrencyState> currencyStateCache; // cached currency states @ heights + updated flag

    // make earned notarizations for one or more notary chains
    std::map<uint160, CNotarySystemInfo> notarySystems;
    std::set<uint160> idsToRevoke;

    CCurrencyDefinition thisChain;
    bool readyToStart;
    std::vector<CNodeData> defaultPeerNodes;    // updated by notarizations
    std::vector<CTxOut> latestMiningOutputs;    // accessible from all merge miners - can be invalid

    int32_t earnedNotarizationHeight;           // zero or the height of one or more potential submissions
    CBlock earnedNotarizationBlock;
    int32_t earnedNotarizationIndex;            // index of earned notarization in block

    bool dirty;
    bool dirtygbt;
    bool lastSubmissionFailed;                  // if we submit a failed block, make another

    uint32_t saveBits;

    std::map<arith_uint256, CBlockHeader> qualifiedHeaders;

    CCriticalSection cs_mergemining;
    CSemaphore sem_submitthread;

    CConnectedChains() :
        currencyDefCache(3000, 0.1F, false),
        currencyStateCache(1000, 0.1F, false),
        lastBlockHeight(0),
        readyToStart(false),
        earnedNotarizationHeight(0),
        earnedNotarizationIndex(0),
        dirty(false),
        dirtygbt(false),
        saveBits(0),
        lastSubmissionFailed(false),
        sem_submitthread(0),
        nextBlockTime(0),
        nextBlockTimeUpdateRequired(0) {}

    uint32_t SetNextBlockTime(uint32_t NextBlockTime);
    uint32_t GetNextBlockTime(const CBlockIndex *pindexPrev);

    arith_uint256 LowestTarget()
    {
        if (mergeMinedTargets.size())
        {
            return mergeMinedTargets.begin()->first;
        }
        else
        {
            return arith_uint256(0);
        }
    }

    void SubmissionThread();
    static void SubmissionThreadStub();
    std::vector<std::pair<std::string, UniValue>> SubmitQualifiedBlocks();

    void QueueNewBlockHeader(CBlockHeader &bh);
    void SetRevokeID(const CIdentityID &idID);
    CIdentityID NextRevokeID();
    void QueueEarnedNotarization(CBlock &blk, int32_t txIndex, int32_t height);
    void CheckImports();
    void SignAndCommitImportTransactions(const CTransaction &lastImportTx, const std::vector<CTransaction> &transactions);
    // send new imports from this chain to the specified chain, which generally will be the notary chain
    void ProcessLocalImports();

    // return the last block if one is cached
    bool GetLastBlock(CBlock &block, uint32_t height);
    void SetLastBlock(CBlock &block, uint32_t height);
    bool AddMergedBlock(CPBaaSMergeMinedChainData &blkData);
    bool RemoveMergedBlock(uint160 chainID);
    bool GetChainInfo(uint160 chainID, CRPCChainData &rpcChainData);
    void PruneOldChains(uint32_t pruneBefore);
    uint32_t CombineBlocks(CBlockHeader &bh);

    // returns false if destinations are empty or first is not either pubkey or pubkeyhash
    bool SetLatestMiningOutputs(const std::vector<CTxOut> &minerOutputs);
    void AggregateChainTransfers(const CTransferDestination &feeRecipient, uint32_t nHeight);
    CCurrencyDefinition GetCachedCurrency(const uint160 &currencyID);
    std::string GetFriendlyCurrencyName(const uint160 &currencyID, bool addVerus=false);
    std::string GetFriendlyIdentityName(const CIdentity &identity, bool addVerus=false);
    std::string GetFriendlyIdentityName(const std::string &name, const uint160 &parentCurrencyID, bool addVerus=false);
    CCurrencyDefinition UpdateCachedCurrency(const CCurrencyDefinition &currentCurrency, uint32_t height);

    bool GetLastImport(const uint160 &currencyID,
                       CTransaction &lastImport,
                       int32_t &outputNum);

    bool GetLastSourceImport(const uint160 &currencyID,
                             CTransaction &lastImport,
                             int32_t &outputNum);

    bool GetUnspentSystemExports(const CCoinsViewCache &view,
                                 const uint160 systemID,
                                 std::vector<std::pair<int, CInputDescriptor>> &exportOutputs);

    bool GetUnspentCurrencyExports(const CCoinsViewCache &view,
                                   const uint160 currencyID,
                                   std::vector<std::pair<int, CInputDescriptor>> &exportOutputs);

    // get the exports to a specific system on this chain from a specific height up to a specific height
    bool GetSystemExports(const uint160 &systemID,                                 // transactions exported to system
                          std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> &exports,
                          uint32_t fromHeight,
                          uint32_t toHeight,
                          bool withProofs=false);

    // gets both the launch notarization and its partial transaction proof if launching to a new system
    bool GetLaunchNotarization(const CCurrencyDefinition &curDef,
                               std::pair<CInputDescriptor, CPartialTransactionProof> &notarizationTx,
                               CPBaaSNotarization &launchNotarization,
                               CPBaaSNotarization &notaryNotarization);

    // gets the definition notarization if it was defined on this system
    bool GetDefinitionNotarization(const CCurrencyDefinition &curDef,
                                   CInputDescriptor &notarizationRef,
                                   CPBaaSNotarization &definitionNotarization);

    // gets the definition notarization if it was defined on this system
    bool GetDefinitionNotarization(const CCurrencyDefinition &curDef,
                                   std::pair<CInputDescriptor, CPartialTransactionProof> &notarizationTx,
                                   CPBaaSNotarization &definitionNotarization,
                                   CPBaaSNotarization &notaryNotarization);

    // get the exports to a specific system on this chain from a specific height up to a specific height
    bool GetCurrencyExports(const uint160 &currencyID,                             // transactions exported to system
                            std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> &exports,
                            uint32_t fromHeight,
                            uint32_t toHeight);

    // given exports on this chain, provide the proofs of those export outputs
    bool GetExportProofs(uint32_t height,
                         std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports);

    static bool GetReserveDeposits(const uint160 &currencyID, const CCoinsViewCache &view, std::vector<CInputDescriptor> &reserveDeposits);
    static bool GetUnspentByIndex(const uint160 &indexID, std::vector<std::pair<CInputDescriptor, uint32_t>> &unspentOutptus);

    static bool IsValidCurrencyDefinitionImport(const CCurrencyDefinition &sourceSystemDef,
                                                const CCurrencyDefinition &destSystemDef,
                                                const CCurrencyDefinition &importingCurrency,
                                                uint32_t height);

    static bool IsValidIdentityDefinitionImport(const CCurrencyDefinition &sourceSystemDef,
                                                const CCurrencyDefinition &destSystemDef,
                                                const CIdentity &importingIdentity,
                                                uint32_t height);

    static bool CurrencyExportStatus(const CCurrencyValueMap &totalExports,
                                     const uint160 &sourceSystemID,
                                     const uint160 &destSystemID,
                                     CCurrencyValueMap &newReserveDeposits,
                                     CCurrencyValueMap &exportBurn);

    static bool CurrencyImportStatus(const CCurrencyValueMap &totalExports,
                                     const uint160 &sourceSystemID,
                                     const uint160 &destSystemID,
                                     CCurrencyValueMap &newReserveDeposits,
                                     CCurrencyValueMap &exportBurn);

    static std::vector<ChainTransferData> CalcTxInputs(const CCurrencyDefinition &_curDef,
                                                        bool &isClearLaunchExport,
                                                        uint32_t sinceHeight,
                                                        uint32_t &addHeight,
                                                        uint32_t &nextHeight,
                                                        uint32_t untilHeight,
                                                        uint32_t nHeight,
                                                        int &curIDExports,
                                                        int &curCurrencyExports,
                                                        const std::multimap<uint32_t, ChainTransferData> &_txInputs);

    bool CreateNextExport(const CCurrencyDefinition &_curDef,
                          const std::multimap<uint32_t, ChainTransferData> &txInputs,
                          const std::vector<CInputDescriptor> &priorExports,
                          const CTransferDestination &feeRecipient,
                          uint32_t sinceHeight,
                          uint32_t curHeight,
                          int32_t inputStartNum,
                          int32_t &inputsConsumed,
                          std::vector<CTxOut> &exportOutputs,
                          std::vector<CReserveTransfer> &exportTransfers,
                          const CPBaaSNotarization &lastNotarization,
                          const CUTXORef &lastNotarizationUTXO,
                          CPBaaSNotarization &newNotarization,
                          int &newNotarizationOutNum,
                          bool onlyIfRequired=true);

    // create a set of imports on the current chain for a set of exports
    bool CreateLatestImports(const CCurrencyDefinition &sourceSystemDef,                            // transactions imported from system
                             const CUTXORef &confirmedSourceNotarization,
                             const std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports,
                             std::map<uint160, std::vector<std::pair<int, CTransaction>>> &newImports);

    // returns the first notary system, if there is more than one
    const CRPCChainData &FirstNotaryChain() const
    {
        if (notarySystems.size())
        {
            return notarySystems.begin()->second.notaryChain;
        }
        static CRPCChainData invalidChain;
        return invalidChain;
    }

    // returns the map of notary systems
    const std::map<uint160, CNotarySystemInfo> &NotarySystems() const
    {
        return notarySystems;
    }

    CProofRoot ConfirmedNotaryChainRoot();
    CProofRoot FinalizedChainRoot();
    uint32_t NotaryChainHeight();

    CCurrencyDefinition &ThisChain()
    {
        return thisChain;
    }

    int GetThisChainPort() const;

    // start with existing currency state and currency definitino and add
    // all pre-launch activity to bring them both up to date
    CCoinbaseCurrencyState AddPrelaunchConversions(CCurrencyDefinition &curDef,
                                                   const CCoinbaseCurrencyState &currencyState,
                                                   int32_t fromHeight,
                                                   int32_t height,
                                                   int32_t curDefHeight,
                                                   const std::vector<CReserveTransfer> &extraConversions=std::vector<CReserveTransfer>());

    CCoinbaseCurrencyState AddPendingConversions(CCurrencyDefinition &curDef,
                                                 const CPBaaSNotarization &currencyState,
                                                 int32_t fromHeight,
                                                 int32_t height,
                                                 int32_t curDefHeight,
                                                 const std::vector<CReserveTransfer> &extraConversions=std::vector<CReserveTransfer>());

    CCoinbaseCurrencyState GetCurrencyState(int32_t height, bool loadPendingTransfers=true);     // gets this chain's native currency state by block height
    CCoinbaseCurrencyState GetCurrencyState(CCurrencyDefinition &curDef, int32_t height, int32_t curDefHeight=0, bool loadPendingTransfers=true); // gets currency state
    CCoinbaseCurrencyState GetCurrencyState(const uint160 &currencyID, int32_t height, bool loadPendingTransfers=true); // gets currency state

    CCurrencyDefinition GetDestinationCurrency(const CReserveTransfer &rt) const;

    uint32_t ParseVersion(const std::string &versionStr) const;
    uint32_t GetVerusVersion() const;
    bool CheckVerusPBaaSAvailable(UniValue &chainInfo, UniValue &chainDef);
    bool CheckVerusPBaaSAvailable();      // may use RPC to call Verus
    bool IsVerusPBaaSAvailable();
    bool IsNotaryAvailable(bool callToCheck=false);
    bool ConfigureEthBridge(bool callToCheck=false);
    void CheckOracleUpgrades();
    bool IsUpgradeActive(const uint160 &upgradeID, uint32_t blockHeight=UINT32_MAX, uint32_t blockTime=UINT32_MAX) const;
    uint32_t GetZeroViaHeight(bool getVerusHeight) const;
    uint32_t GetOptimizedETHProofHeight(bool getVerusHeight=false) const;
    bool ShouldOptimizeETHProof() const;
    bool CheckZeroViaOnlyPostLaunch(uint32_t height) const;
    uint32_t IncludePostLaunchFeeHeight(bool getVerusHeight) const;
    bool IncludePostLaunchFees(uint32_t height) const;
    bool CheckClearConvert(uint32_t height) const;
    uint32_t StrictCheckIDExportHeight(bool getVerusHeight) const;
    bool StrictCheckIDExport(uint32_t height) const;
    uint32_t DiscernBlockOneLaunchInfoHeight(bool getVerusHeight) const;
    bool DiscernBlockOneLaunchInfo(uint32_t height) const;
    uint32_t AutoArbitrageEnabledHeight(bool getVerusHeight) const;
    bool AutoArbitrageEnabled(uint32_t height) const;
    uint32_t vARRRUpdateHeight(bool getVerusHeight) const;
    bool vARRRUpdateEnabled(uint32_t height) const;
    uint160 vARRRChainID() const;
    uint160 vDEXChainID() const;
    uint160 KaijuCurrencyID() const;
    uint160 Chips777TestnetChainID() const;
    uint160 ChipsChainID() const;
    bool ForceIdentityUpgrade(uint32_t height) const;
    bool ForceIdentityUnlock(uint32_t height) const;
    bool IdentityLockOverride(const CIdentity &identity, uint32_t height) const;
    bool DoPreconvertReserveTransferPrecheck(uint32_t height) const;
    bool DoImportPreconvertReserveTransferPrecheck(uint32_t height) const;
    bool IsEnhancedDustCheck(uint32_t height) const;
    bool IsEnhancedNotarizationOrder(uint32_t height) const;
    bool CrossChainPBaaSProofFix(const uint160 &sysID, uint32_t height) const;
    bool BlockOneIDUpgrade() const;
    bool IsPromoteExchangeRate(uint32_t height) const;
    int CheckPastRealTime(uint32_t nTime, int64_t height=0) const;
    bool IsUpgrade01Active(int64_t height=0) const;
    bool IsUpgrade02Active(int64_t height=0) const;
    bool IsPBaaSRefundFixActive(int64_t height=0) const;
    bool IsPBaaSNotarizationFix01Active(int64_t height) const;

    uint32_t GetChainBranchId(const uint160 &sysID, int nHeight, const Consensus::Params& params) const;

    std::vector<CCurrencyDefinition> GetMergeMinedChains()
    {
        std::vector<CCurrencyDefinition> ret;
        LOCK(cs_mergemining);
        for (auto &chain : mergeMinedChains)
        {
            ret.push_back(chain.second.chainDefinition);
        }
        return ret;
    }

    bool GetNotaryCurrencies(const CRPCChainData notaryChain,
                             const std::set<uint160> &currencyIDs,
                             std::map<uint160, std::pair<CCurrencyDefinition,CPBaaSNotarization>> &currencyDefs,
                             uint32_t untilHeight);

    bool GetNotaryIDs(const CRPCChainData notaryChain,
                      const CCurrencyDefinition &pbaasChain,
                      const std::set<uint160> &idIDs,
                      std::map<uint160,CIdentity> &identities,
                      uint32_t untilHeight);

    static std::string UpgradeDataKeyName()
    {
        return "vrsc::system.upgradedata";
    }

    static uint160 UpgradeDataKey(const uint160 &systemID)
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(UpgradeDataKeyName(), nameSpace);
        return CCrossChainRPCData::GetConditionID(key, systemID);
    }

    static std::string OptionalPBaaSUpgradeKeyName()
    {
        return "vrsc::system.upgradedata.optionalpbaasupgrade";
    }

    static uint160 OptionalPBaaSUpgradeKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(OptionalPBaaSUpgradeKeyName(), nameSpace);
        return key;
    }

    static std::string DisableDeFiKeyName()
    {
        return "vrsc::system.upgradedata.disabledefi";
    }

    static uint160 DisableDeFiKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(DisableDeFiKeyName(), nameSpace);
        return key;
    }

    static std::string EnableOptimizedETHProofName()
    {
        return "vrsc::system.upgradedata.enableoptimizedethproof";
    }

    static uint160 EnableOptimizedETHProofKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(EnableOptimizedETHProofName(), nameSpace);
        return key;
    }

    static std::string ResetNotarizationModuloKeyName()
    {
        return "vrsc::system.upgradedata.resetnotarizationmodulo";
    }

    static uint160 ResetNotarizationModuloKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(ResetNotarizationModuloKeyName(), nameSpace);
        return key;
    }

    static std::string ForceIdentityUpgradeKeyName()
    {
        return "vrsc::system.upgradedata.forceidentityupgrade";
    }

    static uint160 ForceIdentityUpgradeKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(ForceIdentityUpgradeKeyName(), nameSpace);
        return key;
    }

    static std::string ForceIdentityUnlockKeyName()
    {
        return "vrsc::system.upgradedata.forceidentityunlock";
    }

    static uint160 ForceIdentityUnlockKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(ForceIdentityUnlockKeyName(), nameSpace);
        return key;
    }

    static std::string PreconvertReserveTransferPrecheckKeyName()
    {
        return "vrsc::system.upgradedata.preconvertreservetransferprecheck";
    }

    static uint160 PreconvertReserveTransferPrecheckKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(PreconvertReserveTransferPrecheckKeyName(), nameSpace);
        return key;
    }

    static std::string ImportPreconvertReserveTransferPrecheckKeyName()
    {
        return "vrsc::system.upgradedata.importpreconvertreservetransferprecheck";
    }

    static uint160 ImportPreconvertReserveTransferPrecheckKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(ImportPreconvertReserveTransferPrecheckKeyName(), nameSpace);
        return key;
    }

    static std::string DisablePBaaSCrossChainKeyName()
    {
        return "vrsc::system.upgradedata.disablepbaascrosschain";
    }

    static uint160 DisablePBaaSCrossChainKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(DisablePBaaSCrossChainKeyName(), nameSpace);
        return key;
    }

    static std::string MagicNumberFixKeyName()
    {
        return "vrsc::system.upgradedata.magicnumberfix";
    }

    static uint160 MagicNumberFixKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(MagicNumberFixKeyName(), nameSpace);
        return key;
    }

    static std::string DisableGatewayCrossChainKeyName()
    {
        return "vrsc::system.upgradedata.disablegatewaycrosschain";
    }

    static uint160 DisableGatewayCrossChainKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(DisableGatewayCrossChainKeyName(), nameSpace);
        return key;
    }

    static std::string PBaaSUpgradeKeyName()
    {
        return "vrsc::system.upgradedata.pbaasupgrade";
    }

    static uint160 PBaaSUpgradeKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(PBaaSUpgradeKeyName(), nameSpace);
        return key;
    }

    static std::string PBaaSCrossChainProofUpgradeKeyName()
    {
        return "vrsc::system.upgradedata.pbaascrosschainproofupgrade";
    }

    static uint160 PBaaSCrossChainProofUpgradeKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF_Data::GetDataKey(PBaaSCrossChainProofUpgradeKeyName(), nameSpace);
        return key;
    }
};

template <typename TOBJ>
CTxOut MakeCC1of1Vout(uint8_t evalcode, CAmount nValue, CPubKey pk, std::vector<CTxDestination> vDest, const TOBJ &obj)
{
    assert(vDest.size() < 256);

    CTxOut vout;
    CC *payoutCond = MakeCCcond1(evalcode, pk);
    vout = CTxOut(nValue, CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<std::vector<unsigned char>> vvch({::AsVector((const TOBJ)obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, (uint8_t)(vDest.size()), vDest, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

template <typename TOBJ>
CTxOut MakeCC1ofAnyVout(uint8_t evalcode, CAmount nValue, std::vector<CTxDestination> vDest, const TOBJ &obj, const CPubKey &pk=CPubKey())
{
    // if pk is valid, we will make sure that it is one of the signature options on this CC
    if (pk.IsValid())
    {
        CCcontract_info C;
        CCcontract_info *cp;
        cp = CCinit(&C, evalcode);
        int i;
        bool addPubKey = false;
        for (i = 0; i < vDest.size(); i++)
        {
            CPubKey oneKey(boost::apply_visitor<GetPubKeyForPubKey>(GetPubKeyForPubKey(), vDest[i]));
            if ((oneKey.IsValid() && oneKey == pk) || CKeyID(GetDestinationID(vDest[i])) == pk.GetID())
            {
                // found, so don't add
                break;
            }
        }
        // if not found, add the pubkey
        if (i >= vDest.size())
        {
            vDest.push_back(CTxDestination(pk));
        }
    }

    CTxOut vout;
    CC *payoutCond = MakeCCcondAny(evalcode, vDest);
    vout = CTxOut(nValue, CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<std::vector<unsigned char>> vvch({::AsVector((const TOBJ)obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 0, (uint8_t)(vDest.size()), vDest, vvch);

    for (auto dest : vDest)
    {
        CPubKey oneKey(boost::apply_visitor<GetPubKeyForPubKey>(GetPubKeyForPubKey(), dest));
        std::vector<unsigned char> bytes = GetDestinationBytes(dest);
        if ((!oneKey.IsValid() && bytes.size() != 20) || (bytes.size() != 33 && bytes.size() != 20))
        {
            printf("Invalid destination %s\n", EncodeDestination(dest).c_str());
        }
    }

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

template <typename TOBJ>
CTxOut MakeCC1of2Vout(uint8_t evalcode, CAmount nValue, CPubKey pk1, CPubKey pk2, const TOBJ &obj)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond1of2(evalcode, pk1, pk2);
    vout = CTxOut(nValue,CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<CTxDestination> vdest({CTxDestination(pk1), CTxDestination(pk2)});
    std::vector<std::vector<unsigned char>> vvch({::AsVector((const TOBJ)obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, 2, vdest, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

template <typename TOBJ>
CTxOut MakeCC1of2Vout(uint8_t evalcode, CAmount nValue, CPubKey pk1, CPubKey pk2, std::vector<CTxDestination> vDest, const TOBJ &obj)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond1of2(evalcode, pk1, pk2);
    vout = CTxOut(nValue,CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<CPubKey> vpk({pk1, pk2});
    std::vector<std::vector<unsigned char>> vvch({::AsVector((const TOBJ)obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, (uint8_t)(vDest.size()), vDest, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

bool IsVerusActive();
bool IsVerusMainnetActive();

bool IsValidExportCurrency(const CCurrencyDefinition &systemDest, const uint160 &exportCurrencyID, uint32_t height);
std::set<uint160> BaseBridgeCurrencies(const CCurrencyDefinition &systemDest, uint32_t height, bool feeOnly=false);
std::set<uint160> ValidExportCurrencies(const CCurrencyDefinition &systemDest, uint32_t height);


// used to export coins from one chain to another, if they are not native, they are represented on the other
// chain as tokens
bool ValidateCrossChainExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool PrecheckCrossChainExport(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool IsCrossChainExportInput(const CScript &scriptSig);

// used to validate import of coins from one chain to another. if they are not native and are supported,
// they are represented o the chain as tokens
bool ValidateCrossChainImport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool PrecheckCrossChainImport(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool IsCrossChainImportInput(const CScript &scriptSig);

bool ValidateFinalizeExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsFinalizeExportInput(const CScript &scriptSig);
bool PreCheckFinalizeExport(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);

bool ValidateNotaryEvidence(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsNotaryEvidenceInput(const CScript &scriptSig);

// used as a proxy token output for a reserve currency on its fractional reserve chain
bool ValidateReserveOutput(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsReserveOutputInput(const CScript &scriptSig);

// used to transfer a reserve currency between chains
bool ValidateReserveTransfer(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsReserveTransferInput(const CScript &scriptSig);

// used as exchange tokens between reserves and fractional reserves
bool ValidateReserveExchange(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsReserveExchangeInput(const CScript &scriptSig);

// used to deposit reserves into a reserve UTXO set
bool ValidateReserveDeposit(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsReserveDepositInput(const CScript &scriptSig);

uint160 ValidateCurrencyName(std::string currencyStr, bool ensureCurrencyValid=false, CCurrencyDefinition *pCurrencyDef=NULL);
bool ValidateCurrencyDefinition(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool PrecheckCurrencyDefinition(const CTransaction &spendingTx, int32_t outNum, CValidationState &state, uint32_t height);
bool IsCurrencyDefinitionInput(const CScript &scriptSig);

bool ValidateCurrencyState(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsCurrencyStateInput(const CScript &scriptSig);

bool SetPeerNodes(const UniValue &nodes);
bool SetThisChain(const UniValue &chainDefinition, CCurrencyDefinition *retDef);

bool EntropyCoinFlip(const uint160 &conditionID, uint32_t nHeight);
uint256 EntropyHashFromHeight(const uint160 &conditionID, uint32_t nHeight, const uint160 &extraEntropy=uint160());

extern CConnectedChains ConnectedChains;
extern uint160 ASSETCHAINS_CHAINID;
extern CCriticalSection smartTransactionCS;

CCoinbaseCurrencyState GetInitialCurrencyState(const CCurrencyDefinition &chainDef);

CCurrencyDefinition ValidateNewUnivalueCurrencyDefinition(const UniValue &uniObj,
                                                          uint32_t height,
                                                          const uint160 systemID,
                                                          std::map<uint160, std::string> &requiredDefinitions,
                                                          bool checkMempool=true);

bool ImportHasAdequateFees(const CTransaction &tx,
                           int32_t outNum,
                           const CCurrencyDefinition &importingToDef,
                           const CCrossChainImport &cci,
                           const CCrossChainExport &ccx,
                           const CPBaaSNotarization &notarization,
                           const std::vector<CReserveTransfer> &reserveTransfers,
                           CValidationState &state,
                           uint32_t height);

#endif
