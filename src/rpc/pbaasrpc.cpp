// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2019 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "core_io.h"
#ifdef ENABLE_MINING
#include "crypto/equihash.h"
#endif
#include "init.h"
#include "main.h"
#include "metrics.h"
#include "miner.h"
#include "net.h"
#include "pow.h"
#include "rpc/server.h"
#include "txmempool.h"
#include "util.h"
#include "validationinterface.h"
#include "wallet/wallet.h"
#include "asyncrpcqueue.h"
#include "asyncrpcoperation.h"
#include "wallet/asyncrpcoperation_sendmany.h"
#include "timedata.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include <univalue.h>

#include "rpc/pbaasrpc.h"
#include "coincontrol.h"

#include <librustzcash.h>
#include "transaction_builder.h"

using namespace std;

extern uint32_t ASSETCHAINS_ALGO;
extern int32_t ASSETCHAINS_EQUIHASH, ASSETCHAINS_LWMAPOS;
extern char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN];
extern uint32_t ASSETCHAINS_STARTING_DIFF;
extern uint64_t ASSETCHAINS_STAKED;
extern int32_t KOMODO_MININGTHREADS;
extern bool VERUS_MINTBLOCKS;
extern uint8_t NOTARY_PUBKEY33[33];
extern uint160 ASSETCHAINS_CHAINID;
extern uint160 VERUS_CHAINID;
extern std::string VERUS_CHAINNAME;
extern int32_t USE_EXTERNAL_PUBKEY;
extern std::string NOTARY_PUBKEY;

#define _ASSETCHAINS_TIMELOCKOFF 0xffffffffffffffff
extern uint64_t ASSETCHAINS_TIMELOCKGTE, ASSETCHAINS_TIMEUNLOCKFROM, ASSETCHAINS_TIMEUNLOCKTO;
extern int64_t ASSETCHAINS_SUPPLY;
extern int64_t ASSETCHAINS_ISSUANCE;
extern uint64_t ASSETCHAINS_REWARD[3], ASSETCHAINS_DECAY[3], ASSETCHAINS_HALVING[3], ASSETCHAINS_ENDSUBSIDY[3], ASSETCHAINS_ERAOPTIONS[3];
extern int32_t PBAAS_STARTBLOCK, PBAAS_ENDBLOCK, ASSETCHAINS_LWMAPOS;
extern uint32_t ASSETCHAINS_ALGO, ASSETCHAINS_VERUSHASH, ASSETCHAINS_LASTERA;
extern std::string VERUS_CHAINNAME;


arith_uint256 komodo_PoWtarget(int32_t *percPoSp,arith_uint256 target,int32_t height,int32_t goalperc);

std::set<uint160> ClosedPBaaSChains({});

UniValue getminingdistribution(const UniValue& params, bool fHelp);
UniValue signdata(const UniValue& params, bool fHelp);

// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    std::string strRejectReason = state.GetRejectReason();
    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
    if (state.IsInvalid())
    {
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {};

protected:
    virtual void BlockChecked(const CBlock& block, const CValidationState& stateIn) {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    };
};

bool GetCurrencyDefinition(const uint160 &chainID, CCurrencyDefinition &chainDef, int32_t *pDefHeight, bool checkMempool, bool notarizationCheck, CUTXORef *pUTXO, std::vector<CNodeData> *pGoodNodes)
{
    static bool isVerusActive = IsVerusActive();
    static bool thisChainLoaded = false;
    std::vector<CNodeData> _goodNodes;
    std::vector<CNodeData> &goodNodes = pGoodNodes ? *pGoodNodes : _goodNodes;

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
    uint160 lookupKey = CCrossChainRPCData::GetConditionID(chainID, CCurrencyDefinition::CurrencyDefinitionKey());

    std::vector<std::pair<uint160, int>> addresses = {{lookupKey, CScript::P2IDX}};
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > results;
    CCurrencyDefinition foundDef;

    if (!ClosedPBaaSChains.count(chainID) && GetAddressUnspent(lookupKey, CScript::P2IDX, unspentOutputs) && unspentOutputs.size())
    {
        for (auto &currencyDefOut : unspentOutputs)
        {
            if ((foundDef = CCurrencyDefinition(currencyDefOut.second.script)).IsValid())
            {
                chainDef = foundDef;
                if (pDefHeight)
                {
                    *pDefHeight = currencyDefOut.second.blockHeight;
                }
                if (pUTXO)
                {
                    *pUTXO = CUTXORef(currencyDefOut.first.txhash, currencyDefOut.first.index);
                }
                if (pGoodNodes)
                {
                    std::vector<CNodeData> nodes;
                    CTransaction nTx;
                    uint256 blockHash;
                    if (!myGetTransaction(currencyDefOut.first.txhash, nTx, blockHash))
                    {
                        LogPrintf("%s: Cannot load currency definition transaction, txid %s\n", __func__, currencyDefOut.first.txhash.GetHex().c_str());
                        continue;
                    }
                    for (int i = currencyDefOut.first.index + 1; i < nTx.vout.size(); i++)
                    {
                        COptCCParams p;
                        CPBaaSNotarization pbn;

                        if (nTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                            p.IsValid() &&
                            (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                            p.vData.size() &&
                            (pbn = CPBaaSNotarization(p.vData[0])).IsValid() &&
                            pbn.currencyID == chainID)
                        {
                            goodNodes = pbn.nodes;
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
    else if (checkMempool && !ClosedPBaaSChains.count(chainID) && mempool.getAddressIndex(addresses, results) && results.size())
    {
        std::set<COutPoint> spentInMempool;
        for (auto &currencyDefOut : mempool.FilterUnspent(results, spentInMempool))
        {
            CTransaction tx;

            if (mempool.lookup(currencyDefOut.first.txhash, tx) &&
                (foundDef = CCurrencyDefinition(tx.vout[currencyDefOut.first.index].scriptPubKey)).IsValid())
            {
                chainDef = foundDef;
                if (pDefHeight)
                {
                    *pDefHeight = chainActive.Height() + 1;
                }
                if (pUTXO)
                {
                    *pUTXO = CUTXORef(currencyDefOut.first.txhash, currencyDefOut.first.index);
                }
                if (pGoodNodes)
                {
                    std::vector<CNodeData> nodes;
                    uint256 blockHash;
                    for (int i = currencyDefOut.first.index + 1; i < tx.vout.size(); i++)
                    {
                        COptCCParams p;
                        CPBaaSNotarization pbn;

                        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                            p.IsValid() &&
                            (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                            p.vData.size() &&
                            (pbn = CPBaaSNotarization(p.vData[0])).IsValid() &&
                            pbn.currencyID == chainID)
                        {
                            goodNodes = pbn.nodes;
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
    if (chainID == ASSETCHAINS_CHAINID && foundDef.IsValid())
    {
        if (pGoodNodes)
        {
            auto extraNodes = GetGoodNodes();
            goodNodes.insert(goodNodes.end(), extraNodes.begin(), extraNodes.end());
        }
        if (!thisChainLoaded)
        {
            thisChainLoaded = true;
            ConnectedChains.ThisChain() = foundDef;
            ConnectedChains.UpdateCachedCurrency(foundDef, pDefHeight ? *pDefHeight : chainActive.Height());
        }
    }
    else if (foundDef.IsValid())
    {
        // add to nodes with last confirmed notarization nodes
        CChainNotarizationData cnd;
        if (notarizationCheck && GetNotarizationData(chainID, cnd) && cnd.IsConfirmed())
        {
            auto extraNodes = cnd.vtx[cnd.lastConfirmed].second.nodes;
            goodNodes.insert(goodNodes.end(), extraNodes.begin(), extraNodes.end());
        }
    }
    else
    {
        if (chainID == ASSETCHAINS_CHAINID && (thisChainLoaded || chainActive.Height() < 1 || isVerusActive))
        {
            chainDef = ConnectedChains.ThisChain();
            if (pDefHeight)
            {
                *pDefHeight = 0;
            }
            if (pUTXO)
            {
                *pUTXO = CUTXORef();
            }
            if (pGoodNodes)
            {
                goodNodes = GetGoodNodes();
            }
            return true;
        }
        else if (!isVerusActive && chainActive.Height() == 0)
        {
            if (ConnectedChains.FirstNotaryChain().IsValid() && (chainID == ConnectedChains.FirstNotaryChain().chainDefinition.GetID()))
            {
                chainDef = ConnectedChains.FirstNotaryChain().chainDefinition;
                if (pDefHeight)
                {
                    *pDefHeight = 0;
                }
                if (pUTXO)
                {
                    *pUTXO = CUTXORef();
                }
                return true;
            }
        }

    }
    return foundDef.IsValid();
}

bool GetCurrencyDefinition(const std::string &name, CCurrencyDefinition &chainDef)
{
    return GetCurrencyDefinition(CCrossChainRPCData::GetID(name), chainDef);
}

CTxDestination ValidateDestination(const std::string &destStr)
{
    CTxDestination destination = DecodeDestination(destStr);
    if (destination.which() == COptCCParams::ADDRTYPE_ID)
    {
        AssertLockHeld(cs_main);
        if (!CIdentity::LookupIdentity(GetDestinationID(destination)).IsValid())
        {
            return CTxDestination();
        }
    }
    return destination;
}

CIdentity ValidateIdentityParameter(const std::string &idStr)
{
    CIdentity retVal;
    CTxDestination destination = DecodeDestination(idStr);
    if (destination.which() == COptCCParams::ADDRTYPE_ID)
    {
        AssertLockHeld(cs_main);
        retVal = CIdentity::LookupIdentity(GetDestinationID(destination));
    }
    return retVal;
}

// set default peer nodes in the current connected chains
bool SetPeerNodes(const UniValue &nodes)
{
    if (mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0)
    {
        printf("%s: Ignoring seednodes due to nodes specified in \"-connect\" parameter\n", __func__);
        LogPrintf("%s: Ignoring seednodes due to nodes specified in \"-connect\" parameter\n", __func__);
        std::vector<std::string> connectNodes = mapMultiArgs["-connect"];
        for (int i = 0; i < connectNodes.size(); i++)
        {
            CNodeData oneNode = CNodeData(connectNodes[i], "");
            if (oneNode.networkAddress != "")
            {
                ConnectedChains.defaultPeerNodes.push_back(oneNode);
            }
        }
    }
    else
    {
        if (!nodes.isArray() || nodes.size() == 0)
        {
            return false;
        }

        LOCK(ConnectedChains.cs_mergemining);
        ConnectedChains.defaultPeerNodes.clear();

        for (int i = 0; i < nodes.size(); i++)
        {
            CNodeData oneNode(nodes[i]);
            if (oneNode.networkAddress != "")
            {
                ConnectedChains.defaultPeerNodes.push_back(oneNode);
            }
        }

        std::vector<std::string> seedNodes = mapMultiArgs["-seednode"];
        for (int i = 0; i < seedNodes.size(); i++)
        {
            CNodeData oneNode = CNodeData(seedNodes[i], "");
            if (oneNode.networkAddress != "")
            {
                ConnectedChains.defaultPeerNodes.push_back(oneNode);
            }
        }
    }

    std::vector<std::string> addNodes = mapMultiArgs["-addnode"];
    for (int i = 0; i < addNodes.size(); i++)
    {
        CNodeData oneNode = CNodeData(addNodes[i], "");
        if (oneNode.networkAddress != "")
        {
            ConnectedChains.defaultPeerNodes.push_back(oneNode);
        }
    }

    // set all command line parameters into mapArgs from chain definition
    vector<string> nodeStrs;

    if (!GetBoolArg("-forcednsseed", false) && !(mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0))
    {
        for (auto node : ConnectedChains.defaultPeerNodes)
        {
            nodeStrs.push_back(node.networkAddress);
        }
    }

    if (!(mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0))
    {
        mapMultiArgs["-seednode"] = nodeStrs;
    }

    for (auto &oneNode : nodeStrs)
    {
        AddOneShot(oneNode);
    }

    if (int port = ConnectedChains.GetThisChainPort())
    {
        mapArgs["-port"] = to_string(port);
    }
    return true;
}

// adds the chain definition for this chain and nodes as well
// this also sets up the notarization chain, if there is one
bool SetThisChain(const UniValue &chainDefinition, CCurrencyDefinition *retDef)
{
    ConnectedChains.ThisChain() = CCurrencyDefinition(chainDefinition);
    //printf("%s: setting current chain to: %s\nfrom univalue: %s\n", __func__, ConnectedChains.ThisChain().ToUniValue().write(1,2).c_str(), chainDefinition.write(1,2).c_str());

    if (!ConnectedChains.ThisChain().IsValid())
    {
        return false;
    }
    if (retDef)
    {
        *retDef = ConnectedChains.ThisChain();
    }
    SetPeerNodes(find_value(chainDefinition, "nodes"));

    memset(ASSETCHAINS_SYMBOL, 0, sizeof(ASSETCHAINS_SYMBOL));
    assert(ConnectedChains.ThisChain().name.size() < sizeof(ASSETCHAINS_SYMBOL));
    strcpy(ASSETCHAINS_SYMBOL, ConnectedChains.ThisChain().name.c_str());

    if (ConnectedChains.ThisChain().GetID() == GetDestinationID(DecodeDestination("iExBJfZYK7KREDpuhj6PzZBzqMAKaFg7d2")))
    {
        arith_uint256 initialTargetVARRR = UintToArith256(uint256S("00000000007f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"));
        ASSETCHAINS_STARTING_DIFF = initialTargetVARRR.GetCompact();
    }
    else
    {
        ASSETCHAINS_STARTING_DIFF = ConnectedChains.ThisChain().initialBits;
    }
    //printf("Starting PBaaS chain:\n%s\n", ConnectedChains.ThisChain().ToUniValue().write(1,2).c_str());

    if (!IsVerusActive())
    {
        // we set the notary chain to either Verus or VerusTest
        CCurrencyDefinition notaryChainDef = CCurrencyDefinition(PBAAS_TESTMODE ? "VRSCTEST" : "VRSC", PBAAS_TESTMODE);

        VERUS_CHAINNAME = notaryChainDef.name;
        VERUS_CHAINID = notaryChainDef.GetID();

        ASSETCHAINS_CHAINID = ConnectedChains.ThisChain().GetID();

        ConnectedChains.notarySystems[notaryChainDef.GetID()] =
            CNotarySystemInfo(0, CRPCChainData(notaryChainDef, PBAAS_HOST, PBAAS_PORT, PBAAS_USERPASS), CPBaaSNotarization());
        ASSETCHAINS_SUPPLY = ConnectedChains.ThisChain().GetTotalPreallocation();
        ASSETCHAINS_ISSUANCE = ConnectedChains.ThisChain().gatewayConverterIssuance;
        ASSETCHAINS_ERAOPTIONS[0] = ConnectedChains.ThisChain().ChainOptions();

        mapArgs["-blocktime"] = to_string(ConnectedChains.ThisChain().blockTime);
        if (mapArgs.count("-powaveragingwindow"))
        {
            ConnectedChains.ThisChain().powAveragingWindow = stoi(mapArgs["-powaveragingwindow"]);
        }
        else
        {
            mapArgs["-powaveragingwindow"] = to_string(ConnectedChains.ThisChain().powAveragingWindow);
        }
        mapArgs["-notarizationperiod"] = to_string(ConnectedChains.ThisChain().blockNotarizationModulo);
    }

    DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA = std::max((uint32_t)CCurrencyDefinition::MIN_DEFAULT_TX_EXPIRY, std::min((uint32_t)CCurrencyDefinition::MAX_DEFAULT_TX_EXPIRY, (uint32_t)((CCurrencyDefinition::MIN_DEFAULT_TX_EXPIRY * CCurrencyDefinition::DEFAULT_BLOCKTIME_TARGET) / ConnectedChains.ThisChain().blockTime)));

    if (ConnectedChains.ThisChain().blockTime < CCurrencyDefinition::DEFAULT_BLOCKTIME_TARGET  && ConnectedChains.Chips777TestnetChainID() != ConnectedChains.ThisChain().GetID()) {
        COINBASE_MATURITY = std::max(
            static_cast<uint32_t>(CCurrencyDefinition::MIN_COINBASE_MATURITY),
            std::min(
                static_cast<uint32_t>(CCurrencyDefinition::MAX_COINBASE_MATURITY),
                static_cast<uint32_t>(
                    (CCurrencyDefinition::MIN_COINBASE_MATURITY * CCurrencyDefinition::DEFAULT_BLOCKTIME_TARGET) /
                    ConnectedChains.ThisChain().blockTime
                )
            )
        );
    }
    else
    {
        COINBASE_MATURITY = static_cast<uint32_t>(CCurrencyDefinition::MIN_COINBASE_MATURITY);
    }

    WITNESS_CACHE_SIZE = COINBASE_MATURITY + 10;
    MAX_REORG_LENGTH = COINBASE_MATURITY - 1;
    auto numEras = ConnectedChains.ThisChain().rewards.size();
    ASSETCHAINS_LASTERA = numEras - 1;
    mapArgs["-ac_eras"] = to_string(numEras);

    mapArgs["-ac_end"] = "";
    mapArgs["-ac_reward"] = "";
    mapArgs["-ac_halving"] = "";
    mapArgs["-ac_decay"] = "";
    mapArgs["-ac_options"] = "";

    for (int j = 0; j < ASSETCHAINS_MAX_ERAS; j++)
    {
        if (j > ASSETCHAINS_LASTERA)
        {
            ASSETCHAINS_REWARD[j] = ASSETCHAINS_REWARD[j-1];
            ASSETCHAINS_DECAY[j] = ASSETCHAINS_DECAY[j-1];
            ASSETCHAINS_HALVING[j] = ASSETCHAINS_HALVING[j-1];
            ASSETCHAINS_ENDSUBSIDY[j] = 0;
            ASSETCHAINS_ERAOPTIONS[j] = ConnectedChains.ThisChain().options;
        }
        else
        {
            ASSETCHAINS_REWARD[j] = ConnectedChains.ThisChain().rewards[j];
            ASSETCHAINS_DECAY[j] = ConnectedChains.ThisChain().rewardsDecay[j];
            ASSETCHAINS_HALVING[j] = ConnectedChains.ThisChain().halving[j];
            ASSETCHAINS_ENDSUBSIDY[j] = ConnectedChains.ThisChain().eraEnd[j];
            ASSETCHAINS_ERAOPTIONS[j] = ConnectedChains.ThisChain().options;
            if (j == 0)
            {
                mapArgs["-ac_reward"] = to_string(ASSETCHAINS_REWARD[j]);
                mapArgs["-ac_decay"] = to_string(ASSETCHAINS_DECAY[j]);
                mapArgs["-ac_halving"] = to_string(ASSETCHAINS_HALVING[j]);
                mapArgs["-ac_end"] = to_string(ASSETCHAINS_ENDSUBSIDY[j]);
                mapArgs["-ac_options"] = to_string(ASSETCHAINS_ERAOPTIONS[j]);
            }
            else
            {
                mapArgs["-ac_reward"] += "," + to_string(ASSETCHAINS_REWARD[j]);
                mapArgs["-ac_decay"] += "," + to_string(ASSETCHAINS_DECAY[j]);
                mapArgs["-ac_halving"] += "," + to_string(ASSETCHAINS_HALVING[j]);
                mapArgs["-ac_end"] += "," + to_string(ASSETCHAINS_ENDSUBSIDY[j]);
                mapArgs["-ac_options"] += "," + to_string(ASSETCHAINS_ERAOPTIONS[j]);
            }
        }
    }

    PBAAS_STARTBLOCK = ConnectedChains.ThisChain().startBlock;
    mapArgs["-startblock"] = to_string(PBAAS_STARTBLOCK);
    PBAAS_ENDBLOCK = ConnectedChains.ThisChain().endBlock;
    mapArgs["-endblock"] = to_string(PBAAS_ENDBLOCK);
    mapArgs["-ac_supply"] = to_string(ASSETCHAINS_SUPPLY);
    mapArgs["-gatewayconverterissuance"] = to_string(ASSETCHAINS_ISSUANCE);

    // default to opt-out contract upgrade if this is non-testnet Verus and there is no "-approvecontractupgrade" set
    if (!PBAAS_TESTMODE && ASSETCHAINS_CHAINID == VERUS_CHAINID && !mapArgs.count("-approvecontractupgrade"))
    {
        auto upgradeContractAddress = CTransferDestination::DecodeEthDestination("0x6a25e3c0cbff55c6faa19404fa6389489fb0f6fc");
        if (!upgradeContractAddress.IsNull())
        {
            APPROVE_CONTRACT_UPGRADE = CTransferDestination(CTransferDestination::DEST_ETH, ::AsVector(upgradeContractAddress));
        }
    }
    return true;
}

void CurrencySystemTypeQuery(const uint160 queryID,
                             std::map<CUTXORef, int> &currenciesFound,
                             std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> &curDefVec,
                             uint32_t startBlock=0,
                             uint32_t endBlock=0)
{
    if (startBlock || endBlock)
    {
        std::vector<CAddressIndexDbEntry> systemAddressIndex;
        if (GetAddressIndex(queryID, CScript::P2IDX, systemAddressIndex, startBlock, endBlock) && systemAddressIndex.size())
        {
            for (auto &oneOut : systemAddressIndex)
            {
                CUTXORef oneRef(oneOut.first.txhash, oneOut.first.index);
                if (!currenciesFound.count(oneRef))
                {
                    currenciesFound.insert(std::make_pair(oneRef, -1));
                }
            }
        }
    }
    else
    {
        std::vector<CAddressUnspentDbEntry> unspentAddressIndex;
        if (GetAddressUnspent(queryID, CScript::P2IDX, unspentAddressIndex) && unspentAddressIndex.size())
        {
            for (auto &oneOut : unspentAddressIndex)
            {
                CCurrencyDefinition curDef(oneOut.second.script);
                if (!curDef.IsValid())
                {
                    LogPrintf("%s: invalid currency definition found in index, txid %s, vout: %d\n", __func__, oneOut.first.txhash.GetHex().c_str(), (int)oneOut.first.index);
                    continue;
                }
                CUTXORef oneRef(oneOut.first.txhash, oneOut.first.index);
                if (!currenciesFound.count(oneRef) || currenciesFound[oneRef] == -1)
                {
                    std::vector<CNodeData> nodes;
                    CTransaction nTx;
                    uint256 blockHash;
                    uint160 curDefID = curDef.GetID();
                    if (!myGetTransaction(oneRef.hash, nTx, blockHash))
                    {
                        LogPrintf("%s: Cannot load currency definition transaction, txid %s\n", __func__, oneOut.first.txhash.GetHex().c_str());
                        continue;
                    }
                    for (int i = oneRef.n + 1; i < nTx.vout.size(); i++)
                    {
                        COptCCParams p;
                        CPBaaSNotarization pbn;

                        if (nTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                            p.IsValid() &&
                            (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                            p.vData.size() &&
                            (pbn = CPBaaSNotarization(p.vData[0])).IsValid() &&
                            pbn.currencyID == curDefID)
                        {
                            nodes = pbn.nodes;
                            break;
                        }
                    }
                    currenciesFound.insert(std::make_pair(oneRef, curDefVec.size()));
                    curDefVec.push_back(std::make_pair(std::make_pair(oneRef, nodes),  curDef));
                }
            }
        }
    }
}



void CurrencyNotarizationTypeQuery(CCurrencyDefinition::EQueryOptions launchStateQuery,
                                   std::map<CUTXORef, int> &currenciesFound,
                                   std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> &curDefVec,
                                   uint32_t startBlock=0,
                                   uint32_t endBlock=0,
                                   const uint160 &converter=uint160())
{
    uint160 queryID;
    if (launchStateQuery == CCurrencyDefinition::QUERY_LAUNCHSTATE_PRELAUNCH)
    {
        queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CPBaaSNotarization::LaunchPrelaunchKey());
    }
    else if (launchStateQuery == CCurrencyDefinition::QUERY_LAUNCHSTATE_REFUND)
    {
        queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CPBaaSNotarization::LaunchRefundKey());
    }
    else if (launchStateQuery == CCurrencyDefinition::QUERY_LAUNCHSTATE_COMPLETE)
    {
        queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CPBaaSNotarization::LaunchCompleteKey());
    }
    else if (launchStateQuery == CCurrencyDefinition::QUERY_LAUNCHSTATE_CONFIRM)
    {
        queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CPBaaSNotarization::LaunchConfirmKey());
    }
    else if (launchStateQuery == CCurrencyDefinition::QUERY_ISCONVERTER)
    {
        queryID = CCoinbaseCurrencyState::IndexConverterKey(converter.IsNull() ? ASSETCHAINS_CHAINID : converter);
    }

    if (launchStateQuery != CCurrencyDefinition::QUERY_LAUNCHSTATE_PRELAUNCH && (startBlock || endBlock))
    {
        std::vector<CAddressIndexDbEntry> notarizationAddressIndex;
        std::map<uint160, CPBaaSNotarization> notarizationsFound;

        if (GetAddressIndex(queryID, CScript::P2IDX, notarizationAddressIndex, startBlock, endBlock) && notarizationAddressIndex.size())
        {
            for (auto &oneOut : notarizationAddressIndex)
            {
                CTransaction notarizationTx;
                uint256 blockHash;
                if (!myGetTransaction(oneOut.first.txhash, notarizationTx, blockHash) ||
                    notarizationTx.vout.size() <= oneOut.first.index)
                {
                    LogPrintf("%s: Error reading transaction %s\n", __func__, oneOut.first.txhash.GetHex().c_str());
                    continue;
                }
                CPBaaSNotarization pbn(notarizationTx.vout[oneOut.first.index].scriptPubKey);
                if (!pbn.IsValid())
                {
                    LogPrintf("%s: Invalid notarization on transaction %s, vout: %d\n", __func__, oneOut.first.txhash.GetHex().c_str(), (int)oneOut.first.index);
                    continue;
                }

                CCurrencyDefinition curDef;
                int32_t currencyHeight;
                CUTXORef curDefUTXO;
                std::vector<CNodeData> goodNodes;
                if (!GetCurrencyDefinition(pbn.currencyID, curDef, &currencyHeight, false, true, &curDefUTXO, &goodNodes))
                {
                    LogPrintf("%s: Error getting currency definition %s\n", __func__, EncodeDestination(CIdentityID(pbn.currencyID)).c_str());
                    continue;
                }
                if (!currenciesFound.count(curDefUTXO))
                {
                    currenciesFound[curDefUTXO] = curDefVec.size();
                    curDefVec.push_back(std::make_pair(std::make_pair(curDefUTXO, goodNodes), curDef));
                }
            }
        }
    }
    else
    {
        std::vector<CAddressUnspentDbEntry> unspentAddressIndex;
        if (GetAddressUnspent(queryID, CScript::P2IDX, unspentAddressIndex) && unspentAddressIndex.size())
        {
            uint32_t curHeight = chainActive.Height();
            for (auto &oneOut : unspentAddressIndex)
            {
                CPBaaSNotarization pbn(oneOut.second.script);
                if (!pbn.IsValid())
                {
                    LogPrintf("%s: Invalid notarization in index for %s, vout: %d\n", __func__, oneOut.first.txhash.GetHex().c_str(), (int)oneOut.first.index);
                    continue;
                }
                CCurrencyDefinition curDef;
                int32_t currencyHeight;
                CUTXORef curDefUTXO;
                std::vector<CNodeData> goodNodes;
                if (!GetCurrencyDefinition(pbn.currencyID, curDef, &currencyHeight, false, true, &curDefUTXO, &goodNodes))
                {
                    LogPrintf("%s: Error getting currency definition %s\n", __func__, EncodeDestination(CIdentityID(pbn.currencyID)).c_str());
                    continue;
                }
                if (!currenciesFound.count(curDefUTXO) &&
                    (!endBlock || curHeight < endBlock) &&
                    (!startBlock || currencyHeight >= startBlock) &&
                    !(launchStateQuery == CCurrencyDefinition::QUERY_LAUNCHSTATE_PRELAUNCH && curDef.startBlock < curHeight))
                {
                    currenciesFound[curDefUTXO] = curDefVec.size();
                    curDefVec.push_back(std::make_pair(std::make_pair(curDefUTXO, goodNodes), curDef));
                }
            }
        }
    }
}

// can query and return currency definitions for currencies on this system or from a specific system specified in systemIDQualifier
void GetCurrencyDefinitions(const uint160 &systemIDQualifier,
                            std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> &chains,
                            CCurrencyDefinition::EQueryOptions launchStateQuery,
                            CCurrencyDefinition::EQueryOptions systemTypeQuery,
                            const std::set<uint160> &converters,
                            uint32_t startBlock=0,
                            uint32_t endBlock=0)
{
    CCcontract_info CC;
    CCcontract_info *cp;

    std::map<CUTXORef, int> currenciesFound;
    std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> curDefVec;

    if (systemTypeQuery == CCurrencyDefinition::QUERY_SYSTEMTYPE_LOCAL)
    {
        uint160 queryID = CCrossChainRPCData::GetConditionID(systemIDQualifier, CCurrencyDefinition::CurrencySystemKey());
        CurrencySystemTypeQuery(queryID, currenciesFound, curDefVec, startBlock, endBlock);
    }
    else if (systemTypeQuery == CCurrencyDefinition::QUERY_SYSTEMTYPE_IMPORTED)
    {
        uint160 queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::ExternalCurrencyKey());
        CurrencySystemTypeQuery(queryID, currenciesFound, curDefVec, startBlock, endBlock);
    }
    else if (systemTypeQuery == CCurrencyDefinition::QUERY_SYSTEMTYPE_PBAAS)
    {
        uint160 queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::PBaaSChainKey());
        CurrencySystemTypeQuery(queryID, currenciesFound, curDefVec, startBlock, endBlock);
    }
    else if (systemTypeQuery == CCurrencyDefinition::QUERY_SYSTEMTYPE_GATEWAY)
    {
        uint160 queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::CurrencyGatewayKey());
        CurrencySystemTypeQuery(queryID, currenciesFound, curDefVec, startBlock, endBlock);
    }

    bool narrowBySystem = systemTypeQuery != CCurrencyDefinition::QUERY_NULL;
    bool narrowByLaunch = launchStateQuery != CCurrencyDefinition::QUERY_NULL;
    if (narrowBySystem && !currenciesFound.size())
    {
        return;
    }

    if (narrowByLaunch)
    {
        std::map<CUTXORef, int> launchStateCurrenciesFound;
        std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> launchStateCurVec;
        static std::set<CCurrencyDefinition::EQueryOptions> validLaunchOptions({CCurrencyDefinition::QUERY_LAUNCHSTATE_PRELAUNCH,
                                                                                CCurrencyDefinition::QUERY_LAUNCHSTATE_REFUND,
                                                                                CCurrencyDefinition::QUERY_LAUNCHSTATE_CONFIRM,
                                                                                CCurrencyDefinition::QUERY_LAUNCHSTATE_COMPLETE});

        if (!validLaunchOptions.count(launchStateQuery))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid launchStateQuery");
        }

        CurrencyNotarizationTypeQuery(launchStateQuery, launchStateCurrenciesFound, launchStateCurVec, startBlock, endBlock);

        if (launchStateCurrenciesFound.size())
        {
            // remove all that are not in the system type of interest
            if (narrowBySystem)
            {
                std::vector<CUTXORef> toRemove;
                for (auto &oneFound : currenciesFound)
                {
                    if (!launchStateCurrenciesFound.count(oneFound.first))
                    {
                        toRemove.push_back(oneFound.first);
                    }
                    else if (currenciesFound[oneFound.first] == -1)
                    {
                        currenciesFound[oneFound.first] = curDefVec.size();
                        curDefVec.push_back(launchStateCurVec[launchStateCurrenciesFound[oneFound.first]]);
                    }
                }
                if (currenciesFound.size() == toRemove.size())
                {
                    return;
                }
                for (auto &oneUtxo : toRemove)
                {
                    currenciesFound.erase(oneUtxo);
                }
            }
            else
            {
                curDefVec.insert(curDefVec.end(), launchStateCurVec.begin(), launchStateCurVec.end());
                currenciesFound = launchStateCurrenciesFound;
            }
        }
        else
        {
            return;
        }
    }

    bool isNarrowing = narrowBySystem || narrowByLaunch;

    if (isNarrowing && !currenciesFound.size())
    {
        return;
    }

    // two options are is converter as narrowing or just is converter
    // for narrowing, we ignore start and end blocks to determine state now
    if (converters.size())
    {
        std::map<CUTXORef, std::pair<std::vector<CNodeData>, CCurrencyDefinition>> totalCurrencies;

        // get converters and return only those already found that are converters
        for (auto &oneCurID : converters)
        {
            std::map<CUTXORef, int> converterCurrenciesFound;
            std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> converterCurVec;
            CurrencyNotarizationTypeQuery(CCurrencyDefinition::QUERY_ISCONVERTER, converterCurrenciesFound, converterCurVec, startBlock, endBlock, oneCurID);
            if (!converterCurrenciesFound.size())
            {
                totalCurrencies.clear();
                break;
            }
            if (totalCurrencies.size())
            {
                std::map<CUTXORef, std::pair<std::vector<CNodeData>, CCurrencyDefinition>> newTotalCurrencies;
                for (auto &oneCurRef : converterCurrenciesFound)
                {
                    if (totalCurrencies.count(oneCurRef.first))
                    {
                        newTotalCurrencies.insert(std::make_pair(oneCurRef.first, std::make_pair(converterCurVec[oneCurRef.second].first.second,
                                                                                                    converterCurVec[oneCurRef.second].second)));
                    }
                }
                totalCurrencies = newTotalCurrencies;
                if (!totalCurrencies.size())
                {
                    break;
                }
            }
            else
            {
                for (auto &oneCurRef : converterCurrenciesFound)
                {
                    totalCurrencies.insert(std::make_pair(oneCurRef.first, std::make_pair(converterCurVec[oneCurRef.second].first.second,
                                                                                            converterCurVec[oneCurRef.second].second)));
                }
            }
        }
        if (isNarrowing)
        {
            std::vector<CUTXORef> toRemove;
            for (auto &oneFound : currenciesFound)
            {
                if (!totalCurrencies.count(oneFound.first))
                {
                    toRemove.push_back(oneFound.first);
                }
                else if (currenciesFound[oneFound.first] == -1)
                {
                    currenciesFound[oneFound.first] = curDefVec.size();
                    curDefVec.push_back(std::make_pair(std::make_pair(oneFound.first, totalCurrencies[oneFound.first].first), totalCurrencies[oneFound.first].second));
                }
            }
            if (currenciesFound.size() == toRemove.size())
            {
                return;
            }
            for (auto &oneUtxo : toRemove)
            {
                currenciesFound.erase(oneUtxo);
            }
        }
        else
        {
            for (auto &oneCurFound : totalCurrencies)
            {
                currenciesFound[oneCurFound.first] = curDefVec.size();
                curDefVec.push_back(std::make_pair(std::make_pair(oneCurFound.first, oneCurFound.second.first), oneCurFound.second.second));
            }
        }
    }
    else if (!isNarrowing)
    {
        // no qualifiers, so we default to this system currencies and retrieve all currencies in the specified block range
        uint160 queryID = CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::CurrencySystemKey());
        CurrencySystemTypeQuery(queryID, currenciesFound, curDefVec, startBlock, endBlock);
    }

    // now, loop through the found currencies and load the currency definition if not loaded, then store all
    // in the return vector
    for (auto &oneCur : currenciesFound)
    {
        if (oneCur.second == -1)
        {
            CTransaction tx;
            uint256 blkHash;
            if (!myGetTransaction(oneCur.first.hash, tx, blkHash) ||
                tx.vout.size() <= oneCur.first.n)
            {
                continue;
            }
            CCurrencyDefinition oneCurDef(tx.vout[oneCur.first.n].scriptPubKey);
            std::vector<CNodeData> nodes;
            if (oneCurDef.IsValid())
            {
                for (int i = oneCur.first.n + 1; i < tx.vout.size(); i++)
                {
                    COptCCParams p;
                    CPBaaSNotarization pbn;

                    if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() &&
                        (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                        p.vData.size() &&
                        (pbn = CPBaaSNotarization(p.vData[0])).IsValid() &&
                        pbn.currencyID == oneCurDef.GetID())
                    {
                        nodes = pbn.nodes;
                        break;
                    }
                }
                chains.push_back(std::make_pair(std::make_pair(oneCur.first, nodes),  oneCurDef));
            }
        }
        else
        {
            chains.push_back(curDefVec[oneCur.second]);
        }
    }
}

static LRUCache<CUTXORef, std::vector<std::vector<int>>> importMappingCache;    // keyed on import UTXO with the vector of 1->many input/output numbers corresponding 1:1 to reserve transfers

// returns the reserve transfer input to output mapping for an import
std::pair<std::vector<CReserveTransfer>, std::vector<std::vector<int>>> GetReserveTransferImportOutputMapping(const CTransaction &tx, int outNum, CCrossChainImport &cci, CCrossChainImport &sysCCI, CPBaaSNotarization &importNotarization, int32_t &importOutput, uint32_t nHeight)
{
    std::pair<std::vector<CReserveTransfer>,std::vector<std::vector<int>>> ret;
    COptCCParams receivedP;
    CCrossChainExport ccx;
    int32_t sysCCIOut = 0, importNotarizationOut = 0, eOutStart = 0, eOutEnd = 0;
    std::vector<CReserveTransfer> reserveTransfers;

    // determine if this is import output and figure out where we are in the import and what reserve transfer or fee source these received funds are from
    // if the funds are from this wallet, relate them back to the source reserve transfer
    for (int i = outNum; i >= 0; i--)
    {
        receivedP = COptCCParams();
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(receivedP) &&
            receivedP.IsValid() &&
            receivedP.evalCode == EVAL_CROSSCHAIN_IMPORT &&
            receivedP.vData.size() &&
            (cci = CCrossChainImport(receivedP.vData[0])).IsValid())
        {
            if (!cci.IsSourceSystemImport())
            {
                importOutput = i;
            }
            else if (i > 0 &&
                        tx.vout[i - 1].scriptPubKey.IsPayToCryptoCondition(receivedP) &&
                        receivedP.IsValid() &&
                        receivedP.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                        receivedP.vData.size() &&
                        (cci = CCrossChainImport(receivedP.vData[0])).IsValid() &&
                        !cci.IsSourceSystemImport())
            {
                importOutput = i - 1;
            }
            if (!cci.IsValid() ||
                cci.IsSourceSystemImport() ||
                cci.IsDefinitionImport() ||
                !cci.GetImportInfo(tx, nHeight, i, ccx, sysCCI, sysCCIOut, importNotarization, importNotarizationOut, eOutStart, eOutEnd, reserveTransfers))
            {
                cci = CCrossChainImport();
            }
            break;
        }

        if (receivedP.IsValid() &&
            (receivedP.evalCode == EVAL_CROSSCHAIN_IMPORT ||
                receivedP.evalCode == EVAL_RESERVE_DEPOSIT))
        {
            cci = CCrossChainImport();
            break;
        }
    }

    if (cci.IsValid())
    {
        // if we have this import in the cache already, use it
        std::vector<std::vector<int>> reserveTransferOutputMapping;
        if (!importMappingCache.Get(CUTXORef(tx.GetHash(), importOutput), reserveTransferOutputMapping))
        {
            // otherwise, tag all reserve transfers, get the starting point for the import, run AddReserveTransferImportOutputs,
            // and see which outputs are attributable to which reserve transfers, then cache them, even if their output is null
            std::vector<CReserveTransfer> taggedTransfers;

            for (int32_t i = 0; i < reserveTransfers.size(); i++)
            {
                uint32_t tagVal = i + 1;
                auto oneRT = reserveTransfers[i];

                // identity & currency exports must have the original value
                // in all other cases, tag the RT by sending it to the number of its reserve transfer + 1
                if (oneRT.IsIdentityExport() || oneRT.IsCurrencyExport())
                {
                    // tag auxdests as well
                    if (!oneRT.destination.AuxDestCount())
                    {
                        oneRT.destination.SetAuxDest(CTransferDestination(CTransferDestination::DEST_PKH, std::vector<unsigned char>(20)), 0);
                    }
                }
                else
                {
                    std::vector<unsigned char> tagVec = std::vector<unsigned char>(oneRT.destination.destination.size(), 0);
                    if (tagVec.size() < 4)
                    {
                        tagVec = std::vector<unsigned char>(4, 0);
                    }

                    // tag destination
                    *(tagVec.end() - 1) = (unsigned char)(tagVal & 0xff);
                    *(tagVec.end() - 2) = (unsigned char)((tagVal >> 8) & 0xff);
                    *(tagVec.end() - 3) = (unsigned char)((tagVal >> 16) & 0xff);
                    *(tagVec.end() - 4) = (unsigned char)((tagVal >> 24) & 0xff);
                    oneRT.destination = CTransferDestination(oneRT.destination.type, tagVec, oneRT.destination.gatewayID, oneRT.destination.gatewayCode, oneRT.destination.fees, oneRT.destination.auxDests);
                }

                for (int j = 0; j < oneRT.destination.AuxDestCount(); j++)
                {
                    CTransferDestination oneAux = oneRT.destination.GetAuxDest(j);
                    std::vector<unsigned char> auxTagVec = std::vector<unsigned char>(oneAux.destination.size(), 0);
                    if (auxTagVec.size() < 4)
                    {
                        auxTagVec = std::vector<unsigned char>(4, 0);
                    }
                    *(auxTagVec.end() - 1) = (unsigned char)(tagVal & 0xff);
                    *(auxTagVec.end() - 2) = (unsigned char)((tagVal >> 8) & 0xff);
                    *(auxTagVec.end() - 3) = (unsigned char)((tagVal >> 16) & 0xff);
                    *(auxTagVec.end() - 4) = (unsigned char)((tagVal >> 24) & 0xff);
                    oneRT.destination.SetAuxDest(CTransferDestination(oneAux.type, auxTagVec, oneAux.gatewayID, oneAux.gatewayCode, oneAux.fees, oneAux.auxDests), j);
                }
                taggedTransfers.push_back(oneRT);
            }

            // reverse import currency state and rerun with taggedTransfers to determine output,
            // currencies and identities that aren't tagged are matched if present, or skipped

            CCurrencyDefinition importCurrencyDef = ConnectedChains.GetCachedCurrency(cci.importCurrencyID);
            CCurrencyDefinition sourceSystemDef = ConnectedChains.GetCachedCurrency(cci.sourceSystemID);

            if (sourceSystemDef.IsValid() && importCurrencyDef.IsValid())
            {
                std::vector<CTxOut> checkOutputs;
                CCurrencyValueMap importedCurrency, gatewayDeposits, spentCurrencyOut;

                CCoinbaseCurrencyState checkState = importNotarization.currencyState;
                CCoinbaseCurrencyState newState;

                bool isClearLaunch = (ccx.IsClearLaunch() && ccx.sourceSystemID == importCurrencyDef.launchSystemID);

                CReserveTransactionDescriptor rtxd;

                uint256 weakEntropyHash = EntropyHashFromHeight(CBlockIndex::BlockEntropyKey(), importNotarization.notarizationHeight, importCurrencyDef.GetID());

                bool updatedChecks = ConnectedChains.CheckZeroViaOnlyPostLaunch(nHeight);

                if (updatedChecks &&
                    isClearLaunch &&
                    reserveTransfers.size())
                {
                    // we need the prior import's notarization as a starting point
                    CValidationState state;
                    CTransaction priorTx;
                    int32_t priorOutNum = 0;
                    CCrossChainImport priorCCI = cci.GetPriorImport(tx, state, &priorTx, &priorOutNum);
                    // clearlaunch should always have a prior
                    if (priorCCI.IsValid())
                    {
                        bool validNotarization = false;

                        // get the prior output notarization
                        for (int o = priorOutNum; o < priorTx.vout.size(); o++)
                        {
                            COptCCParams priorP;
                            CPBaaSNotarization priorNotar;
                            if (priorTx.vout[o].scriptPubKey.IsPayToCryptoCondition(priorP) &&
                                priorP.IsValid() &&
                                (priorP.evalCode == EVAL_ACCEPTEDNOTARIZATION || priorP.evalCode == EVAL_EARNEDNOTARIZATION) &&
                                (priorNotar = CPBaaSNotarization(priorP.vData[0])).IsValid() &&
                                priorNotar.currencyID == cci.importCurrencyID)
                            {
                                checkState = priorNotar.currencyState;
                                checkState.SetPrelaunch(false);

                                // clear launch export is not clear launch import
                                checkState.SetLaunchClear(false);

                                if (rtxd.AddReserveTransferImportOutputs(sourceSystemDef,
                                                                            ConnectedChains.thisChain,
                                                                            importCurrencyDef,
                                                                            checkState,
                                                                            taggedTransfers,
                                                                            nHeight,
                                                                            checkOutputs,
                                                                            importedCurrency,
                                                                            gatewayDeposits,
                                                                            spentCurrencyOut,
                                                                            &newState,
                                                                            ccx.exporter,
                                                                            importNotarization.proposer,
                                                                            weakEntropyHash))
                                {
                                    checkState.conversionPrice = newState.conversionPrice;
                                    checkState.viaConversionPrice = newState.viaConversionPrice;
                                    validNotarization = true;
                                    checkOutputs.clear();
                                    importedCurrency = gatewayDeposits = spentCurrencyOut = CCurrencyValueMap();
                                    break;
                                }
                            }
                        }
                        if (!validNotarization)
                        {
                            if (LogAcceptCategory("defi"))
                            {
                                LogPrintf("%s: Invalid prior notarization at clear launch for import: %s\n", __func__, cci.ToUniValue().write(1,2).c_str());
                            }
                            return ret;
                        }
                    }
                    else
                    {
                        if (LogAcceptCategory("defi"))
                        {
                            LogPrintf("%s: Invalid prior import: %s\n", __func__, cci.ToUniValue().write(1,2).c_str());
                        }
                        return ret;
                    }
                }
                else
                {
                    // if clear launch, don't set launch complete beforehand to match outputs
                    if (isClearLaunch)
                    {
                        checkState.SetLaunchCompleteMarker(false);
                    }

                    checkState.RevertReservesAndSupply(importCurrencyDef,
                                                        ASSETCHAINS_CHAINID,
                                                        ((importCurrencyDef.IsGatewayConverter() && importCurrencyDef.gatewayID == ASSETCHAINS_CHAINID) ||
                                                            (!IsVerusActive() && importCurrencyDef.GetID() == ASSETCHAINS_CHAINID)),
                                                        !updatedChecks ? CCoinbaseCurrencyState::PBAAS_1_0_0 : CCoinbaseCurrencyState::ReversionUpdateForHeight(nHeight));

                    // between clear launch and complete, we need to adjust supply for verification
                    if (!checkState.IsFractional() &&
                        checkState.GetID() != ASSETCHAINS_CHAINID &&
                        !checkState.IsPrelaunch() &&
                        checkState.IsLaunchConfirmed() &&
                        !checkState.IsLaunchCompleteMarker() &&
                        importNotarization.currencyState.supply == checkState.supply &&
                        checkState.preConvertedOut)
                    {
                        checkState.supply = checkState.AddToSupply(-checkState.preConvertedOut);
                    }
                }

                if (LogAcceptCategory("defi"))
                {
                    LogPrintf("%s: reverted currency state: %s\n", __func__, checkState.ToUniValue().write(1,2).c_str());
                }

                if (!cci.IsPostLaunch() && cci.IsInitialLaunchImport())
                {
                    checkState.SetLaunchClear();
                }

                rtxd = CReserveTransactionDescriptor();

                if (!rtxd.AddReserveTransferImportOutputs(sourceSystemDef,
                                                            ConnectedChains.thisChain,
                                                            importCurrencyDef,
                                                            checkState,
                                                            taggedTransfers,
                                                            nHeight,
                                                            checkOutputs,
                                                            importedCurrency,
                                                            gatewayDeposits,
                                                            spentCurrencyOut,
                                                            &newState,
                                                            ccx.exporter,
                                                            importNotarization.proposer,
                                                            weakEntropyHash,
                                                            true))
                {
                    return ret;
                }

                if (importNotarization.currencyState.flags != newState.flags)
                {
                    // this will be a transition, accept valid transitions without
                    // enforcement, as that will be handled in the notarization precheck
                    if (!newState.IsLaunchCompleteMarker() &&
                        importNotarization.currencyState.IsLaunchCompleteMarker())
                    {
                        newState.SetLaunchCompleteMarker();
                        LogPrintf("Setting launch complete for %s\n", EncodeDestination(CIdentityID(newState.GetID())).c_str());
                    }
                }

                // these affect comparison, but not calculations
                if (newState.reserveIn != importNotarization.currencyState.reserveIn ||
                    newState.reserveOut != importNotarization.currencyState.reserveOut)
                {
                    if (LogAcceptCategory("defi"))
                    {
                        LogPrintf("%s: Expected: %s\nActual: %s\n", __func__, newState.ToUniValue().write(1,2).c_str(), importNotarization.currencyState.ToUniValue().write(1,2).c_str());
                    }
                }
                newState.reserveIn = importNotarization.currencyState.reserveIn;
                newState.reserveOut = importNotarization.currencyState.reserveOut;
                newState.primaryCurrencyIn = importNotarization.currencyState.primaryCurrencyIn;

                // match every reserve transfer to 0 or more calculated outputs
                if (!cci.IsDefinitionImport() &&
                    !cci.IsSourceSystemImport())
                {
                    int startingOutput = importNotarizationOut + 1;
                    if (eOutEnd > 0)
                    {
                        startingOutput = eOutEnd + 1;
                    }
                    if (startingOutput < 0 ||
                        checkOutputs.size() != cci.numOutputs ||
                        (startingOutput + checkOutputs.size()) > tx.vout.size())
                    {
                        LogPrint("importtransactions", "%s: import outputs would index beyond import transaction\n", __func__);
                        return ret;
                    }

                    int loop = 0;
                    // loop through the reserve transfers and add an entry to the ret value
                    for (int rtl=0; rtl < reserveTransfers.size(); rtl++)
                    {
                        std::vector<int> outNumVec;
                        if (loop >= checkOutputs.size())
                        {
                            reserveTransferOutputMapping.push_back(outNumVec);
                            continue;
                        }
                        auto &oneRT = reserveTransfers[rtl];
                        auto &oneOut = checkOutputs[loop];

                        COptCCParams ooP;
                        oneOut.scriptPubKey.IsPayToCryptoCondition(ooP);

                        if (oneRT.HasNextLeg())
                        {
                            // expect a reserve transfer or failure with early out + refund
                            // either way, it's one output
                            outNumVec.push_back(startingOutput + loop++);
                        }
                        else if (oneRT.IsCurrencyExport())
                        {
                            // deal with output variance/duplication failure
                            if (ooP.IsValid() &&
                                ooP.evalCode == EVAL_CURRENCY_DEFINITION &&
                                CCurrencyDefinition(ooP.vData[0]).GetID() == TransferDestinationToCurrency(oneRT.destination).GetID())
                            {
                                outNumVec.push_back(startingOutput + loop++);
                            }
                        }
                        else if (oneRT.IsIdentityExport())
                        {
                            CIdentityID idID(TransferDestinationToIdentity(oneRT.destination).GetID());
                            // deal with output variance, can have no output, and if non-0 output to ID, can be 2 outputs
                            if (ooP.IsValid() && ooP.evalCode == EVAL_CURRENCY_DEFINITION)
                            {
                                if (idID == CIdentity(ooP.vData[0]).GetID())
                                {
                                    outNumVec.push_back(startingOutput + loop++);
                                    if (oneRT.FirstValue())
                                    {
                                        CTxDestination outAddr;
                                        if (loop < checkOutputs.size() &&
                                            ExtractDestination(checkOutputs[loop].scriptPubKey, outAddr) &&
                                            outAddr.which() == COptCCParams::ADDRTYPE_ID &&
                                            GetDestinationID(outAddr) == idID)
                                        {
                                            outNumVec.push_back(startingOutput + loop++);
                                        }
                                    }
                                }
                            }
                            else if (oneRT.FirstValue())
                            {
                                CTxDestination outAddr;
                                if (ExtractDestination(checkOutputs[loop].scriptPubKey, outAddr) &&
                                    outAddr.which() == COptCCParams::ADDRTYPE_ID &&
                                    GetDestinationID(outAddr) == idID)
                                {
                                    outNumVec.push_back(startingOutput + loop++);
                                }
                            }
                        }
                        else if (!oneRT.IsBurn())
                        {
                            // can be conversion, transfer, mint, etc.
                            // check tag of destination to find reserve transfer index, ensure it matches
                            CTxDestination outAddr;
                            if (ExtractDestination(oneOut.scriptPubKey, outAddr))
                            {
                                std::vector<unsigned char> tagVec = std::vector<unsigned char>(20, 0);
                                uint32_t tagVal = rtl + 1;
                                *(tagVec.end() - 1) = (unsigned char)(tagVal & 0xff);
                                *(tagVec.end() - 2) = (unsigned char)((tagVal >> 8) & 0xff);
                                *(tagVec.end() - 3) = (unsigned char)((tagVal >> 16) & 0xff);
                                *(tagVec.end() - 4) = (unsigned char)((tagVal >> 24) & 0xff);
                                if (GetDestinationID(outAddr) == uint160(tagVec))
                                {
                                    outNumVec.push_back(startingOutput + loop++);
                                }
                            }
                        }
                        reserveTransferOutputMapping.push_back(outNumVec);
                    }
                    for (; loop < checkOutputs.size(); loop++)
                    {
                        reserveTransferOutputMapping.push_back({startingOutput + loop});
                    }
                }
            }
            importMappingCache.Put(CUTXORef(tx.GetHash(), outNum), reserveTransferOutputMapping);
        }

        ret.first = reserveTransfers;
        ret.second = reserveTransferOutputMapping;
    }
    return ret;
}

UniValue GetTransferImportProgress(const CTransaction &importTx, const CReserveTransfer &rt, int32_t rtIndexNum, uint32_t blockTime, uint32_t nHeight, CCostBasisTracker *pCurrenciesCostBases,
                                                                                                                                                       std::map<std::pair<uint256, int32_t>, std::multimap<std::pair<uint160,uint32_t>, std::pair<int64_t, int64_t>>> *pIncomingCostBases,
                                                                                                                                                       std::map<std::pair<uint256, int32_t>, std::multimap<std::pair<uint160,uint32_t>, std::pair<int64_t, int64_t>>> *pOutgoingCostBases,
                                                                                                                                                       CEarningsTracker *pAggregateEarnings,
                                                                                                                                                       std::map<std::string, int64_t> *pNativePriceMap)
{
    CCrossChainImport cci;
    CCrossChainImport sysCCI;
    CPBaaSNotarization importNotarization;
    int32_t importOutput = 0;

    // now, we have the import transaction, get import/reserve transfer results from output
    auto rtImportMapping = GetReserveTransferImportOutputMapping(importTx, 3, cci, sysCCI, importNotarization, importOutput, nHeight);

    UniValue importOutputs;

    // use the reserve transfer import number to find the output(s)
    if (rtImportMapping.second.size() > rtIndexNum && rtImportMapping.second[rtIndexNum].size() && rtImportMapping.second[rtIndexNum][0] < importTx.vout.size())
    {
        importOutputs = UniValue(UniValue::VOBJ);
        UniValue importOutputArr(UniValue::VARR);
        importOutputs.pushKV("importtxout", CUTXORef(importTx.GetHash(), importOutput).ToUniValue());
        importOutputs.pushKV("timestampprocessed", (int64_t)blockTime);
        importOutputs.pushKV("timedateprocessed", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", (int64_t)blockTime));

        importOutputs.pushKV("convertfrom", ConnectedChains.GetFriendlyCurrencyName(rt.FirstCurrency()));
        uint160 convertToCurrency = rt.IsReserveToReserve() ? rt.secondReserveID : rt.destCurrencyID;
        importOutputs.pushKV("convertto", ConnectedChains.GetFriendlyCurrencyName(convertToCurrency));

        if (pAggregateEarnings)
        {
            int64_t nativeCostBasis = pCurrenciesCostBases->GetConversionCostBasisNative(importNotarization, convertToCurrency, nHeight);
            importOutputs.pushKV("newcostbasisnative", ValueFromAmount(nativeCostBasis));

            std::map<std::string, int64_t> nativePriceMap;
            int64_t fiatCostBasis = CCoinbaseCurrencyState::NativeToReserveRaw(nativeCostBasis, pCurrenciesCostBases->GetNativeCostBasisFiat(importNotarization, pNativePriceMap ? *pNativePriceMap : nativePriceMap, blockTime, nHeight, pAggregateEarnings->FiatCurrencyID()));
            importOutputs.pushKV("newcostbasisfiat", ValueFromAmount(fiatCostBasis));

            if (pCurrenciesCostBases)
            {
                int64_t amountLeft = 0;
                std::vector<std::tuple<uint32_t, int64_t, int64_t>, std::allocator<std::tuple<uint32_t, int64_t, int64_t>>> fromCostBasis = pCurrenciesCostBases->TakeCurrency(rt.FirstCurrency(), rt.FirstValue(), amountLeft);
                int64_t newAmount = convertToCurrency == ASSETCHAINS_CHAINID ? importTx.vout[rtImportMapping.second[rtIndexNum][0]].nValue : importTx.vout[rtImportMapping.second[rtIndexNum][0]].ReserveOutValue().valueMap[convertToCurrency];
                pCurrenciesCostBases->PutCurrency(convertToCurrency, blockTime, fiatCostBasis, newAmount);

                // get a weighted average of the cost basis, consider unaccounted for currency to have an unchanged cost-basis, but flag it
                if (amountLeft)
                {
                    UniValue missingCostBasis(UniValue::VOBJ);
                    missingCostBasis.pushKV(EncodeDestination(CIdentityID(rt.FirstCurrency())), ValueFromAmount(amountLeft));
                    importOutputs.pushKV("missinginitialcostbasis", missingCostBasis);
                    int64_t currentCostBasis = pCurrenciesCostBases->GetConversionCostBasisNative(importNotarization, rt.FirstCurrency(), nHeight);
                    int64_t currentFiatCostBasis = CCoinbaseCurrencyState::NativeToReserveRaw(currentCostBasis, pCurrenciesCostBases->GetNativeCostBasisFiat(importNotarization, pNativePriceMap ? *pNativePriceMap : nativePriceMap, blockTime, nHeight, pAggregateEarnings->FiatCurrencyID()));
                    fromCostBasis.push_back({blockTime, currentFiatCostBasis, amountLeft});
                }

                // use "from" cost basis and add fees to make total cost basis + fees
                int64_t initialLongTermCostBasis = 0;
                int64_t initialLongTermAmount = 0;
                int64_t initialShortTermCostBasis = 0;
                for (auto &oneCostBasis : fromCostBasis)
                {
                    if ((std::get<0>(oneCostBasis) ? (blockTime - std::get<0>(oneCostBasis)) : 0) > pAggregateEarnings->shortLongTermThresholdSeconds)
                    {
                        initialLongTermAmount += std::get<2>(oneCostBasis);
                        initialLongTermCostBasis += CCoinbaseCurrencyState::NativeToReserveRaw(std::get<2>(oneCostBasis), std::get<1>(oneCostBasis));
                    }
                    else
                    {
                        initialShortTermCostBasis += CCoinbaseCurrencyState::NativeToReserveRaw(std::get<2>(oneCostBasis), std::get<1>(oneCostBasis));
                    }
                }
                int64_t longTermNewAmount = CCurrencyDefinition::CalculateRatioOfValue(newAmount, CCurrencyDefinition::CalculateRatioOfTwoValues(initialLongTermAmount, rt.FirstValue()));
                int64_t shortTermNewAmount = newAmount - longTermNewAmount;

                int64_t longTermNewCostBasis = CCoinbaseCurrencyState::NativeToReserveRaw(longTermNewAmount, fiatCostBasis);
                int64_t shortTermNewCostBasis = CCoinbaseCurrencyState::NativeToReserveRaw(shortTermNewAmount, fiatCostBasis);

                if (longTermNewAmount)
                {
                    pAggregateEarnings->AddLongTerm(longTermNewCostBasis - initialLongTermCostBasis);
                }

                if (shortTermNewAmount)
                {
                    pAggregateEarnings->AddShortTerm(shortTermNewCostBasis - initialShortTermCostBasis);
                }

                // add fees
                if (importNotarization.currencyState.GetReserveMap().count(rt.FeeCurrencyID()))
                {
                    int64_t feeCostBasisNative = pCurrenciesCostBases->GetConversionCostBasisNative(importNotarization, rt.FeeCurrencyID(), nHeight);
                    int64_t feeValueFiat = CCoinbaseCurrencyState::NativeToReserveRaw(rt.nFees, CCoinbaseCurrencyState::NativeToReserveRaw(feeCostBasisNative, pCurrenciesCostBases->GetNativeCostBasisFiat(importNotarization, pNativePriceMap ? *pNativePriceMap : nativePriceMap, blockTime, nHeight, pAggregateEarnings->FiatCurrencyID())));
                    pAggregateEarnings->AddFees(feeValueFiat);
                }
            }
        }

        // if we have available currency / costbasis to use, take from the multimap what we used,
        // calculate the total original cost basis of the currency used
        // subtract the total original cost basis from the new currency cost basis * amount to
        // determine profit or loss in DAI and add it to total
        // add the newly converted currency to the cost basis amount, and if it is going off-chain,
        // add it to the exported amount headed off-chain
        for (auto oneOutNum : rtImportMapping.second[rtIndexNum])
        {
            if (oneOutNum < importTx.vout.size())
            {
                UniValue scriptPubKeyUni(UniValue::VOBJ);
                ScriptPubKeyToUniv(importTx.vout[oneOutNum].scriptPubKey, scriptPubKeyUni, false);
                scriptPubKeyUni.pushKV("nativeout", ValueFromAmount(importTx.vout[oneOutNum].nValue));
                scriptPubKeyUni.pushKV("outnum", oneOutNum);
                importOutputArr.push_back(scriptPubKeyUni);
            }
        }
        importOutputs.pushKV("outputs", importOutputArr);
    }
    return importOutputs;
}

UniValue GetReserveTransferProgress(const CTransaction &tx, int outNum, const CReserveTransfer &rt, CCostBasisTracker *pCurrenciesCostBases,
                                                                                                    std::map<std::pair<uint256, int32_t>, std::multimap<std::pair<uint160,uint32_t>, std::pair<int64_t, int64_t>>> *pIncomingCostBases,
                                                                                                    std::map<std::pair<uint256, int32_t>, std::multimap<std::pair<uint160,uint32_t>, std::pair<int64_t, int64_t>>> *pOutgoingCostBases,
                                                                                                    CEarningsTracker *pAggregateEarnings,
                                                                                                    std::map<std::string, int64_t> *pNativePriceMap)
{
    UniValue ret;
    if (tx.vout.size() > outNum)
    {
        if (fSpentIndex)
        {
            CSpentIndexDbEntry spentIndexEntry({CSpentIndexKey(tx.GetHash(), outNum), CSpentIndexValue()});
            CTransaction spendingTx;
            uint256 blockHash;
            bool pending = true;
            if (GetSpentIndex(spentIndexEntry.first, spentIndexEntry.second) &&
                myGetTransaction(spentIndexEntry.second.txid, spendingTx, blockHash, false) &&
                !blockHash.IsNull())
            {
                auto blockIter = mapBlockIndex.find(blockHash);
                if (blockIter != mapBlockIndex.end() &&
                    chainActive.Contains(blockIter->second))
                {
                    pending = false;
                    CCrossChainExport ccx(spendingTx);

                    // if we have a spent index, an export should spend (arbitrage transfer is spent by an import or normal spend),
                    // follow to the import, if possible, and if there is a second leg, follow the second leg as well
                    // cache useful information for import tracking
                    if (rt.IsArbitrageOnly())
                    {
                        uint32_t nHeight = blockIter->second->GetHeight();

                        CCrossChainImport cci;
                        CCrossChainImport sysCCI;
                        CPBaaSNotarization importNotarization;
                        int32_t importOutput = 0;

                        // now, we have the import transaction, get import/reserve transfer results from output
                        auto rtImportMapping = GetReserveTransferImportOutputMapping(spendingTx, 3, cci, sysCCI, importNotarization, importOutput, blockIter->second->GetHeight());

                        CValidationState state;
                        std::vector<CUTXORef> arbOuts;
                        auto arbTransfers = cci.GetArbitrageTransfers(spendingTx, state, blockIter->second->GetHeight(), nullptr, &arbOuts);
                        int rtIndexNum = 0;
                        for (; rtIndexNum < arbOuts.size(); rtIndexNum++)
                        {
                            if (tx.GetHash() == arbOuts[rtIndexNum].hash && outNum == arbOuts[rtIndexNum].n)
                            {
                                break;
                            }
                        }

                        ret = UniValue(UniValue::VOBJ);
                        if (rtIndexNum < arbOuts.size())
                        {
                            // now rtIndex will actually point to the reserve transfer index and not arbOut index
                            rtIndexNum += rtImportMapping.first.size() - arbOuts.size();

                            if (!cci.IsValid())
                            {
                                ret.pushKV("status","spent");
                            }
                            else
                            {
                                ret.pushKV("processedoutputs", GetTransferImportProgress(spendingTx, rt, rtIndexNum, blockIter->second->nTime, blockIter->second->GetHeight(), pCurrenciesCostBases, pIncomingCostBases, pOutgoingCostBases, pAggregateEarnings, pNativePriceMap));
                            }
                        }
                        else
                        {
                            ret.pushKV("status","spent");
                        }
                    }
                    else
                    {
                        if (ccx.IsValid())
                        {
                            // once we get to an export, we can provide its destination currency and chain
                            CCrossChainExport progressExport;
                            int i = 0, exportOutNum = 0;
                            for (; i < spendingTx.vout.size(); i++)
                            {
                                if ((progressExport = CCrossChainExport(spendingTx.vout[i].scriptPubKey)).IsValid() &&
                                    !progressExport.IsSystemThreadExport() &&
                                    progressExport.destCurrencyID == rt.GetImportCurrency())
                                {
                                    exportOutNum = i;
                                    break;
                                }
                                progressExport = CCrossChainExport();
                            }
                            if (progressExport.IsValid())
                            {
                                // find the reserve transfer import number on the export, which can be used in more than one place
                                int rtIndexNum = progressExport.firstInput;
                                for (; rtIndexNum < spendingTx.vin.size() && rtIndexNum < (progressExport.firstInput + progressExport.numInputs); rtIndexNum++)
                                {
                                    if (spendingTx.vin[rtIndexNum].prevout.hash == tx.GetHash() && spendingTx.vin[rtIndexNum].prevout.n == outNum)
                                    {
                                        break;
                                    }
                                }
                                if (rtIndexNum < spendingTx.vin.size() && rtIndexNum < (progressExport.firstInput + progressExport.numInputs))
                                {
                                    rtIndexNum -= progressExport.firstInput;
                                }
                                else
                                {
                                    rtIndexNum = INT32_MAX;
                                }

                                ret = UniValue(UniValue::VOBJ);
                                ret.pushKV("status", "exported");
                                ret.pushKV("exporttxout", CUTXORef(spendingTx.GetHash(), i).ToUniValue());

                                // if this is a conversion, and it is either heading off-chain to execute it, or there is a next leg, follow the transaction to
                                // either the import or a way to reference the destination, so it can be related
                                if (progressExport.destSystemID == ASSETCHAINS_CHAINID)
                                {
                                    if (rt.IsConversion())
                                    {
                                        // this will be a conversion, optionally followed by a cross-chain transfer, output the conversion reserve transfer from the import
                                        // look for the export finalization on the export transaction, and get the import that spends it
                                        CObjectFinalization of;
                                        for (; i < spendingTx.vout.size(); i++)
                                        {
                                            if ((of = CObjectFinalization(spendingTx.vout[i].scriptPubKey)).IsValid() &&
                                                of.output.hash.IsNull() &&
                                                of.output.n == exportOutNum)
                                            {
                                                break;
                                            }
                                            of = CObjectFinalization();
                                        }
                                        if (of.IsValid())
                                        {
                                            CSpentIndexDbEntry spentFinalizationEntry({CSpentIndexKey(spendingTx.GetHash(), i), CSpentIndexValue()});
                                            CTransaction importTx;
                                            uint256 importBlockHash;
                                            BlockMap::iterator bIT;
                                            if (GetSpentIndex(spentFinalizationEntry.first, spentFinalizationEntry.second) &&
                                                myGetTransaction(spentFinalizationEntry.second.txid, importTx, importBlockHash, false) &&
                                                !importBlockHash.IsNull() &&
                                                (bIT = mapBlockIndex.find(importBlockHash)) != mapBlockIndex.end() &&
                                                chainActive.Contains(bIT->second))
                                            {
                                                ret.pushKV("processedoutputs", GetTransferImportProgress(importTx, rt, rtIndexNum, bIT->second->nTime, bIT->second->GetHeight(), pCurrenciesCostBases, pIncomingCostBases, pOutgoingCostBases, pAggregateEarnings, pNativePriceMap));
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    ret.pushKV("destinationsystem", ConnectedChains.GetFriendlyCurrencyName(progressExport.destSystemID));
                                    ret.pushKV("exporttxid", spendingTx.GetHash().GetHex());
                                    ret.pushKV("reservetransferexportindex", rtIndexNum);

                                    // take needed currency for off-chain send from any available currency and cost basis, and add to the off-chain export
                                    if (pOutgoingCostBases && pCurrenciesCostBases)
                                    {
                                        int64_t amountLeft = 0;
                                        std::vector<std::tuple<uint32_t, int64_t, int64_t>> outGoingCostBases = pCurrenciesCostBases->TakeCurrency(rt.FirstCurrency(), rt.FirstValue(), amountLeft);
                                        for (auto &oneCostBasis : outGoingCostBases)
                                        {
                                            (*pOutgoingCostBases)[{spendingTx.GetHash(), rtIndexNum}].insert({{rt.FirstCurrency(), std::get<0>(oneCostBasis)},{std::get<1>(oneCostBasis), std::get<2>(oneCostBasis)}});
                                        }
                                        if (amountLeft)
                                        {
                                            (*pOutgoingCostBases)[{spendingTx.GetHash(), rtIndexNum}].insert({{rt.FirstCurrency(), blockIter->second->nTime}, {0, amountLeft}});
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (pending)
            {
                ret = UniValue(UniValue::VOBJ);
                ret.pushKV("status", "pending");
            }
        }
    }
    return ret;
}

bool CConnectedChains::GetLastImport(const uint160 &currencyID,
                                     CTransaction &lastImport,
                                     int32_t &outputNum)
{
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> memPoolOutputs;

    LOCK2(cs_main, mempool.cs);

    uint160 importKey = CCrossChainRPCData::GetConditionID(currencyID, CCrossChainImport::CurrencyImportKey());

    std::vector<std::pair<CInputDescriptor, uint32_t>> unspentOutputs;
    if (!GetUnspentByIndex(importKey, unspentOutputs))
    {
        return false;
    }

    // drop out on first match
    const std::pair<CAddressUnspentKey, CAddressUnspentValue> *pOutput = NULL;
    COptCCParams p;
    CAddressUnspentDbEntry foundOutput;
    for (const auto &output : unspentOutputs)
    {
        uint256 blockHash;
        if (output.first.scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
            p.vData.size() &&
            myGetTransaction(output.first.txIn.prevout.hash, lastImport, blockHash))
        {
            outputNum = output.first.txIn.prevout.n;
            return true;
        }
    }
    return false;
}

bool CConnectedChains::GetLastSourceImport(const uint160 &sourceSystemID,
                                            CTransaction &lastImport,
                                            int32_t &outputNum)
{
    std::vector<CAddressUnspentDbEntry> unspentOutputs;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> memPoolOutputs;

    LOCK2(cs_main, mempool.cs);

    uint160 importKey = CCrossChainRPCData::GetConditionID(sourceSystemID, CCrossChainImport::CurrencySystemImportKey());

    if (mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({std::make_pair(importKey, CScript::P2IDX)}), memPoolOutputs) &&
        memPoolOutputs.size())
    {
        // make sure it isn't just a burned transaction to that address, drop out on first match
        COptCCParams p;
        CAddressUnspentDbEntry foundOutput;
        std::set<COutPoint> spentTxOuts;
        std::set<COutPoint> txOuts;

        for (const auto &oneOut : memPoolOutputs)
        {
            // get last one in spending list
            if (oneOut.first.spending)
            {
                CTransaction priorOutTx;
                uint256 blockHash;
                CTransaction curTx;

                if (mempool.lookup(oneOut.first.txhash, curTx) &&
                    curTx.vin.size() > oneOut.first.index)
                {
                    spentTxOuts.insert(curTx.vin[oneOut.first.index].prevout);
                }
                else
                {
                    throw JSONRPCError(RPC_DATABASE_ERROR, "Unable to retrieve data for prior import");
                }
            }
        }
        for (auto &oneOut : memPoolOutputs)
        {
            if (!oneOut.first.spending && !spentTxOuts.count(COutPoint(oneOut.first.txhash, oneOut.first.index)))
            {
                lastImport = mempool.mapTx.find(oneOut.first.txhash)->GetTx();
                outputNum = oneOut.first.index;
                return true;
            }
        }
    }

    // get last import from the specified chain
    if (!GetAddressUnspent(importKey, CScript::P2IDX, unspentOutputs))
    {
        return false;
    }

    // make sure it isn't just a burned transaction to that address, drop out on first match
    const std::pair<CAddressUnspentKey, CAddressUnspentValue> *pOutput = NULL;
    COptCCParams p;
    CAddressUnspentDbEntry foundOutput;
    for (const auto &output : unspentOutputs)
    {
        if (output.second.script.IsPayToCryptoCondition(p) && p.IsValid() &&
            p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
            p.vData.size())
        {
            foundOutput = output;
            pOutput = &foundOutput;
            break;
        }
    }
    if (!pOutput)
    {
        return false;
    }
    uint256 hashBlk;
    CCurrencyDefinition newCur;

    if (!myGetTransaction(pOutput->first.txhash, lastImport, hashBlk))
    {
        return false;
    }

    outputNum = pOutput->first.index;

    return true;
}

void CheckPBaaSAPIsValid()
{
    //printf("Solution version running: %d\n\n", CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()));
    if (!chainActive.LastTip() ||
        CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight() + 1) < CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS)
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "PBaaS not activated on blockchain.");
    }
}

void CheckVerusVaultAPIsValid()
{
    //printf("Solution version running: %d\n\n", CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()));
    if (!chainActive.LastTip() ||
        CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()) < CConstVerusSolutionVector::activationHeight.ACTIVATE_VERUSVAULT)
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Verus Vault and VerusID Marketplace not activated on blockchain.");
    }
}

void CheckIdentityAPIsValid()
{
    if (!chainActive.LastTip() ||
        CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()) < CConstVerusSolutionVector::activationHeight.ACTIVATE_IDENTITY)
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Identity APIs not activated on blockchain.");
    }
}

// returns an i-address string when given a 20 byte hex representation
std::string ConvertAlternateRepresentations(const std::string &paramStr)
{
    // to enable easy conversion from a hex value representation of a currency, which is used in PBaaS folders and
    // conf file names to ensure case insensitive support for unique folders and file names, the prefix "hex:" is allowed
    // on currency names, or even IDs.
    if (paramStr.length() == 44 && paramStr.substr(0, 4) == "hex:")
    {
        std::string hexVal = paramStr.substr(4, 40);
        if (IsHex(hexVal))
        {
            CIdentityID idID;
            idID.SetHex(hexVal);
            return EncodeDestination(idID);
        }
    }
    return paramStr;
}

bool GetOpRetChainOffer(const CTransaction &postedTx,
                        CTransaction &offerTx,
                        CTransaction &inputToOfferTx,
                        uint32_t height,
                        bool getUnexpired,
                        bool getExpired,
                        uint256 &offerBlockHash)
{
    std::vector<CBaseChainObject *> opRetArray;
    CPartialTransactionProof offerTxProof;
    bool isPartial = false, incompleteTx = false;
    COptCCParams p;
    CSpentIndexKey spentKey = CSpentIndexKey(postedTx.GetHash(), 1);
    CSpentIndexValue spentValue;
    CTransaction opRetTx;
    uint256 opRetBlockHash;

    if (postedTx.vout.size() > 1 &&
        postedTx.vout[0].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        (p.evalCode == EVAL_IDENTITY_COMMITMENT || p.evalCode == EVAL_IDENTITY_PRIMARY) &&
        postedTx.vout[0].nValue >= DEFAULT_TRANSACTION_FEE &&
        ((postedTx.vout.back().scriptPubKey.IsOpReturn() &&
          (opRetArray = RetrieveOpRetArray((opRetTx = postedTx).vout.back().scriptPubKey)).size() == 1) ||
         (GetSpentIndex(spentKey, spentValue) &&
          myGetTransaction(spentValue.txid, opRetTx, opRetBlockHash)  &&
          (opRetArray = RetrieveOpRetArray(opRetTx.vout.back().scriptPubKey)).size() == 1)) &&
        opRetArray[0]->objectType == CHAINOBJ_TRANSACTION_PROOF &&
        (offerTxProof = ((CChainObject<CPartialTransactionProof> *)(opRetArray[0]))->object).IsValid() &&
        !offerTxProof.GetPartialTransaction(offerTx, &isPartial).IsNull() &&
        !isPartial &&
        offerTx.vout.size() == 1 &&
        offerTx.vin.size() == 1 &&
        offerTx.vShieldedSpend.size() == 0 &&
        ((spentKey = CSpentIndexKey(offerTx.vin[0].prevout.hash, offerTx.vin[0].prevout.n), !GetSpentIndex(spentKey, spentValue))) &&
        ((getExpired && offerTx.nExpiryHeight <= height) || (getUnexpired && offerTx.nExpiryHeight > height)) &&
        myGetTransaction(offerTx.vin[0].prevout.hash, inputToOfferTx, offerBlockHash))
    {
        return true;
    }
    else if (getExpired &&
             !(offerTxProof.IsValid() && !isPartial && offerTx.nExpiryHeight > height) &&
             p.IsValid() &&
             p.evalCode == EVAL_IDENTITY_COMMITMENT &&
             postedTx.vout[0].nValue >= DEFAULT_TRANSACTION_FEE &&
             p.vData.size() > 1 &&
             COptCCParams(p.vData.back()).vKeys.size() > 1 &&
             myGetTransaction(postedTx.GetHash(), inputToOfferTx, offerBlockHash) &&
             !offerBlockHash.IsNull() &&
             mapBlockIndex.count(offerBlockHash) &&
             (mapBlockIndex[offerBlockHash]->GetHeight() + DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA) < height)
    {
        CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), height);
        mtx.vin.push_back(CTxIn(postedTx.GetHash(), 0));
        mtx.vout.push_back(postedTx.vout[0]);
        mtx.nExpiryHeight = std::min(height - 1, (uint32_t)0);
        offerTx = mtx;
        return true;
    }

    return false;
}

bool GetOpRetChainOffer(const CTransaction &postedTx,
                        CTransaction &offerTx,
                        CTransaction &inputToOfferTx,
                        uint32_t height)
{
    bool getUnexpired = true;
    bool getExpired = false;
    uint256 offerBlockHash;
    return GetOpRetChainOffer(postedTx, offerTx, inputToOfferTx, height, getUnexpired, getExpired, offerBlockHash);
}

LRUCache<std::tuple<int, uint256, uint160>, std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>>> OfferMapCache(50);

// Get internal, compact form of an offer map (on-chain order book) for a currency or ID
//
// This will retrieve all offers for the indicated currency in all currencies or as specified in the filter,
// and also all offers for the particular currency in the indicated currencies.
//
// key is (iscurrency == 1 || 0, currencyoridoffered, forcurrencyorid, price, amount offered),
// value is pair((0 = ID, 1 = currency, CurrencyValueMap to pay/0 val for ID) (CInputDescriptor, CTransaction)
std::multimap<std::tuple<int, uint160, uint160, int64_t, int64_t>, std::pair<std::pair<int, CCurrencyValueMap>, std::pair<CInputDescriptor, CTransaction>>>
GetOfferMap(const uint160 &currencyOrId, bool isCurrency, bool acceptOnlyCurrency, bool acceptOnlyId, const std::set<uint160> &currencyOrIdFilter)
{
    std::multimap<std::tuple<int, uint160, uint160, int64_t, int64_t>, std::pair<std::pair<int, CCurrencyValueMap>, std::pair<CInputDescriptor, CTransaction>>>
            retVal;

    LOCK(cs_main);

    CCurrencyDefinition currencyDef;
    CIdentity identity;

    uint160 lookupID, lookupForID;

    if (isCurrency)
    {
        currencyDef = ConnectedChains.GetCachedCurrency(currencyOrId);
        if (!currencyDef.IsValid())
        {
            LogPrint("marketplace", "%s: invalid currency (%s) specified or cannot be found\n", __func__, EncodeDestination(CIdentityID(currencyOrId)).c_str());
            return retVal;
        }
        lookupForID = COnChainOffer::OnChainOfferForCurrencyKey(currencyOrId);
        lookupID = COnChainOffer::OnChainCurrencyOfferKey(currencyOrId);
    }
    else
    {
        if (!(identity = CIdentity::LookupIdentity(currencyOrId)).IsValid())
        {
            LogPrint("marketplace", "%s: invalid identity (%s) specified or cannot be found\n", __func__, EncodeDestination(CIdentityID(currencyOrId)).c_str());
            return retVal;
        }
        lookupForID = COnChainOffer::OnChainOfferForIdentityKey(currencyOrId);
        lookupID = COnChainOffer::OnChainIdentityOfferKey(currencyOrId);
    }

    uint32_t height = chainActive.Height();

    // bool is "iscurrency" for the offer in a buy and for the request for payment in a sell

    // offers to buy with IDs
    std::multimap<std::pair<uint160, CAmount>, UniValue> uniBuyWithIDs;
    std::multimap<std::pair<uint160, CAmount>, UniValue> uniSellToIDs;

    std::multimap<std::pair<uint160, CAmount>, UniValue> uniBuyWithCurrency;
    std::multimap<std::pair<uint160, CAmount>, UniValue> uniSellToCurrency;

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputOffers;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs = OfferMapCache.Get({(int)isCurrency, chainActive[height]->GetBlockHash(), currencyOrId});

    //printf("%s: looking up keys: %s, %s\n", __func__, EncodeDestination(CKeyID(lookupID)).c_str(), EncodeDestination(CKeyID(lookupForID)).c_str());

    if (!unspentOutputs.size() &&
        (!GetAddressUnspent(lookupID, CScript::P2PKH, unspentOutputOffers) ||
         !GetAddressUnspent(lookupForID, CScript::P2PKH, unspentOutputs) ||
         (!unspentOutputOffers.size() && !unspentOutputs.size())))
    {
        return retVal;
    }
    else
    {
        unspentOutputs.insert(unspentOutputs.end(), unspentOutputOffers.begin(), unspentOutputOffers.end());
        OfferMapCache.Put({(int)isCurrency, chainActive[height]->GetBlockHash(), currencyOrId}, unspentOutputs);

        for (auto &oneOffer : unspentOutputs)
        {
            CTransaction postedTx, offerTx, inputToOfferTx;
            uint256 blockHash;
            CPartialTransactionProof offerTxProof;
            COptCCParams p;
            if (myGetTransaction(oneOffer.first.txhash, postedTx, blockHash))
            {
                if (GetOpRetChainOffer(postedTx, offerTx, inputToOfferTx, height))
                {
                    // find out what the transaction is requesting for payment
                    CCurrencyValueMap offerToPay, wePay;
                    CIdentity offerToTransfer, weTransfer;

                    std::pair<CTxOut, CTxOut> offerOuts(std::make_pair(inputToOfferTx.vout[offerTx.vin[0].prevout.n], offerTx.vout[0]));
                    if (offerTx.vShieldedOutput.size() != 0)
                    {
                        offerOuts.second.nValue -= offerTx.valueBalance;
                    }

                    if (offerOuts.second.scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() &&
                        p.evalCode == EVAL_IDENTITY_PRIMARY &&
                        p.vData.size())
                    {
                        if (!(weTransfer = CIdentity(p.vData[0])).IsValid())
                        {
                            continue;
                        }

                        // if this is not what we are looking for, then it must be a request to trade for what we are looking for
                        if (isCurrency || weTransfer.GetID() != currencyOrId)
                        {
                            // if we are not looking to acquire what we look for, but only offers for it, continue
                            if ((isCurrency && acceptOnlyId) ||
                                (!isCurrency && acceptOnlyCurrency) ||
                                (currencyOrIdFilter.size() && !currencyOrIdFilter.count(currencyOrId)))
                            {
                                continue;
                            }

                            // make sure the offer is offering what we are looking for
                            int64_t price = 0;
                            if (isCurrency)
                            {
                                // verify it is the currency we are looking for
                                p = COptCCParams();
                                if (!(offerOuts.first.scriptPubKey.IsSpendableOutputType(p) &&
                                     ((currencyOrId == ASSETCHAINS_CHAINID && offerOuts.first.nValue > 0) ||
                                      ((currencyOrId != ASSETCHAINS_CHAINID &&
                                       (offerToPay = offerOuts.first.ReserveOutValue()).valueMap.count(currencyOrId) &&
                                        offerToPay.valueMap[currencyOrId] > 0)))))
                                {
                                    continue;
                                }
                                if (offerOuts.first.nValue > 0)
                                {
                                    offerToPay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.first.nValue;
                                }
                                price = offerToPay.valueMap[currencyOrId];
                            }
                            else
                            {
                                // verify it is an ID we are looking for
                                if (!(offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                      p.IsValid() &&
                                      p.evalCode == EVAL_IDENTITY_PRIMARY &&
                                      p.vData.size() &&
                                      (offerToTransfer = CIdentity(p.vData[0])).IsValid() &&
                                      offerToTransfer.GetID() == currencyOrId))
                                {
                                    continue;
                                }
                            }

                            retVal.insert(std::make_pair(std::tuple<int, uint160, uint160, int64_t, int64_t>({(int)!offerToTransfer.IsValid(),
                                                                                                              currencyOrId,
                                                                                                              weTransfer.GetID(),
                                                                                                              price,
                                                                                                              price}),
                                                         std::make_pair(std::make_pair((int64_t)0, CCurrencyValueMap(std::vector<uint160>({weTransfer.GetID()}), std::vector<int64_t>({0}))),
                                                                        std::make_pair(CInputDescriptor(offerOuts.second.scriptPubKey,
                                                                                                        offerOuts.second.nValue,
                                                                                                        CTxIn(COutPoint(oneOffer.first.txhash, 0))),
                                                                                       offerTx))));
                        }
                        else // this is an offer to buy the ID specified in currencyOrId for either currency or another ID, which is in the first output
                        {
                            if (!acceptOnlyCurrency &&
                                offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                p.IsValid() &&
                                p.evalCode == EVAL_IDENTITY_PRIMARY &&
                                p.vData.size() &&
                                (offerToTransfer = CIdentity(p.vData[0])).IsValid() &&
                                !(currencyOrIdFilter.size() && !currencyOrIdFilter.count(offerToTransfer.GetID())))
                            {
                                retVal.insert(std::make_pair(std::tuple<int, uint160, uint160, int64_t, int64_t>({0,
                                                                                                                  offerToTransfer.GetID(),
                                                                                                                  currencyOrId,
                                                                                                                  0,
                                                                                                                  0}),
                                                             std::make_pair(std::make_pair((int64_t)0, CCurrencyValueMap(std::vector<uint160>({currencyOrId}), std::vector<int64_t>({0}))),
                                                                            std::make_pair(CInputDescriptor(offerOuts.second.scriptPubKey,
                                                                                                            offerOuts.second.nValue,
                                                                                                            CTxIn(COutPoint(oneOffer.first.txhash, 0))),
                                                                                           offerTx))));
                            }
                            else if (!acceptOnlyId && !offerToTransfer.IsValid())
                            {
                                // verify that there is a non-zero offer
                                if (!(offerOuts.first.scriptPubKey.IsSpendableOutputType(p) &&
                                      p.IsValid() &&
                                      (offerOuts.first.nValue > 0 ||
                                       ((offerToPay = offerOuts.first.ReserveOutValue()) > CCurrencyValueMap()))))
                                {
                                    continue;
                                }

                                bool nativeOffer = offerOuts.first.nValue > 0 && !offerToPay.valueMap.size();
                                uint160 currencyID = nativeOffer ? ASSETCHAINS_CHAINID : offerToPay.valueMap.begin()->first;
                                CAmount offerAmount = nativeOffer ? offerOuts.first.nValue : offerToPay.valueMap.begin()->second;

                                retVal.insert(std::make_pair(std::tuple<int, uint160, uint160, int64_t, int64_t>({(int)!offerToTransfer.IsValid(),
                                                                                                                  currencyID,
                                                                                                                  weTransfer.GetID(),
                                                                                                                  offerAmount,
                                                                                                                  offerAmount}),
                                                            std::make_pair(std::make_pair((int64_t)0, CCurrencyValueMap(std::vector<uint160>({weTransfer.GetID()}), std::vector<int64_t>({0}))),
                                                                            std::make_pair(CInputDescriptor(offerOuts.second.scriptPubKey,
                                                                                                            offerOuts.second.nValue,
                                                                                                            CTxIn(COutPoint(oneOffer.first.txhash, 0))),
                                                                                        offerTx))));
                            }
                        }
                    }
                    else if (offerOuts.second.scriptPubKey.IsSpendableOutputType(p))
                    {
                        // see if it is a buy with or of the currency we are querying about
                        wePay = offerOuts.second.ReserveOutValue();
                        if (offerOuts.second.nValue > 0)
                        {
                            wePay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.second.nValue;
                        }

                        // if it is an offer to buy the currency we're inquiring about, then the offer should be in something else
                        if (isCurrency && wePay.valueMap.count(currencyOrId) && wePay.valueMap[currencyOrId] > 0)
                        {
                            // if so, then it is a buy with whatever the input is
                            if (offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                p.IsValid() &&
                                p.evalCode == EVAL_IDENTITY_PRIMARY &&
                                !acceptOnlyCurrency &&
                                p.vData.size() &&
                                (offerToTransfer = CIdentity(p.vData[0])).IsValid() &&
                                (!currencyOrIdFilter.size() || currencyOrIdFilter.count(offerToTransfer.GetID())))
                            {
                                retVal.insert(std::make_pair(std::tuple<int, uint160, uint160, int64_t, int64_t>({0,
                                                                                                                  offerToTransfer.GetID(),
                                                                                                                  currencyOrId,
                                                                                                                  wePay.valueMap[currencyOrId],
                                                                                                                  wePay.valueMap[currencyOrId]}),
                                                             std::make_pair(std::make_pair((int64_t)1, CCurrencyValueMap(std::vector<uint160>({currencyOrId}), std::vector<int64_t>({wePay.valueMap[currencyOrId]}))),
                                                                            std::make_pair(CInputDescriptor(offerOuts.second.scriptPubKey,
                                                                                                            offerOuts.second.nValue,
                                                                                                            CTxIn(COutPoint(oneOffer.first.txhash, 0))),
                                                                                           offerTx))));
                            }
                            // exchange with other currency
                            else if (!acceptOnlyId && p.IsValid() &&
                                     p.evalCode == EVAL_IDENTITY_COMMITMENT)
                            {
                                // verify that there is a non-zero offer
                                offerToPay = offerOuts.first.ReserveOutValue();
                                if (offerOuts.first.nValue > 0)
                                {
                                    offerToPay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.first.nValue;
                                }

                                p = COptCCParams();
                                offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p);
                                if (!offerToPay.CanonicalMap().valueMap.size())
                                {
                                    continue;
                                }

                                bool nativeOffer = offerOuts.first.nValue > 0 && offerToPay.CanonicalMap().valueMap.size() == 1;
                                uint160 currencyID;
                                CAmount offerAmount = 0;
                                if (nativeOffer)
                                {
                                    currencyID = ASSETCHAINS_CHAINID;
                                    offerAmount = offerOuts.first.nValue;
                                }
                                else if ((offerToPay.valueMap.size() - offerToPay.valueMap.count(ASSETCHAINS_CHAINID)) < 1)
                                {
                                    continue;
                                }
                                else
                                {
                                    CCurrencyValueMap nonNative = offerToPay;
                                    nonNative.valueMap.erase(ASSETCHAINS_CHAINID);
                                    currencyID = nonNative.valueMap.begin()->first;
                                    offerAmount = nonNative.valueMap.begin()->second;
                                }

                                // filter out if we should
                                if (currencyOrIdFilter.size() && !currencyOrIdFilter.count(currencyID))
                                {
                                    continue;
                                }

                                // calculate price
                                CAmount wePayAmount = wePay.valueMap.begin()->second;
                                if (wePay.valueMap.size() > 1)
                                {
                                    CCurrencyValueMap nonNative = wePay;
                                    nonNative.valueMap.erase(ASSETCHAINS_CHAINID);
                                    wePayAmount = nonNative.valueMap.begin()->second;
                                }

                                wePay = offerOuts.second.ReserveOutValue();
                                if (offerOuts.second.nValue > 0)
                                {
                                    wePay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.second.nValue;
                                }

                                retVal.insert(std::make_pair(std::tuple<int, uint160, uint160, int64_t, int64_t>({1,
                                                                                                                  currencyID,
                                                                                                                  currencyOrId,
                                                                                                                  offerAmount,
                                                                                                                  wePayAmount}),
                                                             std::make_pair(std::make_pair(1, CCurrencyValueMap(std::vector<uint160>({currencyOrId}), std::vector<int64_t>({wePay.valueMap[currencyOrId]}))),
                                                                            std::make_pair(CInputDescriptor(offerOuts.second.scriptPubKey,
                                                                                                            offerOuts.second.nValue,
                                                                                                            CTxIn(COutPoint(oneOffer.first.txhash, 0))),
                                                                                           offerTx))));
                            }
                        }
                        // offer to sell the specified currency for another
                        else if (isCurrency &&
                                 offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                 p.evalCode == EVAL_IDENTITY_COMMITMENT &&
                                 ((currencyOrId == ASSETCHAINS_CHAINID && offerOuts.first.nValue > 0) ||
                                 ((currencyOrId != ASSETCHAINS_CHAINID &&
                                 (offerToPay = offerOuts.first.ReserveOutValue()).valueMap.count(currencyOrId) &&
                                 offerToPay.valueMap[currencyOrId] > 0))))
                        {
                            if (offerOuts.first.nValue > 0)
                            {
                                offerToPay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.first.nValue;
                            }

                            // offer to sell currency we are querying for the output's currency
                            bool nativePay = offerOuts.second.nValue > 0 && wePay.CanonicalMap().valueMap.size() == 1;
                            uint160 currencyID = ASSETCHAINS_CHAINID;
                            CAmount payAmount = offerOuts.second.nValue;
                            if (!nativePay)
                            {
                                CCurrencyValueMap intermediateMap = wePay;
                                intermediateMap.valueMap.erase(ASSETCHAINS_CHAINID);
                                if (!intermediateMap.valueMap.size())
                                {
                                    LogPrint("marketplace", "%s: unrecognized currency payment required\n", __func__);
                                    continue;
                                }
                                currencyID = intermediateMap.valueMap.begin()->first;
                                payAmount = intermediateMap.valueMap.begin()->second;
                            }

                            if (currencyOrIdFilter.size() && !currencyOrIdFilter.count(currencyID))
                            {
                                continue;
                            }

                            retVal.insert(std::make_pair(std::tuple<int, uint160, uint160, int64_t, int64_t>({1,
                                                                                                              currencyOrId,
                                                                                                              currencyID,
                                                                                                              offerToPay.valueMap[currencyOrId],
                                                                                                              payAmount}),
                                                         std::make_pair(std::make_pair(1, CCurrencyValueMap(std::vector<uint160>({currencyID}), std::vector<int64_t>({payAmount}))),
                                                                        std::make_pair(CInputDescriptor(offerOuts.second.scriptPubKey,
                                                                                                        offerOuts.second.nValue,
                                                                                                        CTxIn(COutPoint(oneOffer.first.txhash, 0))),
                                                                                       offerTx))));
                        }
                        // offer to sell the specified ID for a currency
                        else if (!isCurrency &&
                                 offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                 p.IsValid() &&
                                 p.evalCode == EVAL_IDENTITY_PRIMARY &&
                                 p.vData.size() &&
                                 (offerToTransfer = CIdentity(p.vData[0])).IsValid() &&
                                 offerToTransfer.GetID() == currencyOrId)
                        {
                            bool nativePay = offerOuts.second.nValue > 0 && wePay.CanonicalMap().valueMap.size() == 1;
                            uint160 currencyID = nativePay ? ASSETCHAINS_CHAINID : wePay.valueMap.begin()->first;
                            CAmount payAmount = nativePay ? offerOuts.second.nValue : wePay.valueMap.begin()->second;

                            if (currencyOrIdFilter.size() && !currencyOrIdFilter.count(currencyID))
                            {
                                continue;
                            }

                            retVal.insert(std::make_pair(std::tuple<int, uint160, uint160, int64_t, int64_t>({0,
                                                                                                              currencyOrId,
                                                                                                              currencyID,
                                                                                                              payAmount,
                                                                                                              payAmount}),
                                                            std::make_pair(std::make_pair(1, CCurrencyValueMap(std::vector<uint160>({currencyID}), std::vector<int64_t>({payAmount}))),
                                                                        std::make_pair(CInputDescriptor(offerOuts.second.scriptPubKey,
                                                                                                        offerOuts.second.nValue,
                                                                                                        CTxIn(COutPoint(oneOffer.first.txhash, 0))),
                                                                                        offerTx))));
                        }
                    }
                    else
                    {
                        LogPrint("marketplace", "%s: marketplace supports exchange of identities and spendable outputs only\n", __func__);
                    }
                }
            }
            else
            {
                LogPrint("marketplace", "%s: cannot retrieve transaction %s, the local index is likely corrupted and either requires reindex, bootstrap, or resync\n", __func__, oneOffer.first.txhash.GetHex().c_str());
                return retVal;
            }
        }
    }
    return retVal;
}

UniValue takeoffer(const UniValue& params, bool fHelp);

// this takes a number of on-chain offers for the arbitrageCurrencySet, each paying in one of the reserves
// or the primary currency of the the notarization, which must be fractional.
bool SelectArbitrageFromOffers(const std::vector<
    std::multimap<std::tuple<int, uint160, uint160, int64_t, int64_t>, std::pair<std::pair<int, CCurrencyValueMap>, std::pair<CInputDescriptor, CTransaction>>>>
                                                        &offers,
                                                        const CPBaaSNotarization &lastNotarization,
                                                        const CCurrencyDefinition &sourceSystem,
                                                        const CCurrencyDefinition &destCurrency,
                                                        uint32_t startHeight,
                                                        uint32_t nextHeight,
                                                        std::vector<CReserveTransfer> &exportTransfers,
                                                        uint256 &transferHash,
                                                        CPBaaSNotarization &newNotarization,
                                                        std::vector<CTxOut> &newOutputs,
                                                        CCurrencyValueMap &importedCurrency,
                                                        CCurrencyValueMap &gatewayDepositsUsed,
                                                        CCurrencyValueMap &spentCurrencyOut,
                                                        const CTransferDestination &rewardDest,
                                                        const CCurrencyValueMap &arbitrageCurrencies,
                                                        std::vector<std::tuple<CInputDescriptor, CReserveTransfer, CTransaction>> &arbitrageInputs)
{
    if (pwalletMain && (VERUS_DEFAULT_ARBADDRESS.which() != COptCCParams::ADDRTYPE_INVALID && VERUS_DEFAULT_ARBADDRESS.which() != COptCCParams::ADDRTYPE_INDEX))
    {
        LOCK(pwalletMain->cs_wallet);

        static bool arbChecked = false;
        static bool canArb = true;

        if (!arbChecked)
        {
            arbChecked = true;
            if (VERUS_DEFAULT_ARBADDRESS.which() == COptCCParams::ADDRTYPE_ID)
            {
                std::pair<CIdentityMapKey, CIdentityMapValue> checkArbIdentity;
                if (!pwalletMain->GetIdentity(GetDestinationID(VERUS_DEFAULT_ARBADDRESS), checkArbIdentity) || !checkArbIdentity.first.CanSpend())
                {
                    LogPrintf("Arbitrage identity %s is not under control of current wallet\n", EncodeDestination(VERUS_DEFAULT_ARBADDRESS).c_str());
                    VERUS_DEFAULT_ARBADDRESS = CTxDestination();
                    canArb = false;
                }
            }
            else
            {
                if (!pwalletMain->HaveKey(GetDestinationID(VERUS_DEFAULT_ARBADDRESS)))
                {
                    LogPrintf("Arbitrage identity %s is not under control of current wallet\n", EncodeDestination(VERUS_DEFAULT_ARBADDRESS).c_str());
                    VERUS_DEFAULT_ARBADDRESS = CTxDestination();
                    canArb = false;
                }
            }
        }

        if (canArb)
        {
            std::vector<COutput> vCoins;

            // get total amounts of arbitrage currencies that we have available to use
            pwalletMain->AvailableReserveCoins(vCoins,
                                            false,
                                            nullptr,
                                            true,
                                            true,
                                            &VERUS_DEFAULT_ARBADDRESS,
                                            &arbitrageCurrencies, false);

            CCurrencyValueMap availableCurrencies;
            for (auto &oneOutput : vCoins)
            {
                CCurrencyValueMap oneOutVal = oneOutput.tx->vout[oneOutput.i].ReserveOutValue();
                if (oneOutput.tx->vout[oneOutput.i].nValue > 0)
                {
                    oneOutVal.valueMap[ASSETCHAINS_CHAINID] += oneOutput.tx->vout[oneOutput.i].nValue;
                }
                availableCurrencies += oneOutVal.IntersectingValues(arbitrageCurrencies);
            }

            if (availableCurrencies.CanonicalMap() > CCurrencyValueMap())
            {
                // Now, we have all cross-offers for all of the currencies we arbitrage. Each is represented by offers for
                // the currency in question in exchange for any of the other currencies in the basket or the basket currency itself.
                //
                // To arbitrage, we do the following:
                //
                // 1) Answer the question, for which of the offers, given that we would fulfill the on-chain offer and pass
                //    its output into the liquidity basket to convert to the original source, will we get more surplus of
                //    the funding currency out then the original amount entered? If that amount is positive, pass it to #2.
                //
                // 2) Make an arbitrage reserve transfer to convert into the amount needed to convert into enough to execute
                //    the offer selected.
                //
                // 3) Route the output of the import conversion into the offer, executing it and keeping both its output and
                //    any surplus.
                //
                // We can optimize wrt Verus or any currency.
                //

                std::vector<CTxOut> testOutputs;

                // get a preview of our liquidity basket, and if there are orders for those currencies in any currency we
                // arbitrage, and if we can get better execution for the same size by adding a reserve transfer to the liquidity
                // pool, create a transaction that funds the offer and also provides a reserve transfer into the liquidity pool,
                // pipe the same value that would be returned from the transaction into the reserve transfer, get the better execution
                // for same price as we bring the pricing closer to market for everyone, and take the difference in our wallet.
                bool success = lastNotarization.NextNotarizationInfo(sourceSystem,
                                                                    destCurrency,
                                                                    startHeight,
                                                                    nextHeight,
                                                                    exportTransfers,
                                                                    transferHash,
                                                                    newNotarization,
                                                                    testOutputs,
                                                                    importedCurrency,
                                                                    gatewayDepositsUsed,
                                                                    spentCurrencyOut,
                                                                    rewardDest);
                if (!success)
                {
                    return false;
                }

                uint160 currencyInID, currencyOutID;
                std::map<std::pair<uint160, uint160>, std::tuple<int64_t, int64_t, int64_t, std::pair<CInputDescriptor, CReserveTransfer>>> mostProfitablePairs;
                std::tuple<int64_t, int64_t, int64_t, std::pair<CInputDescriptor, CReserveTransfer>> mostProfitablePair;

                for (auto offerIt = offers.begin(); offerIt != offers.end(); offerIt++)
                {
                    // start at the highest priced offer with the highest amount (the most in the offered currency) and move down
                    // to see if we find an offer to execute that is profitable
                    // if we do, we continue to move down until we run out or see an unprofitable arb. we will only try another
                    // in this currency pair if:
                    // 1) the candidate is larger than the one we've already selected
                    // 2) we've not yet seen an unprofitable arb
                    //
                    // once we see an unprofitable arb, move to the next currency pair
                    //
                    auto rIt = offerIt->end();
                    if (rIt != offerIt->begin())
                    {
                        rIt--;
                        do
                        {
                            currencyInID = std::get<1>(rIt->first);
                            currencyOutID = std::get<2>(rIt->first);

                            CCurrencyValueMap neededCurrency;
                            neededCurrency.valueMap[ASSETCHAINS_CHAINID] = ConnectedChains.ThisChain().GetTransactionImportFee();
                            neededCurrency.valueMap[currencyOutID] += std::get<4>(rIt->first);
                            if (!(availableCurrencies - neededCurrency).HasNegative())
                            {
                                CAmount profit = 0;
                                auto lastProfitIt = mostProfitablePairs.find(std::make_pair(currencyInID, currencyOutID));

                                // TODO: for now, we are only going for the absolute most profit
                                CAmount profitToBeat = (lastProfitIt == mostProfitablePairs.end()) ? 0 : std::get<0>(mostProfitablePair);
                                CAmount thisSize = std::get<3>(rIt->first);

                                // basic sanity check to see if profit is possible
                                CCurrencyValueMap lastConversionPrices = newNotarization.currencyState.TargetLastConversionPrices(currencyOutID);
                                CAmount noSlipConversion = newNotarization.currencyState.NativeToReserveRaw(thisSize, lastConversionPrices.valueMap[currencyInID]);
                                bool isOneStep = currencyInID == newNotarization.currencyID || currencyOutID == newNotarization.currencyID;
                                int64_t discountFactor = (isOneStep ? (SATOSHIDEN - 25000) : (SATOSHIDEN - 50000));
                                noSlipConversion = CCurrencyDefinition::CalculateRatioOfValue(noSlipConversion, isOneStep ? (SATOSHIDEN - 25000) : (SATOSHIDEN - 50000));

                                // if the no-slip conversion is bigger than the the input we'd provide,
                                // we have a possibility of getting a positive output, so try it, otherwise, skip to the next pair
                                if (currencyInID == std::get<1>(rIt->first) &&
                                    currencyOutID == std::get<2>(rIt->first) &&
                                    rIt->second.first.second.valueMap.count(currencyOutID) &&
                                    (noSlipConversion - neededCurrency.valueMap[currencyOutID]) > 0)
                                {
                                    uint32_t transferFlags = CReserveTransfer::VALID + CReserveTransfer::ARBITRAGE_ONLY + CReserveTransfer::CONVERT;
                                    if (std::get<1>(rIt->first) == newNotarization.currencyID)
                                    {
                                        transferFlags |= CReserveTransfer::IMPORT_TO_SOURCE;
                                    }

                                    // add the new arb transfer as a what-if, determine how much it costs us to execute it,
                                    // how much comes out the end of the transfers, and how much potential profit we make
                                    CReserveTransfer oneTransfer(transferFlags,
                                                                CCurrencyValueMap(std::vector<uint160>({std::get<1>(rIt->first)}), std::vector<int64_t>({thisSize})),
                                                                ASSETCHAINS_CHAINID,
                                                                ConnectedChains.ThisChain().GetTransactionTransferFee(),
                                                                (transferFlags & CReserveTransfer::IMPORT_TO_SOURCE) ? std::get<2>(rIt->first) : newNotarization.currencyID,
                                                                DestinationToTransferDestination(VERUS_DEFAULT_ARBADDRESS),
                                                                ((transferFlags & CReserveTransfer::IMPORT_TO_SOURCE) ||
                                                                std::get<1>(rIt->first) == newNotarization.currencyID) ? uint160() : std::get<2>(rIt->first));

                                    exportTransfers.insert(exportTransfers.begin(), oneTransfer);
                                    testOutputs.clear();

                                    if (lastNotarization.NextNotarizationInfo(sourceSystem,
                                                                            destCurrency,
                                                                            startHeight,
                                                                            nextHeight,
                                                                            exportTransfers,
                                                                            transferHash,
                                                                            newNotarization,
                                                                            testOutputs,
                                                                            importedCurrency,
                                                                            gatewayDepositsUsed,
                                                                            spentCurrencyOut,
                                                                            rewardDest))
                                    {
                                        if (testOutputs.size())
                                        {
                                            CTxDestination ourDest;
                                            if (ExtractDestination(testOutputs.begin()->scriptPubKey, ourDest) && ourDest == VERUS_DEFAULT_ARBADDRESS)
                                            {
                                                CCurrencyValueMap outputVal = testOutputs.begin()->ReserveOutValue();
                                                if (testOutputs.begin()->nValue > 0)
                                                {
                                                    outputVal.valueMap[ASSETCHAINS_CHAINID] = testOutputs.begin()->nValue;
                                                }
                                                profit = newNotarization.currencyState.ReserveToNative(outputVal) - newNotarization.currencyState.ReserveToNative(neededCurrency);
                                            }
                                            else
                                            {
                                                profit = 0;
                                            }
                                        }
                                    }

                                    // remove test transfer
                                    exportTransfers.erase(exportTransfers.begin());

                                    if (profit > profitToBeat)
                                    {
                                        if (oneTransfer.IsValid())
                                        {
                                            mostProfitablePairs.insert(std::make_pair(std::make_pair(currencyInID, currencyOutID),
                                                                                    std::tuple<int64_t, int64_t, int64_t, std::pair<CInputDescriptor, CReserveTransfer>>(
                                                                                        {profit, thisSize, neededCurrency.valueMap[currencyOutID], std::make_pair(rIt->second.second.first, oneTransfer)})));
                                            mostProfitablePair = {profit, thisSize, neededCurrency.valueMap[currencyOutID], std::make_pair(rIt->second.second.first, oneTransfer)};
                                        }
                                    }
                                }
                            }

                            if (currencyInID != std::get<1>(rIt->first) || currencyOutID != std::get<2>(rIt->first))
                            {
                                // if we're done with this pair, go to the earliest to go backwards below
                                rIt = offerIt->lower_bound({1, currencyInID, currencyOutID, 0, 0});
                            }

                        // if out of space behind us, move to next set of offers
                        } while (rIt-- != offerIt->begin());

                        // now, we have a map of independently profitable pairs that we can also independently fulfill
                        // for the first version, just pick the one that is most profitable

                        // make a transaction that fulfills the offer and sends the output currency back to us via the transfer
                        // then add it to exporttransfers to be used below
                    }
                }

                UniValue result, error;
                // If we have a qualified arbitrage transaction, put it/them in the arbitrageInputs and add to export transfers
                if (mostProfitablePairs.size() &&
                    newNotarization.currencyState.NativeToReserve(std::get<0>(mostProfitablePair), newNotarization.currencyState.GetReserveMap()[ASSETCHAINS_CHAINID]) > (ConnectedChains.ThisChain().GetTransactionImportFee() << 4))
                {
                    // create a transaction for the most profitable arbitrage
                    UniValue takeOfferParams(UniValue::VARR);
                    takeOfferParams.push_back(EncodeDestination(VERUS_DEFAULT_ARBADDRESS));
                    UniValue objParam(UniValue::VOBJ);
                    objParam.pushKV("txid", std::get<3>(mostProfitablePair).first.txIn.prevout.hash.GetHex());
                    objParam.pushKV("changeaddress", EncodeDestination(VERUS_DEFAULT_ARBADDRESS));

                    // make a CTxOut for the reserve transfer in, and serialize it
                    CCcontract_info CC;
                    CCcontract_info *cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                    std::vector<CTxDestination> dests({DecodeDestination(cp->unspendableCCaddr), VERUS_DEFAULT_ARBADDRESS});
                    CScript scriptOut = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &std::get<3>(mostProfitablePair).second));

                    CCurrencyValueMap totalOut = std::get<3>(mostProfitablePair).second.reserveValues;
                    if (std::get<3>(mostProfitablePair).second.feeCurrencyID == ASSETCHAINS_CHAINID)
                    {
                        totalOut.valueMap[ASSETCHAINS_CHAINID] += std::get<3>(mostProfitablePair).second.nFees;
                    }

                    std::vector<unsigned char> txOutVec = ::AsVector(CTxOut(totalOut.valueMap[ASSETCHAINS_CHAINID], scriptOut));
                    UniValue acceptParam(UniValue::VOBJ);
                    acceptParam.pushKV("txout", HexBytes(&txOutVec[0], txOutVec.size()));
                    objParam.pushKV("accept", acceptParam);

                    UniValue deliverParam(UniValue::VOBJ);
                    deliverParam.pushKV("currency", EncodeDestination(CIdentityID(std::get<3>(mostProfitablePair).second.IsReserveToReserve() ? std::get<3>(mostProfitablePair).second.secondReserveID : std::get<3>(mostProfitablePair).second.destCurrencyID)));
                    deliverParam.pushKV("amount", ValueFromAmount(std::get<1>(mostProfitablePair)));
                    objParam.pushKV("deliver", deliverParam);
                    takeOfferParams.push_back(objParam);
                    takeOfferParams.push_back(true);

                    LogPrint("arbitrage", "%s: params to takeoffer:\n%s\n", __func__, takeOfferParams.write(1,2).c_str());
                    try
                    {
                        result = takeoffer(takeOfferParams, false);
                    }
                    catch(const UniValue& e)
                    {
                        error = e;
                    }
                    LogPrint("arbitrage", "%s: result from takeoffer:\n%s\n", __func__, error.isNull() ? result.write(1,2).c_str() : std::string("ERROR: ") + error.write().c_str());

                    if (error.isNull())
                    {
                        // add transaction, input, and reserve transfer to arbitrageInputs and reserve transfer to exportTransfers
                        CTransaction offerTx;
                        if (DecodeHexTx(offerTx, uni_get_str(find_value(result, "tx"))) &&
                            offerTx.vout.size() > 1)
                        {
                            int outIdx;
                            for (outIdx = 1; outIdx < offerTx.vout.size(); outIdx++)
                            {
                                if (::AsVector(offerTx.vout[outIdx]) == txOutVec)
                                {
                                    break;
                                }
                            }
                            if (outIdx < offerTx.vout.size())
                            {
                                arbitrageInputs.push_back({CInputDescriptor(offerTx.vout[outIdx].scriptPubKey, offerTx.vout[outIdx].nValue, CTxIn(offerTx.GetHash(), outIdx)), std::get<3>(mostProfitablePair).second, offerTx});
                                exportTransfers.push_back(std::get<3>(mostProfitablePair).second);
                            }
                        }
                    }
                }

                for (auto oneConversion : mostProfitablePairs)
                {
                    LogPrint("arbitrage", "one profitable arb transfer converting from %s to %s and back: profit: %ld, size: %ld, sourceamount: %ld\nReserveTransfer:\n%s\n",
                        ConnectedChains.GetFriendlyCurrencyName(oneConversion.first.second).c_str(),
                        ConnectedChains.GetFriendlyCurrencyName(oneConversion.first.first).c_str(),
                        std::get<0>(oneConversion.second),
                        std::get<1>(oneConversion.second),
                        std::get<2>(oneConversion.second),
                        std::get<3>(oneConversion.second).second.ToUniValue().write(1,2).c_str());
                }
            }
        }
    }
    return lastNotarization.NextNotarizationInfo(sourceSystem,
                                                 destCurrency,
                                                 startHeight,
                                                 nextHeight,
                                                 exportTransfers,
                                                 transferHash,
                                                 newNotarization,
                                                 newOutputs,
                                                 importedCurrency,
                                                 gatewayDepositsUsed,
                                                 spentCurrencyOut,
                                                 rewardDest);
}

uint160 ValidateCurrencyName(std::string currencyStr, bool ensureCurrencyValid, CCurrencyDefinition *pCurrencyDef)
{
    std::string extraName;
    uint160 retVal;
    if (!currencyStr.size())
    {
        return retVal;
    }
    ParseSubNames(currencyStr, extraName, true);
    if (currencyStr.back() == '@')
    {
        return retVal;
    }
    CTxDestination currencyDest = DecodeDestination(currencyStr);
    if (currencyDest.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        currencyDest = DecodeDestination(currencyStr + "@");
    }
    uint160 currencyID = GetDestinationID(currencyDest);
    if (currencyDest.which() != COptCCParams::ADDRTYPE_INVALID)
    {
        if (currencyID == ConnectedChains.ThisChain().GetID() && (chainActive.Height() < 1 || _IsVerusActive()))
        {
            if (pCurrencyDef)
            {
                *pCurrencyDef = ConnectedChains.ThisChain();
            }
            return ConnectedChains.ThisChain().GetID();
        }
        // make sure there is such a currency defined on this chain
        if (ensureCurrencyValid)
        {
            CCurrencyDefinition currencyDef;
            if (GetCurrencyDefinition(currencyID, currencyDef) || !currencyDef.IsValid())
            {
                retVal = currencyDef.GetID();
                if (pCurrencyDef)
                {
                    *pCurrencyDef = currencyDef;
                }
            }
        }
        else
        {
            retVal = currencyID;
        }
    }
    return retVal;
}

uint160 GetChainIDFromParam(const UniValue &param, CCurrencyDefinition *pCurrencyDef=NULL)
{
    return ValidateCurrencyName(ConvertAlternateRepresentations(uni_get_str(param)), true, pCurrencyDef);
}

UniValue getcurrency(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getcurrency \"currencyname\"\n"
            "\nReturns a complete definition for any given chain if it is registered on the blockchain. If the chain requested\n"
            "\nis NULL, chain definition of the current chain is returned.\n"

            "\nArguments\n"
            "1. \"currencyname\"            (string, optional) name of the chain to look for. no parameter returns current chain in daemon.\n"
            "\nResult:\n"
            "  {\n"
            "    \"version\" : n,                           (int) version of this chain definition\n"
            "    \"name\" : \"string\",                     (string) name or symbol of the chain, same as passed\n"
            "    \"fullyqualifiedname\" : \"string\",       (string) name or symbol of the chain with all parent namespaces, separated by \".\"\n"
            "    \"currencyid\" : \"i-address\",            (string) string that represents the currency ID, same as the ID behind the currency\n"
            "    \"currencyidhex\" : \"hex\",               (string) hex representation of currency ID, getcurrency API supports \"hex:currencyidhex\"\n"
            "    \"parent\" : \"i-address\",                (string) parent blockchain ID\n"
            "    \"systemid\" : \"i-address\",              (string) system on which this currency is considered to run\n"
            "    \"launchsystemid\" : \"i-address\",        (string) system from which this currency was launched\n"
            "    \"notarizationprotocol\" : n               (int) protocol number that determines variations in cross-chain or bridged notarizations\n"
            "    \"proofprotocol\" : n                      (int) protocol number that determines variations in cross-chain or bridged proofs\n"
            "    \"startblock\" : n,                        (int) block # on this chain, which must be notarized into block one of the chain\n"
            "    \"endblock\" : n,                          (int) block # after which, this chain's useful life is considered to be over\n"
            "    \"currencies\" : \"[\"i-address\", ...]\", (stringarray) currencies that can be converted to this currency at launch or makeup a liquidity basket\n"
            "    \"weights\" : \"[n, ...]\",                (numberarray) relative currency weights (only returned for a liquidity basket)\n"
            "    \"conversions\" : \"[n, ...]\",            (numberarray) pre-launch conversion rates for non-fractional currencies\n"
            "    \"minpreconversion\" : \"[n, ...]\",       (numberarray) minimum amounts required in pre-conversions for currency to launch\n"
            "    \"currencies\" : \"[\"i-address\", ...]\", (stringarray) currencies that can be converted to this currency at launch or makeup a liquidity basket\n"
            "    \"currencynames\" : \"{\"i-address\":\"fullname\",...}\", (obj) i-addresses mapped to fully qualified names of all sub-currencies\n"
            "    \"initialsupply\" : n,                     (number) initial currency supply for fractional currencies before preallocation or issuance\n"
            "    \"prelaunchcarveout\" : n,                 (number) pre-launch percentage of proceeds for fractional currency sent to launching ID\n"
            "    \"preallocations\" : \"[{\"i-address\":n}, ...]\", (objarray) VerusIDs and amounts for pre-allocation at launch\n"
            "    \"initialcontributions\" : \"[n, ...]\",   (numberarray) amounts of pre-conversions reserved for launching ID\n"
            "    \"idregistrationfees\" : n,                (number) base cost of IDs for this currency namespace in this currency\n"
            "    \"idreferrallevels\" : n,                  (int) levels of ID referrals (only for native PBaaS chains and IDs)\n"
            "    \"idimportfees\" : n,                      (number) fees required to import an ID to this system (only for native PBaaS chains and IDs)\n"
            "    \"eras\" : \"[obj, ...]\",                 (objarray) different chain phases of rewards and convertibility\n"
            "    {\n"
            "      \"reward\" : \"[n, ...]\",               (int) reward start for each era in native coin\n"
            "      \"decay\" : \"[n, ...]\",                (int) exponential or linear decay of rewards during each era\n"
            "      \"halving\" : \"[n, ...]\",              (int) blocks between halvings during each era\n"
            "      \"eraend\" : \"[n, ...]\",               (int) block marking the end of each era\n"
            "      \"eraoptions\" : \"[n, ...]\",           (int) options (reserved)\n"
            "    }\n"
            "    \"nodes\"      : \"[obj, ..]\",    (objectarray, optional) up to 8 nodes that can be used to connect to the blockchain"
            "      [{\n"
            "         \"nodeidentity\" : \"txid\", (string,  optional) internet, TOR, or other supported address for node\n"
            "         \"paymentaddress\" : n,     (int,     optional) rewards payment address\n"
            "       }, .. ]\n"
            "    \"lastconfirmedcurrencystate\" : {\n"
            "     }\n"
            "    \"besttxid\" : \"txid\"\n"
            "     }\n"
            "    \"confirmednotarization\" : {\n"
            "     }\n"
            "    \"confirmedtxid\" : \"txid\"\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getcurrency", "\"currencyname\"")
            + HelpExampleRpc("getcurrency", "\"currencyname\"")
        );
    }

    LOCK2(cs_main, mempool.cs);
    CheckPBaaSAPIsValid();

    UniValue ret(UniValue::VOBJ);
    uint32_t height = chainActive.Height();

    CCurrencyDefinition chainDef;
    int32_t defHeight = 0;
    CUTXORef defUTXO;
    std::vector<CNodeData> goodNodes;

    uint160 chainID = ValidateCurrencyName(uni_get_str(params[0]));

    if (!GetCurrencyDefinition(chainID, chainDef, &defHeight, false, true, &defUTXO, &goodNodes))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency or currency not found");
    }

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency name or ID");
    }

    if (chainDef.IsValid())
    {
        ret = chainDef.ToUniValue();
        ret.pushKV("currencyidhex", chainDef.GetID().GetHex());
        ret.pushKV("fullyqualifiedname", ConnectedChains.GetFriendlyCurrencyName(chainID));
        ret.pushKV("magicnumber", ((int32_t)chainDef.MagicNumber()));

        if (chainDef.currencies.size())
        {
            UniValue curNames(UniValue::VOBJ);
            for (auto &oneCurID : chainDef.currencies)
            {
                curNames.pushKV(EncodeDestination(CIdentityID(oneCurID)), ConnectedChains.GetFriendlyCurrencyName(oneCurID));
            }
            ret.pushKV("currencynames", curNames);
        }

        if (defUTXO.IsValid())
        {
            ret.push_back(Pair("definitiontxid", defUTXO.hash.GetHex()));
            ret.push_back(Pair("definitiontxout", (int)defUTXO.n));
        }

        UniValue lastStateUni = ConnectedChains.GetCurrencyState(chainDef, height, defHeight).ToUniValue();

        if (chainDef.IsToken() && chainDef.systemID == ASSETCHAINS_CHAINID)
        {
            ret.push_back(Pair("bestheight", chainActive.Height()));
            ret.push_back(Pair("lastconfirmedheight", chainActive.Height()));
            ret.push_back(Pair("bestcurrencystate", lastStateUni));
            ret.push_back(Pair("lastconfirmedcurrencystate", lastStateUni));
        }
        else
        {
            CChainNotarizationData cnd;
            if (GetNotarizationData(chainDef.systemID, cnd) && cnd.IsConfirmed() &&
                cnd.vtx[cnd.lastConfirmed].second.currencyStates.count(chainID))
            {
                ret.push_back(Pair("bestheight", (int64_t)cnd.vtx[cnd.lastConfirmed].second.notarizationHeight));
                if (cnd.vtx[cnd.lastConfirmed].second.IsPreLaunch() && cnd.vtx[cnd.lastConfirmed].second.IsLaunchConfirmed())
                {
                    ret.push_back(Pair("lastconfirmedheight", 0));
                }
                else
                {
                    ret.push_back(Pair("lastconfirmedheight", (int64_t)cnd.vtx[cnd.lastConfirmed].second.notarizationHeight));
                }
                ret.push_back(Pair("bestcurrencystate", lastStateUni));
                ret.push_back(Pair("lastconfirmedcurrencystate", lastStateUni));
            }
            else
            {
                GetNotarizationData(chainID, cnd);

                int32_t confirmedHeight = -1, bestHeight = -1;

                std::set<std::string> nodeAddressSet;
                if (goodNodes.size())
                {
                    UniValue nodeArr(UniValue::VARR);
                    for (auto &oneNode : goodNodes)
                    {
                        if (!nodeAddressSet.count(oneNode.networkAddress))
                        {
                            nodeAddressSet.insert(oneNode.networkAddress);
                            nodeArr.push_back(oneNode.ToUniValue());
                        }
                    }
                    ret.push_back(Pair("nodes", nodeArr));
                }

                if (cnd.forks.size())
                {
                    confirmedHeight = cnd.vtx.size() && cnd.lastConfirmed != -1 ? cnd.vtx[cnd.lastConfirmed].second.notarizationHeight : -1;
                    bestHeight = cnd.vtx.size() && cnd.bestChain != -1 ? cnd.vtx[cnd.forks[cnd.bestChain].back()].second.notarizationHeight : -1;
                }

                if (chainID == ASSETCHAINS_CHAINID)
                {
                    int64_t curHeight = chainActive.Height();
                    ret.push_back(Pair("lastconfirmedheight", curHeight));
                    ret.push_back(Pair("lastconfirmedcurrencystate", lastStateUni));
                    ret.push_back(Pair("bestheight", curHeight));
                }
                else
                {
                    if (!chainDef.IsToken())
                    {
                        ret.push_back(Pair("lastconfirmedheight", confirmedHeight == -1 ? 0 : confirmedHeight));
                        if (confirmedHeight != -1)
                        {
                            ret.push_back(Pair("lastconfirmedtxid", cnd.vtx[cnd.lastConfirmed].first.hash.GetHex().c_str()));
                            ret.push_back(Pair("lastconfirmedcurrencystate", cnd.vtx[cnd.lastConfirmed].second.currencyState.ToUniValue()));
                        }
                    }
                    ret.push_back(Pair("bestheight", bestHeight == -1 ? 0 : bestHeight));
                    if (bestHeight != -1)
                    {
                        ret.push_back(Pair("besttxid", cnd.vtx[cnd.forks[cnd.bestChain].back()].first.hash.GetHex().c_str()));
                        ret.push_back(Pair("bestcurrencystate", cnd.vtx[cnd.forks[cnd.bestChain].back()].second.currencyState.ToUniValue()));
                    }
                }
            }
        }
        return ret;
    }
    else
    {
        return NullUniValue;
    }
}

UniValue getreservedeposits(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        throw runtime_error(
            "getreservedeposits \"currencyname\" (returnutxos)\n"
            "\nReturns all deposits under control of the specified currency or chain. If the currency is of an external system\n"
            "or chain, all deposits will be under the control of that system or chain only, not its independent currencies.\n"

            "\nArguments\n"
            "1. \"currencyname\"       (string, required)       full name or i-ID of controlling currency\n"
            "2. \"returnutxos\"        (bool, optional)         if true, returns a UTXO list and currency values on each\n"

            "\nResult:\n"
            "  {\n"
            "     \"utxos\" : {utxo and currency values},       if returnutxos == true, else null\n"
            "     \"currency 1 i-address\" : value,\n"
            "     \"currency 2 i-address\" : value,\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getreservedeposits", "\"currencyname\"")
            + HelpExampleRpc("getreservedeposits", "\"currencyname\"")
        );
    }

    CheckPBaaSAPIsValid();

    LOCK(cs_main);

    CCurrencyDefinition chainDef;

    uint160 chainID = ValidateCurrencyName(uni_get_str(params[0]), true, &chainDef);

    bool getUTXOs = false;
    if (params.size() > 1)
    {
        getUTXOs = uni_get_bool(params[1]);
    }

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency or currency not found " + uni_get_str(params[0]));
    }

    int32_t defHeight;
    std::vector<CInputDescriptor> reserveDeposits;

    {
        LOCK(mempool.cs);
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);
        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        view.SetBackend(viewMemPool);

        if (!ConnectedChains.GetReserveDeposits(chainID, view, reserveDeposits))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Error getting reserve deposits for on-chain currency");
        }
    }

    UniValue ret(UniValue::VOBJ);
    UniValue utxos(UniValue::VARR);

    CCurrencyValueMap totalReserveDeposits;
    for (auto &oneDeposit : reserveDeposits)
    {
        if (getUTXOs)
        {
            UniValue outputUni = CUTXORef(oneDeposit.txIn.prevout).ToUniValue();
            CCurrencyValueMap outCurMap = oneDeposit.scriptPubKey.ReserveOutValue();
            if (oneDeposit.nValue)
            {
                outCurMap.valueMap[ASSETCHAINS_CHAINID] += oneDeposit.nValue;
            }
            outputUni.pushKV("values", outCurMap.ToUniValue());
            utxos.push_back(outputUni);
        }

        CReserveDeposit rd;
        COptCCParams p;
        if (oneDeposit.scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_RESERVE_DEPOSIT &&
            p.vData.size() &&
            (rd = CReserveDeposit(p.vData[0])).IsValid())
        {
            rd.reserveValues.valueMap[ASSETCHAINS_CHAINID] = oneDeposit.nValue;
            totalReserveDeposits += rd.reserveValues;
        }
    }

    if (getUTXOs)
    {
        ret.pushKV("utxos", utxos);
    }

    if (totalReserveDeposits.valueMap.size())
    {
        for (auto &oneBalance : totalReserveDeposits.valueMap)
        {
            ret.push_back(make_pair(EncodeDestination(CIdentityID(oneBalance.first)), ValueFromAmount(oneBalance.second)));
        }
    }
    return ret;
}

UniValue getpendingtransfers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getpendingtransfers \"chainname\"\n"
            "\nReturns all pending transfers for a particular chain that have not yet been aggregated into an export\n"

            "\nArguments\n"
            "1. \"chainname\"                     (string, optional) name of the chain to look for. no parameter returns current chain in daemon.\n"

            "\nResult:\n"
            "  {\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getpendingtransfers", "\"chainname\"")
            + HelpExampleRpc("getpendingtransfers", "\"chainname\"")
        );
    }

    CheckPBaaSAPIsValid();

    LOCK(cs_main);

    uint160 chainID = GetChainIDFromParam(params[0]);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    CCurrencyDefinition chainDef;
    int32_t defHeight;

    if (GetCurrencyDefinition(chainID, chainDef, &defHeight))
    {
        std::vector<ChainTransferData> unspentOutputs;

        if (GetUnspentChainTransfers(unspentOutputs, chainID))
        {
            UniValue ret(UniValue::VARR);

            for (auto &desc : unspentOutputs)
            {
                UniValue oneExport(UniValue::VOBJ);
                if (std::get<2>(desc).IsValid())
                {
                    oneExport.push_back(Pair("currencyid", EncodeDestination(CIdentityID(chainID))));
                    oneExport.push_back(Pair("height", (int64_t)std::get<0>(desc)));
                    oneExport.push_back(Pair("txid", std::get<1>(desc).txIn.prevout.hash.GetHex()));
                    oneExport.push_back(Pair("n", (int32_t)std::get<1>(desc).txIn.prevout.n));
                    oneExport.push_back(Pair("valueout", std::get<1>(desc).nValue));
                    oneExport.push_back(Pair("reservetransfer", std::get<2>(desc).ToUniValue()));
                    ret.push_back(oneExport);
                }
            }
            if (ret.size())
            {
                return ret;
            }
        }
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unrecognized currency name or ID");
    }

    return NullUniValue;
}

UniValue getexports(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        throw runtime_error(
            "getexports \"chainname\" (heightstart) (heightend)\n"
            "\nReturns pending export transfers to the specified currency from start height to end height if specified\n"

            "\nArguments\n"
            "\"chainname\"                      (string, required)  name/ID of the currency to look for. no parameter returns current chain\n"
            "\"heightstart\"                    (int, optional)     default=0 only return exports at or above this height\n"
            "\"heightend\"                      (int, optional)     dedfault=maxheight only return exports below or at this height\n"

            "\nResult:\n"
            "  [{\n"
            "     \"height\": n,"
            "     \"txid\": \"hexid\","
            "     \"txoutnum\": n,"
            "     \"partialtransactionproof\": \"hexstr\","             // proof's are relative to the heightend, if specified. if not, they are invalid
            "     \"transfers\": [{transfer1}, {transfer2},...]"
            "  }, ...]\n"

            "\nExamples:\n"
            + HelpExampleCli("getexports", "\"chainname\" (heightstart) (heightend)")
            + HelpExampleRpc("getexports", "\"chainname\" (heightstart) (heightend)")
        );
    }

    CheckPBaaSAPIsValid();

    LOCK2(cs_main, mempool.cs);

    uint160 currencyID;
    CCurrencyDefinition curDef;
    std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> exports;

    if ((currencyID = ValidateCurrencyName(uni_get_str(params[0]), true, &curDef)).IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    uint32_t fromHeight = 0, toHeight = INT32_MAX;
    uint32_t proofHeight = 0;
    uint32_t nHeight = chainActive.Height();

    if (params.size() > 1)
    {
        fromHeight = uni_get_int64(params[1]);
    }
    if (params.size() > 2)
    {
        toHeight = uni_get_int64(params[2]);
        proofHeight = toHeight != 0 && (toHeight < nHeight) ? toHeight : nHeight;
        toHeight = proofHeight;
    }

    if ((curDef.IsGateway() && curDef.gatewayID == currencyID) ||
        (curDef.systemID == currencyID))
    {
        ConnectedChains.GetSystemExports(currencyID, exports, fromHeight, toHeight, true);
    }
    else
    {
        ConnectedChains.GetCurrencyExports(currencyID, exports, fromHeight, toHeight);
    }

    UniValue retVal(UniValue::VARR);

    for (auto &oneExport : exports)
    {
        UniValue oneObj(UniValue::VOBJ);
        CTransaction tx;
        uint256 blkHash;
        if (!myGetTransaction(oneExport.first.first.txIn.prevout.hash, tx, blkHash) || blkHash.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid export transaction");
        }
        auto indexIt = mapBlockIndex.find(blkHash);
        if (indexIt == mapBlockIndex.end())
        {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "transaction for export not found in main block index");
        }
        oneObj.push_back(Pair("height", indexIt->second->GetHeight()));
        oneObj.push_back(Pair("txid", oneExport.first.first.txIn.prevout.hash.GetHex()));
        oneObj.push_back(Pair("txoutnum", (int64_t)oneExport.first.first.txIn.prevout.n));
        CCrossChainExport ccx(oneExport.first.first.scriptPubKey);
        oneObj.push_back(Pair("exportinfo", ccx.ToUniValue()));
        if (oneExport.first.second.IsValid())
        {
            oneObj.push_back(Pair("partialtransactionproof", oneExport.first.second.ToUniValue()));
        }

        UniValue transferArr(UniValue::VARR);
        for (auto &oneTransfer : oneExport.second)
        {
            /* // check serialization discrepancies
            if (oneTransfer.IsCurrencyExport() && oneTransfer.destination.TypeNoFlags() == oneTransfer.destination.DEST_REGISTERCURRENCY)
            {
                CCurrencyDefinition exportDef = CCurrencyDefinition(oneTransfer.destination.destination);
                CCurrencyDefinition curDef = ConnectedChains.GetCachedCurrency(exportDef.GetID());
                auto exportDefVec = ::AsVector(exportDef);
                auto onChainDefVec = ::AsVector(curDef);
                auto translatedDefVec = ::AsVector(CCurrencyDefinition(exportDef.ToUniValue()));
                if (exportDefVec != onChainDefVec || onChainDefVec != translatedDefVec)
                {
                    printf("Exported currency:\n%s\nOn-chain currency:\n%s\nSerialized export:\n%s\nSerialized on-chain:\n%s\nSerialized translated:\n%s\n",
                        exportDef.ToUniValue().write(1,2).c_str(),
                        curDef.ToUniValue().write(1,2).c_str(),
                        HexBytes(&(exportDefVec[0]), exportDefVec.size()).c_str(),
                        HexBytes(&(onChainDefVec[0]), onChainDefVec.size()).c_str(),
                        HexBytes(&(translatedDefVec[0]), translatedDefVec.size()).c_str());
                }
                auto transferVec = ::AsVector(oneTransfer);
                printf("ReserveTransfer:\n%s\nSerialized:\n%s\n", oneTransfer.ToUniValue().write(1,2).c_str(), HexBytes(&(transferVec[0]), transferVec.size()).c_str());
            } //*/
            transferArr.push_back(oneTransfer.ToUniValue());
        }
        oneObj.push_back(Pair("transfers", transferArr));

        retVal.push_back(oneObj);
    }

    return retVal;
}

UniValue submitimports(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "submitimports '{\"sourcesystemid\":\"systemid\", \"notarizationtxid\":\"txid\", \"notarizationtxoutnum\":n,\n"
            "\"exports\":[{\"txid\":\"hexid\", \"txoutnum\":n, \"partialtransactionproof\":\"hexstr\", \n"
            "\"transfers\": [{transfer1}, {transfer2},...]}, ...]}'\n\n"
            "\nAccepts a set of exports from another system to post to the " + VERUS_CHAINNAME + " network.\n"

            "\nArguments\n"
            "  {\n"
            "    \"sourcesystemid\":\"systemid\"        ()\n"
            "    \"notarizationtxid\":\"txid\"          ()\n"
            "    \"notarizationtxoutnum\":n             ()\n"
            "    \"exports\": [{\n"
            "       \"height\": n,\n"                                   // height on the other system of this export
            "       \"txid\": \"hexid\",\n"                             // export txid on the other system
            "       \"txoutnum\": n,\n"                                 // export tx out num on the other system
            "       \"partialtransactionproof\": \"hexstr\",\n"         // transaction proof, relative to the specified notarization
            "       \"transfers\": [{transfer1}, {transfer2},...]\n"    // all reserve transfers for this export
            "    }, ...]\n"
            "  }\n"

            "\nResult:\n"
            "  [{\n"                                                    // list of transactions and the specific cross chain outputs created
            "     \"currency\": \"currencyid\"\n"                       // destination currency
            "     \"txid\": \"hexid\",\n"                               // import txid
            "     \"txoutnum\": n\n"                                    // txoutnum on transaction
            "  }, ...]\n"

            "\nExamples:\n"
            + HelpExampleCli("submitimports", "{\"sourcesystemid\":\"systemid\", \"notarizationtxid\":\"txid\", \"notarizationtxoutnum\":n, \"exports\":[{\"height\":n, \"txid\":\"hexid\", \"txoutnum\":n, \"partialtransactionproof\":\"hexstr\", \"transfers\": [{transfer1}, {transfer2},...]}, ...]}")
            + HelpExampleRpc("submitimports", "{\"sourcesystemid\":\"systemid\", \"notarizationtxid\":\"txid\", \"notarizationtxoutnum\":n, \"exports\":[{\"height\":n, \"txid\":\"hexid\", \"txoutnum\":n, \"partialtransactionproof\":\"hexstr\", \"transfers\": [{transfer1}, {transfer2},...]}, ...]}")
        );
    }

    CheckPBaaSAPIsValid();

    if (!params[0].isObject())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. see help.");
    }

    LOCK(cs_main);

    CCurrencyDefinition curDef;
    uint160 sourceSystemID = ValidateCurrencyName(uni_get_str(find_value(params[0], "sourcesystemid")), true, &curDef);

    sourceSystemID = curDef.IsGateway() ? curDef.gatewayID : curDef.systemID;

    // source system must be a different system and an actual system
    if (sourceSystemID.IsNull() ||
        curDef.GetID() != sourceSystemID ||
        sourceSystemID == ASSETCHAINS_CHAINID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid chain name or chain ID");
    }

    uint256 notarizationTxId = uint256S(uni_get_str(find_value(params[0], "notarizationtxid")));
    int notarizationTxOutNum = uni_get_int(find_value(params[0], "notarizationtxoutnum"));
    CTransaction notarizationTx;
    uint256 blkHash;
    COptCCParams p;
    CPBaaSNotarization lastConfirmed;

    {
        LOCK2(smartTransactionCS, mempool.cs);

        if (!(!notarizationTxId.IsNull() &&
            myGetTransaction(notarizationTxId, notarizationTx, blkHash) &&
            !blkHash.IsNull() &&
            notarizationTxOutNum >= 0 &&
            notarizationTx.vout.size() > notarizationTxOutNum &&
            notarizationTx.vout[notarizationTxOutNum].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            (p.evalCode == EVAL_EARNEDNOTARIZATION || p.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
            p.vData.size() &&
            (lastConfirmed = CPBaaSNotarization(p.vData[0])).IsValid()))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid notarization transaction id or transaction");
        }
    }

    std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> exports;
    UniValue exportsUni = find_value(params[0], "exports");
    if (!exportsUni.isArray() ||
        !exportsUni.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "parameters must include valid exports to import");
    }

    for (int i = 0; i < exportsUni.size(); i++)
    {
        // create one import at a time
        uint256 exportTxId = uint256S(uni_get_str(find_value(exportsUni[i], "txid")));
        int32_t exportTxOutNum = uni_get_int(find_value(exportsUni[i], "txoutnum"));
        CPartialTransactionProof txProof = CPartialTransactionProof(find_value(exportsUni[i], "partialtransactionproof"));
        UniValue transferArrUni = find_value(exportsUni[i], "transfers");
        if (exportTxId.IsNull() ||
            exportTxOutNum == -1 ||
            !transferArrUni.isArray())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid export from " + uni_get_str(params[0]));
        }

        CTransaction exportTx;
        uint256 blkHash;
        auto proofRootIt = lastConfirmed.proofRoots.find(sourceSystemID);
        if (!(txProof.IsValid() &&
            !txProof.GetPartialTransaction(exportTx).IsNull() &&
            exportTxId == txProof.TransactionHash() &&
            proofRootIt != lastConfirmed.proofRoots.end() &&
            proofRootIt->second.stateRoot == txProof.CheckPartialTransaction(exportTx) &&
            exportTx.vout.size() > exportTxOutNum))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid export 1 from " + uni_get_str(params[0]));
        }

        std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>> oneExport =
            std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[exportTxOutNum].scriptPubKey,
                                            exportTx.vout[exportTxOutNum].nValue,
                                            CTxIn(exportTxId, exportTxOutNum)),
                                            txProof),
                            std::vector<CReserveTransfer>());

        for (int j = 0; j < transferArrUni.size(); j++)
        {
            oneExport.second.push_back(CReserveTransfer(transferArrUni[j]));
            if (!oneExport.second.back().IsValid())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid reserve transfers from export of " + uni_get_str(params[0]));
            }
        }
        exports.push_back(oneExport);
    }

    std::map<uint160, std::vector<std::pair<int, CTransaction>>> newImports;
    ConnectedChains.CreateLatestImports(curDef, CUTXORef(notarizationTxId, notarizationTxOutNum), exports, newImports);

    UniValue retVal(UniValue::VARR);
    for (auto &oneExportCurrency : newImports)
    {
        for (auto &oneExport : oneExportCurrency.second)
        {
            retVal.push_back(Pair("currencyid", EncodeDestination(CIdentityID(oneExportCurrency.first))));
            retVal.push_back(Pair("txid", oneExport.second.GetHash().GetHex()));
            retVal.push_back(Pair("txoutnum", oneExport.first));
        }
    }
    return retVal;
}

UniValue getlastimportfrom(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getlastimportfrom \"systemname\"\n"
            "\nReturns the last import from a specific originating system.\n"

            "\nArguments\n"
            "1. \"systemname\"                      (string, optional) name or ID of the system to retrieve the last import from\n"

            "\nResult:\n"
            "  {\n"
            "     \"lastimport\" :                  (object) last import from the indicated system on this chain\n"
            "       {\n"
            "       }\n"
            "     \"lastconfirmednotarization\" :   (object) last confirmed notarization of the indicated system on this chain\n"
            "       {\n"
            "       }\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getlastimportfrom", "\"systemname\"")
            + HelpExampleRpc("getlastimportfrom", "\"systemname\"")
        );
    }
    CheckPBaaSAPIsValid();

    LOCK(cs_main);

    uint160 chainID;
    CCurrencyDefinition chainDef;
    int32_t defHeight;

    if ((chainID = ValidateCurrencyName(uni_get_str(params[0]), true, &chainDef)).IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    if ((chainDef.IsToken() && !chainDef.IsGateway()) || chainID == ASSETCHAINS_CHAINID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "getlastimportfrom retrieves the last import from an external, not local system");
    }

    CChainNotarizationData cnd;
    if (!GetNotarizationData(chainID, cnd) || !cnd.IsConfirmed())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot locate confirmed notarization data for system or chain");
    }

    std::vector<CAddressUnspentDbEntry> unspentOutputs;
    CCrossChainImport lastCCI;
    bool found = false;
    CAddressUnspentDbEntry foundEntry;

    if (GetAddressUnspent(CKeyID(CCrossChainRPCData::GetConditionID(chainID, CCrossChainImport::CurrencySystemImportKey())), CScript::P2IDX, unspentOutputs) &&
        unspentOutputs.size())
    {
        for (auto &txidx : unspentOutputs)
        {
            COptCCParams p;
            if (txidx.second.script.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.vData.size() &&
                (lastCCI = CCrossChainImport(p.vData[0])).IsValid())
            {
                found = true;
                foundEntry = txidx;
                break;
            }
        }
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No import thread found for currency");
    }

    UniValue retVal(UniValue::VOBJ);
    if (found)
    {
        retVal.pushKV("lastimport", lastCCI.ToUniValue());
        retVal.pushKV("lastimportutxo", CUTXORef(foundEntry.first.txhash, foundEntry.first.index).ToUniValue());
    }
    retVal.pushKV("lastconfirmednotarization", cnd.vtx[cnd.lastConfirmed].second.ToUniValue());
    retVal.pushKV("lastconfirmedutxo", cnd.vtx[cnd.lastConfirmed].first.ToUniValue());
    return retVal;
}

UniValue getimports(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        throw runtime_error(
            "getimports \"chainname\" (startheight) (endheight)\n"
            "\nReturns all imports into a specific currency, optionally that were imported between a specific block range.\n"

            "\nArguments\n"
            "1. \"chainname\"                     (string, optional) name of the chain to look for. no parameter returns current chain in daemon.\n"
            "1. (startheight)                     (number, optional) startheight default == 0\n"
            "1. (endheight)                       (number, optional) endheight default == 0\n"

            "\nResult:\n"
            "  {\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getimports", "\"chainname\"")
            + HelpExampleRpc("getimports", "\"chainname\"")
        );
    }

    CheckPBaaSAPIsValid();

    LOCK(cs_main);

    uint160 chainID;
    CCurrencyDefinition chainDef;
    int32_t defHeight;

    if ((chainID = ValidateCurrencyName(uni_get_str(params[0]), true, &chainDef)).IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    uint32_t fromHeight = 0, toHeight = INT32_MAX;
    uint32_t proofHeight = 0;
    uint32_t nHeight = chainActive.Height();
    uint32_t maximumImportRange = GetArg("-maximumimportrange", chainActive.Height());

    if (params.size() > 1)
    {
        fromHeight = uni_get_int64(params[1]);
    }
    if (params.size() > 2)
    {
        toHeight = uni_get_int64(params[2]);
    }
    else if (fromHeight == 0 && maximumImportRange < nHeight)
    {
        fromHeight = nHeight - maximumImportRange;
    }
    proofHeight = toHeight < nHeight ? toHeight : nHeight;
    toHeight = proofHeight;

    if ((toHeight ? toHeight : nHeight) - fromHeight > maximumImportRange)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid range for currency state volume and rate information. Maximum range limited to " + std::to_string(GetArg("-maximportrange", chainActive.Height())));
    }

    if (GetCurrencyDefinition(chainID, chainDef, &defHeight))
    {
        // which transaction are we in this block?
        std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;
        uint160 searchKey = CCrossChainRPCData::GetConditionID(chainID, CCrossChainImport::CurrencyImportKey());
        CBlockIndex *pIndex;
        CChainNotarizationData cnd;

        // get all import transactions including and since this one up to the confirmed height
        if (GetAddressIndex(searchKey, CScript::P2IDX, addressIndex, fromHeight, toHeight))
        {
            UniValue ret(UniValue::VARR);

            for (auto &idx : addressIndex)
            {
                uint256 blkHash;
                CTransaction importTx;
                if (!idx.first.spending && myGetTransaction(idx.first.txhash, importTx, blkHash))
                {
                    CCrossChainExport ccx;
                    CCrossChainImport cci;
                    int32_t sysCCIOut;
                    CPBaaSNotarization importNotarization;
                    int32_t importNotOut;
                    int32_t evidenceOutStart, evidenceOutEnd;
                    std::vector<CReserveTransfer> reserveTransfers;
                    uint32_t importHeight = 0;

                    auto importBlockIdxIt = mapBlockIndex.find(blkHash);
                    if (importBlockIdxIt != mapBlockIndex.end() && chainActive.Contains(importBlockIdxIt->second))
                    {
                        importHeight = importBlockIdxIt->second->GetHeight();
                    }
                    else
                    {
                        continue;
                    }

                    /* UniValue scrOut(UniValue::VOBJ);
                    ScriptPubKeyToUniv(importTx.vout[idx.first.index].scriptPubKey, scrOut, false);
                    printf("%s: scriptOut: %s\n", __func__, scrOut.write(1,2).c_str()); */

                    CCrossChainImport sysCCI;
                    if ((cci = CCrossChainImport(importTx.vout[idx.first.index].scriptPubKey)).IsValid() &&
                        cci.GetImportInfo(importTx, importHeight, idx.first.index, ccx, sysCCI, sysCCIOut, importNotarization, importNotOut, evidenceOutStart, evidenceOutEnd, reserveTransfers))
                    {
                        UniValue oneImportUni(UniValue::VOBJ);

                        oneImportUni.push_back(Pair("importheight", (int64_t)importHeight));
                        oneImportUni.push_back(Pair("importtxid", idx.first.txhash.GetHex()));
                        oneImportUni.push_back(Pair("importvout", (int64_t)idx.first.index));
                        oneImportUni.push_back(Pair("import", cci.ToUniValue()));
                        if (sysCCIOut != -1)
                        {
                            oneImportUni.push_back(Pair("sysimport", sysCCI.ToUniValue()));
                        }
                        oneImportUni.push_back(Pair("importnotarization", importNotarization.ToUniValue()));

                        UniValue transferArr(UniValue::VARR);
                        for (auto &oneTransfer : reserveTransfers)
                        {
                            transferArr.push_back(oneTransfer.ToUniValue());
                        }
                        oneImportUni.push_back(Pair("transfers", transferArr));
                        ret.push_back(oneImportUni);
                    }
                }
            }
            if (ret.size())
            {
                return ret;
            }
        }
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unrecognized currency name or ID");
    }
    return NullUniValue;
}

UniValue listcurrencies(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
    {
        throw runtime_error(
            "listcurrencies ({query object}) startblock endblock\n"
            "\nReturns a complete definition for any given chain if it is registered on the blockchain. If the chain requested\n"
            "\nis NULL, chain definition of the current chain is returned.\n"

            "\nArguments\n"
            "{                                    (json, optional) specify valid query conditions\n"
            "   \"launchstate\" :                   (\"prelaunch\" | \"launched\" | \"refund\" | \"complete\") (optional) return only currencies in that state\n"
            "   \"systemtype\" :                    (\"local\" | \"imported\" | \"gateway\" | \"pbaas\")\n"
            "   \"fromsystem\" :                    (\"systemnameeorid\") default is the local chain, but if currency is from another system, specify here\n"
            "   \"converter\": [\"currency1\", (\"currency2\")] (array, optional) default empty, only return fractional currency converters of one or more currencies\n"
            "}\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"version\" : n,                           (int) version of this chain definition\n"
            "    \"name\" : \"string\",                     (string) name or symbol of the chain, same as passed\n"
            "    \"fullyqualifiedname\" : \"string\",       (string) name or symbol of the chain with all parent namespaces, separated by \".\"\n"
            "    \"currencyid\" : \"i-address\",            (string) string that represents the currency ID, same as the ID behind the currency\n"
            "    \"currencyidhex\" : \"hex\",               (string) hex representation of currency ID, getcurrency API supports \"hex:currencyidhex\"\n"
            "    \"parent\" : \"i-address\",                (string) parent blockchain ID\n"
            "    \"systemid\" : \"i-address\",              (string) system on which this currency is considered to run\n"
            "    \"launchsystemid\" : \"i-address\",        (string) system from which this currency was launched\n"
            "    \"notarizationprotocol\" : n               (int) protocol number that determines variations in cross-chain or bridged notarizations\n"
            "    \"proofprotocol\" : n                      (int) protocol number that determines variations in cross-chain or bridged proofs\n"
            "    \"startblock\" : n,                        (int) block # on this chain, which must be notarized into block one of the chain\n"
            "    \"endblock\" : n,                          (int) block # after which, this chain's useful life is considered to be over\n"
            "    \"currencies\" : \"[\"i-address\", ...]\", (stringarray) currencies that can be converted to this currency at launch or makeup a liquidity basket\n"
            "    \"weights\" : \"[n, ...]\",                (numberarray) relative currency weights (only returned for a liquidity basket)\n"
            "    \"conversions\" : \"[n, ...]\",            (numberarray) pre-launch conversion rates for non-fractional currencies\n"
            "    \"minpreconversion\" : \"[n, ...]\",       (numberarray) minimum amounts required in pre-conversions for currency to launch\n"
            "    \"currencies\" : \"[\"i-address\", ...]\", (stringarray) currencies that can be converted to this currency at launch or makeup a liquidity basket\n"
            "    \"currencynames\" : \"{\"i-address\":\"fullname\",...}\", (obj) i-addresses mapped to fully qualified names of all sub-currencies\n"
            "    \"initialsupply\" : n,                     (number) initial currency supply for fractional currencies before preallocation or issuance\n"
            "    \"prelaunchcarveout\" : n,                 (number) pre-launch percentage of proceeds for fractional currency sent to launching ID\n"
            "    \"preallocations\" : \"[{\"i-address\":n}, ...]\", (objarray) VerusIDs and amounts for pre-allocation at launch\n"
            "    \"initialcontributions\" : \"[n, ...]\",   (numberarray) amounts of pre-conversions reserved for launching ID\n"
            "    \"idregistrationfees\" : n,                (number) base cost of IDs for this currency namespace in this currency\n"
            "    \"idreferrallevels\" : n,                  (int) levels of ID referrals (only for native PBaaS chains and IDs)\n"
            "    \"idimportfees\" : n,                      (number) fees required to import an ID to this system (only for native PBaaS chains and IDs)\n"
            "    \"eras\" : \"[obj, ...]\",                 (objarray) different chain phases of rewards and convertibility\n"
            "    {\n"
            "      \"reward\" : \"[n, ...]\",               (int) reward start for each era in native coin\n"
            "      \"decay\" : \"[n, ...]\",                (int) exponential or linear decay of rewards during each era\n"
            "      \"halving\" : \"[n, ...]\",              (int) blocks between halvings during each era\n"
            "      \"eraend\" : \"[n, ...]\",               (int) block marking the end of each era\n"
            "      \"eraoptions\" : \"[n, ...]\",           (int) options (reserved)\n"
            "    }\n"
            "    \"nodes\"      : \"[obj, ..]\",    (objectarray, optional) up to 8 nodes that can be used to connect to the blockchain"
            "      [{\n"
            "         \"nodeidentity\" : \"txid\", (string,  optional) internet, TOR, or other supported address for node\n"
            "         \"paymentaddress\" : n,     (int,     optional) rewards payment address\n"
            "       }, .. ]\n"
            "    \"lastconfirmedcurrencystate\" : {\n"
            "     }\n"
            "    \"besttxid\" : \"txid\"\n"
            "     }\n"
            "    \"confirmednotarization\" : {\n"
            "     }\n"
            "    \"confirmedtxid\" : \"txid\"\n"
            "  }, ...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listcurrencies", "true")
            + HelpExampleRpc("listcurrencies", "true")
        );
    }

    CheckPBaaSAPIsValid();

    UniValue ret(UniValue::VARR);

    uint160 querySystem;
    static std::map<std::string, CCurrencyDefinition::EQueryOptions> launchStates(
        {{"prelaunch", CCurrencyDefinition::QUERY_LAUNCHSTATE_PRELAUNCH},
         {"launched", CCurrencyDefinition::QUERY_LAUNCHSTATE_CONFIRM},
         {"refund", CCurrencyDefinition::QUERY_LAUNCHSTATE_REFUND},
         {"complete", CCurrencyDefinition::QUERY_LAUNCHSTATE_COMPLETE}}
    );
    static std::map<std::string, CCurrencyDefinition::EQueryOptions> systemTypes(
        {{"local", CCurrencyDefinition::QUERY_SYSTEMTYPE_LOCAL},
         {"imported", CCurrencyDefinition::QUERY_SYSTEMTYPE_IMPORTED},
         {"gateway", CCurrencyDefinition::QUERY_SYSTEMTYPE_GATEWAY},
         {"pbaas", CCurrencyDefinition::QUERY_SYSTEMTYPE_PBAAS}}
    );

    CCurrencyDefinition::EQueryOptions launchStateQuery = CCurrencyDefinition::QUERY_NULL;
    CCurrencyDefinition::EQueryOptions systemTypeQuery = CCurrencyDefinition::QUERY_NULL;
    uint32_t startBlock = 0;
    uint32_t endBlock = 0;
    std::set<uint160> converters;
    uint160 fromSystemID = ASSETCHAINS_CHAINID;
    if (params.size())
    {
        if (!params[0].isObject())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid query object parameter");
        }
        int numKeys = params[0].getKeys().size();
        std::string launchState = uni_get_str(find_value(params[0], "launchstate"));
        std::string systemType = uni_get_str(find_value(params[0], "systemtype"));
        std::string fromSystemIDStr = uni_get_str(find_value(params[0], "fromsystem"));
        if (fromSystemIDStr.size())
        {
            fromSystemID = ValidateCurrencyName(fromSystemIDStr, true);
            if (fromSystemID.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Blockchain or gateway specified in fromsystem not found");
            }
            systemType = "local";
        }

        UniValue convertersUni = find_value(params[0], "converter");
        if (!convertersUni.isNull())
        {
            if (!(convertersUni.isArray() && convertersUni.size()))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "If converters are specified, they should consist of one or more valid currencies");
            }
            numKeys--;
            for (int i = 0; i < convertersUni.size(); i++)
            {
                uint160 oneCurID = ValidateCurrencyName(uni_get_str(convertersUni[i]));
                if (oneCurID.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency: " + uni_get_str(convertersUni[i]));
                }
                converters.insert(oneCurID);
            }
        }
        if (launchStates.count(launchState))
        {
            launchStateQuery = launchStates[launchState];
            numKeys--;
        }
        if (systemTypes.count(systemType))
        {
            systemTypeQuery = systemTypes[systemType];
            numKeys--;
        }
        if (numKeys)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid query object parameter, use \"listcurrencies help\"");
        }
        if (params.size() > 1)
        {
            startBlock = uni_get_int64(params[1]);
        }
        if (params.size() > 2)
        {
            endBlock = uni_get_int64(params[2]);
        }
    }

    std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> chains;
    {
        LOCK2(cs_main, mempool.cs);
        GetCurrencyDefinitions(fromSystemID, chains, launchStateQuery, systemTypeQuery, converters, startBlock, endBlock);
    }

    for (auto oneDef : chains)
    {
        LOCK2(cs_main, mempool.cs);
        CCurrencyDefinition &def = oneDef.second;

        UniValue oneChain(UniValue::VOBJ);
        UniValue oneDefUni = def.ToUniValue();
        oneDefUni.pushKV("currencyidhex", def.GetID().GetHex());
        oneDefUni.pushKV("fullyqualifiedname", ConnectedChains.GetFriendlyCurrencyName(def.GetID()));

        if (oneDef.first.first.IsValid())
        {
            oneDefUni.push_back(Pair("definitiontxid", oneDef.first.first.hash.GetHex()));
            oneDefUni.push_back(Pair("definitiontxout", (int)oneDef.first.first.n));
        }

        if (oneDef.first.second.size())
        {
            UniValue nodesUni(UniValue::VARR);
            for (auto node : oneDef.first.second)
            {
                nodesUni.push_back(node.ToUniValue());
            }
            oneDefUni.push_back(Pair("nodes", nodesUni));
        }

        oneChain.push_back(Pair("currencydefinition", oneDefUni));

        CChainNotarizationData cnd;
        GetNotarizationData(def.GetID(), cnd);

        int32_t confirmedHeight = -1, bestHeight = -1;
        confirmedHeight = cnd.vtx.size() && cnd.lastConfirmed != -1 ? cnd.vtx[cnd.lastConfirmed].second.notarizationHeight : -1;
        bestHeight = cnd.vtx.size() && cnd.bestChain != -1 ? cnd.vtx[cnd.forks[cnd.bestChain].back()].second.notarizationHeight : -1;

        if (!def.IsToken())
        {
            oneChain.push_back(Pair("lastconfirmedheight", confirmedHeight == -1 ? 0 : confirmedHeight));
            if (confirmedHeight != -1)
            {
                oneChain.push_back(Pair("lastconfirmedtxid", cnd.vtx[cnd.lastConfirmed].first.hash.GetHex().c_str()));
                oneChain.push_back(Pair("lastconfirmedtxout", (uint64_t)cnd.vtx[cnd.lastConfirmed].first.n));
                oneChain.push_back(Pair("lastconfirmednotarization", cnd.vtx[cnd.lastConfirmed].second.ToUniValue()));
            }
        }
        oneChain.push_back(Pair("bestheight", bestHeight == -1 ? 0 : bestHeight));
        if (bestHeight != -1)
        {
            oneChain.push_back(Pair("besttxid", cnd.vtx[cnd.forks[cnd.bestChain].back()].first.hash.GetHex().c_str()));
            oneChain.push_back(Pair("besttxout", (uint64_t)cnd.vtx[cnd.forks[cnd.bestChain].back()].first.n));
            oneChain.push_back(Pair("bestcurrencystate", cnd.vtx[cnd.forks[cnd.bestChain].back()].second.currencyState.ToUniValue()));
        }
        ret.push_back(oneChain);
    }
    return ret;
}

// returns all chain transfer outputs, both spent and unspent between a specific start and end block with an optional chainFilter. if the chainFilter is not
// NULL, only transfers to that system are returned
bool GetChainTransfers(multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors, uint160 chainFilter, int start, int end, uint32_t flags)
{
    if (!flags)
    {
        flags = CReserveTransfer::VALID;
    }
    bool nofilter = chainFilter.IsNull();

    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    LOCK2(cs_main, mempool.cs);

    if (!GetAddressIndex(CReserveTransfer::ReserveTransferKey(),
                         CScript::P2IDX,
                         addressIndex,
                         start,
                         end))
    {
        return false;
    }
    else
    {
        for (auto it = addressIndex.begin(); it != addressIndex.end(); it++)
        {
            CTransaction ntx;
            uint256 blkHash;

            if (it->first.spending)
            {
                continue;
            }

            if (myGetTransaction(it->first.txhash, ntx, blkHash))
            {
                COptCCParams p, m;
                CReserveTransfer rt;
                if (ntx.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.evalCode == EVAL_RESERVE_TRANSFER &&
                    p.vData.size() > 1 && (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                    (m = COptCCParams(p.vData[1])).IsValid() &&
                    (nofilter || ((rt.flags & rt.IMPORT_TO_SOURCE) ? rt.FirstCurrency() : rt.destCurrencyID) == chainFilter) &&
                    (rt.flags & flags) == flags)
                {
                    inputDescriptors.insert(make_pair(((rt.flags & rt.IMPORT_TO_SOURCE) ? rt.FirstCurrency() : rt.destCurrencyID),
                                                make_pair(CInputDescriptor(ntx.vout[it->first.index].scriptPubKey, ntx.vout[it->first.index].nValue, CTxIn(COutPoint(it->first.txhash, it->first.index))),
                                                            rt)));
                }

                /*
                uint256 hashBlk;
                UniValue univTx(UniValue::VOBJ);
                TxToUniv(ntx, hashBlk, univTx);
                printf("tx: %s\n", univTx.write(1,2).c_str());
                */
            }
            else
            {
                LogPrintf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                printf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                return false;
            }
        }
        return true;
    }
}

LRUCache<std::tuple<uint160, uint256, uint32_t>, std::vector<CInputDescriptor>> chainTransferCache(500);

// returns all chain transfer outputs, both spent and unspent between a specific start and end block with an optional chainFilter. if the chainFilter is not
// NULL, only transfers to that system are returned
bool GetChainTransfersUnspentBy(std::multimap<std::pair<uint32_t, uint160>, std::pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors, uint160 chainFilter, uint32_t start, uint32_t end, uint32_t unspentBy, const uint256 &checkingTxHash, uint32_t flags)
{
    if (!flags)
    {
        flags = CReserveTransfer::VALID;
    }
    bool nofilter = chainFilter.IsNull();

    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    LOCK2(cs_main, mempool.cs);

    if (start && end && chainActive.Height() >= end && (flags == CReserveTransfer::VALID) && !chainFilter.IsNull())
    {
        std::vector<std::pair<uint32_t, uint32_t>> blocksToLoad;
        std::vector<CInputDescriptor> transfersFromCache;
        for (uint32_t i = start; i <= end; i++)
        {
            if (chainTransferCache.Get({chainFilter, chainActive[i]->GetBlockHash(), unspentBy}, transfersFromCache))
            {
                // if we got transfers for this block, add them to the map
                for (auto oneTransfer : transfersFromCache)
                {
                    COptCCParams p;
                    CReserveTransfer rt;
                    if (oneTransfer.scriptPubKey.IsPayToCryptoCondition(p) &&
                        (rt = CReserveTransfer(p.vData[0])).IsValid())
                    {
                        inputDescriptors.insert(std::make_pair(std::make_pair(i, chainFilter), std::make_pair(oneTransfer, rt)));
                    }
                }
            }
            else
            {
                if (blocksToLoad.empty() || blocksToLoad.back().second < (i - 1))
                {
                    blocksToLoad.push_back(std::make_pair(i,i));
                }
                else
                {
                    blocksToLoad.back().second = i;
                }
            }
        }
        // if we found any in the cache, fill in the blocks that were not included
        // since we know none of the missing blocks will be found in the cache, get them with recursion that will cause a lookup
        // if we didn't find any, drop through and lookup
        if (!(blocksToLoad.size() == 1 && blocksToLoad[0].first == start && blocksToLoad[0].second == end))
        {
            for (auto &onePair : blocksToLoad)
            {
                if (!GetChainTransfersUnspentBy(inputDescriptors, chainFilter, onePair.first, onePair.second, unspentBy, checkingTxHash, flags))
                {
                    return false;
                }
            }
            return true;
        }
    }

    if (!GetAddressIndex(CReserveTransfer::ReserveTransferKey(),
                         CScript::P2IDX,
                         addressIndex,
                         start,
                         end))
    {
        return false;
    }
    else
    {
        // This call does not include outputs that were mined in as spent at the
        // end height requested
        for (auto it = addressIndex.begin(); it != addressIndex.end(); it++)
        {
            CTransaction ntx;
            uint256 blkHash;

            if (it->first.spending)
            {
                continue;
            }

            // no matter where we are getting the reserve transfers from, if they are otherwise spent
            // in the block prior, they are not considered unspent by the "end" block, meaning they
            CSpentIndexValue spentInfo;
            CSpentIndexKey spentKey(it->first.txhash, it->first.index);

            if (GetSpentIndex(spentKey, spentInfo) &&
                !spentInfo.IsNull() &&
                spentInfo.txid != checkingTxHash &&
                spentInfo.blockHeight < unspentBy)
            {
                continue;
            }

            std::tuple<uint256, CInputDescriptor, CReserveTransfer> cacheValue;
            bool inCache = false;
            if ((inCache = (reserveTransferCache.Get({it->first.txhash, (uint32_t)it->first.index}, cacheValue)) && mapBlockIndex.count(std::get<0>(cacheValue)) && chainActive.Contains(mapBlockIndex[std::get<0>(cacheValue)])) &&
                ((chainFilter.IsNull() || chainFilter == std::get<2>(cacheValue).GetImportCurrency()) && (flags == CReserveTransfer::VALID)))
            {
                inputDescriptors.insert(std::make_pair(std::make_pair(it->first.blockHeight, (std::get<2>(cacheValue).flags & std::get<2>(cacheValue).IMPORT_TO_SOURCE) ? std::get<2>(cacheValue).FirstCurrency() : std::get<2>(cacheValue).destCurrencyID), std::make_pair(std::get<1>(cacheValue), std::get<2>(cacheValue))));
            }
            else if (!inCache)
            {
                if (myGetTransaction(it->first.txhash, ntx, blkHash))
                {
                    COptCCParams p, m;
                    CReserveTransfer rt;
                    if (ntx.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.evalCode == EVAL_RESERVE_TRANSFER &&
                        p.vData.size() > 1 && (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                        (m = COptCCParams(p.vData[1])).IsValid() &&
                        (nofilter || ((rt.flags & rt.IMPORT_TO_SOURCE) ? rt.FirstCurrency() : rt.destCurrencyID) == chainFilter) &&
                        (rt.flags & flags) == flags)
                    {
                        inputDescriptors.insert(std::make_pair(std::make_pair(it->first.blockHeight, (rt.flags & rt.IMPORT_TO_SOURCE) ? rt.FirstCurrency() : rt.destCurrencyID),
                                                    std::make_pair(CInputDescriptor(ntx.vout[it->first.index].scriptPubKey, ntx.vout[it->first.index].nValue, CTxIn(COutPoint(it->first.txhash, it->first.index))),
                                                                rt)));

                        reserveTransferCache.Put({it->first.txhash, (uint32_t)it->first.index}, {blkHash, CInputDescriptor(ntx.vout[it->first.index].scriptPubKey, ntx.vout[it->first.index].nValue, CTxIn(COutPoint(it->first.txhash, it->first.index))), rt});
                    }
                }
                else
                {
                    LogPrintf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                    printf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                    return false;
                }
            }
        }
        if (!chainFilter.IsNull() && (flags == CReserveTransfer::VALID))
        {
            for (uint32_t i = start; i <= end && i <= chainActive.Height(); i++)
            {
                // find and loop through this block's entries to put in vector then store
                auto itpair = inputDescriptors.equal_range({i, chainFilter});
                std::vector<CInputDescriptor> cacheVec;
                for (auto it = itpair.first; it != itpair.second; it++)
                {
                    cacheVec.push_back(it->second.first);
                }
                chainTransferCache.Put({chainFilter, chainActive[i]->GetBlockHash(), unspentBy}, cacheVec);
            }
        }
        return true;
    }
}

// returns all chain transfer outputs, both spent and unspent between a specific start and end block with an optional chainFilter. if the chainFilter is not
// NULL, only transfers to that system are returned
bool GetChainTransfersBetween(std::multimap<std::pair<uint32_t, uint160>, std::pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors, uint160 chainFilter, uint32_t start, uint32_t end, uint32_t flags)
{
    if (!flags)
    {
        flags = CReserveTransfer::VALID;
    }
    bool nofilter = chainFilter.IsNull();

    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    LOCK2(cs_main, mempool.cs);

    if (start && end && chainActive.Height() >= end && (flags == CReserveTransfer::VALID) && !chainFilter.IsNull())
    {
        std::vector<std::pair<uint32_t, uint32_t>> blocksToLoad;
        std::vector<CInputDescriptor> transfersFromCache;
        for (uint32_t i = start; i <= end; i++)
        {
            if (chainTransferCache.Get({chainFilter, chainActive[i]->GetBlockHash(), 0}, transfersFromCache))
            {
                // if we got transfers for this block, add them to the map
                for (auto oneTransfer : transfersFromCache)
                {
                    COptCCParams p;
                    CReserveTransfer rt;
                    if (oneTransfer.scriptPubKey.IsPayToCryptoCondition(p) &&
                        (rt = CReserveTransfer(p.vData[0])).IsValid())
                    {
                        inputDescriptors.insert(std::make_pair(std::make_pair(i, chainFilter), std::make_pair(oneTransfer, rt)));
                    }
                }
            }
            else
            {
                if (blocksToLoad.empty() || blocksToLoad.back().second < (i - 1))
                {
                    blocksToLoad.push_back(std::make_pair(i,i));
                }
                else
                {
                    blocksToLoad.back().second = i;
                }
            }
        }
        // if we found any in the cache, fill in the blocks that were not included
        // since we know none of the missing blocks will be found in the cache, get them with recursion that will cause a lookup
        // if we didn't find any, drop through and lookup
        if (!(blocksToLoad.size() == 1 && blocksToLoad[0].first == start && blocksToLoad[0].second == end))
        {
            for (auto &onePair : blocksToLoad)
            {
                if (!GetChainTransfersBetween(inputDescriptors, chainFilter, onePair.first, onePair.second, flags))
                {
                    return false;
                }
            }
            return true;
        }
    }

    if (!GetAddressIndex(CReserveTransfer::ReserveTransferKey(),
                         CScript::P2IDX,
                         addressIndex,
                         start,
                         end))
    {
        return false;
    }
    else
    {
        // This call does not include outputs that were mined in as spent at the
        // end height requested
        for (auto it = addressIndex.begin(); it != addressIndex.end(); it++)
        {
            CTransaction ntx;
            uint256 blkHash;

            if (it->first.spending)
            {
                continue;
            }

            if (myGetTransaction(it->first.txhash, ntx, blkHash))
            {
                COptCCParams p, m;
                CReserveTransfer rt;
                if (ntx.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.evalCode == EVAL_RESERVE_TRANSFER &&
                    p.vData.size() > 1 && (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                    (m = COptCCParams(p.vData[1])).IsValid() &&
                    (nofilter || ((rt.flags & rt.IMPORT_TO_SOURCE) ? rt.FirstCurrency() : rt.destCurrencyID) == chainFilter) &&
                    (rt.flags & flags) == flags)
                {
                    inputDescriptors.insert(std::make_pair(std::make_pair(it->first.blockHeight, (rt.flags & rt.IMPORT_TO_SOURCE) ? rt.FirstCurrency() : rt.destCurrencyID),
                                                std::make_pair(CInputDescriptor(ntx.vout[it->first.index].scriptPubKey, ntx.vout[it->first.index].nValue, CTxIn(COutPoint(it->first.txhash, it->first.index))),
                                                               rt)));
                }

                /*
                uint256 hashBlk;
                UniValue univTx(UniValue::VOBJ);
                TxToUniv(ntx, hashBlk, univTx);
                printf("tx: %s\n", univTx.write(1,2).c_str());
                */
            }
            else
            {
                LogPrintf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                printf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                return false;
            }
        }
        if (!chainFilter.IsNull() && (flags == CReserveTransfer::VALID))
        {
            for (uint32_t i = start; i <= end && i <= chainActive.Height(); i++)
            {
                // find and loop through this block's entries to put in vector then store
                auto itpair = inputDescriptors.equal_range({i, chainFilter});
                std::vector<CInputDescriptor> cacheVec;
                for (auto it = itpair.first; it != itpair.second; it++)
                {
                    cacheVec.push_back(it->second.first);
                }
                chainTransferCache.Put({chainFilter, chainActive[i]->GetBlockHash(), 0}, cacheVec);
            }
        }
        return true;
    }
}

// returns all unspent chain transfer outputs with an optional chainFilter. if the chainFilter is not
// NULL, only transfers to that chain are returned
bool GetUnspentChainTransfers(std::multimap<uint160, ChainTransferData> &inputDescriptors, uint160 chainFilter)
{
    bool nofilter = chainFilter.IsNull();

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    LOCK(cs_main);

    if (!GetAddressUnspent(CReserveTransfer::ReserveTransferKey(), CScript::P2IDX, unspentOutputs))
    {
        return false;
    }
    else
    {
        CCoins coins;
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);

        LOCK2(smartTransactionCS, mempool.cs);
        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        view.SetBackend(viewMemPool);

        for (auto it = unspentOutputs.begin(); it != unspentOutputs.end(); it++)
        {
            CCoins coins;

            if (view.GetCoins(it->first.txhash, coins))
            {
                if (coins.IsAvailable(it->first.index))
                {
                    // if this is a transfer output, optionally to this chain, add it to the input vector
                    // chain filter was applied in index search
                    COptCCParams p;
                    COptCCParams m;
                    CReserveTransfer rt;
                    uint160 destCID;
                    if (coins.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.evalCode == EVAL_RESERVE_TRANSFER &&
                        p.vData.size() &&
                        p.version >= p.VERSION_V3 &&
                        (m = COptCCParams(p.vData.back())).IsValid() &&
                        (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                        !(destCID = ((rt.flags & rt.IMPORT_TO_SOURCE) ? rt.FirstCurrency() : rt.destCurrencyID)).IsNull() &&
                        (nofilter || destCID == chainFilter))
                    {
                        inputDescriptors.insert(make_pair(destCID,
                                                          ChainTransferData(coins.nHeight,
                                                                            CInputDescriptor(coins.vout[it->first.index].scriptPubKey,
                                                                                            coins.vout[it->first.index].nValue,
                                                                                            CTxIn(COutPoint(it->first.txhash, it->first.index))),
                                                                            rt)));
                    }
                }
            }
            else
            {
                LogPrint("crosschainexports", "%s: cannot retrieve transaction %s from height %u\n", __func__, it->first.txhash.GetHex().c_str(), it->second.blockHeight);
            }
        }
        return true;
    }
}

// returns all unspent chain transfer outputs, * including from the mempool *
bool GetUnspentChainTransfers(std::vector<ChainTransferData> &inputDescriptors, uint160 chainID)
{
    std::vector<std::pair<CInputDescriptor, uint32_t>> unspentOutputs;

    LOCK(cs_main);
    LOCK2(smartTransactionCS, mempool.cs);

    if (!ConnectedChains.GetUnspentByIndex(CReserveTransfer::ReserveTransferKey(), unspentOutputs))
    {
        return false;
    }
    else
    {
        CCoins coins;
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);

        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        view.SetBackend(viewMemPool);

        for (auto it = unspentOutputs.begin(); it != unspentOutputs.end(); it++)
        {
            CCoins coins;

            if (view.GetCoins(it->first.txIn.prevout.hash, coins))
            {
                if (coins.IsAvailable(it->first.txIn.prevout.n))
                {
                    // if this is a transfer output, optionally to this chain, add it to the input vector
                    // chain filter was applied in index search
                    COptCCParams p;
                    COptCCParams m;
                    CReserveTransfer rt;
                    uint160 destCID;
                    if (coins.vout[it->first.txIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.evalCode == EVAL_RESERVE_TRANSFER &&
                        p.vData.size() &&
                        p.version >= p.VERSION_V3 &&
                        (m = COptCCParams(p.vData.back())).IsValid() &&
                        (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                        !(destCID = rt.GetImportCurrency()).IsNull() &&
                        destCID == chainID)
                    {
                        inputDescriptors.push_back(ChainTransferData(it->second,
                                                                     CInputDescriptor(coins.vout[it->first.txIn.prevout.n].scriptPubKey,
                                                                                      coins.vout[it->first.txIn.prevout.n].nValue,
                                                                                      CTxIn(COutPoint(it->first.txIn.prevout.hash, it->first.txIn.prevout.n))),
                                                                     rt));
                    }
                }
            }
            else
            {
                LogPrint("crosschainexports", "%s: cannot retrieve transaction %s from height %u\n", __func__, it->first.txIn.prevout.hash.GetHex().c_str(), coins.nHeight);
            }
        }
        return true;
    }
}

void CChainNotarizationData::SetBestChain(const CCurrencyDefinition &fromChainDef,
                                          const std::vector<std::pair<CTransaction, uint256>> &txesAndBlocks)
{
    // now, we should have all forks in vectors
    // they should all have roots that point to the same confirmed or initial notarization, which should be enforced by chain rules
    // the best chain should simply be the tip with most power

    uint160 currencyID = fromChainDef.GetID();

    bestChain = 0;
    CChainPower best;
    uint32_t bestHeight = 0;
    for (int i = 0; i < forks.size(); i++)
    {
        if (vtx[forks[i].back()].second.proofRoots.count(currencyID))
        {
            CChainPower curPower =
                CChainPower::ExpandCompactPower(vtx[forks[i].back()].second.proofRoots[currencyID].compactPower);
            if (fromChainDef.proofProtocol == fromChainDef.PROOF_PBAASMMR && curPower > best)
            {
                best = curPower;
                bestHeight = mapBlockIndex[txesAndBlocks[forks[i].back()].second]->GetHeight();
                bestChain = i;
            }
            else if ((curPower == best || fromChainDef.proofProtocol != fromChainDef.PROOF_PBAASMMR) &&
                        mapBlockIndex.count(txesAndBlocks[forks[i].back()].second) &&
                        mapBlockIndex[txesAndBlocks[forks[i].back()].second]->GetHeight() > bestHeight)
            {
                best = curPower;
                bestHeight = mapBlockIndex[txesAndBlocks[forks[i].back()].second]->GetHeight();
                bestChain = i;
            }
        }
        else if (vtx[forks[i].back()].second.IsLaunchCleared() &&
                vtx[forks[i].back()].second.IsPreLaunch() &&
                vtx[forks[i].back()].second.IsLaunchConfirmed())
        {
            bestChain = i;
        }
        else
        {
            printf("%s: invalid notarization expecting proofroot for %s:\n%s\n",
                __func__,
                EncodeDestination(CIdentityID(currencyID)).c_str(),
                vtx[forks[i].back()].second.ToUniValue().write(1,2).c_str());
            LogPrintf("%s: invalid notarization on transaction %s, output %u\n", __func__,
                    vtx[forks[i].back()].first.hash.GetHex().c_str(),
                    vtx[forks[i].back()].first.n);
            //assert(false);
        }
    }
}

// since same chain notarizations are always up to date, we only need to cache cross-chain notarizations that require analysis
LRUCache<std::pair<uint160, uint256>, std::pair<CChainNotarizationData, std::vector<std::pair<CTransaction, uint256>>>> crossChainNotarizationDataCache(100, 0.3);

bool GetNotarizationData(const uint160 &currencyID,
                         CChainNotarizationData &notarizationData,
                         std::vector<std::pair<CTransaction, uint256>> *optionalTxOut,
                         std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>>> *pCounterEvidence,
                         std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence>>> *pEvidence)
{
    notarizationData = CChainNotarizationData();

    vector<std::pair<CTransaction, uint256>> _extraTxOut;
    if (!optionalTxOut)
    {
        optionalTxOut = &_extraTxOut;
    }

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentFinalizations;
    CCurrencyDefinition chainDef = ConnectedChains.GetCachedCurrency(currencyID);
    if (!chainDef.IsValid())
    {
        LogPrint("notarization", "Cannot retrieve currency %s, may need to reindex\n", EncodeDestination(CIdentityID(currencyID)).c_str());
        return false;
    }

    // if we are being asked for a notarization of the current chain, we make one
    uint32_t height = chainActive.Height();
    bool cacheFound = false;

    if ((IsVerusActive() || height == 0) && currencyID == ASSETCHAINS_CHAINID)
    {
        notarizationData = CChainNotarizationData(CChainNotarizationData::CURRENT_VERSION);

        CIdentityID proposer = VERUS_NOTARYID.IsNull() ? (VERUS_DEFAULTID.IsNull() ? VERUS_NODEID : VERUS_DEFAULTID) : VERUS_NOTARYID;

        std::map<uint160, CProofRoot> proofRoots;
        proofRoots[ASSETCHAINS_CHAINID] = CProofRoot::GetProofRoot(height);
        //printf("%s: returning proof root: %s\n", __func__, proofRoots[ASSETCHAINS_CHAINID].ToUniValue().write(1,2).c_str());

        CPBaaSNotarization bestNotarization(currencyID,
                                            ConnectedChains.GetCurrencyState(height),
                                            height,
                                            CUTXORef(),
                                            0,
                                            std::vector<CNodeData>(),
                                            std::map<uint160, CCoinbaseCurrencyState>(),
                                            DestinationToTransferDestination(proposer),
                                            proofRoots,
                                            CPBaaSNotarization::VERSION_CURRENT,
                                            CPBaaSNotarization::FLAG_LAUNCH_CONFIRMED);
        notarizationData.vtx.push_back(std::make_pair(CUTXORef(), bestNotarization));
        notarizationData.lastConfirmed = 0;
        notarizationData.forks.push_back(std::vector<int>({0}));
        notarizationData.bestChain = 0;
        if (pCounterEvidence)
        {
            pCounterEvidence->resize(notarizationData.vtx.size());
        }
        if (pEvidence)
        {
            pEvidence->resize(notarizationData.vtx.size());
        }
        optionalTxOut->resize(notarizationData.vtx.size());
        return true;
    }
    else if (!chainDef.IsToken() && height > 0)
    {
        std::pair<CChainNotarizationData, std::vector<std::pair<CTransaction, uint256>>> cacheResult;
        if (crossChainNotarizationDataCache.Get(std::make_pair(currencyID, chainActive[height]->GetBlockHash()), cacheResult))
        {
            cacheFound = true;
            notarizationData = cacheResult.first;
            if (notarizationData.IsValid())
            {
                *optionalTxOut = cacheResult.second;
            }
            if (!pCounterEvidence && !pEvidence)
            {
                return notarizationData.IsValid() && notarizationData.vtx.size() != 0;
            }
        }
    }

    if (!cacheFound && !notarizationData.IsValid())
    {
        notarizationData = CChainNotarizationData(CChainNotarizationData::CURRENT_VERSION);
        if (chainActive.Height() == 0)
        {
            return false;
        }
        std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> lastFinalized = GetLastConfirmedNotarization(currencyID, chainActive.Height());
        if (std::get<0>(lastFinalized) == 0)
        {
            if (LogAcceptCategory("defi"))
            {
                LogPrintf("No confirmed notarization for %s\n", EncodeDestination(CIdentityID(currencyID)).c_str());
                printf("No confirmed notarization for %s\n", EncodeDestination(CIdentityID(currencyID)).c_str());
            }
            return false;
        }
        if (chainDef.SystemOrGatewayID() == ASSETCHAINS_CHAINID)
        {
            if (pCounterEvidence)
            {
                pCounterEvidence->resize(notarizationData.vtx.size());
            }
            if (pEvidence)
            {
                pEvidence->resize(notarizationData.vtx.size());
            }
            CTransaction returnTx;
            uint256 blkHash;
            LOCK(mempool.cs);
            if (!std::get<1>(lastFinalized).GetOutputTransaction(returnTx, blkHash))
            {
                LogPrintf("Cannot retrieve notarization for %s, node may need to reindex\n", EncodeDestination(CIdentityID(currencyID)).c_str());
                printf("Cannot retrieve notarization for %s, node may need to reindex\n", EncodeDestination(CIdentityID(currencyID)).c_str());
                return false;
            }
            optionalTxOut->push_back(std::make_pair(returnTx, blkHash));
            notarizationData.vtx.push_back(std::make_pair(std::get<1>(lastFinalized), std::get<2>(lastFinalized)));
            notarizationData.lastConfirmed = 0;
            notarizationData.forks.push_back(std::vector<int>({0}));
            notarizationData.bestChain = 0;
            return true;
        }
        CTransaction oneNTx;
        uint256 ntxBlockHash;
        if (myGetTransaction(std::get<1>(lastFinalized).hash, oneNTx, ntxBlockHash) &&
            oneNTx.vout.size() > std::get<1>(lastFinalized).n)
        {
            CPBaaSNotarization thisNotarization(oneNTx.vout[std::get<1>(lastFinalized).n].scriptPubKey);
            if (!thisNotarization.IsValid())
            {
                LogPrintf("Invalid notarization on transaction %s, may need to reindex\n", std::get<1>(lastFinalized).ToUniValue().write().c_str());
                printf("Invalid notarization on transaction %s, may need to reindex\n", std::get<1>(lastFinalized).ToUniValue().write().c_str());
                return false;
            }
            notarizationData.vtx.push_back(std::make_pair(std::get<1>(lastFinalized), thisNotarization));
            notarizationData.forks = std::vector<std::vector<int>>({{0}});
            notarizationData.bestChain = 0;
            notarizationData.lastConfirmed = 0;
            if (optionalTxOut)
            {
                optionalTxOut->push_back(make_pair(oneNTx, ntxBlockHash));
            }
        }

        if (!notarizationData.vtx.size())
        {
            LogPrint("notarization", "%s: failure to find confirmed notarization starting point for currency %s\n", __func__, chainDef.ToUniValue().write(1,2).c_str());
            return false;
        }

        // if from this system, we're done
        if (chainDef.SystemOrGatewayID() == ASSETCHAINS_CHAINID)
        {
            if (pCounterEvidence)
            {
                pCounterEvidence->resize(notarizationData.vtx.size());
            }
            if (pEvidence)
            {
                pEvidence->resize(notarizationData.vtx.size());
            }
            optionalTxOut->resize(notarizationData.vtx.size());
            return true;
        }

        std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> pendingFinalizations;

        // now, add all pending notarizations, if present, and sort them out
        uint160 finalizeNotarizationKey = CCrossChainRPCData::GetConditionID(currencyID, CObjectFinalization::ObjectFinalizationNotarizationKey());
        if (GetAddressUnspent(CCrossChainRPCData::GetConditionID(finalizeNotarizationKey, CObjectFinalization::ObjectFinalizationPendingKey()),
                            CScript::P2IDX,
                            pendingFinalizations) &&
            pendingFinalizations.size())
        {
            // all pending finalizations must be later than the last confirmed transaction and
            // refer to a previous valid / confirmable, not necessarily confirmed, notarization
            // sort the finalizations
            CAddressIndexDBEntryCompare indexComparer;
            std::make_heap(pendingFinalizations.begin(), pendingFinalizations.end(), indexComparer);

            std::multimap<std::pair<CUTXORef, uint32_t>, std::pair<CUTXORef, CPBaaSNotarization>> notarizationReferences;
            bool notarizationOrder = ConnectedChains.IsEnhancedNotarizationOrder(height);

            std::set<CUTXORef> consideredNotarizations;
            std::map<CUTXORef, std::pair<CTransaction, uint256>> referencedTxes;

            CTransaction nTx;
            uint256  blkHash;
            COptCCParams p;
            CObjectFinalization f;
            CPBaaSNotarization n;
            BlockMap::iterator blockIt;
            for (auto it = pendingFinalizations.begin(); it != pendingFinalizations.end(); it++)
            {
                if (!(it->second.script.IsPayToCryptoCondition(p) &&
                      p.IsValid() &&
                      p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                      p.vData.size() &&
                      (f = CObjectFinalization(p.vData[0])).IsValid() &&
                      myGetTransaction(f.output.hash.IsNull() ? it->first.txhash : f.output.hash, nTx, blkHash) &&
                      nTx.vout.size() > f.output.n &&
                      nTx.vout[f.output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                      p.IsValid() &&
                      (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                      p.vData.size() &&
                      (n = CPBaaSNotarization(p.vData[0])).IsValid() &&
                      !blkHash.IsNull() &&
                      (blockIt = mapBlockIndex.find(blkHash)) != mapBlockIndex.end() &&
                      chainActive.Contains(blockIt->second)))
                {
                    LogPrint("notarization", "%s: invalid finalization on transaction %s, output %d\n", __func__, it->first.txhash.GetHex().c_str(), (int)it->first.index);
                    continue;
                }

                std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization> priorNotarization =
                    GetPriorReferencedNotarization(nTx, f.output.n, n);

                if (!optionalTxOut || !mapBlockIndex.count((*optionalTxOut)[0].second))
                {
                    LogPrint("notarization", "%s: invalid nullptr in optionalTxOut or invalid index entry\n", __func__);
                    return false;
                }

                if (!std::get<0>(priorNotarization))
                {
                    std::get<0>(priorNotarization) = mapBlockIndex[(*optionalTxOut)[0].second]->GetHeight();
                    std::get<1>(priorNotarization) = (*optionalTxOut)[0].first;
                    std::get<2>(priorNotarization) = notarizationData.vtx[0].first;
                    std::get<3>(priorNotarization) = notarizationData.vtx[0].second;
                }

                // if finalization is on same transaction as notarization, set it
                if (f.output.hash.IsNull())
                {
                    f.output.hash = it->first.txhash;
                }

                if (consideredNotarizations.count(f.output))
                {
                    continue;
                }
                consideredNotarizations.insert(f.output);

                notarizationReferences.insert({{std::get<2>(priorNotarization), notarizationOrder ? blockIt->second->GetHeight() : 0},{f.output, n}});
                if (optionalTxOut)
                {
                    referencedTxes.insert(std::make_pair(f.output, std::make_pair(nTx, blkHash)));
                }
            }

            // now that we have all pending notarizations (not finalizations) in a sorted list, keep all those which
            // directly or indirectly refer to the last confirmed notarization
            // all others should be pruned
            bool somethingAdded = true;
            while (somethingAdded && notarizationReferences.size())
            {
                somethingAdded = false;
                int numForks = notarizationData.forks.size();
                int forkNum;
                for (forkNum = 0; forkNum < numForks; forkNum++)
                {
                    CUTXORef searchRef = notarizationData.vtx[notarizationData.forks[forkNum].back()].first;

                    std::multimap<std::pair<CUTXORef, uint32_t>, std::pair<CUTXORef, CPBaaSNotarization>>::iterator pendingIt;
                    std::vector<std::pair<CUTXORef, uint32_t>> toRemove;

                    bool newFork = false;

                    for (pendingIt = notarizationReferences.lower_bound({searchRef, 0});
                         pendingIt != notarizationReferences.end() && pendingIt->first.first == searchRef;
                         pendingIt++)
                    {
                        toRemove.push_back(pendingIt->first);
                        notarizationData.vtx.push_back(pendingIt->second);
                        if (optionalTxOut)
                        {
                            optionalTxOut->push_back(referencedTxes[pendingIt->second.first]);
                        }
                        if (newFork)
                        {
                            notarizationData.forks.push_back(notarizationData.forks[forkNum]);
                            notarizationData.forks.back().back() = notarizationData.vtx.size() - 1;
                        }
                        else
                        {
                            notarizationData.forks[forkNum].push_back(notarizationData.vtx.size() - 1);
                            newFork = true;
                            somethingAdded = true;
                        }
                    }
                    for (auto oneKey : toRemove)
                    {
                        notarizationReferences.erase(oneKey);
                    }
                }
            }

            // now, we should have all forks in vectors
            // they should all have roots that point to the same confirmed or initial notarization, which should be enforced by chain rules
            // the best chain should simply be the tip with most power
            notarizationData.SetBestChain(chainDef, *optionalTxOut);
        }

        crossChainNotarizationDataCache.Put(std::make_pair(currencyID, chainActive.LastTip()->GetBlockHash()), std::make_pair(notarizationData, *optionalTxOut));
    }

    // TODO: POST HARDENING - add an LRU cache
    // if we have unconfirmed notarizations and have been asked for
    // evidence or counter evidence, get it
    if (pEvidence)
    {
        pEvidence->resize(notarizationData.vtx.size());
        // evidence is a superset of counterevidence, so get all of it
        for (int i = 1; i < notarizationData.vtx.size(); i++)
        {
            // look for all evidence, pending if not confirmed, or confirmed if so
            std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization>>
                finalizations =
                    CObjectFinalization::GetFinalizations(notarizationData.vtx[i].first,
                                                          i ?
                                                            CObjectFinalization::ObjectFinalizationPendingKey() : CObjectFinalization::ObjectFinalizationConfirmedKey(),
                                                          0,
                                                          0);

            CValidationState state;
            for (auto &oneChallenge : finalizations)
            {
                auto evidenceChunks =
                    std::get<3>(oneChallenge).GetFinalizationEvidence(std::get<2>(oneChallenge), std::get<1>(oneChallenge).n, state);
                for (auto &oneEItem : evidenceChunks)
                {
                    // if we find a rejection, check and store it
                    if (pCounterEvidence && oneEItem.second.IsRejected())
                    {
                        CProofRoot entropyRoot;
                        CProofRoot challengeStartRoot;
                        bool invalidates;
                        CProofRoot alternateRoot =
                            IsValidChallengeEvidence(chainDef,
                                                    notarizationData.vtx[i].second.proofRoots[currencyID],
                                                    oneEItem.second,
                                                    (*optionalTxOut)[i].second,
                                                    invalidates,
                                                    challengeStartRoot,
                                                    std::get<0>(oneChallenge) - 1);
                        if (alternateRoot.IsValid())
                        {
                            (*pCounterEvidence)[i].push_back(std::make_tuple(oneEItem.first, oneEItem.second, alternateRoot, challengeStartRoot));
                        }
                        continue;
                    }
                    (*pEvidence)[i].push_back(std::make_tuple(oneEItem.first, oneEItem.second));
                }
            }
        }
        // in case we did not fill this out, resize it
        if (pCounterEvidence)
        {
            pCounterEvidence->resize(notarizationData.vtx.size());
        }
    }
    else if (pCounterEvidence)
    {
        pCounterEvidence->resize(notarizationData.vtx.size());
        if (notarizationData.vtx.size() > 1)
        {
            std::map<CUTXORef, int> vtxMap;
            auto proofRootIt = notarizationData.vtx[0].second.proofRoots.find(ASSETCHAINS_CHAINID);
            uint32_t startHeight = 0;
            if (proofRootIt != notarizationData.vtx[0].second.proofRoots.end())
            {
                // get block
                auto it = mapBlockIndex.find((*optionalTxOut)[0].second);
                startHeight = it == mapBlockIndex.end() ? 0 : it->second->GetHeight();
            }

            for (int i = 1; i < notarizationData.vtx.size(); i++)
            {
                // look for counter-evidence
                std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization>>
                    finalizations =
                        CObjectFinalization::GetFinalizations(notarizationData.vtx[i].first,
                                                            CObjectFinalization::FinalizationIsChallengeKey(),
                                                            startHeight,
                                                            0);

                CValidationState state;
                for (auto &oneChallenge : finalizations)
                {
                    auto evidenceChunks =
                        std::get<3>(oneChallenge).GetFinalizationEvidence(std::get<2>(oneChallenge), std::get<1>(oneChallenge).n, state);
                    for (auto &oneEItem : evidenceChunks)
                    {
                        // if we find a rejection, check it
                        if (oneEItem.second.IsRejected())
                        {
                            CProofRoot entropyRoot;
                            CProofRoot challengeStartRoot;
                            bool invalidates;
                            CProofRoot alternateRoot =
                                IsValidChallengeEvidence(chainDef,
                                                        notarizationData.vtx[i].second.proofRoots[currencyID],
                                                        oneEItem.second,
                                                        (*optionalTxOut)[i].second,
                                                        invalidates,
                                                        challengeStartRoot,
                                                        std::get<0>(oneChallenge) - 1);
                            if (alternateRoot.IsValid())
                            {
                                (*pCounterEvidence)[i].push_back(std::make_tuple(oneEItem.first, oneEItem.second, alternateRoot, challengeStartRoot));
                            }
                        }
                    }
                }
            }
        }
    }
    return notarizationData.IsValid() && notarizationData.vtx.size() != 0;
}

UniValue getnotarizationdata(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        throw runtime_error(
            "getnotarizationdata \"currencynameorid\" (getevidence) (separatecounterevidence)\n"
            "\nReturns the latest PBaaS notarization data for the specifed currencyid.\n"

            "\nArguments\n"
            "1. \"currencyid\"                  (string, required) the hex-encoded ID or string name search for notarizations on\n"
            "2. \"(getevidence)\"               (bool, optional)    if true, returns notarization evidence as well as other data\n"
            "1. \"(separatecounterevidence)\"   (bool, optional)    if true, counter-evidence is processed and returned with proofroots\n"

            "\nResult:\n"
            "{\n"
            "  \"version\" : n,                 (numeric) The notarization protocol version\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getnotarizationdata", "\"currencyid\"")
            + HelpExampleRpc("getnotarizationdata", "\"currencyid\"")
        );
    }

    CheckPBaaSAPIsValid();

    uint160 chainID;
    CChainNotarizationData nData;

    chainID = GetChainIDFromParam(params[0]);
    bool getEvidence = params.size() > 1 ? uni_get_bool(params[1]) : false;
    bool getCounterEvidence = params.size() > 2 ? uni_get_bool(params[2]) : false;

    LOCK2(cs_main, mempool.cs);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currencyid");
    }

    std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence>>> evidence;
    std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>>> counterEvidence;
    std::vector<std::pair<CTransaction, uint256>> transactionsAndBlockHash;
    if (GetNotarizationData(chainID,
                            nData,
                            &transactionsAndBlockHash,
                            getCounterEvidence ? &counterEvidence : nullptr,
                            getEvidence ? &evidence : nullptr))
    {
        return nData.ToUniValue(transactionsAndBlockHash, counterEvidence, evidence);
    }
    else
    {
        return NullUniValue;
    }
}

UniValue getlaunchinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        throw runtime_error(
            "getlaunchinfo \"currencyid\"\n"
            "\nReturns the launch notarization data and partial transaction proof of the \n"
            "launch notarization for the specifed currencyid.\n"

            "\nArguments\n"
            "1. \"currencyid\"                  (string, required) the hex-encoded ID or string name  search for notarizations on\n"

            "\nResult:\n"
            "{\n"
            "  \"currencydefinition\" : {},     (json) Full currency definition\n"
            "  \"txid\" : \"hexstr\",           (hexstr) transaction ID\n"
            "  \"voutnum\" : \"n\",             (number) vout index of the launch notarization\n"
            "  \"transactionproof\" : {},       (json) Partial transaction proof of the launch transaction and output\n"
            "  \"launchnotarization\" : {},     (json) Final CPBaaSNotarization clearing launch or refund\n"
            "  \"notarynotarization\" : {},     (json) Current notarization of this chain\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getlaunchinfo", "\"currencyid\"")
            + HelpExampleRpc("getlaunchinfo", "\"currencyid\"")
        );
    }

    CheckPBaaSAPIsValid();

    uint160 chainID;
    LOCK(cs_main);

    CCurrencyDefinition curDef;
    chainID = ValidateCurrencyName(uni_get_str(params[0]), true, &curDef);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currencyid or name");
    }

    std::pair<CInputDescriptor, CPartialTransactionProof> notarizationTx;
    CPBaaSNotarization launchNotarization, notaryNotarization;
    if (!ConnectedChains.GetLaunchNotarization(curDef, notarizationTx, launchNotarization, notaryNotarization) ||
        !notaryNotarization.proofRoots.count(ASSETCHAINS_CHAINID))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Valid notarization not found");
    }

    std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> exports;
    ConnectedChains.GetSystemExports(curDef.systemID, exports, 0, notarizationTx.second.GetProofHeight(), true);

    std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>> foundExport;
    bool isExportFound = false;
    if (exports.size())
    {
        for (auto &oneExport : exports)
        {
            CCrossChainExport oneCCX(oneExport.first.first.scriptPubKey);
            if (oneCCX.IsValid() &&
                oneCCX.destCurrencyID == chainID)
            {
                foundExport = oneExport;
                isExportFound = true;
                break;
            }
        }
    }
    if (!isExportFound)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No valid export found");
    }

    UniValue retVal(UniValue::VOBJ);
    retVal.pushKV("currencydefinition", curDef.ToUniValue());
    retVal.pushKV("notarizationtxid", notarizationTx.first.txIn.prevout.hash.GetHex());
    retVal.pushKV("notarizationvoutnum", (int64_t)notarizationTx.first.txIn.prevout.n);
    retVal.pushKV("notarizationproof", notarizationTx.second.ToUniValue());
    retVal.pushKV("exporttxid", foundExport.first.first.txIn.prevout.hash.GetHex());
    retVal.pushKV("exportvoutnum", (int64_t)foundExport.first.first.txIn.prevout.n);
    retVal.pushKV("exportproof", foundExport.first.second.ToUniValue());
    if (foundExport.second.size())
    {
        UniValue exportTransfers(UniValue::VARR);
        for (auto &oneTransfer : foundExport.second)
        {
            exportTransfers.push_back(oneTransfer.ToUniValue());
        }
        retVal.pushKV("exporttransfers", exportTransfers);
    }
    retVal.pushKV("launchnotarization", launchNotarization.ToUniValue());
    retVal.pushKV("notarynotarization", notaryNotarization.ToUniValue());
    return retVal;
}

UniValue getbestproofroot(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1 || params[0].getKeys().size() < 2)
    {
        throw runtime_error(
            "getbestproofroot '{\"proofroots\":[\"version\":n,\"type\":n,\"systemid\":\"currencyidorname\",\"height\":n,"
            "                   \"stateroot\":\"hex\",\"blockhash\":\"hex\",\"power\":\"hex\"],\"lastconfirmed\":n}'\n"
            "\nDetermines and returns the index of the best (most recent, valid, qualified) proof root in the list of proof roots,\n"
            "and the most recent, valid proof root.\n"

            "\nArguments\n"
            "{\n"
            "  \"proofroots\":                  (array, required/may be empty) ordered array of proof roots, indexed on return\n"
            "  [\n"
            "    {\n"
            "      \"version\":n                (int, required) version of this proof root data structure\n"
            "      \"type\":n                   (int, required) type of proof root (chain or system specific)\n"
            "      \"systemid\":\"hexstr\"      (hexstr, required) system the proof root is for\n"
            "      \"height\":n                 (uint32_t, required) height of this proof root\n"
            "      \"stateroot\":\"hexstr\"     (hexstr, required) Merkle or merkle-style tree root for the specified block/sequence\n"
            "      \"blockhash\":\"hexstr\"     (hexstr, required) hash identifier for the specified block/sequence\n"
            "      \"power\":\"hexstr\"         (hexstr, required) work, stake, or combination of the two for most-work/most-power rule\n"
            "    }\n"
            "  .\n"
            "  .\n"
            "  .\n"
            "  ]\n"
            "  \"currencies\":[\"id1\"]         (array, optional) currencies to query for currency states\n"
            "  \"lastconfirmed\":n              (int, required) index into the proof root array indicating the last confirmed root"
            "}\n"

            "\nResult:\n"
            "\"bestindex\"                      (int) index of best proof root not confirmed that is provided, confirmed index, or -1"
            "\"latestproofroot\"                (object) latest valid proof root of chain"
            "\"laststableproofroot\"            (object) either tip-BLOCK_MATURITY or last notarized/witnessed tip"
            "\"lastconfirmedproofroot\"         (object) last proof root of chain that has been confirmed"
            "\"currencystates\"                 (int) currency states of target currency and published bridges"

            "\nExamples:\n"
            + HelpExampleCli("getbestproofroot", "\"{\"proofroots\":[\"version\":n,\"type\":n,\"systemid\":\"currencyidorname\",\"height\":n,\"stateroot\":\"hex\",\"blockhash\":\"hex\",\"power\":\"hex\"],\"lastconfirmed\":n}\"")
            + HelpExampleRpc("getbestproofroot", "\"{\"proofroots\":[\"version\":n,\"type\":n,\"systemid\":\"currencyidorname\",\"height\":n,\"stateroot\":\"hex\",\"blockhash\":\"hex\",\"power\":\"hex\"],\"lastconfirmed\":n}\"")
        );
    }

    CheckPBaaSAPIsValid();

    std::vector<std::string> paramKeys = params[0].getKeys();
    UniValue currenciesUni;
    if (paramKeys.size() > 3 ||
        (paramKeys.size() == 3) && !(currenciesUni = find_value(params[0], "currencies")).isArray())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "too many members in object or invalid currencies array");
    }

    int lastConfirmed = uni_get_int(find_value(params[0], "lastconfirmed"), -1);
    if (lastConfirmed < 0)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid lastconfirmed");
    }

    std::multimap<uint32_t, std::pair<int32_t, CProofRoot>> proofRootMap;
    UniValue uniProofRoots = find_value(params[0], "proofroots");
    if (!uniProofRoots.isArray())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid proof root array parameter");
    }

    CProofRoot lastConfirmedRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID), lastConfirmedRootClaim(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);

    if (uniProofRoots.size() && uniProofRoots.size() > lastConfirmed)
    {
        lastConfirmedRootClaim = CProofRoot(uniProofRoots[lastConfirmed]);
    }

    LOCK(cs_main);

    UniValue retVal(UniValue::VOBJ);

    // no notarization can be considered confirmed by another chain or system, if it has not already been first confirmed
    // by the first notary of this one. any confirmed proof root must map to a confirmed notarization on this chain that is
    // correct and at least before the last confirmed one on this chain
    //
    // it is the responsibility of the calling system or chain to determine the difference between a valid root and a root
    // confirmed, old enough, or stable enough to be relied upon.
    //
    std::vector<std::pair<CTransaction, uint256>> notaryTxVec;
    CChainNotarizationData notaryCND;
    if (ConnectedChains.FirstNotaryChain().IsValid())
    {
        if (GetNotarizationData(ConnectedChains.FirstNotaryChain().GetID(), notaryCND, &notaryTxVec) &&
            notaryCND.IsConfirmed() &&
            notaryCND.vtx[notaryCND.lastConfirmed].second.proofRoots.count(ASSETCHAINS_CHAINID))
        {
            lastConfirmedRoot = notaryCND.vtx[notaryCND.lastConfirmed].second.proofRoots[ASSETCHAINS_CHAINID];
        }
        else
        {
            // if we have a valid first notary, then we should have a valid confirmed notarization, or something is wrong
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid notarization for confirmed proof of current chain");
        }
    }

    for (int i = 0; i < uniProofRoots.size(); i++)
    {
        CProofRoot oneRoot(uniProofRoots[i]);
        if (!oneRoot.IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid proof root in array");
        }
        if (oneRoot.systemID != ASSETCHAINS_CHAINID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("incorrect systemid in proof root for %s", EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID))));
        }
        // if we have no notary chain, we could have an invalid last confirmed
        proofRootMap.insert(std::make_pair(oneRoot.rootHeight, std::make_pair(i, oneRoot)));
    }

    uint32_t nHeight = chainActive.Height();

    std::multimap<uint32_t, int32_t> validRoots;             // height, index (only return the first valid at each height)

    for (auto it = proofRootMap.rbegin(); it != proofRootMap.rend(); it ++)
    {
        if (it->second.second == it->second.second.GetProofRoot(it->second.second.rootHeight))
        {
            validRoots.insert(std::make_pair(it->second.second.rootHeight, it->second.first));
        }
    }

    if (lastConfirmedRoot.IsValid() &&
        lastConfirmedRootClaim.IsValid() &&
        !validRoots.count(lastConfirmedRootClaim.rootHeight))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("incorrect claim of confirmed proof root for height %u, %s", lastConfirmedRoot.rootHeight, EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID))));
    }

    if (validRoots.size())
    {
        UniValue validArr(UniValue::VARR);
        std::set<int> indexSort;
        for (auto &oneRoot : validRoots)
        {
            indexSort.insert(oneRoot.second);
        }
        for (auto &oneIndex : indexSort)
        {
            validArr.push_back(oneIndex);
        }
        retVal.pushKV("validindexes", validArr);
        retVal.pushKV("bestindex", validArr[validArr.size() - 1]);
    }

    // get the latest proof root and currency states
    retVal.pushKV("latestproofroot", CProofRoot::GetProofRoot(nHeight).ToUniValue());
    if (lastConfirmedRoot.IsValid() && validRoots.count(lastConfirmedRoot.rootHeight))
    {
        retVal.pushKV("lastconfirmedproofroot", lastConfirmedRoot.ToUniValue());
        retVal.pushKV("laststableproofroot", lastConfirmedRoot.ToUniValue());
        auto itPair = validRoots.equal_range(lastConfirmedRoot.rootHeight);
        int lastConfirmedIndex = itPair.first == validRoots.end() ? -1 : itPair.first->second;
        for (auto it = itPair.first; it != itPair.second; it++)
        {
            if (it->second > lastConfirmedIndex)
            {
                lastConfirmedIndex = it->second;
            }
        }
        retVal.pushKV("lastconfirmedindex", lastConfirmedIndex);
    }
    else if (lastConfirmedRoot.IsValid())
    {
        retVal.pushKV("laststableproofroot", lastConfirmedRoot.ToUniValue());
    }
    else
    {
        retVal.pushKV("laststableproofroot", CProofRoot::GetProofRoot((nHeight - CPBaaSNotarization::BLOCKS_TO_STABLE_NOTARY_ROOT) > 0 ?
                                             (nHeight - CPBaaSNotarization::BLOCKS_TO_STABLE_NOTARY_ROOT) :
                                             1).ToUniValue());
    }

    std::set<uint160> currenciesSet({ASSETCHAINS_CHAINID});
    CCurrencyDefinition targetCur;
    uint160 targetCurID;
    UniValue currencyStatesUni(UniValue::VARR);
    UniValue confirmedCurrencyStatesUni(UniValue::VARR);
    if ((targetCurID = ValidateCurrencyName(EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)), true, &targetCur)).IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("invalid currency state request for %s", EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID))));
    }
    if (lastConfirmedRoot.IsValid())
    {
        confirmedCurrencyStatesUni.push_back(ConnectedChains.GetCurrencyState(targetCur, lastConfirmedRoot.rootHeight).ToUniValue());
    }
    else
    {
        currencyStatesUni.push_back(ConnectedChains.GetCurrencyState(targetCur, nHeight).ToUniValue());
    }

    for (int i = 0; i < currenciesUni.size(); i++)
    {
        if ((targetCurID = ValidateCurrencyName(uni_get_str(currenciesUni[i]), true, &targetCur)).IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("invalid currency state request for %s", uni_get_str(currenciesUni[i])));
        }
        if (!currenciesSet.count(targetCurID))
        {
            currencyStatesUni.push_back(ConnectedChains.GetCurrencyState(targetCur, nHeight).ToUniValue());
            if (lastConfirmedRoot.IsValid())
            {
                confirmedCurrencyStatesUni.push_back(ConnectedChains.GetCurrencyState(targetCur, lastConfirmedRoot.rootHeight).ToUniValue());
            }
        }
    }
    retVal.pushKV("currencystates", lastConfirmedRoot.IsValid() ? confirmedCurrencyStatesUni : currencyStatesUni);
    retVal.pushKV("latestcurrencystates", currencyStatesUni);

    return retVal;
}

UniValue getnotarizationproofs(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getnotarizationproofs '[{\"type\":\"vrsc::evidence.skipchallenge\" || \"iCwxpRL6h3YeCRtGjgQSsqoKdZCuM4Dxaf\",\n"
            "                      \"evidence\":{CNotaryEvidence},\n"
            "                      \"entropyhash\":\"hex\",\n"
            "                      \"proveheight\":n,\n"
            "                      \"atheight\":n}\n"
            "                     {\"type\":\"vrsc::evidence.primaryproof\" || \"iKDesmiEkEjDG61nQSZJSGhWvC8x8xA578\",\n"
            "                      \"priornotarizationref\":{CUTXORef} || \"priorroot\":{CProofRoot} ,\n"
            "                      \"challengeroots\":[{\"indexkey\":{object}, \"proofroot\":{CProofRoot}}, ...],\n"
            "                      \"evidence\":{CNotaryEvidence},\n"
            "                      \"entropyhash\":\"hex\",\n"
            "                      \"confirmnotarization\":{newnotarization}, |\n"
            "                      \"confirmroot\":{CPRoofRoot}},\n"
            "                      \"fromheight\":n,\n"
            "                      \"toheight\":n},\n"
            "                      ...]'\n"
            "\nReturns proofs to a caller for requested challenges. Some proofs can either independently or in combination\n"
            "with other proofs over time invalidate or force a competing chain to provide more proofs in order to confirm\n"
            "any pending cross-chain notarization of an alternate chain that may not agree with us.\n"
            "\n* It is not valid to have a challenge request with both confirmnotarization and confirmroot.\n"

            "\nArguments\n"
            "\"challengerequests\"             (array, required) one or more challenge requests for unconfirmed notarizations on a bridged system\n"

            "\nResult:\n"
            "{\"evidence\":[{CNotaryEvidence}, ...]   (array) notary evidence challenges, including proofs for challenges requested\n"

            "\nExamples:\n"
            + HelpExampleCli("getnotarizationproofs", "'[{\"type\":\"iCwxpRL6h3YeCRtGjgQSsqoKdZCuM4Dxaf\", \"evidence\":{CNotaryEvidence}, \"proveheight\":n, \"atheight\":n}, ...]'")
            + HelpExampleRpc("getnotarizationproofs", "[{\"type\":\"iCwxpRL6h3YeCRtGjgQSsqoKdZCuM4Dxaf\", \"evidence\":{CNotaryEvidence}, \"proveheight\":n, \"atheight\":n}, ...]")
        );
    }

    CheckPBaaSAPIsValid();

    std::vector<UniValue> retVal;

    if (params[0].isArray() && params[0].size())
    {
        retVal.resize(params[0].size());

        enum EChallengeTypes {
            INVALID_CHALLENGE = 0,
            SKIP_CHALLENGE = 1,
            PRIMARY_PROOF = 2,
        };

        uint32_t nHeight = chainActive.Height();

        for (int i = 0; i < params[0].size(); i++)
        {
            UniValue oneRetObj(UniValue::VOBJ);

            uint160 challengeTypeKey = ParseVDXFKey(uni_get_str(find_value(params[0][i], "type")));
            EChallengeTypes challengeType = challengeTypeKey == CNotaryEvidence::SkipChallengeKey() ? SKIP_CHALLENGE :
                                            challengeTypeKey == CNotaryEvidence::PrimaryProofKey() ? PRIMARY_PROOF :
                                            INVALID_CHALLENGE;

            CNotaryEvidence evidence(find_value(params[0][i], "evidence"));
            if (!evidence.IsValid())
            {
                oneRetObj.pushKV("error", "Challenge request must include valid JSON CNotaryEvidence object to start from");
                retVal[i] = oneRetObj;
                continue;
            }

            uint256 entropyHash = uint256S(uni_get_str(find_value(params[0][i], "entropyhash")));
            if (entropyHash.IsNull())
            {
                oneRetObj.pushKV("error", "Challenge request must include \"entropyhash\"");
                retVal[i] = oneRetObj;
                continue;
            }

            switch (challengeType)
            {
                case SKIP_CHALLENGE:
                {
                    LOCK(cs_main);
                    // all we need to do is prove the header ref at "proveheight" using height "atheight" and add it to the evidence
                    int64_t proveHeight = uni_get_int64(find_value(params[0][i], "proveheight"), -1);
                    int64_t atHeight = uni_get_int64(find_value(params[0][i], "atheight"), -1);

                    if (proveHeight > 0 &&
                        proveHeight < atHeight &&
                        atHeight > 0 &&
                        atHeight <= chainActive.Height())
                    {
                        auto mmrView = chainActive.GetMMV();
                        mmrView.resize(atHeight + 1);
                        CMMRProof blockHeaderProof;
                        if (!evidence.evidence.chainObjects.size() ||
                            evidence.evidence.chainObjects[0]->objectType != CHAINOBJ_PROOF_ROOT ||
                            !chainActive.GetBlockProof(mmrView, blockHeaderProof, proveHeight))
                        {
                            oneRetObj.pushKV("error", "could not create block proof for block at height " + std::to_string(proveHeight) + "from height " + std::to_string(atHeight));
                            break;
                        }
                        evidence.evidence << CBlockHeaderProof(blockHeaderProof, chainActive[proveHeight]->GetBlockHeader());

                        UniValue challengeUni(UniValue::VOBJ);
                        challengeUni.pushKV("type", EncodeDestination(CIdentityID(challengeTypeKey)));
                        challengeUni.pushKV("notarizationref", evidence.output.ToUniValue());
                        challengeUni.pushKV("challengeroot", ((CChainObject<CProofRoot> *)evidence.evidence.chainObjects[0])->object.ToUniValue());
                        challengeUni.pushKV("evidence", evidence.ToUniValue());
                        oneRetObj.pushKV("result", challengeUni);
                    }
                    else
                    {
                        oneRetObj.pushKV("error", "Skip proof request must include valid \"proveheight\" and \"atheight\"");
                    }
                    break;
                }

                case PRIMARY_PROOF:
                {
                    LOCK2(cs_main, mempool.cs);
                    CUTXORef priorNotarizationRef(find_value(params[0][i], "priornotarizationref"));    // prove notarization tx output
                    CProofRoot priorRoot(find_value(params[0][i], "priorroot"));    // prove notarization tx output
                    int64_t fromHeight = uni_get_int64(find_value(params[0][i], "fromheight"), -1);
                    int64_t toHeight = uni_get_int64(find_value(params[0][i], "toheight"), -1);
                    CProofRoot confirmRoot(find_value(params[0][i], "confirmroot"));
                    CUTXORef confirmNotarizationRef(find_value(params[0][i], "confirmnotarizationref"));    // prove notarization tx output

                    UniValue challengeRootsUni(find_value(params[0][i], "challengeroots"));
                    std::vector<std::tuple<CUTXORef, CProofRoot, CBlockHeaderProof>> challengeRoots;

                    CTransaction notarizationTxToProve;
                    uint256 notarizationBlockHash;

                    // in case we have a reorg, the stability of this future root cannot matter too much,
                    // we'll have to prove up to this root if we are challenged, and it is already ahead of
                    // the root in our notarization by quite some ways, however far this chain is in front of
                    // it's confirm root or confirm notarization
                    //
                    // if we are a PBaaS chain needing to to prove confirmation of a notarization, we choose the
                    // finalization block. if we are the notary chain and are notarized, we have two options:
                    //
                    // 1) select any root more than CPBaaSNotarization::BLOCKS_TO_STABLE_PBAAS_ROOT after the last
                    //    confirmed notarization on our notary chain.
                    //
                    // 2) use a root that is CPBaaSNotarization::BLOCKS_ENFORCED_TO_STABLE_NOTARY_ROOT in front of
                    //    the root or transaction we are proving, which may also need proving if challenged.
                    //

                    CProofRoot lastConfirmedRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);

                    if (confirmNotarizationRef.IsNull() &&
                        ConnectedChains.FirstNotaryChain().IsValid())
                    {
                        std::vector<std::pair<CTransaction, uint256>> notaryTxVec;
                        CChainNotarizationData notaryCND;
                        if (GetNotarizationData(ConnectedChains.FirstNotaryChain().GetID(), notaryCND, &notaryTxVec) &&
                            notaryCND.IsConfirmed() &&
                            notaryCND.vtx[notaryCND.lastConfirmed].second.proofRoots.count(ASSETCHAINS_CHAINID))
                        {
                            lastConfirmedRoot = notaryCND.vtx[notaryCND.lastConfirmed].second.proofRoots[ASSETCHAINS_CHAINID];
                        }
                        else
                        {
                            // if we have a valid first notary, then we should have a valid confirmed notarization, or something is wrong
                            oneRetObj.pushKV("error", "Invalid notarization for confirmed proof of current chain");
                            break;
                        }
                    }

                    CPBaaSNotarization confirmNotarization;
                    CPartialTransactionProof notarizationTxProof;
                    BlockMap::iterator blockIt = mapBlockIndex.end();
                    bool isConfirmNotarization = !confirmNotarizationRef.hash.IsNull() && confirmNotarizationRef.n >= 0;
                    if (isConfirmNotarization)
                    {
                        if (!confirmNotarizationRef.GetOutputTransaction(notarizationTxToProve, notarizationBlockHash) ||
                            notarizationBlockHash.IsNull() ||
                            notarizationTxToProve.vout.size() <= confirmNotarizationRef.n ||
                            !(confirmNotarization = CPBaaSNotarization(notarizationTxToProve.vout[confirmNotarizationRef.n].scriptPubKey)).IsValid())
                        {
                            oneRetObj.pushKV("error", "Cannot retrieve cross-confirmed transaction, POSSIBLY DUE TO LOCAL CHAIN STATE CORRUPTION");
                            break;
                        }

                        blockIt = mapBlockIndex.find(notarizationBlockHash);
                        if (blockIt == mapBlockIndex.end() ||
                            !chainActive.Contains(blockIt->second))
                        {
                            oneRetObj.pushKV("error", "Cross-confirmed transaction is not in active chain, MAYBE DUE TO LOCAL CHAIN STATE CORRUPTION");
                            break;
                        }

                    }

                    if (confirmNotarization.IsValid() && confirmNotarization.proofRoots.count(ASSETCHAINS_CHAINID))
                    {
                        confirmRoot = confirmNotarization.proofRoots[ASSETCHAINS_CHAINID];
                    }

                    CProofRoot futureRoot;
                    std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization> finalizationToProve;
                    if (confirmNotarization.IsValid())
                    {
                        // future root must be the root of the height where the finalization for this notarization is,
                        // it must be provable in response to a challenge, so we cannot consider the mempool
                        auto notarizationFinalizations =
                            CObjectFinalization::GetFinalizations(confirmNotarizationRef, CObjectFinalization::ObjectFinalizationFinalizedKey(),
                                                                  blockIt->second->GetHeight(),
                                                                  chainActive.Height());

                        for (auto &oneFinalization : notarizationFinalizations)
                        {
                            if (std::get<0>(oneFinalization) &&
                                std::get<3>(oneFinalization).IsConfirmed() &&
                                std::get<3>(oneFinalization).output == confirmNotarizationRef)
                            {
                                finalizationToProve = oneFinalization;
                                futureRoot.rootHeight = std::get<0>(oneFinalization);
                                break;
                            }
                        }
                        if (!std::get<3>(finalizationToProve).IsValid())
                        {
                            oneRetObj.pushKV("error", "Cannot find and prove confirmation for notarization");
                            break;
                        }
                    }
                    else
                    {
                        futureRoot.rootHeight = lastConfirmedRoot.IsValid() ? lastConfirmedRoot.rootHeight + 5 :
                                                                            std::min(nHeight - CPBaaSNotarization::MIN_BLOCKS_FOR_SEMISTABLE_TIP,
                                                                                    confirmRoot.rootHeight + CPBaaSNotarization::BLOCKS_ENFORCED_TO_STABLE_NOTARY_ROOT);
                    }

                    uint32_t blocksBetween = futureRoot.rootHeight - confirmRoot.rootHeight;
                    int enforceFutureRootDistance = ((confirmNotarization.IsValid() || ConnectedChains.notarySystems.size()) ?
                                                        CPBaaSNotarization::BLOCKS_TO_STABLE_PBAAS_ROOT :
                                                        CPBaaSNotarization::BLOCKS_ENFORCED_TO_STABLE_NOTARY_ROOT);
                    if (futureRoot.rootHeight > nHeight ||
                        (!lastConfirmedRoot.IsValid() && blocksBetween < enforceFutureRootDistance))
                    {
                        oneRetObj.pushKV("error", "Too early for stable proof, have blocks to tip " + std::to_string(blocksBetween) +
                                                  ", need " + std::to_string(enforceFutureRootDistance));
                        break;
                    }

                    futureRoot = CProofRoot::GetProofRoot(futureRoot.rootHeight);
                    if (LogAcceptCategory("notarization")) //  && LogAcceptCategory("verbose")
                    {
                        printf("%s: futureRoot: %s\n", __func__, futureRoot.ToUniValue().write(1,2).c_str());
                        LogPrintf("%s: futureRoot: %s\n", __func__, futureRoot.ToUniValue().write(1,2).c_str());
                    }

                    if (isConfirmNotarization)
                    {
                        notarizationTxProof = CPartialTransactionProof(notarizationTxToProve,
                                                                       std::vector<int>(),
                                                                       std::vector<int>({(int)confirmNotarizationRef.n}),
                                                                       blockIt->second,
                                                                       futureRoot.rootHeight);
                    }

                    if ((priorNotarizationRef.hash.IsNull() && !priorRoot.IsValid()) || !confirmRoot.IsValid())
                    {
                        oneRetObj.pushKV("error", "Invalid notarization reference or missing/invalid proof root\npriorroot: " +
                                                   priorRoot.ToUniValue().write(1,2) + "\nconfirmroot: " + priorRoot.ToUniValue().write(1,2));
                        break;
                    }
                    if (priorRoot.IsValid() && (priorRoot.rootHeight <= 0 || priorRoot.rootHeight > confirmRoot.rootHeight))
                    {
                        oneRetObj.pushKV("error", "Invalid prior proof root");
                        break;
                    }

                    if (confirmRoot.rootHeight <= 0 ||
                        confirmRoot.rootHeight >= futureRoot.rootHeight)
                    {
                        oneRetObj.pushKV("error", "Invalid root or root height in: " + confirmRoot.ToUniValue().write());
                        break;
                    }

                    auto curMMV = chainActive.GetMMV();
                    curMMV.resize(confirmRoot.rootHeight + 1);

                    if (challengeRootsUni.isArray() && challengeRootsUni.size())
                    {
                        bool doBreak = false;
                        for (int j = 0; j < challengeRootsUni.size(); j++)
                        {
                            CUTXORef oneTxOut(find_value(challengeRootsUni[j], "txout"));
                            CProofRoot oneChallengeRoot(find_value(challengeRootsUni[j], "proofroot"));
                            if (oneChallengeRoot.IsValid() &&
                                oneChallengeRoot.systemID == ASSETCHAINS_CHAINID &&
                                confirmRoot.rootHeight >= fromHeight)
                            {
                                uint32_t blockHeight = oneChallengeRoot.rootHeight;
                                if (blockHeight > confirmRoot.rootHeight)
                                {
                                    blockHeight = confirmRoot.rootHeight;
                                }
                                CMMRProof blockHeaderProof;
                                chainActive.GetBlockProof(curMMV, blockHeaderProof, oneChallengeRoot.rootHeight);
                                challengeRoots.push_back({oneTxOut,
                                                          oneChallengeRoot,
                                                          CBlockHeaderProof(blockHeaderProof, chainActive[blockHeight]->GetBlockHeader())});
                            }
                            else
                            {
                                oneRetObj.pushKV("error", "Invalid challenge root: " + oneChallengeRoot.ToUniValue().write());
                                doBreak = true;
                                break;
                            }
                        }
                        if (doBreak)
                        {
                            break;
                        }
                    }

                    // put the challenge proofs in first before the primary proof
                    CCrossChainProof challengeProof(CCrossChainProof::VERSION_INVALID);
                    if (challengeRoots.size())
                    {
                        CPrimaryProofDescriptor proofDescr(CPrimaryProofDescriptor::VERSION_CURRENT);
                        challengeProof.version = CCrossChainProof::VERSION_CURRENT;
                        for (auto &oneTxRef : challengeRoots)
                        {
                            proofDescr.challengeOutputs.push_back(std::get<0>(oneTxRef));
                        }
                        challengeProof << CEvidenceData(CNotaryEvidence::PrimaryProofKey(), ::AsVector(proofDescr));
                        for (auto &oneChallengeProof : challengeRoots)
                        {
                            challengeProof << std::get<1>(oneChallengeProof);
                            challengeProof << std::get<2>(oneChallengeProof);
                        }
                        // we keep this separate, so it can be easily separated by the caller into
                        // challenge evidence reference for indexing and primary evidence
                        evidence.evidence << challengeProof;
                    }

                    CPBaaSNotarization priorNotarization;
                    CTransaction priorNotarizationTx;
                    uint256 blockHash;
                    if (!((priorNotarizationRef.IsValid() &&
                           !priorNotarizationRef.hash.IsNull() &&
                           priorNotarizationRef.GetOutputTransaction(priorNotarizationTx, blockHash) &&
                           !blockHash.IsNull() &&
                           priorNotarizationTx.vout.size() > priorNotarizationRef.n &&
                           (priorNotarization = CPBaaSNotarization(priorNotarizationTx.vout[priorNotarizationRef.n].scriptPubKey)).IsValid()) ||
                           priorRoot.IsValid()))
                    {
                        oneRetObj.pushKV("error", "Cannot find referenced notarization at: " + priorNotarizationRef.ToUniValue().write());
                        break;
                    }

                    // if we have a notarization to prove, do it, otherwise, prove a header
                    // EXPECT_LASTNOTARIZATION_PROOF - transaction proof of last agreed to on this chain or of root header
                    if (priorNotarization.IsValid())
                    {
                        auto blockIt = mapBlockIndex.find(blockHash);
                        if (blockIt == mapBlockIndex.end() ||
                            !chainActive.Contains(blockIt->second))
                        {
                            oneRetObj.pushKV("error", "Cross-confirmed transaction is not in active chain, MAYBE DUE TO LOCAL CHAIN STATE CORRUPTION");
                            break;
                        }

                        std::vector<int> txInsToProve;
                        std::vector<int> txOutsToProve;
                        if (priorNotarization.IsBlockOneNotarization())
                        {
                            // get entire coinbase
                            txInsToProve.push_back(0);
                            txOutsToProve.resize(priorNotarizationTx.vout.size());
                            for (int outNum = 0; outNum < txOutsToProve.size(); outNum++)
                            {
                                txOutsToProve[outNum] = outNum;
                            }
                        }
                        else
                        {
                            txOutsToProve.push_back((int)priorNotarizationRef.n);
                        }

                        CPartialTransactionProof oneTxProof(priorNotarizationTx,
                                                            txInsToProve,
                                                            txOutsToProve,
                                                            blockIt->second,
                                                            confirmRoot.rootHeight);
                        if (!oneTxProof.IsValid())
                        {
                            oneRetObj.pushKV("error", "Unable to create valid cross-confirmed tx proof");
                            break;
                        }
                        evidence.evidence << oneTxProof;
                    }
                    else
                    {
                        CMMRProof headerProof;
                        if (!chainActive.GetBlockProof(curMMV, headerProof, priorRoot.rootHeight))
                        {
                            oneRetObj.pushKV("error", "Cannot prove evidence");
                            break;
                        }
                        CBlockHeader bh = chainActive[priorRoot.rootHeight]->GetBlockHeader();
                        CBlockHeaderAndProof blockHeaderProof(headerProof, bh);
                        evidence.evidence << blockHeaderProof;

                        futureRoot = CProofRoot::GetProofRoot(futureRoot.rootHeight);
                        if (LogAcceptCategory("notarization")) //  && LogAcceptCategory("verbose")
                        {
                            //printf("%s: priorRoot: %s\ncompactPower: %s\nblockHeaderProof: %s\n", __func__, priorRoot.ToUniValue().write(1,2).c_str(), GetCompactPower(bh.nNonce, bh.nBits, bh.nVersion).GetHex().c_str(), blockHeaderProof.ToUniValue().write(1,2).c_str());
                            LogPrintf("%s: confirmRoot: %s\npriorRoot: %s\npriorCompactPower: %s\npriorBlockHeaderProof: %s\n", __func__, priorRoot.ToUniValue().write(1,2).c_str(), GetCompactPower(bh.nNonce, bh.nBits, bh.nVersion).GetHex().c_str(), blockHeaderProof.ToUniValue().write(1,2).c_str());
                        }
                    }

                    // EXPECT_FUTURE_PROOF_ROOT - future root to prove this notarization
                    evidence.evidence << futureRoot;

                    // if we have a notarization to prove, prove it and the finalization, otherwise, prove
                    // a header
                    if (confirmNotarization.IsValid())
                    {
                        evidence.evidence << notarizationTxProof;
                        evidence.evidence << CPartialTransactionProof(std::get<2>(finalizationToProve),
                                                                    std::vector<int>(),
                                                                    std::vector<int>({(int)std::get<1>(finalizationToProve).n}),
                                                                    chainActive[std::get<0>(finalizationToProve)],
                                                                    futureRoot.rootHeight);
                    }
                    else
                    {
                        // we are requested to prove the existence of this notarization on this chain
                        // from the future root
                        curMMV.resize(futureRoot.rootHeight + 1);

                        CMMRProof headerProof;
                        if (!chainActive.GetBlockProof(curMMV, headerProof, confirmRoot.rootHeight))
                        {
                            oneRetObj.pushKV("error", "Cannot prove evidence for challenge");
                            break;
                        }

                        CBlockHeaderAndProof blockHeaderProof(headerProof, chainActive[confirmRoot.rootHeight]->GetBlockHeader());
                        evidence.evidence << blockHeaderProof;

                        // now prove any challenge proof related info from the notarization / root to confirm
                        curMMV.resize(confirmRoot.rootHeight + 1);
                    }

                    uint32_t startHeight = priorNotarization.IsValid() && priorNotarization.proofRoots.count(ASSETCHAINS_CHAINID) ?
                                                priorNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight :
                                                priorRoot.IsValid() ? priorRoot.rootHeight : 1;

                    uint32_t heightChange = futureRoot.rootHeight - startHeight;

                    int blocksPerCheckpoint = CPBaaSNotarization::GetBlocksPerCheckpoint(heightChange);

                    // unless we have another proof range sized chunk at the end, don't add another checkpoint
                    int numCheckPoints = CPBaaSNotarization::GetNumCheckpoints(heightChange);

                    // let any challengers know where we might diverge roots
                    for (int i = 1; i <= numCheckPoints; i++)
                    {
                        evidence.evidence << CProofRoot::GetProofRoot(startHeight + (i * blocksPerCheckpoint));
                    }

                    if (challengeProof.IsValid())
                    {
                        uint32_t rangeStart = startHeight;
                        int32_t rangeLen = futureRoot.rootHeight - rangeStart;

                        curMMV.resize(futureRoot.rootHeight + 1);

                        std::vector<__uint128_t> blockCommitmentsSmall = GetBlockCommitments(rangeStart, futureRoot.rootHeight, entropyHash);
                        if (!blockCommitmentsSmall.size())
                        {
                            oneRetObj.pushKV("error", "Cannot get block commitments for challenge");
                            break;
                        }
                        evidence.evidence << CHashCommitments(blockCommitmentsSmall);

                        std::vector<__uint128_t> checkSmallCommitments;
                        auto checkTypes = ((CChainObject<CHashCommitments> *)evidence.evidence.chainObjects.back())->object.GetSmallCommitments(checkSmallCommitments);
                        if (checkSmallCommitments != blockCommitmentsSmall)
                        {
                            LogPrintf("%s: ERROR - commitments evidence mismatch\n", __func__);
                        }

                        if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                        {
                            for (int currentOffset = 0; currentOffset < checkSmallCommitments.size(); currentOffset++)
                            {
                                LogPrintf("%s: reading small commitments\n", __func__);
                                auto commitmentVec = UnpackBlockCommitment(checkSmallCommitments[currentOffset]);
                                arith_uint256 powTarget, posTarget;
                                powTarget.SetCompact(commitmentVec[1]);
                                posTarget.SetCompact(commitmentVec[2]);
                                LogPrintf("nHeight: %u, nTime: %u, PoW target: %s, PoS target: %s, isPoS: %u\n",
                                            commitmentVec[3] >> 1,
                                            commitmentVec[0],
                                            powTarget.GetHex().c_str(),
                                            posTarget.GetHex().c_str(),
                                            commitmentVec[3] & 1);
                            }
                        }

                        int loopNum = std::min(std::max(rangeLen, (int)CPBaaSNotarization::EXPECT_MIN_HEADER_PROOFS),
                                              std::min((int)CPBaaSNotarization::MAX_HEADER_PROOFS_PER_PROOF, rangeLen / 10));

                        LogPrintf("oldval: %d, newval: %d\n", std::min(std::max(rangeLen / CPBaaSNotarization::NUM_HEADER_PROOF_RANGE_DIVISOR,
                                                                    (int)CPBaaSNotarization::EXPECT_MIN_HEADER_PROOFS),
                                                                    (int)CPBaaSNotarization::MAX_HEADER_PROOFS_PER_PROOF),
                                                           loopNum);

                        uint256 headerSelectionHash = entropyHash;
                        if (LogAcceptCategory("notarization"))
                        {
                            LogPrintf("%s: creating evidence with entropyHash: %s\n", __func__, entropyHash.GetHex().c_str());
                        }

                        int headerLoop;
                        int32_t headerProofsSize = 0;
                        for (headerLoop = 0; headerLoop < loopNum && headerProofsSize < CPBaaSNotarization::MAX_HEADER_PROOFS_SIZE; headerLoop++)
                        {
                            int indexToProve = (UintToArith256(headerSelectionHash).GetLow64() % rangeLen);
                            headerSelectionHash = ::GetHash(headerSelectionHash);
                            uint32_t blockToProve = rangeStart + indexToProve;
                            CMMRProof headerProof;
                            if (!chainActive.GetBlockProof(curMMV, headerProof, blockToProve))
                            {
                                oneRetObj.pushKV("error", "Cannot prove evidence for challenge");
                                break;
                            }
                            CBlockHeaderAndProof blockHeaderProof(headerProof, chainActive[blockToProve]->GetBlockHeader());

                            evidence.evidence << blockHeaderProof;
                            CDataStream ds(SER_DISK, PROTOCOL_VERSION);
                            headerProofsSize += GetSerializeSize(ds, *(CChainObject<CBlockHeaderAndProof> *)evidence.evidence.chainObjects.back());

                            if (blockHeaderProof.blockHeader.IsVerusPOSBlock())
                            {
                                CValidationState state;
                                if (!ProvePosBlock(rangeStart, chainActive[blockToProve], evidence, state, &headerProofsSize))
                                {
                                    oneRetObj.pushKV("error", "Cannot prove primary evidence for PoS block");
                                    break;
                                }
                            }
                        }
                        if (headerLoop < loopNum && headerProofsSize < CPBaaSNotarization::MAX_HEADER_PROOFS_SIZE)
                        {
                            break;
                        }
                    }

                    UniValue challengeUni(UniValue::VOBJ);
                    challengeUni.pushKV("type", EncodeDestination(CIdentityID(challengeTypeKey)));
                    challengeUni.pushKV("priornotarizationref", priorNotarizationRef.ToUniValue());
                    if (confirmNotarization.IsValid())
                    {
                        challengeUni.pushKV("confirmnotarizationref", confirmNotarizationRef.ToUniValue());
                    }
                    else
                    {
                        challengeUni.pushKV("confirmroot", confirmRoot.ToUniValue());
                    }
                    if (challengeProof.IsValid())
                    {
                        challengeUni.pushKV("challengeproof", challengeProof.ToUniValue());
                    }
                    challengeUni.pushKV("futureroot", futureRoot.ToUniValue());
                    challengeUni.pushKV("evidence", evidence.ToUniValue());
                    oneRetObj.pushKV("result", challengeUni);
                    break;
                }

                default:
                {
                    oneRetObj.pushKV("error", "Challenge request must be one of [{\"type\":\"skipchallenge\",...}, {\"type\":\"validitychallenge\",...}] JSON objects");
                    break;
                }
            }
            retVal[i] = oneRetObj;
        }
    }
    UniValue retValUni(UniValue::VARR);
    for (auto &oneResult : retVal)
    {
        retValUni.push_back(oneResult);
    }
    return retValUni;
}

UniValue submitchallenges(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "submitchallenges '[{\"type\":\"vrsc::evidence.skipchallenge\" || \"iCwxpRL6h3YeCRtGjgQSsqoKdZCuM4Dxaf\" ||\n"
            "                       \"type\":\"vrsc::evidence.validitychallenge\" || \"iCPb8ywQna7jYV2SHrGZ6vQMj7kuyWFxvb\",\n"
            "                    \"notarizationref\":{\"txid\":\"hexvalue\",\"voutnum\":n},\n"
            "                    \"forkroot\":{},\n"
            "                    \"challengeroot\":{},\n"
            "                    \"evidence\":{}},\n"
            "                   {...}, ...]'\n"

            "\nSubmits one or more cryptographic challenges to existing, unconfirmed notarizations, proving the existence\n"
            "of an alternate chain. Whether the alternate chain has more power than the chain with a pending notarization\n"
            "is not required, only that it has moved forward multiple blocks since the prior notarization.\n"

            "\nRequires that the local wallet have funds for fees.\n"

            "\nArguments\n"
            "\"challenges\"                 (array, required) one or more challenges to unconfirmed notarizations on this system\n"

            "\nResult:\n"
            "[{\"txid\":\"hex\"}, {\"error\":\"errorstring\"}, ...]   (array) results of submitted challenge transactions\n"

            "\nExamples:\n"
            + HelpExampleCli("submitchallenges", "'[{\"notarizationref\":{\"txid\":\"hexvalue\",\"voutnum\":n},\"challengeroot\":{},\"evidence\":{}}]'")
            + HelpExampleRpc("submitchallenges", "[{\"notarizationref\":{\"txid\":\"hexvalue\",\"voutnum\":n},\"challengeroot\":{},\"evidence\":{}}]")
        );
    }

    CheckPBaaSAPIsValid();

    std::vector<UniValue> retVal;

    if (params[0].isArray() && params[0].size())
    {
        retVal.resize(params[0].size());

        std::map<uint160, std::map<CUTXORef, std::tuple<int, CProofRoot, CProofRoot, CNotaryEvidence>>> challengeMap;

        LOCK2(cs_main, mempool.cs);
        uint32_t nHeight = chainActive.Height();

        for (int i = 0; i < params[0].size(); i++)
        {
            UniValue objRet(UniValue::VOBJ);

            CUTXORef notarizationRef = CUTXORef(find_value(params[0][i], "notarizationref"));
            CProofRoot forkRoot = CProofRoot(find_value(params[0][i], "forkroot"));
            CProofRoot challengeRoot = CProofRoot(find_value(params[0][i], "challengeroot"));
            CNotaryEvidence evidence = CNotaryEvidence(find_value(params[0][i], "evidence"));
            bool skipChallenge = !forkRoot.IsValid();
            if (notarizationRef.IsValid() &&
                challengeRoot.IsValid() &&
                evidence.IsValid())
            {
                if (!forkRoot.IsValid() ||
                    (forkRoot.IsValid() &&
                     (challengeRoot.rootHeight - forkRoot.rootHeight) > CPBaaSNotarization::EXPECT_MIN_HEADER_PROOFS &&
                     forkRoot.systemID == challengeRoot.systemID))
                {
                    challengeMap[challengeRoot.systemID].insert(
                        std::make_pair(notarizationRef, std::make_tuple(i, forkRoot, challengeRoot, evidence)));
                }
                else
                {
                    objRet.pushKV("error", "Invalid challenge entry 1");
                    retVal[i] = objRet;
                }
            }
            else
            {
                objRet.pushKV("error", "Invalid challenge entry 2");
                retVal[i] = objRet;
            }
        }

        for (auto &oneSystemChallenges : challengeMap)
        {
            UniValue objRet(UniValue::VOBJ);
            if (!oneSystemChallenges.second.size())
            {
                continue;
            }
            CChainNotarizationData currentCND;
            std::map<CUTXORef, int> currentNotarizationMap;
            std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>>> counterEvidence;
            std::map<std::pair<CUTXORef, CProofRoot>, std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>> preexistingChallenges;

            if (!GetNotarizationData(oneSystemChallenges.first, currentCND, nullptr, &counterEvidence) ||
                !currentCND.vtx.size())
            {
                objRet.pushKV("error", "Cannot load notarization data for system (" + EncodeDestination(CIdentityID(oneSystemChallenges.first)) + ").");
                for (auto &oneEntry : oneSystemChallenges.second)
                {
                    retVal[std::get<0>(oneEntry.second)] = objRet;
                }
                continue;
            }
            for (int j = 0; j < currentCND.vtx.size(); j++)
            {
                currentNotarizationMap.insert(std::make_pair(currentCND.vtx[j].first, j));
            }
            for (auto &oneCounterSet : counterEvidence)
            {
                for (auto &oneCounterEvidence : oneCounterSet)
                {
                    preexistingChallenges.insert({{std::get<1>(oneCounterEvidence).output, std::get<2>(oneCounterEvidence)}, oneCounterEvidence});
                }
            }

            CCurrencyDefinition challengeDef = ConnectedChains.GetCachedCurrency(oneSystemChallenges.first);

            CCcontract_info CC;
            CCcontract_info *cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            std::vector<CTxDestination> dests({DecodeDestination(cp->unspendableCCaddr)});
            for (auto &oneChallenge : oneSystemChallenges.second)
            {
                objRet = UniValue(UniValue::VOBJ);

                // if we have a valid counter-evidence challenge of this notarization with the same proof root,
                // we will only submit a stronger challenge if we have one
                // multiple, weaker challenges have no material effect in the current protocol and cost fees
                if (preexistingChallenges.count(std::make_pair(oneChallenge.first, std::get<2>(oneChallenge.second))))
                {
                    CProofRoot mostPowerfulRoot;
                    CProofRoot earliestChallenge;
                    bool invalidates = false;
                    for (auto &oneChallengeVec : counterEvidence)
                    {
                        for (auto &oneChallenge : oneChallengeVec)
                        {
                            if (std::get<0>(oneChallenge).Invalidates())
                            {
                                invalidates = true;
                            }
                            else
                            {

                            }
                            if (std::get<0>(oneChallenge).IsMorePowerful())
                            {

                            }
                        }
                    }



                    objRet.pushKV("error", "Duplicate");
                    retVal[std::get<0>(oneChallenge.second)] = objRet;
                    continue;
                }

                // we now have a confirmed, new counter evidence challenge and all we need to make a challenge tx
                bool invalidates = false;
                CObjectFinalization of(CObjectFinalization::FINALIZE_NOTARIZATION,
                                       oneSystemChallenges.first,
                                       std::get<3>(oneChallenge.second).output.hash,
                                       std::get<3>(oneChallenge.second).output.n);

                CTransaction outTx;
                uint256 blockHash;
                CCurrencyDefinition notarizingCurrency;
                CPBaaSNotarization challengedNotarization;
                CProofRoot challengeRoot;
                if (std::get<3>(oneChallenge.second).output.GetOutputTransaction(outTx, blockHash) &&
                    outTx.vout.size() > std::get<3>(oneChallenge.second).output.n &&
                    (challengedNotarization = CPBaaSNotarization(outTx.vout[std::get<3>(oneChallenge.second).output.n].scriptPubKey)).IsValid() &&
                    challengedNotarization.proofRoots.count(std::get<2>(oneChallenge.second).systemID) &&
                    std::get<2>(oneChallenge.second).systemID != ASSETCHAINS_CHAINID &&
                    (notarizingCurrency = ConnectedChains.GetCachedCurrency(std::get<2>(oneChallenge.second).systemID)).IsValid() &&
                    notarizingCurrency.IsPBaaSChain())
                {
                    // determine if our challenge is more powerful and set the flag if so
                    challengeRoot = IsValidChallengeEvidence(challengeDef,
                                                             challengedNotarization.proofRoots[std::get<2>(oneChallenge.second).systemID],
                                                             std::get<3>(oneChallenge.second),
                                                             blockHash,
                                                             invalidates,
                                                             std::get<1>(oneChallenge.second),
                                                             nHeight + 1);
                    if (challengeRoot.IsValid())
                    {
                        of.SetChallenge();
                        if (invalidates)
                        {
                            of.SetInvalidates();
                        }
                        if (challengeRoot != challengedNotarization.proofRoots[std::get<2>(oneChallenge.second).systemID] &&
                            CChainPower::ExpandCompactPower(challengeRoot.compactPower) >
                                CChainPower::ExpandCompactPower(challengedNotarization.proofRoots[std::get<2>(oneChallenge.second).systemID].compactPower))
                        {
                            of.SetMorePowerful();
                        }
                    }
                }

                // get the notarization we refer to
                if (!challengedNotarization.IsValid() ||
                    !challengedNotarization.proofRoots.count(oneSystemChallenges.first))
                {
                    objRet.pushKV("error", "Invalid or inaccessible output transaction 2");
                    retVal[std::get<0>(oneChallenge.second)] = objRet;
                    continue;
                }

                TransactionBuilder tb(Params().GetConsensus(), nHeight, pwalletMain);

                // if it's a skip challenge, finalize the notarization as rejected
                if (!std::get<1>(oneChallenge.second).IsValid())
                {
                    if (!invalidates)
                    {
                        objRet.pushKV("error", "Invalid skip challenge");
                        retVal[std::get<0>(oneChallenge.second)] = objRet;
                        continue;
                    }
                    of.SetRejected();

                    // get block height to get pending evidence since
                    std::vector<std::pair<bool, CProofRoot>> validCounterRoots;
                    CProofRoot challengeStartRoot;
                    std::vector<CInputDescriptor> outputs;
                    CValidationState state;
                    if (of.GetPendingEvidence(challengeDef,
                                              std::get<3>(oneChallenge.second).output,
                                              nHeight,
                                              validCounterRoots,
                                              challengeStartRoot,
                                              outputs,
                                              invalidates,
                                              state))
                    {
                        for (auto &oneInput : outputs)
                        {
                            of.evidenceInputs.push_back(tb.mtx.vin.size());
                            tb.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
                        }
                        std::vector<std::pair<uint32_t, CInputDescriptor>> unspentEvidence = of.GetUnspentEvidence(oneSystemChallenges.first,
                                                                                                    std::get<3>(oneChallenge.second).output.hash,
                                                                                                    std::get<3>(oneChallenge.second).output.n);
                        for (auto &oneInput : unspentEvidence)
                        {
                            tb.AddTransparentInput(oneInput.second.txIn.prevout, oneInput.second.scriptPubKey, oneInput.second.nValue);
                        }
                    }
                }

                CScript evidenceScript = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &std::get<3>(oneChallenge.second)));
                COptCCParams chkP;

                // the value should be considered for reduction
                if (evidenceScript.IsPayToCryptoCondition(chkP, false) &&
                    chkP.IsValid() &&
                    chkP.AsVector().size() >= CScript::MAX_SCRIPT_ELEMENT_SIZE)
                {
                    int baseOverhead = (evidenceScript.size() - ::AsVector(std::get<3>(oneChallenge.second)).size()) + 128;
                    auto evidenceVec = std::get<3>(oneChallenge.second).BreakApart(CScript::MAX_SCRIPT_ELEMENT_SIZE - baseOverhead);
                    if (!evidenceVec.size())
                    {
                        objRet.pushKV("error", "Unable to break apart evidence");
                        retVal[std::get<0>(oneChallenge.second)] = objRet;
                        continue;
                    }
                    for (auto &oneProof : evidenceVec)
                    {
                        of.evidenceOutputs.push_back(tb.mtx.vout.size());
                        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &oneProof)), 0);
                    }
                }
                else if (!chkP.IsValid())
                {
                    objRet.pushKV("error", "Invalid evidence");
                    retVal[std::get<0>(oneChallenge.second)] = objRet;
                    continue;
                }
                else
                {
                    of.evidenceOutputs.push_back(tb.mtx.vout.size());
                    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &std::get<3>(oneChallenge.second))), 0);
                }

                CCcontract_info *cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
                dests = std::vector<CTxDestination>({DecodeDestination(cp->unspendableCCaddr)});

                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &of)), 0);
                tb.SetFee(DEFAULT_TRANSACTION_FEE);

                TransactionBuilderResult preResult = tb.Build();
                CTransaction challengeTx = preResult.GetTxOrThrow();

                LOCK2(smartTransactionCS, mempool.cs);

                bool relayTx;
                CValidationState state;
                {
                    LOCK2(smartTransactionCS, mempool.cs);
                    relayTx = myAddtomempool(challengeTx, &state);
                }

                // add to mem pool and relay
                if (!relayTx)
                {
                    objRet.pushKV("error", "Unable to prepare challenge tx: " + state.GetRejectReason());
                    retVal[std::get<0>(oneChallenge.second)] = objRet;
                }
                else
                {
                    RelayTransaction(challengeTx);
                    objRet.pushKV("txid", challengeTx.GetHash().GetHex());
                    retVal[std::get<0>(oneChallenge.second)] = objRet;
                }
            }
        }
    }
    UniValue retValUni(UniValue::VARR);
    for (auto &oneResult : retVal)
    {
        retValUni.push_back(oneResult);
    }
    return retValUni;
}

bool FundTransparentTransactionBuilder(CWallet *pwallet, TransactionBuilder &tb, const CTxDestination *pFromDest=nullptr)
{
    std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
    std::vector<COutput> vCoins;
    CCurrencyValueMap totalReservesNeeded;
    CAmount nativeNeeded = 0;

    for (auto &oneOutput : tb.mtx.vout)
    {
        totalReservesNeeded += oneOutput.ReserveOutValue();
        nativeNeeded += oneOutput.nValue;
    }
    nativeNeeded += tb.GetFee();
    totalReservesNeeded += tb.GetReserveFee();

    totalReservesNeeded.valueMap.erase(ASSETCHAINS_CHAINID);
    CCurrencyValueMap totalCurrenciesNeeded = totalReservesNeeded;
    totalCurrenciesNeeded.valueMap[ASSETCHAINS_CHAINID] = nativeNeeded;

    pwallet->AvailableReserveCoins(vCoins,
                                    false,
                                    nullptr,
                                    true,
                                    true,
                                    pFromDest,
                                    &totalCurrenciesNeeded,
                                    false);

    for (COutput &out : vCoins)
    {
        std::vector<CTxDestination> addresses;
        int nRequired;
        bool canSign, canSpend;
        CTxDestination address;
        txnouttype txType;
        if (!ExtractDestinations(out.tx->vout[out.i].scriptPubKey, txType, addresses, nRequired, pwallet, &canSign, &canSpend))
        {
            continue;
        }

        // if we have more address destinations than just this address and have specified from a single ID only,
        // the condition must be such that the ID itself can spend, even if this wallet cannot due to a multisig
        // ID. if the ID cannot spend, even given a valid multisig ID, then to select this as a source without
        // an explicit, multisig match would cause potentially unwanted sourcing of funds. a spend just to this ID
        // is fine.

        COptCCParams p, m;
        // if we can't spend and can only sign,
        // ensure that this output is spendable by just this ID as a 1 of n and 1 of n at the master
        // smart transaction level as well
        if (!canSpend &&
            (!canSign ||
                !(out.tx->vout[out.i].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                (p.version < COptCCParams::VERSION_V3 ||
                (p.vData.size() &&
                    (m = COptCCParams(p.vData.back())).IsValid() &&
                    (m.m == 1 || m.m == 0))) &&
                p.m == 1)))
        {
            continue;
        }
        else
        {
            out.fSpendable = true;      // this may not really be spendable, but set it if its the correct ID source and can sign
        }
    }

    CCurrencyValueMap reservesUsed;
    CAmount nativeUsed;
    if (!pwallet->SelectReserveCoinsMinConf(totalReservesNeeded,
                                            nativeNeeded,
                                            0,
                                            1,
                                            vCoins,
                                            setCoinsRet,
                                            reservesUsed,
                                            nativeUsed))
    {
        CTxDestination _dest;
        if (!pFromDest)
        {
            pFromDest = &_dest;
        }
        LogPrintf("%s: ERROR FUNDING TRANSACTION: Insufficient funds held by %s\n", __func__, EncodeDestination(*pFromDest).c_str());
        return false;
    }

    for (auto &oneInput : setCoinsRet)
    {
        tb.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second),
                                                oneInput.first->vout[oneInput.second].scriptPubKey,
                                                oneInput.first->vout[oneInput.second].nValue);
    }
    return true;
}

UniValue submitacceptednotarization(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        throw runtime_error(
            "submitacceptednotarization \"{earnednotarization}\" \"{notaryevidence}\" sourceoffunds\n"
            "\nFinishes an almost complete notarization transaction based on the notary chain and the current wallet or pubkey.\n"
            "If successful in submitting the transaction based on all rules, a transaction ID is returned, otherwise, NULL.\n"

            "\nArguments\n"
            "\"earnednotarization\"             (object, required) notarization earned on the other system, which is the basis for this\n"
            "\"notaryevidence\"                 (object, required) evidence and notary signatures validating the notarization\n"
            "\"sourceoffunds\"                  (string, optional) any valid source of funds to enable privacy when notarizing multiple PBaaS chains\n"

            "\nResult:\n"
            "txid                               (hexstring) transaction ID of submitted transaction\n"

            "\nExamples:\n"
            + HelpExampleCli("submitacceptednotarization", "\"{earnednotarization}\" \"{notaryevidence}\" \"sourceoffunds\"")
            + HelpExampleRpc("submitacceptednotarization", "\"{earnednotarization}\" \"{notaryevidence}\" \"sourceoffunds\"")
        );
    }

    CheckPBaaSAPIsValid();

    uint32_t nHeight = chainActive.Height();

    // decode the transaction and ensure that it is formatted as expected
    CPBaaSNotarization pbn;
    CNotaryEvidence evidence;
    CCurrencyDefinition chainDef;
    int32_t chainDefHeight;

    CTxDestination fromDest;
    std::vector<COutput> vCoins;
    CCurrencyValueMap nativeCurrency = CCurrencyValueMap({ASSETCHAINS_CHAINID}, {CPBaaSNotarization::DEFAULT_NOTARIZATION_FEE});

    if (params.size() == 3)
    {
        fromDest = DecodeDestination(uni_get_str(params[2]));
        if (fromDest.which() != COptCCParams::ADDRTYPE_INVALID)
        {
            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->AvailableReserveCoins(vCoins, false, nullptr, true, true, &fromDest, &nativeCurrency, false);
        }
    }

    if (!vCoins.size())
    {
        fromDest = VERUS_NOTARYID;
        // if we have a valid notary address, see if it has funds
        if (fromDest.which() != COptCCParams::ADDRTYPE_INVALID)
        {
            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->AvailableReserveCoins(vCoins, false, nullptr, true, true, &fromDest, &nativeCurrency, false);
        }
    }

    if (!vCoins.size())
    {
        fromDest = VERUS_DEFAULTID;
        // if we have a valid notary address, see if it has funds
        if (fromDest.which() != COptCCParams::ADDRTYPE_INVALID)
        {
            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->AvailableReserveCoins(vCoins, false, nullptr, true, true, &fromDest, &nativeCurrency, false);
        }
    }

    if (!vCoins.size())
    {
        fromDest = DecodeDestination(GetArg("-mineraddress", ""));
        // if we have a valid notary address, see if it has funds
        if (fromDest.which() != COptCCParams::ADDRTYPE_INVALID)
        {
            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->AvailableReserveCoins(vCoins, false, nullptr, true, true, &fromDest, &nativeCurrency, false);
        }
        if (!vCoins.size())
        {
            fromDest = CTxDestination();
        }
    }

    if (fromDest.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        if (LogAcceptCategory("notarization"))
        {
            LogPrintf("No valid sourceoffunds for notarization transaction\n");
        }
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No valid sourceoffunds for accepted notarization transaction. Set \"-notaryid=id@\", \"-defaultid=id@\", or \"-mineraddress=addr\"");
    }

    /* CPBaaSNotarization checkPbn(params[0]);
    printf("%s: checknotarization before:\n%s\n", __func__, checkPbn.ToUniValue().write(1,2).c_str());
    checkPbn.SetMirror();
    printf("%s: checknotarization mirrored:\n%s\n", __func__, checkPbn.ToUniValue().write(1,2).c_str());
    checkPbn.SetMirror(false);
    printf("%s: checknotarization after:\n%s\n", __func__, checkPbn.ToUniValue().write(1,2).c_str()); */

    TransactionBuilder tb(Params().GetConsensus(), nHeight, pwalletMain);

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        LOCK(mempool.cs);
        if (!(pbn = CPBaaSNotarization(params[0])).IsValid() ||
            !pbn.SetMirror() ||
            !GetCurrencyDefinition(pbn.currencyID, chainDef, &chainDefHeight) ||
            chainDef.systemID == ASSETCHAINS_CHAINID ||
            !(chainDef.IsPBaaSChain() || chainDef.IsGateway()))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid earned notarization");
        }

        if (!(evidence = CNotaryEvidence(params[1])).IsValid() ||
            evidence.systemID != pbn.currencyID)
        {
            if (LogAcceptCategory("notarization"))
            {
                printf("%s: invalid evidence %s\nfrom param: %s\n", __func__, evidence.ToUniValue().write(1,2).c_str(), params[1].write(1,2).c_str());
                LogPrintf("%s: invalid evidence %s\nfrom param: %s\n", __func__, evidence.ToUniValue().write(1,2).c_str(), params[1].write(1,2).c_str());
            }
            throw JSONRPCError(RPC_INVALID_PARAMETER, "insufficient notarization evidence");
        }

        // flip back to normal earned notarization as before
        pbn.SetMirror(false);

        LogPrint("notarization", "%s: evidence: %s\n", __func__, evidence.ToUniValue().write(1,2).c_str());

        // now, make a new notarization based on this earned notarization, mirrored, so it reflects a notarization on this chain,
        // but can be verified with the cross-chain signatures and evidence

        CValidationState state;
        if (!pbn.CreateAcceptedNotarization(chainDef, pbn, evidence, state, tb, fromDest))
        {
            //printf("%s: unable to create accepted notarization: %s\n", __func__, state.GetRejectReason().c_str());
            throw JSONRPCError(RPC_INVALID_PARAMETER, state.GetRejectReason());
        }
        if (fromDest.which() == COptCCParams::ADDRTYPE_INVALID ||
            !FundTransparentTransactionBuilder(pwalletMain, tb, &fromDest))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to fund notarization transaction");
        }
        tb.SendChangeTo(fromDest);
    }

    // get the new notarization transaction
    std::vector<TransactionBuilderResult> buildResultVec;

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        buildResultVec.push_back(tb.Build());
    }
    auto buildResult = buildResultVec[0];
    CTransaction newTx;
    if (buildResult.IsTx())
    {
        newTx = buildResult.GetTxOrThrow();
    }
    else
    {
        if (LogAcceptCategory("notarization"))
        {
            UniValue jsonTx(UniValue::VOBJ);
            TxToUniv(tb.mtx, uint256(), jsonTx);
            LogPrintf("Failure to build and sign notarization transaction: %s\n", jsonTx.write(1,2).c_str());
        }
        LogPrintf("Accepted notarization build error: %s\n", buildResult.GetError().c_str());
        throw JSONRPCError(RPC_INVALID_PARAMETER, buildResult.GetError());
    }

    bool relayTx;
    {
        LOCK(cs_main);
        LOCK2(smartTransactionCS, mempool.cs);
        std::list<CTransaction> removed;
        mempool.removeConflicts(newTx, removed);
        // add to mem pool and relay
        relayTx = myAddtomempool(newTx);
    }

    // add to mem pool and relay
    if (relayTx)
    {
        RelayTransaction(newTx);
        return newTx.GetHash().GetHex();
    }

    if (LogAcceptCategory("notarization"))
    {
        UniValue jsonTx(UniValue::VOBJ);
        TxToUniv(tb.mtx, uint256(), jsonTx);
        LogPrint("notarization", "Failure to add notarization transaction to mempool: %s\n", jsonTx.write(1,2).c_str());
    }
    return NullUniValue;
}

// this must be called after all initial contributions are updated in the currency definition.
CCoinbaseCurrencyState GetInitialCurrencyState(const CCurrencyDefinition &chainDef)
{
    bool isFractional = chainDef.IsFractional();
    CCurrencyState cState;
    uint160 cID = chainDef.GetID();

    // calculate contributions and conversions
    const std::vector<CAmount> reserveFees(chainDef.currencies.size());
    std::vector<int64_t> conversions = chainDef.conversions;

    CAmount nativeFees = 0;
    if (isFractional)
    {
        cState = CCurrencyState(cID,
                                chainDef.currencies,
                                chainDef.weights,
                                std::vector<int64_t>(chainDef.currencies.size(), 0),
                                chainDef.initialFractionalSupply,
                                0,
                                chainDef.initialFractionalSupply,
                                CCurrencyState::FLAG_FRACTIONAL);
        conversions = cState.PricesInReserve();
    }
    else
    {
        cState.currencies = chainDef.currencies;
        cState.reserves = conversions;
        CAmount PreconvertedNative = cState.ReserveToNative(CCurrencyValueMap(chainDef.currencies, chainDef.preconverted));
        cState = CCurrencyState(cID,
                                chainDef.currencies,
                                std::vector<int32_t>(0),
                                conversions,
                                0,
                                PreconvertedNative,
                                PreconvertedNative);
    }

    CCoinbaseCurrencyState retVal(cState,
                                  0,
                                  0,
                                  0,
                                  std::vector<int64_t>(chainDef.currencies.size()),
                                  std::vector<int64_t>(chainDef.currencies.size()),
                                  std::vector<int64_t>(chainDef.currencies.size()),
                                  conversions,
                                  std::vector<int64_t>(chainDef.currencies.size()),
                                  reserveFees,
                                  reserveFees,
                                  0,
                                  std::vector<int32_t>(chainDef.currencies.size()));

    return retVal;
}

std::vector<CAddressUnspentDbEntry> GetFractionalNotarizationsForReserve(const uint160 &currencyID)
{
    std::vector<CAddressUnspentDbEntry> fractionalNotarizations;
    CIndexID indexKey = CCoinbaseCurrencyState::IndexConverterKey(currencyID);
    if (!GetAddressUnspent(indexKey, CScript::P2IDX, fractionalNotarizations))
    {
        LogPrintf("%s: Error reading unspent index\n", __func__);
    }
    return fractionalNotarizations;
}

// calculate the amount necessary for conversion, starting from the currency state & given a max slippage and price target to be less than or equal to
// if we can't meet slippage or target price, we return 0
CAmount GetNecessaryAmountForConversion(const CCurrencyDefinition &destSystem,
                                        const CCurrencyDefinition &destCurrency,
                                        const CCoinbaseCurrencyState &cbState,
                                        uint32_t destHeight,
                                        const uint160 &sourceID,
                                        const uint160 &destID,
                                        CAmount maxSlippage,
                                        CAmount maxPriceTarget,
                                        CAmount destAmount,
                                        CValidationState &state)
{
    CReserveTransfer rt(CReserveTransfer::VALID | CReserveTransfer::CONVERT,
                        CCurrencyValueMap(),
                        ASSETCHAINS_CHAINID,
                        CReserveTransfer::DEFAULT_PER_STEP_FEE << 1,
                        destID,
                        DestinationToTransferDestination(CIdentityID(ASSETCHAINS_CHAINID)));

    auto curMap = cbState.GetReserveMap();
    auto firstPrices = cbState.TargetConversionPrices(destID);
    auto reversePrices = cbState.TargetConversionPricesReverse(destID);

    // reverse our way to an estimated source,
    // which in almost all cases will be an incorrect starting point, but a starting point
    if (cbState.GetID() == destID)
    {
        if (!curMap.count(sourceID))
        {
            state.Error("Invalid converter is not equal to and does not contain source currency");
            return 0;
        }
    }
    else if (cbState.GetID() == sourceID)
    {
        if (!curMap.count(destID))
        {
            state.Error("Invalid converter is not equal to and does not contain destination currency");
            return 0;
        }
        rt.flags |= rt.IMPORT_TO_SOURCE;
    }
    else
    {
        if (!curMap.count(destID) || !curMap.count(sourceID))
        {
            state.Error("Invalid converter is not equal to and does not contain both source and destination currency");
            return 0;
        }
        rt.flags |= rt.RESERVE_TO_RESERVE;
        rt.destCurrencyID = cbState.GetID();
        rt.secondReserveID = destID;
    }
    rt.reserveValues.valueMap[sourceID] = cbState.ReserveToNativeRaw(destAmount, reversePrices.valueMap[sourceID]);

    std::vector<CReserveTransfer> exportObjects({rt});
    CAmount errorCorrection = 0;
    CAmount lastError = INT64_MAX;
    CAmount nextError = 0;

    int64_t firstPrice(firstPrices.valueMap[sourceID]);
    if (maxPriceTarget && firstPrice > maxPriceTarget)
    {
        state.Error("Price too high");
        return 0;
    }

    do
    {
        exportObjects.back().reserveValues.valueMap[sourceID] += nextError;

        // converge on the closest source value, assuming no failure on slippage or
        // price target, and return result, or fail and return 0
        CReserveTransactionDescriptor rtxd;
        std::vector<CTxOut> vOutputs;
        CCurrencyValueMap importedCurrency;
        CCurrencyValueMap gatewayDepositsIn;
        CCurrencyValueMap spentCurrencyOut;
        CCoinbaseCurrencyState newState;
        bool success = rtxd.AddReserveTransferImportOutputs(ConnectedChains.ThisChain(),
                                                            destSystem,
                                                            destCurrency,
                                                            cbState,
                                                            exportObjects,
                                                            destHeight,
                                                            vOutputs,
                                                            importedCurrency,
                                                            gatewayDepositsIn,
                                                            spentCurrencyOut,
                                                            &newState);
        if (!success || !vOutputs.size())
        {
            state.Error("Failure to convert with the latest currency state");
            return 0;
        }

        auto secondPrices = newState.TargetConversionPrices(destID, CCurrencyValueMap(newState.currencies, newState.conversionPrice), CCurrencyValueMap(newState.currencies, newState.viaConversionPrice));
        auto reversePrices = newState.TargetConversionPricesReverse(destID, CCurrencyValueMap(newState.currencies, newState.conversionPrice), CCurrencyValueMap(newState.currencies, newState.viaConversionPrice));

        // get slippage
        int64_t secondPrice(secondPrices.valueMap[sourceID]);

        int64_t difference = firstPrice - secondPrice;
        if (difference < 0)
        {
            difference = -difference;
        }
        else if (maxPriceTarget && secondPrice > maxPriceTarget)
        {
            state.Error("Price too high");
            return 0;
        }

        arith_uint256 bigDifference(difference);
        bigDifference = bigDifference * SATOSHIDEN;
        int64_t slippage = (bigDifference/firstPrice).GetLow64();
        if (maxSlippage && slippage > maxSlippage)
        {
            state.Error("Slippage too high");
            return 0;
        }

        // figure out how much was output in the destination currency, add an error, and loop if error is lower than last
        // get destination currency from the output
        CAmount startingInput = exportObjects.back().reserveValues.valueMap[sourceID];
        CAmount conversionFee = rtxd.CalculateConversionFeeNoMin(startingInput);
        if (exportObjects.back().IsReserveToReserve())
        {
            conversionFee = conversionFee << 1;
        }

        CAmount destCurAmount;

        if (exportObjects.back().IsImportToSource())
        {
            destCurAmount = newState.NativeToReserveRaw(startingInput - conversionFee, newState.conversionPrice[newState.GetReserveMap()[destID]]);
        }
        else
        {
            destCurAmount = newState.ReserveToNativeRaw(startingInput - conversionFee, newState.conversionPrice[newState.GetReserveMap()[sourceID]]);
            if (exportObjects.back().IsReserveToReserve())
            {
                destCurAmount = newState.NativeToReserveRaw(destCurAmount, newState.viaConversionPrice[newState.GetReserveMap()[destID]]);
            }
        }

        nextError = destAmount - destCurAmount;

        // if we have an error and it hasn't changed, we need to increment input by
        // one satoshi, as it's getting truncated away
        if (nextError > 0)
        {
            nextError = newState.ReserveToNativeRaw(nextError, reversePrices.valueMap[sourceID]);
            if (!nextError || nextError == lastError)
            {
                nextError++;
            }
            lastError = nextError;
        }
    } while (nextError > 0);

    return exportObjects.back().reserveValues.valueMap[sourceID];
}

UniValue getcurrencyconverters(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > CCurrencyState::MAX_RESERVE_CURRENCIES)
    {
        throw runtime_error(
            "getcurrencyconverters \"currency1\" \"currency2\" ... |\n"
            "                      '{\"convertto\":\"currencynameorid\",\"fromcurrency\":\"sourcecurrency\" | [{\"currency\":\"sourcecurrency1\", \"targetprice\":n}, ...],\n"
            "                       \"amount\":n, \"slippage\":0.01 (=1 percent slippage)}'\n"
            "\nRetrieves all currencies that will generally satisfy the request at or better than target price without other traffic and have all listed currencies as reserves\n"
            "\nArguments\n"
            "       \"currencyname\"                    : \"string\" ...  (string(s), one or more) all selected currencies are returned with their current state\n"
            "       \"paramobject\"                     : \"object\" ...  (one or more parameters) advanced query with slippage options\n"
            "       {\n"
            "           \"convertto\":\"destcurrency\"              \"string\" target currency\n"
            "           \"fromcurrency\":\"sourcecurrency\" | [...] \"string\" | object array ... (string(s), one or more) currencies to convert from\n"
            "           \"targetprice\":n | [n,...]                 \"number(s)\" ...       (number(s), one or more) target price within slippage required\n"
            "           \"amount\":n                                \"number\"              (number) amount of tocurrency needed\n"
            "           \"slippage\":n                              \"number\"              (number) max slippage with no other conversions max is 50000000 == 50%\n"
            "       }\n"

            "\nResult:\n"
            "       \"[{currency1}, {currency2}]\" : \"array of objects\" (string) All currencies, last currency state, and last amount to convert if amount specified\n"

            "\nExamples:\n"
            + HelpExampleCli("getcurrencyconverters", "'[\"currency1\",\"currency2\",...]'")
            + HelpExampleRpc("getcurrencyconverters", "'[\"currency1\",\"currency2\",...]'")
        );
    }

    CheckPBaaSAPIsValid();

    std::map<uint160, std::pair<CCurrencyDefinition, CAmount>> reserves;

    CCurrencyDefinition toCurrencyDef;
    uint160 toCurID;
    std::string toCurrency;
    std::vector<std::string> fromCurrency;

    int64_t amountTarget = 0;
    int64_t slippageTarget = 0;

    UniValue firstParam;

    if (params[0].isObject())
    {
        firstParam = params[0];
    }
    else
    {
        firstParam.read(uni_get_str(params[0]));
    }

    bool checkIntersect = false;

    // if we have object parameters, process them
    if (firstParam.isObject() &&
        !(toCurrency = uni_get_str(find_value(firstParam, "convertto"))).empty())
    {
        LOCK(cs_main);
        toCurID = ValidateCurrencyName(toCurrency, true, &toCurrencyDef);

        amountTarget = AmountFromValueNoErr(find_value(firstParam, "amount"));
        slippageTarget = AmountFromValueNoErr(find_value(firstParam, "slippage"));
        slippageTarget = std::max((int64_t)0, std::min((int64_t)50000000, slippageTarget));

        if (toCurID.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid tocurrency");
        }

        // assume an object specifying search, target and slippage parameters
        UniValue fromCurUni(UniValue::VOBJ);
        fromCurUni = find_value(firstParam, "fromcurrency");
        if (fromCurUni.isArray())
        {
            for (int i = 0; i < fromCurUni.size(); i++)
            {
                CAmount targetPrice = 0;
                UniValue fromOneCurrency;
                fromOneCurrency = fromCurUni[i];
                uint160 fromCurID;
                CCurrencyDefinition fromCurrencyDef;

                if (fromOneCurrency.isStr())
                {
                    fromCurrency.push_back(uni_get_str(fromOneCurrency));
                }
                else if (!fromOneCurrency.isObject())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMS, "fromcurrency must be an array of currency names or objects with currency name and target price");
                }
                else
                {
                    targetPrice = uni_get_int64(find_value(fromOneCurrency, "targetprice"));
                    fromCurrency.push_back(uni_get_str(find_value(fromOneCurrency, "currency")));
                }

                if (!fromCurrency.back().empty() && !(fromCurID = ValidateCurrencyName(fromCurrency.back(), true, &fromCurrencyDef)).IsNull())
                {
                    reserves.insert({fromCurID, {fromCurrencyDef, targetPrice}});
                }
                else
                {
                    throw JSONRPCError(RPC_INVALID_PARAMS, "fromcurrency must be a valid array of currency names or objects with currency name and target price");
                }
            }
        }
        else
        {
            fromCurrency.push_back(uni_get_str(fromCurUni));
            CCurrencyDefinition fromCurrencyDef;
            uint160 fromCurID;
            if (fromCurrency.back().empty() ||
                (fromCurID = ValidateCurrencyName(fromCurrency.back(), true, &fromCurrencyDef)).IsNull() ||
                reserves.count(fromCurID))
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Each from currency specified must be a valid, unique currency");
            }
            else
            {
                reserves.insert({fromCurID, {fromCurrencyDef, 0}});
            }
        }
    }
    else
    {
        checkIntersect = true;
        LOCK(cs_main);
        toCurrency = uni_get_str(params[0]);
        toCurID = ValidateCurrencyName(toCurrency, true, &toCurrencyDef);

        if (toCurID.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid first currency");
        }

        for (int i = 1; i < params.size(); i++)
        {
            std::string oneName = uni_get_str(params[i]);
            CCurrencyDefinition oneCurrency;
            uint160 oneCurrencyID;
            if (!oneName.size() ||
                (oneCurrencyID = ValidateCurrencyName(oneName, true, &oneCurrency)).IsNull() ||
                reserves.count(oneCurrencyID))
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Each reserve currency specified must be a valid, unique currency");
            }
            reserves[oneCurrencyID] = {oneCurrency, 0};
        }
    }

    // get all currencies that contain all specified reserves in our fractionalsFound set
    // use latest notarizations of the currencies to do so
    std::vector<CAddressUnspentDbEntry> activeFractionals;
    {
        LOCK(cs_main);
        activeFractionals = GetFractionalNotarizationsForReserve(toCurID);
    }
    std::set<int32_t> toRemove;
    if (activeFractionals.size() && reserves.size())
    {
        auto resIt = reserves.begin();
        for (int i = 0; i < activeFractionals.size(); i++)
        {
            CPBaaSNotarization pbn(activeFractionals[i].second.script);
            if (!pbn.IsValid())
            {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Cannot read currency notarization in transaction " + activeFractionals[i].first.txhash.GetHex());
            }
            if (!(pbn.currencyState.IsLaunchConfirmed() && pbn.currencyState.IsLaunchCompleteMarker()))
            {
                toRemove.insert(i);
            }
            else
            {
                auto curMap = pbn.currencyState.GetReserveMap();
                if (checkIntersect)
                {
                    for (auto it = resIt; it != reserves.end(); it++)
                    {
                        if (it->first != pbn.currencyState.GetID() && !curMap.count(it->first))
                        {
                            toRemove.insert(i);
                            break;
                        }
                    }
                }
                else
                {
                    bool foundReserve = false;
                    for (auto it = resIt; it != reserves.end(); it++)
                    {
                        if (it->first == pbn.currencyState.GetID() || curMap.count(it->first))
                        {
                            foundReserve = true;
                            break;
                        }
                    }
                    if (!foundReserve)
                    {
                        toRemove.insert(i);
                    }
                }
            }
        }
        for (auto oneIdx = toRemove.rbegin(); oneIdx != toRemove.rend(); oneIdx++)
        {
            activeFractionals.erase(activeFractionals.begin() + *oneIdx);
        }
    }

    CCoinbaseCurrencyState toState;
    {
        LOCK(cs_main);
        toState = ConnectedChains.GetCurrencyState(toCurID, chainActive.Height(), true);
    }
    if (toCurrencyDef.systemID == ASSETCHAINS_CHAINID && !(toState.IsValid() && toState.IsLaunchConfirmed()))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot get converters for pre-launch or refunded currency " + EncodeDestination(CIdentityID(toCurID)));
    }

    // converter currency, source currency checked, amount required to match conditions
    std::map<uint160, std::tuple<CCurrencyDefinition, CCoinbaseCurrencyState, std::map<uint160, CAmount>>> converterCurrencyOptions;

    // get latest notarizations for all currencies selected to ensure that we have
    // appropriate slippage

    // if toCurrency is fractional and contains all reserves to check, add it as well
    std::map<uint160, int32_t> toCurMap = toCurrencyDef.GetCurrenciesMap();
    if (toCurrencyDef.IsFractional() && toState.IsLaunchCompleteMarker())
    {
        bool addThis = true;
        for (auto oneReserve : reserves)
        {
            if (oneReserve.first != toCurID &&
                !toCurMap.count(oneReserve.first))
            {
                addThis = false;
                break;
            }
        }
        if (addThis)
        {
            converterCurrencyOptions[toCurID] = {toCurrencyDef, toState, std::map<uint160, CAmount>()};
        }
    }

    // if any reserve currency is fractional and contains tuCurrency and other reserves to check, add it as well
    for (auto &oneReserve : reserves)
    {
        LOCK(cs_main);
        if (oneReserve.second.first.IsFractional())
        {
            CCoinbaseCurrencyState oneState = ConnectedChains.GetCurrencyState(oneReserve.first, chainActive.Height(), true);
            if (!(oneState.IsValid() && oneState.IsLaunchConfirmed() && oneState.IsLaunchCompleteMarker()))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert pre-launch or refunded currency " + EncodeDestination(CIdentityID(toCurID)));
            }
            auto curMap = oneReserve.second.first.GetCurrenciesMap();
            bool addThis = curMap.count(toCurID);
            if (addThis)
            {
                if (checkIntersect)
                {
                    for (auto oneReserve : reserves)
                    {
                        if (oneReserve.first != toCurID &&
                            !curMap.count(oneReserve.first))
                        {
                            addThis = false;
                            break;
                        }
                    }
                }
                else
                {
                    addThis = false;
                    for (auto oneReserve : reserves)
                    {
                        if (oneReserve.first == toCurID || curMap.count(oneReserve.first))
                        {
                            addThis = true;
                            break;
                        }
                    }
                }
            }
            if (addThis)
            {
                converterCurrencyOptions[toCurID] = {toCurrencyDef, oneState, std::map<uint160, CAmount>()};
            }
        }
    }

    for (int i = 0; i < activeFractionals.size(); i++)
    {
        LOCK(cs_main);
        CPBaaSNotarization pbn(activeFractionals[i].second.script);
        CCurrencyDefinition oneCur;
        // if we already have it, move on
        if (converterCurrencyOptions.count(pbn.currencyID))
        {
            continue;
        }
        if (reserves.count(pbn.currencyID))
        {
            oneCur = reserves[pbn.currencyID].first;
        }
        else if (!GetCurrencyDefinition(pbn.currencyID, oneCur))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot get currency definition for currency " + EncodeDestination(CIdentityID(pbn.currencyID)));
        }

        CCoinbaseCurrencyState oneState = ConnectedChains.GetCurrencyState(pbn.currencyID, chainActive.Height(), true);
        if (!(oneState.IsValid() && oneState.IsLaunchConfirmed() && oneState.IsLaunchCompleteMarker()))
        {
            continue;
        }
        converterCurrencyOptions[pbn.currencyID] = {oneCur, oneState, std::map<uint160, CAmount>()};
    }

    // now, if we don't have any narrowing, return the converters we have with > 1000 native currency,
    // otherwise, confirm slippage on amount and other data
    std::set<uint160> removeIDs;
    if (reserves.size())
    {
        for (auto &oneConverter : converterCurrencyOptions)
        {
            LOCK(cs_main);
            // only include currencies on the current chain
            if (std::get<0>((oneConverter.second)).systemID != ASSETCHAINS_CHAINID)
            {
                removeIDs.insert(oneConverter.first);
                continue;
            }

            auto curMap = std::get<0>((oneConverter.second)).GetCurrenciesMap();

            for (auto &oneReserve : reserves)
            {
                if (!(slippageTarget || amountTarget))
                {
                    if (std::get<1>((oneConverter.second)).reserves[curMap[ASSETCHAINS_CHAINID]] < 100000000000)
                    {
                        removeIDs.insert(oneConverter.first);
                    }
                }
                // it may be the dest, the source, or contain both
                else
                {
                    // check slippage, amount, and optionally price from reserve to reserve currency
                    CCurrencyDefinition systemDest = ConnectedChains.GetCachedCurrency(std::get<0>(oneConverter.second).systemID);
                    if (!systemDest.IsValid())
                    {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Cannot find system ID for currency ");
                    }
                    CValidationState state;
                    CAmount necessaryAmount = GetNecessaryAmountForConversion(systemDest,
                                                                              std::get<0>(oneConverter.second),
                                                                              std::get<1>(oneConverter.second),
                                                                              chainActive.Height(),
                                                                              oneReserve.first,
                                                                              toCurID,
                                                                              slippageTarget,
                                                                              oneReserve.second.second,
                                                                              amountTarget,
                                                                              state);
                    if (necessaryAmount)
                    {
                        std::get<2>(oneConverter.second)[oneReserve.first] = necessaryAmount;
                    }
                }
            }
            // if we have no valid convert ability to meet targets and have not removed already, remove converter
            if ((slippageTarget || amountTarget) && !std::get<2>(oneConverter.second).size())
            {
                removeIDs.insert(oneConverter.first);
            }
        }
    }
    else
    {
        for (auto &oneConverter : converterCurrencyOptions)
        {
            auto curMap = std::get<0>((oneConverter.second)).GetCurrenciesMap();
            if (std::get<1>((oneConverter.second)).reserves[curMap[ASSETCHAINS_CHAINID]] < 100000000000)
            {
                removeIDs.insert(oneConverter.first);
            }
        }
    }
    for (auto &oneID : removeIDs)
    {
        converterCurrencyOptions.erase(oneID);
    }

    UniValue ret(UniValue::VARR);
    for (auto &oneConverter : converterCurrencyOptions)
    {
        UniValue oneCurrency(UniValue::VOBJ);
        oneCurrency.push_back(Pair(EncodeDestination(CIdentityID(std::get<0>(oneConverter.second).GetID())), std::get<0>(oneConverter.second).ToUniValue()));
        oneCurrency.pushKV("fullyqualifiedname", ConnectedChains.GetFriendlyCurrencyName(std::get<0>(oneConverter.second).GetID()));
        std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> lastNotarization = GetLastConfirmedNotarization(oneConverter.first, chainActive.Height());
        oneCurrency.push_back(Pair("height", int64_t(std::get<0>(lastNotarization))));
        oneCurrency.push_back(Pair("output", std::get<1>(lastNotarization).ToUniValue()));
        oneCurrency.push_back(Pair("lastnotarization", std::get<2>(lastNotarization).ToUniValue()));
        if (amountTarget)
        {
            oneCurrency.push_back(Pair("targetamount", ValueFromAmount(amountTarget)));
            UniValue sourceAmounts(UniValue::VOBJ);
            // if we have conversion sources and amounts, add them
            for (auto &oneConversion : std::get<2>(oneConverter.second))
            {
                sourceAmounts.pushKV(EncodeDestination(CIdentityID(oneConversion.first)), ValueFromAmount(oneConversion.second));
            }
            if (sourceAmounts.size())
            {
                oneCurrency.pushKV("sourceamounts", sourceAmounts);
            }
        }
        ret.push_back(oneCurrency);
    }
    return ret;
}

UniValue estimateconversion(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "estimateconversion '{\"currency\":\"name\",\"convertto\":\"name\",\"amount\":n} | [array of conversions using one basket]'\n"
            "\nThis estimates conversion from one currency to another, taking into account pending conversions, fees and slippage.\n"

            "\nArguments (may be one object or an array of such objects):\n"
            "1. {\n"
            "      \"currency\": \"name\"       (string, required)  Name of the source currency to send in this output, defaults to\n"
            "                                                       native of chain\n"
            "      \"amount\":amount            (numeric, required) The numeric amount of currency, denominated in source currency\n"
            "      \"convertto\":\"name\",      (string, optional)  Valid currency to convert to, either a reserve of a fractional, or fractional\n"
            "      \"preconvert\":\"false\",    (bool,  optional)   Convert to currency at market price (default=false), only works if\n"
            "                                                       transaction is mined before start of currency\n"
            "      \"via\":\"name\",            (string, optional)  If source and destination currency are reserves, via is a common fractional\n"
            "                                                       to convert through\n"
            "   }\n"

            "\nResult (if parameters were an array, the first four return values are returned 1:1 for objects passed in an array named \"conversions\"):\n"
            "   {\n"
            "      \"inputcurrencyid\": iaddress                    i-address of source currency\n"
            "      \"netinputamount\": value                        net amount in, after conversion fees in source currency\n"
            "      \"outputcurrencyid\": iaddress                   i-address of destination currency\n"
            "      \"estimatedcurrencyout\": value                  estimated amount out in destination currency\n"
            "      \"estimatedcurrencystate\": object               Estimation of all currency values, including prices and changes\n"
            "   }\n"

            "\nExamples:\n"
            + HelpExampleCli("estimateconversion", "'{\"currency\":\"name\",\"convertto\":\"name\",\"amount\":n}'")
            + HelpExampleRpc("estimateconversion", "'{\"currency\":\"name\",\"convertto\":\"name\",\"amount\":n}'")
        );
    }

    CheckPBaaSAPIsValid();

    if (!params[0].isArray() && !params[0].isObject())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "First parameter must be either a JSON object or array of objects.");
    }

    std::map<uint160, std::vector<CReserveTransfer>> currencyConversions;

    UniValue uniTransfers = params[0];
    if (uniTransfers.isObject())
    {
        uniTransfers = UniValue(UniValue::VARR);
        uniTransfers.push_back(params[0]);
    }

    CCurrencyDefinition fractionalCurrency;
    bool preConvert = false;

    UniValue retVal(UniValue::VOBJ);
    CCoinbaseCurrencyState currencyState;

    {
        LOCK(cs_main);
        uint32_t nHeight = chainActive.Height();

        for (int i = 0; i < uniTransfers.size(); i++)
        {
            bool isVerusActive = IsVerusActive();
            CCurrencyDefinition &thisChain = ConnectedChains.ThisChain();
            uint160 thisChainID = thisChain.GetID();
            bool toFractional = false;
            bool reserveToReserve = false;

            auto rawCurrencyStr = uni_get_str(find_value(uniTransfers[i], "currency"));
            auto currencyStr = TrimSpaces(rawCurrencyStr, true);
            CAmount sourceAmount = AmountFromValue(find_value(uniTransfers[i], "amount"));
            auto rawConvertToStr = uni_get_str(find_value(uniTransfers[i], "convertto"));
            auto convertToStr = TrimSpaces(rawConvertToStr, true);
            auto rawViaStr = uni_get_str(find_value(uniTransfers[i], "via"));
            auto viaStr = TrimSpaces(rawViaStr, true);

            bool tmpPreConvert = uni_get_bool(find_value(uniTransfers[i], "preconvert"));
            if (currencyConversions.size() && tmpPreConvert != preConvert)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Estimated conversions cannot be a mixture of pre and normal conversions");
            }

            if (rawCurrencyStr != currencyStr ||
                rawConvertToStr != convertToStr ||
                rawViaStr != viaStr)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "all currency names used must be valid with no leading or trailing spaces");
            }


            CCurrencyDefinition sourceCurrencyDef;
            uint160 sourceCurrencyID;
            if (currencyStr != "")
            {
                sourceCurrencyID = ValidateCurrencyName(currencyStr, true, &sourceCurrencyDef);
                if (sourceCurrencyID.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "If source currency is specified, it must be valid.");
                }
            }
            else
            {
                sourceCurrencyDef = thisChain;
                sourceCurrencyID = sourceCurrencyDef.GetID();
                currencyStr = thisChain.name;
            }

            CCurrencyDefinition convertToCurrencyDef;
            uint160 convertToCurrencyID;

            if (convertToStr == "")
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Must specify a \"convertto\" currency for conversion estimation");
            }
            else
            {
                convertToCurrencyID = ValidateCurrencyName(convertToStr, true, &convertToCurrencyDef);
                if (convertToCurrencyID == sourceCurrencyID)
                {
                    convertToCurrencyID.SetNull();
                    convertToCurrencyDef = CCurrencyDefinition();
                }
                else if (convertToCurrencyID.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid \"convertto\" currency " + convertToStr + " specified");
                }
            }

            CCurrencyDefinition secondCurrencyDef;
            uint160 secondCurrencyID;
            if (viaStr != "")
            {
                secondCurrencyID = ValidateCurrencyName(viaStr, true, &secondCurrencyDef);
                std::map<uint160, int32_t> viaIdxMap = secondCurrencyDef.GetCurrenciesMap();
                if (secondCurrencyID.IsNull() ||
                    sourceCurrencyID.IsNull() ||
                    convertToCurrencyID.IsNull() ||
                    secondCurrencyID == sourceCurrencyID ||
                    secondCurrencyID == convertToCurrencyID ||
                    sourceCurrencyID == convertToCurrencyID ||
                    !viaIdxMap.count(sourceCurrencyID) ||
                    !viaIdxMap.count(convertToCurrencyID))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "To specify a fractional currency converter, \"currency\" and \"convertto\" must both be reserves of \"via\"");
                }
                if (preConvert)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot combine reserve to reserve conversion with preconversion");
                }
                CCurrencyDefinition tempDef = convertToCurrencyDef;
                convertToCurrencyDef = secondCurrencyDef;
                secondCurrencyDef = tempDef;
                convertToCurrencyID = convertToCurrencyDef.GetID();
                secondCurrencyID = secondCurrencyDef.GetID();
            }

            // if this is reserve to reserve "via" another currency, ensure that both "from" and "to" are reserves of the "via" currency
            if (secondCurrencyDef.IsValid())
            {
                std::map<uint160, int32_t> checkMap = convertToCurrencyDef.GetCurrenciesMap();
                if (!checkMap.count(sourceCurrencyID) || !checkMap.count(secondCurrencyID))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "If \"via\" is specified, it must be a fractional currency with reserves of both source and \"convertto\" currency");
                }
                reserveToReserve = true;
                fractionalCurrency = convertToCurrencyDef;
            }
            else
            {
                // figure out if fractional to reserve, reserve to fractional, or error
                toFractional = convertToCurrencyDef.GetCurrenciesMap().count(sourceCurrencyID);

                if (toFractional)
                {
                    fractionalCurrency = convertToCurrencyDef;
                }
                else if (!sourceCurrencyDef.GetCurrenciesMap().count(convertToCurrencyID))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Source currency cannot be converted to destination");
                }
                else
                {
                    fractionalCurrency = sourceCurrencyDef;
                }
            }

            if (!fractionalCurrency.IsFractional() && (!preConvert || fractionalCurrency.startBlock <= nHeight))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, fractionalCurrency.name + " must be a fractional currency or prior to start block to estimate a conversion price");
            }

            uint32_t flags = CReserveTransfer::VALID;
            if (!convertToStr.empty())
            {
                flags += CReserveTransfer::CONVERT;
                if (preConvert)
                {
                    if (!secondCurrencyID.IsNull())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "cannot preconvert and also convert reserve to reserve");
                    }
                    flags += CReserveTransfer::PRECONVERT;
                }
                if (reserveToReserve)
                {
                    flags += CReserveTransfer::RESERVE_TO_RESERVE;
                }
                else if (!toFractional)
                {
                    flags += CReserveTransfer::IMPORT_TO_SOURCE;
                }
            }

            CReserveTransfer checkTransfer(flags,
                                        sourceCurrencyID,
                                        sourceAmount,
                                        ASSETCHAINS_CHAINID,
                                        ConnectedChains.ThisChain().GetTransactionTransferFee(),
                                        convertToCurrencyID,
                                        DestinationToTransferDestination(CKeyID(convertToCurrencyID)),
                                        secondCurrencyID);

            uint160 importCurrencyID = checkTransfer.GetImportCurrency();
            if (currencyConversions.size() && !currencyConversions.count(importCurrencyID))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "All conversions to estimate must be to, from, or via the same fractional currency");
            }
            currencyConversions[importCurrencyID].push_back(checkTransfer);
        }

        // now, get last notarization and all pending conversion transactions, calculate new conversions, including the new one to estimate and
        // return results
        CPBaaSNotarization notarization;
        uint160 fractionalCurrencyID = fractionalCurrency.GetID();

        CUTXORef lastUnspentUTXO;
        CTransaction lastUnspentTx;

        if (fractionalCurrency.systemID == ASSETCHAINS_CHAINID)
        {
            notarization.GetLastUnspentNotarization(fractionalCurrencyID,
                                                    lastUnspentUTXO.hash,
                                                    *((int32_t *)&lastUnspentUTXO.n),
                                                    &lastUnspentTx);
        }
        else
        {
            if (!preConvert || fractionalCurrency.launchSystemID != ASSETCHAINS_CHAINID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Can only estimate preconversions to currencies that will launch on the current chain");
            }
            CChainNotarizationData cnd;
            if (GetNotarizationData(fractionalCurrency.systemID, cnd))
            {
                notarization = cnd.vtx[cnd.forks[cnd.bestChain].back()].second;
            }
        }

        if (!notarization.IsValid())
        {
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Cannot find valid notarization for " + fractionalCurrency.name);
        }

        currencyState = ConnectedChains.AddPendingConversions(fractionalCurrency,
                                                                notarization,
                                                                notarization.notarizationHeight,
                                                                nHeight,
                                                                0,
                                                                currencyConversions.begin()->second);
    }

    if (!currencyState.IsValid())
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Cannot process conversion parameters for " + fractionalCurrency.name);
    }

    // if we have only an object parameter, return without an array
    if (params[0].isObject())
    {
        CReserveTransfer oneTransfer(currencyConversions.begin()->second.back());
        CAmount conversionFee = CReserveTransactionDescriptor::CalculateConversionFeeNoMin(oneTransfer.FirstValue());
        if (oneTransfer.IsReserveToReserve())
        {
            conversionFee = conversionFee << 1;
        }
        CAmount startingAmount = oneTransfer.FirstValue() - conversionFee;
        CAmount amountOut = 0;

        if (oneTransfer.IsImportToSource())
        {
            amountOut = currencyState.NativeToReserveRaw(startingAmount, currencyState.conversionPrice[currencyState.GetReserveMap()[oneTransfer.destCurrencyID]]);
        }
        else
        {
            amountOut = currencyState.ReserveToNativeRaw(startingAmount, currencyState.conversionPrice[currencyState.GetReserveMap()[oneTransfer.FirstCurrency()]]);
            if (oneTransfer.IsReserveToReserve())
            {
                amountOut = currencyState.NativeToReserveRaw(amountOut, currencyState.viaConversionPrice[currencyState.GetReserveMap()[oneTransfer.secondReserveID]]);
            }
        }

        retVal.pushKV("inputcurrencyid", EncodeDestination(CIdentityID(oneTransfer.FirstCurrency())));
        retVal.pushKV("netinputamount", ValueFromAmount(startingAmount));
        retVal.pushKV("outputcurrencyid", EncodeDestination(CIdentityID(oneTransfer.IsReserveToReserve() ? oneTransfer.secondReserveID : oneTransfer.destCurrencyID)));
        retVal.pushKV("estimatedcurrencyout", ValueFromAmount(amountOut));
    }
    else
    {
        UniValue retArr(UniValue::VARR);
        for (auto &oneTransfer : currencyConversions.begin()->second)
        {
            UniValue retObj(UniValue::VOBJ);
            CAmount conversionFee = CReserveTransactionDescriptor::CalculateConversionFeeNoMin(oneTransfer.FirstValue());
            if (oneTransfer.IsReserveToReserve())
            {
                conversionFee = conversionFee << 1;
            }
            CAmount startingAmount = oneTransfer.FirstValue() - conversionFee;
            CAmount amountOut = 0;

            if (oneTransfer.IsImportToSource())
            {
                amountOut = currencyState.NativeToReserveRaw(startingAmount, currencyState.conversionPrice[currencyState.GetReserveMap()[oneTransfer.destCurrencyID]]);
            }
            else
            {
                amountOut = currencyState.ReserveToNativeRaw(startingAmount, currencyState.conversionPrice[currencyState.GetReserveMap()[oneTransfer.FirstCurrency()]]);
                if (oneTransfer.IsReserveToReserve())
                {
                    amountOut = currencyState.NativeToReserveRaw(amountOut, currencyState.viaConversionPrice[currencyState.GetReserveMap()[oneTransfer.secondReserveID]]);
                }
            }

            retObj.pushKV("inputcurrencyid", EncodeDestination(CIdentityID(oneTransfer.FirstCurrency())));
            retObj.pushKV("netinputamount", ValueFromAmount(startingAmount));
            retObj.pushKV("outputcurrencyid", EncodeDestination(CIdentityID(oneTransfer.IsReserveToReserve() ? oneTransfer.secondReserveID : oneTransfer.destCurrencyID)));
            retObj.pushKV("estimatedcurrencyout", ValueFromAmount(amountOut));
            retArr.push_back(retObj);
        }
        retVal.pushKV("conversions", retArr);
    }

    retVal.pushKV("estimatedcurrencystate", currencyState.ToUniValue());
    return retVal;
}

bool find_utxos(const CTxDestination &fromtaddr_, std::vector<COutput> &t_inputs_)
{
    std::set<CTxDestination> destinations;

    bool wildCardPKH = false;
    bool wildCardID = false;
    bool isFromSpecificID = fromtaddr_.which() == COptCCParams::ADDRTYPE_ID && !GetDestinationID(fromtaddr_).IsNull();

    // if no specific address type, wildcard outputs to all transparent addresses and IDs are valid to consider
    if (fromtaddr_.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        wildCardPKH = true;
        wildCardID = true;
    }
    // wildcard for all transparent addresses, except IDs is null PKH
    else if (fromtaddr_.which() == COptCCParams::ADDRTYPE_PKH && GetDestinationID(fromtaddr_).IsNull())
    {
        wildCardPKH = true;
    }
    // wildcard for all ID transparent outputs is null ID
    else if (fromtaddr_.which() == COptCCParams::ADDRTYPE_ID && GetDestinationID(fromtaddr_).IsNull())
    {
        wildCardID = true;
    }
    else
    {
        destinations.insert(fromtaddr_);
    }

    vector<COutput> vecOutputs;

    pwalletMain->AvailableReserveCoins(vecOutputs,
                                       false,
                                       NULL,
                                       true,
                                       true,
                                       wildCardPKH || wildCardID ? nullptr : &fromtaddr_,
                                       nullptr,
                                       false,
                                       true);

    for (COutput& out : vecOutputs)
    {
        CTxDestination dest;

        if (!isFromSpecificID && !out.fSpendable) {
            continue;
        }

        if (out.nDepth < 0) {
            continue;
        }

        std::vector<CTxDestination> addresses;
        int nRequired;
        bool canSign, canSpend;
        CTxDestination address;
        txnouttype txType;
        if (!ExtractDestinations(out.tx->vout[out.i].scriptPubKey, txType, addresses, nRequired, pwalletMain, &canSign, &canSpend))
        {
            continue;
        }

        if (isFromSpecificID)
        {
            // if we have more address destinations than just this address and have specified from a single ID only,
            // the condition must be such that the ID itself can spend, even if this wallet cannot due to a multisig
            // ID. if the ID cannot spend, even given a valid multisig ID, then to select this as a source without
            // an explicit, multisig match would cause potentially unwanted sourcing of funds. a spend just to this ID
            // is fine.

            COptCCParams p, m;
            // if we can't spend and can only sign,
            // ensure that this output is spendable by just this ID as a 1 of n and 1 of n at the master
            // smart transaction level as well
            if (!canSpend &&
                (!canSign ||
                 !(out.tx->vout[out.i].scriptPubKey.IsPayToCryptoCondition(p) &&
                   p.IsValid() &&
                   (p.version < COptCCParams::VERSION_V3 ||
                    (p.vData.size() &&
                     (m = COptCCParams(p.vData.back())).IsValid() &&
                     (m.m == 1 || m.m == 0))) &&
                   p.m == 1)))
            {
                continue;
            }
            else
            {
                out.fSpendable = true;      // this may not really be spendable, but set it if its the correct ID source and can sign
            }
        }
        else
        {
            if (!out.fSpendable)
            {
                continue;
            }
        }

        bool keep = false;
        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
        for (auto &address : addresses)
        {
            if (isFromSpecificID)
            {
                if (address == fromtaddr_)
                {
                    keep = true;
                }
            }
            else if (wildCardID || wildCardPKH)
            {
                if (wildCardPKH)
                {
                    keep = (address.which() == COptCCParams::ADDRTYPE_PKH || address.which() == COptCCParams::ADDRTYPE_PK) &&
                            pwalletMain->HaveKey(GetDestinationID(address));
                }
                if (!keep && wildCardID)
                {
                    keep = address.which() == COptCCParams::ADDRTYPE_ID  &&
                           pwalletMain->GetIdentity(CIdentityID(GetDestinationID(address)), keyAndIdentity) &&
                           keyAndIdentity.first.CanSign();
                }
            }
            else
            {
                keep = destinations.count(address);
            }
            if (keep)
            {
                break;
            }
        }

        if (!keep)
        {
            continue;
        }

        t_inputs_.push_back(out);
    }

    // sort in ascending order, so smaller utxos appear first
    std::sort(t_inputs_.begin(), t_inputs_.end(), [](COutput i, COutput j) -> bool {
        return ( i.tx->vout[i.i].nValue < j.tx->vout[j.i].nValue );
    });

    return t_inputs_.size() > 0;
}

std::vector<SaplingNoteEntry> find_unspent_notes(const libzcash::PaymentAddress &fromaddress_)
{
    std::vector<SaplingNoteEntry> retVal;

    std::vector<SproutNoteEntry> sproutEntries;
    std::vector<SaplingNoteEntry> saplingEntries;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        pwalletMain->GetFilteredNotes(sproutEntries, saplingEntries, EncodePaymentAddress(fromaddress_));
    }

    sproutEntries.clear();

    for (auto entry : saplingEntries) {
        retVal.push_back(entry);
        if (LogAcceptCategory("zrpcunsafe"))
        {
            std::vector<unsigned char> rawData(entry.memo.begin(), entry.memo.end());
            UniValue memoUni = CIdentity::VDXFDataToUniValue(rawData);
            LogPrint("zrpcunsafe", "found unspent Sapling note (txid=%s, vShieldedSpend=%d, amount=%s, memo=%s)\n",
                     entry.op.hash.ToString().substr(0, 10).c_str(),
                     entry.op.n,
                     ValueFromAmount(entry.note.value()).write().c_str(),
                     memoUni.write(1,2).c_str());
        }
    }

    if (retVal.empty()) {
        return retVal;
    }

    // sort in descending order, so big notes appear first
    std::sort(retVal.begin(), retVal.end(),
        [](SaplingNoteEntry i, SaplingNoteEntry j) -> bool {
            return i.note.value() > j.note.value();
        });

    return retVal;
}

CAmount CalculateFractionalPrice(CAmount smallNumerator, CAmount smallDenominator, bool roundup)
{
    static arith_uint256 bigZero(0);
    static arith_uint256 BigSatoshi(SATOSHIDEN);
    static arith_uint256 BigSatoshiSquared = BigSatoshi * BigSatoshi;

    arith_uint256 denominator = smallDenominator * BigSatoshi;
    arith_uint256 numerator = smallNumerator * BigSatoshiSquared;
    arith_uint256 bigAnswer = numerator / denominator;
    int64_t remainder = (numerator - (bigAnswer * denominator)).GetLow64();
    CAmount answer = bigAnswer.GetLow64();
    if (remainder && roundup)
    {
        answer++;
    }
    return answer;
}
struct OfferInfo
{
public:
    CTransaction offerTx;
    CTransaction inputToOfferTx;
    uint256 blockHash;
};

// returns a map with the first boolean being the "unexpired" state. if 0, the offer is expired
bool GetMyOffers(std::map<std::pair<bool, uint256>, OfferInfo> &myOffers, uint32_t height, bool getUnexpired, bool getExpired)
{
    bool retVal = false;
    LOCK(pwalletMain->cs_wallet);
    for (auto &txPair : pwalletMain->mapWallet)
    {
        OfferInfo oneOfferInfo;
        if (txPair.second.IsInMainChain() &&
            txPair.second.vout.size() > 0 &&
            !pwalletMain->IsSpent(txPair.second.GetHash(), 0) &&
            GetOpRetChainOffer(txPair.second, oneOfferInfo.offerTx, oneOfferInfo.inputToOfferTx, height, getUnexpired, getExpired, oneOfferInfo.blockHash))
        {
            CSpentIndexKey spentKey = CSpentIndexKey(oneOfferInfo.inputToOfferTx.GetHash(), oneOfferInfo.offerTx.vin[0].prevout.n);
            CSpentIndexValue spentValue;
            if (!GetSpentIndex(spentKey, spentValue))
            {
                bool isExpired = (oneOfferInfo.offerTx.nExpiryHeight <= height);
                myOffers.insert(std::make_pair(std::make_pair(!isExpired, txPair.first), oneOfferInfo));
            }
            retVal = true;
        }
    }
    return retVal;
}

/** Pushes a JSON object for script verification or signing errors to vErrorsRet. */
void SigningErrorToJSON(const CTxIn& txin, UniValue& vErrorsRet, const std::string& strMessage)
{
    UniValue entry(UniValue::VOBJ);
    entry.push_back(Pair("txid", txin.prevout.hash.ToString()));
    entry.push_back(Pair("vout", (uint64_t)txin.prevout.n));
    entry.push_back(Pair("scriptSig", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    entry.push_back(Pair("sequence", (uint64_t)txin.nSequence));
    entry.push_back(Pair("error", strMessage));
    vErrorsRet.push_back(entry);
}

UniValue makeoffer(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
    {
        throw runtime_error(
            "makeoffer fromaddress '{\"changeaddress\":\"transparentoriaddress\", \"expiryheight\":blockheight, \"offer\":{\"currency\":\"anycurrency\", \"amount\":...} | {\"identity\":\"idnameoriaddress\",...}, \"for\":{\"address\":..., \"currency\":\"anycurrency\", \"amount\":...} | {\"name\":\"identityforswap\",\"parent\":\"parentid\",\"primaryaddresses\":[\"R-address(s)\"],\"minimumsignatures\":1,...}}' (returntx) (feeamount)\n"
            "\nThis sends a transaction which provides a completely decentralized, fully on-chain an atomic swap offer for\n"
            "\"decentralized swapping of any blockchain asset, including any/multi currencies, NFTs, identities, contractual\n"
            "\"agreements and rights transfers, or to be used as bids for an on-chain auction of any blockchain asset(s).\n"
            "\"Sources and destination of funds for swaps can be any valid transparent address capable of holding or controlling\n"
            "the specific asset.\n"

            "\nArguments\n"
            "1. \"fromaddress\"             (string, required) The VerusID, or wildcard address to send funds from. \"*\", \"R*\", or \"i*\" are valid wildcards\n"
            "2. {\n"
            "     \"changeaddress\"         (string, required) Change destination when constructing transactions\n"
            "     \"expiryheight\"          (number, optional) Block height at which this offer expires. Defaults to 20 blocks (avg 1/minute)\n"
            "     \"offer\"                 (object, required) Funds description or identity name, \"address\" in this object should be an address of the person making an offer for change\n"
            "     \"for\"                   (object, required) Funds description or full identity description\n"
            "   }\n"
            "3. \"returntx\"                (bool, optional) default = false, if true, returns a transaction waiting for taker completion instead of posting\n"
            "4. \"feeamount\"               (value, optional) default = 0.0001\n"

            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"transactionid\", The hex transaction id on success\n"
            "  \"hex\" : \"serializedtx\"   If hex is requested, hex serialization of partial transaction instead of txid is returned on success\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("makeoffer", "fromaddress '{\"changeaddress\":\"transparentoriaddress\", \"expiryheight\":blockheight, \"offer\":{\"currency\":\"anycurrency\", \"amount\":...} | {\"identity\":\"idnameoriaddress\",...}', \"for\":{\"address\":..., \"currency\":\"anycurrency\", \"amount\":...} | {\"name\":\"identityforswap\",\"parent\":\"parentid\",\"primaryaddresses\":[\"R-address(s)\"],\"minimumsignatures\":1,...}}' (returntx) (feeamount)")
            + HelpExampleRpc("makeoffer", "fromaddress '{\"changeaddress\":\"transparentoriaddress\", \"expiryheight\":blockheight, \"offer\":{\"currency\":\"anycurrency\", \"amount\":...} | {\"identity\":\"idnameoriaddress\",...}', \"for\":{\"address\":..., \"currency\":\"anycurrency\", \"amount\":...} | {\"name\":\"identityforswap\",\"parent\":\"parentid\",\"primaryaddresses\":[\"R-address(s)\"],\"minimumsignatures\":1,...}}' (returntx) (feeamount)")
        );
    }

    CheckVerusVaultAPIsValid();

    std::string sourceAddress = uni_get_str(params[0]);
    CTxDestination sourceDest;

    bool wildCardTransparentAddress = sourceAddress == "*";
    bool wildCardRAddress = sourceAddress == "R*";
    bool wildCardiAddress = sourceAddress == "i*";
    bool wildCardAddress = wildCardTransparentAddress || wildCardRAddress || wildCardiAddress;

    std::vector<CRecipient> outputs;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    libzcash::PaymentAddress zaddressSource;
    libzcash::SaplingExpandedSpendingKey expsk;
    uint256 sourceOvk;
    bool hasZSource = !wildCardAddress && pwalletMain->GetAndValidateSaplingZAddress(sourceAddress, zaddressSource, true);
    // if we have a z-address as a source, re-encode it to a string, which is used
    // by the async operation, to ensure that we don't need to lookup IDs in that operation
    if (hasZSource)
    {
        sourceAddress = EncodePaymentAddress(zaddressSource);
        // We don't need to lock on the wallet as spending key related methods are thread-safe
        if (!boost::apply_visitor(HaveSpendingKeyForPaymentAddress(pwalletMain), zaddressSource)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address, no spending key found for zaddr");
        }

        auto spendingkey_ = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), zaddressSource).get();
        auto sk = boost::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
        expsk = sk.expsk;
        sourceOvk = expsk.full_viewing_key().ovk;
    }

    if (!(hasZSource ||
          wildCardAddress ||
          (sourceDest = DecodeDestination(sourceAddress)).which() != COptCCParams::ADDRTYPE_INVALID))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. First parameter must be sapling address, transparent address, identity, \"*\", \"R*\", or \"i*\",. See help.");
    }

    CTxDestination from_taddress;
    if (wildCardTransparentAddress)
    {
        from_taddress = CTxDestination();
    }
    else if (wildCardRAddress)
    {
        from_taddress = CTxDestination(CKeyID(uint160()));
    }
    else if (wildCardiAddress)
    {
        from_taddress = CTxDestination(CIdentityID(uint160()));
    }
    else
    {
        from_taddress = sourceDest;
    }

    if (!params[1].isObject())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. Second parameter must be object. See help.");
    }

    bool returnHex = false;
    if (params.size() > 2)
    {
        returnHex = uni_get_bool(params[2], returnHex);
    }

    CAmount feeAmount = DEFAULT_TRANSACTION_FEE;
    if (params.size() > 3)
    {
        feeAmount = AmountFromValue(params[3]);
    }

    UniValue offerValue = find_value(params[1], "offer");
    UniValue forValue = find_value(params[1], "for");
    if (!offerValue.isObject() || !forValue.isObject())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Both \"offer\" and \"for\" must be valid objects in the first parameter object");
    }

    uint32_t height = chainActive.Height();

    CMutableTransaction offerTx = CreateNewContextualCMutableTransaction(Params().consensus, height + 1);
    uint32_t expiryHeight = uni_get_int(find_value(params[1], "expiryheight"));
    if (expiryHeight > offerTx.nExpiryHeight && expiryHeight < TX_EXPIRY_HEIGHT_THRESHOLD)
    {
        offerTx.nExpiryHeight = expiryHeight;
    }

    CInputDescriptor offerIn;
    std::vector<CInputDescriptor> postedOfferIns;
    CTxDestination changeDestination;
    CTxDestination fundsDestination;
    uint160 offerID;
    uint160 offerCurrencyID;
    CTxIn idTxIn;
    CIdentity oldID;
    uint32_t idHeight;
    uint160 newIDID;
    uint160 newCurrencyID;
    CTransaction preTx;

    bool hasZDest = false;
    libzcash::PaymentAddress zaddressDest;
    libzcash::SaplingPaymentAddress *saplingAddress;
    void *saplingOutputCtx = nullptr;

    auto changeAddressStr = TrimSpaces(uni_get_str(find_value(params[1], "changeaddress")));
    if (changeAddressStr.empty() || (changeDestination = ValidateDestination(changeAddressStr)).which() == COptCCParams::ADDRTYPE_INVALID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "changeaddress must be valid, transparent address, for privacy use fresh address");
    }

    if (find_value(forValue, "name").isNull())
    {
        if (!find_value(forValue, "identity").isNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "To buy an identity, define the identity by the \"for\" object as you would when registering, with \"name\", \"primaryaddresses\", etc. Do not use an \"identity\" tag");
        }

        auto rawCurrencyStr = uni_get_str(find_value(forValue, "currency"));
        auto currencyStr = TrimSpaces(rawCurrencyStr, true);
        if (rawCurrencyStr != currencyStr)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency name specified must be valid with no leading or trailing spaces");
        }

        CAmount destinationAmount = AmountFromValue(find_value(forValue, "amount"));
        auto memoStr = TrimSpaces(uni_get_str(find_value(forValue, "memo")));

        CCurrencyDefinition sourceCurrencyDef;
        if (currencyStr.empty())
        {
            sourceCurrencyDef = ConnectedChains.ThisChain();
            newCurrencyID = sourceCurrencyDef.GetID();
            currencyStr = EncodeDestination(CIdentityID(ConnectedChains.ThisChain().GetID()));
        }
        else
        {
            newCurrencyID = ValidateCurrencyName(currencyStr, true, &sourceCurrencyDef);
            if (newCurrencyID.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "If source currency is specified, it must be valid.");
            }
        }

        auto destStr = TrimSpaces(uni_get_str(find_value(forValue, "address")), true, "\\/*?\"<>|");

        fundsDestination = ValidateDestination(destStr);
        CTransferDestination dest;

        if (fundsDestination.which() == COptCCParams::ADDRTYPE_INVALID)
        {
            // make the funds output that defines what we are willing to accept for the input we are offering
            hasZDest = pwalletMain->GetAndValidateSaplingZAddress(destStr, zaddressDest, true);
            if (hasZDest)
            {
                saplingAddress = boost::get<libzcash::SaplingPaymentAddress>(&zaddressDest);
            }
            else
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Specified \"for\" destination address must be valid");
            }
            if (saplingAddress == nullptr)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Only sapling addresses may be used as a private \"for\" destination");
            }
        }
    }
    else
    {
        uint160 parentID = uint160(GetDestinationID(DecodeDestination(uni_get_str(find_value(forValue, "parent")))));
        if (parentID.IsNull() && (parentID = ValidateCurrencyName(uni_get_str(find_value(forValue, "parent")), true)).IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "To ensure reference to the correct identity, parent must be a valid, non-null value.");
        }

        CIdentity forID(forValue);
        if (!forID.IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "New ID definition of the ID for which offer is being made must be valid.");
        }

        std::string nameStr = CleanName(uni_get_str(find_value(forValue, "name")), parentID, true);
        newIDID = CIdentity::GetID(nameStr, parentID);
        if (newIDID.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + " specification is not valid -- " + (nameStr.empty() ? "must have valid name" : "maybe needs parent?"));
        }

        if (!(oldID = CIdentity::LookupIdentity(newIDID, 0, &idHeight, &idTxIn)).IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + " (" +EncodeDestination(CIdentityID(newIDID)) + "), not found ");
        }
    }

    bool isPartiallySignedTx = false;

    try
    {
        std:vector<COutput> vCoins;

        // first, construct the "offer" input, which will either be funds or an ID from this wallet
        if (find_value(offerValue, "identity").isNull())
        {
            auto rawCurrencyStr = uni_get_str(find_value(offerValue, "currency"));
            auto currencyStr = TrimSpaces(rawCurrencyStr, true);
            if (rawCurrencyStr != currencyStr)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency name specified in offer must be valid with no leading or trailing spaces");
            }
            CAmount sourceAmount = AmountFromValue(find_value(offerValue, "amount"));

            if (!sourceAmount)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "A currency offer must include a valid amount");
            }

            CCurrencyDefinition sourceCurrencyDef;
            uint160 sourceCurrencyID;
            if (currencyStr != "")
            {
                sourceCurrencyID = ValidateCurrencyName(currencyStr, true, &sourceCurrencyDef);
                if (sourceCurrencyID.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "If source currency is specified, it must be valid.");
                }
            }
            else
            {
                sourceCurrencyDef = ConnectedChains.ThisChain();
                sourceCurrencyID = sourceCurrencyDef.GetID();
                currencyStr = EncodeDestination(CIdentityID(ConnectedChains.ThisChain().GetID()));
            }

            offerCurrencyID = sourceCurrencyID;
            CRecipient oneOutput;

            if (sourceCurrencyID == ASSETCHAINS_CHAINID)
            {
                oneOutput.nAmount = sourceAmount;
                oneOutput.scriptPubKey = GetScriptForDestination(changeDestination);
            }
            else
            {
                oneOutput.nAmount = 0;

                std::vector<CTxDestination> dests = std::vector<CTxDestination>({changeDestination});
                CTokenOutput to(sourceCurrencyID, sourceAmount);

                oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &to));
            }

            bool success = false;
            std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
            std::vector<SaplingNoteEntry> saplingNotes;
            CCurrencyValueMap reserveValueOut;
            CAmount nativeValueOut;
            CAmount totalOriginationFees = feeAmount;
            if (!returnHex)
            {
                totalOriginationFees += feeAmount;
                // if we're posting, and it is not a native currency offer, add an extra fee
                // to enable closing the offer
                if (sourceCurrencyID != ASSETCHAINS_CHAINID)
                {
                    // add one more fee to enable auto-cancellation when offering non-native currencies
                    totalOriginationFees += feeAmount;
                }
            }

            // first make an input transaction to split the offer funds into an exact input and change, if needed
            if (sourceCurrencyID == ASSETCHAINS_CHAINID)
            {
                if (hasZSource)
                {
                    saplingNotes = find_unspent_notes(zaddressSource);
                    CAmount totalFound = 0;
                    int i;
                    for (i = 0; i < saplingNotes.size(); i++)
                    {
                        totalFound += saplingNotes[i].note.value();
                        if (totalFound >= (oneOutput.nAmount + totalOriginationFees))
                        {
                            break;
                        }
                    }
                    // remove all but the notes we'll use
                    if (i < saplingNotes.size())
                    {
                        saplingNotes.erase(saplingNotes.begin() + i + 1, saplingNotes.end());
                        success = true;
                    }
                }
                else
                {
                    success = find_utxos(from_taddress, vCoins) &&
                            pwalletMain->SelectCoinsMinConf(oneOutput.nAmount + totalOriginationFees, 0, 0, vCoins, setCoinsRet, nativeValueOut);
                }
            }
            else if (hasZSource)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot source non-native currencies from a private address");
            }
            else
            {
                success = find_utxos(from_taddress, vCoins);
                success = success && pwalletMain->SelectReserveCoinsMinConf(oneOutput.scriptPubKey.ReserveOutValue(),
                                                                            totalOriginationFees,
                                                                            0,
                                                                            1,
                                                                            vCoins,
                                                                            setCoinsRet,
                                                                            reserveValueOut,
                                                                            nativeValueOut);
            }
            if (!success)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Insufficient funds for offer");
            }

            // we need one output to create the proper index entry
            CKeyID offerIDKey = COnChainOffer::OnChainCurrencyOfferKey(offerCurrencyID);
            CKeyID forIDKey = newIDID.IsNull() ?
                COnChainOffer::OnChainOfferForCurrencyKey(newCurrencyID) :
                COnChainOffer::OnChainOfferForIdentityKey(newIDID);

            // use the transaction builder to properly make change of native and reserves
            TransactionBuilder tb(Params().consensus, height + 1, pwalletMain);

            CCommitmentHash ch;
            std::vector<CTxDestination> dests({changeDestination});
            std::vector<CTxDestination> masterKeyDest({forIDKey, offerIDKey});
            if (sourceCurrencyID == ASSETCHAINS_CHAINID)
            {
                CCommitmentHash commitment = CCommitmentHash(uint256());
                tb.AddTransparentOutput(MakeMofNCCScript(
                    CConditionObj<CCommitmentHash>(EVAL_IDENTITY_COMMITMENT, dests, 1, &commitment), returnHex ? nullptr : &masterKeyDest),
                    oneOutput.nAmount);
            }
            else
            {
                CCommitmentHash commitment = CCommitmentHash(uint256(), CTokenOutput(oneOutput.scriptPubKey.ReserveOutValue()));
                tb.AddTransparentOutput(MakeMofNCCScript(
                    CConditionObj<CCommitmentHash>(EVAL_IDENTITY_COMMITMENT, dests, 1, &commitment), returnHex ? nullptr : &masterKeyDest),
                    returnHex ? oneOutput.nAmount : oneOutput.nAmount + feeAmount);
            }

            // aggregate all inputs into one output with only the offer coins and offer indexes
            if (saplingNotes.size())
            {
                std::vector<SaplingOutPoint> notes;
                for (auto &oneNoteInfo : saplingNotes)
                {
                    notes.push_back(oneNoteInfo.op);
                }
                // Fetch Sapling anchor and witnesses
                uint256 anchor;
                std::vector<boost::optional<SaplingWitness>> witnesses;
                {
                    LOCK2(cs_main, pwalletMain->cs_wallet);
                    pwalletMain->GetSaplingNoteWitnesses(notes, witnesses, anchor);
                }

                // Add Sapling spends
                for (size_t i = 0; i < saplingNotes.size(); i++)
                {
                    tb.AddSaplingSpend(expsk, saplingNotes[i].note, anchor, witnesses[i].get());
                }
            }
            else
            {
                for (auto &oneInput : setCoinsRet)
                {
                    tb.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second),
                                            oneInput.first->vout[oneInput.second].scriptPubKey,
                                            oneInput.first->vout[oneInput.second].nValue);
                }
            }
            tb.SendChangeTo(changeDestination);
            tb.SendChangeTo(libzcash::SaplingPaymentAddress(), uint256());
            tb.SetFee(feeAmount);
            TransactionBuilderResult preResult = tb.Build();
            preTx = preResult.GetTxOrThrow();

            bool relayTx;
            CValidationState state;
            {
                LOCK2(smartTransactionCS, mempool.cs);
                relayTx = myAddtomempool(preTx, &state);
            }

            // add to mem pool and relay
            if (!relayTx)
            {
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Unable to prepare offer tx: " + state.GetRejectReason());
            }
            else
            {
                RelayTransaction(preTx);
            }

            offerIn = CInputDescriptor(preTx.vout[0].scriptPubKey, preTx.vout[0].nValue, CTxIn(preTx.GetHash(), 0));
            offerTx.vin.push_back(offerIn.txIn);

            if (!returnHex)
            {
                postedOfferIns.push_back(CInputDescriptor(preTx.vout[1].scriptPubKey, preTx.vout[1].nValue, CTxIn(preTx.GetHash(), 1)));
            }
        }
        else
        {
            CTxDestination idDest = DecodeDestination(uni_get_str(find_value(offerValue, "identity")));
            if (idDest.which() != COptCCParams::ADDRTYPE_ID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity parameter must be valid friendly name or i-address: \"" + uni_get_str(params[0]) + "\"");
            }
            CIdentityID idID = CIdentityID(GetDestinationID(idDest));
            // we must have the offer value ID in our wallet to offer it
            std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
            if (!pwalletMain->GetIdentity(idID, keyAndIdentity) && keyAndIdentity.first.CanSign())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "To offer an identity, this wallet must have signing authority over the identity offered");
            }

            if (keyAndIdentity.second.HasTokenizedControl())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "To offer an identity that has tokenized ID control, you must offer the token, which controls the identity, not the identity directly");
            }

            isPartiallySignedTx = !keyAndIdentity.first.CanSpend();
            if (!isPartiallySignedTx && keyAndIdentity.second.revocationAuthority != idID)
            {
                std::pair<CIdentityMapKey, CIdentityMapValue> checkSigKeyAndIdentity;
                if (!pwalletMain->GetIdentity(keyAndIdentity.second.revocationAuthority, checkSigKeyAndIdentity))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "To offer an identity directly, not through a control token, revocation authority must be defined on the current chain and will need to countersign the offer");
                }
                isPartiallySignedTx = !checkSigKeyAndIdentity.first.CanSpend();
            }
            if (!isPartiallySignedTx && keyAndIdentity.second.recoveryAuthority != idID)
            {
                std::pair<CIdentityMapKey, CIdentityMapValue> checkSigKeyAndIdentity;
                if (!pwalletMain->GetIdentity(keyAndIdentity.second.recoveryAuthority, checkSigKeyAndIdentity))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "To offer an identity directly, not through a control token, recovery authority must be defined on the current chain and will need to countersign the offer");
                }
                isPartiallySignedTx = !checkSigKeyAndIdentity.first.CanSpend();
            }

            offerID = idID;

            uint32_t idHeight;
            CTxIn idTxIn;
            CIdentity sourceIdentity = CIdentity::LookupIdentity(idID, 0, &idHeight, &idTxIn);
            if (!sourceIdentity.IsValid() && !idTxIn.prevout.hash.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot find identity to offer");
            }

            CTransaction idTx;
            uint256 blockHash;
            if (!myGetTransaction(idTxIn.prevout.hash, idTx, blockHash))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot find identity to offer");
            }

            if (returnHex)
            {
                offerIn.txIn = idTxIn;
                offerIn.nValue = idTx.vout[idTxIn.prevout.n].nValue;
                offerIn.scriptPubKey = idTx.vout[idTxIn.prevout.n].scriptPubKey;
                offerTx.vin.push_back(offerIn.txIn);
            }
            else
            {
                bool success;
                std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
                CCurrencyValueMap reserveValueOut;
                CAmount nativeValueOut;
                CAmount totalOriginationFees = feeAmount * 2;

                success = find_utxos(from_taddress, vCoins) &&
                            pwalletMain->SelectCoinsMinConf(totalOriginationFees, 0, 0, vCoins, setCoinsRet, nativeValueOut);

                // first make an input transaction to split the offer funds into an exact input and change, if needed
                if (!success)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Insufficient funds for posting offer for identity on chain");
                }

                // we need one output to create the proper index entry
                CKeyID offerIDKey = COnChainOffer::OnChainIdentityOfferKey(offerID);
                CKeyID forIDKey = newIDID.IsNull() ?
                    COnChainOffer::OnChainOfferForCurrencyKey(newCurrencyID) :
                    COnChainOffer::OnChainOfferForIdentityKey(newIDID);

                // use the transaction builder to properly make change of native and reserves
                TransactionBuilder tb(Params().consensus, height + 1, pwalletMain);

                CCommitmentHash ch;
                std::vector<CTxDestination> dests({changeDestination});
                std::vector<CTxDestination> indexDests({forIDKey, offerIDKey});

                tb.AddTransparentInput(COutPoint(idTxIn.prevout.hash, idTxIn.prevout.n), idTx.vout[idTxIn.prevout.n].scriptPubKey, idTx.vout[idTxIn.prevout.n].nValue);
                sourceIdentity.UpgradeVersion(height + 1);
                tb.AddTransparentOutput(sourceIdentity.IdentityUpdateOutputScript(height + 1, &indexDests), feeAmount);

                // aggregate all inputs into one output with only the offer coins and offer indexes
                for (auto &oneInput : setCoinsRet)
                {
                    tb.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second),
                                            oneInput.first->vout[oneInput.second].scriptPubKey,
                                            oneInput.first->vout[oneInput.second].nValue);
                }
                tb.SendChangeTo(changeDestination);
                tb.SendChangeTo(libzcash::SaplingPaymentAddress(), uint256());
                tb.SetFee(feeAmount);

                TransactionBuilderResult preResult = tb.Build(isPartiallySignedTx);

                if (isPartiallySignedTx && preResult.IsTx())
                {
                    // setup to throw a partially signed tx for revocation/recovery counter signature before adding to mempool
                    preTx = preResult.GetTxOrThrow();
                    preResult = TransactionBuilderResult(EncodeHexTx(preTx));
                }

                preTx = preResult.GetTxOrThrow();

                bool relayTx = false;
                CValidationState state;
                {
                    LOCK2(smartTransactionCS, mempool.cs);
                    relayTx = relayTx ? false : myAddtomempool(preTx, &state);
                }

                if (!relayTx)
                {
                    UniValue jsonTx(UniValue::VOBJ);
                    extern void TxToUniv(const CTransaction& tx, const uint256& hashBlock, UniValue& entry);
                    TxToUniv(preTx, uint256(), jsonTx);
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Unable to relay offer tx for identity: " + state.GetRejectReason() + "\n" + jsonTx.write(1,2));
                }
                else
                {
                    RelayTransaction(preTx);
                }

                offerIn = CInputDescriptor(preTx.vout[0].scriptPubKey, preTx.vout[0].nValue, CTxIn(preTx.GetHash(), 0));
                offerTx.vin.push_back(offerIn.txIn);

                postedOfferIns.push_back(CInputDescriptor(preTx.vout[1].scriptPubKey, preTx.vout[1].nValue, CTxIn(preTx.GetHash(), 1)));
            }
        }

        CRecipient requestOutput;

        // now we have made and added the offer input, make the output of what we want to exchange directed to us
        // then, sign the transaction, put it in an opreturn, and make the transaction that contains it
        if (find_value(forValue, "name").isNull())
        {
            auto rawCurrencyStr = uni_get_str(find_value(forValue, "currency"));
            auto currencyStr = TrimSpaces(rawCurrencyStr, true);
            if (rawCurrencyStr != currencyStr)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency name must be valid with no leading or trailing spaces");
            }
            CAmount destinationAmount = AmountFromValue(find_value(forValue, "amount"));
            auto memoUni = find_value(forValue, "memo");
            auto memoStr = TrimSpaces(uni_get_str(memoUni));

            if (hasZDest && newCurrencyID != ASSETCHAINS_CHAINID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot send non-native currency when sending proceeds to a private z-address");
            }
            if (!hasZDest && !memoStr.empty())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot include memo when sending proceeds to a transparent address or ID");
            }
            if (hasZDest)
            {
                requestOutput.nAmount = DEFAULT_TRANSACTION_FEE;
                requestOutput.scriptPubKey = GetScriptForDestination(changeDestination);

                // if memo starts with "#", convert it from a string to a hex value
                if (memoStr.size() > 1 && memoStr[0] == '#')
                {
                    // make a hex string out of the chars without the "#"
                    memoStr = HexBytes((const unsigned char *)&(memoStr[1]), memoStr.size());
                }
                if (!memoStr.empty())
                {
                    memoUni = memoStr;
                }

                auto memoVec = VectorEncodeVDXFUni(memoUni);

                if (memoVec.size() > ZC_MEMO_SIZE)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Memo data is too large, consider creating a data transaction first and referencing it");
                }

                std::array<unsigned char, ZC_MEMO_SIZE> hexMemo;

                for (int i = 0; i < ZC_MEMO_SIZE; i++)
                {
                    if (i < memoVec.size())
                    {
                        hexMemo[i] = memoVec[i];
                    }
                    else
                    {
                        hexMemo[i] = 0;
                    }
                }

                if (memoStr.length() > ZC_MEMO_SIZE*2) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,  strprintf("Size of memo is larger than maximum allowed %d", ZC_MEMO_SIZE));
                }
                else if (memoStr.length() > 0)
                {
                    hexMemo = AsyncRPCOperation_sendmany::get_memo_from_hex_string(memoStr);
                }

                // make the z-output
                uint256 ovk;
                HDSeed seed;
                if (!pwalletMain->GetHDSeed(seed)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "wallet seed unavailable for z-address output");
                }
                ovk = ovkForShieldingFromTaddr(seed);

                saplingOutputCtx = librustzcash_sapling_proving_ctx_init();
                auto note = libzcash::SaplingNote(*saplingAddress, destinationAmount);
                OutputDescriptionInfo output(ovk, note, hexMemo);
                offerTx.valueBalance -= destinationAmount;

                auto cm = output.note.cm();
                if (!cm) {
                    librustzcash_sapling_proving_ctx_free(saplingOutputCtx);
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "failed attempt to create private output");
                }

                libzcash::SaplingNotePlaintext notePlaintext(output.note, output.memo);

                auto res = notePlaintext.encrypt(output.note.pk_d);
                if (!res) {
                    librustzcash_sapling_proving_ctx_free(saplingOutputCtx);
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "failed to encrypt note with memo");
                }
                auto enc = res.get();
                auto encryptor = enc.second;

                OutputDescription odesc;
                if (!librustzcash_sapling_output_proof(
                        saplingOutputCtx,
                        encryptor.get_esk().begin(),
                        output.note.d.data(),
                        output.note.pk_d.begin(),
                        output.note.r.begin(),
                        output.note.value(),
                        odesc.cv.begin(),
                        odesc.zkproof.begin())) {
                    librustzcash_sapling_proving_ctx_free(saplingOutputCtx);
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "output proof failed");
                }

                odesc.cm = *cm;
                odesc.ephemeralKey = encryptor.get_epk();
                odesc.encCiphertext = enc.first;

                libzcash::SaplingOutgoingPlaintext outPlaintext(output.note.pk_d, encryptor.get_esk());
                odesc.outCiphertext = outPlaintext.encrypt(
                    output.ovk,
                    odesc.cv,
                    odesc.cm,
                    encryptor);
                offerTx.vShieldedOutput.push_back(odesc);
            }
            else
            {
                // make transparent output and complete transaction
                if (newCurrencyID == ASSETCHAINS_CHAINID)
                {
                    requestOutput.nAmount = destinationAmount;
                    requestOutput.scriptPubKey = GetScriptForDestination(fundsDestination);
                }
                else
                {
                    requestOutput.nAmount = newCurrencyID == ASSETCHAINS_CHAINID ? destinationAmount : 0;

                    std::vector<CTxDestination> dests = std::vector<CTxDestination>({fundsDestination});
                    CTokenOutput to(newCurrencyID, destinationAmount);

                    requestOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &to));
                }
            }
            offerTx.vout.push_back(CTxOut(requestOutput.nAmount, requestOutput.scriptPubKey));
        }
        else
        {
            // create the desired ID output, which the asset this exchange is making an offer for
            // to take the offer, a party in control of the identity defined by the output
            // must provide them on input to turn this into a valid transaction

            uint160 parentID = uint160(GetDestinationID(DecodeDestination(uni_get_str(find_value(forValue, "parent")))));

            if (parentID.IsNull() && (parentID = ValidateCurrencyName(uni_get_str(find_value(forValue, "parent")), true)).IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "To ensure reference to the correct identity, parent must be a correct, non-null value.");
            }
            std::string nameStr = CleanName(uni_get_str(find_value(forValue, "name")), parentID, true);
            newIDID = CIdentity::GetID(nameStr, parentID);
            if (newIDID.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + " specification is not valid -- " + (nameStr.empty() ? "must have valid name" : "maybe needs parent?"));
            }

            CTxIn idTxIn;
            CIdentity oldID;
            uint32_t idHeight;

            if (!(oldID = CIdentity::LookupIdentity(newIDID, 0, &idHeight, &idTxIn)).IsValid())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + " (" +EncodeDestination(CIdentityID(newIDID)) + "), not found ");
            }

            oldID.revocationAuthority = oldID.GetID();
            oldID.recoveryAuthority = oldID.GetID();
            oldID.privateAddresses.clear();
            oldID.primaryAddresses.clear();
            oldID.minSigs = 1;

            uint256 blkHash;
            CTransaction oldIdTx;
            if (!myGetTransaction(idTxIn.prevout.hash, oldIdTx, blkHash))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + ", transaction not found ");
            }

            auto uniOldID = UniObjectToMap(oldID.ToUniValue());

            // overwrite old elements
            for (auto &oneEl : UniObjectToMap(forValue))
            {
                uniOldID[oneEl.first] = oneEl.second;
            }

            uint32_t solVersion = CConstVerusSolutionVector::GetVersionByHeight(height + 1);

            if (solVersion >= CActivationHeight::ACTIVATE_VERUSVAULT)
            {
                uniOldID["version"] = solVersion < CActivationHeight::ACTIVATE_PBAAS ? (int64_t)CIdentity::VERSION_VAULT : (int64_t)CIdentity::VERSION_PBAAS;
                if (oldID.nVersion < CIdentity::VERSION_VAULT)
                {
                    uniOldID["systemid"] = EncodeDestination(CIdentityID(parentID.IsNull() ? oldID.GetID() : parentID));
                }
            }

            UniValue newUniID = MapToUniObject(uniOldID);
            CIdentity newID(newUniID);

            if (!newID.IsValid(true))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid JSON ID parameter");
            }

            // make sure we have a revocation and recovery authority defined
            CIdentity revocationAuth = newID.revocationAuthority == newIDID ? newID : newID.LookupIdentity(newID.revocationAuthority);
            CIdentity recoveryAuth = newID.recoveryAuthority == newIDID ? newID : newID.LookupIdentity(newID.recoveryAuthority);

            if (!revocationAuth.IsValid() || !recoveryAuth.IsValid())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid revocation or recovery authority specified");
            }

            if (!recoveryAuth.IsValidUnrevoked() || !revocationAuth.IsValidUnrevoked())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or revoked recovery, or revocation identity.");
            }

            if (oldID.IsLocked() != newID.IsLocked())
            {
                bool newLocked = newID.IsLocked();
                uint32_t unlockAfter = newID.unlockAfter;
                newID.flags = (newID.flags & ~newID.FLAG_LOCKED) | (newID.IsRevoked() ? 0 : (oldID.flags & oldID.FLAG_LOCKED));
                newID.unlockAfter = oldID.unlockAfter;

                if (!newLocked)
                {
                    newID.Unlock(height + 1, offerTx.nExpiryHeight);
                }
                else
                {
                    newID.Lock(unlockAfter);
                }
            }

            newID.UpgradeVersion(height + 1);
            offerTx.vout.push_back(CTxOut(0, newID.IdentityUpdateOutputScript(height + 1)));
        }

        // now, the offer tx is complete, and we need to sign its input with SIGHASH_SINGLE
        auto consensusBranchId = CurrentEpochBranchId(height, Params().consensus);

        bool showOffer = false;
        if (showOffer)
        {
            CValidationState state;
            UniValue jsonTx(UniValue::VOBJ);
            extern void TxToUniv(const CTransaction& tx, const uint256& hashBlock, UniValue& entry);
            TxToUniv(preTx, uint256(), jsonTx);
            printf("Offer transaction being posted: %s\n", jsonTx.write(1,2).c_str());
        }

        if (offerTx.vShieldedOutput.size())
        {
            // has for SIGHASH_SINGLE | SIGHASH_ANYONECANPAY binding signature for
            // Sapling outputs. Final transaction must only include Sapling outputs, which
            // have a binding signature bound to the single input along with its output and a zero
            // amount. the zero amount allows us to generate and validate this hash without
            // the output script of the prior transaction output, which is bound and verified by the
            // hash signed on that input already
            uint256 dataToBeSigned;
            CScript scriptCode;
            try {
                dataToBeSigned = SignatureHash(scriptCode, offerTx, 0, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, 0, consensusBranchId);
            } catch (std::logic_error ex) {
                librustzcash_sapling_proving_ctx_free(saplingOutputCtx);
                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not construct signature hash");
            }

            librustzcash_sapling_binding_sig(
                saplingOutputCtx,
                offerTx.valueBalance,
                dataToBeSigned.begin(),
                offerTx.bindingSig.data());

            librustzcash_sapling_proving_ctx_free(saplingOutputCtx);
        }

        CTransaction txNewConst(offerTx);
        SignatureData sigdata;

        bool signSuccess = ProduceSignature(
            TransactionSignatureCreator(pwalletMain, &txNewConst, 0, offerIn.nValue, offerIn.scriptPubKey, height + 1, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY), offerIn.scriptPubKey, sigdata, consensusBranchId);

        if (signSuccess || sigdata.scriptSig.size())
        {
            UpdateTransaction(offerTx, 0, sigdata);
        }
        else
        {
            UniValue jsonTx(UniValue::VOBJ);
            extern void TxToUniv(const CTransaction& tx, const uint256& hashBlock, UniValue& entry);
            TxToUniv(txNewConst, uint256(), jsonTx);
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to sign for script:\n " + jsonTx.write(1,2) + "\n");
        }

        UniValue retVal(UniValue::VOBJ);

        // if we're not just returning the hex tx, create a transaction from the postedOfferIns funds
        if (!signSuccess || returnHex)
        {
            if (signSuccess)
            {
                retVal.pushKV("signstatus", "complete");
            }
            else
            {
                retVal.pushKV("signstatus", "incomplete");
            }
            retVal.pushKV("hex", EncodeHexTx(offerTx));
            if (!returnHex)
            {
                retVal.pushKV("listingtransactionid", preTx.GetHash().GetHex());
            }
        }
        else
        {
            if (!postedOfferIns.size())
            {
                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Unable to make offer transaction on chain, try with returnhex as false");
            }
            TransactionBuilder tb(Params().consensus, height + 1, pwalletMain);

            // set expiry of the transaction holding the actual offer to max one day out and not more than the offer is valid
            uint32_t oneDayInBlocks = chainActive.Height() + (86400 / ConnectedChains.ThisChain().blockTime);
            tb.SetExpiryHeight(offerTx.nExpiryHeight > oneDayInBlocks ? oneDayInBlocks : offerTx.nExpiryHeight);

            for (auto &oneIn : postedOfferIns)
            {
                tb.AddTransparentInput(COutPoint(oneIn.txIn.prevout.hash, oneIn.txIn.prevout.n), oneIn.scriptPubKey, oneIn.nValue);
            }

            // now, make the opret to contain this transaction
            CCrossChainProof opRetProof;
            opRetProof << CPartialTransactionProof(CMMRProof(), offerTx);
            tb.AddOpRet(StoreOpRetArray(opRetProof.chainObjects));
            tb.SendChangeTo(changeDestination);
            tb.SetFee(feeAmount);

            TransactionBuilderResult result = tb.Build();
            CTransaction offerPostTx = result.GetTxOrThrow();

            bool relayTx;
            CValidationState state;
            {
                LOCK2(smartTransactionCS, mempool.cs);
                relayTx = myAddtomempool(offerPostTx, &state);
            }

            if (!relayTx)
            {
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Failed to add offer transaction to mempool");
            }
            else
            {
                retVal.pushKV("txid", preTx.GetHash().GetHex());
                retVal.pushKV("oprettxid", offerPostTx.GetHash().GetHex());
                RelayTransaction(offerPostTx);
            }
        }

        return retVal;
    }
    catch(const std::exception& e)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot create offer: " + std::string(e.what()));
    }
    return NullUniValue;
}

UniValue takeoffer(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
    {
        throw runtime_error(
            "takeoffer fromaddress '{\"txid\":\"txid\" | \"tx\":\"hextx\", \"changeaddress\":\"transparentoriaddress\", \"deliver\":\"fullidnameoriaddresstodeliver\" | {\"currency\":\"currencynameorid\",\"amount\":n}, \"accept\":{\"address\":\"addressorid\",\"currency\":\"currencynameorid\",\"amount\":n} | {identitydefinition} | {\"txout\":{\"serializedtxout\"}}}' (returntx) (feeamount)\n"
            "\nIf the current wallet can afford the swap, this accepts a swap offer on the blockchain, creates a transaction\n"
            "to execute it, and posts the transaction to the blockchain.\n"

            "\nArguments\n"
            "\"fromaddress\"            (string, required) The Sapling, VerusID, or wildcard address to send funds from, including fees for ID swaps.\n"
            "                                              \"*\", \"R*\", or \"i*\" are valid wildcards\n"
            "{\n"
                "\"txid\"               (string, required) The transaction ID for the offer to accept\n"
                "\"tx\"                 (string, required) The hex transaction to complete in order to accept the offer\n"
                "\"deliver\"            (object, required) One of \"fullidnameoriaddresstotrade\" or {\"currency\":\"currencynameorid\", \"amount\":value}\n"
                "\"accept\"             (object, required) One of {\"address\":\"addressorid\",\"currency\":\"currencynameorid\",\"amount\"} or {identitydefinition}\n"
                "\"feeamount\"          (number, optional) Specific fee amount requested instead of default miner's fee\n"
            "}\n"

            "\nResult:\n"
            "   \"txid\" : \"transactionid\" (string) The transaction id if (returntx) is false\n"
            "   \"hextx\" : \"hex\"         (string) The hexadecimal, serialized transaction if (returntx) is true\n"

            "\nExamples:\n"
            + HelpExampleCli("takeoffer", "fromaddress '{\"txid\":\"txid\" | \"tx\":\"hextx\", \"deliver\":\"fullidnameoriaddresstodeliver\" | {\"currency\":\"currencynameorid\",\"amount\":...}, \"accept\":{\"address\":\"addressorid\",\"currency\":\"currencynameorid\",\"amount\"} | {identitydefinition}}' (returntx) (feeamount)")
            + HelpExampleRpc("takeoffer", "fromaddress {\"txid\":\"txid\" | \"tx\":\"hextx\", \"deliver\":\"fullidnameoriaddresstodeliver\" | {\"currency\":\"currencynameorid\",\"amount\":...}, \"accept\":{\"address\":\"addressorid\",\"currency\":\"currencynameorid\",\"amount\"} | {identitydefinition}} (returntx) (feeamount)")
        );
    }

    CheckVerusVaultAPIsValid();

    bool returnHex = params.size() > 2 ? uni_get_bool(params[2]) : false;
    CAmount feeAmount = params.size() > 3 ? AmountFromValue(params[3]) : DEFAULT_TRANSACTION_FEE;

    std::string fundsSource = uni_get_str(params[0]);
    if (fundsSource.empty())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "First parameter json object must include a currency funding \"source\", which may be an ID, transparent address, private address, or wildcards (*, R*, i*)");
    }

    CTxDestination sourceDest, changeAddress;

    bool wildCardTransparentAddress = fundsSource == "*";
    bool wildCardRAddress = fundsSource == "R*";
    bool wildCardiAddress = fundsSource == "i*";
    bool wildCardAddress = wildCardTransparentAddress || wildCardRAddress || wildCardiAddress;

    std::vector<CRecipient> outputs;

    libzcash::PaymentAddress zaddressSource;
    libzcash::SaplingExpandedSpendingKey expsk;
    std::vector<SpendDescriptionInfo> saplingSpends;
    void *saplingSpendCtx = nullptr;

    uint256 sourceOvk;
    bool hasZSource = !wildCardAddress && pwalletMain->GetAndValidateSaplingZAddress(fundsSource, zaddressSource, true);
    // if we have a z-address as a source, re-encode it to a string, which is used
    // by the async operation, to ensure that we don't need to lookup IDs in that operation
    if (hasZSource)
    {
        // TODO: enable z-source for funds
        throw JSONRPCError(RPC_INVALID_PARAMETER, "z-address for payment, not yet implemented");
        fundsSource = EncodePaymentAddress(zaddressSource);
        // We don't need to lock on the wallet as spending key related methods are thread-safe
        if (!boost::apply_visitor(HaveSpendingKeyForPaymentAddress(pwalletMain), zaddressSource)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address, no spending key found for zaddr");
        }

        auto spendingkey_ = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), zaddressSource).get();
        auto sk = boost::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
        expsk = sk.expsk;
        sourceOvk = expsk.full_viewing_key().ovk;
    }

    if (!(hasZSource ||
          wildCardAddress ||
          (sourceDest = DecodeDestination(fundsSource)).which() != COptCCParams::ADDRTYPE_INVALID))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. First parameter must be sapling address, transparent address, identity, \"*\", \"R*\", or \"i*\",. See help.");
    }

    CTxDestination from_taddress;
    if (wildCardTransparentAddress)
    {
        from_taddress = CTxDestination();
    }
    else if (wildCardRAddress)
    {
        from_taddress = CTxDestination(CKeyID(uint160()));
    }
    else if (wildCardiAddress)
    {
        from_taddress = CTxDestination(CIdentityID(uint160()));
    }
    else
    {
        from_taddress = sourceDest;
    }

    // now, we either have a z-address source, wild card, or single transparent source
    const UniValue &takeOfferUni = params[1];
    std::string txIdStringToTake = uni_get_str(find_value(takeOfferUni, "txid"));
    std::string txStringToTake = uni_get_str(find_value(takeOfferUni, "tx"));
    std::string changeAddressStr = uni_get_str(find_value(takeOfferUni, "changeaddress"));

    {
        LOCK(cs_main);
        if ((changeAddress = ValidateDestination(changeAddressStr)).which() == COptCCParams::ADDRTYPE_INVALID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "\"changeaddress\" must be specified as a transparent address or identity");
        }
    }

    uint256 txIdToTake;
    CTransaction txToTake, inputTxToOffer;
    uint32_t height;
    uint32_t consensusBranchId;

    {
        LOCK2(cs_main, mempool.cs);
        height = chainActive.Height();
        consensusBranchId = CurrentEpochBranchId(height + 1, Params().GetConsensus());

        if (!txIdStringToTake.empty())
        {
            txIdToTake.SetHex(txIdStringToTake);
            if (txIdToTake.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid txid specified");
            }
            uint256 blockHash;
            CTransaction postedTx;
            if (!myGetTransaction(txIdToTake, postedTx, blockHash))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction " + txIdToTake.GetHex() + " not found");
            }

            // get the actual transaction from the op return
            if (!GetOpRetChainOffer(postedTx, txToTake, inputTxToOffer, height))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to retrieve valid offer");
            }
        }
        else if (!txStringToTake.empty())
        {
            uint256 blockHash;
            if (!(DecodeHexTx(txToTake, txStringToTake) &&
                  txToTake.vout.size() == 1 &&
                  txToTake.vin.size() == 1 &&
                  txToTake.vShieldedSpend.size() == 0 &&
                  txToTake.nExpiryHeight > (height + 3) &&
                  myGetTransaction(txToTake.vin[0].prevout.hash, inputTxToOffer, blockHash)))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer transaction supplied is not valid or expired");
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Must either provide a transaction in \"tx\" or a transaction id in \"txid\" to specify the offer");
        }
    }

    UniValue deliver = find_value(takeOfferUni, "deliver");
    UniValue accept = find_value(takeOfferUni, "accept");

    CIdentityID idIDToDeliver;
    std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
    CTxIn idInput;
    CTxOut oldIdOutput;
    CTxDestination acceptToAddress;

    std::pair<CIdentityMapKey, CIdentityMapValue> keyAndRevocation;
    std::pair<CIdentityMapKey, CIdentityMapValue> keyAndRecovery;

    CIdentity acceptedIdentity;
    CCurrencyValueMap acceptedCurrency, currencyToDeliver;
    CAmount subsidizedFees = 0;

    bool isRawTxOut = false;
    CTxOut rawTxOut;

    if (accept.isNull() || !accept.isObject())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity or currency to accept must be a valid json object");
    }

    std::string revocationStr = uni_get_str(find_value(accept, "revocationauthority"));
    std::string recoveryStr = uni_get_str(find_value(accept, "recoveryauthority"));
    std::string idNameStr = uni_get_str(find_value(accept, "name"));

    CTxDestination revocationDest = DecodeDestination(revocationStr);
    CTxDestination recoveryDest = DecodeDestination(recoveryStr);
    if (idNameStr != "" &&
        ((revocationStr != "" && revocationDest.which() != COptCCParams::ADDRTYPE_ID) ||
         (recoveryStr != "" && recoveryDest.which() != COptCCParams::ADDRTYPE_ID)))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Revocation and recovery identities must be empty or valid identities when accepting an offer for an ID");
    }

    if ((acceptedIdentity = CIdentity(accept)).IsValid())
    {
        uint160 parentID = uint160(GetDestinationID(DecodeDestination(uni_get_str(find_value(accept, "parent")))));
        if (parentID.IsNull() && (parentID = ValidateCurrencyName(uni_get_str(find_value(accept, "parent")), true)).IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "To ensure acceptance of the correct identity, parent must be a correct, non-null value.");
        }

        CTxIn idTxIn;
        CIdentity oldID;
        uint32_t idHeight;

        if (!(oldID = CIdentity::LookupIdentity(acceptedIdentity.GetID(), 0, &idHeight, &idTxIn)).IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + acceptedIdentity.GetID().GetHex() + ", not found ");
        }

        if (oldID.HasTokenizedControl())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Do not buy an ID with tokenized ID control via the marketplace. Buy the token that is the ID control (or NFT) for a revoked ID with all authorities instead. ID: " + acceptedIdentity.GetID().GetHex());
        }

        oldID.revocationAuthority = oldID.GetID();
        oldID.recoveryAuthority = oldID.GetID();
        oldID.privateAddresses.clear();
        oldID.primaryAddresses.clear();
        oldID.minSigs = 1;

        auto uniOldID = UniObjectToMap(oldID.ToUniValue());

        // overwrite old elements
        for (auto &oneEl : UniObjectToMap(accept))
        {
            uniOldID[oneEl.first] = oneEl.second;
        }

        uint32_t solVersion = CConstVerusSolutionVector::GetVersionByHeight(height + 1);

        if (solVersion >= CActivationHeight::ACTIVATE_VERUSVAULT)
        {
            uniOldID["version"] = solVersion < CActivationHeight::ACTIVATE_PBAAS ? (int64_t)CIdentity::VERSION_VAULT : (int64_t)CIdentity::VERSION_PBAAS;
            if (oldID.nVersion < CIdentity::VERSION_VAULT)
            {
                uniOldID["systemid"] = EncodeDestination(CIdentityID(parentID.IsNull() ? oldID.GetID() : parentID));
            }
        }

        UniValue newUniID = MapToUniObject(uniOldID);
        acceptedIdentity = CIdentity(newUniID);
        acceptedIdentity.UpgradeVersion(height + 1);
    }
    else
    {
        std::string acceptTxOutStr = uni_get_str(find_value(accept, "txout"));
        if (!acceptTxOutStr.empty() && IsHex(acceptTxOutStr) && acceptTxOutStr.length() > 30 && !(acceptTxOutStr.length() % 2))
        {
            bool success = false;
            ::FromVector(ParseHex(acceptTxOutStr), rawTxOut, &success);
            if (!(success && rawTxOut.scriptPubKey.size() && MoneyRange(rawTxOut.nValue)))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid serialized hexadecimal txout object");
            }
            acceptedCurrency = rawTxOut.scriptPubKey.ReserveOutValue();
            if (rawTxOut.nValue)
            {
                acceptedCurrency.valueMap[ASSETCHAINS_CHAINID] = rawTxOut.nValue;
            }
            isRawTxOut = true;
        }
        else
        {
            std::string acceptCurrencyStr = uni_get_str(find_value(accept, "currency"));
            std::string acceptToDestStr = uni_get_str(find_value(accept, "address"));
            uint160 currencyID = ValidateCurrencyName(acceptCurrencyStr, true);
            if (acceptCurrencyStr.empty())
            {
                currencyID = ASSETCHAINS_CHAINID;
            }
            CAmount currencyAmount;
            if (currencyID.IsNull() || (currencyAmount = AmountFromValue(find_value(accept, "amount"))) <= 0)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "One of identity or currency to accept must be valid");
            }
            acceptedCurrency.valueMap[currencyID] = currencyAmount;

            LOCK(cs_main);
            if ((acceptToAddress = ValidateDestination(acceptToDestStr)).which() == COptCCParams::ADDRTYPE_INVALID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. To accept an offer of currency, the accept address must be a transparent address or identity. See help.");
            }
        }
    }

    // for use later
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    CMutableTransaction mtx(txToTake);

    int firstFundingInput = 0;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        LOCK(mempool.cs);

        if (deliver.isStr())
        {
            CIdentity revocationIdentity, recoveryIdentity;

            // this needs to be a valid ID in our wallet
            CTxDestination identityDest = DecodeDestination(uni_get_str(deliver));
            if (identityDest.which() != COptCCParams::ADDRTYPE_ID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "If a VerusID is specified to deliver when taking the offer, it must be a valid ID name or i-address on this chain");
            }
            bool idInWallet = pwalletMain->GetIdentity(GetDestinationID(identityDest), keyAndIdentity);

            if (!idInWallet || !(*(CIdentity *)(&keyAndIdentity.second) = CIdentity::LookupIdentity(GetDestinationID(identityDest), 0, nullptr, &idInput)).IsValid())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "No authority over VerusID or ID not found");
            }

            uint256 blkHash;
            CTransaction oldIdTx;
            if (!myGetTransaction(idInput.prevout.hash, oldIdTx, blkHash))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + keyAndIdentity.second.name + " (" + EncodeDestination(CIdentityID(keyAndIdentity.second.GetID())) + "), transaction not found ");
            }
            oldIdOutput = oldIdTx.vout[idInput.prevout.n];

            if (!keyAndIdentity.first.CanSign())
            {
                // we need either signing authority, revocation, recovery, or any combination to be able to create a delivery transaction
                if (keyAndIdentity.second.revocationAuthority == idIDToDeliver && keyAndIdentity.second.recoveryAuthority == idIDToDeliver)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "No authority over VerusID specified for delivery");
                }
                // if recovery is different, get it and see if we have signing authority on that
                if (keyAndIdentity.second.revocationAuthority != idIDToDeliver)
                {
                    if (!pwalletMain->GetIdentity(keyAndIdentity.second.revocationAuthority, keyAndRevocation))
                    {
                        if (!(keyAndRevocation.second = CIdentityMapValue(CIdentity::LookupIdentity(keyAndIdentity.second.revocationAuthority))).IsValid())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Revocation authority not found for ID specified");
                        }
                    }
                }
                else
                {
                    keyAndRevocation = keyAndIdentity;
                }

                // if recovery is different, get it and see if we have signing authority on that
                if (keyAndIdentity.second.recoveryAuthority != idIDToDeliver)
                {
                    if (keyAndIdentity.second.recoveryAuthority == keyAndIdentity.second.revocationAuthority)
                    {
                        keyAndRecovery = keyAndRevocation;
                    }
                    else if (!pwalletMain->GetIdentity(keyAndIdentity.second.recoveryAuthority, keyAndRecovery))
                    {
                        if (!(keyAndRecovery.second = CIdentityMapValue(CIdentity::LookupIdentity(keyAndIdentity.second.recoveryAuthority))).IsValid())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Recovery authority not found for ID specified");
                        }
                    }
                }
                else
                {
                    keyAndRecovery = keyAndIdentity;
                }
            }
            // if we can't sign for any authority on the ID, don't make a transaction
            if (!keyAndIdentity.first.CanSign() && !keyAndRevocation.first.CanSign() && !keyAndRecovery.first.CanSign())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "This wallet has no authority to sign for any part of delivering the ID specified");
            }
            currencyToDeliver.valueMap[ASSETCHAINS_CHAINID] = feeAmount;
        }
        else if (deliver.isObject())
        {
            // determine the currency we are offering to deliver
            auto rawCurrencyStr = uni_get_str(find_value(deliver, "currency"));
            auto currencyStr = TrimSpaces(rawCurrencyStr, true);
            if (rawCurrencyStr != currencyStr)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency name in acceptance must be valid with no leading or trailing spaces");
            }
            CAmount destinationAmount = AmountFromValue(find_value(deliver, "amount"));
            uint160 curID;
            if (!currencyStr.empty())
            {
                curID = ValidateCurrencyName(currencyStr, true);
                if (curID.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency specified for delivery not found");
                }
            }
            else
            {
                curID = ASSETCHAINS_CHAINID;
            }

            currencyToDeliver.valueMap[curID] = destinationAmount;
            currencyToDeliver.valueMap[ASSETCHAINS_CHAINID] += feeAmount;
        }

        // now, ensure that our expected output and the input provided in the offer are the same
        COptCCParams p;
        CIdentity offeredIdentity;
        CCurrencyValueMap offeredCurrency;
        if (inputTxToOffer.vout[txToTake.vin[0].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_IDENTITY_PRIMARY &&
            p.vData.size() &&
            (offeredIdentity = CIdentity(p.vData[0])).IsValid())
        {
            if (offeredIdentity.GetID() != acceptedIdentity.GetID())
            {
                if (isRawTxOut)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity offers cannot be accepted with a txout parameter");
                }
                else
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity offered: " + EncodeDestination(CIdentityID(offeredIdentity.GetID())) + ", is not the same as accepted: " + EncodeDestination(CIdentityID(acceptedIdentity.GetID())));
                }
            }
        }
        else if (inputTxToOffer.vout[txToTake.vin[0].prevout.n].scriptPubKey.IsSpendableOutputType())
        {
            if (inputTxToOffer.vout[txToTake.vin[0].prevout.n].nValue > 0)
            {
                offeredCurrency.valueMap[ASSETCHAINS_CHAINID] = inputTxToOffer.vout[txToTake.vin[0].prevout.n].nValue;
            }
            offeredCurrency += inputTxToOffer.vout[txToTake.vin[0].prevout.n].scriptPubKey.ReserveOutValue();
            if (offeredCurrency < acceptedCurrency)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency offered: " + offeredCurrency.ToUniValue().write() + ", is less than accepted: " + acceptedCurrency.ToUniValue().write());
            }
        }

        CAmount additionalFees = feeAmount;

        // add the output
        if (acceptedIdentity.IsValid())
        {
            mtx.vout.push_back(CTxOut(0, acceptedIdentity.IdentityUpdateOutputScript(height + 1)));
        }
        else if ((acceptedCurrency = acceptedCurrency.CanonicalMap()).valueMap.size())
        {
            if (isRawTxOut)
            {
                mtx.vout.push_back(rawTxOut);
            }
            else
            {
                // if our accepted currency is native, no reserve output
                CAmount nativeOut = acceptedCurrency.valueMap.count(ASSETCHAINS_CHAINID) ? acceptedCurrency.valueMap[ASSETCHAINS_CHAINID] : 0;

                if (acceptedCurrency.valueMap.size() == 1 && nativeOut)
                {
                    mtx.vout.push_back(CTxOut(nativeOut, GetScriptForDestination(acceptToAddress)));
                }
                else
                {
                    acceptedCurrency.valueMap.erase(ASSETCHAINS_CHAINID);
                    std::vector<CTxDestination> dest({acceptToAddress});
                    CTokenOutput to(acceptedCurrency);
                    mtx.vout.push_back(CTxOut(nativeOut, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dest, 1, &to))));
                }
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Must specify valid identity or currency for exchange");
        }

        // if the identity has been initialized, we are delivering an identity in this transaction, input our identity to the
        // transaction, and add an output for our return
        std:vector<COutput> vCoins;
        std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
        CAmount nativeValueOut;
        CCurrencyValueMap reserveValueOut;
        std::vector<SaplingNoteEntry> saplingNotes;

        firstFundingInput = mtx.vin.size();

        if (keyAndIdentity.second.IsValid())
        {
            bool success = true;
            mtx.vin.push_back(idInput);
            // one ID input to fund the transaction
            if (additionalFees)
            {
                if (hasZSource)
                {
                    saplingNotes = find_unspent_notes(zaddressSource);
                    CAmount totalFound = 0;
                    int i;
                    for (i = 0; i < saplingNotes.size(); i++)
                    {
                        totalFound += saplingNotes[i].note.value();
                        if (totalFound >= additionalFees)
                        {
                            break;
                        }
                    }
                    // remove all but the notes we'll use
                    if (i < saplingNotes.size())
                    {
                        saplingNotes.erase(saplingNotes.begin() + i + 1, saplingNotes.end());
                        success = true;
                    }
                    else
                    {
                        success = false;
                    }
                }
                else
                {
                    success = find_utxos(from_taddress, vCoins) &&
                                pwalletMain->SelectCoinsMinConf(additionalFees, 0, 0, vCoins, setCoinsRet, nativeValueOut);
                }
            }
            if (!success)
            {
                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Unable to fund delivery of identity");
            }
        }
        else if (currencyToDeliver.valueMap.size())
        {
            COptCCParams p;
            CCurrencyValueMap currencyRequested;
            if (txToTake.vout[0].scriptPubKey.IsSpendableOutputType(p) || (p.IsValid() && p.evalCode == EVAL_IDENTITY_COMMITMENT))
            {
                if (txToTake.vout[0].nValue - txToTake.valueBalance > 0)
                {
                    currencyRequested.valueMap[ASSETCHAINS_CHAINID] = txToTake.vout[0].nValue - txToTake.valueBalance;
                }
                currencyRequested += txToTake.vout[0].scriptPubKey.ReserveOutValue();
                if (currencyToDeliver < currencyRequested)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency being delivered: " + currencyToDeliver.ToUniValue().write() + ", is less than requested: " + currencyRequested.ToUniValue().write());
                }
                currencyToDeliver = currencyRequested;
            }
            else
            {
                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Invalid currency request from offer transaction");
            }

            // find enough currency from source to fund the acceptance
            CAmount nativeValue = (currencyToDeliver.valueMap[ASSETCHAINS_CHAINID] + additionalFees);
            currencyToDeliver.valueMap.erase(ASSETCHAINS_CHAINID);

            bool success = false;
            if (hasZSource)
            {
                if (currencyToDeliver.CanonicalMap().valueMap.size() != 0)
                {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Private address source cannot be used for non-native currency delivery");
                }
                saplingNotes = find_unspent_notes(zaddressSource);
                CAmount totalFound = 0;
                int i;
                for (i = 0; i < saplingNotes.size(); i++)
                {
                    totalFound += saplingNotes[i].note.value();
                    if (totalFound >= additionalFees)
                    {
                        break;
                    }
                }
                // remove all but the notes we'll use
                if (i < saplingNotes.size())
                {
                    saplingNotes.erase(saplingNotes.begin() + i + 1, saplingNotes.end());
                    success = true;
                }
            }
            else
            {
                success = find_utxos(from_taddress, vCoins) &&
                        pwalletMain->SelectReserveCoinsMinConf(currencyToDeliver,
                                                                nativeValue,
                                                                0,
                                                                1,
                                                                vCoins,
                                                                setCoinsRet,
                                                                reserveValueOut,
                                                                nativeValueOut);
            }

            if (!success)
            {
                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Unable to fund currency delivery");
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "No identity or currency to deliver");
        }

        if (saplingNotes.size())
        {
            if (txToTake.vShieldedOutput.size())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Paying for an offer, which pays to a z-address with a z-address source is not yet implemented");
            }

            std::vector<SaplingOutPoint> notes;
            for (size_t i = 0; i < saplingNotes.size(); i++)
            {
                notes.push_back(saplingNotes[i].op);
            }

            // Fetch Sapling anchor and witnesses
            uint256 anchor;
            std::vector<boost::optional<SaplingWitness>> witnesses;
            {
                LOCK2(cs_main, pwalletMain->cs_wallet);
                pwalletMain->GetSaplingNoteWitnesses(notes, witnesses, anchor);
            }

            saplingSpendCtx = librustzcash_sapling_proving_ctx_init();

            // Add Sapling spends
            for (size_t i = 0; i < saplingNotes.size(); i++)
            {
                SpendDescriptionInfo spend(expsk, saplingNotes[i].note, anchor, boost::get(witnesses[i]));
                //tb.AddSaplingSpend(expsk, saplingNotes[i].note, anchor, witnesses[i].get());

                auto cm = spend.note.cm();
                auto nf = spend.note.nullifier(
                    spend.expsk.full_viewing_key(), spend.witness.position());
                if (!cm || !nf) {
                    librustzcash_sapling_proving_ctx_free(saplingSpendCtx);
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Spend is invalid");
                }

                CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                ss << spend.witness.path();
                std::vector<unsigned char> witness(ss.begin(), ss.end());

                SpendDescription sdesc;
                if (!librustzcash_sapling_spend_proof(
                        saplingSpendCtx,
                        spend.expsk.full_viewing_key().ak.begin(),
                        spend.expsk.nsk.begin(),
                        spend.note.d.data(),
                        spend.note.r.begin(),
                        spend.alpha.begin(),
                        spend.note.value(),
                        spend.anchor.begin(),
                        witness.data(),
                        sdesc.cv.begin(),
                        sdesc.rk.begin(),
                        sdesc.zkproof.data())) {
                    librustzcash_sapling_proving_ctx_free(saplingSpendCtx);
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Spend proof failed");
                }

                sdesc.anchor = spend.anchor;
                sdesc.nullifier = *nf;
                mtx.vShieldedSpend.push_back(sdesc);
            }
        }
        else
        {
            // put all transparent inputs and spends on the transaction, sign and return or post
            for (auto &oneInput : setCoinsRet)
            {
                mtx.vin.push_back(CTxIn(oneInput.first->GetHash(), oneInput.second));
            }
        }

        // Fetch previous transactions (inputs):
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view
        for (auto &txin : mtx.vin)
        {
            const uint256& prevHash = txin.prevout.hash;
            CCoins coins;
            view.AccessCoins(prevHash); // this can fail
        }
        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    CReserveTransactionDescriptor rtxd(mtx, view, height + 1);
    if (!rtxd.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Created invalid transaction");
    }
    CCurrencyValueMap reserveChange = rtxd.ReserveFees();
    CAmount nativeChange = rtxd.NativeFees() - feeAmount;
    if (nativeChange < DEFAULT_TRANSACTION_FEE)
    {
        nativeChange = 0;
    }
    if (reserveChange.valueMap.size())
    {
        std::vector<CTxDestination> dest({changeAddress});
        CTokenOutput to(reserveChange);
        mtx.vout.push_back(CTxOut(nativeChange, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dest, 1, &to))));
    }
    else if (nativeChange)
    {
        mtx.vout.push_back(CTxOut(nativeChange, GetScriptForDestination(changeAddress)));
    }

    CTransaction txConst(mtx);
    UniValue vErrors(UniValue::VARR);

    // Sign what we can

    // first Sapling spends, if we have them
    if (saplingSpends.size())
    {
        uint256 dataToBeSigned;
        CScript scriptCode;
        try {
            dataToBeSigned = SignatureHash(scriptCode, mtx, NOT_AN_INPUT, SIGHASH_ALL, 0, consensusBranchId);
        } catch (std::logic_error ex) {
            librustzcash_sapling_proving_ctx_free(saplingSpendCtx);
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not construct signature hash");
        }

        // Create Sapling spendAuth and binding signatures
        for (size_t i = 0; i < saplingSpends.size(); i++) {
            librustzcash_sapling_spend_sig(
                saplingSpends[i].expsk.ask.begin(),
                saplingSpends[i].alpha.begin(),
                dataToBeSigned.begin(),
                mtx.vShieldedSpend[i].spendAuthSig.data());
        }
        librustzcash_sapling_binding_sig(
            saplingSpendCtx,
            mtx.valueBalance,
            dataToBeSigned.begin(),
            mtx.bindingSig.data());

        librustzcash_sapling_proving_ctx_free(saplingSpendCtx);
    }

    for (int i = firstFundingInput; i < mtx.vin.size(); i++)
    {
        CTxIn& txin = mtx.vin[i];
        const CCoins* coins = view.AccessCoins(txin.prevout.hash);
        if (coins == NULL || !coins->IsAvailable(txin.prevout.n)) {
            SigningErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = CCoinsViewCache::GetSpendFor(coins, txin);
        const CAmount& amount = coins->vout[txin.prevout.n].nValue;

        SignatureData sigdata;
        ProduceSignature(MutableTransactionSignatureCreator(pwalletMain, &mtx, i, amount, prevPubKey), prevPubKey, sigdata, consensusBranchId);

        TransactionSignatureChecker checker(&txConst, i, amount);
        sigdata = CombineSignatures(prevPubKey, checker, sigdata, DataFromTransaction(txConst, i), consensusBranchId);

        UpdateTransaction(mtx, i, sigdata);

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, checker, consensusBranchId, &serror)) {
            SigningErrorToJSON(txin, vErrors, ScriptErrorString(serror));
        }
    }
    bool fComplete = vErrors.empty();
    UniValue retVal(UniValue::VOBJ);

    if (fComplete && !returnHex)
    {
        CValidationState state;
        CTransaction finalTx = mtx;
        LOCK(cs_main);

        bool relayTx;
        {
            LOCK2(smartTransactionCS, mempool.cs);
            relayTx = myAddtomempool(finalTx, &state);
        }

        if (!relayTx)
        {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Could not commit transaction - rejected");
        }
        else
        {
            //printf("%s: success adding %s to mempool\n", __func__, newImportTx.GetHash().GetHex().c_str());
            RelayTransaction(finalTx);
        }
        retVal.pushKV("txid", finalTx.GetHash().GetHex());
    }
    else
    {
        // if this is an ID swap, spend ID to transaction and take funds or pay requird funds and take ID
        // if this is a funds swap, pay required funds and take required funds
        retVal.pushKV("tx", EncodeHexTx(mtx));
        if (!vErrors.empty())
        {
            retVal.pushKV("errors", vErrors);
        }
    }

    return retVal;
}

UniValue IdOfferInfo(const CIdentity &identityOffer)
{
    UniValue retVal(UniValue::VOBJ);
    retVal.pushKV("name", identityOffer.name);
    retVal.pushKV("identityid", EncodeDestination(CIdentityID(identityOffer.GetID())));
    retVal.pushKV("systemid", EncodeDestination(CIdentityID(identityOffer.systemID)));
    retVal.pushKV("original", identityOffer.systemID == ASSETCHAINS_CHAINID);
    return retVal;
}

UniValue getoffers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        throw runtime_error(
            "getoffers \"currencyorid\" (iscurrency) (withtx)\n"
            "\nReturns all open offers for a specific currency or ID\n"

            "\nArguments\n"
            "1. \"currencyorid\"        (string, required) The currency or ID to check for offers, both sale and purchase\n"
            "2. \"iscurrency\"          (bool, optional)   default=false, if false, this looks for ID offers, if true, currencies\n"
            "3. \"withtx\"              (bool, optional)   default=false, if true, this returns serialized hex of the exchange transaction for signing\n"

            "\nResult:\n"
            "all available offers for or in the indicated currency or ID are displayed\n"

            "\nExamples:\n"
            + HelpExampleCli("getoffers", "\"currencyorid\" (iscurrency)")
            + HelpExampleRpc("getoffers", "\"currencyorid\" (iscurrency)")
        );
    }

    CheckVerusVaultAPIsValid();

    bool isCurrency = false;
    if (params.size() > 1)
    {
        isCurrency = uni_get_bool(params[1]);
    }

    bool withTx = false;
    if (params.size() > 2)
    {
        withTx = uni_get_bool(params[2]);
    }

    uint160 lookupID, lookupForID;

    CCurrencyDefinition currencyDef;
    uint160 currencyOrIdID;
    CIdentity identity;
    std::string currencyOrIDStr(uni_get_str(params[0]));

    LOCK(cs_main);

    if (isCurrency)
    {
        lookupID = ValidateCurrencyName(currencyOrIDStr, true, &currencyDef);
        if (lookupID.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency specified as source is not valid");
        }
        lookupForID = COnChainOffer::OnChainOfferForCurrencyKey(lookupID);
        lookupID = COnChainOffer::OnChainCurrencyOfferKey(lookupID);
        currencyOrIdID = currencyDef.GetID();
    }
    else
    {
        CTxDestination idDest = DecodeDestination(currencyOrIDStr);
        if (idDest.which() != COptCCParams::ADDRTYPE_ID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity specified as source is not valid");
        }
        lookupID = GetDestinationID(idDest);
        if (!(identity = CIdentity::LookupIdentity(lookupID)).IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Source identity not found");
        }
        lookupForID = COnChainOffer::OnChainOfferForIdentityKey(lookupID);
        lookupID = COnChainOffer::OnChainIdentityOfferKey(lookupID);
        currencyOrIdID = identity.GetID();
    }

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputOffers;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;

    uint32_t height = chainActive.Height();

    // bool is "iscurrency" for the offer in a buy and for the request for payment in a sell

    // offers to buy with IDs
    std::multimap<std::pair<uint160, CAmount>, UniValue> uniBuyWithIDs;
    std::multimap<std::pair<uint160, CAmount>, UniValue> uniSellToIDs;

    std::multimap<std::pair<uint160, CAmount>, UniValue> uniBuyWithCurrency;
    std::multimap<std::pair<uint160, CAmount>, UniValue> uniSellToCurrency;

    //printf("%s: looking up keys: %s, %s\n", __func__, EncodeDestination(CKeyID(lookupID)).c_str(), EncodeDestination(CKeyID(lookupForID)).c_str());

    if (!GetAddressUnspent(lookupID, CScript::P2PKH, unspentOutputOffers) || !GetAddressUnspent(lookupForID, CScript::P2PKH, unspentOutputs))
    {
        return false;
    }
    else
    {
        UniValue retVal(UniValue::VOBJ);
        unspentOutputs.insert(unspentOutputs.end(), unspentOutputOffers.begin(), unspentOutputOffers.end());

        for (auto &oneOffer : unspentOutputs)
        {
            CTransaction postedTx, offerTx, inputToOfferTx;
            uint256 blockHash;
            CPartialTransactionProof offerTxProof;
            COptCCParams p;
            if (myGetTransaction(oneOffer.first.txhash, postedTx, blockHash))
            {
                if (GetOpRetChainOffer(postedTx, offerTx, inputToOfferTx, height))
                {
                    // find out what the transaction is requesting for payment
                    CCurrencyValueMap offerToPay, wePay;
                    CIdentity offerToTransfer, weTransfer;

                    std::pair<CTxOut, CTxOut> offerOuts(std::make_pair(inputToOfferTx.vout[offerTx.vin[0].prevout.n], offerTx.vout[0]));
                    if (offerTx.vShieldedOutput.size() != 0)
                    {
                        offerOuts.second.nValue -= offerTx.valueBalance;
                    }

                    if (offerOuts.second.scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() &&
                        p.evalCode == EVAL_IDENTITY_PRIMARY &&
                        p.vData.size())
                    {
                        if (!(weTransfer = CIdentity(p.vData[0])).IsValid())
                        {
                            continue;
                        }
                        // if this is not what we are looking for, then it must be a request to trade for what we are looking for
                        if (isCurrency || weTransfer.GetID() != currencyOrIdID)
                        {
                            // make sure the offer is offering what we are looking for
                            if (isCurrency)
                            {
                                // verify it is the currency we are looking for
                                p = COptCCParams();
                                if (!(offerOuts.first.scriptPubKey.IsSpendableOutputType(p) &&
                                     ((currencyOrIdID == ASSETCHAINS_CHAINID && offerOuts.first.nValue > 0) ||
                                      ((currencyOrIdID != ASSETCHAINS_CHAINID &&
                                       (offerToPay = offerOuts.first.ReserveOutValue()).valueMap.count(currencyOrIdID) &&
                                        offerToPay.valueMap[currencyOrIdID] > 0)))))
                                {
                                    continue;
                                }
                                if (offerOuts.first.nValue > 0)
                                {
                                    offerToPay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.first.nValue;
                                }
                            }
                            else
                            {
                                // verify it is the ID we are looking for
                                if (!(offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                      p.IsValid() &&
                                      p.evalCode == EVAL_IDENTITY_PRIMARY &&
                                      p.vData.size() &&
                                      (offerToTransfer = CIdentity(p.vData[0])).IsValid() &&
                                      offerToTransfer.GetID() == currencyOrIdID))
                                {
                                    continue;
                                }
                            }
                            UniValue offerJSON(UniValue::VOBJ);
                            offerJSON.pushKV("offer", offerToTransfer.IsValid() ? IdOfferInfo(offerToTransfer) : offerToPay.ToUniValue());
                            offerJSON.pushKV("accept", IdOfferInfo(weTransfer));
                            offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                            if (withTx)
                            {
                                offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                            }
                            offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                            if (offerToPay.valueMap.begin() != offerToPay.valueMap.end() && offerToPay.valueMap.begin()->first == currencyOrIdID)
                            {
                                uniSellToIDs.insert(std::make_pair(std::make_pair(weTransfer.GetID(), offerToPay.valueMap.begin()->second), offerJSON));
                            }
                            else // offer to transfer is our query ID
                            {
                                uniSellToIDs.insert(std::make_pair(std::make_pair(weTransfer.GetID(), offerOuts.second.nValue > 0 ? offerOuts.second.nValue : 0), offerJSON));
                            }
                        }
                        else // this is an offer to buy the referenced ID for either currency or another ID, which is in the first output
                        {
                            if (offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                p.IsValid() &&
                                p.evalCode == EVAL_IDENTITY_PRIMARY &&
                                p.vData.size() &&
                                (offerToTransfer = CIdentity(p.vData[0])).IsValid())
                            {
                                UniValue offerJSON(UniValue::VOBJ);
                                offerJSON.pushKV("offer", offerToTransfer.IsValid() ? IdOfferInfo(offerToTransfer) : offerToPay.ToUniValue());
                                offerJSON.pushKV("accept", weTransfer.IsValid() ? IdOfferInfo(weTransfer) : wePay.ToUniValue());
                                offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                                if (withTx)
                                {
                                    offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                                }
                                offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                                uniBuyWithIDs.insert(std::make_pair(std::make_pair(offerToTransfer.GetID(), offerOuts.second.nValue > 0 ? offerOuts.second.nValue : 0), offerJSON));
                            }
                            else
                            {
                                // verify that there is a non-zero offer
                                p = COptCCParams();
                                if (!(offerOuts.first.scriptPubKey.IsSpendableOutputType(p) &&
                                     (offerOuts.first.nValue > 0 ||
                                      ((offerToPay = offerOuts.first.ReserveOutValue()) > CCurrencyValueMap()))))
                                {
                                    continue;
                                }
                                uint160 currencyID = offerOuts.first.nValue > 0 ? ASSETCHAINS_CHAINID : offerToPay.valueMap.begin()->first;
                                CAmount offerAmount = offerOuts.first.nValue > 0 ? offerOuts.first.nValue : offerToPay.valueMap.begin()->second;
                                if (offerOuts.first.nValue > 0)
                                {
                                    offerToPay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.first.nValue;
                                }
                                UniValue offerJSON(UniValue::VOBJ);
                                offerJSON.pushKV("offer", offerToTransfer.IsValid() ? IdOfferInfo(offerToTransfer) : offerToPay.ToUniValue());
                                offerJSON.pushKV("accept", weTransfer.IsValid() ? IdOfferInfo(weTransfer) : wePay.ToUniValue());
                                offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                                if (withTx)
                                {
                                    offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                                }
                                offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                                uniBuyWithCurrency.insert(std::make_pair(std::make_pair(currencyID, offerAmount), offerJSON));
                            }
                        }
                    }
                    else if (offerOuts.second.scriptPubKey.IsSpendableOutputType(p))
                    {
                        // see if it is a buy with the currency we are querying for
                        wePay = offerOuts.second.ReserveOutValue();
                        if (offerOuts.second.nValue > 0)
                        {
                            wePay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.second.nValue;
                        }

                        if (isCurrency && wePay.valueMap.count(currencyOrIdID) && wePay.valueMap[currencyOrIdID] > 0)
                        {
                            // if so, then it is a buy with whatever the input is
                            if (offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                p.IsValid() &&
                                p.evalCode == EVAL_IDENTITY_PRIMARY &&
                                p.vData.size() &&
                                (offerToTransfer = CIdentity(p.vData[0])).IsValid())
                            {
                                UniValue offerJSON(UniValue::VOBJ);
                                offerJSON.pushKV("offer", IdOfferInfo(offerToTransfer));
                                offerJSON.pushKV("accept", wePay.ToUniValue());
                                offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                                if (withTx)
                                {
                                    offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                                }
                                offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                                uniBuyWithIDs.insert(std::make_pair(std::make_pair(offerToTransfer.GetID(), wePay.valueMap.begin()->second), offerJSON));
                            }
                            else
                            {
                                // verify that there is a non-zero offer
                                offerToPay = offerOuts.first.ReserveOutValue();
                                if (offerOuts.first.nValue > 0)
                                {
                                    offerToPay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.first.nValue;
                                }

                                p = COptCCParams();
                                if (!(offerOuts.first.scriptPubKey.IsSpendableOutputType(p) && offerToPay > CCurrencyValueMap()))
                                {
                                    continue;
                                }

                                bool nativeOffer = offerOuts.first.nValue > 0 && offerToPay.CanonicalMap().valueMap.size() == 1;
                                uint160 currencyID = nativeOffer ? ASSETCHAINS_CHAINID : offerToPay.valueMap.begin()->first;
                                CAmount offerAmount = nativeOffer ? offerOuts.first.nValue : offerToPay.valueMap.begin()->second;

                                UniValue offerJSON(UniValue::VOBJ);
                                offerJSON.pushKV("offer", offerToPay.ToUniValue());
                                offerJSON.pushKV("accept", wePay.ToUniValue());
                                offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                                if (withTx)
                                {
                                    offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                                }
                                offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                                uniBuyWithCurrency.insert(std::make_pair(std::make_pair(currencyID, CalculateFractionalPrice(offerAmount, wePay.valueMap[currencyOrIdID], true)), offerJSON));
                            }
                        }
                        else if (isCurrency &&
                                 offerOuts.first.scriptPubKey.IsSpendableOutputType(p) &&
                                 ((currencyOrIdID == ASSETCHAINS_CHAINID && offerOuts.first.nValue > 0) ||
                                 ((currencyOrIdID != ASSETCHAINS_CHAINID &&
                                 (offerToPay = offerOuts.first.ReserveOutValue()).valueMap.count(currencyOrIdID) &&
                                 offerToPay.valueMap[currencyOrIdID] > 0))))
                        {
                            if (offerOuts.first.nValue > 0)
                            {
                                offerToPay.valueMap[ASSETCHAINS_CHAINID] = offerOuts.first.nValue;
                            }

                            // offer to sell currency we are querying for the output's currency
                            bool nativePay = offerOuts.second.nValue > 0 && wePay.CanonicalMap().valueMap.size() == 1;
                            uint160 currencyID = nativePay ? ASSETCHAINS_CHAINID : wePay.valueMap.begin()->first;
                            CAmount payAmount = nativePay ? offerOuts.second.nValue : wePay.valueMap.begin()->second;
                            UniValue offerJSON(UniValue::VOBJ);
                            offerJSON.pushKV("offer", offerToPay.ToUniValue());
                            offerJSON.pushKV("accept", wePay.ToUniValue());
                            offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                            if (withTx)
                            {
                                offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                            }
                            offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                            uniSellToCurrency.insert(std::make_pair(std::make_pair(currencyID, CalculateFractionalPrice(payAmount, offerToPay.valueMap[currencyOrIdID], false)), offerJSON));
                        }
                        else if (!isCurrency &&
                                 offerOuts.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                                 p.IsValid() &&
                                 p.evalCode == EVAL_IDENTITY_PRIMARY &&
                                 p.vData.size() &&
                                 (offerToTransfer = CIdentity(p.vData[0])).IsValid() &&
                                 offerToTransfer.GetID() == currencyOrIdID)
                        {
                            bool nativePay = offerOuts.second.nValue > 0 && wePay.CanonicalMap().valueMap.size() == 1;
                            uint160 currencyID = nativePay ? ASSETCHAINS_CHAINID : wePay.valueMap.begin()->first;
                            CAmount payAmount = nativePay ? offerOuts.second.nValue : wePay.valueMap.begin()->second;

                            // offer to sell identity we are querying for the output's currency
                            UniValue offerJSON(UniValue::VOBJ);
                            offerJSON.pushKV("offer", IdOfferInfo(offerToTransfer));
                            offerJSON.pushKV("accept", wePay.ToUniValue());
                            offerJSON.pushKV("blockexpiry", (int64_t)offerTx.nExpiryHeight);
                            if (withTx)
                            {
                                offerJSON.pushKV("tx", EncodeHexTx(offerTx));
                            }
                            offerJSON.pushKV("txid", postedTx.GetHash().GetHex());
                            uniSellToCurrency.insert(std::make_pair(std::make_pair(currencyID, payAmount), offerJSON));
                        }
                    }
                }
            }
            else
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot retrieve transaction " + oneOffer.first.txhash.GetHex() + ", the local index is likely corrupted and either requires reindex, bootstrap, or resync");
            }
        }
        if (isCurrency)
        {
            // for uniSellToIDs (same as offers in this currency for IDs), we will want to order by highest price to lowest price,
            // as the query was only for things that could be traded or purchased from the currency. the long tail is likely
            // less interesting. we do not end up with buy with IDs on a currency only query
            UniValue oneCategory(UniValue::VARR);
            for (auto rIT = uniSellToIDs.rbegin(); rIT != uniSellToIDs.rend(); rIT++)
            {
                UniValue oneOffer(UniValue::VOBJ);
                oneOffer.pushKV("identityid", EncodeDestination(CIdentityID(rIT->first.first)));
                oneOffer.pushKV("price", ValueFromAmount(rIT->first.second));
                oneOffer.pushKV("offer", rIT->second);
                oneCategory.push_back(oneOffer);
            }

            if (oneCategory.size())
            {
                retVal.pushKV("currency_" + EncodeDestination(CIdentityID(currencyOrIdID)) + "_for_ids", oneCategory);
                oneCategory = UniValue(UniValue::VARR);
            }

            // buying currency with IDs is basically selling the ID for this currency
            for (auto rIT = uniBuyWithIDs.rbegin(); rIT != uniBuyWithIDs.rend(); rIT++)
            {
                UniValue oneOffer(UniValue::VOBJ);
                oneOffer.pushKV("identityid", EncodeDestination(CIdentityID(rIT->first.first)));
                oneOffer.pushKV("price", ValueFromAmount(rIT->first.second));
                oneOffer.pushKV("offer", rIT->second);
                oneCategory.push_back(oneOffer);
            }

            if (oneCategory.size())
            {
                retVal.pushKV("ids_for_currency_" + EncodeDestination(CIdentityID(currencyOrIdID)), oneCategory);
                oneCategory = UniValue(UniValue::VARR);
            }

            // we should order these by currency, showing both sellTo and buyWith in each currency together
            auto rSellIT = uniSellToCurrency.rbegin();
            auto rBuyIT = uniBuyWithCurrency.rbegin();
            uint160 lastCurrencyID;
            bool isBuyLast = false;

            while (rSellIT != uniSellToCurrency.rend() || rBuyIT != uniBuyWithCurrency.rend())
            {
                for (;
                    rSellIT != uniSellToCurrency.rend() &&
                        (rBuyIT == uniBuyWithCurrency.rend() || (rSellIT->first.first.GetHex() >= rBuyIT->first.first.GetHex()));
                    rSellIT++)
                {
                    uint160 newLast = rSellIT->first.first;
                    if (lastCurrencyID != newLast)
                    {
                        if (oneCategory.size())
                        {
                            retVal.pushKV("currency_" + EncodeDestination(CIdentityID(lastCurrencyID)) + "_offers_in_currency_" + EncodeDestination(CIdentityID(currencyOrIdID)), oneCategory);
                            oneCategory = UniValue(UniValue::VARR);
                        }
                        lastCurrencyID = newLast;
                    }
                    UniValue oneOffer(UniValue::VOBJ);
                    oneOffer.pushKV("currencyid", EncodeDestination(CIdentityID(rSellIT->first.first)));
                    oneOffer.pushKV("price", ValueFromAmount(rSellIT->first.second));
                    oneOffer.pushKV("offer", rSellIT->second);
                    oneCategory.push_back(oneOffer);
                    isBuyLast = false;
                }

                for (;
                    rBuyIT != uniBuyWithCurrency.rend() &&
                        (rSellIT == uniSellToCurrency.rend() || (rBuyIT->first.first.GetHex() >= lastCurrencyID.GetHex()));
                    rBuyIT++)
                {
                    uint160 newLast = rBuyIT->first.first;
                    if (lastCurrencyID != newLast)
                    {
                        if (oneCategory.size())
                        {
                            retVal.pushKV("currency_" + EncodeDestination(CIdentityID(currencyOrIdID)) + "_offers_in_currency_" + EncodeDestination(CIdentityID(lastCurrencyID)), oneCategory);
                            oneCategory = UniValue(UniValue::VARR);
                        }
                        lastCurrencyID = newLast;
                    }
                    UniValue oneOffer(UniValue::VOBJ);
                    oneOffer.pushKV("currencyid", EncodeDestination(CIdentityID(rBuyIT->first.first)));
                    oneOffer.pushKV("price", ValueFromAmount(rBuyIT->first.second));
                    oneOffer.pushKV("offer", rBuyIT->second);
                    oneCategory.push_back(oneOffer);
                    isBuyLast = true;
                }
            }
            if (oneCategory.size())
            {
                if (isBuyLast)
                {
                    retVal.pushKV("currency_" + EncodeDestination(CIdentityID(currencyOrIdID)) + "_offers_in_currency_" + EncodeDestination(CIdentityID(lastCurrencyID)), oneCategory);
                }
                else
                {
                    retVal.pushKV("currency_" + EncodeDestination(CIdentityID(lastCurrencyID)) + "_offers_in_currency_" + EncodeDestination(CIdentityID(currencyOrIdID)), oneCategory);
                }
            }
        }
        else
        {
            // for uniSellToIDs (same as offer to trade ID in question for other ID(s)) - offered in exchange for IDs
            // for uniBuyWithIDs (same as offer to trade other IDs for the ID in question) - IDs offered in exchange for

            // for uniSellToCurrency, offer(s) to sell for a specific currency at a specific price, list low to high in each currecny
            // uniBuyWithCurrency, offers to buy with a specific currency for a specific price, list high to low

            // for uniSellToIDs (same as this ID on offer for other IDs)
            UniValue oneCategory(UniValue::VARR);
            for (auto rIT = uniSellToIDs.rbegin(); rIT != uniSellToIDs.rend(); rIT++)
            {
                UniValue oneOffer(UniValue::VOBJ);
                oneOffer.pushKV("identityid", EncodeDestination(CIdentityID(rIT->first.first)));
                oneOffer.pushKV("price", ValueFromAmount(rIT->first.second));
                oneOffer.pushKV("offer", rIT->second);
                oneCategory.push_back(oneOffer);
            }

            if (oneCategory.size())
            {
                retVal.pushKV("id_" + EncodeDestination(CIdentityID(currencyOrIdID)) + "_for_ids", oneCategory);
                oneCategory = UniValue(UniValue::VARR);
            }

            for (auto rIT = uniBuyWithIDs.rbegin(); rIT != uniBuyWithIDs.rend(); rIT++)
            {
                UniValue oneOffer(UniValue::VOBJ);
                oneOffer.pushKV("identityid", EncodeDestination(CIdentityID(rIT->first.first)));
                oneOffer.pushKV("price", ValueFromAmount(rIT->first.second));
                oneOffer.pushKV("offer", rIT->second);
                oneCategory.push_back(oneOffer);
            }

            if (oneCategory.size())
            {
                retVal.pushKV("ids_for_id_" + EncodeDestination(CIdentityID(currencyOrIdID)), oneCategory);
                oneCategory = UniValue(UniValue::VARR);
            }

            // we should order these by currency, showing both sellTo and buyWith in each currency together
            auto rSellIT = uniSellToCurrency.rbegin();
            auto rBuyIT = uniBuyWithCurrency.rbegin();
            uint160 lastCurrencyID;
            bool isBuyLast = false;

            while (rSellIT != uniSellToCurrency.rend() || rBuyIT != uniBuyWithCurrency.rend())
            {

                for (;
                    rSellIT != uniSellToCurrency.rend() &&
                        (rBuyIT == uniBuyWithCurrency.rend() || (rSellIT->first.first.GetHex() >= rBuyIT->first.first.GetHex()));
                    rSellIT++)
                {
                    uint160 newLast = rSellIT->first.first;
                    if (lastCurrencyID != newLast)
                    {
                        if (oneCategory.size())
                        {
                            retVal.pushKV("id_" + EncodeDestination(CIdentityID(currencyOrIdID)) + "_for_currency_" + EncodeDestination(CIdentityID(lastCurrencyID)), oneCategory);
                            oneCategory = UniValue(UniValue::VARR);
                        }
                        lastCurrencyID = newLast;
                    }
                    UniValue oneOffer(UniValue::VOBJ);
                    oneOffer.pushKV("currencyid", EncodeDestination(CIdentityID(rSellIT->first.first)));
                    oneOffer.pushKV("price", ValueFromAmount(rSellIT->first.second));
                    oneOffer.pushKV("offer", rSellIT->second);
                    oneCategory.push_back(oneOffer);
                    isBuyLast = false;
                }

                for (;
                    rBuyIT != uniBuyWithCurrency.rend() &&
                        (rSellIT == uniSellToCurrency.rend() || (rBuyIT->first.first.GetHex() >= lastCurrencyID.GetHex()));
                    rBuyIT++)
                {
                    uint160 newLast = rBuyIT->first.first;
                    if (lastCurrencyID != newLast)
                    {
                        if (oneCategory.size())
                        {
                            retVal.pushKV("currency_" + EncodeDestination(CIdentityID(lastCurrencyID)) + "_for_id_" + EncodeDestination(CIdentityID(currencyOrIdID)), oneCategory);
                            oneCategory = UniValue(UniValue::VARR);
                        }
                        lastCurrencyID = newLast;
                    }
                    UniValue oneOffer(UniValue::VOBJ);
                    oneOffer.pushKV("currencyid", EncodeDestination(CIdentityID(rBuyIT->first.first)));
                    oneOffer.pushKV("price", ValueFromAmount(rBuyIT->first.second));
                    oneOffer.pushKV("offer", rBuyIT->second);
                    oneCategory.push_back(oneOffer);
                    isBuyLast = true;
                }
            }
            if (oneCategory.size())
            {
                if (isBuyLast)
                {
                    retVal.pushKV("currency_" + EncodeDestination(CIdentityID(lastCurrencyID)) + "_for_id_" + EncodeDestination(CIdentityID(currencyOrIdID)), oneCategory);
                }
                else
                {
                    retVal.pushKV("id_" + EncodeDestination(CIdentityID(currencyOrIdID)) + "_for_currency_" + EncodeDestination(CIdentityID(lastCurrencyID)), oneCategory);
                }
            }
        }
        return retVal;
    }
    return NullUniValue;
}

// close an offer by spending its source
bool CloseOneOffer(const OfferInfo &oneOffer, TransactionBuilder &tb, const CTxDestination &_dest, uint32_t height, const libzcash::PaymentAddress &zdest=libzcash::PaymentAddress());
bool CloseOneOffer(const OfferInfo &oneOffer, TransactionBuilder &tb, const CTxDestination &_dest, uint32_t height, const PaymentAddress &zdest)
{
    CTxDestination dest = _dest;
    // we just need to be able to spend the output to another input/output
    CScript outScript(oneOffer.inputToOfferTx.vout[oneOffer.offerTx.vin[0].prevout.n].scriptPubKey);
    CAmount value = oneOffer.inputToOfferTx.vout[oneOffer.offerTx.vin[0].prevout.n].nValue;
    tb.AddTransparentInput(COutPoint(oneOffer.offerTx.vin[0].prevout.hash, oneOffer.offerTx.vin[0].prevout.n), outScript, value);
    COptCCParams p;
    if (outScript.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        (p.evalCode == EVAL_IDENTITY_PRIMARY || p.evalCode == EVAL_IDENTITY_COMMITMENT) &&
        p.vData.size())
    {
        const libzcash::SaplingPaymentAddress *pSaplingAddress = boost::get<libzcash::SaplingPaymentAddress>(&zdest);
        bool hasZDest = pSaplingAddress != nullptr;
        bool hasTDest = dest.which() != COptCCParams::ADDRTYPE_INVALID;
        bool hasTokens = false;

        value -= std::min(DEFAULT_TRANSACTION_FEE, value);

        uint256 ovk;
        if (hasZDest)
        {
            HDSeed seed;
            if (!pwalletMain->GetHDSeed(seed)) {
                LogPrintf("%s: Wallet seed unavailable for z-address output\n", __func__);
                return false;
            }
            ovk = ovkForShieldingFromTaddr(seed);
            tb.SendChangeTo(*pSaplingAddress, ovk);
        }
        if (p.evalCode == EVAL_IDENTITY_PRIMARY)
        {
            CIdentity offeredIdentity(p.vData[0]);
            if (!offeredIdentity.IsValid())
            {
                LogPrintf("%s: Invalid identity\n", __func__);
                return false;
            }
            if (!hasTDest)
            {
                dest = CIdentityID(offeredIdentity.GetID());
                hasTDest = true;
            }
            offeredIdentity.UpgradeVersion(height);
            value -= std::min(DEFAULT_TRANSACTION_FEE, value);
            tb.AddTransparentOutput(offeredIdentity.IdentityUpdateOutputScript(height + 1), value);
        }
        else if (p.evalCode == EVAL_IDENTITY_COMMITMENT)
        {
            if (!hasTDest)
            {
                if (p.vKeys.size() > 1)
                {
                    LogPrintf("%s: No transparent destination specified and cannot determine from commitment\n", __func__);
                    return false;
                }
                dest = p.vKeys[0];
                hasTDest = true;
            }
            CCommitmentHash ch(p.vData[0]);
            if (ch.IsValid() && ch.reserveValues.valueMap.size())
            {
                hasTokens = true;
                if (hasZDest)
                {
                    tb.AddSaplingOutput(ovk, *pSaplingAddress, value);
                    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, {dest}, 1, (CTokenOutput *)&ch)), 0);
                }
                else if (dest.which() != COptCCParams::ADDRTYPE_INVALID)
                {
                    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, {dest}, 1, (CTokenOutput *)&ch)), value);
                }
                else
                {
                    LogPrintf("%s: Must close offers with valid, transparent funds destination when offer funds include non-native currency\n", __func__);
                    return false;
                }
            }
            else
            {
                if (hasZDest)
                {
                    tb.AddSaplingOutput(ovk, *pSaplingAddress, value);
                }
                else
                {
                    tb.AddTransparentOutput(dest, value);
                }
            }
        }
        if (hasTokens || !hasZDest)
        {
            tb.SendChangeTo(dest);
        }
    }
    return true;
}

UniValue closeoffers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
    {
        throw runtime_error(
            "closeoffers ('[\"offer1_txid\", \"offer2_txid\", ...]') (transparentorprivatefundsdestination) (privatefundsdestination)\n"
            "\nCloses all offers listed, if they are still valid and belong to this wallet.\n"
            "Always closes expired offers, even if no parameters are given\n\n"

            "\nArguments\n"
            "  [\"offer1_txid\", \"offer2_txid\", ...]      (array, optional) array of hex tx ids of offers to close\n"
            "  transparentorprivatefundsdestination         (transparent or private address, optional) destination for closing funds\n"
            "  privatefundsdestination                      (private address, optional) destination for native funds only\n"

            "\nResult\n"
            "  null return\n"
        );
    }
    CheckVerusVaultAPIsValid();

    UniValue retVal;
    std::set<uint256> txIds;

    if (params.size() > 0)
    {
        if (!params[0].isArray())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "First parameter must be an array of transaction IDs that are offers from this wallet to close. It may be null '[]'");
        }
        for (int i = 0; i < params[0].size(); i++)
        {
            uint256 oneTxId;
            oneTxId.SetHex(uni_get_str(params[0][i]));
            if (oneTxId.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid txid specified, txids must be hex strings with no prefix");
            }
            txIds.insert(oneTxId);
        }
    }

    libzcash::PaymentAddress zaddressDest;
    CTxDestination transparentDest;
    std::string destStr;

    if (params.size() > 1)
    {
        destStr = uni_get_str(params[1]);
        if (destStr.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Closing open offers requires a transparent and/or private address to send funds to when closing");
        }
        transparentDest = ValidateDestination(destStr);
    }

    bool hasTDest = transparentDest.which() != COptCCParams::ADDRTYPE_INVALID;
    bool hasZDest = !hasTDest && pwalletMain->GetAndValidateSaplingZAddress(destStr, zaddressDest, true);

    if (hasTDest)
    {
        if (params.size() > 2)
        {
            if (hasZDest)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Third parameter must be a private address and only one private address may be specified");
            }
            std::string zDestStr = uni_get_str(params[2]);

            if (!(hasZDest = pwalletMain->GetAndValidateSaplingZAddress(zDestStr, zaddressDest, true)))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Third parameter must be a valid private address");
            }
        }
    }

    std::map<std::pair<bool, uint256>, OfferInfo> myOffers;
    uint32_t height;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        LOCK(mempool.cs);
        height = chainActive.Height();
        GetMyOffers(myOffers, height, txIds.size() != 0, true);
    }

    for (auto &oneOffer : myOffers)
    {
        TransactionBuilder tb(Params().GetConsensus(), height + 1, pwalletMain);
        CTransaction oneTx;
        {
            LOCK(pwalletMain->cs_wallet);
            // if this is true, it is unexpired
            if (oneOffer.first.first && !txIds.count(oneOffer.first.second))
            {
                continue;
            }
            if (!CloseOneOffer(oneOffer.second, tb, transparentDest, height, zaddressDest))
            {
                continue;
            }
            TransactionBuilderResult buildResult = tb.Build();
            oneTx = buildResult.GetTxOrThrow();
        }
        LOCK(cs_main);

        bool relayTx;
        CValidationState state;
        {
            LOCK2(smartTransactionCS, mempool.cs);
            relayTx = myAddtomempool(oneTx, &state);
        }

        if (!relayTx)
        {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Close offer transaction rejected: " + state.GetRejectReason());
        }
        else
        {
            RelayTransaction(oneTx);
        }
    }
    return retVal;
}

UniValue listopenoffers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
    {
        throw runtime_error(
            "listopenoffers (unexpired) (expired)'\n"
            "\nShows offers outstanding in this wallet\n"

            "\nArguments\n"
            "  unexpired                (bool, optional) default=true, list those offers in the wallet which are not expired\n"
            "  expired                  (bool, optional) default=true, list those offers in the wallet which are expired\n"

            "\nResult\n"
            "  all open offers\n"
        );
    }
    CheckVerusVaultAPIsValid();

    UniValue retVal;
    std::set<uint256> txIds;

    bool listUnexpired = true;
    bool listExpired = true;
    if (params.size() > 0)
    {
        listUnexpired = uni_get_bool(params[0]);
    }
    if (params.size() > 1)
    {
        listExpired = uni_get_bool(params[1]);
    }

    std::map<std::pair<bool, uint256>, OfferInfo> myOffers;

    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(mempool.cs);

    uint32_t height = chainActive.Height();

    if (GetMyOffers(myOffers, height, listUnexpired, listExpired))
    {
        retVal = UniValue(UniValue::VARR);
        for (auto &oneOffer : myOffers)
        {
            UniValue oneOfferUni(UniValue::VOBJ);
            if (!oneOffer.first.first)
            {
                oneOfferUni.pushKV("expired", true);
            }
            else
            {
                oneOfferUni.pushKV("expires", (int64_t)oneOffer.second.offerTx.nExpiryHeight);
            }

            oneOfferUni.pushKV("txid", oneOffer.first.second.GetHex());
            UniValue scriptPubKeyUni(UniValue::VOBJ);
            ScriptPubKeyToUniv(oneOffer.second.inputToOfferTx.vout[oneOffer.second.offerTx.vin[0].prevout.n].scriptPubKey, scriptPubKeyUni, false);
            scriptPubKeyUni.pushKV("nativeout", ValueFromAmount(oneOffer.second.inputToOfferTx.vout[oneOffer.second.offerTx.vin[0].prevout.n].nValue));
            oneOfferUni.pushKV("offer", scriptPubKeyUni);
            scriptPubKeyUni = UniValue(UniValue::VOBJ);
            ScriptPubKeyToUniv(oneOffer.second.offerTx.vout[0].scriptPubKey, scriptPubKeyUni, false);
            scriptPubKeyUni.pushKV("nativeout", ValueFromAmount(oneOffer.second.offerTx.vout[0].nValue));
            oneOfferUni.pushKV("for", scriptPubKeyUni);
            retVal.push_back(oneOfferUni);
        }
    }
    return retVal;
}

bool IsValidExportCurrency(const CCurrencyDefinition &systemDest, const uint160 &exportCurrencyID, uint32_t height);

CAmount GetMinRelayFeeForBuilder(const TransactionBuilder &tb, CAmount identityFeeFactor, bool isIdentity)
{
    // Require that free transactions have sufficient priority to be mined in the next block.
    CAmount minFee = identityFeeFactor * DEFAULT_TRANSACTION_FEE;

    // if we have more z-outputs + t-outputs than are needed for 1 z-output and change, increase fee
    // we make allowance for 1 z-output or t-output, 1 native z-change, one token change, and 1 blacklisted change
    int idExtraLimit = 0;
    if (isIdentity)
    {
        for (auto &oneOut : tb.mtx.vout)
        {
            COptCCParams idP;
            if (oneOut.scriptPubKey.IsPayToCryptoCondition(idP) &&
                idP.evalCode == EVAL_IDENTITY_RESERVATION)
            {
                idExtraLimit = ConnectedChains.ThisChain().IDReferralLevels() + 2;
            }
            else if (idP.IsValid() &&
                        idP.evalCode == EVAL_IDENTITY_ADVANCEDRESERVATION)
            {
                CAdvancedNameReservation advNewName;
                if (!(idP.vData.size() && (advNewName = CAdvancedNameReservation(idP.vData[0])).IsValid()))
                {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Created invalid transaction.");
                }
                CCurrencyDefinition parentCurrency = advNewName.parent.IsNull() ? ConnectedChains.ThisChain() : ConnectedChains.GetCachedCurrency(advNewName.parent);
                idExtraLimit = parentCurrency.IDReferralLevels() + 2;
            }
        }
    }

    if (!minFee)
    {
        minFee = DEFAULT_TRANSACTION_FEE;
    }

    if (tb.mtx.vout.size() > (1 + idExtraLimit))
    {
        minFee += (std::max((int64_t)(tb.SpendCount() - 1), (int64_t)0) + std::max((int64_t)(tb.mtx.vout.size() - (1 + idExtraLimit)), (int64_t)0)) * DEFAULT_TRANSACTION_FEE;
    }
    else if (tb.mtx.vout.size() > idExtraLimit)
    {
        minFee += std::max((int64_t)(tb.SpendCount() - 1), (int64_t)0) * DEFAULT_TRANSACTION_FEE;
    }
    else
    {
        minFee += std::max((int64_t)(tb.SpendCount() - 2), (int64_t)0) * DEFAULT_TRANSACTION_FEE;
    }

    if (!(identityFeeFactor && tb.mtx.vout.size() <= (1 + idExtraLimit)))
    {
        int64_t extraOutputCostThreshold = CScript::MAX_SCRIPT_ELEMENT_SIZE / 3;
        for (auto &oneOut : tb.mtx.vout)
        {
            int64_t extraSize = std::max((int64_t)oneOut.scriptPubKey.size() - extraOutputCostThreshold, (int64_t)0);
            if (extraSize)
            {
                minFee += DEFAULT_TRANSACTION_FEE + ((extraSize - extraOutputCostThreshold) > 0 ? DEFAULT_TRANSACTION_FEE : 0);
            }
        }

        int64_t extraStorageSpace = 0;
        bool isStorageTx = false;
        bool isImport = false;
        bool isNotarizationPriority = false;

        for (int i = 0; i < tb.mtx.vout.size(); i++)
        {
            COptCCParams evP;

            auto &oneOut = tb.mtx.vout[i];
            int64_t extraSize = std::max((int64_t)oneOut.scriptPubKey.size() - extraOutputCostThreshold, (int64_t)0);
            bool isSC = oneOut.scriptPubKey.IsPayToCryptoCondition(evP) && evP.IsValid();

            isImport = isImport || (isSC && evP.evalCode == EVAL_CROSSCHAIN_IMPORT);
            isNotarizationPriority = isNotarizationPriority || (isSC && (evP.evalCode == EVAL_ACCEPTEDNOTARIZATION || evP.evalCode == EVAL_EARNEDNOTARIZATION || evP.evalCode == EVAL_FINALIZE_NOTARIZATION));
            isStorageTx = (isStorageTx || (isSC && evP.evalCode == EVAL_NOTARY_EVIDENCE)) && !isImport && !isNotarizationPriority;

            if (isStorageTx)
            {
                extraStorageSpace += oneOut.scriptPubKey.size();
            }
            else if (extraSize)
            {
                minFee += DEFAULT_TRANSACTION_FEE + ((extraSize - extraOutputCostThreshold) > 0 ? DEFAULT_TRANSACTION_FEE : 0);
            }
        }
        CScript opRetScript = tb.GetOpRet();
        if (opRetScript.size())
        {
            int64_t extraSize = std::max((int64_t)opRetScript.size() - extraOutputCostThreshold, (int64_t)0);
            COptCCParams evP;
            if (isStorageTx)
            {
                extraStorageSpace += (int64_t)opRetScript.size();
            }
            else if (extraSize)
            {
                minFee += DEFAULT_TRANSACTION_FEE + ((extraSize - extraOutputCostThreshold) > 0 ? DEFAULT_TRANSACTION_FEE : 0);
            }
        }
        minFee += (((int64_t)(extraStorageSpace)) * (STORAGE_FEE_FACTOR * ConnectedChains.ThisChain().transactionExportFee)) / CScript::MAX_SCRIPT_ELEMENT_SIZE;
    }
    return minFee;
}

CAmount GetMinRelayFeeForOutputs(const std::vector<SendManyRecipient> &tOutputs, const std::vector<SendManyRecipient> &zOutputs, CAmount identityFeeFactor, bool isIdentity)
{
    // Require that free transactions have sufficient priority to be mined in the next block.
    CAmount minFee = identityFeeFactor * DEFAULT_TRANSACTION_FEE;

    // if we have more z-outputs + t-outputs than are needed for 1 z-output and change, increase fee
    // we make allowance for 1 z-output or t-output, 1 native z-change, one token change, and 1 blacklisted change
    int idExtraLimit = 0;
    if (isIdentity)
    {
        for (auto &oneOut : tOutputs)
        {
            COptCCParams idP;
            if (std::get<3>(oneOut).IsPayToCryptoCondition(idP) &&
                idP.evalCode == EVAL_IDENTITY_RESERVATION)
            {
                idExtraLimit = ConnectedChains.ThisChain().IDReferralLevels() + 2;
            }
            else if (idP.IsValid() &&
                        idP.evalCode == EVAL_IDENTITY_ADVANCEDRESERVATION)
            {
                CAdvancedNameReservation advNewName;
                if (!(idP.vData.size() && (advNewName = CAdvancedNameReservation(idP.vData[0])).IsValid()))
                {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Created invalid transaction.");
                }
                CCurrencyDefinition parentCurrency = advNewName.parent.IsNull() ? ConnectedChains.ThisChain() : ConnectedChains.GetCachedCurrency(advNewName.parent);
                idExtraLimit = parentCurrency.IDReferralLevels() + 2;
            }
        }
    }

    if (!minFee)
    {
        minFee = DEFAULT_TRANSACTION_FEE;
    }

    if (tOutputs.size() > (1 + idExtraLimit))
    {
        minFee += (std::max((int64_t)(zOutputs.size() - 1), (int64_t)0) + std::max((int64_t)(tOutputs.size() - (1 + idExtraLimit)), (int64_t)0)) * DEFAULT_TRANSACTION_FEE;
    }
    else if (tOutputs.size() > idExtraLimit)
    {
        minFee += std::max((int64_t)(zOutputs.size() - 1), (int64_t)0) * DEFAULT_TRANSACTION_FEE;
    }
    else
    {
        minFee += std::max((int64_t)(zOutputs.size() - 2), (int64_t)0) * DEFAULT_TRANSACTION_FEE;
    }

    if (!(identityFeeFactor && tOutputs.size() <= (1 + idExtraLimit)))
    {
        bool isStorageTx = false;
        bool isImport = false;
        bool isNotarizationPriority = false;

        int64_t extraOutputCostThreshold = CScript::MAX_SCRIPT_ELEMENT_SIZE / 3;
        int64_t extraStorageSpace = 0;

        for (int i = 0; i < tOutputs.size(); i++)
        {
            auto &oneOut = tOutputs[i];

            COptCCParams evP;
            bool isSC = std::get<3>(oneOut).IsPayToCryptoCondition(evP) && evP.IsValid();

            isImport = isImport || (isSC && evP.evalCode == EVAL_CROSSCHAIN_IMPORT);
            isNotarizationPriority = isNotarizationPriority || (isSC && (evP.evalCode == EVAL_ACCEPTEDNOTARIZATION || evP.evalCode == EVAL_EARNEDNOTARIZATION || evP.evalCode == EVAL_FINALIZE_NOTARIZATION));
            isStorageTx = (isStorageTx || (isSC && evP.evalCode == EVAL_NOTARY_EVIDENCE)) && !isImport && !isNotarizationPriority;

            int64_t extraSize = std::max((int64_t)std::get<3>(oneOut).size() - extraOutputCostThreshold, (int64_t)0);
            bool isOpRet = (i == (tOutputs.size() - 1)) && std::get<3>(oneOut).IsOpReturn();
            if (extraSize || isStorageTx)
            {
                if (isStorageTx &&
                    ((extraSize && isOpRet) ||
                     (isSC && evP.evalCode == EVAL_NOTARY_EVIDENCE)))
                {
                    extraStorageSpace += (int64_t)std::get<3>(oneOut).size();
                }
                else if (extraSize)
                {
                    minFee += DEFAULT_TRANSACTION_FEE + ((extraSize - extraOutputCostThreshold) > 0 ? DEFAULT_TRANSACTION_FEE : 0);
                }
            }
        }
        minFee += (((int64_t)(extraStorageSpace)) * (STORAGE_FEE_FACTOR * ConnectedChains.ThisChain().transactionExportFee)) / CScript::MAX_SCRIPT_ELEMENT_SIZE;
    }
    return minFee;
}

UniValue sendcurrency(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 5)
    {
        throw runtime_error(
            "sendcurrency \"fromaddress\" '[{\"address\":... ,\"amount\":...},...]' (minconfs) (feeamount) (returntxtemplate)\n"
            "\nThis sends one or many Verus outputs to one or many addresses on the same or another chain.\n"
            "Funds are sourced automatically from the current wallet, which must be present, as in sendtoaddress.\n"
            "If \"fromaddress\" is specified, all funds will be taken from that address, otherwise funds may come\n"
            "from any source set of UTXOs controlled by the wallet.\n"

            "\nArguments\n"
            "1. \"fromaddress\"             (string, required) The Sapling, VerusID, or wildcard address to send funds from. \"*\", \"R*\", or \"i*\" are valid wildcards\n"
            "2. \"outputs\"                 (array, required) An array of json objects representing currencies, amounts, and destinations to send.\n"
            "    [{\n"
            "      \"currency\": \"name\"   (string, required) Name of the source currency to send in this output, defaults to native of chain\n"
            "      \"amount\":amount        (numeric, required) The numeric amount of currency, denominated in source currency\n"
            "      \"convertto\":\"name\",  (string, optional) Valid currency to convert to, either a reserve of a fractional, or fractional\n"
            "      \"addconversionfees\":\"false\", (bool, optional) Calculate additional conversion fees to convert the full amount specified after fees\n"
            "      \"exportto\":\"name\",   (string, optional) Valid chain or system name or ID to export to\n"
            "      \"exportid\":\"false\",  (bool, optional) if cross-chain export, export the full ID to the destination chain (will cost to export)\n"
            "      \"exportcurrency\":\"false\", (bool, optional) if cross-chain export, export the currency definition (will cost to export)\n"
            "      \"feecurrency\":\"name\", (string, optional) Valid currency that should be pulled from the current wallet and used to pay fee\n"
            "      \"via\":\"name\",        (string, optional) If source and destination currency are reserves, via is a common fractional to convert through\n"
            "      \"address\":\"dest\"     (string, required) The address and optionally chain/system after the \"@\" as a system specific destination\n"
            "      \"refundto\":\"dest\"    (string, optional) For pre-conversions, this is where refunds will go, defaults to fromaddress\n"
            "      \"memo\":memo            (string, optional) If destination is a zaddr (not supported on testnet), a string message (not hexadecimal) to include.\n"
            "      \"data\":\"dataobject\", (object, optional) (for data-only outputs with no other function) stores large, optionally signed data in one or more outputs.\n"
            "      \"preconvert\":\"false\", (bool,  optional) convert to currency at market price (default=false), only works if transaction is mined before start of currency\n"
            "      \"burn\":\"false\",      (bool,  optional) destroy the currency and subtract it from the supply. Currency must be a token.\n"
            "      \"mintnew\":\"false\",   (bool,  optional) if the transaction is sent from the currency ID of a centralized currency, this creates new currency to send\n"
            "    }, ... ]\n"
            "3. \"minconf\"                 (numeric, optional, default=1) only use funds confirmed at least this many times.\n"
            "4. \"feeamount\"               (number, optional) specific fee amount requested instead of default miner's fee\n"

            "\nResult:\n"
            "   \"operation-id\" : \"opid\" (string) The operation id, not public info, if (returntxtemplate) is false\n"
            "\n"
            "   If (returntxtemplate) is true"
            "   {\n"
            "       \"outputtotals\" : {currencyvaluemap}   Total outputs in all currencies that need to be input to the transaction\n"
            "       \"hextx\" : \"hexstring\"               The transaction with all specified outputs and no inputs\n"
            "   }\n"

            "\nExamples:\n"
            + HelpExampleCli("sendcurrency", "\"*\" '[{\"currency\":\"btc\",\"address\":\"RRehdmUV7oEAqoZnzEGBH34XysnWaBatct\" ,\"amount\":500.0},...]'")
            + HelpExampleRpc("sendcurrency", "\"bob@\", [{\"currency\":\"btc\", \"address\":\"alice@quad\", \"amount\":500.0},...]")
        );
    }

    std::string sourceAddress = uni_get_str(params[0]);
    CTxDestination sourceDest;

    bool wildCardTransparentAddress = sourceAddress == "*";
    bool wildCardRAddress = sourceAddress == "R*";
    bool wildCardiAddress = sourceAddress == "i*";
    bool wildCardAddress = wildCardTransparentAddress || wildCardRAddress || wildCardiAddress;

    bool isVerusActive = IsVerusActive();
    CCurrencyDefinition &thisChain = ConnectedChains.ThisChain();
    uint160 thisChainID = thisChain.GetID();
    bool toFractional = false;
    bool fromFractional = false;

    std::vector<CRecipient> outputs;
    std::set<libzcash::PaymentAddress> zaddrDestSet;

    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(mempool.cs);

    libzcash::PaymentAddress zaddress;
    bool hasZSource = !wildCardAddress && pwalletMain->GetAndValidateSaplingZAddress(sourceAddress, zaddress, true);
    // if we have a z-address as a source, re-encode it to a string, which is used
    // by the async operation, to ensure that we don't need to lookup IDs in that operation
    if (hasZSource)
    {
        zaddrDestSet.insert(zaddress);
        sourceAddress = EncodePaymentAddress(zaddress);
    }

    if (!(hasZSource ||
          wildCardAddress ||
          (sourceDest = DecodeDestination(sourceAddress)).which() != COptCCParams::ADDRTYPE_INVALID))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. First parameter must be sapling address, transparent address, identity, \"*\", \"R*\", or \"i*\",. See help.");
    }

    if (!params[1].isArray() || !params[1].size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. Second parameter must be array of outputs. See help.");
    }

    int minConfs = 0;
    if (params.size() > 2)
    {
        minConfs = uni_get_int(params[2]);
    }

    int numHeavyOutputs = 0;

    uint32_t height = chainActive.Height();

    bool returnTx = params.size() > 4 ? uni_get_bool(params[4]) : false;

    if (!returnTx && sourceDest.which() == COptCCParams::ADDRTYPE_ID && !GetDestinationID(sourceDest).IsNull())
    {
        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
        if (!pwalletMain->GetIdentity(GetDestinationID(sourceDest), keyAndIdentity) ||
            !keyAndIdentity.second.IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid identity or identity not in wallet");
        }
        if (keyAndIdentity.second.IsLocked(height + 1))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot send currency from a locked identity");
        }
    }

    const UniValue &uniOutputs = params[1];

    TransactionBuilder tb(Params().GetConsensus(), height + 1, returnTx ? nullptr : pwalletMain);
    std::vector<SendManyRecipient> tOutputs;
    std::vector<SendManyRecipient> zOutputs;

    bool hasOpRet = false;

    static std::set<std::string> paramSet({"currency", "amount", "convertto", "exportto", "feecurrency", "via", "address", "exportid", "exportcurrency", "refundto", "memo", "preconvert",  "burn", "burnweight", "mintnew", "addconversionfees", "opret", "data", "vdxftag"});

    //printf("%s: params[1]: %s\n", __func__, params[1].write(1,2).c_str());

    try
    {
        for (int i = 0; i < uniOutputs.size(); i++)
        {
            auto allKeys = uniOutputs[i].getKeys();
            for (auto oneKey : allKeys)
            {
                if (!paramSet.count(oneKey))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid parameter : " + oneKey);
                }
            }

            auto opRetHex = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "opret")));
            CAmount sourceAmount = AmountFromValue(find_value(uniOutputs[i], "amount"));
            auto destStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "address")), true, "\\/*?\"<>|");
            auto vdxfTag = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "vdxftag")), true, "\\/*?\"<>|");
            auto exportId = uni_get_bool(find_value(uniOutputs[i], "exportid"));
            auto exportCurrency = uni_get_bool(find_value(uniOutputs[i], "exportcurrency"));
            auto refundToStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "refundto")));
            auto memoUni = find_value(uniOutputs[i], "memo");
            auto memoStr = uni_get_str(memoUni);
            UniValue dataUni;
            dataUni = find_value(uniOutputs[i], "data");
            bool preConvert = uni_get_bool(find_value(uniOutputs[i], "preconvert"));
            bool burnCurrency = uni_get_bool(find_value(uniOutputs[i], "burn")) || uni_get_bool(find_value(uniOutputs[i], "burnweight"));
            bool burnWeight = uni_get_bool(find_value(uniOutputs[i], "burnweight"));
            bool mintNew = uni_get_bool(find_value(uniOutputs[i], "mintnew"));
            bool addConversionFees = uni_get_bool(find_value(uniOutputs[i], "addconversionfees"));

            auto rawCurrencyStr = uni_get_str(find_value(uniOutputs[i], "currency"));
            auto currencyStr = TrimSpaces(rawCurrencyStr, true);
            auto rawConvertToStr = uni_get_str(find_value(uniOutputs[i], "convertto"));
            auto convertToStr = TrimSpaces(rawConvertToStr, true);
            auto rawExportToStr = uni_get_str(find_value(uniOutputs[i], "exportto"));
            auto exportToStr = TrimSpaces(rawExportToStr, true);
            auto rawFeeCurrencyStr = uni_get_str(find_value(uniOutputs[i], "feecurrency"));
            auto feeCurrencyStr = TrimSpaces(rawFeeCurrencyStr, true);
            auto rawViaStr = uni_get_str(find_value(uniOutputs[i], "via"));
            auto viaStr = TrimSpaces(rawViaStr, true);

            if (rawCurrencyStr != currencyStr ||
                rawConvertToStr != convertToStr ||
                rawExportToStr != exportToStr ||
                rawFeeCurrencyStr != feeCurrencyStr ||
                rawViaStr != viaStr)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "all currency names specified must be valid with no leading or trailing spaces");
            }

            bool hasPBaaSParams = currencyStr.size() ||
                                  convertToStr.size() ||
                                  exportToStr.size() ||
                                  feeCurrencyStr.size() ||
                                  viaStr.size() ||
                                  refundToStr.size() ||
                                  preConvert ||
                                  mintNew ||
                                  exportId ||
                                  exportCurrency ||
                                  burnCurrency;

            if (hasPBaaSParams)
            {
                CheckPBaaSAPIsValid();
            }

            if (opRetHex.size())
            {
                if (hasOpRet ||
                    hasPBaaSParams ||
                    destStr.size() ||
                    sourceAmount ||
                    !IsHex(opRetHex))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "If opret is specified on output, there must only be one, and it must include only hex data and no other parameters for that output");
                }
                hasOpRet = true;
                CScript opRetScript;
                opRetScript << ParseHex(opRetHex);
                tb.AddOpRet(opRetScript);
                continue;
            }

            std::vector<CTxDestination> *pIndexDests = nullptr;
            std::vector<CTxDestination> indexDests;

            // only x-addresses can be vdxf tags
            if (!vdxfTag.empty())
            {
                CTxDestination vdxfTagDest = DecodeDestination(vdxfTag);
                if (vdxfTagDest.which() != COptCCParams::ADDRTYPE_INDEX)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "If vdxfTag is specified, it must be an \"X\" address, also called an indexId (see getvdxfid)");
                }
                indexDests.push_back(vdxfTagDest);
                pIndexDests = &indexDests;
            }

            CCurrencyDefinition sourceCurrencyDef;
            uint160 sourceCurrencyID;
            if (currencyStr != "")
            {
                sourceCurrencyID = ValidateCurrencyName(currencyStr, true, &sourceCurrencyDef);
                if (sourceCurrencyID.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "If source currency is specified, it must be valid.");
                }
            }
            else
            {
                sourceCurrencyDef = thisChain;
                sourceCurrencyID = sourceCurrencyDef.GetID();
                currencyStr = thisChain.name;
            }

            if (hasZSource && sourceCurrencyID != ASSETCHAINS_CHAINID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Only native " + thisChain.name + " currency can be sourced from a z-address.");
            }

            libzcash::PaymentAddress zaddressDest;
            bool hasZDest = pwalletMain->GetAndValidateSaplingZAddress(destStr, zaddressDest, true);
            if (hasZDest &&
                (convertToStr.size() ||
                 viaStr.size() ||
                 exportToStr.size() ||
                 burnCurrency ||
                 mintNew ||
                 preConvert ||
                 sourceCurrencyID != ASSETCHAINS_CHAINID))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert, preconvert, mint, cross-chain send, burn or send non-native currency when sending to a z-address.");
            }

            // re-encode destination, in case it is specified as the private address of an ID
            if (hasZDest)
            {
                if (pIndexDests)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot add vdxfTag to z-address destination");
                }

                // no duplicate z-address destinations
                if (zaddrDestSet.count(zaddressDest))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot duplicate private address source or destination");
                }
                numHeavyOutputs++;
                zaddrDestSet.insert(zaddressDest);
                destStr = EncodePaymentAddress(zaddressDest);
            }
            else if (!dataUni.isNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot use data parameter unless sending to a private address");
            }

            CCurrencyDefinition convertToCurrencyDef;
            uint160 convertToCurrencyID;
            if (convertToStr != "")
            {
                convertToCurrencyID = ValidateCurrencyName(convertToStr, true, &convertToCurrencyDef);
                if (convertToCurrencyID == sourceCurrencyID)
                {
                    convertToCurrencyID.SetNull();
                    convertToCurrencyDef = CCurrencyDefinition();
                }
                else
                {
                    if (convertToCurrencyID.IsNull())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "If currency conversion is requested, destination currency must be valid.");
                    }
                    if (burnCurrency)
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert and burn currency in a single operation. First convert, then burn.");
                    }
                }
            }

            CCurrencyDefinition secondCurrencyDef;
            uint160 secondCurrencyID;
            bool isVia = false;
            bool isConversion = false;

            if (viaStr != "")
            {
                secondCurrencyID = ValidateCurrencyName(viaStr, true, &secondCurrencyDef);
                std::map<uint160, int32_t> viaIdxMap = secondCurrencyDef.GetCurrenciesMap();
                if (secondCurrencyID.IsNull() ||
                    sourceCurrencyID.IsNull() ||
                    !secondCurrencyDef.IsFractional() ||
                    (!convertToCurrencyID.IsNull() &&
                     !burnCurrency &&
                     (secondCurrencyID == sourceCurrencyID ||
                      secondCurrencyID == convertToCurrencyID ||
                      sourceCurrencyID == convertToCurrencyID ||
                      !viaIdxMap.count(convertToCurrencyID))) ||
                    !(viaIdxMap.count(sourceCurrencyID) ||
                      sourceCurrencyID == secondCurrencyID ||
                      convertToStr.empty()))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "To specify a fractional currency converter, \"currency\" and \"convertto\" must both be reserves of \"via\"");
                }
                if (mintNew || preConvert)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot combine reserve to reserve conversion with minting or preconversion");
                }
                if (convertToCurrencyID.IsNull())
                {
                    convertToCurrencyDef = secondCurrencyDef;
                    convertToCurrencyID = convertToCurrencyDef.GetID();
                    secondCurrencyDef = CCurrencyDefinition();
                    secondCurrencyID = uint160();
                }
                else
                {
                    CCurrencyDefinition tempDef = convertToCurrencyDef;
                    convertToCurrencyDef = secondCurrencyDef;
                    secondCurrencyDef = tempDef;
                    convertToCurrencyID = convertToCurrencyDef.GetID();
                    secondCurrencyID = secondCurrencyDef.GetID();
                    isConversion = true;
                }
                isVia = true;
            }
            else if (!convertToCurrencyID.IsNull())
            {
                isConversion = true;
            }

            // send a reserve transfer preconvert
            uint32_t flags = CReserveTransfer::VALID;
            if (burnCurrency)
            {
                if (convertToCurrencyDef.IsValid() && convertToCurrencyDef.IsFractional())
                {
                    if (mintNew || isConversion ||
                        !(convertToCurrencyID == sourceCurrencyID || convertToCurrencyDef.GetCurrenciesMap().count(sourceCurrencyID)))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot mint and burn currency in a single operation.");
                    }
                    if (convertToCurrencyID != sourceCurrencyID)
                    {
                        if (burnWeight)
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Change weight while burning reserves not implemented.");
                        }
                    }
                    flags |= burnWeight ? CReserveTransfer::BURN_CHANGE_WEIGHT : CReserveTransfer::BURN_CHANGE_PRICE;
                }
                else
                {
                    if (mintNew || isConversion ||
                        !convertToCurrencyID.IsNull() ||
                        !(sourceCurrencyDef.IsFractional() || sourceCurrencyDef.IsToken()))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert and burn currency in a single operation. First convert, then burn.");
                    }
                    flags |= burnWeight ? CReserveTransfer::BURN_CHANGE_WEIGHT : CReserveTransfer::BURN_CHANGE_PRICE;
                    convertToCurrencyID = sourceCurrencyID;
                    convertToCurrencyDef = sourceCurrencyDef;
                }
            }

            std::string systemDestStr;
            uint160 destSystemID = thisChainID;
            CCurrencyDefinition destSystemDef;
            std::vector<std::string> subNames;

            CCurrencyDefinition exportToCurrencyDef;
            uint160 exportToCurrencyID;

            toFractional = isConversion &&
                           convertToCurrencyDef.IsValid() &&
                           convertToCurrencyDef.IsFractional() &&
                           convertToCurrencyDef.GetCurrenciesMap().count(sourceCurrencyID);
            fromFractional = isConversion &&
                             !toFractional &&
                             sourceCurrencyDef.IsFractional() && !convertToCurrencyID.IsNull() && sourceCurrencyDef.GetCurrenciesMap().count(convertToCurrencyID);

            CCurrencyDefinition converterCurrency = fromFractional ? sourceCurrencyDef : (toFractional ? convertToCurrencyDef : CCurrencyDefinition());

            if (addConversionFees && isConversion)
            {
                CAmount additionalFee = CReserveTransactionDescriptor::CalculateAdditionalConversionFeeNoMin(sourceAmount);
                if (isVia)
                {
                    additionalFee <<= 1;
                }
                sourceAmount += additionalFee;
            }

            if (toFractional || preConvert)
            {
                destSystemID = convertToCurrencyDef.systemID;
            }
            else if (fromFractional)
            {
                destSystemID = sourceCurrencyDef.systemID;
            }
            else if (!hasZDest)
            {
                // check for explicit system name specified
                subNames = ParseSubNames(destStr, systemDestStr, true);
                if (systemDestStr != "")
                {
                    destSystemID = ValidateCurrencyName(systemDestStr, true, &destSystemDef);
                    if (destSystemID.IsNull() || destSystemDef.IsToken() || destSystemDef.systemID != destSystemDef.GetID())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "If destination system is specified, destination system or chain must be registered.");
                    }
                    if (exportToStr == "")
                    {
                        exportToStr = systemDestStr;
                        exportToCurrencyID = destSystemID;
                        exportToCurrencyDef = destSystemDef;
                    }
                }
            }
            else
            {
                // things you can't do with a z-destination yet
                if (exportToStr.size() ||
                    isConversion ||
                    burnCurrency ||
                    preConvert ||
                    mintNew)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid operations for z-address destination");
                }
            }

            if (!destSystemDef.IsValid() && !destSystemID.IsNull())
            {
                destSystemDef = ConnectedChains.GetCachedCurrency(destSystemID);
            }

            // see if we should send this currency off-chain. if our target is a fractional currency and can convert but lives on another system,
            // we will not implicitly send it off chain for conversion, even if via is specified. "exportto" requests an explicit system
            // export/import before the operation.
            CCurrencyDefinition exportSystemDef;
            if (exportToStr != "")
            {
                uint160 explicitExportID = ValidateCurrencyName(exportToStr, true, &exportToCurrencyDef);
                if (!exportToCurrencyDef.IsValid() || (!exportToCurrencyID.IsNull() && exportToCurrencyID != explicitExportID))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Duplicate or invalid export system/currency destinations that do not match");
                }
                // if we have a converter currency on the same chain as the explicit export, the converter is
                // our actual export currency
                bool hasConverter = converterCurrency.IsValid();
                if (hasConverter && converterCurrency.systemID == exportToCurrencyDef.SystemOrGatewayID())
                {
                    exportToCurrencyDef = converterCurrency;
                    exportToCurrencyID = converterCurrency.GetID();
                }
                else if (hasConverter && converterCurrency.systemID != ASSETCHAINS_CHAINID)
                {
                    // if the converter is neither on this chain nor the explicit export chain, fail
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Export system and converter currency destinations do not match");
                }
                else
                {
                    exportToCurrencyID = explicitExportID;
                }

                if (exportToCurrencyDef.SystemOrGatewayID() == ASSETCHAINS_CHAINID)
                {
                    exportToStr = "";
                    exportToCurrencyID.SetNull();
                }
            }
            else if ((toFractional && convertToCurrencyDef.IsValid() && convertToCurrencyDef.systemID != ASSETCHAINS_CHAINID) || (fromFractional && sourceCurrencyDef.systemID != ASSETCHAINS_CHAINID))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot implicitly convert with a cross-chain send without explicitly specifying the \"exportto\" parameter");
            }
            if (!exportToCurrencyID.IsNull())
            {
                if (exportToCurrencyID == exportToCurrencyDef.systemID ||
                    (exportToCurrencyDef.IsGateway() && exportToCurrencyID == exportToCurrencyDef.GetID()))
                {
                    exportSystemDef = exportToCurrencyDef;
                }
                else
                {
                    exportSystemDef = ConnectedChains.GetCachedCurrency(exportToCurrencyDef.systemID);
                    if (!exportSystemDef.IsValid() ||
                        (exportSystemDef.systemID != exportSystemDef.GetID() &&
                         !(exportSystemDef.IsGateway() && exportSystemDef.systemID == thisChainID && exportSystemDef.gatewayID == exportSystemDef.GetID())))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid export system definition");
                    }
                }
            }

            // if we have no explicit destination system and non-null export, make export
            // our destination system
            if (destSystemID == ASSETCHAINS_CHAINID &&
                !(converterCurrency.IsValid() && converterCurrency.systemID == ASSETCHAINS_CHAINID) &&
                !exportToCurrencyID.IsNull())
            {
                destSystemID = exportSystemDef.GetID();
                destSystemDef = exportSystemDef;
            }

            // this only applies to the first step, if
            // first step is on-chain convert, then second is off chain, this will be false
            bool sendOffChain = (destSystemID != ASSETCHAINS_CHAINID) || (!exportToCurrencyID.IsNull() && exportToCurrencyID != ASSETCHAINS_CHAINID);
            bool convertBeforeOffChain = sendOffChain && (destSystemID == ASSETCHAINS_CHAINID);

            uint160 feeCurrencyID;
            CCurrencyDefinition feeCurrencyDef;
            if (feeCurrencyStr != "")
            {
                feeCurrencyID = ValidateCurrencyName(feeCurrencyStr, true, &feeCurrencyDef);
                if (!feeCurrencyID.IsNull())
                {
                    CCurrencyValueMap validFeeCurrencies;
                    if (!destSystemDef.launchSystemID.IsNull() && destSystemDef.IsMultiCurrency())
                    {
                        validFeeCurrencies.valueMap[destSystemDef.launchSystemID] = 1;
                    }

                    CCurrencyDefinition tmpConverterDef;
                    if (!preConvert)
                    {
                        validFeeCurrencies.valueMap[destSystemID] = 1;
                        if (feeCurrencyID != destSystemID && (convertToCurrencyID.IsNull() || convertBeforeOffChain))
                        {
                            tmpConverterDef =
                                fromFractional ?
                                    sourceCurrencyDef :
                                    (convertBeforeOffChain ?
                                        convertToCurrencyDef :
                                        (exportToCurrencyDef.IsFractional() ?
                                            exportToCurrencyDef :
                                            (exportToCurrencyDef.GatewayConverterID().IsNull() &&
                                            exportToCurrencyID == thisChain.launchSystemID &&
                                            !thisChain.GatewayConverterID().IsNull() ?
                                                ConnectedChains.GetCachedCurrency(thisChain.GatewayConverterID()) :
                                                CCurrencyDefinition())));
                        }
                        else
                        {
                            tmpConverterDef = convertToCurrencyDef;
                        }
                    }

                    if (tmpConverterDef.IsValid() &&
                        (tmpConverterDef.systemID == ASSETCHAINS_CHAINID || tmpConverterDef.systemID == destSystemID))
                    {
                        validFeeCurrencies.valueMap[tmpConverterDef.GetID()] = 1;
                        for (auto &oneCur : tmpConverterDef.currencies)
                        {
                            validFeeCurrencies.valueMap[oneCur] = 1;
                        }
                    }
                    if (!validFeeCurrencies.valueMap.count(feeCurrencyID))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid fee currency specified");
                    }
                }
                else
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid fee currency specified");
                }
            }
            else
            {
                feeCurrencyDef = ConnectedChains.ThisChain();
                feeCurrencyID = thisChainID;
            }

            // if we are already converting or processing through some currency, that can only be done on its native system
            // and may imply an export off-chain. before creating an off-chain export, we need an explicit "exportto" command that matches.
            // we may also have an "exportafter" command, which enables funding a second leg to up to one more system

            if ((burnWeight &&
                 (!converterCurrency.IsValid() ||
                  (converterCurrency.endBlock > 0 &&
                   converterCurrency.endBlock <= height))) ||
                (mintNew &&
                 (!sourceCurrencyDef.IsValid() ||
                  (sourceCurrencyDef.endBlock > 0 &&
                   sourceCurrencyDef.endBlock <= height))))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(burnWeight ? "burnchangeweight" : "minting") + " is disallowed, even by currency ID after the currency endblock");
            }

            // ensure that any initial export is explicit
            if (sendOffChain && !exportToCurrencyID.IsNull() &&
                !exportToCurrencyDef.IsGateway() &&
                !(exportToCurrencyDef.systemID == destSystemID || (convertBeforeOffChain && destSystemID == ASSETCHAINS_CHAINID)))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Conflicting target system for send -- \"exportto\" must be consistent with any other cross-chain currency targets");
            }
            else if (!exportToCurrencyID.IsNull() &&
                     exportToCurrencyID != thisChainID &&
                     !preConvert)
            {
                if (mintNew)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Cross-system mint operations not supported");
                }

                if (isConversion &&
                    !(((exportToCurrencyDef.IsGateway() || exportToCurrencyDef.IsPBaaSChain()) &&
                       (converterCurrency.systemID == ASSETCHAINS_CHAINID &&
                        converterCurrency.GetID() != exportToCurrencyID &&
                        converterCurrency.IsFractional() &&
                        converterCurrency.GetCurrenciesMap().count(exportToCurrencyDef.systemID) &&
                        converterCurrency.GetCurrenciesMap().count(feeCurrencyID) &&
                        converterCurrency.GetCurrenciesMap().count(toFractional ? sourceCurrencyID : convertToCurrencyID))) ||
                      (convertToCurrencyID == exportToCurrencyDef.GetID() &&
                       exportToCurrencyDef.systemID == destSystemID)))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid export syntax. Fractional converter must be from current chain before \"exportto\" a system currency or if on the alternate system, then that system must be the same destination as \"exportto\".");
                }

                // if fee currency is the export system destination
                // don't see if we should route through a converter
                if (feeCurrencyID == destSystemID)
                {
                    // if we also have an explicit conversion, we must verify that we can either do that on this chain
                    // first and then pass through or pass to the converter currency on the other system
                    if (converterCurrency.IsValid())
                    {
                        if (converterCurrency.systemID != destSystemID &&
                            (converterCurrency.systemID != ASSETCHAINS_CHAINID ||
                             !converterCurrency.IsFractional()) ||
                             (exportSystemDef.IsValid() &&
                              feeCurrencyID != exportSystemDef.GetID() &&
                              !converterCurrency.GetCurrenciesMap().count(exportSystemDef.GetID())))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency " +
                                                                    EncodeDestination(CIdentityID(convertToCurrencyID)) +
                                                                    " is not capable of converting " +
                                                                    EncodeDestination(CIdentityID(feeCurrencyID)) +
                                                                    " to " +
                                                                    EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)));
                        }
                    }
                }
                else if (convertToCurrencyID.IsNull())
                {
                    convertToCurrencyID =
                        exportToCurrencyDef.IsFractional() ?
                        exportToCurrencyID :
                        (exportToCurrencyDef.GatewayConverterID().IsNull() &&
                         exportToCurrencyID == thisChain.launchSystemID && !thisChain.GatewayConverterID().IsNull() ?
                            thisChain.GatewayConverterID() :
                            (exportToCurrencyDef.GatewayConverterID().IsNull() ? uint160() : exportToCurrencyDef.GatewayConverterID()));
                    if (convertToCurrencyID.IsNull() && (convertToCurrencyID = ConnectedChains.ThisChain().GatewayConverterID()).IsNull())
                    {
                        convertToCurrencyID = exportToCurrencyID;
                        convertToCurrencyDef = exportToCurrencyDef;
                    }
                    else
                    {
                        // get gateway converter and set as fee converter/exportto currency
                        convertToCurrencyDef = ConnectedChains.GetCachedCurrency(convertToCurrencyID);
                    }
                    if (!convertToCurrencyDef.IsValid())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "No available fee converter.");
                    }
                    if (convertToCurrencyID != exportToCurrencyID && convertToCurrencyDef.systemID == exportToCurrencyID)
                    {
                        exportToCurrencyID = convertToCurrencyID;
                        exportToCurrencyDef = convertToCurrencyDef;
                    }
                    bool toCurrencyIsFractional = convertToCurrencyDef.IsFractional();
                    if (!convertToCurrencyDef.IsValid() ||
                        (!((convertToCurrencyDef.IsPBaaSChain() && (feeCurrencyID == destSystemDef.launchSystemID ||
                            feeCurrencyID == destSystemID))) &&
                         !(toCurrencyIsFractional && convertToCurrencyDef.GetCurrenciesMap().count(feeCurrencyID) ||
                            convertToCurrencyDef.GetID() == feeCurrencyID)))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid fee currency for system destination.");
                    }
                    // if we are inserting a converter on the current chain, before the destination, adjust
                    if (convertToCurrencyDef.systemID == ASSETCHAINS_CHAINID)
                    {
                        convertBeforeOffChain = true;
                        destSystemID = thisChainID;
                        destSystemDef = thisChain;
                    }
                }
            }

            if (mintNew &&
                (!(sourceCurrencyDef.IsToken() &&
                   !sourceCurrencyDef.NoIDs() &&
                   GetDestinationID(sourceDest) == sourceCurrencyID &&
                   sourceCurrencyDef.proofProtocol == sourceCurrencyDef.PROOF_CHAINID &&
                   destSystemID == thisChainID &&
                   !preConvert &&
                   convertToCurrencyID.IsNull())))
            {
                // attempt to mint currency that isn't under the source ID's control
                if (!sourceCurrencyDef.IsToken() || sourceCurrencyDef.NoIDs())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency for minting");
                }
                if (preConvert || !convertToCurrencyID.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Minting cannot be combined with conversion.");
                }
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Only the ID of a mintable currency can mint such a currency on its system chain.");
            }

            if (hasZDest)
            {
                // if this is a data output, make one or more auxilliary data outputs
                if (dataUni.isObject())
                {
                    std::string dataLabel;
                    if (!memoUni.isNull())
                    {
                        // if memo starts with "#", convert it from a string to a hex value
                        if (memoStr.size() > 1 && memoStr[0] == '#')
                        {
                            // make a string out of the chars without the "#"
                            dataLabel = std::string(memoStr.begin() + 1, memoStr.end());
                        }
                        else
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid memo not starting with '#' as label combined with data parameter for data output #" + std::to_string(i));
                        }
                    }

                    if (!find_value(dataUni, "encrypttoaddress").isNull())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Data output may only be sent to a z-address, is always encrypted, and may not have an explicit ecrypttoaddress option");
                    }

                    dataUni.pushKV("encrypttoaddress", EncodePaymentAddress(zaddressDest));

                    auto createMMR = find_value(dataUni, "createmmr");
                    if (createMMR.isNull())
                    {
                        createMMR = true;
                        dataUni.pushKV("createmmr", createMMR);
                    }
                    if (!uni_get_bool(createMMR))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "If root signature is specified for data storage, it must be true");
                    }

                    UniValue signParams(UniValue::VARR);
                    signParams.push_back(dataUni);
                    UniValue signResult = signdata(signParams, false);

                    // now, we have both a CMMRDescriptor as well as a CSignatureData if we signed, all encrypted to the specified Z-address
                    CMMRDescriptor MMRDesc = CMMRDescriptor(find_value(signResult, "mmrdescriptor_encrypted"));
                    CSignatureData SignatureData = CSignatureData(find_value(signResult, "signaturedata_encrypted"));

                    // if the MMR data isn't valid, we have nothing to store
                    if (!MMRDesc.IsValid() || !MMRDesc.dataDescriptors.size())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "No valid data for data object # " + std::to_string(i));
                    }

                    CVDXF_Data vdxfData(CVDXF_Data::VERSION_INVALID);
                    CVDXF_Data vdxfSignature(CVDXF_Data::VERSION_INVALID);

                    // if we only have one object, the MMR is that salted object, remove the overhead
                    if (MMRDesc.dataDescriptors.size() == 1)
                    {
                        vdxfData = CVDXF_Data(CVDXF_Data::DataDescriptorKey(), ::AsVector(MMRDesc.dataDescriptors[0]));
                    }
                    else
                    {
                        vdxfData = CVDXF_Data(CVDXF_Data::MMRDescriptorKey(), ::AsVector(MMRDesc));
                    }
                    if (SignatureData.IsValid())
                    {
                        vdxfSignature = CVDXF_Data(CVDXF_Data::SignatureDataKey(), ::AsVector(SignatureData));
                    }

                    CNotaryEvidence evidenceData(ASSETCHAINS_CHAINID, CUTXORef(uint256(), 0), CNotaryEvidence::STATE_SUPPORTING, CCrossChainProof(), CNotaryEvidence::TYPE_IMPORT_PROOF);
                    evidenceData.evidence << CEvidenceData(CVDXF_Data::DataDescriptorKey(), ::AsVector(vdxfData));
                    if (vdxfSignature.IsValid())
                    {
                        evidenceData.evidence << CEvidenceData(CVDXF_Data::SignatureDataKey(), ::AsVector(vdxfSignature));
                    }

                    CCcontract_info CC;
                    CCcontract_info *cp;

                    // now add the notary evidence and finalization that uses it to assert validity
                    // make the evidence notarization output
                    cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
                    std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});

                    std::vector<int32_t> evidenceOuts;

                    COptCCParams chkP;
                    if (!MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &evidenceData)).IsPayToCryptoCondition(chkP, false))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to package evidence script in data output #" + std::to_string(i));
                    }

                    CVDXFDataRef memoLink(uint256(), tOutputs.size(), 0);
                    std::vector<unsigned char> memoData = ::AsVector(CVDXFDataDescriptor(::AsVector(memoLink), uni_get_str(find_value(dataUni, "label")), uni_get_str(find_value(dataUni, "mimetype"))));
                    if (vdxfSignature.IsValid())
                    {
                        memoLink = CVDXFDataRef(uint256(), tOutputs.size(), 0, 1);
                        std::vector<unsigned char> memoSig = ::AsVector(CVDXFDataDescriptor(::AsVector(memoLink), "signature", "application/json"));
                        memoData.insert(memoData.end(), memoSig.begin(), memoSig.end());
                    }

                    int labelMaxSize = std::max(std::min(dataLabel.size(), ((ZC_MEMO_SIZE - memoData.size()) - 24)), (std::size_t)0);
                    if (labelMaxSize)
                    {
                        if (labelMaxSize < dataLabel.size())
                        {
                            dataLabel.resize(labelMaxSize);
                        }
                        std::vector<unsigned char> memoLabel = ::AsVector(CVDXF_Data(CVDXF_Data::DataStringKey(), ::AsVector(dataLabel)));
                        memoData.insert(memoData.end(), memoLabel.begin(), memoLabel.end());
                    }
                    memoStr = HexBytes(memoData.data(), memoData.size());

                    // the value should be considered for reduction
                    if (chkP.AsVector().size() >= CScript::MAX_SCRIPT_ELEMENT_SIZE)
                    {
                        CNotaryEvidence emptyEvidence;
                        int baseOverhead = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &emptyEvidence)).size() + 128;
                        auto evidenceVec = evidenceData.BreakApart(CScript::MAX_SCRIPT_ELEMENT_SIZE - baseOverhead);
                        if (!evidenceVec.size())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to package evidence chunk in data output #" + std::to_string(i));
                        }
                        for (auto &oneProof : evidenceVec)
                        {
                            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
                            evidenceOuts.push_back(tb.mtx.vout.size());
                            tOutputs.push_back(SendManyRecipient(EncodeDestination(CKeyID(GetDestinationID(dests[0]))), 0, "", MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &oneProof))));
                        }
                    }
                    else
                    {
                        tOutputs.push_back(SendManyRecipient(EncodeDestination(CKeyID(GetDestinationID(dests[0]))), 0, "", MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &evidenceData))));
                    }

                }
                else if (!dataUni.isNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "data parameter must be valid parameters for the signdata command");
                }

                // if memo starts with "#", convert it from a string to a hex value
                if (memoStr.size() > 1 && memoStr[0] == '#')
                {
                    // make a hex string out of the chars without the "#"
                    memoStr = HexBytes((const unsigned char *)&(memoStr[1]), memoStr.size());
                }

                if (!memoStr.empty())
                {
                    memoUni = memoStr;
                }

                if (!memoUni.isNull())
                {
                    auto memoVec = VectorEncodeVDXFUni(memoUni);
                    memoStr = HexBytes((const unsigned char *)&(memoVec[0]), memoVec.size());
                }

                if (memoStr.size() && !IsHex(memoStr))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected memo data in hexadecimal format or as a non-zero length string, starting with \"#\".");
                }

                if (memoStr.length() > (ZC_MEMO_SIZE << 1)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,  strprintf("Invalid parameter, size of memo is larger than maximum allowed %d", ZC_MEMO_SIZE ));
                }

                zOutputs.push_back(SendManyRecipient(destStr, sourceAmount, memoStr, CScript()));
            }
            else
            {
                if (memoStr.size() > 0)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Memo is only an option for z-address destinations.");
                }

                /*
                // throwing an error if a destination ID is not present on the current chain when sending to an ID on another chain
                // may sometimes be inconvenient, but it also helps ensure that a fat finger error won't lose funds. The alternate way,
                // which does not throw an error is in this comment, if desired.
                CTxDestination destination;

                if (destSystemID != thisChainID || (!exportToCurrencyID.IsNull() && exportToCurrencyID != thisChainID))
                {
                    destination = DecodeDestination(destStr);
                }
                else
                {
                    destination = ValidateDestination(destStr);
                }
                */

                // if enabling the alternate to strict verification of ID on this chain when sending at all times, comment this and uncomment above
                CTxDestination destination = ValidateDestination(destStr);

                CTxDestination refundDestination = DecodeDestination(refundToStr);
                if (refundDestination.which() == COptCCParams::ADDRTYPE_INVALID)
                {
                    if (!hasZSource && !wildCardAddress && sourceDest.which() != COptCCParams::ADDRTYPE_INVALID)
                    {
                        refundDestination = sourceDest;
                    }
                    else if (!VERUS_DEFAULTID.IsNull())
                    {
                        refundDestination = VERUS_DEFAULTID;
                    }
                    else
                    {
                        refundDestination = destination;
                    }
                }
                else if (refundDestination.which() == COptCCParams::ADDRTYPE_ID &&
                    GetDestinationID(refundDestination) != GetDestinationID(destination))
                {
                    if (!CIdentity::LookupIdentity(GetDestinationID(refundDestination)).IsValid())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "When explicitly refunding to an ID, the ID must be valid on the current chain.");
                    }
                }

                CTransferDestination dest;
                if (destination.which() == COptCCParams::ADDRTYPE_INVALID)
                {
                    if (destSystemDef.IsGateway())
                    {
                        // if we expect an ETH address, only accept that
                        if (exportSystemDef.proofProtocol == exportSystemDef.PROOF_ETHNOTARIZATION)
                        {
                            uint160 ethDestination = dest.DecodeEthDestination(destStr);
                            if (ethDestination.IsNull())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid Ethereum destination (null)");
                            }
                            dest = CTransferDestination(CTransferDestination::DEST_ETH, ::AsVector(ethDestination));
                            if (refundDestination.which() != COptCCParams::ADDRTYPE_INVALID)
                            {
                                dest.SetAuxDest(DestinationToTransferDestination(refundDestination), 0);
                            }
                        }
                        else
                        {
                            std::vector<unsigned char> rawDestBytes;
                            for (int i = 0; i < subNames.size(); i++)
                            {
                                if (i)
                                {
                                    rawDestBytes.push_back('.');
                                }
                                rawDestBytes.insert(rawDestBytes.end(), subNames[i].begin(), subNames[i].end());
                            }
                            if (!rawDestBytes.size())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Specified destination must be valid");
                            }
                            dest = CTransferDestination(CTransferDestination::FLAG_DEST_GATEWAY + CTransferDestination::DEST_RAW, rawDestBytes, destSystemID);
                        }
                    }
                    else if (exportSystemDef.IsValid() && exportSystemDef.proofProtocol == exportSystemDef.PROOF_ETHNOTARIZATION)
                    {
                        uint160 ethDestination = dest.DecodeEthDestination(destStr);
                        if (ethDestination.IsNull())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid Ethereum destination (null)");
                        }
                        dest = CTransferDestination(CTransferDestination::DEST_ETH, ::AsVector(ethDestination));
                        dest.type |= dest.FLAG_DEST_GATEWAY;
                        dest.gatewayID = exportSystemDef.GetID();

                        if (refundDestination.which() != COptCCParams::ADDRTYPE_INVALID)
                        {
                            dest.SetAuxDest(DestinationToTransferDestination(refundDestination), 0);
                        }
                    }
                    else
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Specified destination must be valid.");
                    }
                }

                bool refundValid = refundDestination.which() != COptCCParams::ADDRTYPE_INVALID;
                if (!refundValid)
                {
                    refundDestination = destination;
                }

                // make one output
                CRecipient oneOutput;

                if (preConvert)
                {
                    flags |= CReserveTransfer::PRECONVERT;
                }
                if (isConversion && !burnCurrency && !convertToCurrencyID.IsNull())
                {
                    flags |= CReserveTransfer::CONVERT;
                }
                else if (mintNew)
                {
                    flags |= CReserveTransfer::MINT_CURRENCY;
                    convertToCurrencyID = sourceCurrencyID;
                    convertToCurrencyDef = sourceCurrencyDef;
                }
                if (isVia && isConversion)
                {
                    flags |= CReserveTransfer::RESERVE_TO_RESERVE;
                }

                // are we a system/chain transfer with or without conversion?
                if (destSystemID != thisChainID || (!exportToCurrencyID.IsNull() && exportToCurrencyID != thisChainID))
                {
                    // possible cases:
                    // 1. sending currency to another chain, paying with native currencies and no converter
                    // 2. sending currency with or without conversion, paying with fees converted via converter on source or dest system
                    // 3. preconvert on launch of new system
                    //
                    // converting with fees via a converter on the source chain first converts fees and optionally more,
                    // then uses case 1 above

                    if (exportCurrency)
                    {
                        // validate no conflicts with currency export and create a destination of the currency
                        if (mintNew ||
                            isConversion ||
                            preConvert ||
                            exportId ||
                            sourceCurrencyID == ASSETCHAINS_CHAINID)
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot mint or convert currency when exporting a currency definition cross-chain");
                        }
                        // confirm that we can export the intended currency
                        if (IsValidExportCurrency(exportToCurrencyDef, sourceCurrencyID, height + 1))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency ( " + ConnectedChains.GetFriendlyCurrencyName(sourceCurrencyID) + ") already exported to destination system");
                        }
                        if (destSystemID != ASSETCHAINS_CHAINID ? !destSystemDef.IsMultiCurrency() : !exportToCurrencyDef.IsMultiCurrency())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot export currency to single currency system");
                        }
                        dest = CTransferDestination(CTransferDestination::DEST_REGISTERCURRENCY, ::AsVector(sourceCurrencyDef));
                        flags |= CReserveTransfer::CURRENCY_EXPORT;
                        numHeavyOutputs++;
                    }

                    // if we should export the ID, make a full ID destination
                    if (!dest.IsValid())
                    {
                        dest = DestinationToTransferDestination(destination);
                    }
                    if (dest.TypeNoFlags() == dest.DEST_ID)
                    {
                        if (exportId)
                        {
                            // get and export the ID
                            CIdentity destIdentity = CIdentity::LookupIdentity(GetDestinationID(destination));
                            if (!destIdentity.IsValid())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot find identity to export (" + EncodeDestination(destination) + ")");
                            }
                            if (destIdentity.unlockAfter && !destIdentity.IsLocked())
                            {
                                std::string correctCommand = "Identity time lock should be zeroed before sending cross-chain to avoid inadvertent locking on destination chain. Run the command:\nupdateidentity \'{\"name\":\"" + destIdentity.name + "\",\"parent\":\"" + EncodeDestination(CIdentityID(destIdentity.parent)) + "\",\"timelock\":0}\'\nto zero the timelock value before exporting to another chain";
                                throw JSONRPCError(RPC_INVALID_PARAMETER, correctCommand);
                            }
                            destIdentity.contentMap.clear();
                            destIdentity.contentMultiMap.clear();
                            dest = CTransferDestination(CTransferDestination::DEST_FULLID, ::AsVector(destIdentity));
                            flags |= CReserveTransfer::IDENTITY_EXPORT;
                            numHeavyOutputs++;
                        }
                    }

                    // check for potentially unknown currencies being sent across
                    // for now, we can only send currencies that were involved in the launch
                    std::set<uint160> validCurrencies;
                    std::set<uint160> validIDs;
                    CChainNotarizationData cnd;
                    CCurrencyDefinition nonVerusChainDef = IsVerusActive() ?
                        (destSystemID != thisChainID ? destSystemDef : exportToCurrencyDef) :
                        (ConnectedChains.ThisChain());
                    uint160 offChainID = IsVerusActive() ? nonVerusChainDef.GetID() : VERUS_CHAINID;
                    const CCurrencyDefinition &offChainDef = (destSystemID != thisChainID ? destSystemDef : exportToCurrencyDef);

                    if (!offChainDef.IsValidTransferDestinationType(dest.TypeNoFlags()))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Invalid destination address for export system " + offChainDef.name + " (" + dest.ToUniValue().write() + ")");
                    }

                    if (!GetNotarizationData(offChainID, cnd) || !cnd.IsConfirmed())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Cannot retrieve notarization data for export system " + nonVerusChainDef.name + " (" + EncodeDestination(CIdentityID(offChainID)) + ")");
                    }

                    if (!preConvert && cnd.vtx[cnd.lastConfirmed].second.IsPreLaunch() && !cnd.vtx[cnd.lastConfirmed].second.IsLaunchCleared())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Cannot send non-preconvert transfers to import system " + nonVerusChainDef.name + " (" + EncodeDestination(CIdentityID(offChainID)) + ") until after launch");
                    }

                    if (cnd.vtx[cnd.lastConfirmed].second.IsRefunding())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Cannot send to import system " + nonVerusChainDef.name + " (" + EncodeDestination(CIdentityID(offChainID)) + ") that is in a refunding state");
                    }

                    validCurrencies = ValidExportCurrencies(offChainDef, height + 1);
                    if (!converterCurrency.IsValid() && (exportToCurrencyDef.IsFractional() || convertToCurrencyDef.IsFractional()))
                    {
                        converterCurrency = exportToCurrencyDef.IsFractional() ? exportToCurrencyDef : convertToCurrencyDef;
                    }

                    if (exportCurrency)
                    {
                        CCurrencyValueMap canExport, cannotExport;

                        if (ConnectedChains.CurrencyExportStatus(
                            CCurrencyValueMap(std::vector<uint160>({sourceCurrencyID}), std::vector<int64_t>({1})),
                            ASSETCHAINS_CHAINID,
                            offChainID,
                            canExport,
                            cannotExport) &&
                            canExport.valueMap.size() &&
                            !cannotExport.valueMap.size())
                        {
                            if (validCurrencies.count(sourceCurrencyID) ||
                                IsValidExportCurrency(offChainDef, sourceCurrencyID, height))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unnecessary to export currency to system. Currency is already available on destination network.");
                            }
                        }
                        else
                        {
                            if (!CCurrencyDefinition::IsValidDefinitionImport(thisChain, offChainDef, sourceCurrencyDef.parent, height))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot export currency to import system, must first export parent currency " + ConnectedChains.GetFriendlyCurrencyName(sourceCurrencyDef.parent));
                            }
                        }
                    }
                    else if ((!convertBeforeOffChain &&
                              !preConvert &&
                              !convertToCurrencyID.IsNull() &&
                              (!validCurrencies.count(sourceCurrencyID) ||
                               (converterCurrency.IsValid() &&
                                converterCurrency.systemID != exportToCurrencyDef.systemID) ||
                               !validCurrencies.count(convertToCurrencyID) ||
                               (!secondCurrencyID.IsNull() && !validCurrencies.count(secondCurrencyID)))) ||
                             (convertBeforeOffChain && !validCurrencies.count(secondCurrencyID.IsNull() ? convertToCurrencyID : secondCurrencyID)))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency " + sourceCurrencyDef.name + " (" + EncodeDestination(CIdentityID(sourceCurrencyID)) + ") cannot be sent to specified system");
                    }

                    std::set<uint160> validFeeCurrencies;
                    validFeeCurrencies.insert(offChainID);
                    if (IsVerusActive() && offChainDef.IsPBaaSChain() && offChainDef.launchSystemID == ASSETCHAINS_CHAINID)
                    {
                        validFeeCurrencies.insert(ASSETCHAINS_CHAINID);
                    }

                    // calculate the price of the fee currency in the source and destination currencies
                    int64_t reversePriceInFeeCur = SATOSHIDEN;

                    CCcontract_info CC;
                    CCcontract_info *cp;
                    cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                    CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

                    if (preConvert)
                    {
                        if (convertToCurrencyID.IsNull())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot preconvert to unspecified or invalid currency.");
                        }
                        auto validConversionCurrencies = convertToCurrencyDef.GetCurrenciesMap();
                        if (!validConversionCurrencies.count(sourceCurrencyID))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ".");
                        }
                        if (convertToCurrencyDef.launchSystemID == ASSETCHAINS_CHAINID &&
                            convertToCurrencyDef.startBlock <= (height + 1))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Too late to convert " + sourceCurrencyDef.name + " to " + convertToStr + ", as pre-launch is over.");
                        }

                        if (refundValid)
                        {
                            dest.SetAuxDest(DestinationToTransferDestination(refundDestination), 0);
                            std::vector<CTxDestination>({pk.GetID(), refundDestination});
                        }

                        CReserveTransfer rt = CReserveTransfer(flags,
                                                               sourceCurrencyID,
                                                               sourceAmount,
                                                               ASSETCHAINS_CHAINID,
                                                               0,
                                                               convertToCurrencyID,
                                                               dest);
                        rt.nFees = rt.CalculateTransferFee();

                        std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

                        oneOutput.nAmount = sourceCurrencyID == thisChainID ? sourceAmount + rt.CalculateTransferFee() : rt.CalculateTransferFee();
                        oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), pIndexDests);
                    }
                    // through a converter before or after conversion for actual conversion and/or fee conversion
                    else if (isConversion || (destSystemID != exportToCurrencyID && !convertToCurrencyID.IsNull()))
                    {
                        // if we have pricing for converting fees, we add all convertible currencies to valid fee currencies
                        CPBaaSNotarization lastConfirmedNotarization = cnd.vtx[cnd.lastConfirmed].second;
                        CCurrencyValueMap feeConversionPrices;
                        CCoinbaseCurrencyState feePriceState;

                        bool sameChainConversion = converterCurrency.systemID == ASSETCHAINS_CHAINID;

                        uint160 converterID = converterCurrency.GetID();

                        if (fromFractional)
                        {
                            if (!converterCurrency.GetCurrenciesMap().count(convertToCurrencyID))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency conversion.");
                            }
                            flags |= CReserveTransfer::IMPORT_TO_SOURCE;
                        }

                        if (sameChainConversion)
                        {
                            // get the latest notarization for the converter on this chain
                            CChainNotarizationData localCND;

                            if (!GetNotarizationData(converterID, localCND) || !localCND.IsConfirmed())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid converter or converter not ready " + EncodeDestination(CIdentityID(converterID)));
                            }

                            feePriceState = localCND.vtx[localCND.lastConfirmed].second.currencyState;
                        }
                        else if (lastConfirmedNotarization.currencyStates.count(converterID))
                        {
                            feePriceState = lastConfirmedNotarization.currencyStates[converterID];
                            if (!feePriceState.IsValid())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency state for currency " + EncodeDestination(CIdentityID(converterID)));
                            }
                        }

                        if (feePriceState.IsValid())
                        {
                            if (sameChainConversion)
                            {
                                feeConversionPrices = feePriceState.TargetConversionPricesReverse(offChainID, true);

                                if (!feeConversionPrices.valueMap.count(offChainID))
                                {
                                    feeConversionPrices.valueMap[offChainID] = SATOSHIDEN;
                                }
                            }
                            else
                            {
                                // get all currencies that may be converted through the converter to valid fees
                                validFeeCurrencies = BaseBridgeCurrencies(offChainDef, height + 1, true);
                                feeConversionPrices = feePriceState.TargetConversionPricesReverse(offChainID, true);

                                // confirm rules such that no currency could slip through here and have a 1:1
                                // conversion that could be exploited in some way
                                for (auto &oneCur : validFeeCurrencies)
                                {
                                    // if we have a valid currency with no conversion, consider the conversion to be 1
                                    if (!feeConversionPrices.valueMap.count(oneCur))
                                    {
                                        feeConversionPrices.valueMap[oneCur] = SATOSHIDEN;
                                    }
                                }
                            }
                        }
                        else
                        {
                            for (auto &oneCur : validFeeCurrencies)
                            {
                                feeConversionPrices.valueMap[oneCur] = SATOSHIDEN;
                            }
                        }

                        if (!feeConversionPrices.valueMap.count(feeCurrencyID))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid fee currency for cross-chain transaction 1 " + ConnectedChains.GetFriendlyCurrencyName(feeCurrencyID));
                        }

                        // determine required fees
                        CAmount requiredFees;
                        if (feeConversionPrices.valueMap.count(feeCurrencyID))
                        {
                            reversePriceInFeeCur = feeConversionPrices.valueMap[feeCurrencyID];
                        }

                        CAmount feeConversionRate = 0;

                        if (offChainDef.IsGateway() && offChainDef.proofProtocol == offChainDef.PROOF_ETHNOTARIZATION)
                        {
                            CChainNotarizationData cnd;
                            if (!GetNotarizationData(offChainDef.SystemOrGatewayID(), cnd) ||
                                !cnd.IsConfirmed() ||
                                !cnd.vtx[cnd.lastConfirmed].second.proofRoots.count(offChainDef.SystemOrGatewayID()))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot get notarization data for destination system of transfer");
                            }
                            // add an extra satoshi for minimum pricing buffer
                            feeConversionRate = (cnd.vtx[cnd.lastConfirmed].second.currencyState.conversionPrice.size() ?
                                                    cnd.vtx[cnd.lastConfirmed].second.currencyState.conversionPrice[0] :
                                                    cnd.vtx[cnd.lastConfirmed].second.proofRoots[offChainDef.SystemOrGatewayID()].gasPrice);
                        }

                        if (exportCurrency)
                        {
                            CAmount adjustedFees = CCurrencyState::NativeGasToReserveRaw(
                                        offChainDef.GetCurrencyImportFee(sourceCurrencyDef.ChainOptions() & offChainDef.OPTION_NFT_TOKEN), feeConversionRate);
                            if (adjustedFees < 0)
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee calculation overflow 1");
                            }
                            // get source price for export and dest price for import to ensure we have enough fee currency
                            requiredFees =
                                CCurrencyState::ReserveToNativeRaw(adjustedFees, reversePriceInFeeCur);
                            if (requiredFees < 0)
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee calculation overflow 2");
                            }
                            flags |= CReserveTransfer::CURRENCY_EXPORT;
                        }
                        else if (exportId)
                        {
                            CAmount adjustedFees = CCurrencyState::NativeGasToReserveRaw(offChainDef.IDImportFee(), feeConversionRate);
                            if (adjustedFees < 0)
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee calculation overflow 3");
                            }
                            requiredFees = CCurrencyState::ReserveToNativeRaw(adjustedFees, reversePriceInFeeCur);
                            if (requiredFees < 0)
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee calculation overflow 4");
                            }
                        }
                        else
                        {
                            CAmount adjustedFees = CCurrencyState::NativeGasToReserveRaw(offChainDef.GetTransactionImportFee() << (offChainDef.proofProtocol == offChainDef.PROOF_ETHNOTARIZATION ? 0 : 1), feeConversionRate);
                            if (adjustedFees < 0)
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee calculation overflow 5");
                            }
                            requiredFees = CCurrencyState::ReserveToNativeRaw(adjustedFees, reversePriceInFeeCur);
                            if (requiredFees < 0)
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee calculation overflow 6");
                            }
                        }

                        if (sameChainConversion)
                        {
                            // if same chain first, we need to ensure that we have enough fees on the other side or it will get
                            // refunded and fall short. add 20% buffer.
                            requiredFees += CCurrencyDefinition::CalculateRatioOfValue(requiredFees, SATOSHIDEN / (offChainDef.proofProtocol == offChainDef.PROOF_ETHNOTARIZATION ? 2 : 5));

                            // if we're converting and then sending, we don't need an initial fee, so all
                            // fees go into the final destination

                            // if we are sending a full ID, revert back to just ID and set the full ID bit to enable
                            // sending the full ID in the next leg without overhead in the first
                            if (dest.TypeNoFlags() == dest.DEST_FULLID)
                            {
                                dest = CTransferDestination(CTransferDestination::DEST_ID, ::AsVector(CIdentityID(GetDestinationID(destination))));
                                flags |= CReserveTransfer::IDENTITY_EXPORT;
                            }
                            else if (dest.TypeNoFlags() != dest.DEST_ID)
                            {
                                exportId = false;
                            }

                            if (dest.TypeNoFlags() == dest.DEST_REGISTERCURRENCY)
                            {
                                dest = destination.which() == COptCCParams::ADDRTYPE_INVALID ?
                                    DestinationToTransferDestination(CIdentityID(CCurrencyDefinition(dest.destination).GetID())) :
                                    DestinationToTransferDestination(destination);
                            }

                            dest.type |= dest.FLAG_DEST_GATEWAY;
                            dest.gatewayID = exportSystemDef.GetID();

                            if (dest.gatewayID == ASSETCHAINS_CHAINID)
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot export from the current chain to the current chain");
                            }
                            CChainNotarizationData cnd;
                            if (!GetNotarizationData(converterID, cnd) ||
                                !cnd.IsConfirmed())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot get notarization/pricing information for " + exportToCurrencyDef.name);
                            }
                            auto currencyMap = cnd.vtx[cnd.lastConfirmed].second.currencyState.GetReserveMap();
                            if (cnd.vtx[cnd.lastConfirmed].second.currencyState.IsPrelaunch() &&
                                ((isConversion && !preConvert) ||
                                 (feeCurrencyID != dest.gatewayID &&
                                  (!exportToCurrencyDef.IsPBaaSChain() || exportToCurrencyDef.launchSystemID != ASSETCHAINS_CHAINID || feeCurrencyID != ASSETCHAINS_CHAINID))))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid fee currency or conversion specified during pre-launch of converter.");
                            }
                            if (!currencyMap.count(dest.gatewayID) ||
                                !currencyMap.count(ASSETCHAINS_CHAINID) ||
                                (!currencyMap.count(feeCurrencyID) && feeCurrencyID != convertToCurrencyID))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Local converter cannot convert " + feeCurrencyDef.name + " to " + destSystemDef.name + ".");
                            }

                            dest.fees = requiredFees;
                            requiredFees = 0;           // clear them, as they are used below as well when sending directly across
                            reversePriceInFeeCur = feePriceState.TargetConversionPricesReverse(ASSETCHAINS_CHAINID, true).valueMap[feeCurrencyID];

                            printf("%s: setting transfer fees in currency %s to %" PRId64 "\n", __func__, EncodeDestination(CIdentityID(feeCurrencyID)).c_str(), dest.fees);
                            flags &= ~CReserveTransfer::CROSS_SYSTEM;

                            // at this point, we either need a refund ID or a change address for refund, or there is risk of loss, so fail instead
                            if (refundDestination.which() == COptCCParams::ADDRTYPE_INVALID)
                            {
                                if (!VERUS_DEFAULTID.IsNull())
                                {
                                    refundDestination = VERUS_DEFAULTID;
                                }
                                else if (!hasZSource && !wildCardAddress && sourceDest.which() != COptCCParams::ADDRTYPE_INVALID)
                                {
                                    refundDestination = sourceDest;
                                }
                                else
                                {
                                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Must provide refund address, have valid \"-defaultid\" set, or have a non-wildcard transparent source when sending via a converter cross chain");
                                }
                                dest.SetAuxDest(DestinationToTransferDestination(refundDestination), 0);
                            }
                        }
                        else
                        {
                            flags |= CReserveTransfer::CROSS_SYSTEM;
                            if (destSystemID == ASSETCHAINS_CHAINID)
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot export from the current chain to the same chain");
                            }
                        }

                        auto reserveMap = converterCurrency.GetCurrenciesMap();
                        if (feeCurrencyID != destSystemID &&
                            !(converterCurrency.IsFractional() && (feeCurrencyID == converterID || reserveMap.count(feeCurrencyID))))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert fees " + EncodeDestination(CIdentityID(feeCurrencyID)) + " to " + destSystemDef.name + ". 3");
                        }

                        if (refundValid)
                        {
                            dest.SetAuxDest(DestinationToTransferDestination(refundDestination), 0);
                        }

                        // converting from reserve to a fractional of that reserve
                        auto fees = CCurrencyState::ReserveToNativeRaw(CReserveTransfer::CalculateTransferFee(dest, flags), reversePriceInFeeCur);
                        auto add20Pct = CCurrencyDefinition::CalculateRatioOfValue(fees, SATOSHIDEN / 5);
                        fees += (add20Pct ? add20Pct : 1) + requiredFees;

                        CReserveTransfer rt = CReserveTransfer(flags,
                                                               sourceCurrencyID,
                                                               sourceAmount,
                                                               feeCurrencyID,
                                                               fees,
                                                               convertToCurrencyID,
                                                               dest,
                                                               secondCurrencyID,
                                                               destSystemID);

                        std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

                        oneOutput.nAmount = rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID];
                        oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), pIndexDests);
                    }
                    else // direct to another system paying with acceptable fee currency
                    {
                        if (!validFeeCurrencies.count(feeCurrencyID))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid fee currency for cross-chain transaction 2" + ConnectedChains.GetFriendlyCurrencyName(feeCurrencyID));
                        }

                        if (offChainDef.GetID() == ASSETCHAINS_CHAINID)
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot export to and from the same chain");
                        }

                        CAmount feeConversionRate = 0;

                        if (offChainDef.IsGateway() && offChainDef.proofProtocol == offChainDef.PROOF_ETHNOTARIZATION)
                        {
                            CChainNotarizationData cnd;
                            if (!GetNotarizationData(offChainDef.SystemOrGatewayID(), cnd) ||
                                !cnd.IsConfirmed() ||
                                !cnd.vtx[cnd.lastConfirmed].second.proofRoots.count(offChainDef.SystemOrGatewayID()))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot get notarization data for destination system of transfer 2");
                            }
                            // add an extra satoshi for minimum pricing buffer
                            feeConversionRate = (cnd.vtx[cnd.lastConfirmed].second.proofRoots.count(offChainDef.SystemOrGatewayID()) ?
                                                    cnd.vtx[cnd.lastConfirmed].second.proofRoots[offChainDef.SystemOrGatewayID()].gasPrice :
                                                    cnd.vtx[cnd.lastConfirmed].second.currencyState.conversionPrice[0]);
                        }

                        // determine required fees
                        CAmount requiredFees;
                        if (exportCurrency)
                        {
                            // get source price for export and dest price for import to ensure we have enough fee currency
                            CAmount adjustedFees = CCurrencyState::NativeGasToReserveRaw(
                                        offChainDef.GetCurrencyImportFee(sourceCurrencyDef.ChainOptions() & offChainDef.OPTION_NFT_TOKEN), feeConversionRate);

                            if (adjustedFees < 0)
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee calculation overflow 7");
                            }
                            requiredFees = CCurrencyState::ReserveToNativeRaw(adjustedFees, reversePriceInFeeCur);
                            if (requiredFees < 0)
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee calculation overflow 8");
                            }
                            flags |= CReserveTransfer::CURRENCY_EXPORT;
                        }
                        else if (exportId)
                        {
                            CAmount adjustedFees = CCurrencyState::NativeGasToReserveRaw(offChainDef.IDImportFee(), feeConversionRate);
                            requiredFees = CCurrencyState::ReserveToNativeRaw(adjustedFees, reversePriceInFeeCur);
                        }
                        else
                        {
                            CAmount adjustedFees = CCurrencyState::NativeGasToReserveRaw(offChainDef.GetTransactionImportFee() << (offChainDef.proofProtocol == offChainDef.PROOF_ETHNOTARIZATION ? 0 : 1), feeConversionRate);
                            requiredFees = CCurrencyState::ReserveToNativeRaw(adjustedFees, reversePriceInFeeCur);
                        }

                        if (offChainDef.proofProtocol == offChainDef.PROOF_ETHNOTARIZATION)
                        {
                            requiredFees += CCurrencyDefinition::CalculateRatioOfValue(requiredFees, SATOSHIDEN / 10);
                        }

                        if (refundValid)
                        {
                            dest.SetAuxDest(DestinationToTransferDestination(refundDestination), 0);
                            std::vector<CTxDestination>({pk.GetID(), refundDestination});
                        }

                        flags |= CReserveTransfer::CROSS_SYSTEM;
                        auto fees = requiredFees + CCurrencyState::ReserveToNativeRaw(CReserveTransfer::CalculateTransferFee(dest, flags), reversePriceInFeeCur);
                        CReserveTransfer rt = CReserveTransfer(flags,
                                                               sourceCurrencyID,
                                                               sourceAmount,
                                                               feeCurrencyID,
                                                               fees,
                                                               exportToCurrencyID,
                                                               dest,
                                                               secondCurrencyID,
                                                               destSystemID);

                        std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

                        oneOutput.nAmount = rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID];
                        oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), pIndexDests);
                    }
                }
                else if (exportCurrency)
                {
                    // invalid to export currency except off-chain
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot export " + sourceCurrencyDef.name + " without specifying \"exportto\"");
                }
                // a currency conversion without transfer?
                else if (!convertToCurrencyID.IsNull())
                {
                    if (convertToCurrencyDef.IsToken() && preConvert)
                    {
                        if (convertToCurrencyDef.startBlock <= (height + 1))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Too late to convert " + sourceCurrencyDef.name + " to " + convertToStr + ", as pre-launch is over.");
                        }

                        CCurrencyValueMap validConversionCurrencies = CCurrencyValueMap(convertToCurrencyDef.currencies,
                                                                                        std::vector<CAmount>(convertToCurrencyDef.currencies.size(), 1));
                        if (!convertToCurrencyDef.GetCurrenciesMap().count(sourceCurrencyID))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ". 1");
                        }

                        CCcontract_info CC;
                        CCcontract_info *cp;
                        cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                        CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

                        auto dest = DestinationToTransferDestination(destination);
                        if (refundValid)
                        {
                            dest.SetAuxDest(DestinationToTransferDestination(refundDestination), 0);
                            std::vector<CTxDestination>({pk.GetID(), refundDestination});
                        }

                        std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

                        auto fees = CReserveTransfer::CalculateTransferFee(dest, flags);
                        CReserveTransfer rt = CReserveTransfer(flags,
                                                               sourceCurrencyID,
                                                               sourceAmount,
                                                               feeCurrencyID,
                                                               fees,
                                                               convertToCurrencyID,
                                                               dest);
                        rt.nFees = rt.CalculateTransferFee();
                        oneOutput.nAmount = rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID];
                        oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), pIndexDests);
                    }
                    else if (!preConvert && (mintNew || burnCurrency || toFractional || fromFractional))
                    {
                        // the following cases end up here:
                        //   1. we are minting or burning currency
                        //   2. we are converting from a fractional currency to its reserve or back
                        //   3. we are converting from one reserve of a fractional currency to another reserve of the same fractional

                        CCcontract_info CC;
                        CCcontract_info *cp;
                        cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                        CPubKey pk = CPubKey(ParseHex(CC.CChexstr));
                        if (mintNew || burnCurrency)
                        {
                            // we only allow minting/burning of tokens right now
                            // TODO: support centralized minting of native AND fractional currency
                            // minting of fractional currency should emit coins without changing price by
                            // adjusting reserve ratio
                            if (!convertToCurrencyDef.IsToken() || convertToCurrencyDef.systemID != ASSETCHAINS_CHAINID || convertToCurrencyDef.IsGateway())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot mint or burn currency " + convertToCurrencyDef.name);
                            }
                            std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

                            if (burnCurrency && sourceCurrencyID == convertToCurrencyID)
                            {
                                flags |= CReserveTransfer::IMPORT_TO_SOURCE;
                            }

                            CReserveTransfer rt = CReserveTransfer(flags,
                                                                   burnCurrency ? sourceCurrencyID : thisChainID,
                                                                   sourceAmount,
                                                                   ASSETCHAINS_CHAINID,
                                                                   0,
                                                                   convertToCurrencyID,
                                                                   DestinationToTransferDestination(destination));
                            rt.nFees = rt.CalculateTransferFee();
                            oneOutput.nAmount = rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID];
                            oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), pIndexDests);
                        }
                        else
                        {
                            flags |= CReserveTransfer::CONVERT;

                            // determine the currency that is the fractional currency, whether that is the source
                            // or destination
                            CCurrencyDefinition *pFractionalCurrency = &sourceCurrencyDef;

                            // determine the reserve currency of the destination that we are relevant to,
                            // again, whether source or destination
                            CCurrencyDefinition *pReserveCurrency = &convertToCurrencyDef;

                            // is our destination currency, the conversion destination?
                            if (toFractional)
                            {
                                pReserveCurrency = pFractionalCurrency;
                                pFractionalCurrency = &convertToCurrencyDef;
                            }
                            else
                            {
                                flags |= CReserveTransfer::IMPORT_TO_SOURCE;
                            }
                            if (!secondCurrencyID.IsNull())
                            {
                                flags |= CReserveTransfer::RESERVE_TO_RESERVE;
                            }

                            if (pFractionalCurrency->launchSystemID == ASSETCHAINS_CHAINID && pFractionalCurrency->startBlock > (height + 1))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + " except through preconvert before the startblock has passed.");
                            }

                            auto reserveMap = pFractionalCurrency->GetCurrenciesMap();
                            auto reserveIndexIt = reserveMap.find(pReserveCurrency->GetID());
                            if (reserveIndexIt == reserveMap.end())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ". Must have reserve<->fractional relationship.");
                            }

                            /*
                            In order to accept fees in any currency, we need to pin ourselves to an easily accessible, objective price of the
                            fee currency in native currency of the target system. In order to support an objective and hard line of meeting
                            fee requirements, we define the exchange rate of a currency to verify required import fees for any operation to
                            be determined by the last confirmed notarization of the importing currency state, if it is fractional, as of the
                            last export transaction to that currency from this system. An export transaction also includes a predicted
                            notarization, which is not typically finalized, except for the launch notarization, but always includes the last
                            known state based on notarization.
                            Enabling this will also enable us to generate transactions which require Verus to be posted at all, but once
                            posted, use tokens, which are convenient and already in the transaction to pay for all remaining fees on this
                            system or others.
                            Until then, we use the same standard prices and defaults for all currencies.
                            CChainNotarizationData cnd;
                            if (!GetNotarizationData(pFractionalCurrency->GetID(), EVAL_ACCEPTEDNOTARIZATION, cnd))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to get reserve currency data for " + pFractionalCurrency->name + ".");
                            }
                            */

                            CChainNotarizationData cnd;
                            if (!GetNotarizationData(pFractionalCurrency->GetID(), cnd) ||
                                !cnd.IsConfirmed())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot get notarization/pricing information for " + exportToCurrencyDef.name);
                            }
                            CCoinbaseCurrencyState &feePriceState = cnd.vtx[cnd.lastConfirmed].second.currencyState;
                            if (feeCurrencyID.IsNull())
                            {
                                feeCurrencyID = ASSETCHAINS_CHAINID;
                            }
                            CAmount reversePriceInFeeCur = feePriceState.TargetConversionPricesReverse(ASSETCHAINS_CHAINID, true).valueMap[feeCurrencyID];

                            // converting from reserve to a fractional of that reserve
                            auto dest = DestinationToTransferDestination(destination);
                            if (refundValid)
                            {
                                dest.SetAuxDest(DestinationToTransferDestination(refundDestination), 0);
                                std::vector<CTxDestination>({pk.GetID(), refundDestination});
                            }

                            CAmount fees = CCurrencyState::ReserveToNativeRaw(CReserveTransfer::CalculateTransferFee(dest, flags), reversePriceInFeeCur);

                            CReserveTransfer rt = CReserveTransfer(flags,
                                                                   sourceCurrencyID,
                                                                   sourceAmount,
                                                                   feeCurrencyID,
                                                                   fees,
                                                                   convertToCurrencyID,
                                                                   dest,
                                                                   secondCurrencyID);

                            std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

                            oneOutput.nAmount = rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID];
                            oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), pIndexDests);
                        }
                    }
                    else
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ". 4");
                    }
                }
                // or a normal native or reserve output?
                else
                {
                    if (sourceCurrencyID == thisChainID)
                    {
                        oneOutput.nAmount = sourceAmount;
                        if (pIndexDests)
                        {
                            std::vector<CTxDestination> dests = std::vector<CTxDestination>({destination});
                            oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_NONE, dests, 1, nullptr), pIndexDests);
                        }
                        else
                        {
                            oneOutput.scriptPubKey = GetScriptForDestination(destination);
                        }
                    }
                    else
                    {
                        oneOutput.nAmount = 0;

                        std::vector<CTxDestination> dests = std::vector<CTxDestination>({destination});
                        CTokenOutput to(sourceCurrencyID, sourceAmount);

                        oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &to), pIndexDests);
                    }
                }
                if (!oneOutput.scriptPubKey.size())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Failure to make currency output");
                }
                tOutputs.push_back(SendManyRecipient(destStr, oneOutput.nAmount, "", oneOutput.scriptPubKey));
            }
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters.");
    }

    CAmount feeAmount = 0;
    if (params.size() > 3)
    {
        feeAmount = AmountFromValue(params[3]);
    }

    // if fee offer was not specified, calculate
    // only a string value of "-0" is considered as specifying an actual zero fee
    if (!feeAmount && (params.size() <= 3 || uni_get_str(params[3]) != "-0"))
    {
        feeAmount = GetMinRelayFeeForOutputs(tOutputs, zOutputs, 0, false);
    }

    if (returnTx)
    {
        UniValue returnTxUni(UniValue::VOBJ);
        CCurrencyValueMap totalOutput;
        for (auto &oneOut : tOutputs)
        {
            tb.AddTransparentOutput(get<3>(oneOut), get<1>(oneOut));
            totalOutput += get<3>(oneOut).ReserveOutValue();
            if (get<1>(oneOut))
            {
                totalOutput.valueMap[ASSETCHAINS_CHAINID] += get<1>(oneOut);
            }
        }
        returnTxUni.pushKV("outputtotals", totalOutput.ToUniValue());
        returnTxUni.pushKV("feeamount", ValueFromAmount(feeAmount));
        if (zOutputs.size())
        {
            returnTxUni.pushKV("hextxwithoutz", EncodeHexTx(tb.mtx));
        }
        else
        {
            returnTxUni.pushKV("hextx", EncodeHexTx(tb.mtx));
        }
        return returnTxUni;
    }

    // Create operation and add to global queue
    if (hasZSource && minConfs ==0)
    {
        minConfs = 1;
    }

    CMutableTransaction contextualTx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), height + 1);
    std::shared_ptr<AsyncRPCQueue> q = getAsyncRPCQueue();
    std::shared_ptr<AsyncRPCOperation> operation(new AsyncRPCOperation_sendmany(tb,
                                                                                contextualTx,
                                                                                sourceAddress,
                                                                                tOutputs,
                                                                                zOutputs,
                                                                                minConfs,
                                                                                feeAmount,
                                                                                uniOutputs,
                                                                                true) );
    q->addOperation(operation);
    AsyncRPCOperationId operationId = operation->getId();
    return operationId;
}

UniValue refundfailedlaunch(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "refundfailedlaunch \"currencyid\"\n"
            "\nRefunds any funds sent to the chain if they are eligible for refund.\n"
            "This attempts to refund all transactions for all contributors.\n"

            "\nArguments\n"
            "\"currencyid\"         (iaddress or full chain name, required)   the chain to refund contributions to\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("refundfailedlaunch", "\"currencyid\"")
            + HelpExampleRpc("refundfailedlaunch", "\"currencyid\"")
        );
    }
    CheckPBaaSAPIsValid();

    uint160 chainID;

    {
        LOCK(cs_main);
        chainID = GetChainIDFromParam(params[0]);
    }
    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid PBaaS name or currencyid");
    }

    if (chainID == ConnectedChains.ThisChain().GetID() || chainID == ConnectedChains.FirstNotaryChain().chainDefinition.GetID())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot refund the specified chain");
    }

    CTransaction lastImportTx;
    std::vector<CTransaction> refundTxes;
    std::string failReason;

    //if (!RefundFailedLaunch(chainID, lastImportTx, refundTxes, failReason))
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, failReason);
    }

    uint32_t consensusBranchId = CurrentEpochBranchId(chainActive.LastTip()->GetHeight(), Params().GetConsensus());

    UniValue ret(UniValue::VARR);

    CCoinsViewCache view(pcoinsTip);

    // sign and commit the transactions
    for (auto tx : refundTxes)
    {
        LOCK2(cs_main, mempool.cs);

        CMutableTransaction newTx(tx);

        // sign the transaction and submit
        bool signSuccess;
        for (int i = 0; i < tx.vin.size(); i++)
        {
            SignatureData sigdata;
            CAmount value;
            CScript outputScript;

            if (tx.vin[i].prevout.hash == lastImportTx.GetHash())
            {
                value = lastImportTx.vout[tx.vin[i].prevout.n].nValue;
                outputScript = lastImportTx.vout[tx.vin[i].prevout.n].scriptPubKey;
            }
            else
            {
                CCoinsViewCache view(pcoinsTip);
                CCoins coins;
                if (!view.GetCoins(tx.vin[i].prevout.hash, coins))
                {
                    fprintf(stderr,"refundfailedlaunch: cannot get input coins from tx: %s, output: %d\n", tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    LogPrintf("refundfailedlaunch: cannot get input coins from tx: %s, output: %d\n", tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    break;
                }
                value = coins.vout[tx.vin[i].prevout.n].nValue;
                outputScript = coins.vout[tx.vin[i].prevout.n].scriptPubKey;
            }

            signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &tx, i, value, SIGHASH_ALL), outputScript, sigdata, consensusBranchId);

            if (!signSuccess)
            {
                fprintf(stderr,"refundfailedlaunch: failure to sign refund transaction\n");
                LogPrintf("refundfailedlaunch: failure to sign refund transaction\n");
                break;
            } else {
                UpdateTransaction(newTx, i, sigdata);
            }
        }

        if (signSuccess)
        {
            // push to local node and sync with wallets
            CValidationState state;
            bool fMissingInputs;
            CTransaction signedTx(newTx);
            if (!AcceptToMemoryPool(mempool, state, signedTx, false, false, &fMissingInputs)) {
                if (state.IsInvalid()) {
                    fprintf(stderr,"refundfailedlaunch: rejected by memory pool for %s\n", state.GetRejectReason().c_str());
                    LogPrintf("refundfailedlaunch: rejected by memory pool for %s\n", state.GetRejectReason().c_str());
                } else {
                    if (fMissingInputs) {
                        fprintf(stderr,"refundfailedlaunch: missing inputs\n");
                        LogPrintf("refundfailedlaunch: missing inputs\n");
                    }
                    else
                    {
                        fprintf(stderr,"refundfailedlaunch: rejected by memory pool for\n");
                        LogPrintf("refundfailedlaunch: rejected by memory pool for\n");
                    }
                }
                break;
            }
            else
            {
                RelayTransaction(signedTx);
                ret.push_back(signedTx.GetHash().GetHex());
            }
        }
    }
    return ret;
}

UniValue getinitialcurrencystate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getinitialcurrencystate \"name\"\n"
            "\nReturns the total amount of preconversions that have been confirmed on the blockchain for the specified PBaaS chain.\n"
            "This should be used to get information about chains that are not this chain, but are being launched by it.\n"

            "\nArguments\n"
            "   \"name\"                    (string, required) name or chain ID of the chain to get the export transactions for\n"

            "\nResult:\n"
            "   [\n"
            "       {\n"
            "           \"flags\" : n,\n"
            "           \"initialratio\" : n,\n"
            "           \"initialsupply\" : n,\n"
            "           \"emitted\" : n,\n"
            "           \"supply\" : n,\n"
            "           \"reserve\" : n,\n"
            "           \"currentratio\" : n,\n"
            "       },\n"
            "   ]\n"

            "\nExamples:\n"
            + HelpExampleCli("getinitialcurrencystate", "name")
            + HelpExampleRpc("getinitialcurrencystate", "name")
        );
    }
    CheckPBaaSAPIsValid();

    LOCK(cs_main);

    uint160 chainID = GetChainIDFromParam(params[0]);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    CCurrencyDefinition chainDef;
    int32_t definitionHeight;
    if (!GetCurrencyDefinition(chainID, chainDef, &definitionHeight))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Chain " + params[0].get_str() + " not found");
    }
    return ConnectedChains.GetCurrencyState(chainDef.GetID(), chainDef.startBlock - 1, true).ToUniValue();
}

size_t GetImports(const uint160 &currencyID, uint32_t fromHeight, uint32_t toHeight, std::map<std::pair<uint32_t, uint32_t>, std::tuple<CTransaction, int, CCrossChainImport, CPBaaSNotarization, std::vector<CReserveTransfer>>> &importMap)
{
    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;
    uint160 searchKey = CCrossChainRPCData::GetConditionID(currencyID, CCrossChainImport::CurrencyImportKey());
    CBlockIndex *pIndex;
    CChainNotarizationData cnd;

    size_t initialSize = importMap.size();

    // get all import transactions including and since this one up to the confirmed height
    if (GetAddressIndex(searchKey, CScript::P2IDX, addressIndex, fromHeight, toHeight))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction importTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, importTx, blkHash))
            {
                CCrossChainExport ccx;
                CCrossChainImport cci;
                int32_t sysCCIOut;
                CPBaaSNotarization importNotarization;
                int32_t importNotOut;
                int32_t evidenceOutStart, evidenceOutEnd;
                std::vector<CReserveTransfer> reserveTransfers;
                uint32_t importHeight = 0;

                auto importBlockIdxIt = mapBlockIndex.find(blkHash);
                if (importBlockIdxIt != mapBlockIndex.end() && chainActive.Contains(importBlockIdxIt->second))
                {
                    importHeight = importBlockIdxIt->second->GetHeight();
                }
                else
                {
                    continue;
                }

                /* UniValue scrOut(UniValue::VOBJ);
                ScriptPubKeyToUniv(importTx.vout[idx.first.index].scriptPubKey, scrOut, false);
                printf("%s: scriptOut: %s\n", __func__, scrOut.write(1,2).c_str()); */

                CCrossChainImport sysCCI;
                if ((cci = CCrossChainImport(importTx.vout[idx.first.index].scriptPubKey)).IsValid() &&
                    cci.GetImportInfo(importTx, importHeight, idx.first.index, ccx, sysCCI, sysCCIOut, importNotarization, importNotOut, evidenceOutStart, evidenceOutEnd, reserveTransfers))
                {
                    importMap[{idx.first.blockHeight, importHeight}] = {importTx, (int)idx.first.index, cci, importNotarization, reserveTransfers};
                }
            }
        }
    }
    return importMap.size() - initialSize;
}

UniValue getcurrencystate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        throw runtime_error(
            "getcurrencystate \"currencynameorid\" (\"n\") (\"conversiondatacurrency\")\n"
            "\nReturns the currency state(s) on the blockchain for any specified currency, either with all changes on this chain or relative to another system.\n"

            "\nArguments\n"
            "   \"currencynameorid\"                  (string)                  name or i-address of currency in question"
            "   \"n\" or \"m,n\" or \"m,n,o\"         (int or string, optional) height or inclusive range with optional step at which to get the currency state\n"
            "                                                                   If not specified, the latest currency state and height is returned\n"
            "   \"conversiondatacurrency\"            (string)                  optional - if present, market data with volumes in given currency are returned\n"

            "\nResult:\n"
            "   [\n"
            "       {\n"
            "           \"height\": n,\n"
            "           \"blocktime\": n,\n"
            "           \"currencystate\": {\n"
            "               \"flags\" : n,\n"
            "               \"initialratio\" : n,\n"
            "               \"initialsupply\" : n,\n"
            "               \"emitted\" : n,\n"
            "               \"supply\" : n,\n"
            "               \"reserve\" : n,\n"
            "               \"currentratio\" : n,\n"
            "           }\n"
            "           \"conversiondata\": {\n"
            "               \"volumecurrency\": \"reserveorbasket\",\n"
            "               \"volumethisinterval\": n,\n"
            "               \"volumepairs\": [\n"
            "                   {\n"
            "                       \"currency\": \"sourcecurrency\",       // Currency converting from\n"
            "                       \"convertto\": \"destinationcurrency\", // Currency converting to\n"
            "                       \"volume\": n,                          // Volume denominated in \"volumecurrency\"\n"
            "                       \"open\": n,                            // Conversion rates of source currency in destination\n"
            "                       \"high\": n,\n"
            "                       \"low\": n,\n"
            "                       \"close\": n\n"
            "                   },\n"
            "                   ...,\n"
            "               ]\n"
            "           },\n"
            "       },\n"
            "   ]\n"

            "\nExamples:\n"
            + HelpExampleCli("getcurrencystate", "\"currencynameorid\" (\"n\") (\"connectedchainid\")")
            + HelpExampleRpc("getcurrencystate", "\"currencynameorid\" (\"n\") (\"connectedchainid\")")
        );
    }
    CheckPBaaSAPIsValid();

    CCurrencyDefinition currencyToCheck;

    std::string currencyStr = uni_get_str(params[0]);
    uint160 currencyID;

    uint64_t lStart;
    uint64_t startEnd[3] = {0};
    uint32_t start = 0, end = 0, step = 0;

    // if we're supposed to get market data
    uint160 volumePriceCurrencyID;
    CCurrencyDefinition volumePriceCurrency;
    std::map<std::pair<uint32_t, uint32_t>, std::tuple<CTransaction, int, CCrossChainImport, CPBaaSNotarization, std::vector<CReserveTransfer>>> importMap;

    {
        LOCK2(cs_main, mempool.cs);

        if (currencyStr.empty() || (currencyID = ValidateCurrencyName(currencyStr, true, &currencyToCheck)).IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency specified");
        }

        uint32_t nHeight = chainActive.Height();

        lStart = startEnd[1] = startEnd[0] = nHeight;

        if (params.size() > 1)
        {
            if (params[1].isStr())
            {
                std::vector<std::string> retNames;
                boost::split(retNames, uni_get_str(params[1]), boost::is_any_of(","));
                Split(params[1].get_str(), startEnd, startEnd[0], 3);
                if (retNames.size() == 2)
                {
                    int64_t step = 1;
                    int64_t delta = startEnd[1] - startEnd[0];
                    while ((delta / step) > 100)
                    {
                        step *= 10;
                    }
                    // default to step 1
                    startEnd[2] = step;
                }
            }
            else if (uni_get_int(params[1], -1) != -1)
            {
                lStart = startEnd[1] = startEnd[0] = uni_get_int(params[1], lStart);
            }
        }

        if (startEnd[0] > startEnd[1])
        {
            startEnd[0] = startEnd[1];
        }

        if (startEnd[1] > lStart)
        {
            startEnd[1] = lStart;
        }

        if (startEnd[1] < startEnd[0])
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block range for currency state");
        }

        if (startEnd[2] == 0)
        {
            startEnd[2] = 1;
        }

        if (startEnd[2] > INT_MAX)
        {
            startEnd[2] = INT_MAX;
        }

        start = startEnd[0];
        end = startEnd[1];
        step = startEnd[2];

        if (params.size() > 2 && currencyToCheck.IsFractional())
        {
            if (end - start > GetArg("-maximumimportrange", chainActive.Height()))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid range for currency state volume and rate information. Maximum range limited to " + std::to_string(GetArg("-maximumimportrange", chainActive.Height())));
            }

            if (currencyToCheck.systemID != ASSETCHAINS_CHAINID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Can only return conversion data for currencies with a systemID of the current chain.");
            }
            // get currency parameter
            volumePriceCurrencyID = ValidateCurrencyName(uni_get_str(params[2]), true, &volumePriceCurrency);

            // ensure it is a reserve or the basket currency name
            if (volumePriceCurrencyID != currencyID &&
                !currencyToCheck.GetCurrenciesMap().count(volumePriceCurrencyID))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Volume and pricing must be calculated in a reserve or the basket currency itself. " + uni_get_str(params[2]) + " is neither.");
            }

            // get all imports
            GetImports(currencyID, start, end, importMap);
        }
    }

    UniValue ret(UniValue::VARR);

    // currencySource, currencyDest, volume in volume/price currency, starting price, highest during period, lowest during period, final price (all prices in volume/price currency)
    std::map<std::pair<uint160,uint160>,std::tuple<CAmount, CAmount, CAmount, CAmount, CAmount>> pairVolumePrice;
    CAmount totalVolumeInVolumeCurrency = 0;
    CAmount stepVolumeInVolumeCurrency = 0;
    int lastEnd = start;

    for (int i = start; i <= end; i += ((i + step <= end || i == end) ? step : end - i))
    {
        LOCK(cs_main);
        pairVolumePrice.clear();
        stepVolumeInVolumeCurrency = 0;

        int queryStart = lastEnd;
        lastEnd = (i + 1);

        auto importIt = importMap.lower_bound({queryStart, 0});
        auto importNextIt = importIt == importMap.end() ? importMap.end() : importMap.upper_bound({i, 0});
        auto it = importIt;
        CCoinbaseCurrencyState currencyState;
        if (importIt != importMap.end() && it != importNextIt)
        {
            // if we have imports, calculate aggregated volumes, pair volumes, and OHLC in specified currency
            // last import has final currency state for this interval
            for (; it != importNextIt; it++)
            {
                currencyState = std::get<3>(it->second).currencyState;

                // get volume and price conversion rates
                CCurrencyValueMap prices(currencyState.currencies, currencyState.conversionPrice);
                CCurrencyValueMap viaPrices(currencyState.currencies, currencyState.viaConversionPrice);
                CCurrencyValueMap conversionRates(currencyState.TargetConversionPrices(volumePriceCurrencyID, prices, viaPrices));

                for (auto &oneRT : std::get<4>(it->second))
                {
                    if (oneRT.IsConversion())
                    {
                        uint160 sourceCur = oneRT.FirstCurrency();
                        uint160 destCur = oneRT.IsReserveToReserve() ? oneRT.secondReserveID : oneRT.destCurrencyID;

                        CCurrencyValueMap currentRates(volumePriceCurrencyID == destCur ? conversionRates : currencyState.TargetConversionPrices(destCur, prices, viaPrices));

                        CCurrencyValueMap conversionFee = oneRT.ConversionFee();
                        CAmount thisVolume = currencyState.ReserveToNativeRaw(oneRT.FirstValue() - conversionFee.valueMap[sourceCur], conversionRates.valueMap[sourceCur]);
                        totalVolumeInVolumeCurrency += thisVolume;
                        stepVolumeInVolumeCurrency += thisVolume;
                        std::get<0>(pairVolumePrice[{sourceCur,destCur}]) += thisVolume;

                        // save open, high, low, close
                        if (std::get<1>(pairVolumePrice[{sourceCur,destCur}]) == 0)
                        {
                            std::get<1>(pairVolumePrice[{sourceCur,destCur}]) = currentRates.valueMap[sourceCur];
                        }
                        std::get<2>(pairVolumePrice[{sourceCur,destCur}]) = std::max(std::get<2>(pairVolumePrice[{sourceCur,destCur}]), currentRates.valueMap[sourceCur]);
                        if (std::get<3>(pairVolumePrice[{sourceCur,destCur}]) == 0)
                        {
                            std::get<3>(pairVolumePrice[{sourceCur,destCur}]) = currentRates.valueMap[sourceCur];
                        }
                        else
                        {
                            std::get<3>(pairVolumePrice[{sourceCur,destCur}]) = std::min(std::get<3>(pairVolumePrice[{sourceCur,destCur}]), currentRates.valueMap[sourceCur]);
                        }
                        std::get<4>(pairVolumePrice[{sourceCur,destCur}]) = currentRates.valueMap[sourceCur];

                        // conversion fee is converted to native currency, unless source is already native
                        if (sourceCur != ASSETCHAINS_CHAINID)
                        {
                            CAmount feeVolume = currencyState.ReserveToNativeRaw(conversionFee.valueMap[sourceCur], conversionRates.valueMap[sourceCur]);
                            totalVolumeInVolumeCurrency += feeVolume;
                            stepVolumeInVolumeCurrency += feeVolume;

                            CCurrencyValueMap feeRates(volumePriceCurrencyID == ASSETCHAINS_CHAINID ? conversionRates : (destCur == ASSETCHAINS_CHAINID ? currentRates : currencyState.TargetConversionPrices(ASSETCHAINS_CHAINID, prices, viaPrices)));

                            std::get<0>(pairVolumePrice[{sourceCur,ASSETCHAINS_CHAINID}]) += currencyState.ReserveToNativeRaw(conversionFee.valueMap[sourceCur], conversionRates.valueMap[sourceCur]);

                            // save open, high, low, close for fees, in case it isn't there
                            if (std::get<1>(pairVolumePrice[{sourceCur,ASSETCHAINS_CHAINID}]) == 0)
                            {
                                std::get<1>(pairVolumePrice[{sourceCur,ASSETCHAINS_CHAINID}]) = feeRates.valueMap[sourceCur];
                            }
                            std::get<2>(pairVolumePrice[{sourceCur,ASSETCHAINS_CHAINID}]) = std::max(std::get<2>(pairVolumePrice[{sourceCur,ASSETCHAINS_CHAINID}]), feeRates.valueMap[sourceCur]);
                            if (std::get<3>(pairVolumePrice[{sourceCur,ASSETCHAINS_CHAINID}]) == 0)
                            {
                                std::get<3>(pairVolumePrice[{sourceCur,ASSETCHAINS_CHAINID}]) = feeRates.valueMap[sourceCur];
                            }
                            else
                            {
                                std::get<3>(pairVolumePrice[{sourceCur,ASSETCHAINS_CHAINID}]) = std::min(std::get<3>(pairVolumePrice[{sourceCur,ASSETCHAINS_CHAINID}]), feeRates.valueMap[sourceCur]);
                            }
                            std::get<4>(pairVolumePrice[{sourceCur,ASSETCHAINS_CHAINID}]) = feeRates.valueMap[sourceCur];
                        }
                    }
                }
            }
        }
        else
        {
            currencyState = ConnectedChains.GetCurrencyState(currencyID, i, (i + step) > end);
        }
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("height", i));
        entry.push_back(Pair("blocktime", i <= chainActive.Height() ? (uint64_t)(chainActive[i]->nTime) : (uint64_t)(chainActive.LastTip()->nTime)));
        entry.push_back(Pair("currencystate", currencyState.ToUniValue()));

        if (pairVolumePrice.size())
        {
            UniValue conversionData(UniValue::VOBJ);
            UniValue pairArray(UniValue::VARR);

            conversionData.pushKV("volumecurrency", ConnectedChains.GetFriendlyCurrencyName(volumePriceCurrencyID));
            conversionData.pushKV("volumethisinterval", ValueFromAmount(stepVolumeInVolumeCurrency));

            // output conversions as source, destination, volume, open, high, low, close
            for (auto &oneVolPrice : pairVolumePrice)
            {
                UniValue onePairEntry(UniValue::VOBJ);
                onePairEntry.pushKV("currency", ConnectedChains.GetFriendlyCurrencyName(oneVolPrice.first.first));
                onePairEntry.pushKV("convertto", ConnectedChains.GetFriendlyCurrencyName(oneVolPrice.first.second));
                onePairEntry.pushKV("volume", ValueFromAmount(std::get<0>(oneVolPrice.second)));
                onePairEntry.pushKV("open", ValueFromAmount(std::get<1>(oneVolPrice.second)));
                onePairEntry.pushKV("high", ValueFromAmount(std::get<2>(oneVolPrice.second)));
                onePairEntry.pushKV("low", ValueFromAmount(std::get<3>(oneVolPrice.second)));
                onePairEntry.pushKV("close", ValueFromAmount(std::get<4>(oneVolPrice.second)));
                pairArray.push_back(onePairEntry);
            }
            conversionData.pushKV("volumepairs", pairArray);
            entry.pushKV("conversiondata",conversionData);
        }

        ret.push_back(entry);
    }
    if (totalVolumeInVolumeCurrency)
    {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("totalvolume", ValueFromAmount(totalVolumeInVolumeCurrency));
        ret.push_back(entry);
    }
    return ret;
}

UniValue getsaplingtree(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
    {
        throw runtime_error(
            "getsaplingtree \"n\"\n"
            "\nReturns the entries for a light wallet Sapling tree state.\n"

            "\nArguments\n"
            "   \"n\" or \"m,n\" or \"m,n,o\"         (int or string, optional) height or inclusive range with optional step at which to get the Sapling tree state\n"
            "                                                                   If not specified, the latest currency state and height is returned\n"
            "\nResult:\n"
            "   [\n"
            "       {\n"
            "           \"network\": \"VRSC\",\n"
            "           \"height\": n,\n"
            "           \"hash\": \"hex\"\n"
            "           \"time\": n,\n"
            "           \"tree\": \"hex\"\n"
            "       },\n"
            "   ]\n"

            "\nExamples:\n"
            + HelpExampleCli("getsaplingtree", "name")
            + HelpExampleRpc("getsaplingtree", "name")
        );
    }

    uint64_t lStart;
    uint64_t startEnd[3] = {0};

    lStart = startEnd[1] = startEnd[0] = chainActive.LastTip() ? chainActive.LastTip()->GetHeight() : 1;

    if (params.size() == 1)
    {
        if (uni_get_int(params[0], -1) == -1 && params[0].isStr())
        {
            Split(params[0].get_str(), startEnd, startEnd[0], 3);
        }
    }

    if (startEnd[0] > startEnd[1])
    {
        startEnd[0] = startEnd[1];
    }

    if (startEnd[1] > lStart)
    {
        startEnd[1] = lStart;
    }

    if (startEnd[1] < startEnd[0])
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block range for currency state");
    }

    if (startEnd[2] == 0)
    {
        startEnd[2] = 1;
    }

    if (startEnd[2] > INT_MAX)
    {
        startEnd[2] = INT_MAX;
    }

    uint32_t start = startEnd[0], end = startEnd[1], step = startEnd[2];

    UniValue ret(UniValue::VARR);

    LOCK(cs_main);
    CCoinsViewCache view(pcoinsTip);
    SaplingMerkleTree tree;

    std::string networkIDName = EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID));

    for (int i = start; i <= end; i += step)
    {
        CBlockIndex &blkIndex = *(chainActive[i]);
        if (view.GetSaplingAnchorAt(blkIndex.hashFinalSaplingRoot, tree))
        {
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("network", networkIDName));
            entry.push_back(Pair("height", blkIndex.GetHeight()));
            entry.push_back(Pair("hash", blkIndex.GetBlockHash().GetHex()));
            entry.push_back(Pair("time", (uint64_t)chainActive.LastTip()->nTime));
            std::vector<unsigned char> treeBytes = ::AsVector(tree);
            entry.push_back(Pair("tree", HexBytes(treeBytes.data(), treeBytes.size())));
            ret.push_back(entry);
        }
    }
    return ret;
}

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);

CCurrencyDefinition ValidateNewUnivalueCurrencyDefinition(const UniValue &uniObj, uint32_t height, const uint160 systemID, std::map<uint160, std::string> &requiredDefinitions, bool checkMempool)
{
    CCurrencyDefinition newCurrency(uniObj);
    if (find_value(uniObj, "launchsystemid").isNull() && newCurrency.GetID() != ASSETCHAINS_CHAINID && newCurrency.parent != ASSETCHAINS_CHAINID)
    {
        newCurrency.launchSystemID = systemID;
    }

    if (newCurrency.launchSystemID == ASSETCHAINS_CHAINID &&
        newCurrency.blockNotarizationModulo < CCurrencyDefinition::MIN_BLOCK_NOTARIZATION_PERIOD)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency definition - less than minimum notarizationperiod");
    }

    if (!newCurrency.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency definition. see help.");
    }

    CCurrencyDefinition checkDef;
    int32_t defHeight;
    if (GetCurrencyDefinition(newCurrency.GetID(), checkDef, &defHeight, checkMempool) &&
        defHeight < height &&
        !(newCurrency.GetID() == ASSETCHAINS_CHAINID &&
         !defHeight))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, newCurrency.name + " currency already defined. see help.");
    }

    bool currentChainDefinition = newCurrency.GetID() == ASSETCHAINS_CHAINID && _IsVerusActive();
    if (currentChainDefinition)
    {
        newCurrency = checkDef;
    }

    if (newCurrency.parent.IsNull() && !currentChainDefinition)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, newCurrency.name + " invalid currency name and parent combination.");
    }

    for (auto &oneID : newCurrency.preAllocation)
    {
        if (!(newCurrency.IsPBaaSChain() && oneID.first.IsNull()) && !CIdentity::LookupIdentity(CIdentityID(oneID.first)).IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "attempting to pre-allocate currency to a non-existent ID.");
        }
    }

    CDataStream tmpDS(SER_NETWORK, PROTOCOL_VERSION);
    if (GetSerializeSize(tmpDS, newCurrency.nativeCurrencyID) > CCurrencyDefinition::MAX_NATIVE_IDENTITY_SIZE)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Native currency ID too large");
    }

    // a new currency definition must spend an ID that currently has no active currency, which sets a semaphore that "blocks"
    // that ID from having more than one at once. Before submitting the transaction, it must be properly signed by the primary authority.
    // This also has the effect of piggybacking on the ID protocol's deconfliction between mined blocks to avoid name conflicts,
    // as the ID can only have its bit set or unset by one transaction at any time and only as part of a transaction that changes the
    // the state of a potentially active currency.

    // one exception to this is the case when a new currency definition that is also not a name controller creates currencies for its
    // own use. these currencies are created on a chain that can also create the corresponding IDs, but the IDs are not also created
    // automatically. as a consequence, the IDs for those currencies are still available (bridge.veth, for example), but those IDs
    // will never be able to create their own currencies or tokens, as those currencies are already defined before the IDs may be.

    if (newCurrency.IsToken() || newCurrency.IsGateway())
    {
        if (newCurrency.rewards.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "currency cannot be both a token and also specify a mining and staking rewards schedule.");
        }

        if (!newCurrency.IsGateway() &&
            (newCurrency.nativeCurrencyID.TypeNoFlags() == newCurrency.nativeCurrencyID.DEST_ETH ||
             newCurrency.nativeCurrencyID.TypeNoFlags() == newCurrency.nativeCurrencyID.DEST_ETHNFT))
        {
            if (newCurrency.IsPBaaSChain() ||
                !newCurrency.IsToken() ||
                newCurrency.IsFractional())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "mapped currency must be a token with no initial supply and cannot be otherwise functional");
            }
            if (newCurrency.proofProtocol != newCurrency.PROOF_ETHNOTARIZATION)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Ethereum mapped currency must have \"proofprotocol\":%d", (int)newCurrency.PROOF_ETHNOTARIZATION));
            }
            bool nonZeroSupply = (newCurrency.conversions.size() && !newCurrency.maxPreconvert.size()) || newCurrency.GetTotalPreallocation();
            for (auto oneVal : newCurrency.maxPreconvert)
            {
                if (oneVal)
                {
                    nonZeroSupply = true;
                }
            }
            if (nonZeroSupply)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Mapped currency definition requires zero initial supply and no possible conversions");
            }
            CCurrencyDefinition systemCurrency = ConnectedChains.GetCachedCurrency(newCurrency.systemID);
            if (systemCurrency.IsValid() &&
                (!systemCurrency.IsGateway() ||
                 (systemCurrency.launchSystemID != ASSETCHAINS_CHAINID && newCurrency.parent != ASSETCHAINS_CHAINID) ||
                 systemCurrency.proofProtocol != systemCurrency.PROOF_ETHNOTARIZATION))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Ethereum protocol networks are the only mapped currency type currently supported");
            }
        }
        else
        {
            // if this is a token or gateway definition, set systemID
            newCurrency.systemID = systemID;
        }
    }
    else
    {
        // it is a PBaaS chain, and it is its own system, responsible for its own communication and currency control
        newCurrency.systemID = newCurrency.GetID();
    }

    if (newCurrency.maxPreconvert.size() && newCurrency.minPreconvert.size())
    {
        for (int i = 0; i < newCurrency.maxPreconvert.size(); i++)
        {
            if (newCurrency.minPreconvert[i] > newCurrency.maxPreconvert[i])
            {
                uint32_t localHeight = height <= chainActive.Height() ? height : chainActive.Height();
                throw JSONRPCError(RPC_INVALID_PARAMETER, "minpreconversions cannot be greater than maxpreconversions for any currency");
            }
        }
    }

    if (currentChainDefinition)
    {
        return newCurrency;
    }

    // refunding a currency after its launch is aborted, or shutting it down after the endblock has passed must be completed
    // to fully decommission a blockchain and clear the active blockchain bit from an ID

    //if (!newCurrency.startBlock || newCurrency.startBlock < (chainActive.Height() + PBAAS_MINSTARTBLOCKDELTA))
    //{
    //    newCurrency.startBlock = chainActive.Height() + (PBAAS_MINSTARTBLOCKDELTA + 5);    // give a little time to send the tx
    //}

    UniValue expiryUni = find_value(uniObj, "expiryheight");
    UniValue startBlockUni = find_value(uniObj, "startblock");
    uint32_t expiryHeight = uni_get_int(expiryUni, chainActive.Height() + PBAAS_MINSTARTBLOCKDELTA);
    newCurrency.startBlock = std::max(std::max(expiryHeight, chainActive.Height() + DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA), (uint32_t)uni_get_int64(startBlockUni));  // give a little time to send the tx

    if (newCurrency.endBlock && newCurrency.endBlock < (newCurrency.startBlock + CCurrencyDefinition::MIN_CURRENCY_LIFE))
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "If endblock (" + to_string(newCurrency.endBlock) +
                                               ") is specified, it must be at least " + to_string(CCurrencyDefinition::MIN_CURRENCY_LIFE) +
                                               " blocks after startblock (" + to_string(newCurrency.startBlock) + ")\n");
    }

    if (!newCurrency.IsToken())
    {
        // if we have no emission parameters, this is not a PBaaS blockchain, it is a controlled or bridged token.
        // controlled tokens can be centrally or algorithmically controlled.
        if (!newCurrency.IsGateway() && newCurrency.rewards.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "A currency must either be based on a token protocol or must specify blockchain rewards, even if 0\n");
        }

        if (newCurrency.IsFractional())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Fractional currencies must be tokens.\n");
        }

        // we need to also be able to set PBaaS converter and gateway
        if (!newCurrency.IsGateway())
        {
            newCurrency.options |= newCurrency.OPTION_PBAAS;
        }
    }

    UniValue currencyNames = find_value(uniObj, "currencies");
    std::set<uint160> currencySet;

    for (int i = 0; i < currencyNames.size(); i++)
    {
        std::string oneCurName = uni_get_str(currencyNames[i]);
        if (!oneCurName.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid (null) currency name");
        }
        uint160 oneCurID = ValidateCurrencyName(oneCurName, true);
        if (oneCurID.IsNull())
        {
            if ((oneCurID = ValidateCurrencyName(oneCurName)).IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency " + oneCurName + " in \"currencies\" 1");
            }
            if (requiredDefinitions.count(oneCurID))
            {
                oneCurName = requiredDefinitions[oneCurID];
            }
            else
            {
                printf("%s: currency not found: name(%s), ID(%s)\nstored names and IDs:\n", __func__, oneCurName.c_str(), EncodeDestination(CIdentityID(oneCurID)).c_str());
                for (auto &onePair : requiredDefinitions)
                {
                    printf("ID(%s), name(%s)\n", EncodeDestination(CIdentityID(onePair.first)).c_str(), onePair.second.c_str());
                }
            }
            // if the new currency is a PBaaS or gateway converter, and this is the PBaaS chain or gateway,
            // it will be created in this tx as well
            if (newCurrency.IsGatewayConverter() && oneCurID == newCurrency.parent)
            {
                currencySet.insert(oneCurID);
                continue;
            }
            if (!(newCurrency.IsGatewayConverter() && systemID == ASSETCHAINS_CHAINID && newCurrency.parent != ASSETCHAINS_CHAINID))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency " + oneCurName + " in \"currencies\"");
            }

            uint160 parent;
            std::string cleanName = CleanName(oneCurName + "@", parent, true);
            if (cleanName.empty())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot decode currency name " + oneCurName + " in \"currencies\"");
            }

            // the parent of the currency cannot require a new definition
            if (oneCurID != newCurrency.parent)
            {
                if (parent != newCurrency.parent || cleanName == "")
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to auto-create currency " + oneCurName + " in \"currencies\"");
                }
                requiredDefinitions[oneCurID] = oneCurName;
            }
        }
        else
        {
            requiredDefinitions.erase(oneCurID);
        }
        currencySet.insert(oneCurID);
    }

    if (currencyNames.size() != currencySet.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Duplicate currency specified in \"currencies\"");
    }

    // if this is a fractional reserve currency, ensure that all reserves are currently active
    // with at least as long of a life as this currency and that at least one of the currencies
    // is the native currency of the chain.
    std::vector<CCurrencyDefinition> reserveCurrencies;
    bool hasCoreReserve = false;
    if (newCurrency.IsFractional())
    {
        if (newCurrency.currencies.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Fractional reserve currencies must specify at least one reserve currency\n");
        }

        if (newCurrency.contributions.size() != newCurrency.currencies.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "All reserves must have non-zero initial contributions for each reserve for fractional currency " + newCurrency.name);
        }

        newCurrency.preconverted = newCurrency.contributions;

        // for a definition to be valid, it needs to have post-launch reserve ratios of all currencies > CCurrencyDefinition::MIN_RESERVE_RATIO (5%)
        // and no greater than CCurrencyDefinition::MAX_RESERVE_CURRENCIES currencies, including pre-launch
        // carve-outs, pre-allocations, and initial supply
        if (newCurrency.currencies.size() > CCurrencyDefinition::MAX_RESERVE_CURRENCIES)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Fractional currencies may have a maximum of 10 reserve currencies specified");
        }

        CCurrencyDefinition tmpDef = newCurrency;
        auto calcState = ConnectedChains.GetCurrencyState(tmpDef, height);
        CAmount issuedWeight = newCurrency.gatewayConverterIssuance ? newCurrency.weights[newCurrency.GetCurrenciesMap()[newCurrency.systemID]] : 0;

        int32_t totalCarveOut = newCurrency.GetTotalCarveOut();

        if (totalCarveOut)
        {
            if (issuedWeight < totalCarveOut)
            {
                calcState.ApplyCarveouts(totalCarveOut - issuedWeight);
                issuedWeight = 0;
            }
            else
            {
                issuedWeight -= totalCarveOut;
            }
        }
        if (newCurrency.preLaunchDiscount)
        {
            if (issuedWeight <= newCurrency.preLaunchDiscount)
            {
                calcState.ApplyCarveouts(newCurrency.preLaunchDiscount - issuedWeight);
                issuedWeight = 0;
            }
            else
            {
                issuedWeight -= newCurrency.preLaunchDiscount;
            }
        }

        CAmount preAllocTotal = newCurrency.GetTotalPreallocation();

        if (preAllocTotal)
        {
            calcState.UpdateWithEmission(preAllocTotal, issuedWeight);
        }

        // ensure that no weight goes below lower limit
        for (auto oneWeight : calcState.weights)
        {
            if (oneWeight < CCurrencyDefinition::MIN_RESERVE_RATIO)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Fractional currencies must not go below 5% weight of each reserve currency before, during or after launch");
            }
        }

        for (auto &currency : newCurrency.currencies)
        {
            currencySet.insert(currency);
            if (currency == ASSETCHAINS_CHAINID)
            {
                hasCoreReserve = true;
                continue;
            }

            if (newCurrency.systemID == currency)
            {
                continue;
            }

            if (newCurrency.parent == currency)
            {
                continue;
            }

            reserveCurrencies.push_back(CCurrencyDefinition());

            bool currencyIsRegistered = false;
            if (!requiredDefinitions.count(currency))
            {
                if (!GetCurrencyDefinition(currency, reserveCurrencies.back()) ||
                    (reserveCurrencies.back().launchSystemID == ASSETCHAINS_CHAINID && reserveCurrencies.back().startBlock >= height))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "All reserve currencies of a fractional currency must be valid and past the start block " + EncodeDestination(CIdentityID(currency)));
                }
            }
        }
        if (!hasCoreReserve)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Fractional currency requires a reserve of " + std::string(ASSETCHAINS_SYMBOL) + " in addition to any other reserves");
        }
        if (newCurrency.IsGatewayConverter())
        {
            if (!(currencySet.count(newCurrency.launchSystemID) && currencySet.count(newCurrency.gatewayID)))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid gateway converter does not contain both launch chain and new PBaaS chain or gateway's native currencies");
            }
        }
    }
    return newCurrency;
}

UniValue definecurrency(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 14)
    {
        throw runtime_error(
            "definecurrency '{\"name\": \"coinortokenname\", ..., \"nodes\":[{\"networkaddress\":\"identity\"},..]}'\\\n"
            "                '({\"name\": \"fractionalgatewayname\", ..., })' ({\"name\": \"reserveonename\", ..., }) ...\n"
            "\nThis defines a blockchain currency, either as an independent blockchain, or as a token on this blockchain. It also spends\n"
            "the identity after which this currency is named and sets a bit indicating that it has a currently active blockchain in its name.\n"
            "\nTo create a currency of any kind, the identity it is named after must be minted on the blockchain on which the currency is created.\n"
            "Once a currency is activated for an identity name, the same symbol may not be reused for another currency or blockchain, even\n"
            "if the identity is transferred, revoked or recovered, unless there is an endblock specified and the currency or blockchain has\n"
            "deactivated as of that end block.\n"
            "\nAll funds to start the currency and for initial conversion amounts must be available to spend from the identity with the same\n"
            "name and ID as the currency being defined.\n"
            "\nArguments\n"
            "      {\n"
            "         \"options\" : n,                  (int,    optional) bits (in hexadecimal):\n"
            "                                                             1 = FRACTIONAL\n"
            "                                                             2 = IDRESTRICTED\n"
            "                                                             4 = IDSTAKING\n"
            "                                                             8 = IDREFERRALS\n"
            "                                                             0x10 = IDREFERRALSREQUIRED\n"
            "                                                             0x20 = TOKEN\n"
            "                                                             0x40 = RESERVED\n"
            "                                                             0x100 = IS_PBAAS_CHAIN\n"
            "\n"
            "         \"name\" : \"xxxx\",              (string, required) name of existing identity with no active or pending blockchain\n"
            "         \"idregistrationfees\" : \"xx.xx\", (value, required) price of an identity in native currency\n"
            "         \"idreferrallevels\" : n,         (int, required) how many levels ID referrals go back in reward\n"

            "         \"notaries\" : \"[identity,..]\", (list, optional) list of identities that are assigned as chain notaries\n"
            "         \"minnotariesconfirm\" : n,       (int, optional) unique notary signatures required to confirm an auto-notarization\n"
            "         \"notarizationreward\" : \"xx.xx\", (value,  required) default VRSC notarization reward total for first billing period\n"
            "         \"proofprotocol\" : n,            (int,    optional) if 2, currency can be minted by whoever controls the ID\n"
            "                                                           1 = PROOF_PBAASMMR - Verus MMR proof, no notaries required\n"
            "                                                           2 = PROOF_CHAINID - non-native only - currency has centralized control, and\n"
            "                                                                               can mint/burn & change weights\n"
            "                                                           3 = PROOF_ETHNOTARIZATION - ETH & PATRICIA TRIE proof (do not attempt without\n"
            "                                                                                       full understanding + C++, JavaScript & Solidity dev(s))\n"
            "\n"
            "         \"notarizationprotocol\" : n,            (int,    optional) if 2, currency can be minted by whoever controls the ID\n"
            "                                                           1 = PROOF_PBAASMMR - Verus MMR proof, no notaries required\n"
            "                                                           2 = PROOF_CHAINID - chain ID is sole notary for proof, no evidence required\n"
            "                                                           3 = PROOF_ETHNOTARIZATION - Ethereum notarization & PATRICIA TRIE proof\n"
            "\n"
            "         \"expiryheight\"  : n,            (int,    optional) block height at which the transaction expires, default: curheight + 20\n"
            "         \"startblock\"    : n,            (int,    optional) VRSC block must be notarized into block 1 of PBaaS chain, default: expiryheight\n"
            "         \"endblock\"      : n,            (int,    optional) chain or currency intended to end life after this height, 0 = no end\n"

            "         \"currencies\"    : \"[\"VRSC\",..]\", (list, optional) reserve currencies backing this chain in equal amounts\n"
            "         \"weights\"       : \"[\"xx.xx\",..]\", (list, optional) the weight of each reserve currency in a fractional currency\n"
            "         \"conversions\"   : \"[\"xx.xx\",..]\", (list, optional) if present, must be same size as currencies. pre-launch conversion ratio overrides\n"
            "         \"minpreconversion\" : \"[\"xx.xx\",..]\", (list, optional) must be same size as currencies. minimum in each currency to launch\n"
            "         \"maxpreconversion\" : \"[\"xx.xx\",..]\", (list, optional) maximum in each currency allowed\n"

            "         \"initialcontributions\" : \"[\"xx.xx\",..]\", (list, optional) initial contribution in each currency\n"
            "         \"prelaunchdiscount\" : \"xx.xx\" (value, optional) for fractional reserve currencies less than 100%, discount on final price at launch\n"
            "         \"initialsupply\" : \"xx.xx\"    (value, required for fractional) supply after conversion of contributions, before preallocation\n"
            "         \"prelaunchcarveout\" : \"0.xx\", (value, optional) identities and % of pre-converted amounts from each reserve currency\n"
            "         \"preallocations\" : \"[{\"identity\":xx.xx}..]\", (list, optional)  list of identities and amounts from pre-allocation\n"
            "         \"gatewayconvertername\" : \"name\", (string, optional) if this is a PBaaS chain, this names a co-launched gateway converter currency\n"

            "         \"blocktime\"          : n, (int, optional) target time in seconds to average between blocks (default 60 seconds)\n"
            "         \"powaveragingwindow\" : n, (int, optional) total number of blocks to look back when averaging for DAA (default 45 blocks)\n"
            "         \"notarizationperiod\" : n, (int, optional) min period miners/stakers must wait to post new notarization to chain (default 10 min at any blocktime)\n"

            "         \"eras\"          : \"objarray\", (array, optional) data specific to each era, maximum 3\n"
            "         {\n"
            "            \"reward\"     : n,           (int64,  required) native initial block rewards in each period\n"
            "            \"decay\"      : n,           (int64,  optional) reward decay for each era\n"
            "            \"halving\"    : n,           (int,    optional) halving period for each era\n"
            "            \"eraend\"     : n,           (int,    optional) ending block of each era\n"
            "         }\n"
            "         \"nodes\"         : \"[obj, ..]\", (objectarray, optional) up to 5 nodes that can be used to connect to the blockchain"
            "         [{\n"
            "            \"networkaddress\" : \"ip:port\", (string,  optional) internet or other supported address for node\n"
            "            \"nodeidentity\" : \"name@\",  (string, optional) published node identity\n"
            "         }, .. ]\n"
            "      }\n"

            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"transactionid\", (string) The transaction id\n"
            "  \"tx\"   : \"json\",          (json)   The transaction decoded as a transaction\n"
            "  \"hex\"  : \"data\"           (string) Raw data for signed transaction\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("definecurrency", "jsondefinition")
            + HelpExampleRpc("definecurrency", "jsondefinition")
        );
    }

    CheckPBaaSAPIsValid();
    bool isVerusActive = IsVerusActive();

    uint160 thisChainID = ConnectedChains.ThisChain().GetID();

    if (!params[0].isObject())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "JSON object required. see help.");
    }

    if (!pwalletMain)
    {
        throw JSONRPCError(RPC_WALLET_ERROR, "must have active wallet to define PBaaS chain");
    }

    UniValue valStr(UniValue::VSTR);
    if (!valStr.read(params[0].write()))
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid characters in blockchain definition");
    }

    LOCK2(cs_main, pwalletMain->cs_wallet);
    uint32_t height = chainActive.Height();

    std::map<uint160, std::string> requiredCurrencyDefinitions;
    CCurrencyDefinition newChain(ValidateNewUnivalueCurrencyDefinition(params[0], height, ASSETCHAINS_CHAINID, requiredCurrencyDefinitions));

    UniValue expiryUni = find_value(params[0], "expiryheight");
    uint32_t expiryHeight = uni_get_int(expiryUni, chainActive.Height() + PBAAS_MINSTARTBLOCKDELTA);

    if (requiredCurrencyDefinitions.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "currency definition has invalid or undefined currency references");
    }

    CCurrencyDefinition parentCurrency;

    if (!newChain.parent.IsNull())
    {
        parentCurrency = ConnectedChains.GetCachedCurrency(newChain.parent);
    }
    else
    {
        parentCurrency = ConnectedChains.ThisChain();
    }

    bool invalidUnlessNFT = false;
    if (newChain.parent != thisChainID &&
        !(isVerusActive && newChain.GetID() == ASSETCHAINS_CHAINID && newChain.parent.IsNull()) &&
        !(parentCurrency.IsGateway() && !parentCurrency.IsNameController() && parentCurrency.launchSystemID == ASSETCHAINS_CHAINID))
    {
        invalidUnlessNFT = true;
        if (!newChain.IsNFTToken() )
        {
            // parent chain must be current chain or be VRSC or VRSCTEST registered by the owner of the associated ID
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Attempting to define a currency relative to a parent that is not a valid gateway or the current chain.");
        }
    }

    uint160 newChainID = newChain.GetID();

    CIdentity launchIdentity;
    uint32_t idHeight = 0;
    CTxIn idTxIn;
    bool canSign = false, canSpend = false;

    std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
    if (pwalletMain->GetIdentity(newChainID, keyAndIdentity))
    {
        canSign = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SIGN;
        canSpend = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SPEND;
        launchIdentity = static_cast<CIdentity>(keyAndIdentity.second);
    }

    if (!canSign)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot sign for ID " + newChain.name);
    }

    if (!(launchIdentity = CIdentity::LookupIdentity(newChainID, 0, &idHeight, &idTxIn)).IsValidUnrevoked() || launchIdentity.HasActiveCurrency())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ID " + newChain.name + " not found, is revoked, or already has an active currency defined");
    }

    if (launchIdentity.systemID != ASSETCHAINS_CHAINID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot launch any currency or tokenized ID control unless the root identity is rooted on this system");
    }

    CTransaction idTx;
    uint256 blockHash;
    if (!GetTransaction(idTxIn.prevout.hash, idTx, blockHash, true))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot load ID transaction for " + VERUS_CHAINNAME);
    }
    TransactionBuilder tb = TransactionBuilder(Params().GetConsensus(), height + 1, pwalletMain);
    tb.SetExpiryHeight(expiryHeight);
    tb.AddTransparentInput(idTxIn.prevout, idTx.vout[idTxIn.prevout.n].scriptPubKey, idTx.vout[idTxIn.prevout.n].nValue);

    // if this is a PBaaS chain definition, and we have a gateway converter currency to also start,
    // validate and start the converter currency as well
    CCurrencyDefinition newGatewayConverter;
    std::map<uint160, std::map<std::string, UniValue>> newReserveDefinitions;
    std::map<uint160, CCurrencyDefinition> newReserveCurrencies;
    std::vector<CNodeData> startupNodes;
    if (newChain.IsPBaaSChain() || newChain.IsGateway())
    {
        UniValue launchNodesUni = find_value(params[0], "nodes");
        if (launchNodesUni.isArray() && launchNodesUni.size())
        {
            for (int i = 0; i < launchNodesUni.size(); i++)
            {
                std::string networkAddress;
                std::string nodeIdentity;
                CNodeData oneNode;
                if (launchNodesUni[i].isObject() &&
                    (oneNode = CNodeData(launchNodesUni[i])).IsValid())
                {
                    startupNodes.push_back(oneNode);
                }
            }
        }
        if (startupNodes.size() > CCurrencyDefinition::MAX_STARTUP_NODES)
        {
            startupNodes.resize(CCurrencyDefinition::MAX_STARTUP_NODES);
        }
        if (!startupNodes.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Must specify valid, initial launch nodes for a PBaaS chain");
        }

        if (!newChain.gatewayConverterName.empty())
        {
            // create a set of default, necessary parameters
            // then apply the parameters passed, which will simplify the
            // specification with defaults
            std::map<std::string, UniValue> gatewayConverterMap;
            gatewayConverterMap.insert(std::make_pair("options", CCurrencyDefinition::OPTION_FRACTIONAL +
                                                                 CCurrencyDefinition::OPTION_TOKEN +
                                                                 CCurrencyDefinition::OPTION_GATEWAY_CONVERTER));
            gatewayConverterMap.insert(std::make_pair("parent", EncodeDestination(CIdentityID(newChainID))));
            gatewayConverterMap.insert(std::make_pair("name", newChain.gatewayConverterName));
            gatewayConverterMap.insert(std::make_pair("launchsystemid", EncodeDestination(CIdentityID(thisChainID))));
            gatewayConverterMap.insert(std::make_pair("gateway", EncodeDestination(CIdentityID(newChain.GetID()))));

            // if this is a gateway, the converter runs on the launching chain by default
            // if PBaaS chain, on the new system
            if (newChain.IsGateway())
            {
                gatewayConverterMap.insert(std::make_pair("systemid", EncodeDestination(CIdentityID(thisChainID))));
            }
            else
            {
                gatewayConverterMap.insert(std::make_pair("systemid", EncodeDestination(CIdentityID(newChainID))));
            }

            UniValue currenciesUni(UniValue::VARR);
            currenciesUni.push_back(EncodeDestination(CIdentityID(thisChainID)));
            currenciesUni.push_back(EncodeDestination(CIdentityID(newChainID)));
            gatewayConverterMap.insert(std::make_pair("currencies", currenciesUni));

            if (params.size() > 1)
            {
                auto curKeys = params[1].getKeys();
                auto curValues = params[1].getValues();
                for (int i = 0; i < curKeys.size(); i++)
                {
                    gatewayConverterMap[curKeys[i]] = curValues[i];
                }
            }

            // set start block and gateway converter issuance
            if (newChain.IsGateway())
            {
                CEthGateway gatewayCheck;
                if (newChain.GetID() != gatewayCheck.GatewayID())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Ethereum is the only gateway supported at this time");
                }

                if (uni_get_int(gatewayConverterMap["startblock"]) < (int32_t)(height + DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA))
                {
                    gatewayConverterMap["startblock"] = (int32_t)(height + DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA);
                }
                // gateways start already running
                newChain.startBlock = 0;
            }
            else
            {
                gatewayConverterMap["startblock"] = newChain.startBlock;
            }

            gatewayConverterMap["gatewayconverterissuance"] = ValueFromAmount(newChain.gatewayConverterIssuance);

            UniValue newCurUni(UniValue::VOBJ);
            for (auto oneProp : gatewayConverterMap)
            {
                newCurUni.pushKV(oneProp.first, oneProp.second);
            }

            uint32_t converterOptions = uni_get_int64(gatewayConverterMap["options"]);
            converterOptions &= ~(CCurrencyDefinition::OPTION_GATEWAY + CCurrencyDefinition::OPTION_PBAAS);
            converterOptions |= CCurrencyDefinition::OPTION_FRACTIONAL +
                                CCurrencyDefinition::OPTION_TOKEN +
                                CCurrencyDefinition::OPTION_GATEWAY_CONVERTER;
            gatewayConverterMap["options"] = (int64_t)converterOptions;

            //printf("%s: gatewayConverter definition:\n%s\n", __func__, newCurUni.write(1,2).c_str());

            // set the parent and system of the new gateway converter to the new currency
            std::map<uint160, std::string> autoCurrencyNames;
            newGatewayConverter = ValidateNewUnivalueCurrencyDefinition(newCurUni, height, newChain.systemID, autoCurrencyNames);

            if (autoCurrencyNames.size())
            {
                if (!newChain.IsGateway())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Only a gateway definition may also define currencies to use as bridge converter reserves");
                }

                // any required currency definitions will include their text name and have a parent of the gateway
                // to qualify for auto-definition. we also need to parse the remaining parameters
                // and verify that they are only needed definitions

                for (auto &oneCurrencyName : autoCurrencyNames)
                {
                    // for each name, we will create a definition that has a systemID of the current system and parent of the gateway
                    std::map<std::string, UniValue> oneCurEntry;
                    oneCurEntry["name"] = oneCurrencyName.second;
                    oneCurEntry["parent"] = EncodeDestination(CIdentityID(newChainID));
                    oneCurEntry["systemid"] = EncodeDestination(CIdentityID(newChainID));
                    oneCurEntry["launchsystemid"] = EncodeDestination(CIdentityID(newChainID));
                    oneCurEntry["nativecurrencyid"] = DestinationToTransferDestination(CIdentityID(oneCurrencyName.first)).ToUniValue();
                    oneCurEntry["options"] = CCurrencyDefinition::OPTION_TOKEN;
                    oneCurEntry["proofprotocol"] = newChain.proofProtocol;
                    oneCurEntry["notarizationprotocol"] = CCurrencyDefinition::NOTARIZATION_AUTO;

                    newReserveDefinitions[oneCurrencyName.first] = oneCurEntry;
                }

                if (params.size() > 2)
                {
                    for (int paramIdx = 2; paramIdx < params.size(); paramIdx++)
                    {
                        uint160 reserveParentID;
                        std::string checkName = CleanName(uni_get_str(find_value(params[paramIdx], "name")), reserveParentID, true);
                        if (reserveParentID != newChainID && reserveParentID != ASSETCHAINS_CHAINID)
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Only reserves on the gateway may be defined as additional currency definition parameters");
                        }
                        reserveParentID = newChainID;
                        uint160 autoReserveID = CIdentity::GetID(checkName, reserveParentID);
                        if (!newReserveDefinitions.count(autoReserveID))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency " + checkName + " is not a required reserve definition");
                        }
                        auto curKeys = params[paramIdx].getKeys();
                        auto curValues = params[paramIdx].getValues();
                        for (int i = 0; i < curKeys.size(); i++)
                        {
                            newReserveDefinitions[autoReserveID][curKeys[i]] = curValues[i];
                        }
                    }
                }
                // now, loop through all new currency definitions and define them
                // disallow: pre-allocation, prelaunch discount, future start block, fractional currency, any form of launch
                for (auto &oneDefinition : newReserveDefinitions)
                {
                    UniValue oneDefUni(UniValue::VOBJ);
                    for (auto &oneProp : oneDefinition.second)
                    {
                        oneDefUni.pushKV(oneProp.first, oneProp.second);
                    }
                    CCurrencyDefinition newReserveDef(oneDefUni);
                    if (!(newReserveDef.IsValid() &&
                          newReserveDef.IsToken() &&
                          !newReserveDef.IsFractional() &&
                          newReserveDef.systemID == newChainID &&
                          newReserveDef.parent == newChainID &&
                          newReserveDef.nativeCurrencyID.IsValid() &&
                          newReserveDef.launchSystemID == newChainID &&
                          newReserveDef.startBlock == 0 &&
                          newReserveDef.endBlock == 0 &&
                          newReserveDef.proofProtocol == newChain.proofProtocol))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid auto-reserve currency definition");
                    }
                    if (newChain.IsGateway())
                    {
                        newReserveDef.gatewayID = newChainID;
                    }
                    newReserveCurrencies[oneDefinition.first] = newReserveDef;
                }
            }
            else if (params.size() > 2)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Too many parameters. Please see help.");
            }

            // check that basics are correct, fractional that includes correct currencies, etc.
            if (newGatewayConverter.parent != newChainID ||
                !newGatewayConverter.IsFractional() ||
                !newGatewayConverter.IsToken())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "A gateway currency must have the PBaaS chain as parent and be a fractional token");
            }

            auto currencyMap = newGatewayConverter.GetCurrenciesMap();
            if (!currencyMap.count(ASSETCHAINS_CHAINID) ||
                !currencyMap.count(newChainID) ||
                newGatewayConverter.weights[currencyMap[ASSETCHAINS_CHAINID]] < (SATOSHIDEN / 10) ||
                newGatewayConverter.weights[currencyMap[newChainID]] < (SATOSHIDEN / 10))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "A gateway currency must be a fractional token that includes both the launch coin and PBaaS native coin at 10% or greater ratio each");
            }
        }
        else if (!IsVerusActive() || !PBAAS_TESTMODE)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Blockchain and gateway launches currently require a gateway converter basket for fee conversion");
        }
    }
    else if (!newChain.gatewayConverterName.empty() || params.size() > 1)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "A second currency definition is only supported as a converter currency for a PBaaS chain or gateway");
    }

    // now, we have one or two currencies. if we have two, it is because the first is a PBaaS chain, and the second
    // is its gateway currency. We will create an ID and currency launch definition for the new currency. The ID will
    // be controlled by the same primary addresses and have the same revocation and recovery IDs as the primary ID.
    //
    // Create the outputs:
    // 1. Updated identity with active currency
    // 2. Currency definition
    // 3. Notarization thread
    // 4. Export thread - working to deprecate
    // 4. Import thread (if PBaaS, this is for imports from the PBaaS chain)
    // 5. Initial contribution exports
    // (optional for PBaaS chain or gateway):
    // 6. Converter currency ID with active currency
    // 7. Converter currency definition for start on the new PBaaS chain, pre-launching from current chain
    // 3. Converter notarization thread
    // 4. Converter export thread - working to deprecate
    // 8. Converter import thread (for imports to gateway currency from PBaaS chain for this chain as well)
    // ensure that the appropriate identity is an input to the transaction,
    // and fund the transaction

    // first, we need the identity output with currency activated
    launchIdentity.UpgradeVersion(height);
    launchIdentity.ActivateCurrency();
    if (newChain.IsNFTToken())
    {
        launchIdentity.ActivateTokenizedControl();
    }
    tb.AddTransparentOutput(launchIdentity.IdentityUpdateOutputScript(height + 1), 0);

    // now, create the currency definition output
    CCcontract_info CC;
    CCcontract_info *cp;
    cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);
    CPubKey pk(ParseHex(CC.CChexstr));

    std::vector<CTxDestination> dests({pk});

    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, &newChain)),
                                         CCurrencyDefinition::DEFAULT_OUTPUT_VALUE);

    CAmount mainImportFee = ConnectedChains.ThisChain().LaunchFeeImportShare(newChain.options);
    CCurrencyValueMap mainImportFees(std::vector<uint160>({thisChainID}), std::vector<CAmount>({mainImportFee}));
    CAmount converterImportFee = 0;
    CAmount newReserveImportFees = 0;
    CCurrencyValueMap converterImportFees;

    CCoinbaseCurrencyState newCurrencyState;
    uint32_t lastImportHeight = newChain.IsPBaaSChain() || newChain.IsGateway() ? 1 : height;

    // if it's a mapped currency, we don't need to add anything but the definition with no launch period
    bool isMappedCurrency = newChain.IsToken() &&
                            !newChain.IsGateway() && !newChain.IsPBaaSChain() &&
                            !newChain.IsGatewayConverter() &&
                            newChain.nativeCurrencyID.IsValid() &&
                            (parentCurrency.IsGateway() || parentCurrency.GetID() == ASSETCHAINS_CHAINID) &&
                            newChain.systemID != ASSETCHAINS_CHAINID;

    CAmount totalLaunchFee = ConnectedChains.ThisChain().GetCurrencyRegistrationFee(newChain.options);
    CAmount notaryFeeShare = 0;

    if (!isMappedCurrency)
    {
        // create import and export outputs
        cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
        pk = CPubKey(ParseHex(CC.CChexstr));

        if (newChain.proofProtocol == newChain.PROOF_PBAASMMR ||
            newChain.proofProtocol == newChain.PROOF_ETHNOTARIZATION ||
            newChain.proofProtocol == newChain.PROOF_CHAINID)
        {
            dests = std::vector<CTxDestination>({pk.GetID()});
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid notarization protocol specified");
        }

        CCrossChainImport cci = CCrossChainImport(newChain.SystemOrGatewayID(),
                                                lastImportHeight,
                                                newChainID,
                                                CCurrencyValueMap(),
                                                CCurrencyValueMap());
        cci.SetSameChain(newChain.systemID == ASSETCHAINS_CHAINID);
        cci.SetDefinitionImport(true);
        if (newChainID == ASSETCHAINS_CHAINID || newChain.IsGateway())
        {
            cci.SetPostLaunch();
            cci.SetInitialLaunchImport();
        }
        cci.exportTxOutNum = tb.mtx.vout.size() + 2;
        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci)), 0);

        // get initial currency state at this height
        newCurrencyState = ConnectedChains.GetCurrencyState(newChain, height + 1);

        newCurrencyState.SetPrelaunch();

        CPBaaSNotarization pbn = CPBaaSNotarization(newChainID,
                                                    newCurrencyState,
                                                    height,
                                                    CUTXORef(),
                                                    0);

        pbn.SetSameChain();
        pbn.SetDefinitionNotarization();
        pbn.nodes = startupNodes;

        if (newCurrencyState.GetID() == ASSETCHAINS_CHAINID || newChain.IsGateway() || isMappedCurrency)
        {
            newChain.startBlock = 1;
            newCurrencyState.SetPrelaunch(false);
            newCurrencyState.SetLaunchConfirmed();
            newCurrencyState.SetLaunchCompleteMarker();
            pbn.currencyState = newCurrencyState;
            pbn.SetPreLaunch(false);
            pbn.SetLaunchCleared();
            pbn.SetLaunchConfirmed();
            pbn.SetLaunchComplete();
        }
        else
        {
            pbn.SetPreLaunch();
        }

        // make the first chain notarization output
        cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
        CTxDestination notarizationDest;

        if (newChain.notarizationProtocol == newChain.NOTARIZATION_AUTO ||
            newChain.notarizationProtocol == newChain.NOTARIZATION_NOTARY_CONFIRM ||
            newChain.notarizationProtocol == newChain.NOTARIZATION_NOTARY_CHAINID)
        {
            notarizationDest = CPubKey(ParseHex(CC.CChexstr));
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "No valid notarization protocol specified");
        }

        dests = std::vector<CTxDestination>({notarizationDest});

        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &pbn)),
                                            CPBaaSNotarization::MIN_NOTARIZATION_OUTPUT);

        // export thread
        cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

        CCrossChainExport ccx = CCrossChainExport(thisChainID,
                                                0,
                                                height,
                                                (newChain.IsPBaaSChain() || newChain.IsGateway() || newChain.IsGatewayConverter()) ?
                                                    newChain.SystemOrGatewayID() :
                                                    ASSETCHAINS_CHAINID,
                                                newChainID,
                                                0,
                                                mainImportFees,
                                                mainImportFees,
                                                uint256());
        ccx.SetChainDefinition();
        if (newCurrencyState.GetID() == ASSETCHAINS_CHAINID || newChain.IsGateway() || isMappedCurrency)
        {
            ccx.SetPreLaunch(false);
            ccx.SetPostLaunch();
        }
        else
        {
            ccx.SetPreLaunch();
        }
        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &ccx)), 0);

        // make the outputs for initial contributions
        if (newChain.contributions.size() && newChain.contributions.size() == newChain.currencies.size())
        {
            for (int i = 0; i < newChain.currencies.size(); i++)
            {
                if (newChain.contributions[i] > 0)
                {
                    CAmount contribution = newChain.contributions[i] +
                                            CReserveTransactionDescriptor::CalculateAdditionalConversionFee(newChain.contributions[i]);
                    CAmount fee = CReserveTransfer::DEFAULT_PER_STEP_FEE << 1;

                    CReserveTransfer rt = CReserveTransfer(CReserveTransfer::VALID + CReserveTransfer::PRECONVERT,
                                                        newChain.currencies[i],
                                                        contribution,
                                                        ASSETCHAINS_CHAINID,
                                                        fee,
                                                        newChainID,
                                                        DestinationToTransferDestination(CIdentityID(newChainID)));

                    cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                    CPubKey pk(ParseHex(CC.CChexstr));

                    dests = std::vector<CTxDestination>({pk.GetID()});

                    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt)),
                                                        newChain.currencies[i] == thisChainID ? contribution + fee : fee);
                }
            }
        }

        // now, setup the gateway converter currency, if appropriate
        if ((newChain.IsPBaaSChain() || newChain.IsGateway()))
        {
            if (newGatewayConverter.IsValid())
            {
                cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);

                // create any new reserve currencies needed that are mapped to the gateway
                // for now, there is only an import fee for these currencies, since they do not launch
                for (auto oneNewReserve : newReserveCurrencies)
                {
                    // define one currency
                    // and add one import currency fee for each new reserve
                    newReserveImportFees += ConnectedChains.ThisChain().currencyImportFee;
                    std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});
                    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, &oneNewReserve.second)),
                                                        CCurrencyDefinition::DEFAULT_OUTPUT_VALUE);
                }

                if (newChain.IsGateway() &&
                    newChain.notaries.size() &&
                    (newChain.notarizationProtocol == newChain.NOTARIZATION_AUTO ||
                    newChain.notarizationProtocol == newChain.NOTARIZATION_NOTARY_CONFIRM))
                {
                    // notaries all get an even share of 10% of a currency launch fee to use for notarizing
                    notaryFeeShare = ConnectedChains.ThisChain().GetCurrencyRegistrationFee(newChain.options) / 100;
                    totalLaunchFee -= notaryFeeShare;
                    CAmount oneNotaryShare = notaryFeeShare / newChain.notaries.size();
                    CAmount notaryModExtra = notaryFeeShare % newChain.notaries.size();
                    for (auto &oneNotary : newChain.notaries)
                    {
                        tb.AddTransparentOutput(CIdentityID(oneNotary), notaryModExtra ? notaryModExtra--, oneNotaryShare + 1 : oneNotaryShare);
                    }
                }

                newGatewayConverter.gatewayConverterIssuance = newChain.gatewayConverterIssuance;

                cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);
                std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});
                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, &newGatewayConverter)),
                                                    CCurrencyDefinition::DEFAULT_OUTPUT_VALUE);

                // get initial currency state at this height
                CCoinbaseCurrencyState gatewayCurrencyState = ConnectedChains.GetCurrencyState(newGatewayConverter, chainActive.Height());
                int currencyIndex = gatewayCurrencyState.GetReserveMap()[newChainID];

                gatewayCurrencyState.reserveIn[currencyIndex] += newChain.gatewayConverterIssuance;

                uint160 gatewayCurrencyID = newGatewayConverter.GetID();

                CPBaaSNotarization gatewayPbn = CPBaaSNotarization(gatewayCurrencyID,
                                                                gatewayCurrencyState,
                                                                height,
                                                                CUTXORef(),
                                                                0);

                // launch notarizations are on this chain
                gatewayPbn.SetSameChain();
                gatewayPbn.SetPreLaunch();
                gatewayPbn.SetDefinitionNotarization();

                // create import and export outputs
                cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
                pk = CPubKey(ParseHex(CC.CChexstr));

                if (newGatewayConverter.proofProtocol == newGatewayConverter.PROOF_PBAASMMR ||
                    newGatewayConverter.proofProtocol == newGatewayConverter.PROOF_CHAINID ||
                    newGatewayConverter.proofProtocol == newGatewayConverter.PROOF_ETHNOTARIZATION)
                {
                    dests = std::vector<CTxDestination>({pk.GetID()});
                }
                else
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "None or invalid notarization protocol specified");
                }

                // if this is a token on this chain, the transfer that is output here is burned through the export
                // and merges with the import thread. we multiply new input times 2, to cover both the import thread output
                // and the reserve transfer outputs.
                CCrossChainImport gatewayCci = CCrossChainImport(newGatewayConverter.systemID, lastImportHeight, gatewayCurrencyID, CCurrencyValueMap(), CCurrencyValueMap());
                gatewayCci.SetSameChain(newGatewayConverter.systemID == ASSETCHAINS_CHAINID);
                gatewayCci.SetDefinitionImport(true);

                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &gatewayCci)), 0);

                // make the first chain notarization output
                cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
                CTxDestination notarizationDest;

                if (newGatewayConverter.notarizationProtocol == newGatewayConverter.NOTARIZATION_AUTO ||
                    newGatewayConverter.notarizationProtocol == newGatewayConverter.NOTARIZATION_NOTARY_CONFIRM ||
                    newGatewayConverter.notarizationProtocol == newGatewayConverter.NOTARIZATION_NOTARY_CHAINID)
                {
                    notarizationDest = CPubKey(ParseHex(CC.CChexstr));
                }
                else
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "None or notarization protocol specified");
                }

                dests = std::vector<CTxDestination>({notarizationDest});

                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &gatewayPbn)),
                                                    CPBaaSNotarization::MIN_NOTARIZATION_OUTPUT);

                converterImportFee = ConnectedChains.ThisChain().LaunchFeeImportShare(newGatewayConverter.options);
                converterImportFees.valueMap[thisChainID] += converterImportFee;

                // export thread
                cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
                dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
                CCrossChainExport gatewayCcx = CCrossChainExport(thisChainID, 0, height, newGatewayConverter.systemID, gatewayCurrencyID, 0, converterImportFees, converterImportFees, uint256());
                gatewayCcx.SetPreLaunch();
                gatewayCcx.SetChainDefinition();

                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &gatewayCcx)), 0);

                // make the outputs for initial contributions
                if (newGatewayConverter.contributions.size() && newGatewayConverter.contributions.size() == newGatewayConverter.currencies.size())
                {
                    for (int i = 0; i < newGatewayConverter.currencies.size(); i++)
                    {
                        if (newGatewayConverter.contributions[i] > 0)
                        {
                            CAmount contribution = newGatewayConverter.contributions[i] +
                                                    CReserveTransactionDescriptor::CalculateAdditionalConversionFee(newGatewayConverter.contributions[i]);
                            CAmount fee = CReserveTransfer::DEFAULT_PER_STEP_FEE << 1;

                            CReserveTransfer rt = CReserveTransfer(CReserveTransfer::VALID + CReserveTransfer::PRECONVERT,
                                                                newGatewayConverter.currencies[i],
                                                                contribution,
                                                                ASSETCHAINS_CHAINID,
                                                                fee,
                                                                gatewayCurrencyID,
                                                                DestinationToTransferDestination(CIdentityID(newChainID)));

                            cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                            CPubKey pk(ParseHex(CC.CChexstr));

                            dests = std::vector<CTxDestination>({pk.GetID()});

                            tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt)),
                                                                newGatewayConverter.currencies[i] == thisChainID ? contribution + fee : fee);
                        }
                    }
                }
            }
        }
    }

    // figure all launch fees, including export and import
    if (converterImportFee)
    {
        totalLaunchFee += ConnectedChains.ThisChain().GetCurrencyRegistrationFee(newGatewayConverter.options);
    }
    totalLaunchFee += newReserveImportFees;

    CAmount totalLaunchExportFee = totalLaunchFee - (mainImportFee + converterImportFee);
    if (newCurrencyState.IsValid() && newCurrencyState.GetID() != ASSETCHAINS_CHAINID && !isMappedCurrency)
    {
        cp = CCinit(&CC, EVAL_RESERVE_DEPOSIT);
        pk = CPubKey(ParseHex(CC.CChexstr));
        dests = std::vector<CTxDestination>({pk});

        CReserveDeposit launchDeposit = CReserveDeposit(newChainID, CCurrencyValueMap());
        if (mainImportFee)
        {
            launchDeposit.reserveValues.valueMap[ASSETCHAINS_CHAINID] = mainImportFee;
        }
        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &launchDeposit)),
                                            mainImportFee);
    }
    tb.SetFee(totalLaunchExportFee);
    tb.SendChangeTo(launchIdentity.GetID());
    tb.SendChangeTo(libzcash::SaplingPaymentAddress(), uint256());

    if (newGatewayConverter.IsValid())
    {
        uint160 gatewayDepositCurrencyID = newGatewayConverter.systemID == thisChainID ?
                                           newGatewayConverter.GetID() :
                                           newGatewayConverter.systemID;
        CReserveDeposit launchDeposit = CReserveDeposit(gatewayDepositCurrencyID, CCurrencyValueMap());
        if (converterImportFee)
        {
            launchDeposit.reserveValues.valueMap[ASSETCHAINS_CHAINID] = converterImportFee;
        }
        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &launchDeposit)),
                                            converterImportFee);
    }

    // create the transaction
    CReserveTransactionDescriptor rtxd;
    {
        LOCK(mempool.cs);
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);
        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        view.SetBackend(viewMemPool);
        rtxd = CReserveTransactionDescriptor(tb.mtx, view, height + 1);
    }

    // get a native currency input capable of paying a fee, and make our notary ID the change address
    std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
    std::vector<COutput> vCoins;
    CCurrencyValueMap totalReservesNeeded = rtxd.ReserveOutputMap();
    CCurrencyValueMap totalCurrenciesNeeded = totalReservesNeeded;
    totalCurrenciesNeeded.valueMap[ASSETCHAINS_CHAINID] = rtxd.nativeOut + totalLaunchExportFee;
    CTxDestination fromID(CIdentityID(launchIdentity.GetID()));
    pwalletMain->AvailableReserveCoins(vCoins,
                                       false,
                                       nullptr,
                                       true,
                                       true,
                                       &fromID,
                                       &totalCurrenciesNeeded,
                                       false);

    for (COutput &out : vCoins)
    {
        std::vector<CTxDestination> addresses;
        int nRequired;
        bool canSign, canSpend;
        CTxDestination address;
        txnouttype txType;
        if (!ExtractDestinations(out.tx->vout[out.i].scriptPubKey, txType, addresses, nRequired, pwalletMain, &canSign, &canSpend))
        {
            continue;
        }

        // if we have more address destinations than just this address and have specified from a single ID only,
        // the condition must be such that the ID itself can spend, even if this wallet cannot due to a multisig
        // ID. if the ID cannot spend, even given a valid multisig ID, then to select this as a source without
        // an explicit, multisig match would cause potentially unwanted sourcing of funds. a spend just to this ID
        // is fine.

        COptCCParams p, m;
        // if we can't spend and can only sign,
        // ensure that this output is spendable by just this ID as a 1 of n and 1 of n at the master
        // smart transaction level as well
        if (!canSpend &&
            (!canSign ||
                !(out.tx->vout[out.i].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                (p.version < COptCCParams::VERSION_V3 ||
                (p.vData.size() &&
                    (m = COptCCParams(p.vData.back())).IsValid() &&
                    (m.m == 1 || m.m == 0))) &&
                p.m == 1)))
        {
            continue;
        }
        else
        {
            out.fSpendable = true;      // this may not really be spendable, but set it if its the correct ID source and can sign
        }
    }

    CCurrencyValueMap reservesUsed;
    CAmount nativeUsed;
    if (!pwalletMain->SelectReserveCoinsMinConf(rtxd.ReserveOutputMap(),
                                                rtxd.nativeOut + totalLaunchExportFee,
                                                0,
                                                1,
                                                vCoins,
                                                setCoinsRet,
                                                reservesUsed,
                                                nativeUsed))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Insufficient funds held by " + launchIdentity.name + " identity.");
    }

    for (auto &oneInput : setCoinsRet)
    {
        tb.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second),
                                                oneInput.first->vout[oneInput.second].scriptPubKey,
                                                oneInput.first->vout[oneInput.second].nValue);
    }

    auto builtTxResult = tb.Build(true);

    CTransaction retTx;
    bool partialSig = !builtTxResult.IsTx() && IsHex(builtTxResult.GetError()) && DecodeHexTx(retTx, builtTxResult.GetError());

    if (!builtTxResult.IsTx() && !partialSig)
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, newChain.name + ": " + builtTxResult.GetError());
    }
    else if (!partialSig)
    {
        retTx = builtTxResult.GetTxOrThrow();
    }

    UniValue uvret(UniValue::VOBJ);
    UniValue txJSon(UniValue::VOBJ);
    TxToJSON(retTx, uint256(), txJSon);
    uvret.push_back(Pair("tx",  txJSon));

    string strHex = EncodeHexTx(retTx);
    uvret.push_back(Pair("hex", strHex));

    return uvret;
}

UniValue registernamecommitment(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() < 2 || params.size() > 5))
    {
        throw runtime_error(
            "registernamecommitment \"name\" \"controladdress\" (\"referralidentity\") (\"parentnameorid\") (\"sourceoffunds\")\n"
            "\nRegisters a name commitment, which is required as a source for the name to be used when registering an identity. The name commitment hides the name itself\n"
            "while ensuring that the miner who mines in the registration cannot front-run the name unless they have also registered a name commitment for the same name or\n"
            "are willing to forfeit the offer of payment for the chance that a commitment made now will allow them to register the name in the future.\n\n"

            "Names must not have leading, trailing, or multiple consecutive spaces and must not include any of the following characters between parentheses (\\/:*?\"<>|@)\n"

            "\nArguments\n"
            "\"name\"                           (string, required)  the unique name to commit to. creating a name commitment is not a registration, and if one is\n"
            "                                                       created for a name that exists, it may succeed, but will never be able to be used.\n"
            "\"controladdress\"                 (address, required) address that will control this commitment. IMPORTANT: this is not necessarily the address that should\n"
            "                                                         control the actual ID, and it should be present in the current wallet that is registering the ID.\n"
            "                                                         Change may go to this address.\n"
            "\"referralidentity\"               (identity, optional)friendly name or identity address that is provided as a referral mechanism and to lower network cost of the ID\n"
            "\"parentnameorid-pbaasonly\"       (currency, optional)friendly name or currency i-address, which will be the parent of this ID and dictate issuance rules & pricing\n"
            "\"sourceoffunds\"                  (addressorid, optional) optional address to use for source of funds. if not specified, transparent wildcard \"*\" is used\n\n"

            "\nResult: obj\n"
            "{\n"
            "    \"txid\" : \"hexid\"\n"
            "    \"namereservation\" :\n"
            "    {\n"
            "        \"name\"    : \"namestr\",     (string) the unique name in this commitment\n"
            "        \"salt\"    : \"hexstr\",      (hex)    salt used to hide the commitment\n"
            "        \"referral\": \"identityaddress\", (base58) address of the referring identity if there is one\n"
            "        \"parent\"  : \"namestr\",     (string) name of the parent if not Verus or Verus test\n"
            "        \"nameid\"  : \"address\",     (base58) identity address for this identity if it is created\n"
            "    }\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("registernamecommitment", "\"name\"")
            + HelpExampleRpc("registernamecommitment", "\"name\"")
        );
    }

    CheckIdentityAPIsValid();

    // create the transaction with native coin as input
    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint32_t height = chainActive.Height();
    bool isPBaaS = CConstVerusSolutionVector::GetVersionByHeight(height) >= CActivationHeight::ACTIVATE_PBAAS;

    CCurrencyDefinition parentCurrency = ConnectedChains.ThisChain();
    uint160 parentID = parentCurrency.GetID();

    if (params.size() > 3 && !uni_get_str(params[3]).empty())
    {
        if (!isPBaaS)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot issue identities from specified parent currencies until after PBaaS activates");
        }
        parentID = ValidateCurrencyName(uni_get_str(params[3]), true, &parentCurrency);

        if (!parentCurrency.IsValid() || parentID.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parent currency");
        }
    }

    std::string sourceAddress;
    CTxDestination sourceDest;

    bool wildCardTransparentAddress = false;
    bool wildCardRAddress = false;
    bool wildCardiAddress = false;
    bool wildCardAddress = false;

    libzcash::PaymentAddress zaddressSource;
    libzcash::SaplingExpandedSpendingKey expsk;
    uint256 sourceOvk;
    bool hasZSource = false;

    if (params.size() > 4)
    {
        sourceAddress = uni_get_str(params[4]);

        wildCardTransparentAddress = sourceAddress == "*";
        wildCardRAddress = sourceAddress == "R*";
        wildCardiAddress = sourceAddress == "i*";
        wildCardAddress = wildCardTransparentAddress || wildCardRAddress || wildCardiAddress;
        hasZSource = !wildCardAddress && pwalletMain->GetAndValidateSaplingZAddress(sourceAddress, zaddressSource, true);

        // if we have a z-address as a source, re-encode it to a string, which is used
        // by the async operation, to ensure that we don't need to lookup IDs in that operation
        if (hasZSource)
        {
            sourceAddress = EncodePaymentAddress(zaddressSource);
            // We don't need to lock on the wallet as spending key related methods are thread-safe
            if (!boost::apply_visitor(HaveSpendingKeyForPaymentAddress(pwalletMain), zaddressSource)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address, no spending key found for zaddr");
            }

            auto spendingkey_ = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), zaddressSource).get();
            auto sk = boost::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
            expsk = sk.expsk;
            sourceOvk = expsk.full_viewing_key().ovk;
        }

        if (!(hasZSource ||
            wildCardAddress ||
            (sourceDest = DecodeDestination(sourceAddress)).which() != COptCCParams::ADDRTYPE_INVALID))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. First parameter must be sapling address, transparent address, identity, \"*\", \"R*\", or \"i*\",. See help.");
        }
    }

    // if we are registering an identity through a gateway, we can and should redirect fee payment through its
    // fee converter currency

    // TODO: PBAAS - enable PBaaS chains to issue IDs through their gateway converter IDs as gateways can

    CCurrencyDefinition issuingCurrency = parentCurrency;
    uint160 issuerID = parentID;
    if (!parentCurrency.IsNameController() && parentCurrency.launchSystemID == ASSETCHAINS_CHAINID && !parentCurrency.GatewayConverterID().IsNull())
    {
        issuingCurrency = ConnectedChains.GetCachedCurrency(parentCurrency.GatewayConverterID());
        if (!issuingCurrency.IsValid() || issuingCurrency.systemID != ASSETCHAINS_CHAINID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid issuing currency for this network");
        }
    }
    else if (parentCurrency.systemID != ASSETCHAINS_CHAINID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parent currency for this network");
    }

    if (issuingCurrency.NoIDs())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, ConnectedChains.GetFriendlyCurrencyName(issuingCurrency.GetID()) + " is unable to issue currencies");
    }

    std::string rawName = uni_get_str(params[0]);
    std::string name = CleanName(uni_get_str(params[0]), parentID, true, true);
    if (parentID != parentCurrency.GetID())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid implied parent currency");
    }

    uint160 idID = GetDestinationID(DecodeDestination(name + "@"));
    if (idID == ASSETCHAINS_CHAINID &&
        IsVerusActive() &&
        !CVDXF::HasExplicitParent(rawName))
    {
        name = VERUS_CHAINNAME;
        parentID.SetNull();
    }

    // if either we have an invalid name or an implied parent, that is not valid
    if (!(idID == VERUS_CHAINID && IsVerusActive() && parentID.IsNull()) &&
         (name == "" ||
          parentID != parentCurrency.GetID() ||
          (!CVDXF::HasExplicitParent(rawName) &&
           name != uni_get_str(params[0]))))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid name for commitment. Names must not have leading or trailing spaces and must not include any of the following characters between parentheses (\\/:*?\"<>|@)");
    }

    CTxDestination dest = DecodeDestination(uni_get_str(params[1]));
    if (dest.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid control address for commitment");
    }
    if (dest.which() == COptCCParams::ADDRTYPE_ID)
    {
        CIdentity controlIdentity = CIdentity::LookupIdentity(CIdentityID(GetDestinationID(dest)));
        if (!controlIdentity.IsValidUnrevoked())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "If control address in an identity, it must be a currently valid and unrevoked friendly name or i-address");
        }
        if (!pwalletMain)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "If control address in an identity, it must be present in this wallet");
        }

        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
        LOCK(pwalletMain->cs_wallet);
        if (!pwalletMain->GetIdentity(GetDestinationID(dest), keyAndIdentity) ||
            !keyAndIdentity.first.CanSign())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "If control address in an identity, this wallet must have the ability to sign");
        }
    }
    else if (dest.which() == COptCCParams::ADDRTYPE_PK || dest.which() == COptCCParams::ADDRTYPE_PK)
    {
        LOCK(pwalletMain->cs_wallet);
        if (!pwalletMain->HaveKey(GetDestinationID(dest)))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Use a control address that is an ID which this wallet can sign for, or a key address under the control of this wallet.");
        }
    }

    CIdentityID referrer;
    if (params.size() > 2 && !uni_get_str(params[2]).empty())
    {
        CTxDestination referDest = DecodeDestination(uni_get_str(params[2]));
        if (referDest.which() != COptCCParams::ADDRTYPE_ID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid referral identity for commitment, must be a currently registered friendly name or i-address");
        }
        referrer = CIdentityID(GetDestinationID(referDest));
        CIdentity referrerIdentity = CIdentity::LookupIdentity(referrer);
        if (!referrerIdentity.IsValidUnrevoked())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Referral identity for commitment must be a currently valid, unrevoked friendly name or i-address");
        }
        if (referrerIdentity.parent != parentID && referrer != parentID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Referrals must be from an identity of the same parent");
        }
    }

    CNameReservation nameRes;
    CAdvancedNameReservation advNameRes;

    if (isPBaaS && !parentID.IsNull())
    {
        advNameRes = CAdvancedNameReservation(name, parentID, referrer, GetRandHash());
    }
    else
    {
        nameRes = CNameReservation(name, referrer, GetRandHash());
    }

    if (CIdentity::LookupIdentity(CIdentity::GetID(name, parentID)).IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity already exists.");
    }

    if (params.size() <= 4)
    {
        wildCardTransparentAddress = true;
    }

    bool success = false;
    std::vector<CRecipient> newInputs;
    CTxDestination changeDest;

    std::vector<CTxDestination> dests({dest});
    int requiredSigs = 1;

    if (parentCurrency.IDRequiresPermission())
    {
        dests.push_back(CIdentityID(parentID));
        requiredSigs = 2;
    }
    else if (parentCurrency.IDReferralRequired())
    {
        dests.push_back(CIdentityID(referrer));
        requiredSigs = 2;
    }

    CCommitmentHash commitment(advNameRes.IsValid() ? advNameRes.GetCommitment() : nameRes.GetCommitment());
    CConditionObj<CCommitmentHash> condObj(EVAL_IDENTITY_COMMITMENT, dests, requiredSigs, &commitment);
    std::vector<CRecipient> outputs = std::vector<CRecipient>({{MakeMofNCCScript(condObj, &dest), CCommitmentHash::DEFAULT_OUTPUT_AMOUNT, false}});

    std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
    std::vector<SaplingNoteEntry> saplingNotes;
    CCurrencyValueMap reserveValueOut;
    CAmount nativeValueOut;
    std::vector<COutput> vCoins;

    CTxDestination from_taddress;
    if (wildCardTransparentAddress)
    {
        from_taddress = CTxDestination();
    }
    else if (wildCardRAddress)
    {
        from_taddress = CTxDestination(CKeyID(uint160()));
    }
    else if (wildCardiAddress)
    {
        from_taddress = CTxDestination(CIdentityID(uint160()));
    }
    else
    {
        from_taddress = sourceDest;
    }

    CCurrencyValueMap reservesOut;
    for (int i = 0; i < outputs.size(); i++)
    {
        CRecipient &oneOut = outputs[i];

        CCurrencyValueMap oneOutReserves;
        oneOutReserves += oneOut.scriptPubKey.ReserveOutValue();
        if (oneOut.nAmount)
        {
            oneOutReserves.valueMap[ASSETCHAINS_CHAINID] = oneOut.nAmount;
        }
        else
        {
            oneOutReserves.valueMap.erase(ASSETCHAINS_CHAINID);
        }
        reservesOut += oneOutReserves;
    }

    reservesOut = reservesOut.CanonicalMap();

    // use the transaction builder to properly make change of native and reserves
    TransactionBuilder tb(Params().consensus, height + 1, pwalletMain);

    // make sure we have enough
    CAmount nativeNeeded = CCommitmentHash::DEFAULT_OUTPUT_AMOUNT + DEFAULT_TRANSACTION_FEE;

    for (auto &oneOut : outputs)
    {
        tb.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nAmount);
    }

    if (hasZSource)
    {
        saplingNotes = find_unspent_notes(zaddressSource);
        CAmount totalFound = 0;
        int i;
        for (i = 0; i < saplingNotes.size(); i++)
        {
            totalFound += saplingNotes[i].note.value();
            if (totalFound >= nativeNeeded)
            {
                break;
            }
        }
        // remove all but the notes we'll use
        if (i < saplingNotes.size())
        {
            saplingNotes.erase(saplingNotes.begin() + i + 1, saplingNotes.end());
            success = true;
        }
    }
    else
    {
        success = find_utxos(from_taddress, vCoins) &&
                pwalletMain->SelectCoinsMinConf(nativeNeeded, 0, 0, vCoins, setCoinsRet, nativeValueOut);
    }

    if (!success)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Insufficient funds for identity commitment registration");
    }

    // aggregate all inputs into one output with only the offer coins and offer indexes
    if (saplingNotes.size())
    {
        std::vector<SaplingOutPoint> notes;
        for (auto &oneNoteInfo : saplingNotes)
        {
            notes.push_back(oneNoteInfo.op);
        }

        // Fetch Sapling anchor and witnesses
        uint256 anchor;
        std::vector<boost::optional<SaplingWitness>> witnesses;
        {
            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->GetSaplingNoteWitnesses(notes, witnesses, anchor);
        }

        // Add Sapling spends
        for (size_t i = 0; i < saplingNotes.size(); i++)
        {
            tb.AddSaplingSpend(expsk, saplingNotes[i].note, anchor, witnesses[i].get());
        }
    }
    else
    {
        for (auto &oneInput : setCoinsRet)
        {
            tb.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second),
                                    oneInput.first->vout[oneInput.second].scriptPubKey,
                                    oneInput.first->vout[oneInput.second].nValue);
        }
    }

    if (hasZSource)
    {
        tb.SendChangeTo(*boost::get<libzcash::SaplingPaymentAddress>(&zaddressSource), sourceOvk);
    }
    else if (sourceDest.which() != COptCCParams::ADDRTYPE_INVALID && !GetDestinationID(sourceDest).IsNull())
    {
        tb.SendChangeTo(sourceDest);
        changeDest = sourceDest;
    }
    else
    {
        if (dest.which() == COptCCParams::ADDRTYPE_ID)
        {

        }
        tb.SendChangeTo(dest);
        changeDest = dest;
    }

    TransactionBuilderResult preResult = tb.Build();
    CTransaction commitTx = preResult.GetTxOrThrow();

    // add to mem pool and relay
    LOCK(cs_main);

    bool relayTx;
    CValidationState state;
    {
        LOCK2(smartTransactionCS, mempool.cs);
        relayTx = myAddtomempool(commitTx, &state);
    }

    if (!relayTx)
    {
        throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Unable to prepare offer tx: " + state.GetRejectReason());
    }
    else
    {
        RelayTransaction(commitTx);
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("txid", commitTx.GetHash().GetHex()));
    ret.push_back(Pair("namereservation", advNameRes.IsValid() ? advNameRes.ToUniValue() : nameRes.ToUniValue()));
    return ret;
}

UniValue registeridentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 5)
    {
        throw runtime_error(
            "registeridentity \"jsonidregistration\" (returntx) feeoffer sourceoffunds\n"
            "\n\n"

            "\nArguments\n"
            "{\n"
            "    \"txid\" : \"hexid\",          (hex)    the transaction ID of the name commitment for this ID name\n"
            "    \"namereservation\" :\n"
            "    {\n"
            "        \"name\": \"namestr\",     (string) the unique name in this commitment\n"
            "        \"salt\": \"hexstr\",      (hex)    salt used to hide the commitment\n"
            "        \"referral\": \"identityID\", (name@ or address) must be a valid ID to use as a referrer to receive a discount\n"
            "    },\n"
            "    \"identity\" :\n"
            "    {\n"
            "        \"name\": \"namestr\",     (string) the unique name for this identity\n"
            "        ...\n"
            "    }\n"
            "}\n"
            "returntx                           (bool, optional) default=false if true, return a transaction for additional signatures rather than committing it\n"
            "feeoffer                           (amount, optional) amount to offer miner/staker for the registration fee, if missing, uses standard price\n"
            "sourceoffunds                      (addressorid, optional) optional address to use for source of funds. if not specified, transparent wildcard \"*\" is used\n\n"

            "\nResult:\n"
            "   transactionid                   (hexstr)\n"

            "\nExamples:\n"
            + HelpExampleCli("registeridentity", "jsonidregistration")
            + HelpExampleRpc("registeridentity", "jsonidregistration")
        );
    }

    CheckIdentityAPIsValid();

    // all names have a parent of the current chain
    uint160 parent = ConnectedChains.ThisChain().GetID();

    uint256 txid = uint256S(uni_get_str(find_value(params[0], "txid")));

    UniValue nameResUni = find_value(params[0], "namereservation");

    // lookup commitment to be sure that we can register this identity
    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint32_t height = chainActive.Height();
    uint32_t solVersion = CConstVerusSolutionVector::GetVersionByHeight(height + 1);
    bool isPBaaS = solVersion >= CActivationHeight::ACTIVATE_PBAAS;

    CNameReservation reservation;
    CAdvancedNameReservation advReservation;
    std::string rawName = uni_get_str(find_value(nameResUni,"name"));
    if (!find_value(nameResUni, "version").isNull() && !find_value(nameResUni, "parent").isNull())
    {
        if (!isPBaaS)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Advanced identity reservations are only valid after PBaaS activates");
        }
        advReservation = CAdvancedNameReservation(nameResUni);
    }
    else
    {
        reservation = CNameReservation(nameResUni, CVDXF::HasExplicitParent(rawName) ? uint160() : ASSETCHAINS_CHAINID);
    }

    UniValue rawID = find_value(params[0], "identity");

    int idVersion;

    if (isPBaaS)
    {
        idVersion = CIdentity::VERSION_PBAAS;
    }
    else if (solVersion >= CActivationHeight::ACTIVATE_VERUSVAULT)
    {
        idVersion = CIdentity::VERSION_VAULT;
    }
    else
    {
        idVersion = CIdentity::VERSION_VERUSID;
    }

    if (uni_get_int(find_value(rawID,"version")) == 0)
    {
        rawID.pushKV("version", idVersion);
    }

    if (uni_get_int(find_value(rawID,"minimumsignatures")) == 0)
    {
        rawID.pushKV("minimumsignatures", (int32_t)1);
    }

    CCurrencyDefinition parentCurrency = ConnectedChains.GetCachedCurrency(advReservation.IsValid() ? advReservation.parent : parent);
    if (!parentCurrency.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parent currency or currency not found");
    }

    CCurrencyDefinition issuingCurrency = parentCurrency;
    parent = parentCurrency.GetID();
    uint160 issuerID = issuingCurrency.GetID();

    CIdentity newID(rawID);
    if (!newID.IsValid(true))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid identity");
    }

    if (IsVerusActive() &&
        !CVDXF::HasExplicitParent(rawName))
    {
        CIdentity checkIdentity(newID);
        checkIdentity.parent.SetNull();
        if (checkIdentity.GetID() == ASSETCHAINS_CHAINID)
        {
            newID.parent.SetNull();
            parent.SetNull();
        }
    }
    else
    {
        newID.parent = parent;
    }

    newID.systemID = ASSETCHAINS_CHAINID;

    uint160 newIDID = newID.GetID();

    if (find_value(rawID, "revocationauthority").isNull())
    {
        newID.revocationAuthority = newID.GetID();
    }
    if (find_value(rawID, "recoveryauthority").isNull())
    {
        newID.recoveryAuthority = newID.GetID();
    }

    bool returnTx = params.size() > 1 ? uni_get_bool(params[1]) : false;

    // get the primary currency to price in and apply any conversion rates
    uint160 parentID = parentCurrency.GetID();
    issuerID = issuingCurrency.GetID();
    uint160 feePricingCurrency = issuerID;
    int64_t idReferralFee = issuingCurrency.IDReferralAmount();
    int64_t idFullRegistrationFee = issuingCurrency.IDFullRegistrationAmount();
    int64_t idReferredRegistrationFee = issuingCurrency.IDReferredRegistrationAmount();
    CCurrencyValueMap burnAmount;
    CCoinbaseCurrencyState pricingState;

    // set currency and price, as well as burn requirement
    // determine if we may use a gateway converter to issue
    if (isPBaaS)
    {
        if (issuingCurrency.NoIDs() || issuingCurrency.IsNFTToken())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency parent cannot register identities");
        }

        if (!issuingCurrency.IsNameController() && !issuingCurrency.GatewayConverterID().IsNull())
        {
            issuingCurrency = ConnectedChains.GetCachedCurrency(issuingCurrency.GatewayConverterID());
            if (!(issuingCurrency.IsValid() &&
                  issuingCurrency.IsFractional() &&
                  issuingCurrency.IsGatewayConverter() &&
                  issuingCurrency.gatewayID == parentID))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid converter for gateway to register identity");
            }
            issuerID = issuingCurrency.GetID();
        }
        else if (issuingCurrency.IsGatewayConverter())
        {
            if (issuingCurrency.gatewayID.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid gateway converter for identity registration");
            }
            CCurrencyDefinition gatewayCurrency = ConnectedChains.GetCachedCurrency(issuingCurrency.gatewayID);
            if (gatewayCurrency.GetID() != issuingCurrency.systemID)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid gateway converter system for identity registration");
            }
        }
        if (!issuingCurrency.IsValid() || issuingCurrency.systemID != ASSETCHAINS_CHAINID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid issuing currency to register identity");
        }

        if (issuingCurrency.IsFractional())
        {
            feePricingCurrency = issuingCurrency.FeePricingCurrency();
            if (!(pricingState = ConnectedChains.GetCurrencyState(issuerID, height)).IsValid() ||
                !pricingState.IsLaunchConfirmed())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency state for gateway converter to register identity");
            }
            if (feePricingCurrency != issuerID)
            {
                int32_t reserveIndex = pricingState.GetReserveMap()[feePricingCurrency];
                idReferralFee = pricingState.ReserveToNative(idReferralFee, reserveIndex);
                idFullRegistrationFee = pricingState.ReserveToNative(idFullRegistrationFee, reserveIndex);
                idReferredRegistrationFee = pricingState.ReserveToNative(idReferredRegistrationFee, reserveIndex);
            }
        }
        // aside from fractional currencies, tokens on this system or native currencies can issue IDs
        else if (!(issuingCurrency.GetID() == ASSETCHAINS_CHAINID || (issuingCurrency.systemID == ASSETCHAINS_CHAINID)))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parent currency for identity registration on this chain");
        }
    }

    CAmount feeOffer = 0;
    CIdentityID referralID = advReservation.IsValid() ? advReservation.referral : reservation.referral;
    CAmount minFeeOffer = referralID.IsNull() ? idFullRegistrationFee : idReferredRegistrationFee;

    if (params.size() > 2)
    {
        feeOffer = AmountFromValue(params[2]);
    }
    if (feeOffer == 0)
    {
        feeOffer = minFeeOffer;
    }

    if (feeOffer < minFeeOffer)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee offer must be at least " + ValueFromAmount(minFeeOffer).write());
    }

    std::string sourceAddress;
    CTxDestination sourceDest;

    bool wildCardTransparentAddress = false;
    bool wildCardRAddress = false;
    bool wildCardiAddress = false;
    bool wildCardAddress = false;

    libzcash::PaymentAddress zaddressSource;
    libzcash::SaplingExpandedSpendingKey expsk;
    uint256 sourceOvk;
    bool hasZSource = false;

    if (params.size() > 3)
    {
        sourceAddress = uni_get_str(params[3]);

        wildCardTransparentAddress = sourceAddress == "*";
        wildCardRAddress = sourceAddress == "R*";
        wildCardiAddress = sourceAddress == "i*";
        wildCardAddress = wildCardTransparentAddress || wildCardRAddress || wildCardiAddress;
        hasZSource = !wildCardAddress && pwalletMain->GetAndValidateSaplingZAddress(sourceAddress, zaddressSource, true);

        // if we have a z-address as a source, re-encode it to a string, which is used
        // by the async operation, to ensure that we don't need to lookup IDs in that operation
        if (hasZSource)
        {
            sourceAddress = EncodePaymentAddress(zaddressSource);
            // We don't need to lock on the wallet as spending key related methods are thread-safe
            if (!boost::apply_visitor(HaveSpendingKeyForPaymentAddress(pwalletMain), zaddressSource)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address, no spending key found for zaddr");
            }

            auto spendingkey_ = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), zaddressSource).get();
            auto sk = boost::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
            expsk = sk.expsk;
            sourceOvk = expsk.full_viewing_key().ovk;
        }

        if (!(hasZSource ||
            wildCardAddress ||
            (sourceDest = DecodeDestination(sourceAddress)).which() != COptCCParams::ADDRTYPE_INVALID))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. First parameter must be sapling address, transparent address, identity, \"*\", \"R*\", or \"i*\",. See help.");
        }
    }
    else
    {
        wildCardTransparentAddress = true;
    }

    // this is only used to actually create errors and is normally not
    // a parameter used for anything except testing
    enum {
        ERRTEST_NONE = 0,
        ERRTEST_UNDERPAYFEE = 1,
        ERRTEST_UNDERPAYREFERRAL = 2,
        ERRTEST_SKIPREFERRAL = 3,
        ERRTEST_WRONGREFERRAL = 4,
        ERRTEST_LAST = 4
    };
    int errorTest = ERRTEST_NONE;
    if (params.size() > 4)
    {
        errorTest = uni_get_int(params[4]);
        if (errorTest < ERRTEST_NONE || errorTest > ERRTEST_LAST)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Optional test parameter out of range");
        }
    }

    uint160 impliedParent = newID.parent;
    uint160 resParent;
    if (advReservation.IsValid())
    {
        resParent = advReservation.parent;

        if (txid.IsNull() ||
            CleanName(advReservation.name, resParent) != CleanName(newID.name, impliedParent, true) ||
            resParent != impliedParent)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid identity description or mismatched advanced reservation. Is " + CleanName(newID.name, impliedParent) + " should be " + CleanName(advReservation.name, resParent) + ".");
        }
    }
    else
    {
        if (txid.IsNull() ||
            CleanName(rawName, resParent) != CleanName(newID.name, newID.parent, true, !CVDXF::HasExplicitParent(rawName)) ||
            resParent != impliedParent)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid identity description or mismatched reservation.");
        }
    }

    uint256 hashBlk;
    CTransaction txOut;
    CCommitmentHash ch;
    int commitmentOutput;

    uint32_t commitmentHeight;

    // make sure we have a revocation and recovery authority defined
    CIdentity revocationAuth = newID.revocationAuthority == newIDID ? newID : newID.LookupIdentity(newID.revocationAuthority);
    CIdentity recoveryAuth = newID.recoveryAuthority == newIDID ? newID : newID.LookupIdentity(newID.recoveryAuthority);

    if (!recoveryAuth.IsValidUnrevoked() || !revocationAuth.IsValidUnrevoked())
    {
        if (newIDID == ASSETCHAINS_CHAINID)
        {
            revocationAuth = newID;
            recoveryAuth = newID;
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or revoked recovery, or revocation identity.");
        }
    }

    CTxDestination commitmentOutDest;

    // must be present and in a mined block
    {
        {
            LOCK(mempool.cs);
            if (!myGetTransaction(txid, txOut, hashBlk) || hashBlk.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or unconfirmed commitment transaction id");
            }
        }

        auto indexIt = mapBlockIndex.find(hashBlk);
        if (indexIt == mapBlockIndex.end() || indexIt->second->GetHeight() > chainActive.Height() || chainActive[indexIt->second->GetHeight()]->GetBlockHash() != indexIt->second->GetBlockHash())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or unconfirmed commitment");
        }

        commitmentHeight = indexIt->second->GetHeight();

        for (int i = 0; i < txOut.vout.size(); i++)
        {
            COptCCParams p;
            if (txOut.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_COMMITMENT && p.vData.size())
            {
                commitmentOutput = i;
                ::FromVector(p.vData[0], ch);
                std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
                for (auto &oneKey : p.vKeys)
                {
                    if (oneKey.which() == COptCCParams::ADDRTYPE_ID)
                    {
                        std::pair<CIdentityMapKey, CIdentityMapValue> checkKeyAndIdentity;
                        if (pwalletMain->GetIdentity(GetDestinationID(oneKey), checkKeyAndIdentity))
                        {
                            if (checkKeyAndIdentity.first.CanSign())
                            {
                                keyAndIdentity = checkKeyAndIdentity;
                                if (keyAndIdentity.first.CanSpend())
                                {
                                    commitmentOutDest = oneKey;
                                    break;
                                }
                            }
                        }
                    }
                    else if (oneKey.which() == COptCCParams::ADDRTYPE_PKH || oneKey.which() == COptCCParams::ADDRTYPE_PK)
                    {
                        if (pwalletMain->HaveKey(GetDestinationID(oneKey)))
                        {
                            commitmentOutDest = oneKey;
                            break;
                        }
                    }
                    else if (oneKey.which() == COptCCParams::ADDRTYPE_SH)
                    {
                        if (pwalletMain->HaveCScript(GetDestinationID(oneKey)))
                        {
                            commitmentOutDest = oneKey;
                            break;
                        }
                    }
                }
                if (commitmentOutDest.which() == COptCCParams::ADDRTYPE_INVALID && keyAndIdentity.second.IsValid() && keyAndIdentity.first.CanSign())
                {
                    commitmentOutDest = keyAndIdentity.first.idID;
                }
                break;
            }
        }
        if (ch.hash.IsNull() || commitmentOutDest.which() == COptCCParams::ADDRTYPE_INVALID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid commitment hash");
        }
    }

    if (ch.hash != (advReservation.IsValid() ? advReservation.GetCommitment().hash : reservation.GetCommitment().hash))
    {
        uint256 gotHash = ch.hash;
        uint256 expectedHash = (advReservation.IsValid() ? advReservation.GetCommitment().hash : reservation.GetCommitment().hash);

        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid commitment salt or referral ID, got hash: " + gotHash.GetHex() + ", expected: " + expectedHash.GetHex());
    }

    // until PBaaS, the parent is generally the current chains, and it is invalid to specify a parent
    if (newID.parent != parent)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid to specify alternate parent when creating an identity. Parent is determined by the current blockchain.");
    }

    CIdentity dupID = newID.LookupIdentity(newID.GetID());
    if (dupID.IsValid())
    {
        throw JSONRPCError(RPC_VERIFY_ALREADY_IN_CHAIN, "Identity already exists.");
    }

    // create the identity definition transaction
    std::vector<CRecipient> outputs = std::vector<CRecipient>({{newID.IdentityUpdateOutputScript(height + 1), 0, false}});
    int32_t registrationPaymentOut = -1;

    int64_t expectedFee = referralID.IsNull() ? feeOffer : feeOffer - idReferralFee;

    if (issuingCurrency.proofProtocol == issuingCurrency.PROOF_CHAINID &&
        (issuingCurrency.endBlock == 0 || height < issuingCurrency.endBlock))
    {
        if (issuerID == ASSETCHAINS_CHAINID)
        {
            // make an output to the currency ID of the amount less referrers
            registrationPaymentOut = outputs.size();
            outputs.push_back({CIdentity::TransparentOutput(issuerID), expectedFee, false});
        }
        else
        {
            // make an output to the currency ID of the amount less referrers
            CTokenOutput to(CCurrencyValueMap(std::vector<uint160>({issuerID}), std::vector<int64_t>({expectedFee})));
            registrationPaymentOut = outputs.size();
            outputs.push_back({MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, std::vector<CTxDestination>({CIdentityID(issuerID)}), 1, &to)), 0, false});
        }
    }
    else if (issuingCurrency.IsToken())
    {
        // make a burn output of this currency for the amount
        CReserveTransfer rt(CReserveTransfer::VALID + CReserveTransfer::BURN_CHANGE_PRICE,
                            CCurrencyValueMap(std::vector<uint160>({issuerID}),
                            std::vector<int64_t>({expectedFee})),
                            ASSETCHAINS_CHAINID,
                            ConnectedChains.ThisChain().GetTransactionTransferFee(),
                            issuerID,
                            DestinationToTransferDestination(CIdentityID(issuerID)));
        registrationPaymentOut = outputs.size();

        CCcontract_info CC;
        CCcontract_info *cp;
        cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
        CPubKey pk(ParseHex(CC.CChexstr));

        std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

        outputs.push_back({MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt)), ConnectedChains.ThisChain().GetTransactionTransferFee(), false});
    }
    else if (issuingCurrency.GetID() != ASSETCHAINS_CHAINID)
    {
        throw JSONRPCError(RPC_VERIFY_ALREADY_IN_CHAIN, "Invalid issuing/parent currency for this network");
    }

    // wrong referral refers to the source identity instead of specified referral address
    if (errorTest == ERRTEST_WRONGREFERRAL)
    {
        referralID = GetDestinationID(sourceDest);
    }

    // add referrals if any
    if (errorTest != ERRTEST_SKIPREFERRAL &&
        !newID.parent.IsNull() &&
        (parentCurrency.IDReferrals() || (newID.parent == ASSETCHAINS_CHAINID && IsVerusActive())) &&
        !referralID.IsNull())
    {
        uint32_t referralHeight;
        CTxIn referralTxIn;
        CTransaction referralIdTx;
        auto referralIdentity = newID.LookupIdentity(referralID, commitmentHeight - 1);

        if (referralIdentity.IsValidUnrevoked() &&
            referralIdentity.systemID == ASSETCHAINS_CHAINID &&
            newID.systemID == ASSETCHAINS_CHAINID &&
            (referralIdentity.parent == newID.parent || ((referralID != ASSETCHAINS_CHAINID || !ConnectedChains.ThisChain().parent.IsNull()) && referralID == newID.parent)))
        {
            if (!newID.LookupFirstIdentity(referralID, &referralHeight, &referralTxIn, &referralIdTx).IsValid())
            {
                throw JSONRPCError(RPC_DATABASE_ERROR, "Database or blockchain data error, \"" + referralIdentity.name + "\" seems valid, but first instance is not found in index");
            }

            if (errorTest == ERRTEST_UNDERPAYREFERRAL)
            {
                idReferralFee >>= 1;
            }

            // create outputs for this referral and up to n identities back in the referral chain
            if (issuerID == ASSETCHAINS_CHAINID)
            {
                outputs.push_back({newID.TransparentOutput(referralIdentity.GetID()), idReferralFee, false});
            }
            else
            {
                // make an output to the currency ID of the amount less referrers
                CTokenOutput to(CCurrencyValueMap(std::vector<uint160>({issuerID}), std::vector<int64_t>({idReferralFee})));
                outputs.push_back({MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, std::vector<CTxDestination>({referralIdentity.GetID()}), 1, &to)), 0, false});
            }
            feeOffer -= idReferralFee;
            if (referralHeight != 1 && referralID != newID.parent)
            {
                int afterId = referralTxIn.prevout.n +
                               ((parentCurrency.IsPBaaSChain() && parentCurrency.proofProtocol != parentCurrency.PROOF_CHAINID) ? 1 : 2);
                for (int i = afterId; i < (referralIdTx.vout.size() - 1) && (i - afterId) < (parentCurrency.idReferralLevels - 1); i++)
                {
                    CTxDestination nextID;
                    COptCCParams p, master;

                    if (referralIdTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() &&
                        ((p.evalCode == EVAL_NONE && issuingCurrency.GetID() == ASSETCHAINS_CHAINID) ||
                         (p.evalCode == EVAL_RESERVE_OUTPUT && issuingCurrency.GetID() != ASSETCHAINS_CHAINID)) &&
                        p.vKeys.size() == 1 &&
                        (p.vData.size() == 1 ||
                        (p.vData.size() == 2 &&
                        p.vKeys[0].which() == COptCCParams::ADDRTYPE_ID &&
                        (master = COptCCParams(p.vData[1])).IsValid() &&
                        master.evalCode == EVAL_NONE)))
                    {
                        if (issuingCurrency.GetID() == ASSETCHAINS_CHAINID)
                        {
                            outputs.push_back({newID.TransparentOutput(CIdentityID(GetDestinationID(p.vKeys[0]))), idReferralFee, false});
                        }
                        else
                        {
                            // make an output to the currency ID of the amount less referrers
                            CTokenOutput to(CCurrencyValueMap(std::vector<uint160>({issuerID}), std::vector<int64_t>({idReferralFee})));
                            outputs.push_back({MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, std::vector<CTxDestination>({CIdentityID(GetDestinationID(p.vKeys[0]))}), 1, &to)), 0, false});
                        }
                        feeOffer -= idReferralFee;
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or revoked referral identity at time of commitment");
        }
    }

    if (errorTest == ERRTEST_UNDERPAYFEE)
    {
        feeOffer >>= 1;
    }

    CScript reservationOutScript;
    if (advReservation.IsValid())
    {
        reservationOutScript = MakeMofNCCScript(CConditionObj<CAdvancedNameReservation>(EVAL_IDENTITY_ADVANCEDRESERVATION, std::vector<CTxDestination>({CIdentityID(newID.GetID())}), 1, &advReservation));
    }
    else
    {
        reservationOutScript = MakeMofNCCScript(CConditionObj<CNameReservation>(EVAL_IDENTITY_RESERVATION, std::vector<CTxDestination>({CIdentityID(newID.GetID())}), 1, &reservation));
    }
    outputs.push_back({reservationOutScript, CNameReservation::DEFAULT_OUTPUT_AMOUNT, false});

    // use the transaction builder to properly make change of native and reserves
    TransactionBuilder tb(Params().consensus, height + 1, pwalletMain);

    CCurrencyValueMap reservesOut;

    // if we have registration payments, fixup the output amount based on referrals adjustment
    if (registrationPaymentOut >= 0)
    {
        if (issuingCurrency.proofProtocol == issuingCurrency.PROOF_CHAINID &&
            (issuingCurrency.endBlock == 0 || height < issuingCurrency.endBlock))
        {
            if (issuerID == ASSETCHAINS_CHAINID)
            {
                // make an output to the currency ID of the amount less referrers
                outputs[registrationPaymentOut].nAmount = feeOffer;
            }
            else
            {
                // make an output to the currency ID of the amount less referrers
                CTokenOutput to(CCurrencyValueMap(std::vector<uint160>({issuerID}), std::vector<int64_t>({feeOffer})));
                outputs[registrationPaymentOut].scriptPubKey = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT,
                                                                                                            std::vector<CTxDestination>({CIdentityID(issuerID)}),
                                                                                                            1,
                                                                                                            &to));
            }
        }
        else if (issuingCurrency.IsToken())
        {
            // make a burn output of this currency for the amount
            CReserveTransfer rt(CReserveTransfer::VALID + CReserveTransfer::BURN_CHANGE_PRICE,
                                CCurrencyValueMap(std::vector<uint160>({issuerID}), std::vector<int64_t>({feeOffer})),
                                ASSETCHAINS_CHAINID,
                                ConnectedChains.ThisChain().GetTransactionTransferFee(),
                                issuerID,
                                DestinationToTransferDestination(CIdentityID(issuerID)));

            CCcontract_info CC;
            CCcontract_info *cp;
            cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
            CPubKey pk(ParseHex(CC.CChexstr));

            std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

            outputs[registrationPaymentOut].scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER,
                                                                            dests,
                                                                            1,
                                                                            &rt));
        }

        // the fee for a non-native registration is the import fee, as the fee offer was paid to the issuing currency
        tb.SetFee(ConnectedChains.ThisChain().IDImportFee());
        reservesOut.valueMap[ASSETCHAINS_CHAINID] += ConnectedChains.ThisChain().IDImportFee();
    }
    else
    {
        tb.SetFee(feeOffer);
        reservesOut.valueMap[ASSETCHAINS_CHAINID] += feeOffer;
    }

    bool success = false;
    std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
    std::vector<SaplingNoteEntry> saplingNotes;
    CCurrencyValueMap reserveValueOut;
    CAmount nativeValueOut;
    std::vector<COutput> vCoins;

    CTxDestination from_taddress;
    if (wildCardTransparentAddress)
    {
        from_taddress = CTxDestination();
    }
    else if (wildCardRAddress)
    {
        from_taddress = CTxDestination(CKeyID(uint160()));
    }
    else if (wildCardiAddress)
    {
        from_taddress = CTxDestination(CIdentityID(uint160()));
    }
    else
    {
        from_taddress = sourceDest;
    }

    for (int i = 0; i < outputs.size(); i++)
    {
        CRecipient &oneOut = outputs[i];
        tb.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nAmount);

        CCurrencyValueMap oneOutReserves;
        oneOutReserves += oneOut.scriptPubKey.ReserveOutValue();
        if (oneOut.nAmount)
        {
            oneOutReserves.valueMap[ASSETCHAINS_CHAINID] = oneOut.nAmount;
        }
        else
        {
            oneOutReserves.valueMap.erase(ASSETCHAINS_CHAINID);
        }
        reservesOut += oneOutReserves;
    }

    tb.AddTransparentInput(COutPoint(txid, commitmentOutput), txOut.vout[commitmentOutput].scriptPubKey, txOut.vout[commitmentOutput].nValue);

    reservesOut -= txOut.vout[commitmentOutput].scriptPubKey.ReserveOutValue();
    if (txOut.vout[commitmentOutput].nValue)
    {
        reservesOut = reservesOut.SubtractToZero(
                            CCurrencyValueMap(std::vector<uint160>({ASSETCHAINS_CHAINID}),
                                              std::vector<int64_t>({txOut.vout[commitmentOutput].nValue}))).CanonicalMap();
    }
    else
    {
        reservesOut = reservesOut.CanonicalMap();
    }

    reservesOut.valueMap[ASSETCHAINS_CHAINID] += DEFAULT_TRANSACTION_FEE;

    if (reservesOut.valueMap.size() == 1 && reservesOut.valueMap.count(ASSETCHAINS_CHAINID))
    {
        CAmount nativeNeeded = reservesOut.valueMap.begin()->second;

        if (hasZSource)
        {
            saplingNotes = find_unspent_notes(zaddressSource);
            CAmount totalFound = 0;
            int i;
            for (i = 0; i < saplingNotes.size(); i++)
            {
                totalFound += saplingNotes[i].note.value();
                if (totalFound >= nativeNeeded)
                {
                    break;
                }
            }
            // remove all but the notes we'll use
            if (i < saplingNotes.size())
            {
                saplingNotes.erase(saplingNotes.begin() + i + 1, saplingNotes.end());
                success = true;
            }
        }
        else
        {
            success = find_utxos(from_taddress, vCoins) &&
                    pwalletMain->SelectCoinsMinConf(nativeNeeded, 0, 0, vCoins, setCoinsRet, nativeValueOut);
        }
    }
    else if (hasZSource)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot source non-native currencies from a private address");
    }
    else
    {
        CAmount nativeNeeded = reservesOut.valueMap.count(ASSETCHAINS_CHAINID) ? reservesOut.valueMap[ASSETCHAINS_CHAINID] : 0;
        reservesOut.valueMap.erase(ASSETCHAINS_CHAINID);

        success = find_utxos(from_taddress, vCoins);
        success = success && pwalletMain->SelectReserveCoinsMinConf(reservesOut,
                                                                    nativeNeeded,
                                                                    0,
                                                                    1,
                                                                    vCoins,
                                                                    setCoinsRet,
                                                                    reserveValueOut,
                                                                    nativeValueOut);
    }
    if (!success)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Insufficient funds for identity registration");
    }

    // aggregate all inputs into one output with only the offer coins and offer indexes
    if (saplingNotes.size())
    {
        std::vector<SaplingOutPoint> notes;
        for (auto &oneNoteInfo : saplingNotes)
        {
            notes.push_back(oneNoteInfo.op);
        }
        // Fetch Sapling anchor and witnesses
        uint256 anchor;
        std::vector<boost::optional<SaplingWitness>> witnesses;
        {
            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->GetSaplingNoteWitnesses(notes, witnesses, anchor);
        }

        // Add Sapling spends
        for (size_t i = 0; i < saplingNotes.size(); i++)
        {
            tb.AddSaplingSpend(expsk, saplingNotes[i].note, anchor, witnesses[i].get());
        }
    }
    else
    {
        for (auto &oneInput : setCoinsRet)
        {
            tb.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second),
                                    oneInput.first->vout[oneInput.second].scriptPubKey,
                                    oneInput.first->vout[oneInput.second].nValue);
        }
    }

    if (hasZSource)
    {
        tb.SendChangeTo(*boost::get<libzcash::SaplingPaymentAddress>(&zaddressSource), sourceOvk);
    }
    else if (sourceDest.which() != COptCCParams::ADDRTYPE_INVALID && !GetDestinationID(sourceDest).IsNull())
    {
        tb.SendChangeTo(sourceDest);
    }
    else
    {
        tb.SendChangeTo(commitmentOutDest);
    }

    TransactionBuilderResult preResult = tb.Build(true);
    CTransaction commitTx = preResult.GetTxOrThrow();

    if (returnTx)
    {
        return EncodeHexTx(commitTx);
    }
    else
    {
        // add to mem pool and relay
        LOCK(cs_main);

        bool relayTx;
        CValidationState state;
        {
            LOCK2(smartTransactionCS, mempool.cs);
            relayTx = myAddtomempool(commitTx, &state);
        }

        // add to mem pool and relay
        if (!relayTx)
        {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Unable to commit identity registration transaction: " + state.GetRejectReason());
        }
        else
        {
            RelayTransaction(commitTx);
        }
    }

    // including definitions and claims thread
    return UniValue(commitTx.GetHash().GetHex());
}

std::map<std::string, UniValue> UniObjectToMap(const UniValue &obj)
{
    std::map<std::string, UniValue> retVal;
    if (obj.isObject())
    {
        std::vector<std::string> keys = obj.getKeys();
        std::vector<UniValue> values = obj.getValues();
        for (int i = 0; i < keys.size(); i++)
        {
            retVal.insert(std::make_pair(keys[i], values[i]));
        }
    }
    return retVal;
}

UniValue MapToUniObject(const std::map<std::string, UniValue> &uniMap)
{
    UniValue retVal(UniValue::VOBJ);
    for (auto &oneEl : uniMap)
    {
        retVal.pushKV(oneEl.first, oneEl.second);
    }
    return retVal;
}

UniValue updateidentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 5)
    {
        throw runtime_error(
            "updateidentity \"jsonidentity\" (returntx) (tokenupdate) (feeoffer) (sourceoffunds)\n"
            "\n\n"

            "\nArguments\n"
            "       \"jsonidentity\"                    (obj,    required) new definition of the identity\n"
            "       \"returntx\"                        (bool,   optional) defaults to false and transaction is sent, if true, transaction is signed by this wallet and returned\n"
            "       \"tokenupdate\"                     (bool,   optional) defaults to false, if true, the tokenized ID control token, if one exists, will be used to provide\n"
            "                                                              authority for update. This provides revoke and recovery for update, but does not give primary authority\n"
            "                                                              enabling revoke, recover, and changing of the revocation or recovery IDs, even if the wallet holding\n"
            "                                                              the token does not control any other authority besides the token itself.\n"
            "       \"feeoffer\"                        (value,  optional) non-standard fee amount to pay for the transaction\n"
            "       \"sourceoffunds\"                   (string, optional) transparent or private address to source all funds for fees to preserve privacy of the identity\n"

            "\nResult:\n"
            "   hex string of either the txid if returnhex is false or the hex serialized transaction if returntx is true\n"

            "\nExamples:\n"
            + HelpExampleCli("updateidentity", "\'{\"name\" : \"myname\"}\'")
            + HelpExampleRpc("updateidentity", "\'{\"name\" : \"myname\"}\'")
        );
    }

    CheckIdentityAPIsValid();

    bool returnTx = false;
    bool tokenizedIDControl = false;

    if (params.size() > 1)
    {
        returnTx = uni_get_bool(params[1], false);
    }

    CTxDestination parentDest = DecodeDestination(uni_get_str(find_value(params[0], "parent")));
    uint160 parentID = uint160(GetDestinationID(parentDest));
    if (parentID.IsNull() && parentDest.which() != COptCCParams::ADDRTYPE_ID)
    {
        parentID = ValidateCurrencyName(uni_get_str(find_value(params[0], "parent")), true);
    }
    std::string nameStr = CleanName(uni_get_str(find_value(params[0], "name")), parentID, true);
    uint160 newIDID = CIdentity::GetID(nameStr, parentID);

    CTxIn idTxIn;
    CIdentity oldID;
    uint32_t idHeight;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint32_t nHeight = chainActive.Height();

    bool isPBaaS = CConstVerusSolutionVector::GetVersionByHeight(nHeight) >= CActivationHeight::ACTIVATE_PBAAS;
    if (isPBaaS && params.size() > 2)
    {
        tokenizedIDControl = uni_get_bool(params[2], false);
    }

    if (!(oldID = CIdentity::LookupIdentity(newIDID, 0, &idHeight, &idTxIn, true)).IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + " (" +EncodeDestination(CIdentityID(newIDID)) + "), not found ");
    }

    uint256 blkHash;
    CTransaction oldIdTx;
    if (!myGetTransaction(idTxIn.prevout.hash, oldIdTx, blkHash))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "identity, " + nameStr + ", transaction not found ");
    }

    auto uniOldID = UniObjectToMap(oldID.ToUniValue());

    // always clear the contentmultimap
    uniOldID.erase("contentmultimap");

    // overwrite old elements
    for (auto &oneEl : UniObjectToMap(params[0]))
    {
        uniOldID[oneEl.first] = oneEl.second;
    }

    uint32_t solVersion = CConstVerusSolutionVector::GetVersionByHeight(nHeight + 1);

    if (solVersion >= CActivationHeight::ACTIVATE_VERUSVAULT)
    {
        uniOldID["version"] = solVersion < CActivationHeight::ACTIVATE_PBAAS ? (int64_t)CIdentity::VERSION_VAULT : (int64_t)CIdentity::VERSION_PBAAS;
        if (oldID.nVersion < CIdentity::VERSION_VAULT)
        {
            uniOldID["systemid"] = EncodeDestination(CIdentityID(parentID.IsNull() ? oldID.GetID() : parentID));
        }
    }

    // each one of these is entered into the ID as one idexed link to the data output on chain
    // data has key, label, mimetype, actual data, encrypttoaddress
    std::multimap<uint160, std::tuple<std::string, std::string, CNotaryEvidence, libzcash::SaplingPaymentAddress, libzcash::SaplingIncomingViewingKey>> extraData;

    // pull out data to be stored outside the ID definition to extraData
    if (uniOldID.count("contentmultimap"))
    {
        UniValue multiMapUni = uniOldID["contentmultimap"];
        if (multiMapUni.isObject())
        {
            std::vector<int> toRemoveKeys;
            std::vector<std::string> keys = multiMapUni.getKeys();
            std::vector<UniValue> values = multiMapUni.getValues();
            for (int i = 0; i < keys.size(); i++)
            {
                if (values[i].isObject())
                {
                    UniValue valueArr(UniValue::VARR);
                    valueArr.push_back(values[i]);
                    values[i] = valueArr;
                } else if (!values[i].isArray())
                {
                    continue;
                }

                std::vector<int> toRemoveValues;
                for (int j = 0; j < values[i].size(); j++)
                {
                    UniValue chainData = find_value(values[i][j], "data");

                    // if we have a data element, the data will be stored on the transaction and referenced in the ID
                    if (!chainData.isNull())
                    {
                        auto createMMR = find_value(chainData, "createmmr");
                        auto dataLabel = uni_get_str(find_value(chainData, "label"));
                        auto mimeType = uni_get_str(find_value(chainData, "mimetype"));
                        libzcash::PaymentAddress encryptToAddress;
                        libzcash::SaplingIncomingViewingKey ivk;

                        bool encryptData = pwalletMain->GetAndValidateSaplingZAddress(uni_get_str(find_value(chainData, "encrypttoaddress")), encryptToAddress, true);
                        if (!encryptData)
                        {
                            if (!find_value(chainData, "encrypttoaddress").isNull())
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid encryption address in object #" + std::to_string(i));
                            }

                            // if we have no encryption key, we still need a random z-address for encryption
                            HDSeed seed(HDSeed::Random());
                            auto m = libzcash::SaplingExtendedSpendingKey::Master(seed);
                            uint32_t bip44CoinType = Params().BIP44CoinType();

                            // We use a fixed keypath scheme of m/32'/coin_type'/account'
                            // Derive m/32'
                            auto m_32h = m.Derive(32 | ZIP32_HARDENED_KEY_LIMIT);
                            // Derive m/32'/coin_type'
                            auto m_32h_cth = m_32h.Derive(bip44CoinType | ZIP32_HARDENED_KEY_LIMIT);

                            // Derive account key at next index, skip keys already known to the wallet
                            libzcash::SaplingExtendedSpendingKey xsk = m_32h_cth.Derive(0 | ZIP32_HARDENED_KEY_LIMIT);
                            chainData.pushKV("encrypttoaddress", EncodePaymentAddress(xsk.DefaultAddress()));
                            encryptToAddress = xsk.DefaultAddress();

                            // if this is encrypted to a random key, publish the viewing key in the link
                            ivk = xsk.expsk.full_viewing_key().in_viewing_key();
                        }
                        if (createMMR.isNull())
                        {
                            createMMR = true;
                            chainData.pushKV("createmmr", createMMR);
                        }
                        if (!uni_get_bool(createMMR))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "If root signature is specified for data storage, it must be true");
                        }

                        UniValue signParams(UniValue::VARR);
                        signParams.push_back(chainData);

                        if (LogAcceptCategory("dataencryption"))
                        {
                            printf("%s: params to signdata %s\n", __func__, signParams.write(1,2).c_str());
                            LogPrintf("%s: params to signdata %s\n", __func__, signParams.write(1,2).c_str());
                        }
                        UniValue signResult = signdata(signParams, false);
                        if (LogAcceptCategory("dataencryption"))
                        {
                            printf("%s: return from signdata %s\n", __func__, signResult.write(1,2).c_str());
                            LogPrintf("%s: return from signdata %s\n", __func__, signResult.write(1,2).c_str());
                        }

                        // now, we have both a CMMRDescriptor as well as a CSignatureData if we signed, all encrypted to the specified Z-address
                        CMMRDescriptor MMRDesc = CMMRDescriptor(find_value(signResult, "mmrdescriptor_encrypted"));
                        CDataDescriptor SignatureData = CDataDescriptor(find_value(signResult, "signaturedata_encrypted"));

                        // if the MMR data isn't valid, we have nothing to store
                        if (!MMRDesc.IsValid() || !MMRDesc.dataDescriptors.size())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "No valid data for data object # " + std::to_string(i));
                        }

                        CVDXF_Data vdxfData(CVDXF_Data::VERSION_INVALID);
                        CVDXF_Data vdxfSignature(CVDXF_Data::VERSION_INVALID);

                        // if we only have one object, the MMR is that salted object, remove the overhead
                        if (MMRDesc.dataDescriptors.size() == 1)
                        {
                            vdxfData = CVDXF_Data(CVDXF_Data::DataDescriptorKey(), ::AsVector(MMRDesc.dataDescriptors[0]));
                        }
                        else
                        {
                            vdxfData = CVDXF_Data(CVDXF_Data::MMRDescriptorKey(), ::AsVector(MMRDesc));
                        }
                        if (SignatureData.IsValid())
                        {
                            vdxfSignature = CVDXF_Data(CVDXF_Data::SignatureDataKey(), ::AsVector(SignatureData));
                        }

                        // now, we will store the encrypted signature, if present, and MMRDesc in transparent outputs and put the link inside the z-memo
                        CNotaryEvidence evidenceData(ASSETCHAINS_CHAINID, CUTXORef(uint256(), 0), CNotaryEvidence::STATE_SUPPORTING, CCrossChainProof(), CNotaryEvidence::TYPE_IMPORT_PROOF);
                        evidenceData.evidence << CEvidenceData(CVDXF_Data::DataDescriptorKey(), ::AsVector(vdxfData));
                        if (vdxfSignature.IsValid())
                        {
                            evidenceData.evidence << CEvidenceData(CVDXF_Data::SignatureDataKey(), ::AsVector(vdxfSignature));
                        }
                        uint160 key = ParseVDXFKey(keys[i]);
                        if (key.IsNull())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid vdxfkey value: " + keys[i]);
                        }

                        libzcash::SaplingPaymentAddress *pEncryptTo = boost::get<libzcash::SaplingPaymentAddress>(&encryptToAddress);
                        libzcash::SaplingPaymentAddress encryptTo = pEncryptTo ? *pEncryptTo : libzcash::SaplingPaymentAddress();

                        if (LogAcceptCategory("dataencryption"))
                        {
                            printf("%s: Setting evidence data %s\n", __func__, evidenceData.ToUniValue().write(1,2).c_str());
                            LogPrintf("%s: Setting evidence data %s\n", __func__, evidenceData.ToUniValue().write(1,2).c_str());
                        }

                        extraData.insert(std::make_pair(key, std::make_tuple(dataLabel, MMRDesc.dataDescriptors.size() > 1 ? "application/json" : mimeType, evidenceData, encryptTo, ivk)));
                        toRemoveValues.push_back(j);
                        continue;
                    }
                }
                if (toRemoveValues.size())
                {
                    UniValue newUniValue(UniValue::VARR);
                    int removeIdx = 0;
                    for (int j = 0; toRemoveValues.size() && j < values[i].size(); j++)
                    {
                        if (removeIdx < toRemoveValues.size() && toRemoveValues[removeIdx] == j)
                        {
                            removeIdx++;
                            continue;
                        }
                        newUniValue.push_back(values[i][j]);
                    }
                    values[i] = newUniValue;
                }
                if (!values[i].size())
                {
                    toRemoveKeys.push_back(i);
                }
            }
            for (auto rit = toRemoveKeys.rbegin(); rit != toRemoveKeys.rend(); rit++)
            {
                keys.erase(keys.begin() + *rit);
                values.erase(values.begin() + *rit);
            }
            multiMapUni = UniValue(UniValue::VOBJ);
            for (int i = 0; i < keys.size(); i++)
            {
                multiMapUni.pushKV(keys[i], values[i]);
            }
            uniOldID["contentmultimap"] = multiMapUni;
        }
    }

    UniValue newUniID = MapToUniObject(uniOldID);
    CIdentity newID(newUniID);

    if (newID.nVersion < CIdentity::VERSION_PBAAS && newID.contentMultiMap.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "contentmultimap may only be set in identities when PBaaS is active on the network");
    }

    newID.flags &= newID.FLAG_LOCKED + newID.FLAG_REVOKED;
    newID.flags |= (oldID.flags & (oldID.FLAG_ACTIVECURRENCY + oldID.FLAG_TOKENIZED_CONTROL));

    if (!newID.IsValid(true))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid JSON ID parameter");
    }

    if (tokenizedIDControl)
    {
        if (!oldID.HasTokenizedControl())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Can only use ID control token for ID that has tokenized ID control on this chain");
        }
    }

    // check fee offer
    CAmount feeOffer = 0;
    if (params.size() > 3)
    {
        feeOffer = AmountFromValue(params[3]);
    }

    std::string sourceAddress;
    CTxDestination sourceDest;

    bool wildCardTransparentAddress = false;
    bool wildCardRAddress = false;
    bool wildCardiAddress = false;
    bool wildCardAddress = false;

    libzcash::PaymentAddress zaddressSource;
    libzcash::SaplingExpandedSpendingKey expsk;
    uint256 sourceOvk;
    bool hasZSource = false;

    if (params.size() > 4)
    {
        sourceAddress = uni_get_str(params[4]);

        wildCardTransparentAddress = sourceAddress == "*";
        wildCardRAddress = sourceAddress == "R*";
        wildCardiAddress = sourceAddress == "i*";
        wildCardAddress = wildCardTransparentAddress || wildCardRAddress || wildCardiAddress;
        hasZSource = !wildCardAddress && pwalletMain->GetAndValidateSaplingZAddress(sourceAddress, zaddressSource, true);

        // if we have a z-address as a source, re-encode it to a string, which is used
        // by the async operation, to ensure that we don't need to lookup IDs in that operation
        if (hasZSource)
        {
            sourceAddress = EncodePaymentAddress(zaddressSource);
            // We don't need to lock on the wallet as spending key related methods are thread-safe
            if (!boost::apply_visitor(HaveSpendingKeyForPaymentAddress(pwalletMain), zaddressSource)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address, no spending key found for zaddr");
            }

            auto spendingkey_ = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), zaddressSource).get();
            auto sk = boost::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
            expsk = sk.expsk;
            sourceOvk = expsk.full_viewing_key().ovk;
        }

        if (!(hasZSource ||
            wildCardAddress ||
            (sourceDest = DecodeDestination(sourceAddress)).which() != COptCCParams::ADDRTYPE_INVALID))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. First parameter must be sapling address, transparent address, identity, \"*\", \"R*\", or \"i*\",. See help.");
        }
    }
    else
    {
        wildCardTransparentAddress = true;
    }

    // make sure we have a valid revocation and recovery authority defined
    CIdentity revocationAuth = newID.revocationAuthority == newIDID ? newID : newID.LookupIdentity(newID.revocationAuthority);
    CIdentity recoveryAuth = newID.recoveryAuthority == newIDID ? newID : newID.LookupIdentity(newID.recoveryAuthority);

    bool isRevocationMutation = oldID.IsRevocation(newID) || oldID.IsRevocationMutation(newID, nHeight + 1);
    bool isRecoveryMutation = oldID.IsRecovery(newID) || oldID.IsRecoveryMutation(newID, nHeight + 1);

    if (((isRevocationMutation && !revocationAuth.IsValid()) || (isRecoveryMutation && !recoveryAuth.IsValid())) && !newID.HasTokenizedControl())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid revocation or recovery authority without tokenized ID control");
    }

    CMutableTransaction txNew = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nHeight + 1);

    if (oldID.IsLocked() != newID.IsLocked())
    {
        bool newLocked = newID.IsLocked();
        uint32_t unlockAfter = newID.unlockAfter;
        newID.flags = (newID.flags & ~newID.FLAG_LOCKED) | (newID.IsRevoked() ? 0 : (oldID.flags & oldID.FLAG_LOCKED));
        newID.unlockAfter = oldID.unlockAfter;

        if (!newLocked)
        {
            newID.Unlock(nHeight + 1, txNew.nExpiryHeight);
            if (unlockAfter > newID.unlockAfter)
            {
                newID.unlockAfter = unlockAfter;
            }
        }
        else
        {
            newID.Lock(unlockAfter);
        }
    }

    // use the transaction builder to properly make change of native and reserves
    TransactionBuilder tb(Params().consensus, nHeight + 1, pwalletMain);

    // spend the prior ID output
    tb.AddTransparentInput(idTxIn.prevout,
                           oldIdTx.vout[idTxIn.prevout.n].scriptPubKey,
                           oldIdTx.vout[idTxIn.prevout.n].nValue);

    for (auto &oneExtraData : extraData)
    {
        CCcontract_info CC;
        CCcontract_info *cp;

        // now add the notary evidence and finalization that uses it to assert validity
        // make the evidence notarization output
        cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
        std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});

        COptCCParams chkP;
        CScript simpleScript = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &std::get<2>(oneExtraData.second)));
        if (!simpleScript.IsPayToCryptoCondition(chkP, false))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to package evidence script in ID data output #" + std::to_string(tb.mtx.vout.size()));
        }

        if (LogAcceptCategory("dataencryption"))
        {
            printf("%s: Output evidence %s\n", __func__, std::get<2>(oneExtraData.second).ToUniValue().write(1,2).c_str());
            LogPrintf("%s: Output evidence %s\n", __func__, std::get<2>(oneExtraData.second).ToUniValue().write(1,2).c_str());
        }

        CVDXFDataRef idLink(uint256(), tb.mtx.vout.size(), 0);
        CVDXFDataDescriptor dd(::AsVector(idLink), std::get<0>(oneExtraData.second), std::get<1>(oneExtraData.second));
        if (IsValidPaymentAddress(std::get<3>(oneExtraData.second)))
        {
            dd.WrapEncrypted(std::get<3>(oneExtraData.second));
            if (!std::get<4>(oneExtraData.second).IsNull())
            {
                dd.dataDescriptor.ivk = std::vector<unsigned char>(std::get<4>(oneExtraData.second).begin(), std::get<4>(oneExtraData.second).end());
            }
        }
        std::vector<unsigned char> memoData = ::AsVector(dd);
        if (std::get<2>(oneExtraData.second).evidence.chainObjects.size() > 1)
        {
            idLink = CVDXFDataRef(uint256(), tb.mtx.vout.size(), 0, 1);
            dd = CVDXFDataDescriptor(::AsVector(idLink), "signature", "application/json");
            if (IsValidPaymentAddress(std::get<3>(oneExtraData.second)))
            {
                dd.WrapEncrypted(std::get<3>(oneExtraData.second));
                if (!std::get<4>(oneExtraData.second).IsNull())
                {
                    dd.dataDescriptor.ivk = std::vector<unsigned char>(std::get<4>(oneExtraData.second).begin(), std::get<4>(oneExtraData.second).end());
                }
            }
            std::vector<unsigned char> memoSig = ::AsVector(dd);
            memoData.insert(memoData.end(), memoSig.begin(), memoSig.end());
        }

        if (LogAcceptCategory("dataencryption"))
        {
            printf("%s: Encrypted output evidence %s\n", __func__, dd.ToUniValue().write(1,2).c_str());
            LogPrintf("%s: Encrypted output evidence %s\n", __func__, dd.ToUniValue().write(1,2).c_str());
        }

        newID.contentMultiMap.insert(std::make_pair(oneExtraData.first, memoData));

        // the value should be considered for reduction
        if (chkP.AsVector().size() >= CScript::MAX_SCRIPT_ELEMENT_SIZE)
        {
            CNotaryEvidence emptyEvidence;
            int baseOverhead = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &emptyEvidence)).size() + 128;
            auto evidenceVec = std::get<2>(oneExtraData.second).BreakApart(CScript::MAX_SCRIPT_ELEMENT_SIZE - baseOverhead);
            if (!evidenceVec.size())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to package evidence chunk in ID data output #" + std::to_string(tb.mtx.vout.size()));
            }
            for (auto &oneProof : evidenceVec)
            {
                dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &oneProof)), 0);
            }
        }
        else
        {
            tb.AddTransparentOutput(simpleScript, 0);
        }
    }

    tb.AddTransparentOutput(newID.IdentityUpdateOutputScript(nHeight + 1), oldIdTx.vout[idTxIn.prevout.n].nValue);

    // if we are supposed to get our authority from the token, make sure it is present and prepare to spend it
    // this is handled separately from other currency in and out to ensure no mixing and the ability to use a
    // specific source or z-address for fees
    if (tokenizedIDControl)
    {
        std::vector<COutput> controlTokenOuts;
        CCurrencyValueMap tokenCurrencyControlMap(std::vector<uint160>({newIDID}), std::vector<int64_t>({1}));

        COptCCParams tcP;
        CCurrencyValueMap reserveMap;

        pwalletMain->AvailableReserveCoins(controlTokenOuts, true, nullptr, false, false, nullptr, &tokenCurrencyControlMap, false);
        if (controlTokenOuts.size() == 1 && controlTokenOuts[0].fSpendable)
        {
            reserveMap = controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue();
            if (!reserveMap.valueMap.count(newIDID) || reserveMap.valueMap[newIDID] != 1)
            {
                LogPrint("tokenizedidcontrol", "%s: controlTokenOuts.size(): %d, controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue(): %s, reserveMap: %s, reserveMap.valueMap[idID]: %ld\n", __func__, (int)controlTokenOuts.size(), controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue().ToUniValue().write().c_str(), reserveMap.ToUniValue().write().c_str(), reserveMap.valueMap[newIDID]);
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot locate spendable tokenized ID control currency in wallet - if present, may require rescan");
            }
            tb.AddTransparentInput(COutPoint(controlTokenOuts[0].tx->GetHash(), controlTokenOuts[0].i),
                                   controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].scriptPubKey,
                                   controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].nValue);

            tb.AddTransparentOutput(controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].scriptPubKey,
                                    controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].nValue);
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "No spendable tokenized ID control currency for update in wallet");
        }
    }

    bool success = false;
    std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
    std::vector<SaplingNoteEntry> saplingNotes;
    std::vector<COutput> vCoins;

    CTxDestination from_taddress;
    if (wildCardTransparentAddress)
    {
        from_taddress = CTxDestination();
    }
    else if (wildCardRAddress)
    {
        from_taddress = CTxDestination(CKeyID(uint160()));
    }
    else if (wildCardiAddress)
    {
        from_taddress = CTxDestination(CIdentityID(uint160()));
    }
    else
    {
        from_taddress = sourceDest;
    }

    if (tokenizedIDControl && LogAcceptCategory("tokenizedidcontrol"))
    {
        UniValue jsonTx(UniValue::VOBJ);
        TxToUniv(tb.mtx, uint256(), jsonTx);
        LogPrintf("%s: updateidtx:\n%s\n", __func__, jsonTx.write(1,2).c_str());
    }

    // if fee offer was not specified, calculate
    if (!feeOffer && !returnTx)
    {
        // calculate total fee required to update based on content in content maps
        // as of PBaaS, standard contentMaps cost an extra standard fee per entry
        // contentMultiMaps cost an extra standard fee for each 128 bytes in size
        CAmount identityFeeFactor = 0;
        if (newID.contentMultiMap.size())
        {
            CDataStream ss(SER_DISK, PROTOCOL_VERSION);
            auto tempID = newID;
            tempID.contentMultiMap.clear();
            size_t serSize = GetSerializeSize(ss, newID) - GetSerializeSize(ss, tempID);
            identityFeeFactor = (serSize / 128) + ((serSize % 128) ? 1 : 0);
        }

        // if we have more primary addresses than 1 or more private addresses than 1, pay appropriate fee
        identityFeeFactor += newID.contentMap.size();
        identityFeeFactor += newID.primaryAddresses.size() > 1 ? newID.primaryAddresses.size() - 1 : 0;
        identityFeeFactor += newID.privateAddresses.size() > 1 ? newID.privateAddresses.size() - 1 : 0;

        feeOffer = GetMinRelayFeeForBuilder(tb, identityFeeFactor, true);
    }

    CAmount totalFound = 0;

    if (hasZSource)
    {
        saplingNotes = find_unspent_notes(zaddressSource);
        int i;
        for (i = 0; i < saplingNotes.size(); i++)
        {
            totalFound += saplingNotes[i].note.value();
            if (totalFound >= feeOffer)
            {
                break;
            }
        }
        // remove all but the notes we'll use
        if (i < saplingNotes.size())
        {
            saplingNotes.erase(saplingNotes.begin() + i + 1, saplingNotes.end());
            success = true;
        }
    }
    else if (feeOffer)
    {
        success = find_utxos(from_taddress, vCoins) &&
                pwalletMain->SelectCoinsMinConf(feeOffer, 0, 0, vCoins, setCoinsRet, totalFound);
    }

    // aggregate all inputs into one output with only the offer coins and offer indexes
    if (saplingNotes.size())
    {
        std::vector<SaplingOutPoint> notes;
        for (auto &oneNoteInfo : saplingNotes)
        {
            notes.push_back(oneNoteInfo.op);
        }
        // Fetch Sapling anchor and witnesses
        uint256 anchor;
        std::vector<boost::optional<SaplingWitness>> witnesses;
        {
            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->GetSaplingNoteWitnesses(notes, witnesses, anchor);
        }

        // Add Sapling spends
        for (size_t i = 0; i < saplingNotes.size(); i++)
        {
            tb.AddSaplingSpend(expsk, saplingNotes[i].note, anchor, witnesses[i].get());
        }
    }
    else
    {
        for (auto &oneInput : setCoinsRet)
        {
            tb.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second),
                                    oneInput.first->vout[oneInput.second].scriptPubKey,
                                    oneInput.first->vout[oneInput.second].nValue);
        }
    }

    if (totalFound > feeOffer)
    {
        if (hasZSource)
        {
            tb.SendChangeTo(*boost::get<libzcash::SaplingPaymentAddress>(&zaddressSource), sourceOvk);
        }
        else if (sourceDest.which() != COptCCParams::ADDRTYPE_INVALID && !GetDestinationID(sourceDest).IsNull())
        {
            tb.SendChangeTo(sourceDest);
        }
        else
        {
            if (defaultSaplingDest && VERUS_PRIVATECHANGE)
            {
                auto spendingkey_ = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), DecodePaymentAddress(VERUS_DEFAULT_ZADDR)).get();
                auto sk = boost::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
                expsk = sk.expsk;
                auto changeOvk = expsk.full_viewing_key().ovk;

                tb.SendChangeTo(defaultSaplingDest.get(), changeOvk);
            }
            else
            {
                txnouttype typeRet;
                std::vector<CTxDestination> addressRet;
                int nRequiredRet;
                if (ExtractDestinations(setCoinsRet.begin()->first->vout[setCoinsRet.begin()->second].scriptPubKey,
                                        typeRet,
                                        addressRet,
                                        nRequiredRet) &&
                    addressRet.size() == 1)
                {
                    tb.SendChangeTo(addressRet[0]);
                }
                else
                {
                    CReserveKey changeKey(pwalletMain);
                    CPubKey pk;
                    if (changeKey.GetReservedKey(pk))
                    {
                        tb.SendChangeTo(pk.GetID());
                        changeKey.KeepKey();
                    }
                    else
                    {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to create change address");
                    }
                }
            }
        }
    }

    tb.SetFee(feeOffer);

    TransactionBuilderResult preResult = tb.Build(true);
    CTransaction commitTx;

    if (returnTx)
    {
        if (preResult.IsTx() || !preResult.IsHexTx(&commitTx))
        {
            commitTx = preResult.GetTxOrThrow();
        }
        return EncodeHexTx(commitTx);
    }
    else
    {
        commitTx = preResult.GetTxOrThrow();

        // add to mem pool and relay
        LOCK(cs_main);

        bool relayTx;
        CValidationState state;
        {
            LOCK2(smartTransactionCS, mempool.cs);
            relayTx = myAddtomempool(commitTx, &state);
        }

        // add to mem pool and relay
        if (!relayTx)
        {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED, "Unable to commit identity update transaction: " + state.GetRejectReason());
        }
        else
        {
            RelayTransaction(commitTx);
        }
    }

    // including definitions and claims thread
    return UniValue(commitTx.GetHash().GetHex());
}

UniValue setidentitytimelock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 5)
    {
        throw runtime_error(
            "setidentitytimelock \"id@\" '{\"unlockatblock\":absoluteblockheight || \"setunlockdelay\":numberofblocksdelayafterunlock}' (returntx) (feeoffer) (sourceoffunds)\n"
            "\nEnables timelocking and unlocking of funds access for an on-chain VerusID. This does not affect the lock status of VerusIDs on other chains,\n"
            "including VerusIDs with the same identity as this one, which has been exported to another chain.\n"
            "\nUse \"setunlockdelay\" to set a time unlock delay on an identity, which means that once the identity has been unlocked,\n"
            "numberofblocksdelayafterunlock must then pass before the identity will be able to spend funds on this blockchain. Services\n"
            "which support VerusID authentication and recognize this setting may also choose to prevent funds transfers when an ID is locked.\n"
            "\nUse \"unlockatblock\" to either unlock, by passing the current block, which will still require waiting for the specified unlock\n"
            "delay, or to set a future unlock height that immediately begins counting down. Unlike an unlock delay, which only starts counting\n"
            "down when the ID is unlocked, an \"unlockatblock\" time lock is absolute and will automatically unlock when the specified\n"
            "block passes.\n"

            "\nArguments - either \"unlockatblock\" or \"setunlockdelay\" must be specified and not both\n"
            "{\n"
            "  \"unlockatblock\"                (number, optional) unlock at an absolute block height, countdown starts when mined into a block\n"
            "  \"setunlockdelay\"               (number, optional) delay this many blocks after unlock request to unlock, can only be\n"
            "                                                      circumvented by revoke/recover\n"
            "}\n"
            "       \"returntx\"                        (bool,   optional) defaults to false and transaction is sent, if true, transaction is signed by this wallet and returned\n"
            "       \"feeoffer\"                        (value,  optional) non-standard fee amount to pay for the transaction\n"
            "       \"sourceoffunds\"                   (string, optional) transparent or private address to source all funds for fees to preserve privacy of the identity\n"

            "\nResult:\n"
            "   Hex string of either the txid if returnhex is false or the hex serialized transaction if returntx is true.\n"
            "   If returntx is true, the transaction will not have been submitted and must be sent with \"sendrawtransaction\"\n"
            "   after any necessary signatures are applied in the case of multisig.\n"

            "\nExamples:\n"
            + HelpExampleCli("setidentitytimelock", "\"id@\" '{\"unlockatblock\":absoluteblockheight || \"setunlockdelay\":numberofblocksdelayafterunlock}' (returntx)")
            + HelpExampleRpc("setidentitytimelock", "\"id@\" '{\"unlockatblock\":absoluteblockheight || \"setunlockdelay\":numberofblocksdelayafterunlock}' (returntx)")
        );
    }

    CheckIdentityAPIsValid();

    bool returnTx = false;
    if (params.size() > 2)
    {
        returnTx = uni_get_bool(params[2], false);
    }

    std::string idString = uni_get_str(params[0]);
    CIdentity oldIdentity;

    {
        LOCK(cs_main);
        oldIdentity = ValidateIdentityParameter(idString);
    }

    if (!oldIdentity.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity, " + idString + " not found ");
    }

    UniValue unlockDelayUni = find_value(params[1], "setunlockdelay");
    UniValue absoluteUnlockUni = find_value(params[1], "unlockatblock");

    if ((!unlockDelayUni.isNull() && !absoluteUnlockUni.isNull()) || (unlockDelayUni.isNull() && absoluteUnlockUni.isNull()))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Either \"setunlockdelay\" or \"unlockatblock\" must have a non-zero value and not both");
    }

    uint32_t unlockDelay = uni_get_int64(unlockDelayUni);
    uint32_t absoluteUnlock = uni_get_int64(absoluteUnlockUni);

    {
        LOCK(cs_main);
        uint32_t nextHeight = chainActive.Height() + 1;
        CMutableTransaction txNew = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nextHeight);

        if (unlockDelayUni.isNull())
        {
            oldIdentity.Unlock(nextHeight, txNew.nExpiryHeight);
            oldIdentity.unlockAfter = absoluteUnlock;
        }
        else
        {
            oldIdentity.Lock(unlockDelay);
        }
    }

    UniValue newParams(UniValue::VARR);

    oldIdentity.contentMultiMap.clear();
    newParams.push_back(oldIdentity.ToUniValue());
    for (int i = 2; i < params.size(); i++)
    {
        if (i == 3)
        {
            newParams.push_back(false);
        }
        newParams.push_back(params[i]);
    }
    return updateidentity(newParams, fHelp);
}

UniValue revokeidentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 5)
    {
        throw runtime_error(
            "revokeidentity \"nameorID\" (returntx) (tokenrevoke) (feeoffer) (sourceoffunds)\n"
            "\n\n"

            "\nArguments\n"
            "       \"returntx\"                        (bool,   optional) defaults to false and transaction is sent, if true, transaction is signed by this wallet and returned\n"
            "       \"tokenrevoke\"                     (bool,   optional) defaults to false, if true, the tokenized ID control token, if one exists, will be used to revoke\n"
            "       \"feeoffer\"                        (value,  optional) non-standard fee amount to pay for the transaction\n"
            "       \"sourceoffunds\"                   (string, optional) transparent or private address to source all funds for fees to preserve privacy of the identity\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("revokeidentity", "\"nameorID\"")
            + HelpExampleRpc("revokeidentity", "\"nameorID\"")
        );
    }

    CheckIdentityAPIsValid();

    // get identity
    bool returnTx = false;
    bool tokenizedIDControl = false;

    CTxDestination idDest = DecodeDestination(uni_get_str(params[0]));

    if (idDest.which() != COptCCParams::ADDRTYPE_ID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid JSON ID parameter");
    }

    CIdentityID idID(GetDestinationID(idDest));

    if (params.size() > 1)
    {
        returnTx = uni_get_bool(params[1], false);
    }

    CTxIn idTxIn;
    CIdentity oldID;
    uint32_t idHeight;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!(oldID = CIdentity::LookupIdentity(idID, 0, &idHeight, &idTxIn)).IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ID not found " + EncodeDestination(idID));
    }

    uint32_t nHeight = chainActive.Height();
    bool isPBaaS = CConstVerusSolutionVector::GetVersionByHeight(nHeight) >= CActivationHeight::ACTIVATE_PBAAS;
    if (isPBaaS && params.size() > 2)
    {
        tokenizedIDControl = uni_get_bool(params[2], false);
    }

    // if we are supposed to get our authority from the token, make sure it is present and prepare to spend it
    std::vector<COutput> controlTokenOuts;
    CCurrencyValueMap tokenCurrencyControlMap(std::vector<uint160>({idID}), std::vector<int64_t>({1}));

    if (tokenizedIDControl)
    {
        COptCCParams tcP;
        CCurrencyValueMap reserveMap;
        pwalletMain->AvailableReserveCoins(controlTokenOuts, true, nullptr, false, false, nullptr, &tokenCurrencyControlMap, false);
        if (controlTokenOuts.size() == 1 && controlTokenOuts[0].fSpendable)
        {
            reserveMap = controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue();
            if (!reserveMap.valueMap.count(idID) || reserveMap.valueMap[idID] != 1)
            {
                LogPrint("tokenizedidcontrol", "%s: controlTokenOuts.size(): %d, controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue(): %s, reserveMap: %s, reserveMap.valueMap[idID]: %ld\n", __func__, (int)controlTokenOuts.size(), controlTokenOuts[0].tx->vout[controlTokenOuts[0].i].ReserveOutValue().ToUniValue().write().c_str(), reserveMap.ToUniValue().write().c_str(), reserveMap.valueMap[idID]);
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot locate spendable tokenized ID control currency in wallet - if present, may require rescan");
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "No spendable tokenized ID control currency for revoke in wallet");
        }
    }

    CIdentity newID(oldID);
    newID.UpgradeVersion(chainActive.Height() + 1);
    newID.Revoke();

    UniValue newParams(UniValue::VARR);

    newID.contentMultiMap.clear();
    newParams.push_back(newID.ToUniValue());
    for (int i = 1; i < params.size(); i++)
    {
        newParams.push_back(params[i]);
    }
    return updateidentity(newParams, fHelp);
}

UniValue recoveridentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 5)
    {
        throw runtime_error(
            "recoveridentity \"jsonidentity\" (returntx) (tokenrecover) (feeoffer) (sourceoffunds)\n"
            "\n\n"

            "\nArguments\n"
            "       \"returntx\"                        (bool,   optional) defaults to false and transaction is sent, if true, transaction is signed by this wallet and returned\n"
            "       \"tokenrecover\"                    (bool,   optional) defaults to false, if true, the tokenized ID control token, if one exists, will be used to recover\n"
            "       \"feeoffer\"                        (value,  optional) non-standard fee amount to pay for the transaction\n"
            "       \"sourceoffunds\"                   (string, optional) transparent or private address to source all funds for fees to preserve privacy of the identity\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("recoveridentity", "\'{\"name\" : \"myname\"}\'")
            + HelpExampleRpc("recoveridentity", "\'{\"name\" : \"myname\"}\'")
        );
    }
    CheckIdentityAPIsValid();

    // get identity
    bool returnTx = false;
    bool tokenizedIDControl = false;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint32_t nHeight = chainActive.Height();
    bool isPBaaS = CConstVerusSolutionVector::GetVersionByHeight(nHeight) >= CActivationHeight::ACTIVATE_PBAAS;

    UniValue newUniIdentity = params[0];
    if (uni_get_int(find_value(newUniIdentity,"version")) == 0)
    {
        newUniIdentity.pushKV("version",
                              CConstVerusSolutionVector::GetVersionByHeight(nHeight + 1) >= CActivationHeight::ACTIVATE_VERUSVAULT ?
                                CIdentity::VERSION_VAULT :
                                CIdentity::VERSION_VERUSID);
    }

    if (uni_get_int(find_value(newUniIdentity,"minimumsignatures")) == 0)
    {
        newUniIdentity.pushKV("minimumsignatures", (int32_t)1);
    }

    CIdentity newID(newUniIdentity);
    uint160 newIDID = newID.GetID();

    if (!newID.IsValid(true))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid JSON ID parameter");
    }

    if (params.size() > 1)
    {
        returnTx = uni_get_bool(params[1], false);
    }

    if (isPBaaS && params.size() > 2)
    {
        tokenizedIDControl = uni_get_bool(params[2], false);
    }

    CTxIn idTxIn;
    CIdentity oldID;
    uint32_t idHeight;

    if (!(oldID = CIdentity::LookupIdentity(newIDID, 0, &idHeight, &idTxIn)).IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ID not found " + newID.ToUniValue().write());
    }

    if (find_value(newUniIdentity, "systemid").isNull())
    {
        newID.systemID = oldID.systemID;
    }

    if (!oldID.IsRevoked())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity must be revoked in order to recover : " + newID.name);
    }

    UniValue newParams(UniValue::VARR);

    newID.flags |= (oldID.flags & (CIdentity::FLAG_ACTIVECURRENCY + CIdentity::FLAG_TOKENIZED_CONTROL));

    newParams.push_back(newID.ToUniValue());
    for (int i = 1; i < params.size(); i++)
    {
        newParams.push_back(params[i]);
    }
    return updateidentity(newParams, false);
}

UniValue getidentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 4)
    {
        throw runtime_error(
            "getidentity \"name@ || iid\" (height) (txproof) (txproofheight)\n"
            "\n\n"

            "\nArguments\n"
            "    \"name@ || iid\"                       (string, required) name followed by \"@\" or i-address of an identity\n"
            "    \"height\"                             (number, optional) default=current height, return identity as of this height, if -1 include mempool\n"
            "    \"txproof\"                            (bool, optional) default=false, if true, returns proof of ID\n"
            "    \"txproofheight\"                      (number, optional) default=\"height\", height from which to generate a proof\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("getidentity", "\"name@\"")
            + HelpExampleRpc("getidentity", "\"name@\"")
        );
    }

    CheckIdentityAPIsValid();

    CTxDestination idID = DecodeDestination(uni_get_str(params[0]));
    if (idID.which() != COptCCParams::ADDRTYPE_ID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity parameter must be valid friendly name or identity address: \"" + uni_get_str(params[0]) + "\"");
    }

    LOCK(cs_main);

    uint32_t lteHeight = chainActive.Height();
    bool useMempool = false;
    if (params.size() > 1)
    {
        uint32_t tmpHeight = uni_get_int64(params[1]);
        if (tmpHeight > 0 && lteHeight > tmpHeight)
        {
            lteHeight = tmpHeight;
        }
        else if (tmpHeight == -1)
        {
            lteHeight = chainActive.Height() + 1;
            useMempool = true;
        }
    }

    bool txProof = params.size() > 2 ? uni_get_bool(params[2]) : false;
    uint32_t txProofHeight = params.size() > 3 ? uni_get_int64(params[3]) : 0;
    if (txProofHeight < lteHeight)
    {
        txProofHeight = lteHeight;
    }
    if (useMempool)
    {
        txProof = false;
    }

    CTxIn idTxIn;
    uint32_t height;

    CIdentity identity;
    bool canSign = false, canSpend = false;

    if (pwalletMain)
    {
        LOCK(pwalletMain->cs_wallet);
        uint256 txID;
        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
        if (pwalletMain->GetIdentity(GetDestinationID(idID), keyAndIdentity, lteHeight))
        {
            canSign = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SIGN;
            canSpend = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SPEND;
            identity = static_cast<CIdentity>(keyAndIdentity.second);
        }
    }

    uint160 identityID = GetDestinationID(idID);
    identity = CIdentity::LookupIdentity(CIdentityID(identityID), lteHeight, &height, &idTxIn, useMempool);

    if (!identity.IsValid() && identityID == VERUS_CHAINID)
    {
        std::vector<CTxDestination> primary({CTxDestination(CKeyID(uint160()))});
        std::vector<std::pair<uint160, uint256>> contentmap;
        std::multimap<uint160, std::vector<unsigned char>> contentmultimap;

        identity = CIdentity(CConstVerusSolutionVector::GetVersionByHeight(height) >= CActivationHeight::ACTIVATE_PBAAS ? CIdentity::VERSION_PBAAS : CIdentity::VERSION_VAULT,
                             CIdentity::FLAG_ACTIVECURRENCY,
                             primary,
                             1,
                             ConnectedChains.ThisChain().parent,
                             VERUS_CHAINNAME,
                             contentmap,
                             contentmultimap,
                             ConnectedChains.ThisChain().GetID(),
                             ConnectedChains.ThisChain().GetID(),
                             std::vector<libzcash::SaplingPaymentAddress>());
    }

    UniValue ret(UniValue::VOBJ);

    uint160 parent;
    if (identity.IsValid() && identity.name == CleanName(identity.name, parent))
    {
        ret.pushKV("friendlyname", ConnectedChains.GetFriendlyIdentityName(identity));
        ret.pushKV("fullyqualifiedname", ConnectedChains.GetFriendlyIdentityName(identity, true));
        ret.push_back(Pair("identity", identity.ToUniValue()));
        ret.push_back(Pair("status", identity.IsRevoked() ? "revoked" : "active"));
        ret.push_back(Pair("canspendfor", canSpend));
        ret.push_back(Pair("cansignfor", canSign));
        ret.push_back(Pair("blockheight", (int64_t)height));
        ret.push_back(Pair("txid", idTxIn.prevout.hash.GetHex()));
        ret.push_back(Pair("vout", (int32_t)idTxIn.prevout.n));

        if (txProof &&
            !idTxIn.prevout.hash.IsNull() &&
            height > 0 &&
            height <= chainActive.Height())
        {
            CTransaction idTx;
            uint256 blkHash;
            CBlockIndex *pIndex;
            LOCK(mempool.cs);
            if (!myGetTransaction(idTxIn.prevout.hash, idTx, blkHash) ||
                blkHash.IsNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Identity transacton not found or not indexed / committed");
            }
            auto blkMapIt = mapBlockIndex.find(blkHash);
            if (blkMapIt == mapBlockIndex.end()  ||
                !chainActive.Contains(pIndex = blkMapIt->second))
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Identity transacton not indexed / committed");
            }
            CPartialTransactionProof idProof = CPartialTransactionProof(idTx,
                                                                        std::vector<int>(),
                                                                        std::vector<int>({(int)idTxIn.prevout.n}),
                                                                        pIndex,
                                                                        txProofHeight);
            if (idProof.IsValid())
            {
                ret.push_back(Pair("proof", idProof.ToUniValue()));
            }
        }

        return ret;
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Identity not found");
    }
}

bool CConnectedChains::GetNotaryCurrencies(const CRPCChainData notaryChain,
                                           const std::set<uint160> &currencyIDs,
                                           std::map<uint160, std::pair<CCurrencyDefinition, CPBaaSNotarization>> &currencyDefs,
                                           uint32_t untilHeight)
{
    for (auto &curID : currencyIDs)
    {
        CCurrencyDefinition oneDef;
        UniValue params(UniValue::VARR);
        UniValue result, error;
        params.push_back(EncodeDestination(CIdentityID(curID)));

        if (notaryChain.GetID() == ASSETCHAINS_CHAINID)
        {
            try
            {
                result = getcurrency(params, false);
            } catch (std::exception e)
            {
                result = NullUniValue;
            }
        }
        else
        {
            try
            {
                result = find_value(RPCCallRoot("getcurrency", params), "result");
            } catch (exception e)
            {
                result = NullUniValue;
            }
        }

        if (!result.isNull())
        {
            oneDef = CCurrencyDefinition(result);
        }

        if (!oneDef.IsValid())
        {
            // no matter what happens, we should be able to get a valid currency state of some sort, if not, fail
            LogPrintf("Unable to get currency definition for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
            printf("Unable to get currency definition for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
            return false;
        }

        CPBaaSNotarization launchNotarization;

        // get launch notarization from notary chain if on the notary chain or pre-block 1, and from block 1 if on
        // the PBaaS chain after it has been confirmed
        if ((oneDef.IsPBaaSChain() || oneDef.IsGatewayConverter()) &&
            (!ConnectedChains.DiscernBlockOneLaunchInfo(chainActive.Height()) ||
             (notaryChain.GetID() != ASSETCHAINS_CHAINID && oneDef.systemID == ASSETCHAINS_CHAINID) ||
             (notaryChain.GetID() == ASSETCHAINS_CHAINID && oneDef.systemID != ASSETCHAINS_CHAINID)) &&
            oneDef.launchSystemID == notaryChain.GetID())
        {
            if (notaryChain.GetID() == ASSETCHAINS_CHAINID || chainActive.Height() > 0)
            {
                try
                {
                    result = getlaunchinfo(params, false);
                } catch (std::exception e)
                {
                    result = NullUniValue;
                }
            }
            else
            {
                try
                {
                    result = find_value(RPCCallRoot("getlaunchinfo", params), "result");
                } catch (exception e)
                {
                    result = NullUniValue;
                }
            }
            if (result.isNull() || !(launchNotarization = CPBaaSNotarization(find_value(result, "launchnotarization"))).IsValid())
            {
                LogPrintf("Unable to get notarization for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
                printf("Unable to get notarization for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
                return false;
            }
        }

        {
            LOCK(cs_mergemining);
            currencyDefs[oneDef.GetID()].first = oneDef;
            currencyDefs[oneDef.GetID()].second = launchNotarization;
            currencyDefs[oneDef.GetID()].second.SetBlockOneNotarization();
        }
    }
    return true;
}

bool CConnectedChains::GetNotaryIDs(const CRPCChainData notaryChain,
                                    const CCurrencyDefinition &pbaasChain,
                                    const std::set<uint160> &idIDs,
                                    std::map<uint160, CIdentity> &identities,
                                    uint32_t untilHeight)
{
    for (auto &curID : idIDs)
    {
        CIdentity oneDef;

        if (notaryChain.GetID() == ASSETCHAINS_CHAINID)
        {
            oneDef = CIdentity::LookupIdentity(curID, untilHeight);
        }
        else
        {
            UniValue params(UniValue::VARR);
            UniValue result;
            params.push_back(EncodeDestination(CIdentityID(curID)));
            params.push_back((int64_t)untilHeight);
            try
            {
                result = find_value(RPCCallRoot("getidentity", params), "result");
            } catch (exception e)
            {
                result = NullUniValue;
            }
            if (!result.isNull())
            {
                oneDef = CIdentity(find_value(result, "identity"));
            }
            if (!oneDef.IsValid())
            {
                // no matter what happens, we should be able to get a valid currency state of some sort, if not, fail
                LogPrintf("Unable to get identity for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
                printf("Unable to get identity for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
                return false;
            }
        }

        if (untilHeight >= ConnectedChains.vARRRUpdateHeight(notaryChain.GetID() == VERUS_CHAINID))
        {
            oneDef.contentMap.clear();
            oneDef.contentMultiMap.clear();
        }

        if (ConnectedChains.BlockOneIDUpgrade())
        {
            oneDef.UpgradeVersion(ASSETCHAINS_CHAINID == notaryChain.GetID() ? pbaasChain.startBlock : 1);
        }
        else if (oneDef.nVersion < oneDef.VERSION_PBAAS)
        {
            return false;
        }

        {
            identities[oneDef.GetID()] = oneDef;
        }
    }

    // if we have a currency converter, create a new ID as a clone of the main chain ID with revocation and recovery as main chain ID
    if (!pbaasChain.GatewayConverterID().IsNull())
    {
        uint160 pbaasID = pbaasChain.GetID();
        CIdentity newConverterIdentity = identities[pbaasID];
        assert(newConverterIdentity.IsValid());
        newConverterIdentity.parent = pbaasID;
        newConverterIdentity.systemID = pbaasID;
        newConverterIdentity.name = pbaasChain.gatewayConverterName;
        newConverterIdentity.contentMap.clear();
        newConverterIdentity.contentMultiMap.clear();
        newConverterIdentity.revocationAuthority = newConverterIdentity.recoveryAuthority = pbaasID;
        identities[pbaasChain.GatewayConverterID()] = newConverterIdentity;
    }
    return true;
}

UniValue getidentityhistory(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 5)
    {
        throw runtime_error(
            "getidentityhistory \"name@ || iid\" (heightstart) (heightend) (txproofs) (txproofheight)\n"
            "\n\n"

            "\nArguments\n"
            "    \"name@ || iid\"                       (string, required) name followed by \"@\" or i-address of an identity\n"
            "    \"heightstart\"                        (number, optional) default=0, only return content from this height forward, inclusive\n"
            "    \"heightend\"                          (number, optional) default=0 which means max height, only return content up to this height,\n"
            "                                                               inclusive. -1 means also return values from the mempool.\n"
            "    \"txproofs\"                           (bool, optional) default=false, if true, returns proof of ID\n"
            "    \"txproofheight\"                      (number, optional) default=\"height\", height from which to generate a proof\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("getidentityhistory", "\"name@\"")
            + HelpExampleRpc("getidentityhistory", "\"name@\"")
        );
    }

    CheckIdentityAPIsValid();

    CTxDestination idID = DecodeDestination(uni_get_str(params[0]));
    if (idID.which() != COptCCParams::ADDRTYPE_ID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity parameter must be valid friendly name or identity address: \"" + uni_get_str(params[0]) + "\"");
    }

    LOCK(cs_main);

    uint32_t gteHeight = 0;
    uint32_t height = chainActive.Height();
    uint32_t lteHeight = height;
    bool useMempool = false;
    if (params.size() > 1)
    {
        uint32_t tmpHeight = uni_get_int64(params[1]);
        if (tmpHeight > 0)
        {
            gteHeight = tmpHeight;
        }
    }
    if (params.size() > 2)
    {
        uint32_t tmpHeight = uni_get_int64(params[2]);
        if (tmpHeight > 0 && lteHeight > tmpHeight)
        {
            lteHeight = tmpHeight;
        }
        else if (!tmpHeight || tmpHeight == -1)
        {
            lteHeight = height + 1;
            useMempool = tmpHeight == -1;
        }
    }

    bool txProof = params.size() > 3 ? uni_get_bool(params[3]) : false;
    uint32_t txProofHeight = params.size() > 4 ? uni_get_int64(params[4]) : 0;
    if (txProofHeight < lteHeight)
    {
        txProofHeight = lteHeight;
    }

    CTxIn idTxIn;

    CIdentity identity;
    bool canSign = false, canSpend = false;

    if (pwalletMain)
    {
        LOCK(pwalletMain->cs_wallet);
        uint256 txID;
        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
        if (pwalletMain->GetIdentity(GetDestinationID(idID), keyAndIdentity, lteHeight))
        {
            canSign = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SIGN;
            canSpend = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SPEND;
            identity = static_cast<CIdentity>(keyAndIdentity.second);
        }
    }

    uint160 identityID = GetDestinationID(idID);
    identity = CIdentity::LookupIdentity(CIdentityID(identityID), lteHeight, &height, &idTxIn, useMempool);

    if (!identity.IsValid() && identityID == VERUS_CHAINID)
    {
        std::vector<CTxDestination> primary({CTxDestination(CKeyID(uint160()))});
        std::vector<std::pair<uint160, uint256>> contentmap;
        std::multimap<uint160, std::vector<unsigned char>> contentmultimap;

        identity = CIdentity(CConstVerusSolutionVector::GetVersionByHeight(height) >= CActivationHeight::ACTIVATE_PBAAS ? CIdentity::VERSION_PBAAS : CIdentity::VERSION_VAULT,
                             CIdentity::FLAG_ACTIVECURRENCY,
                             primary,
                             1,
                             ConnectedChains.ThisChain().parent,
                             VERUS_CHAINNAME,
                             contentmap,
                             contentmultimap,
                             ConnectedChains.ThisChain().GetID(),
                             ConnectedChains.ThisChain().GetID(),
                             std::vector<libzcash::SaplingPaymentAddress>());
    }

    UniValue ret(UniValue::VOBJ);

    uint160 parent;
    if (identity.IsValid() && identity.name == CleanName(identity.name, parent))
    {
        ret.pushKV("fullyqualifiedname", ConnectedChains.GetFriendlyIdentityName(identity));
        ret.push_back(Pair("status", identity.IsRevoked() ? "revoked" : "active"));
        ret.push_back(Pair("canspendfor", canSpend));
        ret.push_back(Pair("cansignfor", canSign));
        ret.push_back(Pair("blockheight", (int64_t)height));
        ret.push_back(Pair("txid", idTxIn.prevout.hash.GetHex()));
        ret.push_back(Pair("vout", (int32_t)idTxIn.prevout.n));

        auto identities = CIdentity::LookupIdentities(GetDestinationID(idID), gteHeight, lteHeight, useMempool, txProof, txProofHeight, std::vector<uint160>(), true);

        UniValue identityArrUni(UniValue::VARR);
        for (auto &oneIdentity : identities)
        {
            UniValue identityDescr(UniValue::VOBJ);
            identityDescr.pushKV("identity", std::get<0>(oneIdentity).ToUniValue());
            identityDescr.pushKV("blockhash", std::get<1>(oneIdentity).GetHex());
            identityDescr.pushKV("height", (int64_t)std::get<2>(oneIdentity));
            identityDescr.pushKV("output", std::get<3>(oneIdentity).ToUniValue());
            if (txProof && std::get<4>(oneIdentity).IsValid())
            {
                identityDescr.pushKV("proof", std::get<4>(oneIdentity).ToUniValue());
            }
            identityArrUni.push_back(identityDescr);
        }
        ret.pushKV("history", identityArrUni);
        return ret;
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Identity not found");
    }
}

UniValue getidentitycontent(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 7)
    {
        throw runtime_error(
            "getidentitycontent \"name@ || iid\" (heightstart) (heightend) (txproofs) (txproofheight) (vdxfkey) (keepdeleted)\n"
            "\n\n"

            "\nArguments\n"
            "    \"name@ || iid\"                       (string, required) name followed by \"@\" or i-address of an identity\n"
            "    \"heightstart\"                        (number, optional) default=0, only return content from this height forward, inclusive\n"
            "    \"heightend\"                          (number, optional) default=0 which means max height, only return content up to this height,\n"
            "                                                               inclusive. -1 means also return values from the mempool.\n"
            "    \"txproofs\"                           (bool, optional) default=false, if true, returns proof of ID\n"
            "    \"txproofheight\"                      (number, optional) default=\"height\", height from which to generate a proof\n"
            "    \"vdxfkey\"                            (vdxf key, optional) default=null, more selective search for specific content in ID\n"
            "                                                               The key will be automatically bound to the identity and multimap key.\n"
            "    \"keepdeleted\"                        (bool, optional) default=false, if true, return deleted items as well\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("getidentitycontent", "\"name@\"")
            + HelpExampleRpc("getidentitycontent", "\"name@\"")
        );
    }

    CheckIdentityAPIsValid();

    CTxDestination idID = DecodeDestination(uni_get_str(params[0]));
    if (idID.which() != COptCCParams::ADDRTYPE_ID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity parameter must be valid friendly name or identity address: \"" + uni_get_str(params[0]) + "\"");
    }

    LOCK(cs_main);

    uint32_t gteHeight = 0;
    uint32_t height = chainActive.Height();
    uint32_t lteHeight = height;
    bool useMempool = false;
    if (params.size() > 1)
    {
        uint32_t tmpHeight = uni_get_int64(params[1]);
        if (tmpHeight > 0)
        {
            gteHeight = tmpHeight;
        }
    }
    if (params.size() > 2)
    {
        uint32_t tmpHeight = uni_get_int64(params[2]);
        if (tmpHeight > 0 && lteHeight > tmpHeight)
        {
            lteHeight = tmpHeight;
        }
        else if (!tmpHeight || tmpHeight == -1)
        {
            lteHeight = height + 1;
            useMempool = tmpHeight == -1;
        }
    }

    bool txProof = params.size() > 3 ? uni_get_bool(params[3]) : false;
    uint32_t txProofHeight = params.size() > 4 ? uni_get_int64(params[4]) : 0;
    if (txProofHeight < lteHeight)
    {
        txProofHeight = lteHeight;
    }

    uint160 vdxfKey;
    if (params.size() > 5)
    {
        CTxDestination vdxfDest = DecodeDestination(uni_get_str(params[5]));
        if (vdxfDest.which() != COptCCParams::ADDRTYPE_ID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "vdxfkey parameter must be a valid i-address: \"" + uni_get_str(params[5]) + "\"");
        }
        vdxfKey = GetDestinationID(vdxfDest);
    }
    
    // If a vdxfKey is provided, automatically transform it to the proper search key
    // by binding it to the identity ID first, then binding that result with "vrsc::identity.multimapkey"
    uint160 searchKey = vdxfKey;
    if (!vdxfKey.IsNull())
    {
        // Bind the identity ID to the vdxfkey, then to the multimap key
        searchKey = CCrossChainRPCData::GetConditionID(CVDXF_Data::MultiMapKey(), CCrossChainRPCData::GetConditionID(vdxfKey, GetDestinationID(idID)));
    }
    
    bool keepDeleted = params.size() > 6 ? uni_get_bool(params[6]) : false;

    CTxIn idTxIn;

    CIdentity identity;
    bool canSign = false, canSpend = false;

    if (pwalletMain)
    {
        LOCK(pwalletMain->cs_wallet);
        uint256 txID;
        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
        if (pwalletMain->GetIdentity(GetDestinationID(idID), keyAndIdentity, lteHeight))
        {
            canSign = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SIGN;
            canSpend = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SPEND;
            identity = static_cast<CIdentity>(keyAndIdentity.second);
        }
    }

    uint160 identityID = GetDestinationID(idID);
    identity = CIdentity::LookupIdentity(CIdentityID(identityID), lteHeight, &height, &idTxIn, useMempool);

    if (!identity.IsValid() && identityID == VERUS_CHAINID)
    {
        std::vector<CTxDestination> primary({CTxDestination(CKeyID(uint160()))});
        std::vector<std::pair<uint160, uint256>> contentmap;
        std::multimap<uint160, std::vector<unsigned char>> contentmultimap;

        identity = CIdentity(CConstVerusSolutionVector::GetVersionByHeight(height) >= CActivationHeight::ACTIVATE_PBAAS ? CIdentity::VERSION_PBAAS : CIdentity::VERSION_VAULT,
                             CIdentity::FLAG_ACTIVECURRENCY,
                             primary,
                             1,
                             ConnectedChains.ThisChain().parent,
                             VERUS_CHAINNAME,
                             contentmap,
                             contentmultimap,
                             ConnectedChains.ThisChain().GetID(),
                             ConnectedChains.ThisChain().GetID(),
                             std::vector<libzcash::SaplingPaymentAddress>());
    }

    UniValue ret(UniValue::VOBJ);

    uint160 parent;
    if (identity.IsValid() && identity.name == CleanName(identity.name, parent))
    {
        ret.pushKV("fullyqualifiedname", ConnectedChains.GetFriendlyIdentityName(identity));
        ret.push_back(Pair("status", identity.IsRevoked() ? "revoked" : "active"));
        ret.push_back(Pair("canspendfor", canSpend));
        ret.push_back(Pair("cansignfor", canSign));
        ret.push_back(Pair("blockheight", (int64_t)height));
        ret.push_back(Pair("fromheight", (int64_t)gteHeight));
        ret.push_back(Pair("toheight", (int64_t)lteHeight));
        ret.push_back(Pair("txid", idTxIn.prevout.hash.GetHex()));
        ret.push_back(Pair("vout", (int32_t)idTxIn.prevout.n));

        auto contentMap = CIdentity::GetAggregatedIdentityMultimap(identityID,
                                                                   gteHeight,
                                                                   lteHeight,
                                                                   useMempool,
                                                                   txProof,
                                                                   txProofHeight,
                                                                   searchKey,
                                                                   keepDeleted);

        // put the aggregated content map in the ID before rendering
        identity.contentMultiMap.clear();
        for (auto oneMapEntry : contentMap)
        {
            identity.contentMultiMap.insert(std::make_pair(oneMapEntry.first, std::get<0>(oneMapEntry.second)));
        }
        ret.push_back(Pair("identity", identity.ToUniValue()));
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Identity not found");
    }
    return ret;
}

UniValue IdentityPairToUni(const std::pair<CIdentityMapKey, CIdentityMapValue> &identity)
{
    UniValue oneID(UniValue::VOBJ);

    if (identity.first.IsValid() && identity.second.IsValid())
    {
        oneID.push_back(Pair("identity", identity.second.ToUniValue()));
        oneID.push_back(Pair("blockheight", (int64_t)identity.first.blockHeight));
        oneID.push_back(Pair("txid", identity.second.txid.GetHex()));
        if (identity.second.IsRevoked())
        {
            oneID.push_back(Pair("status", "revoked"));
            oneID.push_back(Pair("canspendfor", bool(0)));
            oneID.push_back(Pair("cansignfor", bool(0)));
        }
        else
        {
            oneID.push_back(Pair("status", "active"));
            oneID.push_back(Pair("canspendfor", bool(identity.first.flags & identity.first.CAN_SPEND)));
            oneID.push_back(Pair("cansignfor", bool(identity.first.flags & identity.first.CAN_SIGN)));
        }
    }
    return oneID;
}

UniValue listidentities(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
    {
        throw runtime_error(
            "listidentities (includecanspend) (includecansign) (includewatchonly)\n"
            "\n\n"

            "\nArguments\n"
            "    \"includecanspend\"    (bool, optional, default=true)    Include identities for which we can spend/authorize\n"
            "    \"includecansign\"     (bool, optional, default=true)    Include identities that we can only sign for but not spend\n"
            "    \"includewatchonly\"   (bool, optional, default=false)   Include identities that we can neither sign nor spend, but are either watched or are co-signers with us\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("listidentities", "true")
            + HelpExampleRpc("listidentities", "true")
        );
    }

    CheckIdentityAPIsValid();

    std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> mine, imsigner, notmine;
    CIdentity oneIdentity;
    uint32_t oneIdentityHeight;

    bool includeCanSpend = params.size() > 0 ? uni_get_bool(params[0], true) : true;
    bool includeCanSign = params.size() > 1 ? uni_get_bool(params[1], true) : true;
    bool includeWatchOnly = params.size() > 2 ? uni_get_bool(params[2], false) : false;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (pwalletMain->GetIdentities(mine, imsigner, notmine))
    {
        UniValue ret(UniValue::VARR);
        if (includeCanSpend)
        {
            for (auto identity : mine)
            {
                uint160 parent;
                if (identity.second.IsValid() && identity.second.name == CleanName(identity.second.name, parent))
                {
                    oneIdentity = CIdentity::LookupIdentity(identity.first.idID, 0, &oneIdentityHeight);

                    if (!oneIdentity.IsValid())
                    {
                        if (identity.first.idID != VERUS_CHAINID)
                        {
                            continue;
                        }
                        std::vector<CTxDestination> primary({CTxDestination(CKeyID(uint160()))});
                        std::vector<std::pair<uint160, uint256>> contentmap;
                        std::multimap<uint160, std::vector<unsigned char>> contentmultimap;
                        oneIdentity = CIdentity(CConstVerusSolutionVector::GetVersionByHeight(oneIdentityHeight) >= CActivationHeight::ACTIVATE_PBAAS ?
                                                                                                        CIdentity::VERSION_PBAAS :
                                                                                                        CIdentity::VERSION_VAULT,
                                                CIdentity::FLAG_ACTIVECURRENCY,
                                                primary,
                                                1,
                                                ConnectedChains.ThisChain().parent,
                                                VERUS_CHAINNAME,
                                                contentmap,
                                                contentmultimap,
                                                ConnectedChains.ThisChain().GetID(),
                                                ConnectedChains.ThisChain().GetID(),
                                                std::vector<libzcash::SaplingPaymentAddress>());
                    }
                    (*(CIdentity *)&identity.second) = oneIdentity;
                    // TODO: confirm that missing block order is fine for this API
                    identity.first.blockHeight = oneIdentityHeight;
                    ret.push_back(IdentityPairToUni(identity));
                }
            }
        }
        if (includeCanSign)
        {
            for (auto identity : imsigner)
            {
                uint160 parent;
                if (identity.second.IsValid() && identity.second.name == CleanName(identity.second.name, parent))
                {
                    oneIdentity = CIdentity::LookupIdentity(identity.first.idID, 0, &oneIdentityHeight);

                    if (!oneIdentity.IsValid())
                    {
                        if (identity.first.idID != VERUS_CHAINID)
                        {
                            continue;
                        }
                        std::vector<CTxDestination> primary({CTxDestination(CKeyID(uint160()))});
                        std::vector<std::pair<uint160, uint256>> contentmap;
                        std::multimap<uint160, std::vector<unsigned char>> contentmultimap;
                        oneIdentity = CIdentity(CConstVerusSolutionVector::GetVersionByHeight(oneIdentityHeight) >= CActivationHeight::ACTIVATE_PBAAS ?
                                                                                                        CIdentity::VERSION_PBAAS :
                                                                                                        CIdentity::VERSION_VAULT,
                                                CIdentity::FLAG_ACTIVECURRENCY,
                                                primary,
                                                1,
                                                ConnectedChains.ThisChain().parent,
                                                VERUS_CHAINNAME,
                                                contentmap,
                                                contentmultimap,
                                                ConnectedChains.ThisChain().GetID(),
                                                ConnectedChains.ThisChain().GetID(),
                                                std::vector<libzcash::SaplingPaymentAddress>());
                    }
                    (*(CIdentity *)&identity.second) = oneIdentity;
                    ret.push_back(IdentityPairToUni(identity));
                }
            }
        }
        if (includeWatchOnly)
        {
            for (auto identity : notmine)
            {
                uint160 parent;
                if (identity.second.IsValid() && identity.second.name == CleanName(identity.second.name, parent))
                {
                    oneIdentity = CIdentity::LookupIdentity(identity.first.idID, 0, &oneIdentityHeight);

                    if (!oneIdentity.IsValid())
                    {
                        if (identity.first.idID != VERUS_CHAINID)
                        {
                            continue;
                        }
                        std::vector<CTxDestination> primary({CTxDestination(CKeyID(uint160()))});
                        std::vector<std::pair<uint160, uint256>> contentmap;
                        std::multimap<uint160, std::vector<unsigned char>> contentmultimap;
                        oneIdentity = CIdentity(CConstVerusSolutionVector::GetVersionByHeight(oneIdentityHeight) >= CActivationHeight::ACTIVATE_PBAAS ?
                                                                                                        CIdentity::VERSION_PBAAS :
                                                                                                        CIdentity::VERSION_VAULT,
                                                CIdentity::FLAG_ACTIVECURRENCY,
                                                primary,
                                                1,
                                                ConnectedChains.ThisChain().parent,
                                                VERUS_CHAINNAME,
                                                contentmap,
                                                contentmultimap,
                                                ConnectedChains.ThisChain().GetID(),
                                                ConnectedChains.ThisChain().GetID(),
                                                std::vector<libzcash::SaplingPaymentAddress>());
                    }
                    (*(CIdentity *)&identity.second) = oneIdentity;
                    ret.push_back(IdentityPairToUni(identity));
                }
            }
        }
        return ret;
    }
    else
    {
        return NullUniValue;
    }
}

UniValue getidentitieswithaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getidentitieswithaddress '{\"address\":\"validprimaryaddress\",\"fromheight\":height, \"toheight\":height, \"unspent\":false}'\n"
            "\n\n"

            "\nArguments\n"
            "{\n"
            "    \"address\":\"validaddress\"   (string, required) returns all identities that contain the specified address in its primary addresses\n"
            "    \"fromheight\":n               (number, optional, default=0) Search for qualified identities modified from this height forward only\n"
            "    \"toheight\":n                 (number, optional, default=0) Search for qualified identities only up until this height (0 == no limit)\n"
            "    \"unspent\":bool               (bool, optional, default=false) if true, this will only return active ID UTXOs as of the current block height\n"
            "}\n"

            "\nResult:\n"
            "[                                  (array) array of matching identities\n"
            "  {identityobject},                (object) identity with additional member \"txout\" with txhash and output index\n"
            "  ...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("getidentitieswithaddress", "\'{\"address\":\"validprimaryaddress\",\"fromheight\":height, \"toheight\":height, \"unspent\":false}\'")
            + HelpExampleRpc("getidentitieswithaddress", "\'{\"address\":\"validprimaryaddress\",\"fromheight\":height, \"toheight\":height, \"unspent\":false}\'")
        );
    }

    CheckIdentityAPIsValid();
    if (!fIdIndex)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "getidentitieswithaddress requires -idindex=1 when starting the daemon\n");
    }
    UniValue retVal(UniValue::VARR);

    std::string addressString = uni_get_str(find_value(params[0], "address"));
    CTxDestination addressDest = DecodeDestination(addressString);
    if (addressDest.which() != COptCCParams::ADDRTYPE_PKH && addressDest.which() != COptCCParams::ADDRTYPE_PK)
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "no valid PKH or PK address\n");
    }
    uint32_t fromHeight = uni_get_int64(find_value(params[0], "fromheight"));
    uint32_t toHeight = uni_get_int64(find_value(params[0], "toheight"));

    if (uni_get_bool(find_value(params[0], "unspent")))
    {
        std::map<uint160, std::pair<CAddressUnspentDbEntry, CIdentity>> identities;
        if (CIdentity::GetActiveIdentitiesByPrimaryAddress(addressDest, identities))
        {
            for (auto &oneIdentity : identities)
            {
                if ((!fromHeight || oneIdentity.second.first.second.blockHeight >= fromHeight) &&
                    (!toHeight || oneIdentity.second.first.second.blockHeight <= toHeight))
                {
                    UniValue idUni = oneIdentity.second.second.ToUniValue();
                    idUni.pushKV("txout", CUTXORef(oneIdentity.second.first.first.txhash, oneIdentity.second.first.first.index).ToUniValue());
                    retVal.push_back(idUni);
                }
            }
        }
    }
    else
    {
        std::map<uint160, std::pair<CAddressIndexDbEntry, CIdentity>> identities;
        if (CIdentity::GetIdentityOutsByPrimaryAddress(addressDest, identities, fromHeight, toHeight))
        {
            for (auto &oneIdentity : identities)
            {
                UniValue idUni = oneIdentity.second.second.ToUniValue();
                idUni.pushKV("txout", CUTXORef(oneIdentity.second.first.first.txhash, oneIdentity.second.first.first.index).ToUniValue());
                retVal.push_back(idUni);
            }
        }
    }
    return retVal;
}

UniValue getidentitieswithrevocation(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getidentitieswithrevocation '{\"identityid\":\"idori-address\", \"fromheight\":height, \"toheight\":height, \"unspent\":false}'\n"
            "\n\n"

            "\nArguments\n"
            "{\n"
            "    \"identityid\":\"idori-address\" (string, required) returns all identities where this ID or i-address is the revocation authority\n"
            "    \"fromheight\":n               (number, optional, default=0) Search for qualified identities modified from this height forward only\n"
            "    \"toheight\":n                 (number, optional, default=0) Search for qualified identities only up until this height (0 == no limit)\n"
            "    \"unspent\":bool               (bool, optional, default=false) if true, this will only return active ID UTXOs as of the current block height\n"
            "}\n"

            "\nResult:\n"
            "[                                  (array) array of matching identities\n"
            "  {identityobject},                (object) identity with additional member \"txout\" with txhash and output index\n"
            "  ...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("getidentitieswithrevocation", "\'{\"identityid\":\"idori-address\",\"fromheight\":height,\"toheight\":height,\"unspent\":false}\'")
            + HelpExampleRpc("getidentitieswithrevocation", "\'{\"identityid\":\"idori-address\",\"fromheight\":height,\"toheight\":height,\"unspent\":false}\'")
        );
    }

    CheckIdentityAPIsValid();
    if (!fIdIndex)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "getidentitieswithrevocation requires -idindex=1 when starting the daemon\n");
    }
    UniValue retVal(UniValue::VARR);

    std::string addressString = uni_get_str(find_value(params[0], "identityid"));
    CTxDestination addressDest = DecodeDestination(addressString);
    if (addressDest.which() != COptCCParams::ADDRTYPE_ID)
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "no valid ID address\n");
    }

    CIdentityID idID = GetDestinationID(addressDest);

    uint32_t fromHeight = uni_get_int64(find_value(params[0], "fromheight"));
    uint32_t toHeight = uni_get_int64(find_value(params[0], "toheight"));

    if (uni_get_bool(find_value(params[0], "unspent")))
    {
        std::map<uint160, std::pair<CAddressUnspentDbEntry, CIdentity>> identities;
        if (CIdentity::GetActiveIdentitiesWithRevocationID(idID, identities))
        {
            for (auto &oneIdentity : identities)
            {
                if ((!fromHeight || oneIdentity.second.first.second.blockHeight >= fromHeight) &&
                    (!toHeight || oneIdentity.second.first.second.blockHeight <= toHeight))
                {
                    UniValue idUni = oneIdentity.second.second.ToUniValue();
                    idUni.pushKV("txout", CUTXORef(oneIdentity.second.first.first.txhash, oneIdentity.second.first.first.index).ToUniValue());
                    retVal.push_back(idUni);
                }
            }
        }
    }
    else
    {
        std::map<uint160, std::pair<CAddressIndexDbEntry, CIdentity>> identities;
        if (CIdentity::GetIdentityOutsWithRevocationID(idID, identities, fromHeight, toHeight))
        {
            for (auto &oneIdentity : identities)
            {
                UniValue idUni = oneIdentity.second.second.ToUniValue();
                idUni.pushKV("txout", CUTXORef(oneIdentity.second.first.first.txhash, oneIdentity.second.first.first.index).ToUniValue());
                retVal.push_back(idUni);
            }
        }
    }
    return retVal;
}

UniValue getidentitieswithrecovery(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getidentitieswithrecovery '{\"identityid\":\"idori-address\", \"fromheight\":height, \"toheight\":height, \"unspent\":false}'\n"
            "\n\n"

            "\nArguments\n"
            "{\n"
            "    \"identityid\":\"idori-address\" (string, required) returns all identities where this ID or i-address is the recovery authority\n"
            "    \"fromheight\":n               (number, optional, default=0) Search for qualified identities modified from this height forward only\n"
            "    \"toheight\":n                 (number, optional, default=0) Search for qualified identities only up until this height (0 == no limit)\n"
            "    \"unspent\":bool               (bool, optional, default=false) if true, this will only return active ID UTXOs as of the current block height\n"
            "}\n"

            "\nResult:\n"
            "[                                  (array) array of matching identities\n"
            "  {identityobject},                (object) identity with additional member \"txout\" with txhash and output index\n"
            "  ...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("getidentitieswithrecovery", "\'{\"identityid\":\"idori-address\",\"fromheight\":height,\"toheight\":height,\"unspent\":false}\'")
            + HelpExampleRpc("getidentitieswithrecovery", "\'{\"identityid\":\"idori-address\",\"fromheight\":height,\"toheight\":height,\"unspent\":false}\'")
        );
    }

    CheckIdentityAPIsValid();
    if (!fIdIndex)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "getidentitieswithrecovery requires -idindex=1 when starting the daemon\n");
    }
    UniValue retVal(UniValue::VARR);

    std::string addressString = uni_get_str(find_value(params[0], "identityid"));
    CTxDestination addressDest = DecodeDestination(addressString);
    if (addressDest.which() != COptCCParams::ADDRTYPE_ID)
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "no valid ID address\n");
    }

    CIdentityID idID = GetDestinationID(addressDest);

    uint32_t fromHeight = uni_get_int64(find_value(params[0], "fromheight"));
    uint32_t toHeight = uni_get_int64(find_value(params[0], "toheight"));

    if (uni_get_bool(find_value(params[0], "unspent")))
    {
        std::map<uint160, std::pair<CAddressUnspentDbEntry, CIdentity>> identities;
        if (CIdentity::GetActiveIdentitiesWithRecoveryID(idID, identities))
        {
            for (auto &oneIdentity : identities)
            {
                if ((!fromHeight || oneIdentity.second.first.second.blockHeight >= fromHeight) &&
                    (!toHeight || oneIdentity.second.first.second.blockHeight <= toHeight))
                {
                    UniValue idUni = oneIdentity.second.second.ToUniValue();
                    idUni.pushKV("txout", CUTXORef(oneIdentity.second.first.first.txhash, oneIdentity.second.first.first.index).ToUniValue());
                    retVal.push_back(idUni);
                }
            }
        }
    }
    else
    {
        std::map<uint160, std::pair<CAddressIndexDbEntry, CIdentity>> identities;
        if (CIdentity::GetIdentityOutsWithRecoveryID(idID, identities, fromHeight, toHeight))
        {
            for (auto &oneIdentity : identities)
            {
                UniValue idUni = oneIdentity.second.second.ToUniValue();
                idUni.pushKV("txout", CUTXORef(oneIdentity.second.first.first.txhash, oneIdentity.second.first.first.index).ToUniValue());
                retVal.push_back(idUni);
            }
        }
    }
    return retVal;
}

UniValue setidentitytrust(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "setidentitytrust '{\"clearall\": bool, \"setratings\":{\"id\":JSONRatingObject,...}, \"removeratings\":[\"id\",...], \"identitytrustmode\":<n>}'\n"
            "\n\n"

            "\nArguments\n"
            "{\n"
            "    \"clearall\": bool                             (bool, optional) clears all wallet identity trust lists before adding, removing, or trust mode operations\n"
            "    \"setratings\":{\"id\":JSONRatingObject,...}   (obj, optional) replaces ratings for specified IDs with those given\n"
            "    \"removeratings\":[\"id\",...]                 (strarray, optional) erases ratings for IDs specified\n"
            "    \"identitytrustmode\": <n>                     (number, optional) 0 = no restriction on sync, 1 = only sync to IDs rated approved, 2 = sync to all IDs but those on block list\n"
            "}\n"

            "\nResult:\n"
            "no return on success, else error\n"

            "\nExamples:\n"
            + HelpExampleCli("setidentitytrust", "\'{\"clearall\": bool, \"setratings\":{\"id\":JSONRatingObject,...}, \"removeratings\":[\"id\",...], \"identitytrustmode\":<n>}\'")
            + HelpExampleRpc("setidentitytrust", "\'{\"clearall\": bool, \"setratings\":{\"id\":JSONRatingObject,...}, \"removeratings\":[\"id\",...], \"identitytrustmode\":<n>}\'")
        );
    }

    bool clearAll = uni_get_bool(find_value(params[0], "clearall"));
    UniValue setRatings = find_value(params[0], "setratings");
    UniValue removeRatingArr = find_value(params[0], "removeratings");
    UniValue identityTrustMode = find_value(params[0], "identitytrustmode");

    LOCK2(cs_main, pwalletMain->cs_wallet);
    if (clearAll)
    {
        pwalletMain->ClearIdentityTrust();
    }

    // if we have ratings to set, do it
    if (setRatings.isObject())
    {
        auto keys = setRatings.getKeys();
        auto values = setRatings.getValues();
        for (int i = 0; i < keys.size(); i++)
        {
            auto &oneKey = keys[i];
            auto destKey = DecodeDestination(oneKey);
            CRating oneRating(values[i]);
            uint160 nameSpaceKey;
            uint160 vdxfKey;
            if (oneKey.empty() ||
                (destKey.which() != COptCCParams::ADDRTYPE_ID && ((vdxfKey = CVDXF::GetDataKey(oneKey, nameSpaceKey)).IsNull() || nameSpaceKey.IsNull())) ||
                !oneRating.IsValid())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "keys for setting identity trust ratings must be valid IDs and rating must be valid");
            }
            if (destKey.which() == COptCCParams::ADDRTYPE_ID)
            {
                vdxfKey = GetDestinationID(destKey);
            }
            pwalletMain->SetIdentityTrust(GetDestinationID(destKey), oneRating);
        }
    }

    // if we have ratings to set, do it
    if (removeRatingArr.isArray())
    {
        for (int i = 0; i < removeRatingArr.size(); i++)
        {
            auto oneKey = uni_get_str(removeRatingArr[i]);
            auto destKey = DecodeDestination(oneKey);
            uint160 nameSpaceKey;
            uint160 vdxfKey;
            if (oneKey.empty() ||
                (destKey.which() != COptCCParams::ADDRTYPE_ID && ((vdxfKey = CVDXF::GetDataKey(oneKey, nameSpaceKey)).IsNull() || nameSpaceKey.IsNull())))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "keys for removing identity trust ratings must be valid IDs and rating must be valid");
            }
            if (destKey.which() == COptCCParams::ADDRTYPE_ID)
            {
                vdxfKey = GetDestinationID(destKey);
            }
            pwalletMain->RemoveIdentityTrust(vdxfKey);
        }
    }

    return NullUniValue;
}

UniValue getidentitytrust(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getidentitytrust '[\"id\",...]'\n"
            "\n\n"

            "\nArguments\n"
            "\"[\"id\",...]\"                                       (strarray, optional) if specified, only returns rating values for specified IDs, otherwise all\n"

            "\nResult:\n"
            "{\n"
            "  \"setratings\":{\"id\":JSONRatingObject,...},        (jsonobj) an ID/ratings key/value object\n"
            "  \"identitytrustmode\":<n>                            (int) 0 = no restriction on sync, 1 = only sync to IDs rated approved, 2 = sync to all IDs but those on block list\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getidentitytrust", "\'[\"id\",...]\'")
            + HelpExampleRpc("getidentitytrust", "\'[\"id\",...]\'")
        );
    }

    UniValue retVal;
    UniValue setRatings;

    LOCK(pwalletMain->cs_wallet);
    auto identityTrustMap = pwalletMain->GetIdentityTrustMap();
    for (auto &oneEntry : identityTrustMap)
    {
        setRatings.pushKV(EncodeDestination(CIdentityID(oneEntry.first)), oneEntry.second.ToUniValue());
    }
    retVal.pushKV("setratings", setRatings);
    retVal.pushKV("identitytrustmode", pwalletMain->GetIdentityTrustMode());

    return retVal;
}

UniValue setcurrencytrust(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "setcurrencytrust '{\"clearall\": bool, \"setratings\":[{\"currencyid\":JSONRatingObject},...], \"removeratings\":[\"currencyid\",...], \"currencytrustmode\":<n>}'\n"
            "\n\n"

            "\nArguments\n"
            "{\n"
            "    \"clearall\": bool                             (bool, optional) clears all wallet currency trust lists before adding, removing, or trust mode operations\n"
            "    \"setratings\":[{\"currencyid\":JSONRatingObject},...] (objarray, optional) replaces ratings for specified currencies with those given\n"
            "    \"removeratings\":[\"currencyid\",...]                 (strarray, optional) erases ratings for currencies specified\n"
            "    \"currencytrustmode\": <n>                     (number, optional) 0 = spend/list all currencies, 1 = only spend/list those rated approved, 2 = spend/list all but those on block list\n"
            "}\n"

            "\nResult:\n"
            "no return on success, else error\n"

            "\nExamples:\n"
            + HelpExampleCli("setcurrencytrust", "\'{\"clearall\": bool, \"setratings\":[{\"currencyid\":JSONRatingObject},...], \"removeratings\":[\"currencyid\",...], \"currencytrustmode\":<n>}\'")
            + HelpExampleRpc("setcurrencytrust", "\'{\"clearall\": bool, \"setratings\":[{\"currencyid\":JSONRatingObject},...], \"removeratings\":[\"currencyid\",...], \"currencytrustmode\":<n>}\'")
        );
    }
    CheckPBaaSAPIsValid();

    bool clearAll = uni_get_bool(find_value(params[0], "clearall"));
    UniValue setRatings = find_value(params[0], "setratings");
    UniValue removeRatingArr = find_value(params[0], "removeratings");
    UniValue currencyTrustMode = find_value(params[0], "currencytrustmode");

    LOCK2(cs_main, pwalletMain->cs_wallet);
    if (clearAll)
    {
        pwalletMain->ClearCurrencyTrust();
    }

    // if we have ratings to set, do it
    if (setRatings.isObject())
    {
        auto keys = setRatings.getKeys();
        auto values = setRatings.getValues();
        for (int i = 0; i < keys.size(); i++)
        {
            auto &oneKey = keys[i];
            auto destKey = DecodeDestination(oneKey);
            CRating oneRating(values[i]);
            uint160 nameSpaceKey;
            uint160 vdxfKey;
            if (oneKey.empty() ||
                (destKey.which() != COptCCParams::ADDRTYPE_ID && ((vdxfKey = CVDXF::GetDataKey(oneKey, nameSpaceKey)).IsNull() || nameSpaceKey.IsNull())) ||
                !oneRating.IsValid())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "keys for setting currency trust ratings must be valid currency IDs and rating must be valid");
            }
            if (destKey.which() == COptCCParams::ADDRTYPE_ID)
            {
                vdxfKey = GetDestinationID(destKey);
            }
            pwalletMain->SetCurrencyTrust(GetDestinationID(destKey), oneRating);
        }
    }

    // if we have ratings to set, do it
    if (removeRatingArr.isArray())
    {
        for (int i = 0; i < removeRatingArr.size(); i++)
        {
            auto oneKey = uni_get_str(removeRatingArr[i]);
            auto destKey = DecodeDestination(oneKey);
            uint160 nameSpaceKey;
            uint160 vdxfKey;
            if (oneKey.empty() ||
                (destKey.which() != COptCCParams::ADDRTYPE_ID && ((vdxfKey = CVDXF::GetDataKey(oneKey, nameSpaceKey)).IsNull() || nameSpaceKey.IsNull())))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "keys for removing currency trust ratings must be valid currency IDs and rating must be valid");
            }
            if (destKey.which() == COptCCParams::ADDRTYPE_ID)
            {
                vdxfKey = GetDestinationID(destKey);
            }
            pwalletMain->RemoveCurrencyTrust(vdxfKey);
        }
    }

    return NullUniValue;
}

UniValue getcurrencytrust(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getcurrencytrust '[\"currencyid\",...]'\n"
            "\n\n"

            "\nArguments\n"
            "\"[\"currencyid\",...]\"                                       (strarray, optional) if specified, only returns rating values for specified currencies, otherwise all\n"

            "\nResult:\n"
            "{\n"
            "  \"setratings\":{\"id\":JSONRatingObject,...},        (jsonobj) an ID/ratings key/value object\n"
            "  \"currencytrustmode\":<n>                            (int) 0 = no restriction on sync, 1 = only sync to IDs rated approved, 2 = sync to all IDs but those on block list\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getcurrencytrust", "\'[\"currencyid\",...]\'")
            + HelpExampleRpc("getcurrencytrust", "\'[\"currencyid\",...]\'")
        );
    }
    CheckPBaaSAPIsValid();

    UniValue retVal;
    UniValue setRatings;

    LOCK(pwalletMain->cs_wallet);
    auto currencyTrustMap = pwalletMain->GetCurrencyTrustMap();
    for (auto &oneEntry : currencyTrustMap)
    {
        setRatings.pushKV(EncodeDestination(CIdentityID(oneEntry.first)), oneEntry.second.ToUniValue());
    }
    retVal.pushKV("setratings", setRatings);
    retVal.pushKV("currencytrustmode", pwalletMain->GetCurrencyTrustMode());

    return retVal;
}

UniValue addmergedblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 5)
    {
        throw runtime_error(
            "addmergedblock \"hexdata\" ( \"jsonparametersobject\" )\n"
            "\nAdds a fully prepared block and its header to the current merge mining queue of this daemon.\n"
            "Parameters determine the action to take if adding this block would exceed the available merge mining slots.\n"
            "Default action to take if adding would exceed available space is to replace the choice with the least ROI if this block provides more.\n"

            "\nArguments\n"
            "1. \"hexdata\"                     (string, required) the hex-encoded, complete, unsolved block data to add. nTime, and nSolution are replaced.\n"
            "2. \"name\"                        (string, required) chain name symbol\n"
            "3. \"rpchost\"                     (string, required) host address for RPC connection\n"
            "4. \"rpcport\"                     (int,    required) port address for RPC connection\n"
            "5. \"userpass\"                    (string, required) credentials for login to RPC\n"

            "\nResult:\n"
            "\"deserialize-invalid\" - block could not be deserialized and was rejected as invalid\n"
            "\"blocksfull\"          - block did not exceed others in estimated ROI, and there was no room for an additional merge mined block\n"
            "{\"nextblocktime\": n}  - block has invalid time and must be remade with time returned\n"

            "\nExamples:\n"
            + HelpExampleCli("addmergedblock", "\"hexdata\" \'{\"currencyid\" : \"hexstring\", \"rpchost\" : \"127.0.0.1\", \"rpcport\" : portnum}\'")
            + HelpExampleRpc("addmergedblock", "\"hexdata\" \'{\"currencyid\" : \"hexstring\", \"rpchost\" : \"127.0.0.1\", \"rpcport\" : portnum, \"estimatedroi\" : (verusreward/hashrate)}\'")
        );
    }

    CheckPBaaSAPIsValid();

    // check to see if we should replace any existing block or add a new one. if so, add this to the merge mine vector
    string name = params[1].get_str();
    if (name == "")
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "must provide chain name to merge mine");
    }

    string rpchost = params[2].get_str();
    int32_t rpcport = params[3].get_int();
    string rpcuserpass = params[4].get_str();

    if (rpchost == "" || rpcport == 0 || rpcuserpass == "")
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "must provide valid RPC connection parameters to merge mine");
    }

    CCurrencyDefinition chainDef;
    uint160 chainID = ValidateCurrencyName(name, true, &chainDef);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain for merge mining");
    }

    // confirm data from blockchain
    CRPCChainData chainData;
    if (ConnectedChains.GetChainInfo(chainID, chainData))
    {
        chainDef = chainData.chainDefinition;
    }

    if (!chainDef.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain not found");
    }

    CBlock blk;

    if (!DecodeHexBlk(blk, params[0].get_str()))
        return "deserialize-invalid";

    int64_t nextBlockTime = ConnectedChains.GetNextBlockTime(chainActive.LastTip());
    if (blk.nTime != nextBlockTime)
    {
        UniValue returnTime(UniValue::VOBJ);
        returnTime.pushKV("nextblocktime", nextBlockTime);
        return returnTime;
    }

    CPBaaSMergeMinedChainData blkData = CPBaaSMergeMinedChainData(chainDef, rpchost, rpcport, rpcuserpass, blk);
    return ConnectedChains.AddMergedBlock(blkData) ? NullUniValue : "blocksfull";
}

UniValue submitmergedblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "submitmergedblock \"hexdata\" ( \"jsonparametersobject\" )\n"
            "\nAttempts to submit one more more new blocks to one or more networks.\n"
            "Each merged block submission may be valid for Verus and/or PBaaS merge mined chains.\n"
            "The submitted block consists of a valid block for this chain, along with embedded headers of other PBaaS merge mined chains.\n"
            "If the hash for this header meets targets of other chains that have been added with 'addmergedblock', this API will\n"
            "submit those blocks to the specified URL endpoints with an RPC 'submitmergedblock' request."
            "\nAttempts to submit one more more new blocks to one or more networks.\n"

            "\nArguments\n"
            "1. \"hexdata\"    (string, required) the hex-encoded block data to submit\n"
            "\nResults:\n"
            "\"    { rejected: \"reject reason\" }\n"
            "\n  Submission to our chain and PBaaS chains\n"
            "\"    { blockhash: \"hex\", accepted: true, pbaas_submissions: { \"Quantum\":\"chainID_hex\", ... } }\n"
            "\n  Submission to only PBaaS chains\n"
            "\"    { blockhash: \"hex\", accepted: \"pbaas\", pbaas_submissions: { \"Quantum\":\"chainID_hex\", ... } }\n"
            "\nExamples:\n"
            + HelpExampleCli("submitmergedblock", "\"mydata\"")
            + HelpExampleRpc("submitmergedblock", "\"mydata\"")
        );

    CheckPBaaSAPIsValid();

    CBlock block;
    if (!DecodeHexBlk(block, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    uint256 hash = block.GetHash();
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex *pindex = mi->second;
            if (pindex)
            {
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                // Otherwise, we might only have the header - process the block before returning
                fBlockPresent = true;
            }
        }
    }

    CValidationState state;
    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    //printf("submitmergedblock, height=%d, coinbase sequence: %d, scriptSig: %s\n", chainActive.LastTip()->GetHeight()+1, block.vtx[0].vin[0].nSequence, block.vtx[0].vin[0].scriptSig.ToString().c_str());
    bool fAccepted = ProcessNewBlock(1, chainActive.LastTip()->GetHeight()+1, state, Params(), NULL, &block, true, NULL);
    UnregisterValidationInterface(&sc);
    UniValue result(UniValue::VOBJ);
    if (fBlockPresent)
    {
        if (fAccepted && !sc.found) {
            result.push_back(Pair("rejected", "duplicate-inconclusive"));
            return result;
        }
        result.push_back(Pair("rejected", "duplicate"));
        return result;
    }
    if (fAccepted)
    {
        if (!sc.found) {
            result.push_back(Pair("rejected", "inconclusive"));
            return result;
        }
        state = sc.state;
    }

    UniValue rejected = BIP22ValidationResult(state);
    if (rejected.isNull()) {
        // queue for submission to pbaas chains being merge mined
        ConnectedChains.QueueNewBlockHeader(block);

        // add block hash to response
        result.push_back(Pair("blockhash", block.GetBlockHeader().GetHash().GetHex()));

        // check target, we may have only submitted to pbaas chains
        arith_uint256 target(0); target.SetCompact(block.nBits);
        arith_uint256 block_hash = UintToArith256(block.GetBlockHeader().GetHash());
        if (block_hash > target) {
            // only submitted to pbaas merge mined chains
            result.push_back(Pair("accepted", "pbaas"));
        } else {
            // accepted on primary chain and pbaas chains
            result.push_back(Pair("accepted", true));
        }

        // generate submissions list of pbaas chains being merge mined
        UniValue chains(UniValue::VOBJ);
        std::vector<CCurrencyDefinition> mergeMinedChains =  ConnectedChains.GetMergeMinedChains();
        for (auto &chain : mergeMinedChains)
        {
            chains.push_back(Pair(chain.name, chain.GetID().GetHex()));
        }
        result.push_back(Pair("pbaas_submissions", chains));

    } else {
        result.push_back(Pair("rejected", rejected));
    }

    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "identity",     "registernamecommitment",       &registernamecommitment, true  },
    { "identity",     "registeridentity",             &registeridentity,       true  },
    { "identity",     "updateidentity",               &updateidentity,         true  },
    { "identity",     "revokeidentity",               &revokeidentity,         true  },
    { "identity",     "setidentitytimelock",          &setidentitytimelock,    true  },
    { "identity",     "recoveridentity",              &recoveridentity,        true  },
    { "identity",     "getidentity",                  &getidentity,            true  },
    { "identity",     "getidentityhistory",           &getidentityhistory,     true  },
    { "identity",     "getidentitycontent",           &getidentitycontent,     true  },
    { "identity",     "listidentities",               &listidentities,         true  },
    { "identity",     "getidentitieswithaddress",     &getidentitieswithaddress, true  },
    { "identity",     "getidentitieswithrevocation",  &getidentitieswithrevocation, true  },
    { "identity",     "getidentitieswithrecovery",    &getidentitieswithrecovery, true  },
    { "identity",     "setidentitytrust",             &setidentitytrust,       true  },
    { "identity",     "getidentitytrust",             &getidentitytrust,       true  },
    { "multichain",   "setcurrencytrust",             &setcurrencytrust,       true  },
    { "multichain",   "getcurrencytrust",             &getcurrencytrust,       true  },
    { "multichain",   "estimateconversion",           &estimateconversion,     true  },
    { "marketplace",  "makeoffer",                    &makeoffer,              true  },
    { "marketplace",  "takeoffer",                    &takeoffer,              true  },
    { "marketplace",  "getoffers",                    &getoffers,              true  },
    { "marketplace",  "listopenoffers",               &listopenoffers,         true  },
    { "marketplace",  "closeoffers",                  &closeoffers,            true  },
    { "multichain",   "definecurrency",               &definecurrency,         true  },
    { "multichain",   "listcurrencies",               &listcurrencies,         true  },
    { "multichain",   "getcurrencyconverters",        &getcurrencyconverters,  true  },
    { "multichain",   "getcurrency",                  &getcurrency,            true  },
    { "multichain",   "getreservedeposits",           &getreservedeposits,     true  },
    { "multichain",   "getnotarizationdata",          &getnotarizationdata,    true  },
    { "multichain",   "getlaunchinfo",                &getlaunchinfo,          true  },
    { "multichain",   "getbestproofroot",             &getbestproofroot,       true  },
    { "multichain",   "submitacceptednotarization",   &submitacceptednotarization, true },
    { "multichain",   "submitchallenges",             &submitchallenges,       true },
    { "multichain",   "getnotarizationproofs",        &getnotarizationproofs,  true },
    { "multichain",   "submitimports",                &submitimports,          true },
    { "multichain",   "getinitialcurrencystate",      &getinitialcurrencystate, true  },
    { "multichain",   "getcurrencystate",             &getcurrencystate,       true  },
    { "multichain",   "getsaplingtree",               &getsaplingtree,         true  },
    { "multichain",   "sendcurrency",                 &sendcurrency,           true  },
    { "multichain",   "getpendingtransfers",          &getpendingtransfers,    true  },
    { "multichain",   "getexports",                   &getexports,             true  },
    { "multichain",   "getlastimportfrom",            &getlastimportfrom,      true  },
    { "multichain",   "getimports",                   &getimports,             true  },
    { "multichain",   "refundfailedlaunch",           &refundfailedlaunch,     true  },
    { "multichain",   "refundfailedlaunch",           &refundfailedlaunch,     true  },
    { "multichain",   "addmergedblock",               &addmergedblock,         true  },
    { "multichain",   "submitmergedblock",            &submitmergedblock,      true  }
};

void RegisterPBaaSRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
