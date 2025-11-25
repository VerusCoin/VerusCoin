// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2021 Verus Coin Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "miner.h"
#ifdef ENABLE_MINING
#include "pow/tromp/equi_miner.h"
#endif

#include "amount.h"
#include "chainparams.h"
#include "cc/StakeGuard.h"
#include "consensus/consensus.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#ifdef ENABLE_MINING
#include "crypto/equihash.h"
#include "crypto/verus_hash.h"
#endif
#include "hash.h"
#include "key_io.h"
#include "main.h"
#include "metrics.h"
#include "net.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "random.h"
#include "timedata.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"

#include "zcash/Address.hpp"
#include "transaction_builder.h"

#include "sodium.h"

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#ifdef ENABLE_MINING
#include <functional>
#endif
#include <mutex>

#include "pbaas/pbaas.h"
#include "pbaas/notarization.h"
#include "pbaas/identity.h"
#include "rpc/pbaasrpc.h"
#include "transaction_builder.h"

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.
// The COrphan class keeps track of these 'temporary orphans' while
// CreateBlock is figuring out which transactions to include.
//
class COrphan
{
public:
    const CTransaction* ptx;
    set<uint256> setDependsOn;
    CFeeRate feeRate;
    double dPriority;

    COrphan(const CTransaction* ptxIn) : ptx(ptxIn), feeRate(0), dPriority(0)
    {
    }
};

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

// We want to sort transactions by priority and fee rate, so:
typedef boost::tuple<double, CFeeRate, const CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;

public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }

    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

void UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    pblock->nTime = ConnectedChains.GetNextBlockTime(pindexPrev);

    // Updating time can change work required on testnet as well as the block MMR
    if (consensusParams.nPowAllowMinDifficultyBlocksAfterHeight != boost::none) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }
}

#include "komodo_defs.h"

extern CCriticalSection cs_metrics;
extern int32_t KOMODO_MININGTHREADS,KOMODO_LONGESTCHAIN,IS_KOMODO_NOTARY,USE_EXTERNAL_PUBKEY,KOMODO_CHOSEN_ONE,ASSETCHAIN_INIT,KOMODO_INITDONE,KOMODO_ON_DEMAND,KOMODO_INITDONE,KOMODO_PASSPORT_INITDONE;
extern uint64_t ASSETCHAINS_COMMISSION, ASSETCHAINS_STAKED;
extern bool VERUS_MINTBLOCKS;
extern uint64_t ASSETCHAINS_REWARD[ASSETCHAINS_MAX_ERAS], ASSETCHAINS_TIMELOCKGTE, ASSETCHAINS_NONCEMASK[];
extern const char *ASSETCHAINS_ALGORITHMS[];
extern int32_t VERUS_MIN_STAKEAGE, ASSETCHAINS_EQUIHASH, ASSETCHAINS_VERUSHASH, ASSETCHAINS_LASTERA, ASSETCHAINS_LWMAPOS, ASSETCHAINS_NONCESHIFT[], ASSETCHAINS_HASHESPERROUND[];
extern uint32_t ASSETCHAINS_ALGO;
extern char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN];
extern uint160 ASSETCHAINS_CHAINID;
extern uint160 VERUS_CHAINID;
extern std::string VERUS_CHAINNAME;
extern int32_t PBAAS_STARTBLOCK, PBAAS_ENDBLOCK;
extern string PBAAS_HOST, PBAAS_USERPASS, ASSETCHAINS_RPCHOST, ASSETCHAINS_RPCCREDENTIALS;;
extern int32_t PBAAS_PORT;
extern uint16_t ASSETCHAINS_RPCPORT;
extern std::string NOTARY_PUBKEY,ASSETCHAINS_OVERRIDE_PUBKEY;
extern uint8_t NOTARY_PUBKEY33[33],ASSETCHAINS_OVERRIDE_PUBKEY33[33];
extern CCriticalSection smartTransactionCS;

uint32_t Mining_start, Mining_height;
int32_t My_notaryid = -1;

void vcalc_sha256(char deprecated[(256 >> 3) * 2 + 1],uint8_t hash[256 >> 3],uint8_t *src,int32_t len);
int32_t komodo_chosennotary(int32_t *notaryidp,int32_t height,uint8_t *pubkey33,uint32_t timestamp);
int32_t komodo_pax_opreturn(int32_t height,uint8_t *opret,int32_t maxsize);
int32_t komodo_baseid(char *origbase);
int32_t komodo_validate_interest(const CTransaction &tx,int32_t txheight,uint32_t nTime,int32_t dispflag);
uint64_t komodo_commission(const CBlock *block);
int32_t komodo_staked(CMutableTransaction &txNew,uint32_t nBits,uint32_t *blocktimep,uint32_t *txtimep,uint256 *utxotxidp,int32_t *utxovoutp,uint64_t *utxovaluep,uint8_t *utxosig);
int32_t verus_staked(CBlock *pBlock, CMutableTransaction &txNew, uint32_t &nBits, arith_uint256 &hashResult, std::vector<unsigned char> &utxosig, CTxDestination &rewardDest);
int32_t komodo_notaryvin(CMutableTransaction &txNew,uint8_t *notarypub33);
UniValue getminingdistribution(const UniValue& params, bool fHelp);

// for PoW: don't update MMR if the merkle root, prev MMR && time haven't changed
LRUCache<std::tuple<uint256, uint256, uint32_t>, uint256> powBlockMMRLRU(200);
// for PoS: don't update MMR if the merkle root, prev MMR && entropy hash component haven't changed
LRUCache<std::tuple<uint256, uint256, uint256>, uint256> posBlockMMRLRU(200);
void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int &nExtraNonce, bool buildMerkle, uint32_t *pSaveBits)
{
    uint32_t nHeight = pindexPrev->GetHeight() + 1;
    bool isPBaaS = CConstVerusSolutionVector::GetVersionByHeight(nHeight) >= CActivationHeight::ACTIVATE_PBAAS;
    bool isPoS = pblock->IsVerusPOSBlock();
    bool posSourceInfo = isPBaaS;

    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;

    if (pSaveBits)
    {
        *pSaveBits = pblock->nBits;
    }

    int solutionVersion = CConstVerusSolutionVector::activationHeight.ActiveVersion(nHeight);

    if (solutionVersion >= CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS_HEADER)
    {
        UpdateTime(pblock, Params().GetConsensus(), pindexPrev);

        uint256 entropyHash;
        if (posSourceInfo && pblock->IsVerusPOSBlock())
        {
            LOCK(cs_main);
            // POS entropy hash doesn't depend on block hash
            entropyHash = pblock->GetVerusEntropyHashComponent(pindexPrev->GetHeight() + 1);
        }

        if (!pblock->IsVerusPOSBlock())
        {
            if (isPBaaS)
            {
                // set this first, even though it may be redundant below
                pblock->AddUpdatePBaaSHeader();

                uint8_t dummy;
                // clear extra data to allow adding more PBaaS headers
                pblock->SetExtraData(&dummy, 0);

                // combine blocks and set compact difficulty if necessary
                uint32_t savebits;
                if ((savebits = ConnectedChains.CombineBlocks(*pblock)) && pSaveBits)
                {
                    arith_uint256 ours, merged;
                    ours.SetCompact(pblock->nBits);
                    merged.SetCompact(savebits);
                    if (merged > ours)
                    {
                        *pSaveBits = savebits;
                    }
                }

                // in PBaaS, extra nonce is kept in the header, not in the coinbase any longer
                // this allows instant spend transactions to use coinbase funds for
                // inputs by ensuring that once final, the coinbase transaction hash
                // will not continue to change
                CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
                s << nExtraNonce;
                std::vector<unsigned char> vENonce(s.begin(), s.end());
                assert(pblock->ExtraDataLen() >= vENonce.size());
                pblock->SetExtraData(vENonce.data(), vENonce.size());
            }
            else
            {
                // finalize input of coinbase with extranonce
                CMutableTransaction txcb(pblock->vtx[0]);
                txcb.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
                assert(txcb.vin[0].scriptSig.size() <= 100);
                pblock->vtx[0] = txcb;
            }
        }

        if (buildMerkle)
        {
            uint32_t mmrSize = posSourceInfo ? pindexPrev->GetHeight() + 1 : pindexPrev->GetHeight();
            pblock->hashMerkleRoot = pblock->BuildMerkleTree();
            uint256 prevMMRRoot = ChainMerkleMountainView(chainActive.GetMMR(), mmrSize).GetRoot();
            pblock->SetPrevMMRRoot(prevMMRRoot);

            bool updateBlockRoots = true;
            {
                LOCK(ConnectedChains.cs_mergemining);
                uint256 cachedBlockMMRRoot;
                if ((isPoS &&
                     posBlockMMRLRU.Get({pblock->hashMerkleRoot, prevMMRRoot, entropyHash}, cachedBlockMMRRoot) &&
                     cachedBlockMMRRoot == pblock->GetBlockMMRRoot()) ||
                    (!isPoS &&
                     powBlockMMRLRU.Get({pblock->hashMerkleRoot, prevMMRRoot, pblock->nTime}, cachedBlockMMRRoot) &&
                     cachedBlockMMRRoot == pblock->GetBlockMMRRoot()))
                {
                    updateBlockRoots = false;
                }
            }

            if (updateBlockRoots)
            {
                if (isPoS)
                {
                    LOCK(cs_main);
                    CTransaction tx;
                    uint256 txBlockHash;
                    CBlockIndex *pIndexSource;
                    CBlock sourceBlock;
                    if (myGetTransaction(pblock->vtx.back().vin[0].prevout.hash, tx, txBlockHash, false) &&
                        mapBlockIndex.count(txBlockHash) &&
                        ReadBlockFromDisk(sourceBlock, mapBlockIndex[txBlockHash], Params().GetConsensus()))
                    {
                        ChainMerkleMountainView mmv = chainActive.GetMMV();
                        mmv.resize(nHeight);                                 // we want it pointing right before us, nHeight is our new height

                        std::vector<unsigned char> extraSolutionData = CreatePoSBlockProof(mmv, *pblock, tx, pblock->vtx.back().vin[0].prevout.n, mapBlockIndex[txBlockHash]->GetHeight(), nHeight);
                        CVerusSolutionVector(pblock->nSolution).ResizeExtraData(extraSolutionData.size());
                        pblock->SetExtraData(extraSolutionData.data(), extraSolutionData.size());
                    }
                }

                BlockMMRange mmRange(pblock->BuildBlockMMRTree(entropyHash));
                BlockMMView mmView(mmRange);
                uint256 blockMMRRoot = mmView.GetRoot();
                pblock->SetBlockMMRRoot(blockMMRRoot);
                {
                    LOCK(ConnectedChains.cs_mergemining);
                    if (isPoS)
                    {
                        posBlockMMRLRU.Put({pblock->hashMerkleRoot, pblock->GetPrevMMRRoot(), entropyHash}, blockMMRRoot);
                    }
                    else
                    {
                        powBlockMMRLRU.Get({pblock->hashMerkleRoot, pblock->GetPrevMMRRoot(), pblock->nTime}, blockMMRRoot);
                    }
                }
            }
        }
        pblock->AddUpdatePBaaSHeader();
    }
    else
    {
        // finalize input of coinbase
        CMutableTransaction txcb(pblock->vtx[0]);
        txcb.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
        assert(txcb.vin[0].scriptSig.size() <= 100);
        pblock->vtx[0] = txcb;
        if (buildMerkle)
        {
            pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        }
        UpdateTime(pblock, Params().GetConsensus(), pindexPrev);
    }
}

extern CWallet *pwalletMain;

CPubKey GetSolutionPubKey(const std::vector<std::vector<unsigned char>> &vSolutions, txnouttype txType)
{
    CPubKey pk;

    if (txType == TX_PUBKEY)
    {
        pk = CPubKey(vSolutions[0]);
    }
    else if(txType == TX_PUBKEYHASH)
    {
        // we need to have this in our wallet to get the public key
        LOCK(pwalletMain->cs_wallet);
        pwalletMain->GetPubKey(CKeyID(uint160(vSolutions[0])), pk);
    }
    else if (txType == TX_CRYPTOCONDITION)
    {
        if (vSolutions[0].size() == 33)
        {
            pk = CPubKey(vSolutions[0]);
        }
        else if (vSolutions[0].size() == 34 && vSolutions[0][0] == COptCCParams::ADDRTYPE_PK)
        {
            pk = CPubKey(std::vector<unsigned char>(vSolutions[0].begin() + 1, vSolutions[0].end()));
        }
        else if (vSolutions[0].size() == 20)
        {
            LOCK(pwalletMain->cs_wallet);
            pwalletMain->GetPubKey(CKeyID(uint160(vSolutions[0])), pk);
        }
        else if (vSolutions[0].size() == 21 && vSolutions[0][0] == COptCCParams::ADDRTYPE_ID)
        {
            // destination is an identity, see if we can get its first public key
            std::pair<CIdentityMapKey, CIdentityMapValue> identity;

            if (pwalletMain->GetIdentity(CIdentityID(uint160(std::vector<unsigned char>(vSolutions[0].begin() + 1, vSolutions[0].end()))), identity) &&
                identity.second.IsValidUnrevoked() &&
                identity.second.primaryAddresses.size())
            {
                CPubKey pkTmp = boost::apply_visitor<GetPubKeyForPubKey>(GetPubKeyForPubKey(), identity.second.primaryAddresses[0]);
                if (pkTmp.IsValid())
                {
                    pk = pkTmp;
                }
                else
                {
                    LOCK(pwalletMain->cs_wallet);
                    pwalletMain->GetPubKey(CKeyID(GetDestinationID(identity.second.primaryAddresses[0])), pk);
                }
            }
        }
    }
    return pk;
}

CPubKey GetScriptPublicKey(const CScript &scriptPubKey)
{
    txnouttype typeRet;
    std::vector<std::vector<unsigned char>> vSolutions;
    if (Solver(scriptPubKey, typeRet, vSolutions))
    {
        return GetSolutionPubKey(vSolutions, typeRet);
    }
    return CPubKey();
}

// call a chain that we consider a notary chain, meaning we call its daemon, not the other way around,
// retrieve new exports that we have not imported, and process them. Also, send any exports that are now
// provable with the available notarization on the specified chain.
void ProcessNewImports(const uint160 &sourceChainID, CPBaaSNotarization &lastConfirmed, CUTXORef &lastConfirmedUTXO, uint32_t nHeight)
{
    if (CConstVerusSolutionVector::GetVersionByHeight(nHeight) < CActivationHeight::ACTIVATE_PBAAS ||
        CConstVerusSolutionVector::activationHeight.IsActivationHeight(CActivationHeight::ACTIVATE_PBAAS, nHeight))
    {
        return;
    }

    uint32_t consensusBranchId = CurrentEpochBranchId(nHeight, Params().GetConsensus());

    // get any pending imports from the source chain. if the source chain is this chain, we don't need notarization
    CCurrencyDefinition thisChain = ConnectedChains.ThisChain();
    uint160 thisChainID = thisChain.GetID();
    bool isSameChain = thisChainID == sourceChainID;

    CCurrencyDefinition sourceChain;
    CChainNotarizationData cnd;

    CTransaction lastImportTx;

    // we need to find the last unspent import transaction
    std::vector<CAddressUnspentDbEntry> unspentOutputs;

    bool processIndex = false;

    {
        LOCK(cs_main);
        sourceChain = ConnectedChains.GetCachedCurrency(sourceChainID);
        if (!sourceChain.IsValid())
        {
            printf("Unrecognized source chain %s\n", EncodeDestination(CIdentityID(sourceChainID)).c_str());
            return;
        }

        if (!(GetNotarizationData(sourceChainID, cnd) && cnd.IsConfirmed()))
        {
            printf("Cannot get notarization data for currency %s\n", sourceChain.name.c_str());
            return;
        }

        lastConfirmedUTXO = cnd.vtx[cnd.lastConfirmed].first;
        lastConfirmed = cnd.vtx[cnd.lastConfirmed].second;

        processIndex = (!isSameChain &&
            lastConfirmed.proofRoots.count(sourceChainID) &&
            GetAddressUnspent(CKeyID(CCrossChainRPCData::GetConditionID(sourceChainID, CCrossChainImport::CurrencySystemImportKey())), CScript::P2IDX, unspentOutputs));

    }

    bool found = false;
    CAddressUnspentDbEntry foundEntry;
    CCrossChainImport lastCCI;
    std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> exports;

    if (processIndex)
    {
        // if one spends the prior one, get the one that is not spent
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

        if (found &&
            lastCCI.sourceSystemHeight < lastConfirmed.notarizationHeight)
        {
            UniValue params(UniValue::VARR);

            params.push_back(EncodeDestination(CIdentityID(thisChainID)));
            params.push_back((int64_t)lastCCI.sourceSystemHeight);
            params.push_back((int64_t)lastConfirmed.proofRoots[sourceChainID].rootHeight);

            UniValue result = NullUniValue;
            try
            {
                if (sourceChainID == thisChain.GetID())
                {
                    UniValue getexports(const UniValue& params, bool fHelp);
                    result = getexports(params, false);
                }
                else if (ConnectedChains.IsNotaryAvailable())
                {
                    UniValue fullResult = RPCCallRoot("getexports", params);
                    result = find_value(fullResult, "result");
                }
            } catch (exception e)
            {
                LogPrint("notarization", "Could not get latest export from external chain %s for %s\n", EncodeDestination(CIdentityID(sourceChainID)).c_str(), uni_get_str(params[0]).c_str());
                return;
            }

            // now, we should have a list of exports to import in order
            if (!result.isArray() || !result.size())
            {
                LogPrint("notarization", "Could not get latest export from external chain %s for %s\n", EncodeDestination(CIdentityID(sourceChainID)).c_str(), uni_get_str(params[0]).c_str());
                return;
            }
            bool foundCurrent = false;
            for (int i = 0; i < result.size(); i++)
            {
                uint256 exportTxId = uint256S(uni_get_str(find_value(result[i], "txid")));
                if (!foundCurrent && !lastCCI.exportTxId.IsNull())
                {
                    // when we find our export, take the next
                    if (exportTxId == lastCCI.exportTxId)
                    {
                        foundCurrent = true;
                    }
                    continue;
                }

                // create one import at a time
                uint32_t notarizationHeight = uni_get_int64(find_value(result[i], "height"));
                int32_t exportTxOutNum = uni_get_int(find_value(result[i], "txoutnum"));
                CPartialTransactionProof txProof = CPartialTransactionProof(find_value(result[i], "partialtransactionproof"));
                UniValue transferArrUni = find_value(result[i], "transfers");
                if (!notarizationHeight ||
                    exportTxId.IsNull() ||
                    exportTxOutNum == -1 ||
                    !transferArrUni.isArray())
                {
                    printf("Invalid export from %s\n", uni_get_str(params[0]).c_str());
                    return;
                }

                CTransaction exportTx;
                uint256 blkHash;
                auto proofRootIt = lastConfirmed.proofRoots.find(sourceChainID);
                if (!isSameChain &&
                    !(txProof.IsValid() &&
                        !txProof.GetPartialTransaction(exportTx).IsNull() &&
                        txProof.TransactionHash() == exportTxId &&
                        proofRootIt != lastConfirmed.proofRoots.end() &&
                        proofRootIt->second.stateRoot == txProof.CheckPartialTransaction(exportTx) &&
                        exportTx.vout.size() > exportTxOutNum))
                {
                    /* printf("%s: proofRoot: %s, checkPartialRoot: %s, proofheight: %u, ischainproof: %s, blockhash: %s\n",
                        __func__,
                        proofRootIt->second.ToUniValue().write(1,2).c_str(),
                        txProof.CheckPartialTransaction(exportTx).GetHex().c_str(),
                        txProof.GetProofHeight(),
                        txProof.IsChainProof() ? "true" : "false",
                        txProof.GetBlockHash().GetHex().c_str()); */
                    printf("Invalid export for %s\n", uni_get_str(params[0]).c_str());
                    return;
                }
                {
                    LOCK2(cs_main, mempool.cs);
                    if (isSameChain &&
                        !(myGetTransaction(exportTxId, exportTx, blkHash) &&
                            exportTx.vout.size() > exportTxOutNum))
                    {
                        printf("Invalid export msg2 from %s\n", uni_get_str(params[0]).c_str());
                        return;
                    }
                }
                if (!foundCurrent)
                {
                    CCrossChainExport ccx(exportTx.vout[exportTxOutNum].scriptPubKey);
                    if (!ccx.IsValid())
                    {
                        printf("Invalid export msg3 from %s\n", uni_get_str(params[0]).c_str());
                        return;
                    }
                    if (ccx.IsChainDefinition())
                    {
                        continue;
                    }
                }
                std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>> oneExport =
                    std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[exportTxOutNum].scriptPubKey,
                                                    exportTx.vout[exportTxOutNum].nValue,
                                                    CTxIn(exportTxId, exportTxOutNum)),
                                                    txProof),
                                    std::vector<CReserveTransfer>());
                for (int j = 0; j < transferArrUni.size(); j++)
                {
                    //printf("%s: onetransfer: %s\n", __func__, transferArrUni[j].write(1,2).c_str());
                    oneExport.second.push_back(CReserveTransfer(transferArrUni[j]));
                    if (!oneExport.second.back().IsValid())
                    {
                        printf("Invalid reserve transfers in export from %s\n", sourceChain.name.c_str());
                        return;
                    }
                }
                exports.push_back(oneExport);
            }
        }
        std::map<uint160, std::vector<std::pair<int, CTransaction>>> newImports;
        ConnectedChains.CreateLatestImports(sourceChain, lastConfirmedUTXO, exports, newImports);
    }
    else if (isSameChain)
    {
        ConnectedChains.ProcessLocalImports();
        return;
    }
    else
    {
        LogPrint("crosschain", "Could not get prior import for currency %s\n", sourceChain.name.c_str());
        return;
    }
}

bool CheckNotaryConnection(const CRPCChainData &notarySystem)
{
    // ensure we have connection parameters, or we fail
    if (notarySystem.rpcHost == "" || notarySystem.rpcUserPass == "" || !notarySystem.rpcPort)
    {
        return false;
    }
    return true;
}

bool CallNotary(const CRPCChainData &notarySystem, std::string command, const UniValue &params, UniValue &result, UniValue &error)
{
    // ensure we have connection parameters, or we fail
    if (!CheckNotaryConnection(notarySystem))
    {
        return false;
    }

    try
    {
        UniValue rpcResult = RPCCall(command, params, notarySystem.rpcUserPass, notarySystem.rpcPort, notarySystem.rpcHost);
        result = find_value(rpcResult, "result");
        error = find_value(rpcResult, "error");
    } catch (std::exception e)
    {
        error = strprintf("Failed to connect to %s chain, error: %s\n", notarySystem.chainDefinition.name.c_str(), e.what());
    }
    return error.isNull();
}

// get initial currency state from the notary system specified
bool GetBlockOneLaunchNotarization(const CRPCChainData &notarySystem,
                                   const uint160 &currencyID,
                                   CCurrencyDefinition &curDef,
                                   CPBaaSNotarization &launchNotarization,
                                   CPBaaSNotarization &notaryNotarization,
                                   std::pair<CUTXORef, CPartialTransactionProof> &notarizationOutputProof,
                                   std::pair<CUTXORef, CPartialTransactionProof> &exportOutputProof,
                                   std::vector<CReserveTransfer> &exportTransfers)
{
    UniValue result, error;
    bool retVal = false;

    uint160 notarySystemID = notarySystem.GetID();

    UniValue params(UniValue::VARR);
    params.push_back(EncodeDestination(CIdentityID(currencyID)));

    // VRSC and VRSCTEST do not start with a notary chain
    if (notarySystemID == ASSETCHAINS_CHAINID || (!IsVerusActive() && ConnectedChains.IsNotaryAvailable()))
    {
        // we are starting a PBaaS chain. We only assume that our chain definition and the first notary chain, if there is one, are setup
        // in ConnectedChains. All other currencies and identities necessary to start have not been populated and must be in block 1 by
        // getting the information from the notary chain
        bool notaryCallResult = false;
        if (notarySystemID == ASSETCHAINS_CHAINID)
        {
            UniValue getlaunchinfo(const UniValue& params, bool fHelp);

            try
            {
                result = getlaunchinfo(params, false);
                notaryCallResult = result.isObject();
            } catch (std::exception e)
            {
                error = strprintf("Failed to connect to %s chain, error: %s\n", notarySystem.chainDefinition.name.c_str(), e.what());
            }
            notaryCallResult = error.isNull();
        }
        else
        {
            notaryCallResult = CallNotary(notarySystem, "getlaunchinfo", params, result, error);
        }
        if (notaryCallResult)
        {
            CCurrencyDefinition currency(find_value(result, "currencydefinition"));
            CPBaaSNotarization notarization(find_value(result, "launchnotarization"));
            notaryNotarization = CPBaaSNotarization(find_value(result, "notarynotarization"));
            CPartialTransactionProof notarizationProof(find_value(result, "notarizationproof"));
            CUTXORef notarizationUtxo(uint256S(uni_get_str(find_value(result, "notarizationtxid"))), uni_get_int(find_value(result, "notarizationvoutnum")));

            CPartialTransactionProof exportProof(find_value(result, "exportproof"));
            UniValue exportTransfersUni = find_value(result, "exportransfers");

            bool reject = false;
            if (exportTransfersUni.isArray() && exportTransfersUni.size())
            {
                for (int i = 0; i < exportTransfersUni.size(); i++)
                {
                    CReserveTransfer oneTransfer(exportTransfersUni[i]);
                    if (!oneTransfer.IsValid())
                    {
                        reject = true;
                    }
                    else
                    {
                        exportTransfers.push_back(oneTransfer);
                    }
                }
            }
            CUTXORef exportUtxo(uint256S(uni_get_str(find_value(result, "exporttxid"))), uni_get_int(find_value(result, "exportvoutnum")));

            if (reject ||
                !currency.IsValid() ||
                !notarization.IsValid() ||
                !notarizationProof.IsValid() ||
                !notaryNotarization.IsValid())
            {
                if (LogAcceptCategory("notarization"))
                {
                    LogPrintf("%s: invalid launch notarization for currency %s\nerror: %s\ncurrencydefinition: %s\nnotarization: %s\ntransactionproof: %s\n",
                        __func__,
                        error.write().c_str(),
                        EncodeDestination(CIdentityID(currencyID)).c_str(),
                        currency.ToUniValue().write(1,2).c_str(),
                        notarization.ToUniValue().write(1,2).c_str(),
                        notarizationProof.ToUniValue().write(1,2).c_str());
                    printf("%s: invalid launch notarization for currency %s\nerror: %s\ncurrencydefinition: %s\nnotarization: %s\ntransactionproof: %s\n",
                        __func__,
                        error.write().c_str(),
                        EncodeDestination(CIdentityID(currencyID)).c_str(),
                        currency.ToUniValue().write(1,2).c_str(),
                        notarization.ToUniValue().write(1,2).c_str(),
                        notarizationProof.ToUniValue().write(1,2).c_str());
                }
                else
                {
                    LogPrintf("%s: invalid launch notarization for currency %s\n", __func__, EncodeDestination(CIdentityID(currencyID)).c_str());
                }
            }
            else
            {
                //printf("%s: proofroot: %s\n", __func__, latestProofRoot.ToUniValue().write(1,2).c_str());
                curDef = currency;
                launchNotarization = notarization;
                if (notaryNotarization.proofRoots.size() && !notaryNotarization.proofRoots.count(curDef.systemID))
                {
                    notaryNotarization.proofRoots[curDef.systemID] = CProofRoot::GetProofRoot(0);
                    notaryNotarization.proofRoots[curDef.systemID].systemID = curDef.systemID; // all share block 0
                }
                notarizationOutputProof = std::make_pair(notarizationUtxo, notarizationProof);
                exportOutputProof = std::make_pair(exportUtxo, exportProof);
                retVal = true;
            }
        }
        else
        {
            LogPrintf("%s: error calling notary chain %s\n", __func__, error.write(1,2).c_str());
            printf("%s: error calling notary chain %s\n", __func__, error.write(1,2).c_str());
        }
    }
    return retVal;
}

bool DecodeOneExport(const UniValue obj, CCrossChainExport &ccx,
                     std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>> &oneExport)
{
    uint32_t exportHeight = uni_get_int64(find_value(obj, "height"));
    uint256 txId = uint256S(uni_get_str(find_value(obj, "txid")));
    uint32_t outNum = uni_get_int(find_value(obj, "txoutnum"));
    ccx = CCrossChainExport(find_value(obj, "exportinfo"));
    if (!ccx.IsValid())
    {
        LogPrintf("%s: invalid launch export from notary chain\n", __func__);
        printf("%s: invalid launch export from notary chain\n", __func__);
        return false;
    }
    CPartialTransactionProof partialTxProof(find_value(obj, "partialtransactionproof"));
    CTransaction exportTx;
    COptCCParams p;
    CScript outputScript;
    CAmount outputValue;

    if (!partialTxProof.IsValid() ||
        partialTxProof.GetPartialTransaction(exportTx).IsNull() ||
        partialTxProof.TransactionHash() != txId ||
        exportTx.vout.size() <= outNum ||
        !exportTx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) ||
        !p.IsValid() ||
        p.evalCode != EVAL_CROSSCHAIN_EXPORT ||
        (outputValue = exportTx.vout[outNum].nValue) == -1)
    {
        //UniValue jsonTxOut(UniValue::VOBJ);
        //TxToUniv(exportTx, uint256(), jsonTxOut);
        //printf("%s: proofTxRoot:%s\npartialTx: %s\n", __func__,
        //                                            partialTxProof.GetPartialTransaction(exportTx).GetHex().c_str(),
        //                                            jsonTxOut.write(1,2).c_str());
        LogPrintf("%s: invalid partial transaction proof from notary chain\n", __func__);
        printf("%s: invalid partial transaction proof from notary chain\n", __func__);
        return false;
    }

    UniValue transfers = find_value(obj, "transfers");
    std::vector<CReserveTransfer> reserveTransfers;
    if (transfers.isArray() && transfers.size())
    {
        for (int i = 0; i < transfers.size(); i++)
        {
            CReserveTransfer rt(transfers[i]);
            if (rt.IsValid())
            {
                reserveTransfers.push_back(rt);
            }
        }
    }

    oneExport.first.first = CInputDescriptor(outputScript, outputValue, CTxIn(txId, outNum));
    oneExport.first.second = partialTxProof;
    oneExport.second = reserveTransfers;
    return true;
}

// get initial currency state from the notary system specified
bool GetBlockOneImports(const CRPCChainData &notarySystem, const CPBaaSNotarization &launchNotarization, std::map<uint160, std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>>> &exports)
{
    UniValue result, error;

    UniValue params(UniValue::VARR);
    params.push_back(EncodeDestination(CIdentityID(launchNotarization.currencyID)));
    params.push_back((int)0);
    if (launchNotarization.proofRoots.count(notarySystem.GetID()))
    {
        params.push_back((int64_t)launchNotarization.proofRoots.find(notarySystem.GetID())->second.rootHeight);
    }

    if (notarySystem.GetID() == ASSETCHAINS_CHAINID || (!IsVerusActive() && ConnectedChains.IsNotaryAvailable()))
    {
        // we are starting a PBaaS chain. We only assume that our chain definition and the first notary chain, if there is one, are setup
        // in ConnectedChains. All other currencies and identities necessary to start have not been populated and must be in block 1 by
        // getting the information from the notary chain.

        bool notaryCallResult = false;
        if (notarySystem.GetID() == ASSETCHAINS_CHAINID)
        {
            UniValue getexports(const UniValue& params, bool fHelp);
            try
            {
                result = getexports(params, false);
            } catch (std::exception e)
            {
                error = strprintf("Failed to connect to %s chain, error: %s\n", notarySystem.chainDefinition.name.c_str(), e.what());
            }
            notaryCallResult = error.isNull();
        }
        else
        {
            notaryCallResult = CallNotary(notarySystem, "getexports", params, result, error);
        }

        if (notaryCallResult &&
            result.isArray() &&
            result.size())
        {
            // we now have an array of exports that we should import into this system
            // load up to the last launch export on each currency
            for (int i = 0; i < result.size(); i++)
            {
                CCrossChainExport ccx;
                std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>> oneExport;
                if (DecodeOneExport(result[i], ccx, oneExport))
                {
                    exports[ccx.destCurrencyID].push_back(oneExport);
                }
                else
                {
                    return false;
                }
            }
            return true;
        }
        return false;
    }
    return false;
}

bool AddOneCurrencyImport(const CCurrencyDefinition &newCurrency,
                          const CPBaaSNotarization &lastNotarization,
                          const std::pair<CUTXORef, CPartialTransactionProof> *pLaunchProof,
                          const std::pair<CUTXORef, CPartialTransactionProof> *pFirstExport,
                          const std::vector<CReserveTransfer> &_exportTransfers,
                          CCurrencyValueMap &gatewayDeposits,
                          std::vector<CTxOut> &outputs,
                          CCurrencyValueMap &additionalFees,
                          const CRPCChainData &_launchChain=ConnectedChains.FirstNotaryChain(),
                          const CCurrencyDefinition &_newChain=ConnectedChains.ThisChain());

// This is called with either the initial currency, or the gateway converter currency
// to setup an import/export thread, transfer the initial issuance of native currency
// into the converter, and notarize the state of each currency.
// All outputs to do those things are added to the outputs vector.
bool AddOneCurrencyImport(const CCurrencyDefinition &newCurrency,
                          const CPBaaSNotarization &lastNotarization,
                          const std::pair<CUTXORef, CPartialTransactionProof> *pLaunchProof,
                          const std::pair<CUTXORef, CPartialTransactionProof> *pFirstExport,
                          const std::vector<CReserveTransfer> &_exportTransfers,
                          CCurrencyValueMap &gatewayDeposits,
                          std::vector<CTxOut> &outputs,
                          CCurrencyValueMap &additionalFees,
                          const CRPCChainData &_launchChain,
                          const CCurrencyDefinition &_newChain)
{
    uint160 newCurID = newCurrency.GetID();
    uint160 newChainID = _newChain.GetID();
    uint160 firstNotaryID = _launchChain.GetID();

    CPBaaSNotarization newNotarization = lastNotarization;
    newNotarization.prevNotarization = CUTXORef();
    newNotarization.SetBlockOneNotarization();

    // each currency will get:
    // * one currency definition output
    // * notarization of latest currency state

    CCcontract_info CC;
    CCcontract_info *cp;

    // make a currency definition
    cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);
    std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});
    outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, &newCurrency))));

    if (newChainID == ASSETCHAINS_CHAINID)
    {
        ConnectedChains.UpdateCachedCurrency(newCurrency, 1);
    }

    // import / export capable currencies include the main currency, and converter, they also get an import / export thread
    if (newCurID == newChainID ||
        newCurID == firstNotaryID ||
        (newCurrency.systemID == newChainID &&
         newCurrency.IsFractional() &&
         newCurrency.IsGatewayConverter()))
    {
        // first, put evidence of the notarization pre-import
        int notarizationIdx = -1;
        if (pLaunchProof)
        {
            // add notarization before other outputs
            cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            // now, we need to put the launch notarization evidence, followed by the import outputs
            CCrossChainProof evidenceProof;
            evidenceProof << pLaunchProof->second;
            CNotaryEvidence evidence = CNotaryEvidence(firstNotaryID,
                                                       pLaunchProof->first,
                                                       true,
                                                       evidenceProof,
                                                       CNotaryEvidence::TYPE_IMPORT_PROOF);
            notarizationIdx = outputs.size();
            outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &evidence))));
        }

        // create the import thread output
        cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

        if ((newCurrency.systemID == newChainID) && firstNotaryID == newCurrency.launchSystemID)
        {
            uint256 transferHash;
            std::vector<CTxOut> importOutputs;
            CCurrencyValueMap importedCurrency, gatewayDepositsUsed, spentCurrencyOut;

            CPBaaSNotarization tempLastNotarization = lastNotarization;
            tempLastNotarization.currencyState.SetLaunchCompleteMarker(false);

            // get the first export for launch from the notary chain
            CTransaction firstExportTx;
            if (!pFirstExport || !(pFirstExport->second.IsValid() && !pFirstExport->second.GetPartialTransaction(firstExportTx).IsNull()))
            {
                LogPrintf("%s: invalid first export for PBaaS or converter launch\n");
                return false;
            }

            // get the export for this import
            CCrossChainExport ccx(firstExportTx.vout[pFirstExport->first.n].scriptPubKey);
            if (!ccx.IsValid())
            {
                LogPrintf("%s: invalid export output for PBaaS or converter launch\n");
                return false;
            }

            std::vector<CReserveTransfer> exportTransfers(_exportTransfers);

            bool updatedMinMax = newCurrency.IsPBaaSChain() &&
                                 (!PBAAS_TESTMODE ||
                                  (lastNotarization.proofRoots.count(VERUS_CHAINID) &&
                                   lastNotarization.proofRoots.find(VERUS_CHAINID)->second.rootHeight >= ConnectedChains.GetZeroViaHeight(PBAAS_TESTMODE)));

            if (updatedMinMax)
            {
                tempLastNotarization.currencyState.primaryCurrencyIn = std::vector<int64_t>(tempLastNotarization.currencyState.primaryCurrencyIn.size(), 0);
            }
            if (!tempLastNotarization.NextNotarizationInfo(_launchChain.chainDefinition,
                                                           newCurrency,
                                                           0,
                                                           1,
                                                           exportTransfers,
                                                           transferHash,
                                                           newNotarization,
                                                           importOutputs,
                                                           importedCurrency,
                                                           gatewayDepositsUsed,
                                                           spentCurrencyOut,
                                                           ccx.exporter))
            {
                LogPrintf("%s: invalid import for currency %s on system %s\n", __func__,
                                                                            newCurrency.name.c_str(),
                                                                            EncodeDestination(CIdentityID(newCurID)).c_str());
                return false;
            }

            // if fees are not converted, we will pay out original fees,
            // less liquidity fees, which go into the currency reserves
            bool feesConverted;
            CCurrencyValueMap liquidityFees;
            CCurrencyValueMap originalFees =
                newNotarization.currencyState.CalculateConvertedFees(
                    newNotarization.currencyState.viaConversionPrice,
                    newNotarization.currencyState.viaConversionPrice,
                    newChainID,
                    feesConverted,
                    liquidityFees,
                    additionalFees);

            std::map<uint160, int32_t> currencyIndexMap = newNotarization.currencyState.GetReserveMap();
            bool newGatewayConverter = (newCurrency.IsGatewayConverter() &&
                                        newCurrency.gatewayID == newChainID &&
                                        (!PBAAS_TESTMODE ||
                                        tempLastNotarization.currencyState.reserves[currencyIndexMap[newChainID]] == newCurrency.gatewayConverterIssuance));

            if (!feesConverted)
            {
                additionalFees += (originalFees - liquidityFees);
            }

            newNotarization.SetBlockOneNotarization();

            // display import outputs
            CMutableTransaction debugTxOut;
            debugTxOut.vout = outputs;
            debugTxOut.vout.insert(debugTxOut.vout.end(), importOutputs.begin(), importOutputs.end());
            UniValue jsonTxOut(UniValue::VOBJ);
            TxToUniv(debugTxOut, uint256(), jsonTxOut);
            LogPrint("notarization", "%s: launch outputs: %s\nlast notarization: %s\nnew notarization: %s\n", __func__,
                                                                                            jsonTxOut.write(1,2).c_str(),
                                                                                            lastNotarization.ToUniValue().write(1,2).c_str(),
                                                                                            newNotarization.ToUniValue().write(1,2).c_str());

            newNotarization.prevNotarization = CUTXORef();
            newNotarization.prevHeight = 0;

            tempLastNotarization = lastNotarization;
            tempLastNotarization.SetMirror(false);
            CNativeHashWriter hw;
            hw << tempLastNotarization;
            newNotarization.hashPrevCrossNotarization = hw.GetHash();

            // create an import based on launch conditions that covers all pre-allocations and uses the initial notarization.
            // generate outputs, then fill in numOutputs
            CCrossChainImport cci = CCrossChainImport(newCurrency.launchSystemID,
                                                      newNotarization.notarizationHeight,
                                                      newCurID,
                                                      ccx.totalAmounts,
                                                      CCurrencyValueMap(),
                                                      0,
                                                      ccx.hashReserveTransfers,
                                                      pFirstExport->first.hash,
                                                      pFirstExport->first.n);
            cci.SetSameChain(newCurrency.launchSystemID == newChainID);
            cci.SetPostLaunch();
            cci.SetInitialLaunchImport();

            // anything we had before plus anything imported and minus all spent currency out should
            // be all reserve deposits remaining under control of this currency

            /* printf("%s: ccx.totalAmounts: %s\ngatewayDepositsUsed: %s\nadditionalFees: %s\noriginalFees: %s\n",
                __func__,
                ccx.totalAmounts.ToUniValue().write(1,2).c_str(),
                gatewayDepositsUsed.ToUniValue().write(1,2).c_str(),
                additionalFees.ToUniValue().write(1,2).c_str(),
                originalFees.ToUniValue().write(1,2).c_str()); */

            CAmount totalCurrencyOut = newNotarization.currencyState.primaryCurrencyOut;

            // to determine left over reserves for deposit, consider imported and emitted as the same
            if (updatedMinMax)
            {
                gatewayDeposits = CCurrencyValueMap(lastNotarization.currencyState.currencies, lastNotarization.currencyState.primaryCurrencyIn);
            }
            else
            {
                gatewayDeposits = CCurrencyValueMap(lastNotarization.currencyState.currencies, lastNotarization.currencyState.reserveIn);
            }
            if (!newCurrency.IsFractional() || newGatewayConverter)
            {
                gatewayDeposits += originalFees;
            }
            gatewayDeposits.valueMap[newCurID] += gatewayDepositsUsed.valueMap[newCurID] + totalCurrencyOut;

            printf("importedcurrency %s\nspentcurrencyout %s\ngatewaydeposits %s\n",
                importedCurrency.ToUniValue().write(1,2).c_str(),
                spentCurrencyOut.ToUniValue().write(1,2).c_str(),
                gatewayDeposits.ToUniValue().write(1,2).c_str());

            gatewayDeposits = (gatewayDeposits - spentCurrencyOut).CanonicalMap();

            printf("newNotarization.currencyState %s\nnewgatewaydeposits %s\n",
                newNotarization.currencyState.ToUniValue().write(1,2).c_str(),
                gatewayDeposits.ToUniValue().write(1,2).c_str());

            // add the reserve deposit output with all deposits for this currency for the new chain
            if (gatewayDeposits.valueMap.size())
            {
                CCcontract_info *depositCp;
                CCcontract_info depositCC;

                // create the import thread output
                depositCp = CCinit(&depositCC, EVAL_RESERVE_DEPOSIT);
                std::vector<CTxDestination> depositDests({CPubKey(ParseHex(depositCC.CChexstr))});
                // put deposits under control of the launch system, where the imports using them will be coming from
                CReserveDeposit rd(newCurrency.IsPBaaSChain() ? newCurrency.launchSystemID : newCurID, gatewayDeposits);
                CAmount nativeOut = gatewayDeposits.valueMap.count(newChainID) ? gatewayDeposits.valueMap[newChainID] : 0;
                outputs.push_back(CTxOut(nativeOut, MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, depositDests, 1, &rd))));
            }

            if (newCurrency.notaries.size() && newCurrency.IsPBaaSChain())
            {
                // notaries all get an even share of 10% of the launch fee in the launch currency to use for notarizing
                // they may also get pre-allocations
                uint160 notaryNativeID = _launchChain.chainDefinition.GetID();
                CAmount notaryFeeShare = _launchChain.chainDefinition.currencyRegistrationFee / 10;
                additionalFees -= CCurrencyValueMap(std::vector<uint160>({notaryNativeID}), std::vector<int64_t>({notaryFeeShare}));
                CAmount oneNotaryShare = notaryFeeShare / newCurrency.notaries.size();
                CAmount notaryModExtra = notaryFeeShare % newCurrency.notaries.size();
                for (auto &oneNotary : newCurrency.notaries)
                {
                    CTokenOutput to(notaryNativeID, oneNotaryShare);
                    if (notaryModExtra)
                    {
                        to.reserveValues.valueMap[notaryNativeID]++;
                        notaryModExtra--;
                    }
                    outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT,
                                                    std::vector<CTxDestination>({CIdentityID(oneNotary)}),
                                                    1,
                                                    &to))));
                }
            }

            cci.numOutputs = importOutputs.size();

            // now add the import itself
            outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci))));

            // add notarization before other outputs
            cp = CCinit(&CC, EVAL_EARNEDNOTARIZATION);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_EARNEDNOTARIZATION, dests, 1, &newNotarization))));

            // add export before other outputs
            cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

            // now, we need to put the export evidence, followed by the import outputs
            CCrossChainProof evidenceProof;
            evidenceProof << pFirstExport->second;
            CNotaryEvidence evidence = CNotaryEvidence(cci.sourceSystemID,
                                                       CUTXORef(uint256(), notarizationIdx),
                                                       true,
                                                       evidenceProof,
                                                       CNotaryEvidence::TYPE_IMPORT_PROOF);

            outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &evidence))));
            outputs.insert(outputs.end(), importOutputs.begin(), importOutputs.end());
        }
        else
        {
            // begin with an empty import for this currency
            // create an import based on launch conditions that covers all pre-allocations and uses the initial notarization

            // if the currency is new and owned by this chain, its registration requires the fee, paid in its launch chain currency
            // otherwise, it is being imported from another chain and requires an import fee
            CCurrencyValueMap registrationFees;
            CAmount registrationAmount = 0;
            registrationAmount = 0;

            CCrossChainImport cci = CCrossChainImport(_newChain.launchSystemID,
                                                      1,
                                                      newCurID,
                                                      CCurrencyValueMap());
            cci.SetDefinitionImport(true);
            outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci))));

            // add notarization before other outputs
            cp = CCinit(&CC, EVAL_EARNEDNOTARIZATION);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

            // this currency is not launching now
            newNotarization.SetLaunchConfirmed();
            newNotarization.SetLaunchComplete();
            newNotarization.SetBlockOneNotarization();

            outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_EARNEDNOTARIZATION, dests, 1, &newNotarization))));

            CReserveTransactionDescriptor rtxd;
            CCoinbaseCurrencyState importState = newNotarization.currencyState;
            importState.RevertReservesAndSupply(_newChain);
            CCurrencyValueMap importedCurrency;
            CCurrencyValueMap gatewayDepositsIn;
            CCurrencyValueMap spentCurrencyOut;
            CCoinbaseCurrencyState newCurrencyState;
            if (!rtxd.AddReserveTransferImportOutputs(_launchChain.chainDefinition,
                                                      _newChain,
                                                      newCurrency,
                                                      importState,
                                                      std::vector<CReserveTransfer>(),
                                                      1,
                                                      outputs,
                                                      importedCurrency,
                                                      gatewayDepositsIn,
                                                      spentCurrencyOut,
                                                      &newCurrencyState))
            {
                LogPrintf("Invalid starting currency import for %s\n", _newChain.name.c_str());
                printf("Invalid starting currency import for %s\n", _newChain.name.c_str());
                return false;
            }

            // if fees are not converted, we will pay out original fees,
            // less liquidity fees, which go into the currency reserves
            bool feesConverted;
            CCurrencyValueMap liquidityFees;
            CCurrencyValueMap originalFees =
                newCurrencyState.CalculateConvertedFees(
                    newCurrencyState.viaConversionPrice,
                    newCurrencyState.viaConversionPrice,
                    newChainID,
                    feesConverted,
                    liquidityFees,
                    additionalFees);

            if (!feesConverted)
            {
                additionalFees += (originalFees - liquidityFees);
            }
        }

        // export thread
        cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
        CCrossChainExport ccx;

        ccx = CCrossChainExport(newChainID, 1, 1, newCurrency.systemID, newCurID, 0, CCurrencyValueMap(), CCurrencyValueMap(), uint256());
        outputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &ccx))));
    }
    return true;
}

// create all special PBaaS outputs for block 1
bool BlockOneCoinbaseOutputs(std::vector<CTxOut> &outputs,
                             CPBaaSNotarization &launchNotarization,
                             CCurrencyValueMap &additionalFees,
                             const CRPCChainData &_launchChain,
                             CCurrencyDefinition &newChainCurrency)
{
    CCoinbaseCurrencyState currencyState;
    std::map<uint160, std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>>> blockOneExportImports;

    std::pair<CUTXORef, CPartialTransactionProof> launchNotarizationProof;
    std::pair<CUTXORef, CPartialTransactionProof> launchExportProof;
    std::vector<CReserveTransfer> launchExportTransfers;
    CPBaaSNotarization notaryNotarization, notaryConverterNotarization;
    uint160 launchChainID = _launchChain.GetID();

    if (!GetBlockOneLaunchNotarization(_launchChain,
                                       newChainCurrency.GetID(),
                                       newChainCurrency,
                                       launchNotarization,
                                       notaryNotarization,
                                       launchNotarizationProof,
                                       launchExportProof,
                                       launchExportTransfers))
    {
        // cannot make block 1 unless we can get the initial currency state from the first notary system
        LogPrintf("Cannot find chain on notary system\n");
        printf("Cannot find chain on notary system\n");
        return false;
    }

    // we need to have a launch decision to be able to mine any blocks, prior to launch being clear,
    // it is not an error. we are just not ready.
    if (!launchNotarization.IsLaunchCleared())
    {
        return false;
    }

    if (!launchNotarization.IsLaunchConfirmed())
    {
        // we must reach minimums in all currencies to launch
        LogPrintf("This chain did not receive the minimum currency contributions and cannot launch. Pre-launch contributions to this chain can be refunded.\n");
        printf("This chain did not receive the minimum currency contributions and cannot launch. Pre-launch contributions to this chain can be refunded.\n");
        return false;
    }

    // get initial imports
    if (!GetBlockOneImports(_launchChain, launchNotarization, blockOneExportImports))
    {
        // we must reach minimums in all currencies to launch
        LogPrintf("Cannot retrieve initial export imports from notary system\n");
        printf("Cannot retrieve initial export imports from notary system\n");
        return false;
    }

    // get all currencies/IDs that we will need to retrieve from our notary chain
    std::set<uint160> blockOneCurrencies;
    std::set<uint160> blockOneIDs = {newChainCurrency.GetID()};
    std::set<uint160> convertersToCreate;

    CPBaaSNotarization converterNotarization;
    std::pair<CUTXORef, CPartialTransactionProof> converterNotarizationProof;
    std::pair<CUTXORef, CPartialTransactionProof> converterExportProof;
    std::vector<CReserveTransfer> converterExportTransfers;
    uint160 converterCurrencyID = newChainCurrency.GatewayConverterID();
    CCurrencyDefinition converterCurDef;

    // if we have a converter currency, ensure that it also meets requirements for currency launch
    if (!newChainCurrency.gatewayConverterName.empty())
    {
        if (!GetBlockOneLaunchNotarization(_launchChain,
                                           converterCurrencyID,
                                           converterCurDef,
                                           converterNotarization,
                                           notaryConverterNotarization,
                                           converterNotarizationProof,
                                           converterExportProof,
                                           converterExportTransfers))
        {
            LogPrintf("Unable to get gateway converter initial state\n");
            printf("Unable to get gateway converter initial state\n");
            return false;
        }

        notaryConverterNotarization.currencyStates[converterCurrencyID] = converterNotarization.currencyState;

        // both currency and primary gateway must have their pre-launch phase complete before we can make a decision
        // about launching
        if (!converterNotarization.IsLaunchCleared())
        {
            return false;
        }

        // we need to have a cleared launch to be able to launch
        if (!converterNotarization.IsLaunchConfirmed())
        {
            LogPrintf("Primary currency met requirements for launch, but gateway currency converter did not\n");
            printf("Primary currency met requirements for launch, but gateway currency converter did not\n");
            return false;
        }

        convertersToCreate.insert(converterCurrencyID);

        for (auto &oneCurrency : converterCurDef.currencies)
        {
            blockOneCurrencies.insert(oneCurrency);
        }

        for (auto &onePrealloc : converterCurDef.preAllocation)
        {
            blockOneIDs.insert(onePrealloc.first);
        }
    }

    // Now, add block 1 imports, which provide a foundation of all IDs and currencies needed to launch the
    // new system, including ID and currency outputs for notary chain, all currencies we accept for pre-conversion,

    // first, we need to have the native notary currency itself and its notaries, if it has them
    blockOneCurrencies.insert(launchChainID);
    blockOneIDs.insert(_launchChain.chainDefinition.notaries.begin(), _launchChain.chainDefinition.notaries.end());

    for (auto &oneCurrency : newChainCurrency.currencies)
    {
        blockOneCurrencies.insert(oneCurrency);
    }

    for (auto &onePrealloc : newChainCurrency.preAllocation)
    {
        blockOneIDs.insert(onePrealloc.first);
    }

    // get this chain's notaries
    auto &notaryIDs = newChainCurrency.notaries;
    blockOneIDs.insert(notaryIDs.begin(), notaryIDs.end());

    // now retrieve IDs and currencies
    std::map<uint160, std::pair<CCurrencyDefinition, CPBaaSNotarization>> currencyImports;
    std::map<uint160, CIdentity> identityImports;

    if (!ConnectedChains.GetNotaryCurrencies(_launchChain, blockOneCurrencies, currencyImports, notaryNotarization.proofRoots[launchChainID].rootHeight) ||
        !ConnectedChains.GetNotaryIDs(_launchChain, newChainCurrency, blockOneIDs, identityImports, notaryNotarization.proofRoots[launchChainID].rootHeight))
    {
        // we must reach minimums in all currencies to launch
        LogPrintf("Cannot retrieve identity and currency definitions needed to create block 1\n");
        printf("Cannot retrieve identity and currency definitions needed to create block 1\n");
        return false;
    }

    if (currencyImports.count(notaryNotarization.currencyID))
    {
        currencyImports[notaryNotarization.currencyID].second = notaryNotarization;
    }

    // add all imported currency and identity outputs, identity revocaton and recovery IDs must be explicitly imported if needed
    for (auto &oneIdentity : identityImports)
    {
        outputs.push_back(CTxOut(0, oneIdentity.second.IdentityUpdateOutputScript(1)));
    }

    // calculate all issued currency on this chain for both the native and converter currencies,
    // which is the only currency that can be considered a gateway deposit at launch. this can
    // be used for native currency fee conversions
    CCurrencyValueMap gatewayDeposits;
    launchNotarization.proofRoots = notaryNotarization.proofRoots;
    bool success = AddOneCurrencyImport(newChainCurrency,
                                        launchNotarization,
                                        &launchNotarizationProof,
                                        &launchExportProof,
                                        launchExportTransfers,
                                        gatewayDeposits,
                                        outputs,
                                        additionalFees,
                                        _launchChain,
                                        newChainCurrency);

    // now, the converter
    if (success && converterCurDef.IsValid())
    {
        CCurrencyValueMap converterDeposits;
        converterNotarization.proofRoots = notaryConverterNotarization.proofRoots;
        success = AddOneCurrencyImport(converterCurDef,
                                       converterNotarization,
                                       &converterNotarizationProof,
                                       &converterExportProof,
                                       converterExportTransfers,
                                       converterDeposits,
                                       outputs,
                                       additionalFees,
                                       _launchChain,
                                       newChainCurrency);
    }

    if (success)
    {
        currencyImports.erase(newChainCurrency.GetID());
        currencyImports.erase(converterCurrencyID);
        // now, add the rest of necessary currencies
        for (auto &oneCurrency : currencyImports)
        {
            if (oneCurrency.second.first.GetID() == newChainCurrency.launchSystemID)
            {
                oneCurrency.second.second = notaryNotarization;
                if (!oneCurrency.second.second.SetMirror())
                {
                    success = false;
                    break;
                }
                oneCurrency.second.second.SetMirrorFlag(false);
                oneCurrency.second.second.SetPreLaunch(false);
            }
            else
            {
                oneCurrency.second.second = CPBaaSNotarization();
            }
            success = AddOneCurrencyImport(oneCurrency.second.first,
                                           oneCurrency.second.second,
                                           nullptr,
                                           nullptr,
                                           std::vector<CReserveTransfer>(),
                                           gatewayDeposits,
                                           outputs,
                                           additionalFees,
                                           _launchChain,
                                           newChainCurrency);
            if (!success)
            {
                break;
            }
        }
    }
    return success;
}

// given the total outputs of a block one coinbase of either this chain, if we are a PBaaS chain, or a PBaaS chain,
// this determines with the information available if the outputs can be from a valid block 1 coinbase.
// if this is called on a PBaaS chain node that is not connected to a notary chain, for example VRSC or VRSCTEST,
// it will check the block 1 coinbase according to the outputs on the block, proving against the information it has.
// as a result, it provides maximum security and assurance of block 1 authenticity to have at least one notarization
// confirmed on the launch chain, and/or to be connected to a notary chain node when syncing to the beginning of a
// PBaaS chain.
bool IsValidBlockOneCoinbase(const std::vector<CTxOut> &_outputs,
                             const CRPCChainData &launchChain,
                             const CCurrencyDefinition &_newChainCurrency,
                             CValidationState &state)
{
    uint160 launchChainID = launchChain.GetID();
    CCurrencyDefinition newChainCurrency = _newChainCurrency;
    uint160 newChainID = newChainCurrency.GetID();

    std::vector<CTxOut> __outputs;

    // we have no opinion about OpRets, and they are allowed in a block one coinbase, so if there is one,
    // copy the outputs and remove it before checking
    bool removeOpRet = _outputs.size() && _outputs.back().scriptPubKey.IsOpReturn();
    if (removeOpRet)
    {
        __outputs = _outputs;
        __outputs.pop_back();
    }
    const std::vector<CTxOut> &outputs = removeOpRet ? __outputs : _outputs;

    // if we are on the notary chain, get our version of the block one outputs and remove those that must match,
    // allowing for variation of things that could change with block height but nothing else
    std::vector<CTxOut> checkOutputs;
    CPBaaSNotarization launchNotarization;
    CCurrencyValueMap additionalFees;
    CCurrencyValueMap expectedMinerRewards;

    // determine IDs and currencies
    std::map<uint160, std::pair<CCurrencyDefinition, CPBaaSNotarization>> currencyImports;
    std::map<uint160, CIdentity> identityImports;
    CFeePool feePool;

    CCurrencyDefinition converterDef;

    // if we are on the PBaaS chain itself, we can only reject a valid block 1 if it does not
    // match the one that would be created using the notary chain as a guide
    if ((newChainCurrency.GetID() != ASSETCHAINS_CHAINID && launchChainID == ASSETCHAINS_CHAINID) ||
        (newChainCurrency.GetID() == ASSETCHAINS_CHAINID && (ConnectedChains.IsNotaryAvailable(false) || ConnectedChains.IsNotaryAvailable(true))))
    {
        bool validOutputs = BlockOneCoinbaseOutputs(checkOutputs, launchNotarization, additionalFees, launchChain, newChainCurrency);

        if (!validOutputs)
        {
            return state.Error("Unable to make comparison outputs");
        }

        // setup fee pool
        if (additionalFees.valueMap.count(launchChainID))
        {
            feePool.reserveValues.valueMap[launchChainID] = additionalFees.valueMap[launchChainID];
        }

        if (additionalFees.valueMap.count(newChainID))
        {
            feePool.reserveValues.valueMap[newChainID] = additionalFees.valueMap[newChainID];
            additionalFees.valueMap.erase(newChainID);
        }

        CFeePool oneFeeShare = feePool.OneFeeShare();
        feePool.reserveValues = (feePool.reserveValues - oneFeeShare.reserveValues).CanonicalMap();

        expectedMinerRewards = oneFeeShare.reserveValues;
        CAmount blockReward = (newChainCurrency.rewards.size() ? newChainCurrency.rewards[0] : 0);
        if (blockReward)
        {
            // matching fee pool should be capping the outputs, then we should match the check outputs
            // until emission of the indicated rewards
            expectedMinerRewards.valueMap[newChainID] += blockReward;
        }

        CCcontract_info CC;
        CCcontract_info *cp;
        cp = CCinit(&CC, EVAL_FEE_POOL);
        CPubKey pkCC = CPubKey(ParseHex(CC.CChexstr));
        checkOutputs.push_back(CTxOut(0,MakeMofNCCScript(CConditionObj<CFeePool>(EVAL_FEE_POOL, {pkCC.GetID()}, 1, &feePool))));

        // check all outputs and total additional verus fees and rewardtotal
        // all outputs must be present and rewards + fees must match
        if (LogAcceptCategory("launchnotarization"))
        {
            // display import outputs
            CMutableTransaction debugTxOut;
            debugTxOut.vout = outputs;
            UniValue jsonTxOut1(UniValue::VOBJ);
            UniValue jsonTxOut2(UniValue::VOBJ);
            TxToUniv(debugTxOut, uint256(), jsonTxOut1);
            debugTxOut.vout = checkOutputs;
            TxToUniv(debugTxOut, uint256(), jsonTxOut2);
            LogPrintf("%s: launch outputs: %s\ncheck outputs: %s\n", __func__, jsonTxOut1.write(1,2).c_str(), jsonTxOut2.write(1,2).c_str());
        }
    }
    else
    {
        // get our initial currency definition from the outputs
        const std::vector<CTxOut> &findCurrencyOuts = outputs;
        for (auto &oneOut : findCurrencyOuts)
        {
            if ((newChainCurrency = CCurrencyDefinition(oneOut.scriptPubKey)).IsValid() &&
                newChainCurrency.GetID() == newChainID)
            {
                break;
            }
            newChainCurrency = CCurrencyDefinition();
        }
        if (!newChainCurrency.IsValid())
        {
            return state.Error("Cannot find primary currency in block 1 coinbase");
        }
    }

    // now, use the outputs themselves as the source of IDs and currencies, determining
    // which ones are allowed and checking available proofs
    std::set<uint160> blockOneCurrencies = {newChainCurrency.GetID()};
    std::set<uint160> blockOneIDs = {newChainCurrency.GetID()};
    uint160 converterCurrencyID = newChainCurrency.GatewayConverterID();
    std::set<uint160> removedCurrencies;
    if (!converterCurrencyID.IsNull())
    {
        blockOneCurrencies.insert(converterCurrencyID);
        blockOneIDs.insert(converterCurrencyID);
        // find it in the outputs or checkOutputs, whichever we have, and add converter preallocation IDs
        const std::vector<CTxOut> &findConverterOuts = checkOutputs.size() ? checkOutputs : outputs;
        for (auto &oneOut : findConverterOuts)
        {
            if ((converterDef = CCurrencyDefinition(oneOut.scriptPubKey)).IsValid() &&
                converterDef.GetID() == converterCurrencyID)
            {
                break;
            }
            converterDef = CCurrencyDefinition();
        }
    }

    blockOneCurrencies.insert(launchChainID);
    blockOneIDs.insert(launchChain.chainDefinition.notaries.begin(), launchChain.chainDefinition.notaries.end());

    for (auto &oneCurrency : newChainCurrency.currencies)
    {
        blockOneCurrencies.insert(oneCurrency);
    }

    if (converterDef.IsValid())
    {
        for (auto &onePrealloc : converterDef.preAllocation)
        {
            blockOneIDs.insert(onePrealloc.first);
        }
    }

    for (auto &onePrealloc : newChainCurrency.preAllocation)
    {
        blockOneIDs.insert(onePrealloc.first);
    }

    // get this chain's notaries
    auto &notaryIDs = newChainCurrency.notaries;
    blockOneIDs.insert(notaryIDs.begin(), notaryIDs.end());

    CFeePool cbFeePool;
    bool haveFeePool = false;

    std::map<uint160, CCurrencyValueMap> reserveDeposits;
    std::map<uint160, CCurrencyValueMap> fundsRecipients;
    CCurrencyValueMap blockOneMinerFunds;

    int64_t converterIssuance = 0;
    bool updatedProtocol = !PBAAS_TESTMODE || (newChainCurrency.GetID() != ASSETCHAINS_CHAINID && ConnectedChains.AutoArbitrageEnabled(chainActive.Height()));

    int firstPBaaSOut = 0;
    bool doneMinerOuts = false;

    // loop through outputs and get currencies and identities
    for (int i = 0; i < outputs.size(); i++)
    {
        auto &oneOut = outputs[i];
        COptCCParams p;
        CCurrencyValueMap fundsOut = oneOut.scriptPubKey.ReserveOutValue(p);
        fundsOut.valueMap[newChainCurrency.GetID()] = oneOut.nValue;
        fundsOut = fundsOut.CanonicalMap();

        if (!p.IsValid(true))
        {
            if (!doneMinerOuts)
            {
                blockOneMinerFunds += fundsOut;
            }
            else
            {
                return state.Error("Invalid output in block one coinbase");
            }
        }
        else
        {
            if (fundsOut > CCurrencyValueMap() &&
                p.evalCode != EVAL_RESERVE_DEPOSIT &&
                p.evalCode != EVAL_FEE_POOL)
            {
                if (p.evalCode == EVAL_IDENTITY_PRIMARY)
                {
                    if (!doneMinerOuts)
                    {
                        firstPBaaSOut = i;
                    }
                    doneMinerOuts = true;
                }
                if (!doneMinerOuts)
                {
                    blockOneMinerFunds += fundsOut;
                }
                else
                {
                    txnouttype typeRet;
                    std::vector<CTxDestination> addresses;
                    int nRequired;
                    // no non-miner complex outputs allowed in block 1 coinbase
                    // all funded outputs must be simple 1 of 1 to an ID
                    if (!ExtractDestinations(oneOut.scriptPubKey, typeRet, addresses, nRequired) ||
                        addresses.size() != 1 ||
                        nRequired != 1 ||
                        addresses[0].which() != COptCCParams::ADDRTYPE_ID)
                    {
                        return state.Error("Invalid currency definition in block one coinbase");
                    }
                    fundsRecipients[GetDestinationID(addresses[0])] += fundsOut;
                }
            }
            else
            {
                if (!doneMinerOuts)
                {
                    firstPBaaSOut = i;
                }
                doneMinerOuts = true;
            }

            switch (p.evalCode)
            {
                case EVAL_IDENTITY_PRIMARY:
                {
                    if (!doneMinerOuts)
                    {
                        firstPBaaSOut = i;
                    }
                    doneMinerOuts = true;

                    CIdentity oneIdentity;
                    if (p.vData.size() &&
                        (oneIdentity = CIdentity(p.vData[0])).IsValid())
                    {
                        uint160 oneID = oneIdentity.GetID();
                        if (!blockOneIDs.count(oneID))
                        {
                            return state.Error("Invalid identity definition in block one coinbase");
                        }
                        else if (identityImports.count(oneID))
                        {
                            return state.Error("Duplicate identity definition in block one coinbase");
                        }
                        blockOneIDs.erase(oneID);
                        identityImports[oneID] = oneIdentity;
                    }
                    else
                    {
                        return state.Error("Invalid identity output");
                    }
                    break;
                }
                case EVAL_CURRENCY_DEFINITION:
                {
                    CCurrencyDefinition oneCurrency;
                    if (p.vData.size() &&
                        (oneCurrency = CCurrencyDefinition(p.vData[0])).IsValid())
                    {
                        uint160 oneID = oneCurrency.GetID();
                        if (!blockOneCurrencies.count(oneID))
                        {
                            return state.Error("Invalid currency definition in block one coinbase");
                        }
                        else if (currencyImports.count(oneID))
                        {
                            return state.Error("Duplicate currency definition in block one coinbase");
                        }
                        if (oneID == converterCurrencyID)
                        {
                            // if it is the converterID, first, add all currencies in it to those we should have and have not yet deleted
                            for (auto &oneCurrencyID : oneCurrency.currencies)
                            {
                                if (!removedCurrencies.count(oneCurrencyID))
                                {
                                    blockOneCurrencies.insert(oneCurrencyID);
                                }
                            }
                            converterIssuance = oneCurrency.gatewayConverterIssuance;
                        }
                        blockOneCurrencies.erase(oneID);
                        removedCurrencies.insert(oneID);
                        currencyImports[oneID] = std::make_pair(oneCurrency, CPBaaSNotarization());
                    }
                    else
                    {
                        return state.Error("Invalid currency output");
                    }
                    break;
                }
                case EVAL_CROSSCHAIN_IMPORT:
                {
                    CCrossChainImport cci, sysCCI;
                    CCrossChainExport ccx;
                    CPBaaSNotarization notarization;
                    if (p.vData.size() &&
                        (cci = CCrossChainImport(p.vData[0])).IsValid())
                    {
                        uint160 oneID = cci.importCurrencyID;

                        CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), 1);
                        mtx.vout = outputs;
                        mtx.vin.push_back(CTxIn(uint256(), (uint32_t)-1, CScript() << (uint32_t)1 << OP_0));

                        int32_t sysCCIOut = 0, importNotarizationOut = 0, evidenceOutStart = 0, evidenceOutEnd = 0;
                        std::vector<CReserveTransfer> reserveTransfers;
                        if (!currencyImports.count(oneID) ||
                            !cci.GetImportInfo(mtx, 1, i, ccx, sysCCI, sysCCIOut, notarization, importNotarizationOut, evidenceOutStart, evidenceOutEnd, reserveTransfers))
                        {
                            return state.Error("Invalid currency import info");
                        }
                        currencyImports[oneID].second = notarization;
                        if (notarization.currencyID == converterCurrencyID &&
                            notarization.currencyState.reserves[notarization.currencyState.GetReserveMap()[newChainID]] == converterIssuance)
                        {
                            updatedProtocol = true;
                        }
                    }
                    else
                    {
                        return state.Error("Invalid currency import");
                    }
                    break;
                }
                case EVAL_RESERVE_DEPOSIT:
                {
                    CReserveDeposit oneDeposit;
                    if (p.vData.size() &&
                        (oneDeposit = CReserveDeposit(p.vData[0])).IsValid())
                    {
                        reserveDeposits[oneDeposit.controllingCurrencyID] += oneDeposit.reserveValues;
                    }
                    else
                    {
                        return state.Error("Invalid reserve deposit output");
                    }
                    break;
                }
                case EVAL_FEE_POOL:
                {
                    if (p.vData.size() &&
                        (cbFeePool = CFeePool(p.vData[0])).IsValid() &&
                        !haveFeePool)
                    {
                        haveFeePool = true;
                    }
                    else
                    {
                        return state.Error("Invalid fee pool output");
                    }
                    break;
                }
            }
            if (doneMinerOuts && outputs.size() > i && checkOutputs.size() > (i - firstPBaaSOut))
            {
                if (::AsVector(outputs[i]) != ::AsVector(checkOutputs[i - firstPBaaSOut]))
                {
                    // we will tolerate if this is a notary evidence output and the only difference here is
                    // that the output number is off by the delta of the variable outputs
                    COptCCParams chkP1, chkP2;
                    CNotaryEvidence chkEvidence1, chkEvidence2;
                    bool oneOutOK = false;
                    if (outputs[i].scriptPubKey.IsPayToCryptoCondition(chkP1) &&
                        chkP1.evalCode == EVAL_NOTARY_EVIDENCE &&
                        (chkEvidence1 = CNotaryEvidence(chkP1.vData[0])).IsValid() &&
                        checkOutputs[i - firstPBaaSOut].scriptPubKey.IsPayToCryptoCondition(chkP2) &&
                        chkP2.evalCode == EVAL_NOTARY_EVIDENCE &&
                        chkP1.vData.size() == chkP2.vData.size() &&
                        (chkEvidence2 = CNotaryEvidence(chkP2.vData[0])).IsValid())
                    {
                        CCcontract_info CC;
                        CCcontract_info *cp;

                        chkEvidence2.output.n = chkEvidence1.output.n;
                        chkP2.vData[0] = ::AsVector(chkEvidence2);

                        cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
                        std::vector<CTxDestination> dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
                        oneOutOK = ::AsVector(outputs[i]) == ::AsVector(CTxOut(0, MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &chkEvidence2))));
                    }
                    if (!oneOutOK)
                    {
                        if (LogAcceptCategory("notarization"))
                        {
                            UniValue uniScript1(UniValue::VOBJ);
                            UniValue uniScript2(UniValue::VOBJ);
                            ScriptPubKeyToUniv(outputs[i].scriptPubKey, uniScript1, false, false);
                            ScriptPubKeyToUniv(checkOutputs[i - firstPBaaSOut].scriptPubKey, uniScript2, false, false);
                            LogPrintf("%s: mismatched block one outputs, values:\nactual: %ld\nexpected: %ld\nscripts:\nactual: %s\nexpected: %s\n",
                                    __func__,
                                    outputs[i].nValue,
                                    checkOutputs[i - firstPBaaSOut].nValue,
                                    uniScript1.write(1,2).c_str(),
                                    uniScript2.write(1,2).c_str());
                        }
                        if (updatedProtocol)
                        {
                            return state.Error("Mismatched block one output at #" + std::to_string(i));
                        }
                    }
                }
            }
        }
    }

    if (blockOneIDs.size() || blockOneCurrencies.size())
    {
        return state.Error("Invalid block one coinbase identity and/or currency outputs");
    }

    if (checkOutputs.size())
    {
        if (outputs.size() < checkOutputs.size())
        {
            return state.Error("Invalid coinbase output count");
        }

        // check that we have correct miner rewards
        if (blockOneMinerFunds != expectedMinerRewards)
        {
            return state.Error("Invalid miner outputs");
        }

        if (cbFeePool.reserveValues != feePool.reserveValues.CanonicalMap())
        {
            return state.Error("Invalid fee pool output");
        }

        auto revOutputIt = outputs.rbegin();
        int mismatchCount = 0;
        for (auto revCheckOutputIt = checkOutputs.rbegin(); revCheckOutputIt != checkOutputs.rend(); revCheckOutputIt++, revOutputIt++)
        {
            if (::AsVector(*revCheckOutputIt) != ::AsVector(*revOutputIt))
            {
                // we forgive evidence with an alternate output, but nothing else
                COptCCParams p1, p2;
                CNotaryEvidence ne1, ne2;
                if (revCheckOutputIt->scriptPubKey.IsPayToCryptoCondition(p1) &&
                    p1.IsValid() &&
                    p1.evalCode == EVAL_NOTARY_EVIDENCE &&
                    p1.vData.size() &&
                    (ne1 = CNotaryEvidence(p1.vData[0])).IsValid() &&
                    revOutputIt->scriptPubKey.IsPayToCryptoCondition(p2) &&
                    p2.IsValid() &&
                    p2.evalCode == EVAL_NOTARY_EVIDENCE &&
                    p2.vData.size() &&
                    (ne2 = CNotaryEvidence(p2.vData[0])).IsValid() &&
                    ne2.output.n - ne1.output.n == outputs.size() - checkOutputs.size())
                {
                    ne1.output.n = ne2.output.n;
                    if (::AsVector(ne1) == ::AsVector(ne2) &&
                        revCheckOutputIt->nValue == revOutputIt->nValue)
                    {
                        continue;
                    }
                }
                mismatchCount++;
                LogPrint("notarization", "%s: mismatch block one coinbase output:\nexpected: %s\nactual: %s\n", __func__, revCheckOutputIt->ToString().c_str(), revOutputIt->ToString().c_str());
            }
            LogPrint("notarization", "Matched %d/%d outputs for block 1 coinbase\n", (int)checkOutputs.size() - mismatchCount, (int)checkOutputs.size());
        }
        if (mismatchCount)
        {
            LogPrintf("%s: Invalid block one coinbase for chain %s\n", __func__, newChainCurrency.name.c_str());
            return state.Error(std::string("Invalid block 1 coinbase for chain ") + newChainCurrency.name + std::string(" (") + EncodeDestination(CIdentityID(newChainCurrency.GetID())) + std::string(")"));
        }
    }
    else
    {
        // TODO: POST HARDENING -
        // if we did not get full checkoutputs, we could still double check that we have
        // correct preallocations,
        // correct notary funds distributed
        // expected reserve deposits
        //
        // numbers are already checked for consistency & fully checked if we are on the
        // launch chain or connected to it, but check that all numbers match here
    }
    return true;
}

// create all special PBaaS outputs for block 1
bool MakeBlockOneCoinbaseOutputs(std::vector<CTxOut> &outputs,
                                 CPBaaSNotarization &launchNotarization,
                                 CCurrencyValueMap &additionalFees)
{
    return BlockOneCoinbaseOutputs(outputs,
                                   launchNotarization,
                                   additionalFees,
                                   ConnectedChains.FirstNotaryChain(),
                                   ConnectedChains.ThisChain());
}

uint256 RandomizedNonce()
{
    // Randomize nonce
    arith_uint256 nonce = UintToArith256(GetRandHash());

    // Clear the top 16 and bottom 16 or 24 bits (for local use as thread flags and counters)
    nonce <<= ASSETCHAINS_NONCESHIFT[ASSETCHAINS_ALGO];
    nonce >>= 16;
    return ArithToUint256(nonce);
}

CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const std::vector<CTxOut> &minerOutputs, bool isStake, uint256 useNonce)
{
    // instead of one scriptPubKeyIn, we take a vector of them along with relative weight. each is assigned a percentage of the block subsidy and
    // mining reward based on its weight relative to the total
    if (!(minerOutputs.size() && ConnectedChains.SetLatestMiningOutputs(minerOutputs) || isStake))
    {
        fprintf(stderr,"%s: Must have valid miner outputs, including script with valid PK, PKH, or Verus ID destination.\n", __func__);
        return NULL;
    }

    CTxDestination firstDestination;

    if (minerOutputs.size())
    {
        int64_t shareCheck = 0;
        CTxDestination checkDest;
        if (LogAcceptCategory("mining"))
        {
            printf("%s: Calculating miner distribution {\"address\": amount}:", __func__);
        }
        for (auto &output : minerOutputs)
        {
            shareCheck += output.nValue;
            if (LogAcceptCategory("mining"))
            {
                UniValue scriptUni(UniValue::VOBJ);
                ScriptPubKeyToUniv(output.scriptPubKey, scriptUni, true, true);
                printf("%s, \"shareratio\": %" PRId64 ", \"total\": %" PRId64 "\n", scriptUni.write(1, 2).c_str(), output.nValue, shareCheck);
                LogPrintf("%s, \"shareratio\": %" PRId64 ", \"total\": %" PRId64 "\n", scriptUni.write(1, 2).c_str(), output.nValue, shareCheck);

                if (shareCheck > INT_MAX)
                {
                    printf("OVERFLOW, value greater than %d\n", INT_MAX);
                    LogPrintf("OVERFLOW, value greater than %d\n", INT_MAX);
                }
            }
            if (shareCheck < 0 ||
                shareCheck > INT_MAX ||
                !ExtractDestination(output.scriptPubKey, checkDest) ||
                (checkDest.which() == COptCCParams::ADDRTYPE_INVALID))
            {
                fprintf(stderr,"Invalid miner outputs share specifications\n");
                return NULL;
            }
        }
        ExtractDestination(minerOutputs[0].scriptPubKey, firstDestination);
    }

    uint32_t blocktime;
    //fprintf(stderr,"create new block\n");
    // Create new block
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
    {
        fprintf(stderr,"pblocktemplate.get() failure\n");
        return NULL;
    }
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    pblock->nSolution.resize(Eh200_9.SolutionWidth);

    pblock->SetVersionByHeight(chainActive.LastTip()->GetHeight() + 1);

    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = GetArg("-blockversion", pblock->nVersion);

    // Add dummy coinbase tx placeholder as first transaction
    pblock->vtx.push_back(CTransaction());

    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);

    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    CAmount nFees = 0;
    CAmount takenFees = 0;

    bool isVerusActive = IsVerusActive();
    CCurrencyDefinition &thisChain = ConnectedChains.ThisChain();

    std::vector<CAmount> exchangeRate(thisChain.currencies.size());

    // we will attempt to spend any cheats we see
    CTransaction cheatTx;
    boost::optional<CTransaction> cheatSpend;
    uint256 cbHash;

    CBlockIndex* pindexPrev = 0;
    bool loop = true;
    while (loop)
    {
        loop = false;
        int nHeight;
        const Consensus::Params &consensusParams = chainparams.GetConsensus();
        uint32_t consensusBranchId;
        int64_t nMedianTimePast = 0;
        uint32_t proposedTime = 0;

        {
            while (proposedTime == nMedianTimePast)
            {
                if (proposedTime)
                {
                    MilliSleep(20);
                }
                LOCK(cs_main);
                pindexPrev = chainActive.LastTip();
                nHeight = pindexPrev->GetHeight() + 1;
                consensusBranchId = CurrentEpochBranchId(nHeight, consensusParams);
                nMedianTimePast = pindexPrev->GetMedianTimePast();
                proposedTime = GetAdjustedTime();

                if (proposedTime == nMedianTimePast)
                {
                    boost::this_thread::interruption_point();
                }
            }
        }

        CCoinbaseCurrencyState currencyState;

        uint32_t expired; uint64_t commission;

        {
            LOCK2(cs_main, mempool.cs);

            if (pindexPrev != chainActive.LastTip())
            {
                // try again
                loop = true;
                continue;
            }
            pblock->nTime = GetAdjustedTime();

            currencyState = ConnectedChains.GetCurrencyState(nHeight, true);
        }

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;
        bool fPrintPriority = GetBoolArg("-printpriority", false);

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        std::map<uint256, int> vecPriTxMap;
        vecPriority.reserve(mempool.mapTx.size() + 1);

        {
            LOCK(cs_main);

            // check if we should add cheat transaction
            CBlockIndex *ppast;
            CTransaction cb;
            int cheatHeight = nHeight - COINBASE_MATURITY < 1 ? 1 : nHeight - COINBASE_MATURITY;
            if (defaultSaplingDest &&
                chainActive.Height() > 100 &&
                (ppast = chainActive[cheatHeight]) &&
                ppast->IsVerusPOSBlock() &&
                cheatList.IsHeightOrGreaterInList(cheatHeight))
            {
                // get the block and see if there is a cheat candidate for the stake tx
                CBlock b;
                if (!(fHavePruned && !(ppast->nStatus & BLOCK_HAVE_DATA) && ppast->nTx > 0) && ReadBlockFromDisk(b, ppast, chainparams.GetConsensus(), 1))
                {
                    CTransaction &stakeTx = b.vtx[b.vtx.size() - 1];

                    if (cheatList.IsCheatInList(stakeTx, &cheatTx))
                    {
                        // make and sign the cheat transaction to spend the coinbase to our address
                        CMutableTransaction mtx = CreateNewContextualCMutableTransaction(consensusParams, nHeight);

                        uint32_t voutNum;
                        // get the first vout with value
                        for (voutNum = 0; voutNum < b.vtx[0].vout.size(); voutNum++)
                        {
                            if (b.vtx[0].vout[voutNum].nValue > 0)
                                break;
                        }

                        // send to the same pub key as the destination of this block reward
                        if (MakeCheatEvidence(mtx, b.vtx[0], voutNum, cheatTx))
                        {
                            LOCK(pwalletMain->cs_wallet);
                            TransactionBuilder tb = TransactionBuilder(consensusParams, nHeight);
                            cb = b.vtx[0];
                            cbHash = cb.GetHash();

                            bool hasInput = false;
                            for (uint32_t i = 0; i < cb.vout.size(); i++)
                            {
                                // add the spends with the cheat
                                if (cb.vout[i].nValue > 0)
                                {
                                    tb.AddTransparentInput(COutPoint(cbHash,i), cb.vout[0].scriptPubKey, cb.vout[0].nValue);
                                    hasInput = true;
                                }
                            }

                            if (hasInput)
                            {
                                // this is a send from a t-address to a sapling address, which we don't have an ovk for.
                                // Instead, generate a common one from the HD seed. This ensures the data is
                                // recoverable, at least for us, while keeping it logically separate from the ZIP 32
                                // Sapling key hierarchy, which the user might not be using.
                                uint256 ovk;
                                HDSeed seed;
                                if (pwalletMain->GetHDSeed(seed)) {
                                    ovk = ovkForShieldingFromTaddr(seed);

                                    // send everything to Sapling address
                                    tb.SendChangeTo(defaultSaplingDest.value(), ovk);

                                    tb.AddOpRet(mtx.vout[mtx.vout.size() - 1].scriptPubKey);

                                    TransactionBuilderResult buildResult(tb.Build());
                                    if (!buildResult.IsError() && buildResult.IsTx())
                                    {
                                        cheatSpend = buildResult.GetTxOrThrow();
                                    }
                                    else
                                    {
                                        LogPrintf("Error building cheat catcher transaction: %s\n", buildResult.GetError().c_str());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (cheatSpend)
            {
                LOCK2(smartTransactionCS, mempool.cs);

                cheatTx = cheatSpend.value();
                std::list<CTransaction> removed;
                mempool.removeConflicts(cheatTx, removed);
                printf("Found cheating stake! Adding cheat spend for %.8f at block #%d, coinbase tx\n%s\n",
                    (double)cb.GetValueOut() / (double)COIN, nHeight, cheatSpend.value().vin[0].prevout.hash.GetHex().c_str());

                // add to mem pool and relay
                if (myAddtomempool(cheatTx))
                {
                    RelayTransaction(cheatTx);
                }
            }
        }

        //
        // Now start solving the block
        //

        uint64_t nBlockSize = 1000;             // initial size
        uint64_t nBlockTx = 1;                  // number of transactions - always have a coinbase
        uint32_t autoTxSize = 0;                // extra transaction overhead that we will add while creating the block
        int nBlockSigOps = 100;

        {
            LOCK(mempool.cs);
            std::vector<CTransaction> txesToRemove;
            for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
                mi != mempool.mapTx.end(); ++mi)
            {
                const CTransaction& tx = mi->GetTx();
                if (IsExpiredTx(tx, nHeight))
                {
                    txesToRemove.push_back(tx);
                }
            }
            for (auto &oneTx : txesToRemove)
            {
                std::list<CTransaction> expiredRemoved;
                mempool.remove(oneTx, expiredRemoved, true);
            }
        }

        // Now the coinbase -
        // A PBaaS coinbase must have some additional outputs to enable certain chain state and functions to be properly
        // validated. All but currency state and the first chain definition are either optional or not valid on non-fractional reserve PBaaS blockchains
        // All of these are instant spend outputs that have no maturity wait time and may be spent in the same block.
        //
        // 1. (required) currency state - current state of currency supply and optionally reserve, premine, etc. This is primarily a data output to provide
        //    cross check for coin minting and burning operations, making it efficient to determine up-to-date supply, reserves, and conversions. To provide
        //    an extra level of supply cross-checking and fast data retrieval, this is part of all PBaaS chains' protocol, not just reserves.
        //    This output also includes reserve and native amounts for total conversions, less fees, of any conversions between Verus reserve and the
        //    native currency.
        //
        // 2. (block 1 required) chain definition - in order to confirm the amount of coins converted and issued within the possible range, before chain start,
        //    new PBaaS chains have a zero-amount, unspendable chain definition output.
        //
        // 3. (block 1 optional) initial import utxo - for any chain with conversion or pre-conversion, the first coinbase must include an initial import utxo.
        //    Pre-conversions are handled on the launch chain before the PBaaS chain starts, so they are an additional output, which begins
        //    as a fixed amount and is spent with as many outputs as necessary to the recipients of the pre-conversion transactions when those pre-conversions
        //    are imported. All pre-converted outputs get their source currency from a thread that starts with this output in block 1.
        //
        // 4. (block 1 optional) initial export utxo - reserve chains, or any chain that will use exports to another chain must have an initial export utxo, any chain
        //    may have one, but currently, they can only be spent with valid exports, which only occur on reserve chains
        //
        // 5. (optional) notarization output - in order to ensure that notarization can occur independent of the availability of fungible
        //    coins on the network, and also that the notarization can provide a spendable finalization output and possible reward
        //
        // In addition, each PBaaS block can be mined with optional, fee-generating transactions. Inporting transactions from the reserve chain or sending
        // exported transactions to the reserve chain are optional fee-generating steps that would be easy to do when running multiple daemons.
        // The types of transactions miners/stakers may facilitate or create for fees are as follows:
        //
        // 1. Earned notarization of Verus chain - spends the notarization instant out. must be present and spend the notarization output if there is a notarization output
        //
        // 2. Imported transactions from the export thread for this PBaaS chain on the Verus blockchain - imported transactions must spend the import utxo
        //    thread, represent the export from the alternate chain which spends the export output from the prior import transaction, carry a notary proof, and
        //    include outputs that map to each of its inputs on the source chain. Outputs can include unconverted reserve outputs only on fractional
        //    reserve chains, pre-converted outputs for any chain with launch conversion, and post launch outputs to be converted on fractional reserve
        //    chains. Each are handled in the following way:
        //      a. Unconverted outputs are left as outputs to the intended destination of Verus reserve token and do not pass through the coinbase
        //      b. Pre-converted outputs require that the import transaction spend the last pre-conversion output starting at block 1 as the source for
        //         pre-converted currency.
        //
        // 3. Zero or more aggregated exports that combine individual cross-chain transactions and reserve transfer outputs for export to the Verus chain.
        //
        // 4. Conversion distribution transactions for all native and reserve currency conversions, including reserve transfer outputs without conversion as
        //    a second step for reserve transfers that have conversion included. Any remaining pre-converted reserve must always remain in a change output
        //    until it is exhausted
        CTxOut premineOut;

        // size of conversion tx
        std::vector<CInputDescriptor> conversionInputs;

        // if we are a PBaaS chain, first make sure we don't start prematurely, and if
        // we should make an earned notarization, make it and set index to non-zero value
        int32_t notarizationTxIndex = 0;                            // index of notarization if it is added
        int32_t conversionTxIndex = 0;                              // index of conversion transaction if it is added

        // export transactions can be created here by aggregating all pending transfer requests and either getting 10 or more together, or
        // waiting n (10) blocks since the last one. each export must spend the output of the one before it
        std::vector<CMutableTransaction> exportTransactions;

        // all transaction outputs requesting conversion to another currency (PBaaS fractional reserve only)
        // these will be used to calculate conversion price, fees, and generate coinbase conversion output as well as the
        // conversion output transaction
        std::vector<CTxOut> reserveConversionTo;
        std::vector<CTxOut> reserveConversionFrom;

        int64_t pbaasTransparentIn = 0;
        int64_t pbaasTransparentOut = 0;
        //extern int64_t ASSETCHAINS_SUPPLY;
        //printf("%lu premine\n", ASSETCHAINS_SUPPLY);
        int64_t blockSubsidy = GetBlockSubsidy(nHeight, consensusParams);

        uint160 thisChainID = ConnectedChains.ThisChain().GetID();

        uint256 mmrRoot;
        vector<CInputDescriptor> notarizationInputs;

        // used as scratch for making CCs, should be reinitialized each time
        CCcontract_info CC;
        CCcontract_info *cp;
        std::vector<CTxDestination> dests;
        CPubKey pkCC;

        // Create coinbase tx and set up the null input with height
        CMutableTransaction coinbaseTx = CreateNewContextualCMutableTransaction(consensusParams, nHeight);
        coinbaseTx.vin.push_back(CTxIn(uint256(), (uint32_t)-1, CScript() << nHeight << OP_0));

        CAmount totalEmission = blockSubsidy;
        CCurrencyValueMap additionalFees;

        // if we don't have a connected root PBaaS chain, we can't properly check
        // and notarize the start block, so we have to pass the notarization and cross chain steps
        bool notaryConnected = ConnectedChains.IsNotaryAvailable();
        uint32_t solutionVersion = CConstVerusSolutionVector::GetVersionByHeight(nHeight);

        if (isVerusActive &&
            solutionVersion >= CActivationHeight::ACTIVATE_PBAAS &&
            !notaryConnected)
        {
            // until we have connected to the ETH bridge, after PBaaS has launched, we check each block to see if there is now an
            // ETH bridge defined
            if (ConnectedChains.FirstNotaryChain().IsValid())
            {
                // once PBaaS is active, we attempt to connect to the Ethereum bridge, in case it is active
                notaryConnected = ConnectedChains.IsNotaryAvailable(true);
            }
            else
            {
                notaryConnected = ConnectedChains.ConfigureEthBridge(true);
            }
        }

        // at block 1 for a PBaaS chain, we validate launch conditions
        bool isPBaaSBlock1 = !isVerusActive && nHeight == 1;
        if (isPBaaSBlock1)
        {
            CPBaaSNotarization launchNotarization;

            if (!ConnectedChains.readyToStart &&
                !ConnectedChains.CheckVerusPBaaSAvailable())
            {
                return NULL;
            }
            coinbaseTx.vout.insert(coinbaseTx.vout.end(), minerOutputs.begin(), minerOutputs.end());
            if (!MakeBlockOneCoinbaseOutputs(coinbaseTx.vout, launchNotarization, additionalFees))
            {
                // can't mine block 1 if we are not connected to a notary
                printf("%s: cannot create block one coinbase outputs\n", __func__);
                LogPrintf("%s: cannot create block one coinbase outputs\n", __func__);
                return NULL;
            }
            currencyState = launchNotarization.currencyState;
        }

        // if we can, notarize
        if (nHeight > ConnectedChains.ThisChain().GetMinBlocksToSignNotarize() && !VERUS_NOTARYID.IsNull())
        {
            CValidationState state;
            std::vector<TransactionBuilder> notarizationBuilders;
            std::vector<CTransaction> notarizations;
            CTransaction notarizationTx;
            const CRPCChainData &notaryChain = ConnectedChains.FirstNotaryChain();
            if (notaryChain.IsValid() &&
                CPBaaSNotarization::ConfirmOrRejectNotarizations(pwalletMain, ConnectedChains.FirstNotaryChain(), state, notarizationBuilders, Mining_height) &&
                notarizationBuilders.size())
            {
                int txCount = 0;

                // check to see if there is a finalization already in the mem pool, and if so, skip making it
                COptCCParams optP;
                CObjectFinalization finalization;

                uint160 searchID = CCrossChainRPCData::GetConditionID(CObjectFinalization::ObjectFinalizationFinalizedKey(),
                                                                      finalization.output.hash,
                                                                      finalization.output.n);

                std::vector<std::pair<uint160, int>> addresses =
                                        std::vector<std::pair<uint160, int>>({std::pair<uint160, int>({searchID, CScript::P2IDX})});
                std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> results;

                if (!(notarizationBuilders.back().mtx.vout.size() &&
                      notarizationBuilders.back().mtx.vout.back().scriptPubKey.IsPayToCryptoCondition(optP) &&
                      optP.IsValid() &&
                      optP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                      optP.vData.size() &&
                      (finalization = CObjectFinalization(optP.vData[0])).IsValid() &&
                      finalization.IsConfirmed() &&
                      mempool.getAddressIndex(addresses, results) &&
                      results.size()))
                {
                    for (int i = 0; i < notarizationBuilders.size(); i++)
                    {
                        auto &notarizationBuilder = notarizationBuilders[i];

                        if (!notarizationBuilder.mtx.vin.size())
                        {
                            bool success = false;
                            CCurrencyValueMap reserveValueOut;
                            CAmount nativeValueOut = 0;
                            // get a native currency input capable of paying a fee, and make our notary ID the change address
                            std::set<std::pair<const CWalletTx *, unsigned int>> setCoinsRet;
                            {
                                LOCK2(cs_main, pwalletMain->cs_wallet);
                                std::vector<COutput> vCoins;
                                CTxDestination notaryDest(VERUS_NOTARYID);
                                if (IsVerusActive())
                                {
                                    CCurrencyValueMap totalTxFees;
                                    totalTxFees.valueMap[ASSETCHAINS_CHAINID] = CPBaaSNotarization::DEFAULT_NOTARIZATION_FEE;
                                    nativeValueOut = CPBaaSNotarization::DEFAULT_NOTARIZATION_FEE;
                                    pwalletMain->AvailableReserveCoins(vCoins,
                                                                    false,
                                                                    nullptr,
                                                                    true,
                                                                    true,
                                                                    &notaryDest,
                                                                    &totalTxFees,
                                                                    false);
                                    success = pwalletMain->SelectCoinsMinConf(CPBaaSNotarization::DEFAULT_NOTARIZATION_FEE, 0, 0, vCoins, setCoinsRet, nativeValueOut);
                                    notarizationBuilder.SetFee(CPBaaSNotarization::DEFAULT_NOTARIZATION_FEE);
                                }
                                else
                                {
                                    // first try to pay with native currency, then the notary chain's currency
                                    CCurrencyValueMap totalTxFees({ConnectedChains.FirstNotaryChain().chainDefinition.GetID(), ASSETCHAINS_CHAINID},
                                                                   {CPBaaSNotarization::DEFAULT_NOTARIZATION_FEE, CPBaaSNotarization::DEFAULT_NOTARIZATION_FEE});
                                    nativeValueOut = CPBaaSNotarization::DEFAULT_NOTARIZATION_FEE;
                                    notarizationBuilder.SetReserveFee(CCurrencyValueMap());
                                    notarizationBuilder.SetFee(nativeValueOut);
                                    pwalletMain->AvailableReserveCoins(vCoins,
                                                                    false,
                                                                    nullptr,
                                                                    true,
                                                                    true,
                                                                    &notaryDest,
                                                                    &totalTxFees,
                                                                    false);

                                    success = pwalletMain->SelectReserveCoinsMinConf(CCurrencyValueMap(),
                                                                                    nativeValueOut,
                                                                                    0,
                                                                                    1,
                                                                                    vCoins,
                                                                                    setCoinsRet,
                                                                                    reserveValueOut,
                                                                                    nativeValueOut);

                                    // if we don't have enough native currency, use notary chain's
                                    if (!success)
                                    {
                                        nativeValueOut = 0;
                                        totalTxFees.valueMap.erase(ASSETCHAINS_CHAINID);
                                        notarizationBuilder.SetReserveFee(totalTxFees);
                                        notarizationBuilder.SetFee(0);
                                        success = pwalletMain->SelectReserveCoinsMinConf(totalTxFees,
                                                                                         nativeValueOut,
                                                                                         0,
                                                                                         1,
                                                                                         vCoins,
                                                                                         setCoinsRet,
                                                                                         reserveValueOut,
                                                                                         nativeValueOut);
                                    }
                                }
                            }
                            if (success)
                            {
                                for (auto &oneInput : setCoinsRet)
                                {
                                    notarizationBuilder.AddTransparentInput(COutPoint(oneInput.first->GetHash(), oneInput.second),
                                                                            oneInput.first->vout[oneInput.second].scriptPubKey,
                                                                            oneInput.first->vout[oneInput.second].nValue);
                                }
                                notarizationBuilder.SendChangeTo(CTxDestination(VERUS_NOTARYID));
                            }
                        }
                        else
                        {
                            notarizationBuilder.SetFee(0);
                        }

                        std::vector<TransactionBuilderResult> buildResultVec;

                        {
                            LOCK2(cs_main, pwalletMain->cs_wallet);
                            buildResultVec.push_back(notarizationBuilder.Build());
                        }
                        if (buildResultVec.back().IsTx())
                        {
                            notarizationTx = buildResultVec[0].GetTxOrThrow();
                            bool relayTx = false;
                            {
                                std::list<CTransaction> removedTxVec;
                                LOCK(cs_main);
                                LOCK2(smartTransactionCS, mempool.cs);
                                mempool.removeConflicts(notarizationTx, removedTxVec);
                                CValidationState mempoolState;
                                relayTx = myAddtomempool(notarizationTx, &state, 0, false);
                                if (LogAcceptCategory("notarization"))
                                {
                                    for (auto oneTx : removedTxVec)
                                    {
                                        if (LogAcceptCategory("verbose"))
                                        {
                                            UniValue jsonNTx(UniValue::VOBJ);
                                            TxToUniv(oneTx, uint256(), jsonNTx);
                                            LogPrintf("%s: transaction removed from mempool due to conflicts:\n%s\n", __func__, jsonNTx.write(1,2).c_str());
                                        }
                                        else
                                        {
                                            LogPrintf("%s: transaction removed from mempool due to conflicts:\n%s\n", __func__, oneTx.GetHash().GetHex().c_str());
                                        }
                                    }
                                    if (!relayTx)
                                    {
                                        if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                                        {
                                            UniValue jsonNTx(UniValue::VOBJ);
                                            TxToUniv(notarizationTx, uint256(), jsonNTx);
                                            LogPrintf("%s: failed to add transaction to mempool:\n%s\n", __func__, jsonNTx.write(1,2).c_str());
                                        }
                                        else
                                        {
                                            LogPrintf("%s: failed to add transaction to mempool:\n%s\n", __func__, notarizationTx.GetHash().GetHex().c_str());
                                        }
                                    }
                                }
                            }
                            if (relayTx)
                            {
                                notarizations.push_back(notarizationTx);

                                // if this is not the last transaction we make, then we add a spend of the 0th output,
                                // which is a rolled up finalization of prior evidence to the last tx
                                if ((i + 1) < notarizationBuilders.size())
                                {
                                    notarizationBuilders.back().AddTransparentInput(COutPoint(notarizationTx.GetHash(), 0),
                                                                                    notarizationTx.vout[0].scriptPubKey,
                                                                                    notarizationTx.vout[0].nValue);
                                }
                            }
                            else
                            {
                                LogPrintf("%s: Failed to add transaction to mempool, reason: %s\n", __func__, state.GetRejectReason());
                                break;
                            }
                        }
                        else
                        {
                            printf("%s: (PII) error adding notary evidence: %s\n", __func__, buildResultVec[0].GetError().c_str());
                            LogPrint("notarization", "%s: (PII) error adding notary evidence: %s\n", __func__, buildResultVec[0].GetError().c_str());
                            break;
                        }
                    }

                    if (notarizations.size() == notarizationBuilders.size())
                    {
                        if (LogAcceptCategory("notarization"))
                        {
                            LogPrintf("%s: Committed %d notarization transactions to mempool\n", __func__, txCount);
                        }
                        LOCK(cs_main);
                        for (auto &oneTx : notarizations)
                        {
                            RelayTransaction(oneTx);
                        }
                    }
                    else
                    {
                        LOCK(mempool.cs);
                        // we failed to put them in
                        for (auto &oneTx : notarizations)
                        {
                            std::list<CTransaction> removed;
                            mempool.remove(oneTx, removed, true);
                        }
                    }
                }
            }
        }

        // we will update amounts and fees later, but convert the guarded output now for validity checking and size estimate
        // VerusPoP staking transaction data
        CMutableTransaction txStaked;           // if this is a stake operation, the staking transaction that goes at the end
        uint32_t nStakeTxSize = 0;              // serialized size of the stake transaction

        // if this is not for mining, first determine if we have a right to make a block
        if (isStake)
        {
            uint64_t txfees, utxovalue;
            uint32_t txtime;
            uint256 utxotxid;
            int32_t i, siglen, numsigs, utxovout;
            std::vector<unsigned char> utxosig;

            txStaked = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nHeight);

            uint32_t nBitsPOS;
            arith_uint256 posHash;

            siglen = verus_staked(pblock, txStaked, nBitsPOS, posHash, utxosig, firstDestination);
            blocktime = GetAdjustedTime();

            bool stakeValid = siglen > 0;

            if (stakeValid)
            {
                pblock->nTime = blocktime;
                nStakeTxSize = GetSerializeSize(txStaked, SER_NETWORK, PROTOCOL_VERSION);
                nBlockSize += nStakeTxSize;
            }

            // if there is a specific destination, use it
            CTransaction stakeTx(txStaked);
            CStakeParams p;

            if (stakeValid && ValidateStakeTransaction(stakeTx, p, false))
            {
                if (p.Version() < p.VERSION_EXTENDED_STAKE && !p.pk.IsValid())
                {
                    LogPrintf("CreateNewBlock: invalid public key\n");
                    fprintf(stderr,"CreateNewBlock: invalid public key\n");
                }
                else
                {
                    CTxDestination guardedOutputDest = (p.Version() < p.VERSION_EXTENDED_STAKE) ? p.pk : p.delegate;
                    coinbaseTx.vout.push_back(CTxOut(1, CScript()));
                    if (!MakeGuardedOutput(1, guardedOutputDest, stakeTx, coinbaseTx.vout.back()))
                    {
                        LogPrintf("CreateNewBlock: failed to make GuardedOutput on staking coinbase\n");
                        fprintf(stderr,"CreateNewBlock: failed to make GuardedOutput on staking coinbase\n");
                    }
                    else
                    {
                        COptCCParams optP;
                        if (!coinbaseTx.vout.back().scriptPubKey.IsPayToCryptoCondition(optP) || !optP.IsValid())
                        {
                            if (LogAcceptCategory("notarization"))
                            {
                                MakeGuardedOutput(1, guardedOutputDest, stakeTx, coinbaseTx.vout.back());
                            }
                            LogPrintf("%s: created invalid staking coinbase\n", __func__);
                            fprintf(stderr,"%s: created invalid staking coinbase\n", __func__);
                        }
                        else
                        {
                            stakeValid = true;
                        }
                    }
                }
            }
            if (!stakeValid)
            {
                if (notaryConnected)
                {
                    CPBaaSNotarization lastImportNotarization;
                    CUTXORef lastImportNotarizationUTXO;
                    CValidationState state;

                    CPBaaSNotarization::SubmitFinalizedNotarizations(ConnectedChains.FirstNotaryChain(), state);
                    ProcessNewImports(ConnectedChains.FirstNotaryChain().chainDefinition.GetID(), lastImportNotarization, lastImportNotarizationUTXO, nHeight);
                }
                return NULL;
            }
        }
        else if (!isPBaaSBlock1)
        {
            // default outputs for mining and before stake guard or fee calculation
            // store the relative weight in the amount output to convert later to a relative portion
            // of the reward + fees
            coinbaseTx.vout.insert(coinbaseTx.vout.end(), minerOutputs.begin(), minerOutputs.end());
        }

        ConnectedChains.AggregateChainTransfers(DestinationToTransferDestination(firstDestination), nHeight);

        if (notaryConnected)
        {
            // if we should make an earned notarization, do so
            if (nHeight != 1 && !(VERUS_NOTARYID.IsNull() && VERUS_DEFAULTID.IsNull() && VERUS_NODEID.IsNull()))
            {
                CTransferDestination proposer;
                if (firstDestination.which() == COptCCParams::ADDRTYPE_INVALID)
                {
                    proposer = DestinationToTransferDestination(CIdentityID(VERUS_DEFAULTID.IsNull() ? (VERUS_NODEID.IsNull() ? VERUS_NOTARYID : VERUS_NODEID) : VERUS_DEFAULTID));
                }
                else
                {
                    proposer = DestinationToTransferDestination(firstDestination.which() == COptCCParams::ADDRTYPE_PK ? CKeyID(GetDestinationID(firstDestination)) : firstDestination);
                }

                // if we have access to our notary daemon
                // create a notarization if we would qualify to do so. add it to the mempool and next block
                ChainMerkleMountainView mmv = chainActive.GetMMV();
                mmrRoot = mmv.GetRoot();
                int32_t confirmedInput = -1;
                CValidationState state;
                CPBaaSNotarization earnedNotarization;

                int numOuts = coinbaseTx.vout.size();
                if (CPBaaSNotarization::CreateEarnedNotarization(ConnectedChains.FirstNotaryChain(),
                                                                 proposer,
                                                                 isStake,
                                                                 state,
                                                                 coinbaseTx.vout,
                                                                 earnedNotarization) &&
                    numOuts != coinbaseTx.vout.size() &&
                    LogAcceptCategory("notarization"))
                {
                    LogPrintf("%s: entering earned notarization into block %u, notarization: %s\n", __func__, Mining_height, earnedNotarization.ToUniValue().write(1,2).c_str());
                }
                CPBaaSNotarization lastImportNotarization;
                CUTXORef lastImportNotarizationUTXO;

                CPBaaSNotarization::SubmitFinalizedNotarizations(ConnectedChains.FirstNotaryChain(), state);
                ProcessNewImports(ConnectedChains.FirstNotaryChain().chainDefinition.GetID(), lastImportNotarization, lastImportNotarizationUTXO, nHeight);
            }
        }

        // done calling out, take locks for the rest
        LOCK(cs_main);
        LOCK2(smartTransactionCS, mempool.cs);

        CCoinsViewCache view(pcoinsTip);
        SaplingMerkleTree sapling_tree;

        if (!(view.GetSaplingAnchorAt(view.GetBestAnchor(SAPLING), sapling_tree)))
        {
            LogPrintf("%s: failed to get Sapling anchor\n", __func__);
            assert(false);
        }

        totalEmission = GetBlockSubsidy(nHeight, consensusParams);
        blockSubsidy = totalEmission;

        // PBaaS chain's block 1 currency state is done by the time we get here,
        // including pre-allocations, etc.
        if (isVerusActive || nHeight != 1)
        {
            currencyState.UpdateWithEmission(totalEmission);
        }

        // process any imports from the current chain to itself
        ConnectedChains.ProcessLocalImports();

        CFeePool feePool;
        if (!CFeePool::GetCoinbaseFeePool(feePool, nHeight - 1) ||
            (!feePool.IsValid() && CConstVerusSolutionVector::GetVersionByHeight(nHeight - 1) >= CActivationHeight::ACTIVATE_PBAAS))
        {
            // we should be able to get a valid currency state, if not, fail
            LogPrintf("Failure to get fee pool information for blockchain height #%d\n", nHeight - 1);
            printf("Failure to get fee pool information for blockchain height #%d\n", nHeight - 1);
            return NULL;
        }

        if (solutionVersion >= CActivationHeight::ACTIVATE_PBAAS && !feePool.IsValid())
        {
            // first block with a fee pool, so make it valid and empty
            feePool = CFeePool();
        }

        // coinbase should have all necessary outputs
        uint32_t nCoinbaseSize = GetSerializeSize(coinbaseTx, SER_NETWORK, PROTOCOL_VERSION);
        nBlockSize += nCoinbaseSize;

        // now create the priority array, including market order reserve transactions, since they can always execute, leave limits for later
        bool haveReserveTransactions = false;
        uint32_t reserveExchangeLimitSize = 0;
        std::vector<CReserveTransactionDescriptor> limitOrders;

        if (LogAcceptCategory("createblock"))
        {
            UniValue getrawmempool(const UniValue& params, bool fHelp);
            LogPrint("createblock", "%s: mempool: %s\n", __func__, getrawmempool(UniValue(UniValue::VARR), false).write(1,2).c_str());
        }

        // store export counts to ensure we don't exceed any limits
        std::set<uint160> newIDRegistrations;
        std::map<uint160, std::pair<int32_t, int32_t>> exportTransferCount;
        std::map<uint160, int32_t> currencyExportTransferCount;
        std::map<uint160, int32_t> identityExportTransferCount;

        std::set<uint160> currencyImports;
        std::set<std::pair<uint160, uint160>> idDestAndExport;
        std::set<std::pair<uint160, uint160>> currencyDestAndExport;

        std::set<std::tuple<uint160, uint160>> idSecondLegExport;
        std::set<std::tuple<uint160, uint160>> currencySecondLegExport;

        // we enforce the numeric limits on transactions in precheck exports
        std::map<uint160, std::pair<int32_t, int32_t>> tmpExportTransfers;
        std::map<uint160, int32_t> tmpCurrencyExportTransfers;
        std::map<uint160, int32_t> tmpIdentityExportTransfers;

        std::set<uint160> tmpNewIDRegistrations;
        std::set<uint160> tmpCurrencyImports;
        std::set<std::pair<uint160, uint160>> tmpIDDestAndExport;
        std::set<std::pair<uint160, uint160>> tmpCurrencyDestAndExport;

        std::set<std::tuple<uint160, uint160>> tmpIDSecondLegExport;
        std::set<std::tuple<uint160, uint160>> tmpCurrencySecondLegExport;

        std::list<CTransaction> txesToRemove;
        std::set<CUTXORef> orphanArbs;

        // now add transactions from the mem pool to the priority heap
        for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi)
        {
            const CTransaction& tx = mi->GetTx();
            uint256 hash = tx.GetHash();

            int64_t nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
            ? nMedianTimePast
            : pblock->GetBlockTime();

            CValidationState state;

            if (!IsFinalTx(tx, nHeight, nLockTimeCutoff))
            {
                continue;
            }
            if (tx.IsCoinBase() ||
                IsExpiredTx(tx, nHeight) ||
                (mi->GetHeight() != nHeight &&
                 !ContextualCheckTransaction(tx, state, Params(), nHeight, 0)))
            {
                txesToRemove.push_back(tx);
                continue;
            }

            COrphan* porphan = NULL;
            double dPriority = 0;
            CAmount nTotalIn = 0;
            CCurrencyValueMap totalReserveIn;
            bool fMissingInputs = false;
            CReserveTransactionDescriptor rtxd;
            bool isReserve = mempool.IsKnownReserveTransaction(hash, rtxd);

            CAmount delayedFee = 0;
            if (isReserve)
            {
                nTotalIn += rtxd.nativeIn;
                totalReserveIn = rtxd.ReserveInputMap();
                assert(!totalReserveIn.valueMap.count(ASSETCHAINS_CHAINID));

                if (rtxd.IsReserveTransfer() || rtxd.IsImport())
                {
                    for (int j = 0; j < tx.vout.size(); j++)
                    {
                        auto &oneOut = tx.vout[j];
                        COptCCParams p;
                        uint160 oneIdID;
                        if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                            p.IsValid() &&
                            p.version >= p.VERSION_V3 &&
                            p.vData.size())
                        {
                            if (p.evalCode == EVAL_CROSSCHAIN_IMPORT)
                            {
                                // make sure we spend all of our arbs via imports
                                CCrossChainImport cci, sysCCI;
                                CCrossChainExport ccx;
                                int primaryImportOut;
                                int32_t sysCCIOut, notarizationOut, evidenceOutStart, evidenceOutEnd;
                                CPBaaSNotarization importNotarization;
                                CCurrencyDefinition destSystem;
                                std::vector<CReserveTransfer> reserveTransfers;
                                std::vector<CTransaction> arbTxes;
                                std::vector<CUTXORef> arbTxOuts;
                                if ((cci = CCrossChainImport(p.vData[0])).IsValid() &&
                                    !cci.IsSourceSystemImport() &&
                                    (reserveTransfers = cci.GetArbitrageTransfers(tx, state, nHeight, &arbTxes, &arbTxOuts)).size())
                                {
                                    for (auto &oneRef : arbTxOuts)
                                    {
                                        orphanArbs.erase(oneRef);
                                    }
                                }
                            }
                            else if (p.evalCode == EVAL_RESERVE_TRANSFER)
                            {
                                //if the destination currency is fractional, this considers the total fee that
                                // will actually be realized on import as fee for prioritization

                                // make sure we don't export the same identity or currency to the same destination more than once in any block
                                // we cover the single block case here, and the protocol for each must reject anything relating to prior blocks
                                CReserveTransfer rt;
                                CCurrencyDefinition destSystem;
                                if ((rt = CReserveTransfer(p.vData[0])).IsValid())
                                {
                                    if (rt.IsArbitrageOnly())
                                    {
                                        orphanArbs.insert(CUTXORef(tx.GetHash(), j));
                                    }
                                    uint160 destCurrencyID = rt.GetImportCurrency();
                                    CCurrencyDefinition destCurrency = ConnectedChains.GetCachedCurrency(destCurrencyID);
                                    CCurrencyDefinition destSystem = ConnectedChains.GetCachedCurrency(destCurrency.SystemOrGatewayID());
                                    CCurrencyDefinition secondLegSystem;

                                    if (!destCurrency.IsValid() || !destSystem.IsValid())
                                    {
                                        if (LogAcceptCategory("crosschainexports"))
                                        {
                                            UniValue jsonTx(UniValue::VOBJ);
                                            TxToUniv(tx, uint256(), jsonTx);
                                            printf("%s: invalid or inaccessible destination currency/system in reserve transfer in output %d on tx: %s\n", __func__, j, jsonTx.write(1,2).c_str());
                                            LogPrintf("%s: invalid or inaccessible destination currency/system in reserve transfer in output %d on tx: %s\n", __func__, j, jsonTx.write(1,2).c_str());
                                        }
                                        txesToRemove.push_back(tx);
                                        continue;
                                    }

                                    // determine second system dest if there is any, and enforce limits to that system as well
                                    if (rt.destination.HasGatewayLeg() && rt.destination.gatewayID != destSystem.GetID())
                                    {
                                        secondLegSystem = ConnectedChains.GetCachedCurrency(rt.destination.gatewayID);
                                        if (!secondLegSystem.IsValid())
                                        {
                                            if (LogAcceptCategory("crosschainexports"))
                                            {
                                                UniValue jsonTx(UniValue::VOBJ);
                                                TxToUniv(tx, uint256(), jsonTx);
                                                printf("%s: invalid or inaccessible second leg destination system in reserve transfer in output %d on tx: %s\n", __func__, j, jsonTx.write(1,2).c_str());
                                                LogPrintf("%s: invalid or inaccessible second leg destination system in reserve transfer in output %d on tx: %s\n", __func__, j, jsonTx.write(1,2).c_str());
                                            }
                                            txesToRemove.push_back(tx);
                                            continue;
                                        }
                                    }

                                    // if this is a conversion, estimate delayed converted fees
                                    if (destCurrency.IsFractional() &&
                                        rt.IsConversion() &&
                                        !rt.IsPreConversion() &&
                                        nHeight > destCurrency.startBlock)
                                    {
                                        CCurrencyValueMap delayedFees = rt.CalculateFee();
                                        if (delayedFees.valueMap.count(ASSETCHAINS_CHAINID))
                                        {
                                            delayedFee += delayedFees.valueMap[ASSETCHAINS_CHAINID];
                                            delayedFees.valueMap.erase(ASSETCHAINS_CHAINID);
                                        }
                                        if (delayedFees.valueMap.size())
                                        {
                                            CCoinbaseCurrencyState pricingState = ConnectedChains.GetCurrencyState(destCurrency, nHeight);
                                            for (auto &oneCurFee : delayedFees.valueMap)
                                            {
                                                delayedFee += pricingState.ReserveToNativeRaw(
                                                                    oneCurFee.second,
                                                                    pricingState.TargetConversionPrice(oneCurFee.first, ASSETCHAINS_CHAINID));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            for (int inNum = 0; inNum < tx.vin.size(); inNum++)
            {
                const CTxIn &txin = tx.vin[inNum];
                CAmount nValueIn = 0;
                CCurrencyValueMap reserveValueIn;

                // Read prev transaction
                if (!view.HaveCoins(txin.prevout.hash))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        LogPrintf("ERROR: mempool transaction missing input\n");
                        LogPrint("mempool", "mempool transaction missing input");
                        fMissingInputs = true;

                        txesToRemove.push_back(tx);
        
                        if (porphan)
                        {
                            for (int inNumStart = 0; inNumStart < inNum; inNumStart++)
                            {
                                auto depIt = mapDependers.find(tx.vin[inNumStart].prevout.hash);
                                if (depIt != mapDependers.end())
                                {
                                    for (auto orphanIt = depIt->second.end(); orphanIt != depIt->second.begin(); )
                                    {
                                        orphanIt--;
                                        if (*orphanIt == porphan)
                                        {
                                            bool isPriorIt = orphanIt != depIt->second.begin();
                                            auto nextIt = !isPriorIt ? depIt->second.end() : orphanIt;
                                            if (isPriorIt)
                                            {
                                                nextIt--;
                                            }
                                            depIt->second.erase(orphanIt);
                                            if (isPriorIt)
                                            {
                                                orphanIt = ++nextIt;
                                            }
                                            else
                                            {
                                                orphanIt = depIt->second.begin();
                                            }
                                        }
                                    }
                                    if (!depIt->second.size())
                                    {
                                        mapDependers.erase(tx.vin[inNumStart].prevout.hash);
                                    }
                                }
                            }
                            vOrphan.pop_back();
                        }
                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);

                    const CTransaction &otx = mempool.mapTx.find(txin.prevout.hash)->GetTx();
                    // consider reserve outputs and set priority according to their value here as well
                    if (isReserve)
                    {
                        totalReserveIn += otx.vout[txin.prevout.n].ReserveOutValue();
                    }
                    nTotalIn += otx.vout[txin.prevout.n].nValue;
                    continue;
                }
                const CCoins* coins = view.AccessCoins(txin.prevout.hash);
                assert(coins);

                if (isReserve)
                {
                    reserveValueIn = coins->vout[txin.prevout.n].ReserveOutValue();
                    totalReserveIn += reserveValueIn;
                }

                nValueIn = coins->vout[txin.prevout.n].nValue;
                int nConf = nHeight - coins->nHeight;

                dPriority += ((double)((reserveValueIn.valueMap.size() ? currencyState.ReserveToNative(reserveValueIn) : 1) + nValueIn)) * nConf;
                nTotalIn += nValueIn;
            }

            // prioritize notarizations, finalizations, and exports for our notary chain
            if (rtxd.IsNotaryPrioritized() || rtxd.IsExport())
            {
                // always very high priority
                dPriority += (double)(SATOSHIDEN * SATOSHIDEN);
            }
            nTotalIn += tx.GetShieldedValueIn();

            if (fMissingInputs) continue;

            // Priority is sum(valuein * age) / modified_txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority = tx.ComputePriority(dPriority, nTxSize);

            CAmount nDeltaValueIn = nTotalIn + (totalReserveIn.valueMap.count(VERUS_CHAINID) ? totalReserveIn.valueMap[VERUS_CHAINID] : 0);
            CAmount nFeeValueIn = nDeltaValueIn;
            mempool.ApplyDeltas(hash, dPriority, nDeltaValueIn);

            CFeeRate feeRate((nFeeValueIn + delayedFee) - tx.GetValueOut(), nTxSize);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->feeRate = feeRate;
            }
            else
            {
                vecPriTxMap.insert({tx.GetHash(), vecPriority.size()});
                vecPriority.push_back(TxPriority(dPriority, feeRate, &(mi->GetTx())));
            }
        }

        std::set<uint256> arbTxOrphans;
        for (auto &oneOrphanArb : orphanArbs)
        {
            arbTxOrphans.insert(oneOrphanArb.hash);
        }
        for (auto &oneTxToRemove : arbTxOrphans)
        {
            txesToRemove.push_back(*mempool.get(oneTxToRemove));
        }

        // remove transactions that we should from the mempool
        std::set<int> toRemoveFromPriVec;
        for (auto &oneTx : txesToRemove)
        {
            auto txPriLoc = vecPriTxMap.find(oneTx.GetHash());
            if (txPriLoc != vecPriTxMap.end())
            {
                toRemoveFromPriVec.insert(txPriLoc->second);
            }
            std::list<CTransaction> removed;
            mempool.remove(oneTx, removed, true);
            mapDependers.erase(oneTx.GetHash());
            for (auto &oneRemovedTx : removed)
            {
                txPriLoc = vecPriTxMap.find(oneRemovedTx.GetHash());
                if (txPriLoc != vecPriTxMap.end())
                {
                    toRemoveFromPriVec.insert(txPriLoc->second);
                }
                mapDependers.erase(oneRemovedTx.GetHash());
            }
        }
        txesToRemove.clear();

        for (auto rIt = toRemoveFromPriVec.rbegin(); rIt != toRemoveFromPriVec.rend(); rIt++)
        {
            vecPriority.erase(vecPriority.begin() + *rIt);
        }

        //
        // NOW -- REALLY START TO FILL THE BLOCK
        //
        // estimate number of conversions, staking transaction size, and additional coinbase outputs that will be required

        int32_t maxNormalTXBlockSize = nBlockMaxSize - autoTxSize;

        int64_t interest;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        if (LogAcceptCategory("createblock"))
        {
            printf("%s: vecPriority.size(): %d\n", __func__, (int)vecPriority.size());
        }

        // now loop and fill the block, leaving space for reserve exchange limit transactions
        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            CFeeRate feeRate = vecPriority.front().get<1>();
            const CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= maxNormalTXBlockSize) // room for extra autotx
            {
                LogPrint("mining", "nBlockSize %d + %d nTxSize >= %d maxNormalTXBlockSize\n",(int32_t)nBlockSize,(int32_t)nTxSize,(int32_t)maxNormalTXBlockSize);
                continue;
            }

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = GetLegacySigOpCount(tx);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS-1)
            {
                //fprintf(stderr,"A nBlockSigOps %d + %d nTxSigOps >= %d MAX_BLOCK_SIGOPS-1\n",(int32_t)nBlockSigOps,(int32_t)nTxSigOps,(int32_t)MAX_BLOCK_SIGOPS);
                continue;
            }
            // Skip free transactions if we're past the minimum block size:
            const uint256& hash = tx.GetHash();
            double dPriorityDelta = 0;
            CAmount nFeeDelta = 0;
            mempool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
            if (fSortedByFee && (dPriorityDelta <= 0) && (nFeeDelta <= 0) && (feeRate < ::minRelayTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
            {
                //fprintf(stderr,"fee rate skip\n");
                continue;
            }

            // Prioritise by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            if (!view.HaveInputs(tx))
            {
                //fprintf(stderr,"dont have inputs\n");
                continue;
            }

            CAmount nTxFees;
            CReserveTransactionDescriptor rtxd;
            bool isReserve = mempool.IsKnownReserveTransaction(hash, rtxd);

            nTxFees = view.GetValueIn(chainActive.LastTip()->GetHeight(),&interest,tx,chainActive.LastTip()->nTime) - tx.GetValueOut();

            nTxSigOps += GetP2SHSigOpCount(tx, view);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS-1)
            {
                //fprintf(stderr,"B nBlockSigOps %d + %d nTxSigOps >= %d MAX_BLOCK_SIGOPS-1\n",(int32_t)nBlockSigOps,(int32_t)nTxSigOps,(int32_t)MAX_BLOCK_SIGOPS);
                continue;
            }

            // Note that flags: we don't want to set mempool/IsStandard()
            // policy here, but we still have to ensure that the block we
            // create only contains transactions that are valid in new blocks.
            CValidationState state;
            PrecomputedTransactionData txdata(tx);
            if (!ContextualCheckInputs(tx, state, view, nHeight, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true, txdata, Params().GetConsensus(), consensusBranchId))
            {
                //fprintf(stderr,"context failure\n");
                continue;
            }

            bool usedImportExportIDCounters = false;

            // first, eliminate conflicts at the output level, then we can verify inputs
            if (isReserve)
            {
                // we have already looped through to determine these things, so don't do it again if we know it's not them
                if (rtxd.IsValid() && (rtxd.IsIdentityDefinition() || rtxd.IsImport() || rtxd.IsExport() || rtxd.IsReserveTransfer()))
                {
                    // this is in the prioritization loop to eliminate dups early and
                    // enable consideration of delayed reserve transfer rewards when prioritizing
                    //
                    // go through all outputs and record all currency and identity definitions, either import-based definitions or
                    // identity reservations to check for collision, which is disallowed
                    bool disqualified = false;
                    bool isImport = false;
                    for (int j = 0; j < tx.vout.size(); j++)
                    {
                        auto &oneOut = tx.vout[j];
                        COptCCParams p;
                        uint160 oneIdID;
                        if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                            p.IsValid() &&
                            p.version >= p.VERSION_V3 &&
                            p.vData.size())
                        {
                            switch (p.evalCode)
                            {
                                case EVAL_IDENTITY_ADVANCEDRESERVATION:
                                {
                                    CAdvancedNameReservation advNameRes;
                                    if ((advNameRes = CAdvancedNameReservation(p.vData[0])).IsValid() &&
                                        (oneIdID = advNameRes.parent, advNameRes.name == CleanName(advNameRes.name, oneIdID, true)) &&
                                        !(oneIdID = CIdentity::GetID(advNameRes.name, oneIdID)).IsNull() &&
                                        !newIDRegistrations.count(oneIdID) &&
                                        !tmpNewIDRegistrations.count(oneIdID))
                                    {
                                        usedImportExportIDCounters = true;
                                        tmpNewIDRegistrations.insert(oneIdID);
                                    }
                                    else
                                    {
                                        disqualified = true;
                                    }
                                    break;
                                }

                                case EVAL_IDENTITY_RESERVATION:
                                {
                                    CNameReservation nameRes;
                                    if ((nameRes = CNameReservation(p.vData[0])).IsValid() &&
                                        nameRes.name == CleanName(nameRes.name, oneIdID) &&
                                        !(oneIdID = CIdentity::GetID(nameRes.name, oneIdID)).IsNull() &&
                                        !newIDRegistrations.count(oneIdID) &&
                                        !tmpNewIDRegistrations.count(oneIdID))
                                    {
                                        usedImportExportIDCounters = true;
                                        tmpNewIDRegistrations.insert(oneIdID);
                                    }
                                    else
                                    {
                                        disqualified = true;
                                    }
                                    break;
                                }

                                case EVAL_CROSSCHAIN_EXPORT:
                                {
                                    // make sure we don't export the same identity or currency to the same destination more than once in any block
                                    // we cover the single block case here, and the protocol for each must reject anything invalid on prior blocks
                                    CCrossChainExport ccx;
                                    int primaryExportOut;
                                    int32_t nextOutput;
                                    CPBaaSNotarization exportNotarization;
                                    CCurrencyDefinition destSystem;
                                    std::vector<CReserveTransfer> reserveTransfers;
                                    if ((ccx = CCrossChainExport(p.vData[0])).IsValid() &&
                                        !ccx.IsSystemThreadExport() &&
                                        (destSystem = ConnectedChains.GetCachedCurrency(ccx.destSystemID)).IsValid() &&
                                        (destSystem.IsGateway() || destSystem.IsPBaaSChain()) &&
                                        destSystem.SystemOrGatewayID() != ASSETCHAINS_CHAINID &&
                                        ccx.GetExportInfo(tx, j, primaryExportOut, nextOutput, exportNotarization, reserveTransfers, state,
                                                (CCurrencyDefinition::EProofProtocol)(destSystem.IsGateway() ?
                                                    destSystem.proofProtocol :
                                                    ConnectedChains.ThisChain().proofProtocol)))
                                    {
                                        for (auto &oneTransfer : reserveTransfers)
                                        {
                                            if (oneTransfer.IsCurrencyExport())
                                            {
                                                std::pair<uint160, uint160> checkKey({ccx.destSystemID, oneTransfer.FirstCurrency()});
                                                usedImportExportIDCounters = true;
                                                tmpCurrencyDestAndExport.insert(checkKey);
                                            }
                                            else if (oneTransfer.IsIdentityExport())
                                            {
                                                std::pair<uint160, uint160> checkKey({ccx.destSystemID, GetDestinationID(TransferDestinationToDestination(oneTransfer.destination))});
                                                usedImportExportIDCounters = true;
                                                tmpIDDestAndExport.insert(checkKey);
                                            }
                                        }
                                    }
                                    break;
                                }

                                case EVAL_CROSSCHAIN_IMPORT:
                                {
                                    isImport = true;
                                    break;
                                }

                                case EVAL_RESERVE_TRANSFER:
                                {
                                    //if the destination currency is fractional, this considers the total fee that
                                    // will actually be realized on import as fee for prioritization

                                    // make sure we don't export the same identity or currency to the same destination more than once in any block
                                    // we cover the single block case here, and the protocol for each must reject anything relating to prior blocks
                                    CReserveTransfer rt;
                                    CCurrencyDefinition destSystem;
                                    if ((rt = CReserveTransfer(p.vData[0])).IsValid())
                                    {
                                        uint160 destCurrencyID = rt.GetImportCurrency();
                                        CCurrencyDefinition destCurrency = ConnectedChains.GetCachedCurrency(destCurrencyID);
                                        CCurrencyDefinition destSystem = ConnectedChains.GetCachedCurrency(destCurrency.SystemOrGatewayID());
                                        CCurrencyDefinition secondLegSystem;

                                        if (!destCurrency.IsValid() || !destSystem.IsValid())
                                        {
                                            if (LogAcceptCategory("crosschainexports"))
                                            {
                                                UniValue jsonTx(UniValue::VOBJ);
                                                TxToUniv(tx, uint256(), jsonTx);
                                                printf("%s: invalid or inaccessible destination currency/system in reserve transfer in output %d on tx: %s\n", __func__, j, jsonTx.write(1,2).c_str());
                                                LogPrintf("%s: invalid or inaccessible destination currency/system in reserve transfer in output %d on tx: %s\n", __func__, j, jsonTx.write(1,2).c_str());
                                            }
                                            txesToRemove.push_back(tx);
                                            disqualified = true;
                                            break;
                                        }

                                        // determine second system dest if there is any, and enforce limits to that system as well
                                        if (rt.destination.HasGatewayLeg() && rt.destination.gatewayID != destSystem.GetID())
                                        {
                                            secondLegSystem = ConnectedChains.GetCachedCurrency(rt.destination.gatewayID);
                                            if (!secondLegSystem.IsValid())
                                            {
                                                if (LogAcceptCategory("crosschainexports"))
                                                {
                                                    UniValue jsonTx(UniValue::VOBJ);
                                                    TxToUniv(tx, uint256(), jsonTx);
                                                    printf("%s: invalid or inaccessible second leg destination system in reserve transfer in output %d on tx: %s\n", __func__, j, jsonTx.write(1,2).c_str());
                                                    LogPrintf("%s: invalid or inaccessible second leg destination system in reserve transfer in output %d on tx: %s\n", __func__, j, jsonTx.write(1,2).c_str());
                                                }
                                                txesToRemove.push_back(tx);
                                                disqualified = true;
                                                break;
                                            }
                                        }

                                        // all reserve transfers use the counters
                                        usedImportExportIDCounters = true;

                                        if (destCurrency.SystemOrGatewayID() != ASSETCHAINS_CHAINID ||
                                            (secondLegSystem.IsValid() && secondLegSystem.GetID() != ASSETCHAINS_CHAINID))
                                        {
                                            bool checkSecondLeg = secondLegSystem.IsValid() &&
                                                                    secondLegSystem.SystemOrGatewayID() != ASSETCHAINS_CHAINID &&
                                                                    secondLegSystem.SystemOrGatewayID() != destCurrency.SystemOrGatewayID();
                                            if (checkSecondLeg)
                                            {
                                                uint160 secondLegID = secondLegSystem.SystemOrGatewayID();
                                                if ((++tmpExportTransfers[secondLegID].first + exportTransferCount[secondLegID].first) > secondLegSystem.MaxTransferExportCount() ||
                                                    ((tmpExportTransfers[secondLegID].second += oneOut.scriptPubKey.size()) +
                                                        exportTransferCount[secondLegID].second) > secondLegSystem.MaxTransferExportSize())
                                                {
                                                    disqualified = true;
                                                    break;
                                                }
                                            }

                                            if (rt.IsCurrencyExport())
                                            {
                                                if (destCurrency.SystemOrGatewayID() != ASSETCHAINS_CHAINID)
                                                {
                                                    std::pair<uint160, uint160> checkKey({destCurrency.SystemOrGatewayID(), rt.FirstCurrency()});
                                                    if (!isImport && (currencyDestAndExport.count(checkKey) || tmpCurrencyDestAndExport.count(checkKey)))
                                                    {
                                                        disqualified = true;
                                                        break;
                                                    }
                                                    tmpCurrencyDestAndExport.insert(checkKey);
                                                }
                                                if (checkSecondLeg)
                                                {
                                                    std::pair<uint160, uint160> checkKey({secondLegSystem.SystemOrGatewayID(), rt.FirstCurrency()});
                                                    if (!isImport && (currencyDestAndExport.count(checkKey) || tmpCurrencyDestAndExport.count(checkKey)))
                                                    {
                                                        disqualified = true;
                                                        break;
                                                    }
                                                    tmpCurrencyDestAndExport.insert(checkKey);

                                                    uint160 secondLegID = secondLegSystem.SystemOrGatewayID();
                                                    if ((++tmpCurrencyExportTransfers[secondLegID] + currencyExportTransferCount[secondLegID]) > secondLegSystem.MaxCurrencyDefinitionExportCount())
                                                    {
                                                        disqualified = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            else if (rt.IsIdentityExport())
                                            {
                                                if (destCurrency.SystemOrGatewayID() != ASSETCHAINS_CHAINID)
                                                {
                                                    std::pair<uint160, uint160> checkKey({destCurrency.SystemOrGatewayID(), GetDestinationID(TransferDestinationToDestination(rt.destination))});
                                                    if (!isImport && (idDestAndExport.count(checkKey) || tmpIDDestAndExport.count(checkKey)))
                                                    {
                                                        disqualified = true;
                                                        break;
                                                    }
                                                    tmpIDDestAndExport.insert(checkKey);
                                                }
                                                if (checkSecondLeg)
                                                {
                                                    std::pair<uint160, uint160> checkKey({secondLegSystem.SystemOrGatewayID(), GetDestinationID(TransferDestinationToDestination(rt.destination))});
                                                    if (!isImport && (idDestAndExport.count(checkKey) || tmpIDDestAndExport.count(checkKey)))
                                                    {
                                                        disqualified = true;
                                                        break;
                                                    }
                                                    tmpIDDestAndExport.insert(checkKey);

                                                    uint160 secondLegID = secondLegSystem.SystemOrGatewayID();
                                                    if ((++tmpIdentityExportTransfers[secondLegID] + identityExportTransferCount[secondLegID]) > secondLegSystem.MaxIdentityDefinitionExportCount())
                                                    {
                                                        disqualified = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        }

                                        if ((++tmpExportTransfers[destCurrencyID].first + exportTransferCount[destCurrencyID].first) > destSystem.MaxTransferExportCount() ||
                                            ((tmpExportTransfers[destCurrencyID].second += oneOut.scriptPubKey.size()) +
                                                        exportTransferCount[destCurrencyID].second) > secondLegSystem.MaxTransferExportSize() ||
                                            (rt.IsCurrencyExport() && (++tmpCurrencyExportTransfers[destCurrencyID] + currencyExportTransferCount[destCurrencyID]) > destSystem.MaxCurrencyDefinitionExportCount()) ||
                                            (rt.IsIdentityExport() && (++tmpIdentityExportTransfers[destCurrencyID] + identityExportTransferCount[destCurrencyID]) > destSystem.MaxIdentityDefinitionExportCount()))
                                        {
                                            disqualified = true;
                                            break;
                                        }
                                    }
                                    break;
                                }
                            }
                            if (disqualified)
                            {
                                break;
                            }
                        }
                    }
                    if (disqualified)
                    {
                        if (LogAcceptCategory("createblock"))
                        {
                            UniValue jsonTxOut(UniValue::VOBJ);
                            TxToUniv(tx, uint256(), jsonTxOut);
                            printf("%s: disqualified transaction (dup ID or currency): %s\n", __func__, jsonTxOut.write(1,2).c_str());
                            LogPrintf("%s: disqualified transaction (dup ID or currency): %s\n", __func__, jsonTxOut.write(1,2).c_str());
                        }
                        continue;
                    }
                }
            }

            if (usedImportExportIDCounters)
            {
                // update total counts
                for (auto it = tmpExportTransfers.begin(); it != tmpExportTransfers.end(); it++)
                {
                    exportTransferCount[it->first].first += it->second.first;
                    exportTransferCount[it->first].second += it->second.second;
                }
                tmpExportTransfers.clear();
                for (auto it = tmpCurrencyExportTransfers.begin(); it != tmpCurrencyExportTransfers.end(); it++)
                {
                    currencyExportTransferCount[it->first] += it->second;
                }
                tmpCurrencyExportTransfers.clear();
                for (auto it = tmpIdentityExportTransfers.begin(); it != tmpIdentityExportTransfers.end(); it++)
                {
                    identityExportTransferCount[it->first] += it->second;
                }
                tmpIdentityExportTransfers.clear();

                // update import and export combinations
                for (auto it = tmpNewIDRegistrations.begin(); it != tmpNewIDRegistrations.end(); it++)
                {
                    newIDRegistrations.insert(*it);
                }
                tmpNewIDRegistrations.clear();
                for (auto it = tmpCurrencyImports.begin(); it != tmpCurrencyImports.end(); it++)
                {
                    currencyImports.insert(*it);
                }
                tmpCurrencyImports.clear();
                for (auto it = tmpIDDestAndExport.begin(); it != tmpIDDestAndExport.end(); it++)
                {
                    idDestAndExport.insert(*it);
                }
                tmpIDDestAndExport.clear();
                for (auto it = tmpCurrencyDestAndExport.begin(); it != tmpCurrencyDestAndExport.end(); it++)
                {
                    currencyDestAndExport.insert(*it);
                }
                tmpCurrencyDestAndExport.clear();
            }

            UpdateCoins(tx, view, nHeight);

            if (isReserve)
            {
                haveReserveTransactions = true;
                additionalFees += rtxd.ReserveFees();
            }

            BOOST_FOREACH(const OutputDescription &outDescription, tx.vShieldedOutput) {
                sapling_tree.append(outDescription.cm);
            }

            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;
            if (fPrintPriority)
            {
                LogPrintf("priority %.1f fee %s txid %s\n",dPriority, feeRate.ToString(), tx.GetHash().ToString());
            }

            // Add transactions that depend on this one to the priority queue
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->feeRate, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        // remove transactions that we should from the mempool
        for (auto &oneTx : txesToRemove)
        {
            std::list<CTransaction> removed;
            mempool.remove(oneTx, removed, true);
        }

        // first calculate and distribute block rewards, including fees in the minerOutputs vector
        CAmount rewardTotalShareAmount = 0;
        CAmount rewardFees = nFees;
        if (additionalFees.valueMap.count(thisChainID))
        {
            rewardFees += additionalFees.valueMap[thisChainID];
            additionalFees.valueMap.erase(thisChainID);
        }

        CAmount verusFees = 0;
        if (VERUS_CHAINID != ASSETCHAINS_CHAINID && additionalFees.valueMap.count(VERUS_CHAINID))
        {
            verusFees += additionalFees.valueMap[VERUS_CHAINID];
            additionalFees.valueMap.erase(VERUS_CHAINID);
        }

        if (additionalFees.valueMap.size())
        {
            printf("%s: burning reserve currency: %s\n", __func__, additionalFees.ToUniValue().write(1,2).c_str());
        }

        if (feePool.IsValid())
        {
            // we support only the current native currency or VRSC on PBaaS chains in the fee pool for now
            feePool.reserveValues.valueMap[thisChainID] += rewardFees;
            if (verusFees)
            {
                feePool.reserveValues.valueMap[VERUS_CHAINID] += verusFees;
            }
            CFeePool oneFeeShare = feePool.OneFeeShare();
            rewardFees = oneFeeShare.reserveValues.valueMap[thisChainID];
            feePool.reserveValues.valueMap[thisChainID] -= rewardFees;

            if (VERUS_CHAINID != ASSETCHAINS_CHAINID && oneFeeShare.reserveValues.valueMap.count(VERUS_CHAINID))
            {
                verusFees = oneFeeShare.reserveValues.valueMap[VERUS_CHAINID];
                feePool.reserveValues.valueMap[VERUS_CHAINID] -= verusFees;
            }

            cp = CCinit(&CC, EVAL_FEE_POOL);
            pkCC = CPubKey(ParseHex(CC.CChexstr));
            coinbaseTx.vout.push_back(CTxOut(0,MakeMofNCCScript(CConditionObj<CFeePool>(EVAL_FEE_POOL,{pkCC.GetID()},1,&feePool))));
        }

        // printf("%s: rewardfees: %ld, verusfees: %ld\n", __func__, rewardFees, verusFees);

        CAmount rewardTotal = blockSubsidy + rewardFees;

        // now that we have the total reward, update the coinbase outputs
        if (isStake)
        {
            coinbaseTx.vout[0].nValue = rewardTotal;
            COptCCParams stakeP;
            if (!IsVerusActive() &&
                verusFees &&
                coinbaseTx.vout[0].scriptPubKey.IsPayToCryptoCondition(stakeP) &&
                stakeP.IsValid())
            {
                std::vector<CTxDestination> outDests = stakeP.vKeys;
                CTokenOutput to = CTokenOutput(VERUS_CHAINID, verusFees);
                coinbaseTx.vout.insert(coinbaseTx.vout.end() - 1, CTxOut(0, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, stakeP.vKeys, stakeP.m, &to))));
            }
        }
        else
        {
            for (auto &outputShare : minerOutputs)
            {
                rewardTotalShareAmount += outputShare.nValue;
            }

            int cbOutIdx;
            CAmount rewardLeft = rewardTotal;
            CAmount verusFeeLeft = verusFees;
            for (cbOutIdx = 0; cbOutIdx < minerOutputs.size(); cbOutIdx++)
            {
                CAmount amount = (arith_uint256(rewardTotal) * arith_uint256(minerOutputs[cbOutIdx].nValue) / arith_uint256(rewardTotalShareAmount)).GetLow64();
                if (rewardLeft <= amount || (cbOutIdx + 1) == minerOutputs.size())
                {
                    amount = rewardLeft;
                }
                rewardLeft -= amount;

                // now make outputs for non-native, VRSC fees
                if (verusFeeLeft)
                {
                    CAmount verusFee = (arith_uint256(verusFees) * arith_uint256(minerOutputs[cbOutIdx].nValue) / arith_uint256(rewardTotalShareAmount)).GetLow64();
                    if (verusFeeLeft <= verusFee || (cbOutIdx + 1) == minerOutputs.size())
                    {
                        verusFee = verusFeeLeft;
                    }
                    CTxDestination minerDestination;
                    if (verusFee >= CFeePool::MIN_SHARE_SIZE && ExtractDestination(coinbaseTx.vout[cbOutIdx].scriptPubKey, minerDestination))
                    {
                        CTokenOutput to = CTokenOutput(VERUS_CHAINID, verusFee);
                        coinbaseTx.vout[cbOutIdx].scriptPubKey = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT,
                                                                                  std::vector<CTxDestination>({minerDestination}),
                                                                                  1,
                                                                                  &to));
                    }
                    verusFeeLeft -= verusFee;
                }

                // we had to wait to update this here to ensure it represented a correct distribution ratio
                coinbaseTx.vout[cbOutIdx].nValue = amount;
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        blocktime = std::max(pindexPrev->GetMedianTimePast(), GetAdjustedTime());

        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());

        coinbaseTx.nExpiryHeight = 0;
        coinbaseTx.nLockTime = blocktime;

        // finalize input of coinbase
        coinbaseTx.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(0)) + COINBASE_FLAGS;
        assert(coinbaseTx.vin[0].scriptSig.size() <= 100);

        // coinbase is done
        pblock->vtx[0] = coinbaseTx;
        uint256 cbHash = coinbaseTx.GetHash();

        // display it at block 1 for PBaaS debugging
        /* if (nHeight == 1)
        {
            UniValue jsonTxOut(UniValue::VOBJ);
            TxToUniv(coinbaseTx, uint256(), jsonTxOut);
            printf("%s: new coinbase transaction: %s\n", __func__, jsonTxOut.write(1,2).c_str());
        } */

        // if there is a stake transaction, add it to the very end
        if (isStake)
        {
            UpdateCoins(txStaked, view, nHeight);
            pblock->vtx.push_back(txStaked);
            pblocktemplate->vTxFees.push_back(0);
            int txSigOps = GetLegacySigOpCount(txStaked);
            pblocktemplate->vTxSigOps.push_back(txSigOps);
            // already added to the block size above
            ++nBlockTx;
            nBlockSigOps += txSigOps;
        }

        pblock->vtx[0] = coinbaseTx;
        pblocktemplate->vTxFees[0] = -nFees;
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);

        // if not Verus stake, setup nonce, otherwise, leave it alone
        if (!isStake)
        {
            if (useNonce.IsNull())
            {
                pblock->nNonce = RandomizedNonce();
            }
            else
            {
                pblock->nNonce = useNonce;
            }
        }

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        pblock->hashFinalSaplingRoot   = sapling_tree.root();

        // all Verus PBaaS chains need this data in the block at all times
        UpdateTime(pblock, Params().GetConsensus(), pindexPrev);
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());
    }
    //fprintf(stderr,"done new block\n");

    // setup the header and buid the Merkle tree
    unsigned int extraNonce = 0;
    IncrementExtraNonce(pblock, pindexPrev, extraNonce, true);

    return pblocktemplate.release();
}

CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const CScript& _scriptPubKeyIn, bool isStake, uint256 useNonce)
{
    std::vector<CTxOut> minerOutputs = _scriptPubKeyIn.size() ? std::vector<CTxOut>({CTxOut(1, _scriptPubKeyIn)}) : std::vector<CTxOut>();
    return CreateNewBlock(chainparams, minerOutputs, isStake, useNonce);
}

//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//

#ifdef ENABLE_MINING

class MinerAddressScript : public CReserveScript
{
    // CReserveScript requires implementing this function, so that if an
    // internal (not-visible) wallet address is used, the wallet can mark it as
    // important when a block is mined (so it then appears to the user).
    // If -mineraddress is set, the user already knows about and is managing the
    // address, so we don't need to do anything here.
    void KeepScript() {}
};

void GetScriptForMinerAddress(boost::shared_ptr<CReserveScript> &script)
{
    CTxDestination addr = DecodeDestination(GetArg("-mineraddress", ""));
    if (!IsValidDestination(addr)) {
        return;
    }

    boost::shared_ptr<MinerAddressScript> mAddr(new MinerAddressScript());
    script = mAddr;
    script->reserveScript = GetScriptForDestination(addr);
}

#ifdef ENABLE_WALLET
//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//

CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey, int32_t nHeight, bool isStake, uint256 useNonce)
{
    CPubKey pubkey;
    CScript scriptPubKey;
    uint8_t *ptr;
    int32_t i;
    boost::shared_ptr<CReserveScript> coinbaseScript;

    UniValue miningDistributionUni;
    if (!GetArg("-miningdistribution", "").empty() &&
        (miningDistributionUni = getminingdistribution(UniValue(UniValue::VARR), false)).isObject() &&
        miningDistributionUni.size())
    {
        std::vector<CTxOut> minerOutputs;
        auto rewardAddresses = miningDistributionUni.getKeys();
        for (int i = 0; i < rewardAddresses.size(); i++)
        {
            CTxDestination oneDest = DecodeDestination(rewardAddresses[i]);
            CAmount relVal = 0;
            if (oneDest.which() == COptCCParams::ADDRTYPE_INVALID ||
                !(relVal = AmountFromValue(find_value(miningDistributionUni, rewardAddresses[i]))))
            {
                continue;
            }
            minerOutputs.push_back(CTxOut(relVal, GetScriptForDestination(oneDest)));
        }
        if (minerOutputs.size())
        {
            return CreateNewBlock(Params(), minerOutputs, false, useNonce);
        }
        LogPrintf("%s: invalid -miningdistribution parameter\n", __func__);
    }
    if ( nHeight == 1 && ASSETCHAINS_OVERRIDE_PUBKEY33[0] != 0 )
    {
        scriptPubKey = CScript() << ParseHex(ASSETCHAINS_OVERRIDE_PUBKEY) << OP_CHECKSIG;
    }
    else if ( USE_EXTERNAL_PUBKEY != 0 )
    {
        //fprintf(stderr,"use notary pubkey\n");
        scriptPubKey = CScript() << ParseHex(NOTARY_PUBKEY) << OP_CHECKSIG;
    }
    else if (GetArg("-mineraddress", "").empty() || !(GetScriptForMinerAddress(coinbaseScript), (scriptPubKey = coinbaseScript->reserveScript).size()))
    {
        if (!isStake)
        {
            if (!reservekey.GetReservedKey(pubkey))
            {
                return NULL;
            }
            scriptPubKey = GetScriptForDestination(pubkey);
        }
    }
    return CreateNewBlock(Params(), scriptPubKey, isStake, useNonce);
}

void komodo_broadcast(const CBlock *pblock,int32_t limit)
{
    int32_t n = 1;
    //fprintf(stderr,"broadcast new block t.%u\n",(uint32_t)time(NULL));
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
            if ( pnode->hSocket == INVALID_SOCKET )
                continue;
            if ( (rand() % n) == 0 )
            {
                pnode->PushMessage("block", *pblock);
                if ( n++ > limit )
                    break;
            }
        }
    }
    //fprintf(stderr,"finished broadcast new block t.%u\n",(uint32_t)time(NULL));
}

static bool ProcessBlockFound(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
#else
static bool ProcessBlockFound(CBlock* pblock)
#endif // ENABLE_WALLET
{
    int32_t height = chainActive.LastTip()->GetHeight()+1;
    //LogPrintf("%s\n", pblock->ToString());
    LogPrintf("generated %s height.%d\n", FormatMoney(pblock->vtx[0].vout[0].nValue), height);

    // Found a solution
    {
        if (pblock->hashPrevBlock != chainActive.LastTip()->GetBlockHash())
        {
            uint256 hash; int32_t i;
            hash = pblock->hashPrevBlock;
            for (i=31; i>=0; i--)
                fprintf(stderr,"%02x",((uint8_t *)&hash)[i]);
            fprintf(stderr," <- prev (stale)\n");
            hash = chainActive.LastTip()->GetBlockHash();
            for (i=31; i>=0; i--)
                fprintf(stderr,"%02x",((uint8_t *)&hash)[i]);
            fprintf(stderr," <- chainTip (stale)\n");

            return error("VerusMiner: generated block is stale");
        }
    }

#ifdef ENABLE_WALLET
    // Remove key from key pool
    if ( IS_KOMODO_NOTARY == 0 )
    {
        if (GetArg("-mineraddress", "").empty()) {
            // Remove key from key pool
            reservekey.KeepKey();
        }
    }
    // Track how many getdata requests this block gets
    //if ( 0 )
    {
        //fprintf(stderr,"lock cs_wallet\n");
        LOCK(wallet.cs_wallet);
        wallet.mapRequestCount[pblock->GetHash()] = 0;
    }
#endif
    //fprintf(stderr,"process new block\n");

    // Process this block (almost) the same as if we had received it from another node
    CValidationState state;
    if (!ProcessNewBlock(1, chainActive.LastTip()->GetHeight()+1, state, Params(), NULL, pblock, true, NULL))
        return error("VerusMiner: ProcessNewBlock, block not accepted");

    TrackMinedBlock(pblock->GetHash());
    komodo_broadcast(pblock,16);
    return true;
}

int32_t komodo_baseid(char *origbase);
int32_t komodo_eligiblenotary(uint8_t pubkeys[66][33],int32_t *mids,uint32_t *blocktimes,int32_t *nonzpkeysp,int32_t height);
arith_uint256 komodo_PoWtarget(int32_t *percPoSp,arith_uint256 target,int32_t height,int32_t goalperc);
int32_t FOUND_BLOCK,KOMODO_MAYBEMINED;
extern int32_t KOMODO_LASTMINED,KOMODO_INSYNC;
int32_t roundrobin_delay;
arith_uint256 HASHTarget,HASHTarget_POW;
int32_t komodo_longestchain();

// wait for peers to connect
void waitForPeers(const CChainParams &chainparams)
{
    if (chainparams.MiningRequiresPeers())
    {
        bool fvNodesEmpty;
        {
            boost::this_thread::interruption_point();
            LOCK(cs_vNodes);
            fvNodesEmpty = vNodes.empty();
        }
        int longestchain = komodo_longestchain();
        int lastlongest = 0;
        if (fvNodesEmpty || IsNotInSync() || (longestchain != 0 && longestchain > chainActive.LastTip()->GetHeight()))
        {
            int loops = 0, blockDiff = 0, newDiff = 0;

            do {
                if (fvNodesEmpty)
                {
                    MilliSleep(1000 + rand() % 4000);
                    boost::this_thread::interruption_point();
                    LOCK(cs_vNodes);
                    fvNodesEmpty = vNodes.empty();
                    loops = 0;
                    blockDiff = 0;
                    lastlongest = 0;
                }
                else if ((newDiff = IsNotInSync()) > 0)
                {
                    if (blockDiff != newDiff)
                    {
                        blockDiff = newDiff;
                    }
                    else
                    {
                        if (++loops <= 5)
                        {
                            MilliSleep(1000);
                        }
                        else break;
                    }
                    lastlongest = 0;
                }
                else if (!fvNodesEmpty && !IsNotInSync() && longestchain > chainActive.LastTip()->GetHeight())
                {
                    // the only thing may be that we are seeing a long chain that we'll never get
                    // don't wait forever
                    if (lastlongest == 0)
                    {
                        MilliSleep(3000);
                        lastlongest = longestchain;
                    }
                }
            } while (fvNodesEmpty || IsNotInSync());
            MilliSleep(500 + rand() % 1000);
        }
    }
}

#ifdef ENABLE_WALLET
CBlockIndex *get_chainactive(int32_t height)
{
    if ( chainActive.LastTip() != 0 )
    {
        if ( height <= chainActive.LastTip()->GetHeight() )
        {
            LOCK(cs_main);
            return(chainActive[height]);
        }
        // else fprintf(stderr,"get_chainactive height %d > active.%d\n",height,chainActive.Tip()->GetHeight());
    }
    //fprintf(stderr,"get_chainactive null chainActive.Tip() height %d\n",height);
    return(0);
}

/*
 * A separate thread to stake, while the miner threads mine.
 */
void static VerusStaker(CWallet *pwallet)
{
    LogPrintf("Verus staker thread started\n");
    RenameThread("verus-staker");

    const CChainParams& chainparams = Params();
    auto consensusParams = chainparams.GetConsensus();
    bool isNotaryConnected = ConnectedChains.CheckVerusPBaaSAvailable();

    // Each thread has its own key
    CReserveKey reservekey(pwallet);

    // Each thread has its own counter
    unsigned int nExtraNonce = 0;

    uint8_t *script; uint64_t total,checktoshis; int32_t i,j;

    while ( (ASSETCHAIN_INIT == 0 || KOMODO_INITDONE == 0) ) //chainActive.Tip()->GetHeight() != 235300 &&
    {
        sleep(1);
        if ( komodo_baseid(ASSETCHAINS_SYMBOL) < 0 )
            break;
    }

    // try a nice clean peer connection to start
    CBlockIndex *pindexPrev, *pindexCur;
    do {
        pindexPrev = chainActive.LastTip();
        MilliSleep(5000 + rand() % 5000);
        waitForPeers(chainparams);
        pindexCur = chainActive.LastTip();
    } while (pindexPrev != pindexCur);

    try {
        static int32_t lastStakingHeight = 0;

        while (true)
        {
            waitForPeers(chainparams);
            CBlockIndex* pindexPrev = chainActive.LastTip();

            // Create new block
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();

            if ( Mining_height != pindexPrev->GetHeight()+1 )
            {
                Mining_height = pindexPrev->GetHeight()+1;
                Mining_start = (uint32_t)time(NULL);
            }

            // Check for stop or if block needs to be rebuilt
            boost::this_thread::interruption_point();

            // try to stake a block
            CBlockTemplate *ptr = NULL;

            // get height locally for consistent reporting
            int32_t newHeight = Mining_height;

            if (newHeight > VERUS_MIN_STAKEAGE)
                ptr = CreateNewBlockWithKey(reservekey, newHeight, true);

            // TODO - putting this output here tends to help mitigate announcing a staking height earlier than
            // announcing the last block win when we start staking before a block's acceptance has been
            // acknowledged by the mining thread - a better solution may be to put the output on the submission
            // thread.
            if ( ptr == 0 && newHeight != lastStakingHeight )
            {
                printf("Staking height %d for %s\n", newHeight, ASSETCHAINS_SYMBOL);
            }
            lastStakingHeight = newHeight;

            if ( ptr == 0 )
            {
                if (newHeight == 1 && (isNotaryConnected = ConnectedChains.IsNotaryAvailable()))
                {
                    static int outputCounter;
                    if (outputCounter++ % 60 == 0)
                    {
                        printf("%s: waiting for confirmation of launch at or after block %u on %s before mining block 1\n", __func__,
                                                                                        (uint32_t)ConnectedChains.ThisChain().startBlock,
                                                                                        ConnectedChains.FirstNotaryChain().chainDefinition.name.c_str());
                        sleep(1);
                    }
                }
                // wait to try another staking block until after the tip moves again
                while ( chainActive.LastTip() == pindexPrev )
                    MilliSleep(250);
                if (newHeight == 1)
                {
                    sleep(10);
                }
                continue;
            }

            unique_ptr<CBlockTemplate> pblocktemplate(ptr);
            if (!pblocktemplate.get())
            {
                if (GetArg("-mineraddress", "").empty()) {
                    LogPrintf("Error in %s staker: Keypool ran out, please call keypoolrefill before restarting the mining thread\n",
                              ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
                } else {
                    // Should never reach here, because -mineraddress validity is checked in init.cpp
                    LogPrintf("Error in %s staker: Invalid %s -mineraddress\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO], ASSETCHAINS_SYMBOL);
                }
                return;
            }

            CBlock *pblock = &pblocktemplate->block;
            LogPrint("staking", "Staking with %u transactions in block (%u bytes)\n", pblock->vtx.size(),::GetSerializeSize(*pblock,SER_NETWORK,PROTOCOL_VERSION));
            //
            // Search
            //
            int64_t nStart = GetTime();

            if (vNodes.empty() && chainparams.MiningRequiresPeers())
            {
                if ( Mining_height > ASSETCHAINS_MINHEIGHT )
                {
                    fprintf(stderr,"no nodes, attempting reconnect\n");
                    continue;
                }
            }

            if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
            {
                fprintf(stderr,"timeout, retrying\n");
                continue;
            }

            if ( pindexPrev != chainActive.LastTip() )
            {
                printf("Block %d added to chain\n", chainActive.LastTip()->GetHeight());
                MilliSleep(250);
                continue;
            }

            int64_t subsidy = (int64_t)(pblock->vtx[0].vout[0].nValue);

            uint256 hashTarget = ArithToUint256(arith_uint256().SetCompact(pblock->nBits));

            pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

            UpdateTime(pblock, consensusParams, pindexPrev);

            if (ProcessBlockFound(pblock, *pwallet, reservekey))
            {
                LogPrintf("Using %s algorithm:\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
                LogPrintf("Staked block found  \n  hash: %s  \ntarget: %s\n", pblock->GetHash().GetHex(), hashTarget.GetHex());
                printf("Found block %d \n", newHeight);
                printf("staking reward %.8f %s!\n", (double)subsidy / (double)COIN, ASSETCHAINS_SYMBOL);
                arith_uint256 post;
                post.SetCompact(pblock->GetVerusPOSTarget());

                CTransaction &sTx = pblock->vtx[pblock->vtx.size()-1];
                printf("POS hash: %s  \ntarget:   %s\n\n",
                    CTransaction::_GetVerusPOSHash(&(pblock->nNonce),
                                                     sTx.vin[0].prevout.hash,
                                                     sTx.vin[0].prevout.n,
                                                     newHeight,
                                                     chainActive.GetVerusEntropyHash(newHeight),
                                                     sTx.vout[0].nValue).GetHex().c_str(),
                                                     ArithToUint256(post).GetHex().c_str());
            }
            else
            {
                LogPrintf("Found block rejected at staking height: %d\n", Mining_height);
                printf("Found block rejected at staking height: %d\n", Mining_height);
            }

            // Check for stop or if block needs to be rebuilt
            boost::this_thread::interruption_point();

            sleep(3);

            // In regression test mode, stop mining after a block is found.
            if (chainparams.MineBlocksOnDemand()) {
                throw boost::thread_interrupted();
            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("VerusStaker terminated\n");
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("VerusStaker runtime error: %s\n", e.what());
        return;
    }
}

typedef bool (*minefunction)(CBlockHeader &bh, CVerusHashV2bWriter &vhw, uint256 &finalHash, uint256 &target, uint64_t start, uint64_t *count);
bool mine_verus_v2(CBlockHeader &bh, CVerusHashV2bWriter &vhw, uint256 &finalHash, uint256 &target, uint64_t start, uint64_t *count);
bool mine_verus_v2_port(CBlockHeader &bh, CVerusHashV2bWriter &vhw, uint256 &finalHash, uint256 &target, uint64_t start, uint64_t *count);

void static BitcoinMiner_noeq(CWallet *pwallet)
#else
void static BitcoinMiner_noeq()
#endif
{
    LogPrintf("%s miner started\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
    RenameThread("verushash-miner");

#ifdef ENABLE_WALLET
    // Each thread has its own key
    CReserveKey reservekey(pwallet);
#endif

    miningTimer.clear();

    const CChainParams& chainparams = Params();
    // Each thread has its own counter
    unsigned int nExtraNonce = 0;

    uint8_t *script; uint64_t total,checktoshis; int32_t i,j;

    while ( (ASSETCHAIN_INIT == 0 || KOMODO_INITDONE == 0) ) //chainActive.Tip()->GetHeight() != 235300 &&
    {
        sleep(1);
        if ( komodo_baseid(ASSETCHAINS_SYMBOL) < 0 )
            break;
    }

    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    // try a nice clean peer connection to start
    CBlockIndex *pindexPrev, *pindexCur;
    do {
        pindexPrev = chainActive.LastTip();
        MilliSleep(5000 + rand() % 5000);
        waitForPeers(chainparams);
        pindexCur = chainActive.LastTip();
    } while (pindexPrev != pindexCur);

    // make sure that we have checked for PBaaS availability
    ConnectedChains.CheckVerusPBaaSAvailable();

    // this will not stop printing more than once in all cases, but it will allow us to print in all cases
    // and print duplicates rarely without having to synchronize
    static CBlockIndex *lastChainTipPrinted;
    static int32_t lastMiningHeight = 0;

    miningTimer.start();
    bool mergeMining = false;

    try {
        printf("Mining %s with %s\n", ASSETCHAINS_SYMBOL, ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);

        while (true)
        {
            miningTimer.stop();
            waitForPeers(chainparams);

            pindexPrev = chainActive.LastTip();

            // prevent forking on startup before the diff algorithm kicks in,
            // but only for a startup Verus test chain. PBaaS chains have the difficulty inherited from
            // their parent
            if (chainparams.MiningRequiresPeers() && ((IsVerusActive() && pindexPrev->GetHeight() < 50) || pindexPrev != chainActive.LastTip()))
            {
                do {
                    pindexPrev = chainActive.LastTip();
                    MilliSleep(2000 + rand() % 2000);
                } while (pindexPrev != chainActive.LastTip());
            }

            // Create new block
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            if ( Mining_height != pindexPrev->GetHeight()+1 )
            {
                Mining_height = pindexPrev->GetHeight()+1;
                if (lastMiningHeight != Mining_height)
                {
                    lastMiningHeight = Mining_height;
                    printf("Mining %s at height %d\n", ASSETCHAINS_SYMBOL, Mining_height);
                }
                Mining_start = (uint32_t)time(NULL);
            }

            miningTimer.start();

            CBlock *pblock = nullptr;
            unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate);

            boost::shared_ptr<CReserveScript> tmpScript;
            if ((USE_EXTERNAL_PUBKEY != 0 ||
                 (!GetArg("-mineraddress", "").empty() && (GetScriptForMinerAddress(tmpScript), tmpScript->reserveScript.size())) ||
                 !GetArg("-miningdistribution", "").empty()) &&
                pblocktemplate.get() &&
                ConnectedChains.GetLastBlock(pblocktemplate->block, Mining_height))
            {
                pblock = &pblocktemplate->block;
            }
            else
            {
#ifdef ENABLE_WALLET
                CBlockTemplate *ptr = CreateNewBlockWithKey(reservekey, Mining_height);
#else
                CBlockTemplate *ptr = CreateNewBlockWithKey();
#endif
                if ( ptr == 0 )
                {
                    static uint32_t counter;
                    if ( counter++ % 40 == 0 )
                    {
                        if (!IsVerusActive() &&
                            ConnectedChains.IsNotaryAvailable() &&
                            !ConnectedChains.readyToStart)
                        {
                            fprintf(stderr,"waiting for confirmation of launch at or after block %u on %s chain to start\n", (uint32_t)ConnectedChains.ThisChain().startBlock,
                                                                                            ConnectedChains.FirstNotaryChain().chainDefinition.name.c_str());
                        }
                        else
                        {
                            fprintf(stderr,"Unable to create valid block... will continue to try\n");
                        }
                    }
                    MilliSleep(2000);
                    continue;
                }

                pblocktemplate = unique_ptr<CBlockTemplate>(ptr);
                if (!pblocktemplate.get())
                {
                    if (GetArg("-mineraddress", "").empty()) {
                        LogPrintf("Error in %s miner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n",
                                ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
                    } else {
                        // Should never reach here, because -mineraddress validity is checked in init.cpp
                        LogPrintf("Error in %s miner: Invalid %s -mineraddress\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO], ASSETCHAINS_SYMBOL);
                    }
                    miningTimer.stop();
                    miningTimer.clear();
                    return;
                }
                pblock = &pblocktemplate->block;
            }

            uint32_t savebits;
            savebits = pblock->nBits;

            uint32_t solutionVersion = CConstVerusSolutionVector::Version(pblock->nSolution);
            if (pblock->nVersion != CBlockHeader::VERUS_V2)
            {
                // must not be in sync
                printf("Mining on incorrect block version.\n");
                sleep(2);
                continue;
            }
            bool verusSolutionPBaaS = solutionVersion >= CActivationHeight::ACTIVATE_PBAAS;

            // v2 hash writer with adjustments for the current height
            CVerusHashV2bWriter ss2 = CVerusHashV2bWriter(SER_GETHASH, PROTOCOL_VERSION, solutionVersion);

            // randomize the nonce for each thread
            pblock->nNonce = RandomizedNonce();

            // set our easiest target, if V3+, no need to rebuild the merkle tree
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce, true, &savebits);

            // cache the last block or copy of last
            ConnectedChains.SetLastBlock(*pblock, Mining_height);

            // update PBaaS header
            if (verusSolutionPBaaS)
            {
                if (!IsVerusActive() && (mergeMining || ConnectedChains.IsVerusPBaaSAvailable()))
                {
                    UniValue params(UniValue::VARR);
                    UniValue error(UniValue::VARR);

                    bool tryAgain = true;
                    int retryCount = 0;
                    while (tryAgain && retryCount++ < 5)
                    {
                        tryAgain = false;
                        params.push_back(EncodeHexBlk(*pblock));
                        params.push_back(ASSETCHAINS_SYMBOL);
                        params.push_back(ASSETCHAINS_RPCHOST);
                        params.push_back(ASSETCHAINS_RPCPORT);
                        params.push_back(ASSETCHAINS_RPCCREDENTIALS);
                        try
                        {
                            ConnectedChains.lastSubmissionFailed = false;
                            params = RPCCallRoot("addmergedblock", params);
                            error = find_value(params, "error");
                            params = find_value(params, "result");
                        } catch (std::exception e)
                        {
                            LogPrintf("Failed to connect to %s chain\n", ConnectedChains.FirstNotaryChain().chainDefinition.name.c_str());
                            params = UniValue(e.what());
                        }
                        uint32_t nextBlockTime;
                        if (error.isNull() &&
                            params.isObject() &&
                            (nextBlockTime = (uint32_t)uni_get_int64(find_value(params, "nextblocktime"))) != 0)
                        {
                            ConnectedChains.SetNextBlockTime(nextBlockTime);
                            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce, true, &savebits);
                            ConnectedChains.SetLastBlock(*pblock, Mining_height);
                            params = UniValue(UniValue::VARR);
                            error = UniValue(UniValue::VARR);
                            tryAgain = true;
                        }
                    }

                    if (mergeMining && !(params.isNull() && error.isNull()))
                    {
                        printf("Lost connection to merge mining chain %s. Will attempt to retry. Restart mining to switch to solo\n", ConnectedChains.GetFriendlyCurrencyName(ConnectedChains.FirstNotaryChain().GetID()).c_str());
                        LogPrintf("Lost connection to merge mining chain %s. Will attempt to retry. Restart mining to switch to solo\n", ConnectedChains.GetFriendlyCurrencyName(ConnectedChains.FirstNotaryChain().GetID()).c_str());
                        for (int loop = 0; loop < 15; loop++)
                        {
                            sleep(1);
                            boost::this_thread::interruption_point();
                        }
                        continue;
                    }
                    mergeMining = (params.isNull() && error.isNull());
                    if (mergeMining)
                    {
                        printf("Merge mining %s with %s as the hashing chain\n", ASSETCHAINS_SYMBOL, ConnectedChains.FirstNotaryChain().chainDefinition.name.c_str());
                        LogPrintf("Merge mining with %s as the hashing chain\n", ConnectedChains.FirstNotaryChain().chainDefinition.name.c_str());
                    }
                }
            }

            LogPrintf("Running %s miner with %u transactions in block (%u bytes)\n",ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO],
                       pblock->vtx.size(),::GetSerializeSize(*pblock,SER_NETWORK,PROTOCOL_VERSION));
            //
            // Search
            //
            int64_t nStart = GetTime();

            arith_uint256 hashTarget = arith_uint256().SetCompact(savebits);
            uint256 uintTarget = ArithToUint256(hashTarget);
            arith_uint256 ourTarget;
            ourTarget.SetCompact(pblock->nBits);

            Mining_start = 0;

            if ( pindexPrev != chainActive.LastTip() )
            {
                if (lastChainTipPrinted != chainActive.LastTip())
                {
                    lastChainTipPrinted = chainActive.LastTip();
                    printf("Block %d added to chain\n", lastChainTipPrinted->GetHeight());
                }
                MilliSleep(100);
                continue;
            }

            uint64_t count;
            uint64_t hashesToGo = 0;
            uint64_t totalDone = 0;

            int64_t subsidy = (int64_t)(pblock->vtx[0].vout[0].nValue);
            count = ((ASSETCHAINS_NONCEMASK[ASSETCHAINS_ALGO] >> 3) + 1) / ASSETCHAINS_HASHESPERROUND[ASSETCHAINS_ALGO];
            CVerusHashV2 *vh2 = &ss2.GetState();
            u128 *hashKey;
            verusclhasher &vclh = vh2->vclh;
            minefunction mine_verus;
            mine_verus = IsCPUVerusOptimized() ? &mine_verus_v2 : &mine_verus_v2_port;

            while (true)
            {
                uint256 hashResult = uint256();

                unsigned char *curBuf;

                if (mergeMining)
                {
                    // loop for a few minutes before refreshing the block
                    while (true)
                    {
                        uint256 ourMerkle = pblock->hashMerkleRoot;
                        if ( pindexPrev != chainActive.LastTip() )
                        {
                            if (lastChainTipPrinted != chainActive.LastTip())
                            {
                                lastChainTipPrinted = chainActive.LastTip();
                                printf("Block %d added to chain\n\n", lastChainTipPrinted->GetHeight());
                                arith_uint256 target;
                                target.SetCompact(lastChainTipPrinted->nBits);
                                if (ourMerkle == lastChainTipPrinted->hashMerkleRoot)
                                {
                                    LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", lastChainTipPrinted->GetBlockHash().GetHex().c_str(), ArithToUint256(ourTarget).GetHex().c_str());
                                    printf("Found block %d \n", lastChainTipPrinted->GetHeight());
                                    printf("mining reward %.8f %s!\n", (double)subsidy / (double)COIN, ASSETCHAINS_SYMBOL);
                                    printf("  hash: %s\ntarget: %s\n", lastChainTipPrinted->GetBlockHash().GetHex().c_str(), ArithToUint256(ourTarget).GetHex().c_str());
                                }
                            }
                            break;
                        }

                        // if PBaaS is no longer available, we can't count on merge mining
                        if (!ConnectedChains.IsVerusPBaaSAvailable())
                        {
                            break;
                        }

                        if (vNodes.empty() && chainparams.MiningRequiresPeers())
                        {
                            if ( Mining_height > ASSETCHAINS_MINHEIGHT )
                            {
                                fprintf(stderr,"no nodes, attempting reconnect\n");
                                break;
                            }
                        }

                        // update every few minutes, regardless
                        int64_t elapsed = GetTime() - nStart;

                        if ((mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && elapsed > 30) || elapsed > 30 || ConnectedChains.lastSubmissionFailed)
                        {
                            break;
                        }

                        boost::this_thread::interruption_point();
                        MilliSleep(500);
                    }
                    break;
                }
                else
                {
                    // check NONCEMASK at a time
                    for (uint64_t i = 0; i < count; i++)
                    {
                        // this is the actual mining loop, which enables us to drop out and queue a header anytime we earn a block that is good enough for a
                        // merge mined block, but not our own
                        bool blockFound;
                        arith_uint256 arithHash;
                        totalDone = 0;
                        do
                        {
                            // pickup/remove any new/deleted headers
                            if (ConnectedChains.dirty || (pblock->NumPBaaSHeaders() < ConnectedChains.mergeMinedChains.size() + 1))
                            {
                                IncrementExtraNonce(pblock, pindexPrev, nExtraNonce, true, &savebits);

                                hashTarget.SetCompact(savebits);
                                uintTarget = ArithToUint256(hashTarget);
                            }

                            // hashesToGo gets updated with actual number run for metrics
                            hashesToGo = ASSETCHAINS_HASHESPERROUND[ASSETCHAINS_ALGO];
                            uint64_t start = i * hashesToGo + totalDone;
                            hashesToGo -= totalDone;

                            if (verusSolutionPBaaS)
                            {
                                // mine on canonical header for merge mining
                                CPBaaSPreHeader savedHeader(*pblock);

                                pblock->ClearNonCanonicalData();
                                blockFound = (*mine_verus)(*pblock, ss2, hashResult, uintTarget, start, &hashesToGo);
                                savedHeader.SetBlockData(*pblock);
                            }
                            else
                            {
                                blockFound = (*mine_verus)(*pblock, ss2, hashResult, uintTarget, start, &hashesToGo);
                            }

                            arithHash = UintToArith256(hashResult);
                            totalDone += hashesToGo + 1;
                            if (blockFound && IsVerusActive())
                            {
                                ConnectedChains.QueueNewBlockHeader(*pblock);
                                if (arithHash > ourTarget)
                                {
                                    // all blocks qualified with this hash will be submitted
                                    // until we redo the block, we might as well not try again with anything over this hash
                                    hashTarget = arithHash;
                                    uintTarget = ArithToUint256(hashTarget);
                                }
                            }
                        } while (blockFound && arithHash > ourTarget);

                        if (!blockFound || arithHash > ourTarget)
                        {
                            // Check for stop or if block needs to be rebuilt
                            boost::this_thread::interruption_point();
                            if ( pindexPrev != chainActive.LastTip() )
                            {
                                if (lastChainTipPrinted != chainActive.LastTip())
                                {
                                    lastChainTipPrinted = chainActive.LastTip();
                                    printf("Block %d added to chain\n", lastChainTipPrinted->GetHeight());
                                }
                                break;
                            }
                        }
                        else
                        {
                            // Check for stop or if block needs to be rebuilt
                            boost::this_thread::interruption_point();

                            if (pblock->nSolution.size() != 1344)
                            {
                                LogPrintf("ERROR: Block solution is not 1344 bytes as it should be");
                                break;
                            }

                            SetThreadPriority(THREAD_PRIORITY_NORMAL);

#ifdef VERUSHASHDEBUG
                            std::string validateStr = hashResult.GetHex();
                            std::string hashStr = pblock->GetHash().GetHex();
                            uint256 *bhalf1 = (uint256 *)vh2->CurBuffer();
                            uint256 *bhalf2 = bhalf1 + 1;
#else
                            std::string hashStr = hashResult.GetHex();
#endif

                            LogPrintf("Using %s algorithm:\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
                            LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hashStr, ArithToUint256(ourTarget).GetHex());
                            printf("Found block %d \n", Mining_height );
                            printf("mining reward %.8f %s!\n", (double)subsidy / (double)COIN, ASSETCHAINS_SYMBOL);
#ifdef VERUSHASHDEBUG
                            printf("  hash: %s\n   val: %s  \ntarget: %s\n\n", hashStr.c_str(), validateStr.c_str(), ArithToUint256(ourTarget).GetHex().c_str());
                            printf("intermediate %lx\n", intermediate);
                            printf("Curbuf: %s%s\n", bhalf1->GetHex().c_str(), bhalf2->GetHex().c_str());
                            bhalf1 = (uint256 *)verusclhasher_key.get();
                            bhalf2 = bhalf1 + ((vh2->vclh.keyMask + 1) >> 5);
                            printf("   Key: %s%s\n", bhalf1->GetHex().c_str(), bhalf2->GetHex().c_str());
#else
                            printf("  hash: %s\ntarget: %s", hashStr.c_str(), ArithToUint256(ourTarget).GetHex().c_str());
#endif
                            printf("\n");
#ifdef ENABLE_WALLET
                            ProcessBlockFound(pblock, *pwallet, reservekey);
#else
                            ProcessBlockFound(pblock);
#endif
                            SetThreadPriority(THREAD_PRIORITY_LOWEST);
                            break;
                        }

                        if ((i + 1) < count)
                        {
                            // if we haven't broken out and will not drop through, update hashcount
                            {
                                miningTimer += totalDone;
                            }
                        }
                    }

                    miningTimer += totalDone;
                }

                // Check for stop or if block needs to be rebuilt
                boost::this_thread::interruption_point();

                if (vNodes.empty() && chainparams.MiningRequiresPeers())
                {
                    if ( Mining_height > ASSETCHAINS_MINHEIGHT )
                    {
                        fprintf(stderr,"no nodes, attempting reconnect\n");
                        break;
                    }
                }

                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                {
                    fprintf(stderr,"timeout, retrying\n");
                    break;
                }

                if ( pindexPrev != chainActive.LastTip() )
                {
                    if (lastChainTipPrinted != chainActive.LastTip())
                    {
                        lastChainTipPrinted = chainActive.LastTip();
                        printf("Block %d added to chain\n\n", lastChainTipPrinted->GetHeight());
                    }
                    break;
                }

                // totalDone now has the number of hashes actually done since starting on one nonce mask worth
                uint64_t hashesPerNonceMask = ASSETCHAINS_NONCEMASK[ASSETCHAINS_ALGO] >> 3;
                if (!(totalDone < hashesPerNonceMask))
                {
                    printf("%" PRIu64 " mega hashes complete - working\n", (hashesPerNonceMask + 1) / 1048576);
                }
                break;

            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        miningTimer.stop();
        miningTimer.clear();
        LogPrintf("%s miner terminated\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
        throw;
    }
    catch (const std::runtime_error &e)
    {
        miningTimer.stop();
        miningTimer.clear();
        LogPrintf("%s miner runtime error: %s\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO], e.what());
        return;
    }
    miningTimer.stop();
    miningTimer.clear();
}

#ifdef ENABLE_WALLET
    void GenerateBitcoins(bool fGenerate, CWallet* pwallet, int nThreads)
#else
    void GenerateBitcoins(bool fGenerate, int nThreads)
#endif
    {
        static CCriticalSection cs_startmining;

        LOCK(cs_startmining);
        if (!AreParamsInitialized())
        {
            return;
        }

        VERUS_MINTBLOCKS = (VERUS_MINTBLOCKS && ASSETCHAINS_LWMAPOS != 0);

        if (fGenerate == true || VERUS_MINTBLOCKS)
        {
            mapArgs["-gen"] = "1";

            if (VERUS_DEFAULT_ZADDR.size() > 0)
            {
                if (defaultSaplingDest == boost::none)
                {
                    LogPrintf("ERROR: -defaultzaddr parameter is invalid Sapling payment address\n");
                    fprintf(stderr, "-defaultzaddr parameter is invalid Sapling payment address\n");
                }
                else
                {
                    LogPrintf("StakeGuard searching for double stakes on %s\n", VERUS_DEFAULT_ZADDR.c_str());
                    fprintf(stderr, "StakeGuard searching for double stakes on %s\n", VERUS_DEFAULT_ZADDR.c_str());
                }
            }
        }

        static boost::thread_group* minerThreads = NULL;

        if (nThreads < 0)
            nThreads = GetNumCores();

        if (minerThreads != NULL)
        {
            minerThreads->interrupt_all();
            minerThreads->join_all();
            delete minerThreads;
            minerThreads = NULL;
        }

        //fprintf(stderr,"nThreads.%d fGenerate.%d\n",(int32_t)nThreads,fGenerate);
        if ( nThreads == 0 && ASSETCHAINS_STAKED )
            nThreads = 1;

        if (!fGenerate)
            return;

        minerThreads = new boost::thread_group();

        // add the PBaaS thread when mining or staking
        minerThreads->create_thread(boost::bind(&CConnectedChains::SubmissionThreadStub));

#ifdef ENABLE_WALLET
        if (VERUS_MINTBLOCKS && pwallet != NULL)
        {
            minerThreads->create_thread(boost::bind(&VerusStaker, pwallet));
        }
#endif

        for (int i = 0; i < nThreads; i++) {
#ifdef ENABLE_WALLET
            minerThreads->create_thread(boost::bind(&BitcoinMiner_noeq, pwallet));
#else
            minerThreads->create_thread(&BitcoinMiner_noeq);
#endif
        }
    }

#endif // ENABLE_MINING
