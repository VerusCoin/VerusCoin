/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This implements the public blockchains as a service (PBaaS) notarization protocol, VerusLink.
 * VerusLink is a new distributed consensus protocol that enables multiple public blockchains 
 * to operate as a decentralized ecosystem of chains, which can interact and easily engage in cross 
 * chain transactions.
 * 
 */

#include "pbaas/notarization.h"
#include "pbaas/crosschainrpc.h"
#include "rpc/pbaasrpc.h"
#include "cc/CCinclude.h"
#include "main.h"

#include <assert.h>

using namespace std;

extern uint160 VERUS_CHAINID;
extern uint160 ASSETCHAINS_CHAINID;
extern string VERUS_CHAINNAME;
extern string PBAAS_HOST;
extern string PBAAS_USERPASS;
extern int32_t PBAAS_PORT;

CPBaaSNotarization::CPBaaSNotarization(const CTransaction &tx, bool validate)
{
    // the PBaaS notarization itself is a combination of proper inputs, one output, and
    // a sequence of opret chain objects as proof of the output values on the chain to which the
    // notarization refers, the opret can be reconstructed from chain data in order to validate
    // the txid of a transaction that does not contain the opret itself
    
    // a notarization must have notarization output that spends to the address indicated by the 
    // ChainID, an opret, that there is only one, and that it can be properly decoded to a notarization 
    // output, whether or not validate is true
    bool notarizationFound = false;
    bool error = false;
    for (auto out : tx.vout)
    {
        uint32_t ecode;
        if (out.scriptPubKey.IsPayToCryptoCondition(&ecode))
        {
            if (ecode == EVAL_ACCEPTEDNOTARIZATION || ecode == EVAL_EARNEDNOTARIZATION)
            {
                if (notarizationFound)
                {
                    error = true;
                    mmrRoot.SetNull();
                }
                else
                {
                    COptCCParams p;
                    notarizationFound = true;

                    // TODO: this only tells us it is a pay to CC tx. we need to validate ourselves after
                    if (!IsPayToCryptoCondition(out.scriptPubKey, p, *this))
                    {
                        mmrRoot.SetNull();
                    }
                }
            }
        }
    }

    // the following rules are enforced if validate is true:
    // 1) must either have the chain definition output on output 0 or spend the notarization
    //    thread for this chain.
    // 2) must spend and distribute funds from the last validated notarization and invalidate
    //    all invalidated notarizations, returning their payout to the notarization pool
    // 3) all values in notarization must match the opret
    // 4) all referenced objects must be consistent with this chain
    // 5) validation output must either be spent as validated or unspent
    //
    if (validate)
    {
        
    }
}

CPBaaSNotarization::CPBaaSNotarization(const UniValue &obj)
{
    nVersion = (uint32_t)uni_get_int(find_value(obj, "version"));
    chainID.SetHex(uni_get_str(find_value(obj, "chainid")));

    CBitcoinAddress notaryAddress(uni_get_str(find_value(obj, "notaryaddress")));
    CKeyID notaryKey;
    notaryAddress.GetKeyID(notaryKey);
    notaryKeyID = notaryKey;

    notarizationHeight = uni_get_int(find_value(obj, "notarizationheight"));
    mmrRoot = uint256S(uni_get_str(find_value(obj, "mmrroot")));
    notarizationPreHash = uint256S(uni_get_str(find_value(obj, "notarizationprehash")));
    compactPower = ArithToUint256((UintToArith256(uint256S(uni_get_str(find_value(obj, "stake")))) << 128) + 
                                   UintToArith256(uint256S(uni_get_str(find_value(obj, "work")))));
    prevNotarization = uint256S(uni_get_str(find_value(obj, "prevnotarization")));
    prevHeight = uni_get_int(find_value(obj, "prevheight"));
    crossNotarization = uint256S(uni_get_str(find_value(obj, "crossnotarization")));
    crossHeight = uni_get_int(find_value(obj, "crossheight"));
    auto nodesUni = find_value(obj, "nodes");
    if (nodesUni.isArray())
    {
        vector<UniValue> nodeVec = nodesUni.getValues();
        for (auto node : nodeVec)
        {
            nodes.push_back(CNodeData(uni_get_str(find_value(node, "networkaddress")), uni_get_str(find_value(node, "paymentaddress"))));
        }
    }
}

UniValue CPBaaSNotarization::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int32_t)nVersion));
    obj.push_back(Pair("chainid", chainID.GetHex()));
    obj.push_back(Pair("notaryaddress", CBitcoinAddress(CKeyID(notaryKeyID)).ToString()));
    obj.push_back(Pair("notarizationheight", (int32_t)notarizationHeight));
    obj.push_back(Pair("mmrroot", mmrRoot.GetHex()));
    obj.push_back(Pair("notarizationprehash", notarizationPreHash.GetHex()));
    obj.push_back(Pair("work", ((UintToArith256(compactPower) << 128) >> 128).ToString()));
    obj.push_back(Pair("stake", (UintToArith256(compactPower) >> 128).ToString()));
    obj.push_back(Pair("prevnotarization", prevNotarization.GetHex()));
    obj.push_back(Pair("prevheight", prevHeight));
    obj.push_back(Pair("crossnotarization", crossNotarization.GetHex()));
    obj.push_back(Pair("crossheight", crossHeight));
    UniValue nodesUni(UniValue::VARR);
    for (auto node : nodes)
    {
        nodesUni.push_back(node.ToUniValue());
    }
    obj.push_back(Pair("nodes", nodesUni));
    return obj;
}

CNotarizationFinalization::CNotarizationFinalization(const CTransaction &tx, bool validate)
{
    bool found = false;
    bool error = false;
    for (auto out : tx.vout)
    {
        uint32_t ecode;
        if (out.scriptPubKey.IsPayToCryptoCondition(&ecode))
        {
            if (ecode == EVAL_FINALIZENOTARIZATION)
            {
                if (found)
                {
                    error = true;
                    confirmedInput = -1;
                }
                else
                {
                    COptCCParams p;
                    found = true;

                    if (!IsPayToCryptoCondition(out.scriptPubKey, p, *this))
                    {
                        confirmedInput = -1;
                    }
                }
            }
        }
    }

    if (validate)
    {
        
    }
}

CChainNotarizationData::CChainNotarizationData(UniValue &obj)
{
    version = (uint32_t)uni_get_int(find_value(obj, "version"));
    UniValue vtxUni = find_value(obj, "vtx");
    if (vtxUni.isArray())
    {
        vector<UniValue> vvtx = vtxUni.getValues();
        for (auto o : vvtx)
        {
            vtx.push_back(make_pair(uint256S(uni_get_str(find_value(o, "txid"))), CPBaaSNotarization(find_value(o, "notarization"))));
        }
    }

    lastConfirmed = (uint32_t)uni_get_int(find_value(obj, "lastconfirmed"));
    UniValue forksUni = find_value(obj, "forks");
    if (forksUni.isArray())
    {
        vector<UniValue> forksVec = forksUni.getValues();
        for (auto fv : forksVec)
        {
            if (fv.isArray())
            {
                forks.push_back(vector<int32_t>());
                vector<UniValue> forkVec = fv.getValues();
                for (auto fidx : forkVec)
                {
                    forks.back().push_back(uni_get_int(fidx));
                }
            }
        }
    }

    bestChain = (uint32_t)uni_get_int(find_value(obj, "bestchain"));
}

UniValue CChainNotarizationData::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int32_t)version));
    UniValue notarizations(UniValue::VARR);
    for (int64_t i = 0; i < vtx.size(); i++)
    {
        UniValue notarization(UniValue::VOBJ);
        notarization.push_back(Pair("index", i));
        notarization.push_back(Pair("txid", vtx[i].first.GetHex()));
        notarization.push_back(Pair("notarization", vtx[i].second.ToUniValue()));
        notarizations.push_back(notarization);
    }
    obj.push_back(Pair("notarizations", notarizations));
    obj.push_back(Pair("lastconfirmed", lastConfirmed));
    UniValue Forks(UniValue::VARR);
    for (int32_t i = 0; i < forks.size(); i++)
    {
        UniValue Fork(UniValue::VARR);
        for (int32_t j = 0; j < forks[i].size(); j++)
        {
            Fork.push_back(forks[i][j]);
        }
        Forks.push_back(Fork);
    }
    obj.push_back(Pair("forks", Forks));
    obj.push_back(Pair("bestchain", bestChain));
    return obj;
}

vector<CInputDescriptor> AddSpendsAndFinalizations(const CChainNotarizationData &cnd, 
                                                   const uint256 &lastNotarizationID, 
                                                   const CTransaction &lastTx, 
                                                   CMutableTransaction &mnewTx, 
                                                   int32_t *pConfirmedInput, 
                                                   int32_t *pConfirmedIdx, 
                                                   CTxDestination *pConfirmedDest)
{
    // determine all finalized and orphaned transactions that should be spent as input
    // always spend the notarization thread
    vector<CInputDescriptor> txInputs;

    set<int32_t> finalized;
    int32_t &confirmedIdx = *pConfirmedIdx;
    confirmedIdx = -1;
    int32_t confirmOffset = (cnd.lastConfirmed == -1) ? 0 : 1;

    // now, create inputs from the most recent notarization in cnd and the finalization outputs that we either confirm or invalidate
    for (int j = 0; j < cnd.forks.size(); j++)
    {
        int k;
        for (k = cnd.forks[j].size() - 1; k >= 0; k--)
        {
            // the first instance of the prior notarization we find represents the prior fork we are confirming
            // it may be intact or part of another. in any case, we may create a new fork or add on to an existing one
            // whether we create a new fork or add to an existing one, we may confirm an entry
            // if we do, we will spend the finalizatoin output of every fork that does no include that entry as well
            // as that entry itself
            if (cnd.vtx[cnd.forks[j][k]].first == lastNotarizationID)
            {
                // if we have a fork that is long enough that we will add to, we are confirming the entry final confirmations before us
                if (k >= CPBaaSNotarization::FINAL_CONFIRMATIONS + confirmOffset)
                {
                    int32_t confirmedEntry = k - CPBaaSNotarization::FINAL_CONFIRMATIONS;
                    confirmedIdx = cnd.forks[j][confirmedEntry];
                    finalized.insert(confirmedIdx);
                    // if we would add the 10th confirmation to the second in this fork, we are confirming 
                    // a new notarization, spend it's finalization output and all those that disagree with it
                    // the only chains that are confirmed to disagree will have a different index in the
                    // second position, which is the one we are confirming
                    for (int l = 0; l < cnd.forks.size(); l++)
                    {
                        // spend all forks that do not contain the notarization from the confirmed offset forward
                        if (cnd.forks[l][confirmOffset] != confirmedIdx)
                        {
                            for (int m = confirmOffset; m < cnd.forks[l].size(); m++)
                            {
                                // put indexes of all orphans into the finalized set
                                finalized.insert(cnd.forks[l][m]);
                            }
                        }
                    }
                    break;
                }
            }
        }
        // if we short circuited by confirmation, short circuit here too
        if (k >= 0)
        {
            break;
        }
    }

    LOCK2(cs_main, mempool.cs);

    // now, we should spend the last notarization output and all finalization outputs in the finalized set
    // first, we need to get the outpoint for the notarization, then each finalization as well
    uint256 notarizationThreadID, blkHash;
    CTransaction threadTx;
    uint32_t j;
    if (cnd.vtx.size())
    {
        notarizationThreadID = cnd.vtx.back().first;
        if (myGetTransaction(notarizationThreadID, threadTx, blkHash))
        {
            for (j = 0; j < threadTx.vout.size(); j++)
            {
                uint32_t code;
                if (threadTx.vout[j].scriptPubKey.IsPayToCryptoCondition(&code) && (code == EVAL_EARNEDNOTARIZATION || code == EVAL_ACCEPTEDNOTARIZATION))
                {
                    break;
                }
            }
        }
        else
        {
            notarizationThreadID.SetNull();
        }
    }

    // either we have no last notarization, or we found its notarization output
    assert(notarizationThreadID.IsNull() || j < threadTx.vout.size());

    // if this isn't the first notarization, setup inputs
    if (!notarizationThreadID.IsNull())
    {
        // spend notarization output of the last notarization
        txInputs.push_back(CInputDescriptor(threadTx.vout[j].scriptPubKey, threadTx.vout[j].nValue, CTxIn(notarizationThreadID, j, CScript())));
        mnewTx.vin.push_back(CTxIn(notarizationThreadID, j, CScript()));

        for (auto nidx : finalized)
        {
            // we need to reload all transactions and get their finalization outputs
            // this could be made more efficient by keeping them earlier or standardizing output numbers
            CCoins coins;
            uint256 hblk;
            if (!pcoinsTip->GetCoins(cnd.vtx[nidx].first, coins))
            {
                // if this fails, we can't follow consensus and must fail
                return vector<CInputDescriptor>();
            }
            int k;
            CPBaaSNotarization pbn;
            for (k = 0; k < coins.vout.size(); k++)
            {
                COptCCParams p;

                if (!coins.vout[k].IsNull() && IsPayToCryptoCondition(coins.vout[k].scriptPubKey, p))
                {
                    if (nidx == confirmedIdx && (p.evalCode == EVAL_EARNEDNOTARIZATION || p.evalCode == EVAL_ACCEPTEDNOTARIZATION))
                    {
                        pbn = CPBaaSNotarization(p.vData[0]);
                    }
                    else if (p.evalCode == EVAL_FINALIZENOTARIZATION)
                    {
                        break;
                    }
                }
            }
            assert(k < coins.vout.size());

            printf("spending finalization output of hash: %s\nprevout.n: %d\n", cnd.vtx[nidx].first.GetHex().c_str(), k);

            // spend all of them
            txInputs.push_back(CInputDescriptor(coins.vout[k].scriptPubKey, coins.vout[k].nValue, CTxIn(cnd.vtx[nidx].first, k, CScript())));
            mnewTx.vin.push_back(CTxIn(cnd.vtx[nidx].first, k, CScript()));
            if (nidx == confirmedIdx)
            {
                *pConfirmedInput = mnewTx.vin.size() - 1;
                *pConfirmedDest = CTxDestination(CKeyID(pbn.notaryKeyID));
            }
        }
    }
    return txInputs;
}

bool GetNotarizationAndFinalization(int32_t ecode, CMutableTransaction mtx, CPBaaSNotarization &pbn, uint32_t *pNotarizeOutIndex, uint32_t *pFinalizeOutIndex)
{
    bool notarize = false, finalize = false, duplicate = false;
    for (int j = 0; j < mtx.vout.size(); j++)
    {
        COptCCParams p;

        if (IsPayToCryptoCondition(mtx.vout[j].scriptPubKey, p))
        {
            if (p.evalCode == ecode)
            {
                *pNotarizeOutIndex = j;
                pbn = CPBaaSNotarization(p.vData[0]);
                if (notarize) duplicate = true;
                notarize = true;
            }
            else if (p.evalCode == EVAL_FINALIZENOTARIZATION)
            {
                *pFinalizeOutIndex = j;
                if (finalize) duplicate = true;
                finalize = true;
            }
        }
    }
    return finalize && notarize && !duplicate;
}

// This assumes it is running on the PBaaS chain.
// Creates a notarization that will be in the current block and use the prevMMR to prove the block before us
// we refer to the transactions on the Verus chain and on our chain with which we agree, and if we have added the
// 10th validation to a notarization in our lineage, we finalize it as validated and finalize any conflicting notarizations
// as invalidated.
// Currently may return with insufficient or excess input relative to outputs.
bool CreateEarnedNotarization(CMutableTransaction &mnewTx, vector<CInputDescriptor> &inputs, CTransaction &lastTx, CTransaction &crossTx, int32_t height, int32_t *pConfirmedInput, CTxDestination *pConfirmedDest)
{
    char funcname[] = "CreateEarnedNotarization: ";

    //printf("%senter\n", funcname);

    // we can only create a notarization if there is an available Verus chain
    if (!ConnectedChains.IsVerusPBaaSAvailable())
    {
        return false;
    }

    UniValue params(UniValue::VARR);
    params.push_back(ASSETCHAINS_CHAINID.GetHex());

    CChainNotarizationData cnd;

    UniValue txidArr(UniValue::VARR);

    if (GetNotarizationData(VERUS_CHAINID, EVAL_EARNEDNOTARIZATION, cnd))
    {
        // make an array of all possible txids on this chain
        for (auto it : cnd.vtx)
        {
            txidArr.push_back(it.first.GetHex());
        }
    }
    else if (height != 1)
    {
        return false;
    }

    params.push_back(txidArr);

    //printf("%sabout to get cross notarization with %lu notarizations found\n", funcname, cnd.vtx.size());

    UniValue result;
    try
    {
        result = find_value(RPCCallRoot("getcrossnotarization", params), "result");
    } catch (exception e)
    {
        result = NullUniValue;
    }

    // if no error, prepare notarization
    auto uv1 = find_value(result, "crosstxid");
    auto uv2 = find_value(result, "txid");
    auto uv3 = find_value(result, "rawtx");
    auto uv4 = find_value(result, "newtx");

    // if we passed no prior notarizations, the crosstxid returned can be null
    if ((!uv1.isStr() && (cnd.vtx.size() != 0)) || !uv2.isStr() || !uv3.isStr() || !uv4.isStr())
    {
        printf("%sinvalid parameters\n", funcname);
        return false;
    }

    uint256 lastNotarizationID;
    lastNotarizationID.SetHex((uv1.get_str()));
    uint256 crossNotarizationID;
    crossNotarizationID.SetHex((uv2.get_str()));

    if (crossNotarizationID.IsNull() || !DecodeHexTx(crossTx, uv3.get_str()))
    {
        printf("%sinvalid parameters 2\n", funcname);
        return false;
    }

    CTransaction newTx;
    if (!DecodeHexTx(newTx, uv4.get_str()))
    {
        LogPrintf("%sinvalid transaction decode.\n", funcname);
        return false;
    }

    // we have more work to do on it
    mnewTx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), height);
    // there should be no inputs, copy the outputs to the new transaction
    uint32_t notarizeOutIndex = -1, finalizeOutIndex = -1;
    CPBaaSNotarization pbn;
    for (int j = 0; j < newTx.vout.size(); j++)
    {
        COptCCParams p;

        if (IsPayToCryptoCondition(newTx.vout[j].scriptPubKey, p))
        {
            if (p.evalCode == EVAL_EARNEDNOTARIZATION)
            {
                notarizeOutIndex = j;
                pbn = CPBaaSNotarization(p.vData[0]);
            }
            else if (p.evalCode == EVAL_FINALIZENOTARIZATION)
            {
                finalizeOutIndex = j;
            }
        }
        mnewTx.vout.push_back(newTx.vout[j]);
    }

    if (notarizeOutIndex == -1 || finalizeOutIndex == -1 || !pbn.IsValid() || pbn.nVersion != PBAAS_VERSION)
    {
        LogPrintf("%sinvalid notarization transaction returned from %s\n", funcname, VERUS_CHAINNAME.c_str());
        return false;
    }

    LOCK2(cs_main, mempool.cs);

    vector<CBaseChainObject *> chainObjs = RetrieveOpRetArray(mnewTx.vout.back().scriptPubKey);
    vector<CBaseChainObject *> compressedChainObjs;

    // convert any op_return header to a smaller header_ref if it was merge mined, which modifies both the
    // op_return and the opRetProof in the notarization
    for (int j = 0; j < chainObjs.size(); j++)
    {
        uint256 hash;
        if (chainObjs[j]->objectType == CHAINOBJ_HEADER && 
            !((CChainObject<CBlockHeader> *)chainObjs[j])->object.IsVerusPOSBlock() && 
            mapBlockIndex.count(hash = ((CChainObject<CBlockHeader> *)chainObjs[j])->object.GetHash()))
        {
            // this is a common block between chains, replace the header with a header_ref in both the opret and proof
            pbn.opRetProof.types[j] = CHAINOBJ_HEADER_REF;
            CHeaderRef hr = CHeaderRef(hash, CPBaaSPreHeader(((CChainObject<CBlockHeader> *)chainObjs[j])->object));
            CBaseChainObject *hRef = new CChainObject<CHeaderRef>(CHAINOBJ_HEADER_REF, hr);
            compressedChainObjs.push_back(hRef);
            delete (CChainObject<CBlockHeader> *)chainObjs[j];
        }
        else
        {
            compressedChainObjs.push_back(chainObjs[j]);
        }
    }

    mnewTx.vout.back().scriptPubKey = StoreOpRetArray(compressedChainObjs);

    // now that we've finished making the opret, free the objects
    DeleteOpRetObjects(compressedChainObjs);

    if (!mnewTx.vout.back().scriptPubKey.size())
    {
        printf("%sfailed to create OP_RETURN output", funcname);
        return false;
    }

    // we need to update our earned notarization and finalization outputs, which should both be present and incomplete
    // add up inputs, and make sure that the main notarization output holds any excess over minimum, if not enough, we need
    // to spend a coinbase instant spend

    CPBaaSNotarization crossNotarizaton(crossTx);
    CPBaaSChainDefinition chainDef(crossTx);        // only matters if we get no cross notarization prior
    if (crossNotarizaton.prevNotarization.IsNull() && !chainDef.IsValid())
    {
        // must either have a prior notarization or be the definition
        printf("%sNo prior notarization and no chain definition in cross notarization\n", funcname);
        return false;
    }

    pbn.prevNotarization = lastNotarizationID;
    if (lastNotarizationID.IsNull())
    {
        pbn.prevHeight = 0;
    }
    else
    {
        uint256 hashBlk;
        // get the last notarization
        if (!myGetTransaction(lastNotarizationID, lastTx, hashBlk))
        {
            printf("Error: cannot find notarization transaction %s on %s chain\n", lastNotarizationID.GetHex().c_str(), ASSETCHAINS_SYMBOL);
            return false;
        }
        auto lastTxBlkIt = mapBlockIndex.find(hashBlk);
        if (lastTxBlkIt == mapBlockIndex.end())
        {
            printf("Error: cannot find block %s on %s chain\n", hashBlk.GetHex().c_str(), ASSETCHAINS_SYMBOL);
            return false;
        }

        CPBaaSNotarization prevNZ(lastTx);
        pbn.prevHeight = prevNZ.notarizationHeight;

        int32_t blocksToWait = (pbn.prevHeight + CPBaaSNotarization::MIN_BLOCKS_BETWEEN_ACCEPTED) - pbn.notarizationHeight;
        if (blocksToWait > 0)
        {
            // can't make another notarization yet
            printf("%sWaiting for %d blocks to notarize - prevHeight.%d, notarizationHeight.%d\n", funcname, blocksToWait, pbn.prevHeight, pbn.notarizationHeight);
            return false;
        }
    }

    // determine all finalized transactions that should be spent as input
    int32_t confirmedIndex;
    inputs = AddSpendsAndFinalizations(cnd, lastNotarizationID, lastTx, mnewTx, pConfirmedInput, &confirmedIndex, pConfirmedDest);

    CCcontract_info CC;
    CCcontract_info *cp;
    vector<CTxDestination> vKeys;

    // make the earned notarization output
    cp = CCinit(&CC, EVAL_EARNEDNOTARIZATION);
    // send this to EVAL_PBAASDEFINITION address as a destination, locked by the default pubkey
    CPubKey pk(ParseHex(CC.CChexstr));

    vKeys.push_back(CTxDestination(CKeyID(CCrossChainRPCData::GetConditionID(VERUS_CHAINID, EVAL_EARNEDNOTARIZATION))));
    mnewTx.vout[notarizeOutIndex] = MakeCC1of1Vout(EVAL_EARNEDNOTARIZATION, PBAAS_MINNOTARIZATIONOUTPUT, pk, vKeys, pbn);
    
    // make the finalization output
    cp = CCinit(&CC, EVAL_FINALIZENOTARIZATION);
    pk = CPubKey(ParseHex(CC.CChexstr));

    // we need to store the input that we confirmed if we spent finalization outputs
    CNotarizationFinalization nf(*pConfirmedInput);

    vKeys[0] = CTxDestination(CKeyID(CCrossChainRPCData::GetConditionID(VERUS_CHAINID, EVAL_FINALIZENOTARIZATION)));

    // update crypto condition with final notarization output data
    mnewTx.vout[finalizeOutIndex] = MakeCC1of1Vout(EVAL_FINALIZENOTARIZATION, PBAAS_MINNOTARIZATIONOUTPUT, pk, vKeys, nf);

    return true;
}

// this validates that the data in the earned notarization, including its distance from the prior cross-notarization being adequate
// are all correct. it makes no calls outside of the current daemon to do its validation
// it requires that the cs_main is held, as it uses the mapBlockIndex
bool ValidateEarnedNotarization(CTransaction &ntx, CPBaaSNotarization *notarization)
{
    char funcname[] = "ValidateEarnedNotarization: ";

    // validate:
    //  - the notarization refers to the first prior notarization on this chain that refers to the cross notarization commitment
    //  - the notarization is either in a PoS block, or a block that meets the hash qualification to be merge mined into
    //    our notary chain. this does not mean that it will be validated further, but it disqualifies all earned notarizations that
    //    are definitely not valid PoS or winners on both this and its notary chain. This ensures variable cross checking
    //    of PoS notarizations, depending on VRSC rewards for notaries, but keeps the weighted control of the chain's
    //    definition most in the hands of those with the stake in the chain.
    //  - all objects referred to by the cross notarization tx, which no longer contains its op_ret, are present on this chain
    //    and can be used to re-create the cross chain transaction's op_ret. ensure that when doing so, the cross-chain
    //    tranaction hashes to the same value as committed to in the notarization
    //

    CPBaaSNotarization pbn;

    // only recreate the notarization if we weren't passed one
    if (notarization == NULL)
    {
        if (!(pbn = CPBaaSNotarization(ntx)).IsValid())
        {
            LogPrintf("%sinvalid notarization transaction %s\n", funcname, ntx.GetHash().GetHex().c_str());
            return false;
        }
        notarization = &pbn;
    }

    CPBaaSNotarization &n = *notarization;

    // check all the basics
    // if we are running on the Verus chain, we assume it is checking against a chain we are notarizing
    if (IsVerusActive())
    {
        // for now, we fail in this case
        LogPrintf("%scalled from %s chain\n", funcname, ASSETCHAINS_SYMBOL);
        return false;
    }
    else if (n.chainID != VERUS_CHAINID || !ntx.vout.size() || !ntx.vout.back().scriptPubKey.IsOpReturn())
    {
        LogPrintf("%searned notarization for chain %s for unrecognized chain ID %s\n", funcname, VERUS_CHAINNAME, n.chainID.GetHex().c_str());
        return false;
    }

    vector<CBaseChainObject *> chainObjects = RetrieveOpRetArray(ntx.vout.back().scriptPubKey);

    // we now have ownership of all chain object memory to delete below, make sure the objects are as we expect
    // first object should be a header that is either PoS on this chain, or header ref and mined with a block hash that could meet the
    // requirements of the block in our notary chain
    bool retVal = false;

    // all earned notarizations have chain objects, one header/headerref, one tx, and two proofs at least
    if (chainObjects.size() != 5 ||
        (chainObjects[0]->objectType != CHAINOBJ_HEADER && chainObjects[0]->objectType != CHAINOBJ_HEADER_REF) || 
        chainObjects[1]->objectType != CHAINOBJ_PROOF || 
        chainObjects[2]->objectType != CHAINOBJ_TRANSACTION || 
        chainObjects[3]->objectType != CHAINOBJ_PROOF || 
        chainObjects[4]->objectType != CHAINOBJ_PRIORBLOCKS)
    {
        LogPrintf("%snotarization must contain at least one block and one transaction proof\n", funcname);
    }
    else
    {
        // make a reference to the block header, either the full POS header, or a reconstructed, merge mined header
        CBlockHeader *pbh = NULL;
        CBlockHeader blockHeader;
        if (chainObjects[0]->objectType == CHAINOBJ_HEADER)
        {
            pbh = &((CChainObject<CBlockHeader> *)chainObjects[0])->object;
        }
        else
        {
            auto it = mapBlockIndex.find(n.opRetProof.hashes[0]);
            if (it != mapBlockIndex.end())
            {
                blockHeader = it->second->GetBlockHeader();
                ((CChainObject<CPBaaSPreHeader> *)chainObjects[0])->object.SetBlockData(blockHeader);
                pbh = &blockHeader;
            }
        }
        if (pbh)
        {
            CBlockHeader &bh = *pbh;

            CMerkleBranch &blockProof = ((CChainObject<CMerkleBranch> *)chainObjects[1])->object;
            CTransaction &cntx = ((CChainObject<CTransaction> *)chainObjects[2])->object;
            CMerkleBranch &cntxProof = ((CChainObject<CMerkleBranch> *)chainObjects[3])->object;

            arith_uint256 target;
            target.SetCompact(bh.nBits);
            uint256 blkHash = bh.GetHash();
            arith_uint256 arithHash = UintToArith256(blkHash);

            if (blockProof.SafeCheck(blkHash) == pbn.mmrRoot && arithHash <= target)
            {
                // block is correct, reconstruct op_ret and check tx
                CMutableTransaction mcntx(cntx);

                // get prior cross notarization
                CPBaaSNotarization cpbn(cntx);

                if (!cpbn.IsValid() || cpbn.opRetProof.orIndex)
                {
                    LogPrintf("%snotarization must be valid and opret must start at index 0\n", funcname);
                }
                else
                {
                    // now assume true return and fall through on false
                    retVal = true;
                    vector<CBaseChainObject *> chainObjs;

                    // loop through the proof and locate elements on this chain to reconstruct
                    for (int i = 0; i < cpbn.opRetProof.hashes.size() && retVal; i ++)
                    {
                        switch (cpbn.opRetProof.types[i])
                        {
                            // if chain object header, it should be PoS, merge mined headers are header refs
                            case CHAINOBJ_HEADER:
                            {
                                auto it = mapBlockIndex.find(cpbn.opRetProof.hashes[i]);
                                if (it == mapBlockIndex.end() ||
                                    !it->second->IsVerusPOSBlock() ||
                                    it->second->GetHeight() != cpbn.notarizationHeight)
                                {
                                    LogPrintf("%sfull block header in cross-notarization from %s should be PoS\n", funcname, VERUS_CHAINNAME.c_str());
                                    retVal = false;
                                }
                                else if (!GetCompactPower(it->second->nNonce, it->second->nBits, it->second->nVersion) != UintToArith256(cpbn.compactPower))
                                {
                                    LogPrintf("%sinvalid chain power in cross-notarization from %s\n", funcname, VERUS_CHAINNAME.c_str());
                                    retVal = false;
                                }
                                else
                                {
                                    CBlockHeader blk = it->second->GetBlockHeader();
                                    chainObjs.push_back(new CChainObject<CBlockHeader>(CHAINOBJ_HEADER, blk));
                                    if (!chainObjs.back())
                                    {
                                        chainObjs.pop_back();
                                        retVal = false;
                                    }
                                }
                                break;
                            }

                            // header refs are for merge mined headers and should also be on this chain
                            case CHAINOBJ_HEADER_REF:
                            {
                                auto it = mapBlockIndex.find(cpbn.opRetProof.hashes[i]);
                                if (it == mapBlockIndex.end())
                                {
                                    LogPrintf("%sblock in notarization from %s chain not found\n", funcname, VERUS_CHAINNAME.c_str());
                                    retVal = false;
                                }
                                else
                                {
                                    CBlockHeader blk = it->second->GetBlockHeader();
                                    CHeaderRef hr = CHeaderRef(blk);
                                    chainObjs.push_back(new CChainObject<CHeaderRef>(CHAINOBJ_HEADER_REF, hr));
                                    if (!chainObjs.back())
                                    {
                                        chainObjs.pop_back();
                                        retVal = false;
                                    }
                                }
                                break;
                            }

                            // we don't need proofs, since all objects are on this chain
                            case CHAINOBJ_PROOF:
                            {
                                // prove either a transaction or header, whichever is before us in the objects
                                uint32_t objType = chainObjs.back()->objectType;
                                if (objType == CHAINOBJ_HEADER_REF || objType == CHAINOBJ_HEADER)
                                {
                                    // TODO: make a proof that proves the block hash in the opRetProof from the indicated height
                                }
                                else if (objType == CHAINOBJ_TRANSACTION)
                                {
                                    // TODO: make a proof that proves the transaction hash in the opRetProof from the indicated block
                                }
                                else
                                {
                                    retVal = false;
                                }
                                break;
                            }

                            // we don't need proofs, since all objects are on this chain
                            case CHAINOBJ_PRIORBLOCKS:
                            {
                                break;
                            }

                            case CHAINOBJ_TRANSACTION:
                            {
                                // TODO: get tansaction
                                break;
                            }

                            default:
                                LogPrintf("%snotarization must be valid and opret must start at index 0\n", funcname);
                                retVal = false;
                        }
                    }
                    if (retVal)
                    {
                        // store chainObjs into reconstructed opRet and verify txid and proof of reconstructed transaction
                    }
                    DeleteOpRetObjects(chainObjs);
                }
            }
        }
    }

    DeleteOpRetObjects(chainObjects);

    return retVal;
}

// This creates an accepted notarization from an earned notarization created by a PBaaS chain.
// this assumes it is running on the PBaaS chain when called.
// it creates much of the required accepted notarization, then passes it to the Verus daemon for completion.
// The earned notarization will have the last notarization that we agree with. In order to make a valid
// accepted notarization, we must meet the following requireents:
// 1) the last notarization must still be the last we agree with
// 2) the last notarization must be CPBaaSNotarization::MIN_BLOCKS_BETWEEN_ACCEPTED or more blocks behind us
// 3) the earned notarization must be in either a POS block of the chain being notarized, or a block that is merge mined and
//    has the same block hash on both notary chain and chain being notarized.
// block is block of earned notarization, entx is earned notarization transaction, height is height of block
uint256 CreateAcceptedNotarization(const CBlock &blk, int32_t txIndex, int32_t height)
{
    char funcname[] = "CreateAcceptedNotarization: ";
    uint256 nullRet = uint256();
    const CTransaction &entx = blk.vtx[txIndex];
   
    // we can only create a notarization if there is an available Verus chain
    if (!ConnectedChains.IsVerusPBaaSAvailable())
    {
        LogPrintf("%scannot connect to %s\n", funcname, VERUS_CHAINNAME.c_str());
        return nullRet;
    }

    CPBaaSNotarization crosspbn(entx);
    if (!crosspbn.IsValid())
    {
        LogPrintf("%sinvalid earned notarization\n", funcname);
        return nullRet;
    }

    vector<CBaseChainObject *> chainObjects;
    CChainObject<CBlockHeader> latestHeaderObj;
    CChainObject<CHeaderRef> latestHeaderObjRef;
    CChainObject<CMerkleBranch> latestHeaderProof;
    CChainObject<CTransaction> strippedTxObj;
    CChainObject<CMerkleBranch> txProofObj;
    CChainObject<CPriorBlocksCommitment> priorBlocksObj;

    COpRetProof orp;
    CPBaaSNotarization pbn;
    {
        LOCK(cs_main);
        if (height > chainActive.Height())
        {
            LogPrintf("%sheight requested is greater than chain height\n", funcname);
            return nullRet;
        }
        // prepare a partial notarization with all that is needed from this PBaaS chain at the height requested
        // if it is from a mined block, prepare the notarization assuming merge mined block
        // it will be rejected if it was not successfully merge mined
        auto mmv = chainActive.GetMMV();
        mmv.resize(height + 1);
        uint256 preHash = mmv.mmr.GetNode(height).hash;

        CMerkleBranch blockProof;
        chainActive.GetBlockProof(mmv, blockProof, height);
        CMerkleBranch txProof;
        uint256 txHash = entx.GetHash();
        int i;
        for (i = 0; i < blk.vtx.size(); i++)
        {
            if (blk.vtx[i].GetHash() == txHash)
            {
                txProof.branch = blk.GetMerkleBranch(i);
                txProof.nIndex = i;
                break;
            }
        }

        if (i == blk.vtx.size())
        {
            LogPrintf("%scannot locate earned notarization in block\n", funcname);
            return nullRet;
        }

        chainActive.GetMerkleProof(mmv, txProof, height);

        // if this is a POS header, include the whole header, if merge mined,
        // only the header ref and pre-header
        if (blk.IsVerusPOSBlock())
        {
            latestHeaderObj = CChainObject<CBlockHeader>(CHAINOBJ_HEADER, blk);
            chainObjects.push_back(&latestHeaderObj);
            orp.AddObject(CHAINOBJ_HEADER, blk.GetHash());
        }
        else
        {
            CHeaderRef hr(blk);
            latestHeaderObjRef = CChainObject<CHeaderRef>(CHAINOBJ_HEADER_REF, hr);
            chainObjects.push_back(&latestHeaderObjRef);
            orp.AddObject(CHAINOBJ_HEADER_REF, blk.GetHash());
        }

        latestHeaderProof = CChainObject<CMerkleBranch>(CHAINOBJ_PROOF, blockProof);
        chainObjects.push_back(&latestHeaderProof);
        orp.AddObject(blk, chainActive[height]->GetBlockHash());

        // we need to refer to the earned notarization as the cross transaction, and the prior cross
        // transaction as the last matching transaction to confirm. we also need to ensure that when
        // we are added as an accepted notarization, that there is no more recent earned notarization
        // to do that, accepted notarizations will also include

        // add the earned notarization as the cross transaction for this accepted notarization after stripping its op_return
        CMutableTransaction mentx(entx);

        if (mentx.vout[mentx.vout.size() - 1].scriptPubKey.IsOpReturn())
        {
            // remove the opret
            mentx.vout.pop_back();
        }
        CTransaction strippedTx(mentx);

        //printf("entx.vout size: %lu\n", entx.vout.size());
        //printf("strippedTx.vout size: %lu\n", strippedTx.vout.size());

        strippedTxObj = CChainObject<CTransaction>(CHAINOBJ_TRANSACTION, strippedTx);
        chainObjects.push_back(&strippedTxObj);
        orp.AddObject(CHAINOBJ_TRANSACTION, entx.GetHash());

        // add proof of the transaction
        txProofObj = CChainObject<CMerkleBranch>(CHAINOBJ_PROOF, txProof);
        chainObjects.push_back(&txProofObj);
        orp.AddObject(CHAINOBJ_PROOF, txHash);

        // add the MMR block nodes between the last notarization and this one, containing root that combines merkle, block, and compact power hashes
        CPriorBlocksCommitment priorBlocks;
        int numPriorBlocks = height - crosspbn.crossHeight;
        int maxPriorBlocks = PBAAS_MAXPRIORBLOCKS > (height - 1) ? ((height - 1) < 1 ? 0 : (height - 1)) : PBAAS_MAXPRIORBLOCKS;

        if (numPriorBlocks > maxPriorBlocks) numPriorBlocks = maxPriorBlocks;

        // push back the merkle, block hash, and block power commitments for prior blocks to ensure no
        // unintended notary overlap
        for (int i = numPriorBlocks - 1; i >= 0; i--)
        {
            priorBlocks.priorBlocks.push_back(mmv.mmr.GetNode(height - i).hash);
        }

        priorBlocksObj = CChainObject<CPriorBlocksCommitment>(CHAINOBJ_PRIORBLOCKS, priorBlocks);
        chainObjects.push_back(&priorBlocksObj);
        orp.AddObject(CHAINOBJ_PRIORBLOCKS, ::GetHash(priorBlocks));

        pbn.nVersion = CPBaaSNotarization::CURRENT_VERSION;
        pbn.chainID = ASSETCHAINS_CHAINID;
        pbn.notaryKeyID = crosspbn.notaryKeyID;
        pbn.notarizationHeight = height;

        auto node = mmv.GetRootNode();
        pbn.mmrRoot = node->hash;
        pbn.notarizationPreHash = preHash;
        pbn.compactPower = node->power;

        pbn.prevNotarization = crosspbn.crossNotarization;
        pbn.prevHeight = crosspbn.crossHeight;
        pbn.crossNotarization = entx.GetHash();
        pbn.crossHeight = crosspbn.notarizationHeight;

        pbn.opRetProof = orp;
    }

    // get node keys and addresses
    const static int MAX_NODES = 2;

    {
        LOCK(cs_vNodes);
        if (!vNodes.empty())
        {
            for (int i = 0; i < vNodes.size(); i++)
            {
                CNodeStats stats;
                vNodes[i]->copyStats(stats);
                if (vNodes[i]->fSuccessfullyConnected && !vNodes[i]->fInbound)
                {
                    pbn.nodes.push_back(CNodeData(vNodes[i]->addr.ToString(), CKeyID(vNodes[i]->hashPaymentAddress)));
                }
            }
        }
    }

    // reduce number to max by removing randomly
    while (pbn.nodes.size() > MAX_NODES)
    {
        int toErase = GetRandInt(pbn.nodes.size() - 1);
        pbn.nodes.erase(pbn.nodes.begin() + toErase);
    }

    CScript opRet = StoreOpRetArray(chainObjects);

    // we are ready to create a transaction to send to the other chain

    // setup to create the accepted notarization transaction
    CMutableTransaction mnewTx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), height);

    // create notarization output
    CCcontract_info CC;
    CCcontract_info *cp;
    vector<CTxDestination> vKeys;

    // make the accepted notarization output
    cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);

    CPubKey pk(ParseHex(CC.CChexstr));

    // make a notarization out
    vKeys.push_back(CTxDestination(CKeyID(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, EVAL_ACCEPTEDNOTARIZATION))));
    mnewTx.vout.push_back(MakeCC1of1Vout(EVAL_ACCEPTEDNOTARIZATION, PBAAS_MINNOTARIZATIONOUTPUT, pk, vKeys, pbn));

    mnewTx.vout.push_back(CTxOut(0, opRet));

    // finish transaction by sending it to the other notary chain for completion and submission
    CTransaction notarization(mnewTx);

    // call an API, submit notarization that takes a partially complete notarization tx
    // then completes and submits it if possible
    // we can only create a notarization if there is an available Verus chain

    UniValue params(UniValue::VARR);
    params.push_back(EncodeHexTx(notarization));
    UniValue result = NullUniValue;
    try
    {
        result = find_value(RPCCallRoot("submitacceptednotarization", params), "result");
    } catch (exception e)
    {
        result = NullUniValue;
    }
    uint256 notarizationId;
    if (result.isStr())
    {
        notarizationId.SetHex(result.get_str());
    }
    return notarizationId;
}

/*
 * Validates a notarization output spend by ensuring that the spending transaction fulfills all requirements.
 * to accept an earned notarization as valid on the Verus blockchain, it must prove a transaction on the alternate chain, which is 
 * either the original chain definition transaction, which CAN and MUST be proven ONLY in block 1, or the latest notarization transaction 
 * on the alternate chain that represents an accurate MMR for this chain.
 * In addition, any accepted notarization must fullfill the following requirements:
 * 1) Must prove either a PoS block from the alternate chain or a merge mined block that is owned by the submitter and in either case, 
 *    the block must be exactly 8 blocks behind the submitted MMR used for proof.
 * 2) Must prove a chain definition tx and be block 1 or asserts a previous, valid MMR for the notarizing
 *    chain and properly prove objects using that MMR.
 * 3) Must spend the main notarization thread as well as any finalization outputs of either valid or invalid prior
 *    notarizations, and any unspent notarization contributions for this era. May also spend other inputs.
 * 4) Must output:
 *      a) finalization output of the expected reward amount, which will be sent when finalized
 *      b) normal output of reward from validated/finalized input if present, 50% to recipient / 50% to block miner less miner fee this tx
 *      c) main notarization thread output with remaining funds, no other output or fee deduction
 * 
 */
bool ValidateAcceptedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    // TODO: this validates the spending transaction
    // check the following things:
    // 1. It represents a valid PoS or merge mined block on the other chain, and contains the header in the opret
    // 2. The MMR and proof provided for the currently asserted block can prove the provided header. The provided
    //    header can prove the last block referenced.
    // 3. This notarization is not a superset of an earlier notarization posted before it that it does not
    //    reference. If that is the case, it is rejected.
    // 4. Has all relevant inputs, including finalizes all necessary transactions, both confirmed and orphaned
    //printf("ValidateAcceptedNotarization\n");
    return true;
}
bool IsAcceptedNotarizationInput(const CScript &scriptSig)
{
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_ACCEPTEDNOTARIZATION;
}


/*
 * Ensures that a spend in an earned notarization of either an OpRet support transaction or summary notarization
 * are valid with respect to this chain. Any transaction that spends from an opret trasaction is either disconnected,
 * or contains the correct hashes of each object and transaction data except for the opret, which can be validated by
 * reconstructing the opret from the hashes on the other chain and verifying that it hashes to the same input value. This
 * enables full validation without copying redundant data back to its original chain.
 * 
 * In addition, each earned notarization must reference the last earned notarization with which it agrees and prove the last
 * accepted notarization on the alternate chain with the latest MMR. The earned notarization will not be accepted if there is
 * a later notarization that agrees with it already present in the alternate chain when it is submitted. 
 * 
 */
bool ValidateEarnedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    // this needs to validate that the block is mined or staked, that the notarization is properly formed,
    // cryptographically correct, and that it spends the proper finalization outputs
    // if the notarization causes a fork, it must include additional proof of blocks and their
    // power based on random block hash bits
    //printf("ValidateEarnedNotarization\n");
    return true;
}
bool IsEarnedNotarizationInput(const CScript &scriptSig)
{
    // this is an output check, and is incorrect. need to change to input
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_EARNEDNOTARIZATION;
}

/*
 * Ensures that the finalization, either as validated or orphaned, is determined by
 * 10 confirmations, either of this transaction, or of an alternate transaction on the chain that we do not derive
 * from. If the former, then this should be asserted to be validated, otherwise, it should be asserted to be invalidated.
 *  
 */
bool ValidateFinalizeNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    // this must be spent by a transaction that is either the correct number of transactions ahead in confirming
    // us, or the correct number ahead in confirming another
    //printf("ValidateFinalizeNotarization\n");
    return true;
}
bool IsFinalizeNotarizationInput(const CScript &scriptSig)
{
    // this is an output check, and is incorrect. need to change to input
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_FINALIZENOTARIZATION;
}

/*
 * Ensures that this transaction has no outputs besides those related to earned notarization, which means it cannot be spent
 * to supply. This allows it to be safely included in a block, spending a normally unspendable output from the coinbase, without
 * actually increasing the available supply.
 */
bool IsBlockBoundTransaction(const CTransaction &tx)
{
    int earnedNotarizations = 0, finalizations = 0, oprets = 0, unknown = 0;
    uint256 notarizationHash;
    for (auto output : tx.vout)
    {
        uint32_t ecode;
        if (output.scriptPubKey.IsPayToCryptoCondition(&ecode))
        {
            if (ecode == EVAL_FINALIZENOTARIZATION)
            {
                finalizations++;
            }
            else if (ecode == EVAL_EARNEDNOTARIZATION)
            {
                COptCCParams p;
                CPBaaSNotarization notarization;
                earnedNotarizations++;
                IsPayToCryptoCondition(output.scriptPubKey, p, notarization);
                notarizationHash = ::GetHash(notarization);
            }
            else
            {
                unknown++;
                break;
            }
        }
        else if (output.scriptPubKey.IsOpReturn())
        {
            oprets++;
        }
        else
        {
            unknown++;
            break;
        }
    }
    
    // no fungible outputs and a notarization that refers to itself and will need to match the coinbase output
    return earnedNotarizations == 1 && finalizations == 1 & oprets == 1 && tx.vin.size() > 0;
}
