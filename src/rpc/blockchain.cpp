// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "base58.h"
#include "consensus/validation.h"
#include "cc/eval.h"
#include "key_io.h"
#include "main.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "streams.h"
#include "sync.h"
#include "util.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "wallet/wallet.h"
#include "pbaas/pbaas.h"
#include "pbaas/notarization.h"

#include <stdint.h>

#include <univalue.h>

#include <regex>

using namespace std;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);
int32_t komodo_longestchain();

double GetDifficultyINTERNAL(const CBlockIndex* blockindex, bool networkDifficulty)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        if (chainActive.LastTip() == NULL)
            return 1.0;
        else
            blockindex = chainActive.LastTip();
    }

    uint32_t bits;
    if (networkDifficulty) {
        bits = GetNextWorkRequired(blockindex, nullptr, Params().GetConsensus());
    } else {
        bits = blockindex->nBits;
    }

    uint32_t powLimit =
        UintToArith256(Params().GetConsensus().powLimit).GetCompact();
    int nShift = (bits >> 24) & 0xff;
    int nShiftAmount = (powLimit >> 24) & 0xff;

    double dDiff =
        (double)(powLimit & 0x00ffffff) /
        (double)(bits & 0x00ffffff);

    while (nShift < nShiftAmount)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > nShiftAmount)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

double GetDifficulty(const CBlockIndex* blockindex)
{
    return GetDifficultyINTERNAL(blockindex, false);
}

double GetNetworkDifficulty(const CBlockIndex* blockindex)
{
    return GetDifficultyINTERNAL(blockindex, true);
}

static UniValue ValuePoolDesc(
    const std::string &name,
    const boost::optional<CAmount> chainValue,
    const boost::optional<CAmount> valueDelta)
{
    UniValue rv(UniValue::VOBJ);
    rv.push_back(Pair("id", name));
    rv.push_back(Pair("monitored", (bool)chainValue));
    if (chainValue) {
        rv.push_back(Pair("chainValue", ValueFromAmount(*chainValue)));
        rv.push_back(Pair("chainValueZat", *chainValue));
    }
    if (valueDelta) {
        rv.push_back(Pair("valueDelta", ValueFromAmount(*valueDelta)));
        rv.push_back(Pair("valueDeltaZat", *valueDelta));
    }
    return rv;
}

UniValue blockheaderToJSON(const CBlockIndex* blockindex)
{
    UniValue result(UniValue::VOBJ);
    if ( blockindex == 0 )
    {
        result.push_back(Pair("error", "null blockhash"));
        return(result);
    }
    result.push_back(Pair("hash", blockindex->GetBlockHash().GetHex()));
    result.push_back(Pair("calchash", blockindex->GetBlockHeader().GetHash().GetHex()));
    int confirmations = -1;

    CBlockHeader block = blockindex->GetBlockHeader();

    if (block.IsVerusPOSBlock())
    {
        result.push_back(Pair("validationtype", "stake"));
        arith_uint256 posTarget;
        posTarget.SetCompact(block.GetVerusPOSTarget());
        result.push_back(Pair("postarget", ArithToUint256(posTarget).GetHex()));
        uint256 rawPOSHash;
        block.GetRawVerusPOSHash(rawPOSHash, blockindex->GetHeight());
        result.push_back(Pair("rawposhashbh", rawPOSHash.GetHex()));
        CPOSNonce scratchNonce(block.nNonce);
    }
    else
    {
        result.push_back(Pair("validationtype", "work"));
    }

    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->GetHeight() + 1;
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("height", blockindex->GetHeight()));
    result.push_back(Pair("version", blockindex->nVersion));
    result.push_back(Pair("merkleroot", blockindex->hashMerkleRoot.GetHex()));
    result.push_back(Pair("finalsaplingroot", blockindex->hashFinalSaplingRoot.GetHex()));
    result.push_back(Pair("time", (int64_t)blockindex->nTime));
    result.push_back(Pair("nonce", blockindex->nNonce.GetHex()));
    result.push_back(Pair("solution", HexStr(blockindex->nSolution.nSolution())));
    result.push_back(Pair("bits", strprintf("%08x", blockindex->nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("chainwork", blockindex->chainPower.chainWork.GetHex()));
    result.push_back(Pair("chainstake", blockindex->chainPower.chainStake.GetHex()));
    result.push_back(Pair("segid", (int64_t)blockindex->segid));
    if (block.nVersion >= block.VERUS_V2)
    {
        auto vch = block.nSolution;
        CPBaaSSolutionDescriptor solDescr = CVerusSolutionVector(vch).Descriptor();
        result.push_back(Pair("previousstateroot", solDescr.hashPrevMMRRoot.GetHex()));
        result.push_back(Pair("blockmmrroot", solDescr.hashBlockMMRRoot.GetHex()));
    }

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));
    return result;
}

UniValue blockToDeltasJSON(const CBlock& block, const CBlockIndex* blockindex)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex)) {
        confirmations = chainActive.Height() - blockindex->GetHeight() + 1;
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block is an orphan");
    }
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->GetHeight()));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("segid", (int64_t)blockindex->segid));

    UniValue deltas(UniValue::VARR);

    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        const CTransaction &tx = block.vtx[i];
        const uint256 txhash = tx.GetHash();

        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", txhash.GetHex()));
        entry.push_back(Pair("index", (int)i));

        UniValue inputs(UniValue::VARR);

        if (!tx.IsCoinBase()) {

            for (size_t j = 0; j < tx.vin.size(); j++) {
                const CTxIn input = tx.vin[j];

                UniValue delta(UniValue::VOBJ);

                CSpentIndexValue spentInfo;
                CSpentIndexKey spentKey(input.prevout.hash, input.prevout.n);

                if (GetSpentIndex(spentKey, spentInfo)) {
                    if (spentInfo.addressType == 1) {
                        delta.push_back(Pair("address", CBitcoinAddress(CKeyID(spentInfo.addressHash)).ToString()));
                    }
                    else if (spentInfo.addressType == 2)  {
                        delta.push_back(Pair("address", CBitcoinAddress(CScriptID(spentInfo.addressHash)).ToString()));
                    }
                    else {
                        continue;
                    }
                    delta.push_back(Pair("satoshis", -1 * spentInfo.satoshis));
                    delta.push_back(Pair("index", (int)j));
                    delta.push_back(Pair("prevtxid", input.prevout.hash.GetHex()));
                    delta.push_back(Pair("prevout", (int)input.prevout.n));

                    inputs.push_back(delta);
                } else {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Spent information not available");
                }

            }
        }

        entry.push_back(Pair("inputs", inputs));

        UniValue outputs(UniValue::VARR);

        for (unsigned int k = 0; k < tx.vout.size(); k++) {
            const CTxOut &out = tx.vout[k];

            UniValue delta(UniValue::VOBJ);

            if (out.scriptPubKey.IsPayToScriptHash()) {
                vector<unsigned char> hashBytes(out.scriptPubKey.begin()+2, out.scriptPubKey.begin()+22);
                delta.push_back(Pair("address", CBitcoinAddress(CScriptID(uint160(hashBytes))).ToString()));

            }
            else if (out.scriptPubKey.IsPayToPublicKeyHash()) {
                vector<unsigned char> hashBytes(out.scriptPubKey.begin()+3, out.scriptPubKey.begin()+23);
                delta.push_back(Pair("address", CBitcoinAddress(CKeyID(uint160(hashBytes))).ToString()));
            }
            else if (out.scriptPubKey.IsPayToPublicKey() || out.scriptPubKey.IsPayToCryptoCondition()) {
                CTxDestination address;
                if (ExtractDestination(out.scriptPubKey, address))
                {
                    //vector<unsigned char> hashBytes(out.scriptPubKey.begin()+1, out.scriptPubKey.begin()+34);
                    //xxx delta.push_back(Pair("address", CBitcoinAddress(CKeyID(uint160(hashBytes))).ToString()));
                    delta.push_back(Pair("address", CBitcoinAddress(address).ToString()));
                }
            }
            else {
                continue;
            }

            delta.push_back(Pair("satoshis", out.nValue));
            delta.push_back(Pair("index", (int)k));

            outputs.push_back(delta);
        }

        entry.push_back(Pair("outputs", outputs));
        deltas.push_back(entry);

    }
    result.push_back(Pair("deltas", deltas));
    result.push_back(Pair("time", block.GetBlockTime()));
    result.push_back(Pair("mediantime", (int64_t)blockindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", block.nNonce.GetHex()));
    result.push_back(Pair("bits", strprintf("%08x", block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("chainwork", blockindex->chainPower.chainWork.GetHex()));
    result.push_back(Pair("chainstake", blockindex->chainPower.chainStake.GetHex()));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));
    if (block.nVersion >= block.VERUS_V2)
    {
        auto vch = block.nSolution;
        CPBaaSSolutionDescriptor solDescr = CVerusSolutionVector(vch).Descriptor();
        result.push_back(Pair("previousstateroot", solDescr.hashPrevMMRRoot.GetHex()));
        result.push_back(Pair("blockmmrroot", solDescr.hashBlockMMRRoot.GetHex()));
    }
    return result;
}

UniValue blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool txDetails = false)
{
    UniValue result(UniValue::VOBJ);
    int32_t height = blockindex->GetHeight();
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    if (block.IsVerusPOSBlock())
    {
        result.push_back(Pair("validationtype", "stake"));
        arith_uint256 posTarget;
        posTarget.SetCompact(block.GetVerusPOSTarget());
        result.push_back(Pair("postarget", ArithToUint256(posTarget).GetHex()));
        uint256 rawPOSHash;
        block.GetRawVerusPOSHash(rawPOSHash, height);
        result.push_back(Pair("poshashbh", ArithToUint256(UintToArith256(rawPOSHash) / block.vtx.back().vout[0].nValue).GetHex()));
        CPOSNonce scratchNonce(block.nNonce);
        CTransaction posSourceTx;
        uint256 posSrcBlkHash;
        LOCK(cs_main);
        if (GetTransaction(block.vtx.back().vin[0].prevout.hash, posSourceTx, posSrcBlkHash, true) && chainActive.Height() > 100)
        {
            uint256 pastHash = chainActive.GetVerusEntropyHash(height);

            result.push_back(Pair("poshashtx", posSourceTx.GetVerusPOSHash(&scratchNonce, block.vtx.back().vin[0].prevout.n, height, pastHash).GetHex()));
            result.push_back(Pair("possourcetxid", block.vtx.back().vin[0].prevout.hash.GetHex()));
            result.push_back(Pair("possourcevoutnum", (int)block.vtx.back().vin[0].prevout.n));
            COptCCParams p;
            if (block.vtx[0].vout[0].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid())
            {
                CTxDestination posRewardDest;
                ExtractDestination(block.vtx[0].vout[0].scriptPubKey, posRewardDest, true);
                result.push_back(Pair("posrewarddest", EncodeDestination(posRewardDest)));
                CPubKey pk = boost::apply_visitor<GetPubKeyForPubKey>(GetPubKeyForPubKey(), posRewardDest);
                if (pk.IsValid())
                {
                    result.push_back(Pair("posrewardpk", HexBytes(std::vector<unsigned char>(pk.begin(), pk.end()).data(), pk.end() - pk.begin())));
                }
                CTxDestination posTxDest;
                ExtractDestination(block.vtx.back().vout[0].scriptPubKey, posTxDest);
                result.push_back(Pair("postxddest", EncodeDestination(posTxDest)));
            }
        }
    }
    else
    {
        result.push_back(Pair("validationtype", "work"));
    }

    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->GetHeight() + 1;
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->GetHeight()));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("segid", (int64_t)blockindex->segid));
    result.push_back(Pair("finalsaplingroot", block.hashFinalSaplingRoot.GetHex()));
    UniValue txs(UniValue::VARR);
    BOOST_FOREACH(const CTransaction&tx, block.vtx)
    {
        if(txDetails)
        {
            UniValue objTx(UniValue::VOBJ);
            TxToJSON(tx, uint256(), objTx);
            txs.push_back(objTx);
        }
        else
            txs.push_back(tx.GetHash().GetHex());
    }
    result.push_back(Pair("tx", txs));
    result.push_back(Pair("time", block.GetBlockTime()));
    result.push_back(Pair("nonce", block.nNonce.GetHex()));
    result.push_back(Pair("solution", HexStr(block.nSolution)));
    result.push_back(Pair("bits", strprintf("%08x", block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("chainwork", blockindex->chainPower.chainWork.GetHex()));
    result.push_back(Pair("chainstake", blockindex->chainPower.chainStake.GetHex()));
    result.push_back(Pair("anchor", blockindex->hashFinalSproutRoot.GetHex()));
    result.push_back(Pair("blocktype", block.IsVerusPOSBlock() ? "minted" : "mined"));

    UniValue valuePools(UniValue::VARR);
    valuePools.push_back(ValuePoolDesc("sprout", blockindex->nChainSproutValue, blockindex->nSproutValue));
    valuePools.push_back(ValuePoolDesc("sapling", blockindex->nChainSaplingValue, blockindex->nSaplingValue));
    result.push_back(Pair("valuePools", valuePools));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));
    return result;
}

UniValue getblockcount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "\nReturns the number of blocks in the best valid block chain.\n"
            "\nResult:\n"
            "n    (numeric) The current block count\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockcount", "")
            + HelpExampleRpc("getblockcount", "")
        );

    return chainActive.LastTip() ? chainActive.LastTip()->GetHeight() : 0;
}

UniValue getbestblockhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getbestblockhash\n"
            "\nReturns the hash of the best (tip) block in the longest block chain.\n"
            "\nResult\n"
            "\"hex\"      (string) the block hash hex encoded\n"
            "\nExamples\n"
            + HelpExampleCli("getbestblockhash", "")
            + HelpExampleRpc("getbestblockhash", "")
        );

    LOCK(cs_main);
    return chainActive.LastTip()->GetBlockHash().GetHex();
}

UniValue getdifficulty(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nResult:\n"
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nExamples:\n"
            + HelpExampleCli("getdifficulty", "")
            + HelpExampleRpc("getdifficulty", "")
        );

    LOCK(cs_main);
    return GetNetworkDifficulty();
}

UniValue mempoolToJSON(bool fVerbose = false, bool fullTxes = false, bool includeNonSmart = false, bool excludeNonSmart = false,
                       int32_t includeCodes = 0, int32_t excludeCodes = 0, uint32_t expiresBefore = 0, uint32_t expiresAfter = 0)
{
    UniValue o(UniValue::VOBJ);
    UniValue a(UniValue::VARR);
    int32_t includeMask = 0x77fc;

    if (fVerbose || fullTxes || includeNonSmart || excludeNonSmart || includeCodes || excludeCodes || expiresBefore || expiresAfter)
    {
        LOCK(mempool.cs);

        BOOST_FOREACH(const CTxMemPoolEntry& e, mempool.mapTx)
        {
            const CTransaction& tx = e.GetTx();
            const uint256& hash = tx.GetHash();

            // filter, if we should
            if (includeNonSmart || excludeNonSmart || includeCodes || excludeCodes || expiresBefore || expiresAfter)
            {
                // check all outputs & conditions, if we should not proceed, continue the loop
                CReserveTransactionDescriptor rtxd;
                if (!mempool.IsKnownReserveTransaction(hash, rtxd) ||
                    ((rtxd.flags & includeMask) == 0 && !includeNonSmart) ||
                    ((rtxd.flags & includeMask) == 0 && excludeNonSmart) ||
                    ((rtxd.flags & includeMask) != 0 && (rtxd.flags & includeCodes) == 0) || 
                    (rtxd.flags & excludeCodes) != 0 ||
                    (expiresBefore && tx.nExpiryHeight >= expiresBefore) ||
                    (expiresAfter && tx.nExpiryHeight <= expiresAfter))
                {
                    continue;
                }
            }

            UniValue info(UniValue::VOBJ);

            if (fVerbose)
            {
                info.push_back(Pair("size", (int)e.GetTxSize()));
                info.push_back(Pair("fee", ValueFromAmount(e.GetFee())));
                info.push_back(Pair("time", e.GetTime()));
                info.push_back(Pair("height", (int)e.GetHeight()));
                info.push_back(Pair("startingpriority", e.GetPriority(e.GetHeight())));
                info.push_back(Pair("currentpriority", e.GetPriority(chainActive.Height())));

                set<string> setDepends;
                BOOST_FOREACH(const CTxIn& txin, tx.vin)
                {
                    if (mempool.exists(txin.prevout.hash))
                        setDepends.insert(txin.prevout.hash.ToString());
                }

                UniValue depends(UniValue::VARR);
                BOOST_FOREACH(const string& dep, setDepends)
                {
                    depends.push_back(dep);
                }

                info.push_back(Pair("depends", depends));
            }
            if (fullTxes)
            {
                // add full tx to info
                UniValue jsonTx(UniValue::VOBJ);
                uint256 blockHash;
                TxToJSON(tx, blockHash, jsonTx);
                info.pushKV("fulltx", jsonTx);
                o.push_back(Pair(hash.ToString(), info));
            }
            else if (!fVerbose)
            {
                a.push_back(hash.ToString());
            }
            else
            {
                o.push_back(Pair(hash.ToString(), info));
            }
        }
    }
    else
    {
        vector<uint256> vtxid;
        mempool.queryHashes(vtxid);

        BOOST_FOREACH(const uint256& hash, vtxid)
            a.push_back(hash.ToString());
    }
    return (fVerbose || fullTxes) ? o : a;
}

UniValue getrawmempool(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getrawmempool ( verbose ) '{\"include\":[],\"exclude\":[]}'\n"
            "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n"
            "\nArguments:\n"
            "1. verbose           (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"
            "2. qualifiers        (object, optional, default=null) enables selective display of specific transaction types without others\n"
            "\n"
            
            "\nResult: (for verbose = false):\n"
            "[                     (json array of string)\n"
            "  \"transactionid\"     (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nResult: (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n"
            "    \"size\" : n,             (numeric) transaction size in bytes\n"
            "    \"fee\" : n,              (numeric) transaction fee in " + CURRENCY_UNIT + "\n"
            "    \"time\" : n,             (numeric) local time transaction entered pool in seconds since 1 Jan 1970 GMT\n"
            "    \"height\" : n,           (numeric) block height when transaction entered pool\n"
            "    \"startingpriority\" : n, (numeric) priority when transaction entered pool\n"
            "    \"currentpriority\" : n,  (numeric) transaction priority now\n"
            "    \"depends\" : [           (array) unconfirmed transactions used as inputs for this transaction\n"
            "        \"transactionid\",    (string) parent transaction id\n"
            "       ... ]\n"
            "  }, ...\n"
            "}\n"
            "\nExamples\n"
            + HelpExampleCli("getrawmempool", "true")
            + HelpExampleRpc("getrawmempool", "true")
        );

    LOCK(cs_main);

    bool fVerbose = false;

    std::set<std::string> validKeySet = {"include","exclude","expiresbefore","expiresafter", "fulltxes"};
    std::string validKeys = "include, exclude, expiresbefore, expiresafter, fulltxes";

    std::string validIncludes = "evalnone, currencydef, evidence, storage"
                                "notarization, reservetransfer, reserveoutput, identitydefinition"
                                "reservedeposit, export, import, identity"
                                "commitment, identitycommitment, nonsmart";

    // those postfixed with invalid should never be found
    std::map<std::string, int32_t> keyWords = { {"evalnone", 0x20}, 
                                                {"currencydef", 0x1000},
                                                {"evidence", 0x4000}, 
                                                {"storage", 0x4000}, 
                                                {"notarization", 0x2000},
                                                {"reservetransfer", 8},
                                                {"reserveoutput", 4},
                                                {"identitydefinition", 0x400},
                                                {"reservedeposit", 0x10},
                                                {"export", 0x100},
                                                {"import", 0x80},
                                                {"identity", 0x200},
                                                {"commitment", 0x40},
                                                {"identitycommitment", 0x40},
                                                {"nonsmart", 0x10000} };

    int32_t includeMask = 0x77fc;
    int32_t includeCodes = 0;
    bool includeNonSmart = false;
    int32_t excludeCodes = 0;
    bool excludeNonSmart = false;
    uint32_t expiresBefore = 0;
    uint32_t expiresAfter = 0;
    bool displayFullTx = false;

    if (params.size() > 0)
    {
        fVerbose = params[0].get_bool();
        if (params.size() > 1)
        {
            UniValue param1 = params[1];
            if (params[1].isStr())
            {
                param1.read(params[1].get_str());
            }
            if (!param1.isObject())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter. Second parameter, if present, must be valid JSON. See help.");
            }

            std::vector<std::string> paramKeys = param1.getKeys();
            if (paramKeys.size() > validKeySet.size())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter. Second parameter, if present, must be valid JSON with the following keys: " + validKeys);
            }
            for (auto &oneKey : paramKeys)
            {
                if (!validKeySet.count(oneKey))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter. Second parameter, if present, must be valid JSON with only the following keys: " + validKeys);
                }
            }

            // take the next parameter and use it to determine a query for mem pool transactions
            UniValue includeUni = find_value(param1, "include");
            UniValue excludeUni = find_value(param1, "exclude");
            expiresBefore = uni_get_int64(find_value(param1, "expiresbefore"));
            expiresAfter = uni_get_int64(find_value(param1, "expiresafter"));
            displayFullTx = uni_get_bool(find_value(param1, "fulltxes"));
            if (includeUni.isArray() && includeUni.size() <= keyWords.size())
            {
                for (int i = 0; i < includeUni.size(); i++)
                {
                    if (!includeUni[i].isStr() || !keyWords.count(uni_get_str(includeUni[i])))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter for \"includes\", must be an array of valid strings, including: " + validIncludes);
                    }
                    includeCodes |= keyWords[uni_get_str(includeUni[i])];
                    if (includeCodes & 0x10000)
                    {
                        includeNonSmart = true;
                        includeCodes &= includeMask;
                    }
                }
            }
            if (excludeUni.isArray() && excludeUni.size() <= keyWords.size())
            {
                for (int i = 0; i < excludeUni.size(); i++)
                {
                    if (!excludeUni[i].isStr() || !keyWords.count(uni_get_str(excludeUni[i])))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter for \"excludes\", must be an array of valid strings, including: " + validIncludes);
                    }
                    excludeCodes |= keyWords[uni_get_str(excludeUni[i])];
                    if (excludeCodes & 0x10000)
                    {
                        excludeNonSmart = true;
                        excludeCodes &= includeMask;
                    }
                }
            }
        }
    }

    return mempoolToJSON(fVerbose, displayFullTx, includeNonSmart, excludeNonSmart, includeCodes, excludeCodes, expiresBefore, expiresAfter);
}

extern LRUCache<CUTXORef, std::tuple<uint256, CTransaction, std::vector<std::pair<CObjectFinalization, CNotaryEvidence>>>> finalizationEvidenceCache;
extern LRUCache<std::pair<uint256, uint32_t>, std::tuple<uint256, CInputDescriptor, CReserveTransfer>> reserveTransferCache;
extern LRUCache<std::tuple<int, uint256, uint160>, std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>>> OfferMapCache;
extern LRUCache<std::tuple<uint160, uint256, uint32_t>, std::vector<CInputDescriptor>> chainTransferCache;
extern LRUCache<std::tuple<uint256, uint32_t, uint32_t, CUTXORef, uint160, uint160>, CCurrencyValueMap> priorConversionCache;

void ClearMainCaches()
{
    finalizationEvidenceCache.Clear();
    reserveTransferCache.Clear();
    OfferMapCache.Clear();
    chainTransferCache.Clear();
    priorConversionCache.Clear();
}

UniValue clearrawmempool(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "clearrawmempool\n"
            "\nClear the mempool of all transactions on this node.\n"
            "\nArguments:\n"
            "   none\n"
            "\nResult:\n"
            "   none on success\n"
            "\n"
            "\nExamples\n"
            + HelpExampleCli("clearrawmempool", "")
            + HelpExampleRpc("clearrawmempool", "")
        );

    LOCK2(cs_main, mempool.cs);

    mempool.clear();
    ClearMainCaches();
    return NullUniValue;
}

UniValue getblockdeltas(const UniValue& params, bool fHelp)
{
    std::string enableArg = "insightexplorer";
    bool enabled = fExperimentalMode && fInsightExplorer;
    std::string disabledMsg = "";
    if (!enabled) {
        disabledMsg = experimentalDisabledHelpMsg("getblockdeltas", enableArg);
    }
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblockdeltas \"blockhash\"\n"
            "\nReturns information about the given block and its transactions.\n"
            + disabledMsg +
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "\nResult:\n"
            "{\n"
            "  \"hash\": \"hash\",              (string) block ID\n"
            "  \"confirmations\": n,          (numeric) number of confirmations\n"
            "  \"size\": n,                   (numeric) block size in bytes\n"
            "  \"height\": n,                 (numeric) block height\n"
            "  \"version\": n,                (numeric) block version (e.g. 4)\n"
            "  \"merkleroot\": \"hash\",        (hexstring) block Merkle root\n"
            "  \"deltas\": [\n"
            "    {\n"
            "      \"txid\": \"hash\",          (hexstring) transaction ID\n"
            "      \"index\": n,              (numeric) The offset of the tx in the block\n"
            "      \"inputs\": [                (array of json objects)\n"
            "        {\n"
            "          \"address\": \"taddr\",  (string) transparent address\n"
            "          \"satoshis\": n,       (numeric) negative of spend amount\n"
            "          \"index\": n,          (numeric) vin index\n"
            "          \"prevtxid\": \"hash\",  (string) source utxo tx ID\n"
            "          \"prevout\": n         (numeric) source utxo index\n"
            "        }, ...\n"
            "      ],\n"
            "      \"outputs\": [             (array of json objects)\n"
            "        {\n"
            "          \"address\": \"taddr\",  (string) transparent address\n"
            "          \"satoshis\": n,       (numeric) amount\n"
            "          \"index\": n           (numeric) vout index\n"
            "        }, ...\n"
            "      ]\n"
            "    }, ...\n"
            "  ],\n"
            "  \"time\" : n,                  (numeric) The block version\n"
            "  \"mediantime\": n,             (numeric) The most recent blocks' ave time\n"
            "  \"nonce\" : \"nonce\",           (hex string) The nonce\n"
            "  \"bits\" : \"1d00ffff\",         (hex string) The bits\n"
            "  \"difficulty\": n,             (numeric) the current difficulty\n"
            "  \"chainwork\": \"xxxx\"          (hex string) total amount of work in active chain\n"
            "  \"previousblockhash\" : \"hash\",(hex string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"     (hex string) The hash of the next block\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockdeltas", "00227e566682aebd6a7a5b772c96d7a999cadaebeaf1ce96f4191a3aad58b00b")
            + HelpExampleRpc("getblockdeltas", "\"00227e566682aebd6a7a5b772c96d7a999cadaebeaf1ce96f4191a3aad58b00b\"")
        );

    if (!enabled) {
        throw JSONRPCError(RPC_MISC_ERROR, "Error: getblockdeltas is disabled. "
            "Run './verus help getblockdeltas' for instructions on how to enable this feature.");
    }

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Block not available (pruned data)");

    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus(), 1))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    return blockToDeltasJSON(block, pblockindex);
}

UniValue getblockhashes(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2)
        throw runtime_error(
            "getblockhashes timestamp\n"
            "\nReturns array of hashes of blocks within the timestamp range provided.\n"
            "\nArguments:\n"
            "1. high         (numeric, required) The newer block timestamp\n"
            "2. low          (numeric, required) The older block timestamp\n"
            "3. options      (string, required) A json object\n"
            "    {\n"
            "      \"noOrphans\":true   (boolean) will only include blocks on the main chain\n"
            "      \"logicalTimes\":true   (boolean) will include logical timestamps with hashes\n"
            "    }\n"
            "\nResult:\n"
            "[\n"
            "  \"hash\"         (string) The block hash\n"
            "]\n"
            "[\n"
            "  {\n"
            "    \"blockhash\": (string) The block hash\n"
            "    \"logicalts\": (numeric) The logical timestamp\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockhashes", "1231614698 1231024505")
            + HelpExampleRpc("getblockhashes", "1231614698, 1231024505")
            + HelpExampleCli("getblockhashes", "1231614698 1231024505 '{\"noOrphans\":false, \"logicalTimes\":true}'")
            );

    unsigned int high = params[0].get_int();
    unsigned int low = params[1].get_int();
    bool fActiveOnly = false;
    bool fLogicalTS = false;

    if (params.size() > 2) {
        if (params[2].isObject()) {
            UniValue noOrphans = find_value(params[2].get_obj(), "noOrphans");
            UniValue returnLogical = find_value(params[2].get_obj(), "logicalTimes");

            if (noOrphans.isBool())
                fActiveOnly = noOrphans.get_bool();

            if (returnLogical.isBool())
                fLogicalTS = returnLogical.get_bool();
        }
    }

    std::vector<std::pair<uint256, unsigned int> > blockHashes;

    if (fActiveOnly)
        LOCK(cs_main);

    if (!GetTimestampIndex(high, low, fActiveOnly, blockHashes)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for block hashes");
    }

    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<uint256, unsigned int> >::const_iterator it=blockHashes.begin(); it!=blockHashes.end(); it++) {
        if (fLogicalTS) {
            UniValue item(UniValue::VOBJ);
            item.push_back(Pair("blockhash", it->first.GetHex()));
            item.push_back(Pair("logicalts", (int)it->second));
            result.push_back(item);
        } else {
            result.push_back(it->first.GetHex());
        }
    }
    return result;
}

//! Sanity-check a height argument and interpret negative values.
int interpretHeightArg(int nHeight, int currentHeight)
{
    if (nHeight < 0) {
        nHeight += currentHeight + 1;
    }
    if (nHeight < 0 || nHeight > currentHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
    }
    return nHeight;
}

//! Parse and sanity-check a height argument, return its integer representation.
int parseHeightArg(const std::string& strHeight, int currentHeight)
{
    // std::stoi allows (locale-dependent) whitespace and optional '+' sign,
    // whereas we want to be strict.
    regex r("(?:(-?)[1-9][0-9]*|[0-9]+)");
    if (!regex_match(strHeight, r)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block height parameter");
    }
    int nHeight;
    try {
        nHeight = std::stoi(strHeight);
    }
    catch (const std::exception &e) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block height parameter");
    }
    return interpretHeightArg(nHeight, currentHeight);
}

UniValue z_gettreestate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_gettreestate \"hash|height\"\n"
            "Return information about the given block's tree state.\n"
            "\nArguments:\n"
            "1. \"hash|height\"          (string, required) The block hash or height. Height can be negative where -1 is the last known valid block\n"
            "\nResult:\n"
            "{\n"
            "  \"hash\": \"hash\",         (string) hex block hash\n"
            "  \"height\": n,            (numeric) block height\n"
            "  \"sprout\": {\n"
            "    \"skipHash\": \"hash\",   (string) hash of most recent block with more information\n"
            "    \"commitments\": {\n"
            "      \"finalRoot\": \"hex\", (string)\n"
            "      \"finalState\": \"hex\" (string)\n"
            "    }\n"
            "  },\n"
            "  \"sapling\": {\n"
            "    \"skipHash\": \"hash\",   (string) hash of most recent block with more information\n"
            "    \"commitments\": {\n"
            "      \"finalRoot\": \"hex\", (string)\n"
            "      \"finalState\": \"hex\" (string)\n"
            "    }\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("z_gettreestate", "\"00000000febc373a1da2bd9f887b105ad79ddc26ac26c2b28652d64e5207c5b5\"")
            + HelpExampleRpc("z_gettreestate", "\"00000000febc373a1da2bd9f887b105ad79ddc26ac26c2b28652d64e5207c5b5\"")
            + HelpExampleCli("z_gettreestate", "12800")
            + HelpExampleRpc("z_gettreestate", "12800")
        );

    LOCK(cs_main);

    std::string strHash = params[0].get_str();

    // If height is supplied, find the hash
    if (strHash.size() < (2 * sizeof(uint256))) {
        strHash = chainActive[parseHeightArg(strHash, chainActive.Height())]->GetBlockHash().GetHex();
    }
    uint256 hash(uint256S(strHash));

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    const CBlockIndex* const pindex = mapBlockIndex[hash];
    if (!chainActive.Contains(pindex)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Requested block is not part of the main chain");
    }

    UniValue res(UniValue::VOBJ);
    res.pushKV("hash", pindex->GetBlockHash().GetHex());
    res.pushKV("height", pindex->GetHeight());
    res.pushKV("time", int64_t(pindex->nTime));

    // sprout
    {
        UniValue sprout_result(UniValue::VOBJ);
        UniValue sprout_commitments(UniValue::VOBJ);
        sprout_commitments.pushKV("finalRoot", pindex->hashFinalSproutRoot.GetHex());
        SproutMerkleTree tree;
        if (pcoinsTip->GetSproutAnchorAt(pindex->hashFinalSproutRoot, tree)) {
            CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
            s << tree;
            sprout_commitments.pushKV("finalState", HexStr(s.begin(), s.end()));
        } else {
            // Set skipHash to the most recent block that has a finalState.
            const CBlockIndex* pindex_skip = pindex->pprev;
            while (pindex_skip && !pcoinsTip->GetSproutAnchorAt(pindex_skip->hashFinalSproutRoot, tree)) {
                pindex_skip = pindex_skip->pprev;
            }
            if (pindex_skip) {
                sprout_result.pushKV("skipHash", pindex_skip->GetBlockHash().GetHex());
            }
        }
        sprout_result.pushKV("commitments", sprout_commitments);
        res.pushKV("sprout", sprout_result);
    }

    // sapling
    {
        UniValue sapling_result(UniValue::VOBJ);
        UniValue sapling_commitments(UniValue::VOBJ);
        sapling_commitments.pushKV("finalRoot", pindex->hashFinalSaplingRoot.GetHex());
        bool need_skiphash = false;
        SaplingMerkleTree tree;
        if (pcoinsTip->GetSaplingAnchorAt(pindex->hashFinalSaplingRoot, tree)) {
            CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
            s << tree;
            sapling_commitments.pushKV("finalState", HexStr(s.begin(), s.end()));
        } else {
            // Set skipHash to the most recent block that has a finalState.
            const CBlockIndex* pindex_skip = pindex->pprev;
            while (pindex_skip && !pcoinsTip->GetSaplingAnchorAt(pindex_skip->hashFinalSaplingRoot, tree)) {
                pindex_skip = pindex_skip->pprev;
            }
            if (pindex_skip) {
                sapling_result.pushKV("skipHash", pindex_skip->GetBlockHash().GetHex());
            }
        }
        sapling_result.pushKV("commitments", sapling_commitments);
        res.pushKV("sapling", sapling_result);
    }

    return res;
}

inline CBlockIndex* LookupBlockIndex(const uint256& hash)
{
    AssertLockHeld(cs_main);
    BlockMap::const_iterator it = mapBlockIndex.find(hash);
    return it == mapBlockIndex.end() ? nullptr : it->second;
}

UniValue getchaintxstats(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
                "getchaintxstats\n"
                "\nCompute statistics about the total number and rate of transactions in the chain.\n"
                "\nArguments:\n"
                "1. nblocks   (numeric, optional) Number of blocks in averaging window.\n"
                "2. blockhash (string, optional) The hash of the block which ends the window.\n"
                "\nResult:\n"
            "{\n"
            "  \"time\": xxxxx,                         (numeric) The timestamp for the final block in the window in UNIX format.\n"
            "  \"txcount\": xxxxx,                      (numeric) The total number of transactions in the chain up to that point.\n"
            "  \"window_final_block_hash\": \"...\",      (string) The hash of the final block in the window.\n"
            "  \"window_block_count\": xxxxx,           (numeric) Size of the window in number of blocks.\n"
            "  \"window_tx_count\": xxxxx,              (numeric) The number of transactions in the window. Only returned if \"window_block_count\" is > 0.\n"
            "  \"window_interval\": xxxxx,              (numeric) The elapsed time in the window in seconds. Only returned if \"window_block_count\" is > 0.\n"
            "  \"txrate\": x.xx,                        (numeric) The average rate of transactions per second in the window. Only returned if \"window_interval\" is > 0.\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getchaintxstats", "")
            + HelpExampleRpc("getchaintxstats", "2016")
        );

    const CBlockIndex* pindex;
    int blockcount = 30 * 24 * 60 * 60 / Params().GetConsensus().nPowTargetSpacing; // By default: 1 month

    if (params[1].isNull()) {
        LOCK(cs_main);
        pindex = chainActive.Tip();
    } else {
        uint256 hash(ParseHashV(params[1], "blockhash"));
        LOCK(cs_main);
        pindex = LookupBlockIndex(hash);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        if (!chainActive.Contains(pindex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not in main chain");
        }
    }

    assert(pindex != nullptr);

    if (params[0].isNull()) {
        blockcount = std::max(0, std::min(blockcount, pindex->GetHeight() - 1));
    } else {
        blockcount = params[0].get_int();

        if (blockcount < 0 || (blockcount > 0 && blockcount >= pindex->GetHeight())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block count: should be between 0 and the block's height - 1");
        }
    }

    const CBlockIndex* pindexPast = pindex->GetAncestor(pindex->GetHeight() - blockcount);
    int nTimeDiff = pindex->GetMedianTimePast() - pindexPast->GetMedianTimePast();
    int nTxDiff = pindex->nChainTx - pindexPast->nChainTx;

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("time", (int64_t)pindex->nTime);
    ret.pushKV("txcount", (int64_t)pindex->nChainTx);
    ret.pushKV("window_final_block_hash", pindex->GetBlockHash().GetHex());
    ret.pushKV("window_block_count", blockcount);
    if (blockcount > 0) {
        ret.pushKV("window_tx_count", nTxDiff);
        ret.pushKV("window_interval", nTimeDiff);
        if (nTimeDiff > 0) {
            ret.pushKV("txrate", ((double)nTxDiff) / nTimeDiff);
        }
    }

    return ret;
}

UniValue getblockhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblockhash index\n"
            "\nReturns hash of block in best-block-chain at index provided.\n"
            "\nArguments:\n"
            "1. index         (numeric, required) The block index\n"
            "\nResult:\n"
            "\"hash\"         (string) The block hash\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockhash", "1000")
            + HelpExampleRpc("getblockhash", "1000")
        );

    LOCK(cs_main);

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > chainActive.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    CBlockIndex* pblockindex = chainActive[nHeight];
    return pblockindex->GetBlockHash().GetHex();
}

UniValue getblockheader(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblockheader \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.\n"
            "If verbose is true, returns an Object with information about blockheader <hash>.\n"
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"
            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"finalsaplingroot\" : \"xxxx\", (string) The root of the Sapling commitment tree after applying this block\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"       (string) The hash of the next block\n"
            "}\n"
            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
        );

    LOCK(cs_main);

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (!fVerbose)
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << pblockindex->GetBlockHeader();
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockheaderToJSON(pblockindex);
}

UniValue getblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblock \"hash|height\" ( verbosity )\n"
            "\nIf verbosity is 0, returns a string that is serialized, hex-encoded data for the block.\n"
            "If verbosity is 1, returns an Object with information about the block.\n"
            "If verbosity is 2, returns an Object with information about the block and information about each transaction. \n"
            "\nArguments:\n"
            "1. \"hash|height\"          (string, required) The block hash or height\n"
            "2. verbosity              (numeric, optional, default=1) 0 for hex encoded data, 1 for a json object, and 2 for json object with transaction data\n"
            "\nResult (for verbosity = 0):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for the block.\n"
            "\nResult (for verbosity = 1):\n"
            "{\n"
            "  \"hash\" : \"hash\",       (string) the block hash (same as provided hash)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"size\" : n,            (numeric) The block size\n"
            "  \"height\" : n,          (numeric) The block height or index (same as provided height)\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"finalsaplingroot\" : \"xxxx\", (string) The root of the Sapling commitment tree after applying this block\n"
            "  \"tx\" : [               (array of string) The transaction ids\n"
            "     \"transactionid\"     (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\",   (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"       (string) The hash of the next block\n"
            "}\n"
            "\nResult (for verbosity = 2):\n"
            "{\n"
            "  ...,                     Same output as verbosity = 1.\n"
            "  \"tx\" : [               (array of Objects) The transactions in the format of the getrawtransaction RPC. Different from verbosity = 1 \"tx\" result.\n"
            "         ,...\n"
            "  ],\n"
            "  ,...                     Same output as verbosity = 1.\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getblock", "\"00000000febc373a1da2bd9f887b105ad79ddc26ac26c2b28652d64e5207c5b5\"")
            + HelpExampleRpc("getblock", "\"00000000febc373a1da2bd9f887b105ad79ddc26ac26c2b28652d64e5207c5b5\"")
            + HelpExampleCli("getblock", "12800")
            + HelpExampleRpc("getblock", "12800")
        );

    LOCK(cs_main);

    std::string strHash = params[0].get_str();

    // If height is supplied, find the hash
    if (strHash.size() < (2 * sizeof(uint256))) {
        // std::stoi allows characters, whereas we want to be strict
        regex r("[[:digit:]]+");
        if (!regex_match(strHash, r)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block height parameter");
        }

        int nHeight = -1;
        try {
            nHeight = std::stoi(strHash);
        }
        catch (const std::exception &e) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block height parameter");
        }

        if (nHeight < 0 || nHeight > chainActive.Height()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
        }
        strHash = chainActive[nHeight]->GetBlockHash().GetHex();
    }

    uint256 hash(uint256S(strHash));

    int verbosity = 1;
    if (params.size() > 1) {
        if(params[1].isNum()) {
            verbosity = params[1].get_int();
        } else {
            verbosity = params[1].get_bool() ? 1 : 0;
        }
    }

    if (verbosity < 0 || verbosity > 2) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Verbosity must be in range from 0 to 2");
    }

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Block not available (pruned data)");

    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus(), 1))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    if (verbosity == 0)
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }
    UniValue blockUni = blockToJSON(block, pblockindex, verbosity >= 2);
    if (pblockindex)
    {
        blockUni.pushKV("proofroot", CProofRoot::GetProofRoot(pblockindex->GetHeight()).ToUniValue());
        if (CConstVerusSolutionVector::GetVersionByHeight(pblockindex->GetHeight()) >= CActivationHeight::ACTIVATE_PBAAS_HEADER)
        {
            blockUni.pushKV("prevmmrroot", block.GetPrevMMRRoot().GetHex());
        }
    }
    return blockUni;
}

UniValue gettxoutsetinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "gettxoutsetinfo\n"
            "\nReturns statistics about the unspent transaction output set.\n"
            "Note this call may take some time.\n"
            "\nResult:\n"
            "{\n"
            "  \"height\":n,     (numeric) The current block height (index)\n"
            "  \"bestblock\": \"hex\",   (string) the best block hash hex\n"
            "  \"transactions\": n,      (numeric) The number of transactions\n"
            "  \"txouts\": n,            (numeric) The number of output transactions\n"
            "  \"bytes_serialized\": n,  (numeric) The serialized size\n"
            "  \"hash_serialized\": \"hash\",   (string) The serialized hash\n"
            "  \"total_amount\": x.xxx          (numeric) The total amount\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("gettxoutsetinfo", "")
            + HelpExampleRpc("gettxoutsetinfo", "")
        );

    UniValue ret(UniValue::VOBJ);

    CCoinsStats stats;
    FlushStateToDisk();
    if (pcoinsTip->GetStats(stats)) {
        ret.push_back(Pair("height", (int64_t)stats.nHeight));
        ret.push_back(Pair("bestblock", stats.hashBlock.GetHex()));
        ret.push_back(Pair("transactions", (int64_t)stats.nTransactions));
        ret.push_back(Pair("txouts", (int64_t)stats.nTransactionOutputs));
        ret.push_back(Pair("bytes_serialized", (int64_t)stats.nSerializedSize));
        ret.push_back(Pair("hash_serialized", stats.hashSerialized.GetHex()));
        ret.push_back(Pair("total_amount", ValueFromAmount(stats.nTotalAmount)));
    }
    return ret;
}

#include "komodo_defs.h"
#include "komodo_structs.h"

#define IGUANA_MAXSCRIPTSIZE 10001
#define KOMODO_KVDURATION 1440
#define KOMODO_KVBINARY 2
extern char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN];
extern int32_t ASSETCHAINS_LWMAPOS;
int32_t komodo_notaries(uint8_t pubkeys[64][33],int32_t height,uint32_t timestamp);
char *bitcoin_address(char *coinaddr,uint8_t addrtype,uint8_t *pubkey_or_rmd160,int32_t len);
int32_t komodo_minerids(uint8_t *minerids,int32_t height,int32_t width);

UniValue minerids(const UniValue& params, bool fHelp)
{
    uint32_t timestamp = 0; UniValue ret(UniValue::VOBJ); UniValue a(UniValue::VARR); uint8_t minerids[2000],pubkeys[65][33]; int32_t i,j,n,numnotaries,tally[129];
    if ( fHelp || params.size() != 1 )
        throw runtime_error("minerids needs height\n");
    LOCK(cs_main);
    int32_t height = atoi(params[0].get_str().c_str());
    if ( height <= 0 )
        height = chainActive.LastTip()->GetHeight();
    else
    {
        CBlockIndex *pblockindex = chainActive[height];
        if ( pblockindex != 0 )
            timestamp = pblockindex->GetBlockTime();
    }
    if ( (n= komodo_minerids(minerids,height,(int32_t)(sizeof(minerids)/sizeof(*minerids)))) > 0 )
    {
        memset(tally,0,sizeof(tally));
        numnotaries = komodo_notaries(pubkeys,height,timestamp);
        if ( numnotaries > 0 )
        {
            for (i=0; i<n; i++)
            {
                if ( minerids[i] >= numnotaries )
                    tally[128]++;
                else tally[minerids[i]]++;
            }
            for (i=0; i<64; i++)
            {
                UniValue item(UniValue::VOBJ); std::string hex,kmdaddress; char *hexstr,kmdaddr[64],*ptr; int32_t m;
                hex.resize(66);
                hexstr = (char *)hex.data();
                for (j=0; j<33; j++)
                    sprintf(&hexstr[j*2],"%02x",pubkeys[i][j]);
                item.push_back(Pair("notaryid", i));

                bitcoin_address(kmdaddr,60,pubkeys[i],33);
                m = (int32_t)strlen(kmdaddr);
                kmdaddress.resize(m);
                ptr = (char *)kmdaddress.data();
                memcpy(ptr,kmdaddr,m);
                item.push_back(Pair("KMDaddress", kmdaddress));

                item.push_back(Pair("pubkey", hex));
                item.push_back(Pair("blocks", tally[i]));
                a.push_back(item);
            }
            UniValue item(UniValue::VOBJ);
            item.push_back(Pair("pubkey", (char *)"external miners"));
            item.push_back(Pair("blocks", tally[128]));
            a.push_back(item);
        }
        ret.push_back(Pair("mined", a));
        ret.push_back(Pair("numnotaries", numnotaries));
    } else ret.push_back(Pair("error", (char *)"couldnt extract minerids"));
    return ret;
}

UniValue notaries(const UniValue& params, bool fHelp)
{
    UniValue a(UniValue::VARR); uint32_t timestamp=0; UniValue ret(UniValue::VOBJ); int32_t i,j,n,m; char *hexstr;  uint8_t pubkeys[64][33]; char btcaddr[64],kmdaddr[64],*ptr;
    if ( fHelp || (params.size() != 1 && params.size() != 2) )
        throw runtime_error("notaries height timestamp\n");
    LOCK(cs_main);
    int32_t height = atoi(params[0].get_str().c_str());
    if ( params.size() == 2 )
        timestamp = (uint32_t)atol(params[1].get_str().c_str());
    else timestamp = (uint32_t)time(NULL);
    if ( height < 0 )
    {
        height = chainActive.LastTip()->GetHeight();
        timestamp = chainActive.LastTip()->GetBlockTime();
    }
    else if ( params.size() < 2 )
    {
        CBlockIndex *pblockindex = chainActive[height];
        if ( pblockindex != 0 )
            timestamp = pblockindex->GetBlockTime();
    }
    if ( (n= komodo_notaries(pubkeys,height,timestamp)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            UniValue item(UniValue::VOBJ);
            std::string btcaddress,kmdaddress,hex;
            hex.resize(66);
            hexstr = (char *)hex.data();
            for (j=0; j<33; j++)
                sprintf(&hexstr[j*2],"%02x",pubkeys[i][j]);
            item.push_back(Pair("pubkey", hex));

            bitcoin_address(btcaddr,0,pubkeys[i],33);
            m = (int32_t)strlen(btcaddr);
            btcaddress.resize(m);
            ptr = (char *)btcaddress.data();
            memcpy(ptr,btcaddr,m);
            item.push_back(Pair("BTCaddress", btcaddress));

            bitcoin_address(kmdaddr,60,pubkeys[i],33);
            m = (int32_t)strlen(kmdaddr);
            kmdaddress.resize(m);
            ptr = (char *)kmdaddress.data();
            memcpy(ptr,kmdaddr,m);
            item.push_back(Pair("KMDaddress", kmdaddress));
            a.push_back(item);
        }
    }
    ret.push_back(Pair("notaries", a));
    ret.push_back(Pair("numnotaries", n));
    ret.push_back(Pair("height", height));
    ret.push_back(Pair("timestamp", (uint64_t)timestamp));
    return ret;
}

uint64_t komodo_accrued_interest(int32_t *txheightp,uint32_t *locktimep,uint256 hash,int32_t n,int32_t checkheight,uint64_t checkvalue,int32_t tipheight);

UniValue gettxout(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "gettxout \"txid\" n ( includemempool )\n"
            "\nReturns details about an unspent transaction output.\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id\n"
            "2. n              (numeric, required) vout value\n"
            "3. includemempool  (boolean, optional) Whether to include the mempool\n"
            "\nResult:\n"
            "{\n"
            "  \"bestblock\" : \"hash\",    (string) the block hash\n"
            "  \"confirmations\" : n,       (numeric) The number of confirmations\n"
            "  \"value\" : x.xxx,           (numeric) The transaction value in " + CURRENCY_UNIT + "\n"
            "  \"scriptPubKey\" : {         (json object)\n"
            "     \"asm\" : \"code\",       (string) \n"
            "     \"hex\" : \"hex\",        (string) \n"
            "     \"reqSigs\" : n,          (numeric) Number of required signatures\n"
            "     \"type\" : \"pubkeyhash\", (string) The type, eg pubkeyhash\n"
            "     \"addresses\" : [          (array of string) array of Verus addresses\n"
            "        \"verusaddress\"        (string) Verus address\n"
            "        ,...\n"
            "     ]\n"
            "  },\n"
            "  \"version\" : n,              (numeric) The version\n"
            "  \"coinbase\" : true|false     (boolean) Coinbase or not\n"
            "}\n"

            "\nExamples:\n"
            "\nGet unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nView the details\n"
            + HelpExampleCli("gettxout", "\"txid\" 1") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("gettxout", "\"txid\", 1")
        );

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    int n = params[1].get_int();
    bool fMempool = true;
    if (params.size() > 2)
        fMempool = params[2].get_bool();

    CCoins coins;
    if (fMempool) {
        LOCK(mempool.cs);
        CCoinsViewMemPool view(pcoinsTip, mempool);
        if (!view.GetCoins(hash, coins))
            return NullUniValue;
        mempool.pruneSpent(hash, coins); // TODO: this should be done by the CCoinsViewMemPool
    } else {
        if (!pcoinsTip->GetCoins(hash, coins))
            return NullUniValue;
    }
    if (n<0 || (unsigned int)n>=coins.vout.size() || coins.vout[n].IsNull())
        return NullUniValue;

    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->GetBestBlock());
    CBlockIndex *pindex = it->second;
    ret.push_back(Pair("bestblock", pindex->GetBlockHash().GetHex()));
    if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
        ret.push_back(Pair("confirmations", 0));
    else ret.push_back(Pair("confirmations", pindex->GetHeight() - coins.nHeight + 1));
    ret.push_back(Pair("value", ValueFromAmount(coins.vout[n].nValue)));
    uint64_t interest; int32_t txheight; uint32_t locktime;
    if ( (interest= komodo_accrued_interest(&txheight,&locktime,hash,n,coins.nHeight,coins.vout[n].nValue,(int32_t)pindex->GetHeight())) != 0 )
        ret.push_back(Pair("interest", ValueFromAmount(interest)));
    UniValue o(UniValue::VOBJ);
    ScriptPubKeyToJSON(coins.vout[n].scriptPubKey, o, true);
    ret.push_back(Pair("scriptPubKey", o));
    ret.push_back(Pair("version", coins.nVersion));
    ret.push_back(Pair("coinbase", coins.fCoinBase));

    return ret;
}

UniValue verifychain(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "verifychain ( checklevel numblocks )\n"
            "\nVerifies blockchain database.\n"
            "\nArguments:\n"
            "1. checklevel   (numeric, optional, 0-4, default=3) How thorough the block verification is.\n"
            "2. numblocks    (numeric, optional, default=288, 0=all) The number of blocks to check.\n"
            "\nResult:\n"
            "true|false       (boolean) Verified or not\n"
            "\nExamples:\n"
            + HelpExampleCli("verifychain", "")
            + HelpExampleRpc("verifychain", "")
        );

    LOCK(cs_main);

    int nCheckLevel = GetArg("-checklevel", 3);
    int nCheckDepth = GetArg("-checkblocks", 288);
    if (params.size() > 0)
        nCheckLevel = params[0].get_int();
    if (params.size() > 1)
        nCheckDepth = params[1].get_int();

    return CVerifyDB().VerifyDB(Params(), pcoinsTip, nCheckLevel, nCheckDepth);
}

/** Implementation of IsSuperMajority with better feedback */
static UniValue SoftForkMajorityDesc(int minVersion, CBlockIndex* pindex, int nRequired, const Consensus::Params& consensusParams)
{
    int nFound = 0;
    CBlockIndex* pstart = pindex;
    for (int i = 0; i < consensusParams.nMajorityWindow && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }

    UniValue rv(UniValue::VOBJ);
    rv.push_back(Pair("status", nFound >= nRequired));
    rv.push_back(Pair("found", nFound));
    rv.push_back(Pair("required", nRequired));
    rv.push_back(Pair("window", consensusParams.nMajorityWindow));
    return rv;
}

static UniValue SoftForkDesc(const std::string &name, int version, CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    UniValue rv(UniValue::VOBJ);
    rv.push_back(Pair("id", name));
    rv.push_back(Pair("version", version));
    rv.push_back(Pair("enforce", SoftForkMajorityDesc(version, pindex, consensusParams.nMajorityEnforceBlockUpgrade, consensusParams)));
    rv.push_back(Pair("reject", SoftForkMajorityDesc(version, pindex, consensusParams.nMajorityRejectBlockOutdated, consensusParams)));
    return rv;
}

static UniValue NetworkUpgradeDesc(const Consensus::Params& consensusParams, Consensus::UpgradeIndex idx, int height)
{
    UniValue rv(UniValue::VOBJ);
    auto upgrade = NetworkUpgradeInfo[idx];
    rv.push_back(Pair("name", upgrade.strName));
    rv.push_back(Pair("activationheight", consensusParams.vUpgrades[idx].nActivationHeight));
    switch (NetworkUpgradeState(height, consensusParams, idx)) {
        case UPGRADE_DISABLED: rv.push_back(Pair("status", "disabled")); break;
        case UPGRADE_PENDING: rv.push_back(Pair("status", "pending")); break;
        case UPGRADE_ACTIVE: rv.push_back(Pair("status", "active")); break;
    }
    rv.push_back(Pair("info", upgrade.strInfo));
    return rv;
}

void NetworkUpgradeDescPushBack(
    UniValue& networkUpgrades,
    const Consensus::Params& consensusParams,
    Consensus::UpgradeIndex idx,
    int height)
{
    // Network upgrades with an activation height of NO_ACTIVATION_HEIGHT are
    // hidden. This is used when network upgrade implementations are merged
    // without specifying the activation height.
    if (consensusParams.vUpgrades[idx].nActivationHeight != Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT) {
        networkUpgrades.push_back(Pair(
            HexInt(NetworkUpgradeInfo[idx].nBranchId),
            NetworkUpgradeDesc(consensusParams, idx, height)));
    }
}


UniValue getblockchaininfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockchaininfo\n"
            "Returns an object containing various state info regarding block chain processing.\n"
            "\nNote that when the chain tip is at the last block before a network upgrade activation,\n"
            "consensus.chaintip != consensus.nextblock.\n"
            "\nResult:\n"
            "{\n"
            "  \"chain\": \"xxxx\",        (string) current network type of blockchain (main, test, regtest)\n"
            "  \"name\": \"xxxx\",         (string) current network name of blockchain ID (VRSC, VRSCTEST, PBAASNAME)\n"
            "  \"chainid\": \"xxxx\",      (string) blockchain ID (i-address of the native blockchain currency)\n"
            "  \"blocks\": xxxxxx,         (numeric) the current number of blocks processed in the server\n"
            "  \"headers\": xxxxxx,        (numeric) the current number of headers we have validated\n"
            "  \"bestblockhash\": \"...\", (string) the hash of the currently best block\n"
            "  \"difficulty\": xxxxxx,     (numeric) the current difficulty\n"
            "  \"verificationprogress\": xxxx, (numeric) estimate of verification progress [0..1]\n"
            "  \"chainwork\": \"xxxx\"     (string) total amount of work in active chain, in hexadecimal\n"
            "  \"size_on_disk\": xxxxxx,       (numeric) the estimated size of the block and undo files on disk\n"
            "  \"commitments\": xxxxxx,    (numeric) the current number of note commitments in the commitment tree\n"
            "  \"softforks\": [            (array) status of softforks in progress\n"
            "     {\n"
            "        \"id\": \"xxxx\",        (string) name of softfork\n"
            "        \"version\": xx,         (numeric) block version\n"
            "        \"enforce\": {           (object) progress toward enforcing the softfork rules for new-version blocks\n"
            "           \"status\": xx,       (boolean) true if threshold reached\n"
            "           \"found\": xx,        (numeric) number of blocks with the new version found\n"
            "           \"required\": xx,     (numeric) number of blocks required to trigger\n"
            "           \"window\": xx,       (numeric) maximum size of examined window of recent blocks\n"
            "        },\n"
            "        \"reject\": { ... }      (object) progress toward rejecting pre-softfork blocks (same fields as \"enforce\")\n"
            "     }, ...\n"
            "  ],\n"
            "  \"upgrades\": {                (object) status of network upgrades\n"
            "     \"xxxx\" : {                (string) branch ID of the upgrade\n"
            "        \"name\": \"xxxx\",        (string) name of upgrade\n"
            "        \"activationheight\": xxxxxx,  (numeric) block height of activation\n"
            "        \"status\": \"xxxx\",      (string) status of upgrade\n"
            "        \"info\": \"xxxx\",        (string) additional information about upgrade\n"
            "     }, ...\n"
            "  },\n"
            "  \"consensus\": {               (object) branch IDs of the current and upcoming consensus rules\n"
            "     \"chaintip\": \"xxxxxxxx\",   (string) branch ID used to validate the current chain tip\n"
            "     \"nextblock\": \"xxxxxxxx\"   (string) branch ID that the next block will be validated under\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockchaininfo", "")
            + HelpExampleRpc("getblockchaininfo", "")
        );

    LOCK(cs_main);
    double progress;
    if ( ASSETCHAINS_SYMBOL[0] == 0 ) {
        progress = Checkpoints::GuessVerificationProgress(Params().Checkpoints(), chainActive.LastTip());
    } else {
	    int32_t longestchain = komodo_longestchain();
	    progress = (longestchain > 0 ) ? (double) chainActive.Height() / longestchain : 1.0;
    }
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("chain",                 PBAAS_TESTMODE ? "test" : "main"));
    obj.push_back(Pair("name",                  ConnectedChains.ThisChain().name));
    obj.push_back(Pair("chainid",               EncodeDestination(CIdentityID(ConnectedChains.ThisChain().GetID()))));
    obj.push_back(Pair("blocks",                (int)chainActive.Height()));
    obj.push_back(Pair("headers",               pindexBestHeader ? pindexBestHeader->GetHeight() : -1));
    obj.push_back(Pair("bestblockhash",         chainActive.LastTip()->GetBlockHash().GetHex()));
    obj.push_back(Pair("difficulty",            (double)GetNetworkDifficulty()));
    obj.push_back(Pair("verificationprogress",  progress));
    obj.push_back(Pair("chainwork",             chainActive.LastTip()->chainPower.chainWork.GetHex()));
    if (ASSETCHAINS_LWMAPOS)
    {
        obj.push_back(Pair("chainstake",        chainActive.LastTip()->chainPower.chainStake.GetHex()));
    }
    obj.push_back(Pair("pruned",                fPruneMode));
    obj.push_back(Pair("size_on_disk",          CalculateCurrentUsage()));

    SproutMerkleTree tree;
    pcoinsTip->GetSproutAnchorAt(pcoinsTip->GetBestAnchor(SPROUT), tree);
    obj.push_back(Pair("commitments",           static_cast<uint64_t>(tree.size())));

    CBlockIndex* tip = chainActive.LastTip();
    UniValue valuePools(UniValue::VARR);
    valuePools.push_back(ValuePoolDesc("sprout", tip->nChainSproutValue, boost::none));
    valuePools.push_back(ValuePoolDesc("sapling", tip->nChainSaplingValue, boost::none));
    obj.push_back(Pair("valuePools",            valuePools));

    const Consensus::Params& consensusParams = Params().GetConsensus();
    UniValue softforks(UniValue::VARR);
    softforks.push_back(SoftForkDesc("bip34", 2, tip, consensusParams));
    softforks.push_back(SoftForkDesc("bip66", 3, tip, consensusParams));
    softforks.push_back(SoftForkDesc("bip65", 4, tip, consensusParams));
    obj.push_back(Pair("softforks",             softforks));

    UniValue upgrades(UniValue::VOBJ);
    for (int i = Consensus::UPGRADE_OVERWINTER; i < Consensus::MAX_NETWORK_UPGRADES; i++) {
        NetworkUpgradeDescPushBack(upgrades, consensusParams, Consensus::UpgradeIndex(i), tip->GetHeight());
    }
    obj.push_back(Pair("upgrades", upgrades));

    UniValue consensus(UniValue::VOBJ);
    consensus.push_back(Pair("chaintip", HexInt(CurrentEpochBranchId(tip->GetHeight(), consensusParams))));
    consensus.push_back(Pair("nextblock", HexInt(CurrentEpochBranchId(tip->GetHeight() + 1, consensusParams))));
    obj.push_back(Pair("consensus", consensus));

    if (fPruneMode)
    {
        CBlockIndex *block = chainActive.LastTip();
        while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA))
            block = block->pprev;

        obj.push_back(Pair("pruneheight",        block->GetHeight()));
    }
    return obj;
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight
{
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->GetHeight() != b->GetHeight())
          return (a->GetHeight() > b->GetHeight());

        return a < b;
    }
};

UniValue getchaintips(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getchaintips\n"
            "Return information about all known tips in the block tree,"
            " including the main chain as well as orphaned branches.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"height\": xxxx,         (numeric) height of the chain tip\n"
            "    \"hash\": \"xxxx\",         (string) block hash of the tip\n"
            "    \"branchlen\": 0          (numeric) zero for main chain\n"
            "    \"status\": \"active\"      (string) \"active\" for the main chain\n"
            "  },\n"
            "  {\n"
            "    \"height\": xxxx,\n"
            "    \"hash\": \"xxxx\",\n"
            "    \"branchlen\": 1          (numeric) length of branch connecting the tip to the main chain\n"
            "    \"status\": \"xxxx\"        (string) status of the chain (active, valid-fork, valid-headers, headers-only, invalid)\n"
            "  }\n"
            "]\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid\n"
            "\nExamples:\n"
            + HelpExampleCli("getchaintips", "")
            + HelpExampleRpc("getchaintips", "")
        );

    LOCK(cs_main);

    /* Build up a list of chain tips.  We start with the list of all
       known blocks, and successively remove blocks that appear as pprev
       of another block.  */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    for (const auto &item : mapBlockIndex)
    {
        setTips.insert(item.second);
    }
    for (const auto &item : mapBlockIndex)
    {
        const CBlockIndex* pprev=0;
        if ( item.second != 0 )
            pprev = item.second->pprev;
        if (pprev)
            setTips.erase(pprev);
    }

    // Always report the currently active tip.
    setTips.insert(chainActive.LastTip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR); const CBlockIndex *forked;
    BOOST_FOREACH(const CBlockIndex* block, setTips)
        {
            UniValue obj(UniValue::VOBJ);
            obj.push_back(Pair("height", block->GetHeight()));
            obj.push_back(Pair("hash", block->phashBlock->GetHex()));
            forked = chainActive.FindFork(block);
            if ( forked != 0 )
            {
                const int branchLen = block->GetHeight() - forked->GetHeight();
                obj.push_back(Pair("branchlen", branchLen));

                string status;
                if (chainActive.Contains(block)) {
                    // This block is part of the currently active chain.
                    status = "active";
                } else if (block->nStatus & BLOCK_FAILED_MASK) {
                    // This block or one of its ancestors is invalid.
                    status = "invalid";
                } else if (block->nChainTx == 0) {
                    // This block cannot be connected because full block data for it or one of its parents is missing.
                    status = "headers-only";
                } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
                    // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized.
                    status = "valid-fork";
                } else if (block->IsValid(BLOCK_VALID_TREE)) {
                    // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain.
                    status = "valid-headers";
                } else {
                    // No clue.
                    status = "unknown";
                }
                obj.push_back(Pair("status", status));
            }
            res.push_back(obj);
        }

    return res;
}

UniValue mempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("size", (int64_t) mempool.size()));
    ret.push_back(Pair("bytes", (int64_t) mempool.GetTotalTxSize()));
    ret.push_back(Pair("usage", (int64_t) mempool.DynamicMemoryUsage()));

    if (Params().NetworkIDString() == "regtest") {
        ret.push_back(Pair("fullyNotified", mempool.IsFullyNotified()));
    }

    return ret;
}

UniValue getmempoolinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getmempoolinfo\n"
            "\nReturns details on the active state of the TX memory pool.\n"
            "\nResult:\n"
            "{\n"
            "  \"size\": xxxxx                (numeric) Current tx count\n"
            "  \"bytes\": xxxxx               (numeric) Sum of all tx sizes\n"
            "  \"usage\": xxxxx               (numeric) Total memory usage for the mempool\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmempoolinfo", "")
            + HelpExampleRpc("getmempoolinfo", "")
        );

    return mempoolInfoToJSON();
}

UniValue invalidateblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "invalidateblock \"hash\"\n"
            "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to mark as invalid\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("invalidateblock", "\"blockhash\"")
            + HelpExampleRpc("invalidateblock", "\"blockhash\"")
        );

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        InvalidateBlock(state, Params(), pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(state, Params());
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue reconsiderblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "reconsiderblock \"hash\"\n"
            "\nRemoves invalidity status of a block and its descendants, reconsider them for activation.\n"
            "This can be used to undo the effects of invalidateblock.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to reconsider\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("reconsiderblock", "\"blockhash\"")
            + HelpExampleRpc("reconsiderblock", "\"blockhash\"")
        );

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        ReconsiderBlock(state, pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(state, Params());
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "blockchain",         "getblockchaininfo",      &getblockchaininfo,      true  },
    { "blockchain",         "getbestblockhash",       &getbestblockhash,       true  },
    { "blockchain",         "getblockcount",          &getblockcount,          true  },
    { "blockchain",         "getblock",               &getblock,               true  },
    { "blockchain",         "getblockhash",           &getblockhash,           true  },
    { "blockchain",         "getblockheader",         &getblockheader,         true  },
    { "blockchain",         "getchaintips",           &getchaintips,           true  },
    { "blockchain",         "z_gettreestate",         &z_gettreestate,         true  },
    { "blockchain",         "getchaintxstats",        &getchaintxstats,        true  },
    { "blockchain",         "getdifficulty",          &getdifficulty,          true  },
    { "blockchain",         "getmempoolinfo",         &getmempoolinfo,         true  },
    { "blockchain",         "getrawmempool",          &getrawmempool,          true  },
    { "blockchain",         "clearrawmempool",        &clearrawmempool,        true  },
    { "blockchain",         "gettxout",               &gettxout,               true  },
    { "blockchain",         "gettxoutsetinfo",        &gettxoutsetinfo,        true  },
    { "blockchain",         "verifychain",            &verifychain,            true  },

    // insightexplorer
    { "blockchain",         "getblockdeltas",         &getblockdeltas,         false },
    { "blockchain",         "getblockhashes",         &getblockhashes,         true  },

    /* Not shown in help */
    { "hidden",             "invalidateblock",        &invalidateblock,        true  },
    { "hidden",             "reconsiderblock",        &reconsiderblock,        true  },
};

void RegisterBlockchainRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
