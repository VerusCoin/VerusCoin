// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "txmempool.h"

#include "clientversion.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "main.h"
#include "policy/fees.h"
#include "streams.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"
#include "version.h"
#include "cc/CCinclude.h"
#include "pbaas/pbaas.h"
#include "pbaas/identity.h"
#include "pbaas/notarization.h"

using namespace std;

CTxMemPoolEntry::CTxMemPoolEntry():
    nFee(0), nTxSize(0), nModSize(0), nUsageSize(0), nTime(0), dPriority(0.0),
    hadNoDependencies(false), spendsCoinbase(false), hasReserve(false), feeDelta(0)
{
    nHeight = MEMPOOL_HEIGHT;
}

CTxMemPoolEntry::CTxMemPoolEntry(const CTransaction& _tx, const CAmount& _nFee,
                                 int64_t _nTime, double _dPriority,
                                 unsigned int _nHeight, bool poolHasNoInputsOf,
                                 bool _spendsCoinbase, uint32_t _nBranchId, bool hasreserve, int64_t FeeDelta):
    tx(std::make_shared<CTransaction>(_tx)), nFee(_nFee), nTime(_nTime), dPriority(_dPriority), nHeight(_nHeight),
    hadNoDependencies(poolHasNoInputsOf), hasReserve(hasreserve),
    spendsCoinbase(_spendsCoinbase), feeDelta(FeeDelta), nBranchId(_nBranchId)
{
    nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
    nModSize = _tx.CalculateModifiedSize(nTxSize);
    nUsageSize = RecursiveDynamicUsage(*tx) + memusage::DynamicUsage(tx);
    feeRate = CFeeRate(nFee, nTxSize);
}

CTxMemPoolEntry::CTxMemPoolEntry(const CTxMemPoolEntry& other)
{
    *this = other;
}

double
CTxMemPoolEntry::GetPriority(unsigned int currentHeight) const
{
    CAmount nValueIn = tx->GetValueOut() + nFee;
    unsigned int lastHeight = currentHeight < 1 ? 0 : currentHeight - 1;
    AssertLockHeld(cs_main);
    double deltaPriority = ((double)(currentHeight-nHeight)*nValueIn)/nModSize;
    double dResult = dPriority + deltaPriority;
    return dResult;
}

CTxMemPool::CTxMemPool(const CFeeRate& _minRelayFee) :
    nTransactionsUpdated(0)
{
    // Sanity checks off by default for performance, because otherwise
    // accepting transactions becomes O(N^2) where N is the number
    // of transactions in the pool
    nCheckFrequency = 0;

    minerPolicyEstimator = new CBlockPolicyEstimator(_minRelayFee);
}

CTxMemPool::~CTxMemPool()
{
    delete minerPolicyEstimator;
}

bool CTxMemPool::CompareDepthAndScore(const uint256& hasha, const uint256& hashb)
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hasha);
    if (i == mapTx.end()) return false;
    indexed_transaction_set::const_iterator j = mapTx.find(hashb);
    if (j == mapTx.end()) return true;
    // We don't actually compare by depth here because we haven't backported
    // https://github.com/bitcoin/bitcoin/pull/6654
    //
    // But the method name is left as-is because renaming it is not worth the
    // merge conflicts.
    return CompareTxMemPoolEntryByScore()(*i, *j);
}

void CTxMemPool::pruneSpent(const uint256 &hashTx, CCoins &coins)
{
    LOCK(cs);

    std::map<COutPoint, CInPoint>::iterator it = mapNextTx.lower_bound(COutPoint(hashTx, 0));

    // iterate over all COutPoints in mapNextTx whose hash equals the provided hashTx
    while (it != mapNextTx.end() && it->first.hash == hashTx) {
        coins.Spend(it->first.n); // and remove those outputs from coins
        it++;
    }
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    LOCK(cs);
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    LOCK(cs);
    nTransactionsUpdated += n;
}


bool CTxMemPool::addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry, bool fCurrentEstimate)
{
    // Add to memory pool without checking anything.
    // Used by main.cpp AcceptToMemoryPool(), which DOES do
    // all the appropriate checks.
    LOCK(cs);
    mapTx.insert(entry);
    const CTransaction& tx = mapTx.find(hash)->GetTx();
    mapRecentlyAddedTx[tx.GetHash()] = &tx;
    nRecentlyAddedSequence += 1;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        mapNextTx[tx.vin[i].prevout] = CInPoint(&tx, i);
        
    BOOST_FOREACH(const JSDescription &joinsplit, tx.vJoinSplit) {
        BOOST_FOREACH(const uint256 &nf, joinsplit.nullifiers) {
            mapSproutNullifiers[nf] = &tx;
        }
    }
    for (const SpendDescription &spendDescription : tx.vShieldedSpend) {
        mapSaplingNullifiers[spendDescription.nullifier] = &tx;
    }
    nTransactionsUpdated++;
    totalTxSize += entry.GetTxSize();
    cachedInnerUsage += entry.DynamicMemoryUsage();
    minerPolicyEstimator->processTransaction(entry, fCurrentEstimate);

    return true;
}

void CTxMemPool::addAddressIndex(const CTxMemPoolEntry &entry, const CCoinsViewCache &view)
{
    LOCK(cs);
    const CTransaction& tx = entry.GetTx();
    std::vector<CMempoolAddressDeltaKey> inserted;

    uint256 txhash = tx.GetHash();
    if (!tx.IsCoinBase())
    {
        for (unsigned int j = 0; j < tx.vin.size(); j++) {
            const CTxIn input = tx.vin[j];
            const CTxOut &prevout = view.GetOutputFor(input);
            COptCCParams p;
            if (prevout.scriptPubKey.IsPayToCryptoCondition(p))
            {
                std::vector<CTxDestination> dests;
                if (p.IsValid())
                {
                    dests = p.GetDestinations();
                }
                else
                {
                    dests = prevout.scriptPubKey.GetDestinations();
                }

                uint32_t nHeight = chainActive.Height();
                std::map<uint160, uint32_t> heightOffsets = p.GetIndexHeightOffsets(chainActive.Height());

                for (auto dest : dests)
                {
                    if (dest.which() != COptCCParams::ADDRTYPE_INVALID)
                    {
                        uint160 destID = GetDestinationID(dest);
                        if (!(dest.which() == COptCCParams::ADDRTYPE_INDEX && heightOffsets.count(destID) && heightOffsets[destID] != nHeight))
                        {
                            CMempoolAddressDeltaKey key(AddressTypeFromDest(dest), destID, txhash, j, 1);
                            CMempoolAddressDelta delta(entry.GetTime(), prevout.nValue * -1, input.prevout.hash, input.prevout.n);
                            mapAddress.insert(make_pair(key, delta));
                            inserted.push_back(key);
                        }
                    }
                }
            }
            else
            {
                CScript::ScriptType type = prevout.scriptPubKey.GetType();
                if (type == CScript::UNKNOWN)
                    continue;

                CMempoolAddressDeltaKey key(type, prevout.scriptPubKey.AddressHash(), txhash, j, 1);
                CMempoolAddressDelta delta(entry.GetTime(), prevout.nValue * -1, input.prevout.hash, input.prevout.n);
                mapAddress.insert(make_pair(key, delta));
                inserted.push_back(key);
            }
        }
    }

    for (unsigned int j = 0; j < tx.vout.size(); j++) {
        const CTxOut &out = tx.vout[j];

        COptCCParams p;
        if (out.scriptPubKey.IsPayToCryptoCondition(p))
        {
            std::vector<CTxDestination> dests;
            if (p.IsValid())
            {
                dests = p.GetDestinations();
            }
            else
            {
                dests = out.scriptPubKey.GetDestinations();
            }

            uint32_t nHeight = chainActive.Height();
            std::map<uint160, uint32_t> heightOffsets = p.GetIndexHeightOffsets(nHeight);

            for (auto dest : dests)
            {
                if (dest.which() != COptCCParams::ADDRTYPE_INVALID)
                {
                    uint160 destID = GetDestinationID(dest);
                    if (!(dest.which() == COptCCParams::ADDRTYPE_INDEX && heightOffsets.count(destID) && heightOffsets[destID] > nHeight))
                    {
                        CMempoolAddressDeltaKey key(AddressTypeFromDest(dest), GetDestinationID(dest), txhash, j, 0);
                        mapAddress.insert(make_pair(key, CMempoolAddressDelta(entry.GetTime(), out.nValue)));
                        inserted.push_back(key);
                    }
                }
            }
        }
        else
        {
            CScript::ScriptType type = out.scriptPubKey.GetType();
            if (type == CScript::UNKNOWN)
                continue;

            CMempoolAddressDeltaKey key(type, out.scriptPubKey.AddressHash(), txhash, j, 0);
            mapAddress.insert(make_pair(key, CMempoolAddressDelta(entry.GetTime(), out.nValue)));
            inserted.push_back(key);
        }
    }
    mapAddressInserted.insert(make_pair(txhash, inserted));
}

bool CTxMemPool::getAddressIndex(const std::vector<std::pair<uint160, int> > &addresses, std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > &results)
{
    LOCK(cs);
    for (std::vector<std::pair<uint160, int> >::const_iterator it = addresses.begin(); it != addresses.end(); it++) {
        auto ait = mapAddress.lower_bound(CMempoolAddressDeltaKey((*it).second, (*it).first));
        while (ait != mapAddress.end() && (*ait).first.addressBytes == (*it).first && (*ait).first.type == (*it).second) {
            results.push_back(*ait);
            ait++;
        }
    }
    return true;
}

std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> CTxMemPool::FilterUnspent(const std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> &memPoolOutputs,
                                                                                                std::set<COutPoint> &spentTxOuts)
{
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> retVal;
    std::set<COutPoint> txOuts;

    for (const auto &oneOut : memPoolOutputs)
    {
        // get last one in spending list
        if (oneOut.first.spending)
        {
            CTransaction curTx;

            if (mempool.lookup(oneOut.first.txhash, curTx) &&
                curTx.vin.size() > oneOut.first.index)
            {
                spentTxOuts.insert(curTx.vin[oneOut.first.index].prevout);
            }
            else
            {
                LogPrint("mempool", "Unable to retrieve data for spending mempool transaction\n");
                return retVal;
            }
        }
    }
    for (auto &oneOut : memPoolOutputs)
    {
        if (!oneOut.first.spending && !spentTxOuts.count(COutPoint(oneOut.first.txhash, oneOut.first.index)))
        {
            retVal.push_back(oneOut);
        }
    }
    return retVal;
}

bool CTxMemPool::removeAddressIndex(const uint256 txhash)
{
    LOCK(cs);
    auto it = mapAddressInserted.find(txhash);

    if (it != mapAddressInserted.end()) {
        std::vector<CMempoolAddressDeltaKey> keys = (*it).second;
        for (std::vector<CMempoolAddressDeltaKey>::iterator mit = keys.begin(); mit != keys.end(); mit++) {
            mapAddress.erase(*mit);
        }
        mapAddressInserted.erase(it);
    }

    return true;
}

void CTxMemPool::addSpentIndex(const CTxMemPoolEntry &entry, const CCoinsViewCache &view)
{
    LOCK(cs);
    const CTransaction& tx = entry.GetTx();
    uint256 txhash = tx.GetHash();
    std::vector<CSpentIndexKey> inserted;

    for (unsigned int j = 0; j < tx.vin.size(); j++) {
        const CTxIn input = tx.vin[j];
        const CTxOut &prevout = view.GetOutputFor(input);
        CSpentIndexKey key = CSpentIndexKey(input.prevout.hash, input.prevout.n);
        CSpentIndexValue value = CSpentIndexValue(txhash, j, -1, prevout.nValue,
            prevout.scriptPubKey.GetType(),
            prevout.scriptPubKey.AddressHash());
        mapSpent.insert(make_pair(key, value));
        inserted.push_back(key);
    }
    mapSpentInserted.insert(make_pair(txhash, inserted));
}

bool CTxMemPool::getSpentIndex(const CSpentIndexKey &key, CSpentIndexValue &value)
{
    LOCK(cs);
    std::map<CSpentIndexKey, CSpentIndexValue, CSpentIndexKeyCompare>::iterator it = mapSpent.find(key);
    if (it != mapSpent.end()) {
        value = it->second;
        return true;
    }
    return false;
}

bool CTxMemPool::removeSpentIndex(const uint256 txhash)
{
    LOCK(cs);
    auto it = mapSpentInserted.find(txhash);

    if (it != mapSpentInserted.end()) {
        std::vector<CSpentIndexKey> keys = (*it).second;
        for (std::vector<CSpentIndexKey>::iterator mit = keys.begin(); mit != keys.end(); mit++) {
            mapSpent.erase(*mit);
        }
        mapSpentInserted.erase(it);
    }

    return true;
}

void CTxMemPool::remove(const CTransaction &origTx, std::list<CTransaction>& removed, bool fRecursive)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        std::deque<uint256> txToRemove;
        txToRemove.push_back(origTx.GetHash());
        if (fRecursive && !mapTx.count(origTx.GetHash())) {
            // If recursively removing but origTx isn't in the mempool
            // be sure to remove any children that are in the pool. This can
            // happen during chain re-orgs if origTx isn't re-accepted into
            // the mempool for any reason.
            for (unsigned int i = 0; i < origTx.vout.size(); i++) {
                std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(COutPoint(origTx.GetHash(), i));
                if (it == mapNextTx.end())
                    continue;
                txToRemove.push_back(it->second.ptx->GetHash());
            }
        }
        while (!txToRemove.empty())
        {
            uint256 hash = txToRemove.front();
            txToRemove.pop_front();
            if (!mapTx.count(hash))
                continue;
            const CTransaction& tx = mapTx.find(hash)->GetTx();
            if (fRecursive) {
                for (unsigned int i = 0; i < tx.vout.size(); i++) {
                    std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(COutPoint(hash, i));
                    if (it == mapNextTx.end())
                        continue;
                    txToRemove.push_back(it->second.ptx->GetHash());
                }
            }
            mapRecentlyAddedTx.erase(hash);
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
                mapNextTx.erase(txin.prevout);
            BOOST_FOREACH(const JSDescription& joinsplit, tx.vJoinSplit) {
                BOOST_FOREACH(const uint256& nf, joinsplit.nullifiers) {
                    mapSproutNullifiers.erase(nf);
                }
            }
            for (const SpendDescription &spendDescription : tx.vShieldedSpend) {
                mapSaplingNullifiers.erase(spendDescription.nullifier);
            }
            removed.push_back(tx);
            totalTxSize -= mapTx.find(hash)->GetTxSize();
            cachedInnerUsage -= mapTx.find(hash)->DynamicMemoryUsage();
            mapTx.erase(hash);
            nTransactionsUpdated++;
            minerPolicyEstimator->removeTx(hash);
            if (fAddressIndex)
                removeAddressIndex(hash);
            if (fSpentIndex)
                removeSpentIndex(hash);
            ClearPrioritisation(hash);
        }
    }
}

extern uint64_t ASSETCHAINS_TIMELOCKGTE;
int64_t komodo_block_unlocktime(uint32_t nHeight);
extern LRUCache<CUTXORef, std::tuple<uint256, CTransaction, std::vector<std::pair<CObjectFinalization, CNotaryEvidence>>>> finalizationEvidenceCache;
extern LRUCache<std::pair<uint160, uint256>, std::pair<CChainNotarizationData, std::vector<std::pair<CTransaction, uint256>>>> crossChainNotarizationDataCache;
extern LRUCache<std::tuple<uint256, uint32_t, uint32_t, CUTXORef, uint160, uint160>, CCurrencyValueMap> priorConversionCache;
extern LRUCache<std::tuple<uint160, uint256, uint32_t>, std::vector<CInputDescriptor>> chainTransferCache;

void CTxMemPool::removeForReorg(const CCoinsViewCache *pcoins, unsigned int nMemPoolHeight, int flags)
{
    // remove:
    // 1) transactions spending a coinbase which are now immature
    // 2) exports, notarizations, reserve transfers, and imports that that are no longer valid at the current height

    // Remove transactions spending a coinbase which are now immature and no-longer-final transactions
    LOCK(cs);

    finalizationEvidenceCache.Clear();
    crossChainNotarizationDataCache.Clear();
    priorConversionCache.Clear();
    reserveTransferCache.Clear();
    chainTransferCache.Clear();

    list<CTransaction> transactionsToRemove;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        const CTransaction& tx = it->GetTx();
        if (!CheckFinalTx(tx, flags)) {
            transactionsToRemove.push_back(tx);
        } else if (it->GetSpendsCoinbase()) {
            BOOST_FOREACH(const CTxIn& txin, tx.vin) {
                indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
                if (it2 != mapTx.end())
                    continue;
                const CCoins *coins = pcoins->AccessCoins(txin.prevout.hash);
		        if (nCheckFrequency != 0) assert(coins);

                if (!coins || (coins->IsCoinBase() &&
                               (((signed long)nMemPoolHeight) - coins->nHeight < COINBASE_MATURITY) ||
                                    (_IsVerusMainnetActive() &&
                                        (signed long)nMemPoolHeight < komodo_block_unlocktime(coins->nHeight) &&
                                        coins->IsAvailable(0) && coins->vout[0].nValue >= ASSETCHAINS_TIMELOCKGTE))) {
                    transactionsToRemove.push_back(tx);
                    break;
                }
            }
        }

        CValidationState state;
        if (!ContextualCheckTransaction(tx, state, Params(), nMemPoolHeight, 0))
        {
            transactionsToRemove.push_back(tx);
        }
        else
        {
            bool oneRemoved = false;
            for (auto &oneOut : tx.vout)
            {
                COptCCParams p;

                if (oneOut.scriptPubKey.IsPayToCryptoCondition(p))
                {
                    switch(p.evalCode)
                    {
                        case EVAL_EARNEDNOTARIZATION:
                        case EVAL_ACCEPTEDNOTARIZATION:
                        {
                            CPBaaSNotarization notarization;

                            if (p.vData.size() && (notarization = CPBaaSNotarization(p.vData[0])).IsValid())
                            {
                                uint32_t rootHeight;
                                auto mmv = chainActive.GetMMV();
                                if ((!notarization.IsMirror() &&
                                    notarization.IsSameChain() &&
                                    notarization.notarizationHeight >= nMemPoolHeight) ||
                                    (notarization.proofRoots.count(ASSETCHAINS_CHAINID) &&
                                    ((rootHeight = notarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight) > (nMemPoolHeight - 1) ||
                                    (mmv.resize(rootHeight + 1), rootHeight != (mmv.size() - 1)) ||
                                    notarization.proofRoots[ASSETCHAINS_CHAINID].blockHash != chainActive[rootHeight]->GetBlockHash() ||
                                    notarization.proofRoots[ASSETCHAINS_CHAINID].stateRoot != mmv.GetRoot())))
                                {
                                    transactionsToRemove.push_back(tx);
                                    oneRemoved = true;
                                }
                            }
                            else
                            {
                                transactionsToRemove.push_back(tx);
                                oneRemoved = true;
                            }
                            break;
                        }

                        // TODO: POST HARDENING - we need to make it so that once a transaction is proven as valid,
                        // its proof remains valid, even when the blockchain is unwound backwards to the point
                        // where that transaction originally exists on chain
                        // this is an optimization, not hardening issue pre-PBaaS, and may possibly be addressed as easily
                        // as calling ContextualCheckTransaction on the transaction without all of this.
                        // currently, transactions rendered invalid by reorgs will end up removed at block creation and are
                        // not accepted when relayed once invalid.
                        case EVAL_NOTARY_EVIDENCE:
                        case EVAL_FINALIZE_NOTARIZATION:
                        case EVAL_RESERVE_TRANSFER:
                        case EVAL_IDENTITY_PRIMARY:
                        case EVAL_IDENTITY_RESERVATION:
                        case EVAL_IDENTITY_ADVANCEDRESERVATION:
                        case EVAL_FINALIZE_EXPORT:
                        {
                            break;
                        }

                        case EVAL_CROSSCHAIN_EXPORT:
                        {
                            CCrossChainExport ccx;

                            if (!(p.vData.size() &&
                                (ccx = CCrossChainExport(p.vData[0])).IsValid() &&
                                (ccx.sourceSystemID != ASSETCHAINS_CHAINID ||
                                ccx.sourceHeightEnd < nMemPoolHeight)))
                            {
                                transactionsToRemove.push_back(tx);
                                oneRemoved = true;
                            }
                            break;
                        }

                        case EVAL_CROSSCHAIN_IMPORT:
                        {
                            CCrossChainImport cci;

                            if (!(p.vData.size() &&
                                (cci = CCrossChainImport(p.vData[0])).IsValid() &&
                                (cci.sourceSystemID != ASSETCHAINS_CHAINID ||
                                cci.sourceSystemHeight < nMemPoolHeight)))
                            {
                                transactionsToRemove.push_back(tx);
                                oneRemoved = true;
                            }
                            break;
                        }
                    }
                    if (oneRemoved)
                    {
                        break;
                    }
                }
            }
        }
    }
    BOOST_FOREACH(const CTransaction& tx, transactionsToRemove) {
        list<CTransaction> removed;
        remove(tx, removed, true);
    }
}


void CTxMemPool::removeWithAnchor(const uint256 &invalidRoot, ShieldedType type)
{
    // If a block is disconnected from the tip, and the root changed,
    // we must invalidate transactions from the mempool which spend
    // from that root -- almost as though they were spending coinbases
    // which are no longer valid to spend due to coinbase maturity.
    LOCK(cs);
    list<CTransaction> transactionsToRemove;

    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        const CTransaction& tx = it->GetTx();
        switch (type) {
            case SPROUT:
                BOOST_FOREACH(const JSDescription& joinsplit, tx.vJoinSplit) {
                    if (joinsplit.anchor == invalidRoot) {
                        transactionsToRemove.push_back(tx);
                        break;
                    }
                }
            break;
            case SAPLING:
                BOOST_FOREACH(const SpendDescription& spendDescription, tx.vShieldedSpend) {
                    if (spendDescription.anchor == invalidRoot) {
                        transactionsToRemove.push_back(tx);
                        break;
                    }
                }
            break;
            default:
                throw runtime_error("Unknown shielded type");
            break;
        }
    }

    BOOST_FOREACH(const CTransaction& tx, transactionsToRemove) {
        list<CTransaction> removed;
        remove(tx, removed, true);
    }
}

bool CTxMemPool::checkNameConflicts(const CTransaction &tx, std::list<CTransaction> &conflicting)
{
    LOCK(cs);

    // easy way to check if there are any transactions in the memory pool that define the name specified but are not the same as tx
    conflicting.clear();

    // first, be sure that this is a name definition. if so, it will have both a definition and reservation output. if it is a name definition,
    // our only concern is whether or not there is a conflicting definition in the mempool. we assume that a check for any conflicting definition
    // in the blockchain has already taken place.
    CIdentity identity;
    CNameReservation reservation;
    CAdvancedNameReservation advNameRes;
    CCurrencyDefinition newCurDef;
    std::set<uint160> newIDs;
    std::set<uint160> newCurrencies;
    for (auto output : tx.vout)
    {
        COptCCParams p;
        if (output.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3 && p.vData.size())
        {
            switch (p.evalCode)
            {
                case EVAL_IDENTITY_ADVANCEDRESERVATION:
                {
                    if ((advNameRes = CAdvancedNameReservation(p.vData[0])).IsValid())
                    {
                        uint160 parentID;
                        newIDs.insert(CIdentity::GetID(advNameRes.name, advNameRes.parent));
                    }
                    break;
                }
                case EVAL_IDENTITY_RESERVATION:
                {
                    if ((reservation = CNameReservation(p.vData[0])).IsValid())
                    {
                        uint160 parentID = ASSETCHAINS_CHAINID;
                        newIDs.insert(CIdentity::GetID(reservation.name, parentID));
                    }
                    break;
                }
                case EVAL_CURRENCY_DEFINITION:
                {
                    if ((newCurDef = CCurrencyDefinition(p.vData[0])).IsValid())
                    {
                        newCurrencies.insert(newCurDef.GetID());
                    }
                    break;
                }
            }
        }
    }

    // first, look for ID conflicts, any new ID that matches should be removed
    for (auto &oneIDID : newIDs)
    {
        std::vector<std::pair<uint160, int>> addresses =
            std::vector<std::pair<uint160, int>>({{CCrossChainRPCData::GetConditionID(oneIDID, EVAL_IDENTITY_RESERVATION), CScript::P2IDX},
                                                  {CCrossChainRPCData::GetConditionID(oneIDID, EVAL_IDENTITY_ADVANCEDRESERVATION), CScript::P2IDX}});
        std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> results;
        if (mempool.getAddressIndex(addresses, results) && results.size())
        {
            std::map<uint256, std::pair<CTransaction, int>> txesAndSources;   // first hash is transaction of input of prior identity or commitment output in the mempool, second pair is tx and ID output num if identity

            uint256 txHash = tx.GetHash();
            CNameReservation conflictingRes;
            for (auto r : results)
            {
                if (r.first.txhash == txHash)
                {
                    continue;
                }
                CTransaction mpTx;
                if (lookup(r.first.txhash, mpTx))
                {
                    conflicting.push_back(mpTx);
                }
            }
        }
    }

    for (auto &oneCurID : newCurrencies)
    {
        std::vector<std::pair<uint160, int>> addresses =
            std::vector<std::pair<uint160, int>>({{CCrossChainRPCData::GetConditionID(oneCurID, CCurrencyDefinition::CurrencyDefinitionKey()), CScript::P2IDX}});
        std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> results;
        if (mempool.getAddressIndex(addresses, results) && results.size())
        {
            std::map<uint256, std::pair<CTransaction, int>> txesAndSources;   // first hash is transaction of input of prior identity or commitment output in the mempool, second pair is tx and ID output num if identity

            uint256 txHash = tx.GetHash();
            CNameReservation conflictingRes;
            for (auto r : results)
            {
                if (r.first.txhash == txHash)
                {
                    continue;
                }
                CTransaction mpTx;
                if (lookup(r.first.txhash, mpTx))
                {
                    conflicting.push_back(mpTx);
                }
            }
        }
    }

    return conflicting.size();
}

void CTxMemPool::removeConflicts(const CTransaction &tx, std::list<CTransaction>& removed)
{
    LOCK(cs);

    // names are enforced as unique without requiring related spends.
    // if this is a definition that conflicts with an existing, unrelated name definition, remove the
    // definition that exists in the mempool
    std::list<CTransaction> conflicting;
    if (checkNameConflicts(tx, conflicting))
    {
        for (auto &remTx : conflicting)
        {
            remove(remTx, removed, true);
        }
    }

    // Remove transactions which depend on inputs of tx, recursively
    list<CTransaction> result;
    BOOST_FOREACH(const CTxIn &txin, tx.vin) {
        std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second.ptx;
            if (txConflict != tx)
            {
                remove(txConflict, removed, true);
            }
        }
    }

    BOOST_FOREACH(const JSDescription &joinsplit, tx.vJoinSplit) {
        BOOST_FOREACH(const uint256 &nf, joinsplit.nullifiers) {
            std::map<uint256, const CTransaction*>::iterator it = mapSproutNullifiers.find(nf);
            if (it != mapSproutNullifiers.end()) {
                const CTransaction &txConflict = *it->second;
                if (txConflict != tx) {
                    remove(txConflict, removed, true);
                }
            }
        }
    }
    for (const SpendDescription &spendDescription : tx.vShieldedSpend) {
        std::map<uint256, const CTransaction*>::iterator it = mapSaplingNullifiers.find(spendDescription.nullifier);
        if (it != mapSaplingNullifiers.end()) {
            const CTransaction &txConflict = *it->second;
            if (txConflict != tx) {
                remove(txConflict, removed, true);
            }
        }
    }
}

int32_t komodo_validate_interest(const CTransaction &tx,int32_t txheight,uint32_t nTime,int32_t dispflag);
extern char ASSETCHAINS_SYMBOL[];

void CTxMemPool::removeExpired(unsigned int nBlockHeight)
{
    CBlockIndex *tipindex;
    // Remove expired txs and leftover coinbases from the mempool
    LOCK(cs);
    list<CTransaction> transactionsToRemove;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++)
    {
        const CTransaction& tx = it->GetTx();
        tipindex = chainActive.LastTip();
        if (tx.IsCoinBase() || IsExpiredTx(tx, nBlockHeight))
        {
            transactionsToRemove.push_back(tx);
        }
    }
    for (const CTransaction& tx : transactionsToRemove) {
        list<CTransaction> removed;
        remove(tx, removed, true);
        LogPrint("mempool", "Removing expired txid: %s\n", tx.GetHash().ToString());
    }
}

/**
 * Called when a block is connected. Removes from mempool and updates the miner fee estimator.
 */
void CTxMemPool::removeForBlock(const std::vector<CTransaction>& vtx, unsigned int nBlockHeight,
                                std::list<CTransaction>& conflicts, bool fCurrentEstimate)
{
    LOCK(cs);
    std::vector<CTxMemPoolEntry> entries;
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        uint256 hash = tx.GetHash();

        indexed_transaction_set::iterator i = mapTx.find(hash);
        if (i != mapTx.end())
            entries.push_back(*i);
    }
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        std::list<CTransaction> dummy;
        remove(tx, dummy, false);
        removeConflicts(tx, conflicts);
        ClearPrioritisation(tx.GetHash());
    }
    // After the txs in the new block have been removed from the mempool, update policy estimates
    minerPolicyEstimator->processBlock(nBlockHeight, entries, fCurrentEstimate);
}

/**
 * Called whenever the tip changes. Removes transactions which don't commit to
 * the given branch ID from the mempool.
 */
void CTxMemPool::removeWithoutBranchId(uint32_t nMemPoolBranchId)
{
    LOCK(cs);
    std::list<CTransaction> transactionsToRemove;

    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        const CTransaction& tx = it->GetTx();
        if (it->GetValidatedBranchId() != nMemPoolBranchId) {
            transactionsToRemove.push_back(tx);
        }
    }

    for (const CTransaction& tx : transactionsToRemove) {
        std::list<CTransaction> removed;
        remove(tx, removed, true);
    }
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    mapReserveTransactions.clear();
    mapDeltas.clear();
    mapRecentlyAddedTx.clear();
    mapAddress.clear();
    mapAddressInserted.clear();
    mapSpent.clear();
    mapSpentInserted.clear();
    mapSproutNullifiers.clear();
    mapSaplingNullifiers.clear();
    totalTxSize = 0;
    cachedInnerUsage = 0;
    ++nTransactionsUpdated;
}

void CTxMemPool::check(const CCoinsViewCache *pcoins) const
{
    if (nCheckFrequency == 0)
        return;

    if (insecure_rand() >= nCheckFrequency)
        return;

    LogPrint("mempool", "Checking mempool with %u transactions and %u inputs\n", (unsigned int)mapTx.size(), (unsigned int)mapNextTx.size());

    uint64_t checkTotal = 0;
    uint64_t innerUsage = 0;

    CCoinsViewCache mempoolDuplicate(const_cast<CCoinsViewCache*>(pcoins));
    const int64_t nSpendHeight = GetSpendHeight(mempoolDuplicate);

    LOCK(cs);
    list<const CTxMemPoolEntry*> waitingOnDependants;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        unsigned int i = 0;
        checkTotal += it->GetTxSize();
        innerUsage += it->DynamicMemoryUsage();
        const CTransaction& tx = it->GetTx();
        bool fDependsWait = false;
        BOOST_FOREACH(const CTxIn &txin, tx.vin) {
            // Check that every mempool transaction's inputs refer to available coins, or other mempool tx's.
            indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
            if (it2 != mapTx.end()) {
                const CTransaction& tx2 = it2->GetTx();
                assert(tx2.vout.size() > txin.prevout.n && !tx2.vout[txin.prevout.n].IsNull());
                fDependsWait = true;
            } else {
                const CCoins* coins = pcoins->AccessCoins(txin.prevout.hash);
                assert(coins && coins->IsAvailable(txin.prevout.n));
            }
            // Check whether its inputs are marked in mapNextTx.
            std::map<COutPoint, CInPoint>::const_iterator it3 = mapNextTx.find(txin.prevout);
            assert(it3 != mapNextTx.end());
            assert(it3->second.ptx == &tx);
            assert(it3->second.n == i);
            i++;
        }

        boost::unordered_map<uint256, SproutMerkleTree, CCoinsKeyHasher> intermediates;

        BOOST_FOREACH(const JSDescription &joinsplit, tx.vJoinSplit) {
            BOOST_FOREACH(const uint256 &nf, joinsplit.nullifiers) {
                assert(!pcoins->GetNullifier(nf, SPROUT));
            }

            SproutMerkleTree tree;
            auto it = intermediates.find(joinsplit.anchor);
            if (it != intermediates.end()) {
                tree = it->second;
            } else {
                assert(pcoins->GetSproutAnchorAt(joinsplit.anchor, tree));
            }

            BOOST_FOREACH(const uint256& commitment, joinsplit.commitments)
            {
                tree.append(commitment);
            }

            intermediates.insert(std::make_pair(tree.root(), tree));
        }
        for (const SpendDescription &spendDescription : tx.vShieldedSpend) {
            SaplingMerkleTree tree;

            assert(pcoins->GetSaplingAnchorAt(spendDescription.anchor, tree));
            assert(!pcoins->GetNullifier(spendDescription.nullifier, SAPLING));
        }
        if (fDependsWait)
            waitingOnDependants.push_back(&(*it));
        else {
            CValidationState state;
            bool fCheckResult = tx.IsCoinBase() ||
                Consensus::CheckTxInputs(tx, state, mempoolDuplicate, nSpendHeight, Params().GetConsensus());
            assert(fCheckResult);
            UpdateCoins(tx, mempoolDuplicate, 1000000);
        }
    }
    unsigned int stepsSinceLastRemove = 0;
    while (!waitingOnDependants.empty()) {
        const CTxMemPoolEntry* entry = waitingOnDependants.front();
        waitingOnDependants.pop_front();
        CValidationState state;
        if (!mempoolDuplicate.HaveInputs(entry->GetTx())) {
            waitingOnDependants.push_back(entry);
            stepsSinceLastRemove++;
            assert(stepsSinceLastRemove < waitingOnDependants.size());
        } else {
            bool fCheckResult = entry->GetTx().IsCoinBase() ||
                Consensus::CheckTxInputs(entry->GetTx(), state, mempoolDuplicate, nSpendHeight, Params().GetConsensus());
            assert(fCheckResult);
            UpdateCoins(entry->GetTx(), mempoolDuplicate, 1000000);
            stepsSinceLastRemove = 0;
        }
    }
    for (std::map<COutPoint, CInPoint>::const_iterator it = mapNextTx.begin(); it != mapNextTx.end(); it++) {
        uint256 hash = it->second.ptx->GetHash();
        indexed_transaction_set::const_iterator it2 = mapTx.find(hash);
        const CTransaction& tx = it2->GetTx();
        assert(it2 != mapTx.end());
        assert(&tx == it->second.ptx);
        assert(tx.vin.size() > it->second.n);
        assert(it->first == it->second.ptx->vin[it->second.n].prevout);
    }

    checkNullifiers(SPROUT);
    checkNullifiers(SAPLING);

    assert(totalTxSize == checkTotal);
    assert(innerUsage == cachedInnerUsage);
}

void CTxMemPool::checkNullifiers(ShieldedType type) const
{
    const std::map<uint256, const CTransaction*>* mapToUse;
    switch (type) {
        case SPROUT:
            mapToUse = &mapSproutNullifiers;
            break;
        case SAPLING:
            mapToUse = &mapSaplingNullifiers;
            break;
        default:
            throw runtime_error("Unknown nullifier type");
    }
    for (const auto& entry : *mapToUse) {
        uint256 hash = entry.second->GetHash();
        CTxMemPool::indexed_transaction_set::const_iterator findTx = mapTx.find(hash);
        const CTransaction& tx = findTx->GetTx();
        assert(findTx != mapTx.end());
        assert(&tx == entry.second);
    }
}

void CTxMemPool::queryHashes(vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (indexed_transaction_set::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back(mi->GetTx().GetHash());
}

std::shared_ptr<const CTransaction> CTxMemPool::get(const uint256& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return nullptr;
    return i->GetSharedTx();
}

TxMempoolInfo CTxMemPool::info(const uint256& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return TxMempoolInfo();
    return TxMempoolInfo{i->GetSharedTx(), i->GetTime(), CFeeRate(i->GetFee(), i->GetTxSize())};
}

bool CTxMemPool::lookup(uint256 hash, CTransaction& result) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end()) return false;
    result = i->GetTx();
    return true;
}

CFeeRate CTxMemPool::estimateFee(int nBlocks) const
{
    LOCK(cs);
    return minerPolicyEstimator->estimateFee(nBlocks);
}
double CTxMemPool::estimatePriority(int nBlocks) const
{
    LOCK(cs);
    return minerPolicyEstimator->estimatePriority(nBlocks);
}

bool
CTxMemPool::WriteFeeEstimates(CAutoFile& fileout) const
{
    try {
        LOCK(cs);
        fileout << 109900; // version required to read: 0.10.99 or later
        fileout << CLIENT_VERSION; // version that wrote the file
        minerPolicyEstimator->Write(fileout);
    }
    catch (const std::exception&) {
        LogPrintf("CTxMemPool::WriteFeeEstimates(): unable to write policy estimator data (non-fatal)\n");
        return false;
    }
    return true;
}

bool
CTxMemPool::ReadFeeEstimates(CAutoFile& filein)
{
    try {
        int nVersionRequired, nVersionThatWrote;
        filein >> nVersionRequired >> nVersionThatWrote;
        if (nVersionRequired > CLIENT_VERSION)
            return error("CTxMemPool::ReadFeeEstimates(): up-version (%d) fee estimate file", nVersionRequired);

        LOCK(cs);
        minerPolicyEstimator->Read(filein);
    }
    catch (const std::exception&) {
        LogPrintf("CTxMemPool::ReadFeeEstimates(): unable to read policy estimator data (non-fatal)\n");
        return false;
    }
    return true;
}

void CTxMemPool::PrioritiseTransaction(const uint256 &hash, const string strHash, double dPriorityDelta, const CAmount& nFeeDelta)
{
    {
        LOCK(cs);
        std::pair<double, CAmount> &deltas = mapDeltas[hash];
        deltas.first += dPriorityDelta;
        deltas.second += nFeeDelta;
    }
    if (fDebug)
    {
        LogPrintf("PrioritiseTransaction: %s priority += %f, fee += %d\n", strHash, dPriorityDelta, FormatMoney(nFeeDelta));
    }
}

void CTxMemPool::ApplyDeltas(const uint256 hash, double &dPriorityDelta, CAmount &nFeeDelta)
{
    LOCK(cs);
    std::map<uint256, std::pair<double, CAmount> >::iterator pos = mapDeltas.find(hash);
    if (pos == mapDeltas.end())
        return;
    const std::pair<double, CAmount> &deltas = pos->second;
    dPriorityDelta += deltas.first;
    nFeeDelta += deltas.second;
}

void CTxMemPool::ClearPrioritisation(const uint256 hash)
{
    LOCK(cs);
    mapDeltas.erase(hash);
    mapReserveTransactions.erase(hash);
}

bool CTxMemPool::PrioritiseReserveTransaction(const CReserveTransactionDescriptor &txDesc)
{
    LOCK(cs);
    uint256 hash = txDesc.ptx->GetHash();
    auto it = mapReserveTransactions.find(hash);
    if (txDesc.IsValid())
    {
        mapReserveTransactions[hash] = txDesc;
        CAmount feeDelta = txDesc.NativeFees();
        if (!IsVerusActive())
        {
            CCurrencyValueMap reserveFees = txDesc.ReserveFees();
            auto it = reserveFees.valueMap.find(VERUS_CHAINID);
            if (it != reserveFees.valueMap.end())
            {
                feeDelta += it->second;
            }
        }
        PrioritiseTransaction(hash, hash.GetHex().c_str(), (double)feeDelta * 100.0, feeDelta);
        return true;
    }
    return false;
}

bool CTxMemPool::IsKnownReserveTransaction(const uint256 &hash, CReserveTransactionDescriptor &txDesc)
{
    LOCK(cs);
    auto it = mapReserveTransactions.find(hash);
    if (it != mapReserveTransactions.end() && it->second.IsValid())
    {
        // refresh transaction from mempool or delete it if not found (we may not need this at all)
        indexed_transaction_set::const_iterator i = mapTx.find(hash);
        if (i == mapTx.end())
        {
            ClearPrioritisation(hash);
        }
        else
        {
            it->second.ptx = &(i->GetTx());

            txDesc = it->second;
            return true;
        }
    }
    return false;
}

bool CTxMemPool::HasNoInputsOf(const CTransaction &tx) const
{
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        if (exists(tx.vin[i].prevout.hash))
            return false;
    return true;
}

bool CTxMemPool::nullifierExists(const uint256& nullifier, ShieldedType type) const
{
    switch (type) {
        case SPROUT:
            return mapSproutNullifiers.count(nullifier);
        case SAPLING:
            return mapSaplingNullifiers.count(nullifier);
        default:
            throw runtime_error("Unknown nullifier type");
    }
}

void CTxMemPool::NotifyRecentlyAdded()
{
    uint64_t recentlyAddedSequence;
    std::vector<CTransaction> txs;
    {
        LOCK(cs);
        recentlyAddedSequence = nRecentlyAddedSequence;
        for (const auto& kv : mapRecentlyAddedTx) {
            txs.push_back(*(kv.second));
        }
        mapRecentlyAddedTx.clear();
    }

    // A race condition can occur here between these SyncWithWallets calls, and
    // the ones triggered by block logic (in ConnectTip and DisconnectTip). It
    // is harmless because calling SyncWithWallets(_, NULL) does not alter the
    // wallet transaction's block information.
    for (auto tx : txs) {
        try {
            SyncWithWallets(tx, NULL);
        } catch (const boost::thread_interrupted&) {
            throw;
        } catch (const std::exception& e) {
            PrintExceptionContinue(&e, "CTxMemPool::NotifyRecentlyAdded()");
        } catch (...) {
            PrintExceptionContinue(NULL, "CTxMemPool::NotifyRecentlyAdded()");
        }
    }

    // Update the notified sequence number. We only need this in regtest mode,
    // and should not lock on cs after calling SyncWithWallets otherwise.
    if (Params().NetworkIDString() == "regtest") {
        LOCK(cs);
        nNotifiedSequence = recentlyAddedSequence;
    }
}

bool CTxMemPool::IsFullyNotified() {
    assert(Params().NetworkIDString() == "regtest");
    LOCK(cs);
    return nRecentlyAddedSequence == nNotifiedSequence;
}

CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView *baseIn, CTxMemPool &mempoolIn) : CCoinsViewBacked(baseIn), mempool(mempoolIn) { }

bool CCoinsViewMemPool::GetNullifier(const uint256 &nf, ShieldedType type) const
{
    return mempool.nullifierExists(nf, type) || base->GetNullifier(nf, type);
}

bool CCoinsViewMemPool::GetCoins(const uint256 &txid, CCoins &coins) const {
    // If an entry in the mempool exists, always return that one, as it's guaranteed to never
    // conflict with the underlying cache, and it cannot have pruned entries (as it contains full)
    // transactions. First checking the underlying cache risks returning a pruned entry instead.
    CTransaction tx;
    if (mempool.lookup(txid, tx)) {
        coins = CCoins(tx, MEMPOOL_HEIGHT);
        return true;
    }
    return (base->GetCoins(txid, coins) && !coins.IsPruned());
}

bool CCoinsViewMemPool::HaveCoins(const uint256 &txid) const {
    return mempool.exists(txid) || base->HaveCoins(txid);
}

size_t CTxMemPool::DynamicMemoryUsage() const {
    LOCK(cs);
    // Estimate the overhead of mapTx to be 6 pointers + an allocation, as no exact formula for boost::multi_index_contained is implemented.
    return memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 6 * sizeof(void*)) * mapTx.size() + memusage::DynamicUsage(mapNextTx) + memusage::DynamicUsage(mapDeltas) + memusage::DynamicUsage(mapDeltas) + memusage::DynamicUsage(mapDeltas) + cachedInnerUsage;
}
