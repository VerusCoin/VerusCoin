/********************************************************************
 * (C) 2019 Michael Toutonghi
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * This provides support for PBaaS identity definition,
 *
 * This is a decentralized identity class that provides the minimum
 * basic function needed to enable persistent DID-similar identities,
 * needed for signatories, that will eventually bridge compatibly to
 * DID identities.
 *
 *
 */
#include "main.h"
#include "pbaas/pbaas.h"
#include "pbaas/notarization.h"
#include "identity.h"
#include "txdb.h"

extern CTxMemPool mempool;
bool IsValidBlockOneCoinbase(const std::vector<CTxOut> &outputs,
                            const CRPCChainData &launchChain,
                            const CCurrencyDefinition &newChainCurrency,
                            CValidationState &state);

CCommitmentHash::CCommitmentHash(const CTransaction &tx)
{
    for (auto txOut : tx.vout)
    {
        COptCCParams p;
        if (txOut.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_COMMITMENT && p.vData.size())
        {
            ::FromVector(p.vData[0], *this);
            break;
        }
    }
}

CIdentity::CIdentity(const CTransaction &tx, int *voutNum, const uint160 &onlyThisID)
{
    std::set<uint160> ids;
    int idIndex;
    bool found = false;

    nVersion = VERSION_INVALID;
    for (int i = 0; i < tx.vout.size(); i++)
    {
        CIdentity foundIdentity(tx.vout[i].scriptPubKey);
        bool justFound = (foundIdentity.IsValid() && (onlyThisID.IsNull() || foundIdentity.GetID() == onlyThisID));
        if (justFound && !found)
        {
            *this = foundIdentity;
            found = true;
            idIndex = i;
        }
        else if (justFound)
        {
            *this = CIdentity();
        }
    }
    if (voutNum && IsValid())
    {
        *voutNum = idIndex;
    }
}

bool CIdentity::IsInvalidMutation(const CIdentity &newIdentity, uint32_t height, uint32_t expiryHeight) const
{
    auto nSolVersion = CConstVerusSolutionVector::GetVersionByHeight(height);
    if (parent != newIdentity.parent ||
        (nSolVersion < CActivationHeight::ACTIVATE_IDCONSENSUS2 && name != newIdentity.name) ||
        (nSolVersion < CActivationHeight::ACTIVATE_VERUSVAULT && (newIdentity.IsLocked() || newIdentity.nVersion >= VERSION_VAULT)) ||
        (nSolVersion >= CActivationHeight::ACTIVATE_VERUSVAULT && (newIdentity.nVersion < VERSION_VAULT ||
                                                                  (newIdentity.systemID != (nVersion < VERSION_VAULT ? parent : systemID)))) ||
        (nSolVersion < CActivationHeight::ACTIVATE_PBAAS &&
         (newIdentity.HasActiveCurrency() || newIdentity.contentMultiMap.size() || newIdentity.nVersion >= VERSION_PBAAS)) ||
        (nSolVersion >= CActivationHeight::ACTIVATE_PBAAS && (newIdentity.nVersion < VERSION_PBAAS)) ||
        GetID() != newIdentity.GetID() ||
        ((newIdentity.flags & ~FLAG_REVOKED) && newIdentity.nVersion < VERSION_VAULT) ||
        ((newIdentity.flags & ~(FLAG_REVOKED + FLAG_LOCKED)) && newIdentity.nVersion < VERSION_PBAAS) ||
        ((newIdentity.flags & ~(FLAG_REVOKED + FLAG_ACTIVECURRENCY + FLAG_LOCKED + FLAG_TOKENIZED_CONTROL)) && (newIdentity.nVersion >= VERSION_PBAAS)) ||
        (IsLocked(height) && (!newIdentity.IsRevoked() && !newIdentity.IsLocked(height))) ||
        (HasActiveCurrency() && !HasActiveCurrency()) ||
        (HasTokenizedControl() && !HasTokenizedControl()) ||
        newIdentity.nVersion < VERSION_FIRSTVALID ||
        newIdentity.nVersion > VERSION_LASTVALID)
    {
        return true;
    }

    // we cannot unlock instantly unless we are revoked, we also cannot relock
    // to enable an earlier unlock time
    if (newIdentity.nVersion >= VERSION_VAULT)
    {
        if (IsLocked(height))
        {
            if (!newIdentity.IsRevoked())
            {
                // if we are locked due to the lock flag and not counting down
                if (IsLocked())
                {
                    if (newIdentity.IsLocked() && newIdentity.unlockAfter < unlockAfter)
                    {
                        return true;
                    }
                    else if (!newIdentity.IsLocked() &&
                                (newIdentity.unlockAfter < (unlockAfter + expiryHeight)) &&
                                !(unlockAfter > MAX_UNLOCK_DELAY && newIdentity.unlockAfter == (MAX_UNLOCK_DELAY + expiryHeight)))
                    {
                        return true;
                    }
                }
                else
                {
                    // only revocation can change unlock after time, and we don't allow re-lock to an earlier time until unlock either,
                    // which can change the new unlock time
                    if (newIdentity.IsLocked())
                    {
                        if ((expiryHeight + newIdentity.unlockAfter < unlockAfter))
                        {
                            return true;
                        }
                    }
                    else if ((nSolVersion < CActivationHeight::ACTIVATE_PBAAS && newIdentity.unlockAfter != unlockAfter) ||
                             (nSolVersion >= CActivationHeight::ACTIVATE_PBAAS && newIdentity.unlockAfter < unlockAfter))
                    {
                        return true;
                    }
                }
            }
        }
        else if (newIdentity.IsLocked(height))
        {
            if (newIdentity.IsLocked() && newIdentity.unlockAfter > MAX_UNLOCK_DELAY)
            {
                return true;
            }
            else if (!newIdentity.IsLocked() && newIdentity.unlockAfter <= expiryHeight)
            {
                // we never set the locked bit, but we are counting down to the block set to unlock
                // cannot lock with unlock before the expiry height
                return true;
            }
        }
    }
    return false;
}

LRUCache<std::pair<uint256, CIdentityID>, std::tuple<CIdentity, uint32_t, CTxIn>> CIdentity::IdentityLookupCache(6000);

CIdentity CIdentity::LookupIdentity(const CIdentityID &nameID, uint32_t height, uint32_t *pHeightOut, CTxIn *pIdTxIn, bool checkMempool)
{
    LOCK(mempool.cs);

    CIdentity ret;

    uint32_t heightOut = 0;

    if (!pHeightOut)
    {
        pHeightOut = &heightOut;
    }
    else
    {
        *pHeightOut = 0;
    }

    CTxIn _idTxIn;
    if (!pIdTxIn)
    {
        pIdTxIn = &_idTxIn;
    }
    CTxIn &idTxIn = *pIdTxIn;

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs, unspentNewIDX;
    std::vector<std::pair<CInputDescriptor, uint32_t>> unspentInputs;

    uint160 keyID(CCrossChainRPCData::GetConditionID(nameID, EVAL_IDENTITY_PRIMARY));

    if ((!height || height > chainActive.Height()) && checkMempool)
    {
        ConnectedChains.GetUnspentByIndex(keyID, unspentInputs);
        // if we got it from the mempool, don't check view
        if (unspentInputs.size() && !unspentInputs[0].second)
        {
            COptCCParams p;
            if (unspentInputs[0].first.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_IDENTITY_PRIMARY &&
                (ret = CIdentity(unspentInputs[0].first.scriptPubKey)).IsValid())
            {
                if (ret.GetID() == nameID)
                {
                    idTxIn = CTxIn(unspentInputs[0].first.txIn.prevout.hash, unspentInputs[0].first.txIn.prevout.n);
                    *pHeightOut = -1;
                }
                else
                {
                    // got an identity masquerading as another, clear it
                    ret = CIdentity();
                }
                return ret;
            }
        }
        unspentInputs.clear();
    }
    // TODO: NEXTRELEASE - uncomment cache code
    /* else if (height)
    {
        std::tuple<CIdentity, uint32_t, CTxIn> cachedIdentity;
        if (std::get<0>(cachedIdentity = IdentityLookupCache.Get({chainActive[height > chainActive.Height() ? chainActive.Height() : height]->GetBlockHash(), nameID})).IsValid())
        {
            *pHeightOut = std::get<1>(cachedIdentity);
            idTxIn = std::get<2>(cachedIdentity);
            ret = std::get<0>(cachedIdentity);
            return ret;
        }
    } */

    if (unspentOutputs.size() || GetAddressUnspent(keyID, CScript::P2IDX, unspentNewIDX) && GetAddressUnspent(keyID, CScript::P2PKH, unspentOutputs))
    {
        // combine searches into 1 vector
        unspentOutputs.insert(unspentOutputs.begin(), unspentNewIDX.begin(), unspentNewIDX.end());
        CCoinsViewCache view(pcoinsTip);

        for (auto it = unspentOutputs.begin(); !ret.IsValid() && it != unspentOutputs.end(); it++)
        {
            CCoins coins;

            if (view.GetCoins(it->first.txhash, coins))
            {
                if (coins.IsAvailable(it->first.index))
                {
                    // check the mempool for spent/modified
                    CSpentIndexKey key(it->first.txhash, it->first.index);
                    CSpentIndexValue value;

                    COptCCParams p;
                    if (coins.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() &&
                        p.evalCode == EVAL_IDENTITY_PRIMARY &&
                        (ret = CIdentity(coins.vout[it->first.index].scriptPubKey)).IsValid())
                    {
                        if (ret.GetID() == nameID)
                        {
                            idTxIn = CTxIn(it->first.txhash, it->first.index);
                            *pHeightOut = it->second.blockHeight;
                        }
                        else
                        {
                            // got an identity masquerading as another, clear it
                            ret = CIdentity();
                        }
                    }
                }
            }
        }

        if (height != 0 && (*pHeightOut > height || (height == 1 && *pHeightOut == height)))
        {
            *pHeightOut = 0;
            ret = CIdentity();

            // if we must check up to a specific height that is less than the latest height, do so
            std::vector<CAddressIndexDbEntry> addressIndex, addressIndex2;

            if (GetAddressIndex(keyID, CScript::P2PKH, addressIndex, 0, height) &&
                GetAddressIndex(keyID, CScript::P2IDX, addressIndex2, 0, height) &&
                (addressIndex.size() || addressIndex2.size()))
            {
                if (addressIndex2.size())
                {
                    addressIndex.insert(addressIndex.begin(), addressIndex2.begin(), addressIndex2.end());
                }
                int txIndex = 0;
                // look from last backward to find the first valid ID
                for (int i = addressIndex.size() - 1; i >= 0; i--)
                {
                    if (addressIndex[i].first.blockHeight < *pHeightOut)
                    {
                        break;
                    }
                    CTransaction idTx;
                    uint256 blkHash;
                    COptCCParams p;
                    LOCK(mempool.cs);
                    if (!addressIndex[i].first.spending &&
                        (addressIndex[i].first.blockHeight == 1 || addressIndex[i].first.txindex > txIndex) &&    // always select the latest in a block, if there can be more than one
                        myGetTransaction(addressIndex[i].first.txhash, idTx, blkHash) &&
                        idTx.vout[addressIndex[i].first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() &&
                        p.evalCode == EVAL_IDENTITY_PRIMARY &&
                        (ret = CIdentity(idTx.vout[addressIndex[i].first.index].scriptPubKey)).IsValid())
                    {
                        idTxIn = CTxIn(addressIndex[i].first.txhash, addressIndex[i].first.index);
                        *pHeightOut = addressIndex[i].first.blockHeight;
                        txIndex = addressIndex[i].first.txindex;
                    }
                }
            }
            else
            {
                // not found at that height
                ret = CIdentity();
                idTxIn = CTxIn();
            }
        }
    }

    // TODO: NEXTRELEASE - uncomment cache code
    /* if (height && !(height > chainActive.Height() && checkMempool))
    {
        IdentityLookupCache.Put({chainActive[height > chainActive.Height() ? chainActive.Height() : height]->GetBlockHash(), nameID}, {ret, *pHeightOut, idTxIn});
    } */

    return ret;
}

std::vector<std::tuple<CIdentity, uint256, uint32_t, CUTXORef, CPartialTransactionProof>>
CIdentity::LookupIdentities(const CIdentityID &nameID,
                            uint32_t gteHeight,
                            uint32_t lteHeight,
                            bool checkMempool,
                            bool getProofs,
                            uint32_t proofHeight,
                            const std::vector<uint160> &_indexKeys,
                            bool sorted)
{
    // if we don't have an endHeight, we also check the mempool
    if (!lteHeight || lteHeight == -1)
    {
        lteHeight = chainActive.Height();
    }

    std::vector<uint160> indexKeys = _indexKeys.size() ?
                                        _indexKeys :
                                        std::vector<uint160>({CCrossChainRPCData::GetConditionID(nameID, EVAL_IDENTITY_PRIMARY)});

    std::vector<std::tuple<CIdentity, uint256, uint32_t, CUTXORef, CPartialTransactionProof>> retVal;
    std::vector<CAddressIndexDbEntry> identityIndex;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> mempoolIdentities;

    std::vector<std::pair<uint160, int32_t>> indexVec;
    for (auto &oneKey : indexKeys)
    {
        GetAddressIndex(oneKey, CScript::P2IDX, identityIndex, gteHeight, lteHeight);
        indexVec.push_back({oneKey, CScript::P2IDX});
    }

    if (sorted)
    {
        std::map<std::pair<uint32_t, uint32_t>, int> sortMap;
        std::vector<CAddressIndexDbEntry> sortedIdentityIndex;
        for (int i = 0; i < identityIndex.size(); i++)
        {
            auto &oneIdx = identityIndex[i];
            if (oneIdx.first.spending)
            {
                continue;
            }
            sortMap.insert(std::make_pair(std::make_pair(((uint32_t)oneIdx.first.blockHeight), oneIdx.first.txindex), i));
        }
        for (auto &idx : sortMap)
        {
            sortedIdentityIndex.push_back(identityIndex[idx.second]);
        }
        identityIndex = sortedIdentityIndex;
    }

    LOCK(mempool.cs);

    if (checkMempool)
    {
        mempool.getAddressIndex(indexVec, mempoolIdentities);
    }

    // order from first that spends unknown to last that has no spender
    if (identityIndex.size() || mempoolIdentities.size())
    {
        std::vector<int> toRemove;
        std::map<COutPoint, int> outputMap;
        for (int i = 0; i < identityIndex.size(); i++)
        {
            if (!identityIndex[i].first.spending)
            {
                CTransaction identityTx;
                CIdentity identity;
                uint256 blkHash;
                COptCCParams fP;
                BlockMap::iterator oneBlockIt;
                if (!myGetTransaction(identityIndex[i].first.txhash, identityTx, blkHash) ||
                    (oneBlockIt = mapBlockIndex.find(blkHash)) == mapBlockIndex.end() ||
                    !chainActive.Contains(oneBlockIt->second) ||
                    identityIndex[i].first.index >= identityTx.vout.size() ||
                    !(identityTx.vout[identityIndex[i].first.index].scriptPubKey.IsPayToCryptoCondition(fP) &&
                        fP.IsValid() &&
                        fP.evalCode == EVAL_IDENTITY_PRIMARY &&
                        fP.vData.size() &&
                        (identity = CIdentity(fP.vData[0])).IsValid()))
                {
                    LogPrintf("Invalid identity transaction %s:\n", identityIndex[i].first.txhash.GetHex().c_str());
                    printf("Invalid identity transaction %s:\n", identityIndex[i].first.txhash.GetHex().c_str());
                    return retVal;
                }
                retVal.push_back({identity,
                                  oneBlockIt->first,
                                  oneBlockIt->second->GetHeight(),
                                  CUTXORef(identityIndex[i].first.txhash, identityIndex[i].first.index),
                                  getProofs ?
                                    CPartialTransactionProof(identityTx,
                                                            std::vector<int>(),
                                                            std::vector<int>({(int)identityIndex[i].first.index}),
                                                            oneBlockIt->second,
                                                            proofHeight) :
                                    CPartialTransactionProof()});
            }
        }
        for (int i = 0; i < mempoolIdentities.size(); i++)
        {
            if (mempoolIdentities[i].first.spending)
            {
                continue;
            }
            CTransaction identityTx;
            if (mempool.lookup(mempoolIdentities[i].first.txhash, identityTx))
            {
                CIdentity identity;
                COptCCParams fP;
                if (mempoolIdentities[i].first.index >= identityTx.vout.size() ||
                    !(identityTx.vout[mempoolIdentities[i].first.index].scriptPubKey.IsPayToCryptoCondition(fP) &&
                        fP.IsValid() &&
                        fP.evalCode == EVAL_IDENTITY_PRIMARY &&
                        fP.vData.size() &&
                        (identity = CIdentity(fP.vData[0])).IsValid()))
                {
                    LogPrintf("Invalid identity transaction from mempool %s:\n", mempoolIdentities[i].first.txhash.GetHex().c_str());
                    printf("Invalid identity transaction from mempool %s:\n", mempoolIdentities[i].first.txhash.GetHex().c_str());
                    return retVal;
                }
                retVal.push_back({identity,
                                  uint256(),
                                  0,
                                  CUTXORef(mempoolIdentities[i].first.txhash, mempoolIdentities[i].first.index),
                                  CPartialTransactionProof()});
            }
        }
    }
    return retVal;
}

std::multimap<uint160, std::tuple<std::vector<unsigned char>, uint256, uint32_t, CUTXORef, CPartialTransactionProof>>
CIdentity::GetAggregatedIdentityMultimap(const uint160 &idID,
                                         uint32_t startHeight,
                                         uint32_t endHeight,
                                         bool checkMempool,
                                         bool getProofs,
                                         uint32_t proofHeight,
                                         const uint160 &indexKey,
                                         bool keepDeleted,
                                         bool sorted)
{
    std::multimap<uint160, std::tuple<std::vector<unsigned char>, uint256, uint32_t, CUTXORef, CPartialTransactionProof>>
        retMap;

    std::vector<uint160> indexKeys;
    if (!indexKey.IsNull())
    {
        indexKeys.push_back(indexKey);
        if (!keepDeleted)
        {
            indexKeys.push_back(
                CCrossChainRPCData::GetConditionID(CVDXF_Data::MultiMapKey(), CCrossChainRPCData::GetConditionID(CVDXF_Data::ContentMultiMapRemoveKey(), idID))
            );
            if (LogAcceptCategory("oracles"))
            {
                LogPrintf("%s: lookupKey: %s\n", __func__, EncodeDestination(CIdentityID(CCrossChainRPCData::GetConditionID(CVDXF_Data::MultiMapKey(), CCrossChainRPCData::GetConditionID(CVDXF_Data::ContentMultiMapRemoveKey(), idID)))).c_str());
            }
        }
    }

    auto identityHistory = LookupIdentities(idID, startHeight, endHeight, checkMempool, getProofs, proofHeight, indexKeys, sorted);
    for (auto &oneIdentity : identityHistory)
    {
        for (auto it = std::get<0>(oneIdentity).contentMultiMap.begin(); it != std::get<0>(oneIdentity).contentMultiMap.end(); it++)
        {
            if (it->first == CVDXF_Data::ContentMultiMapRemoveKey() &&
                it->second.size())
            {
                CDataStream ss(it->second, PROTOCOL_VERSION, SER_DISK);
                uint160 objTypeKey;
                uint32_t serVersion;
                size_t serSize;
                CContentMultiMapRemove removeAction;

                ss >> objTypeKey;
                ss >> VARINT(serVersion);
                ss >> VARINT(serSize);
                ss >> removeAction;

                if (objTypeKey != CVDXF_Data::ContentMultiMapRemoveKey() ||
                    !removeAction.IsValid())
                {
                    continue;
                }
                if (removeAction.action == removeAction.ACTION_CLEAR_MAP)
                {
                    retMap.clear();
                }
                else if (removeAction.action == removeAction.ACTION_REMOVE_ALL_KEY)
                {
                    retMap.erase(removeAction.entryKey);
                }
                else if (removeAction.action == removeAction.ACTION_REMOVE_ALL_KEYVALUE || removeAction.action == removeAction.ACTION_REMOVE_ONE_KEYVALUE)
                {
                    // all other actions require referencing specific keyed elements
                    auto removeItemRange = retMap.equal_range(removeAction.entryKey);
                    std::vector<std::multimap<uint160,
                                    std::tuple<std::vector<unsigned char>, uint256, uint32_t, CUTXORef, CPartialTransactionProof>>::iterator>
                        itemsToRemove;
                    for (auto removeItemCursor = removeItemRange.first; removeItemCursor != removeItemRange.second; removeItemCursor++)
                    {
                        CNativeHashWriter hw;
                        if (std::get<0>(removeItemCursor->second).size())
                        {
                            hw.write((char *)&(std::get<0>(removeItemCursor->second)[0]), std::get<0>(removeItemCursor->second).size());

                            uint256 hashVal = hw.GetHash();
                            if (hashVal == removeAction.valueHash)
                            {
                                itemsToRemove.push_back(removeItemCursor);
                                if (removeAction.action == removeAction.ACTION_REMOVE_ONE_KEYVALUE)
                                {
                                    break;
                                }
                            }
                        }
                    }
                    for (auto &oneCursor : itemsToRemove)
                    {
                        retMap.erase(oneCursor);
                    }
                }
            }
            else
            {
                retMap.insert(std::make_pair(it->first, std::make_tuple(it->second, std::get<1>(oneIdentity), std::get<2>(oneIdentity), std::get<3>(oneIdentity), std::get<4>(oneIdentity))));
            }
        }
    }
    return retMap;
}

std::vector<std::tuple<std::vector<unsigned char>, uint256, uint32_t, CUTXORef, CPartialTransactionProof>>
CIdentity::GetIdentityContentByKey(const uint160 &idID,
                                   const uint160 &vdxfKey,
                                   uint32_t startHeight,
                                   uint32_t endHeight,
                                   bool checkMempool,
                                   bool getProofs,
                                   uint32_t proofHeight,
                                   bool keepDeleted,
                                   bool sorted)
{
    uint160 lookupKey = CCrossChainRPCData::GetConditionID(CVDXF_Data::MultiMapKey(), CCrossChainRPCData::GetConditionID(vdxfKey, idID));

    if (LogAcceptCategory("oracles"))
    {
        LogPrintf("%s: vdxfKey: %s, idID: %s, lookupKey: %s\n", __func__, EncodeDestination(CIdentityID(vdxfKey)).c_str(), EncodeDestination(CIdentityID(idID)).c_str(), EncodeDestination(CIdentityID(lookupKey)).c_str());
    }

    auto aggregatedMap = GetAggregatedIdentityMultimap(idID, startHeight, endHeight, checkMempool, getProofs, proofHeight, lookupKey, keepDeleted, sorted);

    std::vector<std::tuple<std::vector<unsigned char>, uint256, uint32_t, CUTXORef, CPartialTransactionProof>> retVec;
    auto keyRange = aggregatedMap.equal_range(vdxfKey);
    std::multimap<uint32_t, std::tuple<std::vector<unsigned char>, uint256, uint32_t, CUTXORef, CPartialTransactionProof> &> sortMap;
    for (auto keyIt = keyRange.first; keyIt != keyRange.second; keyIt++)
    {
        sortMap.insert({std::get<2>(keyIt->second), keyIt->second});
    }
    for (auto &oneEntry : sortMap)
    {
        retVec.push_back(oneEntry.second);
    }
    return retVec;
}

bool CIdentity::IsLocked(uint32_t height) const
{
    return nVersion >= VERSION_VAULT &&
            (IsLocked() || (!ConnectedChains.IdentityLockOverride(*this, height) && unlockAfter >= height)) &&
            !IsRevoked();
}

CIdentity CIdentity::LookupIdentity(const std::string &name, uint32_t height, uint32_t *pHeightOut, CTxIn *idTxIn)
{
    return LookupIdentity(GetID(name), height, pHeightOut, idTxIn);
}

CIdentity CIdentity::LookupFirstIdentity(const CIdentityID &idID, uint32_t *pHeightOut, CTxIn *pIdTxIn, CTransaction *pidTx)
{
    CIdentity ret;

    uint32_t heightOut = 0;

    if (!pHeightOut)
    {
        pHeightOut = &heightOut;
    }
    else
    {
        *pHeightOut = 0;
    }

    CTxIn _idTxIn;
    if (!pIdTxIn)
    {
        pIdTxIn = &_idTxIn;
    }
    CTxIn &idTxIn = *pIdTxIn;

    std::vector<CAddressUnspentDbEntry> unspentOutputs, unspentNewIDX, unspendAdvancedIDX;

    CKeyID keyID(CCrossChainRPCData::GetConditionID(idID, EVAL_IDENTITY_RESERVATION));

    if ((GetAddressUnspent(keyID, CScript::P2IDX, unspentNewIDX) && unspentNewIDX.size()) ||
        (GetAddressUnspent(CCrossChainRPCData::GetConditionID(idID, EVAL_IDENTITY_ADVANCEDRESERVATION),
                           CScript::P2IDX, unspendAdvancedIDX) && unspendAdvancedIDX.size()) ||
        GetAddressUnspent(keyID, CScript::P2PKH, unspentOutputs))
    {
        if (!unspendAdvancedIDX.size() && !unspentNewIDX.size() && !unspentOutputs.size())
        {
            LOCK(mempool.cs);
            // if we are a PBaaS chain and it is in block 1, get it from there
            std::vector<CAddressIndexDbEntry> checkImported;
            uint256 blockHash;
            CTransaction blockOneCB;
            COptCCParams p;
            CIdentity firstIdentity;
            uint160 identityIdx(CCrossChainRPCData::GetConditionID(idID, EVAL_IDENTITY_PRIMARY));
            if (!IsVerusActive() &&
                GetAddressIndex(identityIdx, CScript::P2IDX, checkImported, 1, 1) &&
                checkImported.size() &&
                myGetTransaction(checkImported[0].first.txhash, blockOneCB, blockHash) &&
                blockOneCB.vout.size() > checkImported[0].first.index &&
                blockOneCB.vout[checkImported[0].first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_IDENTITY_PRIMARY &&
                p.vData.size() &&
                (firstIdentity = CIdentity(p.vData[0])).IsValid())
            {
                if (pHeightOut)
                {
                    *pHeightOut = 1;
                }
                if (pIdTxIn)
                {
                    *pIdTxIn = CTxIn(checkImported[0].first.txhash, checkImported[0].first.index);
                }
                if (pidTx)
                {
                    *pidTx = blockOneCB;
                }
                return firstIdentity;
            }
        }

        // combine searches into 1 vector
        unspentOutputs.insert(unspentOutputs.begin(), unspentNewIDX.begin(), unspentNewIDX.end());
        unspentOutputs.insert(unspentOutputs.begin(), unspendAdvancedIDX.begin(), unspendAdvancedIDX.end());
        CCoinsViewCache view(pcoinsTip);

        for (auto it = unspentOutputs.begin(); !ret.IsValid() && it != unspentOutputs.end(); it++)
        {
            CCoins coins;

            if (view.GetCoins(it->first.txhash, coins))
            {
                if (coins.IsAvailable(it->first.index))
                {
                    COptCCParams p;
                    if (coins.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() &&
                        (p.evalCode == EVAL_IDENTITY_RESERVATION || p.evalCode == EVAL_IDENTITY_ADVANCEDRESERVATION))
                    {
                        CTransaction idTx;
                        uint256 blkHash;
                        if (myGetTransaction(it->first.txhash, idTx, blkHash) && (ret = CIdentity(idTx)).IsValid() && ret.GetID() == idID)
                        {
                            int i;
                            for (i = 0; i < idTx.vout.size(); i++)
                            {
                                COptCCParams p;
                                if (idTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3 && p.evalCode == EVAL_IDENTITY_PRIMARY)
                                {
                                    break;
                                }
                            }

                            if (i < idTx.vout.size())
                            {
                                if (pidTx)
                                {
                                    *pidTx = idTx;
                                }
                                idTxIn = CTxIn(it->first.txhash, i);
                                *pHeightOut = it->second.blockHeight;
                            }
                        }
                    }
                }
            }
        }
    }
    return ret;
}

uint160 CIdentity::IdentityPrimaryAddressKey(const CTxDestination &dest)
{
    CHashWriterSHA256 hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << dest.which();
    hw << GetDestinationBytes(dest);
    uint160 nameSpace;
    return CCrossChainRPCData::GetConditionID(CVDXF::GetDataKey(IdentityPrimaryAddressKeyName(), nameSpace), hw.GetHash());
}

bool CIdentity::GetIdentityOutsByPrimaryAddress(const CTxDestination &address, std::map<uint160, std::pair<CAddressIndexDbEntry, CIdentity>> &identities, uint32_t start, uint32_t end)
{
    if (!fIdIndex)
    {
        return false;
    }
    // which transaction are we in this block?
    std::vector<CAddressIndexDbEntry> addressIndex;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CIdentity::IdentityPrimaryAddressKey(address),
                        CScript::P2IDX,
                        addressIndex,
                        start,
                        end))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction identityTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, identityTx, blkHash))
            {
                CIdentity identity;
                if ((identity = CIdentity(identityTx.vout[idx.first.index].scriptPubKey)).IsValid())
                {
                    identities.insert(std::make_pair(identity.GetID(), std::make_pair(idx, identity)));
                }
                else
                {
                    LogPrintf("%s: invalid identity output: %s, %lu\n", __func__, idx.first.txhash.GetHex().c_str(), idx.first.index);
                }
            }
        }
        return true;
    }
    return false;
}

bool CIdentity::GetIdentityOutsWithRevocationID(const CIdentityID &idID, std::map<uint160, std::pair<CAddressIndexDbEntry, CIdentity>> &identities, uint32_t start, uint32_t end)
{
    if (!fIdIndex)
    {
        return false;
    }
    // which transaction are we in this block?
    std::vector<CAddressIndexDbEntry> addressIndex;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CIdentity::IdentityRevocationKey(idID),
                        CScript::P2IDX,
                        addressIndex,
                        start,
                        end))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction identityTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, identityTx, blkHash))
            {
                CIdentity identity;
                if ((identity = CIdentity(identityTx.vout[idx.first.index].scriptPubKey)).IsValid())
                {
                    identities.insert(std::make_pair(identity.GetID(), std::make_pair(idx, identity)));
                }
                else
                {
                    LogPrintf("%s: invalid identity output: %s, %lu\n", __func__, idx.first.txhash.GetHex().c_str(), idx.first.index);
                }
            }
        }
        return true;
    }
    return false;
}

bool CIdentity::GetIdentityOutsWithRecoveryID(const CIdentityID &idID, std::map<uint160, std::pair<CAddressIndexDbEntry, CIdentity>> &identities, uint32_t start, uint32_t end)
{
    if (!fIdIndex)
    {
        return false;
    }
    // which transaction are we in this block?
    std::vector<CAddressIndexDbEntry> addressIndex;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CIdentity::IdentityRecoveryKey(idID),
                        CScript::P2IDX,
                        addressIndex,
                        start,
                        end))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction identityTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, identityTx, blkHash))
            {
                CIdentity identity;
                if ((identity = CIdentity(identityTx.vout[idx.first.index].scriptPubKey)).IsValid())
                {
                    identities.insert(std::make_pair(identity.GetID(), std::make_pair(idx, identity)));
                }
                else
                {
                    LogPrintf("%s: invalid identity output: %s, %lu\n", __func__, idx.first.txhash.GetHex().c_str(), idx.first.index);
                }
            }
        }
        return true;
    }
    return false;
}

bool CIdentity::GetActiveIdentitiesByPrimaryAddress(const CTxDestination &address, std::map<uint160, std::pair<CAddressUnspentDbEntry, CIdentity>> &identities)
{
    if (!fIdIndex)
    {
        return false;
    }
    // which transaction are we in this block?
    std::vector<CAddressUnspentDbEntry> unspentIndex;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressUnspent(CIdentity::IdentityPrimaryAddressKey(address), CScript::P2IDX, unspentIndex))
    {
        for (auto &idx : unspentIndex)
        {
            uint256 blkHash;
            CTransaction identityTx;
            CIdentity identity;
            if ((identity = CIdentity(idx.second.script)).IsValid())
            {
                identities.insert(std::make_pair(identity.GetID(), std::make_pair(idx, identity)));
            }
            else
            {
                LogPrintf("%s: invalid identity in unspent index 0: %s, %lu\n", __func__, idx.first.txhash.GetHex().c_str(), idx.first.index);
            }
        }
        return true;
    }
    return false;
}

bool CIdentity::GetActiveIdentitiesWithRevocationID(const CIdentityID &idID, std::map<uint160, std::pair<CAddressUnspentDbEntry, CIdentity>> &identities)
{
    if (!fIdIndex)
    {
        return false;
    }
    // which transaction are we in this block?
    std::vector<CAddressUnspentDbEntry> unspentIndex;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressUnspent(CIdentity::IdentityRevocationKey(idID), CScript::P2IDX, unspentIndex))
    {
        for (auto &idx : unspentIndex)
        {
            uint256 blkHash;
            CTransaction identityTx;
            CIdentity identity;
            if ((identity = CIdentity(idx.second.script)).IsValid())
            {
                identities.insert(std::make_pair(identity.GetID(), std::make_pair(idx, identity)));
            }
            else
            {
                LogPrintf("%s: invalid identity in unspent index 2: %s, %lu\n", __func__, idx.first.txhash.GetHex().c_str(), idx.first.index);
            }
        }
        return true;
    }
    return false;
}

bool CIdentity::GetActiveIdentitiesWithRecoveryID(const CIdentityID &idID, std::map<uint160, std::pair<CAddressUnspentDbEntry, CIdentity>> &identities)
{
    if (!fIdIndex)
    {
        return false;
    }
    // which transaction are we in this block?
    std::vector<CAddressUnspentDbEntry> unspentIndex;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressUnspent(CIdentity::IdentityRecoveryKey(idID), CScript::P2IDX, unspentIndex))
    {
        for (auto &idx : unspentIndex)
        {
            uint256 blkHash;
            CTransaction identityTx;
            CIdentity identity;
            if ((identity = CIdentity(idx.second.script)).IsValid())
            {
                identities.insert(std::make_pair(identity.GetID(), std::make_pair(idx, identity)));
            }
            else
            {
                LogPrintf("%s: invalid identity in unspent index 3: %s, %lu\n", __func__, idx.first.txhash.GetHex().c_str(), idx.first.index);
            }
        }
        return true;
    }
    return false;
}

bool HasReferralRequired(const CIdentity &identity, const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height, const CCurrencyDefinition &issuingParent)
{
    CTransaction inputTx;
    uint160 parentID = issuingParent.GetID();
    bool isNativeParent = parentID == ASSETCHAINS_CHAINID;
    bool authorizedIssuance = false;
    uint160 checkReferralID;

    if (identity.parent.IsNull() && issuingParent.parent.IsNull() && identity.GetID() == issuingParent.GetID())
    {
        uint160 idParent = issuingParent.GetID();
        checkReferralID = CIdentity::GetID(identity.name, idParent);
    }

    for (auto &oneIn : tx.vin)
    {
        uint256 blockHash;

        // this is not an input check, but we will check if the input is available
        // the precheck's can be called sometimes before their antecedents are available, but
        // if they are available, which will be checked on the input check, they will also be
        // available here at least once in the verification of the tx
        if (inputTx.GetHash() == oneIn.prevout.hash || myGetTransaction(oneIn.prevout.hash, inputTx, blockHash))
        {
            if (oneIn.prevout.n >= inputTx.vout.size())
            {
                return state.Error("Invalid input number for source transaction");
            }

            COptCCParams p;

            // make sure that no form of complex output could circumvent the test for controller
            // this should be encapsulated as a test that can handle complex cases, but until then
            // require them to be simple when validating
            if (!(inputTx.vout[oneIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.version >= p.VERSION_V3))
            {
                continue;
            }

            std::vector<CIdentity> checkIdentities;
            for (auto oneDest : p.vKeys)
            {
                if (oneDest.which() == COptCCParams::ADDRTYPE_ID)
                {
                    CIdentity checkIdentity = CIdentity::LookupIdentity(GetDestinationID(oneDest), height);
                    uint160 idID = GetDestinationID(oneDest);

                    // any valid, unrevoked ID from the same parent may be a referral by signing the transaction
                    if (checkIdentity.IsValidUnrevoked() &&
                        (checkIdentity.parent == parentID ||
                         idID == parentID ||
                         (chainActive[height]->nTime >= PBAAS_PREMAINNET_ACTIVATION && !checkReferralID.IsNull() && idID == checkReferralID)))
                    {
                        checkIdentities.push_back(checkIdentity);
                    }
                }
            }

            for (auto potentialReferral : checkIdentities)
            {
                std::set<uint160> signingKeys;
                for (auto &oneDest : potentialReferral.primaryAddresses)
                {
                    signingKeys.insert(GetDestinationID(oneDest));
                }

                CSmartTransactionSignatures smartSigs;
                std::vector<unsigned char> ffVec = GetFulfillmentVector(oneIn.scriptSig);
                if (!(ffVec.size() &&
                        (smartSigs = CSmartTransactionSignatures(std::vector<unsigned char>(ffVec.begin(), ffVec.end()))).IsValid() &&
                        smartSigs.sigHashType == SIGHASH_ALL))
                {
                    continue;
                }

                int numIDSigs = 0;

                // ensure that the transaction is sent to the ID and signed by a valid ID signature
                for (auto &oneSig : smartSigs.signatures)
                {
                    if (signingKeys.count(oneSig.first))
                    {
                        numIDSigs++;
                    }
                }

                if (numIDSigs < potentialReferral.minSigs)
                {
                    continue;
                }
                authorizedIssuance = true;
                break;
            }
        }
    }
    return authorizedIssuance;
}

// this enables earliest rejection of invalid identity registrations transactions
bool ValidateSpendingIdentityReservation(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height, CCurrencyDefinition issuingParent)
{
    // CHECK #1 - there is only one reservation output, and there is also one identity output that matches the reservation.
    //            the identity output must come first and have from 0 to 3 referral outputs between it and the reservation.
    int identityCount = 0;
    int reservationCount = 0;
    CIdentity newIdentity;
    CNameReservation newName;
    CAdvancedNameReservation advNewName;
    std::vector<CTxDestination> referrers;
    bool valid = true;

    bool isVault = CConstVerusSolutionVector::GetVersionByHeight(height) >= CActivationHeight::ACTIVATE_VERUSVAULT;
    bool isPBaaS = CConstVerusSolutionVector::GetVersionByHeight(height) >= CActivationHeight::ACTIVATE_PBAAS;

    // get the primary currency to price in and apply any conversion rates
    CCurrencyDefinition issuingCurrency = issuingParent;
    uint160 parentID = issuingParent.GetID();
    uint160 issuerID = issuingCurrency.GetID();
    uint160 feePricingCurrency = issuerID;
    int64_t idReferralFee = issuingCurrency.IDReferralAmount();
    int64_t idFullRegistrationFee = issuingCurrency.IDFullRegistrationAmount();
    int64_t idReferredRegistrationFee = issuingCurrency.IDReferredRegistrationAmount();
    CCurrencyValueMap burnAmount;
    CCoinbaseCurrencyState pricingState;

    if (!isPBaaS && !issuingCurrency.IsPBaaSChain())
    {
        return state.Error("Advanced VerusID registrations invalid until PBaaS upgrade");
    }

    // if issuing IDs from this currency requires permission of the identity/DAO of the
    // currency ID, verify that there is an input from that ID and that the currency ID has signed this transaction
    if (isPBaaS)
    {
        // check if there are authorization requirements
        bool authorizedIssuance = false;

        if (issuingParent.IDRequiresPermission())
        {
            CIdentity signingID = CIdentity::LookupIdentity(parentID, height);

            std::set<uint160> signingKeys;
            for (auto &oneDest : signingID.primaryAddresses)
            {
                signingKeys.insert(GetDestinationID(oneDest));
            }
            if (!signingID.IsValid())
            {
                return state.Error("Invalid identity or identity not found for currency mint or burn with weight change");
            }

            CTransaction inputTx;
            for (auto &oneIn : tx.vin)
            {
                uint256 blockHash;

                // this is not an input check, but we will check if the input is available
                // the precheck's can be called sometimes before their antecedents are available, but
                // if they are available, which will be checked on the input check, they will also be
                // available here at least once in the verification of the tx
                if (inputTx.GetHash() == oneIn.prevout.hash || myGetTransaction(oneIn.prevout.hash, inputTx, blockHash))
                {
                    if (oneIn.prevout.n >= inputTx.vout.size())
                    {
                        return state.Error("Invalid input number for source transaction");
                    }

                    COptCCParams p;

                    // make sure that no form of complex output could circumvent the test for controller
                    // this should be encapsulated as a test that can handle complex cases, but until then
                    // require them to be simple when validating
                    if (!(inputTx.vout[oneIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                            p.IsValid() &&
                            p.version >= p.VERSION_V3))
                    {
                        continue;
                    }

                    bool hasPermittingID = false;
                    for (auto &oneKey : p.vKeys)
                    {
                        if (oneKey.which() == COptCCParams::ADDRTYPE_ID && GetDestinationID(oneKey) == issuerID)
                        {
                            hasPermittingID = true;
                            break;
                        }
                    }
                    if (!hasPermittingID)
                    {
                        continue;
                    }

                    CSmartTransactionSignatures smartSigs;
                    std::vector<unsigned char> ffVec = GetFulfillmentVector(oneIn.scriptSig);
                    if (!(ffVec.size() &&
                            (smartSigs = CSmartTransactionSignatures(std::vector<unsigned char>(ffVec.begin(), ffVec.end()))).IsValid() &&
                            smartSigs.sigHashType == SIGHASH_ALL))
                    {
                        continue;
                    }

                    int numIDSigs = 0;

                    // ensure that the transaction is sent to the ID and signed by a valid ID signature
                    for (auto &oneSig : smartSigs.signatures)
                    {
                        if (signingKeys.count(oneSig.first))
                        {
                            numIDSigs++;
                        }
                    }

                    if (numIDSigs < signingID.minSigs)
                    {
                        continue;
                    }
                    authorizedIssuance = true;
                    break;
                }
            }
        }
        else if (issuingParent.IDReferralRequired())
        {
            CTransaction inputTx;
            for (auto &oneIn : tx.vin)
            {
                uint256 blockHash;

                // this is not an input check, but we will check if the input is available
                // the precheck's can be called sometimes before their antecedents are available, but
                // if they are available, which will be checked on the input check, they will also be
                // available here at least once in the verification of the tx
                if (inputTx.GetHash() == oneIn.prevout.hash || myGetTransaction(oneIn.prevout.hash, inputTx, blockHash))
                {
                    if (oneIn.prevout.n >= inputTx.vout.size())
                    {
                        return state.Error("Invalid input number for source transaction");
                    }

                    COptCCParams p;

                    // make sure that no form of complex output could circumvent the test for controller
                    // this should be encapsulated as a test that can handle complex cases, but until then
                    // require them to be simple when validating
                    if (!(inputTx.vout[oneIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                            p.IsValid() &&
                            p.version >= p.VERSION_V3))
                    {
                        continue;
                    }

                    std::vector<CIdentity> checkIdentities;
                    for (auto oneDest : p.vKeys)
                    {
                        if (oneDest.which() == COptCCParams::ADDRTYPE_ID)
                        {
                            CIdentity checkIdentity = CIdentity::LookupIdentity(GetDestinationID(oneDest), height);

                            // any valid, unrevoked ID from the same parent may be a referral by signing the transaction
                            if (checkIdentity.IsValidUnrevoked() && (checkIdentity.parent == parentID || GetDestinationID(oneDest) == parentID))
                            {
                                checkIdentities.push_back(checkIdentity);
                            }
                        }
                    }

                    for (auto potentialReferral : checkIdentities)
                    {
                        std::set<uint160> signingKeys;
                        for (auto &oneDest : potentialReferral.primaryAddresses)
                        {
                            signingKeys.insert(GetDestinationID(oneDest));
                        }

                        CSmartTransactionSignatures smartSigs;
                        std::vector<unsigned char> ffVec = GetFulfillmentVector(oneIn.scriptSig);
                        if (!(ffVec.size() &&
                                (smartSigs = CSmartTransactionSignatures(std::vector<unsigned char>(ffVec.begin(), ffVec.end()))).IsValid() &&
                                smartSigs.sigHashType == SIGHASH_ALL))
                        {
                            continue;
                        }

                        int numIDSigs = 0;

                        // ensure that the transaction is sent to the ID and signed by a valid ID signature
                        for (auto &oneSig : smartSigs.signatures)
                        {
                            if (signingKeys.count(oneSig.first))
                            {
                                numIDSigs++;
                            }
                        }

                        if (numIDSigs < potentialReferral.minSigs)
                        {
                            continue;
                        }
                        authorizedIssuance = true;
                        break;
                    }
                }
            }
        }
        else
        {
            authorizedIssuance = true;
        }

        if (!authorizedIssuance)
        {
            return state.Error("Attempt to register restricted ID without required authority from currency " + ConnectedChains.GetFriendlyCurrencyName(parentID));
        }

        // determine if we may use a gateway converter to issue
        // if parent is a gateway and not a name controller, we can

        if (!issuingCurrency.IsNameController() && !issuingCurrency.GatewayConverterID().IsNull())
        {
            issuingCurrency = ConnectedChains.GetCachedCurrency(issuingCurrency.GatewayConverterID());
            if (!(issuingCurrency.IsValid() &&
                  issuingCurrency.IsFractional() &&
                  issuingCurrency.IsGatewayConverter() &&
                  issuingCurrency.gatewayID == parentID))
            {
                return state.Error("Invalid converter for gateway to register identity");
            }
            issuerID = issuingCurrency.GetID();
        }
        else if (issuingCurrency.IsGatewayConverter())
        {
            if (issuingCurrency.gatewayID.IsNull())
            {
                return state.Error("Invalid gateway converter for identity registration");
            }
            CCurrencyDefinition gatewayCurrency = ConnectedChains.GetCachedCurrency(issuingCurrency.gatewayID);
            if (gatewayCurrency.GetID() != issuingCurrency.systemID)
            {
                return state.Error("Cannot register an identity directly from a gateway converter of a non-PBaaS gateway");
            }
        }
        if (!issuingCurrency.IsValid() || issuingCurrency.systemID != ASSETCHAINS_CHAINID)
        {
            return state.Error("Invalid issuing currency to register identity " + ConnectedChains.GetFriendlyCurrencyName(issuingCurrency.GetID()));
        }

        if (issuingCurrency.IsFractional())
        {
            feePricingCurrency = issuingCurrency.FeePricingCurrency();
            if ((tx.nExpiryHeight - DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA) > height ||
                !(pricingState = ConnectedChains.GetCurrencyState(issuerID, (tx.nExpiryHeight - DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA) - 1, false)).IsValid() ||
                !pricingState.IsLaunchConfirmed())
            {
                return state.Error("Invalid currency state for gateway converter to register identity");
            }
            if (feePricingCurrency != issuerID)
            {
                int32_t reserveIndex = pricingState.GetReserveMap()[feePricingCurrency];
                idReferralFee = pricingState.ReserveToNative(idReferralFee, reserveIndex);
                idFullRegistrationFee = pricingState.ReserveToNative(idFullRegistrationFee, reserveIndex);
                idReferredRegistrationFee = pricingState.ReserveToNative(idReferredRegistrationFee, reserveIndex);
            }
        }
        // aside from fractional currencies, centralized or native currencies can issue IDs
        else if (!(issuingCurrency.GetID() == ASSETCHAINS_CHAINID || issuingCurrency.IsToken()))
        {
            return state.Error("Invalid parent currency for identity registration on this chain");
        }
    }

    for (auto &txout : tx.vout)
    {
        COptCCParams p;
        if (txout.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
        {
            if (p.evalCode == EVAL_IDENTITY_PRIMARY)
            {
                if (identityCount++ || p.vData.size() < 2)
                {
                    valid = false;
                    break;
                }
                newIdentity = CIdentity(p.vData[0]);
                if (newIdentity.parent.IsNull() &&
                    chainActive[height - 1]->nTime > PBAAS_PREMAINNET_ACTIVATION &&
                    !HasReferralRequired(newIdentity, tx, outNum, state, height, ConnectedChains.ThisChain()))
                {
                    return state.Error("Cannot make identity without valid referral");
                }
            }
            else if (p.evalCode == EVAL_IDENTITY_RESERVATION)
            {
                if (reservationCount++ || p.vData.size() < 2 || !(newName = CNameReservation(p.vData[0])).IsValid())
                {
                    valid = false;
                    break;
                }
            }
            else if (isPBaaS && p.evalCode == EVAL_IDENTITY_ADVANCEDRESERVATION)
            {
                if (reservationCount++ || p.vData.size() < 2 || !(advNewName = CAdvancedNameReservation(p.vData[0])).IsValid())
                {
                    valid = false;
                    break;
                }
            }
            else if (identityCount && !reservationCount)
            {
                if (isPBaaS)
                {
                    bool testModePreUpdate = PBAAS_TESTMODE && !ConnectedChains.IncludePostLaunchFees(height);
                    if (issuingCurrency.proofProtocol == issuingCurrency.PROOF_CHAINID &&
                        (issuingCurrency.endBlock == 0 ||
                         ((testModePreUpdate && issuingCurrency.endBlock <= height) ||
                          (!testModePreUpdate && height <= issuingCurrency.endBlock))))
                    {
                        // if this is a purchase from centralized/DAO-based currency, ensure we have a valid output
                        // of the correct amount to the issuer ID before any of the referrals
                        if (referrers.size() == 0 && burnAmount.valueMap.size() == 0)
                        {
                            // first, we just record the amount/currency and ensure it is a non-zero burn.
                            // after we've verified referrals, we can confirm the amount as being correct.
                            CTokenOutput to;
                            if (p.evalCode == EVAL_RESERVE_OUTPUT &&
                                p.vData.size() == 2 &&
                                (to = CTokenOutput(p.vData[0])).IsValid() &&
                                p.m == 1 &&
                                p.n == 1 &&
                                p.vKeys.size() == 1 &&
                                p.vData.size() == 2 &&
                                p.vKeys[0].which() == COptCCParams::ADDRTYPE_ID &&
                                GetDestinationID(p.vKeys[0]) == issuerID)
                            {
                                burnAmount += to.reserveValues;
                                if (txout.nValue)
                                {
                                    burnAmount.valueMap[ASSETCHAINS_CHAINID] += txout.nValue;
                                }
                                if (!burnAmount.valueMap.size())
                                {
                                    burnAmount.valueMap[ASSETCHAINS_CHAINID] = 0;
                                }
                                continue;
                            }
                            else
                            {
                                return state.Error("Invalid fee output for identity registration with specified currency");
                            }
                        }
                    }
                    else if (issuingCurrency.IsToken())
                    {
                        // if this is a burn and issue, we need to make sure we have a valid burn transaction
                        // of the correct amount before any of the referrals
                        if (referrers.size() == 0 && burnAmount.valueMap.size() == 0)
                        {
                            // first, we just record the amount/currency and ensure it is a non-zero burn.
                            // after we've verified referrals, we can confirm the amount as being correct.
                            CReserveTransfer rt;
                            if (p.evalCode == EVAL_RESERVE_TRANSFER &&
                                p.vData.size() == 2 &&
                                (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                                rt.IsBurn() &&
                                rt.GetImportCurrency() == issuerID &&
                                !rt.HasNextLeg() &&
                                (rt.FirstCurrency() == issuerID || issuingCurrency.GetCurrenciesMap().count(rt.FirstCurrency())))
                            {
                                burnAmount.valueMap[rt.FirstCurrency()] += rt.FirstValue();
                                continue;
                            }
                            else
                            {
                                return state.Error("Invalid fee burn for identity registration with specified currency");
                            }
                        }
                    }

                    if (!issuingCurrency.IDReferralLevels() ||
                        p.vKeys.size() < 1 ||
                        referrers.size() > (issuingCurrency.IDReferralLevels() - 1) ||
                        (p.evalCode != EVAL_NONE && p.evalCode != EVAL_RESERVE_OUTPUT) ||
                        p.n > 1 ||
                        p.m != 1 ||
                        (issuerID == ASSETCHAINS_CHAINID && txout.nValue < idReferralFee) ||
                        (issuerID != ASSETCHAINS_CHAINID && txout.ReserveOutValue().valueMap[issuerID] < idReferralFee))
                    {
                        valid = false;
                        break;
                    }
                    referrers.push_back(p.vKeys[0]);
                }
                else
                {
                    if (!issuingParent.IDReferralLevels() ||
                        p.vKeys.size() < 1 ||
                        referrers.size() > (issuingParent.IDReferralLevels() - 1) ||
                        p.evalCode != 0 ||
                        p.n > 1 ||
                        p.m != 1 ||
                        txout.nValue < issuingParent.IDReferralAmount())
                    {
                        valid = false;
                        break;
                    }
                    referrers.push_back(p.vKeys[0]);
                }
            }
            else if (identityCount != reservationCount)
            {
                valid = false;
                break;
            }
        }
    }

    // we can close a commitment UTXO without an identity
    if (valid && !identityCount)
    {
        return state.Error("Transaction may not have an identity reservation without a matching identity");
    }
    else if (!valid)
    {
        return state.Error("Improperly formed identity definition transaction");
    }

    std::vector<CTxDestination> dests;
    int minSigs;
    txnouttype outType;
    if (ExtractDestinations(tx.vout[outNum].scriptPubKey, outType, dests, minSigs))
    {
        uint160 thisID = newIdentity.GetID();
        for (auto &dest : dests)
        {
            uint160 oneDestID;
            if (dest.which() == COptCCParams::ADDRTYPE_ID && (oneDestID = GetDestinationID(dest)) != thisID && !CIdentity::LookupIdentity(CIdentityID(oneDestID)).IsValid())
            {
                return state.Error("Destination includes invalid identity");
            }
        }
    }

    // for PBaaS, ensure that correct systemID is set to support mapped currencies
    // cases where it is valid to have an issuing parent currency that does not have a system ID of the
    // chain registering the currency include:
    // 1) System of systemID is launched on this chain and is not a name controller AND
    // 2) Parent is systemID
    if (issuingParent.systemID != ASSETCHAINS_CHAINID)
    {
        if (issuingParent.launchSystemID != ASSETCHAINS_CHAINID ||
            !issuingParent.IsGateway() ||
            issuingParent.IsNameController() ||
            issuingParent.systemID != issuingParent.GetID())
        {
            return state.Error("Attempt to register ID on chain other than name controller");
        }
    }

    // CHECK #2 - must be rooted in verified valid parent
    if (newIdentity.parent != parentID &&
        !(isVault && newIdentity.GetID() == ASSETCHAINS_CHAINID && IsVerusActive()))
    {
        return state.Error("Invalid identity parent of new identity registration");
    }

    // CHECK #3 - if dupID is valid, we need to be spending it to recover. redefinition is invalid
    CTxIn idTxIn;
    uint32_t priorHeightOut;
    CIdentity dupID = newIdentity.LookupIdentity(newIdentity.GetID(), height - 1, &priorHeightOut, &idTxIn);

    // CHECK #3a - if dupID is invalid, ensure we spend a matching name commitment
    if (dupID.IsValid())
    {
        return state.Error("Identity already exists");
    }

    // CHECK #3c - check commitment hash match
    int commitmentHeight = 0;
    const CCoins *coins;
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);

    LOCK(mempool.cs);

    CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
    view.SetBackend(viewMemPool);

    CCommitmentHash ch;
    int idx = -1;

    CAmount nValueIn = 0;
    {
        // from here, we must spend a matching name commitment
        std::map<uint256, const CCoins *> txMap;
        for (auto &oneTxIn : tx.vin)
        {
            coins = txMap[oneTxIn.prevout.hash];
            if (!coins && !(coins = view.AccessCoins(oneTxIn.prevout.hash)))
            {
                //LogPrintf("Cannot access input from output %u of transaction %s in transaction %s\n", oneTxIn.prevout.n, oneTxIn.prevout.hash.GetHex().c_str(), tx.GetHash().GetHex().c_str());
                //printf("Cannot access input from output %u of transaction %s in transaction %s\n", oneTxIn.prevout.n, oneTxIn.prevout.hash.GetHex().c_str(), tx.GetHash().GetHex().c_str());
                return state.Error("Cannot access input");
            }
            txMap[oneTxIn.prevout.hash] = coins;

            if (oneTxIn.prevout.n >= coins->vout.size())
            {
                //extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);
                //UniValue uniTx;
                //TxToJSON(tx, uint256(), uniTx);
                //printf("%s\n", uniTx.write(1, 2).c_str());
                return state.Error("Input index out of range");
            }

            COptCCParams p;
            if (idx == -1 &&
                coins->vout[oneTxIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_IDENTITY_COMMITMENT &&
                p.vData.size())
            {
                idx = oneTxIn.prevout.n;
                ::FromVector(p.vData[0], ch);
                commitmentHeight = coins->nHeight;
                // this needs to already be in a prior block, or we can't consider it valid
                if (!commitmentHeight || commitmentHeight == -1)
                {
                    return state.Error("ID commitment was not already in blockchain");
                }
            }
        }
    }

    if (idx == -1 || ch.hash.IsNull())
    {
        std::string specificMsg = "Invalid identity commitment in tx: " + tx.GetHash().GetHex();
        return state.Error(specificMsg);
    }

    // are we spending a matching name commitment?
    if ((advNewName.IsValid() && ch.hash != advNewName.GetCommitment().hash) ||
        (!advNewName.IsValid() && (!newName.IsValid() || ch.hash != newName.GetCommitment().hash)))
    {
        return state.Error("Mismatched identity commitment");
    }

    // CHECK #3d - check referrer validity, if there is one
    CIdentityID referralID = advNewName.IsValid() ? advNewName.referral : newName.referral;

    uint32_t heightOut = 0;
    CTransaction referralTx;

    CIdentity firstReferralIdentity;

    if (!referralID.IsNull() && issuingCurrency.IDReferralLevels() &&
        !((firstReferralIdentity = CIdentity::LookupFirstIdentity(referralID, &heightOut, &idTxIn, &referralTx)).IsValid() && heightOut < commitmentHeight))
    {
        // invalid referral identity
        return state.Error("Invalid referral identity specified");
    }

    CReserveTransactionDescriptor rtxd(tx, view, height);

    // if we're issuing from the native chain directly, we skip the complexity
    if (isPBaaS)
    {
        // CHECK #3e
        // although IDs issued by tokens are paid for by the currency or a reserve,
        // an import fee must be paid in the native currency to register on the current chain
        if (issuerID != ASSETCHAINS_CHAINID && rtxd.NativeFees() < ConnectedChains.ThisChain().IDImportFee())
        {
            return state.Error("Invalid identity registration - must include native currency import fee as well as registration fee.");
        }

        int64_t feePaid =
                issuerID == ASSETCHAINS_CHAINID ?
                    rtxd.NativeFees() :
                    (burnAmount.valueMap.begin()->first == issuerID ?
                     burnAmount.valueMap.begin()->second :
                     (issuingCurrency.IsFractional() ?
                      pricingState.ReserveToNative(burnAmount.valueMap.begin()->second, pricingState.GetReserveMap()[burnAmount.valueMap.begin()->first]) :
                      0));

        // CHECK #4 - if blockchain referrals are not enabled or if there is no referring identity, make sure the fees of this transaction are full price for an identity,
        // all further checks only if referrals are enabled and there is a referrer
        if (!issuingCurrency.IDReferralLevels() || referralID.IsNull())
        {
            // make sure this transaction is burning the full price for an identity if it is not registered, all further checks only if there is a referrer
            if (feePaid < idFullRegistrationFee)
            {
                return state.Error("Invalid identity registration - insufficient fee");
            }
            return true;
        }

        // CHECK #5 - ensure that the first referring output goes to the referring identity followed by additional referrers
        // referrer must be mined in when this transaction is put into the mem pool
        if (firstReferralIdentity.parent != parentID && firstReferralIdentity.GetID() != parentID)
        {
            //printf("%s: cannot find first instance of: %s\n", __func__, EncodeDestination(CIdentityID(newName.referral)).c_str());
            return state.Error("Invalid identity registration referral - different parent");
        }

        bool isReferral = false;
        bool afterPrimary = false;
        std::vector<CTxDestination> checkReferrers = std::vector<CTxDestination>({referralID});

        if (heightOut != 1)
        {
            if (ConnectedChains.IsUpgrade01Active(height - 1) ||
                checkReferrers.size() < issuingParent.IDReferralLevels())
            {
                for (auto &txout : referralTx.vout)
                {
                    COptCCParams p;
                    if (txout.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
                    {
                        if (p.evalCode == EVAL_IDENTITY_PRIMARY)
                        {
                            afterPrimary = true;
                        }
                        else if (afterPrimary &&
                                !isReferral &&
                                issuingParent.IDReferrals() &&
                                issuingParent.IDReferralLevels() &&
                                ((issuingParent.proofProtocol != issuingParent.PROOF_CHAINID && p.evalCode == EVAL_RESERVE_TRANSFER) ||
                                (issuingParent.proofProtocol == issuingParent.PROOF_CHAINID && (p.evalCode == EVAL_RESERVE_OUTPUT || p.evalCode == EVAL_NONE))))
                        {
                            isReferral = true;
                            continue;
                        }
                        else if (p.evalCode == EVAL_IDENTITY_RESERVATION || p.evalCode == EVAL_IDENTITY_ADVANCEDRESERVATION)
                        {
                            break;
                        }
                        else if (isReferral || (afterPrimary &&
                                                issuerID == ASSETCHAINS_CHAINID &&
                                                issuingParent.proofProtocol != issuingParent.PROOF_CHAINID &&
                                                issuingParent.IDReferrals() &&
                                                issuingParent.IDReferralLevels()))
                        {
                            isReferral = true;
                            if (p.vKeys.size() != 1 || p.vKeys[0].which() != COptCCParams::ADDRTYPE_ID)
                            {
                                // invalid referral
                                return state.Error("Invalid identity registration referral outputs");
                            }
                            else
                            {
                                checkReferrers.push_back(p.vKeys[0]);
                                if (checkReferrers.size() == issuingParent.IDReferralLevels())
                                {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // only validate referrers before PBaaS
        if (referrers.size() != checkReferrers.size())
        {
            return state.Error("Invalid identity registration - incorrect referral payments");
        }

        // make sure all paid referrers are correct
        for (int i = 0; i < referrers.size(); i++)
        {
            if (referrers[i] != checkReferrers[i])
            {
                return state.Error("Invalid identity registration - incorrect referral payments");
            }
        }

        // CHECK #6 - ensure that the transaction pays the correct mining and referral fees
        if (feePaid < (idReferredRegistrationFee - (referrers.size() * idReferralFee)))
        {
            return state.Error("Invalid identity registration - insufficient fee");
        }

        return true;
    }
    else
    {
        // CHECK #4 - if blockchain referrals are not enabled or if there is no referring identity, make sure the fees of this transaction are full price for an identity,
        // all further checks only if referrals are enabled and there is a referrer
        if (!issuingCurrency.IDReferralLevels() || referralID.IsNull())
        {
            // make sure the fees of this transaction are full price for an identity, all further checks only if there is a referrer
            if (rtxd.NativeFees() < issuingParent.IDFullRegistrationAmount())
            {
                return state.Error("Invalid identity registration - insufficient fee");
            }
            return true;
        }

        // CHECK #5 - ensure that the first referring output goes to the referring identity followed by up
        //            to two identities that come from the original definition transaction of the referring identity. account for all outputs between
        //            identity out and reservation out and ensure that they are correct and pay 20% of the price of an identity
        uint32_t heightOut = 0;
        CTransaction referralTx;

        CIdentity firstReferralIdentity = CIdentity::LookupFirstIdentity(referralID, &heightOut, &idTxIn, &referralTx);

        // referrer must be mined in when this transaction is put into the mem pool
        if (isPBaaS)
        {
            if (heightOut >= height ||
                !firstReferralIdentity.IsValid() ||
                (firstReferralIdentity.parent != parentID && !(firstReferralIdentity.GetID() == parentID && !firstReferralIdentity.parent.IsNull())))
            {
                return state.Error("Invalid identity registration referral");
            }
        }
        else
        {
            if (heightOut >= height || !firstReferralIdentity.IsValid() || firstReferralIdentity.parent != parentID)
            {
                //printf("%s: cannot find first instance of: %s\n", __func__, EncodeDestination(CIdentityID(newName.referral)).c_str());
                return state.Error("Invalid identity registration referral");
            }
        }

        bool isReferral = false;
        std::vector<CTxDestination> checkReferrers = std::vector<CTxDestination>({referralID});
        if (heightOut != 1)
        {
            for (auto &txout : referralTx.vout)
            {
                COptCCParams p;
                if (txout.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
                {
                    if (p.evalCode == EVAL_IDENTITY_PRIMARY)
                    {
                        isReferral = true;
                    }
                    else if (p.evalCode == EVAL_IDENTITY_RESERVATION || p.evalCode == EVAL_IDENTITY_ADVANCEDRESERVATION)
                    {
                        break;
                    }
                    else if (isReferral && ((p.evalCode == EVAL_NONE && issuerID == ASSETCHAINS_CHAINID) ||
                                            (p.evalCode == EVAL_RESERVE_OUTPUT && issuerID != ASSETCHAINS_CHAINID)))
                    {
                        if (p.vKeys.size() == 0 || p.vKeys[0].which() != COptCCParams::ADDRTYPE_ID)
                        {
                            // invalid referral
                            return state.Error("Invalid identity registration referral outputs");
                        }
                        else
                        {
                            checkReferrers.push_back(p.vKeys[0]);
                            if (checkReferrers.size() == issuingParent.IDReferralLevels())
                            {
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (referrers.size() != checkReferrers.size())
        {
            return state.Error("Invalid identity registration - incorrect referral payments");
        }

        // make sure all paid referrers are correct
        for (int i = 0; i < referrers.size(); i++)
        {
            if (referrers[i] != checkReferrers[i])
            {
                return state.Error("Invalid identity registration - incorrect referral payments");
            }
        }

        // CHECK #6 - ensure that the transaction pays the correct mining and referral fees
        if (rtxd.NativeFees() < (issuingParent.IDReferredRegistrationAmount() - (referrers.size() * issuingParent.IDReferralAmount())))
        {
            return state.Error("Invalid identity registration - insufficient fee");
        }

        return true;
    }
}

bool GetNotarizationData(const uint160 &chainID,
                         CChainNotarizationData &notarizationData,
                         std::vector<std::pair<CTransaction, uint256>> *optionalTxOut=nullptr,
                         std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>> *pCounterEvidence=nullptr,
                         std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence>>> *pEvidence=nullptr);

bool PrecheckIdentityReservation(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    CCurrencyDefinition parentCurrency = ConnectedChains.ThisChain();
    CCurrencyDefinition issuingCurrency = parentCurrency;
    uint160 parentID = issuingCurrency.GetID();
    uint160 issuerID = parentID;

    int identityCount = 0;
    int reservationCount = 0;
    CIdentity newIdentity;
    CNameReservation newName;
    CAdvancedNameReservation advNewName;
    std::vector<CTxDestination> referrers;
    bool valid = true;

    uint32_t networkVersion = CConstVerusSolutionVector::GetVersionByHeight(height);
    bool isPBaaS = networkVersion >= CActivationHeight::ACTIVATE_PBAAS; // this is only PBaaS differences, not Verus Vault
    bool advancedIdentity = networkVersion >= CActivationHeight::ACTIVATE_VERUSVAULT;

    std::set<uint160> burnSet;
    burnSet.insert(GetDestinationID(DecodeDestination("i5oFhZ8Bby47KHbnvomVDtrfd71HQFL7vN")));
    burnSet.insert(GetDestinationID(DecodeDestination("iBvu9M4kEzLYQmT2rB57rwQqfWUVUA9qub")));
    burnSet.insert(GetDestinationID(DecodeDestination("i8j7hatfvNXvj38EfnSQZzqYczrKL9LNoo")));

    AssertLockHeld(cs_main);

    // get output and determine which kind of reservation it is
    COptCCParams p;
    if (tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.version >= p.VERSION_V3 &&
        p.vData.size() > 1)
    {
        if (!((p.evalCode == EVAL_IDENTITY_RESERVATION &&
               (newName = CNameReservation(p.vData[0])).IsValid()) ||
              (isPBaaS &&
               p.evalCode == EVAL_IDENTITY_ADVANCEDRESERVATION &&
               (advNewName = CAdvancedNameReservation(p.vData[0])).IsValid())))
        {
            return state.Error("Invalid identity reservation output");
        }
    }
    else
    {
        return state.Error("Improperly formed identity reservation output");
    }

    if (advNewName.IsValid())
    {
        // see if we should replace issuing currency definition
        if (advNewName.parent.IsNull())
        {
            return state.Error("Invalid parent in identity reservation");
        }
        else
        {
            if (advNewName.parent != ASSETCHAINS_CHAINID)
            {
                issuingCurrency = parentCurrency = ConnectedChains.GetCachedCurrency(advNewName.parent);
                issuerID = parentID = advNewName.parent;
                if (parentCurrency.IsGateway() && !parentCurrency.IsNameController() && !parentCurrency.GatewayConverterID().IsNull())
                {
                    issuingCurrency = ConnectedChains.GetCachedCurrency(parentCurrency.GatewayConverterID());
                    if (!issuingCurrency.IsValid() ||
                        !issuingCurrency.IsFractional() ||
                        !issuingCurrency.IsGatewayConverter() ||
                        issuingCurrency.gatewayID != parentCurrency.GetID())
                    {
                        return state.Error("Invalid gateway converter for gateway in identity reservation");
                    }
                    issuerID = issuingCurrency.GetID();

                }
                else if (parentCurrency.IsGatewayConverter())
                {
                    CCurrencyDefinition gatewayCurrency = ConnectedChains.GetCachedCurrency(parentCurrency.gatewayID);
                    if (!gatewayCurrency.IsValid() ||
                        gatewayCurrency.GetID() != ASSETCHAINS_CHAINID ||
                        parentCurrency.systemID != ASSETCHAINS_CHAINID)
                    {
                        return state.Error("Cannot register identities directly on a gateway converter that is not for this blockchain");
                    }
                }
                if (!(issuingCurrency.GetID() == ASSETCHAINS_CHAINID ||
                      issuingCurrency.IsFractional() ||
                      (issuingCurrency.IsToken() &&
                       !issuingCurrency.IsNFTToken())) ||
                    issuingCurrency.NoIDs() ||
                    issuingCurrency.systemID != ASSETCHAINS_CHAINID)
                {
                    return state.Error("Invalid parent in identity reservation");
                }
            }
        }
    }

    // get the primary currency to price in and apply any conversion rates
    uint160 feePricingCurrency = issuingCurrency.FeePricingCurrency();
    int64_t idReferralFee = parentCurrency.IDReferralAmount();
    int64_t idFullRegistrationFee = parentCurrency.IDFullRegistrationAmount();
    int64_t idReferredRegistrationFee = parentCurrency.IDReferredRegistrationAmount();
    CCurrencyValueMap burnAmount;
    CCoinbaseCurrencyState pricingState;

    if (issuingCurrency.NoIDs() || issuingCurrency.IsNFTToken())
    {
        return state.Error("Currency " + ConnectedChains.GetFriendlyCurrencyName(issuingCurrency.GetID()) + " cannot register IDs");
    }

    if (issuingCurrency.IsFractional())
    {
        // calculate the correct conversion rate that should have been observed when making the transaction and enforce it
        // always use default expiry
        int32_t reserveIndex = issuingCurrency.GetCurrenciesMap().find(feePricingCurrency)->second;
        std::vector<std::pair<CTransaction, uint256>> txOut;

        if ((tx.nExpiryHeight - DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA) > height)
        {
            return state.Error("Identity transaction must have at least " + std::to_string(DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA) + " blocks for transaction expiry");
        }

        pricingState = ConnectedChains.GetCurrencyState(issuerID, (tx.nExpiryHeight - DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA) - 1, false);

        if (feePricingCurrency != issuerID)
        {
            idReferralFee = pricingState.ReserveToNative(idReferralFee, reserveIndex);
            idFullRegistrationFee = pricingState.ReserveToNative(idFullRegistrationFee, reserveIndex);
            idReferredRegistrationFee = pricingState.ReserveToNative(idReferredRegistrationFee, reserveIndex);
        }
    }

    for (auto &txout : tx.vout)
    {
        COptCCParams p;
        if (txout.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
        {
            if (p.evalCode == EVAL_IDENTITY_PRIMARY)
            {
                if (identityCount++ || p.vData.size() < 2)
                {
                    valid = false;
                    break;
                }
                newIdentity = CIdentity(p.vData[0]);
                uint160 dummyParent;
                valid = newIdentity.IsValid() &&
                        (((chainActive.LastTip()->nTime < PBAAS_PREMAINNET_ACTIVATION ||
                           burnSet.count(newIdentity.GetID())) &&
                          newIdentity.name == CleanName(newIdentity.name, dummyParent)) ||
                         newIdentity.name == CleanName(newIdentity.name, dummyParent, true)) &&
                        (advNewName.IsValid() ?
                           newIdentity.parent == advNewName.parent :
                           (newIdentity.parent == ASSETCHAINS_CHAINID ||
                            (IsVerusActive() &&
                             newIdentity.parent.IsNull() &&
                             newIdentity.GetID() == ASSETCHAINS_CHAINID)));
                if (!valid)
                {
                    break;
                }
                else if (!isPBaaS && newIdentity.name != CleanName(newIdentity.name, dummyParent, true))
                {
                    LogPrint("identity", "tagged identity (%s : namehex: %s) at height (%u)\n",
                                            EncodeDestination(CIdentityID(newIdentity.GetID())).c_str(),
                                            HexBytes((unsigned char *)(newIdentity.name.c_str()), strlen(newIdentity.name.c_str())).c_str(),
                                            height);
                }
            }
            else if (p.evalCode == EVAL_IDENTITY_RESERVATION)
            {
                if (reservationCount++ || p.vData.size() < 2)
                {
                    valid = false;
                    break;
                }
            }
            else if (p.evalCode == EVAL_IDENTITY_ADVANCEDRESERVATION)
            {
                if (reservationCount++ || p.vData.size() < 2)
                {
                    valid = false;
                    break;
                }
            }
            else if (identityCount && !reservationCount)
            {
                if (isPBaaS)
                {
                    bool testModePreUpdate = PBAAS_TESTMODE && !ConnectedChains.IncludePostLaunchFees(height);
                    if (issuingCurrency.proofProtocol == issuingCurrency.PROOF_CHAINID &&
                        (issuingCurrency.endBlock == 0 ||
                         ((testModePreUpdate && issuingCurrency.endBlock <= height) ||
                          (!testModePreUpdate && height <= issuingCurrency.endBlock))))
                    {
                        // if this is a purchase from centralized/DAO-based currency, ensure we have a valid output
                        // of the correct amount to the issuer ID before any of the referrals
                        if (referrers.size() == 0 && burnAmount.valueMap.size() == 0)
                        {
                            // first, we just record the amount/currency and ensure it is a non-zero burn.
                            // after we've verified referrals, we can confirm the amount as being correct.
                            CTokenOutput to;
                            if (p.evalCode == EVAL_RESERVE_OUTPUT &&
                                p.vData.size() == 2 &&
                                (to = CTokenOutput(p.vData[0])).IsValid() &&
                                p.m == 1 &&
                                p.n == 1 &&
                                p.vKeys.size() == 1 &&
                                p.vData.size() == 2 &&
                                p.vKeys[0].which() == COptCCParams::ADDRTYPE_ID &&
                                GetDestinationID(p.vKeys[0]) == issuerID)
                            {
                                burnAmount += to.reserveValues;
                                if (txout.nValue)
                                {
                                    burnAmount.valueMap[ASSETCHAINS_CHAINID] += txout.nValue;
                                }
                                if (!burnAmount.valueMap.size())
                                {
                                    burnAmount.valueMap[ASSETCHAINS_CHAINID] = 0;
                                }
                                continue;
                            }
                            else
                            {
                                return state.Error("Invalid fee output for identity registration with specified currency");
                            }
                        }
                    }
                    else if (issuingCurrency.IsToken())
                    {
                        // if this is a burn and issue, we need to make sure we have a valid burn transaction
                        // of the correct amount before any of the referrals
                        if (referrers.size() == 0 && burnAmount.valueMap.size() == 0)
                        {
                            // first, we just record the amount/currency and ensure it is a non-zero burn.
                            // after we've verified referrals, we can confirm the amount as being correct.
                            CReserveTransfer rt;
                            if (p.evalCode == EVAL_RESERVE_TRANSFER &&
                                p.vData.size() == 2 &&
                                (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                                rt.IsBurn() &&
                                rt.GetImportCurrency() == issuerID &&
                                !rt.HasNextLeg() &&
                                (rt.FirstCurrency() == issuerID || issuingCurrency.GetCurrenciesMap().count(rt.FirstCurrency())))
                            {
                                burnAmount.valueMap[rt.FirstCurrency()] += rt.FirstValue();
                                continue;
                            }
                            else
                            {
                                return state.Error("Invalid fee burn for identity registration with specified currency");
                            }
                        }
                    }

                    if (!issuingCurrency.IDReferralLevels() ||
                        p.vKeys.size() < 1 ||
                        referrers.size() > (issuingCurrency.IDReferralLevels() - 1) ||
                        (issuerID == ASSETCHAINS_CHAINID && p.evalCode != EVAL_NONE) ||
                        (issuerID != ASSETCHAINS_CHAINID && p.evalCode != EVAL_RESERVE_OUTPUT) ||
                        p.n > 1 ||
                        p.m != 1 ||
                        !txout.scriptPubKey.IsSpendableOutputType() ||
                        (issuerID == ASSETCHAINS_CHAINID && txout.nValue < idReferralFee) ||
                        (issuerID != ASSETCHAINS_CHAINID && txout.ReserveOutValue().valueMap[issuerID] < idReferralFee))
                    {
                        valid = false;
                        break;
                    }
                    referrers.push_back(p.vKeys[0]);
                }
                else
                {
                    if (!issuingCurrency.IDReferralLevels() ||
                        p.vKeys.size() < 1 ||
                        referrers.size() > (issuingCurrency.IDReferralLevels() - 1) ||
                        p.evalCode != EVAL_NONE ||
                        p.n > 1 ||
                        p.m != 1 ||
                        (isPBaaS && !txout.scriptPubKey.IsSpendableOutputType()) ||
                        (issuerID == ASSETCHAINS_CHAINID && txout.nValue < idReferralFee) ||
                        issuerID != ASSETCHAINS_CHAINID && txout.ReserveOutValue().valueMap[issuerID] < idReferralFee)
                    {
                        valid = false;
                        break;
                    }
                    referrers.push_back(p.vKeys[0]);
                }
            }
            else if (identityCount != reservationCount)
            {
                valid = false;
                break;
            }
        }
    }

    // we can close a commitment UTXO without an identity
    if (valid && !identityCount)
    {
        return state.Error("Transaction may not have an identity reservation without a matching identity");
    }
    else if (!valid)
    {
        return state.Error("Improperly formed identity definition transaction");
    }

    // if issuing currency is fractional, verify burn amount based on pricing state
    if (issuingCurrency.IsFractional())
    {
        int64_t feePaid = burnAmount.valueMap.begin()->first == issuerID ?
                    burnAmount.valueMap.begin()->second :
                    pricingState.ReserveToNative(burnAmount.valueMap.begin()->second, pricingState.GetReserveMap()[burnAmount.valueMap.begin()->first]);
        if (feePaid < (referrers.size() ? (idReferredRegistrationFee - (referrers.size() * idReferralFee)) : idFullRegistrationFee))
        {
            return state.Error("Inadequate fee paid for ID registration");
        }
    }

    std::string cleanName;

    if (advancedIdentity)
    {
        cleanName = CleanName(newIdentity.name, parentID, isPBaaS, false);
        if (cleanName.empty())
        {
            return state.Error("Invalid name characters specified in identity registration");
        }
        std::vector<unsigned char> base58Vec;
        if (DecodeBase58Check(cleanName, base58Vec) && base58Vec.size() > 20)
        {
            return state.Error("Invalid name specified - cannot use base58 checksum address as the name for an identity");
        }
    }

    int commitmentHeight = 0;

    LOCK2(cs_main, mempool.cs);

    CCommitmentHash ch;
    int idx = -1;

    CAmount nValueIn = 0;
    {
        LOCK2(cs_main, mempool.cs);

        // from here, we must spend a matching name commitment
        std::map<uint256, CTransaction> txMap;
        uint256 hashBlk;
        for (auto &oneTxIn : tx.vin)
        {
            CTransaction sourceTx;
            auto sourceTxIt = txMap.find(oneTxIn.prevout.hash);
            if (sourceTxIt == txMap.end() && !myGetTransaction(oneTxIn.prevout.hash, sourceTx, hashBlk))
            {
                //LogPrintf("Cannot access input from output %u of transaction %s in transaction %s\n", oneTxIn.prevout.n, oneTxIn.prevout.hash.GetHex().c_str(), tx.GetHash().GetHex().c_str());
                //printf("Cannot access input from output %u of transaction %s in transaction %s\n", oneTxIn.prevout.n, oneTxIn.prevout.hash.GetHex().c_str(), tx.GetHash().GetHex().c_str());
                return state.Error("Cannot access input");
            }
            else if (sourceTxIt != txMap.end())
            {
                sourceTx = sourceTxIt->second;
            }
            else
            {
                txMap[oneTxIn.prevout.hash] = sourceTx;
            }

            if (oneTxIn.prevout.n >= sourceTx.vout.size())
            {
                //extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);
                //UniValue uniTx;
                //TxToJSON(tx, uint256(), uniTx);
                //printf("%s\n", uniTx.write(1, 2).c_str());
                return state.Error("Input index out of range");
            }

            COptCCParams p;
            if (idx == -1 &&
                sourceTx.vout[oneTxIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_IDENTITY_COMMITMENT &&
                p.vData.size())
            {
                idx = oneTxIn.prevout.n;
                ::FromVector(p.vData[0], ch);

                BlockMap::iterator commitmentBlkIt;
                if (hashBlk.IsNull() ||
                    (commitmentBlkIt = mapBlockIndex.find(hashBlk)) == mapBlockIndex.end() ||
                    !chainActive.Contains(commitmentBlkIt->second))
                {
                    return state.Error("Invalid commitment reference");
                }
            }
        }
    }

    if (idx == -1 || ch.hash.IsNull())
    {
        std::string specificMsg = "Invalid identity commitment in tx: " + tx.GetHash().GetHex();
        return state.Error(specificMsg);
    }

    if (advNewName.IsValid())
    {
        if (advNewName.parent != newIdentity.parent ||
            newIdentity.GetID() != newIdentity.GetID(advNewName.name, parentID) ||
            ch.hash != advNewName.GetCommitment().hash)
        {
            return state.Error("Mismatched advanced identity commitment");
        }
        // another check
        std::vector<unsigned char> base58Vec;
        if (DecodeBase58Check(newIdentity.name, base58Vec) && base58Vec.size() > 20)
        {
            return state.Error("Invalid name specified - cannot use base58 checksum address as the name for an identity");
        }
    }
    // are we spending a matching name commitment?
    else if (ch.hash != newName.GetCommitment().hash)
    {
        return state.Error("Mismatched identity commitment");
    }
    return true;
}

bool PrecheckIdentityCommitment(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    AssertLockHeld(cs_main);

    uint32_t networkVersion = CConstVerusSolutionVector::GetVersionByHeight(height);
    bool isPBaaS = networkVersion >= CActivationHeight::ACTIVATE_PBAAS; // this is only PBaaS differences, not Verus Vault
    bool advancedIdentity = networkVersion >= CActivationHeight::ACTIVATE_VERUSVAULT;

    COptCCParams p;

    static uint160 nativeCurrencyOffer = COnChainOffer::OnChainCurrencyOfferKey(ASSETCHAINS_CHAINID);
    static uint160 offerForNativeCurrency = COnChainOffer::OnChainOfferForCurrencyKey(ASSETCHAINS_CHAINID);

    if (advancedIdentity && !isPBaaS)
    {
        if (tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1 &&
            p.vData[0].size() == 32)
        {
            COptCCParams master(p.vData.back());
            if (master.IsValid())
            {
                int numIndexKeys = 0;
                bool hasNativeOffer = false, hasOfferForNative = false;
                for (auto &oneKey : master.vKeys)
                {
                    if (oneKey.which() == COptCCParams::ADDRTYPE_PKH || oneKey.which() == COptCCParams::ADDRTYPE_PK)
                    {
                        numIndexKeys++;
                        uint160 destID = GetDestinationID(oneKey);
                        if (destID == nativeCurrencyOffer)
                        {
                            hasNativeOffer = true;
                        }
                        else if (destID == offerForNativeCurrency)
                        {
                            hasOfferForNative = true;
                        }
                    }
                }
                if (!(hasNativeOffer && hasOfferForNative) && (numIndexKeys <= 1 || (numIndexKeys > 1 && tx.vout[outNum].nValue >= COnChainOffer::MIN_LISTING_DEPOSIT)))
                {
                    return true;
                }
            }
            LogPrint("onchaincommitment", "Not enough fee to close offer or invalid offer");
            return state.Error("Not enough fee to close commitment or invalid commitment");
        }
        else
        {
            return state.Error("Invalid commitment");
        }
    }
    else if (isPBaaS)
    {
        if (tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1 &&
            p.vData[0].size() >= 20)
        {
            CCommitmentHash ch(p.vData[0]);
            std::vector<unsigned char> vch;
            vch.assign(p.vData[0].begin(), p.vData[0].begin() + 20);
            uint160 checkVal(vch);

            if (p.vData[0].size() == 32 && checkVal != CCommitmentHash::AdvancedCommitmentHashKey())
            {
                COptCCParams master(p.vData.back());
                if (master.IsValid())
                {
                    int numIndexKeys = 0;
                    bool hasNativeOffer = false, hasOfferForNative = false;
                    for (auto &oneKey : master.vKeys)
                    {
                        if (oneKey.which() == COptCCParams::ADDRTYPE_PKH || oneKey.which() == COptCCParams::ADDRTYPE_PK)
                        {
                            numIndexKeys++;
                            uint160 destID = GetDestinationID(oneKey);
                            if (destID == nativeCurrencyOffer)
                            {
                                hasNativeOffer = true;
                            }
                            else if (destID == offerForNativeCurrency)
                            {
                                hasOfferForNative = true;
                            }
                        }
                    }
                    if (!(hasNativeOffer && hasOfferForNative) && (numIndexKeys <= 1 || (numIndexKeys > 1 && tx.vout[outNum].nValue >= DEFAULT_TRANSACTION_FEE)))
                    {
                        return true;
                    }
                }
                LogPrint("onchaincommitment", "Not enough fee to close commitment or invalid commitment");
                return false;
            }
            else if (p.vData[0].size() > 32)
            {
                if ((checkVal == CCommitmentHash::AdvancedCommitmentHashKey()) &&
                    ch.IsValid() &&
                    ch.reserveValues.valueMap.size() &&
                    !ch.reserveValues.valueMap.count(ASSETCHAINS_CHAINID))
                {
                    // for a later version:
                    // for more general use, instead of a fixed subclass of token, we should abstract and contain objects in this output
                    COptCCParams master(p.vData.back());
                    if (master.IsValid())
                    {
                        int numIndexKeys = 0;
                        bool hasNativeOffer = false, hasOfferForNative = false;
                        for (auto &oneKey : master.vKeys)
                        {
                            if (oneKey.which() == COptCCParams::ADDRTYPE_PKH || oneKey.which() == COptCCParams::ADDRTYPE_PK)
                            {
                                numIndexKeys++;
                                uint160 destID = GetDestinationID(oneKey);

                                if (destID == nativeCurrencyOffer)
                                {
                                    hasNativeOffer = true;
                                }
                                else if (destID == offerForNativeCurrency)
                                {
                                    hasOfferForNative = true;
                                }
                            }
                        }
                        if (!(hasNativeOffer && hasOfferForNative) && (numIndexKeys <= 1 || (numIndexKeys > 1 && tx.vout[outNum].nValue >= DEFAULT_TRANSACTION_FEE)))
                        {
                            return true;
                        }
                    }
                    LogPrint("onchaincommitment", "Invalid advanced commitment");
                    return false;
                }
                else
                {
                    LogPrint("onchaincommitment", "Oversized, invalid on chain commitment");
                    return false;
                }
            }
            else
            {
                LogPrint("onchaincommitment", "Undersized, invalid on chain commitment");
                return false;
            }
        }
        else
        {
            LogPrint("onchaincommitment", "Invalid on chain commitment");
            return false;
        }
    }
    return true;
}

// with the thorough check for an identity reservation, the only thing we need to check is that either 1) this transaction includes an identity reservation output or 2)
// this transaction spends a prior identity transaction that does not create a clearly invalid mutation between the two
bool PrecheckIdentityPrimary(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    AssertLockHeld(cs_main);

    bool validReservation = false;
    bool validIdentity = false;
    bool validImport = false;
    bool idMayBeImported = true;
    bool validSourceSysImport = false;
    bool validCrossChainImport = false;

    CNameReservation nameRes;
    CAdvancedNameReservation advNameRes;
    CIdentity identity;
    CCrossChainImport cci;

    COptCCParams p, identityP;

    uint32_t networkVersion = CConstVerusSolutionVector::GetVersionByHeight(height);
    bool isPBaaS = networkVersion >= CActivationHeight::ACTIVATE_PBAAS; // this is only PBaaS differences, not Verus Vault
    bool advancedIdentity = networkVersion >= CActivationHeight::ACTIVATE_VERUSVAULT;
    bool isCoinbase = tx.IsCoinBase();
    bool isInSync = chainActive.Height() >= (height - 1);

    for (int i = 0; i < tx.vout.size(); i++)
    {
        CIdentity checkIdentity;
        auto &output = tx.vout[i];
        bool isSmartOutput = output.scriptPubKey.IsPayToCryptoCondition(p);
        if (isSmartOutput &&
            (!advancedIdentity || p.AsVector().size() < CScript::MAX_SCRIPT_ELEMENT_SIZE) &&
            p.IsValid(isPBaaS, height) &&
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            switch (p.evalCode)
            {
                case EVAL_IDENTITY_RESERVATION:
                {
                    nameRes = CNameReservation(p.vData[0]);
                    if (!nameRes.IsValid())
                    {
                        return state.Error("Invalid identity reservation");
                    }
                    // twice through makes it invalid
                    if (!(isPBaaS && isCoinbase && height == 1) && validReservation)
                    {
                        return state.Error("Invalid multiple identity reservations on one transaction");
                    }
                    validReservation = true;
                }
                break;

                case EVAL_IDENTITY_ADVANCEDRESERVATION:
                {
                    advNameRes = CAdvancedNameReservation(p.vData[0]);
                    if (!advNameRes.IsValid())
                    {
                        return state.Error("Invalid identity reservation");
                    }
                    // twice through makes it invalid
                    if (!(isPBaaS && isCoinbase && height == 1) && validReservation)
                    {
                        return state.Error("Invalid multiple identity reservations on one transaction");
                    }
                    validReservation = true;
                }
                break;

                case EVAL_IDENTITY_PRIMARY:
                {
                    checkIdentity = CIdentity(p.vData[0]);
                    if (!checkIdentity.IsValid())
                    {
                        return state.Error("Invalid identity on transaction output " + std::to_string(i));
                    }

                    if (isPBaaS && isInSync)
                    {
                        std::set<uint160> primaryDests;
                        for (auto &oneDest : checkIdentity.primaryAddresses)
                        {
                            if (oneDest.which() == COptCCParams::ADDRTYPE_PK ||
                                oneDest.which() == COptCCParams::ADDRTYPE_PKH)
                            {
                                primaryDests.insert(GetDestinationID(oneDest));
                            }
                        }
                        if (primaryDests.size() != checkIdentity.primaryAddresses.size())
                        {
                            if (!PBAAS_TESTMODE || chainActive[height - 1]->nTime >= PBAAS_TESTFORK_TIME)
                            {
                                return state.Error("Duplicate or invalid primary address in identity " + ConnectedChains.GetFriendlyIdentityName(checkIdentity));
                            }
                        }
                    }

                    // twice through used to make it invalid
                    if (!advancedIdentity && validIdentity)
                    {
                        return state.Error("Invalid multiple identity definitions on one transaction");
                    }

                    if (i == outNum)
                    {
                        identityP = p;
                        identity = checkIdentity;
                        CDataStream ss(SER_DISK, PROTOCOL_VERSION);
                        if (GetSerializeSize(ss, CReserveTransfer(CReserveTransfer::IDENTITY_EXPORT + CReserveTransfer::VALID + CReserveTransfer::CROSS_SYSTEM,
                                             CCurrencyValueMap(std::vector<uint160>({ASSETCHAINS_CHAINID}), std::vector<int64_t>({1})),
                                             ASSETCHAINS_CHAINID,
                                             0,
                                             checkIdentity.GetID(),
                                             CTransferDestination(CTransferDestination::DEST_FULLID,
                                             ::AsVector(checkIdentity),
                                             checkIdentity.GetID()))) > (CScript::MAX_SCRIPT_ELEMENT_SIZE - 128))
                        {
                            return state.Error("Serialized identity is too large");
                        }
                    }
                    validIdentity = true;
                }
                break;

                case EVAL_CROSSCHAIN_IMPORT:
                {
                    cci = CCrossChainImport(p.vData[0]);
                    if (!cci.IsValid())
                    {
                        return state.Error("Invalid import on transaction output " + std::to_string(i));
                    }

                    // if identity comes before an import and we're not on block 1, the import can't be source of validation
                    if (height != 1 &&
                        (identity.IsValid() ||
                         cci.IsDefinitionImport()))
                    {
                        idMayBeImported = false;
                    }

                    // twice through makes it invalid
                    if (!(isPBaaS && (height == 1 || cci.IsDefinitionImport())) && (validSourceSysImport || (validImport && !cci.IsSourceSystemImport())))
                    {
                        return state.Error("Invalid multiple cross-chain imports on one transaction");
                    }
                    else if (cci.IsSourceSystemImport())
                    {
                        validSourceSysImport = true;
                    }
                    else if (cci.sourceSystemID != ASSETCHAINS_CHAINID)
                    {
                        validCrossChainImport = true;
                    }

                    validImport = true;
                }
                break;
            }
        }
        else if (advancedIdentity && isSmartOutput && !p.IsValid(isPBaaS, height))
        {
            return state.Error("Invalid smart transaction output");
        }
    }

    if (!validIdentity && identity.IsValid())
    {
        return state.Error("Invalid identity definition");
    }

    CIdentityID idID = identity.GetID();
    p = identityP;

    if (advancedIdentity)
    {
        COptCCParams master;
        if (identity.nVersion < identity.VERSION_VAULT)
        {
            return state.Error("Inadequate identity version for post-Verus Vault activation");
        }

        if (isPBaaS && identity.nVersion < identity.VERSION_PBAAS)
        {
            return state.Error("Inadequate identity version for post-PBaaS activation");
        }

        if (p.vData.size() < 3 ||
            !(master = COptCCParams(p.vData.back())).IsValid() ||
            master.evalCode != 0 ||
            master.m != 1)
        {
            return state.Error("Invalid identity output destinations and/or configuration");
        }

        for (auto &oneKey : master.vKeys)
        {
            // if we have an index present, this is likely an offer, and we need to have a deposit as well
            if (oneKey.which() == COptCCParams::ADDRTYPE_PKH)
            {
                if (tx.vout[outNum].nValue < DEFAULT_TRANSACTION_FEE)
                {
                    return state.Error("Invalid identity output destinations and/or configuration");
                }
                else
                {
                    break;
                }
            }
        }

        // we need to have at least 2 of 3 authority spend conditions mandatory at a top level for any primary ID output
        bool revocation = false, recovery = false;
        bool primaryValid = false, revocationValid = false, recoveryValid = false;
        bool isRevoked = identity.IsRevoked();
        for (auto dest : p.vKeys)
        {
            if (dest.which() == COptCCParams::ADDRTYPE_ID && idID == GetDestinationID(dest))
            {
                primaryValid = true;
            }
        }
        if (!isRevoked && !primaryValid)
        {
            std::string errorOut = "Primary identity output condition of \"" + identity.name + "\" is neither revoked nor spendable by self";
            return state.Error(errorOut.c_str());
        }
        for (int i = 1; i < p.vData.size() - 1; i++)
        {
            COptCCParams oneP(p.vData[i]);
            // must be valid and composable
            if (!oneP.IsValid() || oneP.version < oneP.VERSION_V3)
            {
                std::string errorOut = "Invalid output condition from identity: \"" + identity.name + "\"";
                return state.Error(errorOut.c_str());
            }

            if (oneP.evalCode == EVAL_IDENTITY_REVOKE)
            {
                // no dups
                if (!revocation)
                {
                    revocation = true;
                    if (oneP.vKeys.size() == 1 &&
                        oneP.m == 1 &&
                        oneP.n == 1 &&
                        oneP.vKeys[0].which() == COptCCParams::ADDRTYPE_ID &&
                        identity.revocationAuthority == GetDestinationID(oneP.vKeys[0]))
                    {
                        revocationValid = true;
                    }
                }
                else
                {
                    revocationValid = false;
                }
            }
            else if (oneP.evalCode == EVAL_IDENTITY_RECOVER)
            {
                if (!recovery)
                {
                    recovery = true;
                    // tokenized control must allow one output, in this case the recovery,
                    // to be fulfilled. that means it must require only one signature to
                    // fulfill signature requirements. if we only have one signature, and
                    // it is from the publicly available key, ValidateIdentityRecover will
                    // consider the signature unfulfilled
                    if (isPBaaS && identity.HasTokenizedControl())
                    {
                        if (!(oneP.m == 1 && oneP.n >= oneP.m))
                        {
                            std::string errorOut = "Invalid spend condition for tokenized control in: \"" + identity.name + "\"";
                            return state.Error(errorOut.c_str());
                        }

                        // now, make sure that we have both the key for recoveryAuthority
                        // and the key for tokenized control, which anyone can sign, and which is further
                        // validated in the ValidateIdentityRecover
                        bool haveDefaultOutput = false;

                        CCcontract_info CC;
                        CCcontract_info *cp;

                        // make a currency definition
                        cp = CCinit(&CC, EVAL_IDENTITY_RECOVER);
                        CTxDestination recoverDest(CPubKey(ParseHex(CC.CChexstr)).GetID());

                        for (auto &oneKey : oneP.vKeys)
                        {
                            if (oneKey.which() == COptCCParams::ADDRTYPE_ID && identity.recoveryAuthority == GetDestinationID(oneKey))
                            {
                                recoveryValid = true;
                            }
                            else if (oneKey.which() == COptCCParams::ADDRTYPE_PKH &&
                                     GetDestinationID(recoverDest) == GetDestinationID(oneKey))
                            {
                                haveDefaultOutput = true;
                            }
                        }
                        if (!(recoveryValid && haveDefaultOutput))
                        {
                            std::string errorOut = "Invalid recovery spend condition for tokenized control in: \"" + identity.name + "\"";
                            return state.Error(errorOut.c_str());
                        }
                    }
                    else if (oneP.vKeys.size() == 1 &&
                             oneP.m == 1 &&
                             oneP.n == 1 &&
                             oneP.vKeys[0].which() == COptCCParams::ADDRTYPE_ID &&
                             identity.recoveryAuthority == GetDestinationID(oneP.vKeys[0]))
                    {
                        recoveryValid = true;
                    }
                }
                else
                {
                    recoveryValid = false;
                }
            }
        }

        // we need separate spend conditions for both revoke and recover in all cases
        if ((!isRevoked && !(revocationValid && recoveryValid)) || (isRevoked && !recoveryValid))
        {
            std::string errorOut = "Primary identity output \"" + identity.name + "\" must be spendable by revocation and recovery authorities";
            return state.Error(errorOut.c_str());
        }
    }
    else
    {
        if (identity.nVersion >= identity.VERSION_VAULT)
        {
            return state.Error("Invalid identity version before PBaaS activation");
        }

        // ensure that we have all required spend conditions for primary, revocation, and recovery
        // if there are additional spend conditions, their addition or removal is checked for validity
        // depending on which of the mandatory spend conditions is authorized.
        COptCCParams master;
        if (p.vData.size() < 4 || !(master = COptCCParams(p.vData.back())).IsValid() || master.evalCode != 0 || master.m != 1)
        {
            // we need to have 3 authority spend conditions mandatory at a top level for any primary ID output
            bool primary = false, revocation = false, recovery = false;

            for (auto dest : p.vKeys)
            {
                if (dest.which() == COptCCParams::ADDRTYPE_ID && (idID == GetDestinationID(dest)))
                {
                    primary = true;
                }
            }
            if (!primary)
            {
                std::string errorOut = "Primary identity output condition of \"" + identity.name + "\" is not spendable by self";
                return state.Error(errorOut.c_str());
            }
            for (int i = 1; i < p.vData.size() - 1; i++)
            {
                COptCCParams oneP(p.vData[i]);
                // must be valid and composable
                if (!oneP.IsValid() || oneP.version < oneP.VERSION_V3)
                {
                    std::string errorOut = "Invalid output condition from identity: \"" + identity.name + "\"";
                    return state.Error(errorOut.c_str());
                }

                if (oneP.evalCode == EVAL_IDENTITY_REVOKE || oneP.evalCode == EVAL_IDENTITY_RECOVER)
                {
                    for (auto dest : oneP.vKeys)
                    {
                        if (dest.which() == COptCCParams::ADDRTYPE_ID)
                        {
                            if (oneP.evalCode == EVAL_IDENTITY_REVOKE && (identity.revocationAuthority == GetDestinationID(dest)))
                            {
                                revocation = true;
                            }
                            else if (oneP.evalCode == EVAL_IDENTITY_RECOVER && (identity.recoveryAuthority == GetDestinationID(dest)))
                            {
                                recovery = true;
                            }
                        }
                    }
                }
            }

            // we need separate spend conditions for both revoke and recover in all cases
            if (!revocation || !recovery)
            {
                std::string errorOut = "Primary identity output \"" + identity.name + "\" must be spendable by revocation and recovery authorities";
                return state.Error(errorOut.c_str());
            }
        }
    }

    extern uint160 VERUS_CHAINID;
    extern std::string VERUS_CHAINNAME;

    // compare commitment without regard to case or other textual transformations that are irrelevant to matching
    uint160 parentID = advNameRes.IsValid() ? advNameRes.parent : ConnectedChains.ThisChain().GetID();
    if (isPBaaS && identity.GetID() == ASSETCHAINS_CHAINID && IsVerusActive())
    {
        parentID.SetNull();
    }
    if (validReservation &&
        ((advNameRes.IsValid() && identity.GetID(advNameRes.name, parentID) == identity.GetID()) ||
         (identity.GetID(nameRes.name, parentID) == identity.GetID())))
    {
        return true;
    }

    // if we made it to here without an early, positive exit, we must determine that we are spending a matching identity, and if so, all is fine so far
    CTransaction inTx;
    uint256 blkHash;
    LOCK(mempool.cs);
    for (auto &input : tx.vin)
    {
        // first time through may be null
        if ((!input.prevout.hash.IsNull() && input.prevout.hash == inTx.GetHash()) || myGetTransaction(input.prevout.hash, inTx, blkHash))
        {
            if (input.prevout.n >= inTx.vout.size())
            {
                return state.Error("Invalid, malformed transaction");
            }
            if (inTx.vout[input.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_IDENTITY_PRIMARY &&
                p.vData.size() > 1 &&
                (identity = CIdentity(p.vData[0])).IsValid() &&
                idID == identity.GetID())
            {
                return true;
            }
        }
    }

    if (isPBaaS)
    {
        if (height == 1)
        {
            // for block one IDs, ensure they are valid as per the launch parameters
            if (tx.IsCoinBase())
            {
                if (ASSETCHAINS_CHAINID == GetDestinationID(DecodeDestination("iExBJfZYK7KREDpuhj6PzZBzqMAKaFg7d2")))
                {
                    if (tx.GetHash() == uint256S("9986facba28a68bc7d06095b536873f2cd31b0a45b574fa73a994b7a89cba1da"))
                    {
                        return true;
                    }
                    else
                    {
                        return state.Error("Invalid block one coinbase");
                    }
                }
                else
                {
                    // we only check coinbase on the first identity
                    int i;
                    for (i = 0; i < tx.vout.size(); i++)
                    {
                        if (CIdentity(tx.vout[i].scriptPubKey).IsValid())
                        {
                            break;
                        }
                    }
                    if (i == outNum)
                    {
                        if (ConnectedChains.FirstNotaryChain().IsValid() &&
                            IsValidBlockOneCoinbase(tx.vout, ConnectedChains.FirstNotaryChain(), ConnectedChains.ThisChain(), state))
                        {
                            return true;
                        }
                        else
                        {
                            return state.Error("Invalid block 1 coinbase");
                        }
                    }
                    else
                    {
                        return true;
                    }
                }
            }
            else
            {
                return state.Error("Invalid ID minting in block 1");
            }
        }
        else if (idMayBeImported && validCrossChainImport)
        {
            // ensure that we are importing IDs from a source system that can send us these IDs
            return true;
        }
    }

    return state.Error("Invalid primary identity - does not include identity reservation or spend matching identity");
}

CIdentity GetOldIdentity(const CTransaction &spendingTx, uint32_t nIn, CTransaction *pSourceTx, uint32_t *pHeight)
{
    CTransaction _sourceTx;
    CTransaction &sourceTx(pSourceTx ? *pSourceTx : _sourceTx);

    // if not fulfilled, ensure that no part of the primary identity is modified
    CIdentity oldIdentity;
    uint256 blkHash;
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        if (pHeight)
        {
            auto bIt = mapBlockIndex.find(blkHash);
            if (bIt == mapBlockIndex.end() || !bIt->second)
            {
                *pHeight = chainActive.Height();
            }
            else
            {
                *pHeight = bIt->second->GetHeight();
            }
        }
        COptCCParams p;
        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_IDENTITY_PRIMARY &&
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldIdentity = CIdentity(p.vData[0]);
        }
    }
    return oldIdentity;
}

bool ValidateIdentitySpendMutation(Eval* eval, const CTransaction &spendingTx, const CIdentity &oldIdentity, const CIdentity &newIdentity)
{
    uint160 idID = oldIdentity.GetID();
    CCurrencyDefinition matchingCurDef;
    for (auto &oneOut : spendingTx.vout)
    {
        if ((matchingCurDef = CCurrencyDefinition(oneOut.scriptPubKey)).IsValid() &&
            matchingCurDef.GetID() == idID)
        {
            break;
        }
    }

    bool isCurrencyDef = matchingCurDef.IsValid() && matchingCurDef.GetID() == idID;

    if ((oldIdentity.HasActiveCurrency() && !newIdentity.HasActiveCurrency()) ||
        (oldIdentity.HasTokenizedControl() && !newIdentity.HasTokenizedControl()) ||
        (!isCurrencyDef &&
            (oldIdentity.HasActiveCurrency() != oldIdentity.HasActiveCurrency() ||
            oldIdentity.HasTokenizedControl() != newIdentity.HasTokenizedControl())) ||
        (isCurrencyDef && !matchingCurDef.IsNFTToken() && newIdentity.HasTokenizedControl()))
    {
        return false;
    }
    return true;
}

bool ValidateIdentityPrimary(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    CTransaction sourceTx;
    CIdentity oldIdentity = GetOldIdentity(spendingTx, nIn, &sourceTx);

    if (!oldIdentity.IsValid())
    {
        return eval->Error("Spending invalid identity");
    }

    if (!chainActive.LastTip())
    {
        return eval->Error("unable to find chain tip");
    }
    uint32_t height = chainActive.LastTip()->GetHeight() + 1;
    bool advancedIdentity = CVerusSolutionVector::GetVersionByHeight(height) >= CActivationHeight::ACTIVATE_VERUSVAULT;

    int idIndex;
    uint160 idID = oldIdentity.GetID();
    CIdentity newIdentity(spendingTx, &idIndex, advancedIdentity ? idID : uint160());
    if (!newIdentity.IsValid())
    {
        return eval->Error("Attempting to define invalid identity");
    }

    if (oldIdentity.IsInvalidMutation(newIdentity, height, spendingTx.nExpiryHeight))
    {
        LogPrintf("Invalid identity modification %s\n", spendingTx.GetHash().GetHex().c_str());
        return eval->Error("Invalid identity modification");
    }

    if (!ValidateIdentitySpendMutation(eval, spendingTx, oldIdentity, newIdentity))
    {
        return eval->Error("Invalid ID currency state modification");
    }

    // if not fullfilled and not revoked, we are responsible for rejecting any modification of
    // data under primary authority control
    if (!fulfilled && !oldIdentity.IsRevoked())
    {
        if (oldIdentity.IsPrimaryMutation(newIdentity, height))
        {
            return eval->Error("Unauthorized identity modification");
        }
        // make sure that the primary spend conditions are not modified
        COptCCParams p, q;
        sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p);
        spendingTx.vout[idIndex].scriptPubKey.IsPayToCryptoCondition(q);

        if (q.evalCode != EVAL_IDENTITY_PRIMARY ||
            p.version > q.version ||
            p.m != q.m ||
            p.n != q.n ||
            p.vKeys != q.vKeys)
        {
            return eval->Error("Unauthorized modification of identity primary spend condition");
        }
    }

    if (!fulfilled &&
        !oldIdentity.HasActiveCurrency() &&
        newIdentity.HasActiveCurrency())
    {
        return eval->Error("Unauthorized currency or token definition");
    }
    return true;
}

bool ValidateIdentityRevoke(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    CTransaction sourceTx;
    CIdentity oldIdentity = GetOldIdentity(spendingTx, nIn, &sourceTx);

    if (!oldIdentity.IsValid())
    {
        return eval->Error("Invalid source identity");
    }

    if (!chainActive.LastTip())
    {
        return eval->Error("unable to find chain tip");
    }
    uint32_t height = chainActive.LastTip()->GetHeight() + 1;

    bool advancedIdentity = CVerusSolutionVector::GetVersionByHeight(height) >= CActivationHeight::ACTIVATE_VERUSVAULT;

    int idIndex;
    CIdentity newIdentity(spendingTx, &idIndex, advancedIdentity ? oldIdentity.GetID() : uint160());
    if (!newIdentity.IsValid())
    {
        return eval->Error("Attempting to replace identity with one that is invalid");
    }

    if (oldIdentity.IsInvalidMutation(newIdentity, height, spendingTx.nExpiryHeight))
    {
        return eval->Error("Invalid identity modification");
    }

    if (oldIdentity.IsRevocation(newIdentity) && oldIdentity.recoveryAuthority == oldIdentity.GetID() && !oldIdentity.HasTokenizedControl())
    {
        return eval->Error("Cannot revoke an identity with self as the recovery authority");
    }

    if (!ValidateIdentitySpendMutation(eval, spendingTx, oldIdentity, newIdentity))
    {
        return eval->Error("Invalid ID currency state modification");
    }

    // make sure that spend conditions are valid and revocation spend conditions are not modified
    COptCCParams p, q;

    spendingTx.vout[idIndex].scriptPubKey.IsPayToCryptoCondition(q);

    if (!q.IsValid() || q.evalCode != EVAL_IDENTITY_PRIMARY)
    {
        return eval->Error("Invalid identity output in spending transaction");
    }

    bool advanced = newIdentity.nVersion >= newIdentity.VERSION_VAULT;

    uint160 identityID = oldIdentity.GetID();

    if (!fulfilled)
    {
        if (!oldIdentity.HasActiveCurrency() &&
            newIdentity.HasActiveCurrency())
        {
            return eval->Error("Missing revocation signature. All authorities must sign for currency or token definition");
        }

        if (oldIdentity.HasTokenizedControl())
        {
            if (spendingTx.vout.size() > (idIndex + 1) && spendingTx.vin.size() > (nIn + 1))
            {
                CAmount controlCurrencyVal = spendingTx.vout[idIndex + 1].ReserveOutValue().valueMap[identityID];
                CTransaction tokenOutTx;
                uint256 hashBlock;
                COptCCParams tokenP;
                if (controlCurrencyVal > 0 &&
                    myGetTransaction(spendingTx.vin[nIn + 1].prevout.hash, tokenOutTx, hashBlock) &&
                    tokenOutTx.vout[spendingTx.vin[nIn + 1].prevout.n].ReserveOutValue().valueMap[identityID] == controlCurrencyVal &&
                    tokenOutTx.vout[spendingTx.vin[nIn + 1].prevout.n].scriptPubKey == spendingTx.vout[idIndex + 1].scriptPubKey)
                {
                    fulfilled = true;
                }
            }
        }
    }

    if (advanced)
    {
        // if not fulfilled, neither revocation data nor its spend condition may be modified
        if (!fulfilled && !oldIdentity.IsRevoked())
        {
            if (oldIdentity.IsRevocation(newIdentity) || oldIdentity.IsRevocationMutation(newIdentity, height))
            {
                return eval->Error("Unauthorized modification of revocation information");
            }
        }
        // aside from that, validity of spend conditions is done in advanced precheck
        return true;
    }

    COptCCParams oldRevokeP, newRevokeP;

    for (int i = 1; i < q.vData.size() - 1; i++)
    {
        COptCCParams oneP(q.vData[i]);
        // must be valid and composable
        if (!oneP.IsValid() || oneP.version < oneP.VERSION_V3)
        {
            std::string errorOut = "Invalid output condition from identity: \"" + newIdentity.name + "\"";
            return eval->Error(errorOut.c_str());
        }

        if (oneP.evalCode == EVAL_IDENTITY_REVOKE)
        {
            if (newRevokeP.IsValid())
            {
                std::string errorOut = "Invalid output condition from identity: \"" + newIdentity.name + "\", more than one revocation condition";
                return eval->Error(errorOut.c_str());
            }
            newRevokeP = oneP;
        }
    }

    if (!newRevokeP.IsValid())
    {
        std::string errorOut = "Invalid revocation output condition for identity: \"" + newIdentity.name + "\"";
        return eval->Error(errorOut.c_str());
    }

    // if not fulfilled, neither revocation data nor its spend condition may be modified
    if (!fulfilled)
    {
        sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p);

        for (int i = 1; i < p.vData.size() - 1; i++)
        {
            COptCCParams oneP(p.vData[i]);
            if (oneP.evalCode == EVAL_IDENTITY_REVOKE)
            {
                oldRevokeP = oneP;
            }
        }

        if (!oldRevokeP.IsValid() ||
            !newRevokeP.IsValid() ||
            oldRevokeP.version > newRevokeP.version ||
            oldRevokeP.m != newRevokeP.m ||
            oldRevokeP.n != newRevokeP.n ||
            oldRevokeP.vKeys != newRevokeP.vKeys)
        {
            return eval->Error("Unauthorized modification of identity revocation spend condition");
        }
    }

    return true;
}

bool ValidateIdentityRecover(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    CTransaction sourceTx;
    CIdentity oldIdentity = GetOldIdentity(spendingTx, nIn, &sourceTx);
    if (!oldIdentity.IsValid())
    {
        return eval->Error("Invalid source identity");
    }

    if (!chainActive.LastTip())
    {
        return eval->Error("unable to find chain tip");
    }
    uint32_t height = chainActive.LastTip()->GetHeight() + 1;

    bool advancedIdentity = CVerusSolutionVector::GetVersionByHeight(height) >= CActivationHeight::ACTIVATE_VERUSVAULT;

    int idIndex;
    CIdentity newIdentity(spendingTx, &idIndex, advancedIdentity ? oldIdentity.GetID() : uint160());
    if (!newIdentity.IsValid())
    {
        return eval->Error("Attempting to replace identity with one that is invalid");
    }

    if (oldIdentity.IsInvalidMutation(newIdentity, height, spendingTx.nExpiryHeight))
    {
        return eval->Error("Invalid identity modification");
    }

    if (!ValidateIdentitySpendMutation(eval, spendingTx, oldIdentity, newIdentity))
    {
        return eval->Error("Invalid ID currency state modification");
    }

    // make sure that spend conditions are valid and revocation spend conditions are not modified
    COptCCParams p, q;

    spendingTx.vout[idIndex].scriptPubKey.IsPayToCryptoCondition(q);

    if (q.evalCode != EVAL_IDENTITY_PRIMARY)
    {
        return eval->Error("Invalid identity output in spending transaction");
    }

    bool advanced = newIdentity.nVersion >= newIdentity.VERSION_VAULT;

    uint160 identityID = oldIdentity.GetID();

    // before we start conditioning decisions on fulfilled status,
    // check to see if it has been fulfilled by using a control token/NFT
    if (!fulfilled && !oldIdentity.HasActiveCurrency() && newIdentity.HasActiveCurrency())
    {
        return eval->Error("Missing recovery signature. All authorities must sign for currency or token definition");
    }

    if (oldIdentity.HasTokenizedControl())
    {
        bool fulfilledWithToken = false;
        if (spendingTx.vout.size() > (idIndex + 1) && spendingTx.vin.size() > (nIn + 1))
        {
            CAmount controlCurrencyVal = spendingTx.vout[idIndex + 1].ReserveOutValue().valueMap[identityID];
            CTransaction tokenOutTx;
            uint256 hashBlock;
            COptCCParams tokenP;
            if (controlCurrencyVal == 1 &&
                myGetTransaction(spendingTx.vin[nIn + 1].prevout.hash, tokenOutTx, hashBlock) &&
                tokenOutTx.vout.size() > spendingTx.vin[nIn + 1].prevout.n &&
                tokenOutTx.vout[spendingTx.vin[nIn + 1].prevout.n].ReserveOutValue().valueMap[identityID] == controlCurrencyVal &&
                tokenOutTx.vout[spendingTx.vin[nIn + 1].prevout.n].scriptPubKey == spendingTx.vout[idIndex + 1].scriptPubKey)
            {
                fulfilledWithToken = true;
                fulfilled = true;
            }
        }

        // if we are not fulfilled by the token, we should reverse fulfilled state if we are not completely fulfilled by the
        // recovery authority
        if (!fulfilledWithToken)
        {
            // get transaction hash and verify signature
            auto consensusBranchID = CurrentEpochBranchId(height, Params().GetConsensus());
            CSmartTransactionSignatures smartSigs;
            bool signedByDefaultKey = false;
            std::vector<unsigned char> ffVec = GetFulfillmentVector(spendingTx.vin[nIn].scriptSig);
            smartSigs = CSmartTransactionSignatures(std::vector<unsigned char>(ffVec.begin(), ffVec.end()));

            CIdentity recoveryIdentity = oldIdentity.recoveryAuthority == identityID ? oldIdentity : CIdentity::LookupIdentity(oldIdentity.recoveryAuthority, height);
            CIdentity revocationIdentity = oldIdentity.revocationAuthority == identityID ? oldIdentity : CIdentity::LookupIdentity(oldIdentity.recoveryAuthority, height);

            std::set<CTxDestination> recoverySigDests = recoveryIdentity.IdentityPrimaryAddressKeySet();
            std::set<CTxDestination> revocationSigDests = revocationIdentity.IdentityPrimaryAddressKeySet();
            std::set<CTxDestination> primarySigDests = oldIdentity.IdentityPrimaryAddressKeySet();

            int numIDSigsValid = 0;
            int recSigsValid = 0;
            int revSigsValid = 0;
            int priSigsValid = 0;

            int sigCount = 0;
            if (smartSigs.IsValid())
            {
                for (auto &keySig : smartSigs.signatures)
                {
                    CPubKey thisKey;
                    thisKey.Set(keySig.second.pubKeyData.begin(), keySig.second.pubKeyData.end());
                    if (recoveryIdentity.IsValid() && recoverySigDests.count(thisKey.GetID()))
                    {
                        recSigsValid++;
                    }
                    if (revocationIdentity.IsValid() && revocationSigDests.count(thisKey.GetID()))
                    {
                        revSigsValid++;
                    }
                    if (oldIdentity.IsValid() && primarySigDests.count(thisKey.GetID()))
                    {
                        priSigsValid++;
                    }
                }
                if (!recoveryIdentity.IsValid() || recSigsValid < recoveryIdentity.minSigs)
                {
                    fulfilled = false;
                }
                // one of the three authorities must be satisfied if no token fulfilled, or we should fail
                if ((!revocationIdentity.IsValid() || revSigsValid < revocationIdentity.minSigs) && priSigsValid < oldIdentity.minSigs)
                {
                    return eval->Error("Neither valid authority signature nor token authorization for ID update");
                }
            }
            else
            {
                return eval->Error("Invalid signature for ID update");
            }
        }
    }

    if (advanced)
    {
        // if not fulfilled, neither recovery data nor its spend condition may be modified
        if (!fulfilled)
        {
            if (oldIdentity.IsRecovery(newIdentity) || oldIdentity.IsRecoveryMutation(newIdentity, height))
            {
                return eval->Error("Unauthorized modification of recovery information");
            }

            // if revoked, only fulfilled recovery condition allows any mutation
            if (oldIdentity.IsRevoked() &&
                (oldIdentity.IsPrimaryMutation(newIdentity, height) ||
                 oldIdentity.IsRevocationMutation(newIdentity, height)))
            {
                return eval->Error("Unauthorized modification of revoked identity without recovery authority");
            }
        }
        // aside from that, validity of spend conditions is done in advanced precheck
        return true;
    }

    COptCCParams oldRecoverP, newRecoverP;

    for (int i = 1; i < q.vData.size() - 1; i++)
    {
        COptCCParams oneP(q.vData[i]);
        // must be valid and composable
        if (!oneP.IsValid() || oneP.version < oneP.VERSION_V3)
        {
            std::string errorOut = "Invalid output condition from identity: \"" + newIdentity.name + "\"";
            return eval->Error(errorOut.c_str());
        }

        if (oneP.evalCode == EVAL_IDENTITY_RECOVER)
        {
            if (newRecoverP.IsValid())
            {
                std::string errorOut = "Invalid output condition from identity: \"" + newIdentity.name + "\", more than one recovery condition";
                return eval->Error(errorOut.c_str());
            }
            newRecoverP = oneP;
        }
    }

    if (!newRecoverP.IsValid())
    {
        std::string errorOut = "Invalid recovery output condition for identity: \"" + newIdentity.name + "\"";
        return eval->Error(errorOut.c_str());
    }

    // if not fulfilled, neither recovery data nor its spend condition may be modified
    if (!fulfilled)
    {
        // if revoked, only fulfilled recovery condition allows primary mutation
        if (oldIdentity.IsRevoked() && (oldIdentity.IsPrimaryMutation(newIdentity, height)))
        {
            return eval->Error("Unauthorized modification of revoked identity without recovery authority");
        }

        if (oldIdentity.IsRecovery(newIdentity) || oldIdentity.IsRecoveryMutation(newIdentity, height))
        {
            return eval->Error("Unauthorized modification of recovery information");
        }

        sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p);

        for (int i = 1; i < p.vData.size() - 1; i++)
        {
            COptCCParams oneP(p.vData[i]);
            if (oneP.evalCode == EVAL_IDENTITY_RECOVER)
            {
                oldRecoverP = oneP;
            }
        }

        if (!oldRecoverP.IsValid() ||
            !newRecoverP.IsValid() ||
            oldRecoverP.version > newRecoverP.version ||
            oldRecoverP.m != newRecoverP.m ||
            oldRecoverP.n != newRecoverP.n ||
            oldRecoverP.vKeys != newRecoverP.vKeys)
        {
            return eval->Error("Unauthorized modification of identity recovery spend condition");
        }
    }
    return true;
}

bool ValidateIdentityCommitment(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    // if not fulfilled, fail
    if (!fulfilled)
    {
        return eval->Error("missing required signature to spend");
    }

    if (!chainActive.LastTip())
    {
        return eval->Error("unable to find chain tip");
    }
    uint32_t height = chainActive.LastTip()->GetHeight() + 1;

    CCommitmentHash ch;
    CNameReservation reservation;
    CAdvancedNameReservation advReservation;
    CTransaction sourceTx;
    uint256 blkHash;

    LOCK(mempool.cs);
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        COptCCParams p;
        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_IDENTITY_COMMITMENT &&
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1 &&
            !blkHash.IsNull())
        {
            ch = CCommitmentHash(p.vData[0]);
        }
        else
        {
            return eval->Error("Invalid source commitment output");
        }

        int i;
        int outputNum = -1;
        for (i = 0; i < spendingTx.vout.size(); i++)
        {
            auto &output = spendingTx.vout[i];
            if (output.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.vData.size() > 1 && (p.evalCode == EVAL_IDENTITY_RESERVATION || p.evalCode == EVAL_IDENTITY_ADVANCEDRESERVATION))
            {
                if (reservation.IsValid() || advReservation.IsValid())
                {
                    return eval->Error("Invalid identity reservation output spend");
                }
                else
                {
                    if (p.evalCode == EVAL_IDENTITY_RESERVATION)
                    {
                        reservation = CNameReservation(p.vData[0]);
                        if (!reservation.IsValid() || reservation.GetCommitment().hash != ch.hash)
                        {
                            return eval->Error("Identity reservation output spend does not match commitment");
                        }
                    }
                    else
                    {
                        advReservation = CAdvancedNameReservation(p.vData[0]);
                        if (!advReservation.IsValid() || advReservation.GetCommitment().hash != ch.hash)
                        {
                            return eval->Error("Advanced identity reservation output spend does not match commitment");
                        }
                    }

                    outputNum = i;
                    break;
                }
            }
        }
        if (outputNum != -1)
        {
            // can only be spent by a matching name reservation if validated
            // if there is no matching name reservation, it can be spent just by a valid signature
            CCurrencyDefinition issuingCurrency;
            if (advReservation.IsValid())
            {
                issuingCurrency = advReservation.parent.IsNull() ? CCurrencyDefinition() : ConnectedChains.GetCachedCurrency(advReservation.parent);
                if (!issuingCurrency.IsValid())
                {
                    return eval->Error("Invalid name parent for identity reservation");
                }
            }
            else
            {
                issuingCurrency = ConnectedChains.ThisChain();
            }
            bool success = ValidateSpendingIdentityReservation(spendingTx, outputNum, eval->state, height, issuingCurrency);
            if (!success && LogAcceptCategory("identity"))
            {
                UniValue jsonTx;
                TxToUniv(spendingTx, uint256(), jsonTx);
                LogPrintf("%s: failed to validate identity reservation:\n%s\n", __func__, jsonTx.write(1,2).c_str());
            }
            return success;
        }
    }
    else
    {
        printf("%s: error getting transaction %s to spend\n", __func__, spendingTx.vin[nIn].prevout.hash.GetHex().c_str());
        LogPrintf("%s: error getting transaction %s to spend\n", __func__, spendingTx.vin[nIn].prevout.hash.GetHex().c_str());
        return false;
    }

    return true;
}

bool ValidateIdentityReservation(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    // identity reservations are unspendable
    return eval->Error("Identity reservations are unspendable");
}

bool ValidateAdvancedNameReservation(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    // identity reservations are unspendable
    return eval->Error("Identity reservations are unspendable");
}

// quantum key outputs can be spent without restriction
bool ValidateQuantumKeyOut(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    return true;
}

bool IsQuantumKeyOutInput(const CScript &scriptSig)
{
    return false;
}

bool PrecheckQuantumKeyOut(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // inactive for now
    return false;
}

bool IsIdentityInput(const CScript &scriptSig)
{
    return false;
}

