// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "keystore.h"

#include "key.h"
#include "util.h"
#include "pbaas/identity.h"
#include "cc/CCinclude.h"
#include "boost/algorithm/string.hpp"

#include <boost/foreach.hpp>

bool CKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key))
        return false;
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CKeyStore::AddKey(const CKey &key) {
    return AddKeyPubKey(key, key.GetPubKey());
}

bool CBasicKeyStore::SetHDSeed(const HDSeed& seed)
{
    LOCK(cs_KeyStore);
    if (!hdSeed.IsNull()) {
        // Don't allow an existing seed to be changed. We can maybe relax this
        // restriction later once we have worked out the UX implications.
        return false;
    }
    hdSeed = seed;
    return true;
}

bool CBasicKeyStore::HaveHDSeed() const
{
    LOCK(cs_KeyStore);
    return !hdSeed.IsNull();
}

bool CBasicKeyStore::GetHDSeed(HDSeed& seedOut) const
{
    LOCK(cs_KeyStore);
    if (hdSeed.IsNull()) {
        return false;
    } else {
        seedOut = hdSeed;
        return true;
    }
}

CScriptID ScriptOrIdentityID(const CScript& scr)
{
    COptCCParams p;
    CIdentity identity;
    if (scr.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_PRIMARY && p.vData.size() && (identity = CIdentity(p.vData[0])).IsValid())
    {
        return CScriptID(identity.GetID());
    }
    else
    {
        return CScriptID(scr);
    }
}

bool CBasicKeyStore::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > CScript::MAX_SCRIPT_ELEMENT_SIZE)
        return error("CBasicKeyStore::AddCScript(): redeemScripts > %i bytes are invalid", CScript::MAX_SCRIPT_ELEMENT_SIZE);

    LOCK(cs_KeyStore);
    mapScripts[ScriptOrIdentityID(redeemScript)] = redeemScript;
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

void CBasicKeyStore::ClearIdentities(uint32_t fromHeight)
{
    if (fromHeight <= 1)
    {
        mapIdentities.clear();
    }
    else
    {
        std::vector<arith_uint256> vKeys;
        for (auto &idPair : mapIdentities)
        {
            if (CIdentityMapKey(idPair.first).blockHeight >= fromHeight)
            {
                vKeys.push_back(idPair.first);
            }
        }
        for (auto &idKey : vKeys)
        {
            mapIdentities.erase(idKey);
        }
    }
}

bool CBasicKeyStore::HaveIdentity(const CIdentityID &idID) const
{
    return mapIdentities.count(CIdentityMapKey(idID).MapKey()) != 0;
}

bool CBasicKeyStore::AddIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity)
{
    if (mapIdentities.count(mapKey.MapKey()) || !mapKey.IsValid())
    {
        return false;
    }
    mapIdentities.insert(make_pair(mapKey.MapKey(), identity));
    return true;
}

bool CBasicKeyStore::UpdateIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity)
{
    if (!mapIdentities.count(mapKey.MapKey()) || !mapKey.IsValid())
    {
        return false;
    }
    // erase and insert to replace
    mapIdentities.erase(mapKey.MapKey());
    mapIdentities.insert(make_pair(mapKey.MapKey(), identity));
    return true;
}

bool CBasicKeyStore::AddUpdateIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity)
{
    arith_uint256 arithKey = mapKey.MapKey();
    return CBasicKeyStore::AddIdentity(mapKey, identity) || CBasicKeyStore::UpdateIdentity(mapKey, identity);
}

bool CBasicKeyStore::RemoveIdentity(const CIdentityMapKey &mapKey, const uint256 &txid)
{
    auto localKey = mapKey;
    if (localKey.idID.IsNull())
    {
        return false;
    }
    auto startIt = mapIdentities.lower_bound(localKey.MapKey());
    if (localKey.blockHeight == 0)
    {
        localKey.blockHeight = 0x7fffffff;
    }

    if (startIt != mapIdentities.end())
    {
        if (txid.IsNull())
        {
            mapIdentities.erase(startIt, mapIdentities.upper_bound(localKey.MapKey()));
        }
        else
        {
            auto endIt = mapIdentities.upper_bound(localKey.MapKey());
            for (; startIt != endIt; startIt++)
            {
                if (startIt->second.txid == txid)
                {
                    mapIdentities.erase(startIt);
                    break;
                }
            }
        }

        return true;
    }
    return false;
}

// return an identity if it is in the store
bool CBasicKeyStore::GetIdentity(const CIdentityID &idID, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity, uint32_t lteHeight) const
{
    // debug test - comment normally
    // printf("lower_bound: %s\n", CIdentityMapKey(idID).ToString().c_str());
    // printf("upper_bound: %s\n", CIdentityMapKey(idID, lteHeight >= INT32_MAX ? INT32_MAX : lteHeight + 1).ToString().c_str());
    // printf("first: %s\n", mapIdentities.size() ? CIdentityMapKey(mapIdentities.begin()->first).ToString().c_str() : "");
    // end debug test

    auto itStart = mapIdentities.lower_bound(CIdentityMapKey(idID).MapKey());
    if (itStart == mapIdentities.end())
    {
        return false;
    }
    // point to the last
    auto itEnd = mapIdentities.upper_bound(CIdentityMapKey(idID, lteHeight >= INT32_MAX ? INT32_MAX : lteHeight + 1).MapKey());
    if (itEnd == mapIdentities.begin())
    {
        return false;
    }

    itEnd--;
    CIdentityMapKey foundKey(itEnd->first);
    if (foundKey.idID != idID)
    {
        return false;
    }
    keyAndIdentity = make_pair(foundKey, itEnd->second);
    return true;
}

// return all identities between two map keys, inclusive
bool CBasicKeyStore::GetIdentity(const CIdentityMapKey &keyStart, const CIdentityMapKey &keyEnd, std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &keysAndIdentityUpdates) const
{
    auto itStart = mapIdentities.lower_bound(keyStart.MapKey());
    if (itStart == mapIdentities.end())
    {
        return false;
    }
    auto itEnd = mapIdentities.upper_bound(keyEnd.MapKey());
    for (; itStart != mapIdentities.end() && itStart != itEnd; itStart++)
    {
        keysAndIdentityUpdates.push_back(make_pair(CIdentityMapKey(itStart->first), itStart->second));
    }
    return true;
}

bool CBasicKeyStore::GetIdentity(const CIdentityMapKey &mapKey, const uint256 &txid, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity) const
{
    CIdentityMapKey localKey = mapKey;
    std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> toCheck;
    bool found = false;

    if (localKey.blockHeight == 0)
    {
        localKey.blockHeight = 0x7fffffff;
    }
    if (!GetIdentity(mapKey, localKey, toCheck))
    {
        return found;
    }

    for (auto id : toCheck)
    {
        if (id.second.txid == txid)
        {
            keyAndIdentity = id;
            found = true;
        }
    }
    return found;
}

// return the first identity not less than a specific key
bool CBasicKeyStore::GetFirstIdentity(const CIdentityID &idID, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity, uint32_t gteHeight) const
{
    auto it = mapIdentities.lower_bound(CIdentityMapKey(idID, gteHeight).MapKey());
    if (it == mapIdentities.end())
    {
        return false;
    }
    keyAndIdentity = make_pair(CIdentityMapKey(it->first), it->second);
    return true;
}

// return the first identity not less than a specific key
bool CBasicKeyStore::GetPriorIdentity(const CIdentityMapKey &idMapKey, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity) const
{
    auto it = mapIdentities.lower_bound(idMapKey.MapKey());
    if (it == mapIdentities.end() || it == mapIdentities.begin() || CIdentityMapKey((--it)->first).idID != idMapKey.idID)
    {
        return false;
    }
    keyAndIdentity = make_pair(CIdentityMapKey(it->first), it->second);
    return true;
}

bool CBasicKeyStore::GetIdentities(const std::vector<uint160> &queryList,
                                   std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &mine,
                                   std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &imsigner,
                                   std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &notmine) const
{
    std::set<CIdentityID> identitySet;

    for (auto &identity : queryList)
    {
        identitySet.insert(identity);
    }

    for (auto &idID : identitySet)
    {
        std::pair<CIdentityMapKey, CIdentityMapValue> primaryIdentity;
        if (GetIdentity(idID, primaryIdentity))
        {
            std::pair<CIdentityMapKey, CIdentityMapValue> revocationAuthority;
            std::pair<CIdentityMapKey, CIdentityMapValue> recoveryAuthority;

            CIdentityMapKey idKey(primaryIdentity.first);

            // consider our canspend and cansign on revocation and recovery
            if (!primaryIdentity.second.IsRevoked() && primaryIdentity.second.revocationAuthority != idID)
            {
                if (GetIdentity(primaryIdentity.second.revocationAuthority, revocationAuthority))
                {
                    idKey.flags |= (CIdentityMapKey(revocationAuthority.first).flags & (idKey.CAN_SPEND | idKey.CAN_SIGN));
                }
            }

            if (primaryIdentity.second.IsRevoked() && primaryIdentity.second.recoveryAuthority != idID)
            {
                if (GetIdentity(primaryIdentity.second.recoveryAuthority, recoveryAuthority))
                {
                    idKey.flags |= (CIdentityMapKey(recoveryAuthority.first).flags & (idKey.CAN_SPEND | idKey.CAN_SIGN));
                }
            }

            if (idKey.flags & idKey.CAN_SPEND)
            {
                mine.push_back(make_pair(idKey, primaryIdentity.second));
            }
            else if (idKey.flags & idKey.CAN_SIGN)
            {
                imsigner.push_back(make_pair(idKey, primaryIdentity.second));
            }
            else
            {
                notmine.push_back(make_pair(idKey, primaryIdentity.second));
            }
        }
    }
    return (mine.size() || imsigner.size() || notmine.size());
}

bool CBasicKeyStore::GetIdentities(std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &mine,
                                   std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &imsigner,
                                   std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &notmine) const
{
    std::set<CIdentityID> identitySet;

    for (auto &identity : mapIdentities)
    {
        identitySet.insert(identity.second.GetID());
    }

    for (auto &idID : identitySet)
    {
        std::pair<CIdentityMapKey, CIdentityMapValue> primaryIdentity;
        if (GetIdentity(idID, primaryIdentity))
        {
            std::pair<CIdentityMapKey, CIdentityMapValue> revocationAuthority;
            std::pair<CIdentityMapKey, CIdentityMapValue> recoveryAuthority;

            CIdentityMapKey idKey(primaryIdentity.first);

            // consider our canspend and cansign on revocation and recovery
            if (!primaryIdentity.second.IsRevoked() && primaryIdentity.second.revocationAuthority != idID)
            {
                if (GetIdentity(primaryIdentity.second.revocationAuthority, revocationAuthority))
                {
                    idKey.flags |= (CIdentityMapKey(revocationAuthority.first).flags & idKey.CAN_SIGN);
                }
            }

            if (primaryIdentity.second.IsRevoked() && primaryIdentity.second.recoveryAuthority != idID)
            {
                if (GetIdentity(primaryIdentity.second.recoveryAuthority, recoveryAuthority))
                {
                    idKey.flags |= (CIdentityMapKey(recoveryAuthority.first).flags & (idKey.CAN_SPEND | idKey.CAN_SIGN));
                }
            }

            if (idKey.flags & idKey.CAN_SPEND)
            {
                mine.push_back(make_pair(idKey, primaryIdentity.second));
            }
            else if (idKey.flags & idKey.CAN_SIGN)
            {
                imsigner.push_back(make_pair(idKey, primaryIdentity.second));
            }
            else
            {
                notmine.push_back(make_pair(idKey, primaryIdentity.second));
            }
        }
    }
    return (mine.size() || imsigner.size() || notmine.size());
}

// returns a set of key IDs that have private keys in this wallet and control the identities in this wallet
std::set<CKeyID> CBasicKeyStore::GetIdentityKeyIDs() const
{
    std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> mine;
    std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> imsigner;
    std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> notmine;

    std::set<CKeyID> ret;
    if (GetIdentities(mine, imsigner, notmine))
    {
        for (auto &idpair : mine)
        {
            for (auto &dest : idpair.second.primaryAddresses)
            {
                CKeyID keyid = GetDestinationID(dest);
                if (HaveKey(keyid))
                {
                    ret.insert(keyid);
                }
            }
        }
        for (auto &idpair : imsigner)
        {
            for (auto &dest : idpair.second.primaryAddresses)
            {
                CKeyID keyid = GetDestinationID(dest);
                if (HaveKey(keyid))
                {
                    ret.insert(keyid);
                }
            }
        }
    }
    return ret;
}

void CBasicKeyStore::ClearCurrencyTrust()
{
    mapCurrencyTrust.clear();
}

bool CBasicKeyStore::RemoveCurrencyTrust(const uint160 &currencyID)
{
    return (bool)mapCurrencyTrust.erase(currencyID);
}

CRating CBasicKeyStore::GetCurrencyTrust(const uint160 &currencyID) const
{
    auto it = mapCurrencyTrust.find(currencyID);
    if (it == mapCurrencyTrust.end())
    {
        return CRating();
    }
    else
    {
        return it->second;
    }
}

bool CBasicKeyStore::SetCurrencyTrust(const uint160 &currencyID, const CRating &trust)
{
    mapCurrencyTrust[currencyID] = trust;
    return true;
}

bool CBasicKeyStore::SetCurrencyTrustMode(int trustMode)
{
    if (trustMode >= CRating::TRUSTMODE_FIRST && trustMode <= CRating::TRUSTMODE_LAST)
    {
        currencyTrustMode = trustMode;
        return true;
    }
    else
    {
        return false;
    }
}

int CBasicKeyStore::GetCurrencyTrustMode() const
{
    return currencyTrustMode;
}

CCurrencyValueMap CBasicKeyStore::RemoveBlockedCurrencies(const CCurrencyValueMap inputMap) const
{
    CCurrencyValueMap retVal = inputMap;
    if (currencyTrustMode != CRating::TRUSTMODE_NORESTRICTION)
    {
        if (currencyTrustMode == CRating::TRUSTMODE_WHITELISTONLY)
        {
            // remove all currencies that aren't on the white list
            for (auto &oneCurVal : inputMap.valueMap)
            {
                if (GetCurrencyTrust(oneCurVal.first).trustLevel != CRating::TRUST_APPROVED)
                {
                    retVal.valueMap.erase(oneCurVal.first);
                    if (!retVal.valueMap.size())
                    {
                        break;
                    }
                }
            }
        }
        else
        {
            // remove all currencies on the black list
            for (auto &oneCurVal : inputMap.valueMap)
            {
                if (GetCurrencyTrust(oneCurVal.first).trustLevel == CRating::TRUST_BLOCKED)
                {
                    retVal.valueMap.erase(oneCurVal.first);
                    if (!retVal.valueMap.size())
                    {
                        break;
                    }
                }
            }
        }
    }
    return retVal;
}

void CBasicKeyStore::ClearIdentityTrust()
{
    mapIdentityTrust.clear();
    identityTrustMode = CRating::TRUSTMODE_NORESTRICTION;
}

bool CBasicKeyStore::RemoveIdentityTrust(const CIdentityID &idID)
{
    return (bool)mapIdentityTrust.erase(idID);
}

CRating CBasicKeyStore::GetIdentityTrust(const CIdentityID &idID) const
{
    auto it = mapIdentityTrust.find(idID);
    if (it == mapIdentityTrust.end())
    {
        return CRating();
    }
    else
    {
        return it->second;
    }
}

bool CBasicKeyStore::SetIdentityTrust(const CIdentityID &idID, const CRating &trust)
{
    mapIdentityTrust[idID] = trust;
    return true;
}

bool CBasicKeyStore::SetIdentityTrustMode(int trustMode)
{
    if (trustMode >= CRating::TRUSTMODE_FIRST && trustMode <= CRating::TRUSTMODE_LAST)
    {
        identityTrustMode = trustMode;
        return true;
    }
    else
    {
        return false;
    }
}

int CBasicKeyStore::GetIdentityTrustMode() const
{
    return identityTrustMode;
}

bool CBasicKeyStore::IsBlockedIdentity(const CIdentityID &idID) const
{
    if (identityTrustMode != CRating::TRUSTMODE_NORESTRICTION)
    {
        if (identityTrustMode == CRating::TRUSTMODE_WHITELISTONLY)
        {
            if (GetIdentityTrust(idID).trustLevel != CRating::TRUST_APPROVED)
            {
                return true;
            }
        }
        else
        {
            if (GetIdentityTrust(idID).trustLevel == CRating::TRUST_BLOCKED)
            {
                return true;
            }
        }
    }
    return false;
}

bool CBasicKeyStore::AddWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.erase(dest);
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}

bool CBasicKeyStore::AddSproutSpendingKey(const libzcash::SproutSpendingKey &sk)
{
    LOCK(cs_KeyStore);
    auto address = sk.address();
    mapSproutSpendingKeys[address] = sk;
    mapNoteDecryptors.insert(std::make_pair(address, ZCNoteDecryption(sk.receiving_key())));
    return true;
}

//! Sapling 
bool CBasicKeyStore::AddSaplingSpendingKey(
    const libzcash::SaplingExtendedSpendingKey &sk)
{
    LOCK(cs_KeyStore);
    auto extfvk = sk.ToXFVK();

    // if extfvk is not in SaplingFullViewingKeyMap, add it
    if (!CBasicKeyStore::AddSaplingFullViewingKey(extfvk)) {
        return false;
    }

    mapSaplingSpendingKeys[extfvk] = sk;

    return true;
}

bool CBasicKeyStore::AddSproutViewingKey(const libzcash::SproutViewingKey &vk)
{
    LOCK(cs_KeyStore);
    auto address = vk.address();
    mapSproutViewingKeys[address] = vk;
    mapNoteDecryptors.insert(std::make_pair(address, ZCNoteDecryption(vk.sk_enc)));
    return true;
}

bool CBasicKeyStore::AddSaplingFullViewingKey(
    const libzcash::SaplingExtendedFullViewingKey &extfvk)
{
    LOCK(cs_KeyStore);
    auto ivk = extfvk.fvk.in_viewing_key();
    mapSaplingFullViewingKeys[ivk] = extfvk;

    return CBasicKeyStore::AddSaplingIncomingViewingKey(ivk, extfvk.DefaultAddress());
}

// This function updates the wallet's internal address->ivk map. 
// If we add an address that is already in the map, the map will
// remain unchanged as each address only has one ivk.
bool CBasicKeyStore::AddSaplingIncomingViewingKey(
    const libzcash::SaplingIncomingViewingKey &ivk,
    const libzcash::SaplingPaymentAddress &addr)
{
    LOCK(cs_KeyStore);

    // Add addr -> SaplingIncomingViewing to SaplingIncomingViewingKeyMap
    mapSaplingIncomingViewingKeys[addr] = ivk;

    return true;
}

bool CBasicKeyStore::RemoveSproutViewingKey(const libzcash::SproutViewingKey &vk)
{
    LOCK(cs_KeyStore);
    mapSproutViewingKeys.erase(vk.address());
    return true;
}

bool CBasicKeyStore::HaveSproutViewingKey(const libzcash::SproutPaymentAddress &address) const
{
    LOCK(cs_KeyStore);
    return mapSproutViewingKeys.count(address) > 0;
}

bool CBasicKeyStore::HaveSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk) const
{
    LOCK(cs_KeyStore);
    return mapSaplingFullViewingKeys.count(ivk) > 0;
}

bool CBasicKeyStore::HaveSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr) const
{
    LOCK(cs_KeyStore);
    return mapSaplingIncomingViewingKeys.count(addr) > 0;
}

bool CBasicKeyStore::GetSproutViewingKey(
    const libzcash::SproutPaymentAddress &address,
    libzcash::SproutViewingKey &vkOut) const
{
    LOCK(cs_KeyStore);
    SproutViewingKeyMap::const_iterator mi = mapSproutViewingKeys.find(address);
    if (mi != mapSproutViewingKeys.end()) {
        vkOut = mi->second;
        return true;
    }
    return false;
}

bool CBasicKeyStore::GetSaplingFullViewingKey(
    const libzcash::SaplingIncomingViewingKey &ivk,
    libzcash::SaplingExtendedFullViewingKey &extfvkOut) const
{
    LOCK(cs_KeyStore);
    SaplingFullViewingKeyMap::const_iterator mi = mapSaplingFullViewingKeys.find(ivk);
    if (mi != mapSaplingFullViewingKeys.end()) {
        extfvkOut = mi->second;
        return true;
    }
    return false;
}

bool CBasicKeyStore::GetSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr,
                                   libzcash::SaplingIncomingViewingKey &ivkOut) const
{
    LOCK(cs_KeyStore);
    SaplingIncomingViewingKeyMap::const_iterator mi = mapSaplingIncomingViewingKeys.find(addr);
    if (mi != mapSaplingIncomingViewingKeys.end()) {
        ivkOut = mi->second;
        return true;
    }
    return false;
}

bool CBasicKeyStore::DecryptWithSaplingViewingKey(const CDataDescriptor &dataDescr, CDataDescriptor &decryptedDescr, libzcash::SaplingIncomingViewingKey *pIvkOut) const
{
    bool decrypted = false;
    for (auto &oneIvk : mapSaplingIncomingViewingKeys)
    {
        decryptedDescr = dataDescr;
        decrypted = decryptedDescr.UnwrapEncryption(oneIvk.second, true);
        if (decrypted)
        {
            if (pIvkOut)
            {
                *pIvkOut = oneIvk.second;
            }
            break;
        }
    }
    return decrypted;
}

bool CBasicKeyStore::GetSaplingExtendedSpendingKey(const libzcash::SaplingPaymentAddress &addr,
                                    libzcash::SaplingExtendedSpendingKey &extskOut) const {
    libzcash::SaplingIncomingViewingKey ivk;
    libzcash::SaplingExtendedFullViewingKey extfvk;

    LOCK(cs_KeyStore);
    return GetSaplingIncomingViewingKey(addr, ivk) &&
            GetSaplingFullViewingKey(ivk, extfvk) &&
            GetSaplingSpendingKey(extfvk, extskOut);
}
