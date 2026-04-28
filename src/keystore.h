// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_KEYSTORE_H
#define BITCOIN_KEYSTORE_H

#include "key.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "script/script_ext.h"
#include "sync.h"
#include "zcash/Address.hpp"
#include "zcash/NoteEncryption.hpp"
#include "pbaas/identity.h"

#include <boost/signals2/signal.hpp>
#include <boost/variant.hpp>

/** A virtual base class for key stores */
class CKeyStore
{
protected:
    mutable CCriticalSection cs_KeyStore;

public:
    virtual ~CKeyStore() {}

    //! Set the HD seed for this keystore
    virtual bool SetHDSeed(const HDSeed& seed) =0;
    virtual bool HaveHDSeed() const =0;
    //! Get the HD seed for this keystore
    virtual bool GetHDSeed(HDSeed& seedOut) const =0;

    //! Add a key to the store.
    virtual bool AddKeyPubKey(const CKey &key, const CPubKey &pubkey) =0;
    virtual bool AddKey(const CKey &key);

    //! Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID &address) const =0;
    virtual bool GetKey(const CKeyID &address, CKey& keyOut) const =0;
    virtual void GetKeys(std::set<CKeyID> &setAddress) const =0;
    virtual bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;

    //! Support for BIP 0013 : see https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
    virtual bool AddCScript(const CScript& redeemScript) =0;
    virtual bool HaveCScript(const CScriptID &hash) const =0;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const =0;

    //! Support for Watch-only addresses
    virtual bool AddWatchOnly(const CScript &dest) =0;
    virtual bool RemoveWatchOnly(const CScript &dest) =0;
    virtual bool HaveWatchOnly(const CScript &dest) const =0;
    virtual bool HaveWatchOnly() const =0;

    //! Support for identities
    virtual void ClearIdentities(uint32_t fromHeight=0) =0;
    virtual bool HaveIdentity(const CIdentityID &idID) const =0;
    virtual bool AddIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity) =0;
    virtual bool UpdateIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity) =0;
    virtual bool AddUpdateIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity) =0;
    virtual bool RemoveIdentity(const CIdentityMapKey &mapKey, const uint256 &txid=uint256()) =0;
    virtual bool GetIdentity(const CIdentityID &idID, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity, uint32_t lteHeight=0x7fffffff) const =0;
    virtual bool GetIdentity(const CIdentityMapKey &keyStart, const CIdentityMapKey &keyEnd, std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &keysAndIdentityUpdates) const =0;
    virtual bool GetIdentity(const CIdentityMapKey &mapKey, const uint256 &txid, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity) const =0;
    virtual bool GetFirstIdentity(const CIdentityID &idID, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity, uint32_t gteHeight=0) const =0;

    //! Support for trust and ratings for currencies
    virtual void ClearCurrencyTrust() = 0;
    virtual bool RemoveCurrencyTrust(const uint160 &currencyID) = 0;
    virtual CRating GetCurrencyTrust(const uint160 &currencyID) const = 0;
    virtual bool SetCurrencyTrust(const uint160 &currencyID, const CRating &trust) = 0;
    virtual bool SetCurrencyTrustMode(int trustMode=CRating::TRUSTMODE_NORESTRICTION) = 0;
    virtual int GetCurrencyTrustMode() const = 0;
    virtual const std::map<uint160, CRating> &GetCurrencyTrustMap() const = 0;
    virtual CCurrencyValueMap RemoveBlockedCurrencies(const CCurrencyValueMap inputMap) const = 0;

    //! Support for trust and ratings for identities
    virtual void ClearIdentityTrust() = 0;
    virtual bool RemoveIdentityTrust(const CIdentityID &idID) = 0;
    virtual CRating GetIdentityTrust(const CIdentityID &idID) const = 0;
    virtual bool SetIdentityTrust(const CIdentityID &idID, const CRating &trust) = 0;
    virtual bool SetIdentityTrustMode(int trustMode=CRating::TRUSTMODE_NORESTRICTION) = 0;
    virtual int GetIdentityTrustMode() const = 0;
    virtual const std::map<uint160, CRating> &GetIdentityTrustMap() const = 0;
    virtual bool IsBlockedIdentity(const CIdentityID &idID) const = 0;

    //! Add a spending key to the store.
    virtual bool AddSproutSpendingKey(const libzcash::SproutSpendingKey &sk) =0;

    //! Check whether a spending key corresponding to a given payment address is present in the store.
    virtual bool HaveSproutSpendingKey(const libzcash::SproutPaymentAddress &address) const =0;
    virtual bool GetSproutSpendingKey(const libzcash::SproutPaymentAddress &address, libzcash::SproutSpendingKey& skOut) const =0;
    virtual void GetSproutPaymentAddresses(std::set<libzcash::SproutPaymentAddress> &setAddress) const =0;
    
    //! Add a Sapling spending key to the store.
    virtual bool AddSaplingSpendingKey(const libzcash::SaplingExtendedSpendingKey &sk) =0;
    
    //! Check whether a Sapling spending key corresponding to a given Sapling viewing key is present in the store.
    virtual bool HaveSaplingSpendingKey(
        const libzcash::SaplingExtendedFullViewingKey &extfvk) const =0;
    virtual bool GetSaplingSpendingKey(
        const libzcash::SaplingExtendedFullViewingKey &extfvk,
        libzcash::SaplingExtendedSpendingKey& skOut) const =0;

    //! Support for Sapling full viewing keys
    virtual bool AddSaplingFullViewingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk) =0;
    virtual bool HaveSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk) const =0;
    virtual bool GetSaplingFullViewingKey(
        const libzcash::SaplingIncomingViewingKey &ivk, 
        libzcash::SaplingExtendedFullViewingKey& extfvkOut) const =0;

    //! Sapling incoming viewing keys 
    virtual bool AddSaplingIncomingViewingKey(
        const libzcash::SaplingIncomingViewingKey &ivk,
        const libzcash::SaplingPaymentAddress &addr) =0;
    virtual bool HaveSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr) const =0;
    virtual bool GetSaplingIncomingViewingKey(
        const libzcash::SaplingPaymentAddress &addr, 
        libzcash::SaplingIncomingViewingKey& ivkOut) const =0;
    virtual void GetSaplingPaymentAddresses(std::set<libzcash::SaplingPaymentAddress> &setAddress) const =0;

    //! Support for Sprout viewing keys
    virtual bool AddSproutViewingKey(const libzcash::SproutViewingKey &vk) =0;
    virtual bool RemoveSproutViewingKey(const libzcash::SproutViewingKey &vk) =0;
    virtual bool HaveSproutViewingKey(const libzcash::SproutPaymentAddress &address) const =0;
    virtual bool GetSproutViewingKey(
        const libzcash::SproutPaymentAddress &address,
        libzcash::SproutViewingKey& vkOut) const =0;
};

typedef std::map<CKeyID, CKey> KeyMap;
typedef std::map<CScriptID, CScript> ScriptMap;
typedef std::multimap<arith_uint256, CIdentityMapValue> IdentityMap;
typedef std::set<CScript> WatchOnlySet;
typedef std::map<libzcash::SproutPaymentAddress, libzcash::SproutSpendingKey> SproutSpendingKeyMap;
typedef std::map<libzcash::SproutPaymentAddress, libzcash::SproutViewingKey> SproutViewingKeyMap;
typedef std::map<libzcash::SproutPaymentAddress, ZCNoteDecryption> NoteDecryptorMap;

// Full viewing key has equivalent functionality to a transparent address
// When encrypting wallet, encrypt SaplingSpendingKeyMap, while leaving SaplingFullViewingKeyMap unencrypted
typedef std::map<
    libzcash::SaplingExtendedFullViewingKey,
    libzcash::SaplingExtendedSpendingKey> SaplingSpendingKeyMap;
typedef std::map<
    libzcash::SaplingIncomingViewingKey,
    libzcash::SaplingExtendedFullViewingKey> SaplingFullViewingKeyMap;
// Only maps from default addresses to ivk, may need to be reworked when adding diversified addresses. 
typedef std::map<libzcash::SaplingPaymentAddress, libzcash::SaplingIncomingViewingKey> SaplingIncomingViewingKeyMap;

/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore
{
protected:
    HDSeed hdSeed;
    KeyMap mapKeys;
    ScriptMap mapScripts;
    IdentityMap mapIdentities;

    std::map<uint160, CRating> mapCurrencyTrust;
    int currencyTrustMode;
    std::map<uint160, CRating> mapIdentityTrust;
    int identityTrustMode;

    WatchOnlySet setWatchOnly;
    SproutSpendingKeyMap mapSproutSpendingKeys;
    SproutViewingKeyMap mapSproutViewingKeys;
    NoteDecryptorMap mapNoteDecryptors;

    SaplingSpendingKeyMap mapSaplingSpendingKeys;
    SaplingFullViewingKeyMap mapSaplingFullViewingKeys;
    SaplingIncomingViewingKeyMap mapSaplingIncomingViewingKeys;

public:
    bool SetHDSeed(const HDSeed& seed);
    bool HaveHDSeed() const;
    bool GetHDSeed(HDSeed& seedOut) const;

    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey);
    bool HaveKey(const CKeyID &address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapKeys.count(address) > 0);
        }
        return result;
    }
    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.begin();
            while (mi != mapKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }
    bool GetKey(const CKeyID &address, CKey &keyOut) const
    {
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.find(address);
            if (mi != mapKeys.end())
            {
                keyOut = mi->second;
                return true;
            }
        }
        return false;
    }
    virtual bool AddCScript(const CScript& redeemScript);
    virtual bool HaveCScript(const CScriptID &hash) const;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const;

    virtual void ClearIdentities(uint32_t fromHeight);
    virtual bool HaveIdentity(const CIdentityID &idID) const;
    virtual bool AddIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity);
    virtual bool UpdateIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity);
    virtual bool AddUpdateIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity);
    virtual bool RemoveIdentity(const CIdentityMapKey &mapKey, const uint256 &txid=uint256());
    virtual bool GetIdentity(const CIdentityID &idID, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity, uint32_t lteHeight=INT32_MAX) const;
    virtual bool GetIdentity(const CIdentityMapKey &keyStart, const CIdentityMapKey &keyEnd, std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &keysAndIdentityUpdates) const;
    virtual bool GetIdentity(const CIdentityMapKey &mapKey, const uint256 &txid, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity) const;
    virtual bool GetFirstIdentity(const CIdentityID &idID, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity, uint32_t gteHeight=0) const;
    virtual bool GetPriorIdentity(const CIdentityMapKey &mapKey, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity) const;
    virtual bool GetIdentities(std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &mine,
                               std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &imsigner,
                               std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &notmine) const;
    virtual bool GetIdentities(const std::vector<uint160> &queryList,
                               std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &mine,
                               std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &imsigner,
                               std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &notmine) const;
    virtual std::set<CKeyID> GetIdentityKeyIDs() const;

    virtual void ClearCurrencyTrust();
    virtual bool RemoveCurrencyTrust(const uint160 &currencyID);
    virtual CRating GetCurrencyTrust(const uint160 &currencyID) const;
    virtual bool SetCurrencyTrust(const uint160 &currencyID, const CRating &trust);
    virtual bool SetCurrencyTrustMode(int trustMode=CRating::TRUSTMODE_NORESTRICTION);
    virtual int GetCurrencyTrustMode() const;
    virtual const std::map<uint160, CRating> &GetCurrencyTrustMap() const
    {
        return mapCurrencyTrust;
    }
    virtual CCurrencyValueMap RemoveBlockedCurrencies(const CCurrencyValueMap inputMap) const;

    virtual void ClearIdentityTrust();
    virtual bool RemoveIdentityTrust(const CIdentityID &idID);
    virtual CRating GetIdentityTrust(const CIdentityID &idID) const;
    virtual bool SetIdentityTrust(const CIdentityID &idID, const CRating &trust);
    virtual bool SetIdentityTrustMode(int trustMode=CRating::TRUSTMODE_NORESTRICTION);
    virtual int GetIdentityTrustMode() const;
    virtual const std::map<uint160, CRating> &GetIdentityTrustMap() const
    {
        return mapIdentityTrust;
    }
    virtual bool IsBlockedIdentity(const CIdentityID &idID) const;

    virtual bool AddWatchOnly(const CScript &dest);
    virtual bool RemoveWatchOnly(const CScript &dest);
    virtual bool HaveWatchOnly(const CScript &dest) const;
    virtual bool HaveWatchOnly() const;

    bool AddSproutSpendingKey(const libzcash::SproutSpendingKey &sk);
    bool HaveSproutSpendingKey(const libzcash::SproutPaymentAddress &address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapSproutSpendingKeys.count(address) > 0);
        }
        return result;
    }
    bool GetSproutSpendingKey(const libzcash::SproutPaymentAddress &address, libzcash::SproutSpendingKey &skOut) const
    {
        {
            LOCK(cs_KeyStore);
            SproutSpendingKeyMap::const_iterator mi = mapSproutSpendingKeys.find(address);
            if (mi != mapSproutSpendingKeys.end())
            {
                skOut = mi->second;
                return true;
            }
        }
        return false;
    }
    bool GetNoteDecryptor(const libzcash::SproutPaymentAddress &address, ZCNoteDecryption &decOut) const
    {
        {
            LOCK(cs_KeyStore);
            NoteDecryptorMap::const_iterator mi = mapNoteDecryptors.find(address);
            if (mi != mapNoteDecryptors.end())
            {
                decOut = mi->second;
                return true;
            }
        }
        return false;
    }
    void GetSproutPaymentAddresses(std::set<libzcash::SproutPaymentAddress> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            SproutSpendingKeyMap::const_iterator mi = mapSproutSpendingKeys.begin();
            while (mi != mapSproutSpendingKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
            SproutViewingKeyMap::const_iterator mvi = mapSproutViewingKeys.begin();
            while (mvi != mapSproutViewingKeys.end())
            {
                setAddress.insert((*mvi).first);
                mvi++;
            }
        }
    }

    //! Sapling 
    bool AddSaplingSpendingKey(const libzcash::SaplingExtendedSpendingKey &sk);
    bool HaveSaplingSpendingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapSaplingSpendingKeys.count(extfvk) > 0);
        }
        return result;
    }
    bool GetSaplingSpendingKey(
        const libzcash::SaplingExtendedFullViewingKey &extfvk,
        libzcash::SaplingExtendedSpendingKey &skOut) const
    {
        {
            LOCK(cs_KeyStore);

            SaplingSpendingKeyMap::const_iterator mi = mapSaplingSpendingKeys.find(extfvk);
            if (mi != mapSaplingSpendingKeys.end())
            {
                skOut = mi->second;
                return true;
            }
        }
        return false;
    }

    virtual bool AddSaplingFullViewingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk);
    virtual bool HaveSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk) const;
    virtual bool GetSaplingFullViewingKey(
        const libzcash::SaplingIncomingViewingKey &ivk,
        libzcash::SaplingExtendedFullViewingKey& extfvkOut) const;

    virtual bool AddSaplingIncomingViewingKey(
        const libzcash::SaplingIncomingViewingKey &ivk,
        const libzcash::SaplingPaymentAddress &addr);
    virtual bool HaveSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr) const;
    virtual bool GetSaplingIncomingViewingKey(
        const libzcash::SaplingPaymentAddress &addr, 
        libzcash::SaplingIncomingViewingKey& ivkOut) const;

    virtual bool DecryptWithSaplingViewingKey(const CDataDescriptor &dataDescr, CDataDescriptor &decryptedDescr, libzcash::SaplingIncomingViewingKey *pIvkOut=nullptr) const;

    bool GetSaplingExtendedSpendingKey(
        const libzcash::SaplingPaymentAddress &addr, 
        libzcash::SaplingExtendedSpendingKey &extskOut) const;
    
    void GetSaplingPaymentAddresses(std::set<libzcash::SaplingPaymentAddress> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            auto mi = mapSaplingIncomingViewingKeys.begin();
            while (mi != mapSaplingIncomingViewingKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }

    virtual bool AddSproutViewingKey(const libzcash::SproutViewingKey &vk);
    virtual bool RemoveSproutViewingKey(const libzcash::SproutViewingKey &vk);
    virtual bool HaveSproutViewingKey(const libzcash::SproutPaymentAddress &address) const;
    virtual bool GetSproutViewingKey(
        const libzcash::SproutPaymentAddress &address,
        libzcash::SproutViewingKey& vkOut) const;
};

typedef std::vector<unsigned char, secure_allocator<unsigned char> > CKeyingMaterial;
typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;
typedef std::map<libzcash::SproutPaymentAddress, std::vector<unsigned char> > CryptedSproutSpendingKeyMap;

//! Sapling 
typedef std::map<libzcash::SaplingExtendedFullViewingKey, std::vector<unsigned char> > CryptedSaplingSpendingKeyMap;

CScriptID ScriptOrIdentityID(const CScript& scr);

#endif // BITCOIN_KEYSTORE_H
