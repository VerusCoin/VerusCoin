// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2016-2018 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <key_io.h>

#include <base58.h>
#include <bech32.h>
#include <script/script.h>
#include <utilstrencodings.h>

#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>

#include "pbaas/identity.h"
#include "cc/CCinclude.h"
#include "boost/algorithm/string.hpp"
#include "rpc/protocol.h"

#include <assert.h>
#include <string.h>
#include <algorithm>

extern uint160 VERUS_CHAINID;
extern std::string VERUS_CHAINNAME;

CIdentityID VERUS_DEFAULTID;
CIdentityID VERUS_NOTARYID;
CIdentityID PBAAS_NOTIFICATION_ORACLE;                                  // an identity that can be used to coordinate on-chain actions or upgrades
CTransferDestination APPROVE_CONTRACT_UPGRADE;                          // approve a contract to be upgraded on the ETH bridge, enables the network to decide
std::string PBAAS_DEFAULT_NOTIFICATION_ORACLE = "";                     // please see "-notificationoracle" and coordinate with ALL network validators to change this default,
                                                                        // if empty, it's the current chain

std::set<uint160> FREE_CURRENCY_IMPORTS;

int32_t MAX_OUR_UTXOS_ID_RESCAN = 1000; // this can be set with "-maxourutxosidrescan=n"
int32_t MAX_UTXOS_ID_RESCAN = 100;      // this can be set with "-maxutxosidrescan=n"
bool ONLY_ADD_WHITELISTED_UTXOS_ID_RESCAN = false;
uint160 VERUS_NODEID;
bool VERUS_PRIVATECHANGE;
std::string VERUS_DEFAULT_ZADDR;
CTxDestination VERUS_DEFAULT_ARBADDRESS;
std::vector<uint160> VERUS_ARBITRAGE_CURRENCIES;

uint160 ParseVDXFIDInternal(const std::string &vdxfName)
{
    uint160 vdxfID;
    uint160 parentID;

    if (vdxfName.empty())
    {
        return uint160();
    }

    // first, try to interpret the ID as an ID, in case it is
    CTxDestination idDest = DecodeDestination(vdxfName);

    if (idDest.which() == COptCCParams::ADDRTYPE_ID)
    {
        return GetDestinationID(idDest);
    }
    else if (vdxfName.back() != '@')
    {
        idDest = DecodeDestination(vdxfName + "@");
    }

    if (idDest.which() == COptCCParams::ADDRTYPE_ID)
    {
        vdxfID = GetDestinationID(idDest);
    }
    else
    {
        vdxfID = CVDXF::GetDataKey(vdxfName, parentID);
    }
    return vdxfID;
}

UniValue getvdxfid_internal(const UniValue& params)
{
    std::string vdxfName = uni_get_str(params[0]);
    if (!vdxfName.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No message to hash");
    }

    UniValue secondObj = (params.size() > 1) ? params[1] : UniValue(UniValue::VOBJ);
    UniValue vdxfKeyInputUni = find_value(secondObj, "vdxfkey");
    UniValue hashUniValue = find_value(secondObj, "uint256");
    UniValue numUniValue = find_value(secondObj, "indexnum");

    uint160 vdxfKeyInput;
    uint256 hash256KeyKeyInput;
    if (!vdxfKeyInputUni.isNull())
    {
        std::string vdxfKeyInputStr = uni_get_str(vdxfKeyInputUni);
        vdxfKeyInput = ParseVDXFIDInternal(vdxfKeyInputStr);
        if (vdxfKeyInput.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid additional vdxf key to combine");
        }
    }
    if (!hashUniValue.isNull())
    {
        hash256KeyKeyInput = uint256S(uni_get_str(hashUniValue));
        if (hash256KeyKeyInput.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hash value to combine");
        }
    }
    int32_t hashInputNum = uni_get_int(numUniValue);

    uint160 vdxfID;
    uint160 parentID;
    std::string cleanName;
    std::string parentIDName = "parentid";

    // first, try to interpret the ID as an ID, in case it is
    CTxDestination idDest = DecodeDestination(vdxfName);

    bool isIndexKey = false;

    if (idDest.which() == COptCCParams::ADDRTYPE_ID)
    {
        cleanName = CleanName(vdxfName, parentID);
        vdxfID = GetDestinationID(idDest);
    }
    else if (vdxfName.substr(0,2) == "0x" && !(vdxfID = CTransferDestination::DecodeEthDestination(vdxfName)).IsNull())
    {
        parentIDName = "currencyaddresstype";
        parentID = CIdentity::GetID("veth", parentID);
        cleanName = vdxfName;
    }
    else
    {
        isIndexKey = true;
        parentIDName = "namespace";
        vdxfID = CVDXF::GetDataKey(vdxfName, parentID);
        cleanName = vdxfName;
    }

    if (vdxfID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid ID or URI format");
    }

    // now, add optional values
    UniValue boundData(UniValue::VOBJ);
    if (!vdxfKeyInputUni.isNull())
    {
        isIndexKey = true;

        if (hashUniValue.isNull())
        {
            vdxfID = CCrossChainRPCData::GetConditionID(vdxfID, vdxfKeyInput);
            boundData.pushKV("vdxfkey", EncodeDestination(CIdentityID(vdxfKeyInput)));
            if (!numUniValue.isNull())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify index without hash value");
            }
        }
        else
        {
            if (numUniValue.isNull())
            {
                vdxfID = CCrossChainRPCData::GetConditionID(vdxfID, vdxfKeyInput, hash256KeyKeyInput);
                boundData.pushKV("vdxfkey", EncodeDestination(CIdentityID(vdxfKeyInput)));
                boundData.pushKV("uint256", hash256KeyKeyInput.GetHex());
            }
            else
            {
                vdxfID = CCrossChainRPCData::GetConditionID(vdxfID, vdxfKeyInput, hash256KeyKeyInput, hashInputNum);
                boundData.pushKV("vdxfkey", EncodeDestination(CIdentityID(vdxfKeyInput)));
                boundData.pushKV("uint256", hash256KeyKeyInput.GetHex());
                boundData.pushKV("indexnum", hashInputNum);
            }
        }
    }
    else if (!hashUniValue.isNull() && !numUniValue.isNull())
    {
        isIndexKey = true;
        vdxfID = CCrossChainRPCData::GetConditionID(vdxfID, hash256KeyKeyInput, hashInputNum);
        boundData.pushKV("uint256", hash256KeyKeyInput.GetHex());
        boundData.pushKV("indexnum", hashInputNum);
    }
    else if (!hashUniValue.isNull() && numUniValue.isNull())
    {
        isIndexKey = true;
        vdxfID = CCrossChainRPCData::GetConditionID(vdxfID, hash256KeyKeyInput);
        boundData.pushKV("uint256", hash256KeyKeyInput.GetHex());
    }
    else if (hashUniValue.isNull() && !numUniValue.isNull())
    {
        isIndexKey = true;
        vdxfID = CCrossChainRPCData::GetConditionID(vdxfID, hashInputNum);
        boundData.pushKV("indexnum", hashInputNum);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("vdxfid", EncodeDestination(CIdentityID(vdxfID)));
    if (isIndexKey)
    {
        result.pushKV("indexid", EncodeDestination(CIndexID(vdxfID)));
    }
    result.pushKV("hash160result", vdxfID.GetHex());
    UniValue nameWithParent(UniValue::VOBJ);
    nameWithParent.pushKV(parentIDName, EncodeDestination(CIdentityID(parentID)));
    nameWithParent.pushKV("name", cleanName);
    result.pushKV("qualifiedname", nameWithParent);
    if (boundData.getKeys().size())
    {
        result.pushKV("bounddata", boundData);
    }
    return result;
}

namespace
{
class DestinationEncoder : public boost::static_visitor<std::string>
{
private:
    const CChainParams& m_params;

public:
    DestinationEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const CKeyID& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CPubKey& key) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        CKeyID id = key.GetID();
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CScriptID& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CIdentityID& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::IDENTITY_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CIndexID& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::INDEX_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CQuantumID& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::QUANTUM_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CNoDestination& no) const { return {}; }
};

class DestinationBytes : public boost::static_visitor<std::vector<unsigned char>>
{
public:
    DestinationBytes() {}

    std::vector<unsigned char> operator()(const CKeyID& id) const
    {
        return std::vector<unsigned char>(id.begin(), id.end());
    }

    std::vector<unsigned char> operator()(const CPubKey& key) const
    {
        return std::vector<unsigned char>(key.begin(), key.end());
    }

    std::vector<unsigned char> operator()(const CScriptID& id) const
    {
        return std::vector<unsigned char>(id.begin(), id.end());
    }

    std::vector<unsigned char> operator()(const CIdentityID& id) const
    {
        return std::vector<unsigned char>(id.begin(), id.end());
    }

    std::vector<unsigned char> operator()(const CIndexID& id) const
    {
        return std::vector<unsigned char>(id.begin(), id.end());
    }

    std::vector<unsigned char> operator()(const CQuantumID& id) const
    {
        return std::vector<unsigned char>(id.begin(), id.end());
    }

    std::vector<unsigned char> operator()(const CNoDestination& no) const { return {}; }
};

class DestinationID : public boost::static_visitor<uint160>
{
public:
    DestinationID() {}

    uint160 operator()(const CKeyID& id) const
    {
        return (uint160)id;
    }

    uint160 operator()(const CPubKey& key) const
    {
        return (uint160)key.GetID();
    }

    uint160 operator()(const CScriptID& id) const
    {
        return (uint160)id;
    }

    uint160 operator()(const CIdentityID& id) const
    {
        return (uint160)id;
    }

    uint160 operator()(const CIndexID& id) const
    {
        return (uint160)id;
    }

    uint160 operator()(const CQuantumID& id) const
    {
        return (uint160)id;
    }

    uint160 operator()(const CNoDestination& no) const { return CKeyID(); }
};

CTxDestination DecodeDestination(const std::string& str, const CChainParams& params)
{
    std::vector<unsigned char> data;
    uint160 hash;
    if (DecodeBase58Check(str, data)) {
        // base58-encoded Bitcoin addresses.
        // The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
        const std::vector<unsigned char>& pubkey_prefix = params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        if (data.size() == hash.size() + pubkey_prefix.size() && std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin())) {
            std::copy(data.begin() + pubkey_prefix.size(), data.end(), hash.begin());
            return CKeyID(hash);
        }

        // The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
        const std::vector<unsigned char>& script_prefix = params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        if (data.size() == hash.size() + script_prefix.size() && std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) {
            std::copy(data.begin() + script_prefix.size(), data.end(), hash.begin());
            return CScriptID(hash);
        }

        const std::vector<unsigned char>& identity_prefix = params.Base58Prefix(CChainParams::IDENTITY_ADDRESS);
        if (data.size() == hash.size() + identity_prefix.size() && std::equal(identity_prefix.begin(), identity_prefix.end(), data.begin())) {
            std::copy(data.begin() + identity_prefix.size(), data.end(), hash.begin());
            return CIdentityID(hash);
        }

        const std::vector<unsigned char>& index_prefix = params.Base58Prefix(CChainParams::INDEX_ADDRESS);
        if (data.size() == hash.size() + index_prefix.size() && std::equal(index_prefix.begin(), index_prefix.end(), data.begin())) {
            std::copy(data.begin() + index_prefix.size(), data.end(), hash.begin());
            return CIndexID(hash);
        }

        const std::vector<unsigned char>& quantum_prefix = params.Base58Prefix(CChainParams::QUANTUM_ADDRESS);
        if (data.size() == hash.size() + quantum_prefix.size() && std::equal(quantum_prefix.begin(), quantum_prefix.end(), data.begin())) {
            std::copy(data.begin() + quantum_prefix.size(), data.end(), hash.begin());
            return CQuantumID(hash);
        }
    }
    else if (std::count(str.begin(), str.end(), '@') == 1)
    {
        uint160 parent;
        std::string cleanName = CleanName(str, parent, true, true);
        if (cleanName != "")
        {
            parent.SetNull();
            return CIdentityID(CIdentity::GetID(str, parent));
        }
    }

    return CNoDestination();
}

class PaymentAddressEncoder : public boost::static_visitor<std::string>
{
private:
    const CChainParams& m_params;

public:
    PaymentAddressEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const libzcash::SproutPaymentAddress& zaddr) const
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << zaddr;
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::ZCPAYMENT_ADDRRESS);
        data.insert(data.end(), ss.begin(), ss.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const libzcash::SaplingPaymentAddress& zaddr) const
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << zaddr;
        // ConvertBits requires unsigned char, but CDataStream uses char
        std::vector<unsigned char> seraddr(ss.begin(), ss.end());
        std::vector<unsigned char> data;
        // See calculation comment below
        data.reserve((seraddr.size() * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, seraddr.begin(), seraddr.end());
        return bech32::Encode(m_params.Bech32HRP(CChainParams::SAPLING_PAYMENT_ADDRESS), data);
    }

    std::string operator()(const libzcash::InvalidEncoding& no) const { return {}; }
};

class ViewingKeyEncoder : public boost::static_visitor<std::string>
{
private:
    const CChainParams& m_params;

public:
    ViewingKeyEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const libzcash::SproutViewingKey& vk) const
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << vk;
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::ZCVIEWING_KEY);
        data.insert(data.end(), ss.begin(), ss.end());
        std::string ret = EncodeBase58Check(data);
        memory_cleanse(data.data(), data.size());
        return ret;
    }

    std::string operator()(const libzcash::SaplingExtendedFullViewingKey& extfvk) const
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << extfvk;
        // ConvertBits requires unsigned char, but CDataStream uses char
        std::vector<unsigned char> serkey(ss.begin(), ss.end());
        std::vector<unsigned char> data;
        // See calculation comment below
        data.reserve((serkey.size() * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, serkey.begin(), serkey.end());
        std::string ret = bech32::Encode(m_params.Bech32HRP(CChainParams::SAPLING_EXTENDED_FVK), data);
        memory_cleanse(serkey.data(), serkey.size());
        memory_cleanse(data.data(), data.size());
        return ret;
    }

    std::string operator()(const libzcash::InvalidEncoding& no) const { return {}; }
};

class SpendingKeyEncoder : public boost::static_visitor<std::string>
{
private:
    const CChainParams& m_params;

public:
    SpendingKeyEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const libzcash::SproutSpendingKey& zkey) const
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << zkey;
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::ZCSPENDING_KEY);
        data.insert(data.end(), ss.begin(), ss.end());
        std::string ret = EncodeBase58Check(data);
        memory_cleanse(data.data(), data.size());
        return ret;
    }

    std::string operator()(const libzcash::SaplingExtendedSpendingKey& zkey) const
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << zkey;
        // ConvertBits requires unsigned char, but CDataStream uses char
        std::vector<unsigned char> serkey(ss.begin(), ss.end());
        std::vector<unsigned char> data;
        // See calculation comment below
        data.reserve((serkey.size() * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, serkey.begin(), serkey.end());
        std::string ret = bech32::Encode(m_params.Bech32HRP(CChainParams::SAPLING_EXTENDED_SPEND_KEY), data);
        memory_cleanse(serkey.data(), serkey.size());
        memory_cleanse(data.data(), data.size());
        return ret;
    }

    std::string operator()(const libzcash::InvalidEncoding& no) const { return {}; }
};

// Sizes of SaplingPaymentAddress, SaplingExtendedFullViewingKey, and
// SaplingExtendedSpendingKey after ConvertBits<8, 5, true>(). The calculations
// below take the regular serialized size in bytes, convert to bits, and then
// perform ceiling division to get the number of 5-bit clusters.
const size_t ConvertedSaplingPaymentAddressSize = ((32 + 11) * 8 + 4) / 5;
const size_t ConvertedSaplingExtendedFullViewingKeySize = (ZIP32_XFVK_SIZE * 8 + 4) / 5;
const size_t ConvertedSaplingExtendedSpendingKeySize = (ZIP32_XSK_SIZE * 8 + 4) / 5;
const size_t ConvertedSaplingIncomingViewingKeySize = (32 * 8 + 4) / 5;
} // namespace

CKey DecodeSecret(const std::string& str)
{
    CKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data)) {
        const std::vector<unsigned char>& privkey_prefix = Params().Base58Prefix(CChainParams::SECRET_KEY);
        if ((data.size() == 32 + privkey_prefix.size() || (data.size() == 33 + privkey_prefix.size() && data.back() == 1)) &&
            std::equal(privkey_prefix.begin(), privkey_prefix.end(), data.begin())) {
            bool compressed = data.size() == 33 + privkey_prefix.size();
            key.Set(data.begin() + privkey_prefix.size(), data.begin() + privkey_prefix.size() + 32, compressed);
        }
    }
    else
    {
        // if it's hex and 32 bytes of data, use it as the raw secret
        if (IsHex(str) && str.length() == 64)
        {
            data = ParseHex(str);
            key.Set(data.begin(), data.begin() + 32, true);
        }
    }
    memory_cleanse(data.data(), data.size());
    return key;
}

std::string EncodeSecret(const CKey& key)
{
    assert(key.IsValid());
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::SECRET_KEY);
    data.insert(data.end(), key.begin(), key.end());
    if (key.IsCompressed()) {
        data.push_back(1);
    }
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

CExtPubKey DecodeExtPubKey(const std::string& str)
{
    CExtPubKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    return key;
}

std::string EncodeExtPubKey(const CExtPubKey& key)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    return ret;
}

CExtKey DecodeExtKey(const std::string& str)
{
    CExtKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    return key;
}

std::string EncodeExtKey(const CExtKey& key)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

std::string EncodeDestination(const CTxDestination& dest)
{
    return boost::apply_visitor(DestinationEncoder(Params()), dest);
}

std::vector<unsigned char> GetDestinationBytes(const CTxDestination& dest)
{
    return boost::apply_visitor(DestinationBytes(), dest);
}

uint160 GetDestinationID(const CTxDestination dest)
{
    return boost::apply_visitor(DestinationID(), dest);
}

CTxDestination DecodeDestination(const std::string& str)
{
    return DecodeDestination(str, Params());
}

bool IsValidDestinationString(const std::string& str, const CChainParams& params)
{
    return IsValidDestination(DecodeDestination(str, params));
}

bool IsValidDestinationString(const std::string& str)
{
    return IsValidDestinationString(str, Params());
}

std::string EncodePaymentAddress(const libzcash::PaymentAddress& zaddr)
{
    return boost::apply_visitor(PaymentAddressEncoder(Params()), zaddr);
}

template<typename T1, typename T2, typename T3>
T1 DecodeAny(
    const std::string& str,
    std::pair<CChainParams::Base58Type, size_t> sprout,
    std::pair<CChainParams::Bech32Type, size_t> sapling)
{
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(sprout.first);
        if ((data.size() == sprout.second + prefix.size()) &&
            std::equal(prefix.begin(), prefix.end(), data.begin())) {
            CSerializeData serialized(data.begin() + prefix.size(), data.end());
            CDataStream ss(serialized, SER_NETWORK, PROTOCOL_VERSION);
            T2 ret;
            ss >> ret;
            memory_cleanse(serialized.data(), serialized.size());
            memory_cleanse(data.data(), data.size());
            return ret;
        }
    }

    data.clear();
    auto bech = bech32::Decode(str);
    if (bech.first == Params().Bech32HRP(sapling.first) &&
        bech.second.size() == sapling.second) {
        // Bech32 decoding
        data.reserve((bech.second.size() * 5) / 8);
        if (ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); }, bech.second.begin(), bech.second.end())) {
            CDataStream ss(data, SER_NETWORK, PROTOCOL_VERSION);
            T3 ret;
            ss >> ret;
            memory_cleanse(data.data(), data.size());
            return ret;
        }
    }

    memory_cleanse(data.data(), data.size());
    return libzcash::InvalidEncoding();
}

libzcash::PaymentAddress DecodePaymentAddress(const std::string& str)
{
    return DecodeAny<libzcash::PaymentAddress,
        libzcash::SproutPaymentAddress,
        libzcash::SaplingPaymentAddress>(
            str,
            std::make_pair(CChainParams::ZCPAYMENT_ADDRRESS, libzcash::SerializedSproutPaymentAddressSize),
            std::make_pair(CChainParams::SAPLING_PAYMENT_ADDRESS, ConvertedSaplingPaymentAddressSize)
        );
}

bool IsValidPaymentAddressString(const std::string& str) {
    return IsValidPaymentAddress(DecodePaymentAddress(str));
}

std::string EncodeViewingKey(const libzcash::ViewingKey& vk)
{
    return boost::apply_visitor(ViewingKeyEncoder(Params()), vk);
}

libzcash::ViewingKey DecodeViewingKey(const std::string& str)
{
    return DecodeAny<libzcash::ViewingKey,
        libzcash::SproutViewingKey,
        libzcash::SaplingExtendedFullViewingKey>(
            str,
            std::make_pair(CChainParams::ZCVIEWING_KEY, libzcash::SerializedSproutViewingKeySize),
            std::make_pair(CChainParams::SAPLING_EXTENDED_FVK, ConvertedSaplingExtendedFullViewingKeySize)
        );
}

std::string EncodeSpendingKey(const libzcash::SpendingKey& zkey)
{
    return boost::apply_visitor(SpendingKeyEncoder(Params()), zkey);
}

libzcash::SpendingKey DecodeSpendingKey(const std::string& str)
{

    return DecodeAny<libzcash::SpendingKey,
        libzcash::SproutSpendingKey,
        libzcash::SaplingExtendedSpendingKey>(
            str,
            std::make_pair(CChainParams::ZCSPENDING_KEY, libzcash::SerializedSproutSpendingKeySize),
            std::make_pair(CChainParams::SAPLING_EXTENDED_SPEND_KEY, ConvertedSaplingExtendedSpendingKeySize)
        );
}

CProofRoot::CProofRoot(const UniValue &uni) :
    version(VERSION_CURRENT),
    type(TYPE_PBAAS),
    rootHeight(0)
{
    if (uni.isNull())
    {
        version = VERSION_INVALID;
        return;
    }
    version = (uint32_t)uni_get_int(find_value(uni, "version"));
    type = (uint32_t)uni_get_int(find_value(uni, "type"));
    systemID = GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "systemid"))));
    rootHeight = (uint32_t)uni_get_int(find_value(uni, "height"));
    stateRoot = uint256S(uni_get_str(find_value(uni, "stateroot")));
    blockHash = uint256S(uni_get_str(find_value(uni, "blockhash")));
    compactPower = uint256S(uni_get_str(find_value(uni, "power")));
    if (type == TYPE_ETHEREUM)
    {
        gasPrice = AmountFromValueNoErr(find_value(uni, "gasprice"));
    }
}

UniValue CProofRoot::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int64_t)version));
    obj.push_back(Pair("type", (int64_t)type));
    obj.push_back(Pair("systemid", EncodeDestination(CIdentityID(systemID))));
    obj.push_back(Pair("height", (int64_t)rootHeight));
    obj.push_back(Pair("stateroot", stateRoot.GetHex()));
    obj.push_back(Pair("blockhash", blockHash.GetHex()));
    obj.push_back(Pair("power", compactPower.GetHex()));
    if (type == TYPE_ETHEREUM)
    {
        obj.push_back(Pair("gasprice", ValueFromAmount(gasPrice)));
    }
    return obj;
}

CTokenOutput::CTokenOutput(const UniValue &obj)
{
    nVersion = (uint32_t)uni_get_int(find_value(obj, "version"), VERSION_CURRENT);
    UniValue values = find_value(obj, "currencyvalues");
    if (values.isObject())
    {
        reserveValues = CCurrencyValueMap(values);
    }
}

CReserveTransfer::CReserveTransfer(const UniValue &uni) : CTokenOutput(uni), nFees(0)
{
    flags = uni_get_int64(find_value(uni, "flags"), 0);
    feeCurrencyID = GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "feecurrencyid"))));
    nFees = AmountFromValueNoErr(find_value(uni, "fees"));

    if (IsReserveToReserve())
    {
        secondReserveID = GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "destinationcurrencyid"))));
        destCurrencyID = GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "via"))));
    }
    else
    {
        destCurrencyID = GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "destinationcurrencyid"))));
    }
    if (IsCrossSystem())
    {
        destSystemID = GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "exportto"))));
    }
    destination = CTransferDestination(find_value(uni, "destination"));
}

CReserveTransfer::CReserveTransfer(const CScript &script) : flags(0)
{
    COptCCParams p;
    if (script.IsPayToCryptoCondition(p) && p.IsValid())
    {
        if (p.evalCode == EVAL_RESERVE_TRANSFER && p.vData.size())
        {
            FromVector(p.vData[0], *this);
        }
    }
}

CPrincipal::CPrincipal(const UniValue &uni)
{
    nVersion = uni_get_int(find_value(uni, "version"), VERSION_VAULT);
    flags = uni_get_int(find_value(uni, "flags"));
    UniValue primaryAddressesUni = find_value(uni, "primaryaddresses");
    if (primaryAddressesUni.isArray())
    {
        for (int i = 0; i < primaryAddressesUni.size(); i++)
        {
            try
            {
                CTxDestination dest = DecodeDestination(uni_get_str(primaryAddressesUni[i]));
                if (dest.which() == COptCCParams::ADDRTYPE_PK || dest.which() == COptCCParams::ADDRTYPE_PKH)
                {
                    primaryAddresses.push_back(dest);
                }
            }
            catch (const std::exception &e)
            {
                LogPrintf("%s: bad address %s\n", __func__, primaryAddressesUni[i].write().c_str());
                nVersion = VERSION_INVALID;
            }
        }
    }

    minSigs = uni_get_int(find_value(uni, "minimumsignatures"));
}

uint160 ParseVDXFKey(const std::string &keyString)
{
    uint160 nameSpaceID;

    if (keyString.empty())
    {
        return uint160();
    }

    CTxDestination keyDest;
    if ((keyDest = DecodeDestination(keyString)).which() == COptCCParams::ADDRTYPE_ID)
    {
        return GetDestinationID(keyDest);
    }

    UniValue jsonKey(UniValue::VOBJ);
    if (!jsonKey.read(keyString))
    {
        uint160 nameSpaceID;
        uint160 simpleVDXFKey = CVDXF::GetDataKey(keyString, nameSpaceID);
        if (!simpleVDXFKey.IsNull())
        {
            return simpleVDXFKey;
        }
        LogPrint("contentmap", "%s: invalid key, neither i-address nor json vdxfid: %s\n", __func__, keyString.c_str());
        return uint160();
    }
    UniValue parms(UniValue::VARR);

    std::string vdxfUri = uni_get_str(find_value(jsonKey, "vdxfuri"));
    if (vdxfUri.empty())
    {
        LogPrint("contentmap", "%s: invalid key, no vdxfuri: %s\n", __func__, jsonKey.write(1,2).c_str());
        return uint160();
    }

    parms.push_back(vdxfUri);

    auto vdxfKeyKeys = jsonKey.getKeys();
    auto &vdxfValues = jsonKey.getValues();
    if (vdxfKeyKeys.size() > 1)
    {
        UniValue vdxfObjParms(UniValue::VOBJ);
        for (int j = 0; j < vdxfKeyKeys.size(); j++)
        {
            if (vdxfKeyKeys[j] != "vdxfuri")
            {
                vdxfObjParms.pushKV(vdxfKeyKeys[j], vdxfValues[j]);
            }
        }
        parms.push_back(vdxfObjParms);
    }

    jsonKey = getvdxfid_internal(parms);
    std::string vdxfKeyStr = uni_get_str(find_value(jsonKey, "vdxfid"));
    return vdxfKeyStr.empty() ? uint160() : GetDestinationID(DecodeDestination(vdxfKeyStr));
}

CRating::CRating(const UniValue uni) :
    version(VERSION_CURRENT),
    trustLevel(TRUST_UNKNOWN)
{
    version = uni_get_int64(find_value(uni, "version"), version);
    trustLevel = uni_get_int(find_value(uni, "trustlevel"), trustLevel);
    UniValue ratingsObj = find_value(uni, "ratingsmap");
    if (ratingsObj.isObject())
    {
        auto keys = ratingsObj.getKeys();
        auto values = ratingsObj.getValues();

        for (int i = 0; i < keys.size(); i++)
        {
            uint160 vdxfKey = ParseVDXFKey(keys[i]);
            if (vdxfKey.IsNull())
            {
                LogPrint("ratings", "%s: invalid json rating key: %s\n", __func__, keys[i].c_str());
                version = VERSION_INVALID;
                return;
            }

            const std::multimap<uint160, std::vector<std::string>> &ratingMap = GetRatingDefinitionMap();
            std::vector<unsigned char> oneRatingVec;

            auto it = ratingMap.find(vdxfKey);
            if (it != ratingMap.end() && !(values[i].isStr() && IsHex(uni_get_str(values[i]))))
            {
                std::map<std::string, int> ratingKeyMap;
                for (int j = 0; j < it->second.size(); j++)
                {
                    ratingKeyMap.insert(std::make_pair(it->second[j], j));
                }
                // if one rating, store it in an array anyhow
                UniValue oneValueArr = values[i].isArray() ? values[i] : UniValue(UniValue::VARR);
                if (values[i].isStr())
                {
                    oneValueArr.push_back(values[i]);
                }
                for (int j = 0; j < oneValueArr.size(); j++)
                {
                    std::string oneRatingStr = uni_get_str(oneValueArr[j]);
                    auto ratingIt = ratingKeyMap.find(oneRatingStr);
                    if (ratingIt == ratingKeyMap.end())
                    {
                        LogPrint("ratings", "%s: invalid rating keyword: %s\n", __func__, oneRatingStr.c_str());
                        version = VERSION_INVALID;
                        return;
                    }
                    else
                    {
                        oneRatingVec.push_back((uint8_t)ratingIt->second);
                    }
                }
            }
            else if (values[i].isStr() && IsHex(uni_get_str(values[i])))
            {
                oneRatingVec = ParseHex(uni_get_str(values[i]));
            }
            else
            {
                LogPrint("ratings", "%s: invalid rating in key: %s\n", __func__, keys[i].c_str());
                version = VERSION_INVALID;
                return;
            }

            ratings[vdxfKey] = oneRatingVec;
        }
    }
}

CCredential::CCredential(const UniValue uni) : 
    version(uni_get_int64(find_value(uni, "version"))),
    flags(uni_get_int64(find_value(uni, "flags"))),
    credentialKey(GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "credentialkey"))))),
    credential(find_value(uni, "credential")),
    scopes(find_value(uni, "scopes")),
    label(TrimSpaces(uni_get_str(find_value(uni, "label")), true, ""))
{
    SetFlags();
}

std::vector<unsigned char> VectorEncodeVDXFUni(const UniValue &_obj)
{
    CDataStream ss(PROTOCOL_VERSION, SER_DISK);

    UniValue obj = _obj;

    if (!obj.isObject())
    {
        std::string objStr = uni_get_str(obj);
        if (IsHex(objStr))
        {
            return ParseHex(objStr);
        }
        return std::vector<unsigned char>(objStr.begin(), objStr.end());
    }

    std::string serializedHex = uni_get_str(find_value(obj, "serializedhex"));
    if (!serializedHex.empty())
    {
        if (!IsHex(serializedHex))
        {
            LogPrint("contentmap", "%s: if the \"serializedhex\" key is present, it's data must be only valid hex and complete: %s\n", __func__, serializedHex.c_str());
            return std::vector<unsigned char>();
        }
        return ParseHex(serializedHex);
    }
    std::string serializedBase64 = uni_get_str(find_value(obj, "serializedbase64"));
    if (!serializedBase64.empty())
    {
        bool isValid = false;
        auto retVec = DecodeBase64(serializedBase64.c_str(), &isValid);
        return isValid ? retVec : std::vector<unsigned char>();
    }
    std::string serializedMessage = uni_get_str(find_value(obj, "message"));
    if (!serializedMessage.empty())
    {
        return std::vector<unsigned char>(serializedMessage.begin(), serializedMessage.end());
    }

    // this should be an object with "vdxfkey" as the key and {object} as the json object to serialize
    auto oneValKeys = obj.getKeys();
    auto oneValValues = obj.getValues();

    // TODO: change if / else to a map lookup

    for (int k = 0; k < oneValKeys.size(); k++)
    {
        uint160 objTypeKey = ParseVDXFKey(oneValKeys[k]);
        if (objTypeKey == CVDXF_Data::DataByteKey())
        {
            uint8_t oneByte = uni_get_int(oneValValues[k]);
            ss << oneByte;
        }
        else if (objTypeKey == CVDXF_Data::DataInt16Key())
        {
            int16_t oneShort = uni_get_int(oneValValues[k]);
            ss << oneShort;
        }
        else if (objTypeKey == CVDXF_Data::DataUint16Key())
        {
            uint16_t oneUShort = uni_get_int(oneValValues[k]);
            ss << oneUShort;
        }
        else if (objTypeKey == CVDXF_Data::DataInt32Key())
        {
            int32_t oneInt = uni_get_int(oneValValues[k]);
            ss << oneInt;
        }
        else if (objTypeKey == CVDXF_Data::DataUint32Key())
        {
            uint32_t oneUInt = uni_get_int64(oneValValues[k]);
            ss << oneUInt;
        }
        else if (objTypeKey == CVDXF_Data::DataInt64Key())
        {
            int64_t oneInt64 = uni_get_int64(oneValValues[k]);
            ss << oneInt64;
        }
        else if (objTypeKey == CVDXF_Data::DataUint160Key())
        {
            uint160 oneKey = GetDestinationID(DecodeDestination(uni_get_str(oneValValues[k])));
            ss << oneKey;
        }
        else if (objTypeKey == CVDXF_Data::DataUint256Key())
        {
            uint256 oneHash = uint256S(uni_get_str(oneValValues[k]));
            ss << oneHash;
        }
        else if (objTypeKey == CVDXF_Data::DataStringKey())
        {
            ss << objTypeKey;
            ss << VARINT(1);
            std::string stringVal = uni_get_str(oneValValues[k]);
            ss << COMPACTSIZE((uint64_t)GetSerializeSize(ss, stringVal));
            ss << stringVal;
        }
        else if (objTypeKey == CVDXF_Data::DataByteVectorKey())
        {
            ss << objTypeKey;
            ss << VARINT(1);
            std::vector<unsigned char> byteVec = ParseHex(uni_get_str(oneValValues[k]));
            ss << COMPACTSIZE((uint64_t)GetSerializeSize(ss, byteVec));
            ss << byteVec;
        }
        else if (objTypeKey == CVDXF_Data::DataCurrencyMapKey())
        {
            CCurrencyValueMap oneCurMap(oneValValues[k]);
            ss << objTypeKey;
            ss << VARINT(1);
            ss << COMPACTSIZE((uint64_t)GetSerializeSize(ss, oneCurMap));
            ss << oneCurMap;
        }
        else if (objTypeKey == CVDXF_Data::DataRatingsKey())
        {
            CRating oneRatingObj(oneValValues[k]);
            ss << objTypeKey;
            ss << VARINT(oneRatingObj.version);
            ss << COMPACTSIZE((uint64_t)GetSerializeSize(ss, oneRatingObj));
            ss << oneRatingObj;
        }
        else if (objTypeKey == CVDXF_Data::DataCredentialKey())
        {
            CCredential oneCredentialObj(oneValValues[k]);
            ss << objTypeKey;
            ss << VARINT(oneCredentialObj.version);
            ss << COMPACTSIZE((uint64_t)GetSerializeSize(ss, oneCredentialObj));
            ss << oneCredentialObj;
        }
        else if (objTypeKey == CVDXF_Data::DataTransferDestinationKey())
        {
            CTransferDestination oneTransferDest(oneValValues[k]);
            ss << objTypeKey;
            ss << VARINT(oneTransferDest.TypeNoFlags());
            ss << COMPACTSIZE((uint64_t)GetSerializeSize(ss, oneTransferDest));
            ss << oneTransferDest;
        }
        else if (objTypeKey == CVDXF_Data::ContentMultiMapRemoveKey())
        {
            CContentMultiMapRemove contentRemove(oneValValues[k]);
            ss << objTypeKey;
            ss << VARINT(contentRemove.version);
            ss << COMPACTSIZE((uint64_t)GetSerializeSize(ss, contentRemove));
            ss << contentRemove;
        }
        else if (objTypeKey == CVDXF_Data::CrossChainDataRefKey())
        {
            CCrossChainDataRef dataRef(oneValValues[k]);
            ss << objTypeKey;
            ss << VARINT((int32_t)CVDXF_Data::DEFAULT_VERSION);
            ss << COMPACTSIZE((uint64_t)GetSerializeSize(ss, dataRef));
            ss << dataRef;
        }
        else if (objTypeKey == CVDXF_Data::DataDescriptorKey())
        {
            CDataDescriptor descr(oneValValues[k]);
            ss << objTypeKey;
            ss << VARINT(descr.version);
            ss << COMPACTSIZE((uint64_t)GetSerializeSize(ss, descr));
            ss << descr;
        }
        else if (objTypeKey == CVDXF_Data::MMRDescriptorKey())
        {
            CMMRDescriptor descr(oneValValues[k]);
            ss << objTypeKey;
            ss << VARINT(descr.version);
            ss << COMPACTSIZE((uint64_t)GetSerializeSize(ss, descr));
            ss << descr;
        }
        else if (objTypeKey == CVDXF_Data::SignatureDataKey())
        {
            CSignatureData sigData(oneValValues[k]);
            ss << objTypeKey;
            ss << VARINT(sigData.version);
            ss << COMPACTSIZE((uint64_t)GetSerializeSize(ss, sigData));
            ss << sigData;
        }
        else
        {
            LogPrint("contentmap", "%s: invalid or unrecognized vdxfkey for object type: %s\n", __func__, EncodeDestination(CIdentityID(objTypeKey)).c_str());
            return std::vector<unsigned char>();
        }
    }
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

CIdentity::CIdentity(const UniValue &uni) : CPrincipal(uni)
{
    UniValue parentUni = find_value(uni, "parent");
    std::string parentStr = uni_get_str(parentUni);
    if (!parentStr.empty())
    {
        CTxDestination parentDest = DecodeDestination(parentStr);
        parent = GetDestinationID(parentDest);
        if (parent.IsNull() && parentStr.back() != '@' && parentDest.which() != COptCCParams::ADDRTYPE_ID)
        {
            parent = GetDestinationID(DecodeDestination(parentStr + "@"));
        }
    }
    name = CleanName(uni_get_str(find_value(uni, "name")), parent);

    if (parent.IsNull())
    {
        // if either:
        // 1. we have an explicitly null parent or
        // 2. with one name and a null parent, we have the verus chain ID, assume we have a null parent
        // otherwise, default our current chain as the parent of a null-parented ID
        parent = (!parentUni.isNull() || GetID() == VERUS_CHAINID) ? uint160() : ASSETCHAINS_CHAINID;
    }

    if (nVersion >= VERSION_VAULT)
    {
        systemID = DecodeCurrencyName(uni_get_str(find_value(uni, "systemid")));
        if (systemID.IsNull())
        {
            systemID = parent.IsNull() ? GetID() : parent;
        }
    }
    else
    {
        systemID = parent.IsNull() ? GetID() : parent;
    }

    UniValue hashesUni = find_value(uni, "contentmap");
    if (hashesUni.isObject())
    {
        std::vector<std::string> keys = hashesUni.getKeys();
        std::vector<UniValue> values = hashesUni.getValues();
        for (int i = 0; i < keys.size(); i++)
        {
            try
            {
                uint160 key;
                key.SetHex(keys[i]);
                if (!key.IsNull() && i < values.size())
                {
                    contentMap[key] = uint256S(uni_get_str(values[i]));
                }
                else
                {
                    nVersion = VERSION_INVALID;
                }
            }
            catch (const std::exception &e)
            {
                nVersion = VERSION_INVALID;
            }
            if (nVersion == VERSION_INVALID)
            {
                LogPrintf("%s: contentmap entry is not valid keys: %s, values: %s\n", __func__, keys[i].c_str(), values[i].write().c_str());
                break;
            }
        }
    }

    if (nVersion >= VERSION_PBAAS)
    {
        UniValue multiMapUni = find_value(uni, "contentmultimap");
        if (multiMapUni.isObject())
        {
            std::vector<std::string> keys = multiMapUni.getKeys();
            std::vector<UniValue> values = multiMapUni.getValues();
            for (int i = 0; i < keys.size(); i++)
            {
                try
                {
                    uint160 key = ParseVDXFKey(keys[i]);

                    if (!key.IsNull() &&
                        i < values.size())
                    {
                        if (values[i].isArray())
                        {
                            for (int j = 0; j < values[i].size(); j++)
                            {
                                UniValue oneValue = values[i][j];
                                std::string valueString;
                                if (oneValue.isStr() && IsHex(valueString = uni_get_str(oneValue)))
                                {
                                    std::vector<unsigned char> rawBytes = ParseHex(valueString);
                                    if (key == CVDXF_Data::ContentMultiMapRemoveKey())
                                    {
                                        try
                                        {
                                            CDataStream ss(rawBytes, PROTOCOL_VERSION, SER_DISK);
                                            uint160 objTypeKey;
                                            uint32_t serVersion;
                                            size_t serSize;
                                            CContentMultiMapRemove removeAction;
                                            ss >> objTypeKey;
                                            ss >> VARINT(serVersion);
                                            ss >> VARINT(serSize);
                                            ss >> removeAction;
                                            if (objTypeKey != CVDXF_Data::ContentMultiMapRemoveKey() || !removeAction.IsValid())
                                            {
                                                nVersion = VERSION_INVALID;
                                                break;
                                            }
                                        }
                                        catch (const std::exception &)
                                        {
                                            nVersion = VERSION_INVALID;
                                            break;
                                        }
                                    }
                                    contentMultiMap.insert(std::make_pair(key, rawBytes));
                                }
                                else if (oneValue.isObject())
                                {
                                    std::vector<unsigned char> mapBytesValue = VectorEncodeVDXFUni(oneValue);
                                    if (!mapBytesValue.size() || nVersion == VERSION_INVALID)
                                    {
                                        nVersion = VERSION_INVALID;
                                        break;
                                    }
                                    contentMultiMap.insert(std::make_pair(key, mapBytesValue));
                                }
                            }
                        }
                        else if (values[i].isStr())
                        {
                            std::string valueString;
                            if (IsHex(valueString = uni_get_str(values[i])))
                            {
                                std::vector<unsigned char> rawBytes = ParseHex(valueString);
                                if (key == CVDXF_Data::ContentMultiMapRemoveKey())
                                {
                                    try
                                    {
                                        CDataStream ss(rawBytes, PROTOCOL_VERSION, SER_DISK);
                                        uint160 objTypeKey;
                                        uint32_t serVersion;
                                        size_t serSize;
                                        CContentMultiMapRemove removeAction;
                                        ss >> objTypeKey;
                                        ss >> VARINT(serVersion);
                                        ss >> VARINT(serSize);
                                        ss >> removeAction;
                                        if (objTypeKey != CVDXF_Data::ContentMultiMapRemoveKey() || !removeAction.IsValid())
                                        {
                                            nVersion = VERSION_INVALID;
                                            break;
                                        }
                                    }
                                    catch (const std::exception &)
                                    {
                                        nVersion = VERSION_INVALID;
                                        break;
                                    }
                                }
                                contentMultiMap.insert(std::make_pair(key, rawBytes));
                            }
                            else
                            {
                                nVersion = VERSION_INVALID;
                                break;
                            }
                        }
                        else if (values[i].isObject())
                        {
                            std::vector<unsigned char> mapBytesValue = VectorEncodeVDXFUni(values[i]);
                            if (!mapBytesValue.size() || nVersion == VERSION_INVALID)
                            {
                                nVersion = VERSION_INVALID;
                                break;
                            }
                            contentMultiMap.insert(std::make_pair(key, mapBytesValue));
                        }
                        else
                        {
                            nVersion = VERSION_INVALID;
                            break;
                        }
                    }
                    else
                    {
                        nVersion = VERSION_INVALID;
                        break;
                    }
                }
                catch (const std::exception &e)
                {
                    nVersion = VERSION_INVALID;
                }
                if (nVersion == VERSION_INVALID)
                {
                    LogPrint("contentmap", "%s: contentmultimap entry is not valid keys: %s, values: %s\n", __func__, keys[i].c_str(), values[i].write().c_str());
                    break;
                }
            }
        }
    }

    std::string revocationStr = uni_get_str(find_value(uni, "revocationauthority"));
    std::string recoveryStr = uni_get_str(find_value(uni, "recoveryauthority"));

    CTxDestination revocationDest = DecodeDestination(revocationStr);
    CTxDestination recoveryDest = DecodeDestination(recoveryStr);
    if ((revocationStr != "" && revocationDest.which() != COptCCParams::ADDRTYPE_ID) ||
        (recoveryStr != "" && recoveryDest.which() != COptCCParams::ADDRTYPE_ID))
    {
        nVersion = VERSION_INVALID;
    }

    revocationAuthority = revocationStr == "" ? GetID() : uint160(GetDestinationID(revocationDest));
    recoveryAuthority = recoveryStr == "" ? GetID() : uint160(GetDestinationID(recoveryDest));
    libzcash::PaymentAddress pa = DecodePaymentAddress(uni_get_str(find_value(uni, "privateaddress")));

    unlockAfter = uni_get_int(find_value(uni, "timelock"));

    if (revocationAuthority.IsNull() || recoveryAuthority.IsNull())
    {
        LogPrintf("%s: invalid address\n", __func__);
        nVersion = VERSION_INVALID;
    }
    else if (boost::get<libzcash::SaplingPaymentAddress>(&pa) != nullptr)
    {
        privateAddresses.push_back(*boost::get<libzcash::SaplingPaymentAddress>(&pa));
    }
}

CETHNFTAddress::CETHNFTAddress(const UniValue &uni)
{
    std::string contractAddrStr = uni_get_str(find_value(uni, "contract"));
    std::string TokenIDStr = uni_get_str(find_value(uni, "tokenid"));

    if (!(contractID = CTransferDestination::DecodeEthDestination(contractAddrStr)).IsNull() &&
        TokenIDStr.length() == 66 &&
        TokenIDStr.substr(0,2) == "0x" &&
        IsHex(TokenIDStr.substr(2,64)))
    {
        tokenID = uint256(ParseHex(TokenIDStr.substr(2,64)));
    }
}

CTransferDestination::CTransferDestination(const UniValue &obj) : fees(0)
{
    type = uni_get_int(find_value(obj, "type"));

    switch (TypeNoFlags())
    {
        case CTransferDestination::DEST_PKH:
        case CTransferDestination::DEST_SH:
        case CTransferDestination::DEST_ID:
        case CTransferDestination::DEST_QUANTUM:
        {
            CTxDestination checkDest = DecodeDestination(uni_get_str(find_value(obj, "address")));
            if (checkDest.which() != COptCCParams::ADDRTYPE_INVALID)
            {
                destination = GetDestinationBytes(checkDest);
            }
            else
            {
                type = DEST_INVALID;
            }
            break;
        }

        case CTransferDestination::DEST_PK:
        {
            std::string pkStr = uni_get_str(find_value(obj, "address"));
            destination = ParseHex(pkStr);
            break;
        }

        case CTransferDestination::DEST_ETH:
        {
            uint160 ethDestID = DecodeEthDestination(uni_get_str(find_value(obj, "address")));
            destination = ::AsVector(ethDestID);
            break;
        }

        case CTransferDestination::DEST_ETHNFT:
        {
            CETHNFTAddress ethNFTAddress(find_value(obj, "address"));
            destination = ::AsVector(ethNFTAddress);
            break;
        }

        case CTransferDestination::DEST_FULLID:
        {
            std::string serializedHex(uni_get_str(find_value(obj, "serializeddata")));
            CIdentity destID;
            if (serializedHex.size() && IsHex(serializedHex))
            {
                try
                {
                    ::FromVector(ParseHex(serializedHex), destID);
                }
                catch(...)
                {
                    destID = CIdentity();
                }
                // DEBUG ONLY
                auto checkVec = ::AsVector(CIdentity(find_value(obj, "identity")));
                std::string checkString(HexBytes(&(checkVec[0]), checkVec.size()));
                if (checkString != serializedHex)
                {
                    CIdentity checkID;
                    try
                    {
                        ::FromVector(ParseHex(checkString), checkID);
                    }
                    catch(...)
                    {
                        checkID = CIdentity();
                    }
                    printf("%s: mismatch check in serialized identity vs. JSON identity\nserializedHex: \"%s\"\nsourceID: \"%s\"\ncheckString: \"%s\"\ncheckID: \"%s\"\n",
                           __func__, serializedHex.c_str(), destID.ToUniValue().write(1,2).c_str(), checkString.c_str(), checkID.ToUniValue().write(1,2).c_str());
                }
                // END DEBUG */
            }
            else
            {
                destID = CIdentity(find_value(obj, "identity"));
            }
            if (destID.IsValid())
            {
                destination = ::AsVector(destID);
            }
            else
            {
                type = DEST_INVALID;
            }
            break;
        }

        case CTransferDestination::DEST_REGISTERCURRENCY:
        {
            std::string serializedHex(uni_get_str(find_value(obj, "serializeddata")));
            CCurrencyDefinition currencyToRegister;
            if (serializedHex.size() && IsHex(serializedHex))
            {
                try
                {
                    ::FromVector(ParseHex(serializedHex), currencyToRegister);
                }
                catch(...)
                {
                    currencyToRegister = CCurrencyDefinition();
                }
                // DEBUG ONLY
                auto checkVec = ::AsVector(CCurrencyDefinition(find_value(obj, "currency")));
                std::string checkString(HexBytes(&(checkVec[0]), checkVec.size()));
                if (checkString != serializedHex)
                {
                    CCurrencyDefinition checkCur;
                    try
                    {
                        ::FromVector(ParseHex(checkString), checkCur);
                    }
                    catch(...)
                    {
                        checkCur = CCurrencyDefinition();
                    }
                    printf("%s: mismatch check in serialized currency vs. JSON currency\nserializedHex: \"%s\"\nsourceID: \"%s\"\ncheckString: \"%s\"\nprocessedID: \"%s\"\n",
                           __func__, serializedHex.c_str(), currencyToRegister.ToUniValue().write(1,2).c_str(), checkString.c_str(), checkCur.ToUniValue().write(1,2).c_str());
                }
                // END DEBUG */
            }
            else
            {
                currencyToRegister = CCurrencyDefinition(find_value(obj, "currency"));
            }
            if (currencyToRegister.IsValid())
            {
                destination = ::AsVector(currencyToRegister);
            }
            else
            {
                type = DEST_INVALID;
            }
            break;
        }

        case CTransferDestination::DEST_RAW:
        {
            std::string rawStr = uni_get_str(find_value(obj, "address"));
            destination = ParseHex(rawStr);
            break;
        }

        case CTransferDestination::DEST_NESTEDTRANSFER:
        {
            CReserveTransfer nestedTransfer = CReserveTransfer(find_value(obj, "nestedtransfer"));
            destination = ::AsVector(nestedTransfer);
            break;
        }
    }

    UniValue auxDestArr = find_value(obj, "auxdests");
    if ((type & FLAG_DEST_AUX) && auxDestArr.isArray() && auxDestArr.size())
    {
        for (int i = 0; i < auxDestArr.size(); i++)
        {
            CTransferDestination oneAuxDest(auxDestArr[i]);
            if (!oneAuxDest.IsValid() || oneAuxDest.type & FLAG_DEST_AUX)
            {
                type = DEST_INVALID;
                break;
            }
            auxDests.push_back(::AsVector(oneAuxDest));
        }
    }
    else
    {
        type &= ~FLAG_DEST_AUX;
    }

    if (type & FLAG_DEST_GATEWAY)
    {
        gatewayID = GetDestinationID(DecodeDestination(uni_get_str(find_value(obj, "gateway"))));
        fees = AmountFromValueNoErr(find_value(obj, "fees"));
    }
}

uint160 CCrossChainRPCData::GetConditionID(const uint160 &cid, uint32_t condition)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 CCrossChainRPCData::GetConditionID(const uint160 &cid, const uint160 &condition)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 CCrossChainRPCData::GetConditionID(const uint160 &cid, const uint160 &condition, const uint256 &txid, int32_t voutNum)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    hw << txid;
    hw << voutNum;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 CCrossChainRPCData::GetConditionID(const uint160 &cid, const uint256 &txid, int32_t voutNum)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << cid;
    hw << txid;
    hw << voutNum;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 CCrossChainRPCData::GetConditionID(const uint160 &cid, const uint256 &txid)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << cid;
    hw << txid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 CCrossChainRPCData::GetConditionID(const uint160 &cid, const uint160 &condition, const uint256 &txid)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    hw << txid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 CCrossChainRPCData::GetConditionID(std::string name, uint32_t condition)
{
    uint160 parent;
    uint160 cid = CIdentity::GetID(name, parent);

    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

UniValue CNotaryEvidence::ToUniValue() const
{
    UniValue retObj(UniValue::VOBJ);
    retObj.push_back(Pair("version", version));
    retObj.push_back(Pair("type", type));
    retObj.push_back(Pair("systemid", EncodeDestination(CIdentityID(systemID))));
    retObj.push_back(Pair("output", output.ToUniValue()));
    retObj.push_back(Pair("state", (int)state));
    retObj.push_back(Pair("evidence", evidence.ToUniValue()));
    return retObj;
}

CNotarySignature::CNotarySignature(const UniValue &uniObj) : confirmed(false)
{
    version = uni_get_int64(find_value(uniObj, "version"), VERSION_CURRENT);
    systemID = DecodeCurrencyName(uni_get_str(find_value(uniObj, "systemid")));
    output = CUTXORef(find_value(uniObj, "output"));
    confirmed = uni_get_bool(find_value(uniObj, "confirmed"));
    UniValue sigsObj = find_value(uniObj, "signatures");
    auto keys = sigsObj.getKeys();
    auto values = sigsObj.getValues();
    for (int i = 0; i < keys.size(); i++)
    {
        CTxDestination idDest = DecodeDestination(keys[i]);
        if (idDest.which() != COptCCParams::ADDRTYPE_ID)
        {
            version = VERSION_INVALID;
            break;
        }
        CIdentitySignature oneSig(values[i]);
        if (!oneSig.IsValid())
        {
            version = VERSION_INVALID;
            break;
        }
        signatures[CIdentityID(GetDestinationID(idDest))] = oneSig;
    }
}

UniValue CNotarySignature::ToUniValue() const
{
    UniValue retObj(UniValue::VOBJ);
    retObj.push_back(Pair("version", version));
    retObj.push_back(Pair("systemid", EncodeDestination(CIdentityID(systemID))));
    retObj.push_back(Pair("output", output.ToUniValue()));
    retObj.push_back(Pair("confirmed", confirmed));
    UniValue sigObj(UniValue::VOBJ);
    for (auto &oneSig : signatures)
    {
        sigObj.push_back(Pair(EncodeDestination(CIdentityID(oneSig.first)), oneSig.second.ToUniValue()));
    }
    retObj.push_back(Pair("signatures", sigObj));
    return retObj;
}

// this will add the current Verus chain name to subnames if it is not present
// on both id and chain names
std::vector<std::string> ParseSubNames(const std::string &Name, std::string &ChainOut, bool displayfilter, bool addVerus)
{
    return CVDXF::ParseSubNames(Name, ChainOut, displayfilter, addVerus);
}

// takes a multipart name, either complete or partially processed with a Parent hash,
// hash its parent names into a parent ID and return the parent hash and cleaned, single name
std::string CleanName(const std::string &Name, uint160 &Parent, bool displayfilter, bool addVerus)
{
    addVerus = addVerus && Parent.IsNull();

    std::string chainName;
    std::vector<std::string> subNames = ParseSubNames(Name, chainName, displayfilter, addVerus);

    if (!subNames.size())
    {
        return "";
    }

    if (!Parent.IsNull() &&
        subNames.size() > 1 &&
        boost::to_lower_copy(subNames.back()) == boost::to_lower_copy(VERUS_CHAINNAME))
    {
        subNames.pop_back();
    }

    for (int i = subNames.size() - 1; i > 0; i--)
    {
        std::string parentNameStr = boost::algorithm::to_lower_copy(subNames[i]);
        const char *parentName = parentNameStr.c_str();
        uint256 idHash;

        if (Parent.IsNull())
        {
            idHash = Hash(parentName, parentName + parentNameStr.size());
        }
        else
        {
            idHash = Hash(parentName, parentName + strlen(parentName));
            idHash = Hash(Parent.begin(), Parent.end(), idHash.begin(), idHash.end());
        }
        Parent = Hash160(idHash.begin(), idHash.end());
        //printf("uint160 for parent %s: %s\n", parentName, Parent.GetHex().c_str());
    }
    return subNames[0];
}

CNameReservation::CNameReservation(const CTransaction &tx, int *pOutNum)
{
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (IsPayToCryptoCondition(tx.vout[i].scriptPubKey, p))
        {
            if (p.evalCode == EVAL_IDENTITY_RESERVATION)
            {
                FromVector(p.vData[0], *this);
                return;
            }
        }
    }
}

CIdentity::CIdentity(const CScript &scriptPubKey)
{
    COptCCParams p;
    if (IsPayToCryptoCondition(scriptPubKey, p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_PRIMARY && p.vData.size())
    {
        *this = CIdentity(p.vData[0]);
    }
}

CIdentityID CIdentity::GetID(const std::string &Name, uint160 &parent)
{
    std::string cleanName = CleanName(Name, parent, false, parent.IsNull());
    if (cleanName.empty())
    {
        return uint160();
    }

    std::string subName = boost::algorithm::to_lower_copy(cleanName);
    const char *idName = subName.c_str();
    //printf("hashing: %s, %s\n", idName, parent.GetHex().c_str());

    uint256 idHash;
    if (parent.IsNull())
    {
        idHash = Hash(idName, idName + strlen(idName));
    }
    else
    {
        idHash = Hash(idName, idName + strlen(idName));
        idHash = Hash(parent.begin(), parent.end(), idHash.begin(), idHash.end());
    }
    return Hash160(idHash.begin(), idHash.end());
}

CIdentityID CIdentity::GetID(const std::string &Name) const
{
    uint160 parent;
    std::string cleanName = CleanName(Name, parent);

    std::string subName = boost::algorithm::to_lower_copy(cleanName);
    const char *idName = subName.c_str();
    //printf("hashing: %s, %s\n", idName, parent.GetHex().c_str());

    uint256 idHash;
    if (parent.IsNull())
    {
        idHash = Hash(idName, idName + strlen(idName));
    }
    else
    {
        idHash = Hash(idName, idName + strlen(idName));
        idHash = Hash(parent.begin(), parent.end(), idHash.begin(), idHash.end());

    }
    return Hash160(idHash.begin(), idHash.end());
}

CIdentityID CIdentity::GetID() const
{
    uint160 Parent = parent;
    return GetID(name, Parent);
}

uint160 CCrossChainRPCData::GetID(std::string name)
{
    uint160 parent;
    //printf("uint160 for name %s: %s\n", name.c_str(), CIdentity::GetID(name, parent).GetHex().c_str());
    return CIdentity::GetID(name, parent);
}

CScript CIdentity::TransparentOutput() const
{
    CConditionObj<CIdentity> ccObj = CConditionObj<CIdentity>(0, std::vector<CTxDestination>({CTxDestination(CIdentityID(GetID()))}), 1);
    return MakeMofNCCScript(ccObj);
}

CScript CIdentity::TransparentOutput(const CIdentityID &destinationID)
{
    CConditionObj<CIdentity> ccObj = CConditionObj<CIdentity>(0, std::vector<CTxDestination>({destinationID}), 1);
    return MakeMofNCCScript(ccObj);
}

CScript CIdentity::IdentityUpdateOutputScript(uint32_t height, const std::vector<CTxDestination> *indexDests) const
{
    CScript ret;

    if (!IsValid())
    {
        return ret;
    }

    std::vector<CTxDestination> dests1({CTxDestination(CIdentityID(GetID()))});
    CConditionObj<CIdentity> primary(EVAL_IDENTITY_PRIMARY, dests1, 1, this);

    // when PBaaS activates, we no longer need redundant entries, so reduce the size a bit
    uint32_t consensusVersion = CConstVerusSolutionVector::GetVersionByHeight(height);
    if (consensusVersion >= CActivationHeight::ACTIVATE_VERUSVAULT)
    {
        std::vector<CTxDestination> dests3({CTxDestination(CIdentityID(recoveryAuthority))});
        if (HasTokenizedControl())
        {
            CCcontract_info CC;
            CCcontract_info *cp;

            // make a currency definition
            cp = CCinit(&CC, EVAL_IDENTITY_RECOVER);
            dests3.push_back(CPubKey(ParseHex(CC.CChexstr)).GetID());
        }
        CConditionObj<CIdentity> recovery(EVAL_IDENTITY_RECOVER, dests3, 1);

        if (IsRevoked())
        {
            ret = MakeMofNCCScript(1, primary, recovery, indexDests);
        }
        else
        {
            std::vector<CTxDestination> dests2({CTxDestination(CIdentityID(revocationAuthority))});
            CConditionObj<CIdentity> revocation(EVAL_IDENTITY_REVOKE, dests2, 1);
            ret = MakeMofNCCScript(1, primary, revocation, recovery, indexDests);
        }
    }
    else
    {
        std::vector<CTxDestination> dests2({CTxDestination(CIdentityID(revocationAuthority))});
        CConditionObj<CIdentity> revocation(EVAL_IDENTITY_REVOKE, dests2, 1);
        std::vector<CTxDestination> dests3({CTxDestination(CIdentityID(recoveryAuthority))});
        CConditionObj<CIdentity> recovery(EVAL_IDENTITY_RECOVER, dests3, 1);
        ret = MakeMofNCCScript(1, primary, revocation, recovery, indexDests);
    }

    return ret;
}

