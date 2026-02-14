/********************************************************************
 * (C) 2020 Michael Toutonghi
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Support for the Verus Data Exchange Format (VDXF)
 *
 */

#include "vdxf.h"
#include "crosschainrpc.h"
#include "utf8.h"
#include "util.h"
#include "sodium.h"
#include "zcash/NoteEncryption.hpp"
#include "librustzcash.h"
#include "key_io.h"
#include "pbaas/identity.h"

std::string CVDXF::DATA_KEY_SEPARATOR = "::";

uint160 CVDXF::STRUCTURED_DATA_KEY = CVDXF_StructuredData::StructuredDataKey();
uint160 CVDXF::ZMEMO_MESSAGE_KEY = CVDXF_Data::ZMemoMessageKey();
uint160 CVDXF::ZMEMO_SIGNATURE_KEY = CVDXF_Data::ZMemoSignatureKey();

std::string TrimLeading(const std::string &Name, unsigned char ch)
{
    std::string nameCopy = Name;
    int removeSpaces;
    for (removeSpaces = 0; removeSpaces < nameCopy.size(); removeSpaces++)
    {
        if (nameCopy[removeSpaces] != ch)
        {
            break;
        }
    }
    if (removeSpaces)
    {
        nameCopy.erase(nameCopy.begin(), nameCopy.begin() + removeSpaces);
    }
    return nameCopy;
}

std::string TrimTrailing(const std::string &Name, unsigned char ch)
{
    std::string nameCopy = Name;
    int removeSpaces;
    for (removeSpaces = nameCopy.size() - 1; removeSpaces >= 0; removeSpaces--)
    {
        if (nameCopy[removeSpaces] != ch)
        {
            break;
        }
    }
    nameCopy.resize(nameCopy.size() - ((nameCopy.size() - 1) - removeSpaces));
    return nameCopy;
}

std::string TrimSpaces(const std::string &Name, bool removeDuals, const std::string &_invalidChars)
{
    std::string invalidChars = _invalidChars;
    if (removeDuals)
    {
        invalidChars += "\n\t\r\b\t\v\f\x1B";
    }
    if (utf8valid(Name.c_str()) != 0)
    {
        return "";
    }
    std::string noDuals = removeDuals ?
        std::string(u8"\u0020\u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u200C\u200D\u202F\u205F\u3000") :
        " ";
    std::vector<int> allDuals;
    std::vector<int> toRemove;

    int len = utf8len(Name.c_str());
    const char *nextChar = Name.c_str();
    for (int i = 0; i < len; i++)
    {
        utf8_int32_t outPoint;
        utf8_int32_t invalidPoint;
        nextChar = utf8codepoint(nextChar, &outPoint);

        if (utf8chr(invalidChars.c_str(), outPoint))
        {
            toRemove.push_back(i);
            allDuals.push_back(i);
            continue;
        }

        char *dualCharPos = utf8chr(noDuals.c_str(), outPoint);

        if ((removeDuals ||
             (i == allDuals.size() ||
              i == (len - 1))) &&
             dualCharPos)
        {
            bool wasLastDual = allDuals.size() && allDuals.back() == (i - 1);
            if (i == allDuals.size() ||
                i == (len - 1) ||
                (removeDuals && wasLastDual))
            {
                toRemove.push_back(i);
            }
            allDuals.push_back(i);
            if (i &&
                i == (Name.size() - 1) &&
                wasLastDual)
            {
                int toRemoveIdx = toRemove.size() - 1;
                int nextDual = 0;
                for (auto dualIt = allDuals.rbegin(); dualIt != allDuals.rend(); dualIt++)
                {
                    if (nextDual && *dualIt != (nextDual - 1))
                    {
                        break;
                    }
                    if (toRemoveIdx < 0 || toRemove[toRemoveIdx] != *dualIt)
                    {
                        toRemove.insert(toRemove.begin() + ++toRemoveIdx, *dualIt);
                    }
                    toRemoveIdx--;
                }
            }
        }
    }

    // now, reconstruct the string char by char, but skip the ones to remove
    if (toRemove.size())
    {
        std::string nameCopy;
        int toRemoveIdx = 0;

        nextChar = Name.c_str();
        for (int i = 0; i < len; i++)
        {
            utf8_int32_t outPoint;
            nextChar = utf8codepoint(nextChar, &outPoint);

            if (toRemoveIdx < toRemove.size() && i++ == toRemove[toRemoveIdx])
            {
                toRemoveIdx++;
                continue;
            }
            char tmpCodePointStr[5] = {0};
            if (!utf8catcodepoint(tmpCodePointStr, outPoint, 5))
            {
                LogPrintf("%s: Invalid name string: %s\n", __func__, Name.c_str());
            }
            nameCopy += std::string(tmpCodePointStr);
        }
        return nameCopy;
    }
    else
    {
        return Name;
    }
}

bool CVDXF::HasExplicitParent(const std::string &Name)
{
    std::string ChainOut;
    bool hasExplicitParent = false;

    std::string nameCopy = Name;

    std::vector<std::string> retNames;
    boost::split(retNames, nameCopy, boost::is_any_of("@"));
    if (!retNames.size() || retNames.size() > 2)
    {
        return false;
    }

    nameCopy = retNames[0];
    boost::split(retNames, nameCopy, boost::is_any_of("."));

    if (retNames.size() && retNames.back().empty())
    {
        return true;
    }
    return false;
}

// this will add the current Verus chain name to subnames if it is not present
// on both id and chain names
std::vector<std::string> CVDXF::ParseSubNames(const std::string &Name, std::string &ChainOut, bool displayfilter, bool addVerus)
{
    std::string nameCopy = Name;

    std::vector<std::string> retNames;
    boost::split(retNames, nameCopy, boost::is_any_of("@"));
    if (!retNames.size() || retNames.size() > 2 || (retNames.size() > 1 && TrimSpaces(retNames[1]) != retNames[1]))
    {
        return std::vector<std::string>();
    }

    bool explicitChain = false;
    if (retNames.size() == 2 && !retNames[1].empty())
    {
        ChainOut = retNames[1];
        explicitChain = true;
    }

    nameCopy = retNames[0];
    boost::split(retNames, nameCopy, boost::is_any_of("."));

    if (retNames.size() && retNames.back().empty())
    {
        addVerus = false;
        retNames.pop_back();
    }

    int numRetNames = retNames.size();

    std::string verusChainName = boost::to_lower_copy(VERUS_CHAINNAME);

    if (addVerus)
    {
        if (explicitChain)
        {
            std::vector<std::string> chainOutNames;
            boost::split(chainOutNames, ChainOut, boost::is_any_of("."));
            std::string lastChainOut = boost::to_lower_copy(chainOutNames.back());

            if (lastChainOut != "" && lastChainOut != verusChainName)
            {
                chainOutNames.push_back(verusChainName);
            }
            else if (lastChainOut == "")
            {
                chainOutNames.pop_back();
            }
        }

        std::string lastRetName = boost::to_lower_copy(retNames.back());
        if (lastRetName != "" && lastRetName != verusChainName)
        {
            retNames.push_back(verusChainName);
        }
        else if (lastRetName == "")
        {
            retNames.pop_back();
        }
    }

    for (int i = 0; i < retNames.size(); i++)
    {
        if (retNames[i].size() > KOMODO_ASSETCHAIN_MAXLEN - 1)
        {
            retNames[i] = std::string(retNames[i], 0, (KOMODO_ASSETCHAIN_MAXLEN - 1));
        }
        // spaces are allowed, but no sub-name can have leading or trailing spaces
        if (!retNames[i].size() || retNames[i] != TrimSpaces(retNames[i], displayfilter))
        {
            return std::vector<std::string>();
        }
    }
    return retNames;
}

// takes a multipart name, either complete or partially processed with a Parent hash,
// hash its parent names into a parent ID and return the parent hash and cleaned, single name
std::string CVDXF::CleanName(const std::string &Name, uint160 &Parent, bool displayfilter)
{
    std::string chainName;
    std::vector<std::string> subNames = ParseSubNames(Name, chainName, displayfilter);

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

uint160 CVDXF::GetID(const std::string &Name)
{
    uint160 parent;
    std::string cleanName = CleanName(Name, parent);
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

uint160 CVDXF::GetID(const std::string &Name, uint160 &parent)
{
    std::string cleanName;
    cleanName = Name == DATA_KEY_SEPARATOR ? Name : CleanName(Name, parent);

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

// calculate the data key for a name inside of a namespace
// if the namespace is null, use VERUS_CHAINID
uint160 CVDXF::GetDataKey(const std::string &keyName, uint160 &nameSpaceID)
{
    std::string keyCopy = keyName;
    std::vector<std::string> addressParts;
    boost::split(addressParts, keyCopy, boost::is_any_of(":"));

    // if the first part of the address is a namespace, it is followed by a double colon
    // namespace specifiers have no implicit root
    if (addressParts.size() > 2 && addressParts[1].empty())
    {
        uint160 nsID = DecodeCurrencyName(addressParts[0].back() == '.' ? addressParts[0] : addressParts[0] + ".");

        if (!nsID.IsNull())
        {
            nameSpaceID = nsID;
        }
        keyCopy.clear();
        for (int i = 2; i < addressParts.size(); i++)
        {
            keyCopy = i == 2 ? addressParts[i] : keyCopy + ":" + addressParts[i];
        }
    }

    if (nameSpaceID.IsNull())
    {
        nameSpaceID = VERUS_CHAINID;
    }
    uint160 parent = GetID(DATA_KEY_SEPARATOR, nameSpaceID);
    return GetID(keyCopy, parent);
}

bool uni_get_bool(const UniValue &uv, bool def)
{
    try
    {
        if (uv.isStr())
        {
            std::string boolStr;
            if ((boolStr = uni_get_str(uv, def ? "true" : "false")) == "true" || boolStr == "1")
            {
                return true;
            }
            else if (boolStr == "false" || boolStr == "0")
            {
                return false;
            }
            return def;
        }
        else if (uv.isNum())
        {
            return uv.get_int() != 0;
        }
        else
        {
            return uv.get_bool();
        }
        return false;
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

int32_t uni_get_int(const UniValue &uv, int32_t def)
{
    try
    {
        if (!uv.isStr() && !uv.isNum())
        {
            return def;
        }
        return (uv.isStr() ? atoi(uv.get_str()) : atoi(uv.getValStr()));
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

int64_t uni_get_int64(const UniValue &uv, int64_t def)
{
    try
    {
        if (!uv.isStr() && !uv.isNum())
        {
            return def;
        }
        return (uv.isStr() ? atoi64(uv.get_str()) : atoi64(uv.getValStr()));
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

std::string uni_get_str(const UniValue &uv, std::string def)
{
    try
    {
        return uv.get_str();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

std::vector<UniValue> uni_getValues(const UniValue &uv, std::vector<UniValue> def)
{
    try
    {
        return uv.getValues();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

// this deserializes a vector into either a VDXF data object or a VDXF structured
// object, which may contain one or more VDXF data objects.
// If the data in the sourceVector is not a recognized VDXF object, the returned
// variant will be empty/invalid, otherwise, it will be a recognized VDXF object
// or a VDXF structured object containing one or more recognized VDXF objects.
VDXFData DeserializeVDXFData(const std::vector<unsigned char> &sourceVector)
{
    CVDXF_StructuredData sData;
    ::FromVector(sourceVector, sData);
    if (sData.IsValid())
    {
        return sData;
    }
    else
    {
        CVDXF_Data Data;
        ::FromVector(sourceVector, Data);
        if (Data.IsValid())
        {
            return Data;
        }
    }
    return VDXFData();
}

std::vector<unsigned char> SerializeVDXFData(const VDXFData &vdxfData)
{
    return boost::apply_visitor(CSerializeVDXFData(), vdxfData);
}

CVDXF::CVDXF(const UniValue &uni) : version(uni_get_int64(find_value(uni, "version"), DEFAULT_VERSION)), key(GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "key")))))
{}

UniValue CVDXF::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);

    ret.pushKV("key", EncodeDestination(CIdentityID(key)));
    ret.pushKV("version", (int64_t)version);
    return ret;
}

CVDXF_Data::CVDXF_Data(const UniValue &uni) : CVDXF(uni), data(VectorEncodeVDXFUni(find_value(uni, "data"))) {}

uint256 CVDXF_Data::GetHash(CNativeHashWriter &hw) const
{
    hw.write((const char *)&(data[0]), data.size());
    return hw.GetHash();
}

CVDXFEncryptor::CVDXFEncryptor(const UniValue &uni) :
        CVDXF_Data(uni), encType(uni_get_int(find_value(uni, "encryption"))), keyData(VectorEncodeVDXFUni(find_value(uni, "keydata"))), cipherData(VectorEncodeVDXFUni(find_value(uni, "cipherdata"))) {}

bool CVDXFEncryptor::GetDecryptionKey(const libzcash::SaplingIncomingViewingKey &ivk, std::vector<unsigned char> &decryptionKey)
{
    uint256 dhsecret;
    uint256 pk(keyData);

    if (cipherData.size() <= CHACHA20POLY1305_CIPHEROVERHEAD ||
        !librustzcash_sapling_ka_agree(pk.begin(), ivk.begin(), dhsecret.begin())) {
        return false;
    }

    // Construct the symmetric key
    unsigned char K[NOTEENCRYPTION_CIPHER_KEYSIZE];

    KDF_Sapling(K, dhsecret, pk);
    decryptionKey = std::vector<unsigned char>(K, K + NOTEENCRYPTION_CIPHER_KEYSIZE);
    return true;
}

bool CVDXFEncryptor::Decrypt(const libzcash::SaplingIncomingViewingKey &ivk, std::vector<unsigned char> &plainText, std::vector<unsigned char> *pSsk)
{
    uint256 dhsecret;
    uint256 pk(keyData);

    if (encType != ENCRYPTION_CHACHA20POLY1305 || 
        cipherData.size() <= CHACHA20POLY1305_CIPHEROVERHEAD ||
        !librustzcash_sapling_ka_agree(pk.begin(), ivk.begin(), dhsecret.begin())) {
        return false;
    }

    // Construct the symmetric key
    unsigned char K[NOTEENCRYPTION_CIPHER_KEYSIZE];

    KDF_Sapling(K, dhsecret, pk);

    // The nonce is zero because we never reuse keys
    unsigned char cipher_nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {};

    plainText.resize(cipherData.size() - CHACHA20POLY1305_CIPHEROVERHEAD);

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        plainText.data(), NULL,
        NULL,
        cipherData.data(), cipherData.size(),
        NULL,
        0,
        cipher_nonce, K) != 0)
    {
        return false;
    }

    if (pSsk)
    {
        *pSsk = std::vector<unsigned char>(K, K + NOTEENCRYPTION_CIPHER_KEYSIZE);
    }

    return true;
}

bool CVDXFEncryptor::Decrypt(const std::vector<unsigned char> &decryptionKey, std::vector<unsigned char> &plainText)
{
    if (encType != ENCRYPTION_CHACHA20POLY1305 || 
        cipherData.size() <= CHACHA20POLY1305_CIPHEROVERHEAD) {
        return false;
    }

    // The nonce is zero because we never reuse keys
    unsigned char cipher_nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {};

    plainText.resize(cipherData.size() - CHACHA20POLY1305_CIPHEROVERHEAD);

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        plainText.data(), NULL,
        NULL,
        cipherData.data(), cipherData.size(),
        NULL,
        0,
        cipher_nonce, decryptionKey.data()) != 0)
    {
        return false;
    }

    return true;
}

bool CVDXFEncryptor::Encrypt(const libzcash::SaplingPaymentAddress &saplingAddress, const std::vector<unsigned char> &plainText, std::vector<unsigned char> *pSsk)
{
    uint256 dhsecret;

    uint256 esk;
    uint256 pk;

    // Pick random esk
    librustzcash_sapling_generate_r(esk.begin());

    if (encType != ENCRYPTION_CHACHA20POLY1305 || 
        !librustzcash_sapling_ka_derivepublic(saplingAddress.d.begin(), esk.begin(), pk.begin())) {
        return false;
    }

    if (!librustzcash_sapling_ka_agree(saplingAddress.pk_d.begin(), esk.begin(), dhsecret.begin())) {
        return false;
    }

    // Construct the symmetric key
    unsigned char K[NOTEENCRYPTION_CIPHER_KEYSIZE];
    KDF_Sapling(K, dhsecret, pk);

    if (pSsk)
    {
        *pSsk = std::vector<unsigned char>(K, K + NOTEENCRYPTION_CIPHER_KEYSIZE);
    }

    // The nonce is zero because we never reuse keys
    unsigned char cipher_nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {};

    cipherData.resize(plainText.size() + CHACHA20POLY1305_CIPHEROVERHEAD);

    crypto_aead_chacha20poly1305_ietf_encrypt(
        cipherData.data(), NULL,
        plainText.data(), plainText.size(),
        NULL, 0, // no "additional data"
        NULL, cipher_nonce, K
    );

    keyData = std::vector<unsigned char>(pk.begin(), pk.end());
    return true;
}

UniValue CVDXFEncryptor::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);

    ret = ((CVDXF *)this)->ToUniValue();
    ret.pushKV("encryption", encType);
    ret.pushKV("keydata", HexBytes(keyData.data(), keyData.size()));
    ret.pushKV("cipherdata", HexBytes(cipherData.data(), cipherData.size()));
    return ret;
}

CSaltedData::CSaltedData(const UniValue &uni) :
    CVDXF_Data(uni), salt(uint256S(uni_get_str(find_value(uni, "salt"))))
{}

uint256 CSaltedData::FreshSalt()
{
    uint256 retVal;
    randombytes(retVal.begin(), sizeof(retVal));
    return retVal;
}

uint256 CSaltedData::GetHash(CNativeHashWriter &hw) const
{
    hw.write((const char *)&(data[0]), data.size());
    hw.write((const char *)salt.begin(), salt.size());
    return hw.GetHash();
}

UniValue CSaltedData::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);

    ret = ((CVDXF_Data *)this)->ToUniValue();
    ret.pushKV("salt", salt.GetHex());
    return ret;
}

CDataDescriptor::CDataDescriptor(const UniValue &uni) :
    version(uni_get_int64(find_value(uni, "version"))),
    flags(uni_get_int64(find_value(uni, "flags"))),
    label(TrimSpaces(uni_get_str(find_value(uni, "label")), true, "")),
    mimeType(TrimSpaces(uni_get_str(find_value(uni, "mimetype")), true, "")),
    salt(ParseHex(uni_get_str(find_value(uni, "salt")))),
    epk(ParseHex(uni_get_str(find_value(uni, "epk")))),
    ivk(ParseHex(uni_get_str(find_value(uni, "ivk")))),
    ssk(ParseHex(uni_get_str(find_value(uni, "ssk"))))
{
    if (uni.isNull())
    {
        version = VERSION_INVALID;
        return;
    }
    if (label.size() > 64)
    {
        label.resize(64);
    }
    if (mimeType.size() > 128)
    {
        mimeType.resize(128);
    }
    SetFlags();
    
    UniValue objUni = find_value(uni, "objectdata");

    if (objUni.isArray())
    {
        for (int j = 0; j < objUni.size(); j++)
        {
            CDataStream ss(PROTOCOL_VERSION, SER_DISK);
            for (int i = 0; i < objUni.size(); i++)
            {
                std::vector<unsigned char> vec = VectorEncodeVDXFUni(objUni[i]);
                ss.write((const char *)vec.data(), vec.size());
            }
            objectData = std::vector<unsigned char>(ss.begin(), ss.end());
        }
    }
    else if (objUni.isStr())
    {
        std::string valueString;
        if (IsHex(valueString = uni_get_str(objUni)))
        {
            objectData = VectorEncodeVDXFUni(objUni);
        }
        else
        {
            objectData = std::vector<unsigned char>();
        }
    }
    else if (objUni.isObject())
    {
        std::vector<unsigned char> mapBytesValue = VectorEncodeVDXFUni(objUni);
        if (!mapBytesValue.size())
        {
            return;
        }
        objectData = mapBytesValue;
    }
    else
    {
        objectData = std::vector<unsigned char>();
    }
}

std::vector<uint256> CDataDescriptor::DecodeHashVector() const
{
    std::vector<uint256> retVal;

    CVDXF_Data linkObject;
    ::FromVector(objectData, linkObject);
    if (linkObject.key == CVDXF_Data::VectorUint256Key())
    {
        ::FromVector(linkObject.data, retVal);
    }
    return retVal;
}

// encrypts to a specific z-address incoming viewing key
bool CDataDescriptor::EncryptData(const libzcash::SaplingPaymentAddress &saplingAddress, const std::vector<unsigned char> &plainText, std::vector<unsigned char> *pSsk)
{
    CVDXFEncryptor encryptor;
    if (!encryptor.Encrypt(saplingAddress, plainText, pSsk))
    {
        return false;
    }
    flags |= FLAG_ENCRYPTED_DATA;
    objectData = encryptor.cipherData;
    uint256 uintEpk = encryptor.GetEPK();
    salt = std::vector<unsigned char>();
    epk = std::vector<unsigned char>(uintEpk.begin(), uintEpk.end());
    ivk = std::vector<unsigned char>();
    ssk = std::vector<unsigned char>();
    return true;
}

// decrypts objectData only if there is a valid key available to decrypt with already present in this object
bool CDataDescriptor::DecryptData(std::vector<unsigned char> &plainText, std::vector<unsigned char> *pSsk) const
{
    CVDXFEncryptor decryptor;
    decryptor.cipherData = objectData;
    // to succeed, we must need to have either an epk and an ivk or just an ssk present
    if (ssk.size())
    {
        if (decryptor.Decrypt(ssk, plainText))
        {
            if (pSsk)
            {
                *pSsk = ssk;
            }
            return true;
        }
    }
    if (!ivk.size() || !epk.size())
    {
        return false;
    }
    decryptor.keyData = epk;

    return decryptor.Decrypt(libzcash::SaplingIncomingViewingKey(uint256(ivk)), plainText, pSsk);
}

// decrypts objectData either with the provided viewing key, or if a key is available
bool CDataDescriptor::DecryptData(const libzcash::SaplingIncomingViewingKey &Ivk, std::vector<unsigned char> &plainText, bool ivkOnly, std::vector<unsigned char> *pSsk) const
{
    CVDXFEncryptor decryptor;
    decryptor.cipherData = objectData;

    bool decrypted = false;
    if (epk.size())
    {
        decryptor.keyData = epk;
        decrypted = decryptor.Decrypt(Ivk, plainText, pSsk);
    }

    if (ivkOnly || decrypted)
    {
        return decrypted;
    }
    return DecryptData(plainText, pSsk);
}

// decrypts objectData either with the provided specific symmetric encryption key, or if a key is available on the link
bool CDataDescriptor::DecryptData(const std::vector<unsigned char> &decryptionKey, std::vector<unsigned char> &plainText, bool sskOnly) const
{
    CVDXFEncryptor decryptor;
    decryptor.cipherData = objectData;

    bool decrypted = decryptor.Decrypt(decryptionKey, plainText);

    if (sskOnly || decrypted)
    {
        return decrypted;
    }
    return DecryptData(plainText);
}

bool CDataDescriptor::GetSSK(std::vector<unsigned char> &Ssk) const
{
    if (ssk.size())
    {
        Ssk = ssk;
        return true;
    }

    if (!ivk.size() || !epk.size())
    {
        return false;
    }

    CVDXFEncryptor decryptor;
    decryptor.keyData = epk;

    return decryptor.GetDecryptionKey(libzcash::SaplingIncomingViewingKey(uint256(ivk)), Ssk);
}

bool CDataDescriptor::GetSSK(const libzcash::SaplingIncomingViewingKey &Ivk, std::vector<unsigned char> &Ssk, bool ivkOnly) const
{
    CVDXFEncryptor decryptor;
    decryptor.cipherData = objectData;

    bool haveKey = false;
    if (epk.size())
    {
        decryptor.keyData = epk;
        haveKey = decryptor.GetDecryptionKey(Ivk, Ssk);
    }

    if (ivkOnly || haveKey)
    {
        return haveKey;
    }
    return GetSSK(Ssk);
}

bool CDataDescriptor::UnwrapEncryption()
{
    if (!HasEncryptedData())
    {
        return false;
    }

    std::vector<unsigned char> innerPlainText;
    if (!DecryptData(innerPlainText))
    {
        return false;
    }

    // we can only unwrap if the inner object is a wrapped link
    // that starts from the first 20 bytes being the correct VDXF key
    if (innerPlainText.size() <= sizeof(uint160))
    {
        return false;
    }
    uint160 checkVDXFKey(std::vector<unsigned char>(innerPlainText.data(), innerPlainText.data() + 20));
    if (checkVDXFKey != CVDXF_Data::DataDescriptorKey())
    {
        return false;
    }

    CVDXF_Data unwrappedData;
    ::FromVector(innerPlainText, unwrappedData);
    if (!unwrappedData.data.size())
    {
        return false;
    }
    *this = CDataDescriptor();
    ::FromVector(unwrappedData.data, *this);
    return true;
}

bool CDataDescriptor::UnwrapEncryption(const libzcash::SaplingIncomingViewingKey &Ivk, bool ivkOnly)
{
    if (!HasEncryptedData())
    {
        return false;
    }

    std::vector<unsigned char> innerPlainText;
    if (!DecryptData(Ivk, innerPlainText, ivkOnly))
    {
        return false;
    }

    // we can only unwrap if the inner object is a wrapped link
    // that starts from the first 20 bytes being the correct VDXF key
    if (innerPlainText.size() <= sizeof(uint160))
    {
        return false;
    }
    uint160 checkVDXFKey(std::vector<unsigned char>(innerPlainText.data(), innerPlainText.data() + 20));
    if (checkVDXFKey != CVDXF_Data::DataDescriptorKey())
    {
        return false;
    }

    CVDXF_Data unwrappedData;
    ::FromVector(innerPlainText, unwrappedData);
    if (!unwrappedData.data.size())
    {
        return false;
    }
    *this = CDataDescriptor();
    ::FromVector(unwrappedData.data, *this);
    return true;
}

bool CDataDescriptor::UnwrapEncryption(const std::vector<unsigned char> &decryptionKey, bool sskOnly)
{
    if (!HasEncryptedData())
    {
        return false;
    }

    std::vector<unsigned char> innerPlainText;
    if (!DecryptData(decryptionKey, innerPlainText, sskOnly))
    {
        return false;
    }

    // we can only unwrap if the inner object is a wrapped link
    // that starts from the first 20 bytes being the correct VDXF key
    if (innerPlainText.size() <= sizeof(uint160))
    {
        return false;
    }
    uint160 checkVDXFKey(std::vector<unsigned char>(innerPlainText.data(), innerPlainText.data() + 20));
    if (checkVDXFKey != CVDXF_Data::DataDescriptorKey())
    {
        return false;
    }

    CVDXF_Data unwrappedData;
    ::FromVector(innerPlainText, unwrappedData);
    if (!unwrappedData.data.size())
    {
        return false;
    }
    *this = CDataDescriptor();
    ::FromVector(unwrappedData.data, *this);
    return true;
}

bool CDataDescriptor::IsValid() const
{
    bool basicValidation = version >= FIRST_VERSION && version <= LAST_VERSION && (flags & ~FLAG_MASK) == 0;
    
    // Additional validation: ensure the label contains valid UTF-8
    if (basicValidation && HasLabel())
    {
        if (utf8valid(label.c_str()) != 0)
        {
            LogPrint("contentmap", "%s: data descriptor label contains invalid UTF-8: %s\n", __func__, label.substr(0, 50).c_str());
            return false;
        }
    }

    if (basicValidation && HasMIME())
    {
        if (utf8valid(mimeType.c_str()) != 0)
        {
            LogPrint("contentmap", "%s: data descriptor MIME type contains invalid UTF-8: %s\n", __func__, mimeType.substr(0, 50).c_str());
            return false;
        }
    }

    return basicValidation;
}

UniValue CDataDescriptor::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    int64_t Flags = CalcFlags();
    bool isText = false;

    ret.pushKV("version", (int64_t)version);
    ret.pushKV("flags", Flags);

    if (HasMIME())
    {
        ret.pushKV("mimetype", TrimSpaces(mimeType, true, ""));
        if (std::string(mimeType.begin(), mimeType.begin() + 5) == std::string("text/"))
        {
            isText = true;
        }
    }

    UniValue processedObject = CIdentity::VDXFDataToUniValue(objectData);

    if (isText &&
        find_value(processedObject, EncodeDestination(CIdentityID(CVDXF_Data::CrossChainDataRefKey()))).isNull())
    {
        // Create a string from the binary data
        std::string messageStr(objectData.begin(), objectData.end());
        
        if (utf8valid(messageStr.c_str()) == 0) {
            // Safe to use as a message string
            UniValue objectDataUni(UniValue::VOBJ);
            objectDataUni.pushKV("message", messageStr);
            ret.pushKV("objectdata", objectDataUni);
        } else {
            // Fall back to hex encoding if utf8 is not valid
            ret.pushKV("objectdata", processedObject);
        }
    }
    else
    {
        ret.pushKV("objectdata", processedObject);
    }

    if (HasLabel())
    {
        ret.pushKV("label", TrimSpaces(label, true, ""));
    }
    if (HasSalt())
    {
        ret.pushKV("salt", HexBytes(salt.data(), salt.size()));
    }
    if (HasEPK())
    {
        ret.pushKV("epk", HexBytes(epk.data(), epk.size()));
    }
    if (HasIVK())
    {
        ret.pushKV("ivk", HexBytes(ivk.data(), ivk.size()));
    }
    if (HasSSK())
    {
        ret.pushKV("ssk", HexBytes(ssk.data(), ssk.size()));
    }
    return ret;
}

CVDXFDataDescriptor::CVDXFDataDescriptor(const UniValue &uni) :
    CVDXF_Data(uni),
    dataDescriptor(uni)
{
}

UniValue CVDXFDataDescriptor::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);

    ret = ((CVDXF *)this)->ToUniValue();
    ret.pushKV("datadescriptor", dataDescriptor.ToUniValue());
    return ret;
}

CSignatureData::CSignatureData(const UniValue &uni) :
    version(uni_get_int64(find_value(uni, "version"))),
    systemID(GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "systemid"))))),
    hashType((CVDXF::EHashTypes)uni_get_int(find_value(uni, "hashtype"))),
    identityID(GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "identityid"))))),
    sigType(uni_get_int(find_value(uni, "signaturetype"), TYPE_VERUSID_DEFAULT))
{
    uint256 dataHash;
    if (hashType == CVDXF::EHashTypes::HASH_SHA256)
    {
        dataHash = uint256(ParseHex(uni_get_str(find_value(uni, "signaturehash"))));
    }
    else
    {
        dataHash.SetHex(uni_get_str(find_value(uni, "signaturehash")));
    }
    signatureHash = std::vector<unsigned char>(dataHash.begin(), dataHash.end());

    std::string sigString = DecodeBase64(uni_get_str(find_value(uni, "signature")));
    signatureAsVch = std::vector<unsigned char>(sigString.begin(), sigString.end());

    auto vdxfKeysUni = find_value(uni, "vdxfkeys");
    if (vdxfKeysUni.isArray())
    {
        for (int i = 0; i < vdxfKeysUni.size(); i++)
        {
            vdxfKeys.push_back(ParseVDXFKey(uni_get_str(vdxfKeysUni[i])));
        }
    }

    auto vdxfKeyNamesUni = find_value(uni, "vdxfkeynames");
    if (vdxfKeyNamesUni.isArray())
    {
        for (int i = 0; i < vdxfKeyNamesUni.size(); i++)
        {
            vdxfKeyNames.push_back(uni_get_str(vdxfKeyNamesUni[i]));
        }
    }

    auto boundHashesUni = find_value(uni, "boundhashes");
    if (boundHashesUni.isArray())
    {
        for (int i = 0; i < boundHashesUni.size(); i++)
        {
            boundHashes.push_back(uint256S(uni_get_str(boundHashesUni[i])));
        }
    }
}

UniValue CSignatureData::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);

    ret.pushKV("version", (int64_t)version);
    ret.pushKV("systemid", EncodeDestination(CIdentityID(systemID)));
    ret.pushKV("hashtype", hashType);
    if (hashType == CVDXF::EHashTypes::HASH_SHA256)
    {
        ret.pushKV("signaturehash", HexBytes(signatureHash.data(), signatureHash.size()));
    }
    else
    {
        uint256 hashVal(signatureHash);
        ret.pushKV("signaturehash", hashVal.GetHex());
    }

    ret.pushKV("identityid", EncodeDestination(CIdentityID(identityID)));
    ret.pushKV("signaturetype", (int64_t)sigType);
    ret.pushKV("signature", EncodeBase64(signatureAsVch.data(), signatureAsVch.size()));

    if (vdxfKeys.size())
    {
        UniValue vdxfKeysUni(UniValue::VARR);
        for (auto &oneKey : vdxfKeys)
        {
            vdxfKeysUni.push_back(EncodeDestination(CIdentityID(oneKey)));
        }
        ret.pushKV("vdxfkeys", vdxfKeysUni);
    }

    if (vdxfKeyNames.size())
    {
        UniValue vdxfKeyNamesUni(UniValue::VARR);
        for (auto &oneKeyName : vdxfKeyNames)
        {
            vdxfKeyNamesUni.push_back(oneKeyName);
        }
        ret.pushKV("vdxfkeynames", vdxfKeyNamesUni);
    }

    if (boundHashes.size())
    {
        UniValue boundHashesUni(UniValue::VARR);
        for (auto &oneBoundHash : boundHashes)
        {
            boundHashesUni.push_back(oneBoundHash.GetHex());
        }
        ret.pushKV("boundhashes", boundHashesUni);
    }
    return ret;
}

UniValue CVDXFSignatureData::ToUniValue() const
{
    UniValue obj = ((CVDXF_Data *)this)->ToUniValue();
    obj.pushKV("signature", signature.ToUniValue());
    return obj;
}

CMMRDescriptor::CMMRDescriptor(const UniValue &uni) :
    version(uni_get_int64(find_value(uni, "version"))),
    objectHashType((CVDXF::EHashTypes)uni_get_int(find_value(uni, "objecthashtype"))),
    mmrHashType((CVDXF::EHashTypes)uni_get_int(find_value(uni, "mmrhashtype"))),
    mmrRoot(find_value(uni, "mmrroot")),
    mmrHashes(find_value(uni, "mmrhashes"))
{
    UniValue dataDescriptorsUni = find_value(uni, "datadescriptors");
    if (dataDescriptorsUni.isArray())
    {
        for (int i = 0; i < dataDescriptorsUni.size(); i++)
        {
            dataDescriptors.push_back(CDataDescriptor(dataDescriptorsUni[i]));
        }
    }
}

CMMRDescriptor CMMRDescriptor::Encrypt(const libzcash::SaplingPaymentAddress &saplingAddress, bool includeSSKs) const
{
    CMMRDescriptor retVal = *this;
    std::vector<unsigned char> Ssk;

    // encrypt everything and add epks
    if (!retVal.mmrRoot.WrapEncrypted(saplingAddress, &Ssk))
    {
        return CMMRDescriptor();
    }
    if (includeSSKs)
    {
        retVal.mmrRoot.ssk = Ssk;
    }
    if (!retVal.mmrHashes.WrapEncrypted(saplingAddress, &Ssk))
    {
        return CMMRDescriptor();
    }
    if (includeSSKs)
    {
        retVal.mmrHashes.ssk = Ssk;
    }

    for (int i = 0; i < retVal.dataDescriptors.size(); i++)
    {
        auto &oneDescriptor = retVal.dataDescriptors[i];
        if (!oneDescriptor.WrapEncrypted(saplingAddress, &Ssk))
        {
            return CMMRDescriptor();
        }
        if (includeSSKs)
        {
            oneDescriptor.ssk = Ssk;
        }
    }

    return retVal;
}

bool CMMRDescriptor::WrapEncrypted(const libzcash::SaplingPaymentAddress &saplingAddress, bool includeSSKs)
{
    CMMRDescriptor thisCopy = *this;
    std::vector<unsigned char> Ssk;

    // encrypt everything and add epks
    if (!thisCopy.mmrRoot.WrapEncrypted(saplingAddress, &Ssk))
    {
        return false;
    }
    if (includeSSKs)
    {
        thisCopy.mmrRoot.ssk = Ssk;
    }
    if (!thisCopy.mmrHashes.WrapEncrypted(saplingAddress, &Ssk))
    {
        return false;
    }
    if (includeSSKs)
    {
        thisCopy.mmrHashes.ssk = Ssk;
    }

    for (int i = 0; i < thisCopy.dataDescriptors.size(); i++)
    {
        auto &oneDescriptor = thisCopy.dataDescriptors[i];
        if (!oneDescriptor.WrapEncrypted(saplingAddress, &Ssk))
        {
            return false;
        }
        if (includeSSKs)
        {
            oneDescriptor.ssk = Ssk;
        }
    }

    *this = thisCopy;
    return true;
}

CMMRDescriptor CMMRDescriptor::Decrypt() const
{
    CMMRDescriptor retVal = *this;

    // decrypt everything we can and add it to retVal
    // encrypt everything and add epks
    retVal.mmrRoot.UnwrapEncryption();
    retVal.mmrHashes.UnwrapEncryption();

    for (int i = 0; i < retVal.dataDescriptors.size(); i++)
    {
        retVal.dataDescriptors[i].UnwrapEncryption();
    }

    return retVal;
}

CMMRDescriptor CMMRDescriptor::Decrypt(const libzcash::SaplingIncomingViewingKey &ivk) const
{
    CMMRDescriptor retVal = *this;

    // decrypt everything and add it to retVal
    retVal.mmrRoot.UnwrapEncryption(ivk);
    retVal.mmrHashes.UnwrapEncryption(ivk);

    for (int i = 0; i < retVal.dataDescriptors.size(); i++)
    {
        retVal.dataDescriptors[i].UnwrapEncryption(ivk);
    }

    return retVal;
}

std::vector<uint256> CMMRDescriptor::DecryptMMRHashes(const libzcash::SaplingIncomingViewingKey &Ivk) const
{
    std::vector<uint256> retVal;
    CDataDescriptor descrCopy = mmrHashes;

    // deserialize unencrypted MMR hashes, encrypted with key present or return nothing
    if (!descrCopy.HasEncryptedData() ||
        (descrCopy.UnwrapEncryption(Ivk) && !descrCopy.HasEncryptedData()))
    {
        CVDXF_Data linkObject;
        ::FromVector(descrCopy.objectData, linkObject);
        if (linkObject.key == CVDXF_Data::VectorUint256Key())
        {
            ::FromVector(linkObject.data, retVal);
        }
    }
    return retVal;
}

std::vector<uint256> CMMRDescriptor::DecryptMMRHashes(const std::vector<unsigned char> &Ssk) const
{
    std::vector<uint256> retVal;
    CDataDescriptor descrCopy = mmrHashes;

    if (!descrCopy.HasEncryptedData() ||
        (descrCopy.UnwrapEncryption(Ssk) && !descrCopy.HasEncryptedData()))
    {
        CVDXF_Data linkObject;
        ::FromVector(descrCopy.objectData, linkObject);
        if (linkObject.key == CVDXF_Data::VectorUint256Key())
        {
            ::FromVector(linkObject.data, retVal);
        }
    }
    return retVal;
}

std::vector<uint256> CMMRDescriptor::GetMMRHashes() const
{
    std::vector<uint256> retVal;
    CDataDescriptor descrCopy = mmrHashes;

    if (!descrCopy.HasEncryptedData() ||
        (descrCopy.UnwrapEncryption() && !descrCopy.HasEncryptedData()))
    {
        CVDXF_Data linkObject;
        ::FromVector(descrCopy.objectData, linkObject);
        if (linkObject.key == CVDXF_Data::VectorUint256Key())
        {
            ::FromVector(linkObject.data, retVal);
        }
    }
    return retVal;
}

uint256 CMMRDescriptor::DecryptMMRRoot(const libzcash::SaplingIncomingViewingKey &Ivk) const
{
    uint256 retVal;

    CDataDescriptor descrCopy = mmrRoot;

    // deserialize unencrypted MMR hashes, encrypted with key present or return nothing
    if (!descrCopy.HasEncryptedData() ||
        (descrCopy.UnwrapEncryption(Ivk) && !descrCopy.HasEncryptedData()))
    {
        CVDXF_Data linkObject;
        ::FromVector(descrCopy.objectData, linkObject);
        if (linkObject.data.size() >= 32)
        {
            retVal = uint256(std::vector<unsigned char>(linkObject.data.data(), linkObject.data.data() + 32));
        }
    }
    return retVal;
}

uint256 CMMRDescriptor::DecryptMMRRoot(const std::vector<unsigned char> &Ssk) const
{
    uint256 retVal;

    CDataDescriptor descrCopy = mmrRoot;

    // deserialize unencrypted MMR hashes, encrypted with key present or return nothing
    if (!descrCopy.HasEncryptedData() ||
        (descrCopy.UnwrapEncryption(Ssk) && !descrCopy.HasEncryptedData()))
    {
        CVDXF_Data linkObject;
        ::FromVector(descrCopy.objectData, linkObject);
        if (linkObject.data.size() >= 32)
        {
            retVal = uint256(std::vector<unsigned char>(linkObject.data.data(), linkObject.data.data() + 32));
        }
    }
    return retVal;
}

uint256 CMMRDescriptor::GetMMRRoot() const
{
    uint256 retVal;

    CDataDescriptor descrCopy = mmrRoot;

    // deserialize unencrypted MMR hashes, encrypted with key present or return nothing
    if (!descrCopy.HasEncryptedData() ||
        (descrCopy.UnwrapEncryption() && !descrCopy.HasEncryptedData()))
    {
        CVDXF_Data linkObject;
        ::FromVector(descrCopy.objectData, linkObject);
        if (linkObject.data.size() >= 32)
        {
            retVal = uint256(std::vector<unsigned char>(linkObject.data.data(), linkObject.data.data() + 32));
        }
    }
    return retVal;
}

std::vector<CDataDescriptor> CMMRDescriptor::DecryptDataDescriptors(const libzcash::SaplingIncomingViewingKey &ivk) const
{
    // decrypt and deserialize descriptors
    CMMRDescriptor thisCopy = *this;
    thisCopy.mmrHashes = CDataDescriptor();

    for (int i = 0; i < thisCopy.dataDescriptors.size(); i++)
    {
        thisCopy.dataDescriptors[i].UnwrapEncryption(ivk);
    }

    return thisCopy.dataDescriptors;
}

std::vector<CDataDescriptor> CMMRDescriptor::GetDataDescriptors() const
{
    // decrypt and deserialize descriptors
    CMMRDescriptor thisCopy = *this;
    thisCopy.mmrHashes = CDataDescriptor();

    for (int i = 0; i < thisCopy.dataDescriptors.size(); i++)
    {
        thisCopy.dataDescriptors[i].UnwrapEncryption();
    }

    return thisCopy.dataDescriptors;
}

CDataDescriptor CMMRDescriptor::DecryptDataDescriptor(int idx, const std::vector<unsigned char> &ssk) const
{
    // decrypt and deserialize descriptors
    CDataDescriptor oneDescr;
    if (idx < dataDescriptors.size())
    {
        oneDescr = dataDescriptors[idx];
        oneDescr.UnwrapEncryption(ssk);
    }
    else if (idx == dataDescriptors.size())
    {
        oneDescr = mmrRoot;
        oneDescr.UnwrapEncryption(ssk);
    }
    else if (idx == dataDescriptors.size() + 1)
    {
        oneDescr = mmrHashes;
        oneDescr.UnwrapEncryption(ssk);
    }
    return oneDescr;
}

CDataDescriptor CMMRDescriptor::DecryptDataDescriptor(int idx, const libzcash::SaplingIncomingViewingKey &ivk) const
{
    // decrypt and deserialize descriptors
    CDataDescriptor oneDescr;
    if (idx < dataDescriptors.size())
    {
        oneDescr = dataDescriptors[idx];
        oneDescr.UnwrapEncryption(ivk);
    }
    else if (idx == dataDescriptors.size())
    {
        oneDescr = mmrRoot;
        oneDescr.UnwrapEncryption(ivk);
    }
    else if (idx == dataDescriptors.size() + 1)
    {
        oneDescr = mmrHashes;
        oneDescr.UnwrapEncryption(ivk);
    }
    return oneDescr;
}

CDataDescriptor CMMRDescriptor::GetDataDescriptor(int idx) const
{
    // decrypt and deserialize descriptors
    CDataDescriptor oneDescr;
    if (idx < dataDescriptors.size())
    {
        oneDescr = dataDescriptors[idx];
        oneDescr.UnwrapEncryption();
    }
    else if (idx == dataDescriptors.size())
    {
        oneDescr = mmrRoot;
        oneDescr.UnwrapEncryption();
    }
    else if (idx == dataDescriptors.size() + 1)
    {
        oneDescr = mmrHashes;
        oneDescr.UnwrapEncryption();
    }
    return oneDescr;
}

CMMRDescriptor CMMRDescriptor::AddSymmetricKeys(const libzcash::SaplingIncomingViewingKey &ivk) const
{
    CMMRDescriptor retVal = *this;

    retVal.mmrRoot.GetSSK(ivk, retVal.mmrRoot.ssk);
    retVal.mmrHashes.GetSSK(ivk, retVal.mmrHashes.ssk);

    for (int i = 0; i < retVal.dataDescriptors.size(); i++)
    {
        retVal.dataDescriptors[i].GetSSK(ivk, retVal.dataDescriptors[i].ssk);
    }

    return retVal;
}

CMMRDescriptor CMMRDescriptor::AddSymmetricKeys(const std::vector<std::pair<int, std::vector<unsigned char>>> &ssks) const
{
    CMMRDescriptor retVal = *this;

    if (!ssks.size())
    {
        return retVal;
    }

    for (int i = 0; i < ssks.size(); i++)
    {
        if (ssks[i].first == retVal.dataDescriptors.size())
        {
            retVal.mmrRoot.ssk = ssks[i].second;
        }
        if (ssks[i].first == retVal.dataDescriptors.size() + 1)
        {
            retVal.mmrHashes.ssk = ssks[i].second;
        }
        else if (ssks[i].first < retVal.dataDescriptors.size())
        {
            retVal.dataDescriptors[ssks[i].first].ssk = ssks[i].second;
        }
    }

    return retVal;
}

std::vector<std::pair<int, std::vector<unsigned char>>> CMMRDescriptor::GetSymmetricKeys(const libzcash::SaplingIncomingViewingKey &ivk) const
{
    std::vector<std::pair<int, std::vector<unsigned char>>> retVal;
    std::vector<unsigned char> oneSsk;

    if (mmrRoot.GetSSK(ivk, oneSsk))
    {
        retVal.push_back({dataDescriptors.size(), oneSsk});
    }

    if (mmrHashes.GetSSK(ivk, oneSsk))
    {
        retVal.push_back({dataDescriptors.size() + 1, oneSsk});
    }

    for (int i = 0; i < dataDescriptors.size(); i++)
    {
        if (dataDescriptors[i].GetSSK(ivk, oneSsk))
        {
            retVal.push_back({i, oneSsk});
        }
    }

    return retVal;
}

UniValue CMMRDescriptor::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);

    ret.pushKV("version", (int64_t)version);
    ret.pushKV("objecthashtype", (int32_t)objectHashType);
    ret.pushKV("mmrhashtype", (int32_t)mmrHashType);
    ret.pushKV("mmrroot", mmrRoot.ToUniValue());
    ret.pushKV("mmrhashes", mmrHashes.ToUniValue());

    UniValue dataDescriptorsUni(UniValue::VARR);
    for (int i = 0; i < dataDescriptors.size(); i++)
    {
        dataDescriptorsUni.push_back(dataDescriptors[i].ToUniValue());
    }
    ret.pushKV("datadescriptors", dataDescriptorsUni);
    return ret;
}

UniValue CVDXFMMRDescriptor::ToUniValue() const
{
    UniValue obj = ((CVDXF_Data *)this)->ToUniValue();
    obj.pushKV("mmr", mmrDescriptor.ToUniValue());
    return obj;
}

bool CCredential::IsValid() const
{
    bool basicValid = (version >= VERSION_FIRST && version <= VERSION_LAST) && credentialKey != uint160();
    
    // Validate UTF-8 in label field
    if (basicValid && !label.empty())
    {
        if (utf8valid(label.c_str()) != 0)
        {
            return false;
        }
    }
    
    return basicValid;
}

UniValue CCredential::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    int64_t Flags = CalcFlags();

    ret.pushKV("version", (int64_t)version);
    ret.pushKV("flags", Flags);
    ret.pushKV("credentialkey", EncodeDestination(CIdentityID(credentialKey)));

    ret.pushKV("credential", credential);
    ret.pushKV("scopes", scopes);

    if (HasLabel()) {
        ret.pushKV("label", TrimSpaces(label, true, ""));
    }

    return ret;
}

