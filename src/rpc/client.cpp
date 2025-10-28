// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <univalue.h>
#include "rpc/protocol.h"
#include "pbaas/crosschainrpc.h"
#include "pbaas/identity.h"
#include "rpc/client.h"
#include "util.h"

using namespace std;
extern std::string VERUS_CHAINNAME;

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
};

// DUMMY for compile - only used in server
UniValue RPCCallRoot(const string& strMethod, const UniValue& params, int timeout)
{
    printf("%s: Unable to communicate with specified blockchain network\n", __func__);
    return NullUniValue;
}

bool SetThisChain(const UniValue &chainDefinition, CCurrencyDefinition *retDef) {
    return true; // (?) pbaas/pbaas.h
}

CAmount AmountFromValueNoErr(const UniValue& value)
{
    try
    {
        CAmount amount;
        if (!value.isNum() && !value.isStr())
        {
            amount = 0;
        }
        else if (!ParseFixedPoint(value.getValStr(), 8, &amount))
        {
            amount = 0;
        }
        return amount;
    }
    catch(const std::exception& e)
    {
        return 0;
    }
}

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    // Skip & count leading zeroes.
    int zeroes = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    std::vector<unsigned char> b58((pend - pbegin) * 138 / 100 + 1); // log(256) / log(58), rounded up.
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin(); it != b58.rend(); it++) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }
        assert(carry == 0);
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    std::vector<unsigned char>::iterator it = b58.begin();
    while (it != b58.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end())
        str += pszBase58[*(it++)];
    return str;
}

std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(vch.data(), vch.data() + vch.size());
}

std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch)
{
    // Skip leading spaces.
    while (*psz && isspace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    std::vector<unsigned char> b256(strlen(psz) * 733 / 1000 + 1); // log(58) / log(256), rounded up.
    // Process the characters.
    while (*psz && !isspace(*psz)) {
        // Decode base58 character
        const char* ch = strchr(pszBase58, *psz);
        if (ch == NULL)
            return false;
        // Apply "b256 = b256 * 58 + ch".
        int carry = ch - pszBase58;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); it != b256.rend(); it++) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        psz++;
    }
    // Skip trailing spaces.
    while (isspace(*psz))
        psz++;
    if (*psz != 0)
        return false;
    // Skip leading zeroes in b256.
    std::vector<unsigned char>::iterator it = b256.begin();
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
        vch.push_back(*(it++));
    return true;
}

bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58(str.c_str(), vchRet);
}

bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet) ||
        (vchRet.size() < 4)) {
        vchRet.clear();
        return false;
    }
    // re-calculate the checksum, insure it matches the included 4-byte checksum
    uint256 hash = Hash(vchRet.begin(), vchRet.end() - 4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}

class DestinationEncoder : public boost::static_visitor<std::string>
{
public:
    std::vector<std::vector<unsigned char>> base58Prefixes;

    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        IDENTITY_ADDRESS,
        INDEX_ADDRESS,
        QUANTUM_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        ZCPAYMENT_ADDRRESS,
        ZCSPENDING_KEY,
        ZCVIEWING_KEY,

        MAX_BASE58_TYPES
    };

    DestinationEncoder() :
        base58Prefixes({{60}, {85}, {102}, {137}, {58}, {188}, {0x04, 0x88, 0xB2, 0x1E}, {0x04, 0x88, 0xAD, 0xE4}, {22,154}, {0xA8,0xAB,0xD3}, {171,54}})
    {
    }

    std::string operator()(const CKeyID& id) const
    {
        std::vector<unsigned char> data = base58Prefixes[CChainParams::PUBKEY_ADDRESS];
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CPubKey& key) const
    {
        std::vector<unsigned char> data = base58Prefixes[CChainParams::PUBKEY_ADDRESS];
        CKeyID id = key.GetID();
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CScriptID& id) const
    {
        std::vector<unsigned char> data = base58Prefixes[CChainParams::SCRIPT_ADDRESS];
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CIdentityID& id) const
    {
        std::vector<unsigned char> data = base58Prefixes[CChainParams::IDENTITY_ADDRESS];
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CIndexID& id) const
    {
        std::vector<unsigned char> data = base58Prefixes[CChainParams::INDEX_ADDRESS];
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CQuantumID& id) const
    {
        std::vector<unsigned char> data = base58Prefixes[CChainParams::QUANTUM_ADDRESS];
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CNoDestination& no) const { return {}; }
};

std::string EncodeDestination(const CTxDestination& dest)
{
    return boost::apply_visitor(DestinationEncoder(), dest);
}

CTxDestination DecodeDestination(const std::string& str)
{
    DestinationEncoder encoder;
    std::vector<unsigned char> data;
    uint160 hash;
    if (DecodeBase58Check(str, data)) {
        // base58-encoded Bitcoin addresses.
        // The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
        const std::vector<unsigned char>& pubkey_prefix = encoder.base58Prefixes[CChainParams::PUBKEY_ADDRESS];
        if (data.size() == hash.size() + pubkey_prefix.size() && std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin())) {
            std::copy(data.begin() + pubkey_prefix.size(), data.end(), hash.begin());
            return CKeyID(hash);
        }

        // The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
        const std::vector<unsigned char>& script_prefix = encoder.base58Prefixes[CChainParams::SCRIPT_ADDRESS];
        if (data.size() == hash.size() + script_prefix.size() && std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) {
            std::copy(data.begin() + script_prefix.size(), data.end(), hash.begin());
            return CScriptID(hash);
        }

        const std::vector<unsigned char>& identity_prefix = encoder.base58Prefixes[CChainParams::IDENTITY_ADDRESS];
        if (data.size() == hash.size() + identity_prefix.size() && std::equal(identity_prefix.begin(), identity_prefix.end(), data.begin())) {
            std::copy(data.begin() + identity_prefix.size(), data.end(), hash.begin());
            return CIdentityID(hash);
        }

        const std::vector<unsigned char>& index_prefix = encoder.base58Prefixes[CChainParams::INDEX_ADDRESS];
        if (data.size() == hash.size() + index_prefix.size() && std::equal(index_prefix.begin(), index_prefix.end(), data.begin())) {
            std::copy(data.begin() + index_prefix.size(), data.end(), hash.begin());
            return CIndexID(hash);
        }

        const std::vector<unsigned char>& quantum_prefix = encoder.base58Prefixes[CChainParams::QUANTUM_ADDRESS];
        if (data.size() == hash.size() + quantum_prefix.size() && std::equal(quantum_prefix.begin(), quantum_prefix.end(), data.begin())) {
            std::copy(data.begin() + quantum_prefix.size(), data.end(), hash.begin());
            return CQuantumID(hash);
        }
    }
    else if (std::count(str.begin(), str.end(), '@') == 1)
    {
        uint160 parent;
        std::string cleanName = CleanName(str, parent, true);
        if (cleanName != "")
        {
            parent.SetNull();
            return CIdentityID(CIdentity::GetID(str, parent));
        }
    }

    return CNoDestination();
}

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

uint160 GetDestinationID(const CTxDestination dest)
{
    return boost::apply_visitor(DestinationID(), dest);
}

uint160 DecodeCurrencyName(std::string currencyStr)
{
    uint160 retVal;
    if (!currencyStr.size())
    {
        return retVal;
    }
    if (currencyStr.back() == '@')
    {
        return retVal;
    }
    std::string copyStr = currencyStr;

    uint160 parent;

    currencyStr = CleanName(currencyStr, parent, true, currencyStr.back() != '.');

    if (!parent.IsNull() && CCurrencyDefinition::GetID(currencyStr, parent) == ASSETCHAINS_CHAINID)
    {
        return ASSETCHAINS_CHAINID;
    }

    CTxDestination currencyDest = DecodeDestination(currencyStr);

    if (currencyDest.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        currencyDest = DecodeDestination(copyStr + "@");
    }
    if (currencyDest.which() != COptCCParams::ADDRTYPE_INVALID)
    {
        return GetDestinationID(currencyDest);
    }
    return retVal;
}

uint160 CCurrencyDefinition::GetID(const std::string &Name, uint160 &Parent)
{
    return CIdentity::GetID(Name, Parent);
}

CCurrencyDefinition::CCurrencyDefinition(const UniValue &obj) :
    initialFractionalSupply(0),
    gatewayConverterIssuance(0),
    preLaunchDiscount(0),
    preLaunchCarveOut(0),
    minNotariesConfirm(0),
    idRegistrationFees(IDENTITY_REGISTRATION_FEE),
    idReferralLevels(DEFAULT_ID_REFERRAL_LEVELS),
    idImportFees(IDENTITY_IMPORT_FEE),
    currencyRegistrationFee(CURRENCY_REGISTRATION_FEE),
    pbaasSystemLaunchFee(PBAAS_SYSTEM_LAUNCH_FEE),
    currencyImportFee(CURRENCY_IMPORT_FEE),
    transactionImportFee(TRANSACTION_CROSSCHAIN_FEE >> 1),
    transactionExportFee(TRANSACTION_CROSSCHAIN_FEE >> 1),
    initialBits(DEFAULT_START_TARGET),
    blockTime(DEFAULT_BLOCKTIME_TARGET),
    powAveragingWindow(DEFAULT_AVERAGING_WINDOW),
    blockNotarizationModulo(BLOCK_NOTARIZATION_MODULO)
{
    try
    {
        nVersion = uni_get_int64(find_value(obj, "version"), VERSION_CURRENT);
        options = (uint32_t)uni_get_int64(find_value(obj, "options"));
        name = std::string(uni_get_str(find_value(obj, "name")), 0, (KOMODO_ASSETCHAIN_MAXLEN - 1));

        std::string parentStr = uni_get_str(find_value(obj, "parent"));
        if (parentStr != "")
        {
            parent = DecodeCurrencyName(parentStr);
            if (parent.IsNull())
            {
                LogPrintf("%s: invalid parent for currency: %s\n", __func__, parentStr.c_str());
                nVersion = PBAAS_VERSION_INVALID;
                return;
            }
        }

        name = CleanName(name, parent, true);

        std::string systemIDStr = uni_get_str(find_value(obj, "systemid"));
        if (systemIDStr != "")
        {
            systemID = DecodeCurrencyName(systemIDStr);
            // if we have a system, but it is invalid, the json for this definition cannot be valid
            if (systemID.IsNull())
            {
                nVersion = PBAAS_VERSION_INVALID;
                return;
            }
        }
        else
        {
            systemID = parent;
        }

        gatewayConverterName = uni_get_str(find_value(obj, "gatewayconvertername"));
        if (!gatewayConverterName.empty())
        {
            if (!(IsPBaaSChain() || IsGateway()) || (IsPBaaSChain() && IsGateway()))
            {
                LogPrintf("%s: a gateway converter currency may only be defined as part of a gateway or PBaaS system definition\n", __func__);
                nVersion = PBAAS_VERSION_INVALID;
                return;
            }
            else if (IsGateway())
            {
                gatewayID = GetID();
            }
            uint160 parent = GetID();
            std::string cleanGatewayName = CleanName(gatewayConverterName, parent, true);
            uint160 converterID = GetID(cleanGatewayName, parent);
            if (parent != GetID())
            {
                LogPrintf("%s: invalid name for gateway converter %s\n", __func__, cleanGatewayName.c_str());
                nVersion = PBAAS_VERSION_INVALID;
                return;
            }
        }

        if (IsPBaaSChain() || IsGateway() || IsGatewayConverter())
        {
            gatewayConverterIssuance = AmountFromValueNoErr(find_value(obj, "gatewayconverterissuance"));
        }

        notarizationProtocol = (ENotarizationProtocol)uni_get_int(find_value(obj, "notarizationprotocol"), (int32_t)NOTARIZATION_AUTO);
        if (notarizationProtocol != NOTARIZATION_AUTO && notarizationProtocol != NOTARIZATION_NOTARY_CONFIRM)
        {
            LogPrintf("%s: notarization protocol for PBaaS chains must be %d (NOTARIZATION_AUTO) or %d (NOTARIZATION_NOTARY_CONFIRM)\n", __func__, (int)NOTARIZATION_NOTARY_CONFIRM);
            nVersion = PBAAS_VERSION_INVALID;
            return;
        }
        proofProtocol = (EProofProtocol)uni_get_int(find_value(obj, "proofprotocol"), (int32_t)PROOF_PBAASMMR);
        if (proofProtocol != PROOF_PBAASMMR && proofProtocol != PROOF_CHAINID && proofProtocol != PROOF_ETHNOTARIZATION)
        {
            LogPrintf("%s: proofprotocol must be %d, %d, or %d\n", __func__, (int)PROOF_PBAASMMR, (int)PROOF_CHAINID, (int)PROOF_ETHNOTARIZATION);
            nVersion = PBAAS_VERSION_INVALID;
            return;
        }

        if (proofProtocol == PROOF_CHAINID && IsPBaaSChain())
        {
            LogPrintf("%s: proofprotocol %d not yet implemented\n", __func__, (int)PROOF_CHAINID);
            nVersion = PBAAS_VERSION_INVALID;
            return;
        }

        nativeCurrencyID = CTransferDestination();

        std::string launchIDStr = uni_get_str(find_value(obj, "launchsystemid"));
        if (launchIDStr != "")
        {
            launchSystemID = DecodeCurrencyName(launchIDStr);
            // if we have a system, but it is invalid, the json for this definition cannot be valid
            if (launchSystemID.IsNull())
            {
                nVersion = PBAAS_VERSION_INVALID;
                return;
            }
        }
        else
        {
            launchSystemID = parent;
        }

        startBlock = (uint32_t)uni_get_int64(find_value(obj, "startblock"));
        endBlock = (uint32_t)uni_get_int64(find_value(obj, "endblock"));

        int32_t totalReserveWeight = IsFractional() ? SATOSHIDEN : 0;
        UniValue currencyArr = find_value(obj, "currencies");
        UniValue weightArr = find_value(obj, "weights");
        UniValue conversionArr = find_value(obj, "conversions");
        UniValue minPreconvertArr = find_value(obj, "minpreconversion");
        UniValue maxPreconvertArr = find_value(obj, "maxpreconversion");
        UniValue initialContributionArr = find_value(obj, "initialcontributions");

        if (currencyArr.isArray() && currencyArr.size())
        {
            contributions = preconverted = std::vector<int64_t>(currencyArr.size());

            if (initialContributionArr.isNull())
            {
                initialContributionArr = UniValue(UniValue::VARR);
                for (int i = 0; i < currencyArr.size(); i++)
                {
                    initialContributionArr.push_back((CAmount)0);
                }
            }

            if (IsFractional())
            {
                preLaunchDiscount = AmountFromValueNoErr(find_value(obj, "prelaunchdiscount"));
                initialFractionalSupply = AmountFromValueNoErr(find_value(obj, "initialsupply"));

                if (!initialFractionalSupply)
                {
                    LogPrintf("%s: cannot specify zero initial supply for fractional currency\n", __func__);
                    printf("%s: cannot specify zero initial supply for fractional currency\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }

                preLaunchCarveOut = AmountFromValueNoErr(find_value(obj, "prelaunchcarveout"));

                // if weights are defined, use them as relative ratios of each member currency
                if (weightArr.isArray() && weightArr.size())
                {
                    if (weightArr.size() != currencyArr.size())
                    {
                        LogPrintf("%s: reserve currency weights must be specified for all currencies\n", __func__);
                        nVersion = PBAAS_VERSION_INVALID;
                    }
                    else
                    {
                        CAmount total = 0;
                        for (int i = 0; i < currencyArr.size(); i++)
                        {
                            int32_t weight = (int32_t)AmountFromValueNoErr(weightArr[i]);
                            if (weight <= 0)
                            {
                                nVersion = PBAAS_VERSION_INVALID;
                                total = 0;
                                break;
                            }
                            total += weight;
                            weights.push_back(weight);
                        }
                        if (nVersion != PBAAS_VERSION_INVALID)
                        {
                            // calculate each weight as a relative part of the total
                            // reserve weight
                            int64_t totalRelativeWeight = 0;
                            for (auto &onew : weights)
                            {
                                totalRelativeWeight += onew;
                            }

                            int weightIdx;
                            arith_uint256 bigReserveWeight(totalReserveWeight);
                            int32_t reserveLeft = totalReserveWeight;
                            for (weightIdx = 0; weightIdx < weights.size(); weightIdx++)
                            {
                                CAmount amount = (bigReserveWeight * arith_uint256(weights[weightIdx]) / arith_uint256(totalRelativeWeight)).GetLow64();
                                if (reserveLeft <= amount || (weightIdx + 1) == weights.size())
                                {
                                    amount = reserveLeft;
                                }
                                reserveLeft -= amount;
                                weights[weightIdx] = amount;
                            }
                        }
                    }
                }
                else if (totalReserveWeight)
                {
                    uint32_t oneWeight = totalReserveWeight / currencyArr.size();
                    uint32_t mod = totalReserveWeight % currencyArr.size();
                    for (int i = 0; i < currencyArr.size(); i++)
                    {
                        // distribute remainder of weight among first come currencies
                        int32_t weight = oneWeight;
                        if (mod > 0)
                        {
                            weight++;
                            mod--;
                        }
                        weights.push_back(weight);
                    }
                }
            }

            // if we have weights, we can be a fractional currency
            if (weights.size())
            {
                // if we are fractional, explicit conversion values are not valid
                // and are based on non-zero, initial contributions relative to supply
                if ((conversionArr.isArray() && conversionArr.size() != currencyArr.size()) ||
                    !initialContributionArr.isArray() ||
                    initialContributionArr.size() != currencyArr.size() ||
                    weights.size() != currencyArr.size() ||
                    !IsFractional())
                {
                    LogPrintf("%s: fractional currencies must have weights, initial contributions in at least one currency\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
            }
            else
            {
                // if we are not a reserve currency, we either have a conversion vector, or we are not convertible at all
                if (IsFractional())
                {
                    LogPrintf("%s: reserve currencies must define currency weight\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                else if (conversionArr.isArray() && conversionArr.size() && conversionArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: non-reserve currencies must define all conversion rates for supported currencies if they define any\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                else if (initialContributionArr.isArray() && initialContributionArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: initial contributions for currencies must all be specified if any are specified\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
            }

            if (nVersion != PBAAS_VERSION_INVALID && IsFractional())
            {
                if (minPreconvertArr.isArray() && minPreconvertArr.size() && minPreconvertArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: currencies with minimum conversion required must define all minimums if they define any\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                if (maxPreconvertArr.isArray() && maxPreconvertArr.size() && maxPreconvertArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: currencies that include maximum conversions on pre-launch must specify all maximums\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                if (initialContributionArr.isArray() && initialContributionArr.size() && initialContributionArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: currencies that include initial contributions in one currency on pre-launch must specify all currency amounts\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
            }

            bool isInitialContributions = initialContributionArr.isArray() && initialContributionArr.size();
            bool isPreconvertMin = minPreconvertArr.isArray() && minPreconvertArr.size();
            bool isPreconvertMax = maxPreconvertArr.isArray() && maxPreconvertArr.size();
            bool explicitConversions = (!IsFractional() && conversionArr.isArray()) && conversionArr.size();

            for (int i = 0; nVersion != PBAAS_VERSION_INVALID && i < currencyArr.size(); i++)
            {
                uint160 currencyID = DecodeCurrencyName(uni_get_str(currencyArr[i]));
                // if we have a destination, but it is invalid, the json for this definition cannot be valid
                if (currencyID.IsNull())
                {
                    nVersion = PBAAS_VERSION_INVALID;
                    break;
                }
                else
                {
                    currencies.push_back(currencyID);
                }

                if (isInitialContributions && i < initialContributionArr.size())
                {
                    int64_t contrib = AmountFromValueNoErr(initialContributionArr[i]);
                    contributions[i] = contrib;
                    preconverted[i] = contrib;
                }

                int64_t minPre = 0;
                if (isPreconvertMin)
                {
                    minPre = AmountFromValueNoErr(minPreconvertArr[i]);
                    if (minPre < 0)
                    {
                        LogPrintf("%s: minimum preconversions for any currency may not be less than 0\n", __func__);
                        nVersion = PBAAS_VERSION_INVALID;
                        break;
                    }
                    minPreconvert.push_back(minPre);
                }
                if (isPreconvertMax)
                {
                    int64_t maxPre = AmountFromValueNoErr(maxPreconvertArr[i]);
                    if (maxPre < 0 || maxPre < minPre)
                    {
                        LogPrintf("%s: maximum preconversions for any currency may not be less than 0 or minimum\n", __func__);
                        nVersion = PBAAS_VERSION_INVALID;
                        break;
                    }
                    maxPreconvert.push_back(maxPre);
                }
                if (explicitConversions)
                {
                    int64_t conversion = AmountFromValueNoErr(conversionArr[i]);
                    if (conversion < 0)
                    {
                        LogPrintf("%s: conversions for any currency must be greater than 0\n", __func__);
                        nVersion = PBAAS_VERSION_INVALID;
                        break;
                    }
                    conversions.push_back(conversion);
                }
                else
                {
                    conversions.push_back(0);
                }
            }
        }

        UniValue preallocationArr = find_value(obj, "preallocations");
        if (preallocationArr.isArray())
        {
            for (int i = 0; i < preallocationArr.size(); i++)
            {
                std::vector<std::string> preallocationKey = preallocationArr[i].getKeys();
                std::vector<UniValue> preallocationValue = preallocationArr[i].getValues();
                if (preallocationKey.size() != 1 || preallocationValue.size() != 1)
                {
                    LogPrintf("%s: each preallocation entry must contain one destination identity and one amount\n", __func__);
                    printf("%s: each preallocation entry must contain one destination identity and one amount\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                    break;
                }

                CTxDestination preallocDest = DecodeDestination(preallocationKey[0]);

                if (preallocDest.which() != COptCCParams::ADDRTYPE_ID && preallocDest.which() != COptCCParams::ADDRTYPE_INVALID)
                {
                    LogPrintf("%s: preallocation destination must be an identity\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                    break;
                }

                CAmount preAllocAmount = AmountFromValueNoErr(preallocationValue[0]);
                if (preAllocAmount <= 0)
                {
                    LogPrintf("%s: preallocation values must be greater than zero\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                    break;
                }
                preAllocation.push_back(make_pair(CIdentityID(GetDestinationID(preallocDest)), preAllocAmount));
            }
        }

        UniValue notaryArr = find_value(obj, "notaries");
        minNotariesConfirm = 0;
        if (notaryArr.isArray())
        {
            for (int i = 0; i < notaryArr.size(); i++)
            {
                CIdentityID notaryID;
                CTxDestination notaryDest = DecodeDestination(uni_get_str(notaryArr[i]));
                notaryID = GetDestinationID(notaryDest);
                // if we have a destination, but it is invalid, the json for this definition cannot be valid
                if (notaryID.IsNull())
                {
                    nVersion = PBAAS_VERSION_INVALID;
                }
                else
                {
                    notaries.push_back(notaryID);
                }
            }
            minNotariesConfirm = uni_get_int(find_value(obj, "minnotariesconfirm"));
        }

        UniValue registrationFeeValue = find_value(obj, "idregistrationfees");
        idRegistrationFees = registrationFeeValue.isNull() ? idRegistrationFees : AmountFromValueNoErr(registrationFeeValue);

        idReferralLevels = uni_get_int(find_value(obj, "idreferrallevels"), idReferralLevels);

        registrationFeeValue = find_value(obj, "idimportfees");
        idImportFees = registrationFeeValue.isNull() ? idImportFees : AmountFromValueNoErr(registrationFeeValue);

        registrationFeeValue = find_value(obj, "currencyregistrationfee");
        currencyRegistrationFee = registrationFeeValue.isNull() ? currencyRegistrationFee : AmountFromValueNoErr(registrationFeeValue);

        registrationFeeValue = find_value(obj, "pbaassystemregistrationfee");
        pbaasSystemLaunchFee = registrationFeeValue.isNull() ? pbaasSystemLaunchFee : AmountFromValueNoErr(registrationFeeValue);

        registrationFeeValue = find_value(obj, "currencyimportfee");
        currencyImportFee = registrationFeeValue.isNull() ? currencyImportFee : AmountFromValueNoErr(registrationFeeValue);

        registrationFeeValue = find_value(obj, "transactionimportfee");
        transactionImportFee = registrationFeeValue.isNull() ? transactionImportFee : AmountFromValueNoErr(registrationFeeValue);

        registrationFeeValue = find_value(obj, "transactionexportfee");
        transactionExportFee = registrationFeeValue.isNull() ? transactionExportFee : AmountFromValueNoErr(registrationFeeValue);

        if (!gatewayID.IsNull())
        {
            gatewayConverterIssuance = AmountFromValueNoErr(find_value(obj, "gatewayconverterissuance"));
        }

        auto vEras = uni_getValues(find_value(obj, "eras"));
        if (vEras.size() > ASSETCHAINS_MAX_ERAS)
        {
            vEras.resize(ASSETCHAINS_MAX_ERAS);
        }

        if (vEras.size())
        {
            try
            {
                uint32_t newInitialBits = UintToArith256(uint256S(uni_get_str(find_value(obj, "initialtarget")))).GetCompact();
                if (newInitialBits)
                {
                    initialBits = newInitialBits;
                }
            }
            catch(const std::exception& e)
            {
                LogPrintf("%s: Invalid initial target, must be 256 bit hex target\n", __func__);
                throw e;
            }

            blockTime = uni_get_int64(find_value(obj, "blocktime"), DEFAULT_BLOCKTIME_TARGET);
            powAveragingWindow = uni_get_int64(find_value(obj, "powaveragingwindow"), DEFAULT_AVERAGING_WINDOW);
            blockNotarizationModulo = uni_get_int64(find_value(obj, "notarizationperiod"),
                                                    std::max((int64_t)(DEFAULT_BLOCK_NOTARIZATION_TIME / blockTime), (int64_t)MIN_BLOCK_NOTARIZATION_PERIOD));

            for (auto era : vEras)
            {
                rewards.push_back(uni_get_int64(find_value(era, "reward")));
                rewardsDecay.push_back(uni_get_int64(find_value(era, "decay")));
                halving.push_back(uni_get_int64(find_value(era, "halving")));
                eraEnd.push_back(uni_get_int64(find_value(era, "eraend")));
            }

            if (!rewards.size())
            {
                LogPrintf("%s: PBaaS chain does not have valid rewards eras");
                nVersion = PBAAS_VERSION_INVALID;
            }
        }
    }
    catch (exception e)
    {
        LogPrintf("%s: exception reading currency definition JSON\n", __func__, e.what());
        nVersion = PBAAS_VERSION_INVALID;
    }
}

CCurrencyDefinition::CCurrencyDefinition(const std::string &currencyName, bool testMode) :
    nVersion(VERSION_CURRENT),
    preLaunchDiscount(0),
    initialFractionalSupply(0),
    gatewayConverterIssuance(0),
    minNotariesConfirm(0),
    idRegistrationFees(IDENTITY_REGISTRATION_FEE),
    idReferralLevels(DEFAULT_ID_REFERRAL_LEVELS),
    idImportFees(IDENTITY_IMPORT_FEE),
    currencyRegistrationFee(CURRENCY_REGISTRATION_FEE),
    pbaasSystemLaunchFee(PBAAS_SYSTEM_LAUNCH_FEE),
    currencyImportFee(CURRENCY_IMPORT_FEE),
    transactionImportFee(TRANSACTION_CROSSCHAIN_FEE >> 1),
    transactionExportFee(TRANSACTION_CROSSCHAIN_FEE >> 1),
    initialBits(DEFAULT_START_TARGET),
    blockTime(DEFAULT_BLOCKTIME_TARGET),
    powAveragingWindow(DEFAULT_AVERAGING_WINDOW),
    blockNotarizationModulo(BLOCK_NOTARIZATION_MODULO)
{
    name = boost::to_upper_copy(CleanName(currencyName, parent, true));
    if (parent.IsNull())
    {
        UniValue uniCurrency(UniValue::VOBJ);
        uint160 thisCurrencyID = GetID();

        uniCurrency.pushKV("options", CCurrencyDefinition::OPTION_PBAAS + CCurrencyDefinition::OPTION_ID_REFERRALS);
        uniCurrency.pushKV("name", name);
        uniCurrency.pushKV("systemid", EncodeDestination(CIdentityID(thisCurrencyID)));
        uniCurrency.pushKV("notarizationprotocol", (int32_t)NOTARIZATION_AUTO);
        uniCurrency.pushKV("proofprotocol", (int32_t)PROOF_PBAASMMR);

        uniCurrency.pushKV("blocktime", (int64_t)DEFAULT_BLOCKTIME_TARGET);
        uniCurrency.pushKV("powaveragingwindow", (int64_t)DEFAULT_AVERAGING_WINDOW);
        uniCurrency.pushKV("notarizationperiod", (int)BLOCK_NOTARIZATION_MODULO);

        if (name == "VRSC" && !testMode)
        {
            UniValue uniEras(UniValue::VARR);
            UniValue uniEra1(UniValue::VARR);
            uniEra1.pushKV("reward", 0);
            uniEra1.pushKV("decay", 100000000);
            uniEra1.pushKV("halving", 1);
            uniEra1.pushKV("eraend", 10080);
            uniEras.push_back(uniEra1);

            UniValue uniEra2(UniValue::VARR);
            uniEra2.pushKV("reward", (int64_t)38400000000);
            uniEra2.pushKV("decay", 0);
            uniEra2.pushKV("halving", 43200);
            uniEra2.pushKV("eraend", 226080);
            uniEras.push_back(uniEra2);

            UniValue uniEra3(UniValue::VARR);
            uniEra2.pushKV("reward", (int64_t)2400000000);
            uniEra2.pushKV("decay", 0);
            uniEra2.pushKV("halving", 1051920);
            uniEra2.pushKV("eraend", 0);
            uniEras.push_back(uniEra2);

            uniCurrency.pushKV("eras", uniEras);

            *this = CCurrencyDefinition(uniCurrency);
        }
        else if (name == "VRSCTEST" || (testMode && name == "VRSC"))
        {
            name = "VRSCTEST";

            UniValue preAllocUni(UniValue::VOBJ);
            preAllocUni.pushKV(EncodeDestination(CIdentityID()), (int64_t)5000000000000000);

            UniValue uniEras(UniValue::VARR);
            UniValue uniEra1(UniValue::VARR);
            uniEra1.pushKV("reward", 1200000000);
            uniEra1.pushKV("decay", 0);
            uniEra1.pushKV("halving", 1174000);
            uniEra1.pushKV("eraend", 0);
            uniEras.push_back(uniEra1);

            uniCurrency.pushKV("eras", uniEras);

            *this = CCurrencyDefinition(uniCurrency);
        }
        else
        {
            nVersion = VERSION_INVALID;
        }
    }
    else
    {
        nVersion = VERSION_INVALID;
    }
}

UniValue CCurrencyDefinition::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);

    obj.push_back(Pair("version", (int64_t)nVersion));
    obj.push_back(Pair("options", (int64_t)options));
    obj.push_back(Pair("name", name));
    obj.push_back(Pair("currencyid", EncodeDestination(CIdentityID(GetID()))));
    if (!parent.IsNull())
    {
        obj.push_back(Pair("parent", EncodeDestination(CIdentityID(parent))));
    }

    obj.push_back(Pair("systemid", EncodeDestination(CIdentityID(systemID))));
    obj.push_back(Pair("notarizationprotocol", (int)notarizationProtocol));
    obj.push_back(Pair("proofprotocol", (int)proofProtocol));

    if (nativeCurrencyID.IsValid())
    {
        //obj.push_back(Pair("nativecurrencyid", nativeCurrencyID.ToUniValue()));
    }

    if (!launchSystemID.IsNull())
    {
        obj.push_back(Pair("launchsystemid", EncodeDestination(CIdentityID(launchSystemID))));
    }
    obj.push_back(Pair("startblock", (int64_t)startBlock));
    obj.push_back(Pair("endblock", (int64_t)endBlock));

    // currencies that can be converted for pre-launch or fractional usage
    if (currencies.size())
    {
        UniValue currencyArr(UniValue::VARR);
        for (auto &currency : currencies)
        {
            currencyArr.push_back(EncodeDestination(CIdentityID(currency)));
        }
        obj.push_back(Pair("currencies", currencyArr));
    }

    if (weights.size())
    {
        UniValue weightArr(UniValue::VARR);
        for (auto &weight : weights)
        {
            weightArr.push_back(ValueFromAmount(weight));
        }
        obj.push_back(Pair("weights", weightArr));
    }

    if (conversions.size())
    {
        UniValue conversionArr(UniValue::VARR);
        for (auto &conversion : conversions)
        {
            conversionArr.push_back(ValueFromAmount(conversion));
        }
        obj.push_back(Pair("conversions", conversionArr));
    }

    if (minPreconvert.size())
    {
        UniValue minPreconvertArr(UniValue::VARR);
        for (auto &oneMin : minPreconvert)
        {
            minPreconvertArr.push_back(ValueFromAmount(oneMin));
        }
        obj.push_back(Pair("minpreconversion", minPreconvertArr));
    }

    if (maxPreconvert.size())
    {
        UniValue maxPreconvertArr(UniValue::VARR);
        for (auto &oneMax : maxPreconvert)
        {
            maxPreconvertArr.push_back(ValueFromAmount(oneMax));
        }
        obj.push_back(Pair("maxpreconversion", maxPreconvertArr));
    }

    if (preLaunchDiscount)
    {
        obj.push_back(Pair("prelaunchdiscount", ValueFromAmount(preLaunchDiscount)));
    }

    if (IsFractional())
    {
        obj.push_back(Pair("initialsupply", ValueFromAmount(initialFractionalSupply)));
        obj.push_back(Pair("prelaunchcarveout", ValueFromAmount(preLaunchCarveOut)));
    }

    if (preAllocation.size())
    {
        UniValue preAllocationArr(UniValue::VARR);
        for (auto &onePreAllocation : preAllocation)
        {
            UniValue onePreAlloc(UniValue::VOBJ);
            onePreAlloc.push_back(Pair(onePreAllocation.first.IsNull() ? "blockoneminer" : EncodeDestination(CIdentityID(onePreAllocation.first)),
                                       ValueFromAmount(onePreAllocation.second)));
            preAllocationArr.push_back(onePreAlloc);
        }
        obj.push_back(Pair("preallocations", preAllocationArr));
    }

    if (!gatewayID.IsNull())
    {
        obj.push_back(Pair("gateway", EncodeDestination(CIdentityID(gatewayID))));
    }

    if (contributions.size())
    {
        UniValue initialContributionArr(UniValue::VARR);
        for (auto &oneCurContributions : contributions)
        {
            initialContributionArr.push_back(ValueFromAmount(oneCurContributions));
        }
        obj.push_back(Pair("initialcontributions", initialContributionArr));
    }

    if (IsGateway() || IsGatewayConverter() || IsPBaaSChain())
    {
        obj.push_back(Pair("gatewayconverterissuance", ValueFromAmount(gatewayConverterIssuance)));
    }

    obj.push_back(Pair("idregistrationfees", ValueFromAmount(idRegistrationFees)));
    obj.push_back(Pair("idreferrallevels", idReferralLevels));
    obj.push_back(Pair("idimportfees", ValueFromAmount(idImportFees)));

    if (IsGateway() || IsPBaaSChain())
    {
        // notaries are identities that perform specific functions for the currency's operation
        // related to notarizing an external currency source, as well as proving imports
        if (notaries.size())
        {
            UniValue notaryArr(UniValue::VARR);
            for (auto &notary : notaries)
            {
                notaryArr.push_back(EncodeDestination(CIdentityID(notary)));
            }
            obj.push_back(Pair("notaries", notaryArr));
        }
        obj.push_back(Pair("minnotariesconfirm", minNotariesConfirm));

        obj.push_back(Pair("currencyregistrationfee", ValueFromAmount(currencyRegistrationFee)));
        obj.push_back(Pair("pbaassystemregistrationfee", ValueFromAmount(pbaasSystemLaunchFee)));
        obj.push_back(Pair("currencyimportfee", ValueFromAmount(currencyImportFee)));
        obj.push_back(Pair("transactionimportfee", ValueFromAmount(transactionImportFee)));
        obj.push_back(Pair("transactionexportfee", ValueFromAmount(transactionExportFee)));

        if (!gatewayConverterName.empty())
        {
            obj.push_back(Pair("gatewayconverterid", EncodeDestination(CIdentityID(GatewayConverterID()))));
            obj.push_back(Pair("gatewayconvertername", gatewayConverterName));
        }

        if (IsPBaaSChain())
        {
            arith_uint256 target;
            target.SetCompact(initialBits);
            obj.push_back(Pair("initialtarget", ArithToUint256(target).GetHex()));

            obj.pushKV("blocktime", (int64_t)blockTime);
            obj.pushKV("powaveragingwindow", (int64_t)powAveragingWindow);
            obj.pushKV("notarizationperiod", (int)blockNotarizationModulo);

            UniValue eraArr(UniValue::VARR);
            for (int i = 0; i < rewards.size(); i++)
            {
                UniValue era(UniValue::VOBJ);
                era.push_back(Pair("reward", rewards.size() > i ? rewards[i] : (int64_t)0));
                era.push_back(Pair("decay", rewardsDecay.size() > i ? rewardsDecay[i] : (int64_t)0));
                era.push_back(Pair("halving", halving.size() > i ? (int32_t)halving[i] : (int32_t)0));
                era.push_back(Pair("eraend", eraEnd.size() > i ? (int32_t)eraEnd[i] : (int32_t)0));
                eraArr.push_back(era);
            }
            obj.push_back(Pair("eras", eraArr));
        }
    }

    return obj;
}

CTransferDestination CTransferDestination::GetAuxDest(int destNum) const
{
    CTransferDestination retVal;
    if (destNum >= 0 && destNum < auxDests.size())
    {
        ::FromVector(auxDests[destNum], retVal);
        if (retVal.type & FLAG_DEST_AUX || retVal.auxDests.size())
        {
            retVal.type = DEST_INVALID;
        }
        // no gateways or flags, only simple destinations work
        switch (retVal.type)
        {
            case DEST_ID:
            case DEST_PK:
            case DEST_PKH:
            case DEST_ETH:
            case DEST_SH:
                break;
            default:
                retVal.type = DEST_INVALID;
        }
    }
    return retVal;
}

int64_t CCurrencyDefinition::GetTotalPreallocation() const
{
    CAmount totalPreallocatedNative = 0;
    for (auto &onePreallocation : preAllocation)
    {
        if (!MoneyRange(onePreallocation.second) ||
            !MoneyRange(totalPreallocatedNative += onePreallocation.second))
        {
            totalPreallocatedNative = INT64_MAX;
            break;
        }
    }
    return totalPreallocatedNative;
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
        if (uv.isStr())
        {
            return atoi(uv.get_str());
        }
        return uv.get_int();
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
        if (uv.isStr())
        {
            return atoi64(uv.get_str());
        }
        return uv.get_int64();
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

uint160 CCrossChainRPCData::GetConditionID(const uint160 &cid, uint32_t condition)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 GetConditionID(const uint160 &cid, const uint160 &condition)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 GetConditionID(const uint160 &cid, const uint160 &condition, const uint256 &txid, int32_t voutNum)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    hw << txid;
    hw << voutNum;
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

std::string TrimSpaces(const std::string &Name, bool removeDuals, const std::string &invalidChars)
{
    std::string nameCopy = Name;
    std::string noDuals = "\u0020\u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u200C\u200D\u202F\u205F\u3000";
    std::vector<int> allDuals;
    std::vector<int> toRemove;
    for (int i = 0; i < nameCopy.size(); i++)
    {
        size_t dualCharPos = noDuals.find(nameCopy[i]);
        if ((removeDuals ||
                (i == allDuals.size() ||
                i == (nameCopy.size() - 1))) &&
                dualCharPos != std::string::npos)
        {
            bool wasLastDual = allDuals.size() && allDuals.back() == (i - 1);
            if (i == allDuals.size() ||
                i == (nameCopy.size() - 1) ||
                (removeDuals && wasLastDual))
            {
                toRemove.push_back(i);
            }
            allDuals.push_back(i);
            if (i &&
                i == (nameCopy.size() - 1) &&
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
    for (auto posIt = toRemove.rbegin(); posIt != toRemove.rend(); posIt++)
    {
        nameCopy.erase(nameCopy.begin() + *posIt);
    }
    return nameCopy;
}

// this will add the current Verus chain name to subnames if it is not present
// on both id and chain names
std::vector<std::string> ParseSubNames(const std::string &Name, std::string &ChainOut, bool displayfilter, bool addVerus)
{
    std::string nameCopy = Name;

    std::vector<std::string> retNames;
    boost::split(retNames, nameCopy, boost::is_any_of("@"));
    if (!retNames.size() || retNames.size() > 2)
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
        nameCopy.pop_back();
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
// takes a multipart name, either complete or partially processed with a Parent hash,
// hash its parent names into a parent ID and return the parent hash and cleaned, single name
std::string CleanName(const std::string &Name, uint160 &Parent, bool displayfilter, bool addVerus)
{
    // The line below should make sense, but this path should be tested in test mode until we are sure there are
    // no edge cases
    addVerus = addVerus && (!PBAAS_TESTMODE || Parent.IsNull());
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

UniValue CNodeData::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("networkaddress", networkAddress));
    obj.push_back(Pair("nodeidentity", ""));
    return obj;
}

CNodeData::CNodeData(std::string netAddr, std::string paymentAddr) :
    networkAddress(netAddr)
{
}

// returns 1 object or none if no valid, recognize object at front of stream
template <typename Stream> UniValue CIdentity::VDXFDataToUniValue(Stream &ss, bool *pSuccess)
{
    if (pSuccess)
    {
        *pSuccess = false;
    }
    return UniValue(UniValue::VNULL);
}

UniValue CIdentity::VDXFDataToUniValue(const std::vector<unsigned char> &dataVch)
{
    return UniValue(UniValue::VNULL);
}

CIdentityID CIdentity::GetID(const std::string &Name, uint160 &parent)
{
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
    return GetID(name);
}

uint160 CCrossChainRPCData::GetID(std::string name)
{
    uint160 parent;
    return CIdentity::GetID(name,parent);
}

UniValue ValueFromAmount(const CAmount& amount)
{
    bool sign = amount < 0;
    int64_t n_abs = (sign ? -amount : amount);
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;
    return UniValue(UniValue::VNUM,
            strprintf("%s%d.%08d", sign ? "-" : "", quotient, remainder));
}

static const CRPCConvertParam vRPCConvertParams[] =
{
    { "stop", 0 },
    { "setmocktime", 0 },
    { "getaddednodeinfo", 0 },
    { "setgenerate", 0 },
    { "setgenerate", 1 },
    { "generate", 0 },
    { "getnetworkhashps", 0 },
    { "getnetworkhashps", 1 },
    { "getnetworksolps", 0 },
    { "getnetworksolps", 1 },
    { "sendtoaddress", 1 },
    { "sendtoaddress", 4 },
    { "settxfee", 0 },
    { "getreceivedbyaddress", 1 },
    { "getreceivedbyaccount", 1 },
    { "listreceivedbyaddress", 0 },
    { "listreceivedbyaddress", 1 },
    { "listreceivedbyaddress", 2 },
    { "listreceivedbyaccount", 0 },
    { "listreceivedbyaccount", 1 },
    { "listreceivedbyaccount", 2 },
    { "getbalance", 1 },
    { "getbalance", 2 },
    { "getcurrencybalance", 1},
    { "getcurrencybalance", 2},
    //{ "getcurrencyconverters", 0},
    { "getblockhash", 0 },
    { "move", 2 },
    { "move", 3 },
    { "sendfrom", 2 },
    { "sendfrom", 3 },
    { "listtransactions", 1 },
    { "listtransactions", 2 },
    { "listtransactions", 3 },
    { "listaccounts", 0 },
    { "listaccounts", 1 },
    { "walletpassphrase", 1 },
    { "setminingdistribution", 0 },
    { "getblocktemplate", 0 },
    { "listsinceblock", 1 },
    { "listsinceblock", 2 },
    { "sendmany", 1 },
    { "sendmany", 2 },
    { "sendmany", 4 },
    { "addmultisigaddress", 0 },
    { "addmultisigaddress", 1 },
    { "createmultisig", 0 },
    { "createmultisig", 1 },
    { "listunspent", 0 },
    { "listunspent", 1 },
    { "listunspent", 2 },
    { "getblock", 1 },
    { "getblockheader", 1 },
    { "gettransaction", 1 },
    { "getrawtransaction", 1 },
    { "createrawtransaction", 0 },
    { "createrawtransaction", 1 },
    { "createrawtransaction", 2 },
    { "createrawtransaction", 3 },
    { "signrawtransaction", 1 },
    { "signrawtransaction", 2 },
    { "sendrawtransaction", 1 },
    { "fundrawtransaction", 1 },
    { "estimateconversion", 0 },
    { "gettxout", 1 },
    { "gettxout", 2 },
    { "gettxoutproof", 0 },
    { "lockunspent", 0 },
    { "lockunspent", 1 },
    { "importprivkey", 2 },
    { "importaddress", 2 },
    { "verifychain", 0 },
    { "verifychain", 1 },
    { "keypoolrefill", 0 },
    { "getrawmempool", 0 },
    { "estimatefee", 0 },
    { "estimatepriority", 0 },
    { "prioritisetransaction", 1 },
    { "prioritisetransaction", 2 },
    { "setban", 2 },
    { "setban", 3 },
    { "getspentinfo", 0},
    { "getaddresstxids", 0},
    { "getaddressbalance", 0},
    { "getaddressdeltas", 0},
    { "getaddressutxos", 0},
    { "getaddressmempool", 0},
    { "getblockhashes", 0},
    { "getblockhashes", 1},
    { "getblockhashes", 2},
    { "getblockdeltas", 0},
    { "zcrawjoinsplit", 1 },
    { "zcrawjoinsplit", 2 },
    { "zcrawjoinsplit", 3 },
    { "zcrawjoinsplit", 4 },
    { "zcbenchmark", 1 },
    { "zcbenchmark", 2 },
    { "getblocksubsidy", 0},
    { "z_listaddresses", 0},
    { "z_listreceivedbyaddress", 1},
    { "z_listunspent", 0 },
    { "z_listunspent", 1 },
    { "z_listunspent", 2 },
    { "z_listunspent", 3 },
    { "z_getbalance", 1},
    { "z_gettotalbalance", 0},
    { "z_gettotalbalance", 1},
    { "z_gettotalbalance", 2},
    { "z_mergetoaddress", 0},
    { "z_mergetoaddress", 2},
    { "z_mergetoaddress", 3},
    { "z_mergetoaddress", 4},
    { "z_sendmany", 1},
    { "z_sendmany", 2},
    { "z_sendmany", 3},
    { "z_shieldcoinbase", 2},
    { "z_shieldcoinbase", 3},
    { "z_getoperationstatus", 0},
    { "z_getoperationresult", 0},
    //{ "z_importkey", 1 },
    { "paxprice", 4 },
    { "paxprices", 3 },
    { "paxpending", 0 },
    { "notaries", 2 },
    { "minerids", 1 },
    { "kvupdate", 4 },
    { "z_importkey", 2 },
    { "z_getencryptionaddress", 0 },
    { "z_importviewingkey", 2 },
    { "z_getpaymentdisclosure", 1},
    { "z_getpaymentdisclosure", 2},
    // crosschain
    { "assetchainproof", 1},
    { "crosschainproof", 1},
    { "getbestproofroot", 0},
    { "submitacceptednotarization", 0},
    { "submitchallenges", 0},
    { "getnotarizationproofs", 0},
    { "submitimports", 0},
    { "height_MoM", 1},
    { "calc_MoM", 2},
    // pbaas
    { "definecurrency", 0},
    { "definecurrency", 1},
    { "definecurrency", 2},
    { "definecurrency", 3},
    { "definecurrency", 4},
    { "definecurrency", 5},
    { "definecurrency", 6},
    { "definecurrency", 7},
    { "definecurrency", 8},
    { "definecurrency", 9},
    { "definecurrency", 10},
    { "definecurrency", 11},
    { "definecurrency", 12},
    { "definecurrency", 13},
    { "listcurrencies", 0},
    { "listcurrencies", 1},
    { "sendcurrency", 1},
    { "registeridentity", 0},
    { "updateidentity", 0},
    { "setidentitytimelock", 1},
    { "recoveridentity", 0},
    { "signdata", 0},
    { "decryptdata", 0},
    { "verifysignature", 0},
    { "getidentitieswithaddress", 0},
    { "getidentitieswithrevocation", 0},
    { "getidentitieswithrecovery", 0},
    { "estimateconversion", 1},
    { "makeoffer", 1},
    { "takeoffer", 1},
    { "closeoffers", 0},
    { "getvdxfid", 1},
    { "processupgradedata", 0},
    // Zcash addition
    { "z_setmigration", 0},
};

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int> > members;

public:
    CRPCConvertTable();

    bool convert(const std::string& method, int idx) {
        return (members.count(std::make_pair(method, idx)) > 0);
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    const unsigned int n_elem =
        (sizeof(vRPCConvertParams) / sizeof(vRPCConvertParams[0]));

    for (unsigned int i = 0; i < n_elem; i++) {
        members.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                      vRPCConvertParams[i].paramIdx));
    }
}

static CRPCConvertTable rpcCvtTable;

/** Non-RFC4627 JSON parser, accepts internal values (such as numbers, true, false, null)
 * as well as objects and arrays.
 */
UniValue ParseNonRFCJSONValue(const std::string& strVal)
{
    UniValue jVal;
    if (!jVal.read(std::string("[")+strVal+std::string("]")) ||
        !jVal.isArray() || jVal.size()!=1)
        throw runtime_error(string("Error JSON:")+strVal);
    return jVal[0];
}

/** Convert strings to command-specific RPC representation */
UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        const std::string& strVal = strParams[idx];
        if (!rpcCvtTable.convert(strMethod, idx)) {
            // insert string value directly
            params.push_back(strVal);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.push_back(ParseNonRFCJSONValue(strVal));
        }
    }

    return params;
}
