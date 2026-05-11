/********************************************************************
 * (C) 2019 Michael Toutonghi
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * This provides support for PBaaS cross chain communication.
 *
 * In merge mining and notarization, Verus acts as a hub that other PBaaS chains
 * call via RPC in order to get information that allows earning and submitting
 * notarizations.
 *
 */

#ifndef CROSSCHAINRPC_H
#define CROSSCHAINRPC_H

#include "version.h"
#include "uint256.h"
#include <univalue.h>
#include <sstream>
#include "streams.h"
#include "boost/algorithm/string.hpp"
#include "pbaas/vdxf.h"
#include "utilstrencodings.h"

#ifndef __GLIBCXX__
#include "pbaas/shuffle_compat.h"
#endif

template<typename RAIterator, typename RNG>
void pbaas_shuffle(RAIterator first, RAIterator last, RNG&& rng)
{
#ifdef __GLIBCXX__
    std::shuffle(first, last, rng);
#else
    gcc_compatible_shuffle(first, last, rng);
#endif
}

static const int DEFAULT_RPC_TIMEOUT=900;
static const uint32_t PBAAS_VERSION = 1;
static const uint32_t PBAAS_VERSION_INVALID = 0;

extern const uint32_t PBAAS_PREMAINNET_ACTIVATION;
extern const uint32_t PBAAS_LARGE_ETH_PROOF_ACTIVATION;
extern const uint32_t PBAAS_TESTFORK_TIME;

class CTransaction;
class CScript;
class CIdentity;
class CKeyStore;

class CCrossChainRPCData
{
public:
    std::string host;
    int32_t port;
    std::string credentials;

    CCrossChainRPCData() : port(0) {}

    CCrossChainRPCData(std::string Host, int32_t Port, std::string Credentials) :
        host(Host), port(Port), credentials(Credentials) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(host);
        READWRITE(port);
        READWRITE(credentials);
    }

    static CCrossChainRPCData LoadFromConfig(std::string fPath="");

    static uint160 GetID(std::string name);

    static uint160 GetConditionID(const uint160 &cid, uint32_t condition);
    static uint160 GetConditionID(const uint160 &cid, const uint160 &condition);
    static uint160 GetConditionID(const uint160 &cid, const uint160 &condition, const uint256 &txid, int32_t voutNum);
    static uint160 GetConditionID(const uint160 &cid, const uint256 &hash256);
    static uint160 GetConditionID(const uint160 &cid, const uint256 &txid, int32_t voutNum);
    static uint160 GetConditionID(const uint160 &cid, const uint160 &condition, const uint256 &txid);
    static uint160 GetConditionID(std::string name, uint32_t condition);

    UniValue ToUniValue() const;
};

class COnChainOffer
{
public:
    enum EOfferConstants {
        MIN_LISTING_DEPOSIT = 100000000
    };

    static std::string OnChainIdentityOfferKeyName()
    {
        return "vrsc::system.exchange.identityoffer";
    }

    static std::string OnChainCurrencyOfferKeyName()
    {
        return "vrsc::system.exchange.currencyoffer";
    }

    static std::string OnChainOfferForIdentityKeyName()
    {
        return "vrsc::system.exchange.offerforidentity";
    }

    static std::string OnChainOfferForCurrencyKeyName()
    {
        return "vrsc::system.exchange.offerforcurrency";
    }

    static uint160 OnChainIdentityOfferKey(const uint160 &idID)
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(OnChainIdentityOfferKeyName(), nameSpace);
        return CCrossChainRPCData::GetConditionID(signatureKey, idID);
    }

    static uint160 OnChainCurrencyOfferKey(const uint160 &currencyID)
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(OnChainCurrencyOfferKeyName(), nameSpace);
        return CCrossChainRPCData::GetConditionID(signatureKey, currencyID);
    }

    static uint160 OnChainOfferForIdentityKey(const uint160 &idID)
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(OnChainOfferForIdentityKeyName(), nameSpace);
        return CCrossChainRPCData::GetConditionID(signatureKey, idID);
    }

    static uint160 OnChainOfferForCurrencyKey(const uint160 &currencyID)
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(OnChainOfferForCurrencyKeyName(), nameSpace);
        return CCrossChainRPCData::GetConditionID(signatureKey, currencyID);
    }
};

// credentials for now are "user:password"
UniValue RPCCall(const std::string& strMethod,
                 const UniValue& params,
                 const std::string credentials="user:pass",
                 int port=27486,
                 const std::string host="127.0.0.1",
                 int timeout=DEFAULT_RPC_TIMEOUT);

UniValue RPCCallRoot(const std::string& strMethod, const UniValue& params, int timeout=DEFAULT_RPC_TIMEOUT);

class CNodeData
{
public:
    std::string networkAddress;
    uint160 nodeIdentity;

    CNodeData() {}
    CNodeData(const UniValue &uni);
    CNodeData(std::string netAddr, uint160 paymentID) : networkAddress(netAddr), nodeIdentity(paymentID) {}
    CNodeData(std::string netAddr, std::string paymentAddr);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(LIMITED_STRING(networkAddress, 512));
        READWRITE(nodeIdentity);
    }

    UniValue ToUniValue() const;
    bool IsValid()
    {
        return networkAddress != "";
    }
};

class CETHNFTAddress
{
public:
    uint160 contractID;
    uint256 tokenID;

    CETHNFTAddress() {}
    CETHNFTAddress(const UniValue &uni);
    CETHNFTAddress(const uint160 &contract, const uint256 &token) : contractID(contract), tokenID(token) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(contractID);
        READWRITE(tokenID);
    }

    UniValue ToUniValue() const;
};

class CTransferDestination
{
public:
    enum
    {
        DEST_INVALID = 0,
        DEST_PK = 1,
        DEST_PKH = 2,
        DEST_SH = 3,
        DEST_ID = 4,
        DEST_FULLID = 5,
        DEST_REGISTERCURRENCY = 6,
        DEST_QUANTUM = 7,
        DEST_NESTEDTRANSFER = 8,            // used to chain transfers, enabling them to be routed through multiple systems
        DEST_ETH = 9,
        DEST_ETHNFT = 10,                   // used when defining a mapped NFT to gateway that uses an ETH compatible model
        DEST_RAW = 11,
        LAST_VALID_TYPE_NO_FLAGS = DEST_RAW,
        FLAG_RESERVED1 = 16,
        FLAG_RESERVED2 = 32,
        FLAG_DEST_AUX = 64,
        FLAG_DEST_GATEWAY = 128,
        FLAG_MASK = FLAG_DEST_AUX + FLAG_DEST_GATEWAY + FLAG_RESERVED1 + FLAG_RESERVED2
    };
    uint8_t type;
    std::vector<unsigned char> destination;
    uint160 gatewayID;                      // gateway fee currency/systemID
    uint160 gatewayCode;                    // code for function to execute on the gateway
    int64_t fees;                           // amount for transfer fees this is holding
    std::vector<std::vector<unsigned char>> auxDests;

    CTransferDestination() : type(DEST_INVALID), fees(0) {}
    CTransferDestination(const UniValue &uni);
    CTransferDestination(const std::vector<unsigned char> asVector)
    {
        bool success = true;
        ::FromVector(asVector, *this, &success);
        if (!success)
        {
            type = DEST_INVALID;
        }
    }

    CTransferDestination(uint8_t Type,
                         std::vector<unsigned char> Destination,
                         const uint160 &GatewayID=uint160(),
                         const uint160 &GatewayCode=uint160(),
                         int64_t Fees=0,
                         const std::vector<std::vector<unsigned char>> &AuxDests=std::vector<std::vector<unsigned char>>()) :
                         type(Type),
                         destination(Destination),
                         gatewayID(GatewayID),
                         gatewayCode(GatewayCode),
                         fees(Fees),
                         auxDests(AuxDests)
    {
        type |= ((auxDests.size() > 0 && auxDests[0].size() > 0) ? FLAG_DEST_AUX : 0) + (gatewayID.IsNull() ? 0 : FLAG_DEST_GATEWAY);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(type);
        READWRITE(destination);
        if (type & FLAG_DEST_GATEWAY)
        {
            READWRITE(gatewayID);
            READWRITE(gatewayCode);
            READWRITE(fees);
        }
        if (type & FLAG_DEST_AUX)
        {
            READWRITE(auxDests);
        }
    }

    bool HasGatewayLeg() const
    {
        return (type & FLAG_DEST_GATEWAY) && !gatewayID.IsNull();
    }

    int AuxDestCount() const
    {
        if (type & FLAG_DEST_AUX)
        {
            return auxDests.size();
        }
        return 0;
    }

    void SetAuxDest(const CTransferDestination &auxDest, int destNum);
    CTransferDestination GetAuxDest(int destNum) const;
    bool EraseAuxDest(int destNum);
    void ClearAuxDests()
    {
        auxDests.clear();
        type &= ~FLAG_DEST_AUX;
    }

    void SetGatewayLeg(const uint160 &GatewayID=uint160(), int64_t Fees=0, const uint160 &vdxfCode=uint160())
    {
        type |= FLAG_DEST_GATEWAY;
        gatewayID = GatewayID;
        gatewayCode = vdxfCode;
        fees = Fees;
    }

    void ClearGatewayLeg()
    {
        type &= ~FLAG_DEST_GATEWAY;
        gatewayID.SetNull();
        gatewayCode.SetNull();
        fees = 0;
    }

    int TypeNoFlags() const
    {
        return type & ~FLAG_MASK;
    }

    bool IsValid() const
    {
        // verify aux dests
        bool valid = (((type & FLAG_DEST_AUX) && auxDests.size()) || (!(type & FLAG_DEST_AUX) && !auxDests.size()));
        if (valid && auxDests.size())
        {
            for (int i = 0; i < auxDests.size(); i++)
            {
                if (!GetAuxDest(i).IsValid())
                {
                    valid = false;
                    break;
                }
            }
        }
        return valid &&
               TypeNoFlags() != DEST_INVALID &&
               TypeNoFlags() <= LAST_VALID_TYPE_NO_FLAGS &&
               ((!(type & FLAG_DEST_GATEWAY) && gatewayID.IsNull()) || !gatewayID.IsNull());
    }

    static uint160 DecodeEthDestination(const std::string &destStr)
    {
        uint160 retVal;
        if (destStr.substr(0,2) == "0x" &&
                destStr.length() == 42 &&
                IsHex(destStr.substr(2,40)))
        {
            retVal = uint160(ParseHex(destStr.substr(2,64)));
        }
        return retVal;
    }

    static std::string EncodeEthDestination(const uint160 &ethDestID)
    {
        // reverse bytes to match ETH encoding
        return "0x" + HexBytes(ethDestID.begin(), ethDestID.size());
    }

    static std::pair<uint160, uint256> DecodeEthNFTDestination(const std::string &destStr)
    {
        uint160 retContract;
        uint256 retTokenID;
        UniValue nftJSON(UniValue::VOBJ);
        nftJSON.read(destStr);
        CETHNFTAddress retAddr(nftJSON);
        return std::make_pair(retAddr.contractID, retAddr.tokenID);
    }

    static std::string EncodeEthNFTDestination(const uint160 &ethContractID, const uint256 &tokenID)
    {
        // reverse bytes to match ETH encoding
        return "{\"contract\":\"0x" + HexBytes(ethContractID.begin(), ethContractID.size()) + "\", \"tokenid\":\"0x" + HexBytes(tokenID.begin(), tokenID.size()) + "\"}";
    }

    static std::string CurrencyDefinitionExportKeyName()
    {
        return "vrsc::system.currency.definitionexport";
    }

    static uint160 UnboundCurrencyDefinitionExportKey()
    {
        static uint160 nameSpace;
        static uint160 exportKey = CVDXF::GetDataKey(CurrencyDefinitionExportKeyName(), nameSpace);
        return exportKey;
    }

    static uint160 CurrencyDefinitionExportKeyToSystem(const uint160 &exportToSystemID);
    static uint160 GetBoundCurrencyDefinitionExportKey(const uint160 &exportToSystemID, const uint160 &curToExportID);
    uint160 GetBoundCurrencyDefinitionExportKey(const uint160 &exportToSystemID) const;

    UniValue ToUniValue() const;
};

extern int64_t AmountFromValueNoErr(const UniValue& value);

// convenience class for collections of currencies that supports comparisons, including ==, >, >=, <, <=, as well as addition, and subtraction
class CCurrencyValueMap
{
public:
    std::map<uint160, int64_t> valueMap;

    CCurrencyValueMap() {}
    CCurrencyValueMap(const CCurrencyValueMap &operand) : valueMap(operand.valueMap) {}
    CCurrencyValueMap(const std::map<uint160, int64_t> &vMap) : valueMap(vMap) {}
    CCurrencyValueMap(const std::vector<uint160> &currencyIDs, const std::vector<int64_t> &amounts);
    CCurrencyValueMap(const UniValue &uni);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(valueMap);
    }

    friend bool operator<(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend bool LegacyLT(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend bool operator>(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend bool operator==(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend bool operator!=(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend bool operator<=(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend bool operator>=(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend CCurrencyValueMap operator+(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend CCurrencyValueMap operator-(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend CCurrencyValueMap operator+(const CCurrencyValueMap& a, int b);
    friend CCurrencyValueMap operator-(const CCurrencyValueMap& a, int b);
    friend CCurrencyValueMap operator*(const CCurrencyValueMap& a, int b);
    friend CCurrencyValueMap operator/(const CCurrencyValueMap& a, int b);

    const CCurrencyValueMap &operator=(const CCurrencyValueMap& operand)
    {
        valueMap = operand.valueMap;
        return *this;
    }
    const CCurrencyValueMap &operator-=(const CCurrencyValueMap& operand);
    const CCurrencyValueMap &operator+=(const CCurrencyValueMap& operand);

    // determine if the operand intersects this map
    bool Intersects(const CCurrencyValueMap& operand) const;
    CCurrencyValueMap CanonicalMap() const;
    CCurrencyValueMap IntersectingValues(const CCurrencyValueMap& operand) const;
    CCurrencyValueMap NonIntersectingValues(const CCurrencyValueMap& operand) const;
    bool IsValid() const;
    bool HasNegative() const;

    // subtract, but do not subtract to negative values
    CCurrencyValueMap SubtractToZero(const CCurrencyValueMap& operand) const;

    std::vector<int64_t> AsCurrencyVector(const std::vector<uint160> &currencies) const;

    UniValue ToUniValue() const;
};

// This defines the currency characteristics of a PBaaS currency that will be the native coins of a PBaaS chain
class CCurrencyDefinition
{
public:
    enum EVersion
    {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = 1
    };

    enum ELimitsDefaults
    {
        TRANSACTION_CROSSCHAIN_FEE = 2000000,       // 0.02 destination currency per cross chain transfer, chain's accept notary currency or have converter
        TRANSACTION_TRANSFER_FEE = 20000,           // 0.0002 per same chain transfer total, chain's accept notary currency or have converter
        CURRENCY_REGISTRATION_FEE = 20000000000,    // default 200 to register a currency, except tokenizing ID control
        PBAAS_SYSTEM_LAUNCH_FEE = 1000000000000,    // default 10000 to register and launch a PBaaS chain
        CURRENCY_IMPORT_FEE = 10000000000,          // default 100 to import a currency
        IDENTITY_REGISTRATION_FEE = 10000000000,    // 100 full price to register an identity
        IDENTITY_IMPORT_FEE = 2000000,              // 0.02 in native currency to import an identity
        EXTRA_Z_OUTPUT_FEE = (TRANSACTION_TRANSFER_FEE >> 1), // 2 or more z-outputs accompanied by t-outputs on a transaction
        DEFAULT_STORAGE_OUTPUT_FACTOR = 6,          // default multiplier times the export fee to equal the cost of 6K of storage output
        MIN_CURRENCY_LIFE = 480,                    // 8 hour minimum lifetime, which gives 8 hours of minimum billing to notarize conclusion
        DEFAULT_OUTPUT_VALUE = 0,                   // 0 VRSC default output value
        DEFAULT_ID_REFERRAL_LEVELS = 3,
        MAX_ID_REFERRAL_LEVELS = 5,
        MAX_NAME_LEN = 64,
        MAX_RESERVE_CURRENCIES = 10,
        MIN_RESERVE_RATIO = 5000000,
        MAX_STARTUP_NODES = 5,
        MAX_NATIVE_IDENTITY_SIZE = 512,
        DEFAULT_START_TARGET = 0x1e01e1e1,
        MAX_CURRENCY_DEFINITION_EXPORTS_PER_BLOCK = 20,
        MAX_IDENTITY_DEFINITION_EXPORTS_PER_BLOCK = 100,
        MAX_TRANSFER_EXPORTS_PER_BLOCK = 500,       // this is per block, and up to two of these limits go into an export
        MAX_EXPORT_INPUT_OVERHEAD_PER_BLOCK = 10,   // in addition to transfer inputs, we may have up to 10 inputs extra for an export transaction
        MAX_TRANSFER_EXPORTS_SIZE_PER_BLOCK = 100000, // same as above, but regarding space
        MAX_ETH_CURRENCY_DEFINITION_EXPORTS_PER_BLOCK = 1,
        MAX_ETH_IDENTITY_DEFINITION_EXPORTS_PER_BLOCK = 0,
        MAX_ETH_TRANSFER_EXPORTS_PER_BLOCK = 50,
        MAX_ETH_TRANSFER_EXPORTS_SIZE_PER_BLOCK = 50000,
        MIN_DEFAULT_TX_EXPIRY = 20,                 // minimum blocks for transaction expiry
        MAX_DEFAULT_TX_EXPIRY = 60,                 // maximum blocks for transaction expiry
        MIN_AVERAGING_WINDOW = 20,                  // min averaging window
        MAX_AVERAGING_WINDOW = 180,                 // max averaging window
        DEFAULT_BLOCK_NOTARIZATION_TIME = 600,      // default target time for block notarizations
        MIN_BLOCK_NOTARIZATION_PERIOD = 5,          // minimum target blocks for notarization period
        MAX_NOTARIZATION_CONVERSION_PRICING_INTERVAL = 100,  // there must be a notarization with conversion at least 100 blocks before reserve transfer
        DEFAULT_BLOCKTIME_TARGET = 60,              // default block time target for difficulty adjustment, in seconds
        MIN_BLOCKTIME_TARGET = 10,                  // min 10 seconds in first version of PBaaS
        MAX_BLOCKTIME_TARGET = 120,                 // max 2 minutes in first version of PBaaS
        DEFAULT_AVERAGING_WINDOW = 45,              // default target spacing (blocks) for difficulty adjustment
        BLOCK_NOTARIZATION_MODULO = (DEFAULT_BLOCK_NOTARIZATION_TIME / DEFAULT_BLOCKTIME_TARGET), // default min notarization spacing (10 minutes)
        MIN_EARNED_FOR_AUTO = 4,
        MIN_BLOCKS_TO_SIGNCONFIRM = 15,
        MIN_BLOCKS_TO_AUTOCONFIRM = 150,
        MIN_COINBASE_MATURITY = 100,                // minimum blocks to spend coinbase transaction outputs
        MAX_COINBASE_MATURITY = 150 - 1,            // maximum blocks to spend coinbase transaction outputs, equal to mininum confirmations to stake minus 1
    };

    enum ECurrencyOptions
    {
        OPTION_FRACTIONAL = 1,              // allows reserve conversion using base calculations when set
        OPTION_ID_ISSUANCE = 2,             // clear is permissionless, if set, IDs may only be created by controlling ID
        OPTION_ID_STAKING = 4,              // all IDs on chain stake equally, rather than value-based staking
        OPTION_ID_REFERRALS = 8,            // if set, this chain supports referrals
        OPTION_ID_REFERRALREQUIRED = 0x10,  // if set, this chain requires a referrer to approve an ID issuance
        OPTION_TOKEN = 0x20,                // if set, this is a token, not a native currency
        OPTION_SINGLECURRENCY = 0x40,       // for PBaaS chains or gateways to potentially restrict to single currency
        OPTION_GATEWAY = 0x80,              // if set, this routes external currencies
        OPTION_PBAAS = 0x100,               // this is a PBaaS chain definition
        OPTION_GATEWAY_CONVERTER = 0x200,   // this means that for a specific PBaaS gateway, this is the default converter and will publish prices
        OPTION_GATEWAY_NAMECONTROLLER = 0x400, // when not set on a gateway, top level ID and currency registration happen on launch chain
        OPTION_NFT_TOKEN = 0x800,           // single satoshi NFT token, tokenizes control over the root ID
        OPTION_NO_IDS = 0x1000,             // this currency cannot issue IDs
        OPTIONS_FLAG_MASK = 0x1fff
    };

    // these should be pluggable in function
    enum ENotarizationProtocol
    {
        NOTARIZATION_INVALID = 0,           // notarization protocol must have valid type
        NOTARIZATION_AUTO = 1,              // PBaaS autonotarization
        NOTARIZATION_NOTARY_CONFIRM = 2,    // confirmation by specified notaries with no auto-protocol requirements
        NOTARIZATION_NOTARY_CHAINID = 3,    // chain identity controls notarization and imports
        NOTARIZATION_NOTARY_LAST = 3        // last valid value
    };

    enum EProofProtocol
    {
        PROOF_INVALID = 0,                  // proof protocol must have valid type
        PROOF_PBAASMMR = 1,                 // Verus MMR proof, no notaries required
        PROOF_CHAINID = 2,                  // if signed by the chain ID, that is considered proof
        PROOF_ETHNOTARIZATION = 3,          // proven by Ethereum notarization
        PROOF_LASTPROTOCOL = 3,
        PROOF_KOMODONOTARIZATION = 4,       // Komodo protocol is not valid until someone from Komodo finishes it
        PROOF_SOLANANOTARIZATION = 5        // proven by Solana notarization, Keccak-form ECDSA signatures verified on-chain
    };

    enum EHashTypes
    {
        HASH_INVALID = 0,
        HASH_BLAKE2BMMR = 1,
        HASH_BLAKE2BMMR2 = 2,
        HASH_KECCAK = 3,
        HASH_SHA256D = 4,
        HASH_SHA256 = 5,
        HASH_LASTTYPE = 5
    };

    // Maps an EProofProtocol value to the EHashTypes its signatures are emitted with.
    // The original design aligned the numeric values (PROOF_PBAASMMR=1 ↔ HASH_BLAKE2BMMR=1,
    // PROOF_ETHNOTARIZATION=3 ↔ HASH_KECCAK=3, PROOF_KOMODONOTARIZATION=4 ↔ HASH_SHA256D=4)
    // so callers could static_cast directly. PROOF_SOLANANOTARIZATION=5 lands on HASH_SHA256=5
    // by coincidence, but Solana actually signs with Keccak (matching the EVM bridge), so it
    // must be remapped explicitly here. All four sites that previously did `(EHashTypes)pp`
    // now go through this helper.
    static EHashTypes ProofProtocolHashType(int proofProtocol)
    {
        if (proofProtocol == PROOF_SOLANANOTARIZATION)
        {
            return HASH_KECCAK;
        }
        return (EHashTypes)proofProtocol;
    }

    enum EQueryOptions
    {
        QUERY_NULL = 0,
        QUERY_LAUNCHSTATE_PRELAUNCH = 1,
        QUERY_LAUNCHSTATE_REFUND = 2,
        QUERY_LAUNCHSTATE_CONFIRM = 3,
        QUERY_LAUNCHSTATE_COMPLETE = 4,
        QUERY_SYSTEMTYPE_LOCAL = 5,
        QUERY_SYSTEMTYPE_IMPORTED = 6,
        QUERY_SYSTEMTYPE_GATEWAY = 7,
        QUERY_SYSTEMTYPE_PBAAS = 8,
        QUERY_ISCONVERTER = 9
    };

    uint32_t nVersion;                      // version of this chain definition data structure to allow for extensions (not daemon version)
    uint32_t options;                       // flags to determine fungibility, type of currency, blockchain and ID options, and conversion

    uint160 parent;                         // parent PBaaS namespace. if not this systemID, the ID of this currency is name.(parentstring)@(systemID)
    std::string name;                       // currency name matching name of identity in namespace

    // the interface to the currency controller. systemID refers to the controlling blockchain or gateway currency
    uint160 systemID;                       // native currency home, for gateways, it is the chain that manages the gateway
    int32_t notarizationProtocol;           // method of notarization
    int32_t proofProtocol;                  // method of proving imports and other elements

    // launch host, system start and end block if there is an end time for the expected use of this currency
    uint160 launchSystemID;                 // where is this currency launched? for PBaaS chains, vrsc. startblock is measured against launch system
    int32_t startBlock;                     // block # that indicates the end of pre-launch when a chain fails or begins running and if token, becomes active for use
    int32_t endBlock;                       // block after which this is considered end-of-lifed, which applies to task-specific currencies

    int64_t initialFractionalSupply;        // initial supply available for all pre-launch conversions, not including pre-allocation, which will be added to this
    std::vector<std::pair<uint160, int64_t>> preAllocation; // pre-allocation recipients, from pre-allocation/premine, emitted after reserve weights are set
    int64_t gatewayConverterIssuance;       // how much native coin does the gateway converter, if there is one, start with?

    // initial states for reserve currencies
    std::vector<uint160> currencies;        // currency identifiers
    std::vector<int32_t> weights;           // value weights of each currency

    std::vector<int64_t> conversions;       // initial conversion ratio in each currency value is conversion * maxpreconvert/(maxpreconvert + premine)
    std::vector<int64_t> minPreconvert;     // can be used for Kickstarter-like launch and return all non-network fees upon failure to meet minimum
    std::vector<int64_t> maxPreconvert;     // maximum amount of each reserve that can be pre-converted
    std::vector<int64_t> contributions;     // initial contributions
    std::vector<int64_t> preconverted;      // actual converted amount if known

    int32_t preLaunchDiscount;              // if non-zero, a ratio of the initial supply instead of a fixed number is used to calculate total preallocation
    int32_t preLaunchCarveOut;              // pre-launch carve-out amount as a ratio of satoshis, from reserve contributions, taken from reserve percentage

    // this section for gateways
    CTransferDestination nativeCurrencyID;  // ID of the currency in its native system (for gateways)
    uint160 gatewayID;                      // ID of the gateway used for gateway currencies as import/export

    // notaries, if present on a gateway or PBaaS chain, have the power to finalize notarizations on either blockchain. notarizations can be
    // used as anchors to prove transactions on other currency systems that may import/export tokens, IDs or other things from other networks
    std::vector<uint160> notaries;          // a list of notary IDs, which if present, are the only identities capable of confirming notarizations

    // this is enforced to be at least a majority to be valid & avoid forks
    int32_t minNotariesConfirm;             // requires this many unique notaries to confirm a notarization

    // costs to register and import IDs
    int64_t idRegistrationFees;             // normal cost of ID registration in PBaaS native currency, for gateways, current native
    int32_t idReferralLevels;               // number of referral levels to divide among
    int64_t idImportFees;                   // for gateway/system - cost to import currency to this system, for fractional - pricing currency index

    // costs to register and import currencies
    int64_t currencyRegistrationFee;        // cost in native currency to register a currency on this system
    int64_t pbaasSystemLaunchFee;           // cost in native currency to register and launch a connected PBaaS chain on this system
    int64_t currencyImportFee;              // cost in native currency to import currency into this system (PBaaS or Gateway)

    int64_t transactionImportFee;           // how much to import a basic transaction
    int64_t transactionExportFee;           // how much to export transaction

    // for PBaaS chains, this defines the currency issuance schedule
    // external chains or custodial tokens do not require a PBaaS chain to import and export currency
    // if a currency definition is for a PBaaS chain, its gatewayConverter currency is the one that
    // people can participate in to have access to the currency itself. pre-mine to a NULL address
    // puts it into the initial gateway currency reserves.
    uint32_t initialBits;                   // initial starting difficulty

    uint32_t blockTime;                     // block time target in seconds between blocks
    uint32_t powAveragingWindow;            // averaging window in number of blocks for DAA
    uint16_t blockNotarizationModulo;       // periodicity of notarizations that can finalize against the notary chain

    std::vector<int64_t> rewards;           // initial reward in each of native coin, if this is a reserve the number represents percentage of supply w/satoshis
    std::vector<int64_t> rewardsDecay;      // decay of rewards at halvings during the era
    std::vector<int32_t> halving;           // number of blocks between halvings
    std::vector<int32_t> eraEnd;            // block number that ends each era

    std::string gatewayConverterName;       // reserved ID and currency that is a basket of all currencies accepted on launch, parent chain, and native

    CCurrencyDefinition() : nVersion(VERSION_INVALID),
                            options(0),
                            notarizationProtocol(NOTARIZATION_INVALID),
                            proofProtocol(PROOF_INVALID),
                            startBlock(0),
                            endBlock(0),
                            initialFractionalSupply(0),
                            gatewayConverterIssuance(0),
                            preLaunchDiscount(0),
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
    {}

    CCurrencyDefinition(const UniValue &obj);

    CCurrencyDefinition(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CCurrencyDefinition(const CScript &scriptPubKey);
    static std::vector<CCurrencyDefinition> GetCurrencyDefinitions(const CTransaction &tx);

    CCurrencyDefinition(uint32_t Options, uint160 Parent, const std::string &Name, const uint160 &LaunchSystemID, const uint160 &SystemID,
                        ENotarizationProtocol NotarizationProtocol, EProofProtocol ProofProtocol,
                        int32_t StartBlock, int32_t EndBlock, int64_t InitialFractionalSupply, std::vector<std::pair<uint160, int64_t>> PreAllocation,
                        int64_t ConverterIssuance, std::vector<uint160> Currencies, std::vector<int32_t> Weights, std::vector<int64_t> Conversions,
                        std::vector<int64_t> MinPreconvert, std::vector<int64_t> MaxPreconvert, std::vector<int64_t> Contributions,
                        std::vector<int64_t> Preconverted, int32_t PreLaunchDiscount, int32_t PreLaunchCarveOut,
                        const CTransferDestination &NativeID, const uint160 &GatewayID,
                        const std::vector<uint160> &Notaries, int32_t MinNotariesConfirm,
                        const std::vector<int64_t> &chainRewards, const std::vector<int64_t> &chainRewardsDecay,
                        const std::vector<int32_t> &chainHalving, const std::vector<int32_t> &chainEraEnd,
                        const std::string &LaunchGatewayName,
                        int64_t TransactionTransferFee=TRANSACTION_CROSSCHAIN_FEE, int64_t CurrencyRegistrationFee=CURRENCY_REGISTRATION_FEE,
                        int64_t PBaaSSystemRegistrationFee=PBAAS_SYSTEM_LAUNCH_FEE,
                        int64_t CurrencyImportFee=CURRENCY_IMPORT_FEE, int64_t IDRegistrationAmount=IDENTITY_REGISTRATION_FEE,
                        int32_t IDReferralLevels=DEFAULT_ID_REFERRAL_LEVELS, int64_t IDImportFee=IDENTITY_IMPORT_FEE,
                        uint32_t InitialBits=DEFAULT_START_TARGET,
                        uint32_t BlockTime=DEFAULT_BLOCKTIME_TARGET,
                        uint32_t PowAveragingWindow=DEFAULT_AVERAGING_WINDOW,
                        uint32_t BlockNotarizationModulo=BLOCK_NOTARIZATION_MODULO,
                        uint32_t Version=VERSION_CURRENT) :
                        nVersion(Version),
                        options(Options),
                        parent(Parent),
                        name(Name),
                        launchSystemID(LaunchSystemID),
                        systemID(SystemID),
                        notarizationProtocol(NotarizationProtocol),
                        proofProtocol(ProofProtocol),
                        startBlock(StartBlock),
                        endBlock(EndBlock),
                        initialFractionalSupply(InitialFractionalSupply),
                        preAllocation(PreAllocation),
                        gatewayConverterIssuance(ConverterIssuance),
                        currencies(Currencies),
                        weights(Weights),
                        conversions(Conversions),
                        minPreconvert(MinPreconvert),
                        maxPreconvert(MaxPreconvert),
                        contributions(Contributions),
                        preconverted(Preconverted),
                        preLaunchDiscount(PreLaunchDiscount),
                        preLaunchCarveOut(PreLaunchCarveOut),
                        nativeCurrencyID(NativeID),
                        gatewayID(GatewayID),
                        notaries(Notaries),
                        minNotariesConfirm(MinNotariesConfirm),
                        idRegistrationFees(IDRegistrationAmount),
                        idReferralLevels(IDReferralLevels),
                        idImportFees(IDImportFee),
                        currencyRegistrationFee(CurrencyRegistrationFee),
                        pbaasSystemLaunchFee(PBaaSSystemRegistrationFee),
                        currencyImportFee(CurrencyImportFee),
                        transactionImportFee(TransactionTransferFee >> 1),
                        transactionExportFee(TransactionTransferFee >> 1),
                        initialBits(InitialBits),
                        blockTime(BlockTime),
                        powAveragingWindow(PowAveragingWindow),
                        blockNotarizationModulo(BlockNotarizationModulo),
                        rewards(chainRewards),
                        rewardsDecay(chainRewardsDecay),
                        halving(chainHalving),
                        eraEnd(chainEraEnd),
                        gatewayConverterName(LaunchGatewayName)
    {
        if (name.size() > (KOMODO_ASSETCHAIN_MAXLEN - 1))
        {
            name.resize(KOMODO_ASSETCHAIN_MAXLEN - 1);
        }
        if (!IsGateway())
        {
            gatewayID = uint160();
        }
    }

    // get canonical representations of VRSC and VRSCTEST, potentially others later
    CCurrencyDefinition(const std::string &currencyName, bool testMode);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(options);
        READWRITE(parent);
        READWRITE(LIMITED_STRING(name, MAX_NAME_LEN));
        READWRITE(launchSystemID);
        READWRITE(systemID);
        READWRITE(notarizationProtocol);
        READWRITE(proofProtocol);
        READWRITE(nativeCurrencyID);
        READWRITE(gatewayID);
        READWRITE(VARINT(startBlock));
        READWRITE(VARINT(endBlock));
        READWRITE(initialFractionalSupply);
        READWRITE(preAllocation);
        READWRITE(gatewayConverterIssuance);
        READWRITE(currencies);
        READWRITE(weights);
        READWRITE(conversions);
        READWRITE(minPreconvert);
        READWRITE(maxPreconvert);
        READWRITE(contributions);
        READWRITE(preconverted);
        READWRITE(VARINT(preLaunchDiscount));
        READWRITE(preLaunchCarveOut);
        READWRITE(notaries);
        READWRITE(VARINT(minNotariesConfirm));
        READWRITE(VARINT(idRegistrationFees));
        READWRITE(VARINT(idReferralLevels));
        READWRITE(VARINT(idImportFees));
        if (IsGateway() || IsPBaaSChain())
        {
            READWRITE(VARINT(currencyRegistrationFee));
            READWRITE(VARINT(pbaasSystemLaunchFee));
            READWRITE(VARINT(currencyImportFee));
            READWRITE(VARINT(transactionImportFee));
            READWRITE(VARINT(transactionExportFee));
            READWRITE(LIMITED_STRING(gatewayConverterName, MAX_NAME_LEN));
            if (IsPBaaSChain())
            {
                READWRITE(initialBits);
                READWRITE(blockTime);
                READWRITE(powAveragingWindow);
                READWRITE(blockNotarizationModulo);
                READWRITE(rewards);
                READWRITE(rewardsDecay);
                READWRITE(halving);
                READWRITE(eraEnd);
            }
            else if (ser_action.ForRead())
            {
                blockNotarizationModulo = BLOCK_NOTARIZATION_MODULO;
            }
        }
        else
        {
            // replace "s" in scope
            CDataStream s = CDataStream(SER_DISK, PROTOCOL_VERSION);
            // pad for read
            int64_t initZero = 0;
            s << initZero;
            s << initZero;
            s << initZero;
            s << initZero;
            s << initZero;
            READWRITE(VARINT(currencyRegistrationFee));
            READWRITE(VARINT(pbaasSystemLaunchFee));
            READWRITE(VARINT(currencyImportFee));
            READWRITE(VARINT(transactionImportFee));
            READWRITE(VARINT(transactionExportFee));
        }
    }

    std::vector<unsigned char> AsVector() const
    {
        return ::AsVector(*this);
    }

    static uint160 GetID(const std::string &Name, uint160 &Parent);

    static inline uint160 GetID(const std::string &Name)
    {
        uint160 Parent;
        return GetID(Name, Parent);
    }

    uint32_t MagicNumber() const;

    std::set<uint160> GetNotarySet() const
    {
        std::set<uint160> notarySet;
        if (notarizationProtocol == NOTARIZATION_NOTARY_CHAINID)
        {
            notarySet.insert(GetID());
        }
        else
        {
            for (auto &oneSigID : notaries)
            {
                notarySet.insert(oneSigID);
            }
        }
        return notarySet;
    }

    int MinimumNotariesConfirm() const
    {
        if (notarizationProtocol == NOTARIZATION_NOTARY_CHAINID)
        {
            return 1;
        }
        else
        {
            return minNotariesConfirm;
        }
    }

    inline static int32_t MinBlocksToAutoNotarization(uint32_t notarizationBlockModulo)
    {
        return std::max((uint32_t)(notarizationBlockModulo * MIN_EARNED_FOR_AUTO), (uint32_t)MIN_BLOCKS_TO_AUTOCONFIRM);
    }

    inline static int32_t MinBlocksToSignedNotarization(uint32_t notarizationBlockModulo)
    {
        return std::max(notarizationBlockModulo + (notarizationBlockModulo >> 1), (uint32_t)MIN_BLOCKS_TO_SIGNCONFIRM);
    }

    inline static int32_t MinBlocksToStartNotarization(uint32_t notarizationBlockModulo)
    {
        return ((MinBlocksToSignedNotarization(notarizationBlockModulo) << 1) + 1);
    }

    // we may sign and confirm a notarization this many blocks after it has been posted
    // if when confirming it, it has passed all necessary challenges and is signed by
    // required notary witnesses
    int32_t GetMinBlocksToSignNotarize() const
    {
        return MinBlocksToSignedNotarization(blockNotarizationModulo);
    }

    int32_t GetMinBlocksToAutoNotarize() const
    {
        return MinBlocksToAutoNotarization(blockNotarizationModulo);
    }

    int32_t GetMinBlocksToStartNotarization() const
    {
        return MinBlocksToStartNotarization(blockNotarizationModulo);
    }

    uint160 GatewayConverterID() const
    {
        uint160 retVal;
        if (!gatewayConverterName.empty())
        {
            uint160 thisParentID = GetID();
            retVal = GetID(gatewayConverterName, thisParentID);
        }
        return retVal;
    }

    uint160 SystemOrGatewayID() const
    {
        return (IsGateway() ? gatewayID : systemID);
    }

    uint160 FeePricingCurrency() const
    {
        if (!IsFractional() || idImportFees < 0 || idImportFees >= currencies.size())
        {
            return GetID();
        }
        else
        {
            return currencies[idImportFees];
        }
    }

    int32_t MaxTransferExportCount() const
    {
        return proofProtocol == PROOF_ETHNOTARIZATION ? MAX_ETH_TRANSFER_EXPORTS_PER_BLOCK : MAX_TRANSFER_EXPORTS_PER_BLOCK;
    }

    int32_t MaxTransferExportSize() const
    {
        return proofProtocol == PROOF_ETHNOTARIZATION ? MAX_ETH_TRANSFER_EXPORTS_SIZE_PER_BLOCK : MAX_TRANSFER_EXPORTS_SIZE_PER_BLOCK;
    }

    int32_t MaxCurrencyDefinitionExportCount() const
    {
        return proofProtocol == PROOF_ETHNOTARIZATION ? MAX_ETH_CURRENCY_DEFINITION_EXPORTS_PER_BLOCK : MAX_CURRENCY_DEFINITION_EXPORTS_PER_BLOCK;
    }

    int32_t MaxIdentityDefinitionExportCount() const
    {
        return proofProtocol == PROOF_ETHNOTARIZATION ? MAX_ETH_IDENTITY_DEFINITION_EXPORTS_PER_BLOCK : MAX_IDENTITY_DEFINITION_EXPORTS_PER_BLOCK;
    }

    static bool IsValidDefinitionImport(const CCurrencyDefinition &sourceSystem, const CCurrencyDefinition &destSystem, const uint160 &nameParent, uint32_t height);

    bool IsValidTransferDestinationType(int destinationType) const
    {
        switch (destinationType)
        {
            case CTransferDestination::DEST_ETH:
            {
                if (proofProtocol != CCurrencyDefinition::PROOF_ETHNOTARIZATION)
                {
                    return false;
                }
                break;
            }
            case CTransferDestination::DEST_FULLID:
            case CTransferDestination::DEST_ID:
            case CTransferDestination::DEST_PK:
            case CTransferDestination::DEST_PKH:
            case CTransferDestination::DEST_SH:
            {
                if (proofProtocol != CCurrencyDefinition::PROOF_PBAASMMR)
                {
                    return false;
                }
                break;
            }
        }
        return true;
    }

    int64_t GetCurrencyRegistrationFee(uint32_t currencyOptions) const
    {
        if (currencyOptions & (OPTION_PBAAS + OPTION_GATEWAY))
        {
            return pbaasSystemLaunchFee;
        }
        else if (currencyOptions & OPTION_NFT_TOKEN)
        {
            return idImportFees;
        }
        else
        {
            return currencyRegistrationFee;
        }
    }

    int64_t GetCurrencyImportFee(bool isTokenizedControlCurrency=false) const
    {
        if ((proofProtocol == PROOF_PBAASMMR || proofProtocol == PROOF_CHAINID) && isTokenizedControlCurrency)
        {
            return idImportFees;
        }
        return currencyImportFee;
    }

    int64_t GetTransactionImportFee() const
    {
        return transactionImportFee;
    }

    int64_t GetTransactionExportFee() const
    {
        return transactionExportFee;
    }

    int64_t GetTransactionTransferFee() const
    {
        return TRANSACTION_TRANSFER_FEE;
    }

    // fee amount released at definition
    int64_t LaunchFeeExportShare(uint32_t currencyOptions) const
    {
        return GetCurrencyRegistrationFee(currencyOptions) >> 1;
    }

    int64_t LaunchFeeImportShare(uint32_t currencyOptions) const
    {
        return GetCurrencyRegistrationFee(currencyOptions) - LaunchFeeExportShare(currencyOptions);
    }

    // fee amount released for notarization at launch of PBaaS chains
    // currently 1/10th of import
    int64_t TotalNotaryLaunchFeeShare(uint32_t currencyOptions) const
    {
        int64_t importShare = LaunchFeeImportShare(currencyOptions);
        return importShare / 10;
    }

    uint160 GetID() const
    {
        uint160 Parent = parent;
        return GetID(name, Parent);
    }

    uint160 GetConditionID(int32_t condition) const;

    static std::string CurrencyDefinitionKeyName()
    {
        return "vrsc::system.currency.definition";
    }

    static uint160 CurrencyDefinitionKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(CurrencyDefinitionKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string CurrencyLaunchKeyName()
    {
        return "vrsc::system.currency.launch";
    }

    static uint160 CurrencyLaunchKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(CurrencyLaunchKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string CurrencyGatewayKeyName()
    {
        return "vrsc::system.currency.gatewaycurrency";
    }

    static uint160 CurrencyGatewayKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(CurrencyGatewayKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string PBaaSChainKeyName()
    {
        return "vrsc::system.currency.pbaaschain";
    }

    static uint160 PBaaSChainKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(PBaaSChainKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string ExternalCurrencyKeyName()
    {
        return "vrsc::system.currency.externalcurrency";
    }

    static uint160 ExternalCurrencyKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(ExternalCurrencyKeyName(), nameSpace);
        return signatureKey;
    }

    static std::string CurrencySystemKeyName()
    {
        return "vrsc::system.currency.systemdefinition";
    }

    static uint160 CurrencySystemKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(CurrencySystemKeyName(), nameSpace);
        return signatureKey;
    }

    bool IsValid() const
    {
        return (nVersion != PBAAS_VERSION_INVALID) &&
                (!notaries.size() || minNotariesConfirm > (notaries.size() >> 1)) &&
                !(options & ~OPTIONS_FLAG_MASK) &&
                !(IsPBaaSChain() && (NoIDs() || IsToken() || IsFractional())) &&
                idReferralLevels <= MAX_ID_REFERRAL_LEVELS &&
                name.size() > 0 &&
                name.size() <= (KOMODO_ASSETCHAIN_MAXLEN - 1) &&
                std::max({rewards.size(), rewardsDecay.size(), halving.size(), eraEnd.size()}) <= ASSETCHAINS_MAX_ERAS;
    }

    uint32_t ChainOptions() const
    {
        return options;
    }

    UniValue ToUniValue() const;

    int GetDefinedPort() const;

    bool IsFractional() const
    {
        return ChainOptions() & OPTION_FRACTIONAL;
    }

    bool IsToken() const
    {
        return ChainOptions() & OPTION_TOKEN;
    }

    bool IsNFTToken() const
    {
        return ChainOptions() & OPTION_NFT_TOKEN;
    }

    bool NoIDs() const
    {
        return IsNFTToken() || ChainOptions() & OPTION_NO_IDS;
    }

    bool IsGateway() const
    {
        return ChainOptions() & OPTION_GATEWAY;
    }

    bool IsPBaaSChain() const
    {
        return ChainOptions() & OPTION_PBAAS;
    }

    bool IsMultiCurrency() const
    {
        return !(ChainOptions() & OPTION_SINGLECURRENCY);
    }

    bool IsGatewayConverter() const
    {
        // all PBaaS chains are name controllers
        return ChainOptions() & OPTION_GATEWAY_CONVERTER;
    }

    bool IsNameController() const
    {
        return ChainOptions() & (OPTION_PBAAS | OPTION_GATEWAY_NAMECONTROLLER);
    }

    void SetToken(bool isToken)
    {
        if (isToken)
        {
            options |= OPTION_TOKEN;
        }
        else
        {
            options &= ~OPTION_TOKEN;
        }
    }

    void SetNFTToken(bool isToken)
    {
        if (isToken)
        {
            options |= OPTION_NFT_TOKEN;
        }
        else
        {
            options &= ~OPTION_NFT_TOKEN;
        }
    }

    void SetNoIDs(bool noIDs)
    {
        if (noIDs)
        {
            options |= OPTION_NO_IDS;
        }
        else
        {
            options &= ~OPTION_NO_IDS;
        }
    }

    std::map<uint160, int32_t> GetCurrenciesMap() const
    {
        std::map<uint160, int32_t> retVal;
        for (int i = 0; i < currencies.size(); i++)
        {
            retVal[currencies[i]] = i;
        }
        return retVal;
    }

    bool IDRequiresPermission() const
    {
        return ChainOptions() & OPTION_ID_ISSUANCE;
    }

    bool IDStaking() const
    {
        return ChainOptions() & OPTION_ID_STAKING;
    }

    bool IDReferrals() const
    {
        return ChainOptions() & OPTION_ID_REFERRALS;
    }

    bool IDReferralRequired() const
    {
        return ChainOptions() & OPTION_ID_REFERRALREQUIRED;
    }

    int IDReferralLevels() const
    {
        if (IDReferrals() || IDReferralRequired())
        {
            return idReferralLevels;
        }
        else
        {
            return 0;
        }
    }

    int64_t IDFullRegistrationAmount() const
    {
        return idRegistrationFees;
    }

    int64_t IDReferredRegistrationAmount() const
    {
        if (!IDReferrals())
        {
            return idRegistrationFees;
        }
        else
        {
            return (idRegistrationFees * (idReferralLevels + 1)) / (idReferralLevels + 2);
        }
    }

    int64_t IDReferralAmount() const
    {
        if (!IDReferrals())
        {
            return 0;
        }
        else
        {
            return idRegistrationFees / (idReferralLevels + 2);
        }
    }

    int64_t IDImportFee() const
    {
        return idImportFees;
    }

    static int64_t CalculateRatioOfValue(int64_t value, int64_t ratio);
    static int64_t CalculateRatioOfTwoValues(int64_t value1, int64_t value2);
    int64_t GetTotalPreallocation() const;
    int32_t GetTotalCarveOut() const;
};

// an identity signature is a compound signature consisting of the block height of its creation, and one or more cryptographic
// signatures of the controlling addresses. validation can be performed based on the validity when signed, using the block height
// stored in the signature instance, or based on the continued signature validity of the current identity, which may automatically
// invalidate when the identity is updated.
class CIdentitySignature
{
public:
    enum EVersions {
        VERSION_INVALID = 0,
        VERSION_VERUSID = 1,
        VERSION_FIRST = 1,
        VERSION_DEFAULT = 1,
        VERSION_ETHBRIDGE = 2,
        VERSION_LAST = 2
    };

    enum ESignatureSizes {
        ECDSA_RECOVERABLE_SIZE = 65U
    };

    enum ESignatureVerification {
        SIGNATURE_INVALID = 0,
        SIGNATURE_PARTIAL = 1,
        SIGNATURE_COMPLETE = 2,
        SIGNATURE_EMPTY = 3
    };

    uint8_t version;
    uint8_t hashType;
    uint32_t blockHeight;
    std::set<std::vector<unsigned char>> signatures;

    CIdentitySignature(const UniValue &uni);
    CIdentitySignature(CCurrencyDefinition::EHashTypes hType=CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR, uint8_t ver=VERSION_DEFAULT) :
        version(ver), hashType(hType), blockHeight(0)
    {
        if (IsValidHashType(hType) &&
            hType != CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR)
        {
            version = VERSION_ETHBRIDGE;
        }
    }

    CIdentitySignature(uint32_t height, const std::vector<unsigned char> &oneSig,
        CCurrencyDefinition::EHashTypes hType=CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR, uint8_t ver=VERSION_DEFAULT) :
        version(ver), hashType(hType), blockHeight(height), signatures({oneSig})
    {
        if (IsValidHashType(hType) &&
            hType != CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR)
        {
            version = VERSION_ETHBRIDGE;
        }
    }
    CIdentitySignature(uint32_t height, const std::set<std::vector<unsigned char>> &sigs,
        CCurrencyDefinition::EHashTypes hType=CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR, uint8_t ver=VERSION_DEFAULT) :
        version(ver), hashType(hType), blockHeight(height), signatures(sigs)
    {
        if (IsValidHashType(hType) &&
            hType != CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR)
        {
            version = VERSION_ETHBRIDGE;
        }
    }

    CIdentitySignature(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        if (version <= VERSION_LAST && version >= VERSION_FIRST)
        {
            if (version >= VERSION_ETHBRIDGE)
            {
                READWRITE(hashType);
            }
            else
            {
                hashType = CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR;
            }
            READWRITE(blockHeight);
            std::vector<std::vector<unsigned char>> sigs;
            if (ser_action.ForRead())
            {
                READWRITE(sigs);

                for (auto &oneSig : sigs)
                {
                    signatures.insert(oneSig);
                }
            }
            else
            {
                for (auto &oneSig : signatures)
                {
                    sigs.push_back(oneSig);
                }

                READWRITE(sigs);
            }
        }
    }

    ADD_SERIALIZE_METHODS;

    static bool IsValidHashType(CCurrencyDefinition::EHashTypes hashType)
    {
        return (hashType > CCurrencyDefinition::EHashTypes::HASH_INVALID && hashType <= CCurrencyDefinition::EHashTypes::HASH_LASTTYPE);
    }

    void AddSignature(const std::vector<unsigned char> &signature)
    {
        signatures.insert(signature);
    }

    static std::string IdentitySignatureKeyName()
    {
        return "vrsc::system.identity.signature";
    }

    static uint160 IdentitySignatureKey()
    {
        static uint160 nameSpace;
        static uint160 signatureKey = CVDXF::GetDataKey(IdentitySignatureKeyName(), nameSpace);
        return signatureKey;
    }

    uint256 IdentitySignatureHash(const std::vector<uint160> &vdxfCodes,
                                  const std::vector<std::string> &vdxfCodeNames,
                                  const std::vector<uint256> &statements,
                                  const uint160 &systemID,
                                  uint32_t blockHeight,
                                  const uint160 &signingID,
                                  const std::string &prefixString,
                                  const uint256 &msgHash) const;

    ESignatureVerification NewSignature(const CIdentity &signingID,
                                        const std::vector<uint160> &vdxfCodes,
                                        const std::vector<std::string> &vdxfCodeNames,
                                        const std::vector<uint256> &statements,
                                        const uint160 &systemID,
                                        uint32_t height,
                                        const std::string &prefixString,
                                        const uint256 &msgHash,
                                        const CKeyStore *pWallet=nullptr);

    ESignatureVerification AddSignature(const CIdentity &signingID,
                                        const std::vector<uint160> &vdxfCodes,
                                        const std::vector<std::string> &vdxfCodeNames,
                                        const std::vector<uint256> &statements,
                                        const uint160 &systemID,
                                        uint32_t blockHeight,
                                        const std::string &prefixString,
                                        const uint256 &msgHash,
                                        const CKeyStore *pWallet=nullptr);

    ESignatureVerification CheckSignature(const CIdentity &signingID,
                                          const std::vector<uint160> &vdxfCodes,
                                          const std::vector<std::string> &vdxfCodeNames,
                                          const std::vector<uint256> &statements,
                                          const uint160 systemID,
                                          const std::string &prefixString,
                                          const uint256 &msgHash,
                                          std::vector<std::vector<unsigned char>> *pDupSigs=nullptr) const;

    uint32_t Version()
    {
        return version;
    }

    static const std::map<std::string, CCurrencyDefinition::EHashTypes> &HashTypeStringMap();

    UniValue ToUniValue() const
    {
        UniValue retObj(UniValue::VOBJ);
        retObj.push_back(Pair("version", version));
        retObj.push_back(Pair("blockheight", (int64_t)blockHeight));
        switch (hashType)
        {
            case CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR:
            case CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR2:
            {
                retObj.push_back(Pair("hashtype", "blake2b"));
                break;
            }
            case CCurrencyDefinition::EHashTypes::HASH_SHA256:
            {
                retObj.push_back(Pair("hashtype", "sha256"));
                break;
            }
            case CCurrencyDefinition::EHashTypes::HASH_KECCAK:
            {
                retObj.push_back(Pair("hashtype", "keccak"));
                break;
            }
            case CCurrencyDefinition::EHashTypes::HASH_SHA256D:
            {
                retObj.push_back(Pair("hashtype", "sha256D"));
                break;
            }
            default:
            {
                retObj.push_back(Pair("hashtype", "unknown"));
            }
        }
        retObj.push_back(Pair("blockheight", (int64_t)blockHeight));
        UniValue sigs(UniValue::VARR);
        for (auto &oneSig : signatures)
        {
            sigs.push_back(HexBytes(&(oneSig[0]), oneSig.size()));
        }
        retObj.push_back(Pair("signatures", sigs));
        return retObj;
    }

    uint32_t IsValid()
    {
        return version <= VERSION_LAST && version >= VERSION_FIRST &&
            (hashType == CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR || (version >= VERSION_ETHBRIDGE && IsValidHashType((CCurrencyDefinition::EHashTypes)hashType)));
    }
};


class CProofRoot
{
public:
    enum EVersions
    {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = 1
    };
    enum ETypes
    {
        TYPE_PBAAS=1,                       // Verus and other PBaaS chain proof root type
        TYPE_ETHEREUM=2,                    // Ethereum proof root with patricia tree
        TYPE_KOMODO=3,                      // Komodo MoMoM proof root
        TYPE_SOLANA=4                       // Solana proof root: Keccak-hashed CPBaaSNotarization,
                                            // 13-of-N notary ECDSA quorum verified on Solana via
                                            // sol_secp256k1_recover. No equivalent of gasPrice — the
                                            // Solana side uses prioritization fees, not per-tx gas.
    };
    int16_t version;                        // to enable future data types with various functions
    int16_t type;                           // type of proof root
    uint160 systemID;                       // system that can have things proven on it with this root
    uint32_t rootHeight;                    // height (or sequence) of the notarization we certify
    uint256 stateRoot;                      // latest MMR root of the notarization height
    uint256 blockHash;                      // combination of block hash, block MMR root, and compact power (or external proxy) for the notarization height
    uint256 compactPower;                   // compact power (or external proxy) of the block height notarization to compare
    int64_t gasPrice;                       // Ethereum protocol gas price

    CProofRoot(int Type=TYPE_PBAAS, int Version=VERSION_INVALID) : type(Type), version(Version), rootHeight(0) {}
    CProofRoot(const UniValue &uni);
    CProofRoot(const uint160 &sysID,
                uint32_t nHeight,
                const uint256 &root,
                const uint256 &blkHash,
                const uint256 &power,
                int64_t GasPrice=0,
                int16_t Type=TYPE_PBAAS,
                int16_t Version=VERSION_CURRENT) :
                systemID(sysID), rootHeight(nHeight), stateRoot(root), blockHash(blkHash), compactPower(power), version(Version), type(Type), gasPrice(GasPrice) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(type);
        READWRITE(systemID);
        READWRITE(rootHeight);
        READWRITE(stateRoot);
        READWRITE(blockHash);
        READWRITE(compactPower);
        if (type == TYPE_ETHEREUM)
        {
            READWRITE(gasPrice);
        }
    }

    static CProofRoot GetProofRoot(uint32_t blockHeight);

    bool IsValid() const
    {
        return version >= VERSION_FIRST &&
               version <= VERSION_LAST &&
               rootHeight >= 0 &&
               !systemID.IsNull() &&
               !stateRoot.IsNull() &&
               !blockHash.IsNull();
    }

    friend bool operator==(const CProofRoot &op1, const CProofRoot &op2);
    friend bool operator!=(const CProofRoot &op1, const CProofRoot &op2);
    friend bool operator<(const CProofRoot &op1, const CProofRoot &op2);

    UniValue ToUniValue() const;
};

class CNativeHashWriter
{
private:
    CCurrencyDefinition::EHashTypes nativeHashType;
    union nativeHashWriter
    {
        CBLAKE2bWriter *hw_blake2b;
        CKeccack256Writer *hw_keccack;
        CHashWriterSHA256 *hw_sha256;
        CHashWriter *hw_sha256D;
    };
    nativeHashWriter state;

public:
    CNativeHashWriter(CCurrencyDefinition::EHashTypes hashType=CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR,
                      const unsigned char *personal=nullptr)
    {
        nativeHashType = hashType;
        switch (nativeHashType)
        {
            case CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR:
            case CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR2:
            {
                if (!personal)
                {
                    state.hw_blake2b = new CBLAKE2bWriter(SER_GETHASH, PROTOCOL_VERSION);
                }
                else
                {
                    state.hw_blake2b = new CBLAKE2bWriter(SER_GETHASH, PROTOCOL_VERSION, personal);
                }
                break;
            }
            case CCurrencyDefinition::EHashTypes::HASH_KECCAK:
            {
                state.hw_keccack = new CKeccack256Writer();
                break;
            }
            case CCurrencyDefinition::EHashTypes::HASH_SHA256:
            {
                state.hw_sha256 = new CHashWriterSHA256(SER_GETHASH, PROTOCOL_VERSION);
                break;
            }
            case CCurrencyDefinition::EHashTypes::HASH_SHA256D:
            {
                state.hw_sha256D = new CHashWriter(SER_GETHASH, PROTOCOL_VERSION);
                break;
            }
            default:
            {
                assert(false);
            }
        }
    }

    CNativeHashWriter(CCurrencyDefinition::EProofProtocol proofProtocol, const unsigned char *personal=nullptr) :
        CNativeHashWriter(CCurrencyDefinition::ProofProtocolHashType(proofProtocol), personal) {}

    ~CNativeHashWriter()
    {
        if (IsValid())
        {
            switch (nativeHashType)
            {
                case CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR:
                case CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR2:
                {
                    delete state.hw_blake2b;
                    break;
                }
                case CCurrencyDefinition::EHashTypes::HASH_KECCAK:
                {
                    delete state.hw_keccack;
                    break;
                }
                case CCurrencyDefinition::EHashTypes::HASH_SHA256:
                {
                    delete state.hw_sha256;
                    break;
                }
                case CCurrencyDefinition::EHashTypes::HASH_SHA256D:
                {
                    delete state.hw_sha256D;
                    break;
                }
                default:
                // No action needed for HASH_INVALID or HASH_LASTTYPE
                break;
            }
        }
        state.hw_blake2b = nullptr;
    }

    static bool IsValidHashType(CCurrencyDefinition::EHashTypes hashType)
    {
        return (hashType > CCurrencyDefinition::EHashTypes::HASH_INVALID && hashType <= CCurrencyDefinition::EHashTypes::HASH_LASTTYPE);
    }

    bool IsValid()
    {
        return IsValidHashType(nativeHashType) && state.hw_blake2b;
    }

    int GetType() const { return SER_GETHASH; }
    CCurrencyDefinition::EHashTypes GetHashType() const { return nativeHashType; }
    int GetVersion() const { return PROTOCOL_VERSION; }

    template<typename T>
    CNativeHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }

    // disallow copy/move until we implement these constructors and operators
    CNativeHashWriter(CNativeHashWriter const&) = delete;             // Copy construct
    CNativeHashWriter(CNativeHashWriter&&) = delete;                  // Move construct
    CNativeHashWriter& operator=(CNativeHashWriter const&) = delete;  // Copy assign
    CNativeHashWriter& operator=(CNativeHashWriter &&) = delete;      // Move assign

    CNativeHashWriter& write(const char *pch, size_t size)
    {
        switch (nativeHashType)
        {
            case CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR:
            case CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR2:
            {
                state.hw_blake2b->write(pch, size);
                break;
            }
            case CCurrencyDefinition::EHashTypes::HASH_KECCAK:
            {
                state.hw_keccack->write(pch, size);
                break;
            }
            case CCurrencyDefinition::EHashTypes::HASH_SHA256:
            {
                state.hw_sha256->write(pch, size);
                break;
            }
            case CCurrencyDefinition::EHashTypes::HASH_SHA256D:
            {
                state.hw_sha256D->write(pch, size);
                break;
            }
            default:
                // No action for HASH_INVALID or HASH_LASTTYPE
            break;
        }
        return (*this);
    }

    // invalidates the object
    uint256 GetHash() {
        uint256 result;
        switch (nativeHashType)
        {
            case CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR:
            case CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR2:
            {
                result = state.hw_blake2b->GetHash();
                break;
            }
            case CCurrencyDefinition::EHashTypes::HASH_KECCAK:
            {
                result = state.hw_keccack->GetHash();
                break;
            }
            case CCurrencyDefinition::EHashTypes::HASH_SHA256:
            {
                result = state.hw_sha256->GetHash();
                break;
            }
            case CCurrencyDefinition::EHashTypes::HASH_SHA256D:
            {
                result = state.hw_sha256D->GetHash();
                break;
            }
            default:
                // No action for HASH_INVALID or HASH_LASTTYPE
            break;
        }
        return result;
    }
};

extern int64_t AmountFromValue(const UniValue& value);
extern int64_t AmountFromValueNoErr(const UniValue& value);
extern UniValue ValueFromAmount(const int64_t& amount);
extern uint160 DecodeCurrencyName(std::string currencyStr);

// we wil uncomment service types as they are implemented
// commented service types are here as guidance and reminders
enum PBAAS_SERVICE_TYPES {
    SERVICE_INVALID = 0,
    SERVICE_NOTARIZATION = 1,
    SERVICE_LAST = 1
};

#endif
