/********************************************************************
 * (C) 2019 Michael Toutonghi
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * This provides reserve currency functions, leveraging the multi-precision boost libraries to calculate reserve currency conversions
 * in a predictable manner that can achieve consensus.
 *
 */

#ifndef PBAAS_RESERVES_H
#define PBAAS_RESERVES_H

#include <sstream>
#include <univalue.h>
#include "pbaas/crosschainrpc.h"
#include "arith_uint256.h"
#include <boost/multiprecision/cpp_dec_float.hpp>
#include "librustzcash.h"
#include "pubkey.h"
#include "amount.h"
#include "lrucache.h"

#ifndef SATOSHIDEN
#define SATOSHIDEN ((uint64_t)100000000L)
#endif

using boost::multiprecision::cpp_dec_float_50;
class CCoinsViewCache;
class CInputDescriptor;
class CBaseChainObject;
class CTransaction;
class CUTXORef;
class CMutableTransaction;
class CTxOut;
class CReserveTransactionDescriptor;
class CCurrencyState;
class CValidationState;
class CPBaaSNotarization;
extern uint160 ASSETCHAINS_CHAINID;


extern uint32_t PBAAS_ENFORCE_CORRECT_EVIDENCE_TIME;
extern uint32_t PBAAS_MAINDEFI3_HEIGHT;
extern uint32_t PBAAS_CLEARCONVERT_HEIGHT;
extern uint32_t PBAAS_LASTKNOWNCLEARORACLE_HEIGHT;
extern uint32_t PBAAS_OPTIMIZE_ETH_HEIGHT;

// reserve output is a special kind of token output that does not have to carry it's identifier, as it
// is always assumed to be the reserve currency of the current chain.
class CTokenOutput
{
public:
    enum
    {
        VERSION_INVALID = 0,
        VERSION_CURRENT = 1,
        VERSION_FIRSTVALID = 1,
        VERSION_LASTVALID = 1,
        VERSION_MULTIVALUE = 0x80000000 // used for serialization/deserialization
    };

    uint32_t nVersion;                  // version of the token output class
    CCurrencyValueMap reserveValues;    // all outputs of this reserve deposit

    CTokenOutput(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CTokenOutput(const UniValue &obj);

    CTokenOutput(uint32_t ver=VERSION_CURRENT) : nVersion(ver) {}

    CTokenOutput(const uint160 &curID, CAmount value) : nVersion(VERSION_CURRENT), reserveValues(std::vector<uint160>({curID}), std::vector<int64_t>({value})) {}
    CTokenOutput(CCurrencyValueMap values) : nVersion(VERSION_CURRENT), reserveValues(values) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        if (ser_action.ForRead())
        {
            READWRITE(VARINT(nVersion));
            if (nVersion & VERSION_MULTIVALUE)
            {
                READWRITE(reserveValues);
                nVersion &= ~VERSION_MULTIVALUE;
            }
            else
            {
                uint160 currencyID;
                CAmount nValue;
                READWRITE(currencyID);
                READWRITE(VARINT(nValue));
                reserveValues = CCurrencyValueMap(std::vector<uint160>({currencyID}), std::vector<int64_t>({nValue}));
            }
        }
        else
        {
            if (reserveValues.valueMap.size() == 1)
            {
                nVersion &= ~VERSION_MULTIVALUE;
                READWRITE(VARINT(nVersion));

                std::pair<uint160, int64_t> oneValPair = *reserveValues.valueMap.begin();
                uint160 currencyID = oneValPair.first;
                CAmount nValue = oneValPair.second;
                READWRITE(currencyID);
                READWRITE(VARINT(nValue));
            }
            else
            {
                nVersion |= VERSION_MULTIVALUE;
                READWRITE(VARINT(nVersion));
                READWRITE(reserveValues);
            }
        }
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    UniValue ToUniValue() const;

    uint160 FirstCurrency() const
    {
        auto it = reserveValues.valueMap.begin();
        return it == reserveValues.valueMap.end() ? uint160() : it->first;
    }

    CAmount FirstValue() const
    {
        auto it = reserveValues.valueMap.begin();
        return it == reserveValues.valueMap.end() ? 0 : it->second;
    }

    uint32_t Version() const
    {
        return nVersion;
    }

    bool IsValid() const
    {
        // we don't support op returns, value must be in native or reserve
        return nVersion >= VERSION_FIRSTVALID && nVersion <= VERSION_LASTVALID;
    }
};

class CCoinbaseCurrencyState;

class CReserveTransfer : public CTokenOutput
{
public:
    enum EOptions
    {
        VALID = 1,
        CONVERT = 2,
        PRECONVERT = 4,
        FEE_OUTPUT = 8,                     // one per import, amount must match total percentage of fees for exporter, no pre-convert allowed
        RESERVED = 0x10,                    // reserved
        MINT_CURRENCY = 0x20,               // set when this output is being minted on import
        CROSS_SYSTEM = 0x40,                // if this is set, there is a systemID serialized and deserialized as well for destination
        BURN_CHANGE_PRICE = 0x80,           // this output is being burned on import and will change the price
        BURN_CHANGE_WEIGHT = 0x100,         // this output is being burned on import and will change the reserve ratio
        IMPORT_TO_SOURCE = 0x200,           // set when the source currency, not destination is the import currency
        RESERVE_TO_RESERVE = 0x400,         // for arbitrage or transient conversion, 2 stage solving (2nd from new fractional to reserves)
        REFUND = 0x800,                     // this transfer should be refunded, individual property when conversions exceed limits
        IDENTITY_EXPORT = 0x1000,           // this exports a full identity when the next cross-chain leg is processed
        CURRENCY_EXPORT = 0x2000,           // this exports a currency definition
        ARBITRAGE_ONLY = 0x4000,            // in PBaaS V1, one additional reserve transfer from the local system may be added by the importer
    };

    enum EConstants
    {
        DESTINATION_BYTE_DIVISOR = 128,     // destination vector is divided by this and result is multiplied by normal fee and added to transfer fee
        SUCCESS_FEE = 25000,
        MIN_SUCCESS_FEE = 20000,
        MAX_NORMAL_TRANSFER_SIZE = 256,
        MAX_CURRENCYEXPORT_SIZE = 2048,
        MAX_IDENTITYEXPORT_SIZE = 1024,
    };

    static const CAmount DEFAULT_PER_STEP_FEE = 10000; // default fee for each step of each transfer (initial mining, transfer, mining on new chain)

    uint32_t flags;                         // type of transfer and options
    uint160 feeCurrencyID;                  // explicit fee currency
    CAmount nFees;                          // cross-chain network fees only, separated out to enable market conversions, conversion fees are additional
    CTransferDestination destination;       // system specific address to send funds to on the target system
    uint160 destCurrencyID;                 // system to export to, which may represent a PBaaS chain or external bridge
    uint160 secondReserveID;                // set if this is a reserve to reserve conversion
    uint160 destSystemID;                   // set if this is a cross-system send

    CReserveTransfer() : CTokenOutput(), flags(0), nFees(0) { }

    CReserveTransfer(const UniValue &uni);
    CReserveTransfer(const CScript &script);

    CReserveTransfer(const std::vector<unsigned char> &asVector)
    {
        bool success;
        FromVector(asVector, *this, &success);
        if (!success)
        {
            nVersion = VERSION_INVALID;
        }
    }

    CReserveTransfer(uint32_t version) : CTokenOutput(version), flags(0), nFees(0) { }

    CReserveTransfer(uint32_t Flags,
                     const CCurrencyValueMap values,
                     const uint160 &FeeCurrencyID,
                     CAmount fees,
                     const uint160 &destCurID,
                     const CTransferDestination &dest,
                     const uint160 &secondCID=uint160(),
                     const uint160 &destinationSystemID=uint160()) :
        CTokenOutput(values),
        flags(Flags),
        feeCurrencyID(FeeCurrencyID),
        nFees(fees),
        destCurrencyID(destCurID),
        destination(dest),
        secondReserveID(secondCID),
        destSystemID(destinationSystemID)
    {
        if (!secondReserveID.IsNull())
        {
            flags |= RESERVE_TO_RESERVE;
        }
    }

    CReserveTransfer(uint32_t Flags,
                     const uint160 &cID,
                     CAmount value,
                     const uint160 &FeeCurrencyID,
                     CAmount fees,
                     const uint160 &destCurID,
                     const CTransferDestination &dest,
                     const uint160 &secondCID=uint160(),
                     const uint160 &destinationSystemID=uint160()) :
        CTokenOutput(CCurrencyValueMap(std::vector<uint160>({cID}), std::vector<int64_t>({value}))),
        flags(Flags),
        feeCurrencyID(FeeCurrencyID),
        nFees(fees),
        destCurrencyID(destCurID),
        destination(dest),
        secondReserveID(secondCID),
        destSystemID(destinationSystemID)
    {
        if (!secondReserveID.IsNull())
        {
            flags |= RESERVE_TO_RESERVE;
        }
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CTokenOutput *)this);
        READWRITE(VARINT(flags));
        READWRITE(feeCurrencyID);
        READWRITE(VARINT(nFees));
        READWRITE(destination);
        READWRITE(destCurrencyID);
        if (flags & RESERVE_TO_RESERVE)
        {
            READWRITE(secondReserveID);
        }
        if (flags & CROSS_SYSTEM)
        {
            READWRITE(destSystemID);
        }
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    UniValue ToUniValue() const;

    CCurrencyValueMap TotalTransferFee() const;
    CCurrencyValueMap ConversionFee() const;
    CCurrencyValueMap CalculateFee() const;
    CCurrencyValueMap TotalCurrencyOut() const;

    static CAmount CalculateTransferFee(const CTransferDestination &destination, uint32_t flags=VALID);

    CAmount CalculateTransferFee() const;

    uint160 GetImportCurrency() const
    {
        return (flags & IMPORT_TO_SOURCE) ? FirstCurrency() : destCurrencyID;
    }

    bool IsValid() const
    {
        if ((IsPreConversion() && (IsBurn() || IsMint() || IsReserveToReserve() || IsFeeOutput() || IsIdentityExport() || IsCurrencyExport())) ||
            (IsConversion() && (IsBurn() || IsMint() || IsFeeOutput() || IsCurrencyExport())))
        {
            return false;
        }

        bool isCrossSystemIDNull = destSystemID.IsNull();
        return CTokenOutput::IsValid() &&
                reserveValues.valueMap.size() == 1 &&
                destination.IsValid() &&
                ((IsCrossSystem() &&  !isCrossSystemIDNull) || (!IsCrossSystem() &&  isCrossSystemIDNull));
    }

    bool IsConversion() const
    {
        return flags & CONVERT;
    }

    bool IsRefund() const
    {
        return flags & REFUND;
    }

    bool IsCrossSystem() const
    {
        return flags & CROSS_SYSTEM;
    }

    bool IsImportToSource() const
    {
        return flags & IMPORT_TO_SOURCE;
    }

    uint160 SystemDestination() const
    {
        return IsCrossSystem() ? destSystemID : ASSETCHAINS_CHAINID;
    }

    bool IsPreConversion() const
    {
        return flags & PRECONVERT;
    }

    uint160 FeeCurrencyID() const
    {
        return feeCurrencyID;
    }

    bool IsFeeOutput() const
    {
        return flags & FEE_OUTPUT;
    }

    bool IsBurn() const
    {
        return flags & (BURN_CHANGE_PRICE | BURN_CHANGE_WEIGHT);
    }

    bool IsBurnChangePrice() const
    {
        return flags & BURN_CHANGE_PRICE;
    }

    bool IsBurnChangeWeight() const
    {
        return flags & BURN_CHANGE_WEIGHT;
    }

    bool IsMint() const
    {
        return flags & MINT_CURRENCY;
    }

    bool IsReserveToReserve() const
    {
        return flags & RESERVE_TO_RESERVE;
    }

    void SetIdentityExport(bool isExport=true)
    {
        if (isExport)
        {
            flags |= IDENTITY_EXPORT;
        }
        else
        {
            flags &= ~IDENTITY_EXPORT;
        }
    }

    bool IsIdentityExport() const
    {
        return flags & IDENTITY_EXPORT || (destination.TypeNoFlags() == destination.DEST_FULLID);
    }

    void SetCurrencyExport(bool isExport=true)
    {
        if (isExport)
        {
            flags |= CURRENCY_EXPORT;
        }
        else
        {
            flags &= ~CURRENCY_EXPORT;
        }
    }

    bool IsCurrencyExport() const
    {
        return flags & CURRENCY_EXPORT || (destination.TypeNoFlags() == destination.DEST_REGISTERCURRENCY);
    }

    void SetArbitrageOnly(bool isArbitrage=true)
    {
        if (isArbitrage)
        {
            flags |= ARBITRAGE_ONLY;
        }
        else
        {
            flags &= ~ARBITRAGE_ONLY;
        }
    }

    bool IsArbitrageOnly() const
    {
        return flags & ARBITRAGE_ONLY;
    }

    CReserveTransfer GetRefundTransfer(bool clearCrossSystem=true, bool recoverFees=false) const;

    static std::string ReserveTransferKeyName()
    {
        return "vrsc::system.currency.reservetransfer";
    }

    static uint160 ReserveTransferKey()
    {
        static uint160 nameSpace;
        static uint160 reserveTransferKey = CVDXF::GetDataKey(ReserveTransferKeyName(), nameSpace);
        return reserveTransferKey;
    }

    static uint160 ReserveTransferSystemKey(const uint160 &systemID)
    {
        return CCrossChainRPCData::GetConditionID(systemID, ReserveTransferKey());
    }

    uint160 ReserveTransferSystemSourceKey()
    {
        return ReserveTransferSystemKey(ASSETCHAINS_CHAINID);
    }

    bool HasNextLeg() const
    {
        return destination.HasGatewayLeg();
    }

    // this returns either an output for the next leg or a normal output if there is no next leg
    // the next leg output can enable chaining of conversions and system transfers
    // typically, the txOutputs vector will not get any additional entry unless there is a support
    // definition required, such as full ID or currency definition.
    bool GetTxOut(const CCurrencyDefinition &sourceSystem,
                  const CCurrencyDefinition &destSystem,
                  const CCurrencyDefinition &destCurrency,
                  const CCoinbaseCurrencyState &curState,
                  CCurrencyValueMap reserves,
                  int64_t nativeAmount,
                  CTxOut &txOut,
                  std::vector<CTxOut> &txOutputs,
                  uint32_t height,
                  std::set<uint160> &exportedIDs,
                  std::set<uint160> &exportedCurrencies,
                  const uint256 &existingTxHash=uint256()) const;
};

class CReserveDeposit : public CTokenOutput
{
public:
    uint160 controllingCurrencyID;          // system to export to, which may represent a PBaaS chain or external bridge

    CReserveDeposit() : CTokenOutput() {}

    CReserveDeposit(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CReserveDeposit(const uint160 &controllingID, const CCurrencyValueMap &reserveOut) :
        CTokenOutput(reserveOut), controllingCurrencyID(controllingID) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CTokenOutput *)this);
        READWRITE(controllingCurrencyID);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    UniValue ToUniValue() const;

    bool IsValid() const
    {
        return CTokenOutput::IsValid() && !controllingCurrencyID.IsNull();
    }

    static std::string ReserveDepositKeyName()
    {
        return "vrsc::system.currency.reservedeposit";
    }

    static uint160 ReserveDepositKey()
    {
        static uint160 nameSpace;
        static uint160 reserveDepositKey = CVDXF::GetDataKey(ReserveDepositKeyName(), nameSpace);
        return reserveDepositKey;
    }

    uint160 ReserveDepositIndexKey() const
    {
        return CCrossChainRPCData::GetConditionID(controllingCurrencyID, ReserveDepositKey());
    }

    static uint160 ReserveDepositIndexKey(const uint160 &currencyID)
    {
        return CCrossChainRPCData::GetConditionID(currencyID, ReserveDepositKey());
    }
};

class CFeePool : public CTokenOutput
{
public:
    enum
    {
        PER_BLOCK_RATIO = 1000000,
        MIN_SHARE_SIZE = 10000,
        FLAG_COINBASE_POOL = 1,
        FLAG_CURRENCY_NOTARY_POOL = 2
    };
    uint32_t flags;
    uint160 notaryCurrencyID;
    CFeePool(uint32_t ver=VERSION_CURRENT, uint32_t Flags=FLAG_COINBASE_POOL) : CTokenOutput(ver), flags(FLAG_COINBASE_POOL) {}

    CFeePool(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CFeePool(const CTransaction &coinbaseTx);

    CFeePool(const CCurrencyValueMap &reserveOut, uint32_t Flags=FLAG_COINBASE_POOL, const uint160 &notaryCID=uint160()) :
        flags(Flags), notaryCurrencyID(notaryCID), CTokenOutput(reserveOut) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CTokenOutput *)this);
        READWRITE(VARINT(flags));
        if (flags & FLAG_CURRENCY_NOTARY_POOL)
        {
            READWRITE(notaryCurrencyID);
        }
        else
        {
            notaryCurrencyID = uint160();
        }
    }

    // returns false if fails to get block, otherwise, CFeePool if present
    // invalid CFeePool if not
    static bool GetCoinbaseFeePool(CFeePool &feePool, uint32_t height=0);

    CFeePool OneFeeShare()
    {
        CFeePool retVal;
        for (auto &oneCur : reserveValues.valueMap)
        {
            CAmount share = (oneCur.second <= MIN_SHARE_SIZE) ? oneCur.second : CCurrencyDefinition::CalculateRatioOfValue(oneCur.second, PER_BLOCK_RATIO);
            if (oneCur.second > MIN_SHARE_SIZE && share < MIN_SHARE_SIZE)
            {
                share = MIN_SHARE_SIZE;
            }
            if (share)
            {
                retVal.reserveValues.valueMap[oneCur.first] = share;
            }
        }
        return retVal;
    }

    void SetInvalid()
    {
        nVersion = VERSION_INVALID;
    }

    bool IsValid() const
    {
        return CTokenOutput::IsValid();
    }
};

class CCrossChainExport;

// import transactions and tokens from another chain
// this represents the chain, the currencies, and the amounts of each
// it may also import IDs from the chain on which they were defined
class CCrossChainImport
{
public:
    enum EVersion {
        VERSION_INVALID = 0,
        VERSION_CURRENT = 1,
        VERSION_LAST = 1,
    };
    enum EFlags {
        FLAG_DEFINITIONIMPORT = 1,
        FLAG_INITIALLAUNCHIMPORT = 2,
        FLAG_POSTLAUNCH = 4,
        FLAG_SAMECHAIN = 8,                             // means proof/reserve transfers are from export on chain
        FLAG_HASSUPPLEMENT = 0x10,                      // indicates that we have additional outputs containing the reservetransfers for this export
        FLAG_SUPPLEMENTAL = 0x20,                       // this flag indicates that this is a supplemental output to a prior output
        FLAG_SOURCESYSTEM = 0x40,                       // import flag used to indicate source system
    };

    uint16_t nVersion;
    uint16_t flags;
    uint160 sourceSystemID;                             // the native source currency system from where these transactions are imported
    uint32_t sourceSystemHeight;                        // export system height at export
    uint160 importCurrencyID;                           // the import currency ID
    CCurrencyValueMap importValue;                      // total amount of coins imported from source system with or without conversion, including fees
    CCurrencyValueMap totalReserveOutMap;               // all non-native currencies being held in this thread and released on import
    int32_t numOutputs;                                 // number of outputs generated by this import on this transaction for validation

    uint256 hashReserveTransfers;                       // hash of complete reserve transfer list in order if (txinputs, m=0, m=1, ..., m=(n-1))
    uint256 exportTxId;                                 // txid of export
    int32_t exportTxOutNum;                             // output of the tx

    CCrossChainImport() : nVersion(VERSION_INVALID), flags(0), sourceSystemHeight(0), numOutputs(0) {}
    CCrossChainImport(const uint160 &sourceSysID,
                      uint32_t sourceSysHeight,
                      const uint160 &importCID,
                      const CCurrencyValueMap &ImportValue,
                      const CCurrencyValueMap &InitialReserveOutput=CCurrencyValueMap(),
                      int32_t NumOutputs=0,
                      uint256 HashReserveTransfers=uint256(),
                      uint256 ExportTxId=uint256(),
                      int32_t ExportTxOutNum=-1,
                      uint16_t Flags=FLAG_SAMECHAIN,
                      uint16_t version=VERSION_CURRENT) :
                        nVersion(version),
                        flags(Flags),
                        sourceSystemID(sourceSysID),
                        sourceSystemHeight(sourceSysHeight),
                        importCurrencyID(importCID),
                        importValue(ImportValue),
                        totalReserveOutMap(InitialReserveOutput),
                        numOutputs(NumOutputs),
                        hashReserveTransfers(HashReserveTransfers),
                        exportTxId(ExportTxId),
                        exportTxOutNum(ExportTxOutNum)
                        { }

    CCrossChainImport(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CCrossChainImport(const CTransaction &tx, int32_t *pOutNum=nullptr);
    CCrossChainImport(const CScript &script);
    CCrossChainImport(const UniValue &obj);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(flags);
        READWRITE(sourceSystemID);
        READWRITE(sourceSystemHeight);
        READWRITE(importCurrencyID);
        READWRITE(importValue);
        READWRITE(totalReserveOutMap);
        READWRITE(numOutputs);
        READWRITE(hashReserveTransfers);
        READWRITE(exportTxId);
        READWRITE(exportTxOutNum);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return nVersion > VERSION_INVALID && nVersion <= VERSION_LAST && !sourceSystemID.IsNull();
    }

    bool IsSameChain() const
    {
        return flags & FLAG_SAMECHAIN;
    }

    void SetSameChain(bool isSameChain)
    {
        if (isSameChain)
        {
            flags |= FLAG_SAMECHAIN;
        }
        else
        {
            flags &= ~FLAG_SAMECHAIN;
        }
    }

    void SetDefinitionImport(bool isDefinition)
    {
        if (isDefinition)
        {
            flags |= FLAG_DEFINITIONIMPORT;
        }
        else
        {
            flags &= ~FLAG_DEFINITIONIMPORT;
        }
    }

    bool IsDefinitionImport() const
    {
        return flags & FLAG_DEFINITIONIMPORT;
    }

    bool IsPostLaunch() const
    {
        return flags & FLAG_POSTLAUNCH;
    }

    void SetPostLaunch(bool isPostLaunch=true)
    {
        if (isPostLaunch)
        {
            flags |= FLAG_POSTLAUNCH;
        }
        else
        {
            flags &= ~FLAG_POSTLAUNCH;
        }
    }

    bool IsSourceSystemImport() const
    {
        return flags & FLAG_SOURCESYSTEM;
    }

    // still importing from pre-launch exports that may contain pre-conversions but not conversions
    // after all of those imports are complete, we can import post-launch exports
    bool IsInitialLaunchImport() const
    {
        return flags & FLAG_INITIALLAUNCHIMPORT;
    }

    void SetInitialLaunchImport(bool isInitialLaunchImport=true)
    {
        if (isInitialLaunchImport)
        {
            flags |= FLAG_INITIALLAUNCHIMPORT;
        }
        else
        {
            flags &= ~FLAG_INITIALLAUNCHIMPORT;
        }
    }

    UniValue ToUniValue() const;

    static std::string CurrencyImportKeyName()
    {
        return "vrsc::system.currency.currencyimport";
    }

    static uint160 CurrencyImportKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(CurrencyImportKeyName(), nameSpace);
        return key;
    }

    static std::string CurrencyImportFromSystemKeyName()
    {
        return "vrsc::system.currency.currencyimportfromsystem";
    }

    static uint160 CurrencyImportFromSystemKey(const uint160 &fromSystem, const uint160 &toCurrency)
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(CurrencyImportFromSystemKeyName(), nameSpace);
        return CCrossChainRPCData::GetConditionID(key, CCrossChainRPCData::GetConditionID(fromSystem, toCurrency));
    }

    static std::string CurrencySystemImportKeyName()
    {
        return "vrsc::system.currency.systemimport";
    }

    static uint160 CurrencySystemImportKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(CurrencySystemImportKeyName(), nameSpace);
        return key;
    }

    std::vector<CReserveTransfer> GetArbitrageTransfers(const CTransaction &tx,
                                                        CValidationState &state,
                                                        uint32_t nHeight,
                                                        std::vector<CTransaction> *pArbTxes=nullptr,
                                                        std::vector<CUTXORef> *pArbOuts=nullptr,
                                                        std::vector<uint256> *pArbTxBlockHash=nullptr) const;

    CCrossChainImport GetPriorImport(const CTransaction &tx,
                                     CValidationState &state,
                                     CTransaction *priorTx=nullptr,
                                     int32_t *priorOutNum=nullptr,
                                     uint256 *ppriorTxBlockHash=nullptr) const;

    CCrossChainImport GetPriorImportFromSystem(const CTransaction &tx,
                                               CValidationState &state,
                                               CTransaction *priorTx=nullptr,
                                               int32_t *priorOutNum=nullptr,
                                               uint256 *ppriorTxBlockHash=nullptr) const;

    CCurrencyValueMap GetBestPriorConversions(const CTransaction &tx,
                                              int32_t outNum,
                                              const uint160 &converterCurrencyID,
                                              const uint160 &targetCurrencyID,
                                              const CCoinbaseCurrencyState &curConverterState,
                                              CValidationState &state,
                                              uint32_t height,
                                              uint32_t minHeight,
                                              uint32_t maxHeight) const;

    bool UnconfirmedNameImports(const CTransaction &tx,
                                int32_t outNum,
                                CValidationState &state,
                                uint32_t height,
                                std::set<uint160> *pIDImports=nullptr,
                                std::set<uint160> *pCurrencyImports=nullptr) const;

    bool VerifyNameTransfers(const CTransaction &tx,
                             int32_t outNum,
                             CValidationState &state,
                             uint32_t height,
                             std::set<uint160> *pIDConflicts=nullptr,
                             std::set<uint160> *pCurrencyConflicts=nullptr) const;

    // returns false if the information is unavailable, indicating an invalid, out of context, or
    // incomplete import transaction
    bool GetImportInfo(const CTransaction &importTx,
                       uint32_t nHeight,
                       int numImportOut,
                       CCrossChainExport &ccx,
                       CCrossChainImport &sysCCI,
                       int32_t &sysCCIOut,
                       CPBaaSNotarization &importNotarization,
                       int32_t &importNotarizationOut,
                       int32_t &evidenceOutStart,
                       int32_t &evidenceOutEnd,
                       std::vector<CReserveTransfer> &reserveTransfers,
                       CValidationState &state,
                       bool deepCheck=false) const;

    bool GetImportInfo(const CTransaction &importTx,
                       uint32_t nHeight,
                       int numImportOut,
                       CCrossChainExport &ccx,
                       CCrossChainImport &sysCCI,
                       int32_t &sysCCIOut,
                       CPBaaSNotarization &importNotarization,
                       int32_t &importNotarizationOut,
                       int32_t &evidenceOutStart,
                       int32_t &evidenceOutEnd,
                       std::vector<CReserveTransfer> &reserveTransfers,
                       bool deepCheck=false) const;

    // ensures that all import rules were properly followed to create
    // the import inputs and outputs on this transaction
    bool ValidateImport(const CTransaction &tx,
                        int numImportin,
                        int numImportOut,
                        CCrossChainExport &ccx,
                        CPBaaSNotarization &importNotarization,
                        std::vector<CReserveTransfer> &reserveTransfers,
                        CValidationState &state) const;
    bool ValidateImport(const CTransaction &tx,
                        int numImportin,
                        int numImportOut,
                        CCrossChainExport &ccx,
                        CPBaaSNotarization &importNotarization,
                        std::vector<CReserveTransfer> &reserveTransfers) const;
};

// describes an entire output that will be realized on a target chain. target is specified as part of an aggregated transaction.
class CCrossChainExport
{
public:
    enum {
        MIN_BLOCKS = 10,
        MIN_INPUTS = 10,
        MAX_FEE_INPUTS = 50                         // when we reach 50 or more inputs, we get maximum fees as an exporter
    };

    enum
    {
        MIN_FEES_BEFORE_FEEPOOL = 20000,            // MAX(MIN(this, max avail), RATIO_OF_EXPORT_FEE of export fees) is sent to exporter
        RATIO_OF_EXPORT_FEE = 10000000,
    };

    enum EVersions
    {
        VERSION_INVALID = 0,
        VERSION_CURRENT = 1,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
    };

    enum EFlags
    {
        FLAG_PRELAUNCH = 1,                     // prior to launch
        FLAG_CLEARLAUNCH = 2,                   // when launch state is determined, there is one of these
        FLAG_HASSUPPLEMENT = 4,                 // indicates that we have additional outputs containing the reservetransfers for this export
        FLAG_SUPPLEMENTAL = 8,                  // this flag indicates that this is a supplemental output to a prior output
        FLAG_EVIDENCEONLY = 0x10,               // when set, this is not indexed as an active export
        FLAG_UNUSED = 0x20,                     // currently unused
        FLAG_DEFINITIONEXPORT = 0x40,           // set on only the first export
        FLAG_POSTLAUNCH = 0x80,                 // set post launch
        FLAG_SYSTEMTHREAD = 0x100               // export that is there to ensure continuous export thread only
    };

    /*
    int32_t &nextOutput,
    CPBaaSNotarization &exportNotarization,
    std::vector<CReserveTransfer> &reserveTransfers,
    CCurrencyDefinition::EProofProtocol hashType
    */
    static LRUCache<CUTXORef, std::tuple<int, CCrossChainExport, CPBaaSNotarization, std::vector<CReserveTransfer>, CCurrencyDefinition::EProofProtocol>>
        exportInfoCache;

    uint16_t nVersion;                          // current version
    uint16_t flags;                             // controls serialization and active state

    // these amounts are not serialized for supplemental export outputs, which identify themselves,
    // indicate their position in the relative group of outputs, and carry the additional reserve transfers.
    uint160 sourceSystemID;                     // imported from native system or gateway (notarization payout to this system)
    uint256 hashReserveTransfers;               // hash of complete reserve transfer list in order of (txinputs, m=0, m=1, ..., m=(n-1))
    uint160 destSystemID;                       // exported to target blockchain or system
    uint160 destCurrencyID;                     // exported to target currency
    CTransferDestination exporter;              // typically the exporting miner or staker's address, to accept deferred payment for the export

    int32_t firstInput;                         // if export is from inputs, on chain of reserveTransfers, this is first input, -1 for cross-chain
    int32_t numInputs;                          // total number of inputs aggregated for validation

    uint32_t sourceHeightStart;                 // exporting all items to the destination from source system height...
    uint32_t sourceHeightEnd;                   // to height, inclusive of end, last before start block from launch chain is needed to start a currency

    CCurrencyValueMap totalFees;                // total fees in all currencies to split between this export and import
    CCurrencyValueMap totalAmounts;             // total amount exported of each currency, including fees
    CCurrencyValueMap totalBurned;              // if this is a cross chain export, some currencies will be burned, the rest held in deposits
    std::vector<CReserveTransfer> reserveTransfers; // reserve transfers for this export, can be split across multiple outputs

    CCrossChainExport() : nVersion(VERSION_INVALID), flags(0), sourceHeightStart(0), sourceHeightEnd(0), numInputs(0), firstInput(0) {}

    CCrossChainExport(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CCrossChainExport(const uint160 &SourceSystemID,
                      int32_t SourceHeightStart,
                      int32_t SourceHeightEnd,
                      const uint160 &DestSystemID,
                      const uint160 &DestCurrencyID,
                      int32_t numin,
                      const CCurrencyValueMap &values,
                      const CCurrencyValueMap &transferFees,
                      const uint256 &HashReserveTransfers,
                      const CCurrencyValueMap &TotalBurned=CCurrencyValueMap(),
                      int32_t firstin=-1,
                      const CTransferDestination Exporter=CTransferDestination(),
                      const std::vector<CReserveTransfer> &ReserveTransfers=std::vector<CReserveTransfer>(),
                      int16_t Flags=0, int16_t Version=VERSION_CURRENT) :
                      nVersion(Version),
                      flags(Flags),
                      sourceSystemID(SourceSystemID),
                      hashReserveTransfers(HashReserveTransfers),
                      destSystemID(DestSystemID),
                      destCurrencyID(DestCurrencyID),
                      sourceHeightStart(SourceHeightStart),
                      sourceHeightEnd(SourceHeightEnd),
                      numInputs(numin),
                      totalBurned(TotalBurned),
                      firstInput(firstin),
                      totalAmounts(values),
                      totalFees(transferFees),
                      exporter(Exporter),
                      reserveTransfers(ReserveTransfers)
    {}

    CCrossChainExport(const CScript &script);
    CCrossChainExport(const UniValue &obj);
    CCrossChainExport(const CTransaction &tx, int32_t *pCCXOutputNum=nullptr);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(flags);
        READWRITE(sourceSystemID);
        if (!(flags & FLAG_SUPPLEMENTAL))
        {
            READWRITE(hashReserveTransfers);
            READWRITE(destSystemID);
            READWRITE(destCurrencyID);
            READWRITE(exporter);
            READWRITE(firstInput);
            READWRITE(numInputs);
            READWRITE(VARINT(sourceHeightStart));
            READWRITE(VARINT(sourceHeightEnd));
            READWRITE(totalFees);
            READWRITE(totalAmounts);
            READWRITE(totalBurned);
        }
        READWRITE(reserveTransfers);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsSupplemental() const
    {
        return flags & FLAG_SUPPLEMENTAL;
    }

    bool HasSupplement() const
    {
        return flags & FLAG_HASSUPPLEMENT;
    }

    bool IsValid() const
    {
        return nVersion >= VERSION_FIRST &&
               nVersion <= VERSION_LAST &&
               !sourceSystemID.IsNull() &&
               (IsSupplemental() ||
               (!destSystemID.IsNull() &&
                firstInput >= -1 &&
                numInputs >= 0 &&
                numInputs <= (CCurrencyDefinition::MAX_TRANSFER_EXPORTS_PER_BLOCK << 2) &&
                !destCurrencyID.IsNull()));
    }

    static CCurrencyValueMap CalculateExportFee(const CCurrencyValueMap &fees, int numIn);
    static CAmount CalculateExportFeeRaw(CAmount fee, int numIn);
    CCurrencyValueMap CalculateExportFee() const;
    CCurrencyValueMap CalculateImportFee() const;
    static CAmount ExportReward(const CCurrencyDefinition &destSystem, int64_t exportFee);

    UniValue ToUniValue() const;

    bool IsSameChain() const
    {
        return sourceSystemID == destSystemID;
    }

    bool IsPrelaunch() const
    {
        return flags & FLAG_PRELAUNCH;
    }

    void SetPreLaunch(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_PRELAUNCH;
        }
        else
        {
            flags &= ~FLAG_PRELAUNCH;
        }
    }

    bool IsPostlaunch() const
    {
        return flags & FLAG_POSTLAUNCH;
    }

    void SetPostLaunch(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_POSTLAUNCH;
        }
        else
        {
            flags &= ~FLAG_POSTLAUNCH;
        }
    }

    bool IsSystemThreadExport() const
    {
        return flags & FLAG_SYSTEMTHREAD;
    }

    void SetSystemThreadExport(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_SYSTEMTHREAD;
        }
        else
        {
            flags &= ~FLAG_SYSTEMTHREAD;
        }
    }

    bool IsChainDefinition() const
    {
        return flags & FLAG_DEFINITIONEXPORT;
    }

    void SetChainDefinition(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_DEFINITIONEXPORT;
        }
        else
        {
            flags &= ~FLAG_DEFINITIONEXPORT;
        }
    }

    bool IsClearLaunch() const
    {
        return flags & FLAG_CLEARLAUNCH;
    }

    void SetClearLaunch(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_CLEARLAUNCH;
        }
        else
        {
            flags &= ~FLAG_CLEARLAUNCH;
        }
    }

    bool GetExportInfo(const CTransaction &exportTx,
                       int numExportOut,
                       int &primaryExportOutNumOut,
                       int32_t &nextOutput,
                       CPBaaSNotarization &exportNotarization,
                       std::vector<CReserveTransfer> &reserveTransfers,
                       CValidationState &state,
                       CCurrencyDefinition::EProofProtocol hashType=CCurrencyDefinition::EProofProtocol::PROOF_PBAASMMR) const;

    bool GetExportInfo(const CTransaction &exportTx,
                       int numExportOut,
                       int &primaryExportOutNumOut,
                       int32_t &nextOutput,
                       CPBaaSNotarization &exportNotarization,
                       std::vector<CReserveTransfer> &reserveTransfers,
                       CCurrencyDefinition::EProofProtocol hashType=CCurrencyDefinition::EProofProtocol::PROOF_PBAASMMR) const;

    static std::string CurrencyExportKeyName()
    {
        return "vrsc::system.currency.export";
    }

    static uint160 CurrencyExportKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(CurrencyExportKeyName(), nameSpace);
        return key;
    }

    static std::string SystemExportKeyName()
    {
        return "vrsc::system.currency.systemexport";
    }

    static uint160 SystemExportKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(SystemExportKeyName(), nameSpace);
        return key;
    }
};

class CCurrencyState
{
public:
    enum EVersion {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = 1,
    };

    enum EFlags {
        FLAG_FRACTIONAL = 1,
        FLAG_PRELAUNCH = 2,
        FLAG_REFUNDING = 4,
        FLAG_LAUNCHCLEAR = 8,               // set only on the first import after launch has been cleared, whether refunding or confirmed
        FLAG_LAUNCHCONFIRMED = 0x10,
        FLAG_LAUNCHCOMPLETEMARKER = 0x20    // only set on the currency state when importing the last transfers exported during pre-launch
    };

    enum EConstants {
        MIN_RESERVE_RATIO = 1000000,        // we will not start a chain with less than 1% reserve ratio in any single currency
        MAX_RESERVE_RATIO = 100000000,      // we will not start a chain with greater than 100% reserve ratio
        SHUTDOWN_RESERVE_RATIO = 500000,    // if we hit this reserve ratio in any currency, initiate chain shutdown
        CONVERSION_TX_SIZE_MIN = 1024,      // minimum size accounted for in a conversion transaction
        MAX_RESERVE_CURRENCIES = 10,        // maximum number of reserve currencies that can underly a fractional reserve
        MIN_CONVERTER_RESERVE_TO_INDEX = 1000, // must have at least this much in native reserves to be indexed as a converter
        MIN_CONVERTER_RATIO_TO_INDEX = 10000000 // must have at least 10% reserve ratio of native as well
    };

    uint16_t version;
    uint16_t flags;                         // currency flags (valid, reserve currency, etc.)
    uint160 currencyID;                     // ID of this currency
    std::vector<uint160> currencies;        // the ID in uin160 form (maps to CIdentityID) if each currency in the reserve
    std::vector<int32_t> weights;           // current, individual weights for all currencies to use in calculations
    std::vector<int64_t> reserves;          // total amount of reserves in each currency

    int64_t initialSupply;                  // initial premine + pre-converted coins
    int64_t emitted;                        // emitted coins reduce the reserve ratio and are used to calculate current ratio
    CAmount supply;                         // current supply: total of initial, all emitted, and all purchased coins

    CCurrencyState() : version(VERSION_INVALID), flags(0), initialSupply(0), emitted(0), supply(0) {}

    CCurrencyState(const uint160 &cID,
                   const std::vector<uint160> &Currencies,
                   const std::vector<int32_t> &Weights,
                   const std::vector<int64_t> &Reserves,
                   CAmount InitialSupply,
                   CAmount Emitted,
                   CAmount Supply,
                   uint16_t Flags=0,
                   uint16_t Version=VERSION_CURRENT) :
        version(Version),
        flags(Flags),
        currencyID(cID),
        currencies(Currencies),
        weights(Weights),
        reserves(Reserves),
        initialSupply(InitialSupply),
        emitted(Emitted),
        supply(Supply)
    {
        if (weights.size() != currencies.size())
        {
            weights = std::vector<int32_t>(currencies.size());
        }
        if (reserves.size() != reserves.size())
        {
            reserves = std::vector<int64_t>(currencies.size());
        }
    }

    CCurrencyState(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CCurrencyState(const UniValue &uni);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(flags);
        READWRITE(currencyID);
        READWRITE(currencies);
        READWRITE(weights);
        READWRITE(reserves);
        READWRITE(VARINT(initialSupply));
        READWRITE(VARINT(emitted));
        READWRITE(VARINT(supply));
    }

    std::vector<unsigned char> AsVector() const
    {
        return ::AsVector(*this);
    }

    // this should be done no more than once to prepare a currency state to be moved to the next state
    // emission occurs for a block before any conversion or exchange and that impact on the currency state is calculated
    // excess ratio is used in the case of issuance into a liquidity pool. in that case, the total reserve ratio
    // to be subtracted is first offset by the excessRatio before deduction.
    CCurrencyState &UpdateWithEmission(CAmount emitted, int32_t excessRatio=0);

    cpp_dec_float_50 GetReserveRatio(int32_t reserveIndex=0) const
    {
        return cpp_dec_float_50(std::to_string(weights[reserveIndex])) / cpp_dec_float_50("100000000");
    }

    template<typename cpp_dec_float_type>
    static bool to_int64(const cpp_dec_float_type &input, int64_t &outval)
    {
        std::stringstream ss(input.str(0, std::ios_base::fixed));
        try
        {
            ss >> outval;
            return true;
        }
        catch(const std::exception& e)
        {
            return false;
        }
    }

    // in a fractional reserve with no reserve or supply, this will always return
    // a price of the reciprocal (1/x) of the fractional reserve ratio of the indexed reserve,
    // which will always be >= 1
    CAmount PriceInReserve(int32_t reserveIndex=0, bool roundUp=false) const;

    // return the current price of the fractional reserve in the reserve currency in Satoshis
    cpp_dec_float_50 PriceInReserveDecFloat50(int32_t reserveIndex=0) const;

    std::vector<CAmount> PricesInReserve(bool roundUp=false) const;

    // convert amounts for multi-reserve fractional reserve currencies
    // one entry in the vector for each currency in and one fractional input for each
    // currency expected as output
    std::vector<CAmount> ConvertAmounts(const std::vector<CAmount> &inputReserve,       // reserves to convert to fractional
                                        const std::vector<CAmount> &inputFractional,    // fractional to convert to each reserve
                                        CCurrencyState &newState,
                                        bool promoteExchangeRate,                       // true to compensate for library issue & false to remain compatible with on-chain data
                                        bool layerFixActive,                            // true to enable layer calc fix
                                        CValidationState &validationState,
                                        const std::vector<std::vector<CAmount>> *pCrossConversions=nullptr,
                                        std::vector<CAmount> *pViaPrices=nullptr) const;

    CAmount CalculateConversionFee(CAmount inputAmount, bool convertToNative=false, int32_t reserveIndex=0) const;

    CAmount ReserveToNative(CAmount reserveAmount, int32_t reserveIndex, bool promoteExchangeRate=true) const;
    CAmount ReserveToNative(const CCurrencyValueMap &reserveAmounts) const;

    static CAmount ReserveToNativeRaw(CAmount reserveAmount, const cpp_dec_float_50 &exchangeRate);
    static CAmount ReserveToNativeRaw(CAmount reserveAmount, CAmount exchangeRate, bool promoteExchangeRate=true);
    static CAmount ReserveToNativeRaw(const CCurrencyValueMap &reserveAmounts, const std::vector<uint160> &currencies, const std::vector<CAmount> &exchangeRates);
    static CAmount ReserveToNativeRaw(const CCurrencyValueMap &reserveAmounts, const std::vector<uint160> &currencies, const std::vector<cpp_dec_float_50> &exchangeRates);
    CAmount ReserveToNativeRaw(const CCurrencyValueMap &reserveAmounts, const std::vector<CAmount> &exchangeRates) const;

    const CCurrencyValueMap &NativeToReserve(std::vector<CAmount> nativeAmount, int32_t reserveIndex=0) const;
    CAmount NativeToReserve(CAmount nativeAmount, int32_t reserveIndex=0, bool promoteExchangeRate=true) const;
    static CAmount NativeToReserveRaw(CAmount nativeAmount, const cpp_dec_float_50 &exchangeRate);
    static CAmount NativeToReserveRaw(CAmount nativeAmount, CAmount exchangeRate, bool promoteExchangeRate=true);
    static CAmount NativeGasToReserveRaw(CAmount nativeAmount, CAmount exchangeRate, bool promoteExchangeRate=true);
    CCurrencyValueMap NativeToReserveRaw(const std::vector<CAmount> &, const std::vector<CAmount> &exchangeRates) const;
    CCurrencyValueMap NativeToReserveRaw(const std::vector<CAmount> &, const std::vector<cpp_dec_float_50> &exchangeRates) const;

    CAmount AddToSupply(CAmount nValue) const;

    UniValue ToUniValue() const;

    uint160 GetID() const { return currencyID; }

    bool IsValid() const
    {
        return version >= VERSION_FIRST && version <= VERSION_LAST && !currencyID.IsNull();
    }

    bool IsFractional() const
    {
        return flags & FLAG_FRACTIONAL;
    }

    bool IsRefunding() const
    {
        return flags & FLAG_REFUNDING;
    }

    bool IsPrelaunch() const
    {
        return flags & FLAG_PRELAUNCH;
    }

    bool IsLaunchClear() const
    {
        return flags & FLAG_LAUNCHCLEAR;
    }

    bool IsLaunchConfirmed() const
    {
        return flags & FLAG_LAUNCHCONFIRMED;
    }

    bool IsLaunchCompleteMarker() const
    {
        return flags & FLAG_LAUNCHCOMPLETEMARKER;
    }

    // this is only set after the import that completes all pre-conversions
    void SetLaunchCompleteMarker(bool newState=true)
    {
        if (newState)
        {
            flags &= ~FLAG_PRELAUNCH;
            flags |= FLAG_LAUNCHCOMPLETEMARKER;
        }
        else
        {
            flags &= ~FLAG_LAUNCHCOMPLETEMARKER;
        }
    }

    void SetPrelaunch(bool newState=true)
    {
        if (newState)
        {
            flags |= FLAG_PRELAUNCH;
        }
        else
        {
            flags &= ~FLAG_PRELAUNCH;
        }
    }

    void SetLaunchClear(bool newState=true)
    {
        if (newState)
        {
            flags |= FLAG_LAUNCHCLEAR;
        }
        else
        {
            flags &= ~FLAG_LAUNCHCLEAR;
        }
    }

    void SetLaunchConfirmed(bool newState=true)
    {
        if (newState)
        {
            flags |= FLAG_LAUNCHCONFIRMED;
        }
        else
        {
            flags &= ~FLAG_LAUNCHCONFIRMED;
        }
    }

    void SetRefunding(bool newState=true)
    {
        if (newState)
        {
            flags |= FLAG_REFUNDING;
        }
        else
        {
            flags &= ~FLAG_REFUNDING;
        }
    }

    std::map<uint160, int32_t> GetReserveMap() const
    {
        std::map<uint160, int32_t> retVal;
        for (int i = 0; i < currencies.size(); i++)
        {
            retVal[currencies[i]] = i;
        }
        return retVal;
    }
};

class CCoinbaseCurrencyState : public CCurrencyState
{
public:
    CAmount primaryCurrencyOut;             // converted or generated currency output, emitted, converted, etc. is stored in parent class
    CAmount preConvertedOut;                // how much of the currency out was pre-converted, which is asynchronously added to supply
    CAmount primaryCurrencyFees;
    CAmount primaryCurrencyConversionFees;
    std::vector<CAmount> reserveIn;         // reserve currency converted to native
    std::vector<CAmount> primaryCurrencyIn; // native currency converted to reserve
    std::vector<CAmount> reserveOut;        // output can have both normal and reserve output value, if non-0, this is spent by the required output transactions
    std::vector<CAmount> conversionPrice;   // calculated price in reserve for all conversions * 100000000
    std::vector<CAmount> viaConversionPrice; // the via conversion stage prices
    std::vector<CAmount> fees;              // fee values in native (or reserve if specified) coins for reserve transaction fees for the block
    std::vector<CAmount> conversionFees;    // total of only conversion fees, which will accrue to the conversion transaction
    std::vector<int32_t> priorWeights;      // previous weights to enable reversal of state

    enum ReversionUpdate {
        PBAAS_1_0_0 = 0,
        PBAAS_1_0_8 = 1,
        PBAAS_1_0_10 = 2,
        PBAAS_1_0_12 = 3
    };

    CCoinbaseCurrencyState() : primaryCurrencyOut(0), preConvertedOut(0), primaryCurrencyFees(0), primaryCurrencyConversionFees(0) {}

    CCoinbaseCurrencyState(const CCurrencyState &CurrencyState,
                           CAmount NativeOut=0, CAmount NativeFees=0, CAmount NativeConversionFees=0,
                           const std::vector<CAmount> &ReserveIn=std::vector<CAmount>(),
                           const std::vector<CAmount> &NativeIn=std::vector<CAmount>(),
                           const std::vector<CAmount> &ReserveOut=std::vector<CAmount>(),
                           const std::vector<CAmount> &ConversionPrice=std::vector<CAmount>(),
                           const std::vector<CAmount> &ViaConversionPrice=std::vector<CAmount>(),
                           const std::vector<CAmount> &Fees=std::vector<CAmount>(),
                           const std::vector<CAmount> &ConversionFees=std::vector<CAmount>(),
                           CAmount PreConvertedOut=0,
                           const std::vector<int32_t> &PriorWeights=std::vector<int32_t>()) :
        CCurrencyState(CurrencyState), primaryCurrencyOut(NativeOut), primaryCurrencyFees(NativeFees), primaryCurrencyConversionFees(NativeConversionFees),
        reserveIn(ReserveIn),
        primaryCurrencyIn(NativeIn),
        reserveOut(ReserveOut),
        conversionPrice(ConversionPrice),
        viaConversionPrice(ViaConversionPrice),
        fees(Fees),
        conversionFees(ConversionFees),
        preConvertedOut(PreConvertedOut),
        priorWeights(PriorWeights)
    {
        int numCurrencies = currencies.size();
        if (reserveIn.size() != numCurrencies) reserveIn.resize(currencies.size());
        if (primaryCurrencyIn.size() != numCurrencies) primaryCurrencyIn.resize(currencies.size());
        if (reserveOut.size() != numCurrencies) reserveOut.resize(currencies.size());
        if (conversionPrice.size() != numCurrencies) conversionPrice.resize(currencies.size());
        if (viaConversionPrice.size() != numCurrencies) viaConversionPrice.resize(currencies.size());
        if (fees.size() != numCurrencies) fees.resize(currencies.size());
        if (conversionFees.size() != numCurrencies) conversionFees.resize(currencies.size());
        if (priorWeights.size() != numCurrencies) priorWeights.resize(currencies.size());
    }

    CCoinbaseCurrencyState(const UniValue &uni);

    CCoinbaseCurrencyState(const std::vector<unsigned char> asVector)
    {
        ::FromVector(asVector, *this);
    }

    CCoinbaseCurrencyState(const CTransaction &tx, int *pOutIdx=NULL);

    bool ValidateConversionLimits(bool checkZeroViaOnlyPostLaunch=false) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CCurrencyState *)this);
        READWRITE(primaryCurrencyOut);
        READWRITE(preConvertedOut);
        READWRITE(primaryCurrencyFees);
        READWRITE(primaryCurrencyConversionFees);
        READWRITE(reserveIn);
        READWRITE(primaryCurrencyIn);
        READWRITE(reserveOut);
        READWRITE(conversionPrice);
        READWRITE(viaConversionPrice);
        READWRITE(fees);
        READWRITE(priorWeights);
        READWRITE(conversionFees);
    }

    std::vector<unsigned char> AsVector() const
    {
        return ::AsVector(*this);
    }

    UniValue ToUniValue() const;

    CCoinbaseCurrencyState &UpdateWithEmission(CAmount toEmit, int32_t excessRatio=0);
    CCoinbaseCurrencyState &ApplyCarveouts(int32_t carveOut);

    void ClearForNextBlock()
    {
        priorWeights = weights.size() ? weights : std::vector<int32_t>(currencies.size());
        emitted = 0;
        primaryCurrencyOut = 0;
        preConvertedOut = 0;
        primaryCurrencyFees = 0;
        primaryCurrencyConversionFees = 0;
        reserveIn = std::vector<CAmount>(currencies.size());
        primaryCurrencyIn = std::vector<CAmount>(currencies.size());
        reserveOut = std::vector<CAmount>(currencies.size());
        fees = std::vector<CAmount>(currencies.size());
        conversionFees = std::vector<CAmount>(currencies.size());
    }

    // given that all reserves in and out are accurate, this reverts the reserves and supply to the prior state,
    // while leaving conversion prices the same
    void RevertFees(const std::vector<CAmount> &conversionPrice,
                    const std::vector<CAmount> &viaConversionPrice,
                    const uint160 &systemID=ASSETCHAINS_CHAINID);

    // returns all unconverted fees, liquidity fees, and converted fees
    // convertedFees are only added to if fees are found and never modified other than that, so this can
    // be used for accumulation.
    CCurrencyValueMap CalculateConvertedFees(const std::vector<CAmount> &normalConversionPrice,
                                             const std::vector<CAmount> &outgoingConversionPrice,
                                             const uint160 &systemID,
                                             bool &feesConverted,
                                             CCurrencyValueMap &liquidityFees,
                                             CCurrencyValueMap &convertedFees) const;

    static ReversionUpdate ReversionUpdateForHeight(uint32_t height);
    void RevertReservesAndSupply(const CCurrencyDefinition &revertCur,
                                 const uint160 &systemID=ASSETCHAINS_CHAINID,
                                 bool pbaasInitialChainCurrency=false,
                                 ReversionUpdate reversionUpdate=PBAAS_1_0_0);

    template <typename NUMBERVECTOR>
    static NUMBERVECTOR AddVectors(const NUMBERVECTOR &a, const NUMBERVECTOR &b)
    {
        const NUMBERVECTOR *shortVec, *longVec;
        int64_t count, max;
        if (a.size() <= b.size())
        {
            count = a.size();
            max = b.size();
            shortVec = &a;
            longVec = &b;
        }
        else
        {
            count = b.size();
            max = a.size();
            shortVec = &b;
            longVec = &a;
        }

        NUMBERVECTOR ret;
        ret.resize(max);
        for (int i = 0; i < count; i++)
        {
            ret[i] = (*longVec)[i] + (*shortVec)[i];
        }
        for (int i = count; i < max; i++)
        {
            ret[i] = (*longVec)[i];
        }
        return ret;
    }

    inline static int64_t IndexConverterReserveMinimum()
    {
        // TODO: this needs to be specific to the current blockchain
        // on Verus, we will consider any currency with 1000 or more in Verus reserves and >= 10% reserve a possible
        // converter
        return MIN_CONVERTER_RESERVE_TO_INDEX;
    }

    inline static int32_t IndexConverterReserveRatio()
    {
        // currencies must have at least 10% native reserve to be considered a converter
        return MIN_CONVERTER_RATIO_TO_INDEX;
    }

    static std::string CurrencyStateKeyName()
    {
        return "vrsc::system.currency.state";
    }

    static uint160 CurrencyStateKey()
    {
        static uint160 nameSpace;
        static uint160 currencyStateKey = CVDXF::GetDataKey(CurrencyStateKeyName(), nameSpace);
        return currencyStateKey;
    }

    static std::string CurrencyConverterKeyName()
    {
        return "vrsc::system.currency.converter";
    }

    static uint160 CurrencyConverterKey()
    {
        static uint160 nameSpace;
        static uint160 converterKey = CVDXF::GetDataKey(CurrencyConverterKeyName(), nameSpace);
        return converterKey;
    }

    inline static uint160 IndexConverterKey(const uint160 &currencyID)
    {
        return CCrossChainRPCData::GetConditionID(currencyID, CurrencyConverterKey());
    }

    int64_t TargetConversionPrice(const uint160 &sourceCurrencyID, const uint160 &targetCurrencyID) const;
    CCurrencyValueMap TargetConversionPrices(const uint160 &targetCurrencyID) const;
    CCurrencyValueMap TargetConversionPrices(const uint160 &targetCurrencyID, const CCurrencyValueMap &prices, const CCurrencyValueMap &viaPrices) const;
    CCurrencyValueMap TargetLastConversionPrices(const uint160 &targetCurrencyID) const;
    CCurrencyValueMap TargetConversionPricesReverse(const uint160 &targetCurrencyID, bool addFeePct=false) const;
    CCurrencyValueMap TargetConversionPricesReverse(const uint160 &targetCurrencyID, const CCurrencyValueMap &prices, const CCurrencyValueMap &viaPrices, bool addFeePct=false) const;
};

class CReserveInOuts
{
public:
    int64_t reserveIn;
    int64_t reserveOut;
    int64_t reserveOutConverted;
    int64_t nativeOutConverted;
    int64_t reserveConversionFees;
    CReserveInOuts() : reserveIn(0), reserveOut(0), reserveOutConverted(0), nativeOutConverted(0), reserveConversionFees(0) {}
    CReserveInOuts(int64_t ReserveIn, int64_t ReserveOut, int64_t ReserveOutConverted, int64_t NativeOutConverted, int64_t ReserveConversionFees) :
                    reserveIn(ReserveIn),
                    reserveOut(ReserveOut),
                    reserveOutConverted(ReserveOutConverted),
                    nativeOutConverted(NativeOutConverted),
                    reserveConversionFees(ReserveConversionFees) {}
    UniValue ToUniValue() const;
};

class CReserveTransactionDescriptor
{
public:
    enum EFlagBits {
        IS_VALID=1,                             // known to be valid
        IS_REJECT=2,                            // if set, tx is known to be invalid
        IS_RESERVE_OUTPUT=4,                    // if set, this transaction is a reserve output
        IS_RESERVETRANSFER=8,                   // is this a reserve/exchange transaction?
        IS_RESERVE_DEPOSIT=0x10,                // if reserve deposit?
        IS_EVAL_NONE=0x20,                      // If set, this is an EVAL_NONE output
        IS_COMMITMENT=0x40,                     // If set, this is an identity or advanced commitment
        IS_IMPORT=0x80,                         // non-supplemental export
        IS_EXPORT=0x100,                        // import
        IS_IDENTITY=0x200,                      // If set, this is an identity definition or update
        IS_IDENTITY_DEFINITION=0x400,           // If set, this is an identity definition
        IS_HIGH_FEE=0x800,                      // If set, this may have "absurdly high fees"
        IS_CURRENCY_DEFINITION=0x1000,          // If set, this is a currency definition
        IS_CHAIN_NOTARIZATION=0x2000,           // If set, this is to do with primary chain notarization and connection
        IS_EVIDENCE_STORAGE=0x4000              // If set, this is evidence or storage
    };

    enum ESubIndexCodes {
        ONE_RESERVE_IDX = 1                     // used to create a condition code that indexed reserves of a fractional currency
    };

    const CTransaction *ptx;                    // pointer to the actual transaction if valid
    uint16_t flags;                             // indicates transaction state
    std::map<uint160, CReserveInOuts> currencies; // currency entries in this transaction
    int16_t numBuys = 0;
    int16_t numSells = 0;
    int16_t numTransfers = 0;                   // number of transfers, each of which also requires a transfer fee
    CAmount nativeIn = 0;
    CAmount nativeOut = 0;
    CAmount nativeConversionFees = 0;           // non-zero only if there is a conversion

    CReserveTransactionDescriptor() :
        flags(0),
        ptx(NULL),
        numBuys(0),
        numSells(0),
        numTransfers(0),
        nativeIn(0),
        nativeOut(0),
        nativeConversionFees(0) {}              // non-zero only if there is a conversion, stored vs. calculated to get exact number with each calculated seperately

    CReserveTransactionDescriptor(const CTransaction &tx, const CCoinsViewCache &view, int32_t nHeight);

    UniValue ToUniValue() const;

    bool IsReject() const { return flags & IS_REJECT; }
    bool IsValid() const { return flags & IS_VALID && !IsReject(); }
    bool IsReserveOutput() const { return IsValid() && flags & IS_RESERVE_OUTPUT; }
    bool IsReserveTransfer() const { return flags & IS_RESERVETRANSFER; }
    bool IsReserveDeposit() const { return flags & IS_RESERVE_DEPOSIT; }
    bool IsEvalNone() const { return flags & IS_EVAL_NONE; }
    bool IsCommitment() const { return flags & IS_COMMITMENT; }
    bool IsIdentity() const { return flags & IS_IDENTITY; }
    bool IsImport() const { return flags & IS_IMPORT; }
    bool IsExport() const { return flags & IS_EXPORT; }
    bool IsCurrencyDefinition() const { return flags & IS_CURRENCY_DEFINITION; }
    bool IsNotaryPrioritized() const { return flags & IS_CHAIN_NOTARIZATION; }
    bool IsEvidenceOrStorage() const { return flags & IS_EVIDENCE_STORAGE; }
    bool IsStorage() const { return IsEvidenceOrStorage() && !(IsImport() || IsNotaryPrioritized()); }
    bool IsIdentityDefinition() const { return flags & IS_IDENTITY_DEFINITION; }
    bool IsHighFee() const { return flags & IS_HIGH_FEE; }

    static CAmount CalculateConversionFee(CAmount inputAmount);
    static CAmount CalculateConversionFeeNoMin(CAmount inputAmount);
    static CAmount CalculateAdditionalConversionFee(CAmount inputAmount);
    static CAmount CalculateAdditionalConversionFeeNoMin(CAmount inputAmount);

    CAmount TotalNativeOutConverted() const
    {
        CAmount nativeOutConverted = 0;
        for (auto &one : currencies)
        {
            nativeOutConverted += one.second.nativeOutConverted;
        }
        return nativeOutConverted;
    }

    CCurrencyValueMap ReserveFees(const uint160 &nativeID=uint160()) const;
    CAmount NativeFees() const;

    CAmount AllFeesAsNative(const CCurrencyState &currencyState) const;
    CAmount AllFeesAsNative(const CCurrencyState &currencyState, const std::vector<CAmount> &exchangeRates) const;
    CCurrencyValueMap AllFeesAsReserve(const CCurrencyState &currencyState, int defaultReserve=0) const;
    CCurrencyValueMap AllFeesAsReserve(const CCurrencyState &currencyState, const std::vector<CAmount> &exchangeRates, int defaultReserve=0) const;

    // does not check for errors
    void AddReserveInput(const uint160 &currency, CAmount value);
    void AddReserveOutput(const uint160 &currency, CAmount value);
    void AddReserveOutConverted(const uint160 &currency, CAmount value);
    void AddNativeOutConverted(const uint160 &currency, CAmount value);
    void AddReserveConversionFees(const uint160 &currency, CAmount value);

    CCurrencyValueMap ReserveInputMap(const uint160 &nativeID=uint160()) const;
    CCurrencyValueMap ReserveOutputMap(const uint160 &nativeID=uint160()) const;
    CCurrencyValueMap ReserveOutConvertedMap(const uint160 &nativeID=uint160()) const;
    CCurrencyValueMap NativeOutConvertedMap() const;
    CCurrencyValueMap ReserveConversionFeesMap() const;
    CCurrencyValueMap GeneratedImportCurrency(const uint160 &fromSystemID, const uint160 &importSystemID, const uint160 &importCurrencyID) const;

    // returns vectors in same size and order as reserve currencies
    std::vector<CAmount> ReserveInputVec(const CCurrencyState &cState) const;
    std::vector<CAmount> ReserveOutputVec(const CCurrencyState &cState) const;
    std::vector<CAmount> ReserveOutConvertedVec(const CCurrencyState &cState) const;
    std::vector<CAmount> NativeOutConvertedVec(const CCurrencyState &cState) const;
    std::vector<CAmount> ReserveConversionFeesVec(const CCurrencyState &cState) const;

    void AddReserveOutput(const CTokenOutput &ro);
    void AddReserveTransfer(const CReserveTransfer &rt);

    bool AddReserveTransferImportOutputs(const CCurrencyDefinition &systemSource,
                                         const CCurrencyDefinition &systemDest,
                                         const CCurrencyDefinition &importCurrencyDef,
                                         const CCoinbaseCurrencyState &importCurrencyState,
                                         const std::vector<CReserveTransfer> &exportObjects,
                                         uint32_t height,
                                         std::vector<CTxOut> &vOutputs,
                                         CCurrencyValueMap &importedCurrency,
                                         CCurrencyValueMap &gatewayDepositsIn,
                                         CCurrencyValueMap &spentCurrencyOut,
                                         CCoinbaseCurrencyState *pNewCurrencyState=nullptr,
                                         const CTransferDestination &feeRecipient=CTransferDestination(),
                                         const CTransferDestination &blockNotarizer=CTransferDestination(),
                                         const uint256 &entropy=uint256(),
                                         bool finalValidityCheck=false);
};

// FIFO cost basis tracker, could be changed to have FIFO, LIFO, etc.
// Supports storing and retrieving currencies by a combination of currency and block time, and keeping
// association with cost basis and amounts
class CCostBasisTracker
{
public:
    std::multimap<std::pair<uint160,uint32_t>,std::pair<int64_t,int64_t>> costBasisMap;

    CCostBasisTracker() {}
    CCostBasisTracker(const UniValue &uni);
    void PutCurrency(const uint160 &currencyID, uint32_t blockTime, int64_t costBasis, int64_t amount);
    std::vector<std::tuple<uint32_t, int64_t, int64_t>> TakeCurrency(const uint160 &currencyID, int64_t amount, int64_t &amountLeft);
    UniValue ToUniValue() const;

    static std::string FiatDefaultName()
    {
        return "dai.veth";
    }

    static uint160 FiatDefault();

    int64_t GetNativeCostBasisFiat(const CPBaaSNotarization &importNotarization, const std::map<std::string, int64_t> &nativePriceMap, uint32_t blockTime, uint32_t nHeight, const uint160 &fiatCurrency=FiatDefault()) const;

    int64_t GetConversionCostBasisNative(const CPBaaSNotarization &importNotarization, const uint160 &convertToCurrencyID, uint32_t nHeight) const;
};

// consider keeping ordered list of:
// short term transactions
// long term transactions
class CEarningsTracker
{
public:
    enum {
        defaultShortLongTermThresholdSeconds = 31536000
    };
    uint160 fiatCurrencyID;
    uint32_t shortLongTermThresholdSeconds;
    CCurrencyValueMap validationEarnings;
    int64_t validationEarningsFiat;
    int64_t feesInFiat;
    CCurrencyValueMap shortTermGainLoss;
    int64_t shortTermGainLossFiat;
    CCurrencyValueMap longTermGainLoss;
    int64_t longTermGainLossFiat;

    CEarningsTracker(const uint160 &FiatCurrency=CCostBasisTracker::FiatDefault(), uint32_t ShortLongThresholdSeconds=defaultShortLongTermThresholdSeconds) :
        fiatCurrencyID(FiatCurrency), shortLongTermThresholdSeconds(ShortLongThresholdSeconds), validationEarningsFiat(0), feesInFiat(0), shortTermGainLossFiat(0), longTermGainLossFiat(0) {}

    CEarningsTracker(const UniValue &uni);

    uint160 FiatCurrencyID() const;

    UniValue ToUniValue() const;

    void AddValidationEarnings(uint160 originalCurrencyIn, int64_t amountOrig, int64_t valueFiat);

    void AddFees(int64_t valueFiat)
    {
        feesInFiat += valueFiat;
    }

    void AddShortTerm(int64_t valueFiat);

    void AddLongTerm(int64_t valueFiat);
};

struct CCcontract_info;
struct Eval;
class CValidationState;

typedef std::tuple<uint32_t, CInputDescriptor, CReserveTransfer> ChainTransferData;

bool ValidateFeePool(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsFeePoolInput(const CScript &scriptSig);
bool PrecheckFeePool(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool PrecheckReserveTransfer(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
bool PrecheckReserveDeposit(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);

#endif // PBAAS_RESERVES_H
