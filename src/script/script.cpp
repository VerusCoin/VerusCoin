// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "script.h"

#include "tinyformat.h"
#include "utilstrencodings.h"
#include "script/cc.h"
#include "cc/eval.h"
#include "cryptoconditions/include/cryptoconditions.h"
#include "standard.h"
#include "pbaas/reserves.h"
#include "key_io.h"
#include "univalue.h"
#include "pbaas/identity.h"
#include "pbaas/notarization.h"

using namespace std;

extern bool fIdIndex;
extern bool fConversionIndex;

namespace {
    inline std::string ValueString(const std::vector<unsigned char>& vch)
    {
        if (vch.size() <= 4)
            return strprintf("%d", CScriptNum(vch, false).getint());
        else
            return HexStr(vch);
    }
} // anon namespace

const char* GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";
    case OP_CHECKCRYPTOCONDITION   : return "OP_CHECKCRYPTOCONDITION";
    case OP_CHECKCRYPTOCONDITIONVERIFY
                                   : return "OP_CHECKCRYPTOCONDITIONVERIFY";

    // expansion
    case OP_NOP1                   : return "OP_NOP1";
    case OP_NOP2                   : return "OP_NOP2";
    case OP_NOP3                   : return "OP_NOP3";
    case OP_NOP4                   : return "OP_NOP4";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";

    // Note:
    //  The template matching params OP_SMALLDATA/etc are defined in opcodetype enum
    //  as kind of implementation hack, they are *NOT* real opcodes.  If found in real
    //  Script, just let the default: case deal with them.

    default:
        return "OP_UNKNOWN";
    }
}

int64_t STORAGE_FEE_FACTOR;

uint160 GetConditionID(uint160 cid, int32_t condition)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 CTransferDestination::CurrencyDefinitionExportKeyToSystem(const uint160 &exportToSystemID)
{
    return CCrossChainRPCData::GetConditionID(UnboundCurrencyDefinitionExportKey(), exportToSystemID);
}

uint160 CTransferDestination::GetBoundCurrencyDefinitionExportKey(const uint160 &exportToSystemID, const uint160 &curToExportID)
{
    return CCrossChainRPCData::GetConditionID(CurrencyDefinitionExportKeyToSystem(exportToSystemID), curToExportID);;
}

uint160 CTransferDestination::GetBoundCurrencyDefinitionExportKey(const uint160 &exportToSystemID) const
{
    uint160 retVal;
    if (TypeNoFlags() == DEST_REGISTERCURRENCY)
    {
        CCurrencyDefinition curDef(destination);
        if (curDef.IsValid())
        {
            retVal = CCrossChainRPCData::GetConditionID(CurrencyDefinitionExportKeyToSystem(exportToSystemID), curDef.GetID());
        }
    }
    return retVal;
}

CTxDestination GetCompatibleAuxDestination(const CTransferDestination &transferDest, CCurrencyDefinition::EProofProtocol addressProtocol)
{
    for (int i = -1; i < transferDest.AuxDestCount(); i++)
    {
        switch (i == -1 ? transferDest.TypeNoFlags() : transferDest.GetAuxDest(i).TypeNoFlags())
        {
            case CTransferDestination::DEST_PKH:
            case CTransferDestination::DEST_PK:
            case CTransferDestination::DEST_SH:
            case CTransferDestination::DEST_ID:
            case CTransferDestination::DEST_FULLID:
            {
                if (addressProtocol != CCurrencyDefinition::PROOF_ETHNOTARIZATION)
                {
                    try
                    {
                        return TransferDestinationToDestination(i == -1 ? transferDest : transferDest.GetAuxDest(i));
                    }
                    catch(...)
                    {
                        return CTxDestination();
                    }
                }
                break;
            }

            case CTransferDestination::DEST_ETH:
            {
                if (addressProtocol == CCurrencyDefinition::PROOF_ETHNOTARIZATION)
                {
                    try
                    {
                        return TransferDestinationToDestination(i == -1 ? transferDest : transferDest.GetAuxDest(i));
                    }
                    catch(...)
                    {
                        return CTxDestination();
                    }
                }
                break;
            }
        }
    }
    return CTxDestination();
}

CTxDestination TransferDestinationToDestination(const CTransferDestination &transferDest, CCurrencyDefinition::EProofProtocol addressProtocol)
{
    CTxDestination retDest;
    switch (transferDest.TypeNoFlags())
    {
        case CTransferDestination::DEST_PKH:
            retDest = CKeyID(uint160(transferDest.destination));
            break;

        case CTransferDestination::DEST_PK:
            {
                CPubKey pk;
                pk.Set(transferDest.destination.begin(), transferDest.destination.end());
                retDest = pk;
            }
            break;

        case CTransferDestination::DEST_SH:
            retDest = CScriptID(uint160(transferDest.destination));
            break;

        case CTransferDestination::DEST_ID:
            retDest = CIdentityID(uint160(transferDest.destination));
            break;

        case CTransferDestination::DEST_FULLID:
            retDest = CIdentityID(CIdentity(transferDest.destination).GetID());
            break;

        case CTransferDestination::DEST_REGISTERCURRENCY:
        {
            CCcontract_info CC;
            CCcontract_info *cp;

            // return first valid auxilliary address for this chain
            int auxDestCount = transferDest.AuxDestCount();
            for (int i=0; i < auxDestCount; i++)
            {
                CTransferDestination auxDest = transferDest.GetAuxDest(i);
                switch (auxDest.TypeNoFlags())
                {
                    case CTransferDestination::DEST_ID:
                    case CTransferDestination::DEST_PK:
                    case CTransferDestination::DEST_PKH:
                    case CTransferDestination::DEST_SH:
                        return TransferDestinationToDestination(auxDest);
                }
            }
            // no address found, send it to the public key of the currency definition type
            cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);
            retDest = CTxDestination(CPubKey(ParseHex(CC.CChexstr)));
            break;
        }

        case CTransferDestination::DEST_ETHNFT:
        {
            CCcontract_info CC;
            CCcontract_info *cp;
            // this type is only used in currency definitions and does not make sense
            // to be converted to an address at this time
            cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);
            retDest = CTxDestination(CPubKey(ParseHex(CC.CChexstr)));
            break;
        }

        case CTransferDestination::DEST_QUANTUM:
            retDest = CQuantumID(uint160(transferDest.destination));
            break;

        case CTransferDestination::DEST_NESTEDTRANSFER:
        {
            CReserveTransfer rt(transferDest.destination);
            if (rt.IsValid())
            {
                retDest = TransferDestinationToDestination(rt.destination);
            }
        }
        break;
    }
    return retDest;
}

CTransferDestination DestinationToTransferDestination(const CTxDestination &dest)
{
    CTransferDestination retDest;
    switch (dest.which())
    {
    case CTransferDestination::DEST_PKH:
    case CTransferDestination::DEST_PK:
    case CTransferDestination::DEST_SH:
    case CTransferDestination::DEST_ID:
    case CTransferDestination::DEST_QUANTUM:
        retDest = CTransferDestination(dest.which(), GetDestinationBytes(dest));
        break;
    }
    return retDest;
}

CTransferDestination IdentityToTransferDestination(const CIdentity &identity)
{
    return CTransferDestination(CTransferDestination::DEST_FULLID, ::AsVector(identity));
}

CIdentity TransferDestinationToIdentity(const CTransferDestination &dest)
{
    CIdentity retIdentity;
    switch (dest.type)
    {
        case CTransferDestination::DEST_FULLID:
        {
            ::FromVector(dest.destination, retIdentity);
            break;
        }
    }
    return retIdentity;
}

CTransferDestination CurrencyToTransferDestination(const CCurrencyDefinition &currency)
{
    return CTransferDestination(CTransferDestination::DEST_REGISTERCURRENCY, ::AsVector(currency));
}

CCurrencyDefinition TransferDestinationToCurrency(const CTransferDestination &dest)
{
    CCurrencyDefinition retCurrency;
    switch (dest.type)
    {
        case CTransferDestination::DEST_REGISTERCURRENCY:
        {
            ::FromVector(dest.destination, retCurrency);
            break;
        }
    }
    return retCurrency;
}

std::vector<CTransferDestination> DestinationsToTransferDestinations(const std::vector<CTxDestination> &dests)
{
    std::vector<CTransferDestination> retDests;
    for (auto &dest : dests)
    {
        retDests.push_back(DestinationToTransferDestination(dest));
    }
    return retDests;
}

CStakeInfo::CStakeInfo(std::vector<unsigned char> vch)
{
    ::FromVector(vch, *this);
}

std::vector<unsigned char> CStakeInfo::AsVector() const
{
    return ::AsVector(*this);
}

unsigned int CScript::MAX_SCRIPT_ELEMENT_SIZE = MAX_SCRIPT_ELEMENT_SIZE_IDENTITY;

unsigned int CScript::GetSigOpCount(bool fAccurate) const
{
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
        {
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += DecodeOP_N(lastOpcode);
            else
                n += 20;
        }
        lastOpcode = opcode;
    }
    return n;
}

unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const
{
    if (!IsPayToScriptHash())
        return GetSigOpCount(true);

    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    const_iterator pc = scriptSig.begin();
    vector<unsigned char> data;
    while (pc < scriptSig.end())
    {
        opcodetype opcode;
        if (!scriptSig.GetOp(pc, opcode, data))
            return 0;
        if (opcode > OP_16)
            return 0;
    }

    /// ... and return its opcount:
    CScript subscript(data.begin(), data.end());
    return subscript.GetSigOpCount(true);
}

bool CScript::IsPayToPublicKeyHash() const
{
    // Extra-fast test for pay-to-pubkey-hash CScripts:
    return (this->size() == 25 &&
	    (*this)[0] == OP_DUP &&
	    (*this)[1] == OP_HASH160 &&
	    (*this)[2] == 0x14 &&
	    (*this)[23] == OP_EQUALVERIFY &&
	    (*this)[24] == OP_CHECKSIG);
}

bool CScript::IsPayToPublicKey() const
{
    // Extra-fast test for pay-to-pubkey CScripts:
    return (this->size() == 35 &&
            (*this)[0] == 33 &&
            (*this)[34] == OP_CHECKSIG);
}

bool CScript::IsPayToScriptHash() const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    return (this->size() == 23 &&
            (*this)[0] == OP_HASH160 &&
            (*this)[1] == 0x14 &&
            (*this)[22] == OP_EQUAL);
}

// this returns true if either there is nothing left and pc points at the end, or
// all instructions from the pc to the end of the script are balanced pushes and pops
// if there is data, it also returns all the values as byte vectors in a list of vectors
bool CScript::GetBalancedData(const_iterator& pc, std::vector<std::vector<unsigned char>>& vSolutions) const
{
    int netPushes = 0;
    vSolutions.clear();

    while (pc < end())
    {
        vector<unsigned char> data;
        opcodetype opcode;
        if (this->GetOp(pc, opcode, data))
        {
            if (opcode == OP_DROP)
            {
                // this should never pop what it hasn't pushed (like a success code)
                if (--netPushes < 0)
                    return false;
            }
            else
            {
                // push or fail
                netPushes++;
                if (opcode == OP_0)
                {
                    data.resize(1);
                    data[0] = 0;
                    vSolutions.push_back(data);
                }
                else if (opcode >= OP_1 && opcode <= OP_16)
                {
                    data.resize(1);
                    data[0] = (opcode - OP_1) + 1;
                    vSolutions.push_back(data);
                }
                else if (opcode > 0 && opcode <= OP_PUSHDATA4 && data.size() > 0)
                {
                    vSolutions.push_back(data);
                }
                else
                    return false;
            }
        }
        else
            return false;
    }
    return netPushes == 0;
}

// this returns true if either there is nothing left and pc points at the end
// if there is data, it also returns all the values as byte vectors in a list of vectors
bool CScript::GetPushedData(CScript::const_iterator pc, std::vector<std::vector<unsigned char>>& vData) const
{
    vector<unsigned char> data;
    opcodetype opcode;
    std::vector<unsigned char> vch1 = std::vector<unsigned char>(1);

    vData.clear();

    while (pc < end())
    {
        if (GetOp(pc, opcode, data))
        {
            if (opcode == OP_0)
            {
                vch1[0] = 0;
                vData.push_back(vch1);
            }
            else if (opcode >= OP_1 && opcode <= OP_16)
            {
                vch1[0] = (opcode - OP_1) + 1;
                vData.push_back(vch1);
            }
            else if (opcode > 0 && opcode <= OP_PUSHDATA4 && data.size() > 0)
            {
                vData.push_back(data);
            }
            else
                return false;
        }
    }
    return vData.size() != 0;
}

// this returns true if either there is nothing left and pc points at the end
// if there is data, it also returns all the values as byte vectors in a list of vectors
bool CScript::GetOpretData(std::vector<std::vector<unsigned char>>& vData) const
{
    vector<unsigned char> data;
    opcodetype opcode;
    CScript::const_iterator pc = this->begin();

    if (GetOp(pc, opcode, data) && opcode == OP_RETURN)
    {
        return GetPushedData(pc, vData);
    }
    else return false;
}

bool CScript::IsPayToCryptoCondition(CScript *pCCSubScript, std::vector<std::vector<unsigned char>>& vParams) const
{
    const_iterator pc = begin();
    vector<unsigned char> firstParam;
    vector<unsigned char> data;
    opcodetype opcode;
    try
    {
        if (this->GetOp(pc, opcode, firstParam))
        {
            // Sha256 conditions are <76 bytes
            if (opcode > OP_0 && opcode < OP_PUSHDATA1)
            {
                if (this->GetOp(pc, opcode, data))
                {
                    if (opcode == OP_CHECKCRYPTOCONDITION)
                    {
                        const_iterator pcCCEnd = pc;
                        if (GetBalancedData(pc, vParams))
                        {
                            if (pCCSubScript)
                                *pCCSubScript = CScript(begin(), pcCCEnd);
                            vParams.push_back(firstParam);
                            return true;
                        }
                    }
                }
            }
        }
    }
    catch(...)
    {
    }
    return false;
}

bool CScript::IsPayToCryptoCondition(CScript *pCCSubScript) const
{
    std::vector<std::vector<unsigned char>> vParams;
    return IsPayToCryptoCondition(pCCSubScript, vParams);
}

bool CScript::IsPayToCryptoCondition() const
{
    return IsPayToCryptoCondition((CScript *)NULL);
}

extern uint160 ASSETCHAINS_CHAINID, VERUS_CHAINID;

bool CScript::IsInstantSpend() const
{
    COptCCParams p;
    bool isInstantSpend = false;

    if (IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
    {
        // instant spends can be spent from a coinbase before block maturity, but cannot carry any currency value
        if (p.evalCode == EVAL_EARNEDNOTARIZATION ||
            p.evalCode == EVAL_NOTARY_EVIDENCE ||
            p.evalCode == EVAL_FINALIZE_NOTARIZATION ||
            p.evalCode == EVAL_FINALIZE_EXPORT ||
            p.evalCode == EVAL_CROSSCHAIN_IMPORT ||
            p.evalCode == EVAL_CROSSCHAIN_EXPORT)
        {
            isInstantSpend = true;
        }
    }
    return isInstantSpend;
}

bool CScript::IsInstantSpendOrUnspendable() const
{
    COptCCParams p;
    bool isInstantSpend = false;
    if (IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
    {
        if (p.evalCode == EVAL_EARNEDNOTARIZATION ||
            p.evalCode == EVAL_NOTARY_EVIDENCE ||
            p.evalCode == EVAL_FINALIZE_NOTARIZATION ||
            p.evalCode == EVAL_FINALIZE_EXPORT ||
            p.evalCode == EVAL_CROSSCHAIN_IMPORT ||
            p.evalCode == EVAL_CROSSCHAIN_EXPORT ||
            p.evalCode == EVAL_FEE_POOL)
        {
            isInstantSpend = true;
        }
    }
    return isInstantSpend;
}

bool CScript::IsPayToCryptoCondition(COptCCParams &ccParams, bool doSizeCheck) const
{
    CScript subScript;
    std::vector<std::vector<unsigned char>> vParams;

    if (!size() || (doSizeCheck && size() > MAX_SCRIPT_SIZE))
    {
        return false;
    }

    if (IsPayToCryptoCondition(&subScript, vParams))
    {
        if (!vParams.empty())
        {
            ccParams = COptCCParams(vParams[0]);
            for (int i = 1; i < vParams.size(); i++)
            {
                ccParams.vData.push_back(vParams[i]);
            }
        }
        else
        {
            // make sure that we return it in a consistent and known state
            ccParams = COptCCParams();
        }
        return true;
    }
    ccParams = COptCCParams();
    return false;
}

bool CScript::IsPayToCryptoCondition(CScript *ccSubScript, std::vector<std::vector<unsigned char>> &vParams, COptCCParams &optParams) const
{
    if (IsPayToCryptoCondition(ccSubScript, vParams))
    {
        if (vParams.size() > 0)
        {
            optParams = COptCCParams(vParams[0]);
            return optParams.IsValid();
        }
    }
    return false;
}

bool CScript::IsPayToCryptoCondition(uint32_t *ecode) const
{
    CScript sub;
    std::vector<std::vector<unsigned char>> vParams;
    COptCCParams p;
    if (IsPayToCryptoCondition(&sub, vParams, p))
    {
        *ecode = p.evalCode;
        return true;
    }
    return false;
}

bool CScript::IsSpendableOutputType(const COptCCParams &p) const
{
    bool isSpendable = true;
    if (!p.IsValid())
    {
        return !IsOpReturn();
    }
    switch (p.evalCode)
    {
        case EVAL_CURRENCY_DEFINITION:
        case EVAL_NOTARY_EVIDENCE:
        case EVAL_EARNEDNOTARIZATION:
        case EVAL_ACCEPTEDNOTARIZATION:
        case EVAL_FINALIZE_NOTARIZATION:
        case EVAL_RESERVE_TRANSFER:
        case EVAL_IDENTITY_ADVANCEDRESERVATION:
        case EVAL_RESERVE_DEPOSIT:
        case EVAL_CROSSCHAIN_EXPORT:
        case EVAL_FINALIZE_EXPORT:
        case EVAL_CROSSCHAIN_IMPORT:
        case EVAL_IDENTITY_COMMITMENT:
        case EVAL_IDENTITY_PRIMARY:
        case EVAL_IDENTITY_REVOKE:
        case EVAL_IDENTITY_RECOVER:
        case EVAL_IDENTITY_RESERVATION:
        case EVAL_FEE_POOL:
        {
            isSpendable = false;
            break;
        }
    }
    return isSpendable;
}

bool CScript::IsSpendableOutputType() const
{
    COptCCParams p;
    if (IsPayToCryptoCondition(p))
    {
        return IsSpendableOutputType(p);
    }
    return !IsOpReturn();
}

CCurrencyValueMap CReserveTransfer::TotalCurrencyOut() const
{
    CCurrencyValueMap retVal;
    CAmount feeAmount = nFees;
    if (destination.HasGatewayLeg() && destination.fees)
    {
        feeAmount += destination.fees;
    }
    if (feeAmount)
    {
        if (feeCurrencyID.IsNull())
        {
            printf("%s: null fee currency ID\n", __func__);
            retVal.valueMap[ASSETCHAINS_CHAINID] = feeAmount;
        }
        else
        {
            retVal.valueMap[feeCurrencyID] = feeAmount;
        }
    }

    // mint or pre-allocate (which will be deprecated) don't count the primary amount as value until import
    if (!IsMint())
    {
        retVal += reserveValues;
    }
    return retVal;
}

CCurrencyValueMap CScript::ReserveOutValue(COptCCParams &p, bool spendableOnly) const
{
    CCurrencyValueMap retVal;

    // already validated above
    if (IsPayToCryptoCondition(p) && p.IsValid() && (!spendableOnly || IsSpendableOutputType(p)) && p.vData.size())
    {
        switch (p.evalCode)
        {
            case EVAL_RESERVE_OUTPUT:
            {
                CTokenOutput ro(p.vData[0]);
                if (ro.IsValid())
                {
                    retVal = ro.reserveValues;
                }
                break;
            }

            case EVAL_RESERVE_DEPOSIT:
            {
                CReserveDeposit rd(p.vData[0]);
                retVal = rd.reserveValues;
                retVal.valueMap.erase(ASSETCHAINS_CHAINID);
                break;
            }

            case EVAL_RESERVE_TRANSFER:
            {
                CReserveTransfer rt(p.vData[0]);
                retVal = rt.TotalCurrencyOut();
                retVal.valueMap.erase(ASSETCHAINS_CHAINID);
                break;
            }

            case EVAL_CROSSCHAIN_IMPORT:
            {
                CCrossChainImport cci(p.vData[0]);
                // reserve out amount when converting to reserve is 0, since the amount cannot be calculated in isolation as an input
                // if reserve in, we can consider the output the same reserve value as the input
                //retVal = cci.totalReserveOutMap;
                break;
            }

            case EVAL_IDENTITY_COMMITMENT:
            {
                // this can only have an advance commitment hash if the serialization data is larger than the first hash
                // if so, we attempt to get both a hash commitment and a token output from the data. the only time this will be
                // larger in a way that matters is on testnet for now.
                CCommitmentHash ch(p.vData[0]);

                if (ch.IsValid())
                {
                    retVal = ch.reserveValues;
                }
            }
        }
    }
    return retVal;
}

CCurrencyValueMap CScript::ReserveOutValue() const
{
    COptCCParams p;
    return ReserveOutValue(p);
}

bool CScript::MayAcceptCryptoCondition() const
{
    // Get the type mask of the condition
    const_iterator pc = this->begin();
    vector<unsigned char> data;
    opcodetype opcode;
    if (!this->GetOp(pc, opcode, data)) return false;
    if (!(opcode > OP_0 && opcode < OP_PUSHDATA1)) return false;
    CC *cond = cc_readConditionBinary(data.data(), data.size());
    if (!cond) return false;

    uint32_t eCode;
    if (!IsPayToCryptoCondition(&eCode))
    {
        return false;
    }

    bool out = IsSupportedCryptoCondition(cond, eCode);

    cc_free(cond);
    return out;
}

// also checks if the eval code is consistent
bool CScript::MayAcceptCryptoCondition(int evalCode) const
{
    // Get the type mask of the condition
    const_iterator pc = this->begin();
    vector<unsigned char> data;
    opcodetype opcode;
    if (!this->GetOp(pc, opcode, data)) return false;
    if (!(opcode > OP_0 && opcode < OP_PUSHDATA1)) return false;
    CC *cond = cc_readConditionBinary(data.data(), data.size());
    if (!cond) return false;

    bool out = IsSupportedCryptoCondition(cond, evalCode);

    cc_free(cond);
    return out;
}

bool CScript::IsCoinImport() const
{
    const_iterator pc = this->begin();
    vector<unsigned char> data;
    opcodetype opcode;
    if (this->GetOp(pc, opcode, data))
        if (opcode > OP_0 && opcode <= OP_PUSHDATA4)
            return data.begin()[0] == EVAL_IMPORTCOIN;
    return false;
}

bool CScript::IsPushOnly() const
{
    const_iterator pc = begin();
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            return false;
        // Note that IsPushOnly() *does* consider OP_RESERVED to be a
        // push-type opcode, however execution of OP_RESERVED fails, so
        // it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
        // the P2SH special validation code being executed.
        if (opcode > OP_16)
            return false;
    }
    return true;
}

// if the front of the script has check lock time verify. this is a fairly simple check.
// accepts NULL as parameter if unlockTime is not needed.
bool CScript::IsCheckLockTimeVerify(int64_t *unlockTime) const
{
    opcodetype op;
    std::vector<unsigned char> unlockTimeParam = std::vector<unsigned char>();
    CScript::const_iterator it = this->begin();

    if (this->GetOp2(it, op, &unlockTimeParam))
    {
        if (unlockTimeParam.size() >= 0 && unlockTimeParam.size() < 6 &&
            this->size() > (unlockTimeParam.size() + 1) &&
            (*this)[unlockTimeParam.size() + 1] == OP_CHECKLOCKTIMEVERIFY)
        {
            int i = unlockTimeParam.size() - 1;
            for (*unlockTime = 0; i >= 0; i--)
            {
                *unlockTime <<= 8;
                *unlockTime |= *((unsigned char *)unlockTimeParam.data() + i);
            }
            return true;
        }
    }
    return false;
}

bool CScript::IsCheckLockTimeVerify() const
{
    int64_t ult;
    return this->IsCheckLockTimeVerify(&ult);
}

std::string CScript::ToString() const
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    const_iterator pc = begin();
    while (pc < end())
    {
        if (!str.empty())
            str += " ";
        if (!GetOp(pc, opcode, vch))
        {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4)
            str += ValueString(vch);
        else
            str += GetOpName(opcode);
    }
    return str;
}

CScript::ScriptType CScript::GetType() const
{
    if (this->IsPayToPublicKeyHash())
    {
        return CScript::P2PKH;
    }
    else if (this->IsPayToScriptHash())
    {
        return CScript::P2SH;
    }
    else if (this->IsPayToPublicKey())
    {
        return CScript::P2PK;
    }
    else if (this->IsPayToCryptoCondition())
    {
        return CScript::P2CC;
    }

    // We don't know this script type
    return CScript::UNKNOWN;
}

uint160 CScript::AddressHash() const
{
    uint160 addressHash;
    COptCCParams p;
    if (this->IsPayToScriptHash()) {
        addressHash = uint160(std::vector<unsigned char>(this->begin()+2, this->begin()+22));
    }
    else if (this->IsPayToPublicKeyHash())
    {
        addressHash = uint160(std::vector<unsigned char>(this->begin()+3, this->begin()+23));
    }
    else if (this->IsPayToPublicKey())
    {
        std::vector<unsigned char> hashBytes(this->begin()+1, this->begin()+34);
        addressHash = Hash160(hashBytes);
    }
    else if (this->IsPayToCryptoCondition(p)) {
        if (p.IsValid() && (p.vKeys.size()))
        {
            COptCCParams master;
            if (p.version >= p.VERSION_V3 && p.vData.size() > 1 && (master = COptCCParams(p.vData.back())).IsValid() && master.vKeys.size())
            {
                addressHash = GetDestinationID(master.vKeys[0]);
            }
            else
            {
                addressHash = GetDestinationID(p.vKeys[0]);
            }
        }
        else
        {
            vector<unsigned char> hashBytes(this->begin(), this->end());
            addressHash = Hash160(hashBytes);
        }
    }
    return addressHash;
}

bool COptCCParams::IsInstantSpendOrUnspendable() const
{
    bool isInstantSpend = false;
    if (version >= VERSION_V3)
    {
        if (evalCode == EVAL_EARNEDNOTARIZATION ||
            evalCode == EVAL_NOTARY_EVIDENCE ||
            evalCode == EVAL_FINALIZE_NOTARIZATION ||
            evalCode == EVAL_FINALIZE_EXPORT ||
            evalCode == EVAL_CROSSCHAIN_IMPORT ||
            evalCode == EVAL_CROSSCHAIN_EXPORT ||
            evalCode == EVAL_FEE_POOL)
        {
            isInstantSpend = true;
        }
    }
    return isInstantSpend;
}

std::set<CIndexID> COptCCParams::GetIndexKeys() const
{
    std::set<CIndexID> destinations;
    switch(evalCode)
    {
        case EVAL_CURRENCY_DEFINITION:
        {
            CCurrencyDefinition definition;

            if (vData.size() && (definition = CCurrencyDefinition(vData[0])).IsValid())
            {
                uint160 currencyID = definition.GetID();
                destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(currencyID, CCurrencyDefinition::CurrencyDefinitionKey())));
                destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(definition.systemID, CCurrencyDefinition::CurrencySystemKey())));

                // gateways are indexed by the current chain and the gateway key as a starting point to discover all gateway
                // currencies
                if (definition.IsGateway() && definition.gatewayID == currencyID)
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::CurrencyGatewayKey())));
                }
                if (definition.IsPBaaSChain())
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::PBaaSChainKey())));
                }
                if (!definition.gatewayID.IsNull() || definition.systemID != ASSETCHAINS_CHAINID)
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::ExternalCurrencyKey())));
                }
                if (definition.launchSystemID == ASSETCHAINS_CHAINID &&
                    !(definition.IsToken() &&
                      !definition.IsFractional() &&
                      definition.nativeCurrencyID.IsValid() &&
                      definition.GetTotalPreallocation() == 0 &&
                      (definition.nativeCurrencyID.TypeNoFlags() == CTransferDestination::DEST_ETH ||
                       definition.nativeCurrencyID.TypeNoFlags() == CTransferDestination::DEST_ETHNFT) &&
                      definition.systemID != ASSETCHAINS_CHAINID))
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::CurrencyLaunchKey())));
                }
            }
            break;
        }

        case EVAL_NOTARY_EVIDENCE:
        {
            CNotaryEvidence evidence;
            if (vData.size() && (evidence = CNotaryEvidence(vData[0])).IsValid())
            {
                switch (evidence.type)
                {
                    // notary signature
                    case CNotaryEvidence::TYPE_NOTARY_EVIDENCE:
                    {
                        destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(CNotaryEvidence::NotarySignatureKey(),
                                                                                        evidence.output.hash,
                                                                                        evidence.output.n)));
                        break;
                    }

                    // import proof
                    case CNotaryEvidence::TYPE_IMPORT_PROOF:
                    {
                        break;
                    }

                    // data broken into multiple parts
                    case CNotaryEvidence::TYPE_MULTIPART_DATA:
                    {
                        destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(CNotaryEvidence::NotarySignatureKey(),
                                                                                        evidence.output.hash,
                                                                                        evidence.output.n)));
                        break;
                    }
                }
            }
            break;
        }

        case EVAL_EARNEDNOTARIZATION:
        case EVAL_ACCEPTEDNOTARIZATION:
        {
            CPBaaSNotarization notarization;

            if (vData.size() && (notarization = CPBaaSNotarization(vData[0])).IsValid())
            {
                // always index a notarization, without regard to its status
                destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(notarization.currencyID, CPBaaSNotarization::NotaryNotarizationKey())));
                if (evalCode == EVAL_EARNEDNOTARIZATION ||
                    (notarization.proofRoots.count(ASSETCHAINS_CHAINID) &&
                     notarization.currencyID != ASSETCHAINS_CHAINID &&
                     (notarization.proofRoots.count(notarization.currencyID) ||
                      (notarization.IsPreLaunch() &&
                       notarization.IsLaunchConfirmed() &&
                       notarization.currencyState.IsLaunchClear()))))
                {
                    CPBaaSNotarization checkNotarization = notarization;
                    if (checkNotarization.SetMirror(false))
                    {
                        CNativeHashWriter hw;
                        hw << checkNotarization;
                        uint256 objHash = hw.GetHash();
                        destinations.insert(CIndexID(
                            CCrossChainRPCData::GetConditionID(notarization.currencyID, CPBaaSNotarization::EarnedNotarizationKey(), objHash)
                        ));
                        // index forward links for earned notarizations only
                        if (evalCode == EVAL_EARNEDNOTARIZATION)
                        {
                            destinations.insert(CIndexID(
                                CCrossChainRPCData::GetConditionID(CPBaaSNotarization::PriorNotarizationKey(), notarization.prevNotarization.hash, notarization.prevNotarization.n)
                            ));
                        }
                    }
                }

                // index all pre-launch notarizations as pre-launch, then one final index for launchclear of
                // either launch or refund, finally, we create one last index entry for launchcompletemarker

                // if this is the first launch clear notarization, index as confirmed or refunding
                if (notarization.IsDefinitionNotarization())
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(notarization.currencyID, CPBaaSNotarization::DefinitionNotarizationKey())));
                }
                if (notarization.IsPreLaunch())
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CPBaaSNotarization::LaunchPrelaunchKey())));
                    if (notarization.currencyState.IsLaunchClear())
                    {
                        destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(notarization.currencyID, CPBaaSNotarization::LaunchNotarizationKey())));
                        if (notarization.IsRefunding())
                        {
                            destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CPBaaSNotarization::LaunchRefundKey())));
                        }
                        else
                        {
                            destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CPBaaSNotarization::LaunchConfirmKey())));
                        }
                    }
                }
                else if (notarization.IsBlockOneNotarization() &&
                         (notarization.currencyState.IsLaunchClear() ||
                          notarization.IsLaunchConfirmed() ||
                          notarization.currencyID == ConnectedChains.ThisChain().launchSystemID))
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(notarization.currencyID, CPBaaSNotarization::LaunchNotarizationKey())));
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CPBaaSNotarization::LaunchConfirmKey())));
                }
                else if (notarization.currencyState.IsLaunchCompleteMarker())
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(notarization.currencyID, CPBaaSNotarization::LaunchCompleteKey())));
                }

                // determine if the new notarization is automatically final, and if so, store a finalization index key as well
                CCoinbaseCurrencyState &curState = notarization.currencyState;
                if (curState.IsValid() &&
                    ((evalCode == EVAL_ACCEPTEDNOTARIZATION && notarization.IsSameChain()) ||
                     notarization.IsPreLaunch() ||
                     notarization.IsDefinitionNotarization() ||
                     notarization.IsBlockOneNotarization()))
                {
                    uint160 finalizeNotarizationKey = CCrossChainRPCData::GetConditionID(notarization.currencyID, CObjectFinalization::ObjectFinalizationNotarizationKey());
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(finalizeNotarizationKey, CObjectFinalization::ObjectFinalizationConfirmedKey())));
                }
                // determine if this newly notarized currency can be used as a currency converter, and if so, add an index destination, so this
                // currency can be quickly found and used
                int32_t nativeReserveIdx;
                std::map<uint160, int32_t> reserveIdxMap;
                if (curState.IsFractional() &&
                    curState.IsLaunchConfirmed() &&
                    (reserveIdxMap = curState.GetReserveMap()).count(ASSETCHAINS_CHAINID) &&
                    curState.weights[nativeReserveIdx = reserveIdxMap[ASSETCHAINS_CHAINID]] > curState.IndexConverterReserveRatio() &&
                    curState.reserves[nativeReserveIdx] > curState.IndexConverterReserveMinimum())
                {
                    // go through all currencies and add an index entry for each
                    // when looking for a currency converter, we will look through all indexed options
                    // for the best conversion rate from a source currency to the destination
                    for (auto &one : reserveIdxMap)
                    {
                        destinations.insert(CIndexID(curState.IndexConverterKey(one.first)));
                    }
                }
            }
            break;
        }

        case EVAL_FINALIZE_NOTARIZATION:
        {
            CObjectFinalization finalization;

            if (vData.size() && (finalization = CObjectFinalization(vData[0])).IsValid())
            {
                uint160 finalizationNotarizationID = CCrossChainRPCData::GetConditionID(finalization.currencyID, CObjectFinalization::ObjectFinalizationNotarizationKey());
                // we care about confirmed and pending. no index for rejected

                // if this is a more powerful challenge than the confirmation
                // figuring this out quickly enables efficient decision to not confirm
                if (finalization.IsChallenge())
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(CObjectFinalization::FinalizationIsChallengeKey(), finalization.output.hash, finalization.output.n)));
                    if (finalization.IsMorePowerful())
                    {
                        destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(CObjectFinalization::FinalizationMorePowerfulKey(), finalization.output.hash, finalization.output.n)));
                    }
                    if (finalization.Invalidates())
                    {
                        destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(CObjectFinalization::FinalizationInvalidatesKey(), finalization.output.hash, finalization.output.n)));
                    }
                }

                if (finalization.IsConfirmed())
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(finalizationNotarizationID, CObjectFinalization::ObjectFinalizationConfirmedKey())));
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(CObjectFinalization::ObjectFinalizationFinalizedKey(), finalization.output.hash, finalization.output.n)));
                }
                else if (finalization.IsPending())
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(finalizationNotarizationID, CObjectFinalization::ObjectFinalizationPendingKey())));
                    if (!finalization.output.hash.IsNull())
                    {
                        destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(CObjectFinalization::ObjectFinalizationPendingKey(), finalization.output.hash, finalization.output.n)));
                    }
                }
                else if (finalization.IsRejected())
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(finalizationNotarizationID, CObjectFinalization::ObjectFinalizationRejectedKey())));
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(CObjectFinalization::ObjectFinalizationFinalizedKey(), finalization.output.hash, finalization.output.n)));
                }
            }
            break;
        }

        case EVAL_FINALIZE_EXPORT:
        {
            // this is used to determine within a blockchain, what work on local imports is available to do and earn from
            // finalization exports only exist on exports destined for the current chain on or after a currency start block
            // the first export finalization we expect on a currency is when its launch can be confirmed or rejected and
            // refunded.
            CObjectFinalization finalization;

            if (vData.size() && (finalization = CObjectFinalization(vData[0])).IsValid())
            {
                destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(finalization.currencyID, CObjectFinalization::ObjectFinalizationExportKey())));
            }
            break;
        }

        case EVAL_CURRENCYSTATE:
        {
            CCoinbaseCurrencyState cbcs;

            if (vData.size() && (cbcs = CCoinbaseCurrencyState(vData[0])).IsValid())
            {
                destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(cbcs.GetID(), cbcs.CurrencyStateKey())));
            }
            break;
        }

        case EVAL_RESERVE_TRANSFER:
        {
            CReserveTransfer rt;

            if (vData.size() && (rt = CReserveTransfer(vData[0])).IsValid() && !rt.IsArbitrageOnly())
            {
                destinations.insert(CIndexID(rt.ReserveTransferKey()));
            }

            // if this is a currency export, we return a currency export key to mark that this currency is
            // now committed to be exported when this block of transfers is exported to the target chain
            if (rt.IsCurrencyExport() &&
                rt.flags & rt.CROSS_SYSTEM &&
                !rt.destSystemID.IsNull() &&
                rt.destination.TypeNoFlags() == rt.destination.DEST_REGISTERCURRENCY)
            {
                destinations.insert(rt.destination.CurrencyDefinitionExportKeyToSystem(rt.destSystemID));
                destinations.insert(rt.destination.GetBoundCurrencyDefinitionExportKey(rt.destSystemID));
            }
            break;
        }

        case EVAL_RESERVE_DEPOSIT:
        {
            CReserveDeposit rd;

            if (vData.size() && (rd = CReserveDeposit(vData[0])).IsValid())
            {
                destinations.insert(rd.ReserveDepositIndexKey());
            }
            break;
        }

        case EVAL_CROSSCHAIN_EXPORT:
        {
            CCrossChainExport ccx;

            if (vData.size() && (ccx = CCrossChainExport(vData[0])).IsValid())
            {
                if (ccx.sourceSystemID != ASSETCHAINS_CHAINID)
                {
                    // if cross-chain supplemental, index any currency exports in the reserve transfers
                    // as being available for export to the source system
                    if (ccx.reserveTransfers.size())
                    {
                        for (auto &oneRT : ccx.reserveTransfers)
                        {
                            if (oneRT.IsCurrencyExport())
                            {
                                // this provides a way to find all exports of a specific currency or generally all exports
                                // that's why it uses sourceSystemID, not dest
                                destinations.insert(CTransferDestination::GetBoundCurrencyDefinitionExportKey(ccx.sourceSystemID, oneRT.FirstCurrency()));
                                destinations.insert(CTransferDestination::CurrencyDefinitionExportKeyToSystem(ccx.sourceSystemID));
                            }
                        }
                    }
                }
                else
                {
                    // when looking for a currency, not system, we don't need to record system thread exports
                    if (!ccx.IsSystemThreadExport())
                    {
                        destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(ccx.destCurrencyID, ccx.CurrencyExportKey())));
                    }
                    // we will find one of these either in its own exports to another system or after any export to a currency
                    // on that system. we record this for all system exports, whether system thread or not
                    if (ccx.destCurrencyID == ccx.destSystemID || ccx.IsSystemThreadExport())
                    {
                        destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(ccx.destSystemID, ccx.SystemExportKey())));
                    }
                }
            }
            break;
        }

        case EVAL_CROSSCHAIN_IMPORT:
        {
            CCrossChainImport cci;

            if (vData.size() && (cci = CCrossChainImport(vData[0])).IsValid())
            {
                // if source is same as import currency, this is a system import
                // thread. otherwise, not
                if (cci.sourceSystemID == cci.importCurrencyID)
                {
                    destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(cci.sourceSystemID, cci.CurrencySystemImportKey())));
                }
                destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(cci.importCurrencyID, cci.CurrencyImportKey())));
                destinations.insert(CIndexID(cci.CurrencyImportFromSystemKey(cci.sourceSystemID, cci.importCurrencyID)));
            }
            break;
        }

        case EVAL_IDENTITY_PRIMARY:
        {
            CIdentity identity;
            if (vData.size() && (identity = CIdentity(vData[0])).IsValid())
            {
                destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(identity.GetID(), evalCode)));

                // index content multimap entries. also index type definitions separately for direct, non-scoped queries
                for (auto defIT = identity.contentMultiMap.begin(); defIT != identity.contentMultiMap.end(); defIT++)
                {
                    destinations.insert(CCrossChainRPCData::GetConditionID(CVDXF_Data::MultiMapKey(), CCrossChainRPCData::GetConditionID(defIT->first, identity.GetID())));

                    if (LogAcceptCategory("oracles"))
                    {
                        LogPrintf("%s: defIT->first: %s, identity.GetID(): %s, lookupKey: %s\n", __func__,
                                    EncodeDestination(CIdentityID(defIT->first)).c_str(),
                                    EncodeDestination(identity.GetID()).c_str(),
                                    EncodeDestination(CIdentityID(CCrossChainRPCData::GetConditionID(CVDXF_Data::MultiMapKey(), CCrossChainRPCData::GetConditionID(defIT->first, identity.GetID())))).c_str());
                    }

                    if (defIT->first == CVDXF_Data::TypeDefinitionKey())
                    {
                        CDataStream ss(defIT->second, SER_DISK, PROTOCOL_VERSION);
                        std::string typeDefKeyName;
                        try
                        {
                            uint32_t Version;
                            uint32_t Size;
                            ss >> VARINT(Version);
                            ss >> VARINT(Size);
                            if (Version == 1 && Size == ss.size())
                            {
                                ss >> LIMITED_STRING(typeDefKeyName, MAX_SCRIPT_ELEMENT_SIZE_IDENTITY);
                                if (typeDefKeyName.size() > Size - 1)
                                {
                                    typeDefKeyName.clear();
                                }
                            }
                        }
                        catch (...)
                        {
                            typeDefKeyName.clear();
                        }
                        uint160 nameSpace = identity.GetID();
                        if (typeDefKeyName.size())
                        {
                            uint160 newTypeKey = CVDXF::GetDataKey(typeDefKeyName, nameSpace);
                            if (!newTypeKey.IsNull() &&
                                nameSpace == identity.GetID())
                            {
                                destinations.insert(CCrossChainRPCData::GetConditionID(CVDXF_Data::TypeDefinitionKey(), newTypeKey));
                            }
                        }
                    }
                }

                // if we are maintaining an ID index, add keys for primary addresses, revocation, and recovery
                if (fIdIndex)
                {
                    for (auto &oneDest : identity.primaryAddresses)
                    {
                        destinations.insert(identity.IdentityPrimaryAddressKey(oneDest));
                    }
                    destinations.insert(identity.IdentityRecoveryKey(identity.recoveryAuthority));
                    destinations.insert(identity.IdentityRevocationKey(identity.revocationAuthority));
                    destinations.insert(identity.IdentityParentKey(identity.parent));
                    destinations.insert(identity.IdentitySystemKey(identity.systemID));
                }
            }
            break;
        }

        case EVAL_IDENTITY_ADVANCEDRESERVATION:
        {
            CAdvancedNameReservation nameRes;
            if (vData.size() && (nameRes = CAdvancedNameReservation(vData[0])).IsValid())
            {
                uint160 parent = nameRes.parent;
                uint160 ourID = CIdentity::GetID(nameRes.name, parent);
                destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(ourID, evalCode)));
            }
            break;
        }

        case EVAL_IDENTITY_RESERVATION:
        {
            CNameReservation nameRes;
            if (vData.size() && (nameRes = CNameReservation(vData[0])).IsValid())
            {
                uint160 parent = ASSETCHAINS_CHAINID;
                uint160 ourID = CIdentity::GetID(nameRes.name, parent);
                destinations.insert(CIndexID(CCrossChainRPCData::GetConditionID(ourID, evalCode)));
            }
            break;
        }
    }
    return destinations;
}

std::map<uint160, uint32_t> COptCCParams::GetIndexHeightOffsets(uint32_t height) const
{
    // export finalization index keys, which are used when creating imports to determine
    // what work needs to be done, are offset to have a height of the start block, ensuring
    // that they are not considered for import until the start block is reached
    std::map<uint160, uint32_t> offsets;
    CCurrencyDefinition curDef;
    if (evalCode == EVAL_CURRENCY_DEFINITION &&
        vData.size() &&
        (curDef = CCurrencyDefinition(vData[0])).IsValid() &&
        curDef.launchSystemID == ASSETCHAINS_CHAINID &&
        height <= curDef.startBlock)
    {
        offsets.insert(make_pair(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::CurrencyLaunchKey()),
                                 (uint32_t)curDef.startBlock));
    }
    return offsets;
}

bool IsIndexCollision(const std::set<CIndexID> &indexKeys, const CTxDestination &dest)
{
    return ((dest.which() == COptCCParams::ADDRTYPE_PK || dest.which() == COptCCParams::ADDRTYPE_PKH) && indexKeys.count(GetDestinationID(dest)));
}

std::vector<CTxDestination> COptCCParams::GetDestinations() const
{
    std::set<CIndexID> indexKeys = GetIndexKeys();
    std::vector<CTxDestination> destinations;
    destinations.insert(destinations.begin(), indexKeys.begin(), indexKeys.end());
    if (IsValid() && (vKeys.size()))
    {
        COptCCParams master;
        if (version >= VERSION_V3 && vData.size() > 1 && (master = COptCCParams(vData.back())).IsValid())
        {
            std::set<CTxDestination> dests;
            for (auto dest : master.vKeys)
            {
                // index keys cannot be explicit and are not put into the index if so
                if (dest.which() != COptCCParams::ADDRTYPE_INDEX && !IsIndexCollision(indexKeys, dest))
                {
                    dests.insert(dest);
                }
            }
            if (vKeys[0].which() != COptCCParams::ADDRTYPE_INDEX && !IsIndexCollision(indexKeys, vKeys[0]))
            {
                dests.insert(vKeys[0]);
            }
            for (int i = 1; i < vKeys.size(); i++)
            {
                if (vKeys[i].which() == COptCCParams::ADDRTYPE_ID)
                {
                    dests.insert(vKeys[i]);
                }
            }
            for (int i = 1; i < (int)(vData.size() - 1); i++)
            {
                COptCCParams oneP(vData[i]);
                if (oneP.IsValid())
                {
                    for (auto dest : oneP.vKeys)
                    {
                        if (dest.which() == COptCCParams::ADDRTYPE_ID)
                        {
                            dests.insert(dest);
                        }
                    }
                }
            }
            for (auto dest : dests)
            {
                destinations.push_back(dest);
            }
        }
        else
        {
            if (vKeys[0].which() != COptCCParams::ADDRTYPE_INDEX)
            {
                destinations.push_back(vKeys[0]);
            }
        }
    }
    return destinations;
}

bool COptCCParams::IsValid(bool strict, uint32_t nHeight) const
{
    // verify that the output is spendable as a normal smart transaction output with all known combinations and no others
    // that may not be spendable
    uint32_t solutionVer = CConstVerusSolutionVector::GetVersionByHeight(nHeight);
    bool isPBaaS = solutionVer >= CActivationHeight::ACTIVATE_PBAAS;
    bool isVault = solutionVer >= CActivationHeight::ACTIVATE_VERUSVAULT;

    bool versionInRange = (!isPBaaS && (version == VERSION_V1 || version == VERSION_V2 || version == VERSION_V3)) || (isPBaaS && version == VERSION_V3);
    if (!((isPBaaS || isVault) && strict) ||
        !versionInRange)
    {
        return versionInRange;
    }
    else
    {
        if (m > n ||
            n != vKeys.size())
        {
            return false;
        }
        for (auto &oneDest : vKeys)
        {
            if (oneDest.which() != ADDRTYPE_ID &&
                oneDest.which() != ADDRTYPE_PK &&
                oneDest.which() != ADDRTYPE_PKH)
            {
                return false;
            }
        }

        if (vData.size() > 1)
        {
            // back must be a valid master, and if we have more than 2, each must be a valid condition
            // no subconditions can contain objects or funds in their scripts
            COptCCParams master = COptCCParams(vData.back());
            if (!master.IsValid() ||
                !(master.evalCode == EVAL_NONE || master.evalCode == EVAL_STAKEGUARD) ||
                master.m > master.n ||
                master.n > 4 ||
                (master.n != (vData.size() - 1) &&
                 !(vData.size() == 2 &&
                   master.n == std::max((int)master.vKeys.size(), 1))) ||
                master.vData.size())
            {
                return false;
            }
            for (int i = 1; i < (vData.size() - 1); i++)
            {
                COptCCParams oneParam(vData[i]);
                if (!oneParam.IsValid(true, nHeight))
                {
                    return false;
                }
                if (oneParam.m > oneParam.n ||
                    oneParam.n > oneParam.vKeys.size())
                {
                    return false;
                }
                switch (oneParam.evalCode)
                {
                    case EVAL_STAKEGUARD:
                    {
                        // alternate spend
                        // spendable to public key
                        if (vData.size() != 3 ||
                            oneParam.vData.size() ||
                            oneParam.vKeys.size() != 1)
                        {
                            return false;
                        }
                        break;
                    }
                    case EVAL_NONE:
                    case EVAL_IDENTITY_RECOVER:
                    case EVAL_IDENTITY_REVOKE:
                    {
                        if (oneParam.vData.size())
                        {
                            return false;
                        }
                        break;
                    }
                    case EVAL_NOTARY_EVIDENCE:
                    {
                        if (oneParam.vData.size() != 1)
                        {
                            return false;
                        }
                        CNotaryEvidence evidence(vData[0]);
                        if (!evidence.IsValid())
                        {
                            return false;
                        }
                        break;
                    }
                    default:
                    {
                        return false;
                    }
                }
                for (auto &oneDest : vKeys)
                {
                    if (oneDest.which() != ADDRTYPE_ID &&
                        oneDest.which() != ADDRTYPE_PK &&
                        oneDest.which() != ADDRTYPE_PKH)
                    {
                        return false;
                    }
                }
            }
            return true;
        }
        else
        {
            switch (evalCode)
            {
                case EVAL_STAKEGUARD:
                {
                    if (vData.size() ||
                        vKeys.size() != 1)
                    {
                        return false;
                    }
                    CCcontract_info CC;
                    CCcontract_info *cp;

                    cp = CCinit(&CC, evalCode);
                    uint160 evalPKH = CPubKey(ParseHex(CC.CChexstr)).GetID();

                    if ((vKeys[0].which() == ADDRTYPE_PK || vKeys[0].which() == ADDRTYPE_PKH) && GetDestinationID(vKeys[0]) == evalPKH)
                    {
                        return true;
                    }
                    return false;
                }
                case EVAL_NONE:
                {
                    if (vData.size() == 1)
                    {
                        COptCCParams master = COptCCParams(vData.back());
                        if (!master.IsValid() ||
                            master.evalCode != EVAL_NONE)
                        {
                            return false;
                        }
                    }
                    return true;
                }
                case EVAL_IDENTITY_RECOVER:
                case EVAL_IDENTITY_REVOKE:
                {
                    if (vData.size())
                    {
                        return false;
                    }
                    return true;
                }
                case EVAL_NOTARY_EVIDENCE:
                {
                    if (vData.size() != 1)
                    {
                        return false;
                    }
                    CNotaryEvidence evidence(vData[0]);
                    if (!evidence.IsValid())
                    {
                        return false;
                    }
                    return true;
                }
            }
        }
    }
    return false;
}

bool COptCCParams::IsEvalPKOut() const
{
    if (evalCode > EVAL_LAST)
    {
        return false;
    }
    CCcontract_info CC;
    CCcontract_info *cp;

    cp = CCinit(&CC, evalCode);
    uint160 evalPKH = CPubKey(ParseHex(CC.CChexstr)).GetID();

    COptCCParams master;
    if (version >= VERSION_V3 &&
        vData.size() == 2 &&
        (master = COptCCParams(vData.back())).IsValid() &&
        master.evalCode == EVAL_NONE &&
        master.m == 1)
    {
        for (auto &oneKey : vKeys)
        {
            if ((oneKey.which() == ADDRTYPE_PK || oneKey.which() == ADDRTYPE_PKH) && GetDestinationID(oneKey) == evalPKH)
            {
                return true;
            }
        }
    }
    return false;
}

std::vector<CTxDestination> CScript::GetDestinations() const
{
    std::vector<CTxDestination> destinations;
    COptCCParams p;
    if (this->IsPayToCryptoCondition(p))
    {
        if (p.IsValid())
        {
            destinations = p.GetDestinations();
        }
        else
        {
            vector<unsigned char> hashBytes(this->begin(), this->end());
            destinations.push_back(CKeyID(Hash160(hashBytes)));
        }
    }
    else if (this->IsPayToScriptHash()) {
        destinations.push_back(CScriptID(uint160(std::vector<unsigned char>(this->begin()+2, this->begin()+22))));
    }
    else if (this->IsPayToPublicKeyHash())
    {
        destinations.push_back(CKeyID(uint160(std::vector<unsigned char>(this->begin()+3, this->begin()+23))));
    }
    else if (this->IsPayToPublicKey())
    {
        std::vector<unsigned char> hashBytes(this->begin()+1, this->begin()+34);
        destinations.push_back(CPubKey(hashBytes));
    }
    return destinations;
}

uint160 GetNameID(const std::string &Name, const uint160 &parent)
{
    uint160 writeable = parent;
    return CIdentity::GetID(Name, writeable);
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

CCurrencyValueMap::CCurrencyValueMap(const std::vector<uint160> &currencyIDs, const std::vector<CAmount> &amounts)
{
    int commonNum = currencyIDs.size() >= amounts.size() ? amounts.size() : currencyIDs.size();
    for (int i = 0; i < commonNum; i++)
    {
        valueMap[currencyIDs[i]] = amounts[i];
    }
}

bool operator<(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    // to be less than means, in this order:
    // 1. To have fewer non-zero currencies.
    // 2. If not fewer currencies, all present currencies must be less in a than b
    if (!a.valueMap.size() && !b.valueMap.size())
    {
        return false;
    }

    bool isaltb = false;
    std::set<uint160> checked;

    // ensure that we are smaller than all those present in b
    for (auto &oneVal : b.valueMap)
    {
        checked.insert(oneVal.first);
        if (oneVal.second)
        {
            auto it = a.valueMap.find(oneVal.first);

            // negative is less than not present, which is equivalent to 0
            if ((it == a.valueMap.end() && oneVal.second > 0) || (it != a.valueMap.end() && it->second < oneVal.second))
            {
                isaltb = true;
            }
        }
    }
    return isaltb;
}

bool LegacyLT(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    // to be less than means, in this order:
    // 1. To have fewer non-zero currencies.
    // 2. If not fewer currencies, all present currencies must be less in a than b
    if (!a.valueMap.size() && !b.valueMap.size())
    {
        return false;
    }

    bool isaltb = false;
    std::set<uint160> checked;

    // ensure that we are smaller than all those present in b
    for (auto &oneVal : b.valueMap)
    {
        checked.insert(oneVal.first);
        if (oneVal.second)
        {
            auto it = a.valueMap.find(oneVal.first);

            // negative is less than not present, which is equivalent to 0
            if ((it == a.valueMap.end() && oneVal.second > 0) || (it != a.valueMap.end() && it->second < oneVal.second))
            {
                isaltb = true;
            }
        }
    }

    // ensure that for all the currencies we have, b does not have less or equal
    for (auto &oneVal : a.valueMap)
    {
        if (!checked.count(oneVal.first) && oneVal.second)
        {
            auto it = b.valueMap.find(oneVal.first);

            if ((it == b.valueMap.end() && oneVal.second > 0) || (it != b.valueMap.end() && it->second < oneVal.second))
            {
                isaltb = false;
            }
        }
    }
    return isaltb;
}

bool operator>(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    return b < a;
}

bool operator==(const CCurrencyValueMap& _a, const CCurrencyValueMap& _b)
{
    CCurrencyValueMap a = _a.CanonicalMap(), b = _b.CanonicalMap();
    if (a.valueMap.size() != b.valueMap.size())
    {
        return false;
    }

    bool isaeqb = true;
    for (auto &oneVal : a.valueMap)
    {
        auto it = b.valueMap.find(oneVal.first);
        if (it == b.valueMap.end() || it->second != oneVal.second)
        {
            isaeqb = false;
            break;
        }
    }
    return isaeqb;
}

bool operator!=(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    return !(a == b);
}

bool operator<=(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    // to be less or equal to than means, in this order:
    // 1. To have fewer non-zero or both zero currencies.
    // 2. If not fewer or both zero currencies, all present currencies must be less or equal to in a with respect to b
    if (!a.valueMap.size() && !b.valueMap.size())
    {
        return true;
    }

    bool isalteb = false;

    // ensure that we are smaller than all those present in b
    for (auto &oneVal : b.valueMap)
    {
        if (oneVal.second)
        {
            auto it = a.valueMap.find(oneVal.first);

            if ((it == a.valueMap.end() && oneVal.second >= 0) || (it != a.valueMap.end() && it->second <= oneVal.second))
            {
                isalteb = true;
            }
        }
    }

    // ensure that for all the currencies we have, b has equal or more
    for (auto &oneVal : a.valueMap)
    {
        if (oneVal.second)
        {
            auto it = b.valueMap.find(oneVal.first);

            if ((it == b.valueMap.end() && oneVal.second > 0) || (it != b.valueMap.end() && it->second < oneVal.second))
            {
                isalteb = false;
            }
        }
    }
    return isalteb;
}

bool operator>=(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    return b <= a;
}

CCurrencyValueMap operator+(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    CCurrencyValueMap retVal = a;
    if (a.valueMap.size() || b.valueMap.size())
    {
        for (auto &oneVal : b.valueMap)
        {
            auto it = retVal.valueMap.find(oneVal.first);
            if (it == retVal.valueMap.end())
            {
                retVal.valueMap[oneVal.first] = oneVal.second;
            }
            else
            {
                it->second += oneVal.second;
            }
        }
    }
    return retVal;
}

CCurrencyValueMap operator-(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    CCurrencyValueMap retVal = a;
    if (a.valueMap.size() || b.valueMap.size())
    {
        for (auto &oneVal : b.valueMap)
        {
            auto it = retVal.valueMap.find(oneVal.first);
            if (it == retVal.valueMap.end())
            {
                retVal.valueMap[oneVal.first] = -oneVal.second;
            }
            else
            {
                it->second -= oneVal.second;
            }
        }
    }
    return retVal;
}

CCurrencyValueMap operator+(const CCurrencyValueMap& a, int b)
{
    CCurrencyValueMap retVal = a;
    for (auto &oneVal : retVal.valueMap)
    {
        oneVal.second += b;
    }
    return retVal;
}

CCurrencyValueMap operator-(const CCurrencyValueMap& a, int b)
{
    CCurrencyValueMap retVal = a;
    for (auto &oneVal : retVal.valueMap)
    {
        oneVal.second -= b;
    }
    return retVal;
}

CCurrencyValueMap operator*(const CCurrencyValueMap& a, int b)
{
    CCurrencyValueMap retVal = a;
    for (auto &oneVal : retVal.valueMap)
    {
        oneVal.second *= b;
    }
    return retVal;
}

CCurrencyValueMap operator/(const CCurrencyValueMap& a, int b)
{
    CCurrencyValueMap retVal = a;
    for (auto &oneVal : retVal.valueMap)
    {
        oneVal.second /= b;
    }
    return retVal;
}

const CCurrencyValueMap &CCurrencyValueMap::operator-=(const CCurrencyValueMap& operand)
{
    return *this = *this - operand;
}

const CCurrencyValueMap &CCurrencyValueMap::operator+=(const CCurrencyValueMap& operand)
{
    return *this = *this + operand;
}

// determine if the operand intersects this map
bool CCurrencyValueMap::Intersects(const CCurrencyValueMap& operand) const
{
    bool retVal = false;

    if (valueMap.size() && operand.valueMap.size())
    {
        for (auto &oneVal : valueMap)
        {
            auto it = operand.valueMap.find(oneVal.first);
            if (it != operand.valueMap.end())
            {
                if (it->second != 0 && oneVal.second != 0)
                {
                    retVal = true;
                    break;
                }
            }
        }
    }
    return retVal;
}

CCurrencyValueMap CCurrencyValueMap::IntersectingValues(const CCurrencyValueMap& operand) const
{
    CCurrencyValueMap retVal;

    if (valueMap.size() && operand.valueMap.size())
    {
        for (auto &oneVal : valueMap)
        {
            auto it = operand.valueMap.find(oneVal.first);
            if (it != operand.valueMap.end() &&
                it->second != 0 &&
                oneVal.second != 0)
            {
                retVal.valueMap[oneVal.first] = oneVal.second;
            }
        }
    }
    return retVal;
}

CCurrencyValueMap CCurrencyValueMap::CanonicalMap() const
{
    CCurrencyValueMap retVal;
    for (auto valPair : valueMap)
    {
        if (valPair.second != 0)
        {
            retVal.valueMap.insert(valPair);
        }
    }
    return retVal;
}

CCurrencyValueMap CCurrencyValueMap::NonIntersectingValues(const CCurrencyValueMap& operand) const
{
    CCurrencyValueMap retVal = *this;

    if (valueMap.size() && operand.valueMap.size())
    {
        for (auto &oneVal : valueMap)
        {
            if (oneVal.second)
            {
                auto it = operand.valueMap.find(oneVal.first);
                if (it != operand.valueMap.end() && it->second != 0)
                {
                    retVal.valueMap.erase(it->first);
                }
            }
            else
            {
                retVal.valueMap.erase(oneVal.first);
            }
        }
    }
    return retVal;
}

bool CCurrencyValueMap::IsValid() const
{
    for (auto &oneVal : valueMap)
    {
        if (oneVal.first.IsNull())
        {
            return false;
        }
    }
    return true;
}

bool CCurrencyValueMap::HasNegative() const
{
    for (auto &oneVal : valueMap)
    {
        if (oneVal.second < 0)
        {
            return true;
        }
    }
    return false;
}

// subtract, but do not subtract to negative values
CCurrencyValueMap CCurrencyValueMap::SubtractToZero(const CCurrencyValueMap& operand) const
{
    CCurrencyValueMap retVal(*this);
    std::vector<uint160> toRemove;
    if (valueMap.size() && operand.valueMap.size())
    {
        for (auto &oneVal : retVal.valueMap)
        {
            auto it = operand.valueMap.find(oneVal.first);
            if (it != operand.valueMap.end())
            {
                oneVal.second -= it->second;
                if (oneVal.second <= 0)
                {
                    toRemove.push_back(oneVal.first);
                }
            }
        }
    }
    // if we are subtracting a negative in non-intersecting values, they may add to above zero, so consider them
    for (auto &oneVal : operand.NonIntersectingValues(retVal).valueMap)
    {
        if (oneVal.second < 0)
        {
            if ((retVal.valueMap[oneVal.first] -= oneVal.second) <= 0)
            {
                toRemove.push_back(oneVal.first);
            }
        }
    }
    for (auto &toErase : toRemove)
    {
        retVal.valueMap.erase(toErase);
    }
    return retVal;
}

std::vector<CAmount> CCurrencyValueMap::AsCurrencyVector(const std::vector<uint160> &currencies) const
{
    std::vector<CAmount> retVal(currencies.size());
    for (int i = 0; i < currencies.size(); i++)
    {
        auto it = valueMap.find(currencies[i]);
        retVal[i] = it != valueMap.end() ? it->second : 0;
    }
    return retVal;
}
