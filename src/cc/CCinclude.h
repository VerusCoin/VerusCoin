/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#ifndef CC_INCLUDE_H
#define CC_INCLUDE_H

/*
there are only a very few types in bitcoin. pay to pubkey, pay to pubkey hash and pay to script hash
p2pk, p2pkh, p2sh
there are actually more that are possible, but those three are 99%+ of bitcoin transactions
so you can pay to a pubkey, or to its hash. or to a script's hash. the last is how most of the more complex scripts are invoked. to spend a p2sh vout, you need to provide the redeemscript, this script's hash is what the p2sh address was.
all of the above are the standard bitcoin vout types and there should be plenty of materials about it
Encrypted by a verified device
what I did with the CC contracts is created a fourth type of vout, the CC vout. this is using the cryptoconditions standard and it is even a different signature mechanism. ed25519 instead of secp256k1. it is basically a big extension to the bitcoin script. There is a special opcode that is added that says it is a CC script.
 
but it gets more interesting
each CC script has an evalcode
this is just an arbitrary number. but what it does is allows to create a self-contained universe of CC utxo that all have the same evalcode and that is how a faucet CC differentiates itself from a dice CC, the eval code is different

one effect from using a different eval code is that even if the rest of the CC script is the same, the bitcoin address that is calculated is different. what this means is that for each pubkey, there is a unique address for each different eval code!
and this allows efficient segregation of one CC contracts transactions from another
the final part that will make it all clear how the funds can be locked inside the contract. this is what makes a contract, a contract. I put both the privkey and pubkey for a randomly chosen address and associate it with each CC contract. That means anybody can sign outputs for that privkey. However, it is a CC output, so in addition to the signature, whatever constraints a CC contract implements must also be satistifed. This allows funds to be locked and yet anybody is able to spend it, assuming they satisfy the CC's rules

one other technical note is that komodod has the insight-explorer extensions built in. so it can lookup directly all transactions to any address. this is a key performance boosting thing as if it wasnt there, trying to get all the utxo for an address not in the wallet is quite time consuming
*/

#include <cc/eval.h>
#include <script/cc.h>
#include <script/script.h>
#include <cryptoconditions.h>
#include "../script/standard.h"
#include "../base58.h"
#include "../core_io.h"
#include "../key_io.h"
#include "../script/sign.h"
#include "../wallet/wallet.h"
#include <univalue.h>
#include <exception>
#include "../komodo_defs.h"

extern int32_t KOMODO_CONNECTING,KOMODO_CCACTIVATE;
extern uint32_t ASSETCHAINS_CC;
extern std::string CCerror;

#define SMALLVAL 0.000000000000001

struct CCcontract_info
{
    char unspendableCCaddr[64], CChexstr[72], normaladdr[64], unspendableaddr2[64], unspendableaddr3[64];
    uint8_t CCpriv[32], unspendablepriv2[32], unspendablepriv3[32];
    CPubKey unspendablepk2, unspendablepk3;
    bool (*validate)(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
    bool (*ismyvin)(CScript const& scriptSig);
    bool (*contextualprecheck)(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height);
    uint8_t evalcode,evalcode2,evalcode3,didinit;
};
struct CCcontract_info *CCinit(struct CCcontract_info *cp,uint8_t evalcode);

#ifdef ENABLE_WALLET
extern CWallet* pwalletMain;
#endif
bool GetAddressUnspent(const uint160& addressHash, int type, std::vector<CAddressUnspentDbEntry>& unspentOutputs);

bool myGetTransaction(const uint256 &hash, CTransaction &txOut, uint256 &hashBlock, bool checkMempool=true);
int32_t is_hexstr(char *str,int32_t n);
bool myAddtomempool(CTransaction &tx, CValidationState *pstate = NULL, int32_t simHeight = 0, bool limitFree=true, bool limitDust=true, bool *missinginputs = NULL);
//uint64_t myGettxout(uint256 hash,int32_t n);
bool myIsutxo_spentinmempool(uint256 txid,int32_t vout);
int32_t myIsutxo_spent(uint256 &spenttxid,uint256 txid,int32_t vout);
int32_t decode_hex(uint8_t *bytes,int32_t n,char *hex);
int32_t iguana_rwnum(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp);
int32_t iguana_rwbignum(int32_t rwflag,uint8_t *serialized,int32_t len,uint8_t *endianedp);
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys);
bool GetCCParams(Eval* eval, const CTransaction &tx, uint32_t nIn,
                 CTransaction &txOut, std::vector<std::vector<unsigned char>> &preConditions, std::vector<std::vector<unsigned char>> &params);

// CCcustom
CPubKey GetUnspendable(struct CCcontract_info *cp,uint8_t *unspendablepriv);

// CCutils
CPubKey buf2pk(uint8_t *buf33);
CTxOut MakeCC1vout(uint8_t evalcode,CAmount nValue,CPubKey pk);
CTxOut MakeCC1of2vout(uint8_t evalcode,CAmount nValue,CPubKey pk,CPubKey pk2);
CC *MakeCCcond1(uint8_t evalcode,CPubKey pk);
CC *MakeCCcond1(uint8_t evalcode,CTxDestination dest);
CC *MakeCCcondAny(uint8_t evalcode,std::vector<CTxDestination> dests);
CC *MakeCCcond1of2(uint8_t evalcode,CPubKey pk1,CPubKey pk2);
CC *MakeCCcondMofN(uint8_t evalcode, const std::vector<CTxDestination> &dests, int M);
CC *MakeCCcondMofN(uint8_t evalcode, const std::vector<CC*> &conditions, int M);
CC *GetCryptoCondition(CScript const& scriptSig);
std::vector<unsigned char> GetFulfillmentVector(CScript const& scriptSig);
void CCaddr2set(struct CCcontract_info *cp,uint8_t evalcode,CPubKey pk,uint8_t *priv,char *coinaddr);
void CCaddr3set(struct CCcontract_info *cp,uint8_t evalcode,CPubKey pk,uint8_t *priv,char *coinaddr);
bool IsCCInput(CScript const& scriptSig);
int32_t unstringbits(char *buf,uint64_t bits);
uint64_t stringbits(char *str);
uint256 revuint256(uint256 txid);
char *uint256_str(char *dest,uint256 txid);
char *pubkey33_str(char *dest,uint8_t *pubkey33);
uint256 Parseuint256(char *hexstr);
CPubKey pubkey2pk(std::vector<uint8_t> pubkey);
bool _GetCCaddress(char *destaddr,uint8_t evalcode,CPubKey pk);
bool GetCCaddress(struct CCcontract_info *cp,char *destaddr,CPubKey pk);
bool GetCCaddress1of2(struct CCcontract_info *cp,char *destaddr,CPubKey pk,CPubKey pk2);
bool Getscriptaddress(char *destaddr,const CScript &scriptPubKey);

// TOBJ is CConditionObj of a CC output type
template <typename TOBJ>
CScript MakeMofNCCScript(const CConditionObj<TOBJ> &conditionObj, const CTxDestination *indexDest=nullptr)
{
    // indexDest is always added, but we need to index on all can-sign identities as well
    std::vector<CTxDestination> indexIDs = indexDest ? std::vector<CTxDestination>({*indexDest}) : conditionObj.evalCode == EVAL_NONE ? std::vector<CTxDestination>() : std::vector<CTxDestination>({conditionObj.dests[0]});
    int idxSize = indexIDs.size();

    COptCCParams masterParams = COptCCParams(COptCCParams::VERSION_V3, 0, idxSize, idxSize, indexIDs, std::vector<std::vector<unsigned char>>());
    CScript scriptRet = CScript() << masterParams.AsVector() << OP_CHECKCRYPTOCONDITION;

    std::vector<std::vector<unsigned char>> vvch = conditionObj.HaveObject() ? std::vector<std::vector<unsigned char>>({::AsVector(conditionObj.obj)}) : std::vector<std::vector<unsigned char>>();
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V3, conditionObj.evalCode, conditionObj.m, (uint8_t)(conditionObj.dests.size()), conditionObj.dests, vvch);

    // add the object to the end of the script
    scriptRet << vParams.AsVector() << OP_DROP;
    return scriptRet;
}

// TOBJ is CConditionObj of a CC output type
template <typename TOBJ>
CScript MakeMofNCCScript(const CConditionObj<TOBJ> &conditionObj, const std::vector<CTxDestination> *indexDests)
{
    // indexDest is always added, but we need to index on all can-sign identities as well
    std::vector<CTxDestination> indexIDs = indexDests ? *indexDests : conditionObj.evalCode == EVAL_NONE ? std::vector<CTxDestination>() : std::vector<CTxDestination>({conditionObj.dests[0]});
    int idxSize = indexIDs.size();

    COptCCParams masterParams = COptCCParams(COptCCParams::VERSION_V3, 0, idxSize, idxSize, indexIDs, std::vector<std::vector<unsigned char>>());
    CScript scriptRet = CScript() << masterParams.AsVector() << OP_CHECKCRYPTOCONDITION;

    std::vector<std::vector<unsigned char>> vvch = conditionObj.HaveObject() ? std::vector<std::vector<unsigned char>>({::AsVector(conditionObj.obj)}) : std::vector<std::vector<unsigned char>>();
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V3, conditionObj.evalCode, conditionObj.m, (uint8_t)(conditionObj.dests.size()), conditionObj.dests, vvch);

    // add the object to the end of the script
    scriptRet << vParams.AsVector() << OP_DROP;
    return scriptRet;
}

template <typename TOBJ1, typename TOBJ2>
CScript MakeMofNCCScript(int M, TOBJ1 &condition1, TOBJ2 &condition2, const std::vector<CTxDestination> *indexDests=nullptr)
{
    if (M > 2) M = 2;
    std::vector<CTxDestination> indexIDs = indexDests ? *indexDests : std::vector<CTxDestination>({condition1.dests[0], condition2.dests[0]});

    COptCCParams masterParams = COptCCParams(COptCCParams::VERSION_V3, 0, M, 2, indexIDs, std::vector<std::vector<unsigned char>>());
    CScript scriptRet = CScript() << masterParams.AsVector() << OP_CHECKCRYPTOCONDITION;

    std::vector<std::vector<unsigned char>> vvch2 = condition2.HaveObject() ? std::vector<std::vector<unsigned char>>({::AsVector(condition2.obj)}) : std::vector<std::vector<unsigned char>>();
    COptCCParams vParams2 = COptCCParams(COptCCParams::VERSION_V3, condition2.evalCode, condition2.m, (uint8_t)(condition2.dests.size()), condition2.dests, vvch2);

    std::vector<std::vector<unsigned char>> vvch1({::AsVector(condition1.obj), vParams2.AsVector()});
    COptCCParams vParams1 = COptCCParams(COptCCParams::VERSION_V3, condition1.evalCode, condition1.m, (uint8_t)(condition1.dests.size()), condition1.dests, vvch1);

    // add the object to the end of the script
    scriptRet << vParams1.AsVector() << OP_DROP;
    return scriptRet;
}

template <typename TOBJ1, typename TOBJ2, typename TOBJ3>
CScript MakeMofNCCScript(int M, TOBJ1 &condition1, TOBJ2 &condition2, TOBJ3 &condition3, const std::vector<CTxDestination> *indexDests=nullptr)
{
    if (M > 3) M = 3;
    std::vector<CTxDestination> indexIDs = indexDests ? *indexDests : std::vector<CTxDestination>({condition1.dests[0], condition2.dests[0], condition3.dests[0]});

    COptCCParams masterParams = COptCCParams(COptCCParams::VERSION_V3, 0, M, 3, indexIDs, std::vector<std::vector<unsigned char>>());
    CScript scriptRet = CScript() << masterParams.AsVector() << OP_CHECKCRYPTOCONDITION;

    std::vector<std::vector<unsigned char>> vvch2 = condition2.HaveObject() ? std::vector<std::vector<unsigned char>>({::AsVector(condition2.obj)}) : std::vector<std::vector<unsigned char>>();
    COptCCParams vParams2 = COptCCParams(COptCCParams::VERSION_V3, condition2.evalCode, condition2.m, (uint8_t)(condition2.dests.size()), condition2.dests, vvch2);

    std::vector<std::vector<unsigned char>> vvch3 = condition3.HaveObject() ? std::vector<std::vector<unsigned char>>({::AsVector(condition3.obj)}) : std::vector<std::vector<unsigned char>>();
    COptCCParams vParams3 = COptCCParams(COptCCParams::VERSION_V3, condition3.evalCode, condition3.m, (uint8_t)(condition3.dests.size()), condition3.dests, vvch3);

    std::vector<std::vector<unsigned char>> vvch({::AsVector(condition1.obj), vParams2.AsVector(), vParams3.AsVector()});
    COptCCParams vParams1 = COptCCParams(COptCCParams::VERSION_V3, condition1.evalCode, condition1.m, (uint8_t)(condition1.dests.size()), condition1.dests, vvch);

    // add the object to the end of the script
    scriptRet << vParams1.AsVector() << OP_DROP;
    return scriptRet;
}

template <typename TOBJ1, typename TOBJ2, typename TOBJ3, typename TOBJ4>
CScript MakeMofNCCScript(int M, TOBJ1 &condition1, TOBJ2 &condition2, TOBJ3 &condition3, TOBJ4 &condition4, const std::vector<CTxDestination> *indexDests=nullptr)
{
    if (M > 4) M = 4;
    std::vector<CTxDestination> indexIDs = indexDests ? *indexDests : std::vector<CTxDestination>({condition1.dests[0], condition2.dests[0], condition3.dests[0], condition4.dests[0]});

    COptCCParams masterParams = COptCCParams(COptCCParams::VERSION_V3, 0, M, 4, indexIDs, std::vector<std::vector<unsigned char>>());
    CScript scriptRet = CScript() << masterParams.AsVector() << OP_CHECKCRYPTOCONDITION;

    std::vector<std::vector<unsigned char>> vvch2 = condition2.HaveObject() ? std::vector<std::vector<unsigned char>>({::AsVector(condition2.obj)}) : std::vector<std::vector<unsigned char>>();
    COptCCParams vParams2 = COptCCParams(COptCCParams::VERSION_V3, condition2.evalCode, condition2.m, (uint8_t)(condition2.dests.size()), condition2.dests, vvch2);

    std::vector<std::vector<unsigned char>> vvch3 = condition3.HaveObject() ? std::vector<std::vector<unsigned char>>({::AsVector(condition3.obj)}) : std::vector<std::vector<unsigned char>>();
    COptCCParams vParams3 = COptCCParams(COptCCParams::VERSION_V3, condition3.evalCode, condition3.m, (uint8_t)(condition3.dests.size()), condition3.dests, vvch3);

    std::vector<std::vector<unsigned char>> vvch4 = condition3.HaveObject() ? std::vector<std::vector<unsigned char>>({::AsVector(condition4.obj)}) : std::vector<std::vector<unsigned char>>();
    COptCCParams vParams4 = COptCCParams(COptCCParams::VERSION_V3, condition4.evalCode, condition4.m, (uint8_t)(condition4.dests.size()), condition4.dests, vvch4);

    std::vector<std::vector<unsigned char>> vvch({::AsVector(condition1.obj), vParams2.AsVector(), vParams3.AsVector(), vParams4.AsVector()});
    COptCCParams vParams1 = COptCCParams(COptCCParams::VERSION_V3, condition1.evalCode, condition1.m, (uint8_t)(condition1.dests.size()), condition1.dests, vvch);

    // add the object to the end of the script
    scriptRet << vParams1.AsVector() << OP_DROP;
    return scriptRet;
}

// TOBJ is CConditionObj of a CC output type
template <typename TOBJ>
std::vector<unsigned char> MakeMofNCCCond(TOBJ &conditionObj)
{
    CC *cond = MakeCCcondMofN(conditionObj.evalCode, conditionObj.dests, conditionObj.m);
    std::vector<unsigned char> vecRet = CCPubKeyVec(cond);
    cc_free(cond);
    return vecRet;
}

template <typename TOBJ1, typename TOBJ2>
std::vector<unsigned char> MakeMofNCCCond(int M, TOBJ1 &condition1, TOBJ2 &condition2)
{
    if (M > 2) M = 2;
    std::vector<CC*> conditions({MakeCCcondMofN(condition1.evalCode, condition1.dests, condition1.m), MakeCCcondMofN(condition2.evalCode, condition2.dests, condition2.m)});
    CC *cond = CCNewThreshold(M, conditions);
    std::vector<unsigned char> vecRet = CCPubKeyVec(cond);
    cc_free(cond);
    return vecRet;
}

template <typename TOBJ1, typename TOBJ2, typename TOBJ3>
std::vector<unsigned char> MakeMofNCCCond(int M, TOBJ1 &condition1, TOBJ2 &condition2, TOBJ3 &condition3)
{
    if (M > 3) M = 3;
    std::vector<CC*> conditions({MakeCCcondMofN(condition1.evalCode, condition1.dests, condition1.m), MakeCCcondMofN(condition2.evalCode, condition2.dests, condition2.m), MakeCCcondMofN(condition3.evalCode, condition3.dests, condition3.m)});
    CC *cond = CCNewThreshold(M, conditions);
    std::vector<unsigned char> vecRet = CCPubKeyVec(cond);
    cc_free(cond);
    return vecRet;
}

template <typename TOBJ1, typename TOBJ2, typename TOBJ3, typename TOBJ4>
std::vector<unsigned char> MakeMofNCCCond(int M, TOBJ1 &condition1, TOBJ2 &condition2, TOBJ3 &condition3, TOBJ4 &condition4)
{
    if (M > 4) M = 4;
    std::vector<CC*> conditions({MakeCCcondMofN(condition1.evalCode, condition1.dests, condition1.m), 
                                 MakeCCcondMofN(condition2.evalCode, condition2.dests, condition2.m), 
                                 MakeCCcondMofN(condition3.evalCode, condition3.dests, condition3.m), 
                                 MakeCCcondMofN(condition4.evalCode, condition4.dests, condition4.m)});
    CC *cond = CCNewThreshold(M, conditions);
    std::vector<unsigned char> vecRet = CCPubKeyVec(cond);
    cc_free(cond);
    return vecRet;
}

#endif
