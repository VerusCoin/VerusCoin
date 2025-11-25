// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <univalue.h>
#include "clientversion.h"
#include "init.h"
#include "key_io.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "rpc/server.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "../version.h"
#include "pbaas/crosschainrpc.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif
#include "tls/utiltls.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include "zcash/Address.hpp"
#include "pbaas/pbaas.h"
#include <fstream>
#include <ostream>
#include <algorithm>
#include <boost/filesystem.hpp>

using namespace std;

/**
 * @note Do not add or change anything in the information returned by this
 * method. `getinfo` exists for backwards-compatibility only. It combines
 * information from wildly different sources in the program, which is a mess,
 * and is thus planned to be deprecated eventually.
 *
 * Based on the source of the information, new information should be added to:
 * - `getblockchaininfo`,
 * - `getnetworkinfo` or
 * - `getwalletinfo`
 *
 * Or alternatively, create a specific query method for the information.
 **/

extern void CopyNodeStats(std::vector<CNodeStats>& vstats);
int32_t Jumblr_depositaddradd(char *depositaddr);
int32_t Jumblr_secretaddradd(char *secretaddr);
int32_t komodo_longestchain();
int32_t komodo_notarized_height(int32_t *prevhtp,uint256 *hashp,uint256 *txidp);
uint32_t komodo_chainactive_timestamp();
int32_t komodo_whoami(char *pubkeystr,int32_t height,uint32_t timestamp);
extern int32_t KOMODO_LASTMINED,JUMBLR_PAUSE,KOMODO_LONGESTCHAIN;
extern char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN];
uint32_t komodo_segid32(char *coinaddr);
bool GetCoinSupply(int64_t &transparentSupply, int64_t *pzsupply, int64_t *pimmaturesupply, uint32_t height);
int32_t notarizedtxid_height(char *dest,char *txidstr,int32_t *kmdnotarized_heightp);

extern uint16_t ASSETCHAINS_P2PPORT,ASSETCHAINS_RPCPORT;
extern uint32_t ASSETCHAINS_CC;
extern uint32_t ASSETCHAINS_MAGIC;
extern uint64_t ASSETCHAINS_COMMISSION,ASSETCHAINS_STAKED,ASSETCHAINS_SUPPLY,ASSETCHAINS_ISSUANCE,ASSETCHAINS_LASTERA;
extern int32_t ASSETCHAINS_LWMAPOS;
extern uint64_t ASSETCHAINS_ENDSUBSIDY[],ASSETCHAINS_REWARD[],ASSETCHAINS_HALVING[],ASSETCHAINS_DECAY[];
extern uint64_t ASSETCHAINS_ERAOPTIONS[];

UniValue getinfo(const UniValue& params, bool fHelp)
{
    uint256 notarized_hash,notarized_desttxid; int32_t prevMoMheight,notarized_height,longestchain,kmdnotarized_height,txid_height;
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,           (numeric) the server version\n"
            "  \"protocolversion\": xxxxx,   (numeric) the protocol version\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n"
            "  \"timeoffset\": xxxxx,        (numeric) the time offset\n"
            "  \"connections\": xxxxx,       (numeric) the number of connections\n"
            "  \"tls_established\": xxxxx,   (numeric) the number of TLS connections established\n"
            "  \"tls_verified\": xxxxx,      (numeric) the number of TLS connection with validated certificates\n"
            "  \"proxy\": \"host:port\",     (string, optional) the proxy used by the server\n"
            "  \"difficulty\": xxxxxx,       (numeric) the current difficulty\n"
            "  \"testnet\": true|false,      (boolean) if the server is using testnet or not\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,         (numeric) the transaction fee set in " + CURRENCY_UNIT + "/kB\n"
            "  \"relayfee\": x.xxxx,         (numeric) minimum relay fee for non-free transactions in " + CURRENCY_UNIT + "/kB\n"
            "  \"errors\": \"...\"           (string) any error messages\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getinfo", "")
            + HelpExampleRpc("getinfo", "")
        );

    LOCK(cs_main);

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    //notarized_height = komodo_notarized_height(&prevMoMheight,&notarized_hash,&notarized_desttxid);
    //fprintf(stderr,"after notarized_height %u\n",(uint32_t)time(NULL));

    CProofRoot confirmedRoot = ConnectedChains.FinalizedChainRoot();

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("VRSCversion", VERUS_VERSION));
    obj.push_back(Pair("version", CLIENT_VERSION));
    obj.push_back(Pair("protocolversion", PROTOCOL_VERSION));
    obj.push_back(Pair("chainid", EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID))));
    if (ConnectedChains.FirstNotaryChain().IsValid())
    {
        obj.push_back(Pair("notarychainid", EncodeDestination(CIdentityID(ConnectedChains.FirstNotaryChain().GetID()))));
    }
    obj.push_back(Pair("name", ConnectedChains.GetFriendlyCurrencyName(ASSETCHAINS_CHAINID)));
    if (confirmedRoot.IsValid())
    {
        obj.push_back(Pair("notarizedroot", confirmedRoot.ToUniValue()));
    }

#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));
    }
#endif
    //fprintf(stderr,"after wallet %u\n",(uint32_t)time(NULL));
    obj.push_back(Pair("blocks",        (int)chainActive.Height()));
    if ( (longestchain = KOMODO_LONGESTCHAIN) == 0 || chainActive.Height() > longestchain )
        longestchain = chainActive.Height();
    //fprintf(stderr,"after longestchain %u\n",(uint32_t)time(NULL));
    obj.push_back(Pair("longestchain",  longestchain));
    obj.push_back(Pair("timeoffset",    GetTimeOffset()));
    if ( chainActive.LastTip() != 0 )
        obj.push_back(Pair("tiptime", (int)chainActive.LastTip()->nTime));
    obj.push_back(Pair("nextblocktime", (int64_t)ConnectedChains.GetNextBlockTime(chainActive.LastTip())));
    obj.push_back(Pair("connections",   (int)vNodes.size()));
    obj.push_back(Pair("proxy",         (proxy.IsValid() ? proxy.proxy.ToStringIPPort() : string())));
    obj.push_back(Pair("difficulty",    (double)GetDifficulty()));
    obj.push_back(Pair("testnet",       PBAAS_TESTMODE));
#ifdef ENABLE_WALLET
    if (pwalletMain) {
        LOCK(pwalletMain->cs_wallet);
        obj.push_back(Pair("keypoololdest", pwalletMain->GetOldestKeyPoolTime()));
        obj.push_back(Pair("keypoolsize",   (int)pwalletMain->GetKeyPoolSize()));
    }
    if (pwalletMain && pwalletMain->IsCrypted())
        obj.push_back(Pair("unlocked_until", nWalletUnlockTime));
    obj.push_back(Pair("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK())));
#endif

    //Add TLS stats to getinfo
    vector<CNodeStats> vstats;
    CopyNodeStats(vstats);
    int tlsEstablished = 0;
    int tlsVerified = 0;
    BOOST_FOREACH(const CNodeStats& stats, vstats) {
        if (stats.fTLSEstablished)
          tlsEstablished++;

        if (stats.fTLSVerified)
          tlsVerified++;
    }
    obj.push_back(Pair("tls_established",   tlsEstablished));
    obj.push_back(Pair("tls_verified",   tlsVerified));

    obj.push_back(Pair("relayfee",      ValueFromAmount(::minRelayTxFee.GetFeePerK())));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    {
        char pubkeystr[65]; int32_t notaryid;
        if ( (notaryid= komodo_whoami(pubkeystr,(int32_t)chainActive.LastTip()->GetHeight(),komodo_chainactive_timestamp())) >= 0 )
        {
            obj.push_back(Pair("notaryid",        notaryid));
            obj.push_back(Pair("pubkey",        pubkeystr));
            if ( KOMODO_LASTMINED != 0 )
                obj.push_back(Pair("lastmined",        KOMODO_LASTMINED));
        }
    }
    if ( ASSETCHAINS_CC != 0 )
        obj.push_back(Pair("CCid",        (int)ASSETCHAINS_CC));
    if ( ASSETCHAINS_SYMBOL[0] != 0 )
    {
        //obj.push_back(Pair("name",        ASSETCHAINS_SYMBOL));
        obj.push_back(Pair("p2pport",        ASSETCHAINS_P2PPORT));
        obj.push_back(Pair("rpcport",        ASSETCHAINS_RPCPORT));
        obj.push_back(Pair("magic",          (int)ASSETCHAINS_MAGIC));
        if (LogAcceptCategory("magicnumber"))
        {
            obj.push_back(Pair("calculatedmagic",(int)ConnectedChains.ThisChain().MagicNumber()));
        }

        obj.push_back(Pair("premine",        ASSETCHAINS_SUPPLY));

        if (ASSETCHAINS_ISSUANCE)
        {
            obj.push_back(Pair("issuance",        ASSETCHAINS_ISSUANCE));
        }

        if ( ASSETCHAINS_REWARD[0] != 0 || ASSETCHAINS_LASTERA > 0 )
        {
            std::string acReward = "", acHalving = "", acDecay = "", acEndSubsidy = "";
            int lastEra = (int)ASSETCHAINS_LASTERA;     // this is done to work around an ARM cross compiler
            bool isFractional = false;
            for (int i = 0; i <= lastEra; i++)
            {
                if (i == 0)
                {
                    acReward = std::to_string(ASSETCHAINS_REWARD[i]);
                    acHalving = std::to_string(ASSETCHAINS_HALVING[i]);
                    acDecay = std::to_string(ASSETCHAINS_DECAY[i]);
                    acEndSubsidy = std::to_string(ASSETCHAINS_ENDSUBSIDY[i]);
                    if (ASSETCHAINS_ERAOPTIONS[i] & CCurrencyDefinition::OPTION_FRACTIONAL)
                    {
                        //printf("%s: %s, ac_options: %s\n", __func__, std::to_string(ASSETCHAINS_ERAOPTIONS[i]).c_str(), GetArg("-ac_options","").c_str());
                        isFractional = true;
                    }
                }
                else
                {
                    acReward += "," + std::to_string(ASSETCHAINS_REWARD[i]);
                    acHalving += "," + std::to_string(ASSETCHAINS_HALVING[i]);
                    acDecay += "," + std::to_string(ASSETCHAINS_DECAY[i]);
                    acEndSubsidy += "," + std::to_string(ASSETCHAINS_ENDSUBSIDY[i]);
                }
            }
            if (ASSETCHAINS_LASTERA > 0)
            {
                obj.pushKV("eras", ((int)ASSETCHAINS_LASTERA) + 1);
            }
            obj.push_back(Pair("reward", acReward));
            obj.push_back(Pair("halving", acHalving));
            obj.push_back(Pair("decay", acDecay));
            obj.push_back(Pair("endsubsidy", acEndSubsidy));
            if (isFractional)
            {
                obj.push_back(Pair("fractional", "true"));
                obj.push_back(Pair("currencystate", ConnectedChains.GetCurrencyState((int)chainActive.Height()).ToUniValue()));
            }
        }

        if ( ASSETCHAINS_COMMISSION != 0 )
            obj.push_back(Pair("commission",        ASSETCHAINS_COMMISSION));
        if ( ASSETCHAINS_STAKED != 0 )
            obj.push_back(Pair("staked",        ASSETCHAINS_STAKED));
        if ( ASSETCHAINS_LWMAPOS != 0 )
            obj.push_back(Pair("veruspos", ASSETCHAINS_LWMAPOS));
    }
    return obj;
}

#ifdef ENABLE_WALLET
class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    UniValue operator()(const CNoDestination &dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const CKeyID &keyID) const {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        obj.push_back(Pair("isscript", false));
        if (pwalletMain && pwalletMain->GetPubKey(keyID, vchPubKey)) {
            obj.push_back(Pair("pubkey", HexStr(vchPubKey))); // should return pubkeyhash, but not sure about compatibility impact
            obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        }
        return obj;
    }

    UniValue operator()(const CPubKey &key) const {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("isscript", false));
        if (pwalletMain && key.IsValid()) {
            obj.push_back(Pair("pubkey", HexStr(key)));
            obj.push_back(Pair("iscompressed", key.IsCompressed()));
        }
        else
        {
            obj.push_back(Pair("pubkey", "invalid"));
        }
        return obj;
    }

    UniValue operator()(const CScriptID &scriptID) const {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("isscript", true));
        if (pwalletMain && pwalletMain->GetCScript(scriptID, subscript)) {
            std::vector<CTxDestination> addresses;
            txnouttype whichType;
            int nRequired;
            ExtractDestinations(subscript, whichType, addresses, nRequired);
            obj.push_back(Pair("script", GetTxnOutputType(whichType)));
            obj.push_back(Pair("hex", HexStr(subscript.begin(), subscript.end())));
            UniValue a(UniValue::VARR);
            for (const CTxDestination& addr : addresses) {
                a.push_back(EncodeDestination(addr));
            }
            obj.push_back(Pair("addresses", a));
            if (whichType == TX_MULTISIG)
                obj.push_back(Pair("sigsrequired", nRequired));
        }
        return obj;
    }

    UniValue operator()(const CIdentityID &idID) const {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("isidentity", true));
        CIdentity id = CIdentity::LookupIdentity(idID);
        if (id.IsValid()) {
            if (id.IsRevoked())
            {
                obj.push_back(Pair("isrevoked", true));
            }
            else
            {
                obj.push_back(Pair("isrevoked", false));
                UniValue a(UniValue::VARR);
                for (const CTxDestination& addr : id.primaryAddresses) {
                    a.push_back(EncodeDestination(addr));
                }
                obj.push_back(Pair("addresses", a));
                obj.push_back(Pair("sigsrequired", id.minSigs));
            }
        }
        return obj;
    }

    UniValue operator()(const CQuantumID &qID) const {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("isquantumkey", true));
        obj.push_back(Pair("address", EncodeDestination(qID)));
        return obj;
    }

    UniValue operator()(const CIndexID &idxID) const {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("isindexkey", true));
        obj.push_back(Pair("address", EncodeDestination(idxID)));
        return obj;
    }
};
#endif

UniValue coinsupply(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error("coinsupply <height>\n"
            "\nReturn coin supply information at a given block height. If no height is given, the current height is used.\n"
            "\nArguments:\n"
            "1. \"height\"     (integer, optional) Block height\n"
            "\nResult:\n"
            "{\n"
            "  \"result\" : \"success\",         (string) If the request was successful.\n"
            "  \"coin\" : \"VRSC\",              (string) The currency symbol of the native coin of this blockchain.\n"
            "  \"height\" : 420,                 (integer) The height of this coin supply data\n"
            "  \"supply\" : \"777.0\",           (float) The transparent coin supply\n"
            "  \"zfunds\" : \"0.777\",           (float) The shielded coin supply (in zaddrs)\n"
            "  \"total\" :  \"777.777\",         (float) The total coin supply, i.e. sum of supply + zfunds\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("coinsupply", "420")
            + HelpExampleRpc("coinsupply", "420")
        );

    uint32_t height = 0;
    int64_t zfunds = 0, supply = 0, immature = 0;
    UniValue result(UniValue::VOBJ);

    if ( params.size() == 0 )
        height = chainActive.Height();
    else height = atoi(uni_get_str(params[0]));

    if (height > 0 && height <= chainActive.Height()) {
        if (GetCoinSupply(supply, &zfunds, &immature, height))
        {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("coin", ASSETCHAINS_SYMBOL[0] == 0 ? "KMD" : ASSETCHAINS_SYMBOL));
            result.push_back(Pair("height", (int)height));
            result.push_back(Pair("supply", ValueFromAmount(supply)));
            result.push_back(Pair("immature", ValueFromAmount(immature)));
            result.push_back(Pair("zfunds", ValueFromAmount(zfunds)));
            result.push_back(Pair("total", ValueFromAmount(zfunds + supply)));
        } else result.push_back(Pair("error", "couldnt calculate supply"));
    } else {
        result.push_back(Pair("error", "invalid height"));
    }
    return(result);
}

UniValue jumblr_deposit(const UniValue& params, bool fHelp)
{
    int32_t retval; UniValue result(UniValue::VOBJ);
    if (fHelp || params.size() != 1)
        throw runtime_error("jumblr_deposit \"depositaddress\"\n");
    CBitcoinAddress address(params[0].get_str());
    bool isValid = address.IsValid();
    if ( isValid != 0 )
    {
        string addr = params[0].get_str();
        if ( (retval= Jumblr_depositaddradd((char *)addr.c_str())) >= 0 )
        {
            result.push_back(Pair("result", retval));
            JUMBLR_PAUSE = 0;
        }
        else result.push_back(Pair("error", retval));
    } else result.push_back(Pair("error", "invalid address"));
    return(result);
}

UniValue jumblr_secret(const UniValue& params, bool fHelp)
{
    int32_t retval; UniValue result(UniValue::VOBJ);
    if (fHelp || params.size() != 1)
        throw runtime_error("jumblr_secret \"secretaddress\"\n");
    CBitcoinAddress address(params[0].get_str());
    bool isValid = address.IsValid();
    if ( isValid != 0 )
    {
        string addr = params[0].get_str();
        retval = Jumblr_secretaddradd((char *)addr.c_str());
        result.push_back(Pair("result", "success"));
        result.push_back(Pair("num", retval));
        JUMBLR_PAUSE = 0;
    } else result.push_back(Pair("error", "invalid address"));
    return(result);
}

UniValue jumblr_pause(const UniValue& params, bool fHelp)
{
    int32_t retval; UniValue result(UniValue::VOBJ);
    if (fHelp )
        throw runtime_error("jumblr_pause\n");
    JUMBLR_PAUSE = 1;
    result.push_back(Pair("result", "paused"));
    return(result);
}

UniValue jumblr_resume(const UniValue& params, bool fHelp)
{
    int32_t retval; UniValue result(UniValue::VOBJ);
    if (fHelp )
        throw runtime_error("jumblr_resume\n");
    JUMBLR_PAUSE = 0;
    result.push_back(Pair("result", "resumed"));
    return(result);
}

UniValue validateaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "validateaddress \"address\"\n"
            "\nReturn information about the given transparent address.\n"
            "\nArguments:\n"
            "1. \"address\"     (string, required) The transparent address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,         (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"verusaddress\",   (string) The Verus or PBaaS address to be validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the address\n"
            "  \"ismine\" : true|false,          (boolean) If the address is yours or not\n"
            "  \"isscript\" : true|false,        (boolean) If the key is a script\n"
            "  \"pubkey\" : \"publickeyhex\",    (string) The hex value of the raw public key\n"
            "  \"iscompressed\" : true|false,    (boolean) If the address is compressed\n"
            "  \"account\" : \"account\"         (string) DEPRECATED. The account associated with the address, \"\" is the default account\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("validateaddress", "\"RTZMZHDFSTFQst8XmX2dR4DaH87cEUs3gC\"")
            + HelpExampleRpc("validateaddress", "\"RTZMZHDFSTFQst8XmX2dR4DaH87cEUs3gC\"")
        );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    CTxDestination dest = DecodeDestination(params[0].get_str());
    bool isValid = IsValidDestination(dest);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        std::string currentAddress = EncodeDestination(dest);
        ret.push_back(Pair("address", currentAddress));

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));
        ret.push_back(Pair("segid", (int32_t)komodo_segid32((char *)params[0].get_str().c_str()) & 0x3f));
#ifdef ENABLE_WALLET
        isminetype mine = pwalletMain ? IsMine(*pwalletMain, dest) : ISMINE_NO;
        ret.push_back(Pair("ismine", (mine & ISMINE_SPENDABLE) ? true : false));
        ret.push_back(Pair("issharedownership", (mine & ISMINE_SHARED) ? true : false));
        ret.push_back(Pair("iswatchonly", (mine & ISMINE_WATCH_ONLY) ? true: false));
        UniValue detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
        ret.pushKVs(detail);
        if (pwalletMain && pwalletMain->mapAddressBook.count(dest))
            ret.push_back(Pair("account", pwalletMain->mapAddressBook[dest].name));
#endif
    }
    return ret;
}


class DescribePaymentAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    UniValue operator()(const libzcash::InvalidEncoding &zaddr) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const libzcash::SproutPaymentAddress &zaddr) const {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("type", "sprout"));
        obj.push_back(Pair("payingkey", zaddr.a_pk.GetHex()));
        obj.push_back(Pair("transmissionkey", zaddr.pk_enc.GetHex()));
#ifdef ENABLE_WALLET
        if (pwalletMain) {
            obj.push_back(Pair("ismine", HaveSpendingKeyForPaymentAddress(pwalletMain)(zaddr)));
        }
#endif
        return obj;
    }

    UniValue operator()(const libzcash::SaplingPaymentAddress &zaddr) const {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("type", "sapling"));
        obj.push_back(Pair("diversifier", HexStr(zaddr.d)));
        obj.push_back(Pair("diversifiedtransmissionkey", zaddr.pk_d.GetHex()));
#ifdef ENABLE_WALLET
        if (pwalletMain) {
            obj.push_back(Pair("ismine", HaveSpendingKeyForPaymentAddress(pwalletMain)(zaddr)));
        }
#endif
        return obj;
    }
};

UniValue z_validateaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_validateaddress \"zaddr\"\n"
            "\nReturn information about the given z address.\n"
            "\nArguments:\n"
            "1. \"zaddr\"     (string, required) The z address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,      (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"zaddr\",         (string) The z address validated\n"
            "  \"type\" : \"xxxx\",             (string) \"sprout\" or \"sapling\"\n"
            "  \"ismine\" : true|false,       (boolean) If the address is yours or not\n"
            "  \"payingkey\" : \"hex\",         (string) [sprout] The hex value of the paying key, a_pk\n"
            "  \"transmissionkey\" : \"hex\",   (string) [sprout] The hex value of the transmission key, pk_enc\n"
            "  \"diversifier\" : \"hex\",       (string) [sapling] The hex value of the diversifier, d\n"
            "  \"diversifiedtransmissionkey\" : \"hex\", (string) [sapling] The hex value of pk_d\n"

            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("z_validateaddress", "\"zcWsmqT4X2V4jgxbgiCzyrAfRT1vi1F4sn7M5Pkh66izzw8Uk7LBGAH3DtcSMJeUb2pi3W4SQF8LMKkU2cUuVP68yAGcomL\"")
            + HelpExampleRpc("z_validateaddress", "\"zcWsmqT4X2V4jgxbgiCzyrAfRT1vi1F4sn7M5Pkh66izzw8Uk7LBGAH3DtcSMJeUb2pi3W4SQF8LMKkU2cUuVP68yAGcomL\"")
        );


#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain->cs_wallet);
#else
    LOCK(cs_main);
#endif

    string strAddress = params[0].get_str();
    auto address = DecodePaymentAddress(strAddress);
    bool isValid = IsValidPaymentAddress(address);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        ret.push_back(Pair("address", strAddress));
        UniValue detail = boost::apply_visitor(DescribePaymentAddressVisitor(), address);
        ret.pushKVs(detail);
    }
    return ret;
}


/**
 * Used by addmultisigaddress / createmultisig:
 */
CScript _createmultisig_redeemScript(const UniValue& params)
{
    int nRequired = params[0].get_int();
    const UniValue& keys = params[1].get_array();

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("not enough keys supplied "
                      "(got %u keys, but need at least %d to redeem)", keys.size(), nRequired));
    if (keys.size() > 16)
        throw runtime_error("Number of addresses involved in the multisignature address creation > 16\nReduce the number");
    std::vector<CPubKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();
#ifdef ENABLE_WALLET
        // Case 1: Bitcoin address and we have full public key:
        CTxDestination dest = DecodeDestination(ks);
        if (pwalletMain && IsValidDestination(dest)) {
            const CKeyID *keyID = boost::get<CKeyID>(&dest);
            if (!keyID) {
                throw std::runtime_error(strprintf("%s does not refer to a key", ks));
            }
            CPubKey vchPubKey;
            if (!pwalletMain->GetPubKey(*keyID, vchPubKey)) {
                throw std::runtime_error(strprintf("no full public key for address %s", ks));
            }
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }

        // Case 2: hex public key
        else
#endif
        if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }
        else
        {
            throw runtime_error(" Invalid public key: "+ks);
        }
    }
    CScript result = GetScriptForMultisig(nRequired, pubkeys);

    if (result.size() > CScript::MAX_SCRIPT_ELEMENT_SIZE)
        throw runtime_error(
                strprintf("redeemScript exceeds size limit: %d > %d", (int)result.size(), CScript::MAX_SCRIPT_ELEMENT_SIZE));

    return result;
}

UniValue createmultisig(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 2)
    {
        string msg = "createmultisig nrequired [\"key\",...]\n"
            "\nCreates a multi-signature address with n signature of m keys required.\n"
            "It returns a json object with the address and redeemScript.\n"

            "\nArguments:\n"
            "1. nrequired      (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"       (string, required) A json array of keys which are Komodo addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"key\"    (string) Komodo address or hex-encoded public key\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nCreate a multisig address from 2 addresses\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"RTZMZHDFSTFQst8XmX2dR4DaH87cEUs3gC\\\",\\\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"RTZMZHDFSTFQst8XmX2dR4DaH87cEUs3gC\\\",\\\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\\\"]\"")
        ;
        throw runtime_error(msg);
    }

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(params);
    CScriptID innerID(inner);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("address", EncodeDestination(innerID)));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));

    return result;
}

uint256 HashFile(const std::string &filepath, CNativeHashWriter &ss)
{
    if (!boost::filesystem::exists(filepath))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot read file: " + filepath);
    }

    std::ifstream ifs(filepath, std::ios::binary | std::ios::in);
    if (!ifs)
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot open file " + filepath);
    }

    std::vector<char> vch(64 * 1024);

    while (ifs)
    {
        ifs.read(vch.data(), vch.size());
        std::streamsize readNum = ifs.gcount();
        if (ifs.bad())
        {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error while reading file " + filepath);
        }
        if (readNum > 0)
        {
            ss.write(vch.data(), static_cast<size_t>(readNum));
        }
   }

    return ss.GetHash();
}

uint256 HashFile(const std::string &filepath)
{
    if (!GetBoolArg("-enablefileencryption", true))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot read file: " + filepath + " for data output");
    }

    CNativeHashWriter hw(CCurrencyDefinition::EHashTypes::HASH_SHA256);
    return HashFile(filepath, hw);
}

UniValue hashdata(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "hashdata \"hexdata\" \"hashtype\" \"personalstring\"\n"
            "\nReturns the hash of the data in a hex message\n"
            "\nArguments:\n"
            "  \"hexdata\"            (string, required) This message is converted from hex, the data is hashed, then returned\n"
            "  \"hashtype\"           (string, optional) one of (\"sha256rev\", \"sha256D\", \"blake2b\", \"blake2bnopersonal\", \"keccak256\", \"verushash2\", \"verushash2b\", \"verushash2.1\"), defaults to sha256\n"
            "  \"personalstring\"     (string, optional) For hashes with personalization string, such as blake2b, this is optional and will default to daemon default if not specified\n"
            "\nResult:\n"
            "  \"hashresult\"         (hexstring) 32 byte hash in hex of the data passed in using the hash of the specific blockheight\n"
            "\nExamples:\n"
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifymessage", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\", \"signature\", \"my message\"")
        );

    std::string hexMessage = uni_get_str(params[0]);
    if (!hexMessage.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No message to hash");
    }

    std::vector<unsigned char> vmsg;
    try
    {
        vmsg = ParseHex(hexMessage);
    }
    catch(const std::exception& e)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Message to hash must be in hexadecimal format");
    }

    std::string hashType = params.size() > 1 ? uni_get_str(params[1]) : "sha256";

    uint256 result;

    if (hashType == "sha256")
    {
        CHashWriterSHA256 hw(SER_GETHASH, PROTOCOL_VERSION);
        hw.write((const char *)vmsg.data(), vmsg.size());
        result = hw.GetHash();
        // to be compatible with data and file hashing tools when users compare the output, such as sha256sum,
        // we reverse the normally little endian value
        std::reverse(result.begin(), result.end());
    }
    else if (hashType == "sha256D")
    {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw.write((const char *)vmsg.data(), vmsg.size());
        result = hw.GetHash();
    }
    else if (hashType == "blake2b")
    {
        std::string personalString;
        if (params.size() > 2)
        {
            personalString = uni_get_str(params[2]);
            std::vector<unsigned char> personalVec(personalString[0], personalString[0] + personalString.size());
            personalVec.resize(crypto_generichash_blake2b_PERSONALBYTES);
            CBLAKE2bWriter hw(SER_GETHASH, PROTOCOL_VERSION, &(personalVec[0]));
            hw.write((const char *)vmsg.data(), vmsg.size());
            result = hw.GetHash();
        }
        else
        {
            CBLAKE2bWriter hw(SER_GETHASH, PROTOCOL_VERSION);
            hw.write((const char *)vmsg.data(), vmsg.size());
            result = hw.GetHash();
        }
    }
    else if (hashType == "blake2bnopersonal")
    {
        CBLAKE2bWriter hw(SER_GETHASH, PROTOCOL_VERSION, nullptr);
        hw.write((const char *)vmsg.data(), vmsg.size());
        result = hw.GetHash();
    }
    else if (hashType == "keccak256")
    {
        CKeccack256Writer hw;
        hw.write((const char *)vmsg.data(), vmsg.size());
        result = hw.GetHash();
    }
    else if (hashType == "verushash2")
    {
        CVerusHashV2Writer hw(SER_GETHASH, PROTOCOL_VERSION);
        hw.write((const char *)vmsg.data(), vmsg.size());
        result = hw.GetHash();
    }
    else if (hashType == "verushash2b")
    {
        CVerusHashV2bWriter hw(SER_GETHASH, PROTOCOL_VERSION, CActivationHeight::ACTIVATE_VERUSHASH2);
        hw.write((const char *)vmsg.data(), vmsg.size());
        result = hw.GetHash();
    }
    else if (hashType == "verushash2.1")
    {
        CVerusHashV2bWriter hw(SER_GETHASH, PROTOCOL_VERSION, CActivationHeight::ACTIVATE_VERUSHASH2_1);
        hw.write((const char *)vmsg.data(), vmsg.size());
        result = hw.GetHash();
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Hash type " + hashType + " must be one of (\"sha256rev\", \"sha256D\", \"blake2b\", \"blake2bnopersonal\", \"keccak256\", \"verushash2\", \"verushash2b\", \"verushash2.1\")");
    }
    return result.GetHex();
}

uint160 ParseVDXFKey(const std::string &keyString);

CIdentitySignature::ESignatureVerification CheckBasicIDSignature(uint256 msgHash, const std::string &signatureString, const uint160 &systemID, const CIdentityID &idID, bool checkLatest)
{
    // lookup identity from the requested blockheight
    CIdentitySignature signature;
    bool fInvalid;

    // get the signature, a hex string, which is deserialized into an instance of the ID signature class
    std::vector<unsigned char> sigVec;
    try
    {
        sigVec = DecodeBase64(signatureString.c_str(), &fInvalid);
        if (fInvalid)
        {
            sigVec.clear();
        }

        if (sigVec.size())
        {
            signature = CIdentitySignature(sigVec);
        }
    }
    catch(const std::exception& e)
    {
        LogPrintf("Exception %s decoding signature %s\n", e.what(), signatureString.c_str());
        signature = CIdentitySignature();
    }

    if (signature.signatures.size())
    {
        if (msgHash.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid null hash");
        }
        else
        {
            msgHash = signature.IdentitySignatureHash(std::vector<uint160>(),
                                                      std::vector<std::string>(),
                                                      std::vector<uint256>(),
                                                      systemID,
                                                      signature.blockHeight,
                                                      idID,
                                                      verusDataSignaturePrefix,
                                                      msgHash);
        }

        std::set<uint160> signatureKeyIDs;
        for (auto &oneSig : signature.signatures)
        {
            CPubKey pubkey;
            if (pubkey.RecoverCompact(msgHash, oneSig))
            {
                signatureKeyIDs.insert(pubkey.GetID());
            }
        }

        CIdentity identity;
        int numSigs = 0;
        if (signatureKeyIDs.size() != 0)
        {
            identity = CIdentity::LookupIdentity(idID, checkLatest ? 0 : signature.blockHeight);
            if (identity.IsValidUnrevoked())
            {
                // remove all valid addresses and count
                for (auto &oneAddr : identity.primaryAddresses)
                {
                    if (!(oneAddr.which() == COptCCParams::ADDRTYPE_PK || oneAddr.which() == COptCCParams::ADDRTYPE_PKH))
                    {
                        numSigs = 0;
                        break;
                    }
                    uint160 addrID = GetDestinationID(oneAddr);
                    if (signatureKeyIDs.count(addrID))
                    {
                        numSigs++;
                        signatureKeyIDs.erase(addrID);
                        if (!signatureKeyIDs.size())
                        {
                            break;
                        }
                    }
                }

                // all signatures must be from valid keys, and if there are enough, it is valid
                if (signatureKeyIDs.size() == 0 && numSigs >= identity.minSigs)
                {
                    return CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE;
                }
                else if (signatureKeyIDs.size() != 0 || !numSigs)
                {
                    return CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID;
                }
                else
                {
                    return CIdentitySignature::ESignatureVerification::SIGNATURE_PARTIAL;
                }
            }
        }
    }
    return CIdentitySignature::ESignatureVerification::SIGNATURE_EMPTY;
}

UniValue verifyhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 4)
        throw runtime_error(
            "verifyhash \"address or identity\" \"signature\" \"hexhash\" \"checklatest\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"t-addr or identity\" (string, required) The transparent address or identity that signed the data.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signmessage/signfile).\n"
            "3. \"hexhash\"         (string, required) Hash of the message or file that was signed.\n"
            "3. \"checklatest\"     (bool, optional)   If true, checks signature validity based on latest identity. defaults to false,\n"
            "                                          which determines validity of signing height stored in signature.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nCreate the signature\n"
            + HelpExampleCli("signfile", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\" \"filepath/filename\"") +
            "or\n"
            + HelpExampleCli("signmessage", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifyhash", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\" \"signature\" \"hexhash\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifyhash", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\", \"signature\", \"hexhash\"")
        );

    LOCK(cs_main);

    string strAddress  = params[0].get_str();
    string strSign     = params[1].get_str();
    string strHash     = params[2].get_str();

    bool fInvalid = false;
    uint256 msgHash;

    CTxDestination destination = DecodeDestination(strAddress);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    if (!strHash.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No hash to verify");
    }

    try
    {
        msgHash = uint256S(strHash.c_str());
    }
    catch(const std::exception& e)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "hexhash must be a valid hexadecimal hash value");
    }

    // we expect a hash to be passed in reversed, for compatibility with file and data hashing tools like sha256sum
    std::reverse(msgHash.begin(), msgHash.end());

    if (destination.which() == COptCCParams::ADDRTYPE_ID)
    {
        return CheckBasicIDSignature(msgHash,
                                     strSign,
                                     ConnectedChains.ThisChain().GetID(),
                                     GetDestinationID(destination),
                                     params.size() > 3 && uni_get_bool(params[3])) == CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE;
    }
    else
    {
        const CKeyID *keyID = boost::get<CKeyID>(&destination);
        if (!keyID) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
        }

        vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

        if (fInvalid)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

        CHashWriterSHA256 ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << verusDataSignaturePrefix;
        ss << msgHash;

        CPubKey pubkey;
        if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
            return false;

        return (pubkey.GetID() == *keyID);
    }
}

UniValue verifymessage(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 4)
        throw runtime_error(
            "verifymessage \"address or identity\" \"signature\" \"message\" \"checklatest\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"t-addr or identity\" (string, required) The transparent address or identity that signed the message.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n"
            "3. \"message\"         (string, required) The message that was signed.\n"
            "3. \"checklatest\"     (bool, optional)   If true, checks signature validity based on latest identity. defaults to false,\n"
            "                                          which determines validity of signing height stored in signature.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifymessage", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\", \"signature\", \"my message\"")
        );

    LOCK(cs_main);

    string strAddress  = params[0].get_str();
    string strSign     = params[1].get_str();
    string strMessage  = params[2].get_str();
    bool fInvalid = false;

    CTxDestination destination = DecodeDestination(strAddress);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid address");
    }

    if (strMessage.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot verify empty message");
    }

    if (strSign.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid signature");
    }

    if (destination.which() == COptCCParams::ADDRTYPE_ID)
    {
        CHashWriterSHA256 ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << strMessage;
        uint256 msgHash = ss.GetHash();

        return CheckBasicIDSignature(msgHash,
                                     strSign,
                                     ConnectedChains.ThisChain().GetID(),
                                     GetDestinationID(destination),
                                     params.size() > 3 && uni_get_bool(params[3])) == CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE;
    }
    else
    {
        const CKeyID *keyID = boost::get<CKeyID>(&destination);
        if (!keyID) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
        }

        vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

        if (fInvalid)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

        CHashWriterSHA256 ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << strMessage;
        uint256 msgHash = ss.GetHash();
        ss.Reset();
        ss << verusDataSignaturePrefix;
        ss << msgHash;

        CPubKey pubkey;
        if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
            return false;

        return (pubkey.GetID() == *keyID);
    }
}

UniValue verifyfile(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 4)
        throw runtime_error(
            "verifyfile \"address or identity\" \"signature\" \"filepath/filename\" \"checklatest\"\n"
            "\nVerify a signed file\n"
            "\nArguments:\n"
            "1. \"t-addr or identity\" (string, required) The transparent address or identity that signed the file.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signfile).\n"
            "3. \"filename\"        (string, required) The file, which must be available locally to the daemon and that was signed.\n"
            "3. \"checklatest\"     (bool, optional)   If true, checks signature validity based on latest identity. defaults to false,\n"
            "                                          which determines validity of signing height stored in signature.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nCreate the signature\n"
            + HelpExampleCli("signfile", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\" \"filepath/filename\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifyfile", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\" \"signature\" \"filepath/filename\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifyfile", "\"RNKiEBduBru6Siv1cZRVhp4fkZNyPska6z\", \"signature\", \"filepath/filename\"")
        );

    LOCK(cs_main);

    string strAddress  = params[0].get_str();
    string strSign     = params[1].get_str();
    string strFileName = params[2].get_str();
    bool fInvalid = false;

    CTxDestination destination = DecodeDestination(strAddress);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }
    if (strSign.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid signature");
    }

    if (destination.which() == COptCCParams::ADDRTYPE_ID)
    {
        uint256 msgHash = HashFile(strFileName);
        if (msgHash.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot open file " + strFileName);
        }
        else
        {
            return CheckBasicIDSignature(msgHash,
                                        strSign,
                                        ConnectedChains.ThisChain().GetID(),
                                        GetDestinationID(destination),
                                        params.size() > 3 && uni_get_bool(params[3])) == CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE;
        }
    }
    else
    {
        const CKeyID *keyID = boost::get<CKeyID>(&destination);
        if (!keyID) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
        }

        vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

        if (fInvalid)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

        uint256 msgHash = HashFile(strFileName);

        if (msgHash.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot open file " + strFileName);
        }
        else
        {
            CHashWriterSHA256 ss(SER_GETHASH, 0);
            ss << verusDataSignaturePrefix;
            ss << msgHash;
            msgHash = ss.GetHash();
        }

        CPubKey pubkey;
        if (!pubkey.RecoverCompact(msgHash, vchSig))
            return false;

        return (pubkey.GetID() == *keyID);
    }
}

UniValue verifysignature(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1 || !params[0].isObject() || find_value(params[0], "signature").isNull())
        throw runtime_error(
            "verifysignature '{\"address\":\"i-address or friendly name (t-address checks on simple signature w/hash and prefix, nothing else)\",\n"
            "                  \"prefixstring\":\"extra string that is hashed during signature and must be supplied for verification\",\n"
            "                  \"filename\":\"filepath/filename\" |\n"
            "                    \"message\":\"any message\" |\n"
            "                    \"messagehex\":\"hexdata\" |\n"
            "                    \"messagebase64\":\"base64data\" |\n"
            "                    \"datahash\":\"256bithex\",\n"
            "                  \"vdxfkeys\":[\"vdxfkey i-address\", ...],\n"
            "                  \"vdxfkeynames\":[\"vdxfkeyname, object for getvdxfid API, or friendly name ID -- no i-addresses\", ...],\n"
            "                  \"boundhashes\":[\"hexhash\", ...],\n"
            "                  \"hashtype\": \"sha256\" | \"sha256D\" | \"blake2b\" | \"keccak256\"\n"
            "                  \"checklatest\": true | false\n"
            "                  \"signature\":\"verificationsignature\"}'\n\n"

            "\nChecks to see if the signature is valid and returns an error for invalid parameters"
            "{\n"
            "  \"address\":\"t-addr or identity\"                               (string, required) The transparent address or identity to verify against the signature\n"
            "  \"filename\" | \"message\" | \"messagehex\" | \"messagebase64\" | \"datahash\" (string, required) Data or hash of data signed\n"
            "  \"vdxfkeys\":[\"vdxfkey\", ...],                                 (array, optional)  Array of vdxfkeys or ID i-addresses\n"
            "  \"vdxfkeynames\":[\"vdxfkeyname\", ...],                         (array, optional)  Array of vdxfkey names or fully qualified friendly IDs\n"
            "  \"boundhashes\":[\"hexhash\", ...],                              (array, optional)  Array of bound hash values\n"
            "  \"hashtype\"                                                     (string, optional) one of: \"sha256\", \"sha256D\", \"blake2b\", \"keccak256\", defaults to sha256\n"
            "  \"signature\"                                                    (string, optional) The current signature of the message encoded in base 64\n"
            "  \"checklatest\"                                                  (bool, optional)   If true, checks signature validity based on latest identity. defaults to false,\n"
            "                                                                                      which determines validity of signing height stored in signature.\n"
            "}\n"

            "\nResult:\n"
            "{\n"
            "  \"hash\":\"hexhash\"         (string) The hash of the message (SHA256, NOT SHA256D)\n"
            "  \"signature\":\"base64sig\"  (string) The aggregate signature of the message encoded in base 64 if all or partial signing successful\n"
            "}\n"
            "\nExamples:\n"
            "\nVerify the signature\n"
            + HelpExampleCli("verifysignature", "'{\"identity\":\"Verus Coin Foundation.vrsc@\", \"message\":\"hello world\", \"signature\":\"base64sig\"}'") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifysignature", "'{\"identity\":\"Verus Coin Foundation.vrsc@\", \"message\":\"hello world\", \"signature\":\"base64sig\"}'")
        );

    string strAddress;
    string strPrefix;
    string strFileName;
    string strMessage;
    string strHex;
    string strBase64;
    string strDataHash;
    string strSignature;
    string hashTypeStr = "sha256";
    bool checkLatest = false;

    UniValue vdxfKeys(UniValue::VNULL);
    UniValue vdxfKeyNames(UniValue::VNULL);
    UniValue boundHashes(UniValue::VNULL);

    CTxDestination dest;

    strAddress = uni_get_str(find_value(params[0], "address"));
    strPrefix = uni_get_str(find_value(params[0], "prefixstring"), verusDataSignaturePrefix);
    strFileName = uni_get_str(find_value(params[0], "filename"));
    strMessage = uni_get_str(find_value(params[0], "message"));
    strHex = uni_get_str(find_value(params[0], "messagehex"));
    strBase64 = uni_get_str(find_value(params[0], "messagebase64"));
    strDataHash = uni_get_str(find_value(params[0], "datahash"));
    hashTypeStr = uni_get_str(find_value(params[0], "hashtype"), hashTypeStr);
    checkLatest = uni_get_bool(find_value(params[0], "checklatest"));
    vdxfKeys = find_value(params[0], "vdxfkeys");
    vdxfKeyNames = find_value(params[0], "vdxfkeynames");
    boundHashes = find_value(params[0], "boundhashes");
    strSignature = uni_get_str(find_value(params[0], "signature"));
    if (((int)strFileName.empty() +
            (int)strMessage.empty() +
            (int)strHex.empty() +
            (int)strBase64.empty() +
            (int)strDataHash.empty()) != 4)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Must include one and only one of \"filename\", \"message\", \"messagehex\", \"messagebase64\", and \"datahash\"");
    }
    if (strAddress.empty() || hashTypeStr.empty())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Must include a valid \"address\" and either no explicit \"hashtype\" or one that is valid");
    }
    dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "\"identity\" specified in object must be valid VerusID or address");
    }

    // if bound parameters are single strings, make them arrays of one
    if (vdxfKeys.isStr())
    {
        UniValue uniArr(UniValue::VARR);
        uniArr.push_back(vdxfKeys);
        vdxfKeys = uniArr;
    }
    if (vdxfKeyNames.isStr())
    {
        UniValue uniArr(UniValue::VARR);
        uniArr.push_back(vdxfKeyNames);
        vdxfKeyNames = uniArr;
    }
    if (boundHashes.isStr())
    {
        UniValue uniArr(UniValue::VARR);
        uniArr.push_back(boundHashes);
        boundHashes = uniArr;
    }
    if (dest.which() != COptCCParams::ADDRTYPE_ID &&
        ((vdxfKeys.isArray() && vdxfKeys.size()) ||
            (vdxfKeyNames.isArray() && vdxfKeyNames.size()) ||
            (boundHashes.isArray() && vdxfKeyNames.size()) ||
            strSignature.size()))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "When signing with public key and not identity, cannot include vdxf keys, vdxf key names, bound hashes, or multisig");
    }

    uint256 msgHash;
    CCurrencyDefinition::EHashTypes hashType = CCurrencyDefinition::EHashTypes::HASH_SHA256;

    if (hashTypeStr == "sha256")
    {
        hashType = CCurrencyDefinition::EHashTypes::HASH_SHA256;
    }
    else if (hashTypeStr == "sha256D")
    {
        hashType = CCurrencyDefinition::EHashTypes::HASH_SHA256D;
    }
    else if (hashTypeStr == "blake2b")
    {
        hashType = CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR;
    }
    else if (hashTypeStr == "keccak256")
    {
        hashType = CCurrencyDefinition::EHashTypes::HASH_KECCAK;
    }
    else
    {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid hash type" + hashTypeStr + " must be one of -- \"sha256\", \"sha256D\", \"blake2b\", \"keccak256\"");
    }

    {
        CNativeHashWriter hw(hashType);
        if (!strFileName.empty())
        {
            msgHash = HashFile(strFileName, hw);
        }
        else if (!strMessage.empty())
        {
            hw << strMessage;
            msgHash = hw.GetHash();
        }
        else if (!strHex.empty())
        {
            if (!IsHex(strHex))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "\"messagehex\" must be hex string with no extra characters");
            }
            std::vector<unsigned char> vmsg = ParseHex(strHex);
            hw.write((const char *)vmsg.data(), vmsg.size());
            msgHash = hw.GetHash();
        }
        else if (!strBase64.empty())
        {
            std::string vString = DecodeBase64(strBase64);
            if (vString.empty())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "\"messagebase64\" must be a base64 string with non-empty value and no extra characters");
            }
            hw.write(vString.data(), vString.size());
            msgHash = hw.GetHash();
        }
        else if (!strDataHash.empty() && IsHex(strDataHash))
        {
            msgHash.SetHex(strDataHash);
            // sha256 is reversed for sha256sum compatibility
            if (hashType == CCurrencyDefinition::EHashTypes::HASH_SHA256)
            {
                std::reverse(msgHash.begin(), msgHash.end());
            }
        }
    }

    if (msgHash.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Cannot open file " + strFileName);
    }

    if (dest.which() == COptCCParams::ADDRTYPE_ID)
    {
        LOCK(cs_main);

        uint32_t nHeight = chainActive.Height();

        CIdentity identity;

        identity = CIdentity::LookupIdentity(GetDestinationID(dest));
        if (identity.IsValidUnrevoked())
        {
            UniValue ret(UniValue::VOBJ);

            CIdentitySignature identitySig = CIdentitySignature(nHeight, std::vector<unsigned char>(), hashType, CIdentitySignature::VERSION_ETHBRIDGE);
            if (!strSignature.empty())
            {
                std::vector<unsigned char> sigVec;
                try
                {
                    bool fInvalid = false;
                    sigVec = DecodeBase64(strSignature.c_str(), &fInvalid);
                    if (fInvalid)
                    {
                        sigVec.clear();
                    }
                    if (sigVec.size())
                    {
                        identitySig = CIdentitySignature(sigVec);
                        if (!identitySig.IsValid() || identitySig.blockHeight > (nHeight + 1))
                        {
                            sigVec.clear();
                        }
                    }
                }
                catch(const std::exception& e)
                {
                    sigVec.clear();
                }
                if (!sigVec.size())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid pre-existing signature");
                }
            }
            else
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Missing or invalid \"signature\"");
            }

            // go through VDXF keys, VDXF key names, and bound hashes
            std::vector<uint160> vdxfCodes;
            std::vector<std::string> vdxfCodeNames;
            std::vector<uint256> statements;

            for (int i = 0; i < vdxfKeys.size(); i++)
            {
                uint160 oneKey = ParseVDXFKey(uni_get_str(vdxfKeys[i]));
                if (oneKey.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid VDXF key");
                }
                vdxfCodes.push_back(oneKey);
            }
            for (int i = 0; i < vdxfKeyNames.size(); i++)
            {
                std::string oneName = uni_get_str(vdxfKeyNames[i]);
                std::vector<unsigned char> vch;
                if (oneName.empty() || (DecodeBase58Check(oneName, vch) && vch.size()))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid VDXF key name. Key names must be fully qualified, friendly names.");
                }
                UniValue jsonObj(UniValue::VOBJ);
                if (jsonObj.read(oneName))
                {
                    throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid VDXF key name. Must be simple VDXF key or fully qualified ID.");
                }
                jsonObj = UniValue(UniValue::VOBJ);
                jsonObj.pushKV("vdxfuri", oneName);
                uint160 oneKey = ParseVDXFKey(jsonObj.write());
                if (oneKey.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid VDXF key name");
                }
                vdxfCodeNames.push_back(boost::to_lower_copy(oneName));
            }
            for (int i = 0; i < boundHashes.size(); i++)
            {
                uint256 oneHash = uint256S(uni_get_str(boundHashes[i]));
                if (oneHash.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid bound hash");
                }
                if (hashType == CCurrencyDefinition::EHashTypes::HASH_SHA256)
                {
                    std::reverse(oneHash.begin(), oneHash.end());
                }
                statements.push_back(oneHash);
            }

            CIdentitySignature::ESignatureVerification sigCheckResult =
                identitySig.CheckSignature(identity, vdxfCodes, vdxfCodeNames, statements, ASSETCHAINS_CHAINID, strPrefix, msgHash);

            std::string sigCheckStr;
            switch (sigCheckResult)
            {
                case CIdentitySignature::ESignatureVerification::SIGNATURE_EMPTY:
                {
                    sigCheckStr = "empty";
                    break;
                }
                case CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE:
                {
                    sigCheckStr = "verified";
                    break;
                }
                case CIdentitySignature::ESignatureVerification::SIGNATURE_PARTIAL:
                {
                    sigCheckStr = "partial";
                    break;
                }
                default:
                {
                    sigCheckStr = "invalid";
                    break;
                }
            }
            ret.pushKV("signaturestatus", sigCheckStr);

            if (hashType == CCurrencyDefinition::EHashTypes::HASH_SHA256)
            {
                std::reverse(msgHash.begin(), msgHash.end());   // return a reversed hash for compatibility with sha256sum
            }
            ret.push_back(Pair("system", ConnectedChains.GetFriendlyCurrencyName(ASSETCHAINS_CHAINID)));
            ret.push_back(Pair("systemid", EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID))));
            std::string fullName = ConnectedChains.GetFriendlyIdentityName(identity);
            ret.push_back(Pair("identity", fullName));
            ret.push_back(Pair("canonicalname", boost::to_lower_copy(fullName)));
            ret.push_back(Pair("address", EncodeDestination(identity.GetID())));
            ret.push_back(Pair("hashtype", hashTypeStr));
            ret.push_back(Pair("hash", msgHash.GetHex()));
            ret.push_back(Pair("height", (int64_t)nHeight));
            ret.push_back(Pair("signatureheight", (int64_t)identitySig.blockHeight));
            if (vdxfKeys.size())
            {
                ret.push_back(Pair("vdxfkeys", vdxfKeys));
            }
            if (vdxfKeyNames.size())
            {
                ret.push_back(Pair("vdxfkeynames", vdxfKeyNames));
            }
            if (boundHashes.size())
            {
                ret.push_back(Pair("boundhashes", boundHashes));
            }
            ret.push_back(Pair("signature", strSignature));
            return ret;
        }
        else if (!identity.IsValid())
        {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid identity");
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Identity is revoked and cannot sign");
        }
    }
    else
    {
        const CKeyID *keyID = boost::get<CKeyID>(&dest);
        if (!keyID) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
        }

        CKey key;
        if (!pwalletMain->GetKey(*keyID, key)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");
        }

        CHashWriterSHA256 ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << verusDataSignaturePrefix;
        ss << msgHash;

        uint256 sigHash = ss.GetHash();

        CPubKey pubkey;
        std::vector<unsigned char> vchSig = DecodeBase64(strSignature.c_str());
        std::string signatureStat = "verified";
        if (!pubkey.RecoverCompact(sigHash, vchSig) || pubkey.GetID() != GetDestinationID(dest))
        {
            signatureStat = "invalid";
        }

        UniValue ret(UniValue::VOBJ);
        ret.pushKV("signaturestatus", signatureStat);
        ret.push_back(Pair("system", ConnectedChains.GetFriendlyCurrencyName(ASSETCHAINS_CHAINID)));
        ret.push_back(Pair("hashtype", hashTypeStr));
        ret.push_back(Pair("address", EncodeDestination(dest)));
        std::reverse(msgHash.begin(), msgHash.end());   // return a reversed hash for compatibility with sha256sum
        ret.push_back(Pair("hash", msgHash.GetHex()));
        ret.push_back(Pair("signature", strSignature));
        return ret;
    }
}

UniValue getvdxfid_internal(const UniValue& params);
UniValue getvdxfid(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getvdxfid \"vdxfuri\" '{\"vdxfkey\":\"i-address or vdxfkey\", \"uint256\":\"hexstr\", \"indexnum\":0}'\n"
            "\nReturns the VDXF key of the URI string. For example \"vrsc::system.currency.export\"\n"
            "\nArguments:\n"
            "  \"vdxfuri\"                              (string, required) This message is converted from hex, the data is hashed, then returned\n"
            "  \"{\"\n"
            "    \"vdxfkey\":\"i-address or vdxfkey\"   (string, optional) VDXF key or i-address to combine via hash\n"
            "    \"uint256\":\"32bytehex\"              (hexstr, optional) 256 bit hash to combine with hash\n"
            "    \"indexnum\":int                       (integer, optional) int32_t number to combine with hash\n"
            "  \"}\"\n"
            "\nResult:\n"
            "{                                          (object) object with both base58check and hex vdxfid values of string and parents\n"
            "  \"vdxfid\"                               (base58check) i-ID of the URI processed with the VDXF & all combined parameters\n"
            "  \"hash160result\"                        (hexstring) 20 byte hash in hex of the URL string passed in, processed with the VDXF\n"
            "  \"qualifiedname\":                       (object) separate name and parent ID value\n"
            "  {\n"
            "    \"name\": \"namestr\"                  (string) leaf name\n"
            "    \"parentid\" | \"namespace\":\"string\" (string) parent ID (or namespace if VDXF key) of name\n"
            "  }\n"
            "  \"bounddata\": {                         (object) if additional data is bound to create the value, it is returned here"
            "  {\n"
            "    \"vdxfkey\":\"i-address or vdxfkey\"   (string) i-address that was combined via hash\n"
            "    \"uint256\":\"32bytehex\"              (hexstr) 256 bit hash combined with hash\n"
            "    \"indexnum\":int                       (integer) int32_t combined with hash\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            "\nCreate the signature\n"
            + HelpExampleCli("getvdxfid", "\"system.currency.export\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("getvdxfid", "\"idname::userdefinedgroup.subgroup.publishedname\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("getvdxfid", "\"idname::userdefinedgroup.subgroup.publishedname\"")
        );

    return getvdxfid_internal(params);
}

UniValue setmocktime(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "setmocktime timestamp\n"
            "\nSet the local time to given timestamp (-regtest only)\n"
            "\nArguments:\n"
            "1. timestamp  (integer, required) Unix seconds-since-epoch timestamp\n"
            "   Pass 0 to go back to using the system time."
        );

    if (!Params().MineBlocksOnDemand())
        throw runtime_error("setmocktime for regression testing (-regtest mode) only");

    // cs_vNodes is locked and node send/receive times are updated
    // atomically with the time change to prevent peers from being
    // disconnected because we think we haven't communicated with them
    // in a long time.
    LOCK2(cs_main, cs_vNodes);

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM));
    SetMockTime(params[0].get_int64());

    uint64_t t = GetTime();
    BOOST_FOREACH(CNode* pnode, vNodes) {
        pnode->nLastSend = pnode->nLastRecv = t;
    }

    return NullUniValue;
}

bool getAddressFromIndex(
    const int &type, const uint160 &hash, std::string &address)
{
    if (type == CScript::P2ID) {
        address = EncodeDestination(CIdentityID(hash));
    } else if (type == CScript::P2SH) {
        address = EncodeDestination(CScriptID(hash));
    } else if (type == CScript::P2PKH) {
        address = EncodeDestination(CKeyID(hash));
    } else if (type == CScript::P2IDX) {
        address = EncodeDestination(CIndexID(hash));
    } else if (type == CScript::P2QRK) {
        address = EncodeDestination(CQuantumID(hash));
    } else {
        return false;
    }
    return true;
}

bool getAddressesFromParams(const UniValue& params, std::vector<std::pair<uint160, int> > &addresses)
{
    if (params[0].isStr()) {
        CBitcoinAddress address(params[0].get_str());
        uint160 hashBytes;
        int type = 0;
        if (!address.GetIndexKey(hashBytes, type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        }
        addresses.push_back(std::make_pair(hashBytes, type));
    } else if (params[0].isObject()) {

        UniValue addressValues = find_value(params[0].get_obj(), "addresses");
        if (!addressValues.isArray()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Addresses is expected to be an array");
        }

        std::vector<UniValue> values = addressValues.getValues();

        for (std::vector<UniValue>::iterator it = values.begin(); it != values.end(); ++it) {

            CBitcoinAddress address(it->get_str());
            uint160 hashBytes;
            int type = 0;
            if (!address.GetIndexKey(hashBytes, type)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid addresses");
            }
            addresses.push_back(std::make_pair(hashBytes, type));
        }
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    return true;
}

bool heightSort(std::pair<CAddressUnspentKey, CAddressUnspentValue> a,
                std::pair<CAddressUnspentKey, CAddressUnspentValue> b) {
    return a.second.blockHeight < b.second.blockHeight;
}

bool timestampSort(std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> a,
                   std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> b) {
    return a.second.time < b.second.time;
}


void CurrencyValuesAndNames(UniValue &output, bool spending, const CScript &script, CAmount satoshis, bool friendlyNames=false);
void CurrencyValuesAndNames(UniValue &output, bool spending, const CScript &script, CAmount satoshis, bool friendlyNames)
{
    if (CConstVerusSolutionVector::GetVersionByHeight(chainActive.Height()) >= CActivationHeight::ACTIVATE_PBAAS)
    {
        CCurrencyValueMap reserves = script.ReserveOutValue();
        if (spending)
        {
            reserves = reserves * -1;
        }
        if (satoshis)
        {
            reserves.valueMap[ASSETCHAINS_CHAINID] = satoshis;
        }
        if (reserves.valueMap.size())
        {
            UniValue currencyBal(UniValue::VOBJ);
            UniValue currencyNames(UniValue::VOBJ);
            for (auto &oneBalance : reserves.valueMap)
            {
                std::string name = EncodeDestination(CIdentityID(oneBalance.first));
                currencyBal.push_back(make_pair(name, ValueFromAmount(oneBalance.second)));
                if (friendlyNames)
                {
                    currencyNames.pushKV(name, ConnectedChains.GetFriendlyCurrencyName(oneBalance.first));
                }
            }
            output.pushKV("currencyvalues", currencyBal);
            if (friendlyNames)
            {
                output.pushKV("currencynames", currencyNames);
            }
        }
    }
}

void CurrencyValuesAndNames(UniValue &output, bool spending, const CTransaction &tx, int index, CAmount satoshis, bool friendlyNames=false);
void CurrencyValuesAndNames(UniValue &output, bool spending, const CTransaction &tx, int index, CAmount satoshis, bool friendlyNames)
{
    CScript script;
    if (spending) {
        CTransaction priorOutTx;
        uint256 blockHash;
        if (tx.vin.size() > index && index >= 0 && myGetTransaction(tx.vin[index].prevout.hash, priorOutTx, blockHash))
        {

            script = priorOutTx.vout[tx.vin[index].prevout.n].scriptPubKey;
        }
        else
        {
            throw JSONRPCError(RPC_DATABASE_ERROR, "Unable to retrieve data to retrieve spending currency values");
        }
    }
    else
    {
        if (tx.vout.size() > index && index >= 0)
        {
            script = tx.vout[index].scriptPubKey;
        }
        else
        {
            throw JSONRPCError(RPC_DATABASE_ERROR, "Unable to retrieve data to for currency output values");
        }
    }
    CurrencyValuesAndNames(output, spending, script, satoshis, friendlyNames);
}

void GetDeltaOutputDetails(UniValue &delta, const CTransaction &curTx)
{
    std::map<std::set<CTxDestination>, CCurrencyValueMap> destMap;
    UniValue functions(UniValue::VARR);
    for (auto &oneOut : curTx.vout)
    {
        txnouttype typeRet;
        std::vector<CTxDestination> addresses;
        int requiredRet;
        if (ExtractDestinations(oneOut.scriptPubKey, typeRet, addresses, requiredRet) && addresses.size())
        {
            COptCCParams p;
            if (typeRet == txnouttype::TX_CRYPTOCONDITION &&
                oneOut.scriptPubKey.IsPayToCryptoCondition(p))
            {
                if (p.IsValid())
                {
                    switch (p.evalCode)
                    {
                        case EVAL_RESERVE_TRANSFER:
                        {
                            functions.push_back(Pair("reservetransfer", CReserveTransfer(p.vData[0]).ToUniValue()));
                            break;
                        }
                        case EVAL_IDENTITY_ADVANCEDRESERVATION:
                        {
                            functions.push_back(Pair("identityregistration", CAdvancedNameReservation(p.vData[0]).ToUniValue()));
                            break;
                        }
                        case EVAL_RESERVE_DEPOSIT:
                        {
                            functions.push_back(Pair("reservedeposit", CReserveDeposit(p.vData[0]).ToUniValue()));
                            break;
                        }
                        case EVAL_CROSSCHAIN_IMPORT:
                        {
                            functions.push_back(Pair("crosschainimport", CCrossChainImport(p.vData[0]).ToUniValue()));
                            break;
                        }
                        case EVAL_CROSSCHAIN_EXPORT:
                        {
                            functions.push_back(Pair("crosschainexport", CCrossChainExport(p.vData[0]).ToUniValue()));
                            break;
                        }
                        case EVAL_IDENTITY_COMMITMENT:
                        {
                            functions.push_back(Pair("identitycommitment", CCommitmentHash(p.vData[0]).ToUniValue()));
                            break;
                        }
                        case EVAL_IDENTITY_PRIMARY:
                        {
                            functions.push_back(Pair("identity", CIdentity(p.vData[0]).ToUniValue()));
                            break;
                        }
                        case EVAL_IDENTITY_RESERVATION:
                        {
                            functions.push_back(Pair("identityregistration", CNameReservation(p.vData[0]).ToUniValue()));
                            break;
                        }
                    }
                }
                else
                {
                    functions.push_back("invalid");
                }
            }
            std::set<CTxDestination> addrSet;
            for (auto &oneAddr : addresses)
            {
                addrSet.insert(oneAddr);
            }
            CCurrencyValueMap outVal = oneOut.ReserveOutValue();
            outVal.valueMap[ASSETCHAINS_CHAINID] = oneOut.nValue;
            destMap[addrSet] += outVal;
        }
    }
    UniValue sentToUni(UniValue::VOBJ);
    UniValue outputsUni(UniValue::VARR);
    if (functions.size())
    {
        sentToUni.pushKV("outputfunctions", functions);
    }
    for (auto &oneDestSet : destMap)
    {
        UniValue addressesUni(UniValue::VARR);
        for (auto &oneAddr : oneDestSet.first)
        {
            addressesUni.push_back(EncodeDestination(oneAddr));
        }
        UniValue oneDestAmount(UniValue::VOBJ);
        oneDestAmount.pushKV("addresses", addressesUni.size() == 1 ? addressesUni[0] : addressesUni);
        oneDestAmount.pushKV("amounts", oneDestSet.second.ToUniValue());
        outputsUni.push_back(oneDestAmount);
    }
    sentToUni.pushKV("outputs", outputsUni);
    if (curTx.valueBalance < 0)
    {
        sentToUni.pushKV("privateoutput", -curTx.valueBalance);
    }
    if (sentToUni.size())
    {
        delta.pushKV("sent", sentToUni);
    }
}

UniValue AddressMemPoolUni(const std::vector<std::pair<uint160, int>> &addresses, bool friendlyNames, int verbosity)
{
    CTransaction curTx;

    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > indexes;

    if (!mempool.getAddressIndex(addresses, indexes)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
    }

    std::sort(indexes.begin(), indexes.end(), timestampSort);

    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> >::iterator it = indexes.begin();
        it != indexes.end(); it++) {

        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.addressBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        UniValue delta(UniValue::VOBJ);
        delta.push_back(Pair("address", address));
        delta.push_back(Pair("txid", it->first.txhash.GetHex()));
        delta.push_back(Pair("index", (int)it->first.index));
        delta.push_back(Pair("satoshis", it->second.amount));
        delta.push_back(Pair("spending", (bool)it->first.spending));
        if (!it->first.txhash.IsNull() && (it->first.txhash == curTx.GetHash() || mempool.lookup(it->first.txhash, curTx)))
        {
            CurrencyValuesAndNames(delta, it->first.spending, curTx, it->first.index, it->second.amount, friendlyNames);
            if (verbosity && it->first.spending)
            {
                GetDeltaOutputDetails(delta, curTx);
            }
        }
        delta.push_back(Pair("timestamp", it->second.time));
        if (it->second.amount < 0) {
            delta.push_back(Pair("prevtxid", it->second.prevhash.GetHex()));
            delta.push_back(Pair("prevout", (int)it->second.prevout));
        }
        result.push_back(delta);
    }
    return result;
}

UniValue getaddressmempool(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressmempool\n"
            "\nReturns all mempool deltas for an address (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"      (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "  \"friendlynames\"    (boolean) Include additional array of friendly names keyed by currency i-addresses\n"
            "  \"verbosity\"        (number) (default == 0), if 1, include output information for spends, including all reserve amounts and destinations\n"
            "}\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"address\"  (string) The base58check encoded address\n"
            "    \"txid\"  (string) The related txid\n"
            "    \"index\"  (number) The related input or output index\n"
            "    \"satoshis\"  (number) The difference of satoshis\n"
            "    \"timestamp\"  (number) The time the transaction entered the mempool (seconds)\n"
            "    \"prevtxid\"  (string) The previous txid (if spending)\n"
            "    \"prevout\"  (string) The previous transaction output index (if spending)\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressmempool", "'{\"addresses\": [\"RY5LccmGiX9bUHYGtSWQouNy1yFhc5rM87\"]}'")
            + HelpExampleRpc("getaddressmempool", "{\"addresses\": [\"RY5LccmGiX9bUHYGtSWQouNy1yFhc5rM87\"]}")
        );

    std::vector<std::pair<uint160, int> > addresses;
    UniValue result(UniValue::VARR);

    int verbosity = uni_get_bool(find_value(params[0].get_obj(), "verbosity"));
    bool friendlyNames = uni_get_bool(find_value(params[0].get_obj(), "friendlynames"), true);

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    if (verbosity || friendlyNames)
    {
        LOCK2(cs_main, mempool.cs);
        result = AddressMemPoolUni(addresses, friendlyNames, verbosity);
    }
    else
    {
        LOCK(mempool.cs);
        result = AddressMemPoolUni(addresses, false, 0);
    }
    return result;
}

UniValue getaddressutxos(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressutxos\n"
            "\nReturns all unspent outputs for an address (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ],\n"
            "  \"chaininfo\"    (boolean) Include chain info with results\n"
            "  \"friendlynames\" (boolean, optional default=false) Include additional array of friendly names keyed by currency i-addresses\n"
            "  \"verbosity\"    (number) (default == 0), if 1, include output information for spends, including all reserve amounts and destinations\n"
            "}\n"
            "\nResult\n"
            "[\n"
            "  {\n"
            "    \"address\"  (string) The address base58check encoded\n"
            "    \"txid\"  (string) The output txid\n"
            "    \"height\"  (number) The block height\n"
            "    \"outputIndex\"  (number) The output index\n"
            "    \"script\"  (strin) The script hex encoded\n"
            "    \"satoshis\"  (number) The number of satoshis of the output\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressutxos", "'{\"addresses\": [\"RY5LccmGiX9bUHYGtSWQouNy1yFhc5rM87\"]}'")
            + HelpExampleRpc("getaddressutxos", "{\"addresses\": [\"RY5LccmGiX9bUHYGtSWQouNy1yFhc5rM87\"]}")
            );

    bool includeChainInfo = uni_get_bool(find_value(params[0].get_obj(), "chaininfo"));
    bool friendlyNames = uni_get_bool(find_value(params[0].get_obj(), "friendlynames"));

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    LOCK(cs_main);

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (!GetAddressUnspent((*it).first, (*it).second, unspentOutputs)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
        }
    }

    std::sort(unspentOutputs.begin(), unspentOutputs.end(), heightSort);

    UniValue utxos(UniValue::VARR);

    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=unspentOutputs.begin(); it!=unspentOutputs.end(); it++) {
        UniValue output(UniValue::VOBJ);

        std::string address = "";

        COptCCParams p;
        if (it->second.script.IsPayToCryptoCondition(p) && p.IsValid())
        {
            txnouttype outType;
            std::vector<CTxDestination> addresses;
            int required;
            if (ExtractDestinations(it->second.script, outType, addresses, required))
            {
                UniValue addressesUni(UniValue::VARR);
                for (auto addr : addresses)
                {
                    addressesUni.push_back(EncodeDestination(addr));
                    if (GetDestinationID(addr) == it->first.hashBytes)
                    {
                        address = EncodeDestination(addr);
                    }
                }
                if (addressesUni.size() > 1)
                {
                    output.push_back(Pair("addresses", addressesUni));
                }
            }
        }
        if (address == "" && !getAddressFromIndex(it->first.type, it->first.hashBytes, address))
        {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        output.push_back(Pair("address", address));
        output.push_back(Pair("txid", it->first.txhash.GetHex()));
        output.push_back(Pair("outputIndex", (int)it->first.index));
        output.pushKV("isspendable", it->second.script.IsSpendableOutputType(p));
        output.push_back(Pair("script", HexStr(it->second.script.begin(), it->second.script.end())));
        if (p.IsValid())
        {
            CurrencyValuesAndNames(output, false, it->second.script, it->second.satoshis, friendlyNames);
        }
        output.push_back(Pair("satoshis", it->second.satoshis));
        output.push_back(Pair("height", it->second.blockHeight));
        if (chainActive.Height() >= it->second.blockHeight)
        {
            output.push_back(Pair("blocktime", chainActive[it->second.blockHeight]->GetBlockTime()));
        }
        utxos.push_back(output);
    }

    if (includeChainInfo) {
        UniValue result(UniValue::VOBJ);
        result.push_back(Pair("utxos", utxos));

        LOCK(cs_main);
        result.push_back(Pair("hash", chainActive.LastTip()->GetBlockHash().GetHex()));
        result.push_back(Pair("height", (int)chainActive.Height()));
        return result;
    } else {
        return utxos;
    }
}

UniValue getaddressdeltas(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1 || !params[0].isObject())
        throw runtime_error(
            "getaddressdeltas\n"
            "\nReturns all changes for an address (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "  \"start\" (number) The start block height\n"
            "  \"end\" (number) The end block height\n"
            "  \"chaininfo\" (boolean) Include chain info in results, only applies if start and end specified\n"
            "  \"friendlynames\" (boolean) Include additional array of friendly names keyed by currency i-addresses\n"
            "  \"verbosity\" (number) (default == 0), if 1, include output information for spends, including all reserve amounts and destinations\n"
            "}\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"satoshis\"  (number) The difference of satoshis\n"
            "    \"txid\"  (string) The related txid\n"
            "    \"index\"  (number) The related input or output index\n"
            "    \"height\"  (number) The block height\n"
            "    \"address\"  (string) The base58check encoded address\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressdeltas", "'{\"addresses\": [\"RY5LccmGiX9bUHYGtSWQouNy1yFhc5rM87\"]}'")
            + HelpExampleRpc("getaddressdeltas", "{\"addresses\": [\"RY5LccmGiX9bUHYGtSWQouNy1yFhc5rM87\"]}")
        );


    bool includeChainInfo = uni_get_bool(find_value(params[0].get_obj(), "chaininfo"));
    bool friendlyNames = uni_get_bool(find_value(params[0].get_obj(), "friendlynames"));
    int verbosity = uni_get_bool(find_value(params[0].get_obj(), "verbosity"));

    UniValue startValue = find_value(params[0].get_obj(), "start");
    UniValue endValue = find_value(params[0].get_obj(), "end");

    int start = 0;
    int end = 0;

    if (startValue.isNum() && endValue.isNum()) {
        start = startValue.get_int();
        end = endValue.get_int();
        if (start <= 0 || end <= 0) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Start and end is expected to be greater than zero");
        }
        if (end < start) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "End value is expected to be greater than start");
        }
    }

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    {
        LOCK(cs_main);
        for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
            if (start > 0 && end > 0) {
                if (!GetAddressIndex((*it).first, (*it).second, addressIndex, start, end)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
                }
            } else {
                if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
                }
            }
        }
    }

    UniValue deltas(UniValue::VARR);
    {
        LOCK2(cs_main, mempool.cs);

        CTransaction curTx;

        for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
            std::string address;
            if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
            }

            UniValue delta(UniValue::VOBJ);
            delta.push_back(Pair("satoshis", it->second));
            delta.push_back(Pair("txid", it->first.txhash.GetHex()));
            delta.push_back(Pair("index", (int)it->first.index));
            delta.push_back(Pair("blockindex", (int)it->first.txindex));
            delta.push_back(Pair("height", it->first.blockHeight));
            delta.push_back(Pair("spending", it->first.spending));
            delta.push_back(Pair("address", address));
            if (chainActive.Height() >= it->first.blockHeight)
            {
                delta.push_back(Pair("blocktime", chainActive[it->first.blockHeight]->GetBlockTime()));
            }

            uint256 blockHash;
            if (!it->first.txhash.IsNull() && (it->first.txhash == curTx.GetHash() || myGetTransaction(it->first.txhash, curTx, blockHash)))
            {
                CurrencyValuesAndNames(delta, it->first.spending, curTx, it->first.index, it->second, friendlyNames);
                if (verbosity && it->first.spending)
                {
                    GetDeltaOutputDetails(delta, curTx);
                }
            }

            deltas.push_back(delta);
        }
    }

    UniValue result(UniValue::VOBJ);

    if (includeChainInfo && start > 0 && end > 0) {
        LOCK(cs_main);

        if (start > chainActive.Height() || end > chainActive.Height()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Start or end is outside chain range");
        }

        CBlockIndex* startIndex = chainActive[start];
        CBlockIndex* endIndex = chainActive[end];

        UniValue startInfo(UniValue::VOBJ);
        UniValue endInfo(UniValue::VOBJ);

        startInfo.push_back(Pair("hash", startIndex->GetBlockHash().GetHex()));
        startInfo.push_back(Pair("height", start));

        endInfo.push_back(Pair("hash", endIndex->GetBlockHash().GetHex()));
        endInfo.push_back(Pair("height", end));

        result.push_back(Pair("deltas", deltas));
        result.push_back(Pair("start", startInfo));
        result.push_back(Pair("end", endInfo));

        return result;
    } else {
        return deltas;
    }
}

UniValue getaddressbalance(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressbalance\n"
            "\nReturns the balance for an address(es) (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "  \"friendlynames\" (boolean) Include additional array of friendly names keyed by currency i-addresses\n"
            "}\n"
            "\nResult:\n"
            "{\n"
            "  \"balance\"  (number) The current balance in satoshis\n"
            "  \"received\"  (number) The total number of satoshis received (including change)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressbalance", "'{\"addresses\": [\"RY5LccmGiX9bUHYGtSWQouNy1yFhc5rM87\"]}'")
            + HelpExampleRpc("getaddressbalance", "{\"addresses\": [\"RY5LccmGiX9bUHYGtSWQouNy1yFhc5rM87\"]}")
        );

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }
    bool friendlyNames = uni_get_bool(find_value(params[0].get_obj(), "friendlynames"));
    int32_t asOfBlock = uni_get_int(find_value(params[0].get_obj(), "asofblock"));

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    LOCK2(cs_main, mempool.cs);

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (!GetAddressIndex((*it).first, (*it).second, addressIndex, 0, asOfBlock)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
        }
    }

    CTransaction curTx;

    CAmount balance = 0;
    CAmount received = 0;

    CCurrencyValueMap reserveBalance;
    CCurrencyValueMap reserveReceived;

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        uint256 blockHash;
        if (!it->first.txhash.IsNull() && (it->first.txhash == curTx.GetHash() || myGetTransaction(it->first.txhash, curTx, blockHash)))
        {
            if (it->first.spending) {
                CTransaction priorOutTx;
                if (myGetTransaction(curTx.vin[it->first.index].prevout.hash, priorOutTx, blockHash))
                {
                    reserveBalance -= priorOutTx.vout[curTx.vin[it->first.index].prevout.n].ReserveOutValue();
                }
                else
                {
                    throw JSONRPCError(RPC_DATABASE_ERROR, "Unable to retrieve data for reserve output value");
                }
            }
            else
            {
                reserveBalance += curTx.vout[it->first.index].ReserveOutValue();
                reserveReceived += curTx.vout[it->first.index].ReserveOutValue();
            }
        }

        if (it->second > 0) {
            received += it->second;
        }
        balance += it->second;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("balance", balance));
    result.push_back(Pair("received", received));

    if (CConstVerusSolutionVector::GetVersionByHeight(chainActive.Height()) >= CActivationHeight::ACTIVATE_PBAAS)
    {
        if (balance || received)
        {
            reserveBalance.valueMap[ASSETCHAINS_CHAINID] = balance;
            reserveReceived.valueMap[ASSETCHAINS_CHAINID] = received;
        }

        if (reserveBalance.valueMap.size())
        {
            UniValue currencyBal(UniValue::VOBJ);
            for (auto &oneBalance : reserveBalance.valueMap)
            {
                std::string name = EncodeDestination(CIdentityID(oneBalance.first));
                currencyBal.push_back(make_pair(name, ValueFromAmount(oneBalance.second)));
            }
            result.pushKV("currencybalance", currencyBal);
        }
        if (reserveReceived.valueMap.size())
        {
            UniValue currencyBal(UniValue::VOBJ);
            UniValue currencyNames(UniValue::VOBJ);
            for (auto &oneBalance : reserveReceived.valueMap)
            {
                std::string name = EncodeDestination(CIdentityID(oneBalance.first));
                currencyBal.push_back(make_pair(name, ValueFromAmount(oneBalance.second)));
                if (friendlyNames)
                {
                    currencyNames.push_back(make_pair(name, ConnectedChains.GetFriendlyCurrencyName(oneBalance.first)));
                }
            }
            result.pushKV("currencyreceived", currencyBal);
            if (friendlyNames)
            {
                result.pushKV("currencynames", currencyNames);
            }
        }
    }
    return result;
}

UniValue komodo_snapshot(int top);

UniValue getsnapshot(const UniValue& params, bool fHelp)
{
    UniValue result(UniValue::VOBJ); int64_t total; int32_t top = 0;

    if (params.size() > 0 && !params[0].isNull()) {
        top = atoi(params[0].get_str().c_str());
    if (top <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, top must be a positive integer");
    }

    if ( fHelp || params.size() > 1)
    {
        throw runtime_error(
                "getsnapshot\n"
			    "\nReturns a snapshot of (address,amount) pairs at current height (requires addressindex to be enabled).\n"
			    "\nArguments:\n"
			    "  \"top\" (number, optional) Only return this many addresses, i.e. top N richlist\n"
			    "\nResult:\n"
			    "{\n"
			    "   \"addresses\": [\n"
			    "    {\n"
			    "      \"addr\": \"RMEBhzvATA8mrfVK82E5TgPzzjtaggRGN3\",\n"
			    "      \"amount\": \"100.0\"\n"
			    "    },\n"
			    "    {\n"
			    "      \"addr\": \"RqEBhzvATAJmrfVL82E57gPzzjtaggR777\",\n"
			    "      \"amount\": \"23.45\"\n"
			    "    }\n"
			    "  ],\n"
			    "  \"total\": 123.45           (numeric) Total amount in snapshot\n"
			    "  \"average\": 61.7,          (numeric) Average amount in each address \n"
			    "  \"utxos\": 14,              (number) Total number of UTXOs in snapshot\n"
			    "  \"total_addresses\": 2,     (number) Total number of addresses in snapshot,\n"
			    "  \"start_height\": 91,       (number) Block height snapshot began\n"
			    "  \"ending_height\": 91       (number) Block height snapsho finished,\n"
			    "  \"start_time\": 1531982752, (number) Unix epoch time snapshot started\n"
			    "  \"end_time\": 1531982752    (number) Unix epoch time snapshot finished\n"
			    "}\n"
			    "\nExamples:\n"
			    + HelpExampleCli("getsnapshot","")
			    + HelpExampleRpc("getsnapshot", "1000")
                            );
    }
    result = komodo_snapshot(top);
    if ( result.size() > 0 ) {
        result.push_back(Pair("end_time", (int) time(NULL)));
    } else {
	result.push_back(Pair("error", "no addressindex"));
    }
    return(result);
}

UniValue getaddresstxids(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddresstxids\n"
            "\nReturns the txids for an address(es) (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "  \"start\" (number) The start block height\n"
            "  \"end\" (number) The end block height\n"
            "}\n"
            "\nResult:\n"
            "[\n"
            "  \"transactionid\"  (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddresstxids", "'{\"addresses\": [\"RY5LccmGiX9bUHYGtSWQouNy1yFhc5rM87\"]}'")
            + HelpExampleRpc("getaddresstxids", "{\"addresses\": [\"RY5LccmGiX9bUHYGtSWQouNy1yFhc5rM87\"]}")
        );

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    int start = 0;
    int end = 0;
    if (params[0].isObject()) {
        UniValue startValue = find_value(params[0].get_obj(), "start");
        UniValue endValue = find_value(params[0].get_obj(), "end");
        if (startValue.isNum() && endValue.isNum()) {
            start = startValue.get_int();
            end = endValue.get_int();
        }
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (start > 0 && end > 0) {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex, start, end)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        } else {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }
    }

    std::set<std::pair<int, std::string> > txids;
    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        int height = it->first.blockHeight;
        std::string txid = it->first.txhash.GetHex();

        if (addresses.size() > 1) {
            txids.insert(std::make_pair(height, txid));
        } else {
            if (txids.insert(std::make_pair(height, txid)).second) {
                result.push_back(txid);
            }
        }
    }

    if (addresses.size() > 1) {
        for (std::set<std::pair<int, std::string> >::const_iterator it=txids.begin(); it!=txids.end(); it++) {
            result.push_back(it->second);
        }
    }

    return result;
}

UniValue getspentinfo(const UniValue& params, bool fHelp)
{

    if (fHelp || params.size() != 1 || !params[0].isObject())
        throw runtime_error(
            "getspentinfo\n"
            "\nReturns the txid and index where an output is spent.\n"
            "\nArguments:\n"
            "{\n"
            "  \"txid\" (string) The hex string of the txid\n"
            "  \"index\" (number) The start block height\n"
            "}\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\"  (string) The transaction id\n"
            "  \"index\"  (number) The spending input index\n"
            "  ,...\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getspentinfo", "'{\"txid\": \"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9\", \"index\": 0}'")
            + HelpExampleRpc("getspentinfo", "{\"txid\": \"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9\", \"index\": 0}")
        );

    UniValue txidValue = find_value(params[0].get_obj(), "txid");
    UniValue indexValue = find_value(params[0].get_obj(), "index");

    if (!txidValue.isStr() || !indexValue.isNum()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid txid or index");
    }

    uint256 txid = ParseHashV(txidValue, "txid");
    int outputIndex = indexValue.get_int();

    CSpentIndexKey key(txid, outputIndex);
    CSpentIndexValue value;

    if (!GetSpentIndex(key, value)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to get spent info");
    }
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("txid", value.txid.GetHex()));
    obj.push_back(Pair("index", (int)value.inputIndex));
    obj.push_back(Pair("height", value.blockHeight));

    return obj;
}

UniValue processupgradedata(const UniValue& params, bool fHelp)
{

    if (fHelp || params.size() != 1 || !params[0].isObject())
        throw runtime_error(
            "processupgradedata {upgradedata}\n"
            "\nReturns the txid and index where an output is spent.\n"
            "\nArguments:\n"
            "{\n"
            "  \"upgradeid\"                (string) The VDXF key identifier\n"
            "  \"minimumdaemonversion\"     (string) The minimum version required for the upgrade\n"
            "  \"activationheight\"         (number) The block height to activate\n"
            "  \"activationtime\"           (number) Epoch time to activate, depending on upgrade\n"
            "}\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\"  (string) The transaction id\n"
            "  \"index\"  (number) The spending input index\n"
            "  ,...\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("processupgradedata", "'{\"txid\": \"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9\", \"index\": 0}'")
            + HelpExampleRpc("processupgradedata", "{\"txid\": \"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9\", \"index\": 0}")
        );

    CUpgradeDescriptor upgradeDescr(params[0]);

    if (!upgradeDescr.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid upgrade descriptor");
    }

    UniValue retVal = upgradeDescr.ToUniValue();
    auto vch = upgradeDescr.AsVector();
    retVal.pushKV("hex", HexBytes(&(vch[0]), vch.size()));
    return retVal;
}


static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "control",            "getinfo",                &getinfo,                true  }, /* uses wallet if enabled */
    { "util",               "validateaddress",        &validateaddress,        true  }, /* uses wallet if enabled */
    { "util",               "z_validateaddress",      &z_validateaddress,      true  }, /* uses wallet if enabled */
    { "util",               "createmultisig",         &createmultisig,         true  },
    { "identity",           "verifymessage",          &verifymessage,          true  },
    { "identity",           "verifyfile",             &verifyfile,             true  },
    { "identity",           "verifyhash",             &verifyhash,             true  },
    { "identity",           "verifysignature",        &verifysignature,        true  },
    { "vdxf",               "getvdxfid",              &getvdxfid,              true  },
    { "hidden",             "hashdata",               &hashdata,               true  }, // not visible in help

    // START insightexplorer
    /* Address index */
    { "addressindex",       "getaddresstxids",        &getaddresstxids,        false }, /* insight explorer */
    { "addressindex",       "getaddressbalance",      &getaddressbalance,      false }, /* insight explorer */
    { "addressindex",       "getaddressdeltas",       &getaddressdeltas,       false }, /* insight explorer */
    { "addressindex",       "getaddressutxos",        &getaddressutxos,        false }, /* insight explorer */
    { "addressindex",       "getaddressmempool",      &getaddressmempool,      true  }, /* insight explorer */
    { "blockchain",         "getspentinfo",           &getspentinfo,           false }, /* insight explorer */
    { "blockchain",         "processupgradedata",     &processupgradedata,     true },
    // END insightexplorer

    /* Not shown in help */
    { "hidden",             "setmocktime",            &setmocktime,            true  },
};

void RegisterMiscRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
