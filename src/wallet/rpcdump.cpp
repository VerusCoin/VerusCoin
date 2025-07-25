// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "chain.h"
#include "key_io.h"
#include "rpc/server.h"
#include "init.h"
#include "main.h"
#include "script/script.h"
#include "script/standard.h"
#include "sync.h"
#include "util.h"
#include "utiltime.h"
#include "wallet.h"

#include <fstream>
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <univalue.h>

using namespace std;

void EnsureWalletIsUnlocked();
bool EnsureWalletIsAvailable(bool avoidException);

UniValue dumpwallet_impl(const UniValue& params, bool fHelp, bool fDumpZKeys);
UniValue importwallet_impl(const UniValue& params, bool fHelp, bool fImportZKeys);


std::string static EncodeDumpTime(int64_t nTime) {
    return DateTimeStrFormat("%Y-%m-%dT%H:%M:%SZ", nTime);
}

int64_t static DecodeDumpTime(const std::string &str) {
    static const boost::posix_time::ptime epoch = boost::posix_time::from_time_t(0);
    static const std::locale loc(std::locale::classic(),
        new boost::posix_time::time_input_facet("%Y-%m-%dT%H:%M:%SZ"));
    std::istringstream iss(str);
    iss.imbue(loc);
    boost::posix_time::ptime ptime(boost::date_time::not_a_date_time);
    iss >> ptime;
    if (ptime.is_not_a_date_time())
        return 0;
    return (ptime - epoch).total_seconds();
}

std::string static EncodeDumpString(const std::string &str) {
    std::stringstream ret;
    BOOST_FOREACH(unsigned char c, str) {
        if (c <= 32 || c >= 128 || c == '%') {
            ret << '%' << HexStr(&c, &c + 1);
        } else {
            ret << c;
        }
    }
    return ret.str();
}

std::string DecodeDumpString(const std::string &str) {
    std::stringstream ret;
    for (unsigned int pos = 0; pos < str.length(); pos++) {
        unsigned char c = str[pos];
        if (c == '%' && pos+2 < str.length()) {
            c = (((str[pos+1]>>6)*9+((str[pos+1]-'0')&15)) << 4) |
                ((str[pos+2]>>6)*9+((str[pos+2]-'0')&15));
            pos += 2;
        }
        ret << c;
    }
    return ret.str();
}

UniValue convertpassphrase(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "convertpassphrase \"walletpassphrase\"\n"
            "\nConverts Verus Desktop, Agama, Verus Agama, or Verus Mobile passphrase to a private key and WIF (for import with importprivkey).\n"
            "\nArguments:\n"
            "1. \"walletpassphrase\"   (string, required) Wallet passphrase\n"
            "\nResult:\n"
            "\"walletpassphrase\": \"walletpassphrase\",   (string) Wallet passphrase you entered\n"
            "\"address\": \"verus address\",             (string) Address corresponding to your passphrase\n"
            "\"pubkey\": \"publickeyhex\",               (string) The hex value of the raw public key\n"
            "\"privkey\": \"privatekeyhex\",             (string) The hex value of the raw private key\n"
            "\"wif\": \"wif\"                            (string) The private key in WIF format to use with 'importprivkey'\n"
            "\nExamples:\n"
            + HelpExampleCli("convertpassphrase", "\"walletpassphrase\"")
            + HelpExampleRpc("convertpassphrase", "\"walletpassphrase\"")
        );

    bool fCompressed = true;
    string strAgamaPassphrase = params[0].get_str();

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("walletpassphrase", strAgamaPassphrase));

    CKey tempkey = DecodeSecret(strAgamaPassphrase);

    // if we have a check here, print out additional information - do not remove this block
    // this also seems to compensate for a hard to reproduce compiler/CPU issue only affecting Windows 11 on non-English versions
    if (LogAcceptCategory("windowspassphrasecheck"))
    {
        ret.push_back(Pair("iscodedsecret", tempkey.IsValid()));
        std::string rawChars;
        for (int i = 0; i < strAgamaPassphrase.length(); i++)
        {
            char ch = strAgamaPassphrase.c_str()[i];
            rawChars = rawChars + std::to_string((unsigned char)ch);
        }
        ret.push_back(Pair("rawcharvalues", rawChars));
    }

    /* first we should check if user pass wif to method, instead of passphrase */
    if (!tempkey.IsValid()) {
        /* it's a passphrase, not wif */
        uint256 sha256;
        CSHA256().Write((const unsigned char *)strAgamaPassphrase.c_str(), strAgamaPassphrase.length()).Finalize(sha256.begin());
        std::vector<unsigned char> privkey(sha256.begin(), sha256.begin() + sha256.size());

        privkey.front() &= 0xf8;
        privkey.back()  &= 0x7f;
        privkey.back()  |= 0x40;
        CKey key;
        key.Set(privkey.begin(), privkey.end(), fCompressed);
        CPubKey pubkey = key.GetPubKey();
        assert(key.VerifyPubKey(pubkey));
        CKeyID vchAddress = pubkey.GetID();

        ret.push_back(Pair("address", EncodeDestination(vchAddress)));
        ret.push_back(Pair("pubkey", HexStr(pubkey)));
        ret.push_back(Pair("privkey", HexStr(privkey)));
        ret.push_back(Pair("wif", EncodeSecret(key)));
    } else {
        /* seems it's a wif */
        CPubKey pubkey = tempkey.GetPubKey();
        assert(tempkey.VerifyPubKey(pubkey));
        CKeyID vchAddress = pubkey.GetID();
        ret.push_back(Pair("address", EncodeDestination(vchAddress)));
        ret.push_back(Pair("pubkey", HexStr(pubkey)));
        ret.push_back(Pair("privkey", HexStr(tempkey)));
        ret.push_back(Pair("wif", strAgamaPassphrase));
    }

    return ret;
}

UniValue rescanfromheight(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 1)
        throw runtime_error(
            "rescanfromheight (height)\n"
            "\nRescans the current wallet from a specified height\n"
            "\nArguments:\n"
            "1. \"height\"      (int, optional) Defaults to 0, height to start rescanning from\n"
            "\nNote: This call can take minutes or even hours to complete on very large wallets and rescans\n"
            "\nExamples:\n"
            "\nInitiate rescan of entire chain\n"
            + HelpExampleCli("rescanfromheight", "") +
            "\nInitiate rescan from block 1000000\n"
            + HelpExampleCli("rescanfromheight", "1000000")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    uint32_t fromHeight = params.size() < 1 ? 0 : uni_get_int64(params[0]);
    if (fromHeight < chainActive.Height())
    {
        pwalletMain->ScanForWalletTransactions(chainActive[fromHeight], true);
    }
    return NullUniValue;
}

UniValue importprivkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importprivkey \"verusprivkey\" ( \"label\" rescan )\n"
            "\nAdds a private key (as returned by dumpprivkey) to your wallet.\n"
            "\nArguments:\n"
            "1. \"verusprivkey\"   (string, required) The private key (see dumpprivkey)\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nDump a private key\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"") +
            "\nImport the private key with rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\"") +
            "\nImport using a label and without rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importprivkey", "\"mykey\", \"testing\", false")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    CKey key = DecodeSecret(strSecret);
    if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");

    CPubKey pubkey = key.GetPubKey();
    assert(key.VerifyPubKey(pubkey));
    CKeyID vchAddress = pubkey.GetID();
    {
        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBook(vchAddress, strLabel, "receive");

        // Don't throw error in case a key is already there
        if (pwalletMain->HaveKey(vchAddress)) {
            return EncodeDestination(vchAddress);
        }

        pwalletMain->mapKeyMetadata[vchAddress].nCreateTime = 1;

        if (!pwalletMain->AddKeyPubKey(key, pubkey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        // whenever a key is imported, we need to scan the whole chain
        pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value'

        if (fRescan) {
            pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true);
        }
    }

    return EncodeDestination(vchAddress);
}

UniValue importaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importaddress \"address\" ( \"label\" rescan )\n"
            "\nAdds an address or script (in hex) that can be watched as if it were in your wallet but cannot be used to spend.\n"
            "\nArguments:\n"
            "1. \"address\"          (string, required) The address\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nImport an address with rescan\n"
            + HelpExampleCli("importaddress", "\"myaddress\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("importaddress", "\"myaddress\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importaddress", "\"myaddress\", \"testing\", false")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CScript script;

    CTxDestination dest = DecodeDestination(params[0].get_str());
    if (IsValidDestination(dest)) {
        script = GetScriptForDestination(dest);
    } else if (IsHex(params[0].get_str())) {
        std::vector<unsigned char> data(ParseHex(params[0].get_str()));
        script = CScript(data.begin(), data.end());
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Verus address or script");
    }

    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    {
        if (::IsMine(*pwalletMain, script) == ISMINE_SPENDABLE)
            throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");

        // add to address book or update label
        if (IsValidDestination(dest))
            pwalletMain->SetAddressBook(dest, strLabel, "receive");

        // Don't throw error in case an address is already there
        if (pwalletMain->HaveWatchOnly(script))
            return NullUniValue;

        pwalletMain->MarkDirty();

        if (!pwalletMain->AddWatchOnly(script))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");

        if (fRescan)
        {
            pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return NullUniValue;
}

UniValue z_importwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_importwallet \"filename\"\n"
            "\nImports taddr and zaddr keys from a wallet export file (see z_exportwallet).\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The wallet file\n"
            "\nExamples:\n"
            "\nDump the wallet\n"
            + HelpExampleCli("z_exportwallet", "\"nameofbackup\"") +
            "\nImport the wallet\n"
            + HelpExampleCli("z_importwallet", "\"path/to/exportdir/nameofbackup\"") +
            "\nImport using the json rpc call\n"
            + HelpExampleRpc("z_importwallet", "\"path/to/exportdir/nameofbackup\"")
        );

	return importwallet_impl(params, fHelp, true);
}

UniValue importwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "importwallet \"filename\"\n"
            "\nImports taddr keys from a wallet dump file (see dumpwallet).\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The wallet file\n"
            "\nExamples:\n"
            "\nDump the wallet\n"
            + HelpExampleCli("dumpwallet", "\"nameofbackup\"") +
            "\nImport the wallet\n"
            + HelpExampleCli("importwallet", "\"path/to/exportdir/nameofbackup\"") +
            "\nImport using the json rpc call\n"
            + HelpExampleRpc("importwallet", "\"path/to/exportdir/nameofbackup\"")
        );

	return importwallet_impl(params, fHelp, false);
}

UniValue importwallet_impl(const UniValue& params, bool fHelp, bool fImportZKeys)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    ifstream file;
    file.open(params[0].get_str().c_str(), std::ios::in | std::ios::ate);
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    int64_t nTimeBegin = chainActive.LastTip()->GetBlockTime();

    bool fGood = true;

    int64_t nFilesize = std::max((int64_t)1, (int64_t)file.tellg());
    file.seekg(0, file.beg);

    pwalletMain->ShowProgress(_("Importing..."), 0); // show progress dialog in GUI
    while (file.good()) {
        pwalletMain->ShowProgress("", std::max(1, std::min(99, (int)(((double)file.tellg() / (double)nFilesize) * 100))));
        std::string line;
        std::getline(file, line);
        if (line.empty() || line[0] == '#')
            continue;

        std::vector<std::string> vstr;
        boost::split(vstr, line, boost::is_any_of(" "));
        if (vstr.size() < 2)
            continue;

        // Let's see if the address is a valid Zcash spending key
        if (fImportZKeys) {
            auto spendingkey = DecodeSpendingKey(vstr[0]);
            int64_t nTime = DecodeDumpTime(vstr[1]);
            // Only include hdKeypath and seedFpStr if we have both
            boost::optional<std::string> hdKeypath = (vstr.size() > 3) ? boost::optional<std::string>(vstr[2]) : boost::none;
            boost::optional<std::string> seedFpStr = (vstr.size() > 3) ? boost::optional<std::string>(vstr[3]) : boost::none;
            if (IsValidSpendingKey(spendingkey)) {
                auto addResult = boost::apply_visitor(
                    AddSpendingKeyToWallet(pwalletMain, Params().GetConsensus(), nTime, hdKeypath, seedFpStr, true), spendingkey);
                if (addResult == KeyAlreadyExists){
                    LogPrint("zrpc", "Skipping import of zaddr (key already present)\n");
                } else if (addResult == KeyNotAdded) {
                    // Something went wrong
                    fGood = false;
                }
                continue;
            } else {
                LogPrint("zrpc", "Importing detected an error: invalid spending key. Trying as a transparent key...\n");
                // Not a valid spending key, so carry on and see if it's a Verus style t-address.
            }
        }

        CKey key = DecodeSecret(vstr[0]);
        if (!key.IsValid())
            continue;
        CPubKey pubkey = key.GetPubKey();
        assert(key.VerifyPubKey(pubkey));
        CKeyID keyid = pubkey.GetID();
        if (pwalletMain->HaveKey(keyid)) {
            LogPrintf("Skipping import of %s (key already present)\n", EncodeDestination(keyid));
            continue;
        }
        int64_t nTime = DecodeDumpTime(vstr[1]);
        std::string strLabel;
        bool fLabel = true;
        for (unsigned int nStr = 2; nStr < vstr.size(); nStr++) {
            if (boost::algorithm::starts_with(vstr[nStr], "#"))
                break;
            if (vstr[nStr] == "change=1")
                fLabel = false;
            if (vstr[nStr] == "reserve=1")
                fLabel = false;
            if (boost::algorithm::starts_with(vstr[nStr], "label=")) {
                strLabel = DecodeDumpString(vstr[nStr].substr(6));
                fLabel = true;
            }
        }
        LogPrintf("Importing %s...\n", EncodeDestination(keyid));
        if (!pwalletMain->AddKeyPubKey(key, pubkey)) {
            fGood = false;
            continue;
        }
        pwalletMain->mapKeyMetadata[keyid].nCreateTime = nTime;
        if (fLabel)
            pwalletMain->SetAddressBook(keyid, strLabel, "receive");
        nTimeBegin = std::min(nTimeBegin, nTime);
    }
    file.close();
    pwalletMain->ShowProgress("", 100); // hide progress dialog in GUI

    CBlockIndex *pindex = chainActive.LastTip();

    // if the chain is less than 1000 blocks, scan the whole thing
    if (chainActive.Height() < 1000)
    {
        pindex = chainActive.Genesis();
    }
    else
    {
        while (pindex && pindex->pprev && pindex->GetBlockTime() > nTimeBegin - 7200)
            pindex = pindex->pprev;
    }

    if (!pwalletMain->nTimeFirstKey || nTimeBegin < pwalletMain->nTimeFirstKey)
        pwalletMain->nTimeFirstKey = nTimeBegin;

    LogPrintf("Rescanning last %i blocks\n", chainActive.Height() - pindex->GetHeight() + 1);
    pwalletMain->ScanForWalletTransactions(pindex, true);
    pwalletMain->MarkDirty();

    if (!fGood)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");

    return NullUniValue;
}

UniValue dumpprivkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpprivkey \"t-addr\"\n"
            "\nReveals the private key corresponding to 't-addr'.\n"
            "Then the importprivkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"t-addr\"   (string, required) The transparent address for the private key\n"
            "\nResult:\n"
            "\"key\"         (string) The private key\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"")
            + HelpExampleCli("importprivkey", "\"mykey\"")
            + HelpExampleRpc("dumpprivkey", "\"myaddress\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    std::string strAddress = params[0].get_str();
    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid transparent address");
    }
    const CKeyID *keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    CKey vchSecret;
    if (!pwalletMain->GetKey(*keyID, vchSecret)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }
    return EncodeSecret(vchSecret);
}

UniValue z_exportwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "z_exportwallet \"filename\" (omitemptytaddresses)\n"
            "\nExports all wallet keys, for taddr and zaddr, in a human-readable format.  Overwriting an existing file is not permitted.\n"
            "\nArguments:\n"
            "1. \"filename\"            (string, required) The filename, saved in folder set by verusd -exportdir option\n"
            "2. \"omitemptytaddresses\" (boolean, optional) Defaults to false. If true, export only addresses with indexed UTXOs or that control IDs in the wallet\n"
            "                                               (do not use this option without being sure that all addresses of interest are included)\n"
            "\nResult:\n"
            "\"path\"           (string) The full path of the destination file\n"
            "\nExamples:\n"
            + HelpExampleCli("z_exportwallet", "\"test\"")
            + HelpExampleRpc("z_exportwallet", "\"test\"")
        );

	return dumpwallet_impl(params, fHelp, true);
}

UniValue dumpwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "dumpwallet \"filename\" (omitemptytaddresses)\n"
            "\nDumps taddr wallet keys in a human-readable format.  Overwriting an existing file is not permitted.\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The filename, saved in folder set by verusd -exportdir option\n"
            "2. \"omitemptytaddresses\" (boolean, optional) Defaults to false. If true, export only addresses with indexed UTXOs or that control IDs in the wallet\n"
            "                                               (do not use this option without being sure that all addresses of interest are included)\n"
            "\nResult:\n"
            "\"path\"           (string) The full path of the destination file\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpwallet", "\"test\"")
            + HelpExampleRpc("dumpwallet", "\"test\"")
        );

	return dumpwallet_impl(params, fHelp, false);
}

UniValue dumpwallet_impl(const UniValue& params, bool fHelp, bool fDumpZKeys)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    boost::filesystem::path exportdir;
    try {
        exportdir = GetExportDir();
    } catch (const std::runtime_error& e) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, e.what());
    }
    if (exportdir.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot export wallet until the verusd -exportdir option has been set");
    }

    std::string unclean = params[0].get_str();
    std::string clean = SanitizeFilename(unclean);
    if (clean.compare(unclean) != 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Filename is invalid as only alphanumeric characters are allowed.  Try '%s' instead.", clean));
    }
    boost::filesystem::path exportfilepath = exportdir / clean;

    if (boost::filesystem::exists(exportfilepath)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot overwrite existing file " + exportfilepath.string());
    }

    ofstream file;
    file.open(exportfilepath.string().c_str());
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    // this will discard (not export) any addresses that have had UTXOs in the past and now have no UTXOs. new addresses that never had UTXOs are expected to be there for a reason
    // and may have been given to someone for a future payment
    bool omitEmptyAddresses = false;
    if (params.size() > 1)
    {
        omitEmptyAddresses = uni_get_bool(params[1]);
    }

    std::map<CKeyID, int64_t> mapKeyBirth;
    std::set<CKeyID> setKeyPool;
    pwalletMain->GetKeyBirthTimes(mapKeyBirth);
    pwalletMain->GetAllReserveKeys(setKeyPool);

    // sort time/key pairs
    std::vector<std::pair<int64_t, CKeyID> > vKeyBirth;
    for (std::map<CKeyID, int64_t>::const_iterator it = mapKeyBirth.begin(); it != mapKeyBirth.end(); it++) {
        vKeyBirth.push_back(std::make_pair(it->second, it->first));
    }
    mapKeyBirth.clear();
    std::sort(vKeyBirth.begin(), vKeyBirth.end());

    // produce output
    file << strprintf("# Wallet dump created by Verus %s (%s)\n", CLIENT_BUILD, CLIENT_DATE);
    file << strprintf("# * Created on %s\n", EncodeDumpTime(GetTime()));
    file << strprintf("# * Best block at time of backup was %i (%s),\n", chainActive.Height(), chainActive.Tip()->GetBlockHash().ToString());
    file << strprintf("#   mined on %s\n", EncodeDumpTime(chainActive.Tip()->GetBlockTime()));
    {
        HDSeed hdSeed;
        pwalletMain->GetHDSeed(hdSeed);
        auto rawSeed = hdSeed.RawSeed();
        file << strprintf("# HDSeed=%s fingerprint=%s", HexStr(rawSeed.begin(), rawSeed.end()), hdSeed.Fingerprint().GetHex());
        file << "\n";
    }
    file << "\n";

    std::set<CKeyID> idAddresses;
    std::set<CKeyID> utxoAddresses;

    idAddresses = pwalletMain->GetIdentityKeyIDs();
    utxoAddresses = pwalletMain->GetTransactionDestinationIDs();

    for (std::vector<std::pair<int64_t, CKeyID> >::const_iterator it = vKeyBirth.begin(); it != vKeyBirth.end(); it++) {
        const CKeyID &keyid = it->second;
        std::string strTime = EncodeDumpTime(it->first);
        std::string strAddr = EncodeDestination(keyid);
        bool emptyAddr = true;
        CKey key;
        if (pwalletMain->GetKey(keyid, key)) {
            if (utxoAddresses.count(keyid))
            {
                strAddr = strAddr + ", +UTXO(s)";
                emptyAddr = false;
            }

            if (idAddresses.count(keyid))
            {
                strAddr = strAddr + ", +ID(s)";
                emptyAddr = false;
            }

            if (!omitEmptyAddresses || !emptyAddr)
            {
                if (pwalletMain->mapAddressBook.count(keyid)) {
                    file << strprintf("%s %s label=%s # addr=%s\n", EncodeSecret(key), strTime, EncodeDumpString(pwalletMain->mapAddressBook[keyid].name), strAddr);
                } else if (setKeyPool.count(keyid)) {
                    file << strprintf("%s %s reserve=1 # addr=%s\n", EncodeSecret(key), strTime, strAddr);
                } else {
                    file << strprintf("%s %s change=1 # addr=%s\n", EncodeSecret(key), strTime, strAddr);
                }
            }
        }
    }
    file << "\n";

    if (fDumpZKeys) {
        std::set<libzcash::SproutPaymentAddress> sproutAddresses;
        pwalletMain->GetSproutPaymentAddresses(sproutAddresses);
        file << "\n";
        file << "# Zkeys\n";
        file << "\n";
        for (auto addr : sproutAddresses) {
            libzcash::SproutSpendingKey key;
            if (pwalletMain->GetSproutSpendingKey(addr, key)) {
                std::string strTime = EncodeDumpTime(pwalletMain->mapSproutZKeyMetadata[addr].nCreateTime);
                file << strprintf("%s %s # zaddr=%s\n", EncodeSpendingKey(key), strTime, EncodePaymentAddress(addr));
            }
        }
        std::set<libzcash::SaplingPaymentAddress> saplingAddresses;
        pwalletMain->GetSaplingPaymentAddresses(saplingAddresses);
        file << "\n";
        file << "# Sapling keys\n";
        file << "\n";
        for (auto addr : saplingAddresses) {
            libzcash::SaplingExtendedSpendingKey extsk;
            if (pwalletMain->GetSaplingExtendedSpendingKey(addr, extsk)) {
                auto ivk = extsk.expsk.full_viewing_key().in_viewing_key();
                CKeyMetadata keyMeta = pwalletMain->mapSaplingZKeyMetadata[ivk];
                std::string strTime = EncodeDumpTime(keyMeta.nCreateTime);
                // Keys imported with z_importkey do not have zip32 metadata
                if (keyMeta.hdKeypath.empty() || keyMeta.seedFp.IsNull()) {
                    file << strprintf("%s %s # zaddr=%s\n", EncodeSpendingKey(extsk), strTime, EncodePaymentAddress(addr));
                } else {
                    file << strprintf("%s %s %s %s # zaddr=%s\n", EncodeSpendingKey(extsk), strTime, keyMeta.hdKeypath, keyMeta.seedFp.GetHex(), EncodePaymentAddress(addr));
                }
            }
        }
        file << "\n";
    }

    file << "# End of dump\n";
    file.close();

    return exportfilepath.string();
}


UniValue z_importkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "z_importkey \"zkey\" ( rescan startHeight )\n"
            "\nAdds a zkey (as returned by z_exportkey) to your wallet.\n"
            "\nArguments:\n"
            "1. \"zkey\"             (string, required) The zkey (see z_exportkey)\n"
            "2. rescan               (string, optional, default=\"whenkeyisnew\") Rescan the wallet for transactions - can be \"yes\", \"no\" or \"whenkeyisnew\"\n"
            "3. startHeight          (numeric, optional, default=0) Block height to start rescan from\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nResult:\n"
            "{\n"
            "  \"type\" : \"xxxx\",                         (string) \"sprout\" or \"sapling\"\n"
            "  \"address\" : \"address|DefaultAddress\",    (string) The address corresponding to the spending key (for Sapling, this is the default address).\n"
            "}\n"
            "\nExamples:\n"
            "\nExport a zkey\n"
            + HelpExampleCli("z_exportkey", "\"myaddress\"") +
            "\nImport the zkey with rescan\n"
            + HelpExampleCli("z_importkey", "\"mykey\"") +
            "\nImport the zkey with partial rescan\n"
            + HelpExampleCli("z_importkey", "\"mykey\" whenkeyisnew 30000") +
            "\nRe-import the zkey with longer partial rescan\n"
            + HelpExampleCli("z_importkey", "\"mykey\" yes 20000") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("z_importkey", "\"mykey\", \"no\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    // Whether to perform rescan after import
    bool fRescan = true;
    bool fIgnoreExistingKey = true;
    if (params.size() > 1) {
        auto rescan = params[1].get_str();
        if (rescan.compare("whenkeyisnew") != 0) {
            fIgnoreExistingKey = false;
            if (rescan.compare("yes") == 0) {
                fRescan = true;
            } else if (rescan.compare("no") == 0) {
                fRescan = false;
            } else {
                // Handle older API
                UniValue jVal;
                if (!jVal.read(std::string("[")+rescan+std::string("]")) ||
                    !jVal.isArray() || jVal.size()!=1 || !jVal[0].isBool()) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "rescan must be \"yes\", \"no\" or \"whenkeyisnew\"");
                }
                fRescan = jVal[0].getBool();
            }
        }
    }

    // Height to rescan from
    int nRescanHeight = 0;
    if (params.size() > 2)
        nRescanHeight = params[2].get_int();
    if (nRescanHeight < 0 || nRescanHeight > chainActive.Height()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
    }

    string strSecret = params[0].get_str();
    auto spendingkey = DecodeSpendingKey(strSecret);
    if (!IsValidSpendingKey(spendingkey)) {
        bool success = false;
        if (IsHex(strSecret))
        {
            std::vector<unsigned char> data = ParseHex(strSecret);

            // if we should be deserializing an extended spending key, do it
            if (data.size() == 169)
            {
                libzcash::SaplingExtendedSpendingKey sxSK;
                ::FromVector(data, sxSK);
                memory_cleanse(data.data(), data.size());
                spendingkey = sxSK;
            }
            else
            {
                std::vector<unsigned char, secure_allocator<unsigned char>> vch(data.begin(), data.end());
                memory_cleanse(data.data(), data.size());

                if (vch.size() != 32 && vch.size() != 64)
                {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid hex spending key");
                }

                HDSeed seed(vch);

                // Derive the address for Sapling account 0
                auto m = libzcash::SaplingExtendedSpendingKey::Master(seed);
                uint32_t bip44CoinType = Params().BIP44CoinType();

                // We use a fixed keypath scheme of m/32'/coin_type'/account'
                // Derive m/32'
                auto m_32h = m.Derive(32 | ZIP32_HARDENED_KEY_LIMIT);

                // Derive m/32'/coin_type'
                auto m_32h_cth = m_32h.Derive(bip44CoinType | ZIP32_HARDENED_KEY_LIMIT);

                // Derive m/32'/coin_type'/0'
                libzcash::SaplingExtendedSpendingKey xsk = m_32h_cth.Derive(0 | ZIP32_HARDENED_KEY_LIMIT);
                spendingkey = xsk;
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid spending key");
        }
    }

    auto addrInfo = boost::apply_visitor(libzcash::AddressInfoFromSpendingKey{}, spendingkey);
    UniValue result(UniValue::VOBJ);
    result.pushKV("type", addrInfo.first);
    result.pushKV("address", EncodePaymentAddress(addrInfo.second));

    // Sapling support
    auto addResult = boost::apply_visitor(AddSpendingKeyToWallet(pwalletMain, Params().GetConsensus()), spendingkey);
    if (addResult == KeyAlreadyExists && fIgnoreExistingKey) {
        return result;
    }
    pwalletMain->MarkDirty();
    if (addResult == KeyNotAdded) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding spending key to wallet");
    }

    // whenever a key is imported, we need to scan the whole chain
    pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value'

    // We want to scan for transactions and notes
    if (fRescan) {
        pwalletMain->ScanForWalletTransactions(chainActive[nRescanHeight], true);
    }

    return result;
}

UniValue z_getencryptionaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1 || !params[0].isObject())
        throw runtime_error(
            "z_getencryptionaddress '{(\"address\":\"zaddress present in wallet\" | \"seed\":\"wallet seed for address\", \"hdindex\":n - address to derive from seed | \"rootkey\":\"extended private key\"),\n"
            "                          \"fromid\":\"id@ or i-address\",\n"
            "                          \"toid\":\"id@ or i-address\",\n"
            "                          \"returnsecret\": true | false}'\n"
            "\nReturns z-address, viewing key, and optionally an extended secret key.\n"
            "\nArguments:\n"
            "   \"address\"          (string, optional) z-address that is present in this wallet\n"
            "   \"seed\"             (string, optional) raw wallet seed\n"
            "   \"hdindex\"          (number, optional) address to derive from seed (default=0)\n"
            "   \"rootkey\"          (string, optional) extended private key\n"
            "   \"fromid\"           (string, optional) a key to be used between the fromid and the toid\n"
            "   \"toid\"             (string, optional) a key to be used between the fromid and the toid\n"
            "   \"encryptionindex\"  (number, optional) can be used as an index to derive the final encryption HD address from the derived seed (default=0)\n"
            "   \"returnsecret\"     (bool, optional) if true, returns extended private key - defaults to false\n"
            "\n"
            "\nResult:\n"
            "{\n"
            "  \"extendedviewingkey\" : \"evk\",            (string) \"sapling\" extended viewing key\n"
            "  \"address\" : \"encryptionaddress\",         (string) The encryption address derived\n"
            "  \"extendedspendingkey\" : \"encryptionaddress\", (string) Spending key for the address, if requested\n"
            "}\n"
            "\nExamples:\n"
            "\nExample1 description\n"
            + HelpExampleCli("z_getencryptionaddress", "'{\"address\":\"localzaddress\",\"fromid\":\"bob@\",\"toid\":\"alice@\"}") +
            "\nExample2 description\n"
            + HelpExampleCli("z_getencryptionaddress", "'{\"address\":\"localzaddress\",\"fromid\":\"bob@\",\"toid\":\"alice@\"}") +
            "\nExample3 description\n"
            + HelpExampleCli("z_getencryptionaddress", "'{\"address\":\"localzaddress\",\"fromid\":\"bob@\",\"toid\":\"alice@\"}") +
            "\nExample4 description\n"
            + HelpExampleRpc("z_getencryptionaddress", "'{\"address\":\"localzaddress\",\"fromid\":\"bob@\",\"toid\":\"alice@\"}")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // parse parameters
    std::string strAddress = uni_get_str(find_value(params[0], "address"));
    std::string strSeed = uni_get_str(find_value(params[0], "seed"));
    std::string strRootkey = uni_get_str(find_value(params[0], "rootkey"));
    int64_t hdIndex = uni_get_int64(find_value(params[0], "hdindex"));
    int64_t encryptionIndex = uni_get_int64(find_value(params[0], "encryptionindex"));
    CIdentityID fromID = GetDestinationID(DecodeDestination(uni_get_str(find_value(params[0], "fromid"))));
    CIdentityID toID = GetDestinationID(DecodeDestination(uni_get_str(find_value(params[0], "toid"))));
    bool returnSecret = uni_get_bool(find_value(params[0], "returnsecret"));

    if (((int)strAddress.empty() + (int)strSeed.empty() + (int)strRootkey.empty()) != 2)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Must provide one and only one of either a valid Sapling address from this wallet, a valid wallet seed, or a root Sapling extended key to use as a base for the encryption address");
    }

    if (hdIndex != 0 && strSeed.empty())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "if \"hdindex\" is present, seed must be an HD wallet seed for which \"hdindex\" represents a valid address index" + to_string(ZIP32_HARDENED_KEY_LIMIT - 1));
    }

    if (encryptionIndex < 0 || encryptionIndex >= ZIP32_HARDENED_KEY_LIMIT)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "if present, \"encryptionindex\" must be an index between 0 and " + to_string(ZIP32_HARDENED_KEY_LIMIT - 1));
    }

    libzcash::SaplingExtendedSpendingKey baseSpendingKey;
    libzcash::SaplingSpendingKey encryptionSpendingKey;
    libzcash::SaplingPaymentAddress encryptionAddress;
    libzcash::SaplingExtendedFullViewingKey viewingKey;

    // if we are expected to get the secret key from a local wallet, make sure we have access to it
    if (!strAddress.empty())
    {
        EnsureWalletIsAvailable(false);
        EnsureWalletIsUnlocked();

        // get the secret extended key from the wallet
        libzcash::PaymentAddress address;
        pwalletMain->GetAndValidateSaplingZAddress(strAddress, address, true);
        encryptionAddress = boost::get<libzcash::SaplingPaymentAddress>(address);
    
        if (!pwalletMain->GetSaplingExtendedSpendingKey(encryptionAddress, baseSpendingKey))
        {
            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not hold private zkey for the specified address");
        }
    }
    else if (!strSeed.empty())
    {
        if (hdIndex < 0 || hdIndex >= ZIP32_HARDENED_KEY_LIMIT)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "if present, \"hdindex\" must be an index between 0 and " + to_string(ZIP32_HARDENED_KEY_LIMIT - 1));
        }
        else
        {
            if (!IsHex(strSeed))
            {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Seed for encryption address must be in hex and represent a 32 or 64 byte value");
            }

            std::vector<unsigned char> data = ParseHex(strSeed);
            std::vector<unsigned char, secure_allocator<unsigned char>> vch(data.begin(), data.end());
            memory_cleanse(data.data(), data.size());

            if (vch.size() != 32 && vch.size() != 64)
            {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid hex spending key - must represent a 32 or 64 byte value");
            }

            HDSeed seed(vch);

            // Derive the address for Sapling account 0
            auto m = libzcash::SaplingExtendedSpendingKey::Master(seed);
            uint32_t bip44CoinType = Params().BIP44CoinType();

            // We use a fixed keypath scheme of m/32'/coin_type'/account'
            // Derive m/32'
            auto m_32h = m.Derive(32 | ZIP32_HARDENED_KEY_LIMIT);

            // Derive m/32'/coin_type'
            auto m_32h_cth = m_32h.Derive(bip44CoinType | ZIP32_HARDENED_KEY_LIMIT);

            // Derive m/32'/coin_type'/0'
            baseSpendingKey = m_32h_cth.Derive((uint32_t)hdIndex | ZIP32_HARDENED_KEY_LIMIT);
        }
    }
    else
    {
        libzcash::SpendingKey genericSpendingKey;
        genericSpendingKey = DecodeSpendingKey(strRootkey);
        if (!IsValidSpendingKey(genericSpendingKey)) {
            bool success = false;
            if (IsHex(strRootkey))
            {
                std::vector<unsigned char> data = ParseHex(strRootkey);
                bool success = false;

                // if we should be deserializing an extended spending key, do it
                if (data.size() == 169)
                {
                    ::FromVector(data, baseSpendingKey, &success);
                    memory_cleanse(data.data(), data.size());
                }
                if (!success)
                {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid hex root key");
                }
            }
            else
            {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid root key");
            }
        }
        else
        {
            libzcash::SpendingKey testWhich = baseSpendingKey;
            if (genericSpendingKey.which() != testWhich.which())
            {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Root key must be valid Sapling spending key");
            }
            baseSpendingKey = boost::get<libzcash::SaplingExtendedSpendingKey>(genericSpendingKey);
        }
    }

    // now use the base spending key along with from and to addresses to derive encryption key
    uint256 derivedEncryptionSeed;

    CHashWriterSHA256 hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << baseSpendingKey;
    if (!fromID.IsNull())
    {
        hw << fromID;
    }
    if (!toID.IsNull())
    {
        hw << toID;
    }
    derivedEncryptionSeed = hw.GetHash();

    libzcash::SaplingExtendedSpendingKey esk;

    std::vector<unsigned char, secure_allocator<unsigned char>> vch(derivedEncryptionSeed.begin(), derivedEncryptionSeed.end());
    memory_cleanse(derivedEncryptionSeed.begin(), derivedEncryptionSeed.size());

    HDSeed seed(vch);

    // Derive the address for Sapling account 0
    auto m = libzcash::SaplingExtendedSpendingKey::Master(seed);
    uint32_t bip44CoinType = Params().BIP44CoinType();

    // We use a fixed keypath scheme of m/32'/coin_type'/account'
    // Derive m/32'
    auto m_32h = m.Derive(32 | ZIP32_HARDENED_KEY_LIMIT);

    // Derive m/32'/coin_type'
    auto m_32h_cth = m_32h.Derive(bip44CoinType | ZIP32_HARDENED_KEY_LIMIT);

    // Derive m/32'/coin_type'/0'
    libzcash::SaplingExtendedSpendingKey xsk = m_32h_cth.Derive(encryptionIndex | ZIP32_HARDENED_KEY_LIMIT);

    UniValue result(UniValue::VOBJ);

    result.pushKV("address", EncodePaymentAddress(xsk.DefaultAddress()));
    result.pushKV("extendedviewingkey", EncodeViewingKey(xsk.ToXFVK()));
    if (returnSecret)
    {
        result.pushKV("extendedspendingkey", EncodeSpendingKey(xsk));
    }
    return result;
}

UniValue z_importviewingkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "z_importviewingkey \"vkey\" ( rescan startHeight )\n"
            "\nAdds a viewing key (as returned by z_exportviewingkey) to your wallet.\n"
            "\nArguments:\n"
            "1. \"vkey\"             (string, required) The viewing key (see z_exportviewingkey)\n"
            "2. rescan             (string, optional, default=\"whenkeyisnew\") Rescan the wallet for transactions - can be \"yes\", \"no\" or \"whenkeyisnew\"\n"
            "3. startHeight        (numeric, optional, default=0) Block height to start rescan from\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nResult:\n"
            "{\n"
            "  \"type\" : \"xxxx\",                         (string) \"sprout\" or \"sapling\"\n"
            "  \"address\" : \"address|DefaultAddress\",    (string) The address corresponding to the viewing key (for Sapling, this is the default address).\n"
            "}\n"
            "\nExamples:\n"
            "\nImport a viewing key\n"
            + HelpExampleCli("z_importviewingkey", "\"vkey\"") +
            "\nImport the viewing key without rescan\n"
            + HelpExampleCli("z_importviewingkey", "\"vkey\", no") +
            "\nImport the viewing key with partial rescan\n"
            + HelpExampleCli("z_importviewingkey", "\"vkey\" whenkeyisnew 30000") +
            "\nRe-import the viewing key with longer partial rescan\n"
            + HelpExampleCli("z_importviewingkey", "\"vkey\" yes 20000") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("z_importviewingkey", "\"vkey\", \"no\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    // Whether to perform rescan after import
    bool fRescan = true;
    bool fIgnoreExistingKey = true;
    if (params.size() > 1) {
        auto rescan = params[1].get_str();
        if (rescan.compare("whenkeyisnew") != 0) {
            fIgnoreExistingKey = false;
            if (rescan.compare("no") == 0) {
                fRescan = false;
            } else if (rescan.compare("yes") != 0) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "rescan must be \"yes\", \"no\" or \"whenkeyisnew\"");
            }
        }
    }

    // Height to rescan from
    int nRescanHeight = 0;
    if (params.size() > 2) {
        nRescanHeight = params[2].get_int();
    }
    if (nRescanHeight < 0 || nRescanHeight > chainActive.Height()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
    }

    string strVKey = params[0].get_str();
    auto viewingkey = DecodeViewingKey(strVKey);
    if (!IsValidViewingKey(viewingkey)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid viewing key");
    }

    auto addrInfo = boost::apply_visitor(libzcash::AddressInfoFromViewingKey{}, viewingkey);
    UniValue result(UniValue::VOBJ);
    result.pushKV("type", addrInfo.first);
    result.pushKV("address", EncodePaymentAddress(addrInfo.second));

    auto addResult = boost::apply_visitor(AddViewingKeyToWallet(pwalletMain), viewingkey);
    if (addResult == SpendingKeyExists) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "The wallet already contains the private key for this viewing key");
    } else if (addResult == KeyAlreadyExists && fIgnoreExistingKey) {
        return result;
    }
    pwalletMain->MarkDirty();
    if (addResult == KeyNotAdded) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding viewing key to wallet");
    }

    // We want to scan for transactions and notes
    if (fRescan) {
        pwalletMain->ScanForWalletTransactions(chainActive[nRescanHeight], true);
    }

    return result;
}

UniValue z_exportkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || (params.size() < 1 && params.size() > 2))
        throw runtime_error(
            "z_exportkey \"zaddr\" (outputashex)\n"
            "\nReveals the zkey corresponding to 'zaddr'.\n"
            "Then the z_importkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"zaddr\"   (string, required) The zaddr for the private key\n"
            "2. \"outputashex\" (boolean, optional, default=false) If true, output key data as hex bytes\n"
            "\nResult:\n"
            "\"key\"                  (string) The private key\n"
            "\nExamples:\n"
            + HelpExampleCli("z_exportkey", "\"myaddress\"")
            + HelpExampleCli("z_importkey", "\"mykey\"")
            + HelpExampleRpc("z_exportkey", "\"myaddress\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();

    auto address = DecodePaymentAddress(strAddress);

    libzcash::PaymentAddress zaddress;
    if (pwalletMain->GetAndValidateSaplingZAddress(strAddress, zaddress))
    {
        address = zaddress;
    }

    if (!IsValidPaymentAddress(address)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zaddr");
    }

    // Sapling support
    auto sk = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), address);
    if (!sk) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not hold private zkey for this zaddr");
    }
    if (params.size() > 1 && uni_get_bool(params[1]) && sk.get().which() == 2)
    {
        boost::optional<libzcash::SaplingExtendedSpendingKey> sxSK = boost::get<libzcash::SaplingExtendedSpendingKey>(sk.get());
        if (sxSK)
        {
            std::vector<unsigned char> vch = ::AsVector(sxSK.get());
            return HexBytes(&(vch[0]), vch.size());
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot only return hex encoding for sapling addresses or later");
        }
    }
    else
    {
        return EncodeSpendingKey(sk.get());
    }
}

UniValue z_exportviewingkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_exportviewingkey \"zaddr\"\n"
            "\nReveals the viewing key corresponding to 'zaddr'.\n"
            "Then the z_importviewingkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"zaddr\"   (string, required) The zaddr for the viewing key\n"
            "\nResult:\n"
            "\"vkey\"                  (string) The viewing key\n"
            "\nExamples:\n"
            + HelpExampleCli("z_exportviewingkey", "\"myaddress\"")
            + HelpExampleRpc("z_exportviewingkey", "\"myaddress\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();

    auto address = DecodePaymentAddress(strAddress);

    libzcash::PaymentAddress zaddress;
    if (pwalletMain->GetAndValidateSaplingZAddress(strAddress, zaddress))
    {
        address = zaddress;
    }

    if (!IsValidPaymentAddress(address)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zaddr");
    }

    auto vk = boost::apply_visitor(GetViewingKeyForPaymentAddress(pwalletMain), address);
    if (vk) {
        return EncodeViewingKey(vk.get());
    } else {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not hold private key or viewing key for this zaddr");
    }
}

