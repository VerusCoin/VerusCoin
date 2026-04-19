// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "asyncrpcoperation_sendmany.h"

#include "amount.h"
#include "asyncrpcoperation_common.h"
#include "asyncrpcqueue.h"
#include "consensus/upgrades.h"
#include "core_io.h"
#include "init.h"
#include "key_io.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet.h"
#include "walletdb.h"
#include "script/interpreter.h"
#include "utiltime.h"
#include "zcash/IncrementalMerkleTree.hpp"
#include "sodium.h"
#include "miner.h"
#include "wallet/paymentdisclosuredb.h"

#include <stdint.h>

#include <array>
#include <iostream>
#include <chrono>
#include <thread>
#include <string>
#include <set>

using namespace libzcash;

extern char ASSETCHAINS_SYMBOL[65];
extern uint160 ASSETCHAINS_CHAINID;

extern UniValue signrawtransaction(const UniValue& params, bool fHelp);
extern UniValue sendrawtransaction(const UniValue& params, bool fHelp);

int find_output(UniValue obj, int n) {
    UniValue outputMapValue = find_value(obj, "outputmap");
    if (!outputMapValue.isArray()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing outputmap for JoinSplit operation");
    }

    UniValue outputMap = outputMapValue.get_array();
    assert(outputMap.size() == ZC_NUM_JS_OUTPUTS);
    for (size_t i = 0; i < outputMap.size(); i++) {
        if (outputMap[i].get_int() == n) {
            return i;
        }
    }

    throw std::logic_error("n is not present in outputmap");
}

AsyncRPCOperation_sendmany::AsyncRPCOperation_sendmany(
        boost::optional<TransactionBuilder> builder,
        CMutableTransaction contextualTx,
        std::string fromAddress,
        std::vector<SendManyRecipient> tOutputs,
        std::vector<SendManyRecipient> zOutputs,
        int minDepth,
        CAmount fee,
        UniValue contextInfo,
        bool fromsendcurrency) :
        tx_(contextualTx),
        fromaddress_(fromAddress),
        t_outputs_(tOutputs),
        z_outputs_(zOutputs),
        mindepth_(minDepth),
        fee_(fee),
        contextinfo_(contextInfo),
        sendCurrency(fromsendcurrency)
{
    assert(fee_ >= 0);

    if (minDepth < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Minconf cannot be negative");
    }

    if (fromAddress.size() == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "From address parameter missing");
    }

    if (tOutputs.size() == 0 && zOutputs.size() == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No recipients");
    }

    isUsingBuilder_ = false;
    if (builder) {
        isUsingBuilder_ = true;
        builder_ = builder.get();
    }

    if (fromAddress == "*" || fromAddress == "R*" || fromAddress == "i*")
    {
        isfromtaddr_ = true;
        isfromzaddr_ = false;
        if (fromAddress == "R*")
        {
            // null t-address as wild card
            fromtaddr_ = CKeyID(uint160());
        }
        else if (fromAddress == "i*")
        {
            // null i-address is wildcard for i-address
            fromtaddr_ = CIdentityID(uint160());
        }
        else
        {
            // invalid t-address is full wildcard
            fromtaddr_ = CTxDestination();
        }
    }
    else
    {
        fromtaddr_ = DecodeDestination(fromAddress);
        isfromtaddr_ = IsValidDestination(fromtaddr_);
        isfromzaddr_ = false;
    }

    if (!isfromtaddr_) {
        auto address = DecodePaymentAddress(fromAddress);
        if (IsValidPaymentAddress(address)) {
            // We don't need to lock on the wallet as spending key related methods are thread-safe
            if (!boost::apply_visitor(HaveSpendingKeyForPaymentAddress(pwalletMain), address)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address, no spending key found for zaddr");
            }

            isfromzaddr_ = true;
            frompaymentaddress_ = address;
            spendingkey_ = boost::apply_visitor(GetSpendingKeyForPaymentAddress(pwalletMain), address).get();
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address");
        }
    }

    if (isfromzaddr_ && minDepth==0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Minconf cannot be zero when sending from zaddr");
    }

    // Log the context info i.e. the call parameters to z_sendmany
    if (LogAcceptCategory("zrpcunsafe")) {
        LogPrint("zrpcunsafe", "%s: z_sendmany initialized (params=%s)\n", getId(), contextInfo.write());
    } else {
        LogPrint("zrpc", "%s: z_sendmany initialized\n", getId());
    }

    // Enable payment disclosure if requested
    paymentDisclosureMode = fExperimentalMode && GetBoolArg("-paymentdisclosure", false);
}

AsyncRPCOperation_sendmany::~AsyncRPCOperation_sendmany() {
}

void AsyncRPCOperation_sendmany::main() {
    if (isCancelled())
        return;

    set_state(OperationStatus::EXECUTING);
    start_execution_clock();

    bool success = false;

#ifdef ENABLE_MINING
#ifdef ENABLE_WALLET
    GenerateBitcoins(false, NULL, 0);
#else
    GenerateBitcoins(false, 0);
#endif
#endif

    try {
        success = main_impl();
    } catch (const UniValue& objError) {
        int code = find_value(objError, "code").get_int();
        std::string message = find_value(objError, "message").get_str();
        set_error_code(code);
        set_error_message(message);
    } catch (const runtime_error& e) {
        set_error_code(-1);
        set_error_message("runtime error: " + string(e.what()));
    } catch (const logic_error& e) {
        set_error_code(-1);
        set_error_message("logic error: " + string(e.what()));
    } catch (const exception& e) {
        set_error_code(-1);
        set_error_message("general exception: " + string(e.what()));
    } catch (...) {
        set_error_code(-2);
        set_error_message("unknown error");
    }

#ifdef ENABLE_MINING
  #ifdef ENABLE_WALLET
    GenerateBitcoins(GetBoolArg("-gen",false), pwalletMain, GetArg("-genproclimit", 0));
  #else
    GenerateBitcoins(GetBoolArg("-gen",false), GetArg("-genproclimit", 0));
  #endif
#endif

    stop_execution_clock();

    if (success) {
        set_state(OperationStatus::SUCCESS);
    } else {
        set_state(OperationStatus::FAILED);
    }

    std::string s = strprintf("%s: %s finished (status=%s", getId(), sendCurrency ? "sendcurrency" : "z_sendmany", getStateAsString());
    if (success) {
        s += strprintf(", txid=%s)\n", tx_.GetHash().ToString());
    } else {
        s += strprintf(", error=%s)\n", getErrorMessage());
    }
    LogPrintf("%s",s);

    // !!! Payment disclosure START
    if (success && paymentDisclosureMode && paymentDisclosureData_.size()>0) {
        uint256 txidhash = tx_.GetHash();
        std::shared_ptr<PaymentDisclosureDB> db = PaymentDisclosureDB::sharedInstance();
        for (PaymentDisclosureKeyInfo p : paymentDisclosureData_) {
            p.first.hash = txidhash;
            if (!db->Put(p.first, p.second)) {
                LogPrint("paymentdisclosure", "%s: Payment Disclosure: Error writing entry to database for key %s\n", getId(), p.first.ToString());
            } else {
                LogPrint("paymentdisclosure", "%s: Payment Disclosure: Successfully added entry to database for key %s\n", getId(), p.first.ToString());
            }
        }
    }
    // !!! Payment disclosure END
}

// Notes:
// 1. #1159 Currently there is no limit set on the number of joinsplits, so size of tx could be invalid.
// 2. #1360 Note selection is not optimal
// 3. #1277 Spendable notes are not locked, so an operation running in parallel could also try to use them
bool AsyncRPCOperation_sendmany::main_impl() {

    assert(isfromtaddr_ != isfromzaddr_);

    bool isSingleZaddrOutput = (t_outputs_.size()==0 && z_outputs_.size()==1);
    bool isMultipleZaddrOutput = (t_outputs_.size()==0 && z_outputs_.size()>=1);
    bool isPureTaddrOnlyTx = (isfromtaddr_ && z_outputs_.size() == 0);
    CAmount minersFee = fee_;

    bool isFromSpecificID = false;

    uint32_t solutionVersion = CConstVerusSolutionVector::GetVersionByHeight(chainActive.Height() + 1);

    // figure out just how much we need before getting inputs
    CAmount t_outputs_total = 0;
    CCurrencyValueMap t_all_outputs_total;
    for (SendManyRecipient & t : t_outputs_) {
        t_outputs_total += std::get<1>(t);
        CScript outputScript = std::get<3>(t);
        if (outputScript.size())
        {
            t_all_outputs_total += outputScript.ReserveOutValue();
        }
    }

    CAmount z_outputs_total = 0;
    for (SendManyRecipient & t : z_outputs_) {
        z_outputs_total += std::get<1>(t);
    }

    CCurrencyValueMap sendAllAmounts = t_all_outputs_total;
    if (t_outputs_total + z_outputs_total)
    {
        sendAllAmounts.valueMap[ASSETCHAINS_CHAINID] = t_outputs_total + z_outputs_total;
    }

    CCurrencyValueMap targetAllAmounts = sendAllAmounts;
    targetAllAmounts.valueMap[ASSETCHAINS_CHAINID] += minersFee;
    CAmount targetNativeAmount = targetAllAmounts.valueMap[ASSETCHAINS_CHAINID];

    // When spending coinbase utxos, you can only specify a single zaddr as the change must go somewhere
    // and if there are multiple zaddrs, we don't know where to send it.
    if (isfromtaddr_) {
        if (fromtaddr_.which() == COptCCParams::ADDRTYPE_ID && !GetDestinationID(fromtaddr_).IsNull())
        {
            isFromSpecificID = true;
        }

        // if we don't need to protect coinbases, they can be included in inputs
        if (isSingleZaddrOutput || !Params().GetConsensus().fCoinbaseMustBeProtected) {
            bool b = find_utxos(true);
            if (!b) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds in UTXOs found for taddr from address.");
            }
        } else {
            bool b = find_utxos(false);
            if (!b) {
                if (isMultipleZaddrOutput) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Could not find enough UTXOs without shielding requirements to spend. Protected coinbase UTXOs can only be sent to a single zaddr recipient.");
                } else {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Could not find enough UTXOs without shielding requirements to spend.");
                }
            }
        }
    }

    if (isfromzaddr_ && !find_unspent_notes()) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, no unspent notes found for zaddr from address.");
    }

    // At least one of z_sprout_inputs_ and z_sapling_inputs_ must be empty by design
    assert(z_sprout_inputs_.empty() || z_sapling_inputs_.empty());

    CAmount t_inputs_total = 0;
    CCurrencyValueMap t_all_inputs_total;
    if (t_inputs_.size())
    {
        LOCK(pwalletMain->cs_wallet);
        for (int i = 0 ; i < t_inputs_.size(); i++)
        {
            COutput & t = t_inputs_[i];
            if (!pwalletMain->mapWallet.count(t_inputs_txids_[i]))
            {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallet transaction was deleted from wallet after selection and before tx was made.");
            }
            t_all_inputs_total += t.tx->vout[t.i].ReserveOutValue();
            t_inputs_total += t.tx->vout[t.i].nValue;
        }
    }

    if (t_inputs_total)
    {
        t_all_inputs_total.valueMap[ASSETCHAINS_CHAINID] = t_inputs_total;
    }
    //printf("Transparent funds, have %s, need %s\n", t_all_inputs_total.ToUniValue().write(1,2).c_str(), targetAllAmounts.ToUniValue().write(1,2).c_str());

    CAmount z_inputs_total = 0;
    for (SendManyInputJSOP & t : z_sprout_inputs_) {
        z_inputs_total += std::get<2>(t);
    }
    for (auto t : z_sapling_inputs_) {
        z_inputs_total += t.note.value();
    }

    assert(!isfromtaddr_ || z_inputs_total == 0);

    assert(!isfromzaddr_ || t_all_inputs_total.valueMap.size() == 0);

    if (isfromtaddr_ && (t_all_inputs_total < targetAllAmounts)) {
        if (targetAllAmounts.valueMap.size() == 1)
        {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                strprintf("Insufficient transparent funds, have %s, need %s",
                FormatMoney(t_all_inputs_total.valueMap[ASSETCHAINS_CHAINID]), FormatMoney(targetNativeAmount)));
        }
        else
        {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                strprintf("Insufficient transparent funds, have %s, need %s",
                t_all_inputs_total.ToUniValue().write(1,2), targetAllAmounts.ToUniValue().write(1,2)));
        }
    }

    if (isfromzaddr_ && targetAllAmounts.valueMap.size() > 1)
    {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Cannot send non-native currencies from shielded funds, have %s of native, need %s",
            FormatMoney(z_inputs_total), targetAllAmounts.ToUniValue().write(1,2)));
    }

    if (isfromzaddr_ && (z_inputs_total < targetNativeAmount)) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient shielded funds, have %s, need %s",
            FormatMoney(z_inputs_total), FormatMoney(targetNativeAmount)));
    }

    // If from address is a taddr, select UTXOs to spend
    CAmount selectedUTXOAmount = 0;
    bool selectedUTXOCoinbase = false;
    if (isfromtaddr_)
    {
        std::set<std::pair<const CWalletTx*, unsigned int>> setCoinsRet;
        CCurrencyValueMap reserveValueRet;
        CAmount nativeValueRet;
        bool success;

        LOCK2(cs_main, pwalletMain->cs_wallet);

        // sanity check, since we don't always hold locks
        for (int i = 0 ; i < t_inputs_.size(); i++)
        {
            auto pit = pwalletMain->mapWallet.find(t_inputs_txids_[i]);
            if (pit == pwalletMain->mapWallet.end() || t_inputs_[i].tx != &pit->second)
            {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallet transaction was deleted from wallet after selection and before tx was made.");
            }
        }

        if (targetAllAmounts.valueMap.size() == 1 && targetNativeAmount != 0)
        {
            // only native currency matters, so use simpler functon
            success =
              pwalletMain->SelectCoinsMinConf(targetNativeAmount, 0, 0, t_inputs_, setCoinsRet, nativeValueRet);
        }
        else
        {
            // select reserve currency and native inputs
            CCurrencyValueMap targetReserveAmounts = targetAllAmounts;
            targetReserveAmounts.valueMap.erase(ASSETCHAINS_CHAINID);

            /* printf("total currency:\n%s\n", t_all_inputs_total.ToUniValue().write(1,2).c_str());
            printf("target reserve:\n%s\n", targetReserveAmounts.ToUniValue().write(1,2).c_str());
            printf("target native:\n%s\n", ValueFromAmount(targetNativeAmount).write(1,2).c_str()); //*/

            success =
              pwalletMain->SelectReserveCoinsMinConf(targetReserveAmounts, targetNativeAmount, 0, 0, t_inputs_, setCoinsRet, reserveValueRet, nativeValueRet);

            /* if (success)
            {
                printf("value returned:\n%s, native: %s\n", reserveValueRet.ToUniValue().write(1,2).c_str(), ValueFromAmount(nativeValueRet).write(1,2).c_str());
                for (auto &oneOutput : setCoinsRet)
                {
                    printf("Output %s : %d, for native: %s\n    reserve: %s\n\n",
                           oneOutput.first->GetHash().GetHex().c_str(),
                           oneOutput.second,
                           ValueFromAmount(oneOutput.first->vout[oneOutput.second].nValue).write().c_str(),
                           oneOutput.first->vout[oneOutput.second].ReserveOutValue().ToUniValue().write(1,2).c_str());
                }
            }
            else
            {
                printf("%s: selection failed\n", __func__);
            } //*/
        }

        if (!success)
        {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Cannot find adequate utxos to fund transaction");
        }

        // Get dust threshold
        CKey secret;
        secret.MakeNewKey(true);
        CScript scriptPubKey = GetScriptForDestination(secret.GetPubKey().GetID());
        CTxOut out(CAmount(1), scriptPubKey);
        CAmount dustThreshold = out.GetDustThreshold(minRelayTxFee);
        CAmount dustChange = -1;

        std::vector<COutput> selectedTInputs;
        for (auto &oneInput : setCoinsRet) {
            COutput t = COutput(oneInput.first, oneInput.second, 0, true);
            if (t.tx->IsCoinBase()) {
                selectedUTXOCoinbase = true;
            }
            selectedUTXOAmount += t.tx->vout[t.i].nValue;
            selectedTInputs.push_back(t);
            if (selectedUTXOAmount >= targetNativeAmount) {
                // Select another utxo if there is change less than the dust threshold.
                dustChange = selectedUTXOAmount - targetNativeAmount;
            }
        }

        // If there is transparent change, is it valid or is it dust?
        if (dustChange < dustThreshold && dustChange != 0) {
            minersFee += dustChange;
        }

        t_inputs_ = selectedTInputs;
        t_inputs_total = selectedUTXOAmount;

        // Check mempooltxinputlimit to avoid creating a transaction which the local mempool rejects
        size_t limit = (size_t)GetArg("-mempooltxinputlimit", 0);
        {
            LOCK(cs_main);
            if (Params().GetConsensus().NetworkUpgradeActive(chainActive.Height() + 1, Consensus::UPGRADE_OVERWINTER)) {
                limit = 0;
            }
        }
        if (limit > 0) {
            size_t n = t_inputs_.size();
            if (n > limit) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Too many transparent inputs %zu > limit %zu", n, limit));
            }
        }

        // update the transaction with these inputs
        if (isUsingBuilder_)
        {
            for (COutput t : t_inputs_) {
                builder_.AddTransparentInput(COutPoint(t.tx->GetHash(), t.i), t.tx->vout[t.i].scriptPubKey, t.tx->vout[t.i].nValue);
            }
            // for Komodo, set lock time to accure interest, for other chains, set
            // locktime to spend time locked coinbases
            if (ASSETCHAINS_SYMBOL[0] == 0)
            {
                builder_.SetLockTime((uint32_t)time(NULL) - 60); // set lock time for Komodo interest
            }
        } else
        {
            CMutableTransaction rawTx(tx_);
            for (COutput & t : t_inputs_)
            {
                CTxIn in(COutPoint(t.tx->GetHash(), t.i));
                rawTx.vin.push_back(in);
            }
            if (ASSETCHAINS_SYMBOL[0] == 0)
            {
                rawTx.nLockTime = (uint32_t)time(NULL) - 60; // jl777
            }
            tx_ = CTransaction(rawTx);
        }
    }

    LogPrint((isfromtaddr_) ? "zrpc" : "zrpcunsafe", "%s: spending %s to send %s with fee %s\n",
            getId(), targetAllAmounts.ToUniValue().write(1,2), sendAllAmounts.ToUniValue().write(1,2), FormatMoney(minersFee));
    LogPrint("zrpc", "%s: transparent input: %s (to choose from)\n", getId(), FormatMoney(t_inputs_total));
    LogPrint("zrpcunsafe", "%s: private input: %s (to choose from)\n", getId(), FormatMoney(z_inputs_total));
    LogPrint("zrpc", "%s: transparent output: %s\n", getId(), FormatMoney(t_outputs_total));
    LogPrint("zrpcunsafe", "%s: private output: %s\n", getId(), FormatMoney(z_outputs_total));
    LogPrint("zrpc", "%s: fee: %s\n", getId(), FormatMoney(minersFee));

    /**
     * SCENARIO #0
     *
     * Sprout not involved, so we just use the TransactionBuilder and we're done.
     * We added the transparent inputs to the builder earlier.
     */
    if (isUsingBuilder_) {
        builder_.SetFee(minersFee);

        // Get various necessary keys
        SaplingExpandedSpendingKey expsk;
        uint256 ovk;
        if (isfromzaddr_) {
            auto sk = boost::get<libzcash::SaplingExtendedSpendingKey>(spendingkey_);
            expsk = sk.expsk;
            ovk = expsk.full_viewing_key().ovk;
        } else {
            // Sending from a t-address, which we don't have an ovk for. Instead,
            // generate a common one from the HD seed. This ensures the data is
            // recoverable, while keeping it logically separate from the ZIP 32
            // Sapling key hierarchy, which the user might not be using.
            HDSeed seed = pwalletMain->GetHDSeedForRPC();
            ovk = ovkForShieldingFromTaddr(seed);
        }

        // Set change address if we are using transparent funds
        // use fromtaddr_ if this is coming from a specified identity
        // otherwise, generate a change address
        CReserveKey keyChange(pwalletMain);
        if (isfromtaddr_ && builder_.TransparentChangeAddress().which() == COptCCParams::ADDRTYPE_INVALID) {
            LOCK2(cs_main, pwalletMain->cs_wallet);

            EnsureWalletIsUnlocked();

            CTxDestination changeAddr;

            if ((fromtaddr_.which() == COptCCParams::ADDRTYPE_ID || fromtaddr_.which() == COptCCParams::ADDRTYPE_PKH) &&
                !GetDestinationID(fromtaddr_).IsNull())
            {
                changeAddr = fromtaddr_;
            }
            else
            {
                CPubKey vchPubKey;
                bool ret = keyChange.GetReservedKey(vchPubKey);
                if (!ret) {
                    // should never fail, as we just unlocked
                    throw JSONRPCError(
                        RPC_WALLET_KEYPOOL_RAN_OUT,
                        "Could not generate a taddr to use as a change address");
                }
                changeAddr = vchPubKey.GetID();
                keyChange.KeepKey();
            }

            builder_.SendChangeTo(changeAddr);
        }

        // Select Sapling notes
        std::vector<SaplingOutPoint> ops;
        std::vector<SaplingNote> notes;
        CAmount sum = 0;
        for (auto t : z_sapling_inputs_) {
            ops.push_back(t.op);
            notes.push_back(t.note);
            sum += t.note.value();
            if (sum >= targetNativeAmount) {
                break;
            }
        }

        // Fetch Sapling anchor and witnesses
        uint256 anchor;
        std::vector<boost::optional<SaplingWitness>> witnesses;
        {
            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->GetSaplingNoteWitnesses(ops, witnesses, anchor);
        }

        // Add Sapling spends
        for (size_t i = 0; i < notes.size(); i++) {
            if (!witnesses[i]) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Missing witness for Sapling note");
            }
            builder_.AddSaplingSpend(expsk, notes[i], anchor, witnesses[i].get());
        }

        // Add Sapling outputs
        for (auto r : z_outputs_) {
            auto address = std::get<0>(r);
            auto value = std::get<1>(r);
            auto hexMemo = std::get<2>(r);

            auto addr = DecodePaymentAddress(address);
            assert(boost::get<libzcash::SaplingPaymentAddress>(&addr) != nullptr);
            auto to = boost::get<libzcash::SaplingPaymentAddress>(addr);

            auto memo = get_memo_from_hex_string(hexMemo);

            builder_.AddSaplingOutput(ovk, to, value, memo);
        }

        // Add transparent outputs
        for (auto r : t_outputs_) {
            auto amount = std::get<1>(r);
            auto script = std::get<3>(r);

            if (script.size() == 0)
            {
                auto outputAddress = std::get<0>(r);
                auto address = DecodeDestination(outputAddress);
                builder_.AddTransparentOutput(address, amount);
            }
            else
            {
                builder_.AddTransparentOutput(script, amount);
            }
        }

        // Build the transaction
        tx_ = builder_.Build(isFromSpecificID).GetTxOrThrow();

        UniValue sendResult = SendTransaction(tx_, keyChange, testmode);
        set_result(sendResult);

        return true;
    }
    /**
     * END SCENARIO #0
     */


    // Grab the current consensus branch ID
    {
        LOCK(cs_main);
        consensusBranchId_ = CurrentEpochBranchId(chainActive.Height() + 1, Params().GetConsensus());
    }

    /**
     * SCENARIO #1
     *
     * taddr -> taddrs
     *
     * There are no zaddrs or joinsplits involved.
     */
    if (isPureTaddrOnlyTx) {
        add_taddr_outputs_to_tx();

        CAmount funds = selectedUTXOAmount;
        CAmount fundsSpent = t_outputs_total + minersFee;
        CAmount change = funds - fundsSpent;

        CReserveKey keyChange(pwalletMain);
        if (change > 0) {
            add_taddr_change_output_to_tx(keyChange, change);

            LogPrint("zrpc", "%s: transparent change in transaction output (amount=%s)\n",
                    getId(),
                    FormatMoney(change)
                    );
        }

        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("rawtxn", EncodeHexTx(tx_)));
        auto txAndResult = SignSendRawTransaction(obj, keyChange, testmode);
        tx_ = txAndResult.first;
        set_result(txAndResult.second);
        return true;
    }
    /**
     * END SCENARIO #1
     */


    // Prepare raw transaction to handle JoinSplits
    CMutableTransaction mtx(tx_);
    crypto_sign_keypair(joinSplitPubKey_.begin(), joinSplitPrivKey_);
    mtx.joinSplitPubKey = joinSplitPubKey_;
    mtx.nLockTime = (uint32_t)time(NULL) - 60; // jl777
    tx_ = CTransaction(mtx);

    // Copy zinputs and zoutputs to more flexible containers
    std::deque<SendManyInputJSOP> zInputsDeque; // zInputsDeque stores minimum numbers of notes for target amount
    CAmount tmp = 0;
    for (auto o : z_sprout_inputs_) {
        zInputsDeque.push_back(o);
        tmp += std::get<2>(o);
        if (tmp >= targetNativeAmount) {
            break;
        }
    }
    std::deque<SendManyRecipient> zOutputsDeque;
    for (auto o : z_outputs_) {
        zOutputsDeque.push_back(o);
    }

    // When spending notes, take a snapshot of note witnesses and anchors as the treestate will
    // change upon arrival of new blocks which contain joinsplit transactions.  This is likely
    // to happen as creating a chained joinsplit transaction can take longer than the block interval.
    if (z_sprout_inputs_.size() > 0) {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        for (auto t : z_sprout_inputs_) {
            JSOutPoint jso = std::get<0>(t);
            std::vector<JSOutPoint> vOutPoints = { jso };
            uint256 inputAnchor;
            std::vector<boost::optional<SproutWitness>> vInputWitnesses;
            pwalletMain->GetSproutNoteWitnesses(vOutPoints, vInputWitnesses, inputAnchor);
            jsopWitnessAnchorMap[ jso.ToString() ] = WitnessAnchorData{ vInputWitnesses[0], inputAnchor };
        }
    }


    /**
     * SCENARIO #2
     *
     * taddr -> taddrs
     *       -> zaddrs
     *
     * Note: Consensus rule states that coinbase utxos can only be sent to a zaddr.
     *       Local wallet rule does not allow any change when sending coinbase utxos
     *       since there is currently no way to specify a change address and we don't
     *       want users accidentally sending excess funds to a recipient.
     */
    if (isfromtaddr_) {
        add_taddr_outputs_to_tx();

        CAmount funds = selectedUTXOAmount;
        CAmount fundsSpent = t_outputs_total + minersFee + z_outputs_total;
        CAmount change = funds - fundsSpent;

        CReserveKey keyChange(pwalletMain);
        if (change > 0) {
            if (selectedUTXOCoinbase) {
                assert(isSingleZaddrOutput);
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
                    "Change %s not allowed. When shielding coinbase funds, the wallet does not "
                    "allow any change as there is currently no way to specify a change address "
                    "in z_sendmany.", FormatMoney(change)));
            } else {
                add_taddr_change_output_to_tx(keyChange, change);
                LogPrint("zrpc", "%s: transparent change in transaction output (amount=%s)\n",
                        getId(),
                        FormatMoney(change)
                        );
            }
        }

        // Create joinsplits, where each output represents a zaddr recipient.
        UniValue obj(UniValue::VOBJ);
        while (zOutputsDeque.size() > 0) {
            AsyncJoinSplitInfo info;
            info.vpub_old = 0;
            info.vpub_new = 0;
            int n = 0;
            while (n++<ZC_NUM_JS_OUTPUTS && zOutputsDeque.size() > 0) {
                SendManyRecipient smr = zOutputsDeque.front();
                std::string address = std::get<0>(smr);
                CAmount value = std::get<1>(smr);
                std::string hexMemo = std::get<2>(smr);
                zOutputsDeque.pop_front();

                PaymentAddress pa = DecodePaymentAddress(address);
                JSOutput jso = JSOutput(boost::get<libzcash::SproutPaymentAddress>(pa), value);
                if (hexMemo.size() > 0) {
                    jso.memo = get_memo_from_hex_string(hexMemo);
                }
                info.vjsout.push_back(jso);

                // Funds are removed from the value pool and enter the private pool
                info.vpub_old += value;
            }
            obj = perform_joinsplit(info);
        }

        auto txAndResult = SignSendRawTransaction(obj, keyChange, testmode);
        tx_ = txAndResult.first;
        set_result(txAndResult.second);
        return true;
    }
    /**
     * END SCENARIO #2
     */


    /**
     * SCENARIO #3
     *
     * zaddr -> taddrs
     *       -> zaddrs
     *
     * Send to zaddrs by chaining JoinSplits together and immediately consuming any change
     * Send to taddrs by creating dummy z outputs and accumulating value in a change note
     * which is used to set vpub_new in the last chained joinsplit.
     */
    UniValue obj(UniValue::VOBJ);
    CAmount jsChange = 0;   // this is updated after each joinsplit
    int changeOutputIndex = -1; // this is updated after each joinsplit if jsChange > 0
    bool vpubNewProcessed = false;  // updated when vpub_new for miner fee and taddr outputs is set in last joinsplit
    CAmount vpubNewTarget = minersFee;
    if (t_outputs_total > 0) {
        add_taddr_outputs_to_tx();
        vpubNewTarget += t_outputs_total;
    }

    // Keep track of treestate within this transaction
    boost::unordered_map<uint256, SproutMerkleTree, CCoinsKeyHasher> intermediates;
    std::vector<uint256> previousCommitments;

    while (!vpubNewProcessed) {
        AsyncJoinSplitInfo info;
        info.vpub_old = 0;
        info.vpub_new = 0;

        CAmount jsInputValue = 0;
        uint256 jsAnchor;
        std::vector<boost::optional<SproutWitness>> witnesses;

        JSDescription prevJoinSplit;

        // Keep track of previous JoinSplit and its commitments
        if (tx_.vJoinSplit.size() > 0) {
            prevJoinSplit = tx_.vJoinSplit.back();
        }

        // If there is no change, the chain has terminated so we can reset the tracked treestate.
        if (jsChange==0 && tx_.vJoinSplit.size() > 0) {
            intermediates.clear();
            previousCommitments.clear();
        }

        //
        // Consume change as the first input of the JoinSplit.
        //
        if (jsChange > 0) {
            LOCK2(cs_main, pwalletMain->cs_wallet);

            // Update tree state with previous joinsplit
            SproutMerkleTree tree;
            auto it = intermediates.find(prevJoinSplit.anchor);
            if (it != intermediates.end()) {
                tree = it->second;
            } else if (!pcoinsTip->GetSproutAnchorAt(prevJoinSplit.anchor, tree)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Could not find previous JoinSplit anchor");
            }

            assert(changeOutputIndex != -1);
            boost::optional<SproutWitness> changeWitness;
            int n = 0;
            for (const uint256& commitment : prevJoinSplit.commitments) {
                tree.append(commitment);
                previousCommitments.push_back(commitment);
                if (!changeWitness && changeOutputIndex == n++) {
                    changeWitness = tree.witness();
                } else if (changeWitness) {
                    changeWitness.get().append(commitment);
                }
            }
            if (changeWitness) {
                    witnesses.push_back(changeWitness);
            }
            jsAnchor = tree.root();
            intermediates.insert(std::make_pair(tree.root(), tree));    // chained js are interstitial (found in between block boundaries)

            // Decrypt the change note's ciphertext to retrieve some data we need
            ZCNoteDecryption decryptor(boost::get<libzcash::SproutSpendingKey>(spendingkey_).receiving_key());
            auto hSig = prevJoinSplit.h_sig(*pzcashParams, tx_.joinSplitPubKey);
            try {
                SproutNotePlaintext plaintext = SproutNotePlaintext::decrypt(
                        decryptor,
                        prevJoinSplit.ciphertexts[changeOutputIndex],
                        prevJoinSplit.ephemeralKey,
                        hSig,
                        (unsigned char) changeOutputIndex);

                SproutNote note = plaintext.note(boost::get<libzcash::SproutPaymentAddress>(frompaymentaddress_));
                info.notes.push_back(note);

                jsInputValue += plaintext.value();

                LogPrint("zrpcunsafe", "%s: spending change (amount=%s)\n",
                    getId(),
                    FormatMoney(plaintext.value())
                    );

            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Error decrypting output note of previous JoinSplit: %s", e.what()));
            }
        }


        //
        // Consume spendable non-change notes
        //
        std::vector<SproutNote> vInputNotes;
        std::vector<JSOutPoint> vOutPoints;
        std::vector<boost::optional<SproutWitness>> vInputWitnesses;
        uint256 inputAnchor;
        int numInputsNeeded = (jsChange>0) ? 1 : 0;
        while (numInputsNeeded++ < ZC_NUM_JS_INPUTS && zInputsDeque.size() > 0) {
            SendManyInputJSOP t = zInputsDeque.front();
            JSOutPoint jso = std::get<0>(t);
            SproutNote note = std::get<1>(t);
            CAmount noteFunds = std::get<2>(t);
            zInputsDeque.pop_front();

            WitnessAnchorData wad = jsopWitnessAnchorMap[ jso.ToString() ];
            vInputWitnesses.push_back(wad.witness);
            if (inputAnchor.IsNull()) {
                inputAnchor = wad.anchor;
            } else if (inputAnchor != wad.anchor) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Selected input notes do not share the same anchor");
            }

            vOutPoints.push_back(jso);
            vInputNotes.push_back(note);

            jsInputValue += noteFunds;

            int wtxHeight = -1;
            int wtxDepth = -1;
            {
                LOCK2(cs_main, pwalletMain->cs_wallet);
                const CWalletTx& wtx = pwalletMain->mapWallet[jso.hash];
                // Zero-confirmation notes belong to transactions which have not yet been mined
                if (mapBlockIndex.find(wtx.hashBlock) == mapBlockIndex.end()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("mapBlockIndex does not contain block hash %s", wtx.hashBlock.ToString()));
                }
                wtxHeight = mapBlockIndex[wtx.hashBlock]->GetHeight();
                wtxDepth = wtx.GetDepthInMainChain();
            }
            LogPrint("zrpcunsafe", "%s: spending note (txid=%s, vJoinSplit=%d, jsoutindex=%d, amount=%s, height=%d, confirmations=%d)\n",
                    getId(),
                    jso.hash.ToString().substr(0, 10),
                    jso.js,
                    int(jso.n), // uint8_t
                    FormatMoney(noteFunds),
                    wtxHeight,
                    wtxDepth
                    );
        }

        // Add history of previous commitments to witness
        if (vInputNotes.size() > 0) {

            if (vInputWitnesses.size()==0) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Could not find witness for note commitment");
            }

            for (auto & optionalWitness : vInputWitnesses) {
                if (!optionalWitness) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Witness for note commitment is null");
                }
                SproutWitness w = *optionalWitness; // could use .get();
                if (jsChange > 0) {
                    for (const uint256& commitment : previousCommitments) {
                        w.append(commitment);
                    }
                    if (jsAnchor != w.root()) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Witness for spendable note does not have same anchor as change input");
                    }
                }
                witnesses.push_back(w);
            }

            // The jsAnchor is null if this JoinSplit is at the start of a new chain
            if (jsAnchor.IsNull()) {
                jsAnchor = inputAnchor;
            }

            // Add spendable notes as inputs
            std::copy(vInputNotes.begin(), vInputNotes.end(), std::back_inserter(info.notes));
        }

        // Find recipient to transfer funds to
        std::string address, hexMemo;
        CAmount value = 0;
        if (zOutputsDeque.size() > 0) {
            SendManyRecipient smr = zOutputsDeque.front();
            address = std::get<0>(smr);
            value = std::get<1>(smr);
            hexMemo = std::get<2>(smr);
            zOutputsDeque.pop_front();
        }

        // Reset change
        jsChange = 0;
        CAmount outAmount = value;

        // Set vpub_new in the last joinsplit (when there are no more notes to spend or zaddr outputs to satisfy)
        if (zOutputsDeque.size() == 0 && zInputsDeque.size() == 0) {
            assert(!vpubNewProcessed);
            if (jsInputValue < vpubNewTarget) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Insufficient funds for vpub_new %s (miners fee %s, taddr outputs %s)",
                    FormatMoney(vpubNewTarget), FormatMoney(minersFee), FormatMoney(t_outputs_total)));
            }
            outAmount += vpubNewTarget;
            info.vpub_new += vpubNewTarget; // funds flowing back to public pool
            vpubNewProcessed = true;
            jsChange = jsInputValue - outAmount;
            assert(jsChange >= 0);
        }
        else {
            // This is not the last joinsplit, so compute change and any amount still due to the recipient
            if (jsInputValue > outAmount) {
                jsChange = jsInputValue - outAmount;
            } else if (outAmount > jsInputValue) {
                // Any amount due is owed to the recipient.  Let the miners fee get paid first.
                CAmount due = outAmount - jsInputValue;
                SendManyRecipient r = SendManyRecipient(address, due, hexMemo, CScript());
                zOutputsDeque.push_front(r);

                // reduce the amount being sent right now to the value of all inputs
                value = jsInputValue;
            }
        }

        // create output for recipient
        if (address.empty()) {
            assert(value==0);
            info.vjsout.push_back(JSOutput());  // dummy output while we accumulate funds into a change note for vpub_new
        } else {
            PaymentAddress pa = DecodePaymentAddress(address);
            // If we are here, we know we have no Sapling outputs.
            JSOutput jso = JSOutput(boost::get<libzcash::SproutPaymentAddress>(pa), value);
            if (hexMemo.size() > 0) {
                jso.memo = get_memo_from_hex_string(hexMemo);
            }
            info.vjsout.push_back(jso);
        }

        // create output for any change
        if (jsChange>0) {
            info.vjsout.push_back(JSOutput(boost::get<libzcash::SproutPaymentAddress>(frompaymentaddress_), jsChange));

            LogPrint("zrpcunsafe", "%s: generating note for change (amount=%s)\n",
                    getId(),
                    FormatMoney(jsChange)
                    );
        }

        obj = perform_joinsplit(info, witnesses, jsAnchor);

        if (jsChange > 0) {
            changeOutputIndex = find_output(obj, 1);
        }
    }

    // Sanity check in case changes to code block above exits loop by invoking 'break'
    assert(zInputsDeque.size() == 0);
    assert(zOutputsDeque.size() == 0);
    assert(vpubNewProcessed);

    auto txAndResult = SignSendRawTransaction(obj, boost::none, testmode);
    tx_ = txAndResult.first;
    set_result(txAndResult.second);
    return true;
}

bool AsyncRPCOperation_sendmany::find_utxos(bool fAcceptProtectedCoinbase)
{
    assert(isfromtaddr_);

    std::set<CTxDestination> destinations;

    bool wildCardPKH = false;
    bool wildCardID = false;
    bool isFromSpecificID = fromtaddr_.which() == COptCCParams::ADDRTYPE_ID && !GetDestinationID(fromtaddr_).IsNull();

    // if no specific address type, wildcard outputs to all transparent addresses and IDs are valid to consider
    if (fromtaddr_.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        wildCardPKH = true;
        wildCardID = true;
    }
    // wildcard for all transparent addresses, except IDs is null PKH
    else if (fromtaddr_.which() == COptCCParams::ADDRTYPE_PKH && GetDestinationID(fromtaddr_).IsNull())
    {
        wildCardPKH = true;
    }
    // wildcard for all ID transparent outputs is null ID
    else if (fromtaddr_.which() == COptCCParams::ADDRTYPE_ID && GetDestinationID(fromtaddr_).IsNull())
    {
        wildCardID = true;
    }
    else
    {
        // public key must match pkh as an address, so store as phk if we see pk and check pkh
        if (fromtaddr_.which() == COptCCParams::ADDRTYPE_PK)
        {
            destinations.insert(CKeyID(GetDestinationID(fromtaddr_)));
        }
        else
        {
            destinations.insert(fromtaddr_);
        }
    }

    vector<COutput> vecOutputs;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (sendCurrency)
    {
        pwalletMain->AvailableReserveCoins(vecOutputs,
                                           false,
                                           NULL,
                                           true,
                                           true,
                                           wildCardPKH || wildCardID ? nullptr : &fromtaddr_,
                                           nullptr,
                                           false,
                                           true);
    }
    else
    {
        pwalletMain->AvailableCoins(vecOutputs, false, NULL, false, true, fAcceptProtectedCoinbase, false, false, true);
    }

    uint32_t nHeight = chainActive.Height();

    for (COutput& out : vecOutputs)
    {
        CTxDestination dest;

        if (!isFromSpecificID && !out.fSpendable) {
            continue;
        }

        if (out.nDepth < mindepth_) {
            continue;
        }

        if (out.nDepth > nHeight) {
            continue;
        }

        std::vector<CTxDestination> addresses;
        int nRequired;
        bool canSign, canSpend;
        CTxDestination address;
        txnouttype txType;
        if (!ExtractDestinations(out.tx->vout[out.i].scriptPubKey, txType, addresses, nRequired, pwalletMain, &canSign, &canSpend, nHeight - out.nDepth))
        {
            continue;
        }

        if (isFromSpecificID)
        {
            // if we have more address destinations than just this address and have specified from a single ID only,
            // the condition must be such that the ID itself can spend, even if this wallet cannot due to a multisig
            // ID. if the ID cannot spend, even given a valid multisig ID, then to select this as a source without
            // an explicit, multisig match would cause potentially unwanted sourcing of funds. a spend just to this ID
            // is fine.

            COptCCParams p, m;
            // if we can't spend and can only sign,
            // ensure that this output is spendable by just this ID as a 1 of n and 1 of n at the master
            // smart transaction level as well
            if (!canSpend &&
                (!canSign ||
                 !(out.tx->vout[out.i].scriptPubKey.IsPayToCryptoCondition(p) &&
                   p.IsValid() &&
                   (p.version < COptCCParams::VERSION_V3 ||
                    (p.vData.size() &&
                     (m = COptCCParams(p.vData.back())).IsValid() &&
                     (m.m == 1 || m.m == 0))) &&
                   p.m == 1)))
            {
                continue;
            }
            else
            {
                out.fSpendable = true;      // this may not really be spendable, but set it if its the correct ID source and can sign
            }
        }
        else
        {
            if (!out.fSpendable)
            {
                continue;
            }
        }

        bool keep = false;
        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
        for (auto &address : addresses)
        {
            // we check as hash, not key
            if (address.which() == COptCCParams::ADDRTYPE_PK)
            {
                address = CTxDestination(CKeyID(GetDestinationID(address)));
            }
            if (isFromSpecificID)
            {
                if (address == fromtaddr_)
                {
                    keep = true;
                }
            }
            else if (wildCardID || wildCardPKH)
            {
                if (wildCardPKH)
                {
                    keep = (address.which() == COptCCParams::ADDRTYPE_PKH || address.which() == COptCCParams::ADDRTYPE_PK) &&
                            pwalletMain->HaveKey(GetDestinationID(address));
                }
                if (!keep && wildCardID)
                {
                    keep = address.which() == COptCCParams::ADDRTYPE_ID  &&
                           pwalletMain->GetIdentity(CIdentityID(GetDestinationID(address)), keyAndIdentity) &&
                           keyAndIdentity.first.CanSign();
                }
            }
            else
            {
                keep = destinations.count(address);
            }
            if (keep)
            {
                break;
            }
        }

        if (!keep)
        {
            continue;
        }

        t_inputs_.push_back(out);
    }

    // sort in ascending order, so smaller utxos appear first
    std::sort(t_inputs_.begin(), t_inputs_.end(), [](COutput i, COutput j) -> bool {
        return ( i.tx->vout[i.i].nValue < j.tx->vout[j.i].nValue );
    });

    // get txids for verification between holding locks
    for (auto &out : t_inputs_)
    {
        t_inputs_txids_.push_back(out.tx->GetHash());
    }

    return t_inputs_.size() > 0;
}

bool AsyncRPCOperation_sendmany::find_unspent_notes() {
    std::vector<SproutNoteEntry> sproutEntries;
    std::vector<SaplingNoteEntry> saplingEntries;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        pwalletMain->GetFilteredNotes(sproutEntries, saplingEntries, fromaddress_, mindepth_);
    }

    // If using the TransactionBuilder, we only want Sapling notes.
    // If not using it, we only want Sprout notes.
    // TODO: Refactor `GetFilteredNotes()` so we only fetch what we need.
    if (isUsingBuilder_) {
        sproutEntries.clear();
    } else {
        saplingEntries.clear();
    }

    for (SproutNoteEntry & entry : sproutEntries) {
        z_sprout_inputs_.push_back(SendManyInputJSOP(entry.jsop, entry.note, CAmount(entry.note.value())));
        std::string data(entry.memo.begin(), entry.memo.end());
        LogPrint("zrpcunsafe", "%s: found unspent Sprout note (txid=%s, vJoinSplit=%d, jsoutindex=%d, amount=%s, memo=%s)\n",
            getId(),
            entry.jsop.hash.ToString().substr(0, 10),
            entry.jsop.js,
            int(entry.jsop.n),  // uint8_t
            FormatMoney(entry.note.value()),
            HexStr(data).substr(0, 10)
            );
    }

    for (auto entry : saplingEntries) {
        z_sapling_inputs_.push_back(entry);
        std::string data(entry.memo.begin(), entry.memo.end());
        LogPrint("zrpcunsafe", "%s: found unspent Sapling note (txid=%s, vShieldedSpend=%d, amount=%s, memo=%s)\n",
            getId(),
            entry.op.hash.ToString().substr(0, 10),
            entry.op.n,
            FormatMoney(entry.note.value()),
            HexStr(data).substr(0, 10));
    }

    if (z_sprout_inputs_.empty() && z_sapling_inputs_.empty()) {
        return false;
    }

    // sort in descending order, so big notes appear first
    std::sort(z_sprout_inputs_.begin(), z_sprout_inputs_.end(),
        [](SendManyInputJSOP i, SendManyInputJSOP j) -> bool {
            return std::get<2>(i) > std::get<2>(j);
        });
    std::sort(z_sapling_inputs_.begin(), z_sapling_inputs_.end(),
        [](SaplingNoteEntry i, SaplingNoteEntry j) -> bool {
            return i.note.value() > j.note.value();
        });

    return true;
}

UniValue AsyncRPCOperation_sendmany::perform_joinsplit(AsyncJoinSplitInfo & info) {
    std::vector<boost::optional < SproutWitness>> witnesses;
    uint256 anchor;
    {
        LOCK(cs_main);
        anchor = pcoinsTip->GetBestAnchor(SPROUT);    // As there are no inputs, ask the wallet for the best anchor
    }
    return perform_joinsplit(info, witnesses, anchor);
}


UniValue AsyncRPCOperation_sendmany::perform_joinsplit(AsyncJoinSplitInfo & info, std::vector<JSOutPoint> & outPoints) {
    std::vector<boost::optional < SproutWitness>> witnesses;
    uint256 anchor;
    {
        LOCK(cs_main);
        pwalletMain->GetSproutNoteWitnesses(outPoints, witnesses, anchor);
    }
    return perform_joinsplit(info, witnesses, anchor);
}

UniValue AsyncRPCOperation_sendmany::perform_joinsplit(
        AsyncJoinSplitInfo & info,
        std::vector<boost::optional < SproutWitness>> witnesses,
        uint256 anchor)
{
    if (anchor.IsNull()) {
        throw std::runtime_error("anchor is null");
    }

    if (!(witnesses.size() == info.notes.size())) {
        throw runtime_error("number of notes and witnesses do not match");
    }

    for (size_t i = 0; i < witnesses.size(); i++) {
        if (!witnesses[i]) {
            throw runtime_error("joinsplit input could not be found in tree");
        }
        info.vjsin.push_back(JSInput(*witnesses[i], info.notes[i], boost::get<libzcash::SproutSpendingKey>(spendingkey_)));
    }

    // Make sure there are two inputs and two outputs
    while (info.vjsin.size() < ZC_NUM_JS_INPUTS) {
        info.vjsin.push_back(JSInput());
    }

    while (info.vjsout.size() < ZC_NUM_JS_OUTPUTS) {
        info.vjsout.push_back(JSOutput());
    }

    if (info.vjsout.size() != ZC_NUM_JS_INPUTS || info.vjsin.size() != ZC_NUM_JS_OUTPUTS) {
        throw runtime_error("unsupported joinsplit input/output counts");
    }

    CMutableTransaction mtx(tx_);

    LogPrint("zrpcunsafe", "%s: creating joinsplit at index %d (vpub_old=%s, vpub_new=%s, in[0]=%s, in[1]=%s, out[0]=%s, out[1]=%s)\n",
            getId(),
            tx_.vJoinSplit.size(),
            FormatMoney(info.vpub_old), FormatMoney(info.vpub_new),
            FormatMoney(info.vjsin[0].note.value()), FormatMoney(info.vjsin[1].note.value()),
            FormatMoney(info.vjsout[0].value), FormatMoney(info.vjsout[1].value)
            );

    // Generate the proof, this can take over a minute.
    std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> inputs
            {info.vjsin[0], info.vjsin[1]};
    std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> outputs
            {info.vjsout[0], info.vjsout[1]};
    std::array<size_t, ZC_NUM_JS_INPUTS> inputMap;
    std::array<size_t, ZC_NUM_JS_OUTPUTS> outputMap;
    uint256 esk; // payment disclosure - secret

    assert(mtx.fOverwintered && (mtx.nVersion >= SAPLING_TX_VERSION));
    JSDescription jsdesc = JSDescription::Randomized(
            *pzcashParams,
            joinSplitPubKey_,
            anchor,
            inputs,
            outputs,
            inputMap,
            outputMap,
            info.vpub_old,
            info.vpub_new,
            !this->testmode,
            &esk); // parameter expects pointer to esk, so pass in address
    {
        auto verifier = libzcash::ProofVerifier::Strict();
        if (!(jsdesc.Verify(*pzcashParams, verifier, joinSplitPubKey_))) {
            throw std::runtime_error("error verifying joinsplit");
        }
    }

    mtx.vJoinSplit.push_back(jsdesc);

    // Empty output script.
    CScript scriptCode;
    CTransaction signTx(mtx);
    uint256 dataToBeSigned = SignatureHash(scriptCode, signTx, NOT_AN_INPUT, SIGHASH_ALL, 0, consensusBranchId_);

    // Add the signature
    if (!(crypto_sign_detached(&mtx.joinSplitSig[0], NULL,
            dataToBeSigned.begin(), 32,
            joinSplitPrivKey_
            ) == 0))
    {
        throw std::runtime_error("crypto_sign_detached failed");
    }

    // Sanity check
    if (!(crypto_sign_verify_detached(&mtx.joinSplitSig[0],
            dataToBeSigned.begin(), 32,
            mtx.joinSplitPubKey.begin()
            ) == 0))
    {
        throw std::runtime_error("crypto_sign_verify_detached failed");
    }

    CTransaction rawTx(mtx);
    tx_ = rawTx;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rawTx;

    std::string encryptedNote1;
    std::string encryptedNote2;
    {
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
        ss2 << ((unsigned char) 0x00);
        ss2 << jsdesc.ephemeralKey;
        ss2 << jsdesc.ciphertexts[0];
        ss2 << jsdesc.h_sig(*pzcashParams, joinSplitPubKey_);

        encryptedNote1 = HexStr(ss2.begin(), ss2.end());
    }
    {
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
        ss2 << ((unsigned char) 0x01);
        ss2 << jsdesc.ephemeralKey;
        ss2 << jsdesc.ciphertexts[1];
        ss2 << jsdesc.h_sig(*pzcashParams, joinSplitPubKey_);

        encryptedNote2 = HexStr(ss2.begin(), ss2.end());
    }

    UniValue arrInputMap(UniValue::VARR);
    UniValue arrOutputMap(UniValue::VARR);
    for (size_t i = 0; i < ZC_NUM_JS_INPUTS; i++) {
        arrInputMap.push_back(static_cast<uint64_t>(inputMap[i]));
    }
    for (size_t i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        arrOutputMap.push_back(static_cast<uint64_t>(outputMap[i]));
    }


    // !!! Payment disclosure START
    unsigned char buffer[32] = {0};
    memcpy(&buffer[0], &joinSplitPrivKey_[0], 32); // private key in first half of 64 byte buffer
    std::vector<unsigned char> vch(&buffer[0], &buffer[0] + 32);
    uint256 joinSplitPrivKey = uint256(vch);
    size_t js_index = tx_.vJoinSplit.size() - 1;
    uint256 placeholder;
    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        uint8_t mapped_index = outputMap[i];
        // placeholder for txid will be filled in later when tx has been finalized and signed.
        PaymentDisclosureKey pdKey = {placeholder, js_index, mapped_index};
        JSOutput output = outputs[mapped_index];
        libzcash::SproutPaymentAddress zaddr = output.addr;  // randomized output
        PaymentDisclosureInfo pdInfo = {PAYMENT_DISCLOSURE_VERSION_EXPERIMENTAL, esk, joinSplitPrivKey, zaddr};
        paymentDisclosureData_.push_back(PaymentDisclosureKeyInfo(pdKey, pdInfo));

        LogPrint("paymentdisclosure", "%s: Payment Disclosure: js=%d, n=%d, zaddr=%s\n", getId(), js_index, int(mapped_index), EncodePaymentAddress(zaddr));
    }
    // !!! Payment disclosure END

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("encryptednote1", encryptedNote1));
    obj.push_back(Pair("encryptednote2", encryptedNote2));
    obj.push_back(Pair("rawtxn", HexStr(ss.begin(), ss.end())));
    obj.push_back(Pair("inputmap", arrInputMap));
    obj.push_back(Pair("outputmap", arrOutputMap));
    return obj;
}

void AsyncRPCOperation_sendmany::add_taddr_outputs_to_tx() {

    CMutableTransaction rawTx(tx_);

    for (SendManyRecipient & r : t_outputs_) {
        std::string outputAddress = std::get<0>(r);
        CAmount nAmount = std::get<1>(r);
        CScript scriptPubKey = std::get<3>(r);

        CTxDestination address = DecodeDestination(outputAddress);
        if (!IsValidDestination(address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid output address, not a valid taddr.");
        }

        // if we already have script contents, don't make a new one
        if (scriptPubKey.size() == 0)
        {
            scriptPubKey = GetScriptForDestination(address);
        }

        CTxOut out(nAmount, scriptPubKey);
        rawTx.vout.push_back(out);
    }
    rawTx.nLockTime = (uint32_t)time(NULL) - 60; // jl777
    tx_ = CTransaction(rawTx);
}

void AsyncRPCOperation_sendmany::add_taddr_change_output_to_tx(CReserveKey& keyChange, CAmount amount) {

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();
    CPubKey vchPubKey;
    bool ret = keyChange.GetReservedKey(vchPubKey);
    if (!ret) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Could not generate a taddr to use as a change address"); // should never fail, as we just unlocked
    }

    CTxOut out(amount, GetScriptForDestination(vchPubKey.GetID()));

    CMutableTransaction rawTx(tx_);
    rawTx.vout.push_back(out);
    rawTx.nLockTime = (uint32_t)time(NULL) - 60; // jl777
    tx_ = CTransaction(rawTx);
}

std::array<unsigned char, ZC_MEMO_SIZE> AsyncRPCOperation_sendmany::get_memo_from_hex_string(std::string s) {
    // initialize to default memo (no_memo), see section 5.5 of the protocol spec
    std::array<unsigned char, ZC_MEMO_SIZE> memo = {{0xF6}};

    std::vector<unsigned char> rawMemo = ParseHex(s.c_str());

    // If ParseHex comes across a non-hex char, it will stop but still return results so far.
    size_t slen = s.length();
    if (slen % 2 !=0 || (slen>0 && rawMemo.size()!=slen/2)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Memo must be in hexadecimal format");
    }

    if (rawMemo.size() > ZC_MEMO_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Memo size of %d is too big, maximum allowed is %d", rawMemo.size(), ZC_MEMO_SIZE));
    }

    // copy vector into boost array
    int lenMemo = rawMemo.size();
    for (int i = 0; i < ZC_MEMO_SIZE && i < lenMemo; i++) {
        memo[i] = rawMemo[i];
    }
    return memo;
}

/**
 * Override getStatus() to append the operation's input parameters to the default status object.
 */
UniValue AsyncRPCOperation_sendmany::getStatus() const {
    UniValue v = AsyncRPCOperation::getStatus();
    if (contextinfo_.isNull()) {
        return v;
    }

    UniValue obj = v.get_obj();
    obj.push_back(Pair("method", sendCurrency ? "sendcurrency" : "z_sendmany"));
    obj.push_back(Pair("params", contextinfo_ ));
    return obj;
}
