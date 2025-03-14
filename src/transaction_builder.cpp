// Copyright (c) 2018 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "transaction_builder.h"

#include "main.h"
#include "pubkey.h"
#include "rpc/protocol.h"
#include "script/sign.h"
#include "utilmoneystr.h"
#include "cc/CCinclude.h"
#include "pbaas/reserves.h"

#include <boost/variant.hpp>
#include <librustzcash.h>

SpendDescriptionInfo::SpendDescriptionInfo(
    libzcash::SaplingExpandedSpendingKey expsk,
    libzcash::SaplingNote note,
    uint256 anchor,
    SaplingWitness witness) : expsk(expsk), note(note), anchor(anchor), witness(witness)
{
    librustzcash_sapling_generate_r(alpha.begin());
}

TransactionBuilderResult::TransactionBuilderResult(const CTransaction& tx) : maybeTx(tx) {}

TransactionBuilderResult::TransactionBuilderResult(const std::string& error) : maybeError(error) {}

bool TransactionBuilderResult::IsTx() { return maybeTx != boost::none; }

bool TransactionBuilderResult::IsError() { return maybeError != boost::none; }

bool TransactionBuilderResult::IsHexTx(CTransaction *pTx)
{
    CTransaction _tx;
    CTransaction &tx = (pTx == nullptr) ? _tx : *pTx;
    if (maybeError != boost::none &&
        IsHex(maybeError.get()))
    {
        return DecodeHexTx(tx, maybeError.get());
    }
    return false;
}

CTransaction TransactionBuilderResult::GetTxOrThrow() {
    if (maybeTx) {
        return maybeTx.get();
    } else {
        if (IsHex(GetError()))
        {
            throw JSONRPCError(RPC_WALLET_ERROR, GetError());
        }
        else
        {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build transaction: " + GetError());
        }
    }
}

std::string TransactionBuilderResult::GetError() {
    if (maybeError) {
        return maybeError.get();
    } else {
        // This can only happen if isTx() is true in which case we should not call getError()
        throw std::runtime_error("getError() was called in TransactionBuilderResult, but the result was not initialized as an error.");
    }
}

TransactionBuilder::TransactionBuilder(
    const Consensus::Params& consensusParams,
    int nHeight,
    CKeyStore* keystore,
    ZCJoinSplit* sproutParams,
    CCoinsViewCache* coinsView,
    CCriticalSection* cs_coinsView) :
    consensusParams(consensusParams),
    nHeight(nHeight),
    keystore(keystore),
    sproutParams(sproutParams),
    coinsView(coinsView),
    cs_coinsView(cs_coinsView)
{
    if (keystore && VERUS_PRIVATECHANGE && defaultSaplingDest != boost::none)
    {
        uint256 ovk;
        HDSeed seed;
        if (keystore->GetHDSeed(seed))
        {
            ovk = ovkForShieldingFromTaddr(seed);

            // send everything to default Sapling address by default
            SendChangeTo(defaultSaplingDest.value(), ovk);
        }
    }
    mtx = CreateNewContextualCMutableTransaction(consensusParams, nHeight);
}

// This exception is thrown in certain scenarios when building JoinSplits fails.
struct JSDescException : public std::exception
{
    JSDescException (const std::string msg_) : msg(msg_) {}

    const char* what() { return msg.c_str(); }

private:
    std::string msg;
};


void TransactionBuilder::SetExpiryHeight(uint32_t nExpiryHeight)
{
    if (nExpiryHeight < nHeight || nExpiryHeight <= 0 || nExpiryHeight >= TX_EXPIRY_HEIGHT_THRESHOLD) {
        throw new std::runtime_error("TransactionBuilder::SetExpiryHeight: invalid expiry height");
    }
    mtx.nExpiryHeight = nExpiryHeight;
}

void TransactionBuilder::AddSaplingSpend(
    libzcash::SaplingExpandedSpendingKey expsk,
    libzcash::SaplingNote note,
    uint256 anchor,
    SaplingWitness witness)
{
    // Sanity check: cannot add Sapling spend to pre-Sapling transaction
    if (mtx.nVersion < SAPLING_TX_VERSION) {
        throw std::runtime_error("TransactionBuilder cannot add Sapling spend to pre-Sapling transaction");
    }

    // Consistency check: all anchors must equal the first one
    if (spends.size() > 0 && spends[0].anchor != anchor) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Anchor does not match previously-added Sapling spends.");
    }

    spends.emplace_back(expsk, note, anchor, witness);
    mtx.valueBalance += note.value();
}

void TransactionBuilder::AddSaplingOutput(
    uint256 ovk,
    libzcash::SaplingPaymentAddress to,
    CAmount value,
    std::array<unsigned char, ZC_MEMO_SIZE> memo)
{
    // Sanity check: cannot add Sapling output to pre-Sapling transaction
    if (mtx.nVersion < SAPLING_TX_VERSION) {
        throw std::runtime_error("TransactionBuilder cannot add Sapling output to pre-Sapling transaction");
    }

    auto note = libzcash::SaplingNote(to, value);
    outputs.emplace_back(ovk, note, memo);
    mtx.valueBalance -= value;
}

void TransactionBuilder::AddSproutInput(
    libzcash::SproutSpendingKey sk,
    libzcash::SproutNote note,
    SproutWitness witness)
{
    if (sproutParams == nullptr) {
        throw std::runtime_error("Cannot add Sprout inputs to a TransactionBuilder without Sprout params");
    }

    // Consistency check: all anchors must equal the first one
    if (!jsInputs.empty()) {
        if (jsInputs[0].witness.root() != witness.root()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Anchor does not match previously-added Sprout spends.");
        }
    }

    jsInputs.emplace_back(witness, note, sk);
}

void TransactionBuilder::AddSproutOutput(
    libzcash::SproutPaymentAddress to,
    CAmount value,
    std::array<unsigned char, ZC_MEMO_SIZE> memo)
{
    throw std::runtime_error("Sprout outputs are deprecated on the Verus network. Use a Sapling or later destination type for shielded outputs.");
    if (sproutParams == nullptr) {
        throw std::runtime_error("Cannot add Sprout outputs to a TransactionBuilder without Sprout params");
    }

    libzcash::JSOutput jsOutput(to, value);
    jsOutput.memo = memo;
    jsOutputs.push_back(jsOutput);
}

void TransactionBuilder::AddTransparentInput(COutPoint utxo, CScript scriptPubKey, CAmount value, uint32_t _nSequence)
{
    if (keystore == nullptr && !scriptPubKey.IsPayToCryptoCondition())
    {
        throw std::runtime_error("Cannot add transparent inputs to a TransactionBuilder without a keystore, except with crypto conditions");
    }

    mtx.vin.emplace_back(utxo);
    mtx.vin[mtx.vin.size() - 1].nSequence = _nSequence;
    tIns.emplace_back(scriptPubKey, value);
}

void TransactionBuilder::AddTransparentOutput(const CTxDestination &to, CAmount value)
{
    if (!IsValidDestination(to)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid output address, not a valid taddr.");
    }

    CScript scriptPubKey = GetScriptForDestination(to);
    CTxOut out(value, scriptPubKey);
    mtx.vout.push_back(out);
}

bool TransactionBuilder::AddTransparentOutput(const CScript &scriptPubKey, CAmount value)
{
    CTxOut out(value, scriptPubKey);
    mtx.vout.push_back(out);
    return true;
}

bool TransactionBuilder::AddOpRetLast()
{
    CScript s;
    if (opReturn)
    {
        s = opReturn.value();
        CTxOut out(0, s);
        mtx.vout.push_back(out);
    }
    return true;
}

void TransactionBuilder::AddOpRet(const CScript &s)
{
    opReturn.emplace(CScript(s));
}

void TransactionBuilder::SetFee(CAmount fees)
{
    this->fee = fees;
}

void TransactionBuilder::SetReserveFee(const CCurrencyValueMap &fees)
{
    reserveFee = fees;
}

void TransactionBuilder::SendChangeTo(libzcash::SaplingPaymentAddress changeAddr, uint256 ovk)
{
    // this is how we currently clear the private change address
    if (changeAddr.pk_d.IsNull() && ovk.IsNull())
    {
        saplingChangeAddr = boost::none;
    }
    else
    {
        saplingChangeAddr = std::make_pair(ovk, changeAddr);
    }
    sproutChangeAddr = boost::none;
    // tChangeAddr = boost::none;
}

void TransactionBuilder::SendChangeTo(libzcash::SproutPaymentAddress changeAddr)
{
    throw std::runtime_error("Sprout outputs are deprecated on the Verus network for any purpose. Use a Sapling or later destination type for change.");
    sproutChangeAddr = changeAddr;
    saplingChangeAddr = boost::none;
    tChangeAddr = boost::none;
}

void TransactionBuilder::SendChangeTo(const CTxDestination &changeAddr)
{
    if (!IsValidDestination(changeAddr)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid change address, not a valid taddr.");
    }

    tChangeAddr = changeAddr;
    // saplingChangeAddr = boost::none;
    sproutChangeAddr = boost::none;
}

TransactionBuilderResult TransactionBuilder::Build(bool throwTxWithPartialSig)
{
    //
    // Consistency checks
    //

    // calculate change and include all reserve inputs as well
    CCurrencyValueMap reserveChange;

    int64_t interest;
    CAmount nValueIn = 0;

    {
        LOCK(mempool.cs);
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);
        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        view.SetBackend(viewMemPool);

        CReserveTransactionDescriptor rtxd(mtx, view, chainActive.Height() + 1);
        reserveChange = ((rtxd.ReserveInputMap() - rtxd.ReserveOutputMap()) - reserveFee).CanonicalMap();

        if (!rtxd.IsValid() || reserveChange.HasNegative())
        {
            CReserveTransactionDescriptor checkRtxd(mtx, view, chainActive.Height() + 1);
            if (rtxd.IsValid())
            {
                printf("%s: Reserve change is negative: %s\n", __func__, reserveChange.ToUniValue().write().c_str());
                return TransactionBuilderResult("Reserve change is negative: " + reserveChange.ToUniValue().write());
            }
            else
            {
                LogPrint("txbuilder", "Invalid reserve transaction descriptor\n", __func__);
                return TransactionBuilderResult("Invalid reserve transaction descriptor");
            }
        }

        //printf("\n%s: reserve input:\n%s\noutput:\n%s\nchange:\n%s\n\n", __func__, rtxd.ReserveInputMap().ToUniValue().write(1,2).c_str(), rtxd.ReserveOutputMap().ToUniValue().write(1,2).c_str(), reserveChange.ToUniValue().write(1,2).c_str());
        bool hasReserveChange = reserveChange > CCurrencyValueMap();

        // Valid change
        CAmount change = mtx.valueBalance - fee;
        for (auto jsInput : jsInputs) {
            change += jsInput.note.value();
        }
        for (auto jsOutput : jsOutputs) {
            change -= jsOutput.value;
        }
        for (auto tIn : tIns) {
            change += tIn.value;
        }
        for (auto tOut : mtx.vout) {
            change -= tOut.nValue;
        }
        if (change < 0) {
            // it's possible this is an import transaction that is minting currency
            if (LogAcceptCategory("txbuilder"))
            {
                UniValue jsonTx(UniValue::VOBJ);
                TxToUniv(mtx, uint256(), jsonTx);
                if (throwTxWithPartialSig)
                {
                    printf("%s: Returning partial transaction mtx: %s\n", __func__, jsonTx.write(1,2).c_str());
                    printf("%s: Change is negative, %s\n", __func__, ("native: " + std::to_string(change) + "\nreserves: " + reserveChange.ToUniValue().write()).c_str());
                    LogPrintf("%s: Returning partial transaction mtx: %s\n", __func__, jsonTx.write(1,2).c_str());
                    LogPrintf("%s: Change is negative, %s\n", __func__, ("native: " + std::to_string(change) + "\nreserves: " + reserveChange.ToUniValue().write()).c_str());
                }
                else
                {
                    printf("%s: mtx: %s\n", __func__, jsonTx.write(1,2).c_str());
                    printf("%s: Change cannot be negative, %s\n", __func__, ("native: " + std::to_string(change) + "\nreserves: " + reserveChange.ToUniValue().write()).c_str());
                    LogPrintf("%s: mtx: %s\n", __func__, jsonTx.write(1,2).c_str());
                    LogPrintf("%s: Change cannot be negative, %s\n", __func__, ("native: " + std::to_string(change) + "\nreserves: " + reserveChange.ToUniValue().write()).c_str());
                }
            }

            if (throwTxWithPartialSig)
            {
                return TransactionBuilderResult(EncodeHexTx(mtx));
            }

            return TransactionBuilderResult("Change cannot be negative, native: " + std::to_string(change) + "\nreserves: " + reserveChange.ToUniValue().write());
        }

        if ((rtxd.NativeFees() - this->fee) != change)
        {
            //UniValue jsonTx(UniValue::VOBJ);
            //TxToUniv(mtx, uint256(), jsonTx);
            //printf("%s: mtx: %s\n", __func__, jsonTx.write(1,2).c_str());
            printf("%s: native fees do not match builder: %s, blockchain: %s\n", __func__, ValueFromAmount(change).write(1,2).c_str(), ValueFromAmount(rtxd.NativeFees()).write(1,2).c_str());
            LogPrintf("%s: native fees do not match builder: %s, blockchain: %s\n", __func__, ValueFromAmount(change).write(1,2).c_str(), ValueFromAmount(rtxd.NativeFees()).write(1,2).c_str());
            return TransactionBuilderResult("Native fees do not match builder");
        }

        bool hasNativeChange = change > 0;

        if (!tChangeAddr && ((hasNativeChange && !saplingChangeAddr && spends.empty()) || hasReserveChange))
        {
            //printf("%s: nativeChange: %ld, reserveChange: %s\n", __func__, change, reserveChange.ToUniValue().write(1,2).c_str());
            LogPrintf("%s: nativeChange: %ld, reserveChange: %s\n", __func__, change, reserveChange.ToUniValue().write(1,2).c_str());
            if (hasReserveChange)
            {
                return TransactionBuilderResult("Reserve change must be sent to a transparent change address or VerusID");
            }
            else
            {
                return TransactionBuilderResult("Change must be sent to a private or transparent change address or VerusID");
            }
        }

        //
        // Create change output for native, reserve, or both types of currency
        //
        if (hasNativeChange || hasReserveChange)
        {
            // Send change to the specified change address(es). If both tChangeAddr and saplingChangeAddr are set, send native to the sapling address
            // (A t-address or ID can only be used as the change address if explicitly set.)
            if (hasReserveChange)
            {
                // even if reserve currency goes to a t-change address, native currency can go to
                // a Sapling address, if both are specified
                if (hasNativeChange && saplingChangeAddr)
                {
                    AddSaplingOutput(saplingChangeAddr->first, saplingChangeAddr->second, change);
                    hasNativeChange = false;    // no more native change to send
                }
                std::vector<CTxDestination> dest(1, tChangeAddr.get());

                // separate any blocked currencies from non-blocked currencies into separate change outputs
                if (keystore && keystore->GetCurrencyTrustMode() != CRating::TRUSTMODE_NORESTRICTION)
                {
                    CCurrencyValueMap withoutBlockedCurrencies = keystore->RemoveBlockedCurrencies(reserveChange);
                    CCurrencyValueMap removedCurrencies = (reserveChange - withoutBlockedCurrencies);
                    if (removedCurrencies > CCurrencyValueMap())
                    {
                        CTokenOutput unwantedOut(removedCurrencies);
                        AddTransparentOutput(MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dest, 1, &unwantedOut)), 0);
                        reserveChange = withoutBlockedCurrencies;
                    }
                }

                // one output for all reserves, change gets combined
                // we should separate, or remove any currency that is not whitelisted if specified after whitelist is supported
                CTokenOutput to(reserveChange);
                AddTransparentOutput(MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dest, 1, &to)), hasNativeChange ? change : 0);
            }
            else if (saplingChangeAddr)
            {
                AddSaplingOutput(saplingChangeAddr->first, saplingChangeAddr->second, change);
            } else if (tChangeAddr)
            {
                // tChangeAddr has already been validated.
                AddTransparentOutput(tChangeAddr.value(), change);
            } else if (!spends.empty())
            {
                auto fvk = spends[0].expsk.full_viewing_key();
                auto note = spends[0].note;
                libzcash::SaplingPaymentAddress changeAddr(note.d, note.pk_d);
                AddSaplingOutput(fvk.ovk, changeAddr, change);
            } else
            {
                if (hasReserveChange)
                {
                    return TransactionBuilderResult("Could not determine change address for reserve currency change");
                }
                else
                {
                    return TransactionBuilderResult("Could not determine change address for native currency change, amount: " + std::to_string(change));
                }
            }
        }
    }

    //
    // Sapling spends and outputs
    //

    auto ctx = librustzcash_sapling_proving_ctx_init();

    // Create Sapling SpendDescriptions
    for (auto spend : spends) {
        auto cm = spend.note.cm();
        auto nf = spend.note.nullifier(
            spend.expsk.full_viewing_key(), spend.witness.position());
        if (!cm || !nf) {
            librustzcash_sapling_proving_ctx_free(ctx);
            return TransactionBuilderResult("Spend is invalid");
        }

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << spend.witness.path();
        std::vector<unsigned char> witness(ss.begin(), ss.end());

        SpendDescription sdesc;
        if (!librustzcash_sapling_spend_proof(
                ctx,
                spend.expsk.full_viewing_key().ak.begin(),
                spend.expsk.nsk.begin(),
                spend.note.d.data(),
                spend.note.r.begin(),
                spend.alpha.begin(),
                spend.note.value(),
                spend.anchor.begin(),
                witness.data(),
                sdesc.cv.begin(),
                sdesc.rk.begin(),
                sdesc.zkproof.data())) {
            librustzcash_sapling_proving_ctx_free(ctx);
            return TransactionBuilderResult("Spend proof failed");
        }

        sdesc.anchor = spend.anchor;
        sdesc.nullifier = *nf;
        mtx.vShieldedSpend.push_back(sdesc);
    }

    // Create Sapling OutputDescriptions
    for (auto output : outputs) {
        auto cm = output.note.cm();
        if (!cm) {
            librustzcash_sapling_proving_ctx_free(ctx);
            return TransactionBuilderResult("Output is invalid");
        }

        libzcash::SaplingNotePlaintext notePlaintext(output.note, output.memo);

        auto res = notePlaintext.encrypt(output.note.pk_d);
        if (!res) {
            librustzcash_sapling_proving_ctx_free(ctx);
            return TransactionBuilderResult("Failed to encrypt note");
        }
        auto enc = res.get();
        auto encryptor = enc.second;

        OutputDescription odesc;
        if (!librustzcash_sapling_output_proof(
                ctx,
                encryptor.get_esk().begin(),
                output.note.d.data(),
                output.note.pk_d.begin(),
                output.note.r.begin(),
                output.note.value(),
                odesc.cv.begin(),
                odesc.zkproof.begin())) {
            librustzcash_sapling_proving_ctx_free(ctx);
            return TransactionBuilderResult("Output proof failed");
        }

        odesc.cm = *cm;
        odesc.ephemeralKey = encryptor.get_epk();
        odesc.encCiphertext = enc.first;

        libzcash::SaplingOutgoingPlaintext outPlaintext(output.note.pk_d, encryptor.get_esk());
        odesc.outCiphertext = outPlaintext.encrypt(
            output.ovk,
            odesc.cv,
            odesc.cm,
            encryptor);
        mtx.vShieldedOutput.push_back(odesc);
    }

    // add op_return if there is one to add
    AddOpRetLast();

    //
    // Sprout JoinSplits
    //

    unsigned char joinSplitPrivKey[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(mtx.joinSplitPubKey.begin(), joinSplitPrivKey);

    // Create Sprout JSDescriptions
    if (!jsInputs.empty() || !jsOutputs.empty()) {
        try {
            CreateJSDescriptions();
        } catch (JSDescException e) {
            librustzcash_sapling_proving_ctx_free(ctx);
            return TransactionBuilderResult(e.what());
        } catch (std::runtime_error e) {
            librustzcash_sapling_proving_ctx_free(ctx);
            throw e;
        }
    }

    //
    // Signatures
    //

    auto consensusBranchId = CurrentEpochBranchId(nHeight, consensusParams);

    // Empty output script.
    uint256 dataToBeSigned;
    CScript scriptCode;
    try {
        dataToBeSigned = SignatureHash(scriptCode, mtx, NOT_AN_INPUT, SIGHASH_ALL, 0, consensusBranchId);
    } catch (std::logic_error ex) {
        librustzcash_sapling_proving_ctx_free(ctx);
        return TransactionBuilderResult("Could not construct signature hash: " + std::string(ex.what()));
    }

    // Create Sapling spendAuth and binding signatures
    for (size_t i = 0; i < spends.size(); i++) {
        librustzcash_sapling_spend_sig(
            spends[i].expsk.ask.begin(),
            spends[i].alpha.begin(),
            dataToBeSigned.begin(),
            mtx.vShieldedSpend[i].spendAuthSig.data());
    }
    librustzcash_sapling_binding_sig(
        ctx,
        mtx.valueBalance,
        dataToBeSigned.begin(),
        mtx.bindingSig.data());

    librustzcash_sapling_proving_ctx_free(ctx);

    // Create Sprout joinSplitSig
    if (crypto_sign_detached(
        mtx.joinSplitSig.data(), NULL,
        dataToBeSigned.begin(), 32,
        joinSplitPrivKey) != 0)
    {
        return TransactionBuilderResult("Failed to create Sprout joinSplitSig");
    }

    // Sanity check Sprout joinSplitSig
    if (crypto_sign_verify_detached(
        mtx.joinSplitSig.data(),
        dataToBeSigned.begin(), 32,
        mtx.joinSplitPubKey.begin()) != 0)
    {
        return TransactionBuilderResult("Sprout joinSplitSig sanity check failed");
    }

    // Transparent signatures
    bool throwPartialSig = false;
    CTransaction txNewConst(mtx);
    for (int nIn = 0; nIn < mtx.vin.size(); nIn++) {
        auto tIn = tIns[nIn];
        SignatureData sigdata;
        bool signSuccess = ProduceSignature(
            TransactionSignatureCreator(keystore, &txNewConst, nIn, tIn.value, tIn.scriptPubKey), tIn.scriptPubKey, sigdata, consensusBranchId);

        if (!signSuccess) {
            UniValue jsonTx(UniValue::VOBJ);
            extern void TxToUniv(const CTransaction& tx, const uint256& hashBlock, UniValue& entry);
            TxToUniv(txNewConst, uint256(), jsonTx);
            printf("Failed to sign for script, input %d:\n%s\n", nIn, jsonTx.write(1,2).c_str());
            if (throwTxWithPartialSig)
            {
                throwPartialSig = true;
                if (sigdata.scriptSig.size())
                {
                    UpdateTransaction(mtx, nIn, sigdata);
                }
            }
            else
            {
                return TransactionBuilderResult("Failed to sign transaction");
            }
        } else {
            UpdateTransaction(mtx, nIn, sigdata);
        }
    }

    if (throwPartialSig)
    {
        return TransactionBuilderResult(EncodeHexTx(mtx));
    }

    return TransactionBuilderResult(CTransaction(mtx));
}

void TransactionBuilder::CreateJSDescriptions()
{
    // Copy jsInputs and jsOutputs to more flexible containers
    std::deque<libzcash::JSInput> jsInputsDeque;
    for (auto jsInput : jsInputs) {
        jsInputsDeque.push_back(jsInput);
    }
    std::deque<libzcash::JSOutput> jsOutputsDeque;
    for (auto jsOutput : jsOutputs) {
        jsOutputsDeque.push_back(jsOutput);
    }

    // If we have no Sprout shielded inputs, then we do the simpler more-leaky
    // process where we just create outputs directly. We save the chaining logic,
    // at the expense of leaking the sums of pairs of output values in vpub_old.
    if (jsInputs.empty()) {
        // Create joinsplits, where each output represents a zaddr recipient.
        while (jsOutputsDeque.size() > 0) {
            // Default array entries are dummy inputs and outputs
            std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> vjsin;
            std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> vjsout;
            uint64_t vpub_old = 0;

            for (int n = 0; n < ZC_NUM_JS_OUTPUTS && jsOutputsDeque.size() > 0; n++) {
                vjsout[n] = jsOutputsDeque.front();
                jsOutputsDeque.pop_front();

                // Funds are removed from the value pool and enter the private pool
                vpub_old += vjsout[n].value;
            }

            std::array<size_t, ZC_NUM_JS_INPUTS> inputMap;
            std::array<size_t, ZC_NUM_JS_OUTPUTS> outputMap;
            CreateJSDescription(vpub_old, 0, vjsin, vjsout, inputMap, outputMap);
        }
        return;
    }

    // At this point, we are guaranteed to have at least one input note.
    // Use address of first input note as the temporary change address.
    auto changeKey = jsInputsDeque.front().key;
    auto changeAddress = changeKey.address();

    CAmount jsChange = 0;          // this is updated after each joinsplit
    int changeOutputIndex = -1;    // this is updated after each joinsplit if jsChange > 0
    bool vpubOldProcessed = false; // updated when vpub_old for taddr inputs is set in first joinsplit
    bool vpubNewProcessed = false; // updated when vpub_new for miner fee and taddr outputs is set in last joinsplit

    CAmount valueOut = 0;
    for (auto jsInput : jsInputs) {
        valueOut += jsInput.note.value();
    }
    for (auto jsOutput : jsOutputs) {
        valueOut -= jsOutput.value;
    }
    CAmount vpubOldTarget = valueOut < 0 ? -valueOut : 0;
    CAmount vpubNewTarget = valueOut > 0 ? valueOut : 0;

    // Keep track of treestate within this transaction
    boost::unordered_map<uint256, SproutMerkleTree, CCoinsKeyHasher> intermediates;
    std::vector<uint256> previousCommitments;

    while (!vpubNewProcessed) {
        // Default array entries are dummy inputs and outputs
        std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> vjsin;
        std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> vjsout;
        uint64_t vpub_old = 0;
        uint64_t vpub_new = 0;

        // Set vpub_old in the first joinsplit
        if (!vpubOldProcessed) {
            vpub_old += vpubOldTarget; // funds flowing from public pool
            vpubOldProcessed = true;
        }

        CAmount jsInputValue = 0;
        uint256 jsAnchor;

        JSDescription prevJoinSplit;

        // Keep track of previous JoinSplit and its commitments
        if (mtx.vJoinSplit.size() > 0) {
            prevJoinSplit = mtx.vJoinSplit.back();
        }

        // If there is no change, the chain has terminated so we can reset the tracked treestate.
        if (jsChange == 0 && mtx.vJoinSplit.size() > 0) {
            intermediates.clear();
            previousCommitments.clear();
        }

        //
        // Consume change as the first input of the JoinSplit.
        //
        if (jsChange > 0) {
            // Update tree state with previous joinsplit
            SproutMerkleTree tree;
            {
                // assert that coinsView is not null
                assert(coinsView);
                // We do not check cs_coinView because we do not set this in testing
                // assert(cs_coinsView);
                LOCK(cs_coinsView);
                auto it = intermediates.find(prevJoinSplit.anchor);
                if (it != intermediates.end()) {
                    tree = it->second;
                } else if (!coinsView->GetSproutAnchorAt(prevJoinSplit.anchor, tree)) {
                    throw JSDescException("Could not find previous JoinSplit anchor");
                }
            }

            assert(changeOutputIndex != -1);
            assert(changeOutputIndex < prevJoinSplit.commitments.size());
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
            assert(changeWitness.has_value());
            jsAnchor = tree.root();
            intermediates.insert(std::make_pair(tree.root(), tree)); // chained js are interstitial (found in between block boundaries)

            // Decrypt the change note's ciphertext to retrieve some data we need
            ZCNoteDecryption decryptor(changeKey.receiving_key());
            auto hSig = prevJoinSplit.h_sig(*sproutParams, mtx.joinSplitPubKey);
            try {
                auto plaintext = libzcash::SproutNotePlaintext::decrypt(
                    decryptor,
                    prevJoinSplit.ciphertexts[changeOutputIndex],
                    prevJoinSplit.ephemeralKey,
                    hSig,
                    (unsigned char)changeOutputIndex);

                auto note = plaintext.note(changeAddress);
                vjsin[0] = libzcash::JSInput(changeWitness.get(), note, changeKey);

                jsInputValue += plaintext.value();

                LogPrint("zrpcunsafe", "spending change (amount=%s)\n", FormatMoney(plaintext.value()));

            } catch (const std::exception& e) {
                throw JSDescException("Error decrypting output note of previous JoinSplit");
            }
        }

        //
        // Consume spendable non-change notes
        //
        for (int n = (jsChange > 0) ? 1 : 0; n < ZC_NUM_JS_INPUTS && jsInputsDeque.size() > 0; n++) {
            auto jsInput = jsInputsDeque.front();
            jsInputsDeque.pop_front();

            // Add history of previous commitments to witness
            if (jsChange > 0) {
                for (const uint256& commitment : previousCommitments) {
                    jsInput.witness.append(commitment);
                }
                if (jsAnchor != jsInput.witness.root()) {
                    throw JSDescException("Witness for spendable note does not have same anchor as change input");
                }
            }

            // The jsAnchor is null if this JoinSplit is at the start of a new chain
            if (jsAnchor.IsNull()) {
                jsAnchor = jsInput.witness.root();
            }

            jsInputValue += jsInput.note.value();
            vjsin[n] = jsInput;
        }

        // Find recipient to transfer funds to
        libzcash::JSOutput recipient;
        if (jsOutputsDeque.size() > 0) {
            recipient = jsOutputsDeque.front();
            jsOutputsDeque.pop_front();
        }
        // `recipient` is now either a valid recipient, or a dummy output with value = 0

        // Reset change
        jsChange = 0;
        CAmount outAmount = recipient.value;

        // Set vpub_new in the last joinsplit (when there are no more notes to spend or zaddr outputs to satisfy)
        if (jsOutputsDeque.empty() && jsInputsDeque.empty()) {
            assert(!vpubNewProcessed);
            if (jsInputValue < vpubNewTarget) {
                throw JSDescException(strprintf("Insufficient funds for vpub_new %s", FormatMoney(vpubNewTarget)));
            }
            outAmount += vpubNewTarget;
            vpub_new += vpubNewTarget; // funds flowing back to public pool
            vpubNewProcessed = true;
            jsChange = jsInputValue - outAmount;
            assert(jsChange >= 0);
        } else {
            // This is not the last joinsplit, so compute change and any amount still due to the recipient
            if (jsInputValue > outAmount) {
                jsChange = jsInputValue - outAmount;
            } else if (outAmount > jsInputValue) {
                // Any amount due is owed to the recipient.  Let the miners fee get paid first.
                CAmount due = outAmount - jsInputValue;
                libzcash::JSOutput recipientDue(recipient.addr, due);
                recipientDue.memo = recipient.memo;
                jsOutputsDeque.push_front(recipientDue);

                // reduce the amount being sent right now to the value of all inputs
                recipient.value = jsInputValue;
            }
        }

        // create output for recipient
        assert(ZC_NUM_JS_OUTPUTS == 2); // If this changes, the logic here will need to be adjusted
        vjsout[0] = recipient;

        // create output for any change
        if (jsChange > 0) {
            vjsout[1] = libzcash::JSOutput(changeAddress, jsChange);

            LogPrint("zrpcunsafe", "generating note for change (amount=%s)\n", FormatMoney(jsChange));
        }

        std::array<size_t, ZC_NUM_JS_INPUTS> inputMap;
        std::array<size_t, ZC_NUM_JS_OUTPUTS> outputMap;
        CreateJSDescription(vpub_old, vpub_new, vjsin, vjsout, inputMap, outputMap);

        if (jsChange > 0) {
            changeOutputIndex = -1;
            for (size_t i = 0; i < outputMap.size(); i++) {
                if (outputMap[i] == 1) {
                    changeOutputIndex = i;
                }
            }
            assert(changeOutputIndex != -1);
        }
    }
}

void TransactionBuilder::CreateJSDescription(
    uint64_t vpub_old,
    uint64_t vpub_new,
    std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> vjsin,
    std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> vjsout,
    std::array<size_t, ZC_NUM_JS_INPUTS>& inputMap,
    std::array<size_t, ZC_NUM_JS_OUTPUTS>& outputMap)
{
    LogPrint("zrpcunsafe", "CreateJSDescription: creating joinsplit at index %d (vpub_old=%s, vpub_new=%s, in[0]=%s, in[1]=%s, out[0]=%s, out[1]=%s)\n",
        mtx.vJoinSplit.size(),
        FormatMoney(vpub_old), FormatMoney(vpub_new),
        FormatMoney(vjsin[0].note.value()), FormatMoney(vjsin[1].note.value()),
        FormatMoney(vjsout[0].value), FormatMoney(vjsout[1].value));

    uint256 esk; // payment disclosure - secret

    // Generate the proof, this can take over a minute.
    assert(mtx.fOverwintered && (mtx.nVersion >= SAPLING_TX_VERSION));
    JSDescription jsdesc = JSDescription::Randomized(
            *sproutParams,
            mtx.joinSplitPubKey,
            vjsin[0].witness.root(),
            vjsin,
            vjsout,
            inputMap,
            outputMap,
            vpub_old,
            vpub_new,
            true, //!this->testmode,
            &esk); // parameter expects pointer to esk, so pass in address

    {
        auto verifier = libzcash::ProofVerifier::Strict();
        if (!jsdesc.Verify(*sproutParams, verifier, mtx.joinSplitPubKey)) {
            throw std::runtime_error("error verifying joinsplit");
        }
    }

    mtx.vJoinSplit.push_back(jsdesc);

    // TODO: Sprout payment disclosure
}
