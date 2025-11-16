/********************************************************************
 * (C) 2019 Michael Toutonghi
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * This provides support for PBaaS initialization, notarization, and cross-chain token
 * transactions and enabling liquid or non-liquid tokens across the
 * Verus ecosystem.
 *
 */

#include "base58.h"
#include "main.h"
#include "rpc/pbaasrpc.h"
#include "timedata.h"
#include "transaction_builder.h"
#include "deprecation.h"
#include "cc/StakeGuard.h"
#include "consensus/upgrades.h"
#include <map>
#include <random>

CConnectedChains ConnectedChains;
extern uint32_t KOMODO_STOPAT;

bool IsVerusActive()
{
    return ASSETCHAINS_CHAINID == VERUS_CHAINID;
}

bool IsVerusMainnetActive()
{
    return IsVerusActive() && (strcmp(ASSETCHAINS_SYMBOL, "VRSC") == 0);
}

// this adds an opret to a mutable transaction and returns the voutnum if it could be added
int32_t AddOpRetOutput(CMutableTransaction &mtx, const CScript &opRetScript)
{
    if (opRetScript.IsOpReturn() && opRetScript.size() <= MAX_OP_RETURN_RELAY)
    {
        CTxOut vOut = CTxOut();
        vOut.scriptPubKey = opRetScript;
        vOut.nValue = 0;
        mtx.vout.push_back(vOut);
        return mtx.vout.size() - 1;
    }
    else
    {
        return -1;
    }
}

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
uint256 GetChainObjectHash(const CBaseChainObject &bo)
{
    union {
        const CBaseChainObject *retPtr;
        const CChainObject<CBlockHeaderAndProof> *pNewHeader;
        const CChainObject<CPartialTransactionProof> *pNewTx;
        const CChainObject<CBlockHeaderProof> *pNewHeaderRef;
        const CChainObject<CHashCommitments> *pPriors;
        const CChainObject<CProofRoot> *pNewProofRoot;
        const CChainObject<CReserveTransfer> *pExport;
        const CChainObject<CCrossChainProof> *pCrossChainProof;
        const CChainObject<CNotarySignature> *pNotarySignature;
        const CChainObject<CEvidenceData> *pBytes;
    };

    retPtr = &bo;

    switch(bo.objectType)
    {
        case CHAINOBJ_HEADER:
            return pNewHeader->GetHash();

        case CHAINOBJ_TRANSACTION_PROOF:
            return pNewTx->GetHash();

        case CHAINOBJ_HEADER_REF:
            return pNewHeaderRef->GetHash();

        case CHAINOBJ_COMMITMENTDATA:
            return pPriors->GetHash();

        case CHAINOBJ_PROOF_ROOT:
            return ::GetHash(pNewProofRoot->object);

        case CHAINOBJ_RESERVETRANSFER:
            return pExport->GetHash();

        case CHAINOBJ_CROSSCHAINPROOF:
            return pCrossChainProof->GetHash();

        case CHAINOBJ_NOTARYSIGNATURE:
            return pNotarySignature->GetHash();

        case CHAINOBJ_EVIDENCEDATA:
            return pBytes->GetHash();

    }
    return uint256();
}

CCrossChainExport GetExportToSpend(const CTransaction &spendingTx, uint32_t nIn, CTransaction &sourceTx, uint32_t &height, COptCCParams &p)
{
    // if not fulfilled, ensure that no part of the primary identity is modified
    CCrossChainExport oldExport;
    uint256 blkHash;
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        auto bIt = blkHash.IsNull() ? mapBlockIndex.end() : mapBlockIndex.find(blkHash);
        if (bIt == mapBlockIndex.end() || !bIt->second)
        {
            height = chainActive.Height();
        }
        else
        {
            height = bIt->second->GetHeight();
        }

        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldExport = CCrossChainExport(p.vData[0]);
        }
    }
    return oldExport;
}

CCrossChainImport GetImportToSpend(const CTransaction &spendingTx, uint32_t nIn, CTransaction &sourceTx, uint32_t &height, COptCCParams &p)
{
    // if not fulfilled, ensure that no part of the primary identity is modified
    CCrossChainImport oldImport;
    uint256 blkHash;
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        auto bIt = blkHash.IsNull() ? mapBlockIndex.end() : mapBlockIndex.find(blkHash);
        if (bIt == mapBlockIndex.end() || !bIt->second)
        {
            height = chainActive.Height();
        }
        else
        {
            height = bIt->second->GetHeight();
        }

        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldImport = CCrossChainImport(p.vData[0]);
        }
    }
    return oldImport;
}

// used to export coins from one chain to another, if they are not native, they are represented on the other
// chain as tokens
bool ValidateCrossChainExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    uint32_t outNum;
    uint32_t spendingFromHeight;
    CTransaction txToSpend;
    COptCCParams p;

    // get reserve transfer to spend
    CCrossChainExport thisExport = GetExportToSpend(tx, nIn, txToSpend, spendingFromHeight, p);

    if (thisExport.IsValid())
    {
        if (CConstVerusSolutionVector::GetVersionByHeight(spendingFromHeight) < CActivationHeight::ACTIVATE_PBAAS)
        {
            return eval->Error("Multi-currency operation before PBaaS activation");
        }

        if (thisExport.IsSupplemental())
        {
            CCrossChainImport cciBeingSpent, cciSpending;
            for (auto &oneOut : txToSpend.vout)
            {
                if ((cciBeingSpent = CCrossChainImport(oneOut.scriptPubKey)).IsValid())
                {
                    if (cciBeingSpent.sourceSystemID == thisExport.sourceSystemID)
                    {
                        break;
                    }
                    cciBeingSpent = CCrossChainImport();
                }
            }

            if (cciBeingSpent.IsValid())
            {
                for (auto &oneOut : tx.vout)
                {
                    if ((cciSpending = CCrossChainImport(oneOut.scriptPubKey)).IsValid())
                    {
                        if (cciSpending.importCurrencyID == cciBeingSpent.importCurrencyID)
                        {
                            break;
                        }
                        cciSpending = CCrossChainImport();
                    }
                }
            }

            if (!cciBeingSpent.IsValid() || !cciSpending.IsValid())
            {
                if (LogAcceptCategory("crosschainimports"))
                {
                    std::string supplementalCurrency = ConnectedChains.GetFriendlyCurrencyName(thisExport.sourceSystemID);
                    printf("%s: spending supplemental export with source system %s\n", __func__, supplementalCurrency.c_str());
                    LogPrintf("%s: spending supplemental export with source system %s\n", __func__, supplementalCurrency.c_str());
                    if (LogAcceptCategory("verbose"))
                    {
                        UniValue jsonTx(UniValue::VOBJ);
                        uint256 hashBlk;
                        TxToUniv(txToSpend, hashBlk, jsonTx);
                        LogPrintf("from:\n%s\n", jsonTx.write(1,2).c_str());
                        printf("from:\n%s\n", jsonTx.write(1,2).c_str());
                        TxToUniv(tx, hashBlk, jsonTx);
                        LogPrintf("to:\n%s\n", jsonTx.write(1,2).c_str());
                        printf("to:\n%s\n", jsonTx.write(1,2).c_str());
                    }
                }
                return eval->Error("Invalid spend of supplemental export to invalid or non-import");
            }
            return true;
        }

        CCrossChainExport matchedExport;

        for (auto &oneOut : tx.vout)
        {
            // there must be an output with a valid export to the same destination
            if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                p.version >= COptCCParams::VERSION_V3 &&
                p.vData.size() &&
                (matchedExport = CCrossChainExport(p.vData[0])).IsValid() &&
                matchedExport.destCurrencyID == thisExport.destCurrencyID)
            {
                return true;
            }
        }
    }
    return eval->Error("Invalid cross chain export");
}

bool IsCrossChainExportInput(const CScript &scriptSig)
{
    return true;
}

// used to validate import of coins from one chain to another. if they are not native and are supported,
// they are represented o the chain as tokens
bool ValidateCrossChainImport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    uint32_t outNum;
    uint32_t spendingFromHeight;
    CTransaction txToSpend;
    COptCCParams p;

    // get reserve transfer to spend
    CCrossChainImport thisImport = GetImportToSpend(tx, nIn, txToSpend, spendingFromHeight, p);

    if (thisImport.IsValid())
    {
        if (CConstVerusSolutionVector::GetVersionByHeight(spendingFromHeight) < CActivationHeight::ACTIVATE_PBAAS)
        {
            return eval->Error("Multi-currency operation before PBaaS activation");
        }

        CCrossChainImport matchedImport;

        for (auto &oneOut : tx.vout)
        {
            // there must be an output with a valid import to the same destination
            if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.version >= COptCCParams::VERSION_V3 &&
                p.vData.size() &&
                (matchedImport = CCrossChainImport(p.vData[0])).IsValid() &&
                matchedImport.importCurrencyID == thisImport.importCurrencyID)
            {
                return true;
            }
        }
    }
    return eval->Error("Invalid cross chain import");
}

bool ImportHasAdequateFees(const CTransaction &tx,
                           int32_t outNum,
                           const CCurrencyDefinition &importingToDef,
                           const CCrossChainImport &cci,
                           const CCrossChainExport &ccx,
                           const CPBaaSNotarization &notarization,
                           const std::vector<CReserveTransfer> &reserveTransfers,
                           CValidationState &state,
                           uint32_t height)
{
    CCurrencyValueMap conversionMap;

    CCoinbaseCurrencyState startingState;
    uint32_t minHeight = 0;
    uint32_t maxHeight = 0;

    conversionMap.valueMap[ASSETCHAINS_CHAINID] = SATOSHIDEN;
    if (!notarization.IsRefunding() &&
        importingToDef.IsFractional() &&
        (notarization.currencyID == cci.importCurrencyID || notarization.currencyStates.count(cci.importCurrencyID)))
    {
        auto currencyMap = importingToDef.GetCurrenciesMap();
        startingState = notarization.currencyID == cci.importCurrencyID ?
                            notarization.currencyState :
                            notarization.currencyStates.find(cci.importCurrencyID)->second;

        // we need to populate the conversion map fully once we know we need to, then stop checking
        // first, determine the range of notarizations we can accept, which is the first
        // notarization we can determine was available to the other system

        if (cci.IsSameChain())
        {
            // determine the minimum source height of the reserve transfer and add its
            // pre-creation price to the conversion map
            maxHeight = ccx.sourceHeightEnd - 1;
            minHeight = ccx.sourceHeightStart > (DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA + 1) ?
                        ccx.sourceHeightStart - (DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA + 1) :
                        0;
        }
        else
        {
            CAddressIndexDbEntry txOutIdx;
            CTransaction txOut;

            std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> lastNotarization = GetLastConfirmedNotarization(ccx.sourceSystemID, height - 1);

            if (!std::get<0>(lastNotarization))
            {
                return state.Error("Cannot get prior notarization for cross chain import: " + cci.ToUniValue().write(1,2));
            }

            // calculate based on this notarization and our last one how far back to look
            // based on our block at that time
            if (std::get<2>(lastNotarization).proofRoots.count(ASSETCHAINS_CHAINID))
            {
                maxHeight = std::get<2>(lastNotarization).proofRoots[ASSETCHAINS_CHAINID].rootHeight;
                minHeight = std::max((((int32_t)maxHeight) - std::max((int32_t)((60 * 40) / ConnectedChains.ThisChain().blockTime), 50)), 1);
            }
            else
            {
                minHeight = std::max((((int32_t)height) - (int32_t)((60 / ConnectedChains.ThisChain().blockTime) * 100)), 1);
                maxHeight = height - 10;
            }
        }

        conversionMap = cci.GetBestPriorConversions(tx, outNum, importingToDef.GetID(), ASSETCHAINS_CHAINID, startingState, state, height, minHeight, maxHeight);
    }
    else if (!ConnectedChains.ThisChain().launchSystemID.IsNull() && ConnectedChains.ThisChain().IsMultiCurrency())
    {
        // accept Verus (or launching chain/system) fees 1:1 if we have no fractional converter
        conversionMap.valueMap[ConnectedChains.ThisChain().launchSystemID] = SATOSHIDEN;
    }

    for (auto &oneTransfer : reserveTransfers)
    {
        if (!oneTransfer.IsValid())
        {
            return state.Error("Invalid reserve transfer: " + oneTransfer.ToUniValue().write(1,2));
        }
        if (!conversionMap.valueMap.count(oneTransfer.feeCurrencyID))
        {
            // invalid fee currency from system
            return state.Error("Invalid fee currency for transfer 1: " + oneTransfer.ToUniValue().write(1,2));
        }

        CAmount nextLegFeeEquiv = 0;
        CCurrencyValueMap nextLegConversionMap;
        CCurrencyDefinition nextLegCurrency;
        if (importingToDef.IsFractional() && oneTransfer.HasNextLeg() && oneTransfer.destination.gatewayID != ASSETCHAINS_CHAINID)
        {
            nextLegConversionMap = cci.GetBestPriorConversions(tx, outNum, importingToDef.GetID(), oneTransfer.destination.gatewayID, startingState, state, height, minHeight, maxHeight);
            nextLegFeeEquiv = CCurrencyState::ReserveToNativeRaw(oneTransfer.destination.fees, nextLegConversionMap.valueMap[oneTransfer.feeCurrencyID]);
            nextLegCurrency = ConnectedChains.GetCachedCurrency(oneTransfer.destination.gatewayID);
            if (!nextLegCurrency.IsValid() || !(nextLegCurrency.IsPBaaSChain() || nextLegCurrency.IsGateway()))
            {
                return state.Error("Invalid next leg for transfer: " + oneTransfer.ToUniValue().write(1,2));
            }
        }

        // if we get our fees from conversion, consider the conversion + fees
        // still ensure that they are enough
        CAmount feeEquivalent = !oneTransfer.nFees ? 0 :
            oneTransfer.IsPreConversion() ? oneTransfer.nFees : CCurrencyState::ReserveToNativeRaw(oneTransfer.nFees, conversionMap.valueMap[oneTransfer.feeCurrencyID]);

        if (oneTransfer.IsPreConversion())
        {
            if (oneTransfer.feeCurrencyID != importingToDef.launchSystemID)
            {
                return state.Error("Fees for currency launch preconversions must include launch currency: " + oneTransfer.ToUniValue().write(1,2));
            }
            if (ConnectedChains.DoImportPreconvertReserveTransferPrecheck(height) && !importingToDef.GetCurrenciesMap().count(oneTransfer.FirstCurrency()))
            {
                return state.Error("Invalid source currency for preconversion: " + oneTransfer.ToUniValue().write(1,2));
            }
        }

        if (oneTransfer.IsConversion())
        {
            CAmount conversionFee = oneTransfer.IsReserveToReserve() ?
                        CReserveTransactionDescriptor::CalculateConversionFeeNoMin(oneTransfer.FirstValue()) << 1 :
                        CReserveTransactionDescriptor::CalculateConversionFeeNoMin(oneTransfer.FirstValue());

            if (!oneTransfer.IsPreConversion())
            {
                feeEquivalent +=
                    CCurrencyState::ReserveToNativeRaw(conversionFee, conversionMap.valueMap[oneTransfer.FirstCurrency()]);
            }
        }

        if (oneTransfer.IsIdentityExport())
        {
            if ((oneTransfer.HasNextLeg() && oneTransfer.destination.gatewayID != ASSETCHAINS_CHAINID ?
                    nextLegFeeEquiv :
                    feeEquivalent) < ConnectedChains.ThisChain().IDImportFee())
            {
                return state.Error("Insufficient fee for identity import: " + cci.ToUniValue().write(1,2));
            }
        }
        else if (oneTransfer.IsCurrencyExport())
        {
            CCurrencyDefinition exportingDef = oneTransfer.destination.HasGatewayLeg() && oneTransfer.destination.TypeNoFlags() != oneTransfer.destination.DEST_REGISTERCURRENCY ?
                                                    ConnectedChains.GetCachedCurrency(oneTransfer.FirstCurrency()) :
                                                    CCurrencyDefinition(oneTransfer.destination.destination);
            if (!exportingDef.IsValid())
            {
                return state.Error(strprintf("%s: Invalid currency import", __func__));
            }

            // imported currencies do need to conform to type constraints in order
            // to benefit from reduced import fees. this happens on the precheck for currency definition

            CAmount feeConversionRate = 0;

            CChainNotarizationData cnd;
            CCurrencyDefinition nextSys = ConnectedChains.GetCachedCurrency(exportingDef.systemID);
            if (nextSys.IsValid() && nextSys.IsGateway() && nextSys.proofProtocol == nextSys.PROOF_ETHNOTARIZATION)
            {
                auto lastConfirmedNotarization = GetLastConfirmedNotarization(exportingDef.systemID, height - 1);
                if (!std::get<0>(lastConfirmedNotarization) ||
                    !std::get<2>(lastConfirmedNotarization).proofRoots.count(exportingDef.systemID))
                {
                    return state.Error("Cannot get notarization data for destination system of transfer: " + oneTransfer.ToUniValue().write(1,2));
                }
                feeConversionRate = std::get<2>(lastConfirmedNotarization).currencyState.conversionPrice.size() ?
                                        std::get<2>(lastConfirmedNotarization).currencyState.conversionPrice[0] :
                                        std::get<2>(lastConfirmedNotarization).proofRoots[exportingDef.systemID].gasPrice;
            }

            int64_t registrationFee = ConnectedChains.ThisChain().GetCurrencyImportFee(exportingDef.ChainOptions() & exportingDef.OPTION_NFT_TOKEN);
            if ((oneTransfer.HasNextLeg() && oneTransfer.destination.gatewayID != ASSETCHAINS_CHAINID ? nextLegFeeEquiv : feeEquivalent) <
                CCurrencyState::NativeGasToReserveRaw(registrationFee, feeConversionRate))
            {
                return state.Error("Insufficient fee for currency import: " + cci.ToUniValue().write(1,2));
            }
        }
        else if (!cci.IsSameChain() && !oneTransfer.IsPreConversion())
        {
            // import distributes both export and import fees
            if (feeEquivalent < ConnectedChains.ThisChain().GetTransactionImportFee())
            {
                return state.Error("Insufficient fee for transaction in import: " + cci.ToUniValue().write(1,2));
            }
        }
        // import distributes both export and import fees
        if (cci.IsSameChain() && feeEquivalent < ConnectedChains.ThisChain().GetTransactionTransferFee())
        {
            return state.Error("Insufficient fee for transaction transfer in import: " + cci.ToUniValue().write(1,2));
        }
    }
    return true;
}

// ensure that the cross chain import is valid to be posted on the block chain
bool PrecheckCrossChainImport(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // while most checks on import conversion accuracy are carried out in checking reserve deposits and basic checks
    // on a transaction, this check also validates that all reserve transfer fees are adequate, including ID and
    // currency import fees as well as other cross-chain service fees. This involves determining the most favorable
    // conversion price that may have been used to calculate fee conversion and using that to accept or reject every
    // reserve transfer. It also ensures that the fee payout is properly split between miners/stakers, exporters,
    // importers, and notaries.
    if (CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_PBAAS)
    {
        return state.Error("Multi-currency operation before PBaaS activation");
    }

    bool isPreSync = chainActive.Height() < (height - 1);
    bool isPostSync = chainActive.Height() > (height - 1);
    bool deepCheckImportProof = !(isPreSync || isPostSync);

    if (!isPreSync && ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableDeFiKey()))
    {
        if (LogAcceptCategory("defi"))
        {
            LogPrintf("%s: All DeFi functions temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
        }
        return state.Error("All DeFi functions temporarily disabled for security alert by notification oracle. Import rejected.");
    }

    COptCCParams p;
    CCrossChainImport cci, sysCCI;
    CCrossChainExport ccx;
    CTransaction exportTx;
    bool haveExportTx = false;
    CPBaaSNotarization notarization;
    std::vector<CReserveTransfer> reserveTransfers;

    int32_t sysOutNum = -1, notarizationOut = -1, evidenceOutStart = -1, evidenceOutEnd = -1;
    if (tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
        p.vData.size() > 1 &&
        p.IsEvalPKOut() &&
        (cci = CCrossChainImport(p.vData[0])).IsValid() &&
        cci.GetImportInfo(tx, height, outNum, ccx, sysCCI, sysOutNum, notarization, notarizationOut, evidenceOutStart, evidenceOutEnd, reserveTransfers, state, deepCheckImportProof))
    {
        // if this is a source system cci, get the base
        if (cci.IsSourceSystemImport())
        {
            if (sysOutNum != outNum || outNum <= 0 || !sysCCI.IsValid())
            {
                return state.Error("Invalid currency import transaction with import: " + cci.ToUniValue().write(1,2));
            }
            cci = CCrossChainImport(tx.vout[outNum - 1].scriptPubKey);
            if (!cci.IsValid() ||
                cci.sourceSystemID != sysCCI.sourceSystemID ||
                sysCCI.importCurrencyID != sysCCI.sourceSystemID)
            {
                return state.Error("Invalid base import from system import: " + sysCCI.ToUniValue().write(1,2));
            }
            return true;
        }

        for (int i = outNum + 1; i < tx.vout.size(); i++)
        {
            COptCCParams dupP;
            CCrossChainImport dupCCI;
            if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(dupP) &&
                dupP.IsValid() &&
                dupP.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                dupP.vData.size() &&
                (dupCCI = CCrossChainImport(dupP.vData[0])).IsValid() &&
                dupCCI.importCurrencyID == cci.importCurrencyID)
            {
                return state.Error("Duplicate import output");
            }
        }

        if (cci.IsDefinitionImport())
        {
            // validate this belongs on a definition and is correct
            // as a definition import, it is either the block 1 import for a currency defined on
            // another chain, or a currency defined on this chain, and this will be the definition transaction
            // in either case, we should find a currency definition that matches
            auto currencyDefs = CCurrencyDefinition::GetCurrencyDefinitions(tx);
            CCurrencyDefinition importCurrency;
            CCurrencyDefinition systemCurrency;
            for (auto &oneCurrency : currencyDefs)
            {
                if (oneCurrency.GetID() == cci.importCurrencyID)
                {
                    importCurrency = oneCurrency;
                    break;
                }
            }

            if (!importCurrency.IsValid())
            {
                return state.Error("Definition import on transaction without currency definition: " + cci.ToUniValue().write(1,2));
            }

            if (!notarization.IsValid())
            {
                return state.Error("Definition import without accompanying notarization: " + cci.ToUniValue().write(1,2));
            }

            if (notarization.currencyState.currencies.size() != importCurrency.currencies.size())
            {
                return state.Error("Mismatched currency definition and notarization currencies: " + cci.ToUniValue().write(1,2));
            }
            if (notarization.currencyState.currencies.size())
            {
                CCurrencyValueMap expectedReserves;

                CCurrencyState supplyTracker;
                supplyTracker.supply = 0;

                supplyTracker.supply = supplyTracker.AddToSupply(importCurrency.GetTotalPreallocation());
                if (importCurrency.IsPBaaSChain())
                {
                    supplyTracker.supply = supplyTracker.AddToSupply(importCurrency.gatewayConverterIssuance);
                }

                CCurrencyValueMap emptyMap;
                CCurrencyValueMap primaryInMap = CCurrencyValueMap(notarization.currencyState.currencies, notarization.currencyState.primaryCurrencyIn).CanonicalMap();
                CCurrencyValueMap reserveInMap = CCurrencyValueMap(notarization.currencyState.currencies, notarization.currencyState.reserveIn).CanonicalMap();
                CCurrencyValueMap reserveMap = CCurrencyValueMap(notarization.currencyState.currencies, notarization.currencyState.reserves).CanonicalMap();

                if (importCurrency.IsFractional())
                {
                    supplyTracker.supply = supplyTracker.AddToSupply(importCurrency.initialFractionalSupply);
                    if (importCurrency.IsGatewayConverter() &&
                        importCurrency.gatewayID != importCurrency.launchSystemID)
                    {
                        for (auto &oneCurrency : currencyDefs)
                        {
                            if (oneCurrency.GetID() == importCurrency.gatewayID)
                            {
                                systemCurrency = oneCurrency;
                                break;
                            }
                        }
                        if (!systemCurrency.IsValid() ||
                            !(systemCurrency.IsPBaaSChain() || systemCurrency.IsGateway()) ||
                            systemCurrency.gatewayConverterIssuance != importCurrency.gatewayConverterIssuance)
                        {
                            return state.Error("Bridge currency issuance mismatch in definition transaction: " + tx.GetHash().GetHex());
                        }
                        if (importCurrency.gatewayConverterIssuance)
                        {
                            expectedReserves.valueMap[importCurrency.gatewayID] = importCurrency.gatewayConverterIssuance;
                        }
                        if (reserveMap != expectedReserves ||
                            reserveInMap != expectedReserves ||
                            (((notarization.currencyState.IsPrelaunch() && ConnectedChains.CheckZeroViaOnlyPostLaunch(height)) ||
                              (!notarization.currencyState.IsPrelaunch() &&
                               (importCurrency.GetID() != VERUS_CHAINID ||
                                importCurrency.launchSystemID != VERUS_CHAINID ||
                                !notarization.proofRoots.count(VERUS_CHAINID) ||
                                notarization.proofRoots[importCurrency.launchSystemID].rootHeight >= ConnectedChains.GetZeroViaHeight(true)))) &&
                            primaryInMap > CCurrencyValueMap()))
                        {
                            return state.Error("Invalid starting data in notarization for currency definition in tx 1: " + tx.GetHash().GetHex());
                        }
                    }
                }
                else if (importCurrency.currencies.size())
                {
                    if (importCurrency.conversions.size() != importCurrency.currencies.size() ||
                        importCurrency.conversions.size() != notarization.currencyState.currencies.size() ||
                        reserveMap != CCurrencyValueMap(importCurrency.currencies, importCurrency.conversions) ||
                        reserveMap != CCurrencyValueMap(notarization.currencyState.currencies, notarization.currencyState.PricesInReserve()))
                    {
                        return state.Error("Invalid conversion pricing in currency state of definition tx: " + tx.GetHash().GetHex());
                    }
                    if (CCurrencyValueMap(notarization.currencyState.currencies, notarization.currencyState.primaryCurrencyIn).CanonicalMap() != emptyMap ||
                        CCurrencyValueMap(notarization.currencyState.currencies, notarization.currencyState.reserveIn).CanonicalMap() != emptyMap)
                    {
                        return state.Error("Invalid values in notarization currency state of definition tx: " + tx.GetHash().GetHex());
                    }
                    if (((notarization.currencyState.IsPrelaunch() && ConnectedChains.CheckZeroViaOnlyPostLaunch(height)) ||
                         (!notarization.currencyState.IsPrelaunch() &&
                          importCurrency.GetID() != VERUS_CHAINID &&
                          (importCurrency.launchSystemID != VERUS_CHAINID ||
                           !notarization.proofRoots.count(VERUS_CHAINID) ||
                           notarization.proofRoots[importCurrency.launchSystemID].rootHeight >= ConnectedChains.GetZeroViaHeight(true)))) &&
                        primaryInMap > CCurrencyValueMap())
                    {
                        return state.Error("Invalid starting data in notarization for currency definition in tx 2: " + tx.GetHash().GetHex());
                    }
                }
                if (supplyTracker.supply > MAX_SUPPLY)
                {
                    return state.Error("Invalid expected supply for currency definition in tx 2: " + tx.GetHash().GetHex());
                }
            }

            // if launch is complete, it should be one of:
            // 1) a block 1 notarization
            // 2) a gateway that had no delay before startblock
            // 3) self-currency definition
            // 4) mapped currency definition (different systemID than launchSystemID, ETH proof protocol, DEST_ETH or DEST_ETHNFT nativeCurrencyID)
            if (notarization.IsLaunchComplete())
            {
                if (height != 1 &&
                    !(importCurrency.IsGateway() && importCurrency.startBlock <= height) &&
                    !(IsVerusActive() && importCurrency.GetID() == ASSETCHAINS_CHAINID) &&
                    !(importCurrency.launchSystemID == ASSETCHAINS_CHAINID &&
                      importCurrency.proofProtocol == importCurrency.PROOF_ETHNOTARIZATION &&
                      (importCurrency.nativeCurrencyID.TypeNoFlags() == CTransferDestination::DEST_ETH ||
                       importCurrency.nativeCurrencyID.TypeNoFlags() == CTransferDestination::DEST_ETHNFT)))
                {
                    return state.Error("Definition import and simultaneous active launch must be for block 1 definitions or gateway currency: " + cci.ToUniValue().write(1,2));
                }
            }
            if (!cci.hashReserveTransfers.IsNull())
            {
                return state.Error("Definition import cannot contain transfers: " + cci.ToUniValue().write(1,2));
            }
            return true;
        }

        if (ccx.IsValid() && ccx.destSystemID != ASSETCHAINS_CHAINID && notarization.IsValid() && !notarization.IsRefunding())
        {
            return state.Error("Invalid import: " + cci.ToUniValue().write(1,2));
        }
        else if (notarization.IsValid())
        {
            if (notarization.IsSameChain())
            {
                // a notarization for a later height is not valid
                if (!isPreSync &&
                    notarization.notarizationHeight > (height - 1) &&
                    !(notarization.notarizationHeight == 1 &&
                    height == 1))
                {
                    return state.Error("Notarization for import past height, likely due to reorg: " + notarization.ToUniValue().write(1,2));
                }
            }
            else if (notarization.proofRoots.count(ASSETCHAINS_CHAINID))
            {
                uint32_t rootHeight;
                auto mmv = chainActive.GetMMV();
                if ((!notarization.IsMirror() &&
                        notarization.IsSameChain() &&
                        notarization.notarizationHeight >= height) ||
                    (notarization.proofRoots.count(ASSETCHAINS_CHAINID) &&
                        ((rootHeight = notarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight) > (height - 1) ||
                        (mmv.resize(rootHeight + 1), rootHeight != (mmv.size() - 1)) ||
                        notarization.proofRoots[ASSETCHAINS_CHAINID].blockHash != chainActive[rootHeight]->GetBlockHash() ||
                        notarization.proofRoots[ASSETCHAINS_CHAINID].stateRoot != mmv.GetRoot())))
                {
                    return state.Error("Notarization for import past height or invalid: " + notarization.ToUniValue().write(1,2));
                }
            }

            // if we have the chain behind us, verify that the prior import imports the prior export
            CCurrencyDefinition sourceSystem;
            if (!isPreSync && !cci.IsDefinitionImport())
            {
                CTransaction priorImportTx, priorImportFromSystemTx, conversionImportTx;
                CCrossChainImport priorImport, conversionImport;
                CCrossChainImport priorImportFromSystem;
                if (height != 1)
                {
                    sourceSystem = ConnectedChains.GetCachedCurrency(cci.sourceSystemID);
                    priorImport = cci.GetPriorImport(tx, state, &priorImportTx);
                    if (!priorImport.IsValid())
                    {
                        if (!sourceSystem.IsValid() ||
                            sourceSystem.proofProtocol != sourceSystem.PROOF_ETHNOTARIZATION ||
                            !cci.IsInitialLaunchImport())
                        {
                            // we need to look deeper to ensure that there really is not one or that we use it
                            return state.Error("Cannot retrieve prior import: " + cci.ToUniValue().write(1,2));
                        }
                    }
                    else
                    {
                        conversionImport = priorImport;
                        conversionImportTx = priorImportTx;
                    }
                }
                if (!priorImport.IsValid() || priorImport.exportTxId.IsNull())
                {
                    if (ccx.IsValid() && !ccx.IsChainDefinition() && ccx.sourceSystemID == ASSETCHAINS_CHAINID)
                    {
                        return state.Error("Out of order export for import 1: " + cci.ToUniValue().write(1,2));
                    }
                    else if (!ccx.IsValid() && height != 1)
                    {
                        return state.Error("Out of order export for import 2: " + cci.ToUniValue().write(1,2));
                    }
                }
                else
                {
                    if (priorImport.sourceSystemID != cci.sourceSystemID)
                    {
                        for (priorImportFromSystem = priorImport.GetPriorImport(priorImportTx, state, &priorImportFromSystemTx);
                             priorImportFromSystem.IsValid() &&
                                !priorImportFromSystem.IsDefinitionImport() &&
                                !(priorImportFromSystem.IsInitialLaunchImport() && (priorImportFromSystem.importCurrencyID == ASSETCHAINS_CHAINID ||
                                                                                    priorImportFromSystem.importCurrencyID == ConnectedChains.ThisChain().GatewayConverterID())) &&
                                priorImportFromSystem.sourceSystemID != cci.sourceSystemID;
                             priorImportFromSystem = priorImport.GetPriorImport(priorImportFromSystemTx, state, &priorImportFromSystemTx))
                        {}

                        if (priorImportFromSystem.IsValid() &&
                                priorImportFromSystem.sourceSystemID == cci.sourceSystemID)
                        {
                            priorImport = priorImportFromSystem;
                            priorImportTx = priorImportFromSystemTx;
                        }
                    }
                    if (priorImport.sourceSystemID == cci.sourceSystemID)
                    {
                        LOCK(mempool.cs);
                        if (ccx.sourceSystemID == ASSETCHAINS_CHAINID)
                        {
                            // same chain, we can get the export transaction
                            uint256 blockHash;
                            if (!myGetTransaction(cci.exportTxId, exportTx, blockHash))
                            {
                                if (LogAcceptCategory("crosschainimports"))
                                {
                                    return state.Error("Can't get export for import: " + cci.ToUniValue().write(1,2));
                                }
                                else
                                {
                                    return state.Error("Can't get export for import. Missing export: " + cci.exportTxId.GetHex());
                                }
                            }

                            haveExportTx = true;

                            if (ccx.IsSystemThreadExport() || ccx.IsSupplemental())
                            {
                                return state.Error("Invalid prior import tx(" + priorImportTx.GetHash().GetHex() + "): " + cci.ToUniValue().write(1,2));
                            }

                            if (ccx.firstInput > 0)
                            {
                                if (!notarization.IsRefunding() &&
                                    (priorImport.exportTxId != exportTx.vin[ccx.firstInput - 1].prevout.hash ||
                                     priorImport.exportTxOutNum != exportTx.vin[ccx.firstInput - 1].prevout.n))
                                {
                                    LogPrint("crosschainimports", "%s: Out of order export tx(%s) from %s to %s for import %s, priorimport(%s)\n",
                                             __func__,
                                             exportTx.GetHash().GetHex().c_str(),
                                             ConnectedChains.GetFriendlyCurrencyName(cci.sourceSystemID).c_str(),
                                             ConnectedChains.GetFriendlyCurrencyName(cci.importCurrencyID).c_str(),
                                             cci.ToUniValue().write(1,2).c_str(),
                                             priorImport.ToUniValue().write(1,2).c_str());
                                    return state.Error("Out of order export for import 2: " + cci.ToUniValue().write(1,2));
                                }
                                else if (notarization.IsRefunding())
                                {
                                    int priorCCXIndex = 0;
                                    CCrossChainExport priorCcx;
                                    CTransaction priorExportTx;
                                    uint256 hashBlock;
                                    if (ccx.firstInput > 1)
                                    {
                                        if (!myGetTransaction(exportTx.vin[ccx.firstInput - 1].prevout.hash, priorExportTx, hashBlock) ||
                                            exportTx.vin[ccx.firstInput - 1].prevout.n >= priorExportTx.vout.size())
                                        {
                                            return state.Error("Can't get prior export for import: " + cci.ToUniValue().write(1,2));
                                        }
                                        priorCcx = CCrossChainExport(priorExportTx.vout[exportTx.vin[ccx.firstInput - 1].prevout.n].scriptPubKey);
                                        priorCCXIndex = ccx.firstInput - 1;
                                        if (!priorCcx.IsValid() || priorCcx.destCurrencyID != ccx.destCurrencyID)
                                        {
                                            if (ccx.firstInput < 2)
                                            {
                                                return state.Error("Invalid first input for export: " + priorCcx.ToUniValue().write(1,2) + "\nfrom tx: " + priorExportTx.GetHash().GetHex() + "\n");
                                            }
                                            priorCCXIndex--;
                                        }
                                    }
                                    if (priorExportTx.GetHash() != exportTx.vin[priorCCXIndex].prevout.hash &&
                                        (!myGetTransaction(exportTx.vin[priorCCXIndex].prevout.hash, priorExportTx, hashBlock) ||
                                         exportTx.vin[priorCCXIndex].prevout.n >= priorExportTx.vout.size()))
                                    {
                                        return state.Error("Invalid input for export from tx: " + priorExportTx.GetHash().GetHex());
                                    }

                                    // if our prior export is a system thread, go back until we find one that is not, which
                                    // should be our prior
                                    CTransaction checkExportTx = priorExportTx;
                                    int exportTxOut = exportTx.vin[priorCCXIndex].prevout.n;

                                    priorCcx = CCrossChainExport(priorExportTx.vout[exportTxOut].scriptPubKey);
                                    if (!priorCcx.IsValid())
                                    {
                                        return state.Error("Invalid prior export for import: " + cci.ToUniValue().write(1,2));
                                    }

                                    while (priorCcx.IsValid() && (priorCcx.IsSystemThreadExport() && !priorCcx.IsChainDefinition()))
                                    {
                                        int vinIndex = priorCcx.firstInput > 0 ? priorCcx.firstInput - 1 : 0;
                                        CTransaction lastExportTx = checkExportTx;
                                        exportTxOut = lastExportTx.vin[vinIndex].prevout.n;
                                        if (!myGetTransaction(lastExportTx.vin[vinIndex].prevout.hash, checkExportTx, hashBlock) ||
                                            exportTxOut >= checkExportTx.vout.size())
                                        {
                                            return state.Error("Invalid input for prior export from tx: " + checkExportTx.GetHash().GetHex());
                                        }
                                        priorCcx = CCrossChainExport(checkExportTx.vout[exportTxOut].scriptPubKey);
                                        priorCCXIndex = vinIndex;
                                        if (priorCcx.IsValid() && (!priorCcx.IsSystemThreadExport() || priorCcx.IsChainDefinition()))
                                        {
                                            priorExportTx = checkExportTx;
                                        }
                                    }

                                    if (!priorCcx.IsValid() ||
                                        (!(priorImport.IsInitialLaunchImport() && priorImport.sourceSystemHeight == priorCcx.sourceHeightEnd) &&
                                         (priorImport.exportTxId != priorExportTx.GetHash() || priorImport.exportTxOutNum != exportTxOut)) ||
                                        (((priorCcx.sourceHeightEnd + 1) != ccx.sourceHeightStart) &&
                                         ((priorCcx.sourceHeightEnd + 1) != (ccx.sourceHeightEnd + 1))))
                                    {
                                        return state.Error("Out of order export for import: " + cci.ToUniValue().write(1,2));
                                    }

                                    if (LogAcceptCategory("crosschainimports"))
                                    {
                                        if (LogAcceptCategory("verbose"))
                                        {
                                            printf("%s: cci:\n%s\npriorCci:%s\n", __func__, cci.ToUniValue().write(1,2).c_str(), priorImport.ToUniValue().write(1,2).c_str());
                                        }
                                        printf("%s: Refunding -- priorImport.exportTxId: %s, priorImport.exportTxOutNum: %d\n",
                                                __func__,
                                                priorImport.exportTxId.GetHex().c_str(),
                                                priorImport.exportTxOutNum);
                                        printf("exportTx.vin[priorCCXIndex].prevout.hash: %s, exportTx.vin[priorCCXIndex].prevout.n: %d\n",
                                                priorExportTx.GetHash().GetHex().c_str(), exportTxOut);
                                        LogPrintf("%s: Refunding -- priorImport.exportTxId: %s, priorImport.exportTxOutNum: %d\n",
                                                    __func__,
                                                    priorImport.exportTxId.GetHex().c_str(),
                                                    priorImport.exportTxOutNum);
                                        LogPrintf("exportTx.vin[priorCCXIndex].prevout.hash: %s, exportTx.vin[priorCCXIndex].prevout.n: %d\n",
                                                  priorExportTx.GetHash().GetHex().c_str(), exportTxOut);
                                    }
                                }
                            }
                            else
                            {
                                bool inputFound = false;
                                // search for a matching input
                                for (auto &oneIn : exportTx.vin)
                                {
                                    if (priorImport.exportTxId == oneIn.prevout.hash && priorImport.exportTxOutNum == oneIn.prevout.n)
                                    {
                                        inputFound = true;
                                        break;
                                    }
                                }
                                if (!inputFound)
                                {
                                    return state.Error("Out of order export for import 3: " + cci.ToUniValue().write(1,2));
                                }
                            }
                        }
                        else
                        {
                            if (!isPreSync)
                            {
                                if (ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisablePBaaSCrossChainKey()))
                                {
                                    if (LogAcceptCategory("defi"))
                                    {
                                        LogPrintf("%s: All crosschain imports temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
                                    }
                                    return state.Error("All crosschain imports temporarily disabled for security alert by notification oracle - import rejected.");
                                }

                                if (!cci.IsDefinitionImport())
                                {
                                    CCurrencyDefinition sourceSystem = ConnectedChains.GetCachedCurrency(ccx.sourceSystemID);
                                    if (!sourceSystem.IsValid())
                                    {
                                        return state.Error("Invalid source system in import or system not found");
                                    }
                                    if (sourceSystem.IsGateway() &&
                                        ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableGatewayCrossChainKey()))
                                    {
                                        if (LogAcceptCategory("defi"))
                                        {
                                            LogPrintf("%s: All gateway imports temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
                                        }
                                        return state.Error("All gateway imports temporarily disabled for security alert by notification oracle - import rejected.");
                                    }
                                }
                            }

                            // next output should be export in evidence output followed by supplemental reserve transfers for the export
                            int afterEvidence;
                            CNotaryEvidence evidence(tx, evidenceOutStart, evidenceOutEnd, CNotaryEvidence::TYPE_IMPORT_PROOF);

                            if (!evidence.IsValid())
                            {
                                return state.Error(strprintf("%s: cannot retrieve export evidence for import", __func__));
                            }

                            std::set<int> validEvidenceTypes;
                            validEvidenceTypes.insert(CHAINOBJ_TRANSACTION_PROOF);
                            CNotaryEvidence transactionProof(cci.sourceSystemID, evidence.output, evidence.state, evidence.GetSelectEvidence(validEvidenceTypes), CNotaryEvidence::TYPE_IMPORT_PROOF);

                            p = COptCCParams();
                            if (!(transactionProof.evidence.chainObjects.size() &&
                                !((CChainObject<CPartialTransactionProof> *)transactionProof.evidence.chainObjects[0])->object.GetPartialTransaction(exportTx).IsNull() &&
                                ((CChainObject<CPartialTransactionProof> *)transactionProof.evidence.chainObjects[0])->object.TransactionHash() == cci.exportTxId &&
                                exportTx.vout.size() > cci.exportTxOutNum &&
                                exportTx.vout[cci.exportTxOutNum].scriptPubKey.IsPayToCryptoCondition(p) &&
                                p.IsValid() &&
                                p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                                p.vData.size() &&
                                (ccx = CCrossChainExport(p.vData[0])).IsValid()))
                            {
                                return state.Error(strprintf("%s: invalid export evidence for import", __func__));
                            }

                            haveExportTx = true;

                            // if this is not first, get prior import from the same source system to this currency,
                            // and verify that it's last height covered is just before this one
                            CCurrencyDefinition importingCurrency = ConnectedChains.GetCachedCurrency(ccx.destCurrencyID);

                            CValidationState validState;
                            int32_t priorOutputNum = 0;
                            uint256 priorTxBlockHash;
                            CTransaction priorTxFromSys;
                            priorImport = cci.GetPriorImportFromSystem(tx, validState, &priorTxFromSys, &priorOutputNum, &priorTxBlockHash);
                            if (priorImport.IsValid())
                            {
                                if (!(priorImport.sourceSystemHeight == 1 && priorImport.IsInitialLaunchImport()) &&
                                    (priorImport.sourceSystemHeight + 1) != ccx.sourceHeightStart)
                                {
                                    if (!sourceSystem.IsValid())
                                    {
                                        sourceSystem = ConnectedChains.GetCachedCurrency(ccx.sourceSystemID);
                                    }
                                    if (!(IsVerusActive() &&
                                          sourceSystem.GetID() == ASSETCHAINS_CHAINID &&
                                          cci.importCurrencyID == ASSETCHAINS_CHAINID &&
                                          cci.IsInitialLaunchImport()) &&
                                        !(sourceSystem.IsValid() &&
                                          sourceSystem.proofProtocol == sourceSystem.PROOF_ETHNOTARIZATION &&
                                          cci.sourceSystemHeight > priorImport.sourceSystemHeight &&
                                          exportTx.vin.size() &&
                                          exportTx.vin[0].prevout.hash == priorImport.exportTxId &&
                                          exportTx.vin[0].prevout.n == priorImport.exportTxOutNum))
                                    {
                                        return state.Error(strprintf("%s: out of order cross-chain import", __func__));
                                    }
                                }
                            }
                            else if (LogAcceptCategory("notarization"))
                            {
                                UniValue jsonTx(UniValue::VOBJ);
                                TxToUniv(tx, uint256(), jsonTx);
                                LogPrintf("%s: Failed to load prior from import transaction:\n%s\n", __func__, jsonTx.write(1,2).c_str());
                            }

                            if (LogAcceptCategory("crosschainimports"))
                            {
                                if (LogAcceptCategory("verbose"))
                                {
                                    printf("%s: cci:\n%s\npriorImport:%s\n", __func__, cci.ToUniValue().write(1,2).c_str(), priorImport.ToUniValue().write(1,2).c_str());
                                }
                                printf("%s: Crosschain from system: %s to currency: %s -- priorImport.exportTxId: %s, priorImport.exportTxOutNum: %d\n",
                                        __func__,
                                        ConnectedChains.GetFriendlyCurrencyName(cci.sourceSystemID).c_str(),
                                        ConnectedChains.GetFriendlyCurrencyName(cci.importCurrencyID).c_str(),
                                        priorImport.exportTxId.GetHex().c_str(),
                                        priorImport.exportTxOutNum);
                                LogPrintf("%s: Crosschain from system: %s to currency: %s -- priorImport.exportTxId: %s, priorImport.exportTxOutNum: %d\n",
                                        __func__,
                                        ConnectedChains.GetFriendlyCurrencyName(cci.sourceSystemID).c_str(),
                                        ConnectedChains.GetFriendlyCurrencyName(cci.importCurrencyID).c_str(),
                                        priorImport.exportTxId.GetHex().c_str(),
                                        priorImport.exportTxOutNum);
                            }
                        }
                    }
                    else if (!(((priorImportFromSystem.IsDefinitionImport() &&
                                 sourceSystem.IsValid() &&
                                 sourceSystem.IsGateway() &&
                                 sourceSystem.GatewayConverterID() == cci.importCurrencyID &&
                                 priorImportFromSystem.importCurrencyID == cci.importCurrencyID)) ||
                               (priorImportFromSystem.IsInitialLaunchImport() &&
                                (priorImportFromSystem.importCurrencyID == ASSETCHAINS_CHAINID ||
                                 priorImportFromSystem.importCurrencyID == ConnectedChains.ThisChain().GatewayConverterID()))))
                    {
                        if (LogAcceptCategory("DeFi"))
                        {
                            LogPrintf("%s: No valid prior import from system %s\n", __func__, cci.ToUniValue().write(1,2).c_str());
                        }
                        return state.Error("No valid prior import from system on import: " + cci.ToUniValue().write(1,2));
                    }
                }

                CCurrencyDefinition importingToDef = ConnectedChains.GetCachedCurrency(cci.importCurrencyID);
                if (notarization.IsRefunding() &&
                    ccx.destSystemID != ASSETCHAINS_CHAINID &&
                    (importingToDef.systemID != ccx.destSystemID || importingToDef.launchSystemID != ASSETCHAINS_CHAINID))
                {
                    return state.Error("Invalid import to incorrect system: " + cci.ToUniValue().write(1,2));
                }
                // block one is checked completely elsewhere
                if (height == 1)
                {
                    return true;
                }
                if (!importingToDef.IsValid() || !((notarization.IsRefunding() && importingToDef.launchSystemID == ASSETCHAINS_CHAINID) ||
                                                importingToDef.SystemOrGatewayID() == ASSETCHAINS_CHAINID))
                {
                    return state.Error("Unable to retrieve currency for import: " + cci.ToUniValue().write(1,2));
                }

                CPBaaSNotarization pbn;

                for (auto &oneOut : conversionImportTx.vout)
                {
                    CPBaaSNotarization oneN(oneOut.scriptPubKey);
                    if (oneN.IsValid() &&
                        oneN.currencyID == cci.importCurrencyID)
                    {
                        pbn = oneN;
                        break;
                    }
                }

                if (!pbn.IsValid())
                {
                    return state.Error("Unable to retrieve prior notarization for import: " + cci.ToUniValue().write(1,2));
                }

                // if we are launching on this chain, we may be transitioning from export notarization to import/prelaunch to postlaunch
                // if we are launching on a separate chain, we are the PBaaS native or converter, and block 1 is validated differently,
                // so this should only be in the first case
                // if so, we should get the notarization from our export
                if (pbn.IsPreLaunch())
                {
                    bool isCrossChain = cci.sourceSystemID != ASSETCHAINS_CHAINID;
                    if (isCrossChain && !haveExportTx)
                    {
                        return state.Error("Invalid import for export -- import: " + cci.ToUniValue().write(1,2));
                    }
                    else if (isCrossChain)
                    {
                        for (auto &oneOut : exportTx.vout)
                        {
                            CPBaaSNotarization oneN(oneOut.scriptPubKey);
                            if (oneN.IsValid() &&
                                oneN.currencyID == cci.importCurrencyID)
                            {
                                pbn = oneN;
                                break;
                            }
                        }
                    }
                    else if (ccx.IsChainDefinition())
                    {
                        std::pair<CInputDescriptor, CPartialTransactionProof> notarizationRef;
                        CPBaaSNotarization launchNotarization, notaryNotarization;
                        if (!ConnectedChains.GetLaunchNotarization(importingToDef, notarizationRef, pbn, notaryNotarization))
                        {
                            return state.Error("Cannot get launch notarization for import: " + cci.ToUniValue().write(1,2));
                        }
                    }
                    if (!pbn.IsValid())
                    {
                        return state.Error("Cannot get notarization for import's export: " + cci.ToUniValue().write(1,2));
                    }
                }

                if ((pbn.currencyState.IsLaunchCompleteMarker() && !notarization.currencyState.IsLaunchCompleteMarker()) ||
                    (pbn.currencyState.IsRefunding() && !notarization.currencyState.IsRefunding()) ||
                    (pbn.currencyState.IsFractional() != notarization.currencyState.IsFractional()) ||
                    (!pbn.currencyState.IsPrelaunch() && notarization.currencyState.IsPrelaunch()))
                {
                    return state.Error("Invalid currency state change for import: " + cci.ToUniValue().write(1,2));
                }

                if (notarization.IsLaunchCleared() &&
                    !notarization.currencyState.IsLaunchClear())
                {
                    if (pbn.IsPreLaunch())
                    {
                        pbn.currencyState.SetLaunchClear(false);
                    }
                    else
                    {
                        pbn.currencyState.flags = notarization.currencyState.flags;
                    }
                }

                if (!sourceSystem.IsValid())
                {
                    sourceSystem = ConnectedChains.GetCachedCurrency(ccx.sourceSystemID);
                    if (!sourceSystem.IsValid())
                    {
                        return state.Error("Invalid source system for import: " + cci.ToUniValue().write(1,2));
                    }
                }

                uint256 transferHash;
                CPBaaSNotarization checkNotarization;
                std::vector<CTxOut> outputs;
                CCurrencyValueMap importedCurrency, gatewayDepositsIn, spentCurrencyOut;

                if (notarization.IsLaunchComplete() && !pbn.IsLaunchComplete())
                {
                    pbn.currencyState.SetLaunchCompleteMarker(false);
                }

                if (!pbn.NextNotarizationInfo(sourceSystem,
                                                importingToDef,
                                                ccx.sourceHeightStart ? ccx.sourceHeightStart - 1 : 0,
                                                notarization.notarizationHeight,
                                                reserveTransfers,
                                                transferHash,
                                                checkNotarization,
                                                outputs,
                                                importedCurrency,
                                                gatewayDepositsIn,
                                                spentCurrencyOut,
                                                ccx.exporter,
                                                ccx.IsClearLaunch()) ||
                    !checkNotarization.IsValid() ||
                    checkNotarization.IsRefunding() != notarization.IsRefunding())
                {
                    return state.Error("Invalid import notarization mutation\n");
                }
                if (ccx.IsClearLaunch())
                {
                    checkNotarization.SetLaunchComplete();
                    checkNotarization.currencyState.SetLaunchCompleteMarker();
                }
                if (::AsVector(checkNotarization.currencyState) != ::AsVector(notarization.currencyState))
                {
                    if (height == 1 || !ConnectedChains.IncludePostLaunchFees(height - 1))
                    {
                        checkNotarization.currencyState.primaryCurrencyIn = notarization.currencyState.primaryCurrencyIn;
                        checkNotarization.currencyState.reserveIn = notarization.currencyState.reserveIn;
                        checkNotarization.currencyState.reserveOut = notarization.currencyState.reserveOut;
                    }
                    if (ConnectedChains.CheckZeroViaOnlyPostLaunch(height) &&
                        ::AsVector(checkNotarization.currencyState) != ::AsVector(notarization.currencyState))
                    {
                        if (LogAcceptCategory("defi"))
                        {
                            LogPrintf("%s: Mismatched currency states - Expected: %s\nActual: %s\n", __func__, checkNotarization.currencyState.ToUniValue().write(1,2).c_str(), notarization.currencyState.ToUniValue().write(1,2).c_str());
                        }
                        return state.Error("Invalid import notarization output\n");
                    }
                }

                if (reserveTransfers.size())
                {
                    // if we are importing to fractional, determine the last notarization used prior to this one for
                    // imports from the system from that, the most favorable conversion rates for fee compatible conversions
                    // are determined, and those values are passed to the import

                    CCurrencyValueMap conversionMap;
                    conversionMap.valueMap[ASSETCHAINS_CHAINID] = SATOSHIDEN;

                    CCoinbaseCurrencyState startingState;
                    uint32_t minHeight = 0;
                    uint32_t maxHeight = 0;

                    if (!notarization.IsRefunding() &&
                        importingToDef.IsFractional() &&
                        (notarization.currencyID == cci.importCurrencyID || notarization.currencyStates.count(cci.importCurrencyID)))
                    {
                        auto currencyMap = importingToDef.GetCurrenciesMap();
                        startingState = notarization.currencyID == cci.importCurrencyID ?
                                            notarization.currencyState :
                                            notarization.currencyStates[cci.importCurrencyID];

                        // we need to populate the conversion map fully once we know we need to, then stop checking
                        // first, determine the range of notarizations we can accept, which is the first
                        // notarization we can determine was available to the other system

                        if (cci.IsSameChain())
                        {
                            // determine the minimum source height of the reserve transfer and add its
                            // pre-creation price to the conversion map
                            maxHeight = ccx.sourceHeightEnd - 1;
                            minHeight = ccx.sourceHeightStart > (DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA + 1) ?
                                        ccx.sourceHeightStart - (DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA + 1) :
                                        0;
                        }
                        else
                        {
                            CAddressIndexDbEntry txOutIdx;
                            CTransaction txOut;

                            std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> lastNotarization = GetLastConfirmedNotarization(ccx.sourceSystemID, height - 1);

                            if (!std::get<0>(lastNotarization))
                            {
                                return state.Error("Cannot get prior notarization for cross chain import: " + cci.ToUniValue().write(1,2));
                            }

                            // calculate based on this notarization and our last one how far back to look
                            // based on our block at that time
                            if (std::get<2>(lastNotarization).proofRoots.count(ASSETCHAINS_CHAINID))
                            {
                                maxHeight = std::get<2>(lastNotarization).proofRoots[ASSETCHAINS_CHAINID].rootHeight;
                                minHeight = std::max((((int32_t)maxHeight) - std::max((int32_t)((60 * 40) / ConnectedChains.ThisChain().blockTime), 50)), 1);
                            }
                            else
                            {
                                minHeight = std::max((((int32_t)height) - (int32_t)((60 / ConnectedChains.ThisChain().blockTime) * 100)), 1);
                                maxHeight = height - 10;
                            }
                        }

                        conversionMap = cci.GetBestPriorConversions(tx, outNum, importingToDef.GetID(), ASSETCHAINS_CHAINID, startingState, state, height, minHeight, maxHeight);
                    }
                    else if (!ConnectedChains.ThisChain().launchSystemID.IsNull() && ConnectedChains.ThisChain().IsMultiCurrency())
                    {
                        // accept Verus (or launching chain/system) fees 1:1 if we have no fractional converter
                        conversionMap.valueMap[ConnectedChains.ThisChain().launchSystemID] = SATOSHIDEN;
                    }

                    for (auto &oneTransfer : reserveTransfers)
                    {
                        if (!oneTransfer.IsValid())
                        {
                            return state.Error("Invalid reserve transfer: " + oneTransfer.ToUniValue().write(1,2));
                        }
                        if (!conversionMap.valueMap.count(oneTransfer.feeCurrencyID))
                        {
                            // invalid fee currency from system
                            return state.Error("Invalid fee currency for transfer 1: " + oneTransfer.ToUniValue().write(1,2));
                        }

                        CAmount nextLegFeeEquiv = 0;
                        CCurrencyValueMap nextLegConversionMap;
                        CCurrencyDefinition nextLegCurrency;
                        if (importingToDef.IsFractional() && oneTransfer.HasNextLeg() && oneTransfer.destination.gatewayID != ASSETCHAINS_CHAINID)
                        {
                            nextLegConversionMap = cci.GetBestPriorConversions(tx, outNum, importingToDef.GetID(), oneTransfer.destination.gatewayID, startingState, state, height, minHeight, maxHeight);
                            nextLegFeeEquiv = CCurrencyState::ReserveToNativeRaw(oneTransfer.destination.fees, nextLegConversionMap.valueMap[oneTransfer.feeCurrencyID]);
                            nextLegCurrency = ConnectedChains.GetCachedCurrency(oneTransfer.destination.gatewayID);
                            if (!nextLegCurrency.IsValid() || !(nextLegCurrency.IsPBaaSChain() || nextLegCurrency.IsGateway()))
                            {
                                return state.Error("Invalid next leg for transfer: " + oneTransfer.ToUniValue().write(1,2));
                            }
                        }

                        if (oneTransfer.IsPreConversion())
                        {
                            if (oneTransfer.feeCurrencyID != importingToDef.launchSystemID)
                            {
                                return state.Error("Fees for currency launch preconversions must include launch currency: " + oneTransfer.ToUniValue().write(1,2));
                            }
                            if (ConnectedChains.DoImportPreconvertReserveTransferPrecheck(height) && !importingToDef.GetCurrenciesMap().count(oneTransfer.FirstCurrency()))
                            {
                                return state.Error("Invalid source currency for preconversion: " + oneTransfer.ToUniValue().write(1,2));
                            }
                        }

                        if (oneTransfer.IsCurrencyExport() &&
                            ConnectedChains.IncludePostLaunchFees(height))
                        {
                            CCurrencyDefinition nextSys = oneTransfer.destination.HasGatewayLeg() ?
                                                            ConnectedChains.GetCachedCurrency(oneTransfer.destination.gatewayID) :
                                                            ConnectedChains.GetCachedCurrency(oneTransfer.GetImportCurrency());

                            if (!nextSys.systemID.IsNull() &&
                                !(nextSys.IsGateway() || nextSys.IsPBaaSChain()))
                            {
                                nextSys = ConnectedChains.GetCachedCurrency(nextSys.systemID);
                            }
                            uint160 nextSysID = nextSys.GetID();
                            if (nextSysID != ASSETCHAINS_CHAINID)
                            {
                                if (!nextSys.IsValid() ||
                                    !(nextSys.IsGateway() || nextSys.IsPBaaSChain()))
                                {
                                    return state.Error("Invalid destination system for currency export: " + oneTransfer.ToUniValue().write(1,2));
                                }

                                CChainNotarizationData cnd;
                                if (!GetNotarizationData(nextSysID, cnd) ||
                                    !cnd.IsConfirmed() ||
                                    !cnd.vtx[cnd.lastConfirmed].second.proofRoots.count(nextSys.GetID()))
                                {
                                    return state.Error("Cannot get notarization data for destination system of transfer: " + oneTransfer.ToUniValue().write(1,2));
                                }
                            }
                        }
                    }
                    return true;
                }
                else
                {
                    return true;
                }
            }
        }
    }

    if (!state.IsError())
    {
        return state.Error("Invalid cross chain import");
    }
    return false;
}

// ensure that the cross chain export is valid to be posted on the block chain
bool PrecheckCrossChainExport(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // ensure that all reserve transfers spent are properly accounted for
    if (CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_PBAAS)
    {
        return state.Error("Multi-currency operation before PBaaS activation");
    }

    // ensure that this transaction has necessary finalization & notarization outputs, as required
    // - create parameter to add a currency to the wallet black/broken list if a bridge is clearly blocked by an error
    // when rolling up an export, or blocked at import to prevent continuously trying to process transactions on a failed bridge
    // do not roll up or import currencies with broken bridges

    // check that all reserve transfers are matched to this export, and no others are mined in to the block that should be included
    COptCCParams p;
    CCrossChainExport ccx;
    int primaryExportOut = -1, nextOutput;

    CPBaaSNotarization notarization;

    std::vector<CReserveTransfer> reserveTransfers;
    CCurrencyDefinition destSystem;
    std::vector<ChainTransferData> txInputVec;

    bool isPreSync = chainActive.Height() < (height - 1);

    if (!isPreSync && ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableDeFiKey()))
    {
        if (LogAcceptCategory("defi"))
        {
            LogPrintf("%s: All DeFi functions temporarily disabled for security alert by notification oracle %s. Export rejected.\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
        }
        return state.Error("All DeFi functions temporarily disabled for security alert by notification oracle. Export rejected.");
    }

    if (!(tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
          p.IsValid() &&
          p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
          p.vData.size() &&
          (ccx = CCrossChainExport(p.vData[0])).IsValid() &&
          (ccx.IsSupplemental() ||
           (ccx.sourceSystemID == ASSETCHAINS_CHAINID &&
            ccx.numInputs < tx.vin.size() &&
            ((destSystem = ConnectedChains.GetCachedCurrency(ccx.destSystemID)).IsValid() || ccx.IsChainDefinition()) &&
             ccx.GetExportInfo(tx, outNum, primaryExportOut, nextOutput, notarization, reserveTransfers, state,
                ccx.IsChainDefinition() ? CCurrencyDefinition::EProofProtocol::PROOF_PBAASMMR : (CCurrencyDefinition::EProofProtocol)destSystem.proofProtocol))) &&
          p.IsEvalPKOut()))
    {
        return state.Error("Invalid cross chain export");
    }

    // if we are not the primary export out or we are supplemental, no need to check further
    if (ccx.IsSupplemental() || outNum != primaryExportOut)
    {
        return true;
    }

    if (height > 1 && ccx.sourceHeightEnd >= height && ccx.sourceSystemID == ASSETCHAINS_CHAINID)
    {
        return state.Error("Export source height is too high for current height");
    }

    CObjectFinalization exportFinalization, tmpFinalization;

    for (int i = outNum + 1; i < tx.vout.size(); i++)
    {
        COptCCParams dupP;
        CCrossChainExport dupCCX;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(dupP) &&
            dupP.IsValid() &&
            dupP.evalCode == EVAL_CROSSCHAIN_EXPORT &&
            dupP.vData.size() &&
            (dupCCX = CCrossChainExport(dupP.vData[0])).IsValid() &&
            dupCCX.destCurrencyID == ccx.destCurrencyID)
        {
            return state.Error("Duplicate export output");
        }
        else if (dupP.IsValid() &&
                 dupP.evalCode == EVAL_FINALIZE_EXPORT &&
                 dupP.vData.size() &&
                 (tmpFinalization = CObjectFinalization(dupP.vData[0])).IsValid() &&
                 tmpFinalization.output.hash.IsNull() &&
                 tmpFinalization.output.n == outNum)
        {
            if (exportFinalization.IsValid())
            {
                return state.Error("Duplicate export finalization");
            }
            exportFinalization = tmpFinalization;
        }
    }

    // all of the input descriptors and no others should be in the export's reserve transfers
    CCurrencyValueMap totalCurrencyExported;

    CCurrencyDefinition thisDef, sourceDef;

    // if this is the definition export, we need to get the actual currency
    if (ccx.IsChainDefinition())
    {
        bool found = false;
        CCurrencyDefinition newCurrency;
        if (ccx.destSystemID == ASSETCHAINS_CHAINID)
        {
            destSystem = ConnectedChains.ThisChain();
        }
        for (auto &oneOut : tx.vout)
        {
            CCurrencyDefinition tmpCurrency = CCurrencyDefinition(oneOut.scriptPubKey);
            if (tmpCurrency.IsValid())
            {
                if (tmpCurrency.GetID() == ccx.destSystemID)
                {
                    destSystem = tmpCurrency;
                }
                if (tmpCurrency.GetID() == ccx.destCurrencyID)
                {
                    newCurrency = tmpCurrency;
                }
            }

            if (destSystem.IsValid() && newCurrency.IsValid())
            {
                found = true;
                thisDef = newCurrency;
            }
        }
        if (!found)
        {
            return state.Error("Invalid cross chain export - cannot find currency and system definition for destination");
        }
        if (ccx.numInputs)
        {
            return state.Error("Invalid cross chain export - cannot include inputs on definition export");
        }
        if (ccx.totalFees != CCurrencyValueMap(std::vector<uint160>({ASSETCHAINS_CHAINID}),
                                               std::vector<int64_t>({ConnectedChains.ThisChain().LaunchFeeImportShare(newCurrency.options)})) ||
            ccx.totalAmounts != ccx.totalFees)
        {
            return state.Error("Invalid cross chain export for definition - incorrect fee and/or amount totals " + ccx.ToUniValue().write(1,2));
        }
    }
    else if (isPreSync)
    {
        for (auto &oneTransfer : reserveTransfers)
        {
            totalCurrencyExported += oneTransfer.TotalCurrencyOut();
        }
    }
    else
    {
        // make sure that every reserve transfer that SHOULD BE included (all mined in relevant blocks) IS included, no exceptions
        // verify all currency totals
        multimap<std::pair<uint32_t, uint160>, std::pair<CInputDescriptor, CReserveTransfer>> inputDescriptors;

        // ensure we use the correct condition
        // and that there is no risk of missing valid transfers with the check we end up with here
        if (ccx.sourceHeightStart > 0 &&
            (!GetChainTransfersUnspentBy(inputDescriptors, ccx.destCurrencyID, ccx.sourceHeightStart, ccx.sourceHeightEnd, height, tx.GetHash()) ||
             !GetChainTransfersBetween(inputDescriptors, ccx.destCurrencyID, ccx.sourceHeightEnd + 1, std::min(height, ccx.sourceHeightEnd + 2))))
        {
            return state.Error("Error retrieving cross chain transfers");
        }

        thisDef = ConnectedChains.GetCachedCurrency(ccx.destCurrencyID);
        bool isClearLaunchExport = ccx.IsClearLaunch();
        uint32_t addHeight = ccx.sourceHeightEnd, nextHeight = std::min(ccx.sourceHeightEnd + 2, height);
        int curIDExports = 0;
        int curCurrencyExports = 0;

        std::multimap<uint32_t, ChainTransferData> _txInputs;
        for (auto &oneInput : inputDescriptors)
        {
            _txInputs.insert(std::make_pair(oneInput.first.first, ChainTransferData({oneInput.first.first, oneInput.second.first, oneInput.second.second})));
        }

        if (LogAcceptCategory("crosschainexports"))
        {
            printf("%s: checking %ld transfers for inclusion between blocks %u - %u, inclusive at height %d\n", __func__, _txInputs.size(), ccx.sourceHeightStart, addHeight, chainActive.Height());
            LogPrintf("%s: checking %ld transfers for inclusion between blocks %u - %u, inclusive at height %d\n", __func__, _txInputs.size(), ccx.sourceHeightStart, addHeight, chainActive.Height());
            uint32_t curBlockNum = 0;
            int transferCount = 0;
            for (auto &oneTransfer : _txInputs)
            {
                if (curBlockNum && curBlockNum != oneTransfer.first)
                {
                    printf("%d transfers from block %u\n", transferCount, curBlockNum);
                    LogPrintf("%d transfers from block %u\n", transferCount, curBlockNum);
                    curBlockNum = oneTransfer.first;
                    transferCount = 0;
                }
                transferCount++;
            }
            if (curBlockNum)
            {
                printf("%d transfers from block %u\n", transferCount, curBlockNum);
                LogPrintf("%d transfers from block %u\n", transferCount, curBlockNum);
            }
        }

        txInputVec = ConnectedChains.CalcTxInputs(thisDef,
                                                  isClearLaunchExport,
                                                  ccx.sourceHeightStart ? ccx.sourceHeightStart - 1 : 0,
                                                  addHeight,
                                                  nextHeight,
                                                  height,
                                                  height - 1,
                                                  curIDExports,
                                                  curCurrencyExports,
                                                  _txInputs);

        if (LogAcceptCategory("crosschainexports"))
        {
            printf("%ld transfers from block %u to %u\n", txInputVec.size(), ccx.sourceHeightStart ? ccx.sourceHeightStart - 1 : 0, txInputVec.size() ? std::get<0>(txInputVec.back()) : addHeight);
            LogPrintf("%ld transfers from block %u to %u\n", txInputVec.size(), ccx.sourceHeightStart ? ccx.sourceHeightStart - 1 : 0, txInputVec.size() ? std::get<0>(txInputVec.back()) : addHeight);
        }

        // the input vec should be the same as the export transfers
        if (!isPreSync &&
            (ccx.reserveTransfers.size() ||
             reserveTransfers.size() != txInputVec.size() ||
             ccx.IsClearLaunch() != isClearLaunchExport))
        {
            if (LogAcceptCategory("crosschainexports") || LogAcceptCategory("mevattack"))
            {
                printf("%s: mismatch transfer sizes: ccx.reserveTransfers.size(): %ld, reserveTransfers.size(): %ld, txInputVec.size(): %ld\n",
                       __func__, ccx.reserveTransfers.size(), reserveTransfers.size(), txInputVec.size());
                LogPrintf("%s: mismatch transfer sizes: ccx.reserveTransfers.size(): %ld, reserveTransfers.size(): %ld, txInputVec.size(): %ld\n",
                       __func__, ccx.reserveTransfers.size(), reserveTransfers.size(), txInputVec.size());
                printf("height: %u, currencyname: %s, ccx: %s\n", height, thisDef.name.c_str(), ccx.ToUniValue().write(1,2).c_str());
                LogPrintf("height: %u, currencyname: %s, ccx: %s\n", height, thisDef.name.c_str(), ccx.ToUniValue().write(1,2).c_str());
                printf("firsinput: %s\n", CUTXORef(tx.vin[0].prevout).ToUniValue().write().c_str());
                LogPrintf("firsinput: %s\n", CUTXORef(tx.vin[0].prevout).ToUniValue().write().c_str());
            }
            return state.Error("Export is not exporting cross chain transfers correctly as required by protocol, currencyid: " + 
                                EncodeDestination(CIdentityID(ccx.destCurrencyID)) + " hash: " + tx.GetHash().GetHex());
        }

        std::set<std::pair<uint256, int>> utxos;
        if (ccx.numInputs)
        {
            if (ccx.firstInput < 0)
            {
                return state.Error("First export index invalid");
            }
            for (int i = ccx.firstInput; i < (ccx.firstInput + ccx.numInputs); i++)
            {
                if (i < 0 || i >= tx.vin.size())
                {
                    return state.Error("Input index out of range");
                }
                utxos.insert(std::make_pair(tx.vin[i].prevout.hash, tx.vin[i].prevout.n));
            }
        }

        for (auto &oneTransfer : txInputVec)
        {
            std::pair<uint256, int> transferOutput = make_pair(std::get<1>(oneTransfer).txIn.prevout.hash, std::get<1>(oneTransfer).txIn.prevout.n);
            if (!utxos.count(transferOutput))
            {
                return state.Error("Export excludes valid reserve transfer from source block");
            }
            totalCurrencyExported += std::get<2>(oneTransfer).TotalCurrencyOut();
            utxos.erase(transferOutput);
        }

        if (utxos.size())
        {
            if (LogAcceptCategory("crosschainexport"))
            {
                LogPrintf("%s: Invalid export input that was not mined in as valid reserve transfer\n", __func__);
                for (auto &oneUtxo : utxos)
                {
                    LogPrintf("txid: %s, output #: %d\n", oneUtxo.first.GetHex().c_str(), oneUtxo.second);
                }
            }
            return state.Error("Invalid export input that was not mined in as valid reserve transfer");
        }
    }

    if (((ccx.IsClearLaunch() || (ccx.IsSameChain() && ccx.IsPostlaunch())) &&
         !exportFinalization.IsValid()) &&
        !(thisDef.IsValid() &&
          thisDef.GetID() == ASSETCHAINS_CHAINID ||
          thisDef.IsGateway()))
    {
        return state.Error("Clear launch export or post launch of anything but a gateway on same chain must include export finalization output");
    }

    CCurrencyValueMap extraLaunchFee, localFeeShare;

    if (ccx.IsClearLaunch() || ccx.IsChainDefinition())
    {
        // if this is a PBaaS launch, this should be the coinbase, and we need to get the parent chain definition,
        // including currency launch prices from the current transaction
        CCurrencyDefinition gatewayConverter;
        if (height == 1 || ccx.IsChainDefinition())
        {
            CCurrencyDefinition startingDef;
            std::vector<CCurrencyDefinition> currencyDefs = CCurrencyDefinition::GetCurrencyDefinitions(tx);

            for (auto &oneCur : currencyDefs)
            {
                if (oneCur.GetID() == ccx.destCurrencyID)
                {
                    startingDef = oneCur;
                }
            }

            for (auto &oneCur : currencyDefs)
            {
                uint160 curID = oneCur.GetID();
                if (curID == ccx.sourceSystemID)
                {
                    sourceDef = oneCur;
                }
                else if ((oneCur.IsGateway() && height != 1 && startingDef.IsGatewayConverter() && startingDef.gatewayID == oneCur.GetID()) ||
                         (oneCur.GetID() == ccx.destSystemID))
                {
                    destSystem = oneCur;
                }
                else if (oneCur.IsGatewayConverter() && oneCur.gatewayID == ccx.destCurrencyID)
                {
                    gatewayConverter = oneCur;
                }
            }
            if (!sourceDef.IsValid() && ccx.IsChainDefinition())
            {
                sourceDef = ConnectedChains.ThisChain();
            }
            if (!startingDef.IsValid() ||
                (!startingDef.launchSystemID.IsNull() &&
                 (!sourceDef.IsValid() ||
                  startingDef.launchSystemID != sourceDef.GetID())) ||
                (startingDef.IsGatewayConverter() &&
                 destSystem.GetID() != startingDef.gatewayID))
            {
                return state.Error("Invalid launch currency");
            }
            thisDef = startingDef;
        }
        else
        {
            thisDef = ConnectedChains.GetCachedCurrency(ccx.destCurrencyID);
            sourceDef = ConnectedChains.ThisChain();
            if (!thisDef.IsValid() ||
                !sourceDef.IsValid() ||
                (thisDef.launchSystemID != sourceDef.GetID() && !(sourceDef.IsGateway() && thisDef.launchSystemID == thisDef.systemID)) ||
                ccx.sourceSystemID != thisDef.launchSystemID)
            {
                return state.Error("Invalid source or launch currency");
            }
        }
        if (ccx.IsChainDefinition())
        {
            totalCurrencyExported.valueMap[sourceDef.GetID()] += sourceDef.LaunchFeeImportShare(thisDef.ChainOptions());
            localFeeShare.valueMap[sourceDef.GetID()] = sourceDef.LaunchFeeExportShare(thisDef.ChainOptions());
            if (thisDef.IsGatewayConverter())
            {
                if (!destSystem.IsValid() || destSystem.GatewayConverterID() != thisDef.GetID())
                {
                    return state.Error("Invalid system currency or system definition not found");
                }
                if (thisDef.systemID != ASSETCHAINS_CHAINID)
                {
                    localFeeShare.valueMap[sourceDef.GetID()] += sourceDef.LaunchFeeExportShare(destSystem.ChainOptions());
                    extraLaunchFee.valueMap[sourceDef.GetID()] = sourceDef.LaunchFeeImportShare(destSystem.ChainOptions());
                }
            }
            else if (thisDef.IsPBaaSChain() || thisDef.IsGateway())
            {
                if (!thisDef.GatewayConverterID().IsNull() && !gatewayConverter.IsValid())
                {
                    return state.Error("Invalid gateway converter currency or definition not found");
                }
                if (gatewayConverter.IsValid() && gatewayConverter.systemID != ASSETCHAINS_CHAINID)
                {
                    localFeeShare.valueMap[sourceDef.GetID()] += sourceDef.LaunchFeeExportShare(gatewayConverter.ChainOptions());
                    extraLaunchFee.valueMap[sourceDef.GetID()] = sourceDef.LaunchFeeImportShare(gatewayConverter.ChainOptions());
                }
            }
        }
    }

    if (!(height == 1 || ccx.IsChainDefinition()))
    {
        if (!isPreSync)
        {
            if (height <= ccx.sourceHeightEnd)
            {
                if (LogAcceptCategory("crosschainexports"))
                {
                    printf("%s: Invalid export with sourceHeightEnd greater than or equal to height of block\n", __func__);
                    LogPrintf("%s: Invalid export with sourceHeightEnd greater than or equal to height of block\n", __func__);
                }
                return state.Error("Invalid export with sourceHeightEnd greater than or equal to height of block");
            }

            std::set<uint32_t> blockLottery;
            std::vector<uint32_t> blockLotteryVec;
            for (auto &oneInput : txInputVec)
            {
                blockLottery.insert(std::get<0>(oneInput));
            }
            for (auto &oneHeight : blockLottery)
            {
                blockLotteryVec.push_back(oneHeight);
            }

            if (blockLotteryVec.size())
            {
                uint256 selectBlockEntropy = EntropyHashFromHeight(CBlockIndex::BlockEntropyKey(), ccx.sourceHeightEnd, thisDef.GetID());
                uint64_t intermediateEntropy = UintToArith256(selectBlockEntropy).GetLow64();
                int blockRewardNum = blockLotteryVec[intermediateEntropy % blockLotteryVec.size()];

                // after launch, one fee recipient must be the first recipient of the coinbase reward for the last
                // block in the export sequence
                CBlock block;
                CBlockIndex* pblockindex = chainActive[blockRewardNum];

                if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus(), 1))
                {
                    if (LogAcceptCategory("crosschainexports"))
                    {
                        printf("%s: Unable to read block from disk for fee recipient\n", __func__);
                        LogPrintf("%s: Unable to read block from disk for fee recipient\n", __func__);
                    }
                    return state.Error("Unable to determine fee recipient");
                }

                std::vector<CTxDestination> addresses;
                int nRequired;
                COptCCParams frP;
                txnouttype txOutType;
                if (block.vtx.size() &&
                    block.vtx[0].vout.size() &&
                    ExtractDestinations(block.vtx[0].vout[0].scriptPubKey, txOutType, addresses, nRequired) &&
                    addresses.size() &&
                    nRequired == 1)
                {
                    CTxDestination feeRecipient = GetCompatibleAuxDestination(ccx.exporter, CCurrencyDefinition::EProofProtocol::PROOF_PBAASMMR);
                    if (block.vtx[0].vout[0].scriptPubKey.IsPayToCryptoCondition(frP) && frP.evalCode != EVAL_NONE)
                    {
                        CCcontract_info CC;
                        CCcontract_info *cp;

                        cp = CCinit(&CC, frP.evalCode);
                        CTxDestination evalPKH = CPubKey(ParseHex(CC.CChexstr)).GetID();

                        // first non-default address is the fee recipient
                        for (auto &oneDest : addresses)
                        {
                            if (oneDest == evalPKH || oneDest.which() == COptCCParams::ADDRTYPE_INVALID || oneDest.which() == COptCCParams::ADDRTYPE_INDEX)
                            {
                                continue;
                            }
                            feeRecipient = oneDest;
                            break;
                        }
                    }
                    else
                    {
                        feeRecipient = addresses[0];
                    }
                    if (feeRecipient != TransferDestinationToDestination(ccx.exporter) &&
                        feeRecipient != TransferDestinationToDestination(ccx.exporter.GetAuxDest(0)))
                    {
                        if (LogAcceptCategory("crosschainexports"))
                        {
                            printf("%s: Invalid fee recipient for export\n", __func__);
                            LogPrintf("%s: Invalid fee recipient for export\n", __func__);
                        }
                        return state.Error("Invalid fee recipient for export " + ccx.ToUniValue().write());
                    }
                }
            }

            if (!destSystem.IsValid())
            {
                return state.Error("Invalid destination system in export or system not found");
            }
            if (destSystem.systemID != ASSETCHAINS_CHAINID && ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisablePBaaSCrossChainKey()))
            {
                if (LogAcceptCategory("defi"))
                {
                    LogPrintf("%s: All crosschain exports temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
                }
                return state.Error("All crosschain exports temporarily disabled for security alert by notification oracle - export rejected.");
            }
            if (destSystem.IsGateway() &&
                ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableGatewayCrossChainKey()))
            {
                if (LogAcceptCategory("defi"))
                {
                    LogPrintf("%s: All gateway exports temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
                }
                return state.Error("All gateway exports temporarily disabled for security alert by notification oracle - export rejected.");
            }
        }

        if (notarization.IsValid())
        {
            if (!notarization.IsPreLaunch())
            {
                return state.Error("Only prelaunch exports should have valid notarizations");
            }
            CTransaction prevNotTx;
            uint256 blkHash;
            COptCCParams prevP;
            auto priorNotarization = GetPriorReferencedNotarization(tx, nextOutput - 1, notarization);
            if (!std::get<3>(priorNotarization).IsValid())
            {
                return state.Error("Non-definition exports with valid notarizations must have prior notarizations");
            }

            CPBaaSNotarization &pbn = std::get<3>(priorNotarization);
            CCurrencyDefinition destCurrency = ConnectedChains.GetCachedCurrency(pbn.currencyID);

            if (ccx.sourceSystemID != ASSETCHAINS_CHAINID || !destCurrency.IsValid())
            {
                return state.Error("Invalid export source system or destination currency");
            }

            uint256 transferHash;
            CPBaaSNotarization checkNotarization;
            std::vector<CTxOut> outputs;
            CCurrencyValueMap importedCurrency, gatewayDepositsIn, spentCurrencyOut;
            if (!pbn.NextNotarizationInfo(ConnectedChains.ThisChain(),
                                          destCurrency,
                                          ccx.sourceHeightStart ? ccx.sourceHeightStart - 1 : 0,
                                          notarization.notarizationHeight,
                                          reserveTransfers,
                                          transferHash,
                                          checkNotarization,
                                          outputs,
                                          importedCurrency,
                                          gatewayDepositsIn,
                                          spentCurrencyOut,
                                          ccx.exporter) ||
                !checkNotarization.IsValid() ||
                (checkNotarization.IsRefunding() != notarization.IsRefunding()) ||
                ::AsVector(checkNotarization.currencyState) != ::AsVector(notarization.currencyState))
            {
                checkNotarization.currencyState.reserveIn = notarization.currencyState.reserveIn;
                if (ConnectedChains.CheckZeroViaOnlyPostLaunch(height) || ::AsVector(checkNotarization.currencyState) != ::AsVector(notarization.currencyState))
                {
                    if (LogAcceptCategory("defi"))
                    {
                        LogPrintf("%s: Mismatched currency states on export - Expected: %s\nActual: %s\n", __func__, checkNotarization.currencyState.ToUniValue().write(1,2).c_str(), notarization.currencyState.ToUniValue().write(1,2).c_str());
                    }
                    return state.Error("Invalid notarization mutation\n");
                }
            }

            if (ccx.totalFees != CCurrencyValueMap(notarization.currencyState.currencies, notarization.currencyState.fees))
            {
                return state.Error("Export fee estimate doesn't match notarization - may only be result of async loading and not error");
            }
        }
    }
    if (ccx.totalAmounts != totalCurrencyExported && !isPreSync)
    {
        return state.Error("Exported currency totals error");
    }

    // now, check that all amounts taken in have gone into reserve deposits
    if (height != 1 &&
        totalCurrencyExported > CCurrencyValueMap())
    {
        // figure out how much are in reserve deposits. there should not be too much or too little
        bool isCrossSystem = ccx.destSystemID != ASSETCHAINS_CHAINID;
        uint160 reserveDepositHolder = isCrossSystem ? ccx.destSystemID : ccx.destCurrencyID;
        CCurrencyValueMap reserveDepositOutput;
        CCurrencyValueMap expectedReserveDeposits;
        CCurrencyValueMap expectedBurn;
        CCrossChainImport cci;
        for (int i = 0; i < tx.vout.size(); i++)
        {
            COptCCParams p;
            CReserveDeposit rd;
            if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_RESERVE_DEPOSIT &&
                p.vData.size() &&
                (rd = CReserveDeposit(p.vData[0])).IsValid() &&
                rd.controllingCurrencyID == reserveDepositHolder) {
                reserveDepositOutput += rd.reserveValues;
            }
            else if (p.IsValid() &&
                       p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                       !ccx.IsChainDefinition() &&
                       p.vData.size() &&
                       (cci = CCrossChainImport(p.vData[0])).IsValid() &&
                       cci.importCurrencyID == ccx.destCurrencyID)
            {
                return state.Error("Invalid export combined with import without currency definition");
            }
        }
        // if cross system, we may remove some due to burning
        if (isCrossSystem)
        {
            if (!ConnectedChains.CurrencyExportStatus(ccx.totalAmounts, ASSETCHAINS_CHAINID, ccx.destSystemID, expectedReserveDeposits, expectedBurn))
            {
                return state.Error("Cross system currency export error");
            }
            if ((expectedReserveDeposits + extraLaunchFee) != reserveDepositOutput)
            {
                return state.Error("Incorrect reserve deposits for export transaction");
            }
            if (ccx.IsChainDefinition())
            {
                const CCoins *coins;
                CCoinsView dummy;
                CCoinsViewCache view(&dummy);

                LOCK(mempool.cs);

                CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
                view.SetBackend(viewMemPool);
                CReserveTransactionDescriptor rtxd(tx, view, height);
                CCurrencyValueMap totalFees = rtxd.ReserveFees();
                totalFees.valueMap[ASSETCHAINS_CHAINID] = rtxd.NativeFees();
                if ((totalFees - localFeeShare).HasNegative())
                {
                    return state.Error("Insufficient fees for currency definition with export");
                }
            }
        }
        else if (!(ccx.IsChainDefinition() && ASSETCHAINS_CHAINID == ccx.destCurrencyID && IsVerusActive()) && (totalCurrencyExported + extraLaunchFee) != reserveDepositOutput)
        {
            return state.Error("Invalid export transaction");
        }
    }

    return true;
}

bool IsCrossChainImportInput(const CScript &scriptSig)
{
    return true;
}

std::tuple<bool, uint32_t, CTransaction, COptCCParams> GetPriorOutputTx(const CTransaction &spendingTx, uint32_t nIn)
{
    std::tuple<bool, uint32_t, CTransaction, COptCCParams> retVal({false, 0, CTransaction(), COptCCParams()});

    // if not fulfilled, ensure that no part of the primary identity is modified
    COptCCParams p;
    uint256 blkHash;
    if ((std::get<0>(retVal) = myGetTransaction(spendingTx.vin[nIn].prevout.hash, std::get<2>(retVal), blkHash)))
    {
        auto bIt = mapBlockIndex.find(blkHash);
        if (bIt == mapBlockIndex.end() || !bIt->second)
        {
            std::get<1>(retVal) = 0;
        }
        else
        {
            std::get<1>(retVal) = bIt->second->GetHeight();
        }
        if (std::get<2>(retVal).vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid())
        {
            std::get<3>(retVal) = p;
        }
    }
    return retVal;
}

bool ValidateFinalizeExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    auto priorTxInfo = GetPriorOutputTx(tx, nIn);
    if (!std::get<0>(priorTxInfo))
    {
        return eval->Error("Cannot retrieve spent export finalization");
    }

    CObjectFinalization of(std::get<2>(priorTxInfo).vout[tx.vin[nIn].prevout.n].scriptPubKey);
    if (!of.IsValid())
    {
        return eval->Error("Invalid output to spend");
    }

    CTransaction exportTx;
    uint256 blockHash;
    if (!of.GetOutputTransaction(std::get<2>(priorTxInfo), exportTx, blockHash) ||
        exportTx.vout.size() <= of.output.n)
    {
        return eval->Error("Cannot get export output from finalization");
    }
    CCrossChainExport ccx(exportTx.vout[of.output.n].scriptPubKey);
    if (!ccx.IsValid())
    {
        return eval->Error("Invalid export output from finalization");
    }

    if (LogAcceptCategory("finalizeexports") && LogAcceptCategory("verbose"))
    {
        UniValue scriptUni(UniValue::VOBJ);
        ScriptPubKeyToUniv(std::get<2>(priorTxInfo).vout[tx.vin[nIn].prevout.n].scriptPubKey, scriptUni, false, false);
        UniValue jsonTx(UniValue::VOBJ);
        TxToUniv(tx, uint256(), jsonTx);
        LogPrintf("%s: spending finalize export:\n%s\n with tx:\n%s\n\n", __func__, scriptUni.write(1,2).c_str(), jsonTx.write(1,2).c_str());
    }

    if (of.currencyID == ASSETCHAINS_CHAINID)
    {
        // ensure that we have an import to match the export
        // this will be a same chain export and import
        int i;
        COptCCParams p;
        CCrossChainImport cci;

        for (i = 0; i < tx.vout.size(); i++)
        {
            if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.vData.size() &&
                (cci = CCrossChainImport(p.vData[0])).IsValid() &&
                cci.exportTxId == exportTx.GetHash() &&
                cci.exportTxOutNum == of.output.n)
            {
                return true;
            }
        }
    }

    if (LogAcceptCategory("finalizeexports"))
    {
        UniValue scriptUni(UniValue::VOBJ);
        ScriptPubKeyToUniv(std::get<2>(priorTxInfo).vout[tx.vin[nIn].prevout.n].scriptPubKey, scriptUni, false, false);
        UniValue jsonTx(UniValue::VOBJ);
        TxToUniv(tx, uint256(), jsonTx);
        LogPrintf("%s: failed spending finalize export:\n%s\n with tx:\n%s\n\n", __func__, scriptUni.write(1,2).c_str(), jsonTx.write(1,2).c_str());
    }
    return false;
}

bool IsFinalizeExportInput(const CScript &scriptSig)
{
    return false;
}

bool PreCheckFinalizeExport(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // ensure that this finalization represents an export that is either the clear launch beacon of
    // the currency or a same-chain export to be spent by the matching import
    COptCCParams p;
    CObjectFinalization of;
    if (!(tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
          p.IsValid() &&
          p.IsEvalPKOut() &&
          p.vData.size() &&
          (of = CObjectFinalization(p.vData[0])).IsValid() &&
          of.FinalizationType() == CObjectFinalization::EFinalizationType::FINALIZE_EXPORT))
    {
        return state.Error("Invalid export finalization output");
    }

    CTransaction exportTx;
    uint256 blockHash;
    CCrossChainExport ccx;
    if (!of.GetOutputTransaction(tx, exportTx, blockHash) ||
        exportTx.GetHash() != tx.GetHash() ||
        exportTx.vout.size() <= of.output.n ||
        !(ccx = CCrossChainExport(exportTx.vout[of.output.n].scriptPubKey)).IsValid() ||
        ccx.destSystemID != of.currencyID ||
        !(ccx.IsClearLaunch() || (ccx.IsPostlaunch() && ccx.IsSameChain())))
    {
        return state.Error("Invalid export output from finalization");
    }
    for (int i = 0; i < tx.vout.size(); i++)
    {
        if (i == outNum || i == of.output.n)
        {
            continue;
        }
        COptCCParams dupP;
        CObjectFinalization dupOf;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(dupP) &&
            dupP.IsValid() &&
            dupP.evalCode == EVAL_FINALIZE_EXPORT &&
            dupP.vData.size() &&
            (dupOf = CObjectFinalization(dupP.vData[0])).IsValid() &&
            dupOf.output == of.output)
        {
            return state.Error("Duplicate export finalization output");
        }
    }
    if (LogAcceptCategory("finalizeexports"))
    {
        UniValue scriptUni(UniValue::VOBJ);
        ScriptPubKeyToUniv(tx.vout[outNum].scriptPubKey, scriptUni, false, false);
        LogPrintf("%s: precheck export finalization:\n%s\n in tx:\n%s\n\n", __func__, scriptUni.write(1,2).c_str(), tx.GetHash().GetHex().c_str());
    }
    return true;
}

// slowFlag == false early outs for performance
bool verusCheckPOSBlock(int32_t slowflag, const CBlock *pblock, int32_t height)
{
    CBlockIndex *pastBlockIndex;
    uint256 txid, blkHash;
    int32_t txn_count;
    uint32_t voutNum;
    CAmount value;
    bool isPOS = false;
    CTxDestination destaddress, cbaddress;
    arith_uint256 target, hash;
    CTransaction tx;

    if (!pblock->IsVerusPOSBlock())
    {
        printf("%s, height %d not POS block\n", pblock->nNonce.GetHex().c_str(), height);
        return false;
    }

    txn_count = pblock->vtx.size();

    if ( txn_count > 1 )
    {
        target.SetCompact(pblock->GetVerusPOSTarget());
        txid = pblock->vtx[txn_count-1].vin[0].prevout.hash;
        voutNum = pblock->vtx[txn_count-1].vin[0].prevout.n;
        value = pblock->vtx[txn_count-1].vout[0].nValue;

        {
            bool validHash = (value != 0);
            bool enablePOSNonce = CPOSNonce::NewPOSActive(height);
            bool newPOSEnforcement = enablePOSNonce && (Params().GetConsensus().vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight <= height);
            bool isPBaaS = CConstVerusSolutionVector::activationHeight.ActiveVersion(height) >= CActivationHeight::ACTIVATE_PBAAS;
            bool extendedStake = CConstVerusSolutionVector::activationHeight.ActiveVersion(height) >= CActivationHeight::ACTIVATE_EXTENDEDSTAKE;
            uint256 rawHash;
            arith_uint256 posHash;

            // for June 17th attack mitigation
            int exploitMitigationStartHeight = 915055;  // the first stake transaction that fails validation, but should be accepted
            int fullCheckHeight = 1568000;              // height at which full checks resume
            int stakingBackOnHeight = 1576200;          // height after which staking is fully reenabled

            bool fullCheckFix = true;
            bool attackMitigation = false;
            if (IsVerusMainnetActive())
            {
                if (height < fullCheckHeight)
                {
                    fullCheckFix = false;
                }
                if (height >= exploitMitigationStartHeight && height < stakingBackOnHeight)
                {
                    // there were no staking blocks on mainnet between
                    if (height >= fullCheckHeight && height < stakingBackOnHeight)
                    {
                        validHash = false;
                    }
                    attackMitigation = true;
                }
            }

            if (validHash && newPOSEnforcement)
            {
                validHash = pblock->GetRawVerusPOSHash(rawHash, height);
                posHash = UintToArith256(rawHash) / value;

                if (!validHash)
                {
                    validHash = false;
                    printf("%s: invalid nonce value for PoS block\nnNonce: %s\nrawHash: %s\nposHash: %s\nvalue: %" PRId64 "\n",
                            __func__, pblock->nNonce.GetHex().c_str(), rawHash.GetHex().c_str(), posHash.GetHex().c_str(), value);
                }
                else if (!attackMitigation)
                {
                    if (posHash > target)
                    {
                        validHash = false;
                        printf("%s: invalid nonce value for PoS block\nnNonce: %s\nrawHash: %s\nposHash: %s\nvalue: %" PRId64 "\n",
                                __func__, pblock->nNonce.GetHex().c_str(), rawHash.GetHex().c_str(), posHash.GetHex().c_str(), value);
                    }
                    // make sure prev block hash and block height are correct
                    CStakeParams p;
                    if (validHash &&
                        (validHash = GetStakeParams(pblock->vtx[txn_count-1], p) &&
                                     p.prevHash == pblock->hashPrevBlock &&
                                     (int32_t)p.blkHeight == height))
                    {
                        for (int i = 0; validHash && i < pblock->vtx[0].vout.size(); i++)
                        {
                            validHash = false;
                            CCurrencyValueMap reserveOutVal;
                            if (pblock->vtx[0].vout[i].scriptPubKey.IsInstantSpendOrUnspendable() ||
                                (!pblock->vtx[0].vout[i].nValue &&
                                 (((reserveOutVal = pblock->vtx[0].vout[i].ReserveOutValue()) == CCurrencyValueMap()) ||
                                  (isPBaaS &&
                                   !IsVerusActive() &&
                                   reserveOutVal.valueMap.size() == 1 &&
                                   reserveOutVal.valueMap.count(VERUS_CHAINID)))) ||
                                ValidateMatchingStake(pblock->vtx[0], i, pblock->vtx[txn_count-1], validHash, slowflag) && !validHash)
                            {
                                validHash = true;
                            }
                            else
                            {
                                printf("ERROR: invalid block data for stake tx\nblkHash:   %s\ntxBlkHash: %s\nblkHeight: %d, txBlkHeight: %d\n",
                                        pblock->hashPrevBlock.GetHex().c_str(), p.prevHash.GetHex().c_str(), height, p.blkHeight);
                                validHash = false;
                            }
                        }
                    }
                }
            }
            if (validHash)
            {
                if (!slowflag || !fullCheckFix)
                {
                    isPOS = true;
                }
                else if (height < 100 || chainActive.Height() < (height - 100) || !(pastBlockIndex = chainActive[height - 100]))
                {
                    LogPrintf("block %s - no past block found\n",blkHash.ToString().c_str());
                }
                else
#ifndef KOMODO_ZCASH
                if (!GetTransaction(txid, tx, Params().GetConsensus(), blkHash, true))
#else
                if (!GetTransaction(txid, tx, blkHash, true))
#endif
                {
                    fprintf(stderr,"ERROR: invalid PoS block %s - no source transaction\n",blkHash.ToString().c_str());
                }
                else
                {
                    uint256 pastHash = chainActive.GetVerusEntropyHash(height);

                    // if we are on a version requiring the new nonce format, we check that the new format is correct
                    // if over when we have the new POS hash function, we validate that as well
                    // they are 100 blocks apart
                    CPOSNonce nonce = pblock->nNonce;

                    //printf("before nNonce: %s, height: %d\n", pblock->nNonce.GetHex().c_str(), height);
                    validHash = pblock->GetRawVerusPOSHash(rawHash, height);

                    hash = UintToArith256(tx.GetVerusPOSHash(&nonce, voutNum, height, pastHash));

                    if ((!newPOSEnforcement || posHash == hash) && hash <= target)
                    {
                        BlockMap::const_iterator it = mapBlockIndex.find(blkHash);
                        if ((it == mapBlockIndex.end()) ||
                            !(pastBlockIndex = it->second) ||
                            (height - pastBlockIndex->GetHeight()) < VERUS_MIN_STAKEAGE)
                        {
                            fprintf(stderr,"ERROR: invalid PoS block %s - stake source too new or not found\n",blkHash.ToString().c_str());
                        }
                        else
                        {
                            // make sure we have the right target
                            CBlockIndex *previndex;
                            it = mapBlockIndex.find(pblock->hashPrevBlock);
                            if (it == mapBlockIndex.end() || !(previndex = it->second))
                            {
                                fprintf(stderr,"ERROR: invalid PoS block %s - no prev block found\n",blkHash.ToString().c_str());
                            }
                            else
                            {
                                arith_uint256 cTarget;
                                uint32_t nBits = lwmaGetNextPOSRequired(previndex, Params().GetConsensus());
                                cTarget.SetCompact(nBits);
                                bool nonceOK = true;

                                // check to see how many fail
                                //if (nonce != pblock->nNonce)
                                //    printf("Mismatched nNonce: %s\nblkHash: %s, height: %d\n", nonce.GetHex().c_str(), pblock->GetHash().GetHex().c_str(), height);

                                if (CPOSNonce::NewNonceActive(height) && !nonce.CheckPOSEntropy(pastHash, txid, voutNum, pblock->nVersion))
                                {
                                    fprintf(stderr,"ERROR: invalid PoS block %s - nonce entropy corrupted or forged\n",blkHash.ToString().c_str());
                                    return false;
                                }
                                else
                                {
                                    if (cTarget != target)
                                    {
                                        LogPrintf("ERROR: invalid PoS block %s - invalid diff target, actual: %u, correct: %u\n", blkHash.ToString().c_str(), pblock->GetVerusPOSTarget(), nBits);
                                        if (IsVerusMainnetActive() && height < fullCheckHeight)
                                        {
                                            return true;
                                        }
                                        return false;
                                    }
                                }
                                const CTransaction &stakeTx = pblock->vtx[txn_count-1];
                                CStakeParams sp;
                                std::vector<CTxDestination> destinations;
                                txnouttype outType;
                                int nRequired;
                                if (nonceOK &&
                                    ExtractDestinations(stakeTx.vout[0].scriptPubKey, outType, destinations, nRequired) &&
                                    destinations.size() &&
                                    ValidateStakeTransaction(stakeTx, sp, true) &&
                                    ExtractDestination(tx.vout[voutNum].scriptPubKey, destaddress))
                                {
                                    isPOS = true;

                                    // overwrite and set delegate if it is empty as the only destination we care about below
                                    // otherwise, use it as is
                                    if (sp.delegate.which() == COptCCParams::ADDRTYPE_INVALID)
                                    {
                                        sp.delegate = destinations[0];
                                    }

                                    // normalize delegate to PKH if PK
                                    if (sp.delegate.which() == COptCCParams::ADDRTYPE_PK)
                                    {
                                        sp.delegate = CKeyID(GetDestinationID(sp.delegate));
                                    }

                                    // if the source transaction is not spent to the same output as the stake transaction, error
                                    if ((destaddress.which() == COptCCParams::ADDRTYPE_PK ? CTxDestination(CKeyID(GetDestinationID(destaddress))) : destaddress) !=
                                        (destinations[0].which() == COptCCParams::ADDRTYPE_PK ? CTxDestination(CKeyID(GetDestinationID(destinations[0]))) : destinations[0]))
                                    {
                                        printf("ERROR: in staking block %s - source tx and stake have different scripts\n", blkHash.ToString().c_str());
                                        LogPrintf("ERROR: in staking block %s - source tx and stake have different scripts\n", blkHash.ToString().c_str());
                                        return false;
                                    }

                                    if (extendedStake)
                                    {
                                        std::vector<CTxDestination> prevDests;
                                        txnouttype cbType;
                                        int numRequired;
                                        uint160 reserveDepositCurrencyID;
                                        CCurrencyDefinition reserveDepositCurrency;
                                        std::map<uint160, int> reserveDepositReserves;

                                        COptCCParams ccp;
                                        if (tx.vout[voutNum].scriptPubKey.IsPayToCryptoCondition(ccp) &&
                                            ccp.IsValid() &&
                                            ccp.evalCode == EVAL_RESERVE_DEPOSIT)
                                        {
                                            printf("ERROR: in staking block %s - invalid reserve deposit stake\n", blkHash.ToString().c_str());
                                            LogPrintf("ERROR: in staking block %s - invalid reserve deposit stake\n", blkHash.ToString().c_str());
                                            return false;
                                        }

                                        for (int j = 0; j < pblock->vtx[0].vout.size(); j++)
                                        {
                                            auto &oneOut = pblock->vtx[0].vout[j];
                                            if (oneOut.scriptPubKey.IsOpReturn())
                                            {
                                                continue;
                                            }
                                            COptCCParams p;
                                            if ((!oneOut.scriptPubKey.IsPayToCryptoCondition(p) ||
                                                 !p.IsValid(true, height) ||
                                                 p.version < p.VERSION_V3))
                                            {
                                                printf("ERROR: in staking block %s - invalid coinbase output\n", blkHash.ToString().c_str());
                                                LogPrintf("ERROR: in staking block %s - invalid coinbase output\n", blkHash.ToString().c_str());
                                                return false;
                                            }
                                            if (!p.IsInstantSpendOrUnspendable())
                                            {
                                                if (isPBaaS)
                                                {
                                                    if ((IsVerusActive() && !(oneOut.nValue >= 0 && p.evalCode == EVAL_STAKEGUARD)) ||
                                                        (!IsVerusActive() &&
                                                          ((oneOut.nValue > 0 && p.evalCode != EVAL_STAKEGUARD) || (oneOut.nValue == 0 && p.evalCode != EVAL_RESERVE_OUTPUT && p.evalCode != EVAL_STAKEGUARD))))
                                                    {
                                                        printf("ERROR: in staking block %s - invalid coinbase output 1\n", blkHash.ToString().c_str());
                                                        LogPrintf("ERROR: in staking block %s - invalid coinbase output 1\n", blkHash.ToString().c_str());
                                                        return false;
                                                    }
                                                    CTokenOutput to;
                                                    if (p.evalCode == EVAL_RESERVE_OUTPUT &&
                                                        !(p.vData.size() &&
                                                          (to = CTokenOutput(p.vData[0])).IsValid() &&
                                                          to.reserveValues.valueMap.size() == 1 &&
                                                          to.reserveValues.valueMap.count(VERUS_CHAINID)))
                                                    {
                                                        printf("ERROR: in staking block %s - invalid reserve coinbase output\n", blkHash.ToString().c_str());
                                                        LogPrintf("ERROR: in staking block %s - invalid reserve coinbase output\n", blkHash.ToString().c_str());
                                                        return false;
                                                    }
                                                }
                                                std::vector<CTxDestination> oneOutDests;
                                                if (!ExtractDestinations(oneOut.scriptPubKey, cbType, oneOutDests, numRequired) ||
                                                    numRequired > 1)
                                                {
                                                    printf("ERROR: in staking block %s - invalid coinbase output 2\n", blkHash.ToString().c_str());
                                                    LogPrintf("ERROR: in staking block %s - invalid coinbase output 2\n", blkHash.ToString().c_str());
                                                    return false;
                                                }

                                                if (p.version >= p.VERSION_V3 &&
                                                    !oneOut.scriptPubKey.IsInstantSpendOrUnspendable() &&
                                                    (oneOut.scriptPubKey.IsSpendableOutputType()))
                                                {
                                                    // we need to make sure we output only to delegate or back to the currency
                                                    // normalize destination to destinationID
                                                    if (p.vKeys[0].which() == COptCCParams::ADDRTYPE_PK)
                                                    {
                                                        p.vKeys[0] = CKeyID(GetDestinationID(p.vKeys[0]));
                                                    }
                                                    if (p.m > 1 ||
                                                        p.n > 1 ||
                                                        p.vKeys[0] != sp.delegate)
                                                    {
                                                        printf("%s: staking block %s - invalid coinbase destinations\n", __func__, blkHash.ToString().c_str());
                                                        LogPrintf("%s: staking block %s - invalid coinbase destinations\n", __func__, blkHash.ToString().c_str());
                                                        return false;
                                                    }
                                                }
                                                else if (!oneOut.scriptPubKey.IsInstantSpendOrUnspendable() ||
                                                            oneOut.nValue ||
                                                            oneOut.ReserveOutValue() > CCurrencyValueMap())
                                                {
                                                    printf("%s: ERROR: in staking block %s - invalid coinbase output type\n", __func__, blkHash.ToString().c_str());
                                                    LogPrintf("%s: ERROR: in staking block %s - invalid coinbase output type\n", __func__, blkHash.ToString().c_str());
                                                    return false;
                                                }
                                            }
                                            if (isPBaaS)
                                            {
                                                // check the header to ensure that it contains the correct transaction and proofs
                                                auto mmv = chainActive.GetMMV();
                                                // resize to be sure
                                                mmv.resize(height);
                                                std::vector<unsigned char> extraData;
                                                pblock->GetExtraData(extraData);
                                                if (extraData != CreatePoSBlockProof(mmv, *pblock, tx, voutNum, pastBlockIndex->GetHeight(), height))
                                                {
                                                    if (LogAcceptCategory("notarization"))
                                                    {
                                                        auto checkExtra = CreatePoSBlockProof(mmv, *pblock, tx, voutNum, pastBlockIndex->GetHeight(), height);
                                                        LogPrintf("%s: Invalid stake header proofs\nextraData:\n%s\nexpected:\n%s\n",
                                                                    __func__,
                                                                    HexBytes(extraData.data(), extraData.size()).c_str(),
                                                                    HexBytes(checkExtra.data(), checkExtra.size()).c_str());
                                                    }
                                                    printf("ERROR: in staked block %s - invalid header proofs\n", pblock->GetHash().ToString().c_str());
                                                    LogPrintf("ERROR: in staked block %s - invalid header proofs\n", pblock->GetHash().ToString().c_str());
                                                    return false;
                                                }
                                            }
                                        }
                                        // now, we have all the currencies and amounts that are being sent to each destination

                                        // rules for all non instant-spend coinbase outputs:
                                        // 1) Where the stake transaction spends a normal, "spendable" output, cb output must be to:
                                        //    a) the same destination(s) as the output of the stake transaction, or
                                        //    b) the specified delegate in the stake transaction
                                        // 2) Where the stake transaction spends a reserve deposit it is the same, except (TODO):
                                        //    a) coinbase output must send all applicable reserve currency fees to currency reserve
                                        //       deposits, if the currency is a reserve currency. For example, if the currency for which
                                        //       the staker is staking a block uses BTC, ETH, USD, and VRSC as reserves, the staker/miner
                                        //       keeps all block rewards and all fees, except the fees (block reward excluded) earned in
                                        //       those 4 currencies. Those fees are put into reserve deposits for the currency for which
                                        //       the staker earned the block.
                                        // 3) no other recipient than specified may be on the non-instant spend coinbase outputs
                                    }
                                    else if (CScriptExt::ExtractVoutDestination(pblock->vtx[0], 0, cbaddress) &&
                                             (destaddress.which() == COptCCParams::ADDRTYPE_PK ||
                                              destaddress.which() == COptCCParams::ADDRTYPE_PKH) &&
                                             (destinations[0].which() == COptCCParams::ADDRTYPE_PK ||
                                              destinations[0].which() == COptCCParams::ADDRTYPE_PKH) &&
                                             (cbaddress.which() == COptCCParams::ADDRTYPE_PK ||
                                              cbaddress.which() == COptCCParams::ADDRTYPE_PKH))
                                    {
                                        uint160 voutDestID = GetDestinationID(destinations[0]);
                                        uint160 destID = GetDestinationID(destaddress);
                                        uint160 cbDestID = GetDestinationID(cbaddress);
                                        if (newPOSEnforcement)
                                        {
                                            if (GetDestinationID(cbaddress) != GetDestinationID(destinations[0]))
                                            {
                                                // allow delegation of stake, but require all ouputs to be
                                                // crypto conditions
                                                // loop through all outputs to make sure they are sent to the proper pubkey
                                                isPOS = true;
                                                for (auto vout : pblock->vtx[0].vout)
                                                {
                                                    txnouttype tp;
                                                    std::vector<std::vector<unsigned char>> vvch = std::vector<std::vector<unsigned char>>();
                                                    // solve all outputs to check that non-instantspend destinations all go only to the pk
                                                    // specified in the stake params
                                                    if ((!isPBaaS || !vout.scriptPubKey.IsInstantSpend()) &&
                                                        (!Solver(vout.scriptPubKey, tp, vvch) ||
                                                        tp != TX_CRYPTOCONDITION ||
                                                        vvch.size() < 2 ||
                                                        sp.pk != CPubKey(vvch[0])))
                                                    {
                                                        isPOS = false;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        else if (voutDestID == destID && (destID == cbDestID || (IsVerusMainnetActive() && height < 17840)))
                                        {
                                            isPOS = true;
                                        }
                                        else
                                        {
                                            fprintf(stderr,"ERROR: invalid PoS block %s - invalid stake or coinbase destination\n", blkHash.ToString().c_str());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        // improved logging
                        if ((newPOSEnforcement && posHash != hash))
                        {
                            LogPrint("pos", "%s: conflicting hash values between GetRawVerusPOSHash (%s/%s) and GetVerusPOSHash (%s)\n",
                                        __func__,
                                        rawHash.GetHex().c_str(),
                                        ArithToUint256(posHash).GetHex().c_str(),
                                        ArithToUint256(hash).GetHex().c_str());
                        }

                        LogPrint("pos", "%s: malformed nonce value for PoS block\nnNonce: %s\nrawHash: %s\nposHash: %s\nvalue: %lu\n",
                            __func__,
                            pblock->nNonce.GetHex().c_str(),
                            rawHash.GetHex().c_str(),
                            posHash.GetHex().c_str(),
                            value);
                    }
                }
            }
        }
    }
    return isPOS;
}

// Validate notary evidence
bool ValidateNotaryEvidence(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    std::tuple<bool, uint32_t, CTransaction, COptCCParams> sourceTx({false, 0, CTransaction(), COptCCParams()});
    std::multimap<CUTXORef, CObjectFinalization> finalizeSpends;
    CNotaryEvidence thisEvidence;

    bool addedNotarization = false;

    sourceTx = GetPriorOutputTx(tx, nIn);
    if (!std::get<0>(sourceTx))
    {
        return eval->state.Error("Cannot retrieve prior output transaction");
    }
    if (tx.vin[nIn].prevout.n >= std::get<2>(sourceTx).vout.size())
    {
        return eval->state.Error("Invalid output number in prior transaction");
    }

    COptCCParams p;

    if (std::get<2>(sourceTx).vout[tx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.evalCode == EVAL_NOTARY_EVIDENCE &&
        p.vData.size() &&
        (thisEvidence = CNotaryEvidence(p.vData[0])).IsValid())
    {
        if (thisEvidence.output.hash.IsNull())
        {
            thisEvidence.output.hash = tx.vin[nIn].prevout.hash;
        }
    }

    CCrossChainImport cci, nextCCI;

    // if it's an import proof, we need to be spent to the next import
    if (thisEvidence.type == thisEvidence.TYPE_MULTIPART_DATA)
    {
        CNotaryEvidence oneEvidencePart;

        int i;
        for (i = tx.vin[nIn].prevout.n - 1; i >= 0; i--)
        {
            if (std::get<2>(sourceTx).vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.evalCode == EVAL_NOTARY_EVIDENCE &&
                p.vData.size() &&
                (oneEvidencePart = CNotaryEvidence(p.vData[0])).IsValid() &&
                oneEvidencePart.type == oneEvidencePart.TYPE_MULTIPART_DATA)
            {
                continue;
            }
            break;
        }
        i++;

        int32_t nextOutputNum = 0;
        while (nextOutputNum < nIn)
        {
            thisEvidence = CNotaryEvidence(std::get<2>(sourceTx), i, nextOutputNum);

            if (nextOutputNum == i || !thisEvidence.IsValid())
            {
                return eval->state.Error("Invalid evidence");
            }
            i = nextOutputNum;
        }
    }

    if (thisEvidence.type == thisEvidence.TYPE_IMPORT_PROOF)
    {
        // the protocol can deal with spent or not
        return true;
    }
    else if (thisEvidence.type == thisEvidence.TYPE_NOTARY_EVIDENCE)
    {
        CTransaction notaTx;
        uint256 notaBlockHash;
        CPBaaSNotarization referencedNotarization;

        if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
        {
            UniValue jsonTx(UniValue::VOBJ);
            uint256 nullHash;
            TxToUniv(tx, nullHash, jsonTx);
            LogPrintf("Validating input %u of TX %s\n", nIn, jsonTx.write(1,2).c_str());
        }

        for (int i = 0; i < tx.vin.size(); i++)
        {
            if ((uint32_t)i == nIn)
            {
                continue;
            }
            auto &oneIn = tx.vin[i];
            if (LogAcceptCategory("notarization"))
            {
                printf("%s: spending %s\n", __func__, CUTXORef(oneIn.prevout).ToString().c_str());
                LogPrintf("%s: spending %s\n", __func__, CUTXORef(oneIn.prevout).ToString().c_str());
            }
            if (oneIn.prevout.hash != tx.vin[nIn].prevout.hash)
            {
                continue;
            }
            if (std::get<2>(sourceTx).vout[oneIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid())
            {
                CObjectFinalization of;
                CPBaaSNotarization onePBN;
                if (p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                    p.vData.size() &&
                    (of = CObjectFinalization(p.vData[0])).IsValid())
                {
                    for (auto &oneOutNum : of.evidenceOutputs)
                    {
                        if (oneOutNum == tx.vin[nIn].prevout.n)
                        {
                            finalizeSpends.insert(std::make_pair(thisEvidence.output, of));
                            break;
                        }
                    }
                    if (finalizeSpends.size())
                    {
                        break;
                    }
                    continue;
                }
                else if ((p.evalCode == EVAL_EARNEDNOTARIZATION || p.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
                            thisEvidence.output.hash == std::get<2>(sourceTx).GetHash() &&
                            (uint32_t)i == thisEvidence.output.n &&
                            p.vData.size() &&
                            (onePBN = CPBaaSNotarization(p.vData[0])).IsValid() &&
                            (p.evalCode == EVAL_EARNEDNOTARIZATION ||
                            (p.evalCode == EVAL_ACCEPTEDNOTARIZATION &&
                            onePBN.IsDefinitionNotarization())))
                {
                    if (!finalizeSpends.count(thisEvidence.output))
                    {
                        addedNotarization = true;
                        finalizeSpends.insert(std::make_pair(thisEvidence.output, of));
                    }
                    continue;
                }
            }
            else
            {
                continue;
            }
        }
        return finalizeSpends.count(thisEvidence.output) == 1 ?
                true :
                eval->state.Error("Must spend exactly one matching finalization to spend notary evidence output, spending: " + std::to_string(finalizeSpends.count(thisEvidence.output)));
    }
    return eval->state.Error("Invalid evidence spend");
}

bool IsNotaryEvidenceInput(const CScript &scriptSig)
{
    return true;
}

// used as a proxy token output for a reserve currency on its fractional reserve chain
bool ValidateReserveOutput(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsReserveOutputInput(const CScript &scriptSig)
{
    return true;
}

CReserveTransfer GetReserveTransferToSpend(const CTransaction &spendingTx, uint32_t nIn, CTransaction &sourceTx, uint32_t &height, COptCCParams &p)
{
    // if not fulfilled, ensure that no part of the primary identity is modified
    CReserveTransfer oldReserveTransfer;
    uint256 blkHash;
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        auto bIt = blkHash.IsNull() ? mapBlockIndex.end() : mapBlockIndex.find(blkHash);
        if (bIt == mapBlockIndex.end() || !bIt->second)
        {
            height = chainActive.Height();
        }
        else
        {
            height = bIt->second->GetHeight();
        }

        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_RESERVE_TRANSFER &&
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldReserveTransfer = CReserveTransfer(p.vData[0]);
        }
    }
    return oldReserveTransfer;
}


bool ValidateReserveTransfer(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    uint32_t outNum;
    uint32_t spendingFromHeight;
    CTransaction txToSpend;
    COptCCParams p;

    // get reserve transfer to spend
    CReserveTransfer rt = GetReserveTransferToSpend(tx, nIn, txToSpend, spendingFromHeight, p);

    if (p.IsValid() && !p.IsEvalPKOut())
    {
        // if this is an arbitrage transfer with a wallet spend, it can be spent by any controller to a wallet
        return true;
    }

    if (rt.IsValid())
    {
        uint160 systemDestID, importCurrencyID;
        CCurrencyDefinition systemDest, importCurrencyDef;
        CChainNotarizationData cnd;

        if (rt.IsImportToSource())
        {
            importCurrencyID = rt.FirstCurrency();
        }
        else
        {
            importCurrencyID = rt.destCurrencyID;
        }

        importCurrencyDef = ConnectedChains.GetCachedCurrency(importCurrencyID);
        if (!importCurrencyDef.IsValid())
        {
            return eval->Error("Invalid currency definition for reserve transfer being spent");
        }

        uint32_t nHeight = chainActive.Height();

        CCrossChainExport ccx;
        CCrossChainImport cci;
        int32_t primaryExportOut, nextOutput;
        CPBaaSNotarization pbn;
        std::vector<CReserveTransfer> reserveTransfers;
        for (int i = 0; i < tx.vout.size(); i++)
        {
            COptCCParams exportP;
            if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(exportP) &&
                exportP.IsValid() &&
                exportP.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                exportP.vData.size() > 1 &&
                (ccx = CCrossChainExport(exportP.vData[0])).IsValid() &&
                !ccx.IsSystemThreadExport() &&
                ccx.destCurrencyID == importCurrencyID)
            {
                if (ccx.firstInput < 0 || nIn < ccx.firstInput || nIn > ccx.firstInput + ccx.numInputs)
                {
                    return eval->Error("Reserve transfer spend not accounted for in cross-chain export");
                }
                if (!(ccx.destSystemID == (importCurrencyDef.IsGateway() ? importCurrencyDef.gatewayID : importCurrencyDef.systemID)))
                {
                    if (ccx.destSystemID != importCurrencyDef.launchSystemID ||
                        ccx.destSystemID != ASSETCHAINS_CHAINID)
                    {
                        return eval->Error("Invalid destination system " + EncodeDestination(CIdentityID(ccx.destSystemID)) + " for export");
                    }
                }
                if (ccx.numInputs > 0 &&
                    nIn >= ccx.firstInput &&
                    nIn < (ccx.firstInput + ccx.numInputs))
                {
                    // if we successfully got the export info and are included in the export reserve transfers, additional
                    // validation is done by the export
                    return true;
                }
            }
            else if (exportP.IsValid() &&
                        exportP.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                        exportP.vData.size() > 1 &&
                        (cci = CCrossChainImport(exportP.vData[0])).IsValid() &&
                        cci.importCurrencyID == importCurrencyID &&
                        rt.IsArbitrageOnly())
            {
                std::vector<CUTXORef> arbOuts;
                std::vector<CReserveTransfer> arbTransfers = cci.GetArbitrageTransfers(tx, eval->state, nHeight, nullptr, &arbOuts);
                CUTXORef thisUTXORef(tx.vin[nIn].prevout);
                for (auto &oneOut : arbOuts)
                {
                    if (oneOut == thisUTXORef)
                    {
                        return true;
                    }
                }
                return eval->Error("Reserve transfer spend not accounted for in cross-chain import as arbitrage transaction");
            }
        }
        return eval->Error("Unauthorized reserve transfer spend without valid export");
    }
    return eval->Error("Attempt to spend invalid reserve transfer");
}

bool IsReserveTransferInput(const CScript &scriptSig)
{
    return true;
}

CReserveDeposit GetSpendingReserveDeposit(const CTransaction &spendingTx, uint32_t nIn, CTransaction *pSourceTx, uint32_t *pHeight)
{
    CTransaction _sourceTx;
    CTransaction &sourceTx(pSourceTx ? *pSourceTx : _sourceTx);

    // if not fulfilled, ensure that no part of the primary identity is modified
    CReserveDeposit oldReserveDeposit;
    uint256 blkHash;
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        if (pHeight)
        {
            auto bIt = mapBlockIndex.find(blkHash);
            if (bIt == mapBlockIndex.end() || !bIt->second)
            {
                *pHeight = chainActive.Height();
            }
            else
            {
                *pHeight = bIt->second->GetHeight();
            }
        }
        COptCCParams p;
        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_RESERVE_DEPOSIT &&
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldReserveDeposit = CReserveDeposit(p.vData[0]);
        }
    }
    return oldReserveDeposit;
}

bool ValidateReserveDeposit(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // reserve deposits can only spend to the following:
    // 1. If the reserve deposit is controlled by an alternate system or gateway currency, it can be
    //    spent by an import that includes a sys import from the alternate system/gateway. The total
    //    input of all inputs to the tx from the deposit controller is considered and all but the amount
    //    specified in gateway imports of the import must come out as change back to the reserve deposit.
    // 2. If the reserve deposit is controlled by the currency of an import, exactly the amount spent by
    //    the import may be released in total and not sent back to change.

    // first, get the prior reserve deposit and determine the controlling currency
    CTransaction sourceTx;
    uint32_t sourceHeight;
    CReserveDeposit sourceRD = GetSpendingReserveDeposit(tx, nIn, &sourceTx, &sourceHeight);
    if (!sourceRD.IsValid())
    {
        return eval->Error(std::string(__func__) + ": attempting to spend invalid reserve deposit output " + tx.vin[nIn].ToString());
    }

    // now, ensure that the spender transaction includes an import output of this specific currency or
    // where this currency is a system gateway source
    CCrossChainImport authorizingImport;
    CCrossChainImport mainImport;
    CCurrencyDefinition launchingCurrency;

    CCrossChainExport ccxSource;
    CPBaaSNotarization importNotarization;
    int32_t sysCCIOut, importNotarizationOut, evidenceOutStart, evidenceOutEnd;
    std::vector<CReserveTransfer> reserveTransfers;

    // looking for an import output to the controlling currency
    int importOutNum;
    for (importOutNum = 0; importOutNum < tx.vout.size(); importOutNum++)
    {
        COptCCParams p;
        if (tx.vout[importOutNum].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
            p.vData.size() &&
            (authorizingImport = CCrossChainImport(p.vData[0])).IsValid())
        {
            // the simple case
            if (authorizingImport.importCurrencyID == sourceRD.controllingCurrencyID)
            {
                break;
            }

            if (!authorizingImport.IsSourceSystemImport())
            {
                if (authorizingImport.GetImportInfo(tx,
                                                    chainActive.Height(),
                                                    importOutNum,
                                                    ccxSource,
                                                    authorizingImport,
                                                    sysCCIOut,
                                                    importNotarization,
                                                    importNotarizationOut,
                                                    evidenceOutStart,
                                                    evidenceOutEnd,
                                                    reserveTransfers))
                {
                    if (importNotarization.IsRefunding() &&
                        (launchingCurrency = ConnectedChains.GetCachedCurrency(authorizingImport.importCurrencyID)).IsValid() &&
                        launchingCurrency.systemID != ASSETCHAINS_CHAINID &&
                        launchingCurrency.systemID == sourceRD.controllingCurrencyID)
                    {
                        break;
                    }
                }
                else
                {
                    importNotarization = CPBaaSNotarization();
                }
            }
        }
    }

    if (importOutNum >= tx.vout.size())
    {
        LogPrint("reservedeposits", "%s: non import transaction %s attempting to spend reserve deposit %s\n", __func__, EncodeHexTx(tx).c_str(), tx.vin[nIn].ToString().c_str());
        return eval->Error(std::string(__func__) + ": non import transaction attempting to spend reserve deposit");
    }

    // if we found a valid output, determine if the output is direct or system source
    bool gatewaySource = authorizingImport.IsSourceSystemImport();
    if (gatewaySource)
    {
        COptCCParams p;
        importOutNum--;        // set i to the actual import
        if (!(importOutNum >= 0 &&
              tx.vout[importOutNum].scriptPubKey.IsPayToCryptoCondition(p) &&
              p.IsValid() &&
              p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
              p.vData.size() &&
              (mainImport = CCrossChainImport(p.vData[0])).IsValid()))
        {
            LogPrint("reservedeposits", "%s: malformed import transaction %s attempting to spend reserve deposit %s\n", __func__, EncodeHexTx(tx).c_str(), tx.vin[nIn].ToString().c_str());
            return eval->Error(std::string(__func__) + ": malformed import transaction attempting to spend reserve deposit");
        }
    }
    else
    {
        mainImport = authorizingImport;
    }

    uint32_t nHeight = chainActive.Height();

    if (importNotarization.IsValid() ||
        mainImport.GetImportInfo(tx,
                                 nHeight,
                                 importOutNum,
                                 ccxSource,
                                 authorizingImport,
                                 sysCCIOut,
                                 importNotarization,
                                 importNotarizationOut,
                                 evidenceOutStart,
                                 evidenceOutEnd,
                                 reserveTransfers))
    {
        LOCK(mempool.cs);

        CCoinsView dummy;
        CCoinsViewCache view(&dummy);
        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        view.SetBackend(viewMemPool);

        CCurrencyValueMap totalDeposits;

        for (int i = 0; i < tx.vin.size(); i++)
        {
            if (tx.vin[i].prevout.hash.IsNull())
            {
                continue;
            }
            const CCoins *pCoins = view.AccessCoins(tx.vin[i].prevout.hash);

            COptCCParams p;

            // if we can't find the output we are spending, we fail
            if (!pCoins || pCoins->vout.size() <= tx.vin[i].prevout.n)
            {
                return eval->Error(std::string(__func__) + ": cannot get output being spent by input (" + tx.vin[i].ToString() + ") from current view");
            }

            CReserveDeposit oneBeingSpent;
            bool afterNotarization = false;

            if (pCoins->vout[tx.vin[i].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_RESERVE_DEPOSIT)
            {
                if (!(p.vData.size() &&
                      (oneBeingSpent = CReserveDeposit(p.vData[0])).IsValid()))
                {
                    return eval->Error(std::string(__func__) + ": reserve deposit being spent by input (" + tx.vin[i].ToString() + ") is invalid in view");
                }
            }
            else if (p.IsValid() &&
                     importNotarization.currencyID == sourceRD.controllingCurrencyID &&
                     p.evalCode == EVAL_RESERVE_TRANSFER &&
                     !afterNotarization &&
                     p.vData.size())
            {
                CReserveTransfer arbRt(p.vData[0]);
                if (arbRt.IsArbitrageOnly() &&
                    importNotarization.IsValid() &&
                    arbRt.GetImportCurrency() == importNotarization.currencyID)
                {
                    totalDeposits += pCoins->vout[tx.vin[i].prevout.n].scriptPubKey.ReserveOutValue();
                    if (pCoins->vout[tx.vin[i].prevout.n].nValue)
                    {
                        totalDeposits.valueMap[ASSETCHAINS_CHAINID] += pCoins->vout[tx.vin[i].prevout.n].nValue;
                    }
                }
            }
            else if (p.IsValid() &&
                     p.evalCode == EVAL_ACCEPTEDNOTARIZATION)
            {
                afterNotarization = true;
            }

            if (oneBeingSpent.IsValid() &&
                oneBeingSpent.controllingCurrencyID == sourceRD.controllingCurrencyID)
            {
                // if we are not first, this will have to have passed by the first input to have gotten here
                if (i < nIn)
                {
                    return true;
                }
                else
                {
                    totalDeposits += oneBeingSpent.reserveValues;
                }
            }
        }

        // now, determine how much is used and how much change is left
        CCoinbaseCurrencyState checkState = importNotarization.currencyState;
        CCoinbaseCurrencyState newCurState;

        CReserveTransactionDescriptor rtxd;

        CCurrencyDefinition sourceSysDef = ConnectedChains.GetCachedCurrency(ccxSource.sourceSystemID);
        CCurrencyDefinition destSysDef = ConnectedChains.GetCachedCurrency(ccxSource.destSystemID);
        CCurrencyDefinition destCurDef = ConnectedChains.GetCachedCurrency(ccxSource.destCurrencyID);

        if (!(sourceSysDef.IsValid() && destSysDef.IsValid() && destCurDef.IsValid()))
        {
            return eval->Error(std::string(__func__) + ": invalid currencies in export: " + ccxSource.ToUniValue().write(1,2));
        }

        bool isClearLaunch = ccxSource.IsClearLaunch();
        std::vector<CTxOut> vOutputs;

        bool isUpdatedConversion = ConnectedChains.CheckZeroViaOnlyPostLaunch(nHeight);

        int32_t transitionBlocks = (PBAAS_TESTMODE ? ((24 * 60 * 60) / ConnectedChains.ThisChain().blockTime) : 100);
        bool clearConvertTransition = IsVerusMainnetActive() &&
                                      destCurDef.IsFractional() &&
                                      !ConnectedChains.CheckClearConvert(std::max(((int32_t)nHeight) - transitionBlocks, 1)) &&
                                      ConnectedChains.CheckClearConvert(nHeight);

        if (isUpdatedConversion &&
            isClearLaunch &&
            reserveTransfers.size())
        {
            // we need the prior import's notarization as a starting point
            CValidationState state;
            CTransaction priorTx;
            int32_t priorOutNum = 0;
            CCrossChainImport priorCCI = mainImport.GetPriorImport(tx, state, &priorTx, &priorOutNum);
            // clearlaunch should always have a prior
            if (!priorCCI.IsValid())
            {
                if (LogAcceptCategory("defi"))
                {
                    LogPrintf("%s: Invalid prior import: %s\n", __func__, mainImport.ToUniValue().write(1,2).c_str());
                }
                return eval->Error(std::string(__func__) + ": invalid prior import: " + mainImport.ToUniValue().write(1,2));
            }
            bool validNotarization = false;
            // get the prior output notarization
            for (int o = priorOutNum; o < priorTx.vout.size(); o++)
            {
                COptCCParams priorP;
                CPBaaSNotarization priorNotar;
                if (priorTx.vout[o].scriptPubKey.IsPayToCryptoCondition(priorP) &&
                    priorP.IsValid() &&
                    (priorP.evalCode == EVAL_ACCEPTEDNOTARIZATION || priorP.evalCode == EVAL_EARNEDNOTARIZATION) &&
                    (priorNotar = CPBaaSNotarization(priorP.vData[0])).IsValid() &&
                    priorNotar.currencyID == mainImport.importCurrencyID)
                {
                    checkState = priorNotar.currencyState;

                    checkState.SetPrelaunch(false);
                    // clear launch export is not clear launch import
                    checkState.SetLaunchClear(false);
                    CCoinbaseCurrencyState pricingState;
                    CCurrencyValueMap dummyCurrency, dummyCurrencyUsed, dummyCurrencyOut;

                    rtxd.ptx = &tx;
                    if (rtxd.AddReserveTransferImportOutputs(checkState.IsRefunding() ? destSysDef : sourceSysDef,
                                                             checkState.IsRefunding() ? sourceSysDef : destSysDef,
                                                             destCurDef,
                                                             checkState,
                                                             reserveTransfers,
                                                             nHeight,
                                                             vOutputs,
                                                             dummyCurrency,
                                                             dummyCurrencyUsed,
                                                             dummyCurrencyOut,
                                                             &pricingState,
                                                             ccxSource.exporter,
                                                             importNotarization.proposer,
                                                             EntropyHashFromHeight(CBlockIndex::BlockEntropyKey(), importNotarization.notarizationHeight, destCurDef.GetID())))
                    {
                        checkState.conversionPrice = pricingState.conversionPrice;
                        checkState.viaConversionPrice = pricingState.viaConversionPrice;
                        validNotarization = true;
                        vOutputs.clear();
                        rtxd = CReserveTransactionDescriptor();
                        break;
                    }
                    else
                    {
                        if (LogAcceptCategory("defi"))
                        {
                            LogPrintf("%s: Invalid currency state for import: %s\n", __func__, checkState.ToUniValue().write(1,2).c_str());
                        }
                        return eval->Error(std::string(__func__) + ": invalid prior notarization for clear launch import: " + mainImport.ToUniValue().write(1,2));
                    }
                }
            }
            if (!validNotarization)
            {
                if (LogAcceptCategory("defi"))
                {
                    LogPrintf("%s: Invalid prior notarization at clear launch for import: %s\n", __func__, mainImport.ToUniValue().write(1,2).c_str());
                }
                return eval->Error(std::string(__func__) + ": invalid prior notarization for clear launch import: " + mainImport.ToUniValue().write(1,2));
            }
            //checkState.SetLaunchClear(false);
        }
        else
        {
            checkState.RevertReservesAndSupply(destCurDef,
                                                ASSETCHAINS_CHAINID,
                                                (destCurDef.IsGatewayConverter() && destCurDef.gatewayID == ASSETCHAINS_CHAINID) ||
                                                (!IsVerusActive() && destCurDef.GetID() == ASSETCHAINS_CHAINID),
                                                !isUpdatedConversion ? CCoinbaseCurrencyState::PBAAS_1_0_0 : CCoinbaseCurrencyState::ReversionUpdateForHeight(nHeight));

            if (ccxSource.IsClearLaunch() && ccxSource.sourceSystemID == destCurDef.launchSystemID)
            {
                checkState.SetLaunchCompleteMarker(false);
            }
        }

        CCurrencyValueMap importedCurrency, gatewayCurrencyUsed, spentCurrencyOut;

        rtxd.ptx = &tx;
        if (!rtxd.AddReserveTransferImportOutputs(checkState.IsRefunding() ? destSysDef : sourceSysDef,
                                                  checkState.IsRefunding() ? sourceSysDef : destSysDef,
                                                  destCurDef,
                                                  checkState,
                                                  reserveTransfers,
                                                  nHeight,
                                                  vOutputs,
                                                  importedCurrency,
                                                  gatewayCurrencyUsed,
                                                  spentCurrencyOut,
                                                  &newCurState,
                                                  ccxSource.exporter,
                                                  importNotarization.proposer,
                                                  EntropyHashFromHeight(CBlockIndex::BlockEntropyKey(), importNotarization.notarizationHeight, destCurDef.GetID()),
                                                  true))
        {
            return eval->Error(std::string(__func__) + ": invalid import transaction");
        }

        // get outputs total amount to this reserve deposit
        CCurrencyValueMap reserveDepositChange;
        CCurrencyValueMap crossChainAlternateValue;
        CCurrencyValueMap extraOutputsValue;
        CCurrencyValueMap feeCurrencyMap;
        feeCurrencyMap.valueMap[ASSETCHAINS_CHAINID] = 1;
        if (!IsVerusActive() && ConnectedChains.NotarySystems().size())
        {
            feeCurrencyMap.valueMap[VERUS_CHAINID] = 1;
        }
        if (clearConvertTransition)
        {
            feeCurrencyMap.valueMap[destCurDef.GetID()] = 1;
        }

        int startingOutput = importNotarizationOut + 1;
        if (evidenceOutEnd > 0)
        {
            startingOutput = evidenceOutEnd + 1;
        }
        int endingOutput = startingOutput + std::min(((int32_t)vOutputs.size()), mainImport.numOutputs);

        for (int i = 0; i < tx.vout.size(); i++)
        {
            COptCCParams p;
            CReserveDeposit rd;
            if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_RESERVE_DEPOSIT &&
                p.vData.size() &&
                (rd = CReserveDeposit(p.vData[0])).IsValid() &&
                (rd.controllingCurrencyID == sourceRD.controllingCurrencyID ||
                 (ccxSource.sourceSystemID != ccxSource.destSystemID &&
                  ((sourceRD.controllingCurrencyID == ccxSource.sourceSystemID &&
                    rd.controllingCurrencyID == ccxSource.destCurrencyID) ||
                   (sourceRD.controllingCurrencyID != ccxSource.sourceSystemID &&
                   rd.controllingCurrencyID == ccxSource.sourceSystemID)))))
            {
                if (rd.controllingCurrencyID == sourceRD.controllingCurrencyID)
                {
                    reserveDepositChange += rd.reserveValues;
                }
                else
                {
                    crossChainAlternateValue += rd.reserveValues;
                }
                continue;
            }
            if (nHeight != 1 &&
                (i < importOutNum || i > endingOutput))
            {
                extraOutputsValue += tx.vout[i].ReserveOutValue();
                extraOutputsValue.valueMap[ASSETCHAINS_CHAINID] = tx.vout[i].nValue;
            }
        }

        if (extraOutputsValue.IntersectingValues(feeCurrencyMap).valueMap.size())
        {
            LogPrintf("%s: invalid spend of fee currency on import transaction for: %s\n", __func__, EncodeDestination(CIdentityID(destCurDef.GetID())).c_str());
            if (LogAcceptCategory("defi"))
            {
                UniValue jsonTx(UniValue::VOBJ);
                uint256 hashBlk;
                TxToUniv(tx, hashBlk, jsonTx);
                LogPrintf("tx:\n%s\n", jsonTx.write(1,2).c_str()); //*/
                printf("tx:\n%s\n", jsonTx.write(1,2).c_str()); //*/
            }
            return eval->Error(std::string(__func__) + ": invalid spend of fee currency on import transaction for: " + EncodeDestination(CIdentityID(destCurDef.GetID())));
        }

        if (gatewaySource)
        {
            if (totalDeposits != (gatewayCurrencyUsed + reserveDepositChange))
            {
                LogPrintf("%s: invalid use of gateway reserve deposits for currency: %s\n", __func__, EncodeDestination(CIdentityID(destCurDef.GetID())).c_str());
                return eval->Error(std::string(__func__) + ": invalid use of gateway reserve deposits for currency: " + EncodeDestination(CIdentityID(destCurDef.GetID())));
            }
        }
        else
        {
            CCurrencyValueMap currenciesIn(importedCurrency);

            // if we are not coming directly into the source system, there must be a separate source export as well,
            // so add gateway currency
            if (ccxSource.sourceSystemID != ccxSource.destSystemID)
            {
                if (!(checkState.IsRefunding() && destCurDef.launchSystemID == ASSETCHAINS_CHAINID) &&
                    authorizingImport.importCurrencyID != ccxSource.sourceSystemID)
                {
                    return eval->Error(std::string(__func__) + ": invalid currency system import thread for import to: " + EncodeDestination(CIdentityID(destCurDef.GetID())));
                }
                if (!(checkState.IsRefunding() && sourceRD.controllingCurrencyID == destSysDef.GetID()))
                {
                    currenciesIn += gatewayCurrencyUsed;
                }
            }

            if (newCurState.primaryCurrencyOut)
            {
                currenciesIn.valueMap[newCurState.GetID()] += newCurState.primaryCurrencyOut;
            }

            if ((totalDeposits + currenciesIn) != (reserveDepositChange + spentCurrencyOut))
            {
                bool cleanConvertedPrimary = false;
                if (clearConvertTransition)
                {
                    CCurrencyValueMap primaryCheck = ((totalDeposits + currenciesIn) - (reserveDepositChange + spentCurrencyOut)).CanonicalMap();
                    if (primaryCheck.valueMap.size() == 1 &&
                        primaryCheck.valueMap.count(newCurState.GetID()))
                    {
                        cleanConvertedPrimary = true;
                    }
                }
                if (!cleanConvertedPrimary)
                {
                    if (LogAcceptCategory("reservedeposits"))
                    {
                        UniValue jsonTx(UniValue::VOBJ);
                        uint256 hashBlk;
                        TxToUniv(tx, hashBlk, jsonTx);
                        LogPrintf("%s: Reserve deposit error in tx:\n%s\n", __func__, jsonTx.write(1,2).c_str()); //*/
                        printf("%s: Reserve deposit error in tx:\n%s\n", __func__, jsonTx.write(1,2).c_str()); //*/
                    }
                    LogPrintf("%s: Invalid use of reserve deposits -- (totalDeposits + currenciesIn):\n%s\n(reserveDepositChange + spentCurrencyOut):\n%s\n",
                        __func__, (totalDeposits + currenciesIn).ToUniValue().write().c_str(), (reserveDepositChange + spentCurrencyOut).ToUniValue().write().c_str());
                    return eval->Error(std::string(__func__) + ": invalid use of reserve deposits for currency: " + EncodeDestination(CIdentityID(destCurDef.GetID())));
                }
            }
        }

        return true;
    }

    return eval->Error(std::string(__func__) + ": invalid reserve deposit spend");
}

bool IsReserveDepositInput(const CScript &scriptSig)
{
    return true;
}

bool ValidateCurrencyState(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}

bool IsCurrencyStateInput(const CScript &scriptSig)
{
    return true;
}

bool IsAdvancedNameReservationInput(const CScript &scriptSig)
{
    return true;
}

/*
 * Verifies that the input objects match the hashes and returns the transaction.
 *
 * If the opRetTx has the op ret, this calculates based on the actual transaction and
 * validates the hashes. If the opRetTx does not have the opRet itself, this validates
 * by ensuring that all objects are present on this chain, composing the opRet, and
 * ensuring that the transaction then hashes to the correct txid.
 *
 */
bool ValidateOpretProof(CScript &opRet, COpRetProof &orProof)
{
    // enumerate through the objects and validate that they are objects of the expected type that hash
    // to the value expected. return true if so
    return true;
}

int8_t ObjTypeCode(const CBlockHeaderProof &obj)
{
    return CHAINOBJ_HEADER_REF;
}

int8_t ObjTypeCode(const CProofRoot &obj)
{
    return CHAINOBJ_PROOF_ROOT;
}

int8_t ObjTypeCode(const CPartialTransactionProof &obj)
{
    return CHAINOBJ_TRANSACTION_PROOF;
}

int8_t ObjTypeCode(const CBlockHeaderAndProof &obj)
{
    return CHAINOBJ_HEADER;
}

int8_t ObjTypeCode(const CHashCommitments &obj)
{
    return CHAINOBJ_COMMITMENTDATA;
}

int8_t ObjTypeCode(const CReserveTransfer &obj)
{
    return CHAINOBJ_RESERVETRANSFER;
}

int8_t ObjTypeCode(const CCrossChainProof &obj)
{
    return CHAINOBJ_CROSSCHAINPROOF;
}

int8_t ObjTypeCode(const CNotarySignature &obj)
{
    return CHAINOBJ_NOTARYSIGNATURE;
}

int8_t ObjTypeCode(const CEvidenceData &obj)
{
    return CHAINOBJ_EVIDENCEDATA;
}

// this adds an opret to a mutable transaction that provides the necessary evidence of a signed, cheating stake transaction
CScript StoreOpRetArray(const std::vector<CBaseChainObject *> &objPtrs)
{
    CScript vData;
    CDataStream s = CDataStream(SER_NETWORK, PROTOCOL_VERSION);
    s << (int32_t)OPRETTYPE_OBJECTARR;
    bool error = false;

    for (auto pobj : objPtrs)
    {
        try
        {
            if (!DehydrateChainObject(s, pobj))
            {
                error = true;
                break;
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            error = true;
            break;
        }
    }

    //std::vector<unsigned char> schars(s.begin(), s.begin() + 200);
    //printf("stream vector chars: %s\n", HexBytes(&schars[0], schars.size()).c_str());

    std::vector<unsigned char> vch(s.begin(), s.end());
    return error ? CScript() : CScript() << OP_RETURN << vch;
}

std::vector<CBaseChainObject *> RetrieveOpRetArray(const CScript &opRetScript)
{
    std::vector<unsigned char> vch;
    std::vector<CBaseChainObject *> vRet;
    if (opRetScript.IsOpReturn() && GetOpReturnData(opRetScript, vch) && vch.size() > 0)
    {
        CDataStream s = CDataStream(vch, SER_NETWORK, PROTOCOL_VERSION);

        int32_t opRetType;

        try
        {
            s >> opRetType;
            if (opRetType == OPRETTYPE_OBJECTARR)
            {
                CBaseChainObject *pobj;
                while (!s.empty() && (pobj = RehydrateChainObject(s)))
                {
                    vRet.push_back(pobj);
                }
                if (!s.empty())
                {
                    printf("failed to load all objects in opret");
                    DeleteOpRetObjects(vRet);
                    vRet.clear();
                }
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            DeleteOpRetObjects(vRet);
            vRet.clear();
        }
    }
    return vRet;
}

CCrossChainExport::CCrossChainExport(const CScript &script)
{
    COptCCParams p;
    if (script.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.evalCode == EVAL_CROSSCHAIN_EXPORT)
    {
        FromVector(p.vData[0], *this);
    }
}

CCrossChainExport::CCrossChainExport(const UniValue &obj) :
    nVersion(CCrossChainExport::VERSION_CURRENT),
    sourceHeightStart(0),
    sourceHeightEnd(0),
    firstInput(0),
    numInputs(0)
{
    nVersion = uni_get_int(find_value(obj, "version"));
    flags = uni_get_int(find_value(obj, "flags"));
    if (!this->IsSupplemental())
    {
        sourceHeightStart = uni_get_int64(find_value(obj, "sourceheightstart"));
        sourceHeightEnd = uni_get_int64(find_value(obj, "sourceheightend"));
        sourceSystemID = GetDestinationID(DecodeDestination(uni_get_str(find_value(obj, "sourcesystemid"))));
        destSystemID = GetDestinationID(DecodeDestination(uni_get_str(find_value(obj, "destinationsystemid"))));
        destCurrencyID = GetDestinationID(DecodeDestination(uni_get_str(find_value(obj, "destinationcurrencyid"))));
        firstInput = uni_get_int(find_value(obj, "firstinput"));
        numInputs = uni_get_int(find_value(obj, "numinputs"));
        totalAmounts = CCurrencyValueMap(find_value(obj, "totalamounts"));
        totalFees = CCurrencyValueMap(find_value(obj, "totalfees"));
        hashReserveTransfers = uint256S(uni_get_str(find_value(obj, "hashtransfers")));
        totalBurned = CCurrencyValueMap(find_value(obj, "totalburned"));
        exporter = DestinationToTransferDestination(DecodeDestination(uni_get_str(find_value(obj, "rewardaddress"))));
    }

    UniValue transfers = find_value(obj, "transfers");
    if (transfers.isArray() && transfers.size())
    {
        for (int i = 0; i < transfers.size(); i++)
        {
            CReserveTransfer rt(transfers[i]);
            if (rt.IsValid())
            {
                reserveTransfers.push_back(rt);
            }
        }
    }
}

CCrossChainImport::CCrossChainImport(const UniValue &obj) :
    nVersion(CCrossChainImport::VERSION_CURRENT),
    flags(0),
    sourceSystemHeight(0),
    exportTxOutNum(-1),
    numOutputs(0)
{
    nVersion = uni_get_int(find_value(obj, "version"));
    flags = uni_get_int(find_value(obj, "flags"));

    sourceSystemID = GetDestinationID(DecodeDestination(uni_get_str(find_value(obj, "sourcesystemid"))));
    sourceSystemHeight = uni_get_int64(find_value(obj, "sourceheight"));
    importCurrencyID = GetDestinationID(DecodeDestination(uni_get_str(find_value(obj, "importcurrencyid"))));
    importValue = CCurrencyValueMap(find_value(obj, "valuein"));
    totalReserveOutMap = CCurrencyValueMap(find_value(obj, "tokensout"));
    numOutputs = uni_get_int64(find_value(obj, "numoutputs"));
    hashReserveTransfers = uint256S(uni_get_str(find_value(obj, "hashtransfers")));
    exportTxId = uint256S(uni_get_str(find_value(obj, "exporttxid")));
    exportTxOutNum = uni_get_int(find_value(obj, "exporttxout"), -1);
}

CCrossChainExport::CCrossChainExport(const CTransaction &tx, int32_t *pCCXOutputNum)
{
    int32_t _ccxOutputNum = 0;
    int32_t &ccxOutputNum = pCCXOutputNum ? *pCCXOutputNum : _ccxOutputNum;

    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_CROSSCHAIN_EXPORT)
        {
            FromVector(p.vData[0], *this);
            ccxOutputNum = i;
            break;
        }
    }
}

CCurrencyDefinition::CCurrencyDefinition(const CScript &scriptPubKey)
{
    nVersion = PBAAS_VERSION_INVALID;
    COptCCParams p;
    if (scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid())
    {
        if (p.evalCode == EVAL_CURRENCY_DEFINITION && p.vData.size())
        {
            FromVector(p.vData[0], *this);
        }
    }
}

std::vector<CCurrencyDefinition> CCurrencyDefinition::GetCurrencyDefinitions(const CTransaction &tx)
{
    std::vector<CCurrencyDefinition> retVal;
    for (auto &out : tx.vout)
    {
        CCurrencyDefinition oneCur = CCurrencyDefinition(out.scriptPubKey);
        if (oneCur.IsValid())
        {
            retVal.push_back(oneCur);
        }
    }
    return retVal;
}

extern int32_t iguana_rwnum(int32_t rwflag, uint8_t *serialized, int32_t len, void *endianedp);
extern uint32_t calc_crc32(uint32_t crc,const void *buf,size_t size);
extern void vcalc_sha256(char deprecated[(256 >> 3) * 2 + 1], uint8_t hash[256 >> 3], uint8_t *src, int32_t len);

uint32_t CCurrencyDefinition::MagicNumber() const
{
    // this applies to the "this" pointer
    bool isVerusMainnet = (!PBAAS_TESTMODE && GetID() == VERUS_CHAINID);

    // make separate bool to emphasize the difference between this being Verus or running Verus at this time
    bool isVerusOrVerusTestRunning = IsVerusActive();

    std::vector<unsigned char> extraBuffer;
    extraBuffer.reserve(384);

    // compatibility
    int lastSize = 0;

    if (IsPBaaSChain())
    {
        if ((eraEnd.size() && eraEnd[0]) ||
            (rewards.size() && rewards[0]) ||
            (halving.size() && halving[0]) ||
            (rewardsDecay.size() && rewardsDecay[0]))
        {
            extraBuffer.insert(extraBuffer.end(), 33, 0);
            lastSize = extraBuffer.size();

            for (int i = 0; i < rewards.size(); i++)
            {
                int64_t wideHalving = halving[i], wideEndSubsidy = eraEnd[i];
                extraBuffer.resize(extraBuffer.size() +
                                   sizeof(wideEndSubsidy) +
                                   sizeof(rewards[i]) +
                                   sizeof(wideHalving) +
                                   sizeof(rewardsDecay[i]));
                lastSize += iguana_rwnum(1, &(extraBuffer[lastSize]), sizeof(wideEndSubsidy), (void *)&wideEndSubsidy);
                lastSize += iguana_rwnum(1, &(extraBuffer[lastSize]), sizeof(rewards[i]), (void *)&rewards[i]);
                lastSize += iguana_rwnum(1, &(extraBuffer[lastSize]), sizeof(wideHalving), (void *)&wideHalving);
                lastSize += iguana_rwnum(1, &(extraBuffer[lastSize]), sizeof(rewardsDecay[i]), (void *)&rewardsDecay[i]);
            }
            if (rewards.size() > 1)
            {
                uint32_t lastEra = std::min(2, (int)(rewards.size() - 1));
                extraBuffer.resize(extraBuffer.size() + sizeof(lastEra));
                lastSize += iguana_rwnum(1,&(extraBuffer[lastSize]), sizeof(lastEra), (void *)&lastEra);
            }

            // now incorporate time locks, which was only supported on Verus mainnet and is no
            // longer available
            if (isVerusMainnet)
            {
                uint64_t timeLockGTE = 19200000000, timeUnlockFrom = 129600, timeUnlockTo = 1180800;
                extraBuffer.resize(extraBuffer.size() + sizeof(timeLockGTE) + sizeof(timeUnlockFrom) + sizeof(timeUnlockTo));
                lastSize += iguana_rwnum(1, &(extraBuffer[lastSize]), sizeof(timeLockGTE), (void *)&timeLockGTE);
                lastSize += iguana_rwnum(1, &(extraBuffer[lastSize]), sizeof(timeUnlockFrom), (void *)&timeUnlockFrom);
                lastSize += iguana_rwnum(1, &(extraBuffer[lastSize]), sizeof(timeUnlockTo), (void *)&timeUnlockTo);
            }

            uint32_t VERUSHASH_FLAG = 1;
            int32_t LWMAPOSVAL = 50;
            extraBuffer.resize(extraBuffer.size() + sizeof(VERUSHASH_FLAG) + sizeof(LWMAPOSVAL));
            lastSize += iguana_rwnum(1, &(extraBuffer[lastSize]), sizeof(VERUSHASH_FLAG), (void *)&VERUSHASH_FLAG);
            lastSize += iguana_rwnum(1, &(extraBuffer[lastSize]), sizeof(LWMAPOSVAL), (void *)&LWMAPOSVAL);

            // if we have extended PBaaS parameters
            if (startBlock || endBlock)
            {
                extraBuffer.resize(extraBuffer.size() + sizeof(startBlock) + sizeof(endBlock));
                lastSize += iguana_rwnum(1, &extraBuffer[lastSize], sizeof(startBlock), (void *)&startBlock);
                lastSize += iguana_rwnum(1, &extraBuffer[lastSize], sizeof(endBlock), (void *)&endBlock);
            }

            uint64_t val = ((uint64_t)1 << 40);
            extraBuffer.resize(extraBuffer.size() + sizeof(val));
            lastSize += iguana_rwnum(1, &extraBuffer[lastSize], sizeof(val), (void *)&val);

            if (rewards.size() > 1 && (ChainOptions() & CCurrencyDefinition::OPTION_FRACTIONAL))
            {
                uint32_t options = ChainOptions();
                extraBuffer.resize(extraBuffer.size() + sizeof(options));
                lastSize += iguana_rwnum(1, &extraBuffer[lastSize], sizeof(options), (void *)&options);
            }
        }
    }

    std::string currencyName(name);
    if (isVerusMainnet)
    {
        currencyName = boost::to_upper_copy(currencyName);
    }
    else
    {
        currencyName = boost::to_lower_copy(currencyName);
    }
    int64_t supply = GetTotalPreallocation() + gatewayConverterIssuance;
    int nameLen = strlen(currencyName.c_str());

    std::vector<unsigned char> crcHeader(sizeof(supply) + nameLen);
    uint32_t crc0 = 0;
    bits256 hash;

    LogPrint("magicnumber", "hashing buffer: %s\n", HexBytes(&extraBuffer[0], extraBuffer.size()).c_str());

    iguana_rwnum(1, &crcHeader[0], sizeof(supply), (void *)&supply);
    memcpy(&(crcHeader[sizeof(supply)]), currencyName.c_str(), nameLen);

    LogPrint("magicnumber", "crc header buffer: %s\n", HexBytes(&crcHeader[0], crcHeader.size()).c_str());

    if (extraBuffer.size() && extraBuffer.size() >= lastSize)
    {
        vcalc_sha256(nullptr, hash.bytes, &(extraBuffer[0]), lastSize);
        crc0 = hash.uints[0];
    }
    return(calc_crc32(crc0, &crcHeader[0], sizeof(supply) + nameLen));
}

#define _ASSETCHAINS_TIMELOCKOFF 0xffffffffffffffff
extern uint64_t ASSETCHAINS_TIMELOCKGTE, ASSETCHAINS_TIMEUNLOCKFROM, ASSETCHAINS_TIMEUNLOCKTO;
extern int64_t ASSETCHAINS_SUPPLY, ASSETCHAINS_REWARD[3], ASSETCHAINS_DECAY[3], ASSETCHAINS_HALVING[3], ASSETCHAINS_ENDSUBSIDY[3], ASSETCHAINS_ERAOPTIONS[3];
extern int32_t PBAAS_STARTBLOCK, PBAAS_ENDBLOCK, ASSETCHAINS_LWMAPOS;
extern uint32_t ASSETCHAINS_ALGO, ASSETCHAINS_VERUSHASH, ASSETCHAINS_LASTERA;
extern std::string VERUS_CHAINNAME;
extern uint160 VERUS_CHAINID;

// ensures that the currency definition is valid and that there are no other definitions of the same name
// that have been confirmed.
bool ValidateCurrencyDefinition(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    return eval->Error("cannot spend currency definition output in current protocol");
}

bool PrecheckCurrencyDefinition(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    if (IsVerusMainnetActive())
    {
        if (CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_VERUSVAULT)
        {
            return true;
        }
        else if (CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_PBAAS)
        {
            return false;
        }
    }
    else if (CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_PBAAS)
    {
        return false;
    }

    // ensure that the currency definition follows all rules of currency definition, meaning:
    // 1) it is defined by an identity that controls the currency for the first time
    // 2) it is imported by another system that controls the currency for the first time
    // 3) it is defined in block 1 as part of a PBaaS chain launch, where it was required
    //
    // Further conditions, such as valid start block, or flag combinations apply, and as a special case,
    // if the currency is the ETH bridge and this is the Verus (or Rinkeby wrt VerusTest) blockchain,
    // it will assert itself as the notary chain of this network and use the gateway config information
    // to locate the RPC of the Alan (Monty Python's gatekeeper) bridge.
    //

    // first, let's figure out what kind of currency definition this is
    // valid definitions:
    // 1. Currency defined on this system by an ID on this system
    // 2. Imported currency controlled by or launched from another system defined on block 1's coinbase
    // 3. Imported currency from another system on an import from a system, which controls the imported currency
    bool isBlockOneDefinition = tx.IsCoinBase() && height == 1;
    bool isImportDefinition = false;

    CIdentity oldIdentity;
    CCrossChainImport cci, sysCCI;
    CPBaaSNotarization pbn;
    int sysCCIOut = -1, notarizationOut = -1, eOutStart = -1, eOutEnd = -1;
    CCrossChainExport ccx;
    std::vector<CReserveTransfer> transfers;
    CTransaction idTx;
    uint256 blkHash;

    CCurrencyDefinition newCurrency;
    COptCCParams currencyOptParams;
    if (!(tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(currencyOptParams) &&
          currencyOptParams.IsValid() &&
          currencyOptParams.evalCode == EVAL_CURRENCY_DEFINITION &&
          currencyOptParams.vData.size() > 1 &&
          (newCurrency = CCurrencyDefinition(currencyOptParams.vData[0])).IsValid()))
    {
        return state.Error("Invalid currency definition in output");
    }

    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    if (GetSerializeSize(ss, CReserveTransfer(CReserveTransfer::CURRENCY_EXPORT + CReserveTransfer::VALID + CReserveTransfer::CROSS_SYSTEM,
                            CCurrencyValueMap(std::vector<uint160>({ASSETCHAINS_CHAINID}), std::vector<int64_t>({1})),
                            ASSETCHAINS_CHAINID,
                            0,
                            newCurrency.GetID(),
                            CTransferDestination(CTransferDestination::DEST_REGISTERCURRENCY,
                            ::AsVector(newCurrency),
                            newCurrency.GetID()))) > (CScript::MAX_SCRIPT_ELEMENT_SIZE - 128))
    {
        return state.Error("Serialized currency is too large to send across PBaaS networks");
    }

    bool postViaUpdate = ConnectedChains.CheckZeroViaOnlyPostLaunch(height);
    if (postViaUpdate &&
        newCurrency.currencies.size() &&
        !(newCurrency.launchSystemID.IsNull() || newCurrency.GetCurrenciesMap().count(newCurrency.launchSystemID)))
    {
        return state.Error("Currency definition must include launch system native currency in currencies");
    }

    if (!isBlockOneDefinition)
    {
        CCrossChainImport launchCCI;
        CCrossChainExport launchCCX;

        // if this is an imported currency definition,
        // just be sure that it is part of an import and can be imported from the source
        // if so, it is fine
        for (int i = 0; i < tx.vout.size(); i++)
        {
            const CTxOut &oneOut = tx.vout[i];
            COptCCParams p;
            if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                i < outNum &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.vData.size() > 1 &&
                (cci = CCrossChainImport(p.vData[0])).IsValid())
            {
                if (cci.sourceSystemID != ASSETCHAINS_CHAINID &&
                    cci.GetImportInfo(tx, height, i, ccx, sysCCI, sysCCIOut, pbn, notarizationOut, eOutStart, eOutEnd, transfers) &&
                    pbn.IsValid() &&
                    pbn.IsLaunchConfirmed() &&
                    pbn.IsLaunchComplete() &&
                    outNum > eOutEnd &&
                    outNum <= (eOutEnd + cci.numOutputs))
                {
                    isImportDefinition = true;
                    break;
                }
            }
            else if (p.IsValid() &&
                     (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                     p.vData.size() &&
                     !pbn.IsValid() &&
                     (pbn = CPBaaSNotarization(p.vData[0])).IsValid() &&
                     pbn.currencyID == newCurrency.GetID())
            {
                continue;
            }
            if (pbn.IsValid() && pbn.currencyID != newCurrency.GetID())
            {
                pbn = CPBaaSNotarization();
            }
            if (!((launchCCX.IsValid() &&
                   launchCCX.destCurrencyID == newCurrency.GetID())) &&
                p.IsValid() &&
                (p.evalCode == EVAL_CROSSCHAIN_EXPORT) &&
                p.vData.size() &&
                (launchCCX = CCrossChainExport(p.vData[0])).IsValid() &&
                launchCCX.destCurrencyID == newCurrency.GetID())
            {
                continue;
            }
            if (launchCCX.IsValid() && launchCCX.destCurrencyID != newCurrency.GetID())
            {
                launchCCX = CCrossChainExport();
            }
            if (!(launchCCI.IsValid() &&
                  launchCCI.importCurrencyID == newCurrency.GetID()) &&
                p.IsValid() &&
                (p.evalCode == EVAL_CROSSCHAIN_IMPORT) &&
                p.vData.size() &&
                (launchCCI = CCrossChainImport(p.vData[0])).IsValid() &&
                launchCCI.importCurrencyID == newCurrency.GetID())
            {
                continue;
            }
            if (launchCCI.IsValid() && launchCCI.importCurrencyID != newCurrency.GetID())
            {
                launchCCI = CCrossChainImport();
            }
        }

        // in this case, it must either spend an identity or be on an import transaction
        // that has a reserve transfer which imports the currency
        std::map<uint160, std::string> newDefinitions;
        std::string newSystemName;
        CCurrencyDefinition newSystem;
        if (!isImportDefinition)
        {
            std::vector<CCurrencyDefinition> currencyDefs = CCurrencyDefinition::GetCurrencyDefinitions(tx);

            LOCK(mempool.cs);

            if (currencyDefs.size() > 1)
            {
                for (auto &oneCur : currencyDefs)
                {
                    if (oneCur.IsPBaaSChain() || oneCur.IsGateway())
                    {
                        newSystemName = oneCur.name + "." + ConnectedChains.GetFriendlyCurrencyName(oneCur.parent);
                        newSystem = oneCur;
                        newDefinitions.insert(std::make_pair(oneCur.GetID(), newSystemName));
                    }
                    else if (!(oneCur.IsPBaaSChain() || oneCur.IsGateway()) && newSystem.IsValid())
                    {
                        if (oneCur.parent == newSystem.GetID())
                        {
                            newDefinitions.insert(std::make_pair(oneCur.GetID(), oneCur.name + "." + newSystemName));
                        }
                    }
                }
            }
            try
            {
                std::map<uint160, std::string> requiredDefinitions = newDefinitions;

                if (!ValidateNewUnivalueCurrencyDefinition(newCurrency.ToUniValue(), height - 1, newCurrency.systemID, requiredDefinitions, false).IsValid())
                {
                    LogPrint("currencydefinition", "%s: Currency definition in output violates current definition rules.\n%s\n", __func__, newCurrency.ToUniValue().write(1,2).c_str());
                    return state.Error("Currency definition in output violates current definition rules");
                }

                bool isMappedCurrency = (newCurrency.systemID != ASSETCHAINS_CHAINID &&
                                         newCurrency.IsToken() &&
                                         !newCurrency.IsFractional() &&
                                         (newCurrency.nativeCurrencyID.TypeNoFlags() == newCurrency.nativeCurrencyID.DEST_ETH ||
                                          newCurrency.IsNFTToken()));

                if (newCurrency.IsPBaaSChain())
                {
                    uint160 converterID = newCurrency.GatewayConverterID();
                    std::set<uint160> validCurrencyParents({newCurrency.GetID(), newCurrency.launchSystemID});
                    std::set<uint160> validIDParents({newCurrency.launchSystemID});
                    CCurrencyDefinition converterCur;
                    std::map<uint160, int32_t> currencyConverterMap;
                    if (!converterID.IsNull())
                    {
                        CCurrencyDefinition oneNewCur;
                        for (auto &oneNewCur : currencyDefs)
                        {
                            if (oneNewCur.GetID() == converterID)
                            {
                                if (!oneNewCur.IsFractional())
                                {
                                    return state.Error("Converter currencies must be fractional");
                                }
                                converterCur = oneNewCur;
                                break;
                            }
                        }
                        for (auto &oneCurID : newCurrency.currencies)
                        {
                            // if it's new, it can't be a valid ID or currency parent
                            if (newDefinitions.count(oneCurID))
                            {
                                continue;
                            }
                            // not new, look it up to ensure that its parent is present, and if its parent
                            // is present already, add it as a valid parent
                            CCurrencyDefinition oneParentCur = ConnectedChains.GetCachedCurrency(oneCurID);

                            if (!oneParentCur.IsValid() ||
                                (!oneParentCur.parent.IsNull() && !validCurrencyParents.count(oneParentCur.parent)))
                            {
                                return state.Error("Invalid currency inclusion before parent");
                            }

                            // if this currency is new with a new parent, it can not parent any IDs or currencies
                            if (!oneParentCur.parent.IsNull() && newDefinitions.count(oneParentCur.parent))
                            {
                                continue;
                            }
                            validCurrencyParents.insert(oneCurID);
                            validIDParents.insert(oneCurID);
                        }
                        if (converterCur.IsValid())
                        {
                            for (auto &oneCurID : converterCur.currencies)
                            {
                                // new definitions of currency are ok in the converter, as long as it's not itself,
                                // which would prevent it from launching
                                if (oneCurID == converterID)
                                {
                                    return state.Error("A fractional currency cannot launch with itself as a reserve");
                                }
                                // if it's new, it can't be a valid ID or currency parent
                                if (newDefinitions.count(oneCurID))
                                {
                                    continue;
                                }
                                // not new, look it up to ensure that its parent is present, and if its parent
                                // is present already, add it as a valid parent
                                CCurrencyDefinition oneParentCur = ConnectedChains.GetCachedCurrency(oneCurID);
                                if (oneParentCur.parent.IsNull())
                                {
                                    continue;
                                }

                                if (!oneParentCur.IsValid() ||
                                    (!oneParentCur.parent.IsNull() && !validCurrencyParents.count(oneParentCur.parent)))
                                {
                                    return state.Error("Invalid currency inclusion before parent");
                                }
                                // if this currency's parent is new, this currency can not parent any additional IDs or currencies
                                // if not, it can
                                if (!oneParentCur.parent.IsNull() && newDefinitions.count(oneParentCur.parent))
                                {
                                    continue;
                                }
                                validCurrencyParents.insert(oneCurID);
                                validIDParents.insert(oneCurID);
                            }
                        }
                    }

                    // all notaries and preallocated IDs must already exist
                    for (auto &oneIdID : newCurrency.notaries)
                    {
                        CIdentity oneIdentity = CIdentity::LookupIdentity(oneIdID);
                        if (!oneIdentity.IsValid())
                        {
                            return state.Error("All IDs must be defined before specified as notary in a currency definition");
                        }
                        if (!validIDParents.count(oneIdentity.parent))
                        {
                            return state.Error("All notary IDs must have parent currencies that are included in the reserve or launch participation currencies");
                        }
                    }
                    // all preallocated IDs must already exist
                    for (auto &oneIdValPair : newCurrency.preAllocation)
                    {
                        if (!oneIdValPair.first.IsNull())
                        {
                            CIdentity oneIdentity = CIdentity::LookupIdentity(oneIdValPair.first);
                            if (!oneIdentity.IsValid())
                            {
                                return state.Error("All IDs must be defined before specified as preallocation recipient in a currency definition");
                            }
                            if (!validIDParents.count(oneIdentity.parent))
                            {
                                return state.Error("All pre-allocation IDs must have parent currencies that are included in the reserve or launch participation currencies");
                            }
                        }
                    }
                }

                // now, make sure new currency matches any initial notarization
                // if this is not the systemID, we must be either a gateway, PBaaS chain, mapped currency, or gateway converter
                CCurrencyDefinition newSystemCurrency;
                if (isMappedCurrency ||
                    (newCurrency.launchSystemID == ASSETCHAINS_CHAINID &&
                     newCurrency.systemID != ASSETCHAINS_CHAINID))
                {
                    bool failed = true;
                    for (auto &oneCurDef : currencyDefs)
                    {
                        if (oneCurDef.IsValid() &&
                            oneCurDef.GetID() == newCurrency.systemID)
                        {
                            if ((oneCurDef.IsGateway() &&
                                    newCurrency.nativeCurrencyID.TypeNoFlags() != newCurrency.nativeCurrencyID.DEST_INVALID) ||
                                (oneCurDef.IsPBaaSChain() &&
                                    oneCurDef.GatewayConverterID() == newCurrency.GetID() &&
                                    newCurrency.IsGatewayConverter()))
                            {
                                newSystemCurrency = oneCurDef;
                            }
                            failed = false;
                            break;
                        }
                    }
                    if (failed)
                    {
                        newSystemCurrency = ConnectedChains.GetCachedCurrency(newCurrency.systemID);
                        if (newSystemCurrency.IsGateway() &&
                            newCurrency.systemID == newSystemCurrency.GetID() &&
                            (newCurrency.parent == ASSETCHAINS_CHAINID ||
                                (newSystemCurrency.parent == ASSETCHAINS_CHAINID &&
                                !newSystemCurrency.IsNameController() &&
                                newCurrency.parent == newSystemCurrency.GetID())) &&
                            newSystemCurrency.nativeCurrencyID.TypeNoFlags() == newCurrency.nativeCurrencyID.DEST_ETH)
                        {
                            failed = false;
                        }
                        if (failed)
                        {
                            return state.Error("New currency definition does not have a system ID of this chain or as a mapped currency on the new system");
                        }
                    }
                }

                if (!(isMappedCurrency && !pbn.IsValid()))
                {
                    if (!pbn.IsValid() ||
                        !pbn.IsDefinitionNotarization() ||
                        pbn.IsMirror() ||
                        newCurrency.IsFractional() != pbn.currencyState.IsFractional() ||
                        !launchCCX.IsValid() ||
                        launchCCX.destSystemID != newCurrency.SystemOrGatewayID() ||
                        !launchCCX.IsChainDefinition() ||
                        launchCCX.numInputs ||
                        launchCCI.numOutputs ||
                        !launchCCI.IsValid() ||
                        !launchCCI.IsDefinitionImport() ||
                        (!(newCurrency.IsGateway() || newCurrency.GetID() == ASSETCHAINS_CHAINID) &&
                         (!launchCCX.IsPrelaunch() ||
                          launchCCX.IsPostlaunch() ||
                          launchCCI.IsPostLaunch())))
                    {
                        return state.Error("New currency definition must have valid notarization export and import on definition transaction");
                    }
                    if (chainActive.Height() >= (height - 1))
                    {
                        CCoinbaseCurrencyState checkCurrencyState = ConnectedChains.GetCurrencyState(newCurrency, height - 1);
                        checkCurrencyState.flags = pbn.currencyState.flags;

                        if (newCurrency.IsGatewayConverter() &&
                            newSystemCurrency.IsValid())
                        {
                            int currencyIndex = checkCurrencyState.GetReserveMap()[newSystemCurrency.GetID()];
                            checkCurrencyState.reserveIn[currencyIndex] += newSystemCurrency.gatewayConverterIssuance;
                        }

                        if (::AsVector(pbn.currencyState) != ::AsVector(checkCurrencyState))
                        {
                            if (LogAcceptCategory("notarization"))
                            {
                                LogPrintf("%s: Currency state mismatch. Expected:\n%s\nActual\n%s\n", __func__, checkCurrencyState.ToUniValue().write(1,2).c_str(), pbn.currencyState.ToUniValue().write(1,2).c_str());
                            }
                            if (PBAAS_TESTMODE && chainActive[height - 1]->nTime >= PBAAS_TESTFORK_TIME)
                            {
                                return state.Error("New currency definition must have valid currency state in notarization");
                            }
                        }
                    }
                    if (!newCurrency.IsGateway() &&
                        newCurrency.GetID() != ASSETCHAINS_CHAINID &&
                        (!pbn.IsPreLaunch() ||
                        !pbn.currencyState.IsPrelaunch()))
                    {
                        return state.Error("New currency definition must have valid notarization state on output");
                    }
                }

                // ensure that either the required definitions are on this transaction, such as a PBaaS chain and its converter or mapped currencies
                // on the same definition
                // add system check, even though it is checked elsewhere now to ensure
                // adherence
                if (newCurrency.IsFractional() &&
                    newCurrency.systemID == ASSETCHAINS_CHAINID)
                {
                    // if fractional, make sure that the following is true:
                    // 1) if this is a currency converter then:
                    //   a) the system or gateway it is a converter currency for must be defined with this currency
                    //   b) if this is a PBaaS chain, all other currencies in its reserves must be already defined, or
                    //      if this is a gateway currency, it may also include currencies mapped from the gateway
                    // 2) if not a currency converter, all reserves must be already defined
                    // 3) all reserve currencies must have completed their launches successfully without refunding,
                    //    exceptions are PBaaS or gateway currencies that may be co-launching with the converter
                    auto currencyMap = newCurrency.GetCurrenciesMap();
                    for (auto &oneNewCurrency : currencyDefs)
                    {
                        uint160 oneCurID = oneNewCurrency.GetID();
                        if (currencyMap.count(oneCurID))
                        {
                            // NFTs not yet supported as reserves, and any co-defined
                            // reserves must be alternate gateways or PBaaS chains
                            if (oneNewCurrency.IsNFTToken() ||
                                (!isBlockOneDefinition &&
                                 oneNewCurrency.SystemOrGatewayID() == ASSETCHAINS_CHAINID))
                            {
                                return state.Error("Tokenized ID control tokens (NFTs) may not yet be used as reserve currencies in a basket");
                            }
                            currencyMap.erase(oneCurID);
                        }
                    }
                    for (auto &oneCurID : currencyMap)
                    {
                        CCurrencyDefinition oneReserveCur = ConnectedChains.GetCachedCurrency(oneCurID.first);
                        if (!oneReserveCur.IsValid())
                        {
                            return state.Error("Invalid reserve currency");
                        }
                        if (oneReserveCur.launchSystemID == ASSETCHAINS_CHAINID)
                        {
                            std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> lastNotarization = GetLastConfirmedNotarization(oneCurID.first, height - 1);
                            if (std::get<0>(lastNotarization) &&
                                (!std::get<2>(lastNotarization).IsLaunchConfirmed() ||
                                    !std::get<2>(lastNotarization).IsLaunchComplete()))
                            {
                                LogPrintf("%s: txid to exempt from prelaunch reserve check: %s\n", __func__, tx.GetHash().GetHex().c_str());
                            }
                        }
                    }
                }
            }
            catch(const UniValue &e)
            {
                LogPrint("currencydefinition", "%s: %s\n", __func__, uni_get_str(find_value(e, "message")).c_str());
                LogPrint("currencydefinition", "%s\n", newCurrency.ToUniValue().write(1,2).c_str());
                return state.Error("Currency definition in output violates current definition rules");
            }

            for (auto &input : tx.vin)
            {
                COptCCParams p;
                // first time through may be null
                if ((!input.prevout.hash.IsNull() && input.prevout.hash == idTx.GetHash()) || myGetTransaction(input.prevout.hash, idTx, blkHash))
                {
                    if (input.prevout.n >= idTx.vout.size())
                    {
                        return state.Error("Invalid, malformed transaction 2");
                    }
                    if (idTx.vout[input.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() &&
                        p.evalCode == EVAL_IDENTITY_PRIMARY &&
                        p.vData.size() > 1 &&
                        (oldIdentity = CIdentity(p.vData[0])).IsValid() &&
                        (oldIdentity.GetID() == newCurrency.GetID() || oldIdentity.GetID() == newCurrency.parent))
                    {
                        break;
                    }
                    oldIdentity.nVersion = oldIdentity.VERSION_INVALID;
                }
            }
            if (!oldIdentity.IsValid())
            {
                return state.Error("No valid identity found for currency definition");
            }
            if (oldIdentity.HasActiveCurrency())
            {
                return state.Error("Identity already has used its one-time ability to define a currency");
            }
            CIdentity newIdentity;
            for (auto &oneOut : tx.vout)
            {
                COptCCParams p;
                if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_IDENTITY_PRIMARY &&
                    p.vData.size() > 1 &&
                    (newIdentity = CIdentity(p.vData[0])).IsValid() &&
                    (newIdentity.GetID() == newCurrency.GetID() || newIdentity.GetID() == newCurrency.parent))
                {
                    break;
                }
                newIdentity.nVersion = oldIdentity.VERSION_INVALID;
            }
            if (!newIdentity.IsValid())
            {
                return state.Error("Invalid identity found for currency definition");
            }
            if (!newIdentity.HasActiveCurrency())
            {
                return state.Error("Identity has not been set to defined currency status");
            }
            if (newIdentity.GetID() != ASSETCHAINS_CHAINID || !IsVerusActive())
            {
                CCurrencyDefinition parentCurrency = ConnectedChains.GetCachedCurrency(newIdentity.parent);
                if (!parentCurrency.IsValid())
                {
                    return state.Error("Parent currency invalid to issue identities on this chain");
                }

                // any ID with a gateway as its system ID can issue an NFT mapped currency with 0
                // satoshi supply as its currency for the cost of an ID import, not a currency import
                CCurrencyDefinition systemDef = newSystem;
                if (newCurrency.launchSystemID == ASSETCHAINS_CHAINID &&
                    newCurrency.IsNFTToken() &&
                    !systemDef.IsValid())
                {
                    systemDef = ConnectedChains.GetCachedCurrency(newCurrency.systemID);
                }

                bool isNFTMappedCurrency = false;
                if (newCurrency.IsNFTToken())
                {
                    isNFTMappedCurrency = newCurrency.IsNFTToken() &&
                                          systemDef.IsValid() &&
                                          !(newCurrency.options &
                                            newCurrency.OPTION_FRACTIONAL +
                                            newCurrency.OPTION_GATEWAY +
                                            newCurrency.OPTION_PBAAS +
                                            newCurrency.OPTION_GATEWAY_CONVERTER) &&
                                          newCurrency.IsToken();

                    if (!isNFTMappedCurrency ||
                        (!(newCurrency.nativeCurrencyID.TypeNoFlags() == newCurrency.nativeCurrencyID.DEST_ETHNFT &&
                           systemDef.proofProtocol == systemDef.PROOF_ETHNOTARIZATION &&
                           systemDef.IsGateway() &&
                           newCurrency.maxPreconvert.size() == 1 &&
                           newCurrency.maxPreconvert[0] == 0 &&
                           newCurrency.GetTotalPreallocation() == 0) &&
                         !(newCurrency.systemID == ASSETCHAINS_CHAINID &&
                           ((newCurrency.GetTotalPreallocation() == 0 &&
                             newCurrency.maxPreconvert.size() == 1 &&
                             newCurrency.maxPreconvert[0] == 1) ||
                           (newCurrency.GetTotalPreallocation() == 1 &&
                             newCurrency.maxPreconvert.size() == 1 &&
                             newCurrency.maxPreconvert[0] == 0)))))
                    {
                        if (newCurrency.nativeCurrencyID.TypeNoFlags() == newCurrency.nativeCurrencyID.DEST_ETHNFT)
                        {
                            return state.Error("Ethereum NFT mapped currency must have 0 satoshis of supply, maxpreconversions of [0], and follow all definition rules");
                        }
                        else
                        {
                            return state.Error("Tokenized ID control currency must have 1 satoshi of supply, and follow all definition rules");
                        }
                    }
                }

                if (isNFTMappedCurrency && newCurrency.proofProtocol == newCurrency.PROOF_CHAINID)
                {
                    return state.Error("NFT or tokenized control currency may not also be a centralized currency");
                }

                if (isNFTMappedCurrency && !newIdentity.HasTokenizedControl())
                {
                    return state.Error("Identity not set for tokenized control when defining NFT token or tokenized control currency");
                }

                if (newIdentity.parent != ASSETCHAINS_CHAINID &&
                    !isNFTMappedCurrency &&
                    !(parentCurrency.IsGateway() && parentCurrency.launchSystemID == ASSETCHAINS_CHAINID && !parentCurrency.IsNameController()))
                {
                    return state.Error("Only gateway and root chain identities may create non-NFT currencies");
                }

                if (newCurrency.nativeCurrencyID.TypeNoFlags() == newCurrency.nativeCurrencyID.DEST_ETH &&
                    !(systemDef.proofProtocol == systemDef.PROOF_ETHNOTARIZATION &&
                      newCurrency.maxPreconvert.size() == 1 &&
                      newCurrency.maxPreconvert[0] == 0 &&
                      newCurrency.GetTotalPreallocation() == 0)  &&
                    !(newCurrency.systemID == newIdentity.parent ||
                      newIdentity.parent == ASSETCHAINS_CHAINID))
                {
                    return state.Error("Invalid mapped currency definition");
                }
            }
        }
    }
    return true;
}

// return currencies that are registered and may be exported to the specified system
// all returned currencies may also be used as
std::set<uint160> BaseBridgeCurrencies(const CCurrencyDefinition &systemDest, uint32_t height, bool feeOnly)
{
    std::set<uint160> retVal;
    uint160 sysID = systemDest.GetID();
    // if this gateway or PBaaS chain was launched from this system
    if ((systemDest.IsPBaaSChain() || systemDest.IsGateway()) &&
        sysID != ASSETCHAINS_CHAINID &&
        (systemDest.launchSystemID == ASSETCHAINS_CHAINID || ConnectedChains.ThisChain().launchSystemID == sysID))
    {
        // we launched the system we are checking, or we were launched by the system we are checking
        // both cases involve the same lookups for the baseline. all connected, multi-currency systems
        // can accept this currency and the system's native currency
        retVal.insert(sysID);
        if (systemDest.IsMultiCurrency())
        {
            // whether or not we have a converter, launch currency can be used as fees for new system
            if (!feeOnly || systemDest.launchSystemID == ASSETCHAINS_CHAINID)
            {
                retVal.insert(ASSETCHAINS_CHAINID);
                for (auto &oneCur : systemDest.currencies)
                {
                    if (!oneCur.IsNull())
                    {
                        retVal.insert(oneCur);
                    }
                }
            }
            uint160 converterID = systemDest.launchSystemID == ASSETCHAINS_CHAINID ?
                                    systemDest.GatewayConverterID() :
                                    ConnectedChains.ThisChain().GatewayConverterID();
            if (!converterID.IsNull())
            {
                CCurrencyDefinition converter = ConnectedChains.GetCachedCurrency(converterID);
                if (converter.IsValid() && converter.IsFractional())
                {
                    retVal.insert(converterID);
                    for (auto &oneCurID : converter.currencies)
                    {
                        retVal.insert(oneCurID);
                    }
                }
            }
        }
    }
    return retVal;
}

// return currencies that are registered and may be exported to the specified system
std::set<uint160> ValidExportCurrencies(const CCurrencyDefinition &systemDest, uint32_t height)
{
    std::set<uint160> retVal = BaseBridgeCurrencies(systemDest, height, false);
    uint160 sysID = systemDest.GetID();

    // if this gateway or PBaaS chain was launched from this system
    if (retVal.size() && systemDest.IsMultiCurrency())
    {
        // now look for exported currency definitions
        std::vector<CAddressIndexDbEntry> addresses;
        // this will always validate correctly, even if the index for this block is present, as we only look up to height - 1
        if (GetAddressIndex(CTransferDestination::CurrencyDefinitionExportKeyToSystem(sysID), CScript::P2IDX, addresses, 0, height - 1) &&
            addresses.size())
        {
            for (auto &oneIdx : addresses)
            {
                if (oneIdx.first.spending)
                {
                    continue;
                }
                uint256 blkHash;
                CTransaction rtTx;

                if (!myGetTransaction(oneIdx.first.txhash, rtTx, blkHash) || rtTx.vout.size() <= oneIdx.first.index)
                {
                    LogPrintf("%s: ERROR - ACTION REQUIRED: Invalid entry in transaction index, should not move forward as a node. Please bootstrap, sync from scratch, or reindex to continue\n", __func__);
                    printf("%s: ERROR - ACTION REQUIRED: Invalid entry in transaction index, should not move forward as a node. Please bootstrap, sync from scratch, or reindex to continue\n", __func__);
                    KOMODO_STOPAT = chainActive.Height();
                    return std::set<uint160>();
                }
                COptCCParams p;
                CReserveTransfer rt;
                CCurrencyDefinition exportCur;
                CCrossChainExport ccx;
                if (rtTx.vout[oneIdx.first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_RESERVE_TRANSFER &&
                    p.vData.size() &&
                    (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                    rt.IsCurrencyExport() &&
                    rt.IsCrossSystem() &&
                    rt.destSystemID == sysID &&
                    (exportCur = CCurrencyDefinition(rt.destination.destination)).IsValid())
                {
                    // make sure this reserve transfer is spent, so we know it is rolled up to an export
                    CSpentIndexKey spentKey(oneIdx.first.txhash, oneIdx.first.index);
                    CSpentIndexValue spentVal;
                    if (GetSpentIndex(spentKey, spentVal))
                    {
                        retVal.insert(exportCur.GetID());
                    }
                }
                else if (p.IsValid() &&
                            p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                            p.vData.size() &&
                            (ccx = CCrossChainExport(p.vData[0])).IsValid() &&
                            ccx.sourceSystemID != ASSETCHAINS_CHAINID &&
                            ccx.reserveTransfers.size())
                {
                    // look through reserve transfers for export imports
                    for (auto &oneRT : ccx.reserveTransfers)
                    {
                        if (oneRT.IsCurrencyExport())
                        {
                            // store the unbound and bound currency export index
                            // for each currency
                            retVal.insert(oneRT.FirstCurrency());
                        }
                    }
                }
            }
        }
    }
    return retVal;
}

// return currencies that are registered and may be exported to the specified system
bool IsValidExportCurrency(const CCurrencyDefinition &systemDest, const uint160 &exportCurrencyID, uint32_t height)
{
    std::set<uint160> retVal;
    uint160 sysID = systemDest.GetID();

    // assume the currency to export will be validity checked elsewhere,
    // if we are not exporting off chain, all valid currencies are OK
    if (sysID == ASSETCHAINS_CHAINID)
    {
        return true;
    }

    std::set<uint160> validCurrencies;
    if (ConnectedChains.IsUpgrade02Active(height))
    {
        CCurrencyDefinition exportCurrency = ConnectedChains.GetCachedCurrency(exportCurrencyID);
        if (!exportCurrency.IsValid())
        {
            return false;
        }

        if (BaseBridgeCurrencies(systemDest, height, false).count(exportCurrencyID) ||
            ConnectedChains.IsValidCurrencyDefinitionImport(systemDest, ConnectedChains.ThisChain(), exportCurrency, height))
        {
            return true;
        }
    }

    // if this gateway or PBaaS chain was launched from this system
    if ((systemDest.IsPBaaSChain() || systemDest.IsGateway()) &&
        sysID != ASSETCHAINS_CHAINID &&
        (systemDest.launchSystemID == ASSETCHAINS_CHAINID || ConnectedChains.ThisChain().launchSystemID == sysID))
    {
        if (exportCurrencyID == sysID)
        {
            return true;
        }
        if (!systemDest.IsMultiCurrency())
        {
            return false;
        }
        if (exportCurrencyID == ASSETCHAINS_CHAINID)
        {
            return true;
        }

        int64_t thresholdTime = (height > 1 && chainActive.Height() >= height) ? chainActive[height]->nTime : chainActive.LastTip()->nTime;
        uint160 converterID = !IsVerusActive() && ConnectedChains.FirstNotaryChain().GetID() == sysID ? ConnectedChains.ThisChain().GatewayConverterID() : systemDest.GatewayConverterID();
        if (!converterID.IsNull())
        {
            CCurrencyDefinition converter = ConnectedChains.GetCachedCurrency(converterID);
            if (converter.IsValid() && converter.IsFractional())
            {
                if (exportCurrencyID == converterID)
                {
                    return true;
                }

                for (auto &oneCurID : converter.currencies)
                {
                    if (exportCurrencyID == oneCurID)
                    {
                        return true;
                    }
                }
            }
        }

        // now look for exported currency definitions
        std::vector<CAddressIndexDbEntry> addresses;
        // this will always validate correctly, even if the index for this block is present, as we only look up to height - 1
        if (GetAddressIndex(CTransferDestination::GetBoundCurrencyDefinitionExportKey(sysID, exportCurrencyID),
                            CScript::P2IDX,
                            addresses, 0, height - 1) &&
            addresses.size())
        {
            for (auto &oneIdx : addresses)
            {
                if (oneIdx.first.spending)
                {
                    continue;
                }
                uint256 blkHash;
                CTransaction rtTx;

                if (!myGetTransaction(oneIdx.first.txhash, rtTx, blkHash) || rtTx.vout.size() <= oneIdx.first.index)
                {
                    LogPrintf("%s: ERROR - ACTION REQUIRED: Invalid entry in transaction index, should not move forward as a node. Please bootstrap, sync from scratch, or reindex to continue\n", __func__);
                    printf("%s: ERROR - ACTION REQUIRED: Invalid entry in transaction index, should not move forward as a node. Please bootstrap, sync from scratch, or reindex to continue\n", __func__);
                    KOMODO_STOPAT = chainActive.Height();
                    return false;
                }
                COptCCParams p;
                CReserveTransfer rt;
                CCurrencyDefinition exportCur;
                CCrossChainExport ccx;
                if (rtTx.vout[oneIdx.first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_RESERVE_TRANSFER &&
                    p.vData.size() &&
                    (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                    rt.IsCurrencyExport() &&
                    rt.IsCrossSystem() &&
                    rt.destSystemID == sysID &&
                    (exportCur = CCurrencyDefinition(rt.destination.destination)).IsValid() &&
                    exportCur.GetID() == exportCurrencyID)
                {
                    return true;
                }
                else if (p.IsValid() &&
                         p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                         p.vData.size() &&
                         (ccx = CCrossChainExport(p.vData[0])).IsValid() &&
                         ccx.sourceSystemID != ASSETCHAINS_CHAINID &&
                         ccx.reserveTransfers.size())
                {
                    // look through reserve transfers for export imports
                    for (auto &oneRT : ccx.reserveTransfers)
                    {
                        if (oneRT.IsCurrencyExport() && oneRT.FirstCurrency() == exportCurrencyID)
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

bool CheckIdentitySpends(const CTransaction &tx, const uint160 idID, CValidationState &state, uint32_t height, bool allAuthorities=false);
bool CheckIdentitySpends(const CTransaction &tx, const uint160 idID, CValidationState &state, uint32_t height, bool allAuthorities)
{
    // spent by currency ID
    bool authorizedController = false;

    CIdentity signingID = CIdentity::LookupIdentity(idID, height);
    if (!signingID.IsValid())
    {
        return state.Error("Invalid identity or necessary identities not found for approval of ID operation");
    }

    CIdentity revokeID = (!allAuthorities || signingID.revocationAuthority == idID) ? signingID : CIdentity::LookupIdentity(signingID.revocationAuthority, height);
    CIdentity recoveryID = (!allAuthorities || signingID.recoveryAuthority == idID) ? signingID : CIdentity::LookupIdentity(signingID.recoveryAuthority, height);
     if (!revokeID.IsValid() || !recoveryID.IsValid())
    {
        return state.Error("Invalid revoke or recovery identity or necessary identities not found for approval of ID operation");
    }

    std::set<uint160> signingKeys;
    for (auto &oneDest : signingID.primaryAddresses)
    {
        signingKeys.insert(GetDestinationID(oneDest));
    }

    std::set<uint160> revokeKeys;
    for (auto &oneDest : revokeID.primaryAddresses)
    {
        revokeKeys.insert(GetDestinationID(oneDest));
    }

    std::set<uint160> recoverKeys;
    for (auto &oneDest : recoveryID.primaryAddresses)
    {
        recoverKeys.insert(GetDestinationID(oneDest));
    }

    for (auto &oneIn : tx.vin)
    {
        CTransaction inputTx;
        uint256 blockHash;

        // this is not an input check, but we will check if the input is available
        // the precheck's can be called sometimes before their antecedents are available, but
        // if they are available, which will be checked on the input check, they will also be
        // available here at least once in the verification of the tx
        if (myGetTransaction(oneIn.prevout.hash, inputTx, blockHash))
        {
            if (oneIn.prevout.n >= inputTx.vout.size())
            {
                return state.Error("Invalid input number for source transaction");
            }

            COptCCParams p;

            // make sure that no form of complex output could circumvent the test for controller
            // this should be encapsulated as a test that can handle complex cases, but until then
            // require them to be simple when validating
            if (!(inputTx.vout[oneIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.version >= p.VERSION_V3 &&
                    inputTx.vout[oneIn.prevout.n].scriptPubKey.IsSpendableOutputType(p)))
            {
                continue;
            }

            CSmartTransactionSignatures smartSigs;
            std::vector<unsigned char> ffVec = GetFulfillmentVector(oneIn.scriptSig);
            if (!(ffVec.size() &&
                    (smartSigs = CSmartTransactionSignatures(std::vector<unsigned char>(ffVec.begin(), ffVec.end()))).IsValid() &&
                    smartSigs.sigHashType == SIGHASH_ALL))
            {
                continue;
            }

            int numIDSigs = 0;
            int numRevokeSigs = 0;
            int numRecoverSigs = 0;

            // ensure that the transaction is sent to the ID and signed by a valid ID signature
            for (auto &oneSig : smartSigs.signatures)
            {
                if (signingKeys.count(oneSig.first))
                {
                    numIDSigs++;
                }
                if (revokeKeys.count(oneSig.first))
                {
                    numRevokeSigs++;
                }
                if (recoverKeys.count(oneSig.first))
                {
                    numRecoverSigs++;
                }
            }

            if (numIDSigs < signingID.minSigs ||
                (!signingID.HasActiveCurrency() &&
                 (numRevokeSigs < revokeID.minSigs ||
                  numRecoverSigs < recoveryID.minSigs)))
            {
                continue;
            }

            authorizedController = true;
            break;
        }
    }
    return authorizedController;
}

bool CurrenciesAndNotarizations(const CTransaction &tx, std::map<uint160, std::pair<CCurrencyDefinition, CPBaaSNotarization>> &currenciesAndNotarizations)
{
    CPBaaSNotarization oneNotarization;
    CCurrencyDefinition oneCur;

    // we need to get the first notarization and possibly systemDest currency here as well
    for (auto &oneOut : tx.vout)
    {
        COptCCParams p;
        if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.vData.size())
        {
            if (p.evalCode == EVAL_CURRENCY_DEFINITION)
            {
                if (!(oneCur = CCurrencyDefinition(p.vData[0])).IsValid())
                {
                    return false;
                }
                currenciesAndNotarizations[oneCur.GetID()].first = oneCur;
            }
            else if (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION)
            {
                if (!(oneNotarization = CPBaaSNotarization(p.vData[0])).IsValid())
                {
                    return false;
                }
                currenciesAndNotarizations[oneNotarization.currencyID].second = oneNotarization;
            }
        }
    }
    return true;
}

bool PrecheckReserveTransfer(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // do a basic sanity check that this reserve transfer's values are consistent and that it includes the
    // basic fees required to cover the transfer
    COptCCParams p;
    CReserveTransfer rt;

    uint32_t chainHeight = chainActive.Height();
    bool haveFullChain = height <= chainHeight + 1;

    if (haveFullChain && ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableDeFiKey()))
    {
        if (LogAcceptCategory("defi"))
        {
            LogPrintf("%s: DeFi functions temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
        }
        return state.Error("DeFi functions temporarily disabled for security alert by notification oracle. Reserve transfer rejected " + rt.ToUniValue().write(1,2));
    }

    if (tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.evalCode == EVAL_RESERVE_TRANSFER &&
        p.vData.size() &&
        (rt = CReserveTransfer(p.vData[0])).IsValid() &&
        rt.TotalCurrencyOut().valueMap[ASSETCHAINS_CHAINID] == tx.vout[outNum].nValue &&
        (rt.IsArbitrageOnly() || p.IsEvalPKOut()) &&
        rt.destination.AuxDestCount() <= 3)
    {
        // arbitrage transactions are determined by their context and statically setting the flags is prohibited
        if (rt.IsArbitrageOnly() &&
            (rt.IsCurrencyExport() ||
             rt.IsIdentityExport() ||
             rt.IsCrossSystem()))
        {
            return state.Error("Arbitrage transfers must be simple and from/to same chain, even when arbitraging cross-chain imports " + rt.ToUniValue().write(1,2));
        }

        if (p.AsVector().size() >= CScript::MAX_SCRIPT_ELEMENT_SIZE)
        {
            return state.Error("Reserve transfer exceeds maximum size " + rt.ToUniValue().write(1,2));
        }

        uint160 systemDestID, importCurrencyID;
        CCurrencyDefinition systemDest, importCurrencyDef;

        importCurrencyID = rt.GetImportCurrency();
        importCurrencyDef = ConnectedChains.GetCachedCurrency(importCurrencyID);

        // if we are an initial contribution for a currency definition, make sure we include the new currencies when checking
        std::vector<CCurrencyDefinition> newCurrencies;
        CCurrencyDefinition *pGatewayConverter = nullptr;
        std::set<uint160> validExportCurrencies;

        CCoinbaseCurrencyState importState;
        std::map<uint160, std::pair<CCurrencyDefinition, CPBaaSNotarization>> currenciesAndNotarizations;

        if (rt.IsPreConversion())
        {
            if (rt.IsCurrencyExport() || rt.HasNextLeg() || rt.IsIdentityExport())
            {
                return state.Error("Invalid preconversion reserve transfer " + rt.ToUniValue().write(1,2));
            }

            std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> lastConfirmedForImport = GetLastConfirmedNotarization(importCurrencyID, height - 1);

            // if pre-conversion, we may find definitions on the transaction
            // false is error, empty is not false
            if (!std::get<0>(lastConfirmedForImport) &&
                (!CurrenciesAndNotarizations(tx, currenciesAndNotarizations) ||
                 !currenciesAndNotarizations.size()))
            {
                return state.Error("Invalid outputs with reserve transfer " + rt.ToUniValue().write(1,2));
            }

            if (currenciesAndNotarizations.count(importCurrencyID))
            {
                importCurrencyDef = currenciesAndNotarizations[importCurrencyID].first;
                if (importCurrencyDef.IsValid())
                {
                    importState = currenciesAndNotarizations[importCurrencyID].second.currencyState;
                    systemDestID = importCurrencyDef.systemID;
                    if (systemDestID.IsNull())
                    {
                        return state.Error("Invalid currency with reserve transfer " + rt.ToUniValue().write(1,2));
                    }
                    if (currenciesAndNotarizations.count(systemDestID))
                    {
                        systemDest = currenciesAndNotarizations[systemDestID].first;
                    }
                    for (auto &oneVEID : importCurrencyDef.currencies)
                    {
                        // we can export all but a new system
                        if (oneVEID == systemDestID &&
                            systemDestID != ASSETCHAINS_CHAINID &&
                            systemDest.IsValid() &&
                            systemDest.launchSystemID == ASSETCHAINS_CHAINID &&
                            systemDest.startBlock > height)
                        {
                            continue;
                        }
                        validExportCurrencies.insert(oneVEID);
                    }
                    if (importCurrencyDef.GetID() != systemDestID &&
                        systemDest.IsValid())
                    {
                        for (auto &oneVEID : systemDest.currencies)
                        {
                            validExportCurrencies.insert(oneVEID);
                        }
                    }
                    if (!validExportCurrencies.count(rt.FirstCurrency()))
                    {
                        return state.Error("Invalid currency preconversion in reserve transfer " + rt.ToUniValue().write(1,2));
                    }
                }
            }
        }

        // we may have skipped the above, and even if not, we may not have gotten the import state
        if (!importState.IsValid())
        {
            importState = ConnectedChains.GetCurrencyState(importCurrencyID, height - 1, true);
        }

        if (!(importCurrencyDef.IsValid() && importState.IsValid()))
        {
            if (!haveFullChain)
            {
                return true;
            }
            // the only case this is ok is if we are part of a currency definition and this is to a new currency
            // if that is the case, importCurrencyDef will always be invalid
            if (!importCurrencyDef.IsValid())
            {
                return state.Error("Invalid currency in reserve transfer " + rt.ToUniValue().write(1,2));
            }
            else
            {
                return state.Error("Valid currency state required and not found for import currency of reserve transfer " + rt.ToUniValue().write(1,2));
            }
        }

        if (!systemDest.IsValid())
        {
            systemDestID = importCurrencyDef.SystemOrGatewayID();
            systemDest = systemDestID == importCurrencyID ? importCurrencyDef : ConnectedChains.GetCachedCurrency(systemDestID);
        }

        if (!systemDest.IsValid())
        {
            if (!haveFullChain)
            {
                return true;
            }
            return state.Error("Invalid currency system in reserve transfer " + rt.ToUniValue().write(1,2));
        }

        if (rt.flags & rt.CROSS_SYSTEM)
        {
            if (systemDestID != rt.destSystemID)
            {
                return state.Error("Mismatched destination system in reserve transfer " + rt.ToUniValue().write(1,2));
            }
        }

        // ensure that we have enough fees for the currency definition import
        CAmount adjustedImportFee = 0;

        if (systemDestID != ASSETCHAINS_CHAINID)
        {
            if (haveFullChain)
            {
                if (ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisablePBaaSCrossChainKey()))
                {
                    if (LogAcceptCategory("defi"))
                    {
                        LogPrintf("%s: Cross-chain transfers temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
                    }
                    return false;
                }
                if (systemDest.IsGateway() && ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableGatewayCrossChainKey()))
                {
                    if (LogAcceptCategory("defi"))
                    {
                        LogPrintf("%s: Cross-chain transfers for non-PBaaS gateways temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
                    }
                    return false;
                }
            }

            CPBaaSNotarization lastConfirmedNotarization = currenciesAndNotarizations[systemDestID].second;
            std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> lastConfirmed = lastConfirmedNotarization.IsValid() ?
                    std::tuple<uint32_t, CUTXORef, CPBaaSNotarization>({1, CUTXORef(), lastConfirmedNotarization}) :
                    GetLastConfirmedNotarization(systemDestID, height - 1);
            if (!std::get<0>(lastConfirmed))
            {
                return state.Error("Cannot get notarization data for destination system of transfer: " + rt.ToUniValue().write(1,2));
            }
            auto ourLastRoot = std::get<2>(lastConfirmed).proofRoots.find(ASSETCHAINS_CHAINID);
            if (haveFullChain &&
                !(std::get<2>(lastConfirmed).IsPreLaunch() && !std::get<2>(lastConfirmed).IsLaunchCleared() && rt.IsPreConversion()) &&
                (ourLastRoot == std::get<2>(lastConfirmed).proofRoots.end() ||
                 (height - ourLastRoot->second.rootHeight) >
                    ((CPBaaSNotarization::MAX_NOTARIZATION_DELAY_BEFORE_CROSSCHAIN_PAUSE * 60) / ConnectedChains.ThisChain().blockTime)))
            {
                //printf("Confirmed notarizations for destination system are lagging behind, cannot send: %s\n", rt.ToUniValue().write(1,2).c_str());
                return state.Error("Confirmed notarizations for destination system are lagging behind, cannot send: " + rt.ToUniValue().write(1,2));
            }
            if (systemDest.proofProtocol == systemDest.PROOF_ETHNOTARIZATION)
            {
                adjustedImportFee = std::get<2>(lastConfirmed).currencyState.conversionPrice.size() ?
                    std::get<2>(lastConfirmed).currencyState.conversionPrice[0] :
                    std::get<2>(lastConfirmed).proofRoots[systemDestID].gasPrice;
            }
        }

        CReserveTransactionDescriptor rtxd;
        CCoinbaseCurrencyState dummyState = importState;
        std::vector<CTxOut> vOutputs;
        CCurrencyValueMap importedCurrency, gatewayDepositsIn, spentCurrencyOut;
        CCurrencyValueMap newPreConversionReservesIn = rt.TotalCurrencyOut();
        CCurrencyValueMap feeConversionPrices;

        if (importState.IsPrelaunch())
        {
            if (!haveFullChain)
            {
                return true;
            }
            if (!rt.IsPreConversion())
            {
                if (!haveFullChain)
                {
                    return true;
                }
                return state.Error("Only preconversion transfers are valid during the prelaunch phase of a currency " + rt.ToUniValue().write(1,2));
            }
            if (rt.FeeCurrencyID() != importCurrencyDef.launchSystemID || importCurrencyDef.launchSystemID.IsNull())
            {
                return state.Error("Preconversion transfers must use the native fee currency of the launching system " + rt.ToUniValue().write(1,2));
            }
        }
        else if (haveFullChain &&
                 ConnectedChains.CheckZeroViaOnlyPostLaunch(height) &&
                 !importState.IsLaunchCompleteMarker() &&
                 !ConnectedChains.NotarySystems().count(importState.GetID()))
        {
            if (rt.IsCurrencyExport() ||
                rt.IsConversion() ||
                rt.IsIdentityExport())
            {
                return state.Error("No conversions, currency exports, or identity exports are allowed before currency launch is complete " + rt.ToUniValue().write(1,2));
            }
        }

        if (importCurrencyDef.IsFractional() && importState.IsLaunchConfirmed())
        {
            feeConversionPrices = importState.TargetConversionPrices(systemDestID);
        }
        if (importCurrencyDef.IsFractional() && !(importState.IsLaunchConfirmed() && !importState.IsLaunchCompleteMarker()))
        {
            // normalize prices on the way in to prevent overflows on first pass
            std::vector<int64_t> newReservesVector = newPreConversionReservesIn.AsCurrencyVector(importState.currencies);
            dummyState.reserves = dummyState.AddVectors(dummyState.reserves, newReservesVector);
            importState.conversionPrice = dummyState.PricesInReserve();
        }
        if (importState.currencies.size() != importState.conversionPrice.size())
        {
            importState.conversionPrice = dummyState.PricesInReserve();
        }

        CAmount feeEquivalentInNative = rt.feeCurrencyID == systemDestID ? rt.nFees : 0;

        if (importCurrencyDef.IsFractional())
        {
            auto reserveMap = importState.GetReserveMap();

            // fee currency must be destination,
            // if some fees may be coming from the conversion, calculate them
            if (rt.IsPreConversion() || !feeConversionPrices.valueMap.count(systemDestID) || !feeConversionPrices.valueMap.count(rt.feeCurrencyID))
            {
                // preconversion must have standard fees included
                if (rt.feeCurrencyID == systemDestID || rt.feeCurrencyID == systemDest.launchSystemID)
                {
                    feeEquivalentInNative += rt.nFees;
                }
                else
                {
                    return state.Error("Invalid fee currency in reserve transfer 1: " + rt.ToUniValue().write(1,2));
                }
            }
            else
            {
                // figure out all appropriate fees at current prices
                // first non-conversion fees
                if (!feeEquivalentInNative && rt.feeCurrencyID != systemDestID)
                {
                    if (!feeConversionPrices.valueMap.count(rt.feeCurrencyID))
                    {
                        return state.Error("Invalid fee currency in reserve transfer 2: " + rt.ToUniValue().write(1,2));
                    }
                    feeEquivalentInNative = CCurrencyState::ReserveToNativeRaw(rt.nFees, feeConversionPrices.valueMap[rt.feeCurrencyID]);
                }

                // all we have to do now is determine fees for conversion and add them to the explicit fees
                if (rt.IsConversion())
                {
                    CAmount conversionFeeInCur = CReserveTransactionDescriptor::CalculateConversionFee(rt.FirstValue());

                    uint160 expectedImportID = rt.IsImportToSource() ? rt.FirstCurrency() : rt.destCurrencyID;

                    // double conversion for reserve to reserve
                    if (expectedImportID != importCurrencyID)
                    {
                        return state.Error("Invalid import currency specified " + rt.ToUniValue().write(1,2));
                    }
                    else
                    {
                        if (rt.secondReserveID.IsNull() && rt.IsReserveToReserve() || !rt.secondReserveID.IsNull() && !rt.IsReserveToReserve())
                        {
                            return state.Error("Conversion is reserve to reserve but not specified or vice versa " + rt.ToUniValue().write(1,2));
                        }

                        if (rt.IsReserveToReserve())
                        {
                            if (!importCurrencyDef.GetCurrenciesMap().count(rt.secondReserveID))
                            {
                                return state.Error("Invalid reserve to reserve conversion " + rt.ToUniValue().write(1,2));
                            }
                            conversionFeeInCur <<= 1;
                        }
                    }

                    feeEquivalentInNative += CCurrencyState::ReserveToNativeRaw(conversionFeeInCur,
                                                                                feeConversionPrices.valueMap[rt.FirstCurrency()]);
                }
            }
        }
        else if (rt.IsConversion() && !rt.IsPreConversion())
        {
            return state.Error("Invalid conversion requested through non-fractional currency " + rt.ToUniValue().write(1,2));
        }
        else if (rt.feeCurrencyID != systemDestID)
        {
            if (systemDest.launchSystemID.IsNull() || rt.feeCurrencyID != systemDest.launchSystemID)
            {
                return state.Error("Invalid fee currency in reserve transfer 3: " + rt.ToUniValue().write(1,2));
            }
            else
            {
                feeEquivalentInNative += rt.nFees;
            }
        }

        CDataStream ds(SER_DISK, PROTOCOL_VERSION);

        // only an identity can export itself
        bool importPassThrough = false;

        // if this output to export an identity comes from an import, the check will already have happened
        for (int loop=0; loop < outNum; loop++)
        {
            COptCCParams importP;
            CCrossChainImport cci;
            if (tx.vout[loop].scriptPubKey.IsPayToCryptoCondition(importP) &&
                importP.IsValid() &&
                importP.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                importP.vData.size() &&
                (cci = CCrossChainImport(importP.vData[0])).IsValid() &&
                (loop + cci.numOutputs) >= outNum)
            {
                importPassThrough = true;
                break;
            }
        }

        if (rt.IsCurrencyExport())
        {
            CCurrencyDefinition curToExport, exportDestination;
            if (rt.reserveValues > CCurrencyValueMap())
            {
                return state.Error("Currency exports should not include explicit funds beyond required fees " + rt.ToUniValue().write(1,2));
            }

            // if this is a cross chain export, the first currency must be valid and equal the exported currency
            // otherwise, we only need to ensure that the exported currency can be sent to the target destination
            // its definition will be added next round
            CCurrencyDefinition registeredCurrency = ConnectedChains.GetCachedCurrency(rt.FirstCurrency());

            if (importCurrencyDef.systemID == ASSETCHAINS_CHAINID &&
                rt.HasNextLeg() &&
                rt.destination.gatewayID != ASSETCHAINS_CHAINID)
            {
                {
                    CReserveTransfer dummyTransfer = rt;
                    dummyTransfer.destination = CTransferDestination(CTransferDestination::DEST_REGISTERCURRENCY, ::AsVector(registeredCurrency), rt.destination.gatewayID, rt.destination.gatewayCode, rt.DEFAULT_PER_STEP_FEE);
                    for (int i = 0; i < rt.destination.AuxDestCount(); i++)
                    {
                        dummyTransfer.destination.SetAuxDest(rt.destination.GetAuxDest(i), i);
                    }
                    if (GetSerializeSize(ds, dummyTransfer) > rt.MAX_CURRENCYEXPORT_SIZE)
                    {
                        return state.Error("Reserve transfer exporting currency definition exceeds size limits " + rt.ToUniValue().write(1,2));
                    }
                }

                exportDestination = ConnectedChains.GetCachedCurrency(rt.destination.gatewayID);
                if (!(curToExport = ConnectedChains.GetCachedCurrency(rt.FirstCurrency())).IsValid())
                {
                    return state.Error("Invalid currency export in reserve transfer " + rt.ToUniValue().write(1,2));
                }
                if (!exportDestination.IsValid() ||
                    !exportDestination.IsMultiCurrency() ||
                    exportDestination.SystemOrGatewayID() != rt.destination.gatewayID ||
                    exportDestination.SystemOrGatewayID() == ASSETCHAINS_CHAINID ||
                    IsValidExportCurrency(exportDestination, rt.FirstCurrency(), height))
                {
                    return state.Error("Invalid currency export for next leg in reserve transfer " + rt.ToUniValue().write(1,2));
                }
                if (!systemDest.IsValidTransferDestinationType(rt.destination.TypeNoFlags()))
                {
                    return state.Error("Invalid reserve transfer destination for target system" + rt.ToUniValue().write(1,2));
                }
                if (feeEquivalentInNative < systemDest.GetTransactionTransferFee())
                {
                    return state.Error("Not enough fee for first step of currency import in reserve transfer " + rt.ToUniValue().write(1,2));
                }

                if (importState.IsFractional())
                {
                    feeConversionPrices = importState.TargetConversionPrices(rt.destination.gatewayID);
                    feeEquivalentInNative = CCurrencyState::ReserveToNativeRaw(rt.destination.fees, feeConversionPrices.valueMap[rt.feeCurrencyID]);
                }
                else if (rt.feeCurrencyID != systemDestID &&
                         (rt.feeCurrencyID != systemDest.launchSystemID || systemDest.proofProtocol != systemDest.PROOF_PBAASMMR))
                {
                    feeEquivalentInNative = 0;
                }
            }
            else if (!(rt.flags & rt.CROSS_SYSTEM) ||
                     rt.destination.TypeNoFlags() != rt.destination.DEST_REGISTERCURRENCY ||
                     !(curToExport = CCurrencyDefinition(rt.destination.destination)).IsValid() ||
                     curToExport.GetID() != rt.FirstCurrency())
            {
                return state.Error("Invalid currency export in reserve transfer " + rt.ToUniValue().write(1,2));
            }
            else
            {
                if (::AsVector(registeredCurrency) != rt.destination.destination)
                {
                    return state.Error("Mismatched export and currency registration in reserve transfer " + rt.ToUniValue().write(1,2));
                }

                if (!importPassThrough && (!systemDest.IsMultiCurrency() || IsValidExportCurrency(systemDest, rt.FirstCurrency(), height)))
                {
                    // if destination system is not multicurrency or currency is already a valid export currency, invalid
                    return state.Error("Unnecessary currency definition export in reserve transfer " + rt.ToUniValue().write(1,2));
                }

                if (GetSerializeSize(ds, rt) > rt.MAX_CURRENCYEXPORT_SIZE)
                {
                    return state.Error("Reserve transfer exporting currency definition exceeds size limits " + rt.ToUniValue().write(1,2));
                }

                curToExport = registeredCurrency;
                exportDestination = systemDest;

                if (rt.feeCurrencyID != systemDestID &&
                    (rt.feeCurrencyID != systemDest.launchSystemID || systemDest.proofProtocol != systemDest.PROOF_PBAASMMR))
                {
                    feeEquivalentInNative = 0;
                }
            }

            adjustedImportFee = CCoinbaseCurrencyState::NativeGasToReserveRaw(
                        systemDest.GetCurrencyImportFee(curToExport.ChainOptions() & curToExport.OPTION_NFT_TOKEN),
                        adjustedImportFee);
            if (adjustedImportFee < 0 || feeEquivalentInNative < adjustedImportFee)
            {
                return state.Error("Not enough fee for currency import in reserve transfer " + rt.ToUniValue().write(1,2));
            }

            // ensure that it makes sense for us to export this currency from this system to the other
            if ((rt.HasNextLeg() && systemDest.systemID == ASSETCHAINS_CHAINID &&
                 !CConnectedChains::IsValidCurrencyDefinitionImport(ConnectedChains.ThisChain(), exportDestination, curToExport, height)) ||
                 (systemDest.systemID != ASSETCHAINS_CHAINID &&
                  !CConnectedChains::IsValidCurrencyDefinitionImport(ConnectedChains.ThisChain(), systemDest, curToExport, height)))
            {
                return state.Error("Invalid to export specified currency to destination system " + rt.ToUniValue().write(1,2));
            }
        }
        else
        {
            if (systemDestID != ASSETCHAINS_CHAINID && !validExportCurrencies.size())
            {
                validExportCurrencies = ValidExportCurrencies(systemDest, height);
                if (rt.IsPreConversion() &&
                    !importCurrencyDef.GetCurrenciesMap().count(rt.FirstCurrency()))
                {
                    return state.Error("Invalid currency export in reserve transfer " + rt.ToUniValue().write(1,2));
                }
            }

            if (!validExportCurrencies.count(rt.FirstCurrency()) && !IsValidExportCurrency(systemDest, rt.FirstCurrency(), height))
            {
                // if destination system does not already have the exporting currency or
                // is not multicurrency, invalid
                return state.Error("Invalid currency export in reserve transfer " + rt.ToUniValue().write(1,2));
            }

            if (rt.IsIdentityExport())
            {
                CIdentity idToExport;
                CCurrencyDefinition exportDestination;

                if (!((rt.IsCrossSystem() &&
                       rt.destination.TypeNoFlags() == rt.destination.DEST_FULLID &&
                       (idToExport = CIdentity(rt.destination.destination)).IsValid()) ||
                      (!rt.IsCrossSystem() && rt.destination.TypeNoFlags() == rt.destination.DEST_ID && rt.HasNextLeg())))
                {
                    return state.Error("Invalid identity export in reserve transfer " + rt.ToUniValue().write(1,2));
                }

                CIdentity registeredIdentity = CIdentity::LookupIdentity(GetDestinationID(TransferDestinationToDestination(rt.destination)), height);

                if (!registeredIdentity.IsValid())
                {
                    return state.Error("Invalid identity export in reserve transfer " + rt.ToUniValue().write(1,2));
                }

                // only an identity can export itself
                if (!importPassThrough && ConnectedChains.StrictCheckIDExport(height) && !CheckIdentitySpends(tx, registeredIdentity.GetID(), state, height - 1, true))
                {
                    return state.Error("Only the controller of " + ConnectedChains.GetFriendlyIdentityName(registeredIdentity) + " may export it to another system");
                }

                if (!importPassThrough && idToExport.IsValid())
                {
                    // validate everything relating to name and control
                    if (registeredIdentity.primaryAddresses != idToExport.primaryAddresses ||
                        registeredIdentity.minSigs != idToExport.minSigs ||
                        registeredIdentity.revocationAuthority != idToExport.revocationAuthority ||
                        registeredIdentity.recoveryAuthority != idToExport.recoveryAuthority ||
                        registeredIdentity.privateAddresses != idToExport.privateAddresses ||
                        registeredIdentity.parent != idToExport.parent ||
                        boost::to_lower_copy(registeredIdentity.name) != boost::to_lower_copy(idToExport.name))
                    {
                        return state.Error("Identity being exported in reserve transfer does not match blockchain identity control " + rt.ToUniValue().write(1,2));
                    }
                }

                {
                    CReserveTransfer dummyTransfer = rt;
                    if (rt.destination.TypeNoFlags() != CTransferDestination::DEST_FULLID)
                    {
                        dummyTransfer.destination = CTransferDestination(CTransferDestination::DEST_REGISTERCURRENCY, ::AsVector(registeredIdentity), rt.destination.gatewayID, rt.destination.gatewayCode, rt.DEFAULT_PER_STEP_FEE);
                        for (int i = 0; i < rt.destination.AuxDestCount(); i++)
                        {
                            dummyTransfer.destination.SetAuxDest(rt.destination.GetAuxDest(i), i);
                        }
                    }
                    if (GetSerializeSize(ds, dummyTransfer) > rt.MAX_IDENTITYEXPORT_SIZE)
                    {
                        return state.Error("Reserve transfer exporting identity definition exceeds size limits " + rt.ToUniValue().write(1,2));
                    }
                }

                if (rt.IsCrossSystem() && !(exportDestination = ConnectedChains.GetCachedCurrency(rt.SystemDestination())).IsValid())
                {
                    return state.Error("Invalid export destination in reserve transfer with identity export " + rt.ToUniValue().write(1,2));
                }
                else
                {
                    if (rt.HasNextLeg())
                    {
                        exportDestination = ConnectedChains.GetCachedCurrency(rt.destination.gatewayID);
                        if (!exportDestination.IsValid() ||
                            exportDestination.SystemOrGatewayID() != rt.destination.gatewayID ||
                            exportDestination.SystemOrGatewayID() == ASSETCHAINS_CHAINID)
                        {
                            return state.Error("Invalid destination for next leg in reserve transfer " + rt.ToUniValue().write(1,2));
                        }
                    }
                    if (feeEquivalentInNative < systemDest.GetTransactionTransferFee())
                    {
                        return state.Error("Not enough fee for first step of identity import in reserve transfer " + rt.ToUniValue().write(1,2));
                    }
                    if (importState.IsFractional())
                    {
                        feeConversionPrices = importState.TargetConversionPrices(rt.HasNextLeg() ? rt.destination.gatewayID : systemDestID);
                        feeEquivalentInNative = CCurrencyState::ReserveToNativeRaw(rt.HasNextLeg() ? rt.destination.fees : rt.nFees, feeConversionPrices.valueMap[rt.feeCurrencyID]);
                    }
                    else if (rt.feeCurrencyID != systemDestID &&
                              (rt.feeCurrencyID != systemDest.launchSystemID || systemDest.proofProtocol != systemDest.PROOF_PBAASMMR))
                    {
                        feeEquivalentInNative = 0;
                    }
                    else if (rt.HasNextLeg())
                    {
                        if (rt.feeCurrencyID != rt.destination.gatewayID &&
                              (rt.feeCurrencyID != exportDestination.launchSystemID || exportDestination.proofProtocol != exportDestination.PROOF_PBAASMMR))
                        {
                            return state.Error("Invalid identity export for next leg in reserve transfer " + rt.ToUniValue().write(1,2));
                        }
                    }
                }

                adjustedImportFee = CCoinbaseCurrencyState::NativeGasToReserveRaw(systemDest.IDImportFee(), adjustedImportFee);

                // ensure that we have enough fees for the identity import
                if (adjustedImportFee < 0 || feeEquivalentInNative < adjustedImportFee)
                {
                    return state.Error("Not enough fee for identity import in reserve transfer " + rt.ToUniValue().write(1,2));
                }

                if (!CConnectedChains::IsValidIdentityDefinitionImport(ConnectedChains.ThisChain(), systemDest, registeredIdentity, height) ||
                    (rt.HasNextLeg() &&
                     systemDestID == ASSETCHAINS_CHAINID &&
                     !CConnectedChains::IsValidIdentityDefinitionImport(ConnectedChains.ThisChain(), exportDestination, registeredIdentity, height)))
                {
                    return state.Error("Invalid to export specified identity to destination system " + rt.ToUniValue().write(1,2));
                }
            }
            else
            {
                int destType = rt.destination.TypeNoFlags();
                CTxDestination dest = TransferDestinationToDestination(rt.destination);
                if (destType == rt.destination.DEST_ETH)
                {
                    uint160 ethDest;
                    try
                    {
                        ::FromVector(rt.destination.destination, ethDest);
                    }
                    catch(...)
                    {
                        ethDest = uint160();
                    }
                    if (ethDest.IsNull())
                    {
                        return state.Error("Invalid Ethereum transfer destination");
                    }
                }
                else if (dest.which() != COptCCParams::ADDRTYPE_ID && dest.which() != COptCCParams::ADDRTYPE_PKH && dest.which() != COptCCParams::ADDRTYPE_SH)
                {
                    if (rt.destination.TypeNoFlags() != rt.destination.DEST_RAW)
                    {
                        return state.Error("Invalid transfer destination");
                    }
                    dest = GetCompatibleAuxDestination(rt.destination, (CCurrencyDefinition::EProofProtocol)systemDest.proofProtocol);
                    if (dest.which() != COptCCParams::ADDRTYPE_ID && dest.which() != COptCCParams::ADDRTYPE_PKH && dest.which() != COptCCParams::ADDRTYPE_SH)
                    {
                        return state.Error("Transfer destination requires fallback destination compatible with Verus or Ethereum address formats");
                    }
                }
                else if (GetDestinationID(dest).IsNull())
                {
                    return state.Error("NULL is an invalid transfer destination");
                }

                // ensure that we have enough fees for transfer
                if (systemDestID != ASSETCHAINS_CHAINID && !rt.IsPreConversion())
                {
                    adjustedImportFee = CCoinbaseCurrencyState::NativeGasToReserveRaw(systemDest.GetTransactionImportFee(), adjustedImportFee);
                    if (adjustedImportFee < 0 || feeEquivalentInNative < adjustedImportFee)
                    {
                        return state.Error("Not enough fee for cross chain currency operation in reserve transfer " + rt.ToUniValue().write(1,2));
                    }
                }
                else if (feeEquivalentInNative < systemDest.GetTransactionTransferFee())
                {
                    return state.Error("Not enough fee for same chain currency operation in reserve transfer " + rt.ToUniValue().write(1,2));
                }

                if (GetSerializeSize(ds, rt) > rt.MAX_NORMAL_TRANSFER_SIZE)
                {
                    return state.Error("Reserve transfer exceeds size limits " + rt.ToUniValue().write(1,2));
                }
            }

            if (rt.IsMint() || rt.IsBurnChangeWeight())
            {
                if (importCurrencyDef.proofProtocol != importCurrencyDef.PROOF_CHAINID ||
                    importCurrencyDef.SystemOrGatewayID() != ASSETCHAINS_CHAINID)
                {
                    return state.Error("Minting and/or burning while changing reserve ratios is only allowed in centralized (\"proofprotocol\":2) currencies on their native chain " + rt.ToUniValue().write(1,2));
                }

                if (importCurrencyDef.endBlock > 0 &&
                    importCurrencyDef.endBlock < height)
                {
                    return state.Error("Minting and/or burning while changing reserve ratios was only allowed prior to block " + std::to_string(importCurrencyDef.endBlock + 1));
                }

                // ensure that this mint or burnchangeweight is spent by the currency ID
                if (!CheckIdentitySpends(tx, importCurrencyID, state, height - 1))
                {
                    return state.Error("Minting and/or burning while changing reserve ratios is only allowed by the controller of a centralized currency " + rt.ToUniValue().write(1,2));
                }
            }
        }

        if (!rt.HasNextLeg() && !systemDest.IsValidTransferDestinationType(rt.destination.TypeNoFlags()))
        {
            return state.Error("Invalid reserve transfer destination for target system" + rt.ToUniValue().write(1,2));
        }

        if (rtxd.AddReserveTransferImportOutputs(ConnectedChains.ThisChain(),
                                                 systemDest,
                                                 importCurrencyDef,
                                                 importState,
                                                 std::vector<CReserveTransfer>({rt}),
                                                 height,
                                                 vOutputs,
                                                 importedCurrency,
                                                 gatewayDepositsIn,
                                                 spentCurrencyOut,
                                                 &dummyState))
        {
            return true;
        }
    }
    return state.Error("Invalid reserve transfer " + rt.ToUniValue().write(1,2));
}

CCurrencyValueMap CCrossChainExport::CalculateExportFee(const CCurrencyValueMap &fees, int numIn)
{
    CCurrencyValueMap retVal;
    int maxFeeCalc = numIn;

    if (maxFeeCalc > MAX_FEE_INPUTS)
    {
        maxFeeCalc = MAX_FEE_INPUTS;
    }
    static const arith_uint256 satoshis(100000000);

    arith_uint256 ratio(50000000 + ((25000000 / maxFeeCalc) * (numIn - 1)));

    for (auto &feePair : fees.valueMap)
    {
        retVal.valueMap[feePair.first] = (((arith_uint256(feePair.second) * ratio)) / satoshis).GetLow64();
    }
    return retVal.CanonicalMap();
}

CAmount CCrossChainExport::CalculateExportFeeRaw(CAmount fee, int numIn)
{
    int maxFeeCalc = std::min((int)MAX_FEE_INPUTS, std::max(1, numIn));
    static const arith_uint256 satoshis(100000000);

    arith_uint256 ratio(50000000 + ((25000000 / MAX_FEE_INPUTS) * (maxFeeCalc - 1)));

    return (((arith_uint256(fee) * ratio)) / satoshis).GetLow64();
}

CAmount CCrossChainExport::ExportReward(const CCurrencyDefinition &destSystem, int64_t exportFee)
{
    // by default, the individual exporter gets 1/10 of the export fee, which is sent directly to the exporter
    // on the importing system
    int64_t individualExportFee = ((arith_uint256(exportFee) * 10000000) / SATOSHIDEN).GetLow64();
    // if 1/10th of the transfer fee is less than 2x a standard transfer fee, ensure that the exporter
    // gets a standard transfer fee or whatever is available
    CAmount minFee = destSystem.GetTransactionTransferFee() << 1;
    if (individualExportFee < minFee)
    {
        individualExportFee = exportFee > minFee ? minFee : exportFee;
    }
    return individualExportFee;
}

CCurrencyValueMap CCrossChainExport::CalculateExportFee() const
{
    return CalculateExportFee(totalFees, numInputs);
}

CCurrencyValueMap CCrossChainExport::CalculateImportFee() const
{
    CCurrencyValueMap retVal;

    for (auto &feePair : CalculateExportFee().valueMap)
    {
        CAmount feeAmount = feePair.second;
        auto it = totalFees.valueMap.find(feePair.first);
        retVal.valueMap[feePair.first] = (it != totalFees.valueMap.end() ? it->second : 0) - feeAmount;
    }
    return retVal;
}

bool CEthGateway::ValidateDestination(const std::string &destination) const
{
    // just returns true if it looks like a non-NULL ETH address
    return (destination.substr(0,2) == "0x" &&
            destination.length() == 42 &&
            IsHex(destination.substr(2,40)) &&
            !uint160(ParseHex(destination.substr(2,64))).IsNull());
}

CTransferDestination CEthGateway::ToTransferDestination(const std::string &destination) const
{
    // just returns true if it looks like a non-NULL ETH address
    uint160 retVal;
    if (destination.substr(0,2) == "0x" &&
            destination.length() == 42 &&
            IsHex(destination.substr(2,40)) &&
            !(retVal = uint160(ParseHex(destination.substr(2,64)))).IsNull())
    {
        return CTransferDestination(CTransferDestination::FLAG_DEST_GATEWAY + CTransferDestination::DEST_RAW,
                                    std::vector<unsigned char>(retVal.begin(), retVal.end()));
    }
    return CTransferDestination();
}

// hard coded ETH gateway currency, "veth" for Verus chain. should be updated to work with PBaaS chains
std::set<uint160> CEthGateway::FeeCurrencies() const
{
    std::set<uint160> retVal;
    retVal.insert(CCrossChainRPCData::GetID("veth@"));
    return retVal;
}

uint160 CEthGateway::GatewayID() const
{
    return CCrossChainRPCData::GetID("veth@");
}

bool CConnectedChains::RemoveMergedBlock(uint160 chainID)
{
    bool retval = false;
    LOCK(cs_mergemining);

    //printf("RemoveMergedBlock ID: %s\n", chainID.GetHex().c_str());

    auto chainIt = mergeMinedChains.find(chainID);
    if (chainIt != mergeMinedChains.end())
    {
        arith_uint256 target;
        target.SetCompact(chainIt->second.block.nBits);
        std::multimap<arith_uint256, CPBaaSMergeMinedChainData *>::iterator removeIt;
        std::multimap<arith_uint256, CPBaaSMergeMinedChainData *>::iterator nextIt = mergeMinedTargets.begin();
        for (removeIt = nextIt; removeIt != mergeMinedTargets.end(); removeIt = nextIt)
        {
            nextIt++;
            // make sure we don't just match by target
            if (removeIt->second->GetID() == chainID)
            {
                mergeMinedTargets.erase(removeIt);
            }
        }
        mergeMinedChains.erase(chainID);
        dirty = retval = true;

        // if we get to 0, give the thread a kick to stop waiting for mining
        //if (!mergeMinedChains.size())
        //{
        //    sem_submitthread.post();
        //}
    }
    return retval;
}

// remove merge mined chains added and not updated since a specific time
void CConnectedChains::PruneOldChains(uint32_t pruneBefore)
{
    vector<uint160> toRemove;

    LOCK(cs_mergemining);
    for (auto blkData : mergeMinedChains)
    {
        if (blkData.second.block.nTime < pruneBefore)
        {
            toRemove.push_back(blkData.first);
        }
    }

    for (auto id : toRemove)
    {
        //printf("Pruning chainID: %s\n", id.GetHex().c_str());
        RemoveMergedBlock(id);
    }
}


// adds or updates merge mined blocks
// returns false if failed to add
bool CConnectedChains::AddMergedBlock(CPBaaSMergeMinedChainData &blkData)
{
    // determine if we should replace one or add to the merge mine vector
    {
        LOCK(cs_mergemining);

        arith_uint256 target;
        uint160 cID = blkData.GetID();
        auto it = mergeMinedChains.find(cID);
        if (it != mergeMinedChains.end())
        {
            RemoveMergedBlock(cID);             // remove it if already there
        }
        target.SetCompact(blkData.block.nBits);

        mergeMinedChains.insert(make_pair(cID, blkData));
        mergeMinedTargets.insert(make_pair(target, &(mergeMinedChains[cID])));
        dirty = true;
        dirtygbt = true;
        nextBlockTimeUpdateRequired = true;
    }

    // Notify external listeners about a change via broadcasting new, possibly duplicate tip
    {
        CBlockIndex *pIndexNewTip = chainActive.LastTip();
        if (pIndexNewTip)
        {
            GetMainSignals().UpdatedBlockTip(pIndexNewTip);
            uiInterface.NotifyBlockTip(pIndexNewTip->GetBlockHash());
        }
    }

    // let submission thread spin
    sem_submitthread.post();

    return true;
}

bool CConnectedChains::GetLastBlock(CBlock &block, uint32_t height)
{
    LOCK(cs_mergemining);
    if (lastBlockHeight == height && block.nTime == ConnectedChains.GetNextBlockTime(chainActive.LastTip()))
    {
        block = lastBlock;
        return true;
    }
    return false;
}

void CConnectedChains::SetLastBlock(CBlock &block, uint32_t height)
{
    LOCK(cs_mergemining);
    if (lastBlock.GetHash() != block.GetHash())
    {
        lastBlock = block;
        lastBlockHeight = height;
    }
}

bool CInputDescriptor::operator<(const CInputDescriptor &op) const
{
    arith_uint256 left = UintToArith256(txIn.prevout.hash);
    arith_uint256 right = UintToArith256(op.txIn.prevout.hash);
    return left < right ? true : left > right ? false : txIn.prevout.n < op.txIn.prevout.n ? true : false;
}


bool CConnectedChains::GetChainInfo(uint160 chainID, CRPCChainData &rpcChainData)
{
    {
        LOCK(cs_mergemining);
        auto chainIt = mergeMinedChains.find(chainID);
        if (chainIt != mergeMinedChains.end())
        {
            rpcChainData = (CRPCChainData)chainIt->second;
            return true;
        }
        return false;
    }
}

// this returns a pointer to the data without copy and assumes the lock is held
CPBaaSMergeMinedChainData *CConnectedChains::GetChainInfo(uint160 chainID)
{
    {
        auto chainIt = mergeMinedChains.find(chainID);
        if (chainIt != mergeMinedChains.end())
        {
            return &chainIt->second;
        }
        return NULL;
    }
}

void CConnectedChains::QueueNewBlockHeader(CBlockHeader &bh)
{
    LogPrint("mining", "QueueNewBlockHeader %s\n", bh.GetHash().GetHex().c_str());
    {
        LOCK(cs_mergemining);

        qualifiedHeaders[UintToArith256(bh.GetHash())] = bh;

    }
    sem_submitthread.post();
}

void CConnectedChains::SetRevokeID(const CIdentityID &idID)
{
    LogPrint("notarization", "SetRevokeID %s\n", EncodeDestination(idID).c_str());
    {
        LOCK(cs_mergemining);

        idsToRevoke.insert(idID);

    }
}

CIdentityID CConnectedChains::NextRevokeID()
{
    LOCK(cs_mergemining);
    CIdentityID retVal;
    if (idsToRevoke.begin() != idsToRevoke.end())
    {
        retVal = *idsToRevoke.begin();
        idsToRevoke.erase(idsToRevoke.begin());
    }
    return retVal;
}

void CConnectedChains::CheckImports()
{
    sem_submitthread.post();
}

uint32_t CConnectedChains::SetNextBlockTime(uint32_t NextBlockTime)
{
    LOCK(cs_mergemining);
    nextBlockTime = NextBlockTime;
    return NextBlockTime;
}

uint32_t CConnectedChains::GetNextBlockTime(const CBlockIndex *pindexPrev)
{
    LOCK(cs_mergemining);
    static uint32_t height = 0;
    uint32_t nextTimeCandidate = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());
    if (height != pindexPrev->GetHeight())
    {
        height = pindexPrev->GetHeight();
        nextBlockTime = nextTimeCandidate;
    }

    // if sync time is 45 seconds behind or more, use calculated time
    if (nextBlockTime < (nextTimeCandidate - 45))
    {
        nextBlockTime = nextTimeCandidate;
        return nextTimeCandidate;
    }
    else
    {
        return nextBlockTime;
    }
}

// get the latest block header and submit one block at a time, returning after there are no more
// matching blocks to be found
vector<pair<string, UniValue>> CConnectedChains::SubmitQualifiedBlocks()
{
    std::set<uint160> inHeader;
    bool submissionFound;
    CPBaaSMergeMinedChainData chainData;
    vector<pair<string, UniValue>>  results;

    CBlockHeader bh;
    arith_uint256 lastHash;
    CPBaaSBlockHeader pbh;

    do
    {
        submissionFound = false;
        {
            LOCK(cs_mergemining);
            // attempt to submit with the lowest hash answers first to increase the likelihood of submitting
            // common, merge mined headers for notarization, drop out on any submission
            for (auto headerIt = qualifiedHeaders.begin(); !submissionFound && headerIt != qualifiedHeaders.end(); headerIt = qualifiedHeaders.begin())
            {
                // add the PBaaS chain ids from this header to a set for search
                for (uint32_t i = 0; headerIt->second.GetPBaaSHeader(pbh, i); i++)
                {
                    inHeader.insert(pbh.chainID);
                }

                uint160 chainID;
                // now look through all targets that are equal to or above the hash of this header
                for (auto chainIt = mergeMinedTargets.lower_bound(headerIt->first); !submissionFound && chainIt != mergeMinedTargets.end(); chainIt++)
                {
                    chainID = chainIt->second->GetID();
                    if (inHeader.count(chainID))
                    {
                        // first, check that the winning header matches the block that is there
                        CPBaaSPreHeader preHeader(chainIt->second->block);
                        preHeader.SetBlockData(headerIt->second);

                        // check if the block header matches the block's specific data, only then can we create a submission from this block
                        if (headerIt->second.CheckNonCanonicalData(chainID))
                        {
                            // save block as is, remove the block from merged headers, replace header, and submit
                            chainData = *chainIt->second;

                            *(CBlockHeader *)&chainData.block = headerIt->second;

                            submissionFound = true;
                        }
                        //else // not an error condition. code is here for debugging
                        //{
                        //    printf("Mismatch in non-canonical data for chain %s\n", chainIt->second->chainDefinition.name.c_str());
                        //}
                    }
                    //else // not an error condition. code is here for debugging
                    //{
                    //    printf("Not found in header %s\n", chainIt->second->chainDefinition.name.c_str());
                    //}
                }

                // if this header matched no block, discard and move to the next, otherwise, we'll drop through
                if (submissionFound)
                {
                    // once it is going to be submitted, remove block from this chain until a new one is added again
                    RemoveMergedBlock(chainID);
                    break;
                }
                else
                {
                    qualifiedHeaders.erase(headerIt);
                }
            }
        }
        if (submissionFound)
        {
            // submit one block and loop again. this approach allows multiple threads
            // to collectively empty the submission queue, mitigating the impact of
            // any one stalled daemon
            UniValue submitParams(UniValue::VARR);
            submitParams.push_back(EncodeHexBlk(chainData.block));
            UniValue reply, result, error;
            try
            {
                reply = RPCCall("submitblock", submitParams, chainData.rpcUserPass, chainData.rpcPort, chainData.rpcHost);
                result = find_value(reply, "result");
                error = find_value(result, "error");
            }
            catch (exception e)
            {
                result = UniValue(e.what());
            }
            results.push_back(make_pair(chainData.chainDefinition.name, result));
            if (result.isStr() || !error.isNull())
            {
                printf("Error submitting block to %s chain: %s\n", chainData.chainDefinition.name.c_str(), result.isStr() ? result.get_str().c_str() : error.get_str().c_str());
            }
            else
            {
                printf("Successfully submitted block to %s chain\n", chainData.chainDefinition.name.c_str());
            }
        }
    } while (submissionFound);

    return results;
}

// add all merge mined chain PBaaS headers into the blockheader and return the easiest nBits target in the header
uint32_t CConnectedChains::CombineBlocks(CBlockHeader &bh)
{
    vector<uint160> inHeader;
    vector<UniValue> toCombine;
    arith_uint256 blkHash = UintToArith256(bh.GetHash());
    arith_uint256 target(0);
    target.SetCompact(bh.nBits);

    CPBaaSBlockHeader pbh;

    {
        LOCK(cs_mergemining);

        CPBaaSSolutionDescriptor descr = CVerusSolutionVector::solutionTools.GetDescriptor(bh.nSolution);

        for (uint32_t i = 0; i < descr.numPBaaSHeaders; i++)
        {
            if (bh.GetPBaaSHeader(pbh, i))
            {
                inHeader.push_back(pbh.chainID);
            }
        }

        // loop through the existing PBaaS chain ids in the header
        // remove any that are not either this Chain ID or in our local collection and then add all that are present
        for (uint32_t i = 0; i < inHeader.size(); i++)
        {
            auto it = mergeMinedChains.find(inHeader[i]);
            if (inHeader[i] != ASSETCHAINS_CHAINID && (it == mergeMinedChains.end()))
            {
                bh.DeletePBaaSHeader(i);
            }
        }

        for (auto chain : mergeMinedChains)
        {
            // get the native PBaaS header for each chain and put it into the
            // header we are given
            // it must have itself in as a PBaaS header
            uint160 cid = chain.second.GetID();
            if (chain.second.block.GetPBaaSHeader(pbh, cid) != -1)
            {
                if (!bh.AddUpdatePBaaSHeader(pbh))
                {
                    LogPrintf("Failure to add PBaaS block header for %s chain\n", chain.second.chainDefinition.name.c_str());
                    break;
                }
                else
                {
                    arith_uint256 t;
                    t.SetCompact(chain.second.block.nBits);
                    if (t > target)
                    {
                        target = t;
                    }
                }
            }
            else
            {
                LogPrintf("Merge mined block for %s does not contain PBaaS information\n", chain.second.chainDefinition.name.c_str());
            }
        }
        dirty = false;
    }

    saveBits = target.GetCompact();

    return saveBits;
}

bool CConnectedChains::IsVerusPBaaSAvailable()
{
    uint160 parent = VERUS_CHAINID;
    return IsNotaryAvailable() &&
           ((_IsVerusActive() && FirstNotaryChain().chainDefinition.GetID() == CIdentity::GetID("veth", parent)) ||
            FirstNotaryChain().chainDefinition.GetID() == VERUS_CHAINID);
}

int atoicatch(const std::string &istr)
{
    try
    {
        return atoi(istr);
    }
    catch(const std::exception& e)
    {
        return 0;
    }
}

uint32_t CConnectedChains::ParseVersion(const std::string &versionStr) const
{
    std::vector<std::string> versionNums;
    boost::split(versionNums, versionStr, boost::is_any_of(".-"));
    uint32_t currentVersion = 0;
    for (int i = 0; i < 4; i++)
    {
        currentVersion <<= 8;
        currentVersion = (currentVersion & 0xffffff00) | ((versionNums.size() > i ? atoicatch(versionNums[i]) : 0) & 0x000000ff);
    }
    return currentVersion;
}

uint32_t CConnectedChains::GetVerusVersion() const
{
    return ParseVersion(VERUS_VERSION);
}

extern string PBAAS_HOST, PBAAS_USERPASS;
extern int32_t PBAAS_PORT;
bool CConnectedChains::CheckVerusPBaaSAvailable(UniValue &chainInfoUni, UniValue &chainDefUni)
{
    if (chainInfoUni.isObject() && chainDefUni.isObject())
    {
        std::string versionStr = uni_get_str(find_value(chainInfoUni, "VRSCversion"));
        if ((((GetVerusVersion() & 0xffff0000) == (ParseVersion(versionStr) & 0xffff0000)) &&
             uni_get_str(find_value(chainInfoUni, "chainid")) == EncodeDestination(CIdentityID(ConnectedChains.FirstNotaryChain().GetID()))))
        {
            LOCK(cs_mergemining);
            CCurrencyDefinition chainDef(chainDefUni);
            if (chainDef.IsValid())
            {
                if (notarySystems.count(chainDef.GetID()))
                {
                    notarySystems[chainDef.GetID()].height = uni_get_int64(find_value(chainInfoUni, "blocks"));
                    notarySystems[chainDef.GetID()].notaryChain = CRPCChainData(chainDef, PBAAS_HOST, PBAAS_PORT, PBAAS_USERPASS);
                    notarySystems[chainDef.GetID()].notaryChain.SetLastConnection(GetTime());
                }
            }
        }
    }
    return IsVerusPBaaSAvailable();
}

uint32_t CConnectedChains::NotaryChainHeight()
{
    LOCK(cs_mergemining);
    if (!notarySystems.size())
    {
        return 0;
    }
    return notarySystems.begin()->second.height;
}

CProofRoot CConnectedChains::ConfirmedNotaryChainRoot()
{
    CProofRoot invalidRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);

    LOCK(cs_mergemining);
    if (!notarySystems.size())
    {
        return invalidRoot;
    }
    uint160 notaryChainID = notarySystems.begin()->second.notaryChain.GetID();
    return notarySystems.begin()->second.lastConfirmedNotarization.proofRoots.count(notaryChainID) ?
                notarySystems.begin()->second.lastConfirmedNotarization.proofRoots[notaryChainID] :
                invalidRoot;
}

CProofRoot CConnectedChains::FinalizedChainRoot()
{
    CProofRoot invalidRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);

    LOCK(cs_mergemining);
    if (!notarySystems.size())
    {
        return invalidRoot;
    }
    uint160 notaryChainID = notarySystems.begin()->second.notaryChain.GetID();
    return notarySystems.begin()->second.lastConfirmedNotarization.proofRoots.count(ASSETCHAINS_CHAINID) ?
                notarySystems.begin()->second.lastConfirmedNotarization.proofRoots[ASSETCHAINS_CHAINID] :
                invalidRoot;
}

bool CConnectedChains::CheckVerusPBaaSAvailable()
{
    if (FirstNotaryChain().IsValid())
    {
        // if this is a PBaaS chain, poll for presence of Verus / root chain and current Verus block and version number
        // tolerate only 15 second timeout
        UniValue chainInfo, chainDef;
        try
        {
            UniValue params(UniValue::VARR);
            chainInfo = find_value(RPCCallRoot("getinfo", params), "result");
            if (!chainInfo.isNull())
            {
                params.push_back(EncodeDestination(CIdentityID(FirstNotaryChain().chainDefinition.GetID())));
                chainDef = FirstNotaryChain().chainDefinition.launchSystemID == ASSETCHAINS_CHAINID ?
                            FirstNotaryChain().chainDefinition.ToUniValue() :
                            find_value(RPCCallRoot("getcurrency", params), "result");

                if (!chainDef.isNull() && CheckVerusPBaaSAvailable(chainInfo, chainDef))
                {
                    // if we're merge mining, try to use notary time
                    if (!IsVerusActive())
                    {
                        SetNextBlockTime(uni_get_int64(find_value(chainInfo, "nextblocktime")));
                    }
                    if (GetBoolArg("-miningdistributionpassthrough", false))
                    {
                        params = UniValue(UniValue::VARR);
                        UniValue miningDistributionUni = find_value(RPCCallRoot("getminingdistribution", params), "result");
                        if (miningDistributionUni.isObject() && miningDistributionUni.size())
                        {
                            mapArgs["-miningdistribution"] = miningDistributionUni.write();
                        }
                    }

                    // if we have not passed block 1 yet, store the best known update of our current state
                    if ((!chainActive.LastTip() || !chainActive.LastTip()->GetHeight()))
                    {
                        bool success = false;
                        params = UniValue(UniValue::VARR);
                        params.push_back(EncodeDestination(CIdentityID(thisChain.GetID())));
                        chainDef = find_value(RPCCallRoot("getcurrency", params), "result");
                        if (!chainDef.isNull())
                        {
                            CCoinbaseCurrencyState checkState(find_value(chainDef, "lastconfirmedcurrencystate"));
                            CCurrencyDefinition currencyDef(chainDef);
                            if (currencyDef.IsValid() && checkState.IsValid() && (checkState.IsLaunchConfirmed()))
                            {
                                thisChain = currencyDef;
                                if (NotaryChainHeight() >= thisChain.startBlock)
                                {
                                    readyToStart = true;    // this only gates mining of block one, to be sure we have the latest definition
                                }
                                success = true;
                            }
                        }
                        return success;
                    }
                    return true;
                }
            }
        } catch (exception e)
        {
            LogPrint("crosschain", "%s: Error communicating with %s\n", __func__, FirstNotaryChain().chainDefinition.name.c_str());
        }
    }
    return false;
}

bool CConnectedChains::IsNotaryAvailable(bool callToCheck)
{
    if (!callToCheck)
    {
        // if we aren't checking, we consider unavailable no contact in the last two minutes
        return FirstNotaryChain().IsValid() && (GetTime() - FirstNotaryChain().LastConnectionTime() < (120));
    }
    return !(FirstNotaryChain().rpcHost.empty() || FirstNotaryChain().rpcPort == 0 || FirstNotaryChain().rpcUserPass.empty()) &&
           CheckVerusPBaaSAvailable();
}

CUpgradeDescriptor::CUpgradeDescriptor(const UniValue &uni) :
    version(uni_get_int(find_value(uni, "version"), VERSION_CURRENT)),
    upgradeID(ParseVDXFKey(uni_get_str(find_value(uni, "upgradeid")))),
    minDaemonVersion(ConnectedChains.ParseVersion(uni_get_str(find_value(uni, "minimumdaemonversion")))),
    upgradeBlockHeight(uni_get_int64(find_value(uni, "activationheight"))),
    upgradeTargetTime(uni_get_int64(find_value(uni, "activationtargettime")))
{}

UniValue CUpgradeDescriptor::ToUniValue() const
{
    UniValue uni(UniValue::VOBJ);
    uni.pushKV("version", (int64_t)version);
    uni.pushKV("upgradeid", EncodeDestination(CIdentityID(upgradeID)));
    uni.pushKV("minimumdaemonversion", (int64_t)minDaemonVersion);
    uint8_t minorVer = ((minDaemonVersion >> 8) & 0xff);
    uint8_t subMinorVer = (minDaemonVersion & 0xff);
    uni.pushKV("minimumdaemonversionstr", std::to_string((minDaemonVersion >> 24) & 0xff) +
                                          std::string(".") +
                                          std::to_string((minDaemonVersion >> 16) & 0xff) +
                                          ((minorVer || subMinorVer) ? std::string(".") + std::to_string(minorVer) : std::string()) +
                                          (subMinorVer ? std::string("-") + std::to_string(subMinorVer) : std::string()));
    uni.pushKV("activationheight", (int64_t)upgradeBlockHeight);
    uni.pushKV("activationtargettime", (int64_t)upgradeTargetTime);
    return uni;
}

std::string VersionString(uint32_t version)
{
    return ("v" + std::to_string(version >> 24) + "." + std::to_string((version >> 16) & 0xff) + "." + std::to_string((version >> 8) & 0xff) + ((version & 0xff) ? "-" + std::to_string(version & 0xff) : ""));
}

void CConnectedChains::CheckOracleUpgrades()
{
    uint32_t height = chainActive.LastTip() && chainActive.Height() ? chainActive.Height() : 0;

    CIdentityID oracleToUse = (!PBAAS_TESTMODE && IsVerusActive() && height < 2620500) ?
                                    CIdentityID(ASSETCHAINS_CHAINID) :
                                    PBAAS_NOTIFICATION_ORACLE;

    // check for a specific oracle
    if (oracleToUse.IsNull())
    {
        LogPrintf("%s: No notification oracle defined - cannot check for upgrades", __func__);
        return;
    }

    ConnectedChains.activeUpgradesByKey.clear();

    // only check on mainnet after last known clear point
    uint32_t startHeight = 0;
    if (IsVerusMainnetActive() && height >= PBAAS_LASTKNOWNCLEARORACLE_HEIGHT)
    {
        startHeight = PBAAS_LASTKNOWNCLEARORACLE_HEIGHT;
    }

    std::vector<std::tuple<std::vector<unsigned char>, uint256, uint32_t, CUTXORef, CPartialTransactionProof>> upgradeData;
    if (CConstVerusSolutionVector::GetVersionByHeight(chainActive.Height()) >= CActivationHeight::ACTIVATE_PBAAS)
    {
        upgradeData = CIdentity::GetIdentityContentByKey(oracleToUse,
                                                         UpgradeDataKey(ASSETCHAINS_CHAINID),
                                                         startHeight,
                                                         0,
                                                         false,
                                                         false,
                                                         0,
                                                         false,
                                                         ConnectedChains.CheckZeroViaOnlyPostLaunch(chainActive.Height()));
    }
    uint32_t foundIDAt;
    CTxIn txInDesc;
    CIdentity oracleID = CIdentity::LookupIdentity(oracleToUse, chainActive.Height(), &foundIDAt, &txInDesc);

    if (LogAcceptCategory("oracles"))
    {
        LogPrintf("%s: Using %s as oracle\n", __func__, ConnectedChains.GetFriendlyIdentityName(oracleID).c_str());
        LogPrintf("%s: oracle ID (%s) found at height %u in transaction %s output: %u\n",
                  __func__,
                  ConnectedChains.GetFriendlyIdentityName(oracleID).c_str(),
                  foundIDAt,
                  txInDesc.prevout.hash.GetHex().c_str(),
                  txInDesc.prevout.n);
        LogPrintf("UpgradeDataKey: %s\n", EncodeDestination(CIdentityID(UpgradeDataKey(ASSETCHAINS_CHAINID))));
    }

    if (oracleID.contentMap.count(OptionalPBaaSUpgradeKey()))
    {
        upgradeData.resize(upgradeData.size() + 1);
        std::get<0>(*upgradeData.rbegin()) = ParseHex(oracleID.contentMap[OptionalPBaaSUpgradeKey()].GetHex());
    }

    CUpgradeDescriptor oneUpgrade;

    // compatible with vARRR update notarization modulo reset, even if no
    // or different oracle used
    if (IsVerusMainnetActive())
    {
        if (height >= vARRRUpdateHeight(false) && (height - vARRRUpdateHeight(false)) < 800)
        {
            activeUpgradesByKey[ResetNotarizationModuloKey()] = CUpgradeDescriptor(ResetNotarizationModuloKey(), 16908802, 3000000, 0);
        }
        else if (height >= PBAAS_CROSS_CHAIN_PROOF_FIX_HEIGHT && (height - PBAAS_CROSS_CHAIN_PROOF_FIX_HEIGHT) < 800)
        {
            activeUpgradesByKey[ResetNotarizationModuloKey()] = CUpgradeDescriptor(ResetNotarizationModuloKey(), 16909061, PBAAS_CROSS_CHAIN_PROOF_FIX_HEIGHT, 0);
        }
        else if (height >= PBAAS_BLOCK_ONE_ID_UPGRADE_FIX_HEIGHT && (height - PBAAS_BLOCK_ONE_ID_UPGRADE_FIX_HEIGHT) < 800)
        {
            activeUpgradesByKey[ResetNotarizationModuloKey()] = CUpgradeDescriptor(ResetNotarizationModuloKey(), 16909062, PBAAS_BLOCK_ONE_ID_UPGRADE_FIX_HEIGHT, 0);
        }
    }

    if (upgradeData.size())
    {
        for (auto &oneUpgrade : upgradeData)
        {
            CUpgradeDescriptor upgrade(std::get<0>(oneUpgrade));

            if (upgrade.IsValid())
            {
                LOCK(ConnectedChains.cs_mergemining);
                activeUpgradesByKey[upgrade.upgradeID] = upgrade;
            }
        }
    }

    std::map<uint160, CUpgradeDescriptor>::iterator disableDeFiIt = activeUpgradesByKey.find(DisableDeFiKey());
    std::map<uint160, CUpgradeDescriptor>::iterator disablePBaaSCrossChainIt = activeUpgradesByKey.find(DisablePBaaSCrossChainKey());
    std::map<uint160, CUpgradeDescriptor>::iterator disableGatewayCrossChainIt = activeUpgradesByKey.find(DisableGatewayCrossChainKey());
    std::map<uint160, CUpgradeDescriptor>::iterator magicNumberFixIt = IsVerusActive() ? activeUpgradesByKey.find(MagicNumberFixKey()) : activeUpgradesByKey.end();
    std::map<uint160, CUpgradeDescriptor>::iterator enableOptimizedETHProofIt = IsVerusActive() ? activeUpgradesByKey.find(EnableOptimizedETHProofKey()) : activeUpgradesByKey.end();
    std::map<uint160, CUpgradeDescriptor>::iterator stoppingIt = activeUpgradesByKey.end();

    std::string gracefulStop;

    if (magicNumberFixIt != activeUpgradesByKey.end())
    {
        if (magicNumberFixIt->second.minDaemonVersion > GetVerusVersion())
        {
            stoppingIt = magicNumberFixIt;
            gracefulStop = "PROTOCOL CHANGE FOR PBAAS CHAIN VERSION UPDATE";
        }
    }

    if (enableOptimizedETHProofIt != activeUpgradesByKey.end())
    {
        PBAAS_OPTIMIZE_ETH_HEIGHT = enableOptimizedETHProofIt->second.upgradeBlockHeight;
    }

    if (disableDeFiIt != activeUpgradesByKey.end() ||
        disablePBaaSCrossChainIt != activeUpgradesByKey.end() ||
        disableGatewayCrossChainIt != activeUpgradesByKey.end())
    {
        bool pauseDeFi = false;
        bool pausePBaaS = false;

        // disabling all DeFi, both cross-chain protocols, or just gateways
        if (disableDeFiIt != activeUpgradesByKey.end())
        {
            // pause DeFi
            pauseDeFi = true;
            CUpgradeDescriptor waterfallDescriptor(disableDeFiIt->second);
            waterfallDescriptor.upgradeID = DisablePBaaSCrossChainKey();
            activeUpgradesByKey[DisablePBaaSCrossChainKey()] = waterfallDescriptor;
            disablePBaaSCrossChainIt = disableDeFiIt;
        }
        if (disablePBaaSCrossChainIt != activeUpgradesByKey.end())
        {
            // pause cross chain PBaaS
            pausePBaaS = true;
            CUpgradeDescriptor waterfallDescriptor(disablePBaaSCrossChainIt->second);
            waterfallDescriptor.upgradeID = DisableGatewayCrossChainKey();
            activeUpgradesByKey[DisableGatewayCrossChainKey()] = waterfallDescriptor;
            disableGatewayCrossChainIt = disablePBaaSCrossChainIt;
        }
        if (disableGatewayCrossChainIt->second.minDaemonVersion > GetVerusVersion() &&
            (stoppingIt == activeUpgradesByKey.end() ||
             disableGatewayCrossChainIt->second.minDaemonVersion > stoppingIt->second.minDaemonVersion))
        {
            stoppingIt = disableGatewayCrossChainIt;
            gracefulStop = pauseDeFi ? "CRITICAL TEMPORARY PAUSE ALL CROSS CHAIN AND DEFI FUNCTIONS ISSUED FROM ORACLE" :
                           (pausePBaaS ? "CRITICAL TEMPORARY PAUSE ALL CROSS CHAIN FUNCTIONS ISSUED FROM ORACLE" :
                                         "CRITICAL TEMPORARY PAUSE ALL NON-PBAAS CROSS CHAIN FUNCTIONS ISSUED FROM ORACLE");
        }
    }

    if (stoppingIt != activeUpgradesByKey.end())
    {
        printf("%s: ERROR - THE NETWORK IS ACTIVATING \"%s\" - UPGRADE TO VERSION %s TO SYNC PAST BLOCK %u ON THE %s CHAIN\n", __func__, gracefulStop.c_str(), VersionString(stoppingIt->second.minDaemonVersion).c_str(), stoppingIt->second.upgradeBlockHeight - 1, ConnectedChains.GetFriendlyCurrencyName(ASSETCHAINS_CHAINID).c_str());
        if (KOMODO_STOPAT == 0 || KOMODO_STOPAT > (stoppingIt->second.upgradeBlockHeight - 1))
        {
            LogPrintf("%s: ERROR - THE NETWORK IS ACTIVATING \"%s\" - UPGRADE TO VERSION %s TO SYNC PAST BLOCK %u ON THE %s CHAIN\n", __func__, gracefulStop.c_str(), VersionString(stoppingIt->second.minDaemonVersion).c_str(), stoppingIt->second.upgradeBlockHeight - 1, ConnectedChains.GetFriendlyCurrencyName(ASSETCHAINS_CHAINID).c_str());
            KOMODO_STOPAT = stoppingIt->second.upgradeBlockHeight - 1;
        }
    }
}

bool CConnectedChains::IsUpgradeActive(const uint160 &upgradeID, uint32_t blockHeight, uint32_t blockTime) const
{
    auto it = activeUpgradesByKey.find(upgradeID);
    if (it != activeUpgradesByKey.end())
    {
        if (it->second.minDaemonVersion > GetVerusVersion())
        {
            printf("%s: ERROR - THE NETWORK IS PREPARING FOR PUBLIC BLOCKCHAINS AS A SERVICE PROTOCOL (PBAAS) 1.0 - UPGRADE TO VERSION %s OR GREATER TO SYNC PAST BLOCK %u ON THE VERUS NETWORK\n", __func__, VersionString(it->second.minDaemonVersion).c_str(), it->second.upgradeBlockHeight - 1);
            if (KOMODO_STOPAT == 0 || KOMODO_STOPAT > (it->second.upgradeBlockHeight - 1))
            {
                LogPrintf("%s: ERROR - THE NETWORK IS PREPARING FOR PUBLIC BLOCKCHAINS AS A SERVICE PROTOCOL (PBAAS) 1.0 - UPGRADE TO VERSION %s OR GREATER TO SYNC PAST BLOCK %u ON THE VERUS NETWORK\n", __func__, VersionString(it->second.minDaemonVersion).c_str(), it->second.upgradeBlockHeight - 1);
                KOMODO_STOPAT = it->second.upgradeBlockHeight - 1;
            }
        }
        return ((it->second.upgradeBlockHeight && blockHeight >= it->second.upgradeBlockHeight) ||
                (it->second.upgradeTargetTime && blockTime >= it->second.upgradeTargetTime));
    }
    return false;
}

uint32_t CConnectedChains::GetZeroViaHeight(bool getVerusHeight) const
{
    return (getVerusHeight || IsVerusActive()) && !PBAAS_TESTMODE ? 2578653 : 0;
}

uint32_t CConnectedChains::GetOptimizedETHProofHeight(bool getVerusHeight) const
{
    return (getVerusHeight || _IsVerusActive() && !PBAAS_TESTMODE) ? PBAAS_OPTIMIZE_ETH_HEIGHT : 0;
}

bool CConnectedChains::ShouldOptimizeETHProof() const
{
    return chainActive.Height() >= GetOptimizedETHProofHeight();
}

bool CConnectedChains::CheckZeroViaOnlyPostLaunch(uint32_t height) const
{
    return height > GetZeroViaHeight(false);
}

uint32_t CConnectedChains::IncludePostLaunchFeeHeight(bool getVerusHeight) const
{
    return (getVerusHeight || IsVerusActive()) && !PBAAS_TESTMODE ? 2606532 : 0;
}

bool CConnectedChains::IncludePostLaunchFees(uint32_t height) const
{
    return height > IncludePostLaunchFeeHeight(false);
}

uint32_t CConnectedChains::StrictCheckIDExportHeight(bool getVerusHeight) const
{
    return (getVerusHeight || IsVerusActive()) && !PBAAS_TESTMODE ? 2634460 : 0;
}

bool CConnectedChains::StrictCheckIDExport(uint32_t height) const
{
    return height >= StrictCheckIDExportHeight(false);
}

uint32_t CConnectedChains::DiscernBlockOneLaunchInfoHeight(bool getVerusHeight) const
{
    return (getVerusHeight || IsVerusActive()) && !PBAAS_TESTMODE ? 2824790 : 0;
}

bool CConnectedChains::DiscernBlockOneLaunchInfo(uint32_t height) const
{
    height = std::min(((uint32_t)chainActive.Height()), height);
    return height >= DiscernBlockOneLaunchInfoHeight(false);
}

bool CConnectedChains::CheckClearConvert(uint32_t height) const
{
    if (!IsVerusActive())
    {
        return true;
    }
    if (IsVerusMainnetActive())
    {
        return height >= PBAAS_CLEARCONVERT_HEIGHT;
    }
    // TODO: TESTNET RESET - remove these exception heights
    // testnet exception heights to prevent testnet reset
    static std::set<uint32_t> pendingTestnetExportHeights({5723, 5724, 5751, 5752, 5757, 5758, 5770, 5771, 6229, 6230, 6431, 6432, 7014, 7015, 7048, 7049, 7078, 7079, 7593, 7594, 7633, 7634, 7635, 7636});
    return height >= 8330 || pendingTestnetExportHeights.count(height);
}

/* Replace the function above with this on testnet reset
bool CConnectedChains::CheckClearConvert(uint32_t height) const
{
    if (IsVerusMainnetActive())
    {
        if (height < PBAAS_CLEARCONVERT_HEIGHT)
        {
            return false;
        }
    }
    return true;
}
*/

uint32_t CConnectedChains::AutoArbitrageEnabledHeight(bool getVerusHeight) const
{
    return (getVerusHeight || IsVerusActive()) && !PBAAS_TESTMODE ? 2873057 : 2;
}

bool CConnectedChains::AutoArbitrageEnabled(uint32_t height) const
{
    return height >= AutoArbitrageEnabledHeight(false);
}

uint32_t CConnectedChains::vARRRUpdateHeight(bool getVerusHeight) const
{
    return (getVerusHeight || IsVerusActive()) && !PBAAS_TESTMODE ? 3000000 : 0;
}

bool CConnectedChains::vARRRUpdateEnabled(uint32_t height) const
{
    return height >= vARRRUpdateHeight(false);
}

uint160 CConnectedChains::vARRRChainID() const
{
    static uint160 vARRRID = GetDestinationID(DecodeDestination("vARRR.vrsc.@"));
    return vARRRID;
}

uint160 CConnectedChains::KaijuCurrencyID() const
{
    static uint160 KaijuID = GetDestinationID(DecodeDestination("Kaiju.vrsc.@"));
    return KaijuID;
}

uint160 CConnectedChains::vDEXChainID() const
{
    static uint160 vARRRID = GetDestinationID(DecodeDestination("vDEX.vrsc.@"));
    return vARRRID;
}

uint160 CConnectedChains::Chips777TestnetChainID() const
{
    static uint160 Chips777TestnetID = GetDestinationID(DecodeDestination("chips777.vrsctest.@"));
    return Chips777TestnetID;
}

uint160 CConnectedChains::ChipsChainID() const
{
    static uint160 ChipsID = GetDestinationID(DecodeDestination("chips.vrsc.@"));
    return ChipsID;
}

bool CConnectedChains::ForceIdentityUpgrade(uint32_t height) const
{
    if (vARRRChainID() != ASSETCHAINS_CHAINID || height >= 18250)
    {
        return true;
    }

    auto iiuIt = ConnectedChains.activeUpgradesByKey.find(ConnectedChains.ForceIdentityUpgradeKey());
    if (iiuIt != ConnectedChains.activeUpgradesByKey.end() &&
        height >= iiuIt->second.upgradeBlockHeight)
    {
        return true;
    }

    return false;
}

#define FORCE_IDENTITY_UNLOCK_HEIGHT 67000

bool CConnectedChains::ForceIdentityUnlock(uint32_t height) const
{
    if (vARRRChainID() != ASSETCHAINS_CHAINID || height >= FORCE_IDENTITY_UNLOCK_HEIGHT)
    {
        return true;
    }

    auto iiuIt = ConnectedChains.activeUpgradesByKey.find(ConnectedChains.ForceIdentityUnlockKey());
    if (iiuIt != ConnectedChains.activeUpgradesByKey.end() &&
        height >= iiuIt->second.upgradeBlockHeight)
    {
        return true;
    }

    return false;
}

bool CConnectedChains::IdentityLockOverride(const CIdentity &identity, uint32_t height) const
{
    if (identity.unlockAfter > 800000 &&
        ASSETCHAINS_CHAINID == ConnectedChains.vARRRChainID() &&
        ForceIdentityUnlock(height) &&
        height < (FORCE_IDENTITY_UNLOCK_HEIGHT + 10000))
    {
        static std::set<CIdentityID> exemptIDs({GetDestinationID(DecodeDestination("iSXF8KbbvpHDWBm4zHxeA4n7uc1LsfR15X")), GetDestinationID(DecodeDestination("i4UxDzYtNR5oeGEEVritXuzAKjKzoVgiPK")), GetDestinationID(DecodeDestination("i5nQeKAWmxaXdNYv36qLQzz6XV8gZEqbaV"))});
        return exemptIDs.count(identity.GetID());
    }
    return false;
}

bool CConnectedChains::DoPreconvertReserveTransferPrecheck(uint32_t height) const
{
    uint32_t triggerHeight = IsVerusMainnetActive() ? 3050060 : (vARRRChainID() != ASSETCHAINS_CHAINID ? 67000 : 0);
    if (IsVerusMainnetActive() || vARRRChainID() == ASSETCHAINS_CHAINID)
    {
        auto iiuIt = ConnectedChains.activeUpgradesByKey.find(ConnectedChains.PreconvertReserveTransferPrecheckKey());
        if (iiuIt != ConnectedChains.activeUpgradesByKey.end())
        {
            triggerHeight = iiuIt->second.upgradeBlockHeight;
        }
        return height >= triggerHeight;
    }
    return true;
}

bool CConnectedChains::DoImportPreconvertReserveTransferPrecheck(uint32_t height) const
{
    uint32_t triggerHeight = IsVerusMainnetActive() ? 3050000 : (vARRRChainID() != ASSETCHAINS_CHAINID ? 67000 : 0);

    if (IsVerusMainnetActive() || vARRRChainID() == ASSETCHAINS_CHAINID)
    {
        auto iiuIt = ConnectedChains.activeUpgradesByKey.find(ConnectedChains.ImportPreconvertReserveTransferPrecheckKey());
        if (iiuIt != ConnectedChains.activeUpgradesByKey.end())
        {
            triggerHeight = iiuIt->second.upgradeBlockHeight;
        }
        return height < triggerHeight;
    }
    return false;
}

bool CConnectedChains::IsEnhancedDustCheck(uint32_t height) const
{
    uint32_t triggerHeight = IsVerusMainnetActive() ? 3093850 : (vARRRChainID() == ASSETCHAINS_CHAINID ? 107590 : 0);
    return height >= triggerHeight;
}

bool CConnectedChains::IsEnhancedNotarizationOrder(uint32_t height) const
{
    uint32_t triggerHeight = IsVerusMainnetActive() ? PBAAS_NOTARIZATION_ORDER_HEIGHT : (vARRRChainID() == ASSETCHAINS_CHAINID ? PBAAS_NOTARIZATION_ORDER_VARRR_HEIGHT : (vDEXChainID() == ASSETCHAINS_CHAINID ? PBAAS_NOTARIZATION_ORDER_VDEX_HEIGHT : 0));
    return height >= triggerHeight;
}

bool CConnectedChains::CrossChainPBaaSProofFix(const uint160 &sysID, uint32_t height) const
{
    auto oracleProofFix = activeUpgradesByKey.find(CConnectedChains::PBaaSCrossChainProofUpgradeKey());
    uint32_t fixHeight = oracleProofFix == activeUpgradesByKey.end() ? PBAAS_CROSS_CHAIN_PROOF_FIX_HEIGHT : oracleProofFix->second.upgradeBlockHeight;
    if (sysID == VERUS_CHAINID && !PBAAS_TESTMODE)
    {
        return height > 2549420; // This was the Verus PBaaS activation height
    }
    return !IsVerusMainnetActive() || height > fixHeight;
}

bool CConnectedChains::BlockOneIDUpgrade() const
{
    if (IsVerusMainnetActive() && chainActive.Height() < PBAAS_BLOCK_ONE_ID_UPGRADE_FIX_HEIGHT)
    {
        return false;
    }
    return true;
}

bool CConnectedChains::IsPromoteExchangeRate(uint32_t height) const
{
    if (IsVerusActive())
    {
        if (PBAAS_TESTMODE && height < PBAAS_PROMOTE_EXCHANGE_RATE_TEST_HEIGHT) // TODO: TESTNET - remove this check after testnet reset and only check mainnet
        {
            return false;
        }
        else if (!PBAAS_TESTMODE && height < PBAAS_PROMOTE_EXCHANGE_RATE_HEIGHT)
        {
            return false;
        }
    }
    return true;
}

/* Replace function above with this on testnet reset
bool CConnectedChains::IsPromoteExchangeRate(uint32_t height) const
{
    if (IsVerusMainnetActive())
    {
        if (height < PBAAS_PROMOTE_EXCHANGE_RATE_HEIGHT)
        {
            return false;
        }
    }
    return true;
}
*/

// Height is minimum that we must be in sync with for an answer (-1 = don't know, not caught up enough, 0 = before real time as of height, 1 = past real time as of height, if height = 0, based on chain tip)
// If any header is past the time over the last block averaging period, we consider it past that real time.
int CConnectedChains::CheckPastRealTime(uint32_t nTime, int64_t height) const
{
    if (height > chainActive.Height() && chainActive.LastTip()->nTime >= nTime)
    {
        return 1;
    }
    else if (chainActive.Height() >= height)
    {
        if (!height)
        {
            height = chainActive.Height();
        }
        for (int64_t i = height; i > std::max(height - Params().GetConsensus().nPowAveragingWindow, (int64_t)0); i--)
        {
            if (chainActive[i]->nTime >= nTime)
            {
                return 1;
            }
        }
        return 0;
    }
    return -1;
}

bool CConnectedChains::IsUpgrade01Active(int64_t height) const
{
    return CheckPastRealTime(PBAAS_TESTMODE ? PBAAS_SCHEDULED_PROTOCOL_TESTNET_UPGRADE_01 : PBAAS_SCHEDULED_PROTOCOL_UPGRADE_01, height) == 1;
}

bool CConnectedChains::IsUpgrade02Active(int64_t height) const
{
    return CheckPastRealTime(PBAAS_TESTMODE ? PBAAS_SCHEDULED_PROTOCOL_TESTNET_UPGRADE_02 : PBAAS_SCHEDULED_PROTOCOL_UPGRADE_02, height) == 1;
}

bool CConnectedChains::IsPBaaSRefundFixActive(int64_t height) const
{
    return CheckPastRealTime(PBAAS_TESTMODE ? PBAAS_LAUNCH_REFUND_FIX_TESTNET_UPGRADE_02 : PBAAS_LAUNCH_REFUND_FIX_UPGRADE, height) == 1;
}

bool CConnectedChains::IsPBaaSNotarizationFix01Active(int64_t height) const
{
    return CheckPastRealTime(PBAAS_TESTMODE ? PBAAS_ALLCHAINS_NOTARIZATION_FIX_TESTNET_UPGRADE : ASSETCHAINS_CHAINID == ChipsChainID() ? PBAAS_CHIPS_NOTARIZATION_FIX_UPGRADE : PBAAS_ALLCHAINS_NOTARIZATION_FIX_UPGRADE, height) == 1;
}

uint32_t CConnectedChains::GetChainBranchId(const uint160 &sysID, int height, const Consensus::Params& params) const
{
    auto oracleProofFix = activeUpgradesByKey.find(CConnectedChains::PBaaSCrossChainProofUpgradeKey());
    uint32_t fixHeight = oracleProofFix == activeUpgradesByKey.end() ? PBAAS_CROSS_CHAIN_PROOF_FIX_HEIGHT : oracleProofFix->second.upgradeBlockHeight;
    if (sysID == VERUS_CHAINID && !PBAAS_TESTMODE)
    {
        return CurrentEpochBranchId(height, params);
    }
    return !IsVerusMainnetActive() || height > fixHeight ? NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId : CurrentEpochBranchId(height, params);
}

bool CConnectedChains::ConfigureEthBridge(bool callToCheck)
{
    // first time through, we initialize the VETH gateway config file
    if (!_IsVerusActive())
    {
        return false;
    }
    if (IsNotaryAvailable())
    {
        return true;
    }
    LOCK(cs_main);
    if (FirstNotaryChain().IsValid())
    {
        return IsNotaryAvailable(callToCheck);
    }

    CRPCChainData vethNotaryChain;
    uint160 gatewayParent = ASSETCHAINS_CHAINID;
    static uint160 gatewayID;
    if (gatewayID.IsNull())
    {
        gatewayID = CIdentity::GetID("veth", gatewayParent);
    }
    vethNotaryChain.chainDefinition = ConnectedChains.GetCachedCurrency(gatewayID);
    if (vethNotaryChain.chainDefinition.IsValid())
    {
        map<string, string> settings;
        map<string, vector<string>> settingsmulti;

        // create config file for our notary chain if one does not exist already
        try
        {
            if (ReadConfigFile("veth", settings, settingsmulti) &&
                settingsmulti.count("-rpchost") &&
                settingsmulti.count("-rpcuser") &&
                settingsmulti.count("-rpcport") &&
                settingsmulti.count("-rpcpassword"))
            {
                // the Ethereum bridge, "VETH", serves as the root currency to VRSC and for Rinkeby to VRSCTEST
                vethNotaryChain.rpcUserPass = PBAAS_USERPASS = settingsmulti.find("-rpcuser")->second[0] + ":" + settingsmulti.find("-rpcpassword")->second[0];
                vethNotaryChain.rpcPort = PBAAS_PORT = atoi(settingsmulti.find("-rpcport")->second[0]);
                PBAAS_HOST = settingsmulti.find("-rpchost")->second[0];
            }
        }
        catch(const std::exception& e)
        {
            LogPrintf("%s: Error reading veth config file - may be invalid or misconfigured\n", __func__);
        }
        
        if (!PBAAS_HOST.size())
        {
            PBAAS_HOST = "127.0.0.1";
        }
        vethNotaryChain.rpcHost = PBAAS_HOST;
        CNotarySystemInfo notarySystem;
        CChainNotarizationData cnd;
        if (!GetNotarizationData(gatewayID, cnd))
        {
            LogPrintf("%s: Failed to get notarization data for notary chain %s\n", __func__, vethNotaryChain.chainDefinition.name.c_str());
            return false;
        }

        notarySystems.insert(std::make_pair(gatewayID,
                                            CNotarySystemInfo(cnd.IsConfirmed() ? cnd.vtx[cnd.lastConfirmed].second.notarizationHeight : 0,
                                            vethNotaryChain,
                                            cnd.vtx.size() ? cnd.vtx[cnd.forks[cnd.bestChain].back()].second : CPBaaSNotarization(),
                                            CNotarySystemInfo::TYPE_ETH,
                                            CNotarySystemInfo::VERSION_CURRENT)));
        return IsNotaryAvailable(callToCheck);
    }
    return false;
}

int CConnectedChains::GetThisChainPort() const
{
    int port;
    string host;
    for (auto node : defaultPeerNodes)
    {
        SplitHostPort(node.networkAddress, port, host);
        if (port)
        {
            return port;
        }
    }
    return 0;
}

CCoinbaseCurrencyState CConnectedChains::AddPrelaunchConversions(CCurrencyDefinition &curDef,
                                                                 const CCoinbaseCurrencyState &_currencyState,
                                                                 int32_t fromHeight,
                                                                 int32_t height,
                                                                 int32_t curDefHeight,
                                                                 const std::vector<CReserveTransfer> &extraConversions)
{
    CCoinbaseCurrencyState currencyState = _currencyState;
    bool firstUpdate = fromHeight <= curDefHeight;
    if (firstUpdate)
    {
        if (curDef.IsFractional())
        {
            currencyState.supply = curDef.initialFractionalSupply;
            currencyState.reserves = std::vector<int64_t>(currencyState.reserves.size(), 0);
            currencyState.reserveIn = currencyState.reserves;
            if (curDef.IsGatewayConverter() && curDef.gatewayConverterIssuance)
            {
                currencyState.reserves[curDef.GetCurrenciesMap()[curDef.systemID]] = curDef.gatewayConverterIssuance;
            }
            currencyState.weights = curDef.weights;
        }
        else
        {
            // supply is determined by purchases * current conversion rate
            currencyState.supply = curDef.GetTotalPreallocation();
            currencyState.supply = currencyState.AddToSupply(curDef.gatewayConverterIssuance);
        }
    }

    // get chain transfers that should apply before the start block
    // until there is a post-start block notarization, we always consider the
    // currency state to be up to just before the start block
    std::multimap<uint160, ChainTransferData> unspentTransfers;
    std::map<uint160, int32_t> currencyIndexes = currencyState.GetReserveMap();

    if (GetUnspentChainTransfers(unspentTransfers, curDef.GetID()))
    {
        std::vector<CReserveTransfer> transfers = extraConversions;
        for (auto &oneTransfer : unspentTransfers)
        {
            if (std::get<0>(oneTransfer.second) < curDef.startBlock)
            {
                transfers.push_back(std::get<2>(oneTransfer.second));
            }
        }
        uint256 transferHash;
        CPBaaSNotarization newNotarization;
        std::vector<CTxOut> importOutputs;
        CCurrencyValueMap importedCurrency, gatewayDepositsUsed, spentCurrencyOut;
        CPBaaSNotarization workingNotarization(currencyState.GetID(),
                                                currencyState,
                                                fromHeight,
                                                CUTXORef(),
                                                curDefHeight);
        workingNotarization.SetPreLaunch();

        bool getNextNotarization = false;
        CCurrencyDefinition checkDef;
        int32_t defHeight = 0;

        // only get next notarization if mined in
        if ((curDef.systemID != ASSETCHAINS_CHAINID &&
             GetCurrencyDefinition(curDef.systemID, checkDef, &defHeight) &&
             defHeight &&
             defHeight < height) ||
            (curDef.systemID == ASSETCHAINS_CHAINID &&
             GetCurrencyDefinition(curDef.GetID(), checkDef, &defHeight) &&
             defHeight &&
             defHeight < height))
        {
            getNextNotarization = true;
        }

        if (getNextNotarization && // this check is important, as we need consistency of bridge currency definitions not taking this path
            workingNotarization.NextNotarizationInfo(ConnectedChains.ThisChain(),
                                                     curDef,
                                                     fromHeight,
                                                     std::min(height, curDef.startBlock - 1),
                                                     transfers,
                                                     transferHash,
                                                     newNotarization,
                                                     importOutputs,
                                                     importedCurrency,
                                                     gatewayDepositsUsed,
                                                     spentCurrencyOut,
                                                     CTransferDestination(),
                                                     false,
                                                     false))
        {
            return newNotarization.currencyState;
        }
    }
    return currencyState;
}

CCoinbaseCurrencyState CConnectedChains::AddPendingConversions(CCurrencyDefinition &curDef,
                                                               const CPBaaSNotarization &_lastNotarization,
                                                               int32_t fromHeight,
                                                               int32_t height,
                                                               int32_t curDefHeight,
                                                               const std::vector<CReserveTransfer> &extraConversions)
{
    if (curDef.launchSystemID == ASSETCHAINS_CHAINID && fromHeight < curDef.startBlock)
    {
        return AddPrelaunchConversions(curDef, _lastNotarization.currencyState, fromHeight, height, curDefHeight, extraConversions);
    }

    CCoinbaseCurrencyState currencyState = _lastNotarization.currencyState;

    // get chain transfers that should apply before the start block
    // until there is a post-start block notarization, we always consider the
    // currency state to be up to just before the start block
    std::vector<ChainTransferData> unspentTransfers;
    std::map<uint160, int32_t> currencyIndexes = currencyState.GetReserveMap();

    if ((GetUnspentChainTransfers(unspentTransfers, curDef.GetID()) && unspentTransfers.size()) || extraConversions.size())
    {
        std::vector<CReserveTransfer> transfers = extraConversions;
        for (auto &oneTransfer : unspentTransfers)
        {
            transfers.push_back(std::get<2>(oneTransfer));
        }
        uint256 transferHash;
        CPBaaSNotarization newNotarization;
        std::vector<CTxOut> importOutputs;
        CCurrencyValueMap importedCurrency, gatewayDepositsUsed, spentCurrencyOut;
        if (_lastNotarization.NextNotarizationInfo(ConnectedChains.ThisChain(),
                                                    curDef,
                                                    fromHeight,
                                                    std::min(height, chainActive.Height() + 1),
                                                    transfers,
                                                    transferHash,
                                                    newNotarization,
                                                    importOutputs,
                                                    importedCurrency,
                                                    gatewayDepositsUsed,
                                                    spentCurrencyOut))
        {
            return newNotarization.currencyState;
        }
        else
        {
            currencyState = CCoinbaseCurrencyState();
        }
    }
    return currencyState;
}

CCoinbaseCurrencyState CConnectedChains::GetCurrencyState(CCurrencyDefinition &curDef, int32_t height, int32_t curDefHeight, bool loadPendingTransfers)
{
    uint160 chainID = curDef.GetID();
    uint256 blockHash;
    CCoinbaseCurrencyState currencyState;

    bool setCache = true;

    blockHash = chainActive[std::min(chainActive.Height(), height)]->GetBlockHash();
    currencyState = currencyStateCache.Get({chainID, blockHash, loadPendingTransfers});
    if (currencyState.IsValid())
    {
        return currencyState;
    }
    std::vector<CAddressIndexDbEntry> notarizationIndex;

    if ((IsVerusActive() || height == 0) && chainID == ASSETCHAINS_CHAINID)
    {
        currencyState = GetInitialCurrencyState(thisChain);
        currencyState.SetLaunchConfirmed();
        setCache = false;
    }
    // if this is a token on this chain, it will be simply notarized
    else if (curDef.SystemOrGatewayID() == ASSETCHAINS_CHAINID || (curDef.launchSystemID == ASSETCHAINS_CHAINID && curDef.startBlock > height))
    {
        // get the last notarization in the height range for this currency, which is valid by definition for a token
        CPBaaSNotarization notarization;
        notarization.GetLastNotarization(chainID, curDefHeight, height);
        currencyState = notarization.currencyState;
        if (!currencyState.IsValid())
        {
            if (notarization.IsValid() && notarization.currencyStates.count(chainID))
            {
                currencyState = notarization.currencyStates[chainID];
            }
            else
            {
                currencyState = GetInitialCurrencyState(curDef);
                currencyState.SetPrelaunch();
                setCache = false;
            }
        }
        if (currencyState.IsValid() &&
            curDef.launchSystemID == ASSETCHAINS_CHAINID &&
            curDef.startBlock &&
            (!notarization.IsValid() || notarization.notarizationHeight < (curDef.startBlock - 1)))
        {
            // pre-launch
            currencyState.SetPrelaunch(true);
            if (loadPendingTransfers)
            {
                currencyState = AddPrelaunchConversions(curDef,
                                                        currencyState,
                                                        notarization.IsValid() && !notarization.IsDefinitionNotarization() ?
                                                            notarization.notarizationHeight + 1 : curDefHeight,
                                                        std::min(height, curDef.startBlock - 1),
                                                        curDefHeight);
            }
        }
    }
    else
    {
        // we need to get the currency state of a currency not on this chain, so we first get the chain's notarization and see if
        // it is there. if not, look for the latest confirmed notarization and return that
        CChainNotarizationData cnd;
        if (GetNotarizationData(curDef.systemID, cnd) && cnd.IsConfirmed() && cnd.vtx[cnd.lastConfirmed].second.currencyStates.count(chainID))
        {
            currencyState = cnd.vtx[cnd.lastConfirmed].second.currencyStates[chainID];
        }
        else if (GetNotarizationData(chainID, cnd))
        {
            int32_t transfersFrom = curDefHeight;
            if (cnd.lastConfirmed != -1)
            {
                transfersFrom = cnd.vtx[cnd.lastConfirmed].second.notarizationHeight;
                currencyState = cnd.vtx[cnd.lastConfirmed].second.currencyState;
            }
            int32_t transfersUntil = cnd.lastConfirmed == -1 ? curDef.startBlock - 1 :
                                       (cnd.vtx[cnd.lastConfirmed].second.notarizationHeight < curDef.startBlock ?
                                        (height < curDef.startBlock ? height : curDef.startBlock - 1) :
                                        cnd.vtx[cnd.lastConfirmed].second.notarizationHeight);
            if (transfersUntil < curDef.startBlock)
            {
                if (currencyState.reserveIn.size() != curDef.currencies.size())
                {
                    currencyState.reserveIn = std::vector<int64_t>(curDef.currencies.size());
                }
                if (curDef.conversions.size() != curDef.currencies.size())
                {
                    curDef.conversions = std::vector<int64_t>(curDef.currencies.size());
                }
                if (currencyState.conversionPrice.size() != curDef.currencies.size())
                {
                    currencyState.conversionPrice = std::vector<int64_t>(curDef.currencies.size());
                }
                if (currencyState.fees.size() != curDef.currencies.size())
                {
                    currencyState.fees = std::vector<int64_t>(curDef.currencies.size());
                }
                if (currencyState.conversionFees.size() != curDef.currencies.size())
                {
                    currencyState.conversionFees = std::vector<int64_t>(curDef.currencies.size());
                }
                if (currencyState.priorWeights.size() != curDef.currencies.size())
                {
                    currencyState.priorWeights.resize(curDef.currencies.size());
                }
                // get chain transfers that should apply before the start block
                // until there is a post-start block notarization, we always consider the
                // currency state to be up to just before the start block
                std::multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> unspentTransfers;
                if (GetChainTransfers(unspentTransfers, chainID, transfersFrom, transfersUntil))
                {
                    // at this point, all pre-allocation, minted, and pre-converted currency are included
                    // in the currency state before final notarization
                    std::map<uint160, int32_t> currencyIndexes = currencyState.GetReserveMap();
                    if (curDef.IsFractional())
                    {
                        currencyState.supply = curDef.initialFractionalSupply;
                    }
                    else
                    {
                        // supply is determined by purchases * current conversion rate
                        currencyState.supply = curDef.GetTotalPreallocation();
                        currencyState.supply = currencyState.AddToSupply(curDef.gatewayConverterIssuance);
                    }

                    for (auto &transfer : unspentTransfers)
                    {
                        if (transfer.second.second.IsPreConversion())
                        {
                            CAmount conversionFee = CReserveTransactionDescriptor::CalculateConversionFee(transfer.second.second.FirstValue());

                            currencyState.reserveIn[currencyIndexes[transfer.second.second.FirstCurrency()]] += transfer.second.second.FirstValue();
                            curDef.preconverted[currencyIndexes[transfer.second.second.FirstCurrency()]] += transfer.second.second.FirstValue();
                            if (curDef.IsFractional())
                            {
                                currencyState.reserves[currencyIndexes[transfer.second.second.FirstCurrency()]] += transfer.second.second.FirstValue() - conversionFee;
                            }
                            else
                            {
                                currencyState.supply += CCurrencyState::ReserveToNativeRaw(transfer.second.second.FirstValue() - conversionFee, currencyState.PriceInReserve(currencyIndexes[transfer.second.second.FirstCurrency()]));
                            }

                            currencyState.conversionFees[currencyIndexes[transfer.second.second.FirstCurrency()]] += conversionFee;
                            currencyState.fees[currencyIndexes[transfer.second.second.FirstCurrency()]] += conversionFee;
                            currencyState.fees[currencyIndexes[transfer.second.second.feeCurrencyID]] += transfer.second.second.nFees;
                        }
                    }
                    currencyState.supply += currencyState.emitted;
                    for (int i = 0; i < curDef.conversions.size(); i++)
                    {
                        currencyState.conversionPrice[i] = curDef.conversions[i] = currencyState.PriceInReserve(i);
                    }
                }
            }
            else
            {
                std::pair<CUTXORef, CPBaaSNotarization> notPair = cnd.lastConfirmed != -1 ? cnd.vtx[cnd.lastConfirmed] : cnd.vtx[cnd.forks[cnd.bestChain][0]];
                currencyState = notPair.second.currencyState;
            }
        }
        else
        {
            currencyState = GetInitialCurrencyState(curDef);
        }
    }
    if (setCache && currencyState.IsValid())
    {
        currencyStateCache.Put({chainID, blockHash, loadPendingTransfers}, currencyState);
    }
    return currencyState;
}

CCoinbaseCurrencyState CConnectedChains::GetCurrencyState(const uint160 &currencyID, int32_t height, bool loadPendingTransfers)
{
    int32_t curDefHeight;
    CCurrencyDefinition curDef;
    if (GetCurrencyDefinition(currencyID, curDef, &curDefHeight, true))
    {
        return GetCurrencyState(curDef, height, curDefHeight, loadPendingTransfers);
    }
    else
    {
        LogPrintf("%s: currency %s:%s not found\n", __func__, currencyID.GetHex().c_str(), EncodeDestination(CIdentityID(currencyID)).c_str());
        printf("%s: currency %s:%s not found\n", __func__, currencyID.GetHex().c_str(), EncodeDestination(CIdentityID(currencyID)).c_str());
    }
    return CCoinbaseCurrencyState();
}

CCoinbaseCurrencyState CConnectedChains::GetCurrencyState(int32_t height, bool loadPendingTransfers)
{
    return GetCurrencyState(thisChain.GetID(), height, loadPendingTransfers);
}

bool CConnectedChains::SetLatestMiningOutputs(const std::vector<CTxOut> &minerOutputs)
{
    LOCK(cs_mergemining);
    latestMiningOutputs = minerOutputs;
    return true;
}

CCurrencyDefinition CConnectedChains::GetCachedCurrency(const uint160 &currencyID)
{
    std::tuple<uint32_t, uint256, CCurrencyDefinition> specificCurDef = currencyDefCache.Get(currencyID);
    CCurrencyDefinition currencyDef = std::get<2>(specificCurDef);
    if (!currencyDef.IsValid() ||
        (!std::get<0>(specificCurDef) && currencyDef.GetID() != ASSETCHAINS_CHAINID) ||
        (std::get<0>(specificCurDef) > 0 &&
         std::get<0>(specificCurDef) <= chainActive.Height() &&
         chainActive[std::get<0>(specificCurDef)]->GetBlockHash() != std::get<1>(specificCurDef)) ||
        ((chainActive.Height() + 1) == std::get<0>(specificCurDef) &&
          std::get<1>(specificCurDef) != uint256()) ||
        (chainActive.Height() + 1) < std::get<0>(specificCurDef))
    {
        int32_t defHeight;
        if (!GetCurrencyDefinition(currencyID, currencyDef, &defHeight, true))
        {
            return CCurrencyDefinition();
        }
        uint256 blockHash = defHeight == 0 || defHeight > chainActive.Height() ? uint256() : chainActive[defHeight]->GetBlockHash();
        currencyDefCache.Put(currencyID, {defHeight, blockHash, currencyDef});
    }
    return currencyDef;
}

CCurrencyDefinition CConnectedChains::UpdateCachedCurrency(const CCurrencyDefinition &currencyDef, uint32_t height)
{
    // due to the main lock being taken on the thread that waits for transaction checks,
    // low level functions like this must be called either from a thread that holds LOCK(cs_main),
    // or script validation, where it is held either by this thread or one waiting for it.
    // in the long run, the daemon synchonrization model should be improved
    uint160 currencyID = currencyDef.GetID();
    if (!height || chainActive.Height() < height)
    {
        currencyDefCache.Put(currencyID, {height, uint256(), currencyDef});
    }
    else
    {
        currencyDefCache.Put(currencyID, {height, chainActive[height]->GetBlockHash(), currencyDef});
    }
    if (currencyID == ASSETCHAINS_CHAINID)
    {
        ThisChain() = currencyDef;
    }
    return currencyDef;
}

// this must be protected with main lock
std::string CConnectedChains::GetFriendlyCurrencyName(const uint160 &currencyID, bool addVerus)
{
    // basically, we lookup parent until we are at the native currency
    std::string retName;
    uint160 curID = currencyID;
    CCurrencyDefinition curDef;
    for (curDef = GetCachedCurrency(curID); curDef.IsValid(); curDef = curID.IsNull() ? CCurrencyDefinition() : GetCachedCurrency(curID))
    {
        if (!addVerus && curDef.parent.IsNull())
        {
            // if we are at a Verus root, we can omit it unless there is nothing else
            if (curDef.GetID() == VERUS_CHAINID)
            {
                if (retName.empty())
                {
                    retName = curDef.name;
                }
            }
            else
            {
                // if we are at a root that is not Verus, add it and then a "."
                retName += ".";
            }
        }
        else
        {
            if (retName.empty())
            {
                retName = curDef.name;
            }
            else
            {
                retName += "." + curDef.name;
            }
        }
        curID = curDef.parent;
    }
    return retName;
}

std::string CConnectedChains::GetFriendlyIdentityName(const std::string &name, const uint160 &parentCurrencyID, bool addVerus)
{
    uint160 parent;
    std::string cleanName = CleanName(name, parent, false, true);

    if (parentCurrencyID.IsNull())
    {
        std::string lowerName = boost::to_lower_copy(cleanName);
        if (lowerName == "vrsc" || lowerName == "vrsctest")
        {
            return name + "@";
        }
        else
        {
            return name + ".@";
        }
    }
    else
    {
        std::string parentFriendlyName = GetFriendlyCurrencyName(parentCurrencyID, addVerus);
        return parentFriendlyName.empty() ? "" : (name + '.' + parentFriendlyName + '@');
    }
}

std::string CConnectedChains::GetFriendlyIdentityName(const CIdentity &identity, bool addVerus)
{
    return GetFriendlyIdentityName(identity.name, identity.parent, addVerus);
}

// this should only do something when we're seeing dups in the mempool that spend the same prior due to a reorg
// if we confirm that, cleanup the mempool and the vector as well
void CleanupExportOutDups(std::vector<std::pair<int, CInputDescriptor>> &exportOuts)
{
    if (exportOuts.size() > 1)
    {
        // if there is more than one unspent export, that means that only one can be valid, since
        // all should be in the mempool and spending the same prior export.
        // first, confirm that all are spending a shared prior UTXO.
        // if not, we may return more than one
        std::shared_ptr<const CTransaction> pMempoolTx = mempool.get(exportOuts.back().second.txIn.prevout.hash);

        // if not in the mempool, we'll just return what we have, otherwise, cleanup
        // in any legitimate case caused by a reorg that isn't catastrophic, this should be true and cleanup to one value in the vector
        if (pMempoolTx)
        {
            std::list<CTransaction> removedTxes;
            std::set<uint256> removedHashes;
            // we would expect all except the one we are checking to be removed
            // remove those removed from mempool from our return list
            mempool.removeConflicts(*pMempoolTx, removedTxes);
            for (auto &oneTx : removedTxes)
            {
                removedHashes.insert(oneTx.GetHash());
            }

            std::vector<std::pair<int, CInputDescriptor>> newOuts = {exportOuts.back()};

            for (auto &oneOut : exportOuts)
            {
                if (!removedHashes.count(oneOut.second.txIn.prevout.hash))
                {
                    newOuts.push_back(oneOut);
                }
            }
            exportOuts = newOuts;
        }
    }
}

// returns all unspent chain exports for a specific chain/currency
bool CConnectedChains::GetUnspentSystemExports(const CCoinsViewCache &view,
                                               const uint160 systemID,
                                               std::vector<std::pair<int, CInputDescriptor>> &exportOuts)
{
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> exportUTXOs;

    LOCK2(cs_main, mempool.cs);

    uint160 exportIndexKey = CCrossChainRPCData::GetConditionID(systemID, CCrossChainExport::SystemExportKey());

    std::vector<std::pair<CInputDescriptor, uint32_t>> outputs;
    if (GetUnspentByIndex(exportIndexKey, outputs))
    {
        for (auto &oneOutput : outputs)
        {
            COptCCParams p;
            const CCoins *coin = view.AccessCoins(oneOutput.first.txIn.prevout.hash);
            if (coin &&
                !mempool.mapNextTx.count(COutPoint(oneOutput.first.txIn.prevout.hash, oneOutput.first.txIn.prevout.n)) &&
                coin->IsAvailable(oneOutput.first.txIn.prevout.n))
            {
                exportOuts.push_back(std::make_pair(oneOutput.second, oneOutput.first));
            }
        }
        CleanupExportOutDups(exportOuts);
    }
    return exportOuts.size() != 0;
}

// returns all unspent chain exports for a specific chain/currency
bool CConnectedChains::GetUnspentCurrencyExports(const CCoinsViewCache &view,
                                                 const uint160 currencyID,
                                                 std::vector<std::pair<int, CInputDescriptor>> &exportOuts)
{
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> exportUTXOs;

    LOCK2(cs_main, mempool.cs);

    uint160 exportIndexKey = CCrossChainRPCData::GetConditionID(currencyID, CCrossChainExport::CurrencyExportKey());

    std::vector<std::pair<CInputDescriptor, uint32_t>> outputs;
    if (GetUnspentByIndex(exportIndexKey, outputs))
    {
        for (auto &oneOutput : outputs)
        {
            COptCCParams p;
            const CCoins *coin = view.AccessCoins(oneOutput.first.txIn.prevout.hash);
            if (coin &&
                !mempool.mapNextTx.count(COutPoint(oneOutput.first.txIn.prevout.hash, oneOutput.first.txIn.prevout.n)) &&
                coin->IsAvailable(oneOutput.first.txIn.prevout.n))
            {
                exportOuts.push_back(std::make_pair(oneOutput.second, oneOutput.first));
            }
        }
        CleanupExportOutDups(exportOuts);
    }
    return exportOuts.size() != 0;
}

CPartialTransactionProof::CPartialTransactionProof(const CTransaction tx, const std::vector<int32_t> &inputNums, const std::vector<int32_t> &outputNums, const CBlockIndex *pIndex, uint32_t proofAtHeight)
{
    // get map and MMR for transaction
    CTransactionMap txMap(tx);
    TransactionMMView txView(txMap.transactionMMR);
    uint256 txRoot = txView.GetRoot();

    std::vector<CTransactionComponentProof> txProofVec;
    txProofVec.push_back(CTransactionComponentProof(txView, txMap, tx, CTransactionHeader::TX_HEADER, 0));
    for (auto oneInNum : inputNums)
    {
        txProofVec.push_back(CTransactionComponentProof(txView, txMap, tx, CTransactionHeader::TX_PREVOUTSEQ, oneInNum));
    }

    for (auto oneOutNum : outputNums)
    {
        txProofVec.push_back(CTransactionComponentProof(txView, txMap, tx, CTransactionHeader::TX_OUTPUT, oneOutNum));
    }

    // now, both the header and stake output are dependent on the transaction MMR root being provable up
    // through the block MMR, and since we don't cache the new MMR proof for transactions yet, we need the block to create the proof.
    // when we switch to the new MMR in place of a merkle tree, we can keep that in the wallet as well
    CBlock block;
    if (!ReadBlockFromDisk(block, pIndex, Params().GetConsensus(), false))
    {
        LogPrintf("%s: ERROR: could not read block number %u from disk\n", __func__, pIndex->GetHeight());
        version = VERSION_INVALID;
        return;
    }

    bool posEntropyInfo = CVerusSolutionVector(block.nSolution).Version() >= CActivationHeight::ACTIVATE_PBAAS;

    BlockMMRange blockMMR(block.GetBlockMMRTree(posEntropyInfo ? pIndex->GetVerusEntropyHashComponent() : uint256()));
    BlockMMView blockView(blockMMR);

    if (blockView.GetRoot() != block.GetBlockMMRRoot())
    {
        LogPrintf("%s: ERROR: incorrect block tree root\n", __func__);
    }

    int txIndexPos;
    for (txIndexPos = 0; txIndexPos < blockMMR.size(); txIndexPos++)
    {
        uint256 txRootHashFromMMR = blockMMR[txIndexPos].hash;
        if (txRootHashFromMMR == txRoot)
        {
            //printf("tx with root %s found in block\n", txRootHashFromMMR.GetHex().c_str());
            break;
        }
    }

    if (txIndexPos == blockMMR.size())
    {
        LogPrintf("%s: ERROR: could not find transaction root in block %u\n", __func__, pIndex->GetHeight());
        version = VERSION_INVALID;
        return;
    }

    // prove the tx up to the MMR root, which also contains the block hash
    CMMRProof txRootProof;
    if (!blockView.GetProof(txRootProof, txIndexPos))
    {
        LogPrintf("%s: ERROR: could not create proof of source transaction in block %u\n", __func__, pIndex->GetHeight());
        version = VERSION_INVALID;
        return;
    }

    ChainMerkleMountainView mmv = chainActive.GetMMV();
    mmv.resize(proofAtHeight + 1);
    chainActive.GetMerkleProof(mmv, txRootProof, pIndex->GetHeight());
    *this = CPartialTransactionProof(txRootProof, txProofVec);

    /*printf("%s: MMR root at height %u: %s\n", __func__, proofAtHeight, mmv.GetRoot().GetHex().c_str());
    CTransaction outTx;
    if (CheckPartialTransaction(outTx) != mmv.GetRoot())
    {
        printf("%s: invalid proof result: %s\n", __func__, CheckPartialTransaction(outTx).GetHex().c_str());
    }
    CPartialTransactionProof checkProof(ToUniValue());
    if (checkProof.CheckPartialTransaction(outTx) != mmv.GetRoot())
    {
        printf("%s: invalid proof after univalue: %s\n", __func__, checkProof.CheckPartialTransaction(outTx).GetHex().c_str());
    }*/
}

// given exports on this chain, provide the proofs of those export outputs with the MMR root at height "height"
// proofs are added in place
bool CConnectedChains::GetExportProofs(uint32_t height,
                                       std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports)
{
    // fill in proofs of the export outputs for each export at the specified height
    CBlock proofBlock;

    for (auto &oneExport : exports)
    {
        uint256 blockHash;
        CTransaction exportTx;
        if (!myGetTransaction(oneExport.first.first.txIn.prevout.hash, exportTx, blockHash))
        {
            LogPrintf("%s: unable to retrieve export %s\n", __func__, oneExport.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }
        CCrossChainExport ccx(exportTx.vout[oneExport.first.first.txIn.prevout.n].scriptPubKey);
        if (!ccx.IsValid())
        {
            LogPrintf("%s: invalid export on %s\n", __func__, oneExport.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }
        if (blockHash.IsNull())
        {
            LogPrintf("%s: cannot get proof for unconfirmed export %s\n", __func__, oneExport.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }
        auto blockIt = mapBlockIndex.find(blockHash);
        if (blockIt == mapBlockIndex.end() || !chainActive.Contains(blockIt->second))
        {
            LogPrintf("%s: cannot validate block of export tx %s\n", __func__, oneExport.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }
        std::vector<int32_t> inputsToProve;
        oneExport.first.second = CPartialTransactionProof(exportTx,
                                                          inputsToProve,
                                                          std::vector<int32_t>({(int32_t)oneExport.first.first.txIn.prevout.n}),
                                                          blockIt->second,
                                                          height);
    }
    return true;
}

bool CConnectedChains::GetReserveDeposits(const uint160 &currencyID, const CCoinsViewCache &view, std::vector<CInputDescriptor> &reserveDeposits)
{
    std::vector<CAddressUnspentDbEntry> confirmedUTXOs;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> unconfirmedUTXOs;

    LOCK(mempool.cs);

    CCoins coin;

    uint160 depositIndexKey = CReserveDeposit::ReserveDepositIndexKey(currencyID);
    if (!GetAddressUnspent(depositIndexKey, CScript::P2IDX, confirmedUTXOs) ||
        !mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{depositIndexKey, CScript::P2IDX}}), unconfirmedUTXOs))
    {
        LogPrintf("%s: Cannot read address indexes\n", __func__);
        return false;
    }
    std::vector<std::pair<CInputDescriptor, uint32_t>> outputs;
    if (GetUnspentByIndex(depositIndexKey, outputs))
    {
        for (auto &oneOutput : outputs)
        {
            COptCCParams p;
            if (!mempool.mapNextTx.count(COutPoint(oneOutput.first.txIn.prevout.hash, oneOutput.first.txIn.prevout.n)) &&
                view.GetCoins(oneOutput.first.txIn.prevout.hash, coin) &&
                coin.IsAvailable(oneOutput.first.txIn.prevout.n) &&
                oneOutput.first.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_RESERVE_DEPOSIT)
            {
                reserveDeposits.push_back(CInputDescriptor(oneOutput.first.scriptPubKey, oneOutput.first.nValue,
                                                            CTxIn(oneOutput.first.txIn.prevout.hash, oneOutput.first.txIn.prevout.n)));
            }
        }
    }
    return true;
}

bool CConnectedChains::GetUnspentByIndex(const uint160 &indexID, std::vector<std::pair<CInputDescriptor, uint32_t>> &unspentOutputs)
{
    std::vector<CAddressUnspentDbEntry> confirmedUTXOs;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> unconfirmedUTXOs;

    if (!GetAddressUnspent(indexID, CScript::P2IDX, confirmedUTXOs) ||
        !mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{indexID, CScript::P2IDX}}), unconfirmedUTXOs))
    {
        LogPrintf("%s: Cannot read address indexes\n", __func__);
        return false;
    }

    std::set<COutPoint> spentInMempool;
    auto memPoolOuts = mempool.FilterUnspent(unconfirmedUTXOs, spentInMempool);

    for (auto &oneConfirmed : confirmedUTXOs)
    {
        BlockMap::iterator blockIt;
        std::pair<CTransaction, uint256> txAndBlkHash;
        if (spentInMempool.count(COutPoint(oneConfirmed.first.txhash, oneConfirmed.first.index)) ||
            !myGetTransaction(oneConfirmed.first.txhash, txAndBlkHash.first, txAndBlkHash.second) ||
            (blockIt = mapBlockIndex.find(txAndBlkHash.second)) == mapBlockIndex.end() ||
            !chainActive.Contains(blockIt->second))
        {
            continue;
        }
        oneConfirmed.second.blockHeight = blockIt->second->GetHeight();

        COptCCParams p;
        if (!mempool.mapNextTx.count(COutPoint(oneConfirmed.first.txhash, oneConfirmed.first.index)) &&
            oneConfirmed.second.script.IsPayToCryptoCondition(p) && p.IsValid())
        {
            unspentOutputs.push_back(std::make_pair(CInputDescriptor(oneConfirmed.second.script, oneConfirmed.second.satoshis,
                                                        CTxIn(oneConfirmed.first.txhash, oneConfirmed.first.index)),
                                                    (uint32_t)oneConfirmed.second.blockHeight));
        }
    }

    // we need to remove those that are spent
    for (auto &oneUnconfirmed : memPoolOuts)
    {
        const CTransaction oneTx = mempool.mapTx.find(oneUnconfirmed.first.txhash)->GetTx();
        unspentOutputs.push_back(std::make_pair(CInputDescriptor(oneTx.vout[oneUnconfirmed.first.index].scriptPubKey, oneUnconfirmed.second.amount,
                                                    CTxIn(oneUnconfirmed.first.txhash, oneUnconfirmed.first.index)),
                                                0));
    }
    return true;
}

// given a set of provable exports to this chain from either this chain or another chain or system,
// create a set of import transactions
bool CConnectedChains::CreateLatestImports(const CCurrencyDefinition &sourceSystemDef,                      // transactions imported from system
                                           const CUTXORef &confirmedSourceNotarization,                     // relevant notarization of exporting system
                                           const std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports,
                                           std::map<uint160, std::vector<std::pair<int, CTransaction>>> &newImports)
{
    // each export is from the source system, but may be to any currency exposed on this system, so each import
    // made combines the potential currency sources of the source system and the importing currency
    LOCK(cs_main);
    LOCK2(smartTransactionCS, mempool.cs);

    if (!exports.size())
    {
        return false;
    }

    if (ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableDeFiKey()))
    {
        if (LogAcceptCategory("defi"))
        {
            LogPrintf("%s: All DeFi temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
        }
        return false;
    }
    if (sourceSystemDef.SystemOrGatewayID() != ASSETCHAINS_CHAINID && ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisablePBaaSCrossChainKey()))
    {
        if (LogAcceptCategory("crosschainimports"))
        {
            LogPrintf("%s: Cross-chain imports temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
        }
        return false;
    }
    if (sourceSystemDef.IsGateway() && ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableGatewayCrossChainKey()))
    {
        if (LogAcceptCategory("crosschainimports"))
        {
            LogPrintf("%s: Cross-chain imports for non-PBaaS gateways temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
        }
        return false;
    }

    // determine if we are refunding or not, which must be handled correctly when refunding a
    // PBaaS launch. In that case, the refunds must be read as if they are to another chain,
    // and written as same chain

    CCoinsView dummy;
    CCoinsViewCache view(&dummy);
    CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
    view.SetBackend(viewMemPool);

    uint32_t nHeight = chainActive.Height();
    uint160 sourceSystemID = sourceSystemDef.GetID();
    bool useProofs = sourceSystemID != thisChain.GetID();

    CPBaaSNotarization proofNotarization;
    if (useProofs)
    {
        CTransaction proofNotarizationTx;
        uint256 blkHash;
        COptCCParams p;
        if (confirmedSourceNotarization.hash.IsNull() ||
            !myGetTransaction(confirmedSourceNotarization.hash, proofNotarizationTx, blkHash) ||
            confirmedSourceNotarization.n >= proofNotarizationTx.vout.size() ||
            !proofNotarizationTx.vout[confirmedSourceNotarization.n].scriptPubKey.IsPayToCryptoCondition(p) ||
            !p.IsValid() ||
            (p.evalCode != EVAL_ACCEPTEDNOTARIZATION && p.evalCode != EVAL_EARNEDNOTARIZATION) ||
            !p.vData.size() ||
            !(proofNotarization = CPBaaSNotarization(p.vData[0])).IsValid() ||
            !proofNotarization.proofRoots.count(sourceSystemID))
        {
            LogPrintf("%s: invalid notarization for export proof\n", __func__);
            return false;
        }
    }

    // now, if we are creating an import for an external export, spend and output the import thread for that external system to make it
    // easy to find the last import for any external system and confirm that we are also not skipping any exports
    CTransaction lastSourceImportTx;
    int32_t sourceOutputNum = -1;
    CCrossChainImport lastSourceCCI;
    uint256 lastSourceImportTxID;

    uint160 failedCurrencyDest;

    for (auto &oneIT : exports)
    {
        uint256 blkHash;
        CTransaction exportTx;

        if (useProofs)
        {
            if (!oneIT.first.second.IsValid())
            {
                LogPrintf("%s: invalid proof for export tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                continue;
            }

            if (proofNotarization.proofRoots[sourceSystemID].stateRoot != oneIT.first.second.CheckPartialTransaction(exportTx, nullptr, ConnectedChains.ShouldOptimizeETHProof()))
            {
                LogPrintf("%s: export tx %s fails verification\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                continue;
            }

            if (exportTx.vout.size() <= oneIT.first.first.txIn.prevout.n)
            {
                LogPrintf("%s: invalid proof for export tx output %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                continue;
            }
        }
        else
        {
            if (!myGetTransaction(oneIT.first.first.txIn.prevout.hash, exportTx, blkHash))
            {
                LogPrintf("%s: unable to retrieve export tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                continue;
            }
        }

        const CCrossChainExport ccx(exportTx.vout[oneIT.first.first.txIn.prevout.n].scriptPubKey);
        if (!ccx.IsValid())
        {
            LogPrintf("%s: invalid export in tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
            continue;
        }

        if (ccx.destCurrencyID == failedCurrencyDest)
        {
            continue;
        }

        CChainNotarizationData cnd;
        CPBaaSNotarization priorChainNotarization;
        CCurrencyDefinition refundingPBaaSChain;
        bool isRefundingSeparateChain = false;
        if (GetNotarizationData(ccx.destCurrencyID, cnd) &&
            cnd.IsValid() &&
            cnd.IsConfirmed() &&
            (priorChainNotarization = cnd.vtx[cnd.lastConfirmed].second).IsValid() &&
            priorChainNotarization.currencyState.IsValid())
        {
            // if this is a refund from an alternate chain, we accept it to this chain if we are the launch chain
            if (priorChainNotarization.currencyState.IsRefunding() &&
                (refundingPBaaSChain = ConnectedChains.GetCachedCurrency(ccx.destCurrencyID)).IsValid() &&
                refundingPBaaSChain.launchSystemID == ASSETCHAINS_CHAINID &&
                refundingPBaaSChain.systemID != ASSETCHAINS_CHAINID)
            {
                isRefundingSeparateChain = true;
            }
        }

        if (isRefundingSeparateChain)
        {
            printf("%s: processing refund from PBaaS chain currency %s\n", __func__, refundingPBaaSChain.name.c_str());
        }

        // get reserve deposits for destination currency of export. these will be available whether the source is same chain
        // or an external chain/gateway
        std::vector<CInputDescriptor> localDeposits;
        std::vector<CInputDescriptor> crossChainDeposits;

        if (ccx.sourceSystemID != ccx.destCurrencyID)
        {
            if (!ConnectedChains.GetReserveDeposits(ccx.destCurrencyID, view, localDeposits))
            {
                LogPrintf("%s: cannot get reserve deposits for export in tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }
        }

        // DEBUG OUTPUT
        /* for (auto &oneDepositIn : localDeposits)
        {
            UniValue scrUni(UniValue::VOBJ);
            ScriptPubKeyToUniv(oneDepositIn.scriptPubKey, scrUni, false);
            printf("%s: one deposit hash: %s, vout: %u, scriptdecode: %s, amount: %s\n",
                __func__,
                oneDepositIn.txIn.prevout.hash.GetHex().c_str(),
                oneDepositIn.txIn.prevout.n,
                scrUni.write(1,2).c_str(),
                ValueFromAmount(oneDepositIn.nValue).write().c_str());
        } // DEBUG OUTPUT END */

        // if importing from another system/chain, get reserve deposits of source system to make available to import as well
        if (isRefundingSeparateChain || useProofs)
        {
            if (!ConnectedChains.GetReserveDeposits(isRefundingSeparateChain ? refundingPBaaSChain.systemID : sourceSystemID, view, crossChainDeposits))
            {
                LogPrintf("%s: cannot get reserve deposits for cross-system export in tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }

            // DEBUG OUTPUT
            /* for (auto &oneDepositIn : crossChainDeposits)
            {
                UniValue scrUni(UniValue::VOBJ);
                ScriptPubKeyToUniv(oneDepositIn.scriptPubKey, scrUni, false);
                printf("%s: one crosschain deposit hash: %s, vout: %u, scriptdecode: %s, amount: %s\n",
                    __func__,
                    oneDepositIn.txIn.prevout.hash.GetHex().c_str(),
                    oneDepositIn.txIn.prevout.n,
                    scrUni.write(1,2).c_str(),
                    ValueFromAmount(oneDepositIn.nValue).write().c_str());
            } // DEBUG OUTPUT END */
        }

        // now, we have all reserve deposits for both local destination and importing currency, we can use both,
        // but must keep track of them separately, first, get last import for the current export
        CTransaction lastImportTx;
        int32_t outputNum;
        CCrossChainImport lastCCI;
        uint256 lastImportTxID;

        auto lastImportIt = newImports.find(ccx.destCurrencyID);
        if (lastImportIt != newImports.end())
        {
            lastImportTx = lastImportIt->second.back().second;
            outputNum = lastImportIt->second.back().first;
            lastCCI = CCrossChainImport(lastImportTx.vout[outputNum].scriptPubKey);
            lastImportTxID = lastImportTx.GetHash();
        }
        else if (nHeight && !GetLastImport(ccx.destCurrencyID, lastImportTx, outputNum))
        {
            LogPrintf("%s: cannot find last import for export %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), outputNum);
            failedCurrencyDest = ccx.destCurrencyID;
            continue;
        }
        else if (nHeight)
        {
            lastCCI = CCrossChainImport(lastImportTx.vout[outputNum].scriptPubKey);
            lastImportTxID = lastImportTx.GetHash();
        }

        CCurrencyDefinition destCur = ConnectedChains.GetCachedCurrency(ccx.destCurrencyID);
        if (!lastCCI.IsValid() || !destCur.IsValid())
        {
            LogPrintf("%s: invalid destination currency for export %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), outputNum);
            failedCurrencyDest = ccx.destCurrencyID;
            continue;
        }

        // now, we have:
        // 1. last import output + potentially additional reserve transfer storage outputs to spend from prior import
        // 2. reserve transfers for next import
        // 3. proof notarization if export is from off chain
        // 4. reserve deposits for destination currency on this chain. which will matter if it holds reserves
        // 5. reserve deposits for source system, which will matter if we have sent currencies to it that will be used
        // 6. destination currency definition

        // either:
        // 1) it is a gateway on our current chain, and we are creating imports for the system represented by the gateway from this system
        //    or we are importing into this system from the gateway system
        // 2) we are creating an import for a fractional currency on this chain, or
        // 3) destination is a PBaaS currency, which is either the native currency, if we are the PBaaS chain or a token on our current chain.
        //    We are creating imports for this system, which is the PBaaS chain, to receive exports from our notary chain, which is its parent,
        //    or we are creating imports to receive exports from the PBaaS chain.
        if (!(isRefundingSeparateChain && sourceSystemID == ASSETCHAINS_CHAINID) &&
            !((destCur.IsGateway() && destCur.systemID == ASSETCHAINS_CHAINID) &&
                (sourceSystemID == ASSETCHAINS_CHAINID || sourceSystemID == ccx.destCurrencyID)) &&
            !(sourceSystemID == destCur.systemID && destCur.systemID == ASSETCHAINS_CHAINID) &&
            !(destCur.IsPBaaSChain() &&
                (sourceSystemID == ccx.destCurrencyID ||
                  (ccx.destCurrencyID == ASSETCHAINS_CHAINID))) &&
            !(sourceSystemID != ccx.destSystemID))
        {
            LogPrintf("%s: invalid currency for export/import %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), outputNum);
            failedCurrencyDest = ccx.destCurrencyID;
            continue;
        }

        // if we are importing from another system, find the last import from that system and consider this another one
        if (useProofs)
        {
            if (sourceOutputNum == -1 && nHeight && !GetLastSourceImport(ccx.sourceSystemID, lastSourceImportTx, sourceOutputNum))
            {
                LogPrintf("%s: cannot find last source system import for export %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), sourceOutputNum);
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }
            else if (nHeight)
            {
                lastSourceCCI = CCrossChainImport(lastSourceImportTx.vout[sourceOutputNum].scriptPubKey);
                lastSourceImportTxID = lastSourceImportTx.GetHash();
            }
        }

        CPBaaSNotarization lastNotarization;
        CInputDescriptor lastNotarizationOut;
        std::vector<CReserveTransfer> lastReserveTransfers;
        CCrossChainExport lastCCX;
        CCrossChainImport lastSysCCI;
        int32_t sysCCIOutNum = -1, evidenceOutNumStart = -1, evidenceOutNumEnd = -1;

        int32_t notarizationOutNum;
        CValidationState state;

        uint160 destCurID = destCur.GetID();

        // if not the initial import in the thread, it should have a valid prior notarization as well
        // the notarization of the initial import may be superceded by pre-launch exports
        if (nHeight && lastCCI.IsPostLaunch())
        {
            if (!lastCCI.GetImportInfo(lastImportTx,
                                       nHeight,
                                       outputNum,
                                       lastCCX,
                                       lastSysCCI,
                                       sysCCIOutNum,
                                       lastNotarization,
                                       notarizationOutNum,
                                       evidenceOutNumStart,
                                       evidenceOutNumEnd,
                                       lastReserveTransfers,
                                       state))
            {
                LogPrintf("%s: currency: %s, %u - %s\n", __func__, destCur.name.c_str(), state.GetRejectCode(), state.GetRejectReason().c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }

            lastNotarizationOut = CInputDescriptor(lastImportTx.vout[notarizationOutNum].scriptPubKey,
                                                   lastImportTx.vout[notarizationOutNum].nValue,
                                                   CTxIn(lastImportTxID, notarizationOutNum));

            // verify that the current export from the source system spends the prior export from the source system
            if (useProofs &&
                !(ccx.IsChainDefinition() ||
                  lastSourceCCI.exportTxId.IsNull() ||
                  (ccx.firstInput > 0 &&
                   exportTx.vin[ccx.firstInput - 1].prevout.hash == lastSourceCCI.exportTxId &&
                   exportTx.vin[ccx.firstInput - 1].prevout.n == lastSourceCCI.exportTxOutNum)))
            {
                if (LogAcceptCategory("crosschainimports"))
                {
                    printf("%s: out of order export for cci:\n%s\n, expected: (%s, %d) found: (%s, %u)\n",
                        __func__,
                        lastSourceCCI.ToUniValue().write(1,2).c_str(),
                        lastSourceCCI.exportTxId.GetHex().c_str(),
                        lastSourceCCI.exportTxOutNum,
                        exportTx.vin[ccx.firstInput - 1].prevout.hash.GetHex().c_str(),
                        exportTx.vin[ccx.firstInput - 1].prevout.n);
                    LogPrintf("%s: out of order export %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), sourceOutputNum);
                }
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }
            else if (useProofs)
            {
                // make sure we have the latest, confirmed proof roots to prove this import
                if (proofNotarization.proposer.AuxDestCount())
                {
                    lastNotarization.proposer = proofNotarization.proposer.GetAuxDest(0);
                }
                else
                {
                    lastNotarization.proposer = DestinationToTransferDestination(TransferDestinationToDestination(proofNotarization.proposer));
                }

                lastNotarization.proofRoots[sourceSystemID] = proofNotarization.proofRoots[sourceSystemID];
                if (lastNotarization.proofRoots.count(ASSETCHAINS_CHAINID))
                {
                    lastNotarization.proofRoots[ASSETCHAINS_CHAINID] = proofNotarization.proofRoots[ASSETCHAINS_CHAINID];
                }
            }
        }
        else if (nHeight)
        {
            // the first import ever. it is either launched from the launch chain, which is running
            // or as a new chain, started from a different launch chain
            if (useProofs)
            {
                LogPrintf("%s: invalid first import for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }

            // first import, but not first block, so not PBaaS launch - last import has no evidence to spend
            CChainNotarizationData cnd;
            std::vector<std::pair<CTransaction, uint256>> notarizationTxes;

            if (!GetNotarizationData(ccx.destCurrencyID, cnd, &notarizationTxes) || !cnd.IsConfirmed())
            {
                LogPrintf("%s: cannot get notarization for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }

            // if we are running on the chain of this currency, get our
            // most recent notarization, even if it's from the mempool
            if (destCur.systemID == ASSETCHAINS_CHAINID)
            {
                auto lastNotarizationRef = GetLastConfirmedNotarization(destCurID, nHeight + 1);
                if (!std::get<0>(lastNotarizationRef) && std::get<2>(lastNotarizationRef).IsValid())
                {
                    cnd.vtx[0].first = std::get<1>(lastNotarizationRef);
                    cnd.vtx[0].second = std::get<2>(lastNotarizationRef);
                    if (!cnd.vtx[0].first.GetOutputTransaction(notarizationTxes[0].first, notarizationTxes[0].second))
                    {
                        LogPrintf("%s: cannot get notarization tx for currency %s on system %s\n", __func__, destCur.name.c_str());
                        failedCurrencyDest = ccx.destCurrencyID;
                        continue;
                    }
                }
            }

            lastNotarization = cnd.vtx[cnd.lastConfirmed].second;

            if (!lastNotarization.IsValid())
            {
                LogPrintf("%s: invalid notarization for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }
            lastNotarizationOut = CInputDescriptor(notarizationTxes[cnd.lastConfirmed].first.vout[cnd.vtx[cnd.lastConfirmed].first.n].scriptPubKey,
                                                   notarizationTxes[cnd.lastConfirmed].first.vout[cnd.vtx[cnd.lastConfirmed].first.n].nValue,
                                                   CTxIn(cnd.vtx[cnd.lastConfirmed].first));
        }
        else // height is 0 - this is first block of PBaaS chain
        {
            if (!(proofNotarization.currencyID == ccx.destCurrencyID || proofNotarization.currencyStates.count(ccx.destCurrencyID)))
            {
                // last notarization is coming from the launch chain at height 0
                lastNotarization = CPBaaSNotarization(ccx.destCurrencyID,
                                                      proofNotarization.currencyID ==
                                                        ccx.destCurrencyID ? proofNotarization.currencyState :
                                                                             proofNotarization.currencyStates[ccx.destCurrencyID],
                                                      0,
                                                      CUTXORef(),
                                                      0);
                lastNotarizationOut = CInputDescriptor(CScript(), 0, CTxIn());
            }
        }

        CPBaaSNotarization newNotarization;
        uint256 transferHash;
        std::vector<CReserveTransfer> exportTransfers = oneIT.second;

        std::vector<CTxOut> newOutputs;
        CCurrencyValueMap importedCurrency, gatewayDepositsUsed, spentCurrencyOut;

        // if we are transitioning from export to import, allow the function to set launch clear on the currency
        if (lastNotarization.currencyState.IsLaunchClear() && !lastCCI.IsInitialLaunchImport())
        {
            lastNotarization.SetPreLaunch();
            lastNotarization.currencyState.SetLaunchCompleteMarker(false);
            lastNotarization.currencyState.SetLaunchClear(false);
            lastNotarization.currencyState.SetPrelaunch(true);
        }
        else if (lastNotarization.IsValid())
        {
            if (lastCCI.IsInitialLaunchImport())
            {
                if (ccx.IsChainDefinition() ||
                    lastNotarization.currencyState.IsPrelaunch() ||
                    (sourceSystemDef.GetID() == ASSETCHAINS_CHAINID && !lastNotarization.currencyState.IsLaunchClear()))
                {
                    LogPrintf("%s: Post initial launch state import cannot regress to pre-launch or launch clear for %s\n", __func__, ConnectedChains.GetFriendlyCurrencyName(ccx.destCurrencyID).c_str());
                    failedCurrencyDest = ccx.destCurrencyID;
                    continue;
                }
                lastNotarization.SetPreLaunch(false);
                lastNotarization.currencyState.SetPrelaunch(false);
                lastNotarization.currencyState.SetLaunchClear(false);
            }
            else if (ccx.IsChainDefinition() &&
                    !(lastNotarization.currencyState.IsPrelaunch() &&
                      lastNotarization.currencyState.IsLaunchClear()))
            {
                LogPrint("notarization", "%s: Chain definition export may only be imported on first launch import %s\n", __func__, ConnectedChains.GetFriendlyCurrencyName(ccx.destCurrencyID).c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }
        }

        // entropy hash calculation & import verification depends on our import notarization height not exceeding chain active height
        uint32_t nextHeight = useProofs && destCur.SystemOrGatewayID() == ASSETCHAINS_CHAINID || destCurID == ASSETCHAINS_CHAINID ?
            nHeight : std::min(nHeight, std::max(ccx.sourceHeightEnd, lastNotarization.notarizationHeight));

        if (ccx.IsPostlaunch() || lastNotarization.IsLaunchComplete())
        {
            lastNotarization.currencyState.SetLaunchCompleteMarker();
        }

        // this is a place where we can
        // provide a callout for arbitrage and potentially get an additional reserve transfer
        // input for this import. we should also add it to the exportTransfers vector
        // with the arbitrage flag set
        std::vector<std::tuple<CInputDescriptor, CReserveTransfer, CTransaction>> arbitrageTransfersIn;
        if (ConnectedChains.AutoArbitrageEnabled(nHeight) &&
            VERUS_ARBITRAGE_CURRENCIES.size() &&
            destCur.IsFractional() &&
            lastNotarization.IsLaunchComplete() &&
            !lastNotarization.IsRefunding())
        {
            CCurrencyValueMap arbitrageCurrencies(VERUS_ARBITRAGE_CURRENCIES, std::vector<int64_t>(VERUS_ARBITRAGE_CURRENCIES.size(), 1));
            CCurrencyValueMap currenciesInBasket(lastNotarization.currencyState.currencies,
                                                 std::vector<int64_t>(lastNotarization.currencyState.currencies.size(), 1));
            currenciesInBasket.valueMap.insert(std::make_pair(lastNotarization.currencyID, 1));

            // if we have 1 or more after this, we can arb for guaranteed returns
            arbitrageCurrencies = arbitrageCurrencies.IntersectingValues(currenciesInBasket);
            std::set<uint160> arbitrageSet, acceptSet;
            for (auto &oneCur : arbitrageCurrencies.valueMap)
            {
                arbitrageSet.insert(oneCur.first);
            }

            for (auto &oneCur : currenciesInBasket.valueMap)
            {
                acceptSet.insert(oneCur.first);
            }

            std::vector<
                std::multimap<std::tuple<int, uint160, uint160, int64_t, int64_t>, std::pair<std::pair<int, CCurrencyValueMap>, std::pair<CInputDescriptor, CTransaction>>>
                       > arbOffers;

            for (auto &oneCur : arbitrageCurrencies.valueMap)
            {
                auto tempArbSet = acceptSet;
                tempArbSet.erase(oneCur.first);
                if (oneCur.first != lastNotarization.currencyID)
                {
                    auto oneArbOfferVec = GetOfferMap(oneCur.first, true, true, false, tempArbSet);
                    if (oneArbOfferVec.size())
                    {
                        arbOffers.push_back(oneArbOfferVec);
                    }
                }
            }

            if (!SelectArbitrageFromOffers(arbOffers,
                                           lastNotarization,
                                           sourceSystemDef,
                                           destCur,
                                           ccx.sourceHeightStart,
                                           nextHeight,
                                           exportTransfers,
                                           transferHash,
                                           newNotarization,
                                           newOutputs,
                                           importedCurrency,
                                           gatewayDepositsUsed,
                                           spentCurrencyOut,
                                           ccx.exporter,
                                           arbitrageCurrencies,
                                           arbitrageTransfersIn))
            {
                LogPrintf("%s: invalid export or arbitrage offers for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }
        }
        else
        {
            if (!lastNotarization.NextNotarizationInfo(sourceSystemDef,
                                                       destCur,
                                                       ccx.sourceHeightStart,
                                                       nextHeight,
                                                       exportTransfers,
                                                       transferHash,
                                                       newNotarization,
                                                       newOutputs,
                                                       importedCurrency,
                                                       gatewayDepositsUsed,
                                                       spentCurrencyOut,
                                                       ccx.exporter,
                                                       ccx.IsClearLaunch()))
            {
                LogPrintf("%s: invalid export for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }
        }

        if (LogAcceptCategory("defi"))
        {
            LogPrintf("Using lastNotarization: %s, nextHeight: %u, expectedEntropyHash: %s\n",
                        lastNotarization.ToUniValue().write(1,2).c_str(),
                        nextHeight,
                        EntropyHashFromHeight(CBlockIndex::BlockEntropyKey(), nextHeight, lastNotarization.currencyID).GetHex().c_str());
            LogPrint("crosschainimports", "Expected next notarization %s\n", newNotarization.ToUniValue().write(1,2).c_str());
        }

        // after the last clear launch export is imported, we have completed launch
        if (ccx.IsClearLaunch())
        {
            newNotarization.SetLaunchComplete();
            newNotarization.currencyState.SetLaunchCompleteMarker();
        }

        newNotarization.prevNotarization = CUTXORef(lastNotarizationOut.txIn.prevout.hash, lastNotarizationOut.txIn.prevout.n);

        CAmount newPrimaryCurrency = newNotarization.currencyState.primaryCurrencyOut;
        CCurrencyValueMap incomingCurrency = importedCurrency + gatewayDepositsUsed;
        if (newPrimaryCurrency > 0)
        {
            incomingCurrency.valueMap[destCurID] += newPrimaryCurrency;
        }
        CCurrencyValueMap newLocalReserveDeposits = incomingCurrency.SubtractToZero(spentCurrencyOut).CanonicalMap();
        CCurrencyValueMap newLocalDepositsRequired = (((incomingCurrency - spentCurrencyOut) - newLocalReserveDeposits).CanonicalMap() * -1);
        if (newPrimaryCurrency < 0)
        {
            // we need to come up with this currency, as it will be burned
            incomingCurrency.valueMap[destCurID] += newPrimaryCurrency;
            newLocalDepositsRequired.valueMap[destCurID] -= newPrimaryCurrency;
        }

        int32_t transitionBlocks = (PBAAS_TESTMODE ? ((24 * 60 * 60) / ConnectedChains.ThisChain().blockTime) : 100) - 1;
        bool clearConvertTransition = IsVerusMainnetActive() &&
                                      destCur.IsFractional() &&
                                      !ConnectedChains.CheckClearConvert(std::max(((int32_t)nHeight) - transitionBlocks, 1)) &&
                                      ConnectedChains.CheckClearConvert(nHeight + 1) &&
                                      !ConnectedChains.CheckClearConvert(lastNotarization.notarizationHeight) && ConnectedChains.CheckClearConvert(nHeight);

        if (lastNotarization.currencyState.IsLaunchCompleteMarker() &&
            clearConvertTransition)
        {
            CCurrencyValueMap localExtra;

            for (auto &oneDeposit : localDeposits)
            {
                localExtra += oneDeposit.scriptPubKey.ReserveOutValue();
            }

            CAmount extraPrimary = localExtra.valueMap[destCurID];
            newLocalDepositsRequired.valueMap[destCurID] = extraPrimary;
        }

        LogPrint("crosschainimports", "%s: newNotarization:\n%s\n", __func__, newNotarization.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: ccx.totalAmounts: %s\ngatewayDepositsUsed: %s\nimportedCurrency: %s\nspentCurrencyOut: %s\n",
            __func__,
            ccx.totalAmounts.ToUniValue().write(1,2).c_str(),
            gatewayDepositsUsed.ToUniValue().write(1,2).c_str(),
            importedCurrency.ToUniValue().write(1,2).c_str(),
            spentCurrencyOut.ToUniValue().write(1,2).c_str());

        LogPrint("crosschainimports", "%s: incomingCurrency: %s\ncurrencyChange: %s\nnewLocalDepositsRequired: %s\n",
            __func__,
            incomingCurrency.ToUniValue().write(1,2).c_str(),
            newLocalReserveDeposits.ToUniValue().write(1,2).c_str(),
            newLocalDepositsRequired.ToUniValue().write(1,2).c_str());

        // create the import
        CCrossChainImport cci = CCrossChainImport(sourceSystemID,
                                                  ccx.sourceHeightEnd,
                                                  destCurID,
                                                  ccx.totalAmounts,
                                                  lastCCI.totalReserveOutMap,
                                                  newOutputs.size(),
                                                  transferHash,
                                                  oneIT.first.first.txIn.prevout.hash,
                                                  oneIT.first.first.txIn.prevout.n,
                                                  CCrossChainImport::FLAG_POSTLAUNCH +
                                                    ((lastCCI.IsDefinitionImport() && !(sourceSystemDef.IsPBaaSChain() && sourceSystemID != ASSETCHAINS_CHAINID)) ?
                                                        CCrossChainImport::FLAG_INITIALLAUNCHIMPORT :
                                                        0));
        cci.SetSameChain(!useProofs);

        TransactionBuilder tb = TransactionBuilder(Params().GetConsensus(), nHeight + 1);

        CCcontract_info CC;
        CCcontract_info *cp;

        // now add the import itself
        cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
        std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});
        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci)), 0);

        // get the source system import as well
        CCrossChainImport sysCCI;
        if (useProofs && cci.sourceSystemID != cci.importCurrencyID)
        {
            // we need a new import for the source system
            sysCCI = cci;
            sysCCI.importCurrencyID = sysCCI.sourceSystemID;
            sysCCI.flags |= sysCCI.FLAG_SOURCESYSTEM;

            // for exports to the native chain, the system export thread is merged with currency export, so no need to go to next
            if (cci.importCurrencyID != ASSETCHAINS_CHAINID)
            {
                // the source of the export is an external system
                // only in PBaaS chains do we assume the export out increments
                // for gateways or other chains, they must use the same output number and adjust on the other
                // side as needed

                // TODO: this requirement needs to be cleaned up to provide for
                // the ETH-like model, which doesn't benefit from this and the PBaaS model, which does
                // being an option for external chains as well
                if (sourceSystemDef.IsPBaaSChain())
                {
                    sysCCI.exportTxOutNum++;                        // source thread output is +1 from the input
                }
            }
            tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &sysCCI)), 0);
        }

        // add notarization first, so it will be just after the import
        cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &newNotarization)), 0);

        // add the export evidence, null for same chain or reference specific notarization + (proof + reserve transfers) if sourced from external chain
        // add evidence first, then notarization, then import, add reserve deposits after that, if necessary

        if (useProofs)
        {
            cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

            CDataStream ds(SER_DISK, PROTOCOL_VERSION);

            // if we need to put the partial transaction proof and follow it with reserve transfers, do it
            // now, we need to put the launch notarization evidence, followed by the import outputs
            CCrossChainProof evidenceProof;
            evidenceProof << oneIT.first.second;
            CNotaryEvidence evidence = CNotaryEvidence(destCurID,
                                                       CUTXORef(confirmedSourceNotarization.hash, confirmedSourceNotarization.n),
                                                       CNotaryEvidence::STATE_CONFIRMED,
                                                       evidenceProof,
                                                       CNotaryEvidence::TYPE_IMPORT_PROOF);

            int serSize = GetSerializeSize(ds, evidence);

            COptCCParams chkP;
            if (!MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &evidence)).IsPayToCryptoCondition(chkP, false))
            {
                LogPrintf("%s: failed to package import evidence from system %s\n", __func__, EncodeDestination(CIdentityID(destCurID)).c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }

            // the value should be considered for reduction
            if (chkP.AsVector().size() >= CScript::MAX_SCRIPT_ELEMENT_SIZE)
            {
                CNotaryEvidence emptyEvidence;
                int baseOverhead = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &emptyEvidence)).size() + 128;
                auto evidenceVec = evidence.BreakApart(CScript::MAX_SCRIPT_ELEMENT_SIZE - baseOverhead);
                if (!evidenceVec.size())
                {
                    LogPrintf("%s: failed to package evidence from system %s\n", __func__, EncodeDestination(CIdentityID(ccx.sourceSystemID)).c_str());
                    failedCurrencyDest = ccx.destCurrencyID;
                    continue;
                }
                for (auto &oneProof : evidenceVec)
                {
                    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
                    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &oneProof)), 0);
                }
            }
            else
            {
                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &evidence)), 0);
            }

            // supplemental export evidence is posted as a supplemental export
            cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

            // now add all reserve transfers in supplemental outputs
            // ensure that the output doesn't exceed script size limit
            auto transferIT = exportTransfers.begin();
            while (transferIT != exportTransfers.end())
            {
                int transferCount = exportTransfers.end() - transferIT;
                if (transferCount > 25)
                {
                    transferCount = 25;
                }

                CCrossChainExport rtSupplement = ccx;
                rtSupplement.flags = ccx.FLAG_EVIDENCEONLY + ccx.FLAG_SUPPLEMENTAL;
                rtSupplement.reserveTransfers.assign(transferIT, transferIT + transferCount);
                CScript supScript = MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &rtSupplement));
                while (GetSerializeSize(CTxOut(0, supScript), SER_NETWORK, PROTOCOL_VERSION) > supScript.MAX_SCRIPT_ELEMENT_SIZE)
                {
                    transferCount--;
                    rtSupplement.reserveTransfers.assign(transferIT, transferIT + transferCount);
                    supScript = MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &rtSupplement));
                }
                tb.AddTransparentOutput(supScript, 0);
                transferIT += transferCount;
            }
        }

        // add all importing and conversion outputs
        for (auto oneOut : newOutputs)
        {
            tb.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nValue);
        }

        // now, we need to spend previous import, notarization, and evidence or export finalization from export

        // spend evidence or export finalization if necessary
        // if we use proofs, spend the prior, unless we have no prior proofs to spend
        if (lastCCI.IsValid() && !lastImportTxID.IsNull())
        {
            // spend last import
            tb.AddTransparentInput(COutPoint(lastImportTxID, outputNum), lastImportTx.vout[outputNum].scriptPubKey, lastImportTx.vout[outputNum].nValue);

            // if we should add a source import input
            if (useProofs && cci.sourceSystemID != cci.importCurrencyID)
            {
                tb.AddTransparentInput(COutPoint(lastSourceImportTxID, sourceOutputNum),
                                       lastSourceImportTx.vout[sourceOutputNum].scriptPubKey, lastSourceImportTx.vout[sourceOutputNum].nValue);
            }

            // if we qualify to add and also have an additional reserve transfer
            // add it as an input
            if (arbitrageTransfersIn.size())
            {
                tb.AddTransparentInput(std::get<0>(arbitrageTransfersIn[0]).txIn.prevout, std::get<0>(arbitrageTransfersIn[0]).scriptPubKey, std::get<0>(arbitrageTransfersIn[0]).nValue);
            }

            if (!lastNotarizationOut.txIn.prevout.hash.IsNull())
            {
                // and its notarization
                tb.AddTransparentInput(lastNotarizationOut.txIn.prevout, lastNotarizationOut.scriptPubKey, lastNotarizationOut.nValue);
            }

            if (!lastCCI.IsDefinitionImport() && lastCCI.sourceSystemID != ASSETCHAINS_CHAINID && evidenceOutNumStart >= 0)
            {
                for (int i = evidenceOutNumStart; i <= evidenceOutNumEnd; i++)
                {
                    const CCoins *pCoins = view.AccessCoins(lastImportTxID);
                    // be robust to it being spent or not, but do
                    // clean up the UTXO by spending, if that is an option
                    if (pCoins && pCoins->IsAvailable(i))
                    {
                        tb.AddTransparentInput(COutPoint(lastImportTxID, i), lastImportTx.vout[i].scriptPubKey, lastImportTx.vout[i].nValue);
                    }
                }
            }

            if (!useProofs)
            {
                // if same chain and export has a finalization, spend it on import
                CObjectFinalization of;
                COptCCParams p;
                if (exportTx.vout.size() > (oneIT.first.first.txIn.prevout.n + 1) &&
                    exportTx.vout[oneIT.first.first.txIn.prevout.n + 1].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_FINALIZE_EXPORT &&
                    p.vData.size() &&
                    (of = CObjectFinalization(p.vData[0])).IsValid())
                {
                    tb.AddTransparentInput(COutPoint(oneIT.first.first.txIn.prevout.hash, oneIT.first.first.txIn.prevout.n + 1),
                                                        exportTx.vout[oneIT.first.first.txIn.prevout.n + 1].scriptPubKey,
                                                        exportTx.vout[oneIT.first.first.txIn.prevout.n + 1].nValue);
                }
            }
        }

        // now, get all reserve deposits and change for both gateway reserve deposits and local reserve deposits
        CCurrencyValueMap gatewayChange;

        // add gateway deposit inputs and make a change output for those to the source system's deposits, if necessary
        std::vector<CInputDescriptor> depositsToUse;
        cp = CCinit(&CC, EVAL_RESERVE_DEPOSIT);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

        if (gatewayDepositsUsed.valueMap.size())
        {
            CCurrencyValueMap totalDepositsInput;

            // find all deposits intersecting with target currencies
            for (auto &oneDeposit : crossChainDeposits)
            {
                CCurrencyValueMap oneDepositVal = oneDeposit.scriptPubKey.ReserveOutValue();
                if (oneDeposit.nValue)
                {
                    oneDepositVal.valueMap[ASSETCHAINS_CHAINID] = oneDeposit.nValue;
                }
                if (gatewayDepositsUsed.Intersects(oneDepositVal))
                {
                    totalDepositsInput += oneDepositVal;
                    depositsToUse.push_back(oneDeposit);
                }
            }

            gatewayChange = (totalDepositsInput - gatewayDepositsUsed).CanonicalMap();

            LogPrint("crosschainimports", "%s: gatewayDepositsUsed: %s\n", __func__, gatewayDepositsUsed.ToUniValue().write(1,2).c_str());
            LogPrint("crosschainimports", "%s: gatewayChange: %s\n", __func__, gatewayChange.ToUniValue().write(1,2).c_str());

            // we should always be able to fulfill
            // gateway despoit requirements, or this is an error
            if (gatewayChange.HasNegative())
            {
                LogPrintf("%s: insufficient funds for gateway reserve deposits from system %s\n", __func__, EncodeDestination(CIdentityID(ccx.sourceSystemID)).c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }
        }

        // the amount being imported is under the control of the exporting system and
        // will either be minted by the import from that system or spent on this chain from its reserve deposits
        // any remaining unmet output requirements must be met by local chain deposits as a result of conversions
        // conversion outputs may only be of the destination currency itself, or in the case of a fractional currency,
        // the currency or its reserves.
        //
        // if this is a local import, local requirements are any spent currency besides
        //
        // change will all accrue to reserve deposits
        //

        // if this import is from another system, we will need local imports or gateway deposits to
        // cover the imported currency amount. if it is from this system, the reserve deposits are already
        // present from the export, which is also on this chain
        CCurrencyValueMap checkImportedCurrency;
        CCurrencyValueMap checkRequiredDeposits;
        if (cci.sourceSystemID != ASSETCHAINS_CHAINID &&
            (!newNotarization.currencyState.IsLaunchConfirmed() || newNotarization.currencyState.IsLaunchCompleteMarker()))
        {
            if (!ConnectedChains.CurrencyImportStatus(cci.importValue,
                                                      cci.sourceSystemID,
                                                      destCur.systemID,
                                                      checkImportedCurrency,
                                                      checkRequiredDeposits))
            {
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }
        }

        LogPrint("crosschainimports", "%s: newNotarization.currencyState: %s\n", __func__, newNotarization.currencyState.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: cci: %s\n", __func__, cci.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: spentcurrencyout: %s\n", __func__, spentCurrencyOut.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: newcurrencyin: %s\n", __func__, incomingCurrency.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: importedCurrency: %s\n", __func__, importedCurrency.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: localdepositrequirements: %s\n", __func__, newLocalDepositsRequired.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: checkImportedCurrency: %s\n", __func__, checkImportedCurrency.ToUniValue().write(1,2).c_str());
        LogPrint("crosschainimports", "%s: checkRequiredDeposits: %s\n", __func__, checkRequiredDeposits.ToUniValue().write(1,2).c_str());

        // add local reserve deposit inputs and determine change
        if (newLocalDepositsRequired.valueMap.size() ||
            localDeposits.size() ||
            incomingCurrency.valueMap.size())
        {
            CCurrencyValueMap totalDepositsInput;

            // find all deposits intersecting with target currencies
            for (auto &oneDeposit : localDeposits)
            {
                CCurrencyValueMap oneDepositVal = oneDeposit.scriptPubKey.ReserveOutValue();
                if (oneDeposit.nValue)
                {
                    oneDepositVal.valueMap[ASSETCHAINS_CHAINID] = oneDeposit.nValue;
                }
                if (newLocalDepositsRequired.Intersects(oneDepositVal))
                {
                    totalDepositsInput += oneDepositVal;
                    depositsToUse.push_back(oneDeposit);
                }
            }

            CCurrencyValueMap arbitrageDeposits;
            // all currencies from arbitragetransfers are local reserve deposits
            if (arbitrageTransfersIn.size())
            {
                arbitrageDeposits = std::get<0>(arbitrageTransfersIn[0]).scriptPubKey.ReserveOutValue();
                if (std::get<0>(arbitrageTransfersIn[0]).nValue)
                {
                    arbitrageDeposits.valueMap[ASSETCHAINS_CHAINID] = std::get<0>(arbitrageTransfersIn[0]).nValue;
                }
            }

            newLocalReserveDeposits = ((totalDepositsInput + incomingCurrency + arbitrageDeposits) - spentCurrencyOut).CanonicalMap();

            LogPrint("crosschainimports", "%s: totalDepositsInput: %s\nincomingPlusDepositsMinusSpent: %s\n",
                __func__,
                totalDepositsInput.ToUniValue().write(1,2).c_str(),
                newLocalReserveDeposits.ToUniValue().write(1,2).c_str()); //*/

            // we should always be able to fulfill
            // local deposit requirements, or this is an error
            if (newLocalReserveDeposits.HasNegative())
            {
                LogPrintf("%s: insufficient funds for local reserve deposits for currency %s, have:\n%s, need:\n%s\n",
                          __func__,
                          EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str(),
                          (totalDepositsInput + incomingCurrency).ToUniValue().write(1,2).c_str(),
                          spentCurrencyOut.ToUniValue().write(1,2).c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }
            if (clearConvertTransition)
            {
                newLocalReserveDeposits.valueMap.erase(destCurID);
            }
        }

        // add local deposit inputs
        for (auto oneOut : depositsToUse)
        {
            tb.AddTransparentInput(oneOut.txIn.prevout, oneOut.scriptPubKey, oneOut.nValue);
        }

        /*for (auto &oneIn : tb.mtx.vin)
        {
            UniValue scriptObj(UniValue::VOBJ);
            printf("%s: oneInput - hash: %s, n: %d\n", __func__, oneIn.prevout.hash.GetHex().c_str(), oneIn.prevout.n);
        }
        //*/

        // we will keep reserve deposit change to single currency outputs to ensure aggregation of like currencies and
        // prevent fragmentation edge cases
        for (auto &oneChangeVal : gatewayChange.valueMap)
        {
            // dust rules don't apply
            if (oneChangeVal.second)
            {
                CReserveDeposit rd = CReserveDeposit(isRefundingSeparateChain ? refundingPBaaSChain.systemID : sourceSystemID, CCurrencyValueMap());;
                CAmount nativeOutput = 0;
                rd.reserveValues.valueMap[oneChangeVal.first] = oneChangeVal.second;
                if (oneChangeVal.first == ASSETCHAINS_CHAINID)
                {
                    nativeOutput = oneChangeVal.second;
                }
                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &rd)), nativeOutput);
            }
        }

        // we will keep reserve deposit change to single currency outputs to ensure aggregation of like currencies and
        // prevent fragmentation edge cases
        for (auto &oneChangeVal : newLocalReserveDeposits.valueMap)
        {
            // dust rules don't apply
            if (oneChangeVal.second)
            {
                CReserveDeposit rd = CReserveDeposit(ccx.destCurrencyID, CCurrencyValueMap());;
                CAmount nativeOutput = 0;
                rd.reserveValues.valueMap[oneChangeVal.first] = oneChangeVal.second;
                if (oneChangeVal.first == ASSETCHAINS_CHAINID)
                {
                    nativeOutput = oneChangeVal.second;
                }
                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &rd)), nativeOutput);
            }
        }

        CCurrencyValueMap reserveInMap = CCurrencyValueMap(newNotarization.currencyState.currencies,
                                                           newNotarization.currencyState.reserveIn).CanonicalMap();

        // ins and outs are correct. now calculate the fee correctly here and set the transaction builder accordingly
        // to prevent an automatic change output. we could just let it go and have a setting to stop creation of a change output,
        // but this is a nice doublecheck requirement
        LogPrint("crosschainimports", "%s: reserveInMap:\n%s\nspentCurrencyOut:\n%s\nccx.totalAmounts:\n%s\nccx.totalFees:\n%s\n",
                __func__,
                reserveInMap.ToUniValue().write(1,2).c_str(),
                spentCurrencyOut.ToUniValue().write(1,2).c_str(),
                ccx.totalAmounts.ToUniValue().write(1,2).c_str(),
                ccx.totalFees.ToUniValue().write(1,2).c_str());

        if (arbitrageTransfersIn.size())
        {
            if (!myAddtomempool(std::get<2>(arbitrageTransfersIn[0]), &state))
            {
                LogPrintf("%s: arbitrage transaction failure %s\n", __func__, state.GetRejectReason().c_str());
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }
        }

        // pay the fee out to the miner
        CReserveTransactionDescriptor rtxd(tb.mtx, view, nHeight + 1);
        if (!rtxd.IsValid())
        {
            if (arbitrageTransfersIn.size())
            {
                std::list<CTransaction> removedTxes;
                mempool.remove(std::get<2>(arbitrageTransfersIn[0]), removedTxes, true);
            }
            printf("%s: Created invalid import transaction for currency %s\n", __func__, EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str());
            LogPrintf("%s: Created invalid import transaction for currency %s\n", __func__, EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str());
            failedCurrencyDest = ccx.destCurrencyID;
            continue;
        }

        tb.SetFee(rtxd.nativeIn - rtxd.nativeOut);

        CCurrencyValueMap intersectMap;
        intersectMap.valueMap[ASSETCHAINS_CHAINID] = 1;
        if (!IsVerusActive())
        {
            intersectMap.valueMap[VERUS_CHAINID] = 1;
        }
        CCurrencyValueMap reserveFees = rtxd.ReserveFees();
        CCurrencyValueMap reserveChange = reserveFees.NonIntersectingValues(intersectMap);
        if (clearConvertTransition)
        {
            reserveChange.valueMap.erase(destCurID);
            intersectMap.valueMap[destCurID] = 1;
        }
        reserveFees = reserveFees.IntersectingValues(intersectMap);
        if (reserveFees > CCurrencyValueMap())
        {
            tb.SetReserveFee(reserveFees);
        }
        if (reserveChange > CCurrencyValueMap())
        {
            CTxDestination changeDest;
            if (!VERUS_DEFAULTID.IsNull())
            {
                changeDest = VERUS_DEFAULTID;
            }
            else if (!IsValidDestination(changeDest = DecodeDestination(GetArg("-mineraddress", ""))))
            {
                extern CWallet *pwalletMain;
                LOCK(pwalletMain->cs_wallet);
                CPubKey key;

                if (pwalletMain->GetKeyFromPool(key))
                {
                    changeDest = key.GetID();
                }
            }
            tb.SendChangeTo(changeDest);
        }

        if (LogAcceptCategory("crosschainimports"))
        {
            UniValue jsonTx(UniValue::VOBJ);
            uint256 hashBlk;
            TxToUniv(tb.mtx, hashBlk, jsonTx);
            LogPrintf("%s: building:\n%s\n", __func__, jsonTx.write(1,2).c_str()); //*/
            printf("%s: building:\n%s\n", __func__, jsonTx.write(1,2).c_str()); //*/
        }

        tb.SetExpiryHeight(nHeight + 5);
        TransactionBuilderResult result = tb.Build();
        if (result.IsError())
        {
            if (arbitrageTransfersIn.size())
            {
                std::list<CTransaction> removedTxes;
                mempool.remove(std::get<2>(arbitrageTransfersIn[0]), removedTxes, true);
            }
            if (LogAcceptCategory("crosschainimports"))
            {
                UniValue jsonTx(UniValue::VOBJ);
                uint256 hashBlk;
                TxToUniv(tb.mtx, hashBlk, jsonTx);
                printf("%s\n", jsonTx.write(1,2).c_str()); //*/
                LogPrintf("%s\n", jsonTx.write(1,2).c_str()); //*/
            }
            printf("%s: cannot build import transaction for currency %s: %s\n", __func__, EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str(), result.GetError().c_str());
            LogPrintf("%s: cannot build import transaction for currency %s: %s\n", __func__, EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str(), result.GetError().c_str());
            failedCurrencyDest = ccx.destCurrencyID;
            continue;
        }

        CTransaction newImportTx;

        try
        {
            newImportTx = result.GetTxOrThrow();
        }
        catch(const std::exception& e)
        {
            if (arbitrageTransfersIn.size())
            {
                std::list<CTransaction> removedTxes;
                mempool.remove(std::get<2>(arbitrageTransfersIn[0]), removedTxes, true);
            }
            LogPrintf("%s: failure to build transaction for export to %s\n", __func__, EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str());
            failedCurrencyDest = ccx.destCurrencyID;
            continue;
        }

        {
            if (LogAcceptCategory("crosschainimports"))
            {
                printf("%s: inputs for tx\n", __func__);
                LogPrintf("%s: inputs for tx\n", __func__);
                std::vector<CUTXORef> txesToShow;
                for (auto &oneIn : newImportTx.vin)
                {
                    if (!view.HaveCoins(oneIn.prevout.hash))
                    {
                        printf("%s: cannot find input in view %s\n", __func__, oneIn.prevout.hash.GetHex().c_str());
                    }
                    else
                    {
                        txesToShow.push_back(CUTXORef(oneIn.prevout.hash, oneIn.prevout.n));
                    }
                }

                for (int i = 0; i < txesToShow.size(); i++)
                {
                    auto &oneTxId = txesToShow[i];
                    CTransaction inputTx;
                    uint256 inputBlkHash;
                    UniValue out(UniValue::VOBJ);
                    if (myGetTransaction(oneTxId.hash, inputTx, inputBlkHash))
                    {
                        const CTxOut& txout = inputTx.vout[oneTxId.n];
                        out.pushKV("value", ValueFromAmount(txout.nValue));
                        out.pushKV("n", (int64_t)oneTxId.n);

                        UniValue o(UniValue::VOBJ);
                        ScriptPubKeyToUniv(txout.scriptPubKey, o, false, false);
                        out.pushKV("scriptPubKey", o);
                    }
                    else
                    {
                        printf("%s: unable to retrieve input transaction: %s\n", __func__, oneTxId.ToUniValue().write(1,2).c_str());
                        LogPrintf("%s: unable to retrieve input transaction: %s\n", __func__, oneTxId.ToUniValue().write(1,2).c_str());
                    }
                    printf("input %d:\n%s\n", i, out.write(1,2).c_str());
                    LogPrintf("input %d:\n%s\n", i, out.write(1,2).c_str());
                }
            }

            // put our transaction in place of any others
            // std::list<CTransaction> removed;
            // mempool.removeConflicts(newImportTx, removed);

            // add to mem pool and relay
            if (!myAddtomempool(newImportTx, &state, nHeight + 1, true, !ConnectedChains.IsEnhancedDustCheck(nHeight)))
            {
                if (LogAcceptCategory("failimporttx"))
                {
                    UniValue uni(UniValue::VOBJ);
                    TxToUniv(newImportTx, uint256(), uni);
                    printf("%s: newImportTx:\n%s\n", __func__, uni.write(1,2).c_str());
                }
                if (arbitrageTransfersIn.size())
                {
                    std::list<CTransaction> removedTxes;
                    mempool.remove(std::get<2>(arbitrageTransfersIn[0]), removedTxes, true);
                }
                LogPrintf("%s: %s\n", __func__, state.GetRejectReason().c_str());
                if (state.GetRejectReason() == "bad-txns-inputs-missing" || state.GetRejectReason() == "bad-txns-inputs-duplicate")
                {
                    for (auto &oneIn : newImportTx.vin)
                    {
                        printf("{\"vin\":{\"%s\":%d}\n", oneIn.prevout.hash.GetHex().c_str(), oneIn.prevout.n);
                    }
                }
                failedCurrencyDest = ccx.destCurrencyID;
                continue;
            }
            else
            {
                printf("%s: success adding %s to mempool\n", __func__, newImportTx.GetHash().GetHex().c_str());

                // do not relay imports unless they are from a different chain
                if (!arbitrageTransfersIn.size())
                {
                    RelayTransaction(newImportTx);
                }
            }

            if (!mempool.mapTx.count(newImportTx.GetHash()))
            {
                printf("%s: cannot find tx in mempool %s\n", __func__, newImportTx.GetHash().GetHex().c_str());
            }
            UpdateCoins(newImportTx, view, nHeight + 1);
            if (!view.HaveCoins(newImportTx.GetHash()))
            {
                printf("%s: cannot find tx in view %s\n", __func__, newImportTx.GetHash().GetHex().c_str());
            }
        }
        newImports[ccx.destCurrencyID].push_back(std::make_pair(0, newImportTx));
        if (useProofs)
        {
            /* UniValue uni(UniValue::VOBJ);
            TxToUniv(newImportTx, uint256(), uni);
            printf("%s: newImportTx:\n%s\n", __func__, uni.write(1,2).c_str()); */

            lastSourceImportTx = newImportTx;
            lastSourceCCI = cci.importCurrencyID == cci.sourceSystemID ? cci : sysCCI;
            lastSourceImportTxID = newImportTx.GetHash();
            sourceOutputNum = 1;
        }
    }
    return true;
}


// get the exports to a specific system from this chain, starting from a specific height up to a specific height
// export proofs are all returned as null
bool CConnectedChains::GetSystemExports(const uint160 &systemID,
                                        std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports,
                                        uint32_t fromHeight,
                                        uint32_t toHeight,
                                        bool withProofs)
{
    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(systemID, CCrossChainExport::SystemExportKey()),
                        CScript::P2IDX,
                        addressIndex,
                        fromHeight,
                        toHeight))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction exportTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, exportTx, blkHash))
            {
                auto exportIndexIt = mapBlockIndex.find(blkHash);
                if (blkHash.IsNull() || exportIndexIt == mapBlockIndex.end() || !chainActive.Contains(exportIndexIt->second))
                {
                    continue;
                }
                std::vector<CBaseChainObject *> opretTransfers;
                CCrossChainExport ccx;
                int exportOutputNum = idx.first.index;
                std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> coLaunchExports;
                if ((ccx = CCrossChainExport(exportTx.vout[exportOutputNum].scriptPubKey)).IsValid())
                {
                    // we are explicitly a system thread only export, so we need to attempt to
                    // read the export before us
                    if (ccx.IsSystemThreadExport())
                    {
                        if (!(exportOutputNum > 0 &&
                             (ccx = CCrossChainExport(exportTx.vout[--exportOutputNum].scriptPubKey)).IsValid() &&
                             ccx.destSystemID == systemID))
                        {
                            LogPrintf("%s: corrupt index state for transaction %s, output %d\n", __func__, idx.first.txhash.GetHex().c_str(), exportOutputNum);
                            return false;
                        }
                    }
                    else if (ccx.destSystemID == ccx.destCurrencyID &&
                             ccx.IsChainDefinition())
                    {
                        // if this includes a launch export for a currency that has a converter on the new chain co-launched,
                        // return the initial converter export information from this transaction as well
                        // we should find both the chain definition and an export to the converter currency on this transaction
                        uint160 coLaunchedID;
                        COptCCParams p;
                        for (int i = 0; i < exportTx.vout.size(); i++)
                        {
                            CCrossChainExport checkExport;

                            if (exportTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                                p.IsValid() &&
                                p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                                p.vData.size() &&
                                (checkExport = CCrossChainExport(p.vData[0])).IsValid() &&
                                checkExport.IsChainDefinition() &&
                                checkExport.destCurrencyID != checkExport.destSystemID &&
                                checkExport.destSystemID == systemID)
                            {
                                coLaunchExports.push_back(
                                    std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[i].scriptPubKey,
                                                                                    exportTx.vout[i].nValue,
                                                                                    CTxIn(idx.first.txhash, i)),
                                                                    CPartialTransactionProof()),
                                                    std::vector<CReserveTransfer>()));
                            }
                        }
                    }
                }

                if (ccx.IsValid())
                {
                    std::vector<CReserveTransfer> exportTransfers;
                    CPartialTransactionProof exportProof;

                    // get the export transfers from the source
                    if (ccx.sourceSystemID == ASSETCHAINS_CHAINID)
                    {
                        for (int i = ccx.firstInput; i < ccx.firstInput + ccx.numInputs; i++)
                        {
                            CTransaction oneTxIn;
                            uint256 txInBlockHash;
                            if (!myGetTransaction(exportTx.vin[i].prevout.hash, oneTxIn, txInBlockHash))
                            {
                                LogPrintf("%s: cannot access transaction %s\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str());
                                return false;
                            }
                            COptCCParams oneInP;
                            if (!(oneTxIn.vout[exportTx.vin[i].prevout.n].scriptPubKey.IsPayToCryptoCondition(oneInP) &&
                                oneInP.IsValid() &&
                                oneInP.evalCode == EVAL_RESERVE_TRANSFER &&
                                oneInP.vData.size()))
                            {
                                LogPrintf("%s: invalid reserve transfer input %s, %lu\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str(), exportTx.vin[i].prevout.n);
                                return false;
                            }
                            exportTransfers.push_back(CReserveTransfer(oneInP.vData[0]));
                            if (!exportTransfers.back().IsValid())
                            {
                                LogPrintf("%s: invalid reserve transfer input 1 %s, %lu\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str(), exportTx.vin[i].prevout.n);
                                return false;
                            }
                        }
                        // if we should make a partial transaction proof, do it
                        if (withProofs &&
                            ccx.destSystemID != ASSETCHAINS_CHAINID)
                        {
                            std::vector<int> inputsToProve;
                            if (!ccx.IsChainDefinition() && ccx.firstInput > 0)
                            {
                                inputsToProve.push_back(ccx.firstInput - 1);
                            }
                            std::vector<int> outputsToProve({exportOutputNum});
                            auto it = mapBlockIndex.find(blkHash);
                            if (it == mapBlockIndex.end())
                            {
                                LogPrintf("%s: possible corruption, cannot locate block %s for export tx\n", __func__, blkHash.GetHex().c_str());
                                return false;
                            }
                            // prove all co-launch exports
                            for (auto &oneCoLaunch : coLaunchExports)
                            {
                                assert(oneCoLaunch.first.first.txIn.prevout.hash == exportTx.GetHash());
                                oneCoLaunch.first.second = CPartialTransactionProof(exportTx,
                                                                                    std::vector<int>(),
                                                                                    std::vector<int>({(int)oneCoLaunch.first.first.txIn.prevout.n}),
                                                                                    it->second,
                                                                                    toHeight);
                                //printf("%s: co-launch proof: %s\n", __func__, oneCoLaunch.first.second.ToUniValue().write(1,2).c_str());
                            }
                            exportProof = CPartialTransactionProof(exportTx, inputsToProve, outputsToProve, it->second, toHeight);
                            //CPartialTransactionProof checkSerProof(exportProof.ToUniValue());
                            //printf("%s: toheight: %u, txhash: %s\nserialized export proof: %s\n", __func__, toHeight, checkSerProof.TransactionHash().GetHex().c_str(), checkSerProof.ToUniValue().write(1,2).c_str());
                        }
                    }
                    else
                    {
                        LogPrintf("%s: invalid export from incorrect system on this chain in tx %s\n", __func__, idx.first.txhash.GetHex().c_str());
                        return false;
                    }

                    exports.push_back(std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[exportOutputNum].scriptPubKey,
                                                                                     exportTx.vout[exportOutputNum].nValue,
                                                                                     CTxIn(idx.first.txhash, exportOutputNum)),
                                                                    exportProof),
                                                     exportTransfers));
                    exports.insert(exports.end(), coLaunchExports.begin(), coLaunchExports.end());
                }
            }
        }
        return true;
    }
    return false;
}

// get the launch notarization for a specific chain
bool CConnectedChains::GetLaunchNotarization(const CCurrencyDefinition &curDef,
                                             std::pair<CInputDescriptor, CPartialTransactionProof> &notarizationRef,
                                             CPBaaSNotarization &launchNotarization,
                                             CPBaaSNotarization &notaryNotarization)
{
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;
    uint160 currencyID = curDef.GetID();
    bool retVal = false;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(currencyID, CPBaaSNotarization::LaunchNotarizationKey()),
                        CScript::P2IDX,
                        addressIndex))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction notarizationTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, notarizationTx, blkHash))
            {
                CChainNotarizationData cnd;
                if ((launchNotarization = CPBaaSNotarization(notarizationTx.vout[idx.first.index].scriptPubKey)).IsValid() &&
                     (notaryNotarization.IsValid() || (notaryNotarization = launchNotarization).IsValid()))
                {
                    auto blockIt = mapBlockIndex.find(blkHash);
                    if (blockIt != mapBlockIndex.end() &&
                        chainActive.Contains(blockIt->second))
                    {
                        std::vector<int> inputNums, outputNums;
                        if (launchNotarization.IsBlockOneNotarization() && launchNotarization.currencyID == ConnectedChains.ThisChain().launchSystemID)
                        {
                            // get entire coinbase proof
                            inputNums.push_back(0);
                            outputNums.resize(notarizationTx.vout.size());
                            for (int outNum = 0; outNum < outputNums.size(); outNum++)
                            {
                                outputNums[outNum] = outNum;
                            }
                        }
                        else
                        {
                            outputNums.push_back((int)idx.first.index);
                        }
                        notarizationRef.first = CInputDescriptor(notarizationTx.vout[idx.first.index].scriptPubKey,
                                                                 notarizationTx.vout[idx.first.index].nValue,
                                                                 CTxIn(idx.first.txhash, idx.first.index));

                        uint32_t proofHeight = std::max((uint32_t)blockIt->second->GetHeight(), notaryNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight);
                        if (notaryNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight != proofHeight)
                        {
                            notaryNotarization.proofRoots[ASSETCHAINS_CHAINID] = CProofRoot::GetProofRoot(proofHeight);
                        }
                        notarizationRef.second = CPartialTransactionProof(notarizationTx,
                                                                          inputNums,
                                                                          outputNums,
                                                                          blockIt->second,
                                                                          proofHeight);
                        retVal = true;
                    }
                }
            }
        }
    }
    return retVal;
}

// get the exports to a specific system from this chain, starting from a specific height up to a specific height
// export proofs are all returned as null
bool CConnectedChains::GetDefinitionNotarization(const CCurrencyDefinition &curDef,
                                                 CInputDescriptor &notarizationRef,
                                                 CPBaaSNotarization &definitionNotarization)
{
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;
    uint160 currencyID = curDef.GetID();
    bool retVal = false;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(currencyID, CPBaaSNotarization::DefinitionNotarizationKey()),
                        CScript::P2IDX,
                        addressIndex))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction notarizationTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, notarizationTx, blkHash))
            {
                CChainNotarizationData cnd;
                if ((definitionNotarization = CPBaaSNotarization(notarizationTx.vout[idx.first.index].scriptPubKey)).IsValid())
                {
                    auto blockIt = mapBlockIndex.find(blkHash);
                    if (blockIt != mapBlockIndex.end() &&
                        chainActive.Contains(blockIt->second))
                    {
                        notarizationRef = CInputDescriptor(notarizationTx.vout[idx.first.index].scriptPubKey,
                                                                 notarizationTx.vout[idx.first.index].nValue,
                                                                 CTxIn(idx.first.txhash, idx.first.index));
                        retVal = true;
                    }
                }
            }
        }
    }
    return retVal;
}

// get the exports to a specific system from this chain, starting from a specific height up to a specific height
// export proofs are all returned as null
bool CConnectedChains::GetDefinitionNotarization(const CCurrencyDefinition &curDef,
                                                 std::pair<CInputDescriptor, CPartialTransactionProof> &notarizationRef,
                                                 CPBaaSNotarization &definitionNotarization,
                                                 CPBaaSNotarization &notaryNotarization)
{
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;
    uint160 currencyID = curDef.GetID();
    bool retVal = false;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(currencyID, CPBaaSNotarization::DefinitionNotarizationKey()),
                        CScript::P2IDX,
                        addressIndex))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction notarizationTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, notarizationTx, blkHash))
            {
                CChainNotarizationData cnd;
                if ((definitionNotarization = CPBaaSNotarization(notarizationTx.vout[idx.first.index].scriptPubKey)).IsValid() &&
                     GetNotarizationData(ASSETCHAINS_CHAINID, cnd) &&
                     cnd.IsConfirmed() &&
                     (notaryNotarization = cnd.vtx[cnd.lastConfirmed].second).IsValid())
                {
                    auto blockIt = mapBlockIndex.find(blkHash);
                    if (blockIt != mapBlockIndex.end() &&
                        chainActive.Contains(blockIt->second))
                    {
                        notarizationRef.first = CInputDescriptor(notarizationTx.vout[idx.first.index].scriptPubKey,
                                                                 notarizationTx.vout[idx.first.index].nValue,
                                                                 CTxIn(idx.first.txhash, idx.first.index));
                        notarizationRef.second = CPartialTransactionProof(notarizationTx,
                                                                          std::vector<int>(),
                                                                          std::vector<int>({(int)idx.first.index}),
                                                                          blockIt->second,
                                                                          blockIt->second->GetHeight());
                        notaryNotarization.proofRoots[ASSETCHAINS_CHAINID] = CProofRoot::GetProofRoot(blockIt->second->GetHeight());
                        retVal = true;
                    }
                }
            }
        }
    }
    return retVal;
}

// get the exports to a specific system from this chain, starting from a specific height up to a specific height
// proofs are returned as null
bool CConnectedChains::GetCurrencyExports(const uint160 &currencyID,
                                          std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports,
                                          uint32_t fromHeight,
                                          uint32_t toHeight)
{
    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(currencyID, CCrossChainExport::CurrencyExportKey()),
                        CScript::P2IDX,
                        addressIndex,
                        fromHeight,
                        toHeight))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction exportTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, exportTx, blkHash))
            {
                BlockMap::iterator blockIt;
                if (!blkHash.IsNull() &&
                    (blockIt = mapBlockIndex.find(blkHash)) == mapBlockIndex.end() ||
                     !chainActive.Contains(blockIt->second))
                {
                    continue;
                }

                std::vector<CBaseChainObject *> opretTransfers;
                CCrossChainExport ccx;
                if ((ccx = CCrossChainExport(exportTx.vout[idx.first.index].scriptPubKey)).IsValid() &&
                    !ccx.IsSystemThreadExport())
                {
                    std::vector<CReserveTransfer> exportTransfers;
                    CPartialTransactionProof exportProof;

                    // get the export transfers from the source
                    if (ccx.sourceSystemID == ASSETCHAINS_CHAINID)
                    {
                        for (int i = ccx.firstInput; i < (ccx.firstInput + ccx.numInputs); i++)
                        {
                            CTransaction oneTxIn;
                            uint256 txInBlockHash;
                            if (!myGetTransaction(exportTx.vin[i].prevout.hash, oneTxIn, txInBlockHash))
                            {
                                LogPrintf("%s: cannot access transasction %s\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str());
                                return false;
                            }
                            COptCCParams oneInP;
                            if (!(oneTxIn.vout[exportTx.vin[i].prevout.n].scriptPubKey.IsPayToCryptoCondition(oneInP) &&
                                oneInP.IsValid() &&
                                oneInP.evalCode == EVAL_RESERVE_TRANSFER &&
                                oneInP.vData.size()))
                            {
                                LogPrintf("%s: invalid reserve transfer input %s, %lu\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str(), exportTx.vin[i].prevout.n);
                                return false;
                            }
                            exportTransfers.push_back(CReserveTransfer(oneInP.vData[0]));
                            if (!exportTransfers.back().IsValid())
                            {
                                LogPrintf("%s: invalid reserve transfer input 1 %s, %lu\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str(), exportTx.vin[i].prevout.n);
                                return false;
                            }
                        }
                    }
                    else
                    {
                        LogPrintf("%s: invalid export from incorrect system on this chain in tx %s\n", __func__, idx.first.txhash.GetHex().c_str());
                        return false;
                    }

                    exports.push_back(std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[idx.first.index].scriptPubKey,
                                                                                     exportTx.vout[idx.first.index].nValue,
                                                                                     CTxIn(idx.first.txhash, idx.first.index)),
                                                                    exportProof),
                                                     exportTransfers));
                }
                else
                {
                    LogPrintf("%s: invalid export index for txid: %s, %lu\n", __func__, idx.first.txhash.GetHex().c_str(), idx.first.index);
                    return false;
                }
            }
        }
        return true;
    }
    return false;
}

bool CCurrencyDefinition::IsValidDefinitionImport(const CCurrencyDefinition &sourceSystem, const CCurrencyDefinition &destSystem, const uint160 &nameParent, uint32_t height)
{
    // the system from which the currency comes is not source or destination
    uint160 sourceSystemID = sourceSystem.GetID();
    uint160 destSystemID = destSystem.GetID();

    uint160 currencyParentID = nameParent;
    CCurrencyDefinition curSystem = ConnectedChains.GetCachedCurrency(currencyParentID);
    if (sourceSystemID == ASSETCHAINS_CHAINID)
    {
        // if we are sending from this chain, we must know that the parent already exists on the destination, or
        // we would create an invalid import
        if (!IsValidExportCurrency(destSystem, currencyParentID, height))
        {
            if (LogAcceptCategory("crosschain"))
            {
                printf("%s: Currency parent %s is not exported to the destination system, which is required for export.\n", __func__, EncodeDestination(CIdentityID(currencyParentID)).c_str());
                LogPrintf("%s: Currency parent %s is not exported to the destination system, which is required for export.\n", __func__, EncodeDestination(CIdentityID(currencyParentID)).c_str());
            }
            return false;
        }
    }

    do
    {
        if (!curSystem.IsValid())
        {
            if (LogAcceptCategory("crosschain"))
            {
                printf("%s: Invalid currency parent for %s. Index may be corrupt.\n", __func__, EncodeDestination(CIdentityID(currencyParentID)).c_str());
                LogPrintf("%s: Invalid currency parent for %s. Index may be corrupt.\n", __func__, EncodeDestination(CIdentityID(currencyParentID)).c_str());
            }
            return false;
        }

        // fractional currencies can support ID issuance and unless the currency is a gateway converter,
        // cannot support importing a definition from another chain
        if (curSystem.IsFractional())
        {
            // a gateway currency converter of a non-name controller
            // gateway cannot issue IDs directly, as they must be imported
            if (curSystem.IsGatewayConverter())
            {
                // if a gateway converter is the parent,
                // the system to travel up for import name control is always the
                // gateway, whether PBaaS or non-name controller. non-name controller
                // converter currencies cannot issue names themselves on the launch chain.
                curSystem = ConnectedChains.GetCachedCurrency(curSystem.gatewayID);
                if (!curSystem.IsValid())
                {
                    printf("%s: Invalid gateway currency for converter. Index may be corrupt.\n", __func__);
                    LogPrintf("%s: Invalid gateway currency for converter. Index may be corrupt.\n", __func__);
                    return false;
                }
            }
            else
            {
                curSystem = ConnectedChains.GetCachedCurrency(curSystem.systemID);
            }
        }
        // if we encounter a gateway, our action depends on whether it is a name controller or not
        else if (curSystem.IsGateway() || curSystem.IsPBaaSChain())
        {
            // a non-name controller cannot be the root system of a direct descendent
            // instead, the launching chain provides name services to the non-name controller gateway
            if (!curSystem.IsNameController() && curSystem.GetID() == nameParent)
            {
                // root system is the launch system
                curSystem = ConnectedChains.GetCachedCurrency(curSystem.launchSystemID);
            }
        }

        uint160 curSystemID = curSystem.GetID();

        if (!curSystemID.IsNull() && (curSystemID == sourceSystemID || curSystemID == destSystemID))
        {
            return curSystemID == sourceSystemID;
        }

        currencyParentID = curSystem.parent;
        if (!currencyParentID.IsNull())
        {
            curSystem = ConnectedChains.GetCachedCurrency(currencyParentID);
        }
    } while (!currencyParentID.IsNull());

    // if we got to a null root without finding the source, the only way an import from source to destination is valid
    // is if the source system is the launch chain of the destination system
    return destSystem.launchSystemID == sourceSystemID;
}

// Checks to see if a currency can be imported from a particular system to the indicated system
// The current system must be source or destination. Gateways that do not implement name or ID
// technology can use the bridged PBaaS or Verus chain to provide identity and currency definition
// services and attribute fees to the gateway currency converter. In order to do this, the
// gateway must have the option set which indicates it is not a name controller. This means that
// it cannot control or import names at the first level from the root name. All of these must be
// defined on the Verus network. Currencies defined this way must be "mapped currencies", meaning
// that they represent a currency on the other side of the gateway, and can only be acquired by having
// been exported to the gateway and then had either that currency or subcurrency definitions returned (NFTs).
// Protocol rules for a PBaaS chain or Gateway that is a name controller:
//  - All names that have parentage from the root currency of the PBaaS chain derive from it
// Protocol rules for a Gateway that is not a name controller:
//  - First level names must all be allocated on the Gateway's host blockchain (for example Verus or a PBaaS chain)
//  - "mapped currencies" and only mapped currencies may be defined from IDs, which are purchased from the bridge and
//    carry the name of the gateway as a suffix.
//  - When a mapped currency is exported to the Gateway, the gateway may return sub-currency definitions as well as
//    currency. All currencies defined on the PBaaS chain or Verus are controlled by the gateway, and will be minted
//    on import and burned on export.
bool CConnectedChains::IsValidCurrencyDefinitionImport(const CCurrencyDefinition &sourceSystemDef,
                                                       const CCurrencyDefinition &destSystemDef,
                                                       const CCurrencyDefinition &importingCurrency,
                                                       uint32_t height)
{
    assert(sourceSystemDef.IsValid() && destSystemDef.IsValid());
    if (importingCurrency.parent.IsNull())
    {
        return destSystemDef.launchSystemID == sourceSystemDef.GetID() && importingCurrency.GetID() != destSystemDef.launchSystemID;
    }
    return CCurrencyDefinition::IsValidDefinitionImport(sourceSystemDef, destSystemDef, importingCurrency.parent, height);
}

// Checks to see if an identity can be imported from a particular system to the indicated system
// The current system must be source or destination.
bool CConnectedChains::IsValidIdentityDefinitionImport(const CCurrencyDefinition &sourceSystemDef,
                                                       const CCurrencyDefinition &destSystemDef,
                                                       const CIdentity &importingIdentity,
                                                       uint32_t height)
{
    assert(sourceSystemDef.IsValid() && destSystemDef.IsValid());
    if (importingIdentity.parent.IsNull())
    {
        return destSystemDef.launchSystemID == sourceSystemDef.GetID() && importingIdentity.GetID() != destSystemDef.launchSystemID;
    }
    return CCurrencyDefinition::IsValidDefinitionImport(sourceSystemDef, destSystemDef, importingIdentity.parent, height);
}

// Determines if the currency, when exported to the destination system from the current system should:
// 1) have its accounting stored locally as reserve deposits controlled by the destination
//    system, meaning the destination system considers this system the source and controller of
//    those currencies, or
// 2) burn the outgoing currency because the destination system is considered the controlling system.
// 3) fail the export because one or more of the currencies being sent has not yet been exported
//    to the destination system.
bool CConnectedChains::CurrencyExportStatus(const CCurrencyValueMap &totalExports,
                                            const uint160 &sourceSystemID,
                                            const uint160 &destSystemID,
                                            CCurrencyValueMap &newReserveDeposits,
                                            CCurrencyValueMap &exportBurn)
{
    /* printf("%s: num transfers %ld, totalExports: %s\nnewNotarization: %s\n",
        __func__,
        exportTransfers.size(),
        totalExports.ToUniValue().write(1,2).c_str(),
        newNotarization.ToUniValue().write(1,2).c_str()); */

    // if we are exporting off of this system to a gateway or PBaaS chain, don't allow 3rd party
    // or unregistered currencies to export. if same to same chain, all exports are ok.
    if (destSystemID != sourceSystemID)
    {
        for (auto &oneCur : totalExports.valueMap)
        {
            if (oneCur.first == sourceSystemID)
            {
                newReserveDeposits.valueMap[oneCur.first] += oneCur.second;
                continue;
            }
            else if (oneCur.first == destSystemID)
            {
                exportBurn.valueMap[oneCur.first] += oneCur.second;
                continue;
            }

            CCurrencyDefinition oneCurDef;

            // look up the chain to find if the destination system is in the chain of the currency before the source system
            oneCurDef = ConnectedChains.GetCachedCurrency(oneCur.first);

            if (!oneCurDef.IsValid())
            {
                printf("%s: Invalid currency for export or corrupt chain state\n", __func__);
                LogPrintf("%s: Invalid currency for export or corrupt chain state\n", __func__);
                return false;
            }

            if (oneCurDef.IsNFTToken() && oneCur.second > 1)
            {
                printf("%s: No more than 1 satoshi may be transfered cross-chain to represent an NFT or tokenized ID control currency\n", __func__);
                LogPrintf("%s: No more than 1 satoshi may be transfered cross-chain to represent an NFT or tokenized ID control currency\n", __func__);
                return false;
            }

            // if this is a mapped currency to a gateway that isn't a name controller, for this determination,
            // we are interested then in the launch system
            uint160 currencySystemID = oneCurDef.IsGateway() ? oneCurDef.gatewayID : oneCurDef.systemID;
            if (currencySystemID == sourceSystemID)
            {
                newReserveDeposits.valueMap[oneCur.first] += oneCur.second;
                continue;
            }
            else if (currencySystemID == destSystemID)
            {
                exportBurn.valueMap[oneCur.first] += oneCur.second;
                continue;
            }

            // the system from which the currency comes is not source or destination
            CCurrencyDefinition thirdCurSystem;

            do
            {
                thirdCurSystem = ConnectedChains.GetCachedCurrency(currencySystemID);
                if (!thirdCurSystem.IsValid())
                {
                    printf("%s: Invalid currency in origin chain. Index may be corrupt.\n", __func__);
                    LogPrintf("%s: Invalid currency in origin chain. Index may be corrupt.\n", __func__);
                    return false;
                }

                uint160 thirdCurSystemID = currencySystemID;

                // get the system ID of the PBaaS chain with the gateway or parent PBaaS chain of the PBaaS chain
                currencySystemID = thirdCurSystem.IsGateway() ? thirdCurSystem.systemID : thirdCurSystem.parent;

                if (currencySystemID == sourceSystemID)
                {
                    newReserveDeposits.valueMap[oneCur.first] += oneCur.second;
                    break;
                }
                else if (currencySystemID == destSystemID)
                {
                    exportBurn.valueMap[oneCur.first] += oneCur.second;
                    break;
                }
            } while (!currencySystemID.IsNull());

            // if the ultimate parent is null before it is us, then we must assume it is controlled outside our scope
            // meaning that if we are sending to the source system's launch system, the destination is the controller,
            // otherwise, source is the controller.
            if (currencySystemID.IsNull())
            {
                CCurrencyDefinition sourceSystem = ConnectedChains.GetCachedCurrency(sourceSystemID);
                if (!sourceSystem.IsValid())
                {
                    printf("%s: Invalid source system. Index may be corrupt.\n", __func__);
                    LogPrintf("%s: Invalid source system. Index may be corrupt.\n", __func__);
                    return false;
                }

                // if sending from source system to its launch parent,
                // consider the destination the controller, so burn
                if (sourceSystem.launchSystemID == destSystemID)
                {
                    exportBurn.valueMap[oneCur.first] += oneCur.second;
                }
                else
                {
                    newReserveDeposits.valueMap[oneCur.first] += oneCur.second;
                }
            }
        }
    }
    else
    {
        // when we export from this system to a specific currency on this system,
        // we record the reserve deposits for the destination currency to ensure they are available for imports
        // which take them as inputs.
        newReserveDeposits = totalExports;
    }
    return true;
}

bool CConnectedChains::CurrencyImportStatus(const CCurrencyValueMap &totalImports,
                                            const uint160 &sourceSystemID,
                                            const uint160 &destSystemID,
                                            CCurrencyValueMap &mintNew,
                                            CCurrencyValueMap &reserveDepositsRequired)
{
    return CurrencyExportStatus(totalImports, sourceSystemID, destSystemID, mintNew, reserveDepositsRequired);
}

uint256 EntropyHashFromHeight(const uint160 &conditionID, uint32_t nHeight, const uint160 &extraEntropy)
{
    auto hw = CMMRNode<>::GetHashWriter();
    hw << conditionID;
    hw << (chainActive.Height() >= nHeight ? chainActive[nHeight]->GetVerusEntropyHashComponent() : uint256());
    if (!extraEntropy.IsNull())
    {
        hw << extraEntropy;
    }
    return hw.GetHash();
}

bool EntropyCoinFlip(const uint160 &conditionID, uint32_t nHeight)
{
    auto hw = CMMRNode<>::GetHashWriter();
    hw << conditionID;
    hw << (chainActive.Height() >= nHeight ? chainActive[nHeight]->GetVerusEntropyHashComponent() : uint256());
    return UintToArith256(hw.GetHash()).GetLow64() & 1;
}

bool IsHalfMaxed(const std::map<uint160, std::pair<int, int>> &maxTrackerMap)
{
    for (auto &oneCheck : maxTrackerMap)
    {
        if (oneCheck.second.second >= (oneCheck.second.first >> 1) && (oneCheck.second.second | oneCheck.second.first))
        {
            return true;
        }
    }
    return false;
}

bool IsMaxed(const std::map<uint160, std::pair<int, int>> &maxTrackerMap, const uint160 &checkDest)
{
    auto oneCheck = maxTrackerMap.find(checkDest);
    if (oneCheck != maxTrackerMap.end())
    {
        if (oneCheck->second.second >= oneCheck->second.first && (oneCheck->second.second | oneCheck->second.first))
        {
            return true;
        }
    }
    return false;
}

bool IsMaxed(const std::map<uint160, std::pair<int, int>> &maxTrackerMap)
{
    for (auto &oneCheck : maxTrackerMap)
    {
        if (oneCheck.second.second >= oneCheck.second.first && (oneCheck.second.second | oneCheck.second.first))
        {
            return true;
        }
    }
    return false;
}

std::vector<ChainTransferData> CConnectedChains::CalcTxInputs(const CCurrencyDefinition &_curDef,
                                                                bool &isClearLaunchExport,
                                                                uint32_t sinceHeight,
                                                                uint32_t &addHeight,
                                                                uint32_t &nextHeight,
                                                                uint32_t untilHeight,
                                                                uint32_t nHeight,
                                                                int &curIDExports,
                                                                int &curCurrencyExports,
                                                                const std::multimap<uint32_t, ChainTransferData> &_txInputs)
{
    std::vector<ChainTransferData> txInputs;

    int maxInputs = _curDef.MaxTransferExportCount() << 1;
    int maxIDExports = _curDef.MaxIdentityDefinitionExportCount() << 1;
    int maxCurrencyExports = _curDef.MaxCurrencyDefinitionExportCount() << 1;

    // .first = gateway, .second = {max, curtotal}
    std::map<uint160, std::pair<int, int>> secondaryTransfers;
    std::map<uint160, std::pair<int, int>> secondaryCurrencyExports;
    std::map<uint160, std::pair<int, int>> secondaryIDExports;

    bool isPrelaunch = (isClearLaunchExport || (_curDef.launchSystemID == ASSETCHAINS_CHAINID && sinceHeight + 1 < _curDef.startBlock));

    std::multimap<uint32_t, ChainTransferData>::const_iterator it;
    for (it = _txInputs.begin(); it != _txInputs.end(); it++)
    {
        auto &oneInput = *it;

        if (oneInput.first <= sinceHeight)
        {
            continue;
        }

        if (addHeight != oneInput.first)
        {
            // if this is a launch export, we create one at the boundary
            if (isPrelaunch && oneInput.first >= _curDef.startBlock)
            {
                addHeight = _curDef.startBlock - 1;
                break;
            }

            // if we have skipped to the next block, and we have enough to make a clear launch export, we cannot take any more
            if (isPrelaunch &&
                (txInputs.size() >= CCrossChainExport::MAX_FEE_INPUTS ||
                 (txInputs.size() >= CCrossChainExport::MIN_INPUTS && (oneInput.first - sinceHeight) >= CCrossChainExport::MIN_BLOCKS)))
            {
                nextHeight = oneInput.first;
                break;
            }

            // if we qualify by meeting 1/2 of any category limit, drop in and decide if we append or not
            if (!isClearLaunchExport &&
                (txInputs.size() >= CCrossChainExport::MIN_INPUTS ||
                 (oneInput.first - sinceHeight) >= CCrossChainExport::MIN_BLOCKS ||
                 txInputs.size() >= (maxInputs >> 1) ||
                 (curIDExports && curIDExports >= (maxIDExports >> 1)) ||
                 (curCurrencyExports && curCurrencyExports >= (maxCurrencyExports >> 1)) ||
                 IsHalfMaxed(secondaryTransfers) ||
                 IsHalfMaxed(secondaryCurrencyExports) ||
                 IsHalfMaxed(secondaryIDExports)))
            {
                // if we have one or more empty blocks between the next block with transfers, go go with what we have
                if (txInputs.size() && oneInput.first != (addHeight + 1))
                {
                    nextHeight = oneInput.first;
                    break;
                }

                // we're now at a qualified block boundary, so either this marks the next export with a gap of transfers, or,
                // the block after this one is used to determine whether this block is combined with blocks in front of it,
                // or the blocks behind. if we don't have the block after to check, return until we do
                if (std::min(untilHeight, nHeight) <= oneInput.first)
                {
                    // no error, just nothing to do, as we can't decide to include this with the prior block
                    // until we have at least one more block
                    return std::vector<ChainTransferData>();
                }

                // if we get the coin flip using the entropy of the block after the next block in question,
                // separate here, otherwise, the next block will be added
                if (txInputs.size() && EntropyCoinFlip(_curDef.GetID(), oneInput.first + 1))
                {
                    nextHeight = oneInput.first;
                    break;
                }
            }
        }

        bool isCurExport = std::get<2>(oneInput.second).IsCurrencyExport();
        bool isIDExport = std::get<2>(oneInput.second).IsIdentityExport();
        bool hasNextLeg = std::get<2>(oneInput.second).HasNextLeg();
        if (txInputs.size() >= maxInputs ||
            (curIDExports && (curIDExports > maxIDExports || (isIDExport && curIDExports == maxIDExports))) ||
            (curCurrencyExports && (curCurrencyExports > maxCurrencyExports || (isCurExport && curCurrencyExports == maxCurrencyExports))) ||
            (hasNextLeg &&
             (IsMaxed(secondaryTransfers, std::get<2>(oneInput.second).destination.gatewayID)) ||
             (IsMaxed(secondaryCurrencyExports, std::get<2>(oneInput.second).destination.gatewayID) && isCurExport) ||
             (IsMaxed(secondaryIDExports, std::get<2>(oneInput.second).destination.gatewayID) && isIDExport)))
        {
            // we exceed the maximum, so we separate from the last and make the
            // export out of one less than we currently have

            // if the one we are trying to add is the same as those behind us, then we are exceeding limits and must remove the block
            if (oneInput.first == addHeight)
            {
                while (std::get<0>(txInputs.back()) == addHeight)
                {
                    txInputs.pop_back();
                }
                assert(txInputs.size());
                addHeight = std::get<0>(txInputs.back());
            }
            nextHeight = oneInput.first;
            break;
        }

        if (!isClearLaunchExport && untilHeight <= oneInput.first + 1)
        {
            // no error, just nothing to do, as we can't decide to include this with the prior block
            // until we have at least one more block
            return std::vector<ChainTransferData>();
        }

        CReserveTransfer rt(std::get<2>(oneInput.second));

        bool checkSecondLeg = rt.HasNextLeg() && rt.destination.gatewayID != ASSETCHAINS_CHAINID;

        if (checkSecondLeg)
        {
            CCurrencyDefinition secondaryCur;
            auto rtIt = secondaryTransfers.find(rt.destination.gatewayID);
            if (rtIt != secondaryTransfers.end())
            {
                rtIt->second.second++;
            }
            else
            {
                secondaryCur = ConnectedChains.GetCachedCurrency(rt.destination.gatewayID);
                if (secondaryCur.IsValid() && (secondaryCur.IsPBaaSChain() || secondaryCur.IsGateway()))
                {
                    secondaryTransfers[rt.destination.gatewayID] = {secondaryCur.MaxTransferExportCount() << 1, 1};
                    secondaryIDExports[rt.destination.gatewayID] = {secondaryCur.MaxIdentityDefinitionExportCount() << 1, rt.IsIdentityExport() ? 1 : 0};
                    secondaryCurrencyExports[rt.destination.gatewayID] = {secondaryCur.MaxCurrencyDefinitionExportCount() << 1, rt.IsCurrencyExport() ? 1 : 0};
                }
            }
        }

        if (rt.IsCurrencyExport())
        {
            curCurrencyExports++;
            if (checkSecondLeg)
            {
                auto rtIt = secondaryIDExports.find(rt.destination.gatewayID);
                if (rtIt != secondaryIDExports.end())
                {
                    rtIt->second.second++;
                }
            }
        }
        else if (rt.IsIdentityExport())
        {
            curIDExports++;
            if (checkSecondLeg)
            {
                auto rtIt = secondaryCurrencyExports.find(rt.destination.gatewayID);
                if (rtIt != secondaryCurrencyExports.end())
                {
                    rtIt->second.second++;
                }
            }
        }

        addHeight = oneInput.first;
        txInputs.push_back(oneInput.second);
    }

    if (it == _txInputs.end())
    {
        nextHeight = untilHeight;
    }

    // if we have too many exports to clear launch yet, this is no longer clear launch
    isClearLaunchExport = isClearLaunchExport && !(nextHeight && nextHeight < _curDef.startBlock);

    // if we made an export before getting to the end, it doesn't clear launch
    // if we either early outed, due to height or landed right on the correct height, determine launch state
    // a clear launch export may have no inputs yet still be created with a clear launch notarization
    if (isClearLaunchExport)
    {
        addHeight = _curDef.startBlock - 1;
    }
    return txInputs;
}

bool CConnectedChains::CreateNextExport(const CCurrencyDefinition &_curDef,
                                        const std::multimap<uint32_t, ChainTransferData> &_txInputs,
                                        const std::vector<CInputDescriptor> &priorExports,
                                        const CTransferDestination &_feeRecipient,
                                        uint32_t sinceHeight,
                                        uint32_t curHeight, // the height of the next block
                                        int32_t inputStartNum,
                                        int32_t &inputsConsumed,
                                        std::vector<CTxOut> &exportOutputs,
                                        std::vector<CReserveTransfer> &exportTransfers,
                                        const CPBaaSNotarization &lastNotarization,
                                        const CUTXORef &lastNotarizationUTXO,
                                        CPBaaSNotarization &newNotarization,
                                        int &newNotarizationOutNum,
                                        bool createOnlyIfRequired)
{
    // Accepts all reserve transfer inputs to a particular currency destination.
    // Generates a new export transactions and any required notarizations.
    // Observes anti-front-running rules.

    // This assumes that:
    // 1) _txInputs has all currencies since last export on this system with accurate block numbers
    // 2) _txInputs is sorted
    // 3) the last export transaction is added as input outside of this call

    AssertLockHeld(cs_main);

    uint32_t nHeight = chainActive.Height();

    CTransferDestination feeRecipient = _feeRecipient;

    newNotarization = lastNotarization;
    newNotarization.prevNotarization = lastNotarizationUTXO;
    inputsConsumed = 0;

    uint160 destSystemID = _curDef.SystemOrGatewayID();
    uint160 currencyID = _curDef.GetID();
    bool crossSystem = destSystemID != ASSETCHAINS_CHAINID;
    bool isPreLaunch = _curDef.launchSystemID == ASSETCHAINS_CHAINID &&
                       _curDef.startBlock > sinceHeight &&
                       !lastNotarization.IsLaunchCleared();

    bool isClearLaunchExport = isPreLaunch && curHeight >= _curDef.startBlock && !lastNotarization.IsLaunchCleared();

    if (!isClearLaunchExport && (!_txInputs.size() || _txInputs.rbegin()->first <= sinceHeight))
    {
        // no error, just nothing to do
       return true;
    }

    // The aggregation rules require that:
    // 1. Either there are MIN_INPUTS of reservetransfer or MIN_BLOCKS before an
    //    aggregation can be made as an export transaction.
    // 2. We will include as many reserveTransfers as we can, block by block until the
    //    first block that allows us to meet MIN_INPUTS on this export.
    // 3. Additional *conversion* input(s) may be added in the import transaction.
    //

    // determine inputs to include in next export
    // early out if createOnlyIfRequired is true
    if (!isClearLaunchExport &&
        curHeight - sinceHeight < CCrossChainExport::MIN_BLOCKS &&
        _txInputs.size() < CCrossChainExport::MIN_INPUTS &&
        createOnlyIfRequired)
    {
        return true;
    }

    // loop until we have gained a qualified set of transfers over one or more blocks
    // a qualified set occurs when:
    // 1) we know we have passed the minimum blocks or we have more than the minimum inputs - this is true
    // 2) if we reach a maximum per block number of transfers, identities, or currency exports,
    // .  we must determine if the block hitting that number gets grouped with the blocks before it
    // .  or the block(s) after it based on a random bit pulled from the block after it, either nonce
    // .  if POS or block hash if POW block.
    //
    // Each time we pass the minimum number of blocks, minimum number of transfers, or hit the maximum number
    // of any type, we must make a decision of the current block going with the next or prior

    uint32_t addHeight = sinceHeight;
    uint32_t nextHeight = 0;

    int curIDExports = 0;
    int curCurrencyExports = 0;

    std::vector<ChainTransferData> txInputs = CalcTxInputs(_curDef,
                                                           isClearLaunchExport,
                                                           sinceHeight,
                                                           addHeight,
                                                           nextHeight,
                                                           curHeight,
                                                           nHeight,
                                                           curIDExports,
                                                           curCurrencyExports,
                                                           _txInputs);

    // all we expect to add are in txInputs now
    inputsConsumed = txInputs.size();

    // if we are not the clear launch export and have no inputs, including the optional one, we are done
    if (!isClearLaunchExport)
    {
        if (txInputs.size() == 0)
        {
            return true;
        }
    }

    std::set<uint32_t> blockLottery;
    std::vector<uint32_t> blockLotteryVec;
    for (auto &oneInput : txInputs)
    {
        blockLottery.insert(std::get<0>(oneInput));
    }
    for (auto &oneHeight : blockLottery)
    {
        blockLotteryVec.push_back(oneHeight);
    }

    if (blockLotteryVec.size())
    {

        // after launch, the fee recipient must be the first recipient of the coinbase reward for the last
        // block in the export sequence
        CBlock block;

        uint256 selectBlockEntropy = EntropyHashFromHeight(CBlockIndex::BlockEntropyKey(), addHeight, _curDef.GetID());
        uint64_t intermediateEntropy = UintToArith256(selectBlockEntropy).GetLow64();
        int blockRewardNum = blockLotteryVec[intermediateEntropy % blockLotteryVec.size()];

        CBlockIndex* pblockindex = chainActive[blockRewardNum];

        if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus(), 1))
        {
            if (LogAcceptCategory("crosshainexports"))
            {
                printf("%s: Unable to read block from disk to get fee recipient from coinbase\n", __func__);
                LogPrintf("%s: Unable to read block from disk to get fee recipient from coinbase\n", __func__);
            }
            return false;
        }

        std::vector<CTxDestination> addresses;
        int nRequired;
        COptCCParams frP;
        txnouttype txOutType;
        if (block.vtx.size() &&
            block.vtx[0].vout.size() &&
            ExtractDestinations(block.vtx[0].vout[0].scriptPubKey, txOutType, addresses, nRequired) &&
            addresses.size() &&
            nRequired == 1)
        {
            if (block.vtx[0].vout[0].scriptPubKey.IsPayToCryptoCondition(frP) && frP.evalCode != EVAL_NONE)
            {
                CCcontract_info CC;
                CCcontract_info *cp;

                cp = CCinit(&CC, frP.evalCode);
                CTxDestination evalPKH = CPubKey(ParseHex(CC.CChexstr)).GetID();

                // first non-default address is the fee recipient
                for (auto &oneDest : addresses)
                {
                    if (oneDest == evalPKH || oneDest.which() == COptCCParams::ADDRTYPE_INVALID || oneDest.which() == COptCCParams::ADDRTYPE_INDEX)
                    {
                        continue;
                    }
                    feeRecipient.SetAuxDest(DestinationToTransferDestination(oneDest), 0);
                    break;
                }
            }
            else
            {
                feeRecipient.SetAuxDest(DestinationToTransferDestination(addresses[0]), 0);
            }
        }
    }

    // currency from reserve transfers will be stored appropriately for export as follows:
    // 1) Currency with this systemID can be exported to another chain, but it will be held on this
    //    chain in a reserve deposit output. The one exception to this rule is when a gateway currency
    //    that is using this systemID is being exported to itself as the other system. In that case,
    //    it is sent out and assumed burned from this system, just as it is created/minted when sent
    //    in from the gateway as the source system.
    //
    // 2) Currency being sent to the system of its origin is not tracked.
    //
    // 3) Currency from a system that is not this one being sent to a 3rd system is not allowed.
    //
    // get all the new reserve deposits. the only time we will merge old reserve deposit
    // outputs with current reserve deposit outputs is if there is overlap in currencies. the reserve
    // deposits for this new batch will be output together, and the currencies that are not present
    // in the new batch will be left in separate outputs, one per currency. this should enable old
    // currencies to get aggregated but still left behind and not carried forward when they drop out
    // of use.
    CCurrencyDefinition destSystem = ConnectedChains.GetCachedCurrency(destSystemID);

    if (!destSystem.IsValid())
    {
        printf("%s: Invalid data for export system or corrupt chain state\n", __func__);
        LogPrintf("%s: Invalid data for export system or corrupt chain state\n", __func__);
        return false;
    }

    if (isClearLaunchExport && destSystem.IsGateway() && !destSystem.IsNameController() && !_curDef.launchSystemID.IsNull())
    {
        if (_curDef.launchSystemID != ASSETCHAINS_CHAINID)
        {
            printf("%s: Mapped currency clear launch export can only be made on launch chain\n", __func__);
            LogPrintf("%s: Mapped currency clear launch export can only be made on launch chain\n", __func__);
            return false;
        }
        destSystem = ConnectedChains.ThisChain();
        destSystemID = ASSETCHAINS_CHAINID;
    }

    for (int i = 0; i < inputsConsumed; i++)
    {
        exportTransfers.push_back(std::get<2>(txInputs[i]));
    }

    uint256 transferHash;
    CCurrencyValueMap importedCurrency;
    CCurrencyValueMap gatewayDepositsUsed;
    CCurrencyValueMap spentCurrencyOut;
    std::vector<CTxOut> checkOutputs;

    CPBaaSNotarization intermediateNotarization = newNotarization;
    CCrossChainExport lastExport;
    bool isPostLaunch = false;
    if ((!isPreLaunch && !isClearLaunchExport) &&
        priorExports.size() &&
        (lastExport = CCrossChainExport(priorExports[0].scriptPubKey)).IsValid() &&
        (lastExport.IsClearLaunch() ||
          intermediateNotarization.IsLaunchComplete() ||
          (destSystemID != ASSETCHAINS_CHAINID && !isPreLaunch)))
    {
        // now, all exports are post launch
        isPostLaunch = true;
        intermediateNotarization.currencyState.SetLaunchCompleteMarker();
    }

    if (!intermediateNotarization.NextNotarizationInfo(ConnectedChains.ThisChain(),
                                                        _curDef,
                                                        sinceHeight,
                                                        addHeight,
                                                        exportTransfers,
                                                        transferHash,
                                                        newNotarization,
                                                        checkOutputs,
                                                        importedCurrency,
                                                        gatewayDepositsUsed,
                                                        spentCurrencyOut,
                                                        feeRecipient))
    {
        printf("%s: cannot create notarization\n", __func__);
        LogPrintf("%s: cannot create notarization\n", __func__);
        return false;
    }

    //printf("%s: num transfers %ld\n", __func__, exportTransfers.size());

    // if we are refunding, redirect the export back to the launch chain
    if (newNotarization.currencyState.IsRefunding())
    {
        if (destSystemID != _curDef.launchSystemID &&
            inputStartNum > 1)
        {
            inputStartNum--;
        }
        destSystemID = _curDef.launchSystemID;
        crossSystem = destSystemID != ASSETCHAINS_CHAINID;
        destSystem = ConnectedChains.GetCachedCurrency(destSystemID);
        if (!destSystem.IsValid())
        {
            printf("%s: Invalid data for export system or corrupt chain state\n", __func__);
            LogPrintf("%s: Invalid data for export system or corrupt chain state\n", __func__);
            return false;
        }
    }

    newNotarization.prevNotarization = lastNotarizationUTXO;

    CCurrencyValueMap totalExports;
    CCurrencyValueMap newReserveDeposits;
    CCurrencyValueMap exportBurn;

    for (int i = 0; i < exportTransfers.size(); i++)
    {
        totalExports += exportTransfers[i].TotalCurrencyOut();
    }

    /* printf("%s: num transfers %ld, totalExports: %s\nnewNotarization: %s\n",
        __func__,
        exportTransfers.size(),
        totalExports.ToUniValue().write(1,2).c_str(),
        newNotarization.ToUniValue().write(1,2).c_str()); */

    // if we are exporting off of this system to a gateway or PBaaS chain, don't allow 3rd party
    // or unregistered currencies to export. if same to same chain, all exports are ok.
    if (destSystemID != ASSETCHAINS_CHAINID)
    {
        if (!ConnectedChains.CurrencyExportStatus(totalExports, ASSETCHAINS_CHAINID, destSystemID, newReserveDeposits, exportBurn))
        {
            return false;
        }
    }
    else
    {
        // we should have no export from this system to this system directly
        assert(currencyID != ASSETCHAINS_CHAINID);

        // when we export from this system to a specific currency on this system,
        // we record the reserve deposits for the destination currency to ensure they are available for imports
        // which take them as inputs.
        newReserveDeposits = totalExports;
    }

    // now, we have:
    // 1) those transactions that we will take
    // 2) new reserve deposits for this export
    // 3) all transfer and expected conversion fees, including those in the second leg
    // 4) total of all currencies exported, whether fee, reserve deposit, or neither
    // 5) hash of all reserve transfers to be exported
    // 6) all reserve transfers are added to our transaction inputs

    // next actions:
    // 1) create the export
    // 2) add reserve deposit output to transaction
    // 3) if destination currency is pre-launch, update notarization based on pre-conversions
    // 4) if fractional currency is target, check fees against minimums or targets based on conversion rates in currency
    // 5) if post launch, call AddReserveTransferImportOutputs to go from the old currency state and notarization to the new one
    // 6) if actual launch closure, make launch initiating export + initial notarization

    // currencies that are going into this export and not being recorded as reserve deposits will
    // have been recorded on the other side and are being unwound. they should be considered
    // burned on this system.

    // inputs can be:
    // 1. transfers of reserve or tokens for fractional reserve chains
    // 2. pre-conversions for pre-launch participation in the premine
    // 3. reserve market conversions
    //

    CCurrencyValueMap estimatedFees = CCurrencyValueMap(newNotarization.currencyState.currencies, newNotarization.currencyState.fees).CanonicalMap();
    if (newNotarization.currencyState.primaryCurrencyFees)
    {
        estimatedFees.valueMap[newNotarization.currencyState.GetID()] = newNotarization.currencyState.primaryCurrencyFees;
    }

    uint32_t fromBlock = sinceHeight + 1;
    uint32_t toBlock = addHeight < curHeight ? addHeight : addHeight - 1;

    //printf("%s: total export amounts:\n%s\n", __func__, totalAmounts.ToUniValue().write().c_str());
    CCrossChainExport ccx(ASSETCHAINS_CHAINID,
                          fromBlock,
                          toBlock,
                          destSystemID,
                          currencyID,
                          exportTransfers.size(),
                          totalExports.CanonicalMap(),
                          estimatedFees,
                          transferHash,
                          exportBurn,
                          inputStartNum,
                          feeRecipient);

    ccx.SetPreLaunch(isPreLaunch);
    ccx.SetPostLaunch(isPostLaunch);
    ccx.SetClearLaunch(isClearLaunchExport);

    // if we should add a system export, do so
    CCrossChainExport sysCCX;
    if (crossSystem && ccx.destSystemID != ccx.destCurrencyID)
    {
        if (priorExports.size() != 2)
        {
            printf("%s: Invalid prior system export for export ccx: %s\n", __func__, ccx.ToUniValue().write(1,2).c_str());
            return false;
        }
        COptCCParams p;

        if (!(priorExports[1].scriptPubKey.IsPayToCryptoCondition(p) &&
              p.IsValid() &&
              p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
              p.vData.size() &&
              (sysCCX = CCrossChainExport(p.vData[0])).IsValid()))
        {
            printf("%s: Invalid prior system export\n", __func__);
            LogPrintf("%s: Invalid prior system export\n", __func__);
            return false;
        }
        sysCCX = CCrossChainExport(ASSETCHAINS_CHAINID,
                                   sysCCX.sourceHeightStart,
                                   sysCCX.sourceHeightEnd,
                                   destSystemID,
                                   destSystemID,
                                   txInputs.size(),
                                   totalExports.CanonicalMap(),
                                   estimatedFees,
                                   transferHash,
                                   CCurrencyValueMap(),
                                   inputStartNum,
                                   feeRecipient,
                                   std::vector<CReserveTransfer>(),
                                   sysCCX.flags);
        sysCCX.SetSystemThreadExport();
    }

    CAmount nativeReserveDeposit = 0;
    if (newReserveDeposits.valueMap.count(ASSETCHAINS_CHAINID))
    {
        nativeReserveDeposit = newReserveDeposits.valueMap[ASSETCHAINS_CHAINID];
    }

    CCcontract_info CC;
    CCcontract_info *cp;

    if (newReserveDeposits.valueMap.size())
    {
        /* printf("%s: nativeDeposit %ld, reserveDeposits: %s\n",
            __func__,
            nativeReserveDeposit,
            newReserveDeposits.ToUniValue().write(1,2).c_str()); */

        // now send transferred currencies to a reserve deposit
        cp = CCinit(&CC, EVAL_RESERVE_DEPOSIT);

        // send the entire amount to a reserve deposit output of the specific chain
        // we receive our fee on the other chain, when it comes back, or if a token,
        // when it gets imported back to the chain
        std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});
        // if going off-system, reserve deposits accrue to the destination system, if same system, to the currency
        CReserveDeposit rd = CReserveDeposit(crossSystem ? destSystemID : (newNotarization.IsRefunding() && _curDef.systemID != destSystemID ? _curDef.systemID : currencyID), newReserveDeposits);
        exportOutputs.push_back(CTxOut(nativeReserveDeposit, MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &rd))));
    }

    int exportOutNum = exportOutputs.size();

    cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
    std::vector<CTxDestination> dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr)).GetID()});
    exportOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &ccx))));

    // only add an extra system export if we are really exporting to another system. refunds are redirected back.
    bool isRefunding = newNotarization.currencyState.IsRefunding();
    if (!isRefunding && crossSystem && ccx.destSystemID != ccx.destCurrencyID)
    {
        exportOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &sysCCX))));
    }

    // all exports to a currency on this chain include a finalization that is spent by the import of this export
    // external systems and gateways get one finalization for their clear to launch export
    if (isClearLaunchExport || (destSystemID == ASSETCHAINS_CHAINID && newNotarization.IsLaunchCleared()))
    {
        cp = CCinit(&CC, EVAL_FINALIZE_EXPORT);

        CObjectFinalization finalization(CObjectFinalization::FINALIZE_EXPORT, destSystemID, uint256(), exportOutNum);

        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr)).GetID()});
        exportOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_EXPORT, dests, 1, &finalization))));
    }

    // if this is a pre-launch export, including clear launch, update notarization and add it to the export outputs
    if (isClearLaunchExport || isPreLaunch)
    {
        newNotarizationOutNum = exportOutputs.size();
        cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr)).GetID()});
        exportOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &newNotarization))));
    }

    return true;
}

void CConnectedChains::AggregateChainTransfers(const CTransferDestination &feeRecipient, uint32_t nHeight)
{
    // all chains aggregate reserve transfer transactions, so aggregate and add all necessary export transactions to the mem pool
    {
        if (!nHeight)
        {
            return;
        }

        std::multimap<uint160, ChainTransferData> transferOutputs;

        LOCK(cs_main);

        // if we are paused on cross-chain, return error until enabled
        if (ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableDeFiKey()))
        {
            if (LogAcceptCategory("defi"))
            {
                LogPrintf("%s: DeFi functions temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
            }
            return;
        }

        uint160 thisChainID = ConnectedChains.ThisChain().GetID();

        uint32_t nHeight = chainActive.Height();

        // check for currencies that should launch in the last 20 blocks, haven't yet, and can have their launch export mined
        // if we find any that have no export creation pending, add it to imports
        std::vector<CAddressIndexDbEntry> rawCurrenciesToLaunch;
        std::map<uint160, std::pair<CCurrencyDefinition, CUTXORef>> launchCurrencies;
        if (GetAddressIndex(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::CurrencyLaunchKey()),
                            CScript::P2IDX,
                            rawCurrenciesToLaunch,
                            nHeight - 50 < 0 ? 0 : nHeight - 50,
                            nHeight) &&
            rawCurrenciesToLaunch.size())
        {
            // add any unlaunched currencies as an output
            for (auto &oneDefIdx : rawCurrenciesToLaunch)
            {
                CTransaction defTx;
                uint256 hashBlk;
                COptCCParams p;
                CCurrencyDefinition oneDef;
                if (myGetTransaction(oneDefIdx.first.txhash, defTx, hashBlk) &&
                    defTx.vout.size() > oneDefIdx.first.index &&
                    defTx.vout[oneDefIdx.first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_CURRENCY_DEFINITION &&
                    p.vData.size() &&
                    (oneDef = CCurrencyDefinition(p.vData[0])).IsValid() &&
                    oneDef.launchSystemID == ASSETCHAINS_CHAINID)
                {
                    launchCurrencies.insert(std::make_pair(oneDef.GetID(), std::make_pair(oneDef, CUTXORef())));
                }
            }
        }

        // get all available transfer outputs to aggregate into export transactions
        if (GetUnspentChainTransfers(transferOutputs))
        {
            if (!(transferOutputs.size() || launchCurrencies.size()))
            {
                return;
            }

            std::multimap<uint32_t, ChainTransferData> txInputs;
            uint160 lastChain = transferOutputs.size() ? transferOutputs.begin()->first : launchCurrencies.begin()->second.first.GetID();

            CCoins coins;
            CCoinsView dummy;
            CCoinsViewCache view(&dummy);

            LOCK2(smartTransactionCS, mempool.cs);
            CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
            view.SetBackend(viewMemPool);

            auto outputIt = transferOutputs.begin();
            bool checkLaunchCurrencies = false;
            for (int outputsDone = 0;
                 outputsDone <= transferOutputs.size() || launchCurrencies.size();
                 outputsDone++)
            {
                if (outputIt != transferOutputs.end())
                {
                    auto &output = *outputIt;
                    if (output.first == lastChain)
                    {
                        txInputs.insert(std::make_pair(std::get<0>(output.second), output.second));
                        outputIt++;
                        continue;
                    }
                }
                else if (checkLaunchCurrencies || !transferOutputs.size())
                {
                    // we are done with all natural exports and have deleted any launch entries that had natural exports,
                    // since they should also handle launch naturally.
                    // if we have launch currencies that have not been launched and do not have associated
                    // transfer outputs, force launch them
                    std::vector<uint160> toErase;
                    for (auto &oneLaunchCur : launchCurrencies)
                    {
                        CChainNotarizationData cnd;
                        std::vector<std::pair<CTransaction, uint256>> txes;

                        // ensure that a currency is still unlaunched before
                        // marking it for launch
                        if (!(GetNotarizationData(oneLaunchCur.first, cnd, &txes) &&
                              cnd.vtx[cnd.lastConfirmed].second.IsValid() &&
                              !(cnd.vtx[cnd.lastConfirmed].second.currencyState.IsLaunchClear() ||
                                cnd.vtx[cnd.lastConfirmed].second.IsLaunchCleared())))
                        {
                            toErase.push_back(oneLaunchCur.first);
                        }
                    }
                    for (auto &oneToErase : toErase)
                    {
                        launchCurrencies.erase(oneToErase);
                    }
                    if (launchCurrencies.size())
                    {
                        lastChain = launchCurrencies.begin()->first;
                    }
                }
                else
                {
                    // this is when we have to finish one round and then continue with currency launches
                    checkLaunchCurrencies = launchCurrencies.size() != 0;
                }

                CCurrencyDefinition destDef, systemDef;

                destDef = GetCachedCurrency(lastChain);

                if (!destDef.IsValid())
                {
                    printf("%s: cannot find destination currency %s\n", __func__, EncodeDestination(CIdentityID(lastChain)).c_str());
                    LogPrintf("%s: cannot find destination currency %s\n", __func__, EncodeDestination(CIdentityID(lastChain)).c_str());
                    break;
                }
                uint160 destID = lastChain;

                if (destDef.systemID == thisChainID)
                {
                    if (destDef.IsGateway())
                    {
                        // if the currency is a gateway on this system, any exports go through it to the gateway, not the system ID
                        systemDef = GetCachedCurrency(destDef.gatewayID);
                    }
                    else
                    {
                        systemDef = thisChain;
                    }
                }
                else if (destDef.systemID == destID)
                {
                    systemDef = destDef;
                }
                else
                {
                    systemDef = GetCachedCurrency(destDef.systemID);

                    // any sends to a destination that is not connected will fail
                    // if this gateway or PBaaS chain was launched from this system
                    if (!(systemDef.IsPBaaSChain() || systemDef.IsGateway()) ||
                        !(systemDef.launchSystemID == ASSETCHAINS_CHAINID || ConnectedChains.ThisChain().launchSystemID == destDef.systemID))
                    {
                        printf("%s: Attempt to export to disconnected system %s\n", __func__, GetFriendlyCurrencyName(destDef.systemID).c_str());
                        LogPrintf("%s: Attempt to export to disconnected system %s\n", __func__, GetFriendlyCurrencyName(destDef.systemID).c_str());
                        continue;
                    }
                }

                if (!systemDef.IsValid())
                {
                    printf("%s: cannot find destination system definition %s\n", __func__, EncodeDestination(CIdentityID(destDef.systemID)).c_str());
                    LogPrintf("%s: cannot find destination system definition %s\n", __func__, EncodeDestination(CIdentityID(destDef.systemID)).c_str());
                    break;
                }

                bool isSameChain = destDef.SystemOrGatewayID() == thisChainID;

                if (!isSameChain && ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisablePBaaSCrossChainKey()))
                {
                    if (LogAcceptCategory("crosschainexports"))
                    {
                        LogPrintf("%s: Cross-chain functions temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
                    }
                    continue;
                }
                if (systemDef.IsGateway() && ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableGatewayCrossChainKey()))
                {
                    if (LogAcceptCategory("crosschainexports"))
                    {
                        LogPrintf("%s: Cross-chain function for non-PBaaS gateways temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
                    }
                    continue;
                }

                // when we get here, we have a consecutive number of transfer outputs to consume in txInputs
                // we need an unspent export output to export, or use the last one of it is an export to the same
                // system
                std::vector<std::pair<int, CInputDescriptor>> exportOutputs;
                std::vector<std::pair<int, CInputDescriptor>> sysExportOutputs;
                std::vector<CInputDescriptor> allExportOutputs;

                // export outputs must come from the latest, including mempool, to ensure
                // enforcement of sequential exports. get unspent currency export, and if not on the current
                // system, the external system export as well

                bool newSystem = false;
                if (launchCurrencies.count(lastChain) && destDef.SystemOrGatewayID() == lastChain)
                {
                    newSystem = true;
                }

                bool havePrimaryExports = ConnectedChains.GetUnspentCurrencyExports(view, lastChain, exportOutputs) && exportOutputs.size();
                if (!havePrimaryExports && !exportOutputs.size() && destDef.SystemOrGatewayID() == lastChain)
                {
                    havePrimaryExports = ConnectedChains.GetUnspentSystemExports(view, destDef.SystemOrGatewayID(), exportOutputs) && exportOutputs.size();
                }

                if ((isSameChain && havePrimaryExports) ||
                    (!isSameChain &&
                     (lastChain == destDef.SystemOrGatewayID() && havePrimaryExports) ||
                     (lastChain != destDef.SystemOrGatewayID() &&
                      (ConnectedChains.GetUnspentSystemExports(view, destDef.SystemOrGatewayID(), sysExportOutputs) && sysExportOutputs.size() ||
                       ConnectedChains.GetUnspentCurrencyExports(view, destDef.SystemOrGatewayID(), sysExportOutputs) && sysExportOutputs.size()))))
                {
                    if (!exportOutputs.size())
                    {
                        exportOutputs.push_back(sysExportOutputs[0]);
                    }
                    assert(exportOutputs.size() == 1);
                    std::pair<int, CInputDescriptor> lastExport = exportOutputs[0];
                    allExportOutputs.push_back(lastExport.second);
                    std::pair<int, CInputDescriptor> lastSysExport = std::make_pair(-1, CInputDescriptor());
                    if (!isSameChain)
                    {
                        if (lastChain == destDef.SystemOrGatewayID())
                        {
                            lastSysExport = exportOutputs[0];
                        }
                        else
                        {
                            lastSysExport = sysExportOutputs[0];
                            allExportOutputs.push_back(lastSysExport.second);
                        }
                    }

                    COptCCParams p;
                    CCrossChainExport ccx, sysCCX;
                    if (!(lastExport.second.scriptPubKey.IsPayToCryptoCondition(p) &&
                          p.IsValid() &&
                          p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                          p.vData.size() &&
                          (ccx = CCrossChainExport(p.vData[0])).IsValid()) ||
                        !(isSameChain ||
                          (lastSysExport.second.scriptPubKey.IsPayToCryptoCondition(p) &&
                           p.IsValid() &&
                           p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                           p.vData.size() &&
                           (sysCCX = CCrossChainExport(p.vData[0])).IsValid())))
                    {
                        printf("%s: invalid export(s) for %s in index\n", __func__, EncodeDestination(CIdentityID(destID)).c_str());
                        LogPrintf("%s: invalid export(s) for %s in index\n", __func__, EncodeDestination(CIdentityID(destID)).c_str());
                        break;
                    }

                    // now, in the case that these are both the same export, and/or if this is a sys export thread export
                    // merge into one export
                    bool mergedSysExport = false;
                    if (!isSameChain &&
                        ccx.destCurrencyID == ccx.destSystemID)
                    {
                        ccx.SetSystemThreadExport(false);
                        mergedSysExport = true;
                    }

                    CChainNotarizationData cnd;
                    std::vector<std::pair<CTransaction, uint256>> notarizationTxes;

                    // attempt to export from current chain to current chain
                    // skip this
                    if (lastChain == ASSETCHAINS_CHAINID)
                    {
                        if (LogAcceptCategory("crosschainexports"))
                        {
                            LogPrintf("%s: Attempt to export from current chain to current chain on %s\n", ConnectedChains.GetFriendlyCurrencyName(ASSETCHAINS_CHAINID).c_str());
                        }
                        continue;
                    }

                    // get notarization for the actual currency destination
                    if (!GetNotarizationData(lastChain, cnd, &notarizationTxes) ||
                        cnd.lastConfirmed == -1 ||
                        !cnd.vtx.size() ||
                        notarizationTxes.size() != cnd.vtx.size())
                    {
                        if (LogAcceptCategory("crosschainexports"))
                        {
                            printf("%s: missing or invalid notarization for %s\n", __func__, EncodeDestination(CIdentityID(destID)).c_str());
                            LogPrintf("%s: missing or invalid notarization for %s\n", __func__, EncodeDestination(CIdentityID(destID)).c_str());
                            if (notarizationTxes.size() != cnd.vtx.size())
                            {
                                printf("NOTE: notarization and transaction vectors are not the same size - cnd.vtx.size(): %ld, notarizationTxes.size(): %ld\n", cnd.vtx.size(), notarizationTxes.size());
                                LogPrintf("NOTE: notarization and transaction vectors are not the same size\n");
                            }
                        }
                        continue;
                    }

                    CPBaaSNotarization lastNotarization = cnd.vtx[cnd.lastConfirmed].second;
                    CInputDescriptor lastNotarizationInput =
                        CInputDescriptor(notarizationTxes[cnd.lastConfirmed].first.vout[cnd.vtx[cnd.lastConfirmed].first.n].scriptPubKey,
                                         notarizationTxes[cnd.lastConfirmed].first.vout[cnd.vtx[cnd.lastConfirmed].first.n].nValue,
                                         CTxIn(cnd.vtx[cnd.lastConfirmed].first));

                    if (destDef.systemID != ASSETCHAINS_CHAINID &&
                        cnd.vtx[cnd.lastConfirmed].second.IsLaunchConfirmed())
                    {
                        CChainNotarizationData systemCND;
                        if (GetNotarizationData(destDef.systemID, systemCND) &&
                            systemCND.lastConfirmed != -1 &&
                            systemCND.vtx[systemCND.lastConfirmed].second.currencyStates.count(lastChain) &&
                            systemCND.vtx[systemCND.lastConfirmed].second.currencyStates[lastChain].IsLaunchCompleteMarker())
                        {
                            lastNotarization.currencyState = systemCND.vtx[systemCND.lastConfirmed].second.currencyStates[lastChain];
                            lastNotarization.flags = systemCND.vtx[systemCND.lastConfirmed].second.flags;
                        }
                    }

                    CPBaaSNotarization newNotarization;
                    int newNotarizationOutNum;

                    if (lastNotarization.currencyState.IsFractional() && lastNotarization.IsPreLaunch() && destDef.startBlock > nHeight)
                    {
                        // on pre-launch, we need to ensure no overflow in first pass, so we normalize expected pricing
                        // on the way in
                        CCoinbaseCurrencyState pricesState = ConnectedChains.GetCurrencyState(destDef, nHeight);
                        assert(lastNotarization.currencyState.IsValid() && lastNotarization.currencyState.GetID() == lastChain);
                        lastNotarization.currencyState.conversionPrice = pricesState.PricesInReserve();
                    }

                    // now, we have the previous export to this currency/system, which we should spend to
                    // enable this new export. if we find no export, we're done
                    int32_t numInputsUsed;
                    std::vector<CTxOut> exportTxOuts;
                    std::vector<CReserveTransfer> exportTransfers;

                    while (txInputs.size() && txInputs.begin()->first <= ccx.sourceHeightEnd)
                    {
                        txInputs.erase(txInputs.begin());
                    }

                    while (txInputs.size() || launchCurrencies.count(lastChain))
                    {
                        launchCurrencies.erase(lastChain);
                        //printf("%s: launchCurrencies.size(): %ld\n", __func__, launchCurrencies.size());

                        // even if we have no txInputs, currencies that need to will launch
                        newNotarizationOutNum = -1;
                        exportTxOuts.clear();
                        exportTransfers.clear();
                        if (!CConnectedChains::CreateNextExport(destDef,
                                                                txInputs,
                                                                allExportOutputs,
                                                                feeRecipient,
                                                                ccx.sourceHeightEnd,
                                                                nHeight + 1,
                                                                (!isSameChain && !mergedSysExport) ? 2 : 1, // reserve transfers start at input 1 on same chain or after sys
                                                                numInputsUsed,
                                                                exportTxOuts,
                                                                exportTransfers,
                                                                lastNotarization,
                                                                CUTXORef(lastNotarizationInput.txIn.prevout),
                                                                newNotarization,
                                                                newNotarizationOutNum))
                        {
                            printf("%s: unable to create export for %s\n", __func__, EncodeDestination(CIdentityID(destID)).c_str());
                            LogPrintf("%s: unable to create export for  %s\n", __func__, EncodeDestination(CIdentityID(destID)).c_str());
                            break;
                        }

                        // now, if we have created any outputs, we have a transaction to make, if not, we are done
                        if (!exportTxOuts.size())
                        {
                            txInputs.clear();
                            break;
                        }

                        if (newNotarization.IsRefunding() && destDef.launchSystemID == ASSETCHAINS_CHAINID)
                        {
                            isSameChain = true;
                        }

                        TransactionBuilder tb(Params().GetConsensus(), nHeight + 1);
                        tb.SetFee(0);

                        // add input from last export, all consumed txInputs, and all outputs created to make
                        // the new export tx. since we are exporting from this chain

                        //UniValue scriptUniOut;
                        //ScriptPubKeyToUniv(lastExport.second.scriptPubKey, scriptUniOut, false);
                        //printf("adding input %d with %ld nValue and script:\n%s\n", (int)tb.mtx.vin.size(), lastExport.second.nValue, scriptUniOut.write(1,2).c_str());

                        // first add previous export
                        tb.AddTransparentInput(lastExport.second.txIn.prevout, lastExport.second.scriptPubKey, lastExport.second.nValue);

                        // if going to another system, add the system export thread as well
                        if (!isSameChain && !mergedSysExport)
                        {
                            //scriptUniOut = UniValue(UniValue::VOBJ);
                            //ScriptPubKeyToUniv(lastSysExport.second.scriptPubKey, scriptUniOut, false);
                            //printf("adding input %d with %ld nValue and script:\n%s\n", (int)tb.mtx.vin.size(), lastSysExport.second.nValue, scriptUniOut.write(1,2).c_str());

                            tb.AddTransparentInput(lastSysExport.second.txIn.prevout, lastSysExport.second.scriptPubKey, lastSysExport.second.nValue);
                        }

                        // now, all reserve transfers used
                        int numInputsAdded = 0;
                        for (auto &oneInput : txInputs)
                        {
                            if (numInputsAdded >= numInputsUsed)
                            {
                                break;
                            }
                            CInputDescriptor inputDesc = std::get<1>(oneInput.second);

                            //scriptUniOut = UniValue(UniValue::VOBJ);
                            //ScriptPubKeyToUniv(inputDesc.scriptPubKey, scriptUniOut, false);
                            //printf("adding input %d with %ld nValue and script:\n%s\n", (int)tb.mtx.vin.size(), inputDesc.nValue, scriptUniOut.write(1,2).c_str());

                            tb.AddTransparentInput(inputDesc.txIn.prevout, inputDesc.scriptPubKey, inputDesc.nValue);
                            numInputsAdded++;
                        }

                        // if we have an output notarization, spend the last one
                        if (newNotarizationOutNum >= 0)
                        {
                            //scriptUniOut = UniValue(UniValue::VOBJ);
                            //ScriptPubKeyToUniv(lastNotarizationInput.scriptPubKey, scriptUniOut, false);
                            //printf("adding input %d with %ld nValue and script:\n%s\n", (int)tb.mtx.vin.size(), lastNotarizationInput.nValue, scriptUniOut.write(1,2).c_str());

                            tb.AddTransparentInput(lastNotarizationInput.txIn.prevout,
                                                   lastNotarizationInput.scriptPubKey,
                                                   lastNotarizationInput.nValue);
                        }

                        // now, add all outputs to the transaction
                        auto thisExport = lastExport;
                        int outputNum = tb.mtx.vout.size();

                        int exOutNum = -1;
                        int sysExOutNum = -1;

                        for (auto &oneOut : exportTxOuts)
                        {
                            COptCCParams xp;
                            CCrossChainExport checkCCX;
                            if (oneOut.scriptPubKey.IsPayToCryptoCondition(xp) &&
                                xp.IsValid() &&
                                xp.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                                (checkCCX = CCrossChainExport(xp.vData[0])).IsValid())
                            {
                                if (checkCCX.IsSystemThreadExport())
                                {
                                    sysExOutNum = outputNum;
                                }
                                else
                                {
                                    thisExport.second.scriptPubKey = oneOut.scriptPubKey;
                                    thisExport.second.nValue = oneOut.nValue;
                                    thisExport.first = checkCCX.sourceHeightEnd;
                                    thisExport.second.txIn.prevout.n = outputNum;
                                    ccx = checkCCX;
                                    exOutNum = outputNum;
                                }
                            }

                            /* scriptUniOut = UniValue(UniValue::VOBJ);
                            ScriptPubKeyToUniv(oneOut.scriptPubKey, scriptUniOut, false);
                            printf("%s: adding output %d with %ld nValue and script:\n%s\n", __func__, (int)tb.mtx.vout.size(), oneOut.nValue, scriptUniOut.write(1,2).c_str());
                            */

                            tb.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nValue);
                            outputNum++;
                        }

                        allExportOutputs.clear();

                        if (LogAcceptCategory("crosschainexports"))
                        {
                            UniValue uni(UniValue::VOBJ);
                            TxToUniv(tb.mtx, uint256(), uni);
                            printf("%s: Ready to build tx:\n%s\n", __func__, uni.write(1,2).c_str()); // */
                        }

                        TransactionBuilderResult buildResult(tb.Build());

                        if (!buildResult.IsError() && buildResult.IsTx())
                        {
                            // replace the last one only if we have a valid new one
                            CTransaction tx = buildResult.GetTxOrThrow();

                            allExportOutputs.push_back(CInputDescriptor(tx.vout[exOutNum].scriptPubKey, tx.vout[exOutNum].nValue, CTxIn(tx.GetHash(), exOutNum)));

                            if (sysExOutNum >= 0)
                            {
                                allExportOutputs.push_back(CInputDescriptor(tx.vout[sysExOutNum].scriptPubKey, tx.vout[sysExOutNum].nValue, CTxIn(tx.GetHash(), sysExOutNum)));
                            }

                            if (newNotarizationOutNum >= 0)
                            {
                                lastNotarization = newNotarization;
                                lastNotarizationInput = CInputDescriptor(tx.vout[newNotarizationOutNum].scriptPubKey,
                                                                         tx.vout[newNotarizationOutNum].nValue,
                                                                         CTxIn(tx.GetHash(), newNotarizationOutNum));
                            }

                            /* uni = UniValue(UniValue::VOBJ);
                            TxToUniv(tx, uint256(), uni);
                            printf("%s: successfully built tx:\n%s\n", __func__, uni.write(1,2).c_str()); */

                            static int lastHeight = 0;
                            // remove conflicts, so that we get in
                            std::list<CTransaction> removed;
                            mempool.removeConflicts(tx, removed);

                            // add to mem pool, prioritize according to the fee we will get
                            //printf("Created and signed export transaction %s\n", tx.GetHash().GetHex().c_str());
                            //LogPrintf("Created and signed export transaction %s\n", tx.GetHash().GetHex().c_str());
                            CValidationState memPoolState;
                            if (myAddtomempool(tx, &memPoolState, 0, false))
                            {
                                uint256 hash = tx.GetHash();
                                thisExport.second.txIn.prevout.hash = hash;
                                lastExport = thisExport;
                                if (sysExOutNum >= 0)
                                {
                                    lastSysExport.first = thisExport.first;
                                    lastSysExport.second = allExportOutputs.back();
                                }
                                CAmount nativeExportFees = ccx.totalFees.valueMap[ASSETCHAINS_CHAINID] ? ccx.totalFees.valueMap[ASSETCHAINS_CHAINID] : 10000;
                                mempool.PrioritiseTransaction(hash, hash.GetHex(), (double)(nativeExportFees << 1), nativeExportFees);
                            }
                            else
                            {
                                UniValue uni(UniValue::VOBJ);
                                TxToUniv(tx, uint256(), uni);
                                printf("%s: created invalid transaction:\n%s\n", __func__, uni.write(1,2).c_str());
                                LogPrintf("%s: error (%s) created invalid transaction:\n%s\n", __func__, memPoolState.GetRejectReason().c_str(), uni.write(1,2).c_str());
                                break;
                            }

                            UpdateCoins(tx, view, nHeight + 1);
                        }
                        else
                        {
                            // we can't do any more useful work for this chain if we failed here
                            printf("Failed to create export transaction: %s\n", buildResult.GetError().c_str());
                            LogPrintf("Failed to create export transaction: %s\n", buildResult.GetError().c_str());
                            break;
                        }

                        // erase the inputs we've attempted to spend and loop for another export tx
                        for (; numInputsAdded > 0; numInputsAdded--)
                        {
                            txInputs.erase(txInputs.begin());
                        }
                    }
                }
                txInputs.clear();
                launchCurrencies.erase(lastChain);

                if (outputIt != transferOutputs.end())
                {
                    lastChain = outputIt->first;
                    txInputs.insert(std::make_pair(std::get<0>(outputIt->second), outputIt->second));
                    outputIt++;
                }
            }
            CheckImports();
        }
    }
}

void CConnectedChains::SignAndCommitImportTransactions(const CTransaction &lastImportTx, const std::vector<CTransaction> &transactions)
{
    int nHeight = chainActive.LastTip()->GetHeight();
    uint32_t consensusBranchId = CurrentEpochBranchId(nHeight, Params().GetConsensus());
    LOCK2(cs_main, mempool.cs);

    uint256 lastHash, lastSignedHash;
    CCoinsViewCache view(pcoinsTip);

    // sign and commit the transactions
    for (auto &_tx : transactions)
    {
        CMutableTransaction newTx(_tx);

        if (!lastHash.IsNull())
        {
            //printf("last hash before signing: %s\n", lastHash.GetHex().c_str());
            for (auto &oneIn : newTx.vin)
            {
                //printf("checking input with hash: %s\n", oneIn.prevout.hash.GetHex().c_str());
                if (oneIn.prevout.hash == lastHash)
                {
                    oneIn.prevout.hash = lastSignedHash;
                    //printf("updated hash before signing: %s\n", lastSignedHash.GetHex().c_str());
                }
            }
        }
        lastHash = _tx.GetHash();
        CTransaction tx = newTx;

        // sign the transaction and submit
        bool signSuccess = false;
        for (int i = 0; i < tx.vin.size(); i++)
        {
            SignatureData sigdata;
            CAmount value;
            CScript outputScript;

            if (tx.vin[i].prevout.hash == lastImportTx.GetHash())
            {
                value = lastImportTx.vout[tx.vin[i].prevout.n].nValue;
                outputScript = lastImportTx.vout[tx.vin[i].prevout.n].scriptPubKey;
            }
            else
            {
                CCoins coins;
                if (!view.GetCoins(tx.vin[i].prevout.hash, coins))
                {
                    fprintf(stderr,"%s: cannot get input coins from tx: %s, output: %d\n", __func__, tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    LogPrintf("%s: cannot get input coins from tx: %s, output: %d\n", __func__, tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    break;
                }
                value = coins.vout[tx.vin[i].prevout.n].nValue;
                outputScript = coins.vout[tx.vin[i].prevout.n].scriptPubKey;
            }

            signSuccess = ProduceSignature(TransactionSignatureCreator(nullptr, &tx, i, value, SIGHASH_ALL), outputScript, sigdata, consensusBranchId);

            if (!signSuccess)
            {
                fprintf(stderr,"%s: failure to sign transaction\n", __func__);
                LogPrintf("%s: failure to sign transaction\n", __func__);
                break;
            } else {
                UpdateTransaction(newTx, i, sigdata);
            }
        }

        if (signSuccess)
        {
            // push to local node and sync with wallets
            CValidationState state;
            bool fMissingInputs;
            CTransaction signedTx(newTx);

            //DEBUGGING
            //TxToJSON(tx, uint256(), jsonTX);
            //printf("signed transaction:\n%s\n", jsonTX.write(1, 2).c_str());

            if (!AcceptToMemoryPool(mempool, state, signedTx, false, false, &fMissingInputs)) {
                if (state.IsInvalid()) {
                    //UniValue txUni(UniValue::VOBJ);
                    //TxToUniv(signedTx, uint256(), txUni);
                    //fprintf(stderr,"%s: rejected by memory pool for %s\n%s\n", __func__, state.GetRejectReason().c_str(), txUni.write(1,2).c_str());
                    LogPrintf("%s: rejected by memory pool for %s\n", __func__, state.GetRejectReason().c_str());
                } else {
                    if (fMissingInputs) {
                        fprintf(stderr,"%s: missing inputs\n", __func__);
                        LogPrintf("%s: missing inputs\n", __func__);
                    }
                    else
                    {
                        fprintf(stderr,"%s: rejected by memory pool for %s\n", __func__, state.GetRejectReason().c_str());
                        LogPrintf("%s: rejected by memory pool for %s\n", __func__, state.GetRejectReason().c_str());
                    }
                }
                break;
            }
            else
            {
                UpdateCoins(signedTx, view, nHeight + 1);
                lastSignedHash = signedTx.GetHash();
            }
        }
        else
        {
            break;
        }
    }
}

// process token related, local imports and exports
void CConnectedChains::ProcessLocalImports()
{
    // first determine all exports to the current/same system marked for action
    // next, get the last import of each export thread, package all pending exports,
    // and call CreateLatestImports

    std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> exportsOut;
    uint160 thisChainID = thisChain.GetID();

    LOCK(cs_main);
    uint32_t nHeight = chainActive.Height();

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;
    std::set<uint160> currenciesProcessed;
    uint160 finalizeExportKey(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CObjectFinalization::ObjectFinalizationExportKey()));
    std::vector<std::pair<CInputDescriptor, uint32_t>> inputDescriptors;

    {
        LOCK2(smartTransactionCS, mempool.cs);

        if (!ConnectedChains.GetUnspentByIndex(finalizeExportKey, inputDescriptors) || !inputDescriptors.size())
        {
            return;
        }
        std::map<uint160, std::map<uint32_t, std::pair<std::pair<CInputDescriptor,CTransaction>,CCrossChainExport>>>
            orderedExportsToFinalize;
        for (auto &oneFinalization : inputDescriptors)
        {
            COptCCParams p;
            CObjectFinalization of;
            CCrossChainExport ccx;
            CCrossChainImport cci;
            CTransaction scratchTx;
            int32_t importOutputNum;
            uint256 hashBlock;
            if (oneFinalization.first.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_FINALIZE_EXPORT &&
                p.vData.size() &&
                (of = CObjectFinalization(p.vData[0])).IsValid() &&
                myGetTransaction(of.output.hash.IsNull() ? oneFinalization.first.txIn.prevout.hash : of.output.hash, scratchTx, hashBlock) &&
                scratchTx.vout.size() > of.output.n &&
                scratchTx.vout[of.output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                p.vData.size() &&
                (ccx = CCrossChainExport(p.vData[0])).IsValid())
            {
                orderedExportsToFinalize[ccx.destCurrencyID].insert(
                    std::make_pair(ccx.sourceHeightStart,
                                   std::make_pair(std::make_pair(CInputDescriptor(scratchTx.vout[of.output.n].scriptPubKey,
                                                                                  scratchTx.vout[of.output.n].nValue,
                                                                                  CTxIn(of.output.hash.IsNull() ? oneFinalization.first.txIn.prevout.hash : of.output.hash,
                                                                                  of.output.n)),
                                                                 scratchTx),
                                                  ccx)));
            }
        }
        // now, we have a map of all currencies with ordered exports that have work to do and if pre-launch, may have more from this chain
        // export finalizations are either on the same transaction as the export, or in the case of a clear launch export,
        // there may be any number of pre-launch exports still to process prior to spending it
        for (auto &oneCurrencyExports : orderedExportsToFinalize)
        {
            CCrossChainExport &ccx = oneCurrencyExports.second.begin()->second.second;
            COptCCParams p;
            CCrossChainImport cci;
            CTransaction scratchTx;
            int32_t importOutputNum;
            uint256 hashBlock;
            if (GetLastImport(ccx.destCurrencyID, scratchTx, importOutputNum) &&
                scratchTx.vout.size() > importOutputNum &&
                scratchTx.vout[importOutputNum].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.vData.size() &&
                (cci = CCrossChainImport(p.vData[0])).IsValid() &&
                (cci.IsPostLaunch() || cci.IsDefinitionImport() || cci.sourceSystemID == ASSETCHAINS_CHAINID))
            {
                // if not post launch complete, we are launching from this chain and need to get exports
                // after the last import's source height
                if (ccx.IsClearLaunch())
                {
                    std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> exportsFound;
                    if (GetCurrencyExports(ccx.destCurrencyID, exportsFound, cci.sourceSystemHeight, nHeight))
                    {
                        uint256 cciExportTxHash = cci.exportTxId.IsNull() ? scratchTx.GetHash() : cci.exportTxId;
                        if (exportsFound.size())
                        {
                            // make sure we start from the first export not imported and skip the rest
                            auto startingIt = exportsFound.begin();
                            for ( ; startingIt != exportsFound.end(); startingIt++)
                            {
                                // if this is the first. then the first is the one we will always use
                                if (cci.IsDefinitionImport())
                                {
                                    break;
                                }
                                if (startingIt->first.first.txIn.prevout.hash == cciExportTxHash && startingIt->first.first.txIn.prevout.n == cci.exportTxOutNum)
                                {
                                    startingIt++;
                                    break;
                                }
                            }
                            exportsOut.insert(exportsOut.end(), startingIt, exportsFound.end());
                        }
                        currenciesProcessed.insert(ccx.destCurrencyID);
                    }
                    continue;
                }
                else
                {
                    // import all entries that are present, since that is the correct set
                    for (auto &oneExport : oneCurrencyExports.second)
                    {
                        int primaryExportOutNumOut;
                        int32_t nextOutput;
                        CPBaaSNotarization exportNotarization;
                        std::vector<CReserveTransfer> reserveTransfers;

                        if (!oneExport.second.second.GetExportInfo(oneExport.second.first.second,
                                                                   oneExport.second.first.first.txIn.prevout.n,
                                                                   primaryExportOutNumOut,
                                                                   nextOutput,
                                                                   exportNotarization,
                                                                   reserveTransfers))
                        {
                            printf("%s: Invalid export output %s : output - %u\n",
                                __func__,
                                oneExport.second.first.first.txIn.prevout.hash.GetHex().c_str(),
                                oneExport.second.first.first.txIn.prevout.n);
                            break;
                        }
                        exportsOut.push_back(std::make_pair(std::make_pair(oneExport.second.first.first, CPartialTransactionProof()),
                                                            reserveTransfers));
                    }
                }
            }
        }
    }

    std::map<uint160, std::vector<std::pair<int, CTransaction>>> newImports;
    if (exportsOut.size())
    {
        CreateLatestImports(thisChain, CUTXORef(), exportsOut, newImports);
    }
}

std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>>
GetPendingExports(const CCurrencyDefinition &sourceChain,
                  const CCurrencyDefinition &destChain,
                  CPBaaSNotarization &lastConfirmed,
                  CUTXORef &lastConfirmedUTXO)
{
    std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> exports;
    uint160 sourceChainID = sourceChain.GetID();
    uint160 destChainID = destChain.GetID();

    assert(sourceChainID != destChainID);   // this function is only for cross chain exports to or from another system

    // right now, we only communicate automatically to the first notary and back
    uint160 notaryID = ConnectedChains.FirstNotaryChain().GetID();
    assert((sourceChainID == ASSETCHAINS_CHAINID && destChainID == notaryID) || (sourceChainID == notaryID && destChainID == ASSETCHAINS_CHAINID));

    bool exportsToNotary = destChainID == notaryID;

    bool found = false;
    CAddressUnspentDbEntry foundEntry;
    CCrossChainImport lastCCI;

    // if exporting to our notary chain, we need to get the latest notarization and import from that
    // chain. we only have business sending exports if we have pending exports provable by the last
    // notarization and after the last import.
    if (exportsToNotary && ConnectedChains.IsNotaryAvailable())
    {
        UniValue params(UniValue::VARR);
        UniValue result;
        params.push_back(EncodeDestination(CIdentityID(sourceChainID)));

        CPBaaSNotarization pbn;

        try
        {
            result = find_value(RPCCallRoot("getlastimportfrom", params), "result");
            if (result.isNull())
            {
                return exports;
            }
            pbn = CPBaaSNotarization(find_value(result, "lastconfirmednotarization"));
            lastConfirmedUTXO = CUTXORef(find_value(result, "lastconfirmedutxo"));
            found = true;
        } catch (...)
        {
            LogPrint("notarization", "%s: Could not get last import from external chain %s\n", __func__, uni_get_str(params[0]).c_str());
            return exports;
        }
        {
            LOCK2(cs_main, mempool.cs);
            CTransaction confNotTx;
            uint256 blockHash;
            COptCCParams lcP;

            if (lastConfirmedUTXO.hash.IsNull() ||
                lastConfirmedUTXO.n < 0 ||
                !(pbn.IsValid() ||
                  (lastConfirmedUTXO.GetOutputTransaction(confNotTx, blockHash) &&
                   confNotTx.vout.size() > lastConfirmedUTXO.n &&
                   confNotTx.vout[lastConfirmedUTXO.n].scriptPubKey.IsPayToCryptoCondition(lcP) &&
                   lcP.IsValid() &&
                   (lcP.evalCode == EVAL_EARNEDNOTARIZATION || lcP.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
                   lcP.vData.size() &&
                   ((pbn.IsValid() &&
                     pbn.SetMirror(false) &&
                     ::AsVector(pbn) == lcP.vData[0]) ||
                    (pbn = CPBaaSNotarization(lcP.vData[0])).IsValid()))))
            {
                LogPrint("notarization", "%s: Invalid notarization from external chain %s, UTXO: %s\n", __func__, uni_get_str(params[0]).c_str(), lastConfirmedUTXO.ToUniValue().write().c_str());
                return exports;
            }
        }
        if (pbn.IsDefinitionNotarization())
        {
            return exports;
        }
        lastCCI = CCrossChainImport(find_value(result, "lastimport"));
        if (!lastCCI.IsValid())
        {
            LogPrint("crosschainexports", "%s: Invalid last import from external chain %s\n", __func__, uni_get_str(params[0]).c_str());
            return exports;
        }
        if (!pbn.proofRoots.count(sourceChainID))
        {
            LogPrint("crosschainexports", "%s: No adequate notarization available yet to support export to %s\n", __func__, uni_get_str(params[0]).c_str());
            return exports;
        }
        lastConfirmed = pbn;
        if (lastConfirmedUTXO.hash.IsNull() || lastConfirmedUTXO.n < 0)
        {
            LogPrint("crosschainexports", "%s: No confirmed notarization available to support export to %s\n", __func__, uni_get_str(params[0]).c_str());
            return exports;
        }
    }
    else if (!exportsToNotary)
    {
        LOCK(cs_main);
        std::vector<CAddressUnspentDbEntry> unspentOutputs;

        CChainNotarizationData cnd;
        if (!GetNotarizationData(sourceChainID, cnd) ||
            !cnd.IsConfirmed() ||
            !(lastConfirmed = cnd.vtx[cnd.lastConfirmed].second).proofRoots.count(sourceChainID))
        {
            LogPrintf("%s: Unable to get notarization data for %s\n", __func__, EncodeDestination(CIdentityID(sourceChainID)).c_str());
            return exports;
        }

        lastConfirmedUTXO = cnd.vtx[cnd.lastConfirmed].first;

        if (GetAddressUnspent(CKeyID(CCrossChainRPCData::GetConditionID(sourceChainID, CCrossChainImport::CurrencySystemImportKey())), CScript::P2IDX, unspentOutputs))
        {
            // if one spends the prior one, get the one that is not spent
            for (auto &txidx : unspentOutputs)
            {
                COptCCParams p;
                if (txidx.second.script.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                    p.vData.size() &&
                    (lastCCI = CCrossChainImport(p.vData[0])).IsValid())
                {
                    found = true;
                    foundEntry = txidx;
                    break;
                }
            }
        }
    }

    if (found &&
        lastCCI.sourceSystemHeight < lastConfirmed.proofRoots[sourceChainID].rootHeight)
    {
        UniValue params(UniValue::VARR);
        params = UniValue(UniValue::VARR);
        params.push_back(EncodeDestination(CIdentityID(destChainID)));
        params.push_back((int64_t)lastCCI.sourceSystemHeight);

        params.push_back((int64_t)lastConfirmed.proofRoots[sourceChainID].rootHeight);

        UniValue result = NullUniValue;
        try
        {
            if (sourceChainID == ASSETCHAINS_CHAINID)
            {
                UniValue getexports(const UniValue& params, bool fHelp);
                result = getexports(params, false);
            }
            else if (ConnectedChains.IsNotaryAvailable())
            {
                result = find_value(RPCCallRoot("getexports", params), "result");
            }
        } catch (exception e)
        {
            LogPrint("notarization", "Could not get latest export from external chain %s\n", uni_get_str(params[0]).c_str());
            return exports;
        }

        // now, we should have a list of exports to import in order
        if (!result.isArray() || !result.size())
        {
            return exports;
        }

        LOCK2(cs_main, mempool.cs);

        bool foundCurrent = false;
        for (int i = 0; i < result.size(); i++)
        {
            uint256 exportTxId = uint256S(uni_get_str(find_value(result[i], "txid")));
            if (!foundCurrent && !lastCCI.exportTxId.IsNull())
            {
                // when we find our export, take the next
                if (exportTxId == lastCCI.exportTxId)
                {
                    foundCurrent = true;
                }
                continue;
            }

            // create one import at a time
            uint32_t notarizationHeight = uni_get_int64(find_value(result[i], "height"));
            int32_t exportTxOutNum = uni_get_int(find_value(result[i], "txoutnum"));
            CPartialTransactionProof txProof = CPartialTransactionProof(find_value(result[i], "partialtransactionproof"));
            UniValue transferArrUni = find_value(result[i], "transfers");
            if (!notarizationHeight ||
                exportTxId.IsNull() ||
                exportTxOutNum == -1 ||
                !transferArrUni.isArray())
            {
                printf("Invalid export from %s\n", uni_get_str(params[0]).c_str());
                return exports;
            }

            CTransaction exportTx;
            uint256 blkHash;
            auto proofRootIt = lastConfirmed.proofRoots.find(sourceChainID);
            if (!(txProof.IsValid() &&
                    !txProof.GetPartialTransaction(exportTx).IsNull() &&
                    txProof.TransactionHash() == exportTxId &&
                    proofRootIt != lastConfirmed.proofRoots.end() &&
                    proofRootIt->second.stateRoot == txProof.CheckPartialTransaction(exportTx) &&
                    exportTx.vout.size() > exportTxOutNum))
            {
                LogPrint("notarization", "%s: proofRoot: %s,\nGetPartialTransaction: %s, checkPartialTransaction: %s, TransactionHash: %s, exportTxId: %s,\nproofheight: %u,\nischainproof: %s,\nblockhash: %s\n",
                    __func__,
                    proofRootIt->second.ToUniValue().write(1,2).c_str(),
                    txProof.GetPartialTransaction(exportTx).GetHex().c_str(),
                    txProof.CheckPartialTransaction(exportTx).GetHex().c_str(),
                    txProof.TransactionHash().GetHex().c_str(),
                    exportTxId.GetHex().c_str(),
                    txProof.GetProofHeight(),
                    txProof.IsChainProof() ? "true" : "false",
                    txProof.GetBlockHash().GetHex().c_str()); //*/
                printf("Invalid export for %s\n", uni_get_str(params[0]).c_str());
                return exports;
            }
            else if (!(myGetTransaction(exportTxId, exportTx, blkHash) &&
                    exportTx.vout.size() > exportTxOutNum))
            {
                printf("Invalid export msg2 from %s\n", uni_get_str(params[0]).c_str());
                return exports;
            }
            if (!foundCurrent)
            {
                CCrossChainExport ccx(exportTx.vout[exportTxOutNum].scriptPubKey);
                if (!ccx.IsValid())
                {
                    printf("Invalid export msg3 from %s\n", uni_get_str(params[0]).c_str());
                    return exports;
                }
                if (ccx.IsChainDefinition() || ccx.sourceHeightEnd == 1)
                {
                    if (lastCCI.exportTxId.IsNull())
                    {
                        foundCurrent = true;
                    }
                    continue;
                }
            }
            std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>> oneExport =
                std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[exportTxOutNum].scriptPubKey,
                                                exportTx.vout[exportTxOutNum].nValue,
                                                CTxIn(exportTxId, exportTxOutNum)),
                                                txProof),
                                std::vector<CReserveTransfer>());
            for (int j = 0; j < transferArrUni.size(); j++)
            {
                //printf("%s: onetransfer: %s\n", __func__, transferArrUni[j].write(1,2).c_str());
                oneExport.second.push_back(CReserveTransfer(transferArrUni[j]));
                if (!oneExport.second.back().IsValid())
                {
                    printf("Invalid reserve transfers in export from %s\n", sourceChain.name.c_str());
                    return exports;
                }
            }
            exports.push_back(oneExport);
        }
    }
    return exports;
}

void CConnectedChains::SubmissionThread()
{
    try
    {
        arith_uint256 lastHash;
        int64_t lastImportTime = 0;
        bool isVerusActive = IsVerusActive();
        bool isVerusMainnetActive = IsVerusMainnetActive();

        // wait for something to check on, then submit blocks that should be submitted
        while (true)
        {
            boost::this_thread::interruption_point();

            uint32_t height = chainActive.LastTip() ? chainActive.LastTip()->GetHeight() : 0;
            bool isNotaryAvailable = IsNotaryAvailable(true);

            // if this is a PBaaS chain, poll for presence of Verus / root chain and current Verus block and version number
            if (isNotaryAvailable)
            {
                CIdentityID notaryRevokeID;
                std::vector<CIdentityID> revokeIDs;
                std::string notaryRevokeAddr;
                // if we should revoke any IDs, do it here
                {
                    LOCK(cs_mergemining);
                    if (idsToRevoke.size())
                    {
                        notaryRevokeAddr = GetArg("-autonotaryrevoke", "");
                        if (!notaryRevokeAddr.empty())
                        {
                            notaryRevokeID = GetDestinationID(DecodeDestination(notaryRevokeAddr));
                            if (!notaryRevokeID.IsNull() && idsToRevoke.count(notaryRevokeID))
                            {
                                idsToRevoke.erase(notaryRevokeID);
                            }
                            else
                            {
                                notaryRevokeID.SetNull();
                            }
                        }
                    }
                    // if we have additional IDs to revoke beyond our autonotaryrevoke parameter, we are likely not to have
                    // revoke authority and should change the primary key instead, both on this chain and on the notary chain
                    CIdentityID oneToRevoke;
                    while (!(oneToRevoke = NextRevokeID()).IsNull())
                    {
                        revokeIDs.push_back(oneToRevoke);
                    }
                }
                if (!notaryRevokeID.IsNull())
                {
                    UniValue revokeidentity(const UniValue& params, bool fHelp);
                    // revoke on this chain and on the notary, this chain first
                    UniValue params(UniValue::VARR);
                    UniValue result(UniValue::VOBJ);
                    params.push_back(notaryRevokeAddr);
                    try
                    {
                        revokeidentity(params, false);
                    }
                    catch(const std::exception& e)
                    {
                        LogPrintf("%s: exception (%s) revoking ID %s\n", __func__, e.what(), notaryRevokeAddr.c_str());
                    }
                    try
                    {
                        result = RPCCallRoot("revokeidentity", params);
                    }
                    catch(const std::exception& e)
                    {
                        LogPrintf("%s: exception (%s) revoking ID %s\n", __func__, e.what(), notaryRevokeAddr.c_str());
                    }
                }
                // these are going to be our notary IDs, and we need to set new primary keys for them
                for (auto &oneRevokeID : revokeIDs)
                {
                    CIdentity revokeIdentity;
                    uint32_t heightOfID;
                    {
                        LOCK2(cs_main, mempool.cs);
                        revokeIdentity = CIdentity::LookupIdentity(oneRevokeID, 0, &heightOfID, nullptr, true);
                    }
                    if (revokeIdentity.IsValidUnrevoked())
                    {
                        // we don't want to update the ID too many times, so if it is in the mempool and
                        // updated to a new key that is different from the last, skip the new update
                        if (!heightOfID)
                        {
                            auto oldAddresses = revokeIdentity.primaryAddresses;
                            revokeIdentity = CIdentity::LookupIdentity(oneRevokeID);
                            if (revokeIdentity.primaryAddresses != oldAddresses)
                            {
                                continue;
                            }
                        }

                        UniValue importprivkey(const UniValue& params, bool fHelp);
                        UniValue updateidentity(const UniValue& params, bool fHelp);
                        // revoke on this chain and on the notary, this chain first
                        UniValue params(UniValue::VARR);
                        UniValue result(UniValue::VOBJ);
                        UniValue updateIDUni(UniValue::VOBJ);
                        UniValue newAddressesUni(UniValue::VARR);
                        CPubKey newKey;
                        CKey newPrivKey;
                        UniValue importPrivKeyParams(UniValue::VARR);
                        {
                            LOCK(pwalletMain->cs_wallet);
                            newPrivKey.MakeNewKey(true);
                            newKey = newPrivKey.GetPubKey();
                            if (!newPrivKey.IsValid() || !newKey.IsValid())
                            {
                                continue;
                            }
                            newAddressesUni.push_back(EncodeDestination(newKey.GetID()));
                            importPrivKeyParams.push_back(EncodeSecret(newPrivKey));
                            importPrivKeyParams.push_back(false);
                        }
                        updateIDUni.pushKV("name", revokeIdentity.name);
                        updateIDUni.pushKV("parent", EncodeDestination(CIdentityID(revokeIdentity.parent)));
                        updateIDUni.pushKV("primaryaddresses", newAddressesUni);
                        updateIDUni.pushKV("minimumsignatures", 1);
                        try
                        {
                            importprivkey(importPrivKeyParams, false);
                            updateidentity(params, false);
                        }
                        catch(const std::exception& e)
                        {
                            LogPrintf("%s: exception (%s) revoking ID %s\n", __func__, e.what(), notaryRevokeAddr.c_str());
                        }
                        try
                        {
                            result = RPCCallRoot("importprivkey", importPrivKeyParams);
                            result = RPCCallRoot("updateidentity", params);
                        }
                        catch(const std::exception& e)
                        {
                            LogPrintf("%s: exception (%s) revoking ID %s\n", __func__, e.what(), notaryRevokeAddr.c_str());
                        }
                    }
                }
                if (height > ConnectedChains.ThisChain().GetMinBlocksToStartNotarization() &&
                    lastImportTime < (GetAdjustedTime() - 30))
                {
                    // check for exports on this chain that we should send to the notary and do so
                    // exports to another native system should be exported to that system and to the currency
                    // of this system on that system
                    lastImportTime = GetAdjustedTime();

                    std::vector<std::pair<std::pair<CInputDescriptor, CPartialTransactionProof>, std::vector<CReserveTransfer>>> exports;
                    CPBaaSNotarization lastConfirmed;
                    CUTXORef lastConfirmedUTXO;
                    exports = GetPendingExports(ConnectedChains.ThisChain(),
                                                ConnectedChains.FirstNotaryChain().chainDefinition,
                                                lastConfirmed,
                                                lastConfirmedUTXO);

                    if (notaryRevokeID.IsNull() && exports.size())
                    {
                        bool submitImport = true;
                        bool amNotary = false;

                        const CCurrencyDefinition &notaryCurrency = ConnectedChains.FirstNotaryChain().chainDefinition;
                        // if this is an ETH protocol, we could get reverted and still have to pay, so if we are a notary,
                        // to prevent funds loss, sort notaries and make sure we are in the top 2 before we try to submit
                        if (notaryCurrency.proofProtocol == CCurrencyDefinition::PROOF_ETHNOTARIZATION)
                        {
                            for (auto &oneNotary : notaryCurrency.notaries)
                            {
                                if (oneNotary == VERUS_NOTARYID)
                                {
                                    amNotary = true;
                                    break;
                                }
                            }
                            if (amNotary)
                            {
                                CNativeHashWriter hw;
                                hw << height;
                                hw << exports[0].first.first.txIn.prevout;
                                uint256 prHash = hw.GetHash();
                                std::vector<uint160> notaryVec = notaryCurrency.notaries;
                                auto prandom = std::minstd_rand0(UintToArith256(prHash).GetLow64());
                                shuffle(notaryVec.begin(), notaryVec.end(), prandom);
                                if (notaryVec[0] != VERUS_NOTARYID)
                                {
                                    LogPrintf("skipping import submission - was not selected for submission lottery, %s selected\n", EncodeDestination(CIdentityID(notaryVec[0])).c_str());
                                    printf("skipping import submission - was not selected for submission lottery, %s selected\n", EncodeDestination(CIdentityID(notaryVec[0])).c_str());
                                    submitImport = false;
                                }
                            }
                        }

                        if (submitImport)
                        {
                            UniValue exportParamObj(UniValue::VOBJ);

                            exportParamObj.pushKV("sourcesystemid", EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)));
                            exportParamObj.pushKV("notarizationtxid", lastConfirmedUTXO.hash.GetHex());
                            exportParamObj.pushKV("notarizationtxoutnum", (int)lastConfirmedUTXO.n);

                            UniValue exportArr(UniValue::VARR);
                            for (int i = 0; i < exports.size(); i++)
                            {
                                auto &oneExport = exports[i];

                                // use a different random selection for every import and only continue if we are selected again
                                if (amNotary && (!isVerusMainnetActive || (height >= 2930000 && i > 0)))
                                {
                                    CNativeHashWriter hw;
                                    hw << height;
                                    hw << exports[i].first.first.txIn.prevout;
                                    uint256 prHash = hw.GetHash();
                                    std::vector<uint160> notaryVec = notaryCurrency.notaries;
                                    auto prandom = std::minstd_rand0(UintToArith256(prHash).GetLow64());
                                    shuffle(notaryVec.begin(), notaryVec.end(), prandom);
                                    if (notaryVec[0] != VERUS_NOTARYID)
                                    {
                                        LogPrintf("skipping next import submission for #%d of valid exports - was not selected for submission lottery, %s selected\n", i, EncodeDestination(CIdentityID(notaryVec[i])).c_str());
                                        printf("skipping next import submission for #%d of valid exports - was not selected for submission lottery, %s selected\n", i, EncodeDestination(CIdentityID(notaryVec[i])).c_str());
                                        break;
                                    }
                                }

                                if (!oneExport.first.second.IsValid())
                                {
                                    break;
                                }
                                UniValue oneExportUni(UniValue::VOBJ);
                                oneExportUni.pushKV("txid", oneExport.first.first.txIn.prevout.hash.GetHex());
                                oneExportUni.pushKV("txoutnum", (int)oneExport.first.first.txIn.prevout.n);
                                oneExportUni.pushKV("partialtransactionproof", oneExport.first.second.ToUniValue());
                                UniValue rtArr(UniValue::VARR);

                                if (LogAcceptCategory("crosschainexports") && IsVerusActive())
                                {
                                    CDataStream ds = CDataStream(SER_GETHASH, PROTOCOL_VERSION);
                                    for (auto &oneTransfer : oneExport.second)
                                    {
                                        ds << oneTransfer;
                                    }
                                    std::vector<unsigned char> streamVec(ds.begin(), ds.end());
                                    printf("%s: transfers as hex: %s\n", __func__, HexBytes(&(streamVec[0]), streamVec.size()).c_str());
                                    LogPrint("bridge", "%s: transfers as hex: %s\n", __func__, HexBytes(&(streamVec[0]), streamVec.size()).c_str());
                                }

                                for (auto &oneTransfer : oneExport.second)
                                {
                                    rtArr.push_back(oneTransfer.ToUniValue());
                                }
                                oneExportUni.pushKV("transfers", rtArr);
                                exportArr.push_back(oneExportUni);
                            }

                            if (exportArr.size())
                            {
                                exportParamObj.pushKV("exports", exportArr);

                                UniValue params(UniValue::VARR);
                                params.push_back(exportParamObj);
                                UniValue result = NullUniValue;
                                try
                                {
                                    result = find_value(RPCCallRoot("submitimports", params), "result");
                                } catch (exception e)
                                {
                                    LogPrintf("%s: Error submitting imports to notary chain %s\n", uni_get_str(params[0]).c_str());
                                }
                            }
                        }
                    }
                }
            }

            bool submit = false;
            if (IsVerusActive())
            {
                {
                    LOCK(cs_mergemining);
                    if (mergeMinedChains.size() == 0 && qualifiedHeaders.size() != 0)
                    {
                        qualifiedHeaders.clear();
                    }
                    submit = qualifiedHeaders.size() != 0 && mergeMinedChains.size() != 0;

                    //printf("SubmissionThread: qualifiedHeaders.size(): %lu, mergeMinedChains.size(): %lu\n", qualifiedHeaders.size(), mergeMinedChains.size());
                }

                uint32_t lastNextTime = ConnectedChains.nextBlockTime;
                uint32_t newNextTime = lastNextTime;

                if (submit)
                {
                    //printf("SubmissionThread: calling submit qualified blocks\n");
                    SubmitQualifiedBlocks();
                }

                // update block time on submit or PBaaS chain advances forward
                if (submit || nextBlockTimeUpdateRequired) {
                    //SetNextBlockTime(0);
                    newNextTime = SetNextBlockTime(GetNextBlockTime(chainActive.LastTip()));

                    //printf("blocktimeupdate: %d last time: %d new time: %d\n", nextBlockTimeUpdateRequired, lastNextTime, newNextTime);
                    nextBlockTimeUpdateRequired = false;
                }

                // prune outdated blocks
                PruneOldChains(GetAdjustedTime() - 90);
            }
            if (!submit && !FirstNotaryChain().IsValid())
            {
                sem_submitthread.wait();
            }
            else if (isNotaryAvailable)
            {
                MilliSleep(1000);
            }
            else
            {
                MilliSleep(500);
            }

            //printf("SubmissionThread: running ...\n");
            boost::this_thread::interruption_point();
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("Verus merge mining thread terminated\n");
    }
}

void CConnectedChains::SubmissionThreadStub()
{
    RenameThread("verus-submission");
    ConnectedChains.SubmissionThread();
}

void CConnectedChains::QueueEarnedNotarization(CBlock &blk, int32_t txIndex, int32_t height)
{
    // called after winning a block that contains an earned notarization
    // the earned notarization and its height are queued for processing by the submission thread
    // when a new notarization is added, older notarizations are removed, but all notarizations in the current height are
    // kept
    LOCK(cs_mergemining);

    // we only care about the last
    earnedNotarizationHeight = height;
    earnedNotarizationBlock = blk;
    earnedNotarizationIndex = txIndex;
}

bool IsCurrencyDefinitionInput(const CScript &scriptSig)
{
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_CURRENCY_DEFINITION;
}

