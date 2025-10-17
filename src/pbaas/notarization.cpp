/********************************************************************
 * (C) 2019 Michael Toutonghi
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * This implements the public blockchains as a service (PBaaS) notarization protocol, VerusLink.
 * VerusLink is a new distributed consensus protocol that enables multiple public blockchains
 * to operate as a decentralized ecosystem of chains, which can interact and easily engage in cross
 * chain transactions.
 *
 */

#include <univalue.h>
#include "main.h"
#include "txdb.h"
#include "rpc/pbaasrpc.h"
#include "transaction_builder.h"
#include "cc/StakeGuard.h"

#include <timedata.h>
#include <assert.h>
#include <random>

using namespace std;

extern uint160 VERUS_CHAINID;
extern uint160 ASSETCHAINS_CHAINID;
extern string VERUS_CHAINNAME;
extern string PBAAS_HOST;
extern string PBAAS_USERPASS;
extern int32_t PBAAS_PORT;
extern int32_t VERUS_MIN_STAKEAGE;
extern std::string NOTARY_PUBKEY;

CNotaryEvidence::CNotaryEvidence(const UniValue &uni)
{
    if (uni.isNull())
    {
        version = VERSION_INVALID;
    }
    else
    {
        version = uni_get_int(find_value(uni, "version"), VERSION_CURRENT);
        type = uni_get_int(find_value(uni, "type"));
        systemID = GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "systemid"))));
        output = CUTXORef(find_value(uni, "output"));
        state = uni_get_int(find_value(uni, "state"));
        evidence = CCrossChainProof(find_value(uni, "evidence"));
        if (!evidence.IsValid())
        {
            version = VERSION_INVALID;
        }
    }
}

std::vector<CNotarySignature> CNotaryEvidence::GetConfirmedAndRejectedSignatureMaps(
                                                        const std::vector<CNotarySignature> &allSigVec,
                                                        std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> &confirmedByHeight,
                                                        std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> &rejectedByHeight)
{
    CUTXORef output;
    uint160 systemID;
    for (auto notarySig : allSigVec)
    {
        if (output.hash.IsNull())
        {
            output = notarySig.output;
            systemID = notarySig.systemID;
        }
        if (notarySig.IsConfirmed())
        {
            // get the signature proof and add to it, do not make a new one
            for (auto &oneSignature : notarySig.signatures)
            {
                if (confirmedByHeight[oneSignature.second.blockHeight].count(oneSignature.first))
                {
                    // all signatures are the same height, merge the CIdentitySignature
                    for (auto &oneKeySig : oneSignature.second.signatures)
                    {
                        confirmedByHeight[oneSignature.second.blockHeight][oneSignature.first].AddSignature(oneKeySig);
                    }
                }
                else
                {
                    confirmedByHeight[oneSignature.second.blockHeight].insert(oneSignature);
                }
            }
        }
        else
        {
            // get the signature proof and add to it, do not make a new one
            for (auto &oneSignature : notarySig.signatures)
            {
                if (rejectedByHeight[oneSignature.second.blockHeight].count(oneSignature.first))
                {
                    // all signatures are the same height, merge the CIdentitySignature
                    for (auto &oneKeySig : oneSignature.second.signatures)
                    {
                        rejectedByHeight[oneSignature.second.blockHeight][oneSignature.first].AddSignature(oneKeySig);
                    }
                }
                else
                {
                    rejectedByHeight[oneSignature.second.blockHeight].insert(oneSignature);
                }
            }
        }
    }

    std::vector<CNotarySignature> retVal;

    std::multimap<uint32_t, CNotarySignature> combinedSignatures;
    for (auto oneHeightEntry : rejectedByHeight)
    {
        combinedSignatures.insert(std::make_pair(oneHeightEntry.first, CNotarySignature(systemID, output, false, oneHeightEntry.second)));
    }
    for (auto oneHeightEntry : confirmedByHeight)
    {
        combinedSignatures.insert(std::make_pair(oneHeightEntry.first, CNotarySignature(systemID, output, true, oneHeightEntry.second)));
    }
    for (auto &oneNotarySig : combinedSignatures)
    {
        retVal.push_back(oneNotarySig.second);
    }
    return retVal;
}

CNotaryEvidence &CNotaryEvidence::MergeEvidence(const CNotaryEvidence &mergeWith, bool aggregateSignatures, bool onlySignatures)
{
    std::vector<CNotarySignature> notarySignatures;

    if (output.IsNull() && !mergeWith.output.IsNull())
    {
        output = mergeWith.output;
    }
    if (systemID.IsNull() && !mergeWith.systemID.IsNull())
    {
        systemID = mergeWith.systemID;
    }

    std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> confirmedByHeight;
    std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> rejectedByHeight;

    for (auto oneRef : mergeWith.evidence.chainObjects)
    {
        if (aggregateSignatures && oneRef->objectType == CHAINOBJ_NOTARYSIGNATURE)
        {
            notarySignatures.push_back(((CChainObject<CNotarySignature> *)oneRef)->object);
        }
        else if (!onlySignatures || oneRef->objectType == CHAINOBJ_NOTARYSIGNATURE)
        {
            evidence << oneRef;
        }
    }

    if (notarySignatures.size())
    {
        auto orderedNotarySigs = GetConfirmedAndRejectedSignatureMaps(notarySignatures, confirmedByHeight, rejectedByHeight);

        // place all signature blocks at the beginning of the evidence in order of height by inserting them at 0 in reverse order
        for (auto it = orderedNotarySigs.rbegin(); it != orderedNotarySigs.rend(); it++)
        {
            evidence.insert(0, *it);
        }
    }
    return *this;
}

CIdentitySignature::ESignatureVerification CNotaryEvidence::SignConfirmed(const std::set<uint160> &notarySet, int minConfirming, const CKeyStore &keyStore, const CTransaction &txToConfirm, const CIdentityID &signWithID, uint32_t height, CCurrencyDefinition::EHashTypes hashType, CNotaryEvidence *pNewSignatureEvidence)
{
    if (!notarySet.count(signWithID))
    {
        LogPrintf("%s: Attempting to sign as notary with unauthorized ID\n", __func__);
        return CIdentitySignature::SIGNATURE_INVALID;
    }

    COptCCParams p;

    if (txToConfirm.GetHash() != output.hash ||
        txToConfirm.vout.size() <= output.n ||
        !txToConfirm.vout[output.n].scriptPubKey.IsPayToCryptoCondition(p) ||
        !p.vData.size() ||
        !p.vData[0].size() ||
        p.evalCode == EVAL_NONE)
    {
        LogPrintf("%s: Attempting to sign an invalid or incompatible object\n", __func__);
        return CIdentitySignature::SIGNATURE_INVALID;
    }

    // write the object to the hash writer without a vector length prefix
    uint256 objHash;
    uint256 outputUTXOHash;
    {
        CNativeHashWriter hw(hashType);
        objHash = hw.write((const char *)&(p.vData[0][0]), p.vData[0].size()).GetHash();
    }
    {
        CNativeHashWriter hw(hashType);
        hw << output;
        outputUTXOHash = hw.GetHash();
    }

    uint32_t decisionHeight;
    std::map<CIdentityID, CIdentitySignature> notarySetRejects;
    std::map<CIdentityID, CIdentitySignature> notarySetConfirms;

    CNotaryEvidence::EStates sigCheckResult = CheckSignatureConfirmation(objHash,
                                                                         hashType,
                                                                         notarySet,
                                                                         minConfirming,
                                                                         height,
                                                                         &decisionHeight,
                                                                         &notarySetRejects,
                                                                         &notarySetConfirms);

    if (notarySetConfirms.count(signWithID) ||
        sigCheckResult == CNotaryEvidence::EStates::STATE_CONFIRMED ||
        sigCheckResult == CNotaryEvidence::EStates::STATE_REJECTED)
    {
        return CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE;
    }
    else if (sigCheckResult == CNotaryEvidence::EStates::STATE_INVALID)
    {
        return CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID;
    }

    // all signatures present for this ID are correct, so we recover all pub keys and IDs,
    // then see if we have any of the keys in our wallet that are in the ID and have not already
    // signed
    CIdentity sigIdentity = CIdentity::LookupIdentity(signWithID, height);
    if (!sigIdentity.IsValid())
    {
        LogPrint("notarization", "%s: failed lookup of identity for confirmation: %s\n", __func__, EncodeDestination(signWithID).c_str());
        return CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID;
    }
    else
    {
        CIdentitySignature idSignature(height, std::set<std::vector<unsigned char>>(), hashType);

        uint256 signatureHash = idSignature.IdentitySignatureHash(std::vector<uint160>({NotaryConfirmedKey()}),
                                                                  std::vector<std::string>(),
                                                                  std::vector<uint256>({outputUTXOHash}),
                                                                  systemID,
                                                                  height,
                                                                  signWithID,
                                                                  "",
                                                                  objHash);

        std::set<CTxDestination> validKeys;

        for (auto &oneDest : sigIdentity.primaryAddresses)
        {
            if (oneDest.which() == COptCCParams::ADDRTYPE_PK)
            {
                validKeys.insert(CKeyID(GetDestinationID(oneDest)));
            }
            else
            {
                validKeys.insert(oneDest);
            }
        }

        // sign for anything we can that is not already in the confirmed set
        int currentNumSigs = notarySetConfirms[signWithID].signatures.size();

        if (currentNumSigs)
        {
            for (auto &oneSig : notarySetConfirms[signWithID].signatures)
            {
                CPubKey checkKey;
                if (checkKey.RecoverCompact(signatureHash, oneSig))
                {
                    validKeys.erase(checkKey.GetID());
                }
            }
        }

        int sigsToMake = std::max(sigIdentity.minSigs - currentNumSigs, 0);

        // as long as we can continue to make new signatures, we do
        for (auto keyIT = validKeys.begin(); sigsToMake > 0 && keyIT != validKeys.end(); keyIT++)
        {
            CKey signingKey;
            std::vector<unsigned char> newSig;
            if (keyStore.GetKey(GetDestinationID(*keyIT), signingKey) && signingKey.SignCompact(signatureHash, newSig))
            {
                idSignature.signatures.insert(newSig);
                sigsToMake--;
            }
        }

        if (idSignature.signatures.size())
        {
            if (pNewSignatureEvidence)
            {
                std::map<CIdentityID, CIdentitySignature> newSigMap;
                newSigMap.insert(std::make_pair(signWithID, idSignature));
                CNotarySignature newSignature(systemID, output, true, newSigMap);
                CCrossChainProof sigProof;
                sigProof << newSignature;
                pNewSignatureEvidence->MergeEvidence(CNotaryEvidence(systemID, output, STATE_CONFIRMING, sigProof));
            }
            AddToSignatures(notarySet, signWithID, idSignature, STATE_CONFIRMING);
        }

        CIdentitySignature::ESignatureVerification sigResult = idSignature.CheckSignature(sigIdentity,
                                                                                        std::vector<uint160>({NotaryConfirmedKey()}),
                                                                                        std::vector<std::string>(),
                                                                                        std::vector<uint256>({outputUTXOHash}),
                                                                                        systemID,
                                                                                        "",
                                                                                        objHash);

        if (sigResult == CIdentitySignature::ESignatureVerification::SIGNATURE_EMPTY ||
            sigResult == CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID)
        {
            LogPrintf("%s: Error signing confirmed with ID: %s\n", __func__, sigIdentity.ToUniValue().write(1,2).c_str());
            return sigResult;
        }
        // if we have enough signatures for the ID, make sure we return complete
        if (idSignature.signatures.size() >= sigIdentity.minSigs)
        {
            return CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE;
        }
        return sigResult;
    }
}

CIdentitySignature::ESignatureVerification CNotaryEvidence::SignRejected(const std::set<uint160> &notarySet,
                                                                         int minConfirming,
                                                                         const CKeyStore &keyStore,
                                                                         const CTransaction &txToConfirm,
                                                                         const CIdentityID &signWithID,
                                                                         uint32_t height,
                                                                         CCurrencyDefinition::EHashTypes hashType,
                                                                         CNotaryEvidence *pNewSignatureEvidence)
{
    if (!notarySet.count(signWithID))
    {
        LogPrintf("%s: Attempting to sign as notary with unauthorized ID\n", __func__);
        return CIdentitySignature::SIGNATURE_INVALID;
    }

    COptCCParams p;

    if (txToConfirm.GetHash() != output.hash ||
        txToConfirm.vout.size() <= output.n ||
        !txToConfirm.vout[output.n].scriptPubKey.IsPayToCryptoCondition(p) ||
        !p.vData.size() ||
        !p.vData[0].size() ||
        p.evalCode == EVAL_NONE)
    {
        LogPrintf("%s: Attempting to sign an invalid or incompatible object\n", __func__);
        return CIdentitySignature::SIGNATURE_INVALID;
    }

    // write the object to the hash writer without a vector length prefix
    std::map<CIdentityID, CIdentitySignature> confirmedAtHeight;
    std::map<CIdentityID, CIdentitySignature> rejectedAtHeight;

    // write the object to the hash writer without a vector length prefix
    uint256 objHash;
    uint256 outputUTXOHash;
    {
        CNativeHashWriter hw(hashType);
        objHash = hw.write((const char *)&(p.vData[0][0]), p.vData[0].size()).GetHash();
    }
    {
        CNativeHashWriter hw(hashType);
        hw << output;
        outputUTXOHash = hw.GetHash();
    }

    uint32_t decisionHeight;

    CNotaryEvidence::EStates sigCheckResult = CheckSignatureConfirmation(objHash,
                                                                         hashType,
                                                                         notarySet,
                                                                         minConfirming,
                                                                         height,
                                                                         &decisionHeight,
                                                                         &confirmedAtHeight,
                                                                         &rejectedAtHeight);

    if ((sigCheckResult == CNotaryEvidence::EStates::STATE_CONFIRMED && decisionHeight != height) ||
         sigCheckResult == CNotaryEvidence::EStates::STATE_REJECTED)
    {
        return CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE;
    }
    else if (sigCheckResult == CNotaryEvidence::EStates::STATE_INVALID)
    {
        return CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID;
    }

    // all signatures present for this ID are correct, so we recover all pub keys and IDs,
    // then see if we have any of the keys in our wallet that are in the ID and have not already
    // signed
    CIdentity sigIdentity = CIdentity::LookupIdentity(signWithID, height);
    if (!sigIdentity.IsValid())
    {
        LogPrint("notarization", "%s: failed lookup of identity for rejection: %s\n", __func__, EncodeDestination(signWithID).c_str());
        return CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID;
    }
    else
    {
        CIdentitySignature idSignature(height, std::set<std::vector<unsigned char>>(), hashType);

        uint256 signatureHash = idSignature.IdentitySignatureHash(std::vector<uint160>({NotaryRejectedKey()}),
                                                                  std::vector<std::string>(),
                                                                  std::vector<uint256>({outputUTXOHash}),
                                                                  systemID,
                                                                  height,
                                                                  signWithID,
                                                                  "",
                                                                  objHash);

        std::set<CTxDestination> validKeys;

        for (auto &oneDest : sigIdentity.primaryAddresses)
        {
            if (oneDest.which() == COptCCParams::ADDRTYPE_PK)
            {
                validKeys.insert(CKeyID(GetDestinationID(oneDest)));
            }
            else
            {
                validKeys.insert(oneDest);
            }
        }

        // sign for anything we can that is not already in the signature block
        int currentNumSigs = rejectedAtHeight[signWithID].signatures.size();

        if (currentNumSigs)
        {
            for (auto &oneSig : rejectedAtHeight[signWithID].signatures)
            {
                CPubKey checkKey;
                if (checkKey.RecoverCompact(signatureHash, oneSig))
                {
                    validKeys.erase(checkKey.GetID());
                }
            }
        }

        int sigsNeeded = std::max(sigIdentity.minSigs - currentNumSigs, 0);
        if (!sigsNeeded)
        {
            LogPrint("notarization", "%s: Already signed with ID\n", __func__);
            return CIdentitySignature::SIGNATURE_COMPLETE;
        }

        // as long as we can continue to make new signatures, we do
        for (auto keyIT = validKeys.begin(); sigsNeeded > 0 && keyIT != validKeys.end(); keyIT++)
        {
            CKey signingKey;
            std::vector<unsigned char> newSig;
            if (keyStore.GetKey(GetDestinationID(*keyIT), signingKey) && signingKey.SignCompact(signatureHash, newSig))
            {
                idSignature.signatures.insert(newSig);
                sigsNeeded--;
            }
        }

        if (idSignature.signatures.size())
        {
            if (pNewSignatureEvidence)
            {
                std::map<CIdentityID, CIdentitySignature> newSigMap;
                newSigMap.insert(std::make_pair(signWithID, idSignature));
                CNotarySignature newSignature(systemID, output, true, newSigMap);
                CCrossChainProof sigProof;
                sigProof << newSignature;
                pNewSignatureEvidence->MergeEvidence(CNotaryEvidence(systemID, output, STATE_REJECTING, sigProof));
            }
            AddToSignatures(notarySet, signWithID, idSignature, STATE_REJECTING);
        }

        CIdentitySignature::ESignatureVerification sigResult = idSignature.CheckSignature(sigIdentity,
                                                                                          std::vector<uint160>({NotaryRejectedKey()}),
                                                                                          std::vector<std::string>(),
                                                                                          std::vector<uint256>({outputUTXOHash}),
                                                                                          systemID,
                                                                                          "",
                                                                                          objHash);

        if (sigResult == CIdentitySignature::ESignatureVerification::SIGNATURE_EMPTY ||
            sigResult == CIdentitySignature::ESignatureVerification::SIGNATURE_INVALID)
        {
            LogPrintf("%s: Error signing rejected with ID: %s\n", __func__, sigIdentity.ToUniValue().write(1,2).c_str());
            return sigResult;
        }
        // if we have enough signatures for the ID, make sure we return complete
        if (sigsNeeded == 0)
        {
            return CIdentitySignature::ESignatureVerification::SIGNATURE_COMPLETE;
        }
        return sigResult;
    }
}

CNotaryEvidence::EStates CNotaryEvidence::CheckSignatureConfirmation(const uint256 &objHash,
                                                                     CCurrencyDefinition::EHashTypes hashType,
                                                                     const std::set<uint160> &notarySet,
                                                                     int minConfirming,
                                                                     uint32_t checkHeight,
                                                                     uint32_t *pDecisionHeight,
                                                                     std::map<CIdentityID, CIdentitySignature> *pNotarySetRejects,
                                                                     std::map<CIdentityID, CIdentitySignature> *pNotarySetConfirms,
                                                                     std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> *pRejectsByHeight,
                                                                     std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> *pConfirmsByHeight) const
{
    std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> _rejectedByHeight;
    std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> _confirmedByHeight;
    std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> &rejectedByHeight = pRejectsByHeight ? *pRejectsByHeight : _rejectedByHeight;
    std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> &confirmedByHeight = pConfirmsByHeight ? *pConfirmsByHeight : _confirmedByHeight;

    std::vector<CNotarySignature> notarySignatures = GetNotarySignatures(&confirmedByHeight, &rejectedByHeight);

    std::map<CIdentityID, CIdentitySignature> _notarySetRejects;
    std::map<CIdentityID, CIdentitySignature> _notarySetConfirms;
    std::map<CIdentityID, CIdentitySignature> &notarySetRejects = pNotarySetRejects ? *pNotarySetRejects : _notarySetRejects;
    std::map<CIdentityID, CIdentitySignature> &notarySetConfirms = pNotarySetConfirms ? *pNotarySetConfirms : _notarySetConfirms;
    std::map<CIdentityID, CIdentitySignature> partialConfirms;
    std::map<CIdentityID, CIdentitySignature> partialRejects;

    CNotaryEvidence::EStates retVal = CNotaryEvidence::EStates::STATE_CONFIRMING;

    if (!checkHeight)
    {
        checkHeight = UINT32_MAX;
    }

    // if we have full rejection from any IDs in any period, that is considered rejection and that ID is blacklisted from accepting
    // if we have full confirmation in the most recent period, that is considered confirmation

    // write the object to the hash writer without a vector length prefix
    uint256 outputUTXOHash;
    {
        CNativeHashWriter hw(hashType);
        hw << output;
        outputUTXOHash = hw.GetHash();
    }

    // for every height, we check and merge
    uint32_t lastHeight = 0;

    for (auto &oneSigBlock : notarySignatures)
    {
        // we only care up to signing height
        uint32_t height = oneSigBlock.signatures.size() ? oneSigBlock.signatures.begin()->second.blockHeight : 0;
        if (!height)
        {
            continue;
        }

        // if this was signed on this chain, it isn't valid if signed after the check height
        if (oneSigBlock.systemID == ASSETCHAINS_CHAINID && height > checkHeight)
        {
            continue;
        }

        if (height != lastHeight)
        {
            notarySetRejects.clear();
            notarySetConfirms.clear();
        }

        if (oneSigBlock.IsConfirmed())
        {
            for (auto &oneIDSig : oneSigBlock.signatures)
            {
                if (!notarySet.count(oneIDSig.first))
                {
                    LogPrint("notarization", "%s: unauthorized notary identity: %s\n", __func__, EncodeDestination(oneIDSig.first).c_str());
                    continue;
                }

                CIdentity sigIdentity;

                sigIdentity = CIdentity::LookupIdentity(oneIDSig.first, oneSigBlock.systemID == ASSETCHAINS_CHAINID ?
                                                                                    oneIDSig.second.blockHeight :
                                                                                    checkHeight);

                if (!sigIdentity.IsValid())
                {
                    LogPrint("notarization", "%s: invalid notary identity: %s\n", __func__, EncodeDestination(oneIDSig.first).c_str());
                    return EStates::STATE_INVALID;
                }

                // we cannot confirm based on the signature of a revoked identity, but that state does not veto either
                if (sigIdentity.IsRevoked())
                {
                    confirmedByHeight[oneIDSig.second.blockHeight].erase(oneIDSig.first);
                    continue;
                }

                std::vector<std::vector<unsigned char>> dupSigs;
                CIdentitySignature::ESignatureVerification result = oneIDSig.second.CheckSignature(sigIdentity,
                                                                                                   std::vector<uint160>({NotaryConfirmedKey()}),
                                                                                                   std::vector<std::string>(),
                                                                                                   std::vector<uint256>({outputUTXOHash}),
                                                                                                   systemID,
                                                                                                   "",
                                                                                                   objHash,
                                                                                                   &dupSigs);

                for (auto &oneDup : dupSigs)
                {
                    confirmedByHeight[oneIDSig.second.blockHeight][oneIDSig.first].signatures.erase(oneDup);
                }

                if (result == oneIDSig.second.SIGNATURE_INVALID)
                {
                    LogPrint("notarization", "%s: invalid notary signature: %s\n", __func__, EncodeDestination(oneIDSig.first).c_str());
                    continue;
                }

                if (result == oneIDSig.second.SIGNATURE_COMPLETE)
                {
                    partialConfirms.insert(oneIDSig);
                }
                else if (result == oneIDSig.second.SIGNATURE_PARTIAL)
                {
                    auto it = partialConfirms.find(oneIDSig.first);
                    if (it != partialConfirms.end() &&
                        it->second.blockHeight == oneIDSig.second.blockHeight)
                    {
                        for (auto &oneSig : oneIDSig.second.signatures)
                        {
                            it->second.AddSignature(oneSig);
                        }
                    }
                    else
                    {
                        partialConfirms.insert(oneIDSig);
                    }
                }
                if (result != oneIDSig.second.SIGNATURE_COMPLETE)
                {
                    // could store and return partial signatures here
                    continue;
                }
                notarySetConfirms.insert(oneIDSig);
            }
        }
        else
        {
            for (auto &oneIDSig : oneSigBlock.signatures)
            {
                if (!notarySet.count(oneIDSig.first))
                {
                    LogPrint("notarization", "%s: unauthorized notary identity for rejection: %s\n", __func__, EncodeDestination(oneIDSig.first).c_str());
                    return EStates::STATE_INVALID;
                }

                CIdentity sigIdentity = CIdentity::LookupIdentity(oneIDSig.first, oneIDSig.second.blockHeight);
                if (!sigIdentity.IsValid())
                {
                    LogPrint("notarization", "%s: invalid notary identity for rejection: %s\n", __func__, EncodeDestination(oneIDSig.first).c_str());
                    return EStates::STATE_INVALID;
                }

                // we cannot reject based on the signature of a revoked identity, but that state does not veto either
                if (sigIdentity.IsRevoked())
                {
                    rejectedByHeight[oneIDSig.second.blockHeight].erase(oneIDSig.first);
                    continue;
                }

                std::vector<std::vector<unsigned char>> dupSigs;
                CIdentitySignature::ESignatureVerification result = oneIDSig.second.CheckSignature(sigIdentity,
                                                                                                   std::vector<uint160>({NotaryRejectedKey()}),
                                                                                                   std::vector<std::string>(),
                                                                                                   std::vector<uint256>({outputUTXOHash}),
                                                                                                   systemID,
                                                                                                   "",
                                                                                                   objHash,
                                                                                                   &dupSigs);

                for (auto &oneDup : dupSigs)
                {
                    rejectedByHeight[oneIDSig.second.blockHeight][oneIDSig.first].signatures.erase(oneDup);
                }

                if (result == oneIDSig.second.SIGNATURE_INVALID)
                {
                    LogPrint("notarization", "%s: invalid notary signature for rejection: %s\n", __func__, EncodeDestination(oneIDSig.first).c_str());
                    continue;
                }

                if (result == oneIDSig.second.SIGNATURE_COMPLETE)
                {
                    partialRejects.insert(oneIDSig);
                }
                else if (result == oneIDSig.second.SIGNATURE_PARTIAL)
                {
                    auto it = partialRejects.find(oneIDSig.first);
                    if (it != partialRejects.end() &&
                        it->second.blockHeight == oneIDSig.second.blockHeight)
                    {
                        for (auto &oneSig : oneIDSig.second.signatures)
                        {
                            it->second.AddSignature(oneSig);
                        }
                    }
                    else
                    {
                        partialRejects.insert(oneIDSig);
                    }
                }

                if (result != oneIDSig.second.SIGNATURE_COMPLETE)
                {
                    // partial signatures are in the by height maps
                    continue;
                }
                notarySetRejects.insert(oneIDSig);
            }
        }

        lastHeight = height;

        if (notarySetRejects.size() >= minConfirming)
        {
            retVal = EStates::STATE_REJECTED;
            break;
        }
        else if (notarySetConfirms.size() >= minConfirming)
        {
            retVal = EStates::STATE_CONFIRMED;
            break;
        }
    }

    if (pDecisionHeight)
    {
        *pDecisionHeight = lastHeight;
    }

    if (retVal != EStates::STATE_CONFIRMED && retVal != EStates::STATE_REJECTED)
    {
        notarySetConfirms = partialConfirms;
        notarySetRejects = partialRejects;
        if (lastHeight == checkHeight &&
            notarySetConfirms.size() >= notarySetRejects.size())
        {
            retVal = EStates::STATE_CONFIRMING;
        }
        else
        {
            retVal = EStates::STATE_REJECTING;
        }
    }
    return retVal;
}

CPBaaSNotarization::CPBaaSNotarization(const CScript &scriptPubKey) :
                    nVersion(VERSION_INVALID),
                    flags(0),
                    notarizationHeight(0),
                    prevHeight(0)
{
    COptCCParams p;
    if (scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
        p.vData.size())
    {
        ::FromVector(p.vData[0], *this);
    }
}

CPBaaSNotarization::CPBaaSNotarization(const CTransaction &tx, int32_t *pOutIdx) :
                    nVersion(VERSION_INVALID),
                    flags(0),
                    notarizationHeight(0),
                    prevHeight(0)
{
    // the PBaaS notarization itself is a combination of proper inputs, one output, and
    // a sequence of opret chain objects as proof of the output values on the chain to which the
    // notarization refers, the opret can be reconstructed from chain data in order to validate
    // the txid of a transaction that does not contain the opret itself

    int32_t _outIdx;
    int32_t &outIdx = pOutIdx ? *pOutIdx : _outIdx;

    // a notarization must have notarization output that spends to the address indicated by the
    // ChainID, an opret, that there is only one, and that it can be properly decoded to a notarization
    // output, whether or not validate is true
    bool found = false;
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
            p.vData.size())
        {
            if (found)
            {
                nVersion = VERSION_INVALID;
                proofRoots.clear();
                break;
            }
            else
            {
                found = true;
                outIdx = i;
                ::FromVector(p.vData[0], *this);
            }
        }
    }
}

CPBaaSNotarization::CPBaaSNotarization(const UniValue &obj)
{
    nVersion = (uint32_t)uni_get_int64(find_value(obj, "version"));
    flags = FLAGS_NONE;
    SetDefinitionNotarization(uni_get_bool(find_value(obj, "isdefinition")));
    SetBlockOneNotarization(uni_get_bool(find_value(obj, "isblockonenotarization")));
    SetPreLaunch(uni_get_bool(find_value(obj, "prelaunch")));
    SetLaunchCleared(uni_get_bool(find_value(obj, "launchcleared")));
    SetRefunding(uni_get_bool(find_value(obj, "refunding")));
    SetLaunchConfirmed(uni_get_bool(find_value(obj, "launchconfirmed")));
    SetLaunchComplete(uni_get_bool(find_value(obj, "launchcomplete")));
    if (uni_get_bool(find_value(obj, "ismirror")))
    {
        flags |= FLAG_ACCEPTED_MIRROR;
    }
    SetSameChain(uni_get_bool(find_value(obj, "samechain")));

    currencyID = ValidateCurrencyName(uni_get_str(find_value(obj, "currencyid")));
    if (currencyID.IsNull())
    {
        nVersion = VERSION_INVALID;
        return;
    }

    UniValue transferID = find_value(obj, "proposer");
    if (transferID.isObject())
    {
        proposer = CTransferDestination(transferID);
    }

    SetContractUpgrade(proposer.GetAuxDest(0), uni_get_bool(find_value(obj, "contractupgrade")));

    notarizationHeight = (uint32_t)uni_get_int64(find_value(obj, "notarizationheight"));
    currencyState = CCoinbaseCurrencyState(find_value(obj, "currencystate"));
    prevNotarization = CUTXORef(uint256S(uni_get_str(find_value(obj, "prevnotarizationtxid"))), (uint32_t)uni_get_int(find_value(obj, "prevnotarizationout")));
    hashPrevCrossNotarization = uint256S(uni_get_str(find_value(obj, "hashprevcrossnotarization")));
    prevHeight = (uint32_t)uni_get_int64(find_value(obj, "prevheight"));

    auto curStateArr = find_value(obj, "currencystates");
    auto proofRootArr = find_value(obj, "proofroots");
    auto nodesUni = find_value(obj, "nodes");

    if (curStateArr.isArray())
    {
        for (int i = 0; i < curStateArr.size(); i++)
        {
            std::vector<std::string> keys = curStateArr[i].getKeys();
            std::vector<UniValue> values = curStateArr[i].getValues();
            if (keys.size() != 1 or values.size() != 1)
            {
                nVersion = VERSION_INVALID;
                return;
            }
            currencyStates.insert(std::make_pair(GetDestinationID(DecodeDestination(keys[0])), CCoinbaseCurrencyState(values[0])));
        }
    }

    if (proofRootArr.isArray())
    {
        for (int i = 0; i < proofRootArr.size(); i++)
        {
            CProofRoot oneRoot(proofRootArr[i]);
            if (!oneRoot.IsValid())
            {
                nVersion = VERSION_INVALID;
                return;
            }
            proofRoots.insert(std::make_pair(oneRoot.systemID, oneRoot));
        }
    }

    if (nodesUni.isArray())
    {
        vector<UniValue> nodeVec = nodesUni.getValues();
        for (auto node : nodeVec)
        {
            nodes.push_back(CNodeData(uni_get_str(find_value(node, "networkaddress")), uni_get_str(find_value(node, "nodeidentity"))));
        }
    }
}

bool operator==(const CProofRoot &op1, const CProofRoot &op2)
{
    return op1.version == op2.version &&
           op1.type == op2.type &&
           op1.rootHeight == op2.rootHeight &&
           op1.stateRoot == op2.stateRoot &&
           op1.systemID == op2.systemID &&
           op1.blockHash == op2.blockHash &&
           op1.compactPower == op2.compactPower &&
           (op1.type == CProofRoot::TYPE_ETHEREUM ? op1.gasPrice == op2.gasPrice : true);
}

bool operator!=(const CProofRoot &op1, const CProofRoot &op2)
{
    return !(op1 == op2);
}

bool operator<(const CProofRoot &op1, const CProofRoot &op2)
{
    return op1.systemID == op2.systemID ?
                (op1.rootHeight < op2.rootHeight ? true : (op1.rootHeight > op2.rootHeight ? false : ::AsVector(op1) < ::AsVector(op2))) :
                (op1.systemID < op2.systemID);
}

int CPBaaSNotarization::GetBlocksPerCheckpoint(int heightChange)
{
    int blocksPerCheckpoint = std::min(heightChange, (int)MIN_BLOCKS_PER_CHECKPOINT);
    if (heightChange > (MIN_BLOCKS_PER_CHECKPOINT * MAX_PROOF_CHECKPOINTS))
    {
        blocksPerCheckpoint = (heightChange / MAX_PROOF_CHECKPOINTS) +
                                ((heightChange % MAX_PROOF_CHECKPOINTS) ? 1 : 0);
    }
    return blocksPerCheckpoint;
}

int CPBaaSNotarization::GetNumCheckpoints(int heightChange)
{
    int blocksPerCheckpoint = GetBlocksPerCheckpoint(heightChange);

    // unless we have another proof range sized chunk at the end, don't add another checkpoint
    return !blocksPerCheckpoint ? blocksPerCheckpoint :
             (heightChange / blocksPerCheckpoint + ((heightChange % blocksPerCheckpoint) >= NUM_BLOCKS_PER_PROOF_RANGE ? 0 : -1));
}

CProofRoot CProofRoot::GetProofRoot(uint32_t blockHeight)
{
    if (blockHeight > chainActive.Height())
    {
        return CProofRoot(1, VERSION_INVALID);
    }
    auto mmv = chainActive.GetMMV();
    mmv.resize(blockHeight + 1);
    return CProofRoot(ASSETCHAINS_CHAINID,
                      blockHeight,
                      mmv.GetRoot(),
                      chainActive[blockHeight]->GetBlockHash(),
                      chainActive[blockHeight]->chainPower.CompactChainPower());
}

CNotaryEvidence::CNotaryEvidence(const CTransaction &tx, int outputNum, int &afterEvidence, uint8_t EvidenceType) :
    type(EvidenceType), version(CNotaryEvidence::VERSION_INVALID)
{
    afterEvidence = outputNum;

    COptCCParams p;

    if (afterEvidence >= 0 &&
        tx.vout.size() > afterEvidence &&
        tx.vout[afterEvidence++].scriptPubKey.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.evalCode == EVAL_NOTARY_EVIDENCE &&
        p.vData.size() &&
        (*this = CNotaryEvidence(p.vData[0])).IsValid())
    {
        if (IsMultipartProof())
        {
            COptCCParams eP;
            CNotaryEvidence supplementalEvidence;
            std::vector<CNotaryEvidence> partsVector({*this});
            while (tx.vout.size() > afterEvidence &&
                tx.vout[afterEvidence++].scriptPubKey.IsPayToCryptoCondition(eP) &&
                eP.IsValid() &&
                eP.evalCode == EVAL_NOTARY_EVIDENCE &&
                eP.vData.size() &&
                (supplementalEvidence = CNotaryEvidence(eP.vData[0])).IsValid() &&
                supplementalEvidence.IsMultipartProof() &&
                supplementalEvidence.evidence.chainObjects.size() == 1)
            {
                partsVector.push_back(supplementalEvidence);
            }
            *this = CNotaryEvidence(partsVector);
        }
    }
}

// returns false if hash is null
bool CPBaaSEvidenceRef::GetOutputData(std::vector<unsigned char> &data, bool checkMemPool) const
{
    CTransaction tx;
    uint256 blockHash;
    if (GetOutputTransaction(tx, blockHash, checkMemPool))
    {
        // get output data and pull this out of it
        int32_t afterData;
        uint8_t evidenceType;
        CNotaryEvidence evidenceData(tx, output.n, afterData, CNotaryEvidence::TYPE_IMPORT_PROOF);
        if (evidenceData.IsValid() &&
            evidenceData.type == CNotaryEvidence::TYPE_IMPORT_PROOF &&
            evidenceData.evidence.chainObjects.size() > objectNum)
        {
            if (evidenceData.evidence.chainObjects[objectNum]->objectType == CHAINOBJ_EVIDENCEDATA)
            {
                try
                {
                    data = ((CChainObject<CEvidenceData> *)evidenceData.evidence.chainObjects[objectNum])->object.dataVec;
                    return true;
                }
                catch(...)
                {
                    return false;
                }
            }
        }
    }
    return false;
}

// returns false if hash is null
bool CPBaaSEvidenceRef::GetOutputTransaction(CTransaction &tx, uint256 &blockHash, bool checkMemPool) const
{
    if (systemID.IsNull() || systemID == ASSETCHAINS_CHAINID)
    {
        return output.GetOutputTransaction(tx, blockHash, checkMemPool);
    }
    return false;
}

// get data out of an ID entry
bool CIdentityMultimapRef::GetOutputData(std::vector<unsigned char> &data, bool checkMemPool) const
{
    auto dataFromID = CIdentity::GetAggregatedIdentityMultimap(idID, heightStart, heightEnd, checkMemPool, false, 0, key, flags & FLAG_NO_DELETION);
    if (HasDataHash())
    {
        for (auto &oneDataRef : dataFromID)
        {
            CNativeHashWriter hw;
            hw.write((char *)&(std::get<0>(oneDataRef.second)[0]), std::get<0>(oneDataRef.second).size());

            if (hw.GetHash() == dataHash)
            {
                data = std::get<0>(oneDataRef.second);
                return true;
            }
        }
    }
    else if (dataFromID.size())
    {
        // just get the last entry, which should be sorted by position
        data = std::get<0>(dataFromID.rbegin()->second);
    }
    return false;
}

bool CURLRef::GetOutputData(std::vector<unsigned char> &data, bool makeRequest) const
{
    // if makerequest, actually make a network call to get the data
    return false;
}

bool CPBaaSNotarization::GetLastNotarization(const uint160 &currencyID,
                                             int32_t startHeight,
                                             int32_t endHeight,
                                             CAddressIndexDbEntry *txOutIdx,
                                             CTransaction *txOut)
{
    CPBaaSNotarization notarization;
    std::vector<CAddressIndexDbEntry> notarizationIndex;
    // get the last notarization in the indicated height for this currency, which is valid by definition for a token
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(currencyID, CPBaaSNotarization::NotaryNotarizationKey()), CScript::P2IDX, notarizationIndex, startHeight, endHeight))
    {
        // filter out all transactions that do not spend from the notarization thread, or originate as the
        // chain definition
        for (auto it = notarizationIndex.rbegin(); it != notarizationIndex.rend(); it++)
        {
            // first unspent notarization that is valid is the one we want, skip spending
            if (it->first.spending)
            {
                continue;
            }
            LOCK(mempool.cs);
            CTransaction oneTx;
            uint256 blkHash;
            if (myGetTransaction(it->first.txhash, oneTx, blkHash))
            {
                if ((notarization = CPBaaSNotarization(oneTx.vout[it->first.index].scriptPubKey)).IsValid())
                {
                    *this = notarization;
                    if (txOutIdx)
                    {
                        *txOutIdx = *it;
                    }
                    if (txOut)
                    {
                        *txOut = oneTx;
                    }
                    break;
                }
            }
            else
            {
                LogPrintf("%s: error transaction %s not found, may need reindexing\n", __func__, it->first.txhash.GetHex().c_str());
                printf("%s: error transaction %s not found, may need reindexing\n", __func__, it->first.txhash.GetHex().c_str());
                continue;
            }
        }
    }
    return notarization.IsValid();
}

bool CPBaaSNotarization::GetLastUnspentNotarization(const uint160 &currencyID,
                                                    uint256 &txIDOut,
                                                    int32_t &txOutNum,
                                                    CTransaction *txOut)
{
    CPBaaSNotarization notarization;
    std::vector<CAddressUnspentDbEntry> notarizationIndex;
    // get the last notarization in the indicated height for this currency, which is valid by definition for a token
    if (GetAddressUnspent(CCrossChainRPCData::GetConditionID(currencyID, CPBaaSNotarization::NotaryNotarizationKey()), CScript::P2IDX, notarizationIndex))
    {
        // first valid, unspent notarization found is the one we return
        for (auto it = notarizationIndex.rbegin(); it != notarizationIndex.rend(); it++)
        {
            LOCK(mempool.cs);
            CTransaction oneTx;
            uint256 blkHash;
            if (myGetTransaction(it->first.txhash, oneTx, blkHash))
            {
                if ((notarization = CPBaaSNotarization(oneTx.vout[it->first.index].scriptPubKey)).IsValid())
                {
                    *this = notarization;
                    txIDOut = it->first.txhash;
                    txOutNum = it->first.index;
                    if (txOut)
                    {
                        *txOut = oneTx;
                    }
                    break;
                }
            }
            else
            {
                LogPrintf("%s: error transaction %s not found, may need reindexing\n", __func__, it->first.txhash.GetHex().c_str());
                printf("%s: error transaction %s not found, may need reindexing\n", __func__, it->first.txhash.GetHex().c_str());
                continue;
            }
        }
    }
    return notarization.IsValid();
}

bool CPBaaSNotarization::NextNotarizationInfo(const CCurrencyDefinition &sourceSystem,
                                              const CCurrencyDefinition &destCurrency,
                                              uint32_t lastExportHeight,
                                              uint32_t notaHeight,
                                              std::vector<CReserveTransfer> &exportTransfers,       // both in and out. this may refund conversions
                                              uint256 &transferHash,
                                              CPBaaSNotarization &newNotarization,
                                              std::vector<CTxOut> &importOutputs,
                                              CCurrencyValueMap &importedCurrency,
                                              CCurrencyValueMap &gatewayDepositsUsed,
                                              CCurrencyValueMap &spentCurrencyOut,
                                              CTransferDestination feeRecipient,
                                              bool lastImportBeforeComplete,
                                              bool coLaunchCheck) const
{
    uint160 sourceSystemID = sourceSystem.GetID();
    uint160 destSystemID = destCurrency.IsGateway() ? destCurrency.gatewayID : destCurrency.systemID;

    bool forcedRefund = false;

    newNotarization = *this;
    newNotarization.SetDefinitionNotarization(false);
    newNotarization.SetBlockOneNotarization(false);
    newNotarization.prevNotarization = CUTXORef();
    newNotarization.prevHeight = newNotarization.notarizationHeight;
    newNotarization.notarizationHeight = notaHeight;

    // if we are communicating with an external system that uses a different hash, use it for everything
    CCurrencyDefinition::EHashTypes hashType = CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR;

    uint160 externalSystemID = sourceSystem.SystemOrGatewayID() == ASSETCHAINS_CHAINID ?
                                ((destSystemID == ASSETCHAINS_CHAINID) ? uint160() : destSystemID) :
                                sourceSystem.GetID();

    CCurrencyDefinition externalSystemDef;
    if (externalSystemID.IsNull() || externalSystemID == ASSETCHAINS_CHAINID)
    {
        externalSystemDef = ConnectedChains.ThisChain();
    }
    else if (externalSystemID == sourceSystemID)
    {
        externalSystemDef = sourceSystem;
    }
    else if (externalSystemID == destSystemID)
    {
        if (destCurrency.GetID() == destSystemID)
        {
            externalSystemDef = destCurrency;
        }
        else
        {
            externalSystemDef = ConnectedChains.GetCachedCurrency(externalSystemID);
            if (!externalSystemDef.IsValid())
            {
                LogPrintf("%s: cannot retrieve system definition for %s\n", __func__, EncodeDestination(CIdentityID(externalSystemID)));
                return false;
            }
        }
    }

    bool isBlockOnePBaaSLaunchNotarization = notaHeight == 1 &&
                                             IsPreLaunch() &&
                                             IsLaunchConfirmed() &&
                                             (destCurrency.IsPBaaSChain() || destCurrency.IsGatewayConverter()) &&
                                             destCurrency.systemID != destCurrency.launchSystemID;

    uint32_t currentHeight = IsPreLaunch() && IsLaunchConfirmed() && destCurrency.SystemOrGatewayID() == externalSystemID ?
                                1 :
                                notaHeight + 1;

    bool preLaunchPBaaSUpdate = ConnectedChains.vARRRUpdateEnabled(notaHeight + 1);

    bool improvedMinCheck = (externalSystemID == ASSETCHAINS_CHAINID && ConnectedChains.CheckZeroViaOnlyPostLaunch(currentHeight)) ||
                            (!PBAAS_TESTMODE && externalSystemID != ASSETCHAINS_CHAINID) ||
                            (PBAAS_TESTMODE &&
                             destCurrency.IsPBaaSChain() &&
                             notaHeight == 1 &&
                             proofRoots.count(VERUS_CHAINID) &&
                             proofRoots.find(VERUS_CHAINID)->second.rootHeight >= ConnectedChains.GetZeroViaHeight(PBAAS_TESTMODE)) ||
                            (ConnectedChains.CheckZeroViaOnlyPostLaunch(currentHeight));

    bool includePostLaunchFees = ConnectedChains.IncludePostLaunchFees(currentHeight) &&
                                 !(destCurrency.IsGatewayConverter() && destCurrency.systemID != destCurrency.launchSystemID) &&
                                 destCurrency.IsFractional();

    bool clearConvert = ConnectedChains.CheckClearConvert(notaHeight);

    CCoinbaseCurrencyState::ReversionUpdate reversionUpdate = !improvedMinCheck ?
                                                                CCoinbaseCurrencyState::PBAAS_1_0_0 :
                                                                !clearConvert ?
                                                                    CCoinbaseCurrencyState::PBAAS_1_0_8 :
                                                                    CCoinbaseCurrencyState::ReversionUpdateForHeight(chainActive.Height());

    if (!externalSystemID.IsNull())
    {
        hashType = (CCurrencyDefinition::EHashTypes)externalSystemDef.proofProtocol;
    }

    CNativeHashWriter hwPrevNotarization;
    hwPrevNotarization << *this;
    newNotarization.hashPrevCrossNotarization = hwPrevNotarization.GetHash();

    CNativeHashWriter hw(hashType);

    CCurrencyValueMap newPreConversionReservesIn;
    CCurrencyValueMap prelaunchReserveIn;

    if (improvedMinCheck)
    {
        if (IsPreLaunch() || (!IsPreLaunch() && !IsLaunchComplete()))
        {
            newPreConversionReservesIn = IsPreLaunch() ?
                        (currencyState.IsFractional() ?
                            CCurrencyValueMap(currencyState.currencies, currencyState.reserves) :
                            CCurrencyValueMap(currencyState.currencies, currencyState.reserveIn)) :
                        CCurrencyValueMap(currencyState.currencies, currencyState.primaryCurrencyIn);
            if (!currencyState.IsFractional() && !(IsPreLaunch() && destCurrency.IsPBaaSChain()))
            {
                newPreConversionReservesIn =
                    currencyState.NativeToReserveRaw(newPreConversionReservesIn.AsCurrencyVector(currencyState.currencies),
                                                     currencyState.PricesInReserve());
            }
            prelaunchReserveIn = newPreConversionReservesIn;
        }
    }
    else
    {
        if (!IsPreLaunch() && !IsLaunchComplete())
        {
            newPreConversionReservesIn = CCurrencyValueMap(currencyState.currencies, currencyState.primaryCurrencyIn);
        }
    }

    CCurrencyValueMap maxPreconvertMap;
    if (destCurrency.maxPreconvert.size())
    {
        maxPreconvertMap = CCurrencyValueMap(destCurrency.currencies, destCurrency.maxPreconvert);
    }

    for (int i = 0; i < exportTransfers.size(); i++)
    {
        CReserveTransfer reserveTransfer = exportTransfers[i];

        //auto transferVec = ::AsVector(reserveTransfer);
        //printf("%s: ReserveTransfer:\n%s\nSerialized:\n%s\n", __func__, reserveTransfer.ToUniValue().write(1,2).c_str(), HexBytes(&(transferVec[0]), transferVec.size()).c_str());

        // add the pre-mutation reserve transfer to the hash
        hw << reserveTransfer;

        if (currencyState.IsRefunding())
        {
            reserveTransfer = reserveTransfer.GetRefundTransfer();
        }

        // ensure that any pre-conversions or conversions are all valid, based on mined height and
        // maximum pre-conversions
        else if (reserveTransfer.IsPreConversion())
        {
            if (IsLaunchComplete())
            {
                //printf("%s: Invalid pre-conversion, mined on or after start block\n", __func__);
                LogPrintf("%s: Invalid pre-conversion, mined on or after start block\n", __func__);
                reserveTransfer = reserveTransfer.GetRefundTransfer();
            }
            else
            {
                // check if it exceeds pre-conversion maximums, and refund if so
                CCurrencyValueMap newReserveIn = CCurrencyValueMap(std::vector<uint160>({reserveTransfer.FirstCurrency()}),
                                                                   std::vector<int64_t>({reserveTransfer.FirstValue() - CReserveTransactionDescriptor::CalculateConversionFee(reserveTransfer.FirstValue())}));
                CCurrencyValueMap newTotalReserves;
                if (improvedMinCheck)
                {
                    newTotalReserves = (prelaunchReserveIn + newReserveIn).IntersectingValues(newReserveIn);
                }
                else
                {
                    if (IsPreLaunch())
                    {
                        newTotalReserves = CCurrencyValueMap(destCurrency.currencies, newNotarization.currencyState.reserves) + newReserveIn;
                    }
                    else
                    {
                        newTotalReserves = CCurrencyValueMap(destCurrency.currencies, newNotarization.currencyState.primaryCurrencyIn) + newReserveIn;
                    }
                }

                if (destCurrency.maxPreconvert.size() &&
                    ((!improvedMinCheck && LegacyLT(maxPreconvertMap, newTotalReserves)) ||
                     (improvedMinCheck && (maxPreconvertMap - newTotalReserves).HasNegative())))
                {
                    LogPrintf("%s: refunding pre-conversion over maximum\n", __func__);
                    reserveTransfer = reserveTransfer.GetRefundTransfer();
                }
                else
                {
                    newPreConversionReservesIn += newReserveIn;
                    prelaunchReserveIn += newReserveIn;
                }
            }
        }
        else if (reserveTransfer.IsConversion())
        {
            if (!IsLaunchComplete())
            {
                //printf("%s: Invalid conversion, mined before start block\n", __func__);
                LogPrintf("%s: Invalid conversion, mined before start block\n", __func__);
                reserveTransfer = reserveTransfer.GetRefundTransfer();
            }
        }
    }

    if (exportTransfers.size())
    {
        transferHash = hw.GetHash();
    }

    CReserveTransactionDescriptor rtxd;
    std::vector<CTxOut> dummyImportOutputs;
    bool thisIsLaunchSys = destCurrency.launchSystemID == ASSETCHAINS_CHAINID;

    // if this is the clear launch notarization after start, make the notarization and determine if we should launch or refund
    uint256 weakEntropy = EntropyHashFromHeight(CBlockIndex::BlockEntropyKey(), notaHeight, newNotarization.currencyID);

    if (destCurrency.launchSystemID == sourceSystemID &&
        destCurrency.startBlock &&
        ((!isBlockOnePBaaSLaunchNotarization && thisIsLaunchSys && notaHeight <= (destCurrency.startBlock - 1)) ||
         isBlockOnePBaaSLaunchNotarization))
    {
        // we get one pre-launch coming through here, initial supply is set and ready for pre-convert
        if (((thisIsLaunchSys && notaHeight == (destCurrency.startBlock - 1)) || isBlockOnePBaaSLaunchNotarization) &&
            newNotarization.IsPreLaunch())
        {
            bool initialPBaaSStart = destCurrency.IsGatewayConverter() || destCurrency.IsPBaaSChain();

            if (newNotarization.IsLaunchCleared())
            {
                newNotarization.SetPreLaunch(false);
                newNotarization.currencyState.SetLaunchClear();
                newNotarization.currencyState.SetPrelaunch(false);
                newNotarization.currencyState.RevertReservesAndSupply(destCurrency, destCurrency.systemID, initialPBaaSStart, reversionUpdate);
                if (destCurrency.IsPBaaSChain())
                {
                    newNotarization.currencyState.supply = 0;
                }
            }
            else
            {
                newNotarization.SetLaunchCleared();
                newNotarization.currencyState.SetLaunchClear();

                // if we are connected to another currency, make sure it will also start before we confirm that we can
                CCurrencyDefinition coLaunchCurrency;
                CCoinbaseCurrencyState coLaunchState;
                bool coLaunching = false;
                if (coLaunchCheck && destCurrency.IsGatewayConverter())
                {
                    // PBaaS or gateway converters have a parent which is the PBaaS chain or gateway
                    coLaunching = true;
                    coLaunchCurrency = ConnectedChains.GetCachedCurrency(destCurrency.parent);
                }
                else if (coLaunchCheck && destCurrency.IsPBaaSChain() && !destCurrency.GatewayConverterID().IsNull())
                {
                    coLaunching = true;
                    coLaunchCurrency = ConnectedChains.GetCachedCurrency(destCurrency.GatewayConverterID());
                }

                if (coLaunching)
                {
                    if (!coLaunchCurrency.IsValid())
                    {
                        printf("%s: Invalid co-launch currency - likely corruption\n", __func__);
                        LogPrintf("%s: Invalid co-launch currency - likely corruption\n", __func__);
                        return false;
                    }
                    coLaunchState = ConnectedChains.GetCurrencyState(coLaunchCurrency, notaHeight, true);

                    if (!coLaunchState.IsValid())
                    {
                        printf("%s: Invalid co-launch currency state - likely corruption\n", __func__);
                        LogPrintf("%s: Invalid co-launch currency state - likely corruption\n", __func__);
                        return false;
                    }

                    // check our currency and any co-launch currency to determine our eligibility, as ALL
                    // co-launch currencies must launch for one to launch
                    CCurrencyValueMap coLaunchReserveIn = CCurrencyValueMap(coLaunchCurrency.currencies, coLaunchState.reserveIn);
                    CCurrencyValueMap coLaunchMinMap = CCurrencyValueMap(coLaunchCurrency.currencies, coLaunchCurrency.minPreconvert);
                    if (coLaunchState.IsRefunding() ||
                        !coLaunchState.ValidateConversionLimits(true) ||
                        (!improvedMinCheck && LegacyLT(coLaunchReserveIn, coLaunchMinMap)) ||
                        (improvedMinCheck && (coLaunchReserveIn - coLaunchMinMap).HasNegative()) ||
                        (coLaunchCurrency.IsFractional() &&
                         CCurrencyValueMap(coLaunchCurrency.currencies, coLaunchState.reserveIn).CanonicalMap().valueMap.size() != coLaunchCurrency.currencies.size()))
                    {
                        forcedRefund = true;
                    }
                }

                // first time through is export, second is import, then we finish clearing the launch
                // check if the chain is qualified to launch or should refund
                CCurrencyValueMap minPreMap, fees;
                CCurrencyValueMap preConvertedMap = (CCurrencyValueMap(destCurrency.currencies, newNotarization.currencyState.reserveIn) +
                                                     newPreConversionReservesIn).CanonicalMap();

                if (destCurrency.minPreconvert.size() && destCurrency.minPreconvert.size() == destCurrency.currencies.size())
                {
                    minPreMap = CCurrencyValueMap(destCurrency.currencies, destCurrency.minPreconvert).CanonicalMap();
                }

                if (forcedRefund ||
                    (minPreMap.valueMap.size() &&
                     ((!improvedMinCheck && LegacyLT(preConvertedMap, minPreMap)) ||
                      (improvedMinCheck && (preConvertedMap - minPreMap).HasNegative()))) ||
                    (destCurrency.IsFractional() &&
                     (CCurrencyValueMap(destCurrency.currencies, newNotarization.currencyState.reserveIn) +
                                        newPreConversionReservesIn).CanonicalMap().valueMap.size() != destCurrency.currencies.size()))
                {
                    // we force the reserves and supply to zero
                    // in any case where there was less than minimum participation,
                    newNotarization.currencyState.supply = 0;
                    newNotarization.currencyState.reserves = std::vector<int64_t>(newNotarization.currencyState.reserves.size(), 0);
                    newNotarization.currencyState.SetRefunding(true);
                    newNotarization.SetRefunding(true);
                }
                else
                {
                    newNotarization.SetLaunchConfirmed();
                    newNotarization.currencyState.SetLaunchConfirmed();

                    // if this is a launch notarization for a PBaaS chain, add a proofroot of the
                    // current chain as an anchor for the block one import
                    if (destCurrency.IsPBaaSChain() &&
                        destCurrency.launchSystemID == ASSETCHAINS_CHAINID)
                    {
                        CProofRoot curProofRoot = CProofRoot::GetProofRoot(destCurrency.startBlock - 1);
                        if (!curProofRoot.IsValid())
                        {
                            return false;
                        }
                        newNotarization.proofRoots[ASSETCHAINS_CHAINID] = curProofRoot;
                        newNotarization.currencyStates[ASSETCHAINS_CHAINID] = ConnectedChains.GetCurrencyState(destCurrency.startBlock - 1);
                    }
                }
            }
        }
        else if (thisIsLaunchSys && notaHeight < (destCurrency.startBlock - 1))
        {
            newNotarization.currencyState.SetPrelaunch();
        }

        // NOTE: destcurrency systemID is correct here, since this is only prelaunch or block 1, which doesn't apply for gateway's
        CCurrencyDefinition destSystem = newNotarization.IsRefunding() ? ConnectedChains.GetCachedCurrency(destCurrency.launchSystemID) :
                                                                         ConnectedChains.GetCachedCurrency(destCurrency.systemID);

        CCoinbaseCurrencyState tempState = newNotarization.currencyState;
        if (destCurrency.IsFractional() &&
            !(newNotarization.IsLaunchCleared() && !newNotarization.currencyState.IsLaunchCompleteMarker()) &&
            exportTransfers.size())
        {
            // normalize prices on the way in to prevent overflows on first pass
            std::vector<int64_t> newReservesVector = newPreConversionReservesIn.AsCurrencyVector(tempState.currencies);
            tempState.reserves = tempState.AddVectors(tempState.reserves, newReservesVector);
            newNotarization.currencyState.conversionPrice = tempState.PricesInReserve();
        }

        std::vector<CTxOut> tempOutputs;
        bool retVal = rtxd.AddReserveTransferImportOutputs(newNotarization.IsRefunding() ? destSystem : sourceSystem,
                                                           newNotarization.IsRefunding() ? sourceSystem : destSystem,
                                                           destCurrency,
                                                           newNotarization.currencyState,
                                                           exportTransfers,
                                                           currentHeight,
                                                           tempOutputs,
                                                           importedCurrency,
                                                           gatewayDepositsUsed,
                                                           spentCurrencyOut,
                                                           &tempState,
                                                           feeRecipient,
                                                           proposer,
                                                           weakEntropy,
                                                           !destCurrency.IsFractional());

        if (retVal)
        {
            //printf("%s: importedCurrency: %s\ngatewaysDepositsUsed: %s\n", __func__, importedCurrency.ToUniValue().write(1,2).c_str(), gatewayDepositsUsed.ToUniValue().write(1,2).c_str());
            importedCurrency.valueMap.clear();
            gatewayDepositsUsed.valueMap.clear();
            spentCurrencyOut.valueMap.clear();
            newNotarization.currencyState.conversionPrice = tempState.conversionPrice;
            newNotarization.currencyState.viaConversionPrice = tempState.viaConversionPrice;
            rtxd = CReserveTransactionDescriptor();

            retVal = rtxd.AddReserveTransferImportOutputs((newNotarization.IsRefunding() || tempState.IsRefunding()) ? destSystem : sourceSystem,
                                                          (newNotarization.IsRefunding() || tempState.IsRefunding()) ? sourceSystem : destSystem,
                                                          destCurrency,
                                                          newNotarization.currencyState,
                                                          exportTransfers,
                                                          currentHeight,
                                                          importOutputs,
                                                          importedCurrency,
                                                          gatewayDepositsUsed,
                                                          spentCurrencyOut,
                                                          &tempState,
                                                          feeRecipient,
                                                          proposer,
                                                          weakEntropy,
                                                          true);
        }
        else
        {
            return retVal;
        }

        //printf("%s: importedCurrency: %s\ngatewaysDepositsUsed: %s\n", __func__, importedCurrency.ToUniValue().write(1,2).c_str(), gatewayDepositsUsed.ToUniValue().write(1,2).c_str());
        if (tempState.IsRefunding() && !newNotarization.IsRefunding())
        {
            tempState.supply = 0;
            tempState.reserves = std::vector<int64_t>(newNotarization.currencyState.reserves.size(), 0);
            newNotarization.SetRefunding(true);
            newNotarization.SetLaunchConfirmed(false);
            newNotarization.currencyState.SetLaunchConfirmed(false);
        }

        // if we are in the pre-launch phase, all reserves in are cumulative and then calculated together at launch
        // reserves in represent all reserves in, and fees are taken out after launch or refund as well
        //
        // we add up until the end, then stop adding reserves at launch clear. this gives us the ability to reverse the
        // pre-launch state for validation. we continue adding fees up to pre-launch to easily get a total of unconverted
        // fees, which we need when creating a PBaaS chain, as all currency, both reserves and fees exported to the new
        // chain must be either output to specific addresses, taken as fees by miners, or stored in reserve deposits.
        if (!newNotarization.IsRefunding() && tempState.IsPrelaunch())
        {
            if (improvedMinCheck &&
                (destCurrency.IsPBaaSChain() ||
                 (destCurrency.IsGatewayConverter() &&
                  destSystemID != destCurrency.launchSystemID)))
            {
                // total up all reserves entered in prelaunch except fees
                auto currencyIdxMap = tempState.GetReserveMap();
                for (auto &oneCurrencyID : tempState.currencies)
                {
                    int idx = currencyIdxMap[oneCurrencyID];

                    if (destCurrency.IsPBaaSChain())
                    {
                        tempState.primaryCurrencyIn[idx] += this->currencyState.primaryCurrencyIn[idx];
                    }
                    else
                    {
                        tempState.primaryCurrencyIn[idx] = this->currencyState.primaryCurrencyIn[idx];
                        if (rtxd.currencies.count(oneCurrencyID))
                        {
                            if (destCurrency.IsGatewayConverter())
                            {
                                tempState.primaryCurrencyIn[idx] += (tempState.reserveIn[idx] - tempState.conversionFees[idx]);
                            }
                            else
                            {
                                tempState.primaryCurrencyIn[idx] += (rtxd.currencies[oneCurrencyID].reserveIn - tempState.fees[idx]);
                            }
                        }
                    }
                }
            }
            tempState.reserveIn = tempState.AddVectors(tempState.reserveIn, this->currencyState.reserveIn);
            if (!destCurrency.IsFractional() && !this->IsDefinitionNotarization() && !tempState.IsLaunchClear())
            {
                if (!preLaunchPBaaSUpdate)
                {
                    tempState.supply += this->currencyState.supply - this->currencyState.emitted;
                }
                tempState.preConvertedOut += this->currencyState.preConvertedOut;
                tempState.primaryCurrencyOut += this->currencyState.primaryCurrencyOut;
            }
        }
        else if (!newNotarization.currencyState.IsLaunchCompleteMarker() &&
                 !tempState.IsRefunding() &&
                 (includePostLaunchFees && improvedMinCheck && tempState.IsFractional() ?
                    !newNotarization.currencyState.IsPrelaunch()  :
                    !this->currencyState.IsPrelaunch()))
        {
            // accumulate reserves during pre-conversions import to enforce max pre-convert
            CCurrencyValueMap tempReserves;
            CCurrencyValueMap cumulativeReserves;
            auto currencyIdxMap = tempState.GetReserveMap();
            bool newCumulative = improvedMinCheck && tempState.IsFractional();
            for (auto &oneCurrencyID : tempState.currencies)
            {
                int64_t reservesIn;

                if (!includePostLaunchFees && !rtxd.currencies.count(oneCurrencyID))
                {
                    continue;
                }

                if (newCumulative)
                {
                    reservesIn = oneCurrencyID == ASSETCHAINS_CHAINID ?
                        (rtxd.nativeIn - rtxd.nativeOut) :
                        (rtxd.currencies[oneCurrencyID].reserveIn - rtxd.currencies[oneCurrencyID].reserveOut);

                    int idx = currencyIdxMap[oneCurrencyID];
                    if (includePostLaunchFees)
                    {
                        tempState.primaryCurrencyIn[idx] = newNotarization.currencyState.primaryCurrencyIn[idx] + (tempState.reserveIn[idx] - tempState.fees[idx]);
                    }
                    else
                    {
                        reservesIn -= (oneCurrencyID == ASSETCHAINS_CHAINID ? 0 : rtxd.currencies[oneCurrencyID].reserveConversionFees);
                        if (oneCurrencyID == ASSETCHAINS_CHAINID)
                        {
                            tempState.primaryCurrencyIn[idx] =
                                (this->currencyState.primaryCurrencyIn[idx] + rtxd.nativeIn + tempState.reserveOut[idx]) - rtxd.nativeOut;
                        }
                        else
                        {
                            tempState.primaryCurrencyIn[idx] = this->currencyState.primaryCurrencyIn[idx] + reservesIn;
                        }
                    }
                }
                else
                {
                    reservesIn = rtxd.currencies[oneCurrencyID].nativeOutConverted;
                }

                if (reservesIn)
                {
                    tempReserves.valueMap[oneCurrencyID] = reservesIn;
                }
            }

            // use double entry to enable pass through of the accumulated reserve such that when
            // reverting supply and reserves, we end up with what we started, after prelaunch and
            // before all post launch functions are complete, we use primaryCurrencyIn to accumulate
            // reserves to enforce maxPreconvert
            if (!newCumulative)
            {
                tempState.primaryCurrencyIn = tempState.AddVectors(this->currencyState.primaryCurrencyIn, tempReserves.AsCurrencyVector(tempState.currencies));
            }

            if (!(includePostLaunchFees && improvedMinCheck && tempState.IsFractional()))
            {
                tempState.reserveOut =
                        tempState.AddVectors(tempState.reserveOut,
                                            (CCurrencyValueMap(tempState.currencies, tempState.reserveIn) * -1).AsCurrencyVector(tempState.currencies));
            }

            if (!lastImportBeforeComplete && !includePostLaunchFees)
            {
                tempState.reserveIn = tempReserves.AsCurrencyVector(tempState.currencies);
            }
        }
        if (destCurrency.IsPBaaSChain() && tempState.IsLaunchClear() && this->currencyState.IsLaunchClear())
        {
            tempState.reserveIn = this->currencyState.reserveIn;
        }
        newNotarization.currencyState = tempState;
        return retVal;
    }
    else
    {
        if (sourceSystemID != destCurrency.launchSystemID || lastExportHeight >= destCurrency.startBlock || newNotarization.IsLaunchComplete())
        {
            newNotarization.currencyState.SetLaunchCompleteMarker();
        }
        newNotarization.currencyState.SetLaunchClear(false);

        CCurrencyDefinition destSystem = newNotarization.IsRefunding() ? ConnectedChains.GetCachedCurrency(destCurrency.launchSystemID) :
                                                                         ConnectedChains.GetCachedCurrency(destCurrency.SystemOrGatewayID());

        // calculate new state from processing all transfers
        // we are not refunding, and it is possible that we also have
        // normal conversions in addition to pre-conversions. add any conversions that may
        // be present into the new currency state
        CCoinbaseCurrencyState intermediateState = newNotarization.currencyState;
        bool isValidExport = rtxd.AddReserveTransferImportOutputs(sourceSystem,
                                                                  destSystem,
                                                                  destCurrency,
                                                                  intermediateState,
                                                                  exportTransfers,
                                                                  currentHeight,
                                                                  dummyImportOutputs,
                                                                  importedCurrency,
                                                                  gatewayDepositsUsed,
                                                                  spentCurrencyOut,
                                                                  &newNotarization.currencyState,
                                                                  feeRecipient,
                                                                  proposer,
                                                                  weakEntropy,
                                                                  !destCurrency.IsFractional());
        if (!newNotarization.currencyState.IsPrelaunch() &&
            isValidExport)
        {
            if (destCurrency.IsFractional())
            {
                // we want the new price and the old state as a starting point to ensure no rounding error impact
                // on reserves
                importedCurrency = CCurrencyValueMap();
                gatewayDepositsUsed = CCurrencyValueMap();
                CCoinbaseCurrencyState tempCurState = intermediateState;
                tempCurState.conversionPrice = newNotarization.currencyState.conversionPrice;
                tempCurState.viaConversionPrice = newNotarization.currencyState.viaConversionPrice;
                CCoinbaseCurrencyState tempState;
                rtxd = CReserveTransactionDescriptor();
                isValidExport = rtxd.AddReserveTransferImportOutputs(sourceSystem,
                                                                    destSystem,
                                                                    destCurrency,
                                                                    tempCurState,
                                                                    exportTransfers,
                                                                    currentHeight,
                                                                    importOutputs,
                                                                    importedCurrency,
                                                                    gatewayDepositsUsed,
                                                                    spentCurrencyOut,
                                                                    &tempState,
                                                                    feeRecipient,
                                                                    proposer,
                                                                    weakEntropy,
                                                                    true);
                if (isValidExport)
                {
                    tempState.conversionPrice = tempCurState.conversionPrice;
                    tempState.viaConversionPrice = tempCurState.viaConversionPrice;
                    uint32_t heightCheck = currentHeight == 1 ? 1 : currentHeight - 1;
                    if (heightCheck < chainActive.Height())
                    {
                        heightCheck = chainActive.Height();
                    }
                    if (improvedMinCheck)
                    {
                        if (!tempState.IsLaunchCompleteMarker() &&
                            !tempState.IsRefunding() &&
                            !tempState.IsPrelaunch())
                        {
                            // accumulate reserves during pre-conversions import to enforce max pre-convert
                            CCurrencyValueMap cumulativeReserves;
                            auto currencyIdxMap = tempState.GetReserveMap();
                            bool newCumulative = tempState.IsFractional();
                            bool isPBaaSBridge = destCurrency.IsGatewayConverter() && destCurrency.systemID == ASSETCHAINS_CHAINID;
                            for (auto &oneCurrencyID : tempState.currencies)
                            {
                                int64_t reservesIn = newCumulative ?
                                    oneCurrencyID == ASSETCHAINS_CHAINID ?
                                        (isPBaaSBridge ? 0 : (rtxd.nativeIn - rtxd.nativeOut)) :
                                        (rtxd.currencies[oneCurrencyID].reserveIn - (rtxd.currencies[oneCurrencyID].reserveConversionFees + rtxd.currencies[oneCurrencyID].reserveOut)) :
                                    rtxd.currencies[oneCurrencyID].nativeOutConverted;

                                int idx = currencyIdxMap[oneCurrencyID];
                                if (newCumulative && oneCurrencyID == ASSETCHAINS_CHAINID)
                                {
                                    tempState.reserveIn[idx] = (rtxd.nativeIn + tempState.reserveOut[idx]) - rtxd.nativeOut;
                                }
                                else
                                {
                                    tempState.reserveIn[idx] = reservesIn;
                                }
                                tempState.primaryCurrencyIn[idx] = this->currencyState.primaryCurrencyIn[idx] + tempState.reserveIn[idx];
                            }
                        }
                    }
                    newNotarization.currencyState = tempState;
                }
            }
            else
            {
                if (improvedMinCheck && !newNotarization.IsPreLaunch() && !newNotarization.currencyState.IsLaunchCompleteMarker())
                {
                    auto currencyIdxMap = newNotarization.currencyState.GetReserveMap();
                    for (auto &oneCurrencyID : newNotarization.currencyState.currencies)
                    {
                        if (oneCurrencyID == destSystem.GetID())
                        {
                            continue;
                        }
                        int idx = currencyIdxMap[oneCurrencyID];
                        newNotarization.currencyState.reserveIn[idx] = rtxd.currencies[oneCurrencyID].nativeOutConverted;
                        newNotarization.currencyState.primaryCurrencyIn[idx] = this->currencyState.primaryCurrencyIn[idx] + newNotarization.currencyState.reserveIn[idx];
                    }
                }
                importOutputs.insert(importOutputs.end(), dummyImportOutputs.begin(), dummyImportOutputs.end());
            }
        }
        else if (isValidExport)
        {
            importOutputs.insert(importOutputs.end(), dummyImportOutputs.begin(), dummyImportOutputs.end());
        }

        if (!isValidExport)
        {
            LogPrintf("%s: invalid export\n", __func__);
            return false;
        }
        return true;
    }

    // based on the last notarization and existing
    return false;
}

CObjectFinalization::CObjectFinalization(const CScript &script) : version(VERSION_INVALID)
{
    COptCCParams p;
    if (script.IsPayToCryptoCondition(p) && p.IsValid())
    {
        if ((p.evalCode == EVAL_FINALIZE_NOTARIZATION || p.evalCode == EVAL_FINALIZE_EXPORT) &&
            p.vData.size())
        {
            *this = CObjectFinalization(p.vData[0]);
        }
    }
}

CObjectFinalization::CObjectFinalization(const UniValue &uni) : version(VERSION_CURRENT)
{
    version = uni_get_int(find_value(uni, "version"), version);
    finalizationType = uni_get_int(find_value(uni, "finalizationtype"), FINALIZE_INVALID);
    if (finalizationType == FINALIZE_INVALID)
    {
        version = VERSION_INVALID;
        return;
    }

    UniValue evidenceInputsArr = find_value(uni, "evidenceinputs");
    std::set<int> inputSet;
    if (evidenceInputsArr.isArray() && evidenceInputsArr.size())
    {
        for (int i = 0; i < evidenceInputsArr.size(); i++)
        {
            evidenceInputs.push_back(uni_get_int(evidenceInputsArr[i]));
            if (inputSet.count(evidenceInputs.back()) || evidenceInputs.back() < 0)
            {
                version = VERSION_INVALID;
                return;
            }
            inputSet.insert(evidenceInputs.back());
        }
    }

    std::set<int> outputSet;
    UniValue evidenceOutputsArr = find_value(uni, "evidenceoutputs");
    if (evidenceOutputsArr.isArray() && evidenceOutputsArr.size())
    {
        for (int i = 0; i < evidenceOutputsArr.size(); i++)
        {
            evidenceOutputs.push_back(uni_get_int(evidenceOutputsArr[i]));
            if (outputSet.count(evidenceOutputs.back()) || evidenceOutputs.back() < 0)
            {
                version = VERSION_INVALID;
                return;
            }
            inputSet.insert(evidenceOutputs.back());
        }
    }

    currencyID = ValidateCurrencyName(uni_get_str(find_value(uni, "currencyid")));
    output = CUTXORef(find_value(uni, "output"));
}


CObjectFinalization::CObjectFinalization(const CTransaction &tx, uint32_t *pEcode, int32_t *pFinalizationOutNum, uint32_t minFinalHeight, uint8_t Version) :
    minFinalizationHeight(minFinalHeight),
    version(Version)
{
    uint32_t _ecode;
    uint32_t &ecode = pEcode ? *pEcode : _ecode;
    int32_t _finalizeOutNum;
    int32_t &finalizeOutNum = pFinalizationOutNum ? *pFinalizationOutNum : _finalizeOutNum;
    finalizeOutNum = -1;
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid())
        {
            if (p.evalCode == EVAL_FINALIZE_NOTARIZATION || p.evalCode == EVAL_FINALIZE_EXPORT)
            {
                if (finalizeOutNum != -1)
                {
                    version = VERSION_INVALID;
                    finalizeOutNum = -1;
                    break;
                }
                else
                {
                    finalizeOutNum = i;
                    ecode = p.evalCode;
                }
            }
        }
    }
}

CChainNotarizationData::CChainNotarizationData(UniValue &obj,
                                               bool loadNotarizations,
                                               std::vector<uint256> *pBlockHash,
                                               std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>>> *pCounterEvidence,
                                               std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence>>> *pEvidence)
{
    version = (uint32_t)uni_get_int(find_value(obj, "version"));
    UniValue vtxUni = find_value(obj, "notarizations");
    if (pBlockHash)
    {
        pBlockHash->clear();
    }
    if (pCounterEvidence)
    {
        pCounterEvidence->clear();
    }
    if (pEvidence)
    {
        pEvidence->clear();
    }
    if (vtxUni.isArray())
    {
        for (int i = 0; i < vtxUni.size(); i++)
        {
            auto &o = vtxUni[i];

            UniValue notarizationUni = find_value(o, "notarization");
            if (loadNotarizations && notarizationUni.isNull())
            {
                uint256 txid;
                txid.SetHex(uni_get_str(find_value(o, "txid")));
                CUTXORef utxo(txid, uni_get_int(find_value(o, "vout"), -1));
                if (utxo.IsValid())
                {
                    uint256 blockHash;
                    CTransaction tx;
                    COptCCParams p;
                    CPBaaSNotarization pbn;
                    if (utxo.GetOutputTransaction(tx, blockHash) &&
                        tx.vout.size() > utxo.n &&
                        tx.vout[utxo.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                        (p.evalCode == EVAL_EARNEDNOTARIZATION || p.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
                        p.vData.size() &&
                        (pbn = CPBaaSNotarization(p.vData[0])).IsValid())
                    {
                        notarizationUni = pbn.ToUniValue();
                        if (pBlockHash)
                        {
                            pBlockHash->push_back(blockHash);
                        }
                    }
                    else
                    {
                        version = 0;
                        return;
                    }
                }
                else
                {
                    version = 0;
                    return;
                }
            }
            else if (pBlockHash)
            {
                uint256 blockHash;
                blockHash.SetHex(uni_get_str(find_value(o, "blockhash")));
                pBlockHash->push_back(blockHash);
            }

            vtx.push_back(make_pair(CUTXORef(uint256S(uni_get_str(find_value(o, "txid"))),
                                             uni_get_int(find_value(o, "vout"))),
                                    CPBaaSNotarization(notarizationUni)));
            if (pEvidence)
            {
                pEvidence->resize(pEvidence->size() + 1);
                UniValue evidenceUni = find_value(o, "evidence");
                if (evidenceUni.isArray() && evidenceUni.size())
                {
                    for (int j = 0; j < evidenceUni.size(); j++)
                    {
                        if (evidenceUni[j].isObject())
                        {
                            std::tuple<CObjectFinalization, CNotaryEvidence> oneEvidenceItem({
                                                                                    CObjectFinalization(find_value(evidenceUni[j], "finalization")),
                                                                                    CNotaryEvidence(find_value(evidenceUni[j], "notaryevidence"))
                                                                                });

                            if (!std::get<0>(oneEvidenceItem).IsValid() ||
                                !std::get<1>(oneEvidenceItem).IsValid())
                            {
                                continue;
                            }
                            pEvidence->back().push_back(oneEvidenceItem);
                        }
                    }
                }
            }
            if (pCounterEvidence)
            {
                pCounterEvidence->resize(pCounterEvidence->size() + 1);
                UniValue counterEvidenceUni = find_value(o, "counterevidence");
                if (counterEvidenceUni.isArray() && counterEvidenceUni.size())
                {
                    for (int j = 0; j < counterEvidenceUni.size(); j++)
                    {
                        if (counterEvidenceUni[j].isObject())
                        {
                            std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>
                                oneCounterEvidenceItem(
                                    {
                                        CObjectFinalization(find_value(counterEvidenceUni[j], "finalization")),
                                        CNotaryEvidence(find_value(counterEvidenceUni[j], "notaryevidence")),
                                        CProofRoot(find_value(counterEvidenceUni[j], "counterroot")),
                                        CProofRoot(find_value(counterEvidenceUni[j], "challengestart"))
                                    }
                                );

                            if (!std::get<0>(oneCounterEvidenceItem).IsValid() ||
                                !std::get<1>(oneCounterEvidenceItem).IsValid() ||
                                !std::get<2>(oneCounterEvidenceItem).IsValid())
                            {
                                continue;
                            }
                            pCounterEvidence->back().push_back(oneCounterEvidenceItem);
                        }
                    }
                }
            }
        }
    }

    lastConfirmed = (uint32_t)uni_get_int(find_value(obj, "lastconfirmed"));
    UniValue forksUni = find_value(obj, "forks");
    if (forksUni.isArray())
    {
        vector<UniValue> forksVec = forksUni.getValues();
        for (auto fv : forksVec)
        {
            if (fv.isArray() && fv.size())
            {
                forks.push_back(vector<int32_t>());
                for (auto fidx : fv.getValues())
                {
                    forks.back().push_back(uni_get_int(fidx));
                }
            }
        }
    }

    bestChain = (uint32_t)uni_get_int(find_value(obj, "bestchain"));
}

UniValue CChainNotarizationData::ToUniValue(const std::vector<std::pair<CTransaction, uint256>> &transactionsAndBlockHash,
                                            const std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>>> &counterEvidence,
                                            const std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence>>> &evidence) const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int32_t)version));
    UniValue notarizations(UniValue::VARR);
    for (int64_t i = 0; i < vtx.size(); i++)
    {
        UniValue notarization(UniValue::VOBJ);
        notarization.push_back(Pair("index", i));
        notarization.push_back(Pair("txid", vtx[i].first.hash.GetHex()));

        if (i < transactionsAndBlockHash.size())
        {
            notarization.push_back(Pair("blockhash", transactionsAndBlockHash[i].second.GetHex()));
        }
        notarization.push_back(Pair("vout", (int32_t)vtx[i].first.n));
        notarization.push_back(Pair("notarization", vtx[i].second.ToUniValue()));
        if (i < evidence.size())
        {
            UniValue evidenceUni(UniValue::VARR);
            for (auto &oneItem : evidence[i])
            {
                UniValue evidenceElement(UniValue::VOBJ);
                evidenceElement.pushKV("finalization", std::get<0>(oneItem).ToUniValue());
                evidenceElement.pushKV("notaryevidence", std::get<1>(oneItem).ToUniValue());
                evidenceUni.push_back(evidenceElement);
            }
            if (evidenceUni.size())
            {
                notarization.pushKV("evidence", evidenceUni);
            }
        }
        if (i < counterEvidence.size())
        {
            UniValue counterEvidenceUni(UniValue::VARR);
            for (auto &oneCounterItem : counterEvidence[i])
            {
                UniValue counterEvidenceElement(UniValue::VOBJ);
                counterEvidenceElement.pushKV("finalization", std::get<0>(oneCounterItem).ToUniValue());
                counterEvidenceElement.pushKV("notaryevidence", std::get<1>(oneCounterItem).ToUniValue());
                counterEvidenceElement.pushKV("counterroot", std::get<2>(oneCounterItem).ToUniValue());
                counterEvidenceElement.pushKV("challengestart", std::get<3>(oneCounterItem).ToUniValue());
                counterEvidenceUni.push_back(counterEvidenceElement);
            }
            if (counterEvidenceUni.size())
            {
                notarization.pushKV("counterevidence", counterEvidenceUni);
            }
        }
        notarizations.push_back(notarization);
    }
    obj.push_back(Pair("notarizations", notarizations));
    UniValue Forks(UniValue::VARR);
    for (int32_t i = 0; i < forks.size(); i++)
    {
        UniValue Fork(UniValue::VARR);
        for (int32_t j = 0; j < forks[i].size(); j++)
        {
            Fork.push_back(forks[i][j]);
        }
        Forks.push_back(Fork);
    }
    obj.push_back(Pair("forks", Forks));
    if (IsConfirmed())
    {
        obj.push_back(Pair("lastconfirmedheight", (int32_t)vtx[lastConfirmed].second.notarizationHeight));
        if (transactionsAndBlockHash.size() > lastConfirmed)
        {
            auto blockIt = mapBlockIndex.find(transactionsAndBlockHash[lastConfirmed].second);
            if (blockIt != mapBlockIndex.end())
            {
                obj.pushKV("notarizationmodulo", CPBaaSNotarization::GetAdjustedNotarizationModulo(ConnectedChains.ThisChain().blockNotarizationModulo,
                                                                                                            (int32_t)blockIt->second->GetHeight(),
                                                                                                            chainActive.Height() + 1));
            }
        }
    }

    obj.push_back(Pair("lastconfirmed", lastConfirmed));
    obj.push_back(Pair("bestchain", bestChain));
    return obj;
}

bool CChainNotarizationData::CalculateConfirmation(int confirmingIdx, std::set<int> &confirmedOutputNums, std::set<int> &invalidatedOutputNums) const
{
    int forkIdx = -1, forkPos = -1;

    if (confirmingIdx != lastConfirmed)
    {
        // if the third notarization does not equal the last confirmed notarization, it
        // must equal a last pending notarization to confirm. that will always be the
        // first non-confirmed entry in a fork of the notarization data, if it is present
        for (int i = 0; i < forks.size(); i++)
        {
            if (forks[i].size() > 1)
            {
                for (int j = forks[i].size() - 1; j >= 0; j--)
                {
                    if (forks[i][j] == confirmingIdx)
                    {
                        forkIdx = i;
                        forkPos = j;
                        break;
                    }
                }
                if (forkIdx > -1)
                {
                    break;
                }
            }
        }
        // if it wasn't the confirmed entry and wasn't pending confirmation, it is referring to an
        // invalid predecessor and therefore, confirmingIdx is invalid
        if (forkIdx == -1)
        {
            LogPrint("notarization", "%s: invalid prior notarization - neither pending nor confirmed\n", __func__);
            return false;
        }
    }

    if (forkIdx > -1)
    {
        // if this finalization is either confirmed or invalidated by the new accepted notarization,
        // add a spend here
        for (int i = 0; i <= forkPos; i++)
        {
            confirmedOutputNums.insert(forks[forkIdx][i]);
        }

        for (int i = 0; i < forks.size(); i++)
        {
            // already did the fork that is our focus
            if (i == forkIdx)
            {
                continue;
            }
            bool failed = false;

            int j;
            for (j = 0; j < forks[i].size(); j++)
            {
                // if we reach the end, the rest after are ignored
                if (forks[i][j] == confirmingIdx)
                {
                    break;
                }
                if (confirmedOutputNums.count(forks[i][j]))
                {
                    continue;
                }
                // it did not derive from the newly confirmed index, so it is invalid and all after this
                failed = true;
                break;
            }
            // if failed, invalidate all until the end, otherwise, ignore all until the end
            if (failed)
            {
                for (int k = j; k < forks[i].size(); k++)
                {
                    invalidatedOutputNums.insert(forks[i][k]);
                }
            }
        }
    }
    return true;
}

bool CChainNotarizationData::CorrelatedFinalizationSpends(const std::vector<std::pair<CTransaction, uint256>> &txes,
                                                          std::vector<std::vector<CInputDescriptor>> &spendsToClose,
                                                          std::vector<CInputDescriptor> &extraSpends,
                                                          std::vector<std::vector<CNotaryEvidence>> *pEvidenceVec) const
{
    if (!(IsValid() && IsConfirmed()))
    {
        return false;
    }
    uint160 currencyID = vtx[0].second.currencyID;

    if (pEvidenceVec)
    {
        *pEvidenceVec = std::vector<std::vector<CNotaryEvidence>>(vtx.size());
    }

    std::map<CUTXORef, int> notarizationOutputMap;

    for (int i = 0; i < vtx.size(); i++)
    {
        notarizationOutputMap.insert(std::make_pair(vtx[i].first, i));
    }

    uint32_t confirmedBlockHeight = mapBlockIndex.count(txes[lastConfirmed].second) ? mapBlockIndex[txes[lastConfirmed].second]->GetHeight() : 0;
    if (!confirmedBlockHeight)
    {
        LogPrint("notarization", "%s: last confirmed notarization not found in block index\n", __func__);
        return false;
    }

    spendsToClose = std::vector<std::vector<CInputDescriptor>>(vtx.size());

    for (auto onePending : CObjectFinalization::GetUnspentPendingFinalizations(currencyID))
    {
        // determine the notarization output that this is referring to
        COptCCParams p;
        CObjectFinalization existingFinalization;
        CUTXORef pendingNotarizationOutput;
        std::set<CUTXORef> evidenceOutputSet;
        if (onePending.second.scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.vData.size())
        {
            if (p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                (existingFinalization = CObjectFinalization(p.vData[0])).IsValid())
            {
                if (existingFinalization.output.IsOnSameTransaction())
                {
                    pendingNotarizationOutput = CUTXORef(onePending.second.txIn.prevout.hash, existingFinalization.output.n);
                }
                else
                {
                    pendingNotarizationOutput = existingFinalization.output;
                }
            }
            else if (p.evalCode == EVAL_EARNEDNOTARIZATION)
            {
                pendingNotarizationOutput = CUTXORef(onePending.second.txIn.prevout.hash, onePending.second.txIn.prevout.n);
            }
        }
        else
        {
            // this is likely some form of incorrect index
            LogPrintf("%s: LIKELY LOCAL STATE OR INDEX CORRUPTION. Bootstrap, reindex, or resync recommended\n", __func__);
            continue;
        }

        // if this is a finalization with some evidence, add the spends to close it that include the finalization and
        // its evidence outputs
        int associatedIdx = -1;
        if (pendingNotarizationOutput.IsValid() && !pendingNotarizationOutput.hash.IsNull())
        {
            std::vector<CInputDescriptor> associatedSpends;
            associatedSpends.push_back(onePending.second);      // this is a finalization or earned notarization, so it is an associated spend

            if (notarizationOutputMap.count(pendingNotarizationOutput))
            {
                associatedIdx = notarizationOutputMap[pendingNotarizationOutput];
            }

            // if we are associated with a known notarization,
            // get additional associated evidence as well
            if (associatedIdx != -1)
            {
                // if there is a finalization, we need to add it and its evidence,
                if (existingFinalization.IsValid() && pEvidenceVec)
                {
                    CTransaction finalizeTx;
                    uint256 finalizeBlockHash;
                    if (!myGetTransaction(onePending.second.txIn.prevout.hash, finalizeTx, finalizeBlockHash))
                    {
                        LogPrintf("%s: LIKELY LOCAL STATE OR INDEX CORRUPTION. Bootstrap, reindex, or resync recommended\n", __func__);
                        continue;
                    }
                    CValidationState state;
                    std::vector<std::pair<CObjectFinalization, CNotaryEvidence>> finalizationEvidence =
                        existingFinalization.GetFinalizationEvidence(finalizeTx, onePending.second.txIn.prevout.n, state);
                    for (auto oneEvidenceItem : finalizationEvidence)
                    {
                        (*pEvidenceVec)[associatedIdx].push_back(oneEvidenceItem.second);
                    }
                }
                spendsToClose[associatedIdx].insert(spendsToClose[associatedIdx].end(), associatedSpends.begin(), associatedSpends.end());
            }
            else
            {
                // it may be a straggler that came in before confirmation. if so, just clean it up
                if (onePending.first)
                {
                    // add it to unknown closing spends
                    extraSpends.insert(extraSpends.end(), associatedSpends.begin(), associatedSpends.end());
                }
                else
                {
                    LogPrint("notarization", "%s: no associated notarization located for pending finalization in mempool:\n%s\n", __func__, pendingNotarizationOutput.ToString().c_str());
                }
            }
        }
    }

    for (auto oneConfirmed : CObjectFinalization::GetUnspentConfirmedFinalizations(currencyID))
    {
        std::pair<uint32_t, CInputDescriptor> firstUnspentFinalization;
        bool error = false;
        // make sure we can retrieve it

        CTransaction checkTx;
        uint256 checkBlockHash;
        if (!myGetTransaction(oneConfirmed.second.txIn.prevout.hash, checkTx, checkBlockHash))
        {
            continue;
        }

        // since we are creating a new, confirmed finalization, spend old one here
        // determine the notarization output that this is referring to
        COptCCParams p;
        CObjectFinalization confirmedFinalization;
        CUTXORef confirmedNotarizationOutput;
        std::set<CUTXORef> evidenceOutputSet;

        if (oneConfirmed.second.scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid())
        {
            CPBaaSNotarization confirmedNotarization;
            if (p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                p.vData.size() &&
                (confirmedFinalization = CObjectFinalization(p.vData[0])).IsValid())
            {
                if (confirmedFinalization.output.IsOnSameTransaction())
                {
                    confirmedNotarizationOutput = CUTXORef(oneConfirmed.second.txIn.prevout.hash, confirmedFinalization.output.n);
                }
                else
                {
                    confirmedNotarizationOutput = confirmedFinalization.output;
                }
            }
            else if ((p.evalCode == EVAL_EARNEDNOTARIZATION || p.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
                     p.vData.size() &&
                     (confirmedNotarization = CPBaaSNotarization(p.vData[0])).IsValid() &&
                     (confirmedNotarization.IsDefinitionNotarization() ||
                      confirmedNotarization.IsBlockOneNotarization() ||
                      confirmedNotarization.IsPreLaunch()))
            {
                confirmedFinalization = CObjectFinalization(CObjectFinalization::FINALIZE_CONFIRMED + CObjectFinalization::FINALIZE_NOTARIZATION,
                                                            confirmedNotarization.currencyID,
                                                            oneConfirmed.second.txIn.prevout.hash,
                                                            oneConfirmed.second.txIn.prevout.n);
                confirmedNotarizationOutput = confirmedFinalization.output;
            }
        }
        else
        {
            // this is likely some form of incorrect index
            LogPrintf("%s: LIKELY LOCAL STATE OR INDEX CORRUPTION. Bootstrap, reindex, or resync recommended\n", __func__);
            continue;
        }

        // if this is a finalization, add the spends to close it that include the finalization and
        // its evidence outputs
        int associatedIdx = -1;
        if (confirmedFinalization.IsValid())
        {
            std::vector<CInputDescriptor> associatedSpends;
            associatedSpends.push_back(oneConfirmed.second);

            if (notarizationOutputMap.count(confirmedNotarizationOutput))
            {
                associatedIdx = notarizationOutputMap[confirmedNotarizationOutput];
            }

            if (associatedIdx != -1)
            {
                // if there is a finalization, we need to add it and its evidence,
                if (confirmedFinalization.IsValid() && pEvidenceVec)
                {
                    CValidationState state;
                    std::vector<std::pair<CObjectFinalization, CNotaryEvidence>> finalizationEvidence =
                        confirmedFinalization.GetFinalizationEvidence(checkTx, oneConfirmed.second.txIn.prevout.n, state);
                    for (auto oneEvidenceItem : finalizationEvidence)
                    {
                        (*pEvidenceVec)[associatedIdx].push_back(oneEvidenceItem.second);
                    }
                }
                spendsToClose[associatedIdx].insert(spendsToClose[associatedIdx].end(), associatedSpends.begin(), associatedSpends.end());
            }
            else
            {
                extraSpends.insert(extraSpends.end(), associatedSpends.begin(), associatedSpends.end());
            }
        }

        // this output wasn't found associated with any valid confirmed or pending notarization
        if (associatedIdx == -1)
        {
            // for finalizations that have no found association, we warn
            // printf("%s: no associated notarization located for confirmed finalization:\n%s\n", __func__, confirmedNotarizationOutput.ToString().c_str());
            LogPrint("notarization", "%s: no associated notarization located for confirmed finalization:\n%s\n", __func__, confirmedNotarizationOutput.ToString().c_str());
        }
    }
    return true;
}

// Whether this is an earned notarization or accepted, it retrieves the prior notarization on the chain
// for accepted notarizations, there must be valid proof of the prior notarization for it to correctly return the prior
// notarization
std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization> GetPriorReferencedNotarization(const CTransaction &tx,
                                                                                                int32_t notarizationOut,
                                                                                                const CPBaaSNotarization &notarization)
{
    std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization> retVal({0, CTransaction(), CUTXORef(), CPBaaSNotarization()});

    // if we can't go directly to the prior because this is a mirror, we'll need to get the data from
    // the proof that came with it on the blockchain. if it is prior to the testnet fork with that proof coming over,
    // it will return nothing
    if (notarization.IsMirror())
    {
        CObjectFinalization initialOF;
        int finalOutNum;
        for (finalOutNum = notarizationOut + 1; finalOutNum < tx.vout.size(); finalOutNum++)
        {
            if ((initialOF = CObjectFinalization(tx.vout[finalOutNum].scriptPubKey)).IsValid() &&
                initialOF.output.hash.IsNull() &&
                initialOF.output.n == notarizationOut)
            {
                break;
            }
        }
        if (finalOutNum >= tx.vout.size())
        {
            LogPrint("notarization", "%s: pending finalization for mirrored notarization (%s) not found\n", __func__, CUTXORef(tx.GetHash(), notarizationOut).ToString().c_str());
            return retVal;
        }
        CValidationState state;
        auto evidenceVec = initialOF.GetFinalizationEvidence(tx, finalOutNum, state);
        if (!evidenceVec.size())
        {
            LogPrint("notarization", "%s: evidence for mirrored notarization (%s) not found\n", __func__, CUTXORef(tx.GetHash(), notarizationOut).ToString().c_str());
            return retVal;
        }
        CNotaryEvidence &evidence = evidenceVec[0].second;
        int32_t afterEvidence;
        std::set<int> evidenceTypes;

        // proof of the last confirmed notarization matching the one on this chain or block 1 coinbase
        // by the newly confirmed notarization
        // proof of the current notarization by the first proof root mentioned above
        evidenceTypes.insert(CHAINOBJ_TRANSACTION_PROOF);

        CCrossChainProof autoProof(evidence.GetSelectEvidence(evidenceTypes));

        if (!autoProof.chainObjects.size())
        {
            LogPrint("notarization", "%s: notarization block hash proof type not found in block index or active chain at height \n", __func__);
            return retVal;
        }

        CTransaction outTx;
        bool isPartial = false;
        uint256 txMMRRoot = ((CChainObject<CPartialTransactionProof> *)autoProof.chainObjects[0])->object.CheckPartialTransaction(outTx, &isPartial);
        uint256 txHash = ((CChainObject<CPartialTransactionProof> *)autoProof.chainObjects[0])->object.TransactionHash();

        CPBaaSNotarization lastNotarization, lastLocalNotarization;
        CAddressIndexDbEntry lastNotarizationAddressEntry;

        auto rootIt = notarization.proofRoots.find(notarization.currencyID);
        if (rootIt != notarization.proofRoots.end() && txMMRRoot == rootIt->second.stateRoot)
        {
            for (auto &oneOut : outTx.vout)
            {
                COptCCParams lastNotaP;
                if (oneOut.nValue >= 0 &&
                    oneOut.scriptPubKey.size() &&
                    oneOut.scriptPubKey.IsPayToCryptoCondition(lastNotaP) &&
                    lastNotaP.IsValid() &&
                    (lastNotaP.evalCode == EVAL_ACCEPTEDNOTARIZATION || lastNotaP.evalCode == EVAL_EARNEDNOTARIZATION) &&
                    lastNotaP.vData.size() &&
                    (lastNotarization = CPBaaSNotarization(lastNotaP.vData[0])).IsValid() &&
                    (lastNotarization.IsPreLaunch() ||
                        lastNotarization.IsBlockOneNotarization() ||
                        lastNotarization.SetMirror(true)) &&
                    lastNotarization.currencyID == notarization.currencyID)
                {
                    break;
                }
                lastNotarization = CPBaaSNotarization();
            }

            if (lastNotarization.IsValid())
            {
                if (lastNotarization.IsBlockOneNotarization())
                {
                    // the prior confirmed notarization on our chain must be prelaunch when this was made,
                    // and we should be able to find it with a search before the root height of the last
                    // proof root for our chain and up to the height of the block 1 notarization proof root.
                    if (!(lastLocalNotarization.GetLastNotarization(notarization.currencyID,
                                                                    0,
                                                                    lastNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight,
                                                                    &lastNotarizationAddressEntry) &&
                            lastLocalNotarization.IsPreLaunch()))
                    {
                        lastLocalNotarization = lastNotarization = CPBaaSNotarization();
                    }
                }
                else
                {
                    std::vector<CObjectFinalization> lastOfs;
                    std::vector<CAddressIndexDbEntry> lastNotarizationIndexes;
                    lastLocalNotarization = lastNotarization;
                    if (!lastLocalNotarization.FindEarnedNotarizations(lastOfs, &lastNotarizationIndexes) ||
                        !lastNotarizationIndexes.size())
                    {
                        lastLocalNotarization = lastNotarization = CPBaaSNotarization();
                    }
                    else if (lastNotarizationIndexes.size() > 1)
                    {
                        std::set<int> evidenceCheckTypes;

                        // we need to select between multiple priors, and to do that, we
                        // see if there is commitment/challenge evidence that matches one by checking if the
                        // commitments match the respective entropyhash
                        evidenceCheckTypes.insert(CHAINOBJ_COMMITMENTDATA);
                        CCrossChainProof commitmentProof(evidence.GetSelectEvidence(evidenceCheckTypes));

                        evidenceCheckTypes.clear();
                        evidenceCheckTypes.insert(CHAINOBJ_PROOF_ROOT);
                        CCrossChainProof rootProof(evidence.GetSelectEvidence(evidenceCheckTypes));

                        if (commitmentProof.chainObjects.size() &&
                            rootProof.chainObjects.size())
                        {
                            CTransaction notarizationTx;
                            uint256 nBlkHash;
                            // make sure the one we find has a matching proof
                            for (auto &oneIndex : lastNotarizationIndexes)
                            {
                                if (!myGetTransaction(oneIndex.first.txhash, notarizationTx, nBlkHash))
                                {
                                    LogPrint("notarization", "Error retrieving notarization transaction\n");
                                    continue;
                                }
                                std::vector<__uint128_t> checkCommitments;
                                uint256 blockTypes = ((CChainObject<CHashCommitments> *)commitmentProof.chainObjects[0])->object.GetSmallCommitments(checkCommitments);
                                if (lastLocalNotarization.CheckEntropyHashMatch(nBlkHash,
                                                                                checkCommitments,
                                                                                lastLocalNotarization.currencyID,
                                                                                (lastLocalNotarization.proofRoots.count(lastLocalNotarization.currencyID) ?
                                                                                    lastLocalNotarization.proofRoots[lastLocalNotarization.currencyID].rootHeight :
                                                                                    1),
                                                                                ((CChainObject<CProofRoot> *)rootProof.chainObjects[0])->object.rootHeight))
                                {
                                    lastNotarizationAddressEntry = oneIndex;
                                    break;
                                }
                            }
                        }
                        else
                        {
                            int i;
                            for (i = 0; i < lastOfs.size(); i++)
                            {
                                if (lastOfs[i].IsValid())
                                {
                                    lastNotarizationAddressEntry = lastNotarizationIndexes[i];
                                    break;
                                }
                            }
                            if (i >= lastOfs.size())
                            {
                                lastNotarizationAddressEntry = lastNotarizationIndexes.back();
                            }
                        }
                    }
                    else
                    {
                        lastNotarizationAddressEntry = lastNotarizationIndexes.back();
                    }
                }

                std::get<2>(retVal) = CUTXORef(lastNotarizationAddressEntry.first.txhash, lastNotarizationAddressEntry.first.index);
                CTransaction lastNTx;
                uint256 lastBlockHash;
                if (!std::get<2>(retVal).GetOutputTransaction(lastNTx, lastBlockHash))
                {
                    std::get<2>(retVal) = CUTXORef();
                    return retVal;
                }
                std::get<0>(retVal) = lastNotarizationAddressEntry.first.blockHeight;
                std::get<1>(retVal) = lastNTx;
                std::get<3>(retVal) = lastLocalNotarization;
                return retVal;
            }
        }
        else if (LogAcceptCategory("notarization"))
        {
            printf("expected state root: %s, from proof at height %u\ntxid: %s\nproven notarization: %s\n",
                    txMMRRoot.GetHex().c_str(),
                    ((CChainObject<CPartialTransactionProof> *)autoProof.chainObjects[0])->object.GetProofHeight(),
                    txHash.GetHex().c_str(),
                    notarization.ToUniValue().write(1,2).c_str());
            LogPrintf("expected state root: %s, from proof at height %u\ntxid: %s\nproven notarization: %s\n",
                    txMMRRoot.GetHex().c_str(),
                    ((CChainObject<CPartialTransactionProof> *)autoProof.chainObjects[0])->object.GetProofHeight(),
                    txHash.GetHex().c_str(),
                    notarization.ToUniValue().write(1,2).c_str());
        }
    }
    else
    {
        std::get<2>(retVal) = notarization.prevNotarization;
        CTransaction lastNTx;
        uint256 lastBlockHash;
        CPBaaSNotarization lastLocalNotarization;
        BlockMap::iterator lastBlockIt;
        if (!std::get<2>(retVal).GetOutputTransaction(lastNTx, lastBlockHash) ||
            (!lastBlockHash.IsNull() &&
             ((lastBlockIt = mapBlockIndex.find(lastBlockHash)) == mapBlockIndex.end() ||
              !chainActive.Contains(lastBlockIt->second))) ||
            lastNTx.vout.size() <= std::get<2>(retVal).n ||
            !(lastLocalNotarization = CPBaaSNotarization(lastNTx.vout[std::get<2>(retVal).n].scriptPubKey)).IsValid() ||
            lastLocalNotarization.currencyID != notarization.currencyID)
        {
            std::get<2>(retVal) = CUTXORef();
            return retVal;
        }
        std::get<0>(retVal) = lastBlockHash.IsNull() ? 0 : lastBlockIt->second->GetHeight();
        std::get<1>(retVal) = lastNTx;
        std::get<3>(retVal) = lastLocalNotarization;
    }
    return retVal;
}

CProofRoot IsValidChallengeEvidence(const CCurrencyDefinition &externalSystem,
                                    const CProofRoot &defaultProofRoot,
                                    const CNotaryEvidence &e,
                                    const uint256 &entropyHash,
                                    bool &invalidates,
                                    CProofRoot &challengeStartRoot,
                                    uint32_t height)
{
    if (!e.IsRejected() || defaultProofRoot.systemID == ASSETCHAINS_CHAINID)
    {
        return CProofRoot();
    }
    bool validCounterEvidence = false;
    invalidates = false;

    // challenges to earned or accepted notarizations only differ in
    // the polarity of notarizations mirrored or not and each chain's
    // initial states.
    //
    // if the proof root system is a notary chain of this chain, we
    // can assume earned notarizations, except initial definition for
    // gateways. otherwise, we are working with mirrored, accepted
    // notarizations.
    //
    // currently, we support two types of challenges with the following properties:
    // 1) General challenge for proof, must have an alternate chain at least 3 blocks long. There
    //    are two subclasses of this kind of proof:
    //    a) Simply force proof about a chain that does not match the observed chain. In most cases,
    //       this is benign and will self-resolve, especially by sharing "good nodes" in notarizations.
    //    b) Proving a more powerful chain for an extended period of time and preventing finalization
    //       of alternate notarizations.
    //
    // 2) Fraud proof of failure to follow the notarization rule that requires a notarization to refer to
    //    the prior notarization on the blockchain with which it agrees, whether or not doing so would
    //    disqualify the miner or staker from being able to notarize at all.
    //    This type of proof simply proves or more recent notarization than the one claimed as being
    //    prior good one in the chain, using the proof root of the notarization to be invalidated.
    //    A notarization may be finalized as rejected, which invalidates all of its successors, if valid
    //    evidence of fraud is provided.
    //
    bool earnedNotarizations = false;
    if (ConnectedChains.NotarySystems().count(defaultProofRoot.systemID))
    {
        earnedNotarizations = true;
    }

    std::set<int> evidenceTypes;
    evidenceTypes.insert(CHAINOBJ_PROOF_ROOT);
    if (ConnectedChains.IsEnhancedNotarizationOrder(height))
    {
        evidenceTypes.insert(CHAINOBJ_EVIDENCEDATA);
    }
    evidenceTypes.insert(CHAINOBJ_TRANSACTION_PROOF);
    evidenceTypes.insert(CHAINOBJ_COMMITMENTDATA);
    evidenceTypes.insert(CHAINOBJ_HEADER);
    evidenceTypes.insert(CHAINOBJ_HEADER_REF);
    CCrossChainProof autoProof(e.GetSelectEvidence(evidenceTypes));

    CPBaaSNotarization lastNotarization;
    CBlockHeader alternateHeader;

    // valid counter evidence includes:
    // commitment to more powerful chain since the last confirmed notarization:
    //    1) must include:
    //       a) proof root of alternate to the notarization proof root that is more powerful
    //       b) proof of header of the alternate root height
    //       b) block commitments behind header proof that lead to more powerful chain
    //       c) proof of prior random headers based on current system root as of evidence tx submission

    enum EProofState {
        EXPECT_NOTHING = 0,
        EXPECT_ALTERNATE_PROOF_ROOT = 1,            // alternate root to the notarization being challenged
        EXPECT_SKIPPED_NOTARIZATION_REF = 2,        // UTXO reference to the notarization that was skipped
        EXPECT_SKIPPED_HEADERREF_PROOF = 3,         // proof of a header ref from the skipped notarization using the challenged notarization
    };
    EProofState proofState = EXPECT_ALTERNATE_PROOF_ROOT;
    int numHeaderProofs = 0;
    int rangeLen = 0;
    int expectNumHeaderProofs = 0;

    CProofRoot counterEvidenceRoot;
    uint256 evolvingEntropyHash = entropyHash;
    uint256 blockTypes;
    std::map<uint32_t, __uint128_t> priorNotarizationCommitments;

    CBlockHeaderAndProof posBlockHeaderAndProof;
    CPartialTransactionProof posSourceProof;
    CStakeParams stakeParams;
    std::vector<CBlockHeaderProof> posEntropyHeaders;
    std::vector<CIdentity> stakeSpendingIDs;
    CCurrencyDefinition externalCurrency;

    // used for fraud proofs to prove the skipped notarization proof root and other
    // consistencies with the challenged notarization
    CPBaaSNotarization skippedNotarization, priorNotarization, challengedNotarization;

    for (auto &proofComponent : autoProof.chainObjects)
    {
        switch (proofState)
        {
            case EXPECT_ALTERNATE_PROOF_ROOT:
            {
                if (proofComponent->objectType == CHAINOBJ_PROOF_ROOT)
                {
                    counterEvidenceRoot = ((CChainObject<CProofRoot> *)proofComponent)->object;
                    if (counterEvidenceRoot.systemID == defaultProofRoot.systemID)
                    {
                        if (counterEvidenceRoot == defaultProofRoot)
                        {
                            // this is a fraud proof, which must use this proof root to
                            // prove something that should not be able to be proven
                            proofState = EXPECT_SKIPPED_NOTARIZATION_REF;
                        }
                        else
                        {
                            proofState = EXPECT_NOTHING;
                        }
                    }
                    else
                    {
                        proofState = EXPECT_NOTHING;
                    }
                }
                else
                {
                    proofState = EXPECT_NOTHING;
                }
                break;
            }
            case EXPECT_SKIPPED_NOTARIZATION_REF:
            {
                // we should find an output reference to a notarization present on this chain
                // proven in the next step by the non-compliant notarization and which is not
                // referenced as a prior by this notarization, proving that the notarization
                // should have referenced the more recent one, rather than skipping it.
                //
                // proof of a specific header referred to by a notarization that should
                // have been referenced, but was skipped by the notarization this challenge refers to
                CUTXORef notarizationTxRef;
                CTransaction priorTx, skippedTx;
                uint256 priorBlkHash, skippedBlkHash;

                BlockMap::iterator priorIdx, skippedIdx, challengedIdx;

                if (proofComponent->objectType == CHAINOBJ_EVIDENCEDATA &&
                    ((CChainObject<CEvidenceData> *)proofComponent)->object.vdxfd == CVDXF_Data::UTXORefKey() &&
                    ((CChainObject<CEvidenceData> *)proofComponent)->object.dataVec.size() &&
                    (notarizationTxRef = CUTXORef(((CChainObject<CEvidenceData> *)proofComponent)->object.dataVec)).IsValid() &&
                    myGetTransaction(notarizationTxRef.hash, skippedTx, skippedBlkHash) &&
                    !skippedBlkHash.IsNull() &&
                    (skippedIdx = mapBlockIndex.find(skippedBlkHash)) != mapBlockIndex.end() &&
                    chainActive.Contains(skippedIdx->second) &&
                    notarizationTxRef.n > 0 &&
                    skippedTx.vout.size() > notarizationTxRef.n &&
                    (skippedNotarization = CPBaaSNotarization(skippedTx.vout[notarizationTxRef.n].scriptPubKey)).IsValid() &&
                    e.output.GetOutputTransaction(priorTx, priorBlkHash) &&
                    e.output.n > 0 &&
                    priorTx.vout.size() > e.output.n &&
                    (challengedNotarization = CPBaaSNotarization(priorTx.vout[e.output.n].scriptPubKey)).IsValid() &&
                    challengedNotarization.currencyID == defaultProofRoot.systemID &&
                    !priorBlkHash.IsNull() &&
                    (challengedIdx = mapBlockIndex.find(priorBlkHash)) != mapBlockIndex.end() &&
                    chainActive.Contains(challengedIdx->second) &&
                    challengedNotarization.prevNotarization.GetOutputTransaction(priorTx, priorBlkHash) &&
                    !priorBlkHash.IsNull() &&
                    (priorIdx = mapBlockIndex.find(priorBlkHash)) != mapBlockIndex.end() &&
                    chainActive.Contains(priorIdx->second) &&
                    priorTx.vout.size() > challengedNotarization.prevNotarization.n &&
                    (priorNotarization = CPBaaSNotarization(priorTx.vout[challengedNotarization.prevNotarization.n].scriptPubKey)).IsValid() &&
                    skippedIdx->second->GetHeight() <= challengedIdx->second->GetHeight() &&
                    priorIdx->second->GetHeight() <= skippedIdx->second->GetHeight() &&
                    priorNotarization.proofRoots.count(defaultProofRoot.systemID) &&
                    priorNotarization.proofRoots[defaultProofRoot.systemID].rootHeight < skippedNotarization.proofRoots[defaultProofRoot.systemID].rootHeight)
                {
                    proofState = EXPECT_SKIPPED_HEADERREF_PROOF;
                }
                else
                {
                    proofState = EXPECT_NOTHING;
                }
                break;
            }
            case EXPECT_SKIPPED_HEADERREF_PROOF:
            {
                // this should be a header ref proof of the proof root in the skipped notarization with the proof root in
                // the challenged notarization
                if (proofComponent->objectType == CHAINOBJ_HEADER_REF &&
                    challengedNotarization.proofRoots[defaultProofRoot.systemID].stateRoot ==
                     ((CChainObject<CBlockHeaderProof> *)proofComponent)->object.ValidateBlockHash(skippedNotarization.proofRoots[defaultProofRoot.systemID].blockHash,
                                                                                                  skippedNotarization.proofRoots[defaultProofRoot.systemID].rootHeight))
                {
                    validCounterEvidence = true;
                    invalidates = true;
                }
                break;
            }
            default:
            {
                proofState = EXPECT_NOTHING;
                break;
            }
        }
        if (proofState == EXPECT_NOTHING || validCounterEvidence)
        {
            break;
        }
    }
    return validCounterEvidence ? counterEvidenceRoot : CProofRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);
}

int32_t CPBaaSNotarization::GetAdjustedNotarizationModuloExp(int64_t notarizationBlockModulo,
                                                             int64_t fromHeight,
                                                             int64_t untilHeight,
                                                             int64_t notarizationsBeforeModuloExtension,
                                                             int64_t notarizationCount)
{
    auto resetIt = ConnectedChains.activeUpgradesByKey.find(ConnectedChains.ResetNotarizationModuloKey());
    int64_t heightChange = std::max((int64_t)0,
                            untilHeight -
                                std::max(resetIt == ConnectedChains.activeUpgradesByKey.end() ? (int64_t)0 : resetIt->second.upgradeBlockHeight, fromHeight));

    if (heightChange <= GetBlocksBeforeModuloExtension(notarizationBlockModulo) && notarizationCount <= notarizationsBeforeModuloExtension)
    {
        return notarizationBlockModulo;
    }
    int32_t nextCheckModulo = notarizationBlockModulo * MODULO_EXTENSION_MULTIPLIER;
    int32_t nextCheckNotarizationBeforeModulo = notarizationsBeforeModuloExtension << 1;
    return GetAdjustedNotarizationModuloExp(nextCheckModulo, fromHeight, untilHeight, nextCheckNotarizationBeforeModulo, notarizationCount);
}

std::vector<unsigned char> CreatePoSBlockProof(ChainMerkleMountainView &mmrView,
                                               const CBlock &checkBlock,
                                               const CTransaction &stakeSource,
                                               int outNum,
                                               uint32_t sourceBlockNum,
                                               uint32_t height)
{
    std::vector<unsigned char> emptyVec;

    // we get these sources of entropy to prove all sources in the header
    int posHeight = -1, powHeight = -1, altHeight = -1, pastBlockHeight1, pastBlockHeight2;
    uint256 pastHash;
    {
        LOCK(cs_main);
        pastHash = chainActive.GetVerusEntropyHash(height, &posHeight, &powHeight, &altHeight, &pastBlockHeight1, &pastBlockHeight2);
        if (altHeight == -1 && (powHeight == -1 || posHeight == -1))
        {
            printf("Error retrieving entropy hash at height %d, posHeight: %d, powHeight: %d, altHeight: %d\n", height, posHeight, powHeight, altHeight);
            LogPrintf("Error retrieving entropy hash at height %d, posHeight: %d, powHeight: %d, altHeight: %d\n", height, posHeight, powHeight, altHeight);
            return emptyVec;
        }
    }

    // get map and MMR for stake source transaction
    CTransactionMap txMap(stakeSource);
    TransactionMMView txView(txMap.transactionMMR);
    uint256 txRoot = txView.GetRoot();

    std::vector<CTransactionComponentProof> txProofVec;
    txProofVec.push_back(CTransactionComponentProof(txView, txMap, stakeSource, CTransactionHeader::TX_HEADER, 0));
    txProofVec.push_back(CTransactionComponentProof(txView, txMap, stakeSource, CTransactionHeader::TX_OUTPUT, outNum));

    // now, both the header and stake output are dependent on the transaction MMR root being provable up
    // through the block MMR, and since we don't cache the new MMR proof for transactions yet, we need the block to create the proof.
    // when we switch to the new MMR in place of a merkle tree, we can keep that in the wallet as well
    CBlock block;
    if (!ReadBlockFromDisk(block, chainActive[sourceBlockNum], Params().GetConsensus(), false))
    {
        LogPrintf("%s: ERROR: could not read block number  %u from disk\n", __func__, sourceBlockNum);
        return emptyVec;
    }

    bool isPBaaS = CConstVerusSolutionVector::GetVersionByHeight(height) >= CActivationHeight::ACTIVATE_PBAAS;

    bool posSourceInfo = isPBaaS;

    BlockMMRange blockMMR(block.GetBlockMMRTree(posSourceInfo ? block.GetVerusEntropyHashComponent(sourceBlockNum) : uint256()));
    BlockMMView blockView(blockMMR);

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
        LogPrintf("%s: ERROR: could not find source transaction root in block %u\n", __func__, sourceBlockNum);
        return emptyVec;
    }

    // prove the tx up to the MMR root, which also contains the block hash
    CMMRProof txRootProof;
    if (!blockView.GetProof(txRootProof, txIndexPos))
    {
        LogPrintf("%s: ERROR: could not create proof of source transaction in block %u\n", __func__, sourceBlockNum);
        return emptyVec;
    }

    CDataStream headerStream = CDataStream(SER_NETWORK, PROTOCOL_VERSION);

    if (mmrView.mmr.size() < height - 1)
    {
        LogPrintf("%s: ERROR: Invalid height %u\n", __func__, height);
        return emptyVec;
    }

    mmrView.resize(pastBlockHeight1 + 1);
    chainActive.GetMerkleProof(mmrView, txRootProof, sourceBlockNum);

    headerStream << CPartialTransactionProof(txRootProof, txProofVec);

    if (posSourceInfo)
    {
        CBlock entropyBlock1;
        if (!ReadBlockFromDisk(entropyBlock1, chainActive[pastBlockHeight1], Params().GetConsensus(), false))
        {
            LogPrintf("%s: ERROR: could not read block number %u from disk for entropy component 1\n", __func__, pastBlockHeight1);
            return emptyVec;
        }
        headerStream << chainActive.GetPreHeaderProof(entropyBlock1, pastBlockHeight1, pastBlockHeight1);
    }
    else
    {
        CMMRProof blockHeaderProof1;
        if (!chainActive.GetBlockProof(mmrView, blockHeaderProof1, pastBlockHeight1))
        {
            LogPrintf("%s: ERROR: could not create block proof for block %u\n", __func__, sourceBlockNum);
            return emptyVec;
        }
        headerStream << CBlockHeaderProof(blockHeaderProof1, chainActive[pastBlockHeight1]->GetBlockHeader());
    }

    if (posSourceInfo)
    {
        CBlock entropyBlock2;
        if (!ReadBlockFromDisk(entropyBlock2, chainActive[pastBlockHeight2], Params().GetConsensus(), false))
        {
            LogPrintf("%s: ERROR: could not read block number %u from disk for entropy component 1\n", __func__, pastBlockHeight2);
            return emptyVec;
        }
        headerStream << chainActive.GetPreHeaderProof(entropyBlock2, pastBlockHeight2, pastBlockHeight1);
    }
    else
    {
        CMMRProof blockHeaderProof2;
        if (!chainActive.GetBlockProof(mmrView, blockHeaderProof2, pastBlockHeight2))
        {
            LogPrintf("%s: ERROR: could not create block proof for second entropy source block %u\n", __func__, sourceBlockNum);
            chainActive.GetBlockProof(mmrView, blockHeaderProof2, pastBlockHeight2); // repeat for debugging
            return emptyVec;
        }
        headerStream << CBlockHeaderProof(blockHeaderProof2, chainActive[pastBlockHeight2]->GetBlockHeader());
    }
    return std::vector<unsigned char>(headerStream.begin(), headerStream.end());
}

CPBaaSNotarization IsValidPrimaryChainEvidence(const CCurrencyDefinition &externalSystem,
                                               const CNotaryEvidence &evidence,
                                               const CPBaaSNotarization &expectedNotarization,
                                               uint32_t lastConfirmedHeight,
                                               uint32_t height,
                                               uint256 *pEntropyHash,
                                               const CProofRoot &_challengeProofRoot)
{
    std::set<int> evidenceTypes;

    CProofRoot challengeProofRoot(_challengeProofRoot);

    uint160 externalSystemID = externalSystem.GetID();
    bool validateEarned = ConnectedChains.NotarySystems().count(externalSystemID);

    // if this is the first proof, it will extend a prelaunch finalization,
    // which should always pass
    if (expectedNotarization.IsPreLaunch() &&
        expectedNotarization.proofRoots.count(ASSETCHAINS_CHAINID) &&
        expectedNotarization.currencyState.IsPrelaunch())
    {
        return expectedNotarization;
    }

    if (challengeProofRoot.IsValid() && !(expectedNotarization.proofRoots.count(challengeProofRoot.systemID)))
    {
        return CPBaaSNotarization();
    }

    uint256 _entropyHash;
    uint256 &entropyHash = (pEntropyHash ? *pEntropyHash : _entropyHash);

    // one for the proof of the newly witnessed, confirmed notarization
    // one proof root for the entropy from the other chain if this verifies prior commitments
    evidenceTypes.insert(CHAINOBJ_CROSSCHAINPROOF);

    // one for the proof of the newly witnessed, confirmed notarization
    // one proof root for the entropy from the other chain if this verifies prior commitments
    evidenceTypes.insert(CHAINOBJ_PROOF_ROOT);

    // proof of the last confirmed notarization matching the one on this chain or block 1 coinbase
    // by the newly confirmed notarization
    // proof of the current notarization by the first proof root mentioned above
    evidenceTypes.insert(CHAINOBJ_TRANSACTION_PROOF);

    // commitment of last block time, bits, pos diff, and pos/pow
    evidenceTypes.insert(CHAINOBJ_COMMITMENTDATA);

    // random header proof of one or more of last notarization's commitment, proven by the last notarization
    evidenceTypes.insert(CHAINOBJ_HEADER);

    // currently unused
    evidenceTypes.insert(CHAINOBJ_HEADER_REF);
    CCrossChainProof autoProof(evidence.GetSelectEvidence(evidenceTypes));

    auto notaRootIT = expectedNotarization.proofRoots.find(ASSETCHAINS_CHAINID);

    enum EProofState {
        EXPECT_NOTHING = 0,
        EXPECT_LASTNOTARIZATION_PROOF = 1,      // transaction proof of block 1 coinbase or last confirmed on this chain
        EXPECT_FUTURE_PROOF_ROOT = 2,           // future root to prove this notarization
        EXPECT_THISNOTARIZATION_PROOF = 3,      // proof of this notarization
        EXPECT_FINALIZATION_PROOF = 4,          // if this is an accepted notarization, proof of this notarization's finalization transaction
        EXPECT_CHECKPOINT = 5,                  // checkpoints between large spans of notarizations to narrow challenges
        EXPECT_COMMITMENT_PROOF = 6,            // commitments of prior blocks from this notarization (only needed if there is a challenge proof root)
        EXPECT_HEADER_PROOFS = 7,               // header proofs randomly selected from prior commitments, based on entropy
        EXPECT_PROOF_HEADER_REF = 8,            // a header ref with numbers, like prevHashMMR used for subsequent proofs
        EXPECT_STAKE_TX = 9,                    // stake transaction in block for stake headers
        EXPECT_ID_PROOF_OR_STAKEGUARD = 10,     // necessary ID proof(s) to be able to confirm signature & end with coinbase stakeguard output
    };

    EProofState proofState = EXPECT_LASTNOTARIZATION_PROOF;

    CProofRoot futureProofRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);
    CUTXORef thisNotarizationOutput;
    CPBaaSNotarization provenNotarization = expectedNotarization;
    if (!provenNotarization.proofRoots.count(provenNotarization.currencyID) ||
        !provenNotarization.proofRoots.count(ASSETCHAINS_CHAINID))
    {
        return CPBaaSNotarization();
    }

    CTransaction lastNotarizationTx;
    uint256 lastNotarizationBlockHash;
    CPBaaSNotarization lastNotarization;
    CPBaaSNotarization lastLocalNotarization;
    CAddressIndexDbEntry lastNotarizationAddressEntry;
    uint256 commitmentHash;
    uint256 priorCommitmentHash;
    std::map<uint32_t, __uint128_t> priorNotarizationCommitments;
    std::vector<std::pair<uint32_t, uint32_t>> commitmentRanges;

    std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization> priorReferencedNotarization;

    int startingHeight = 0;
    int rangeLen = 0;
    int numHeaders = 0;
    int numExpectedCheckpoints = 0;
    int numCheckpointsFound = 0;
    int blocksPerCheckpoint = 0;
    std::vector<CProofRoot> checkpointRoots;

    int numHeaderProofs = 0;
    int headerProofsSize = 0;
    uint256 blockTypes;

    bool validChallengeEvidence = false;
    bool validBasicEvidence = false;

    uint256 headerSelectionHash;

    CBlockHeaderAndProof posBlockHeaderAndProof;
    bool posNewFormat;
    uint256 posPrevMMRRoot;
    CPBaaSPreHeader proofPreHeader;
    CPartialTransactionProof posSourceProof;
    CTransaction lastStakeTx, lastSourceTx;
    uint32_t provingBlockHeight;
    CStakeParams stakeParams;
    std::vector<CBlockHeaderProof> posEntropyHeaders;
    std::vector<CPartialTransactionProof> posEntropyHeadersAsTxes;
    CPBaaSPreHeader preHeader1, preHeader2;

    std::vector<CIdentity> stakeSpendingIDs;
    CCurrencyDefinition externalCurrency;
    int crossChainProofCount = 0;

    for (auto &proofComponent : autoProof.chainObjects)
    {
        switch (proofState)
        {
            case EXPECT_LASTNOTARIZATION_PROOF:
            {
                switch (proofComponent->objectType)
                {
                    case CHAINOBJ_CROSSCHAINPROOF:
                    {
                        // check for challenge roots
                        CCrossChainProof ccProof = ((CChainObject<CCrossChainProof> *)proofComponent)->object;
                        if (crossChainProofCount++ < 2 &&
                            ccProof.chainObjects.size() &&
                            ccProof.chainObjects[0]->objectType == CHAINOBJ_EVIDENCEDATA &&
                            ((CChainObject<CEvidenceData> *)ccProof.chainObjects[0])->object.type == CEvidenceData::TYPE_DATA)
                        {
                            if (ccProof.chainObjects.size() > 2 &&
                                ((CChainObject<CEvidenceData> *)ccProof.chainObjects[0])->object.vdxfd == CNotaryEvidence::PrimaryProofKey() &&
                                ccProof.chainObjects[1]->objectType == CHAINOBJ_PROOF_ROOT &&
                                ((CChainObject<CProofRoot> *)ccProof.chainObjects[1])->object != provenNotarization.proofRoots[provenNotarization.currencyID])
                            {
                                challengeProofRoot = ((CChainObject<CProofRoot> *)ccProof.chainObjects[1])->object;
                                continue;
                            }
                            else if (crossChainProofCount < 2 && // must be first, added on final confirmation
                                    ((CChainObject<CEvidenceData> *)ccProof.chainObjects[0])->object.vdxfd == CNotaryEvidence::NotarizationTipKey())
                            {
                                CPrimaryProofDescriptor tipOutputDescr(((CChainObject<CEvidenceData> *)ccProof.chainObjects[0])->object.dataVec);
                                // this should be the notarization at the tip of our chain, which should have no primary proof challenge
                                CTransaction tipTx;
                                uint256 tipBlockHash;
                                BlockMap::iterator tipBlockIt;
                                CPBaaSNotarization tipNotarization;
                                if (tipOutputDescr.challengeOutputs.size() &&
                                    tipOutputDescr.challengeOutputs[0].GetOutputTransaction(tipTx, tipBlockHash) &&
                                    !tipBlockHash.IsNull() &&
                                    (tipBlockIt = mapBlockIndex.find(tipBlockHash)) != mapBlockIndex.end() &&
                                    chainActive.Contains(tipBlockIt->second) &&
                                    tipTx.vout.size() > tipOutputDescr.challengeOutputs[0].n &&
                                    (tipNotarization = CPBaaSNotarization(tipTx.vout[tipOutputDescr.challengeOutputs[0].n].scriptPubKey)).IsValid())
                                {
                                    continue;
                                }
                            }
                        }
                        proofState = EXPECT_NOTHING;
                        continue;
                    }
                    case CHAINOBJ_TRANSACTION_PROOF:
                    {
                        CTransaction outTx;
                        bool isPartial = false;
                        uint256 txMMRRoot = ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.CheckPartialTransaction(outTx, &isPartial);
                        uint256 txHash = ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.TransactionHash();
                        uint256 rootPower = ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetRootPower();

                        if (LogAcceptCategory("notarization"))
                        {
                            LogPrint("notarization", "Last notarization proof expected\n");

                            UniValue jsonTx(UniValue::VOBJ);
                            uint256 blockHash;
                            TxToUniv(outTx, blockHash, jsonTx);
                            printf("%s: proof for transaction %s\nwith txid: %s\nproof: %s\nat height: %u, proofheight: %u, rootpower: %s\n",
                                    __func__,
                                    jsonTx.write(1,2).c_str(),
                                    txHash.GetHex().c_str(),
                                    ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.ToUniValue().write(1,2).c_str(),
                                    ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight(),
                                    ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetProofHeight(),
                                    rootPower.GetHex().c_str());
                            LogPrintf("%s: proof for transaction %s\nwith txid: %s\nproof: %s\nat height: %u, proofheight: %u, rootpower: %s\n",
                                    __func__,
                                    jsonTx.write(1,2).c_str(),
                                    txHash.GetHex().c_str(),
                                    ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.ToUniValue().write(1,2).c_str(),
                                    ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight(),
                                    ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetProofHeight(),
                                    rootPower.GetHex().c_str());
                        }

                        // find the last notarization on the transaction. if we need more proof to address a challenge, we will need to retain this
                        // either the notarization is the block 1 coinbase proof, or it is a proof of a transaction on the other chain that corresponds
                        // to a confirmed or pending transaction on this chain.
                        CProofRoot &checkRoot = provenNotarization.proofRoots[provenNotarization.currencyID];
                        if (txMMRRoot == checkRoot.stateRoot &&
                            rootPower == checkRoot.compactPower)
                        {
                            for (auto &oneOut : outTx.vout)
                            {
                                COptCCParams lastNotaP;
                                if (oneOut.nValue >= 0 &&
                                    oneOut.scriptPubKey.size() &&
                                    oneOut.scriptPubKey.IsPayToCryptoCondition(lastNotaP) &&
                                    lastNotaP.IsValid() &&
                                    (lastNotaP.evalCode == EVAL_ACCEPTEDNOTARIZATION || lastNotaP.evalCode == EVAL_EARNEDNOTARIZATION) &&
                                    lastNotaP.vData.size() &&
                                    (lastNotarization = CPBaaSNotarization(lastNotaP.vData[0])).IsValid() &&
                                    (lastNotarization.IsPreLaunch() ||
                                     lastNotarization.IsBlockOneNotarization() ||
                                     lastNotarization.SetMirror(expectedNotarization.IsMirror())) &&
                                    lastNotarization.currencyID == expectedNotarization.currencyID)
                                {
                                    uint32_t checkHeight = provenNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight;

                                    if (checkHeight <= chainActive.Height() &&
                                        (lastNotarization.IsBlockOneNotarization() ||
                                         (checkHeight - lastNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight) >=
                                                CPBaaSNotarization::GetAdjustedNotarizationModulo(ConnectedChains.ThisChain().blockNotarizationModulo,
                                                                                                    lastConfirmedHeight,
                                                                                                    height)))
                                    {
                                        break;
                                    }
                                }
                                lastNotarization = CPBaaSNotarization();
                            }

                            if (lastNotarization.IsValid())
                            {
                                // if any of this is not true, the notarization evidence is not valid
                                uint32_t checkHeight = provenNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight;
                                if (lastNotarization.proofRoots.count(lastNotarization.currencyID) &&
                                    lastNotarization.proofRoots.count(ASSETCHAINS_CHAINID) &&
                                    checkHeight <= chainActive.Height() &&
                                    (lastNotarization.IsBlockOneNotarization() ||
                                     ((provenNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight -
                                            lastNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight) >=
                                                    CPBaaSNotarization::GetAdjustedNotarizationModulo(ConnectedChains.ThisChain().blockNotarizationModulo,
                                                                                                      lastConfirmedHeight,
                                                                                                      height))))
                                {
                                    // evidence from the last notarization, unless it is prelaunch, includes
                                    // proof of a prior notarization that is also on this chain
                                    // it also either includes commitments to pull from when proving headers, or a hash of
                                    // full prior commitments.
                                    // if the proven notarization is block 1, confirm that it is the full coinbase proof.
                                    // if it is not block one, and we find no match in confirmed or pending
                                    // notarizations, we must fail
                                    if (lastNotarization.IsBlockOneNotarization())
                                    {
                                        // the prior confirmed notarization on our chain must be prelaunch when this was made,
                                        // and we should be able to find it with a search before the root height of the last
                                        // proof root for our chain and up to the height of the block 1 notarization proof root.
                                        if (!(lastLocalNotarization.GetLastNotarization(provenNotarization.currencyID,
                                                                                        0,
                                                                                        lastNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight,
                                                                                        &lastNotarizationAddressEntry) &&
                                              lastLocalNotarization.IsPreLaunch()))
                                        {
                                            lastNotarization = CPBaaSNotarization();
                                        }
                                        else
                                        {
                                            // final check is to be sure that the entire
                                            // coinbase output is valid
                                            bool IsValidBlockOneCoinbase(const std::vector<CTxOut> &outputs,
                                                                        const CRPCChainData &launchChain,
                                                                        const CCurrencyDefinition &newChainCurrency,
                                                                        CValidationState &state);
                                            CValidationState state;

                                            bool isNewChainvARRR = externalSystemID == GetDestinationID(DecodeDestination("iExBJfZYK7KREDpuhj6PzZBzqMAKaFg7d2"));
                                            if (isNewChainvARRR)
                                            {
                                                if (txHash != uint256S("9986facba28a68bc7d06095b536873f2cd31b0a45b574fa73a994b7a89cba1da") ||
                                                    !ConnectedChains.vARRRUpdateEnabled(height))
                                                {
                                                    lastNotarization = CPBaaSNotarization();
                                                }
                                            }
                                            else if (!IsValidBlockOneCoinbase(outTx.vout,
                                                                              CRPCChainData(ConnectedChains.ThisChain(), "", ConnectedChains.GetThisChainPort(), ""),
                                                                              externalSystem,
                                                                              state))
                                            {
                                                lastNotarization = CPBaaSNotarization();
                                            }
                                        }
                                    }
                                    else
                                    {
                                        std::vector<CObjectFinalization> lastOfs;
                                        std::vector<CAddressIndexDbEntry> lastNotarizationIndexes;
                                        lastLocalNotarization = lastNotarization;

                                        if (!lastLocalNotarization.FindEarnedNotarizations(lastOfs, &lastNotarizationIndexes) ||
                                            !lastNotarizationIndexes.size())
                                        {
                                            lastLocalNotarization = lastNotarization = CPBaaSNotarization();
                                        }
                                        else if (lastNotarizationIndexes.size() > 1)
                                        {
                                            std::set<int> evidenceCheckTypes;

                                            // we need to select between multiple priors, and to do that, we
                                            // see if there is commitment/challenge evidence that matches one by checking if the
                                            // commitments match the respective entropyhash
                                            evidenceCheckTypes.insert(CHAINOBJ_COMMITMENTDATA);
                                            CCrossChainProof commitmentProof(evidence.GetSelectEvidence(evidenceCheckTypes));

                                            evidenceCheckTypes.clear();
                                            evidenceCheckTypes.insert(CHAINOBJ_PROOF_ROOT);
                                            CCrossChainProof rootProof(evidence.GetSelectEvidence(evidenceCheckTypes));

                                            if (commitmentProof.chainObjects.size() &&
                                                rootProof.chainObjects.size())
                                            {
                                                futureProofRoot = ((CChainObject<CProofRoot> *)rootProof.chainObjects[0])->object;
                                                CTransaction notarizationTx;
                                                uint256 nBlkHash;
                                                // make sure the one we find has a matching proof
                                                for (auto &oneIndex : lastNotarizationIndexes)
                                                {
                                                    if (!myGetTransaction(oneIndex.first.txhash, notarizationTx, nBlkHash))
                                                    {
                                                        LogPrint("notarization", "Error retrieving notarization transaction\n");
                                                        continue;
                                                    }
                                                    std::vector<__uint128_t> checkCommitments;
                                                    uint256 blockTypes = ((CChainObject<CHashCommitments> *)commitmentProof.chainObjects[0])->object.GetSmallCommitments(checkCommitments);
                                                    if (lastLocalNotarization.CheckEntropyHashMatch(nBlkHash,
                                                                                                    checkCommitments,
                                                                                                    lastLocalNotarization.currencyID,
                                                                                                    (lastLocalNotarization.proofRoots.count(lastLocalNotarization.currencyID) ?
                                                                                                        lastLocalNotarization.proofRoots[lastLocalNotarization.currencyID].rootHeight :
                                                                                                        1),
                                                                                                    futureProofRoot.rootHeight))
                                                    {
                                                        lastNotarizationAddressEntry = oneIndex;
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                int i;
                                                for (i = 0; i < lastOfs.size(); i++)
                                                {
                                                    if (lastOfs[i].IsValid())
                                                    {
                                                        lastNotarizationAddressEntry = lastNotarizationIndexes[i];
                                                        break;
                                                    }
                                                }
                                                if (i >= lastOfs.size())
                                                {
                                                    lastNotarizationAddressEntry = lastNotarizationIndexes.back();
                                                }
                                            }
                                        }
                                        else
                                        {
                                            lastNotarizationAddressEntry = lastNotarizationIndexes.back();
                                        }

                                        if (!lastNotarizationIndexes.size())
                                        {
                                            lastLocalNotarization = lastNotarization = CPBaaSNotarization();
                                        }
                                        else
                                        {
                                            headerSelectionHash = entropyHash = chainActive[lastNotarizationAddressEntry.first.blockHeight]->GetBlockHash();
                                        }
                                    }
                                }
                                else
                                {
                                    lastNotarization = CPBaaSNotarization();
                                }
                            }
                        }
                        else if (LogAcceptCategory("notarization"))
                        {
                            printf("expected state root: %s, from proof at height %u\ntxid: %s\nproven notarization: %s\n",
                                    txMMRRoot.GetHex().c_str(),
                                    ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetProofHeight(),
                                    txHash.GetHex().c_str(),
                                    provenNotarization.ToUniValue().write(1,2).c_str());
                            LogPrintf("expected state root: %s, from proof at height %u\ntxid: %s\nproven notarization: %s\n",
                                    txMMRRoot.GetHex().c_str(),
                                    ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetProofHeight(),
                                    txHash.GetHex().c_str(),
                                    provenNotarization.ToUniValue().write(1,2).c_str());
                        }
                        proofState = lastNotarization.IsValid() ? EXPECT_FUTURE_PROOF_ROOT : EXPECT_NOTHING;
                        if (proofState == EXPECT_FUTURE_PROOF_ROOT &&
                            myGetTransaction(lastNotarizationAddressEntry.first.txhash, lastNotarizationTx, lastNotarizationBlockHash) &&
                            !lastNotarization.IsBlockOneNotarization() &&
                            !lastNotarization.IsPreLaunch())
                        {
                            // this will prove our last notarization's proof root for the alternate chain as a header reference
                            // to confirm it, we need to get the last notarization and compare
                            // std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization>
                            priorReferencedNotarization = GetPriorReferencedNotarization(lastNotarizationTx,
                                                                                         lastNotarizationAddressEntry.first.index,
                                                                                         lastNotarization);
                            if (!std::get<0>(priorReferencedNotarization))
                            {
                                lastNotarization = CPBaaSNotarization();
                                proofState = EXPECT_NOTHING;
                            }
                        }
                        break;
                    }
                    case CHAINOBJ_HEADER:
                    {
                        CBlockHeader &bh = ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.blockHeader;
                        if (expectedNotarization.prevNotarization.GetOutputTransaction(lastNotarizationTx, lastNotarizationBlockHash) &&
                            mapBlockIndex.count(lastNotarizationBlockHash) &&
                            lastNotarizationTx.vout.size() > expectedNotarization.prevNotarization.n &&
                            (lastNotarization = lastLocalNotarization =
                                CPBaaSNotarization(lastNotarizationTx.vout[expectedNotarization.prevNotarization.n].scriptPubKey)).IsValid() &&
                            lastNotarization.proofRoots[lastNotarization.currencyID].rootHeight ==
                                ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.GetBlockHeight() &&
                            ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.GetBlockPower() ==
                                ArithToUint256(GetCompactPower(bh.nNonce, bh.nBits, bh.nVersion)) &&
                            ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.ValidateBlockHash(
                                    lastNotarization.proofRoots[lastNotarization.currencyID].blockHash,
                                    ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.GetBlockHeight()) ==
                                        provenNotarization.proofRoots[provenNotarization.currencyID].stateRoot)
                        {
                            // this will prove our last notarization's proof root for the alternate chain as a header reference
                            // to confirm it, we need to get the last notarization and compare
                            // std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization>
                            priorReferencedNotarization = lastNotarization.IsBlockOneNotarization() ?
                                                          std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization>(
                                                            {(uint32_t)0, CTransaction(), CUTXORef(), CPBaaSNotarization()}) :
                                                          GetPriorReferencedNotarization(lastNotarizationTx,
                                                                                         expectedNotarization.prevNotarization.n,
                                                                                         lastNotarization);
                            if (lastNotarization.IsBlockOneNotarization() || std::get<0>(priorReferencedNotarization))
                            {
                                proofState = EXPECT_FUTURE_PROOF_ROOT;
                                break;
                            }
                            else
                            {
                                lastNotarization = CPBaaSNotarization();
                                proofState = EXPECT_NOTHING;
                            }
                        }
                        else
                        {
                            if (LogAcceptCategory("notarization"))
                            {
                                CBlockHeader &bh = ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.blockHeader;
                                printf("%s: lastNotarization: %s, txHeight: %u, proofHeight: %u\nblockpower: %s, proofpower: %s\n",
                                       __func__,
                                       lastNotarization.ToUniValue().write(1,2).c_str(),
                                       mapBlockIndex.count(lastNotarizationBlockHash) ?
                                            mapBlockIndex[lastNotarizationBlockHash]->GetHeight() :
                                            UINT32_MAX,
                                       ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.GetBlockHeight(),
                                       GetCompactPower(bh.nNonce, bh.nBits, bh.nVersion).GetHex().c_str(),
                                       ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.GetBlockPower().GetHex().c_str());
                            }
                            proofState = EXPECT_NOTHING;
                        }
                    }
                    default:
                    {
                        proofState = EXPECT_NOTHING;
                    }
                }
                break;
            }

            case EXPECT_FUTURE_PROOF_ROOT:
            {
                if (proofComponent->objectType == CHAINOBJ_PROOF_ROOT)
                {
                    futureProofRoot = ((CChainObject<CProofRoot> *)proofComponent)->object;
                    if (futureProofRoot.systemID == expectedNotarization.currencyID)
                    {
                        proofState = EXPECT_THISNOTARIZATION_PROOF;
                    }
                    else
                    {
                        proofState = EXPECT_NOTHING;
                    }
                }
                else
                {
                    proofState = EXPECT_NOTHING;
                }
                break;
            }

            case EXPECT_THISNOTARIZATION_PROOF:
            {
                if (proofComponent->objectType == CHAINOBJ_TRANSACTION_PROOF)
                {
                    CTransaction outTx;
                    bool isPartial = false;
                    uint256 txMMRRoot = ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.CheckPartialTransaction(outTx, &isPartial);
                    thisNotarizationOutput.hash = ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.TransactionHash();

                    // loop through and check all the valid outputs to find a match
                    if (!provenNotarization.SetMirror(false) ||
                        txMMRRoot != futureProofRoot.stateRoot)
                    {
                        if (LogAcceptCategory("notarization"))
                        {
                            printf("%s: invalid notarization transaction proof, from height %u, proven at height %u\n", __func__, ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight(), ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetProofHeight());
                            LogPrintf("%s: invalid notarization transaction proof, from height %u, proven at height %u\n", __func__, ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight(), ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetProofHeight());
                        }
                        proofState = EXPECT_NOTHING;
                    }
                    else
                    {
                        for (int outNum = 0; outNum < outTx.vout.size(); outNum++)
                        {
                            auto &oneOut = outTx.vout[outNum];
                            COptCCParams notaP;
                            CPBaaSNotarization checkNotarization;
                            if (oneOut.nValue >= 0 &&
                                oneOut.scriptPubKey.IsPayToCryptoCondition(notaP) &&
                                (notaP.evalCode == EVAL_EARNEDNOTARIZATION || notaP.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
                                notaP.vData.size() &&
                                ::AsVector(CPBaaSNotarization(notaP.vData[0])) == ::AsVector(provenNotarization))
                            {
                                // expect more than nothing
                                thisNotarizationOutput.n = outNum;
                                proofState = EXPECT_CHECKPOINT;
                                break;
                            }
                            else if (LogAcceptCategory("notarization") &&
                                     (notaP.evalCode == EVAL_EARNEDNOTARIZATION || notaP.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
                                     notaP.vData.size() &&
                                     ::AsVector(CPBaaSNotarization(notaP.vData[0])) != ::AsVector(provenNotarization))
                            {
                                printf("%s: Notarization mismatch\nexpected: %s\nactual: %s\n",
                                    __func__,
                                    CPBaaSNotarization(notaP.vData[0]).ToUniValue().write(1,2).c_str(),
                                    provenNotarization.ToUniValue().write(1,2).c_str());
                                LogPrintf("%s: Notarization mismatch\nexpected: %s\nactual: %s\n",
                                            __func__,
                                            CPBaaSNotarization(notaP.vData[0]).ToUniValue().write(1,2).c_str(),
                                            provenNotarization.ToUniValue().write(1,2).c_str());
                            }
                        }
                    }

                    if (LogAcceptCategory("notarization"))
                    {
                        LogPrint("notarization", "This notarization proof expected\n");

                        UniValue jsonTx(UniValue::VOBJ);
                        uint256 blockHash;
                        TxToUniv(outTx, blockHash, jsonTx);
                        printf("%s: proof for transaction %s\nwith txid: %s\nproof: %s\nat height: %u\n",
                                __func__,
                                jsonTx.write(1,2).c_str(),
                                thisNotarizationOutput.hash.GetHex().c_str(),
                                ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.ToUniValue().write(1,2).c_str(),
                                ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight());
                        LogPrint("verbose", "%s: proof for transaction %s\nwith txid: %s\nproof: %s\nat height: %u\n",
                                __func__,
                                jsonTx.write(1,2).c_str(),
                                thisNotarizationOutput.hash.GetHex().c_str(),
                                ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.ToUniValue().write(1,2).c_str(),
                                ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight());
                    }
                }
                else if (proofComponent->objectType == CHAINOBJ_HEADER)
                {
                    CBlockHeader &bh = ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.blockHeader;
                    if (provenNotarization.proofRoots[provenNotarization.currencyID].rootHeight ==
                            ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.GetBlockHeight() &&
                        ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.GetBlockPower() ==
                            ArithToUint256(GetCompactPower(bh.nNonce, bh.nBits, bh.nVersion)) &&
                        ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.ValidateBlockHash(
                                provenNotarization.proofRoots[provenNotarization.currencyID].blockHash,
                                ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.GetBlockHeight()) ==
                                    futureProofRoot.stateRoot)
                    {
                        proofState = EXPECT_CHECKPOINT;
                    }
                    else
                    {
                        proofState = EXPECT_NOTHING;
                    }
                }
                else
                {
                    proofState = EXPECT_NOTHING;
                }
                if (proofState != EXPECT_NOTHING)
                {
                    if (validateEarned)
                    {
                        // if we are spanning more than the min blocks per checkpoint, expect checkpoint(s)
                        int heightChange = futureProofRoot.rootHeight -
                                            lastNotarization.proofRoots[lastNotarization.currencyID].rootHeight;
                        numExpectedCheckpoints = CPBaaSNotarization::GetNumCheckpoints(heightChange);
                        blocksPerCheckpoint = CPBaaSNotarization::GetBlocksPerCheckpoint(heightChange);
                        validBasicEvidence = !challengeProofRoot.IsValid();
                        if (validBasicEvidence)
                        {
                            proofState = EXPECT_NOTHING;
                        }
                    }
                    else
                    {
                        validBasicEvidence = lastLocalNotarization.IsValid() || !challengeProofRoot.IsValid();
                        proofState = validateEarned ? (validBasicEvidence ? EXPECT_NOTHING : EXPECT_COMMITMENT_PROOF) : EXPECT_FINALIZATION_PROOF;
                    }
                }
                break;
            }

            case EXPECT_FINALIZATION_PROOF:
            {
                if (proofComponent->objectType == CHAINOBJ_TRANSACTION_PROOF)
                {
                    CTransaction outTx;
                    bool isPartial = false;
                    uint256 txMMRRoot = ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.CheckPartialTransaction(outTx, &isPartial);
                    uint256 txHash = ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.TransactionHash();

                    // loop through and check all the valid outputs to find a match
                    if (txMMRRoot != futureProofRoot.stateRoot ||
                        !((CChainObject<CPartialTransactionProof> *)proofComponent)->object.IsChainProof() ||
                        ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight() != futureProofRoot.rootHeight)
                    {
                        if (LogAcceptCategory("notarization"))
                        {
                            printf("%s: invalid finalization transaction proof, from height %u, proven at height %u\n", __func__, ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight(), ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetProofHeight());
                            LogPrintf("%s: invalid finalization transaction proof, from height %u, proven at height %u\n", __func__, ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight(), ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetProofHeight());
                        }
                        proofState = EXPECT_NOTHING;
                    }
                    else
                    {
                        for (auto &oneOut : outTx.vout)
                        {
                            COptCCParams ofP;
                            CObjectFinalization of;
                            if (oneOut.nValue >= 0 &&
                                oneOut.scriptPubKey.IsPayToCryptoCondition(ofP) &&
                                (ofP.evalCode == EVAL_FINALIZE_NOTARIZATION) &&
                                ofP.vData.size() &&
                                (of = CObjectFinalization(ofP.vData[0])).IsValid() &&
                                of.IsConfirmed() &&
                                of.output == thisNotarizationOutput)
                            {
                                // expect more than nothing
                                proofState = EXPECT_CHECKPOINT;
                                break;
                            }
                        }
                    }

                    if (LogAcceptCategory("notarization"))
                    {
                        LogPrint("notarization", "Proof of the finalization transaction output expected\n");

                        UniValue jsonTx(UniValue::VOBJ);
                        uint256 blockHash;
                        TxToUniv(outTx, blockHash, jsonTx);
                        printf("%s: proof for transaction %s\nwith txid: %s\nproof: %s\nat height: %u\n",
                                __func__,
                                jsonTx.write(1,2).c_str(),
                                txHash.GetHex().c_str(),
                                ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.ToUniValue().write(1,2).c_str(),
                                ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight());
                        LogPrint("verbose", "%s: proof for transaction %s\nwith txid: %s\nproof: %s\nat height: %u\n",
                                __func__,
                                jsonTx.write(1,2).c_str(),
                                txHash.GetHex().c_str(),
                                ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.ToUniValue().write(1,2).c_str(),
                                ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight());
                    }
                }
                else
                {
                    proofState = EXPECT_NOTHING;
                }
                if (proofState != EXPECT_NOTHING)
                {
                    // if we are spanning more than the min blocks per checkpoint, expect checkpoint(s)
                    int heightChange = futureProofRoot.rootHeight -
                                        lastNotarization.proofRoots[lastNotarization.currencyID].rootHeight;
                    numExpectedCheckpoints = CPBaaSNotarization::GetNumCheckpoints(heightChange);
                    if (numExpectedCheckpoints)
                    {
                        blocksPerCheckpoint = CPBaaSNotarization::GetBlocksPerCheckpoint(heightChange);
                        proofState = EXPECT_CHECKPOINT;
                    }
                    else
                    {
                        validBasicEvidence = (lastLocalNotarization.IsValid() && (lastLocalNotarization.IsPreLaunch() || validateEarned)) || !challengeProofRoot.IsValid();
                        proofState = validBasicEvidence ? EXPECT_NOTHING : EXPECT_COMMITMENT_PROOF;
                    }
                }
                break;
            }

            case EXPECT_CHECKPOINT:
            {
                if (proofComponent->objectType == CHAINOBJ_PROOF_ROOT)
                {
                    CProofRoot oneCheckpoint = ((CChainObject<CProofRoot> *)proofComponent)->object;
                    if (blocksPerCheckpoint &&
                        oneCheckpoint.systemID == expectedNotarization.currencyID &&
                        oneCheckpoint.rootHeight ==
                            (lastNotarization.proofRoots[lastNotarization.currencyID].rootHeight +
                             (++numCheckpointsFound * blocksPerCheckpoint)))
                    {
                        checkpointRoots.push_back(oneCheckpoint);
                        if (numCheckpointsFound == numExpectedCheckpoints)
                        {
                            validChallengeEvidence = ConnectedChains.IsPBaaSNotarizationFix01Active(height) && validateEarned && challengeProofRoot.IsValid() && challengeProofRoot.systemID == externalSystemID;
                            validBasicEvidence = (lastLocalNotarization.IsValid() && lastLocalNotarization.IsPreLaunch()) || !challengeProofRoot.IsValid() || validChallengeEvidence;
                            proofState = validBasicEvidence ? EXPECT_NOTHING : EXPECT_COMMITMENT_PROOF;
                        }
                        else
                        {
                            proofState = EXPECT_CHECKPOINT;
                        }
                    }
                    else
                    {
                        proofState = EXPECT_CHECKPOINT;
                    }
                }
                else
                {
                    proofState = EXPECT_NOTHING;
                }
                break;
            }

            case EXPECT_COMMITMENT_PROOF:
            {
                if (proofComponent->objectType == CHAINOBJ_COMMITMENTDATA)
                {
                    std::vector<__uint128_t> checkCommitments;
                    blockTypes = ((CChainObject<CHashCommitments> *)proofComponent)->object.GetSmallCommitments(checkCommitments);

                    // validity proofs are required to cover the span from the notarization before the prior notarization
                    // up to our current notarization
                    // this has two benefits:
                    // *  it ensures that in highly contentious exchanges, all challenged or potentially challenged branches have
                    //    one or two randomized validity proofs to cross-check all proofs (later protocols should handle dedup of
                    //    overlapping proofs)
                    // *  it enables simple rules to ensure arbitrary statistical security levels for the alternate chain
                    //
                    // The basic rules for PBaaS v1 are:
                    // 1) No notarization chain may be confirmed with a challenge since the second to last notarization.
                    // 2) Every notarization must reference the last notarization with which it agrees and may not skip a notarization
                    //    that it agrees with.
                    // 3) A proof that one notarization which skipped another can be proven in the other or vice versa invalidates the
                    //    first such unconfirmed, protocol violating notarizations.
                    // 4) If a notarization is signed in autonotarization currencies, it may confirm a more recent notarization than
                    //    if it is not signed. If a notarization is not signed, it has a longer stable and more powerful chain
                    //    requirement before confirmation. These values are constants defined in CPBaaSNotarization.
                    // 5) Only one earned or accepted notariation for any system ID may be present in a single block.
                    // 6) Any notarization that skips another prior, unconfirmed notarization is implicitly raising a dispute,
                    //    challenging one or more notarizations that it skips, obligating itself and all notarizations that it
                    //    disagrees with to prove their own chains to progress at all. Proofs must span from the later of the proof
                    //    root height of the notarization tx prior to the last or the last confirmed notarization to the base of
                    //    our own.
                    // 7) Proofs must be randomized by the block hash entropy hash of the alternate chain's block, either containing
                    //    the notarization, or the block of the header from the proof root in question.
                    //

                    startingHeight = lastNotarization.proofRoots.count(expectedNotarization.currencyID) ?
                        lastNotarization.proofRoots[expectedNotarization.currencyID].rootHeight :
                        1;

                    int endHeight = futureProofRoot.rootHeight;
                    rangeLen = endHeight - startingHeight;

                    commitmentRanges = CPBaaSNotarization::GetBlockCommitmentRanges(startingHeight, endHeight, entropyHash);

                    if (LogAcceptCategory("notarization"))
                    {
                        LogPrintf("%s: CHECKING COMMITMENTS with entropyHash: %s\n", __func__, entropyHash.GetHex().c_str());

                        std::vector<__uint128_t> checkSmallCommitments;
                        auto checkTypes = ((CChainObject<CHashCommitments> *)proofComponent)->object.GetSmallCommitments(checkSmallCommitments);
                        for (int currentOffset = 0; currentOffset < checkSmallCommitments.size(); currentOffset++)
                        {
                            auto commitmentVec = UnpackBlockCommitment(checkSmallCommitments[currentOffset]);
                            arith_uint256 powTarget, posTarget;
                            powTarget.SetCompact(commitmentVec[1]);
                            posTarget.SetCompact(commitmentVec[2]);
                            LogPrintf("nHeight: %u, nTime: %u, PoW target: %s, PoS target: %s, isPoS: %u\n",
                                        commitmentVec[3] >> 1,
                                        commitmentVec[0],
                                        powTarget.GetHex().c_str(),
                                        posTarget.GetHex().c_str(),
                                        commitmentVec[3] & 1);
                        }
                    }

                    int checkIndex = 0;
                    bool mismatchIndex = false;
                    for (auto &oneRange : commitmentRanges)
                    {
                        for (uint32_t loop = oneRange.first; loop <= oneRange.second; loop++, checkIndex++)
                        {
                            if (loop != ((uint32_t)checkCommitments[checkIndex]) >> 1)
                            {
                                mismatchIndex = true;
                                break;
                            }
                            priorNotarizationCommitments.insert(std::make_pair(loop, checkCommitments[checkIndex]));
                        }
                        if (mismatchIndex)
                        {
                            break;
                        }
                    }

                    if (!mismatchIndex &&
                        priorNotarizationCommitments.size() &&
                        challengeProofRoot.IsValid())
                    {
                        numHeaders = std::min(std::max(rangeLen, (int)CPBaaSNotarization::EXPECT_MIN_HEADER_PROOFS),
                                              std::min((int)CPBaaSNotarization::MAX_HEADER_PROOFS_PER_PROOF, rangeLen / 10));


                        proofState = EXPECT_HEADER_PROOFS;
                    }
                    else
                    {
                        proofState = EXPECT_NOTHING;
                    }
                }
                else
                {
                    proofState = EXPECT_NOTHING;
                }
                break;
            }

            case EXPECT_HEADER_PROOFS:
            {
                if ((proofComponent->objectType == CHAINOBJ_HEADER) &&
                    (numHeaderProofs < numHeaders &&
                     headerProofsSize < CPBaaSNotarization::MAX_HEADER_PROOFS_SIZE))
                {
                    int indexToProve = (UintToArith256(headerSelectionHash).GetLow64() % rangeLen);
                    headerSelectionHash = ::GetHash(headerSelectionHash);

                    // height is kept shifted up one from the PoS/PoW bit
                    uint32_t blockToProve = startingHeight + indexToProve;

                    CBlockHeader &blockHeader = ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.blockHeader;

                    CDataStream ds(SER_DISK, PROTOCOL_VERSION);
                    headerProofsSize += GetSerializeSize(ds, *(CChainObject<CBlockHeaderAndProof> *)proofComponent);

                    std::vector<uint32_t> oneBlockCommitment = priorNotarizationCommitments.count(blockToProve) ?
                        UnpackBlockCommitment(priorNotarizationCommitments[blockToProve]) :
                        std::vector<uint32_t>({blockHeader.nTime,
                                               blockHeader.nBits,
                                               blockHeader.GetVerusPOSTarget(),
                                               blockToProve << 1 | (uint32_t)blockHeader.IsVerusPOSBlock()});

                    if (((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.GetBlockHeight() == blockToProve &&
                        blockHeader.nTime == oneBlockCommitment[0] &&
                        blockHeader.IsVerusPOSBlock() == (oneBlockCommitment[3] & 1) &&
                        ((oneBlockCommitment[3] & 1) ? blockHeader.GetVerusPOSTarget() == oneBlockCommitment[2] : blockHeader.nBits == oneBlockCommitment[1]) &&
                        ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object.ValidateBlockHash(blockHeader.GetHash(), blockToProve) ==
                            futureProofRoot.stateRoot)
                    {
                        if (blockHeader.IsVerusPOSBlock())
                        {
                            posBlockHeaderAndProof = ((CChainObject<CBlockHeaderAndProof> *)proofComponent)->object;
                            posEntropyHeaders.clear();
                            posEntropyHeadersAsTxes.clear();

                            // make sure we have all the expected objects in the header

                            // get proofs of the following from the PoS header, all proven by the MMR of the
                            // block just behind the PoS block:
                            // 1) proof of the source UTXO for the stake
                            // 2) the two header ref proofs from those used PoS entropy
                            //
                            std::vector<unsigned char> streamVch;
                            posBlockHeaderAndProof.blockHeader.GetExtraData(streamVch);
                            CDataStream ds(streamVch, SER_DISK, PROTOCOL_VERSION);

                            try
                            {
                                posNewFormat = ConnectedChains.CrossChainPBaaSProofFix(futureProofRoot.systemID, height);

                                posSourceProof = CPartialTransactionProof();
                                ds >> posSourceProof;
                                if (posSourceProof.IsValid())
                                {
                                    if (posSourceProof.GetPartialTransaction(lastSourceTx).IsNull())
                                    {
                                        proofState = EXPECT_NOTHING;
                                        break;
                                    }
                                    if (posNewFormat)
                                    {
                                        posEntropyHeadersAsTxes.push_back(CPartialTransactionProof());
                                        ds >> posEntropyHeadersAsTxes.back();
                                        if (posEntropyHeadersAsTxes.back().IsValid())
                                        {
                                            posEntropyHeadersAsTxes.push_back(CPartialTransactionProof());
                                            ds >> posEntropyHeadersAsTxes.back();
                                        }
                                        proofState = posEntropyHeadersAsTxes.size() == 2 && posEntropyHeadersAsTxes.back().IsValid() ? EXPECT_PROOF_HEADER_REF : EXPECT_NOTHING;
                                    }
                                    else
                                    {
                                        // and get the two entropy sources
                                        posEntropyHeaders.push_back(CBlockHeaderProof());
                                        ds >> posEntropyHeaders.back();
                                        if (posEntropyHeaders.back().IsValid())
                                        {
                                            posEntropyHeaders.push_back(CBlockHeaderProof());
                                            ds >> posEntropyHeaders.back();
                                        }
                                        proofState = posEntropyHeaders.size() == 2 && posEntropyHeaders.back().IsValid() ? EXPECT_PROOF_HEADER_REF : EXPECT_NOTHING;
                                    }
                                }
                                provingBlockHeight = blockToProve;
                            }
                            catch(const std::exception& e)
                            {
                                std::cerr << e.what() << '\n';
                                proofState = EXPECT_NOTHING;
                            }
                        }
                        else
                        {
                            numHeaderProofs++;
                            proofState = EXPECT_HEADER_PROOFS;
                        }
                    }
                    else
                    {
                        // invalid proofs fail
                        proofState = EXPECT_NOTHING;
                    }
                    validChallengeEvidence = numHeaderProofs >= numHeaders ||
                                             headerProofsSize >= CPBaaSNotarization::MAX_HEADER_PROOFS_SIZE;
                }
                else
                {
                    proofState = EXPECT_NOTHING;
                }
                break;
            }

            case EXPECT_PROOF_HEADER_REF:
            {
                // this should be a header ref proof of the header just in front of the nearest entropy hash header
                posPrevMMRRoot = posBlockHeaderAndProof.blockHeader.GetPrevMMRRoot();
                if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                {
                    LogPrintf("%s: blockHeight: %u, proofHeight: %u, posPrevMMRRoot: %s, CheckBlockPreHeader(proofPreHeader): %s\n",
                        __func__,
                        ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight(),
                        ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetProofHeight(),
                        posPrevMMRRoot.GetHex().c_str(),
                        ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.CheckBlockPreHeader(proofPreHeader).GetHex().c_str());
                    LogPrintf("proofPreHeader: %s\n", proofPreHeader.ToUniValue().write(1,2).c_str());
                }
                if (proofComponent->objectType == CHAINOBJ_TRANSACTION_PROOF &&
                    (posPrevMMRRoot == ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.CheckBlockPreHeader(proofPreHeader)))
                {
                    if (posEntropyHeadersAsTxes.size() == 2)
                    {
                        if ((proofPreHeader.hashPrevMMRRoot != posEntropyHeadersAsTxes[0].CheckBlockPreHeader(preHeader1) ||
                             proofPreHeader.hashPrevMMRRoot != posEntropyHeadersAsTxes[1].CheckBlockPreHeader(preHeader2)))
                        {
                            proofState = EXPECT_NOTHING;
                            break;
                        }
                        else
                        {
                            proofState = EXPECT_STAKE_TX;
                            break;
                        }
                    }
                }
                else
                {
                    proofPreHeader = posEntropyHeaders.size() ? posEntropyHeaders[0].preHeader : CPBaaSPreHeader();
                }
                if (!PBAAS_TESTMODE || !proofPreHeader.IsValid())
                {
                    proofState = EXPECT_NOTHING;
                    break;
                }

                // if we either don't have a valid proof root of this chain in the
                // notarization or we do and it was made before the TESTFORK2_TIME,
                // drop through to see if it is a valid stake tx proof
                if (lastNotarization.proofRoots.count(ASSETCHAINS_CHAINID))
                {
                    uint32_t rootHeight = lastNotarization.proofRoots.find(ASSETCHAINS_CHAINID)->second.rootHeight;
                    proofState = EXPECT_NOTHING;
                    break;
                }
            }

            case EXPECT_STAKE_TX:
            {
                if (proofComponent->objectType == CHAINOBJ_TRANSACTION_PROOF)
                {
                    // this should be a full transaction proof up to the merkle tree root
                    // of the block header of the actual PoS transaction in the block. along with the source output
                    // entropy blocks, and proof contained in the last PoS header, we can confirm both the
                    // validity of the PoS win from that source transaction, as well as the input script signature
                    // ensuring that it is truly a potentially valid proof of stake, assuming we can trust
                    // the blockchain >100 blocks behind us.
                    CTransaction outTx;
                    bool isPartial = false;
                    uint256 txMerkleRoot = ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.CheckPartialTransaction(outTx, &isPartial);

                    std::vector<uint256> entropyHashes;
                    if (posEntropyHeadersAsTxes.size())
                    {
                        if (CPOSNonce(preHeader1.nNonce).IsPOSNonce(posBlockHeaderAndProof.blockHeader.nVersion))
                        {
                            entropyHashes.push_back(preHeader1.hashBlockMMRRoot);
                            entropyHashes.push_back(CPOSNonce(preHeader2.nNonce).IsPOSNonce(posBlockHeaderAndProof.blockHeader.nVersion) ?
                                                        preHeader2.hashBlockMMRRoot :
                                                        posEntropyHeadersAsTxes[1].GetBlockHash());
                        }
                        else if (CPOSNonce(preHeader2.nNonce).IsPOSNonce(posBlockHeaderAndProof.blockHeader.nVersion))
                        {
                            entropyHashes.push_back(preHeader2.hashBlockMMRRoot);
                            entropyHashes.push_back(posEntropyHeadersAsTxes[0].GetBlockHash());
                        }
                        else
                        {
                            entropyHashes.push_back(posEntropyHeadersAsTxes[0].GetBlockHash());
                            entropyHashes.push_back(posEntropyHeadersAsTxes[1].GetBlockHash());
                        }
                    }

                    bool stakeTxPassed = txMerkleRoot == posBlockHeaderAndProof.blockHeader.hashMerkleRoot &&
                                         ValidateStakeTransaction(outTx, stakeParams, false) &&
                                         stakeParams.prevHash == posBlockHeaderAndProof.blockHeader.hashPrevBlock &&
                                         stakeParams.srcHeight == posSourceProof.GetBlockHeight() &&
                                         stakeParams.blkHeight == provingBlockHeight &&
                                         outTx.vin.size();

                    bool stakeHeadersPassed = (!posEntropyHeadersAsTxes.size() ||
                                               CPOSNonce(posBlockHeaderAndProof.blockHeader.nNonce).CheckPOSEntropy(
                                                                CChain::CombineForPastHash(entropyHashes[0], entropyHashes[1]),
                                                                outTx.vin[0].prevout.hash,
                                                                outTx.vin[0].prevout.n,
                                                                posBlockHeaderAndProof.blockHeader.nVersion) ||
                                               CPOSNonce(posBlockHeaderAndProof.blockHeader.nNonce).CheckPOSEntropy(
                                                                CChain::CombineForPastHash(entropyHashes[1], entropyHashes[2]),
                                                                outTx.vin[0].prevout.hash,
                                                                outTx.vin[0].prevout.n,
                                                                posBlockHeaderAndProof.blockHeader.nVersion));

                    if (proofPreHeader.hashPrevMMRRoot != posSourceProof.CheckPartialTransaction(lastSourceTx, &isPartial))
                    {
                        proofState = EXPECT_NOTHING;
                        break;
                    }

                    // Below, after we have gotten the stakeguard output and when we have any ID keys we may need, we can
                    // verify the spend signature.

                    if (stakeTxPassed)
                    {
                        if (stakeHeadersPassed)
                        {
                            if (LogAcceptCategory("notarization") || LogAcceptCategory("stakeheaders"))
                            {
                                LogPrintf("STAKE TX PASSED\nblockheight: %s\n", posEntropyHeadersAsTxes.size() ? std::to_string(posEntropyHeadersAsTxes[0].GetBlockHeight()) : "unknown");
                            }
                        }
                        else
                        {
                            if (LogAcceptCategory("notarization") || LogAcceptCategory("stakeheaders"))
                            {
                                LogPrintf("STAKE TX DID NOT PASS\nblockheight: %u\n", posEntropyHeadersAsTxes[0].GetBlockHeight());
                                LogPrintf("Stake TX validation failure for tx, actual merkle root: %s\nexpected merkle root: %s\nproof header: %s\nstakeParams.srcHeight: %u\nstakeParams.blkHeight: %u\nstakeParams.prevHash: %s\nposSourceProof.GetBlockHeight(): %u\nprovingBlockHeight: %u\nposBlockHeaderAndProof.blockHeader.hashPrevBlock: %s\n",
                                        txMerkleRoot.GetHex().c_str(),
                                        posBlockHeaderAndProof.blockHeader.hashMerkleRoot.GetHex().c_str(),
                                        outTx.GetHash().GetHex().c_str(),
                                        stakeParams.srcHeight,
                                        stakeParams.blkHeight,
                                        stakeParams.prevHash.GetHex().c_str(),
                                        posSourceProof.GetBlockHeight(),
                                        provingBlockHeight,
                                        posBlockHeaderAndProof.blockHeader.hashPrevBlock.GetHex().c_str());
                            }
                            if (!PBAAS_TESTMODE || posBlockHeaderAndProof.blockHeader.nTime > PBAAS_ENFORCE_CORRECT_EVIDENCE_TIME)
                            {
                                proofState = EXPECT_NOTHING;
                                break;
                            }
                        }
                        CDataStream ds(SER_DISK, PROTOCOL_VERSION);
                        headerProofsSize += GetSerializeSize(ds, *(CChainObject<CPartialTransactionProof> *)proofComponent);

                        // now, the proof we just got should be the stake transaction proven against the merkle root of our
                        // header, followed by proofs of any ID outputs that are needed to verify signatures, followed by
                        // the coinbase output proven against the header MMR root.

                        // with the output, the two header refs from the header proof and this stake transaction,
                        // we can now verify the PoS win against the PoS difficulty.
                        if (!externalCurrency.IsValid())
                        {
                            externalCurrency = ConnectedChains.GetCachedCurrency(expectedNotarization.currencyID);
                        }

                        arith_uint256 posTarget;
                        posTarget.SetCompact(posBlockHeaderAndProof.blockHeader.GetVerusPOSTarget());

                        uint256 rawPosHash = CBlockHeader::GetRawVerusPOSHash(
                            posBlockHeaderAndProof.blockHeader.nVersion,
                            CConstVerusSolutionVector::Version(posBlockHeaderAndProof.blockHeader.nSolution),
                            externalCurrency.MagicNumber(),
                            posBlockHeaderAndProof.blockHeader.nNonce,
                            provingBlockHeight,
                            (!PBAAS_TESTMODE && evidence.systemID == VERUS_CHAINID));

                        if (externalCurrency.IsValid() && outTx.vout[0].nValue && (UintToArith256(rawPosHash) / outTx.vout[0].nValue) > posTarget)
                        {
                            if (LogAcceptCategory("notarization"))
                            {
                                UniValue txUniv(UniValue::VOBJ);
                                TxToUniv(outTx, uint256(), txUniv);
                                LogPrintf("%s: Validation failure - stake transaction winner:\n%s\n", __func__, txUniv.write(1,2).c_str());
                                //LogPrintf("Currency:\n%s\n", externalCurrency.ToUniValue().write(1,2).c_str());

                                LogPrintf("Solution version: %u\nPoS target: %s\nMagic number: %d\nNonce: %s\nHeight: %u\n",
                                            CConstVerusSolutionVector::Version(posBlockHeaderAndProof.blockHeader.nSolution),
                                            ArithToUint256(posTarget).GetHex().c_str(),
                                            (int)externalCurrency.MagicNumber(),
                                            posBlockHeaderAndProof.blockHeader.nNonce.GetHex().c_str(),
                                            ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight());
                            }

                            proofState = EXPECT_NOTHING;
                        }
                        else
                        {
                            lastStakeTx = outTx;
                            proofState = EXPECT_ID_PROOF_OR_STAKEGUARD;
                        }
                    }
                    else
                    {
                        LogPrint("notarization", "Stake TX validation failure for tx, actual merkle root: %s\nexpected merkle root: %s\nproof header: %s\nstakeParams.srcHeight: %u\nstakeParams.blkHeight: %u\nstakeParams.prevHash: %s\nposSourceProof.GetBlockHeight(): %u\nprovingBlockHeight: %u\nposBlockHeaderAndProof.blockHeader.hashPrevBlock: %s\n",
                                  txMerkleRoot.GetHex().c_str(),
                                  posBlockHeaderAndProof.blockHeader.hashMerkleRoot.GetHex().c_str(),
                                  outTx.GetHash().GetHex().c_str(),
                                  stakeParams.srcHeight,
                                  stakeParams.blkHeight,
                                  stakeParams.prevHash.GetHex().c_str(),
                                  posSourceProof.GetBlockHeight(),
                                  provingBlockHeight,
                                  posBlockHeaderAndProof.blockHeader.hashPrevBlock.GetHex().c_str());
                        proofState = EXPECT_NOTHING;
                    }
                }
                else
                {
                    proofState = EXPECT_NOTHING;
                }
                break;
            }

            case EXPECT_ID_PROOF_OR_STAKEGUARD:
            {
                if (proofComponent->objectType == CHAINOBJ_TRANSACTION_PROOF)
                {
                    // this is either an ID proof, proven by the prior block's blockchain MMR root,
                    // or a proof of the coinbase stakeguard output, proven by the block MMR root of the current
                    // POS header.
                    CTransaction outTx;
                    bool isPartial = false;
                    bool foundOut = false;
                    CValidationState tmpState;
                    uint256 txMMRRoot = ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.CheckPartialTransaction(outTx, &isPartial);
                    CProofRoot lastNotarizationRoot = lastNotarization.proofRoots[expectedNotarization.currencyID];

                    CDataStream ds(SER_DISK, PROTOCOL_VERSION);
                    headerProofsSize += GetSerializeSize(ds, *(CChainObject<CPartialTransactionProof> *)proofComponent);

                    // get the proofroot for startingheight
                    CProofRoot startingRoot = lastNotarization.proofRoots.count(expectedNotarization.currencyID) ?
                        lastNotarization.proofRoots[expectedNotarization.currencyID] :
                        CProofRoot();

                    // if it is proven against this block MMR root, it must be the stake transaction
                    // and we must be ready to prove it all
                    if (txMMRRoot == posBlockHeaderAndProof.blockHeader.GetBlockMMRRoot())
                    {
                        for (int j = 0; j < outTx.vout.size(); j++)
                        {
                            COptCCParams optP;
                            auto &oneOut = outTx.vout[j];
                            if (oneOut.nValue >= 0 &&
                                oneOut.scriptPubKey.IsPayToCryptoCondition(optP) &&
                                optP.IsValid() &&
                                optP.evalCode == EVAL_STAKEGUARD &&
                                RawPrecheckStakeGuardOutput(outTx, j, tmpState))
                            {
                                foundOut = true;
                                break;
                            }
                        }

                        // now verify the stake tx signature, even if it spends an ID
                        auto consensusBranchId = ConnectedChains.GetChainBranchId(futureProofRoot.systemID, height, Params().GetConsensus());

                        std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>> idAddressMap;
                        for (auto &oneId : stakeSpendingIDs)
                        {
                            std::vector<std::vector<unsigned char>> idAddrBytes;
                            for (auto &oneAddr : oneId.primaryAddresses)
                            {
                                idAddrBytes.push_back(GetDestinationBytes(oneAddr));
                            }
                            idAddressMap.insert(std::make_pair(oneId.GetID(), std::make_pair(oneId.minSigs, idAddrBytes)));
                        }

                        if (!VerifyScript(lastStakeTx.vin[0].scriptSig,
                                          lastSourceTx.vout[lastStakeTx.vin[0].prevout.n].scriptPubKey,
                                          MANDATORY_SCRIPT_VERIFY_FLAGS,
                                          TransactionSignatureChecker(&lastStakeTx, (uint32_t)0, lastSourceTx.vout[lastStakeTx.vin[0].prevout.n].nValue, &idAddressMap),
                                          consensusBranchId))
                        {
                            proofState = EXPECT_NOTHING;
                            break;
                        }

                        // after confirming stakeguard, we either have another header proof, or we're done
                        validChallengeEvidence = (++numHeaderProofs >= numHeaders ||
                                                  headerProofsSize >= CPBaaSNotarization::MAX_HEADER_PROOFS_SIZE);
                        proofState = EXPECT_HEADER_PROOFS;
                    }
                    else if (((CChainObject<CPartialTransactionProof> *)proofComponent)->object.IsChainProof() &&
                             posBlockHeaderAndProof.GetBlockHeight() > 0 &&
                             (posBlockHeaderAndProof.GetBlockHeight() - ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight()) >= VERUS_MIN_STAKEAGE &&
                             ((((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight() > startingRoot.rootHeight &&
                               txMMRRoot == posBlockHeaderAndProof.blockHeader.GetPrevMMRRoot()) ||
                               txMMRRoot == startingRoot.stateRoot))
                    {
                        for (auto &oneOut : outTx.vout)
                        {
                            COptCCParams optP;
                            CIdentity oneID;
                            if (oneOut.nValue >= 0 &&
                                oneOut.scriptPubKey.IsPayToCryptoCondition(optP) &&
                                optP.IsValid() &&
                                optP.evalCode == EVAL_IDENTITY_PRIMARY &&
                                optP.vData.size() &&
                                (oneID = CIdentity(optP.vData[0])).IsValid())
                            {
                                stakeSpendingIDs.push_back(oneID);
                            }
                            else if (oneOut.nValue >= 0)
                            {
                                // this should only be proving an ID output, nothing else
                                proofState = EXPECT_NOTHING;
                                break;
                            }
                        }
                        // after confirming one ID proof, next should be an ID or the stakeguard
                        // we will leave it to be that unless we have set an error
                    }
                    else
                    {
                        if (LogAcceptCategory("notarization"))
                        {
                            LogPrintf("\nIsChainProof: %s\nProofHeight: %u\nposBlockHeaderAndProof.GetBlockHeight(): %u\n((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight():%u\nlastNotarizationRoot.rootHeight: %u\ntxMMRRoot: %s\nposBlockHeaderAndProof.blockHeader.GetPrevMMRRoot(): %s\nlastNotarizationRoot.stateRoot: %s\nfutureProofRoot.stateroot: %s\n",
                                      ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.IsChainProof() ? "true" : "false",
                                      ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetProofHeight(),
                                      posBlockHeaderAndProof.GetBlockHeight(),
                                      ((CChainObject<CPartialTransactionProof> *)proofComponent)->object.GetBlockHeight(),
                                      lastNotarizationRoot.rootHeight,
                                      txMMRRoot.GetHex().c_str(),
                                      posBlockHeaderAndProof.blockHeader.GetPrevMMRRoot().GetHex().c_str(),
                                      lastNotarizationRoot.stateRoot.GetHex().c_str(),
                                      futureProofRoot.stateRoot.GetHex().c_str());
                        }
                        proofState = EXPECT_NOTHING;
                    }
                }
                break;
            }

            default:
            {
                proofState = EXPECT_NOTHING;
                break;
            }
        }
        if (proofState == EXPECT_NOTHING || validChallengeEvidence)
        {
            break;
        }
    }

    // some incorrect evidence is on testnet, so let it pass if we are on VRSCTEST and before the
    // test fork time
    CPBaaSNotarization retVal(((!validBasicEvidence && !validChallengeEvidence) || (challengeProofRoot.IsValid() && !validChallengeEvidence)) ?
                               CPBaaSNotarization() :
                               expectedNotarization);
    return retVal;
}

// gets the last confirmed notarization for a particular currency confirmed on or before a particular height
// do not use for heights more than 10 blocks before the tip
std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> GetLastConfirmedNotarization(uint160 curID, uint32_t height)
{
    std::vector<std::pair<uint32_t, CInputDescriptor>> unspentFinalizations;

    // prior confirmed must be on the chain before the notarization we are finalizing as confirmed
    // try the easy way first, which won't work if we are in an edge case, but otherwise will
    CTransaction lastTx, lastTx1;
    uint256 lastTxBlock;
    COptCCParams foundP;
    CObjectFinalization foundOf;
    CPBaaSNotarization foundNotarization;

    std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> retVal({0, CUTXORef(), CPBaaSNotarization()});

    unspentFinalizations = CObjectFinalization::GetUnspentConfirmedFinalizations(curID);

    if (unspentFinalizations.size())
    {
        std::pair<uint32_t, CInputDescriptor> firstUnspentFinalization;
        bool present = false;

        CTransaction targetTx;
        uint256 targetBlockHash;
        CObjectFinalization ofCandidate;

        {
            LOCK(mempool.cs);
            bool exitLoop = true;
            do
            {
                exitLoop = true;
                // make sure we can retrieve it and get the latest
                for (auto &oneFinalization : unspentFinalizations)
                {
                    CTransaction checkTx;
                    COptCCParams checkP;
                    uint256 checkBlockHash;
                    if (myGetTransaction(oneFinalization.second.txIn.prevout.hash, checkTx, checkBlockHash) &&
                        (checkBlockHash.IsNull() ||
                         (mapBlockIndex.count(checkBlockHash) &&
                          chainActive.Contains(mapBlockIndex[checkBlockHash]))) &&
                        checkTx.vout.size() > oneFinalization.second.txIn.prevout.n &&
                        checkTx.vout[oneFinalization.second.txIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(checkP) &&
                        checkP.IsValid() &&
                        (checkP.evalCode == EVAL_FINALIZE_NOTARIZATION ||
                        (checkP.evalCode == EVAL_ACCEPTEDNOTARIZATION || checkP.evalCode == EVAL_EARNEDNOTARIZATION)) &&
                        (!present ||
                         oneFinalization.first == 0 ||
                         firstUnspentFinalization.first < oneFinalization.first))
                    {
                        targetBlockHash.SetNull();
                        if (checkP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                            (!((ofCandidate = CObjectFinalization(checkP.vData[0])).IsValid() &&
                               ofCandidate.output.GetOutputTransaction(targetTx, targetBlockHash, true)) ||
                             (!targetBlockHash.IsNull() &&
                              (!mapBlockIndex.count(targetBlockHash) ||
                               !chainActive.Contains(mapBlockIndex[targetBlockHash])))))
                        {
                            // in any of these cases, the finalization has no business being in the mempool
                            // remove it and try again
                            if (checkBlockHash.IsNull())
                            {
                                std::list<CTransaction> removed;
                                mempool.remove(checkTx, removed, true);
                                unspentFinalizations = CObjectFinalization::GetUnspentConfirmedFinalizations(curID);
                                exitLoop = !unspentFinalizations.size();
                                break;
                            }
                            else
                            {
                                continue;
                            }
                        }
                        firstUnspentFinalization = oneFinalization;
                        present = true;
                        continue;
                    }
                }
            } while (!exitLoop);
        }

        CObjectFinalization priorOf;

        {
            LOCK(mempool.cs);
            while (present && (firstUnspentFinalization.first == 0 || firstUnspentFinalization.first > height))
            {
                // get the transaction and go backwards to get the finalized notarization it spends
                CTransaction checkTx;
                COptCCParams checkP;
                CObjectFinalization checkOf;
                uint256 checkBlockHash;
                if (myGetTransaction(firstUnspentFinalization.second.txIn.prevout.hash, checkTx, checkBlockHash) &&
                    checkTx.vout.size() > firstUnspentFinalization.second.txIn.prevout.n &&
                    checkTx.vout[firstUnspentFinalization.second.txIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(checkP) &&
                    checkP.IsValid() &&
                    ((checkP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                    (checkOf = CObjectFinalization(checkP.vData[0])).IsValid() &&
                    checkOf.IsConfirmed() &&
                    checkOf.currencyID == curID) ||
                    ((checkP.evalCode == EVAL_EARNEDNOTARIZATION || checkP.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
                    (foundNotarization = CPBaaSNotarization(checkP.vData[0])).IsValid() &&
                    foundNotarization.currencyID == curID)))
                {
                    bool found = false;
                    if (foundNotarization.IsValid())
                    {
                        if (foundNotarization.IsSameChain())
                        {
                            // if we found an actual notarization,
                            // it is local to this chain and inherently confirmed
                            // all are, so look for the last that was at that height
                            BlockMap::iterator blockIt;
                            firstUnspentFinalization.second.txIn.prevout = foundNotarization.prevNotarization;
                            CTransaction priorNTx;
                            uint256 priorBlockHash;
                            if (foundNotarization.prevNotarization.GetOutputTransaction(priorNTx, priorBlockHash) &&
                                (priorBlockHash.IsNull() ||
                                ((blockIt = mapBlockIndex.find(priorBlockHash)) != mapBlockIndex.end() &&
                                chainActive.Contains(blockIt->second))))
                            {
                                firstUnspentFinalization.first = priorBlockHash.IsNull() ? 0 : blockIt->second->GetHeight();
                                firstUnspentFinalization.second.nValue = priorNTx.vout[foundNotarization.prevNotarization.n].nValue;
                                firstUnspentFinalization.second.scriptPubKey = priorNTx.vout[foundNotarization.prevNotarization.n].scriptPubKey;
                                continue;
                            }
                        }

                        present = false;
                        foundNotarization = CPBaaSNotarization();
                        break;
                    }
                    // go backwards and look for the prior confirmed finalization
                    for (auto &oneIn : checkTx.vin)
                    {
                        CTransaction inTx;
                        uint256 inBlockHash;
                        if (myGetTransaction(oneIn.prevout.hash, inTx, inBlockHash) &&
                            inTx.vout.size() > oneIn.prevout.n &&
                            ((inTx.vout[oneIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(checkP) &&
                            checkP.IsValid() &&
                            ((checkP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                                (priorOf = CObjectFinalization(checkP.vData[0])).IsValid() &&
                                priorOf.IsConfirmed() &&
                                priorOf.currencyID == curID) ||
                            ((checkP.evalCode == EVAL_EARNEDNOTARIZATION || checkP.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
                                (foundNotarization = CPBaaSNotarization(checkP.vData[0])).IsValid() &&
                                foundNotarization.currencyID == curID &&
                                (foundNotarization.IsBlockOneNotarization() ||
                                foundNotarization.IsPreLaunch() ||
                                foundNotarization.IsDefinitionNotarization()))))))
                        {
                            found = true;
                            firstUnspentFinalization.second = CInputDescriptor(inTx.vout[oneIn.prevout.n].scriptPubKey,
                                                                                inTx.vout[oneIn.prevout.n].nValue,
                                                                                oneIn);
                            if (inBlockHash.IsNull())
                            {
                                firstUnspentFinalization.first = 0;
                            }
                            else
                            {
                                auto blockIt = mapBlockIndex.find(inBlockHash);
                                if (blockIt == mapBlockIndex.end() ||
                                    !chainActive.Contains(blockIt->second))
                                {
                                    present = false;
                                }
                                firstUnspentFinalization.first = blockIt->second->GetHeight();
                                if (firstUnspentFinalization.first > height)
                                {
                                    foundNotarization = CPBaaSNotarization();
                                }
                            }
                            break;
                        }
                        foundNotarization = CPBaaSNotarization();
                    }
                    if (!found || !present)
                    {
                        present = false;
                        foundNotarization = CPBaaSNotarization();
                        break;
                    }
                }
                else
                {
                    foundNotarization = CPBaaSNotarization();
                }
            }
        }

        if (present &&
            firstUnspentFinalization.first > 0 &&
            firstUnspentFinalization.first <= height)
        {
            LOCK(mempool.cs);

            COptCCParams foundP;
            CTransaction finalTx;
            uint256 finalBlockHash;
            if (!priorOf.IsValid() && !foundNotarization.IsValid())
            {
                if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                {
                    LogPrintf("%s: getting transaction %s\n", __func__, CUTXORef(firstUnspentFinalization.second.txIn.prevout).ToString().c_str());
                }
                if (myGetTransaction(firstUnspentFinalization.second.txIn.prevout.hash, finalTx, finalBlockHash) &&
                    finalTx.vout[firstUnspentFinalization.second.txIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(foundP) &&
                    foundP.IsValid() &&
                    foundP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                    (priorOf = CObjectFinalization(foundP.vData[0])).IsValid())
                {
                    if (priorOf.output.hash.IsNull())
                    {
                        priorOf.output.hash = finalTx.GetHash();
                    }
                }
            }
            if ((foundP.IsValid() || priorOf.IsValid()) && !foundNotarization.IsValid())
            {
                if (((priorOf.IsValid() &&
                      priorOf.output.GetOutputTransaction(finalTx, finalBlockHash) &&
                      finalTx.vout[priorOf.output.n].scriptPubKey.IsPayToCryptoCondition(foundP) &&
                      foundP.IsValid()) ||
                     foundP.IsValid()) &&
                    ((foundP.evalCode == EVAL_EARNEDNOTARIZATION || foundP.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
                     foundP.vData.size()))
                {
                    foundNotarization = CPBaaSNotarization(foundP.vData[0]);
                    if (priorOf.IsValid())
                    {
                        firstUnspentFinalization.second = CInputDescriptor(finalTx.vout[priorOf.output.n].scriptPubKey,
                                                                            finalTx.vout[priorOf.output.n].nValue,
                                                                            CTxIn(priorOf.output));
                    }
                    if (finalBlockHash.IsNull())
                    {
                        firstUnspentFinalization.first = 0;
                    }
                    else
                    {
                        auto blockIt = mapBlockIndex.find(finalBlockHash);
                        if (blockIt == mapBlockIndex.end() ||
                            !chainActive.Contains(blockIt->second))
                        {
                            present = false;
                        }
                        firstUnspentFinalization.first = blockIt->second->GetHeight();
                        if (!present || firstUnspentFinalization.first > height)
                        {
                            firstUnspentFinalization.first = 0;
                            foundNotarization = CPBaaSNotarization();
                        }
                    }
                }
            }
            if (foundNotarization.IsValid())
            {
                retVal = {firstUnspentFinalization.first, firstUnspentFinalization.second.txIn.prevout, foundNotarization};
            }
        }
    }
    return retVal;
}

bool IsScriptTooLargeToSpend(const CScript &script)
{
    COptCCParams p;
    if ((script.IsPayToCryptoCondition(p) &&
         p.AsVector().size() >= CScript::MAX_SCRIPT_ELEMENT_SIZE) ||
        script.IsOpReturn())
    {
        return true;
    }
    return false;
}

bool CPBaaSNotarization::CreateAcceptedNotarization(const CCurrencyDefinition &externalSystem,
                                                    const CPBaaSNotarization &earnedNotarization,
                                                    const CNotaryEvidence &notaryEvidence,
                                                    CValidationState &state,
                                                    TransactionBuilder &txBuilder,
                                                    const CTxDestination &fromDest)
{
    std::string errorPrefix(strprintf("%s: ", __func__));
    uint160 SystemID = externalSystem.GetID();

    const CCurrencyDefinition *pNotaryCurrency;
    if (IsVerusActive() || !ConnectedChains.notarySystems.count(SystemID))
    {
        pNotaryCurrency = &externalSystem;
    }
    else
    {
        pNotaryCurrency = &ConnectedChains.ThisChain();
    }

    // if we are paused on cross-chain, return error until enabled
    if ((externalSystem.IsPBaaSChain() &&
         (ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableDeFiKey()) ||
          ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisablePBaaSCrossChainKey()))) ||
        (externalSystem.IsGateway() &&
         ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableGatewayCrossChainKey())))
    {
        return state.Error(errorPrefix + "cross-chain temporarily disabled for security alert by notification oracle " + PBAAS_DEFAULT_NOTIFICATION_ORACLE);
    }

    std::set<uint160> notarySet = pNotaryCurrency->GetNotarySet();
    int minimumNotariesConfirm = pNotaryCurrency->MinimumNotariesConfirm();

    // now, verify the evidence. accepted notarizations for another system must have at least one
    // valid piece of evidence referring to the prior notarization with which it agrees

    bool signatureRequired = externalSystem.notarizationProtocol != externalSystem.NOTARIZATION_AUTO ||
                             externalSystem.proofProtocol != externalSystem.PROOF_PBAASMMR;

    bool additionalEvidenceRequired = externalSystem.proofProtocol == externalSystem.PROOF_PBAASMMR &&
                                      externalSystem.notarizationProtocol != externalSystem.NOTARIZATION_NOTARY_CHAINID;

    // create an accepted notarization based on the cross-chain notarization provided
    CPBaaSNotarization newNotarization = earnedNotarization;

    // this should be mirrored for us to continue, if it can't be, it is invalid
    if (earnedNotarization.IsMirror() || !newNotarization.SetMirror())
    {
        return state.Error(errorPrefix + "invalid earned notarization");
    }

    LOCK(cs_main);
    uint32_t height = chainActive.Height();

    // proof of the last confirmed notarization must be present and match the one on this chain or
    // prove the block 1 coinbase of the PBaaS chain
    std::set<int> evidenceTypes;
    evidenceTypes.insert(CHAINOBJ_TRANSACTION_PROOF);
    CCrossChainProof autoProof(notaryEvidence.GetSelectEvidence(evidenceTypes));
    if (additionalEvidenceRequired &&
        !autoProof.chainObjects.size())
    {
        return state.Error(errorPrefix + "Missing evidence of prior notarization, required to accept submission");
    }

    // now, we'll want to put our own proposer as the beneficiary of this notarization, if possible
    newNotarization.proposer.SetAuxDest(DestinationToTransferDestination(fromDest), 0);

    CProofRoot ourRoot = newNotarization.proofRoots[ASSETCHAINS_CHAINID];

    CChainNotarizationData cnd;
    std::vector<std::pair<CTransaction, uint256>> txes;
    if (!GetNotarizationData(SystemID, cnd, &txes) ||
        !cnd.vtx.size())
    {
        return state.Error(errorPrefix + "cannot locate notarization history");
    }

    // our evidence should acknowledge all disagreeing notarizations since the one it
    // refers to and supports. first check is to ensure that it does, as missing one
    // can render it invalid.
    CCrossChainProof challengeRoots(CCrossChainProof::VERSION_INVALID);
    if (notaryEvidence.evidence.chainObjects.size() > 1 &&
        notaryEvidence.evidence.chainObjects[0]->objectType == CHAINOBJ_CROSSCHAINPROOF)
    {
        if (!((challengeRoots = ((CChainObject<CCrossChainProof> *)notaryEvidence.evidence.chainObjects[0])->object).IsValid() &&
              challengeRoots.chainObjects.size() > 2 &&
              challengeRoots.chainObjects[0]->objectType == CHAINOBJ_EVIDENCEDATA &&
              ((CChainObject<CEvidenceData> *)challengeRoots.chainObjects[0])->object.type == CEvidenceData::TYPE_DATA &&
              ((CChainObject<CEvidenceData> *)challengeRoots.chainObjects[0])->object.vdxfd == CNotaryEvidence::PrimaryProofKey()))
        {
            return state.Error(errorPrefix + "invalid evidence data");
        }
    }

    // proof of the last confirmed notarization matching the one on this chain or block 1 coinbase
    // by the newly confirmed notarization
    // proof of the current notarization by the first proof root mentioned above
    CTransaction outTx;
    bool isPartial = false;
    uint256 txMMRRoot;
    uint256 txHash;

    txMMRRoot = ((CChainObject<CPartialTransactionProof> *)autoProof.chainObjects[0])->object.CheckPartialTransaction(outTx, &isPartial);
    txHash = ((CChainObject<CPartialTransactionProof> *)autoProof.chainObjects[0])->object.TransactionHash();
    if (txMMRRoot != newNotarization.proofRoots[newNotarization.currencyID].stateRoot)
    {
        return state.Error(errorPrefix + "state root mismatch in prior notarization proof");
    }

    int priorNotarizationIdx;
    CPBaaSNotarization priorAgreedNotarization;
    CPBaaSNotarization foundNotarization;

    CObjectFinalization foundOf;
    CAddressIndexDbEntry foundOutput;
    for (int i = 0; i < outTx.vout.size(); i++)
    {
        auto &oneOut = outTx.vout[i];
        if (oneOut.nValue >= 0 &&
            (priorAgreedNotarization = CPBaaSNotarization(oneOut.scriptPubKey)).IsValid() &&
            priorAgreedNotarization.currencyID == ASSETCHAINS_CHAINID &&
            priorAgreedNotarization.SetMirror(true) &&
            priorAgreedNotarization.currencyID != ASSETCHAINS_CHAINID &&
            ((priorAgreedNotarization.FindEarnedNotarization(foundOf, &foundOutput) &&
             priorAgreedNotarization.SetMirror(false) &&
             !priorAgreedNotarization.IsBlockOneNotarization()) ||
             (cnd.vtx[cnd.lastConfirmed].second.IsPreLaunch() &&
              priorAgreedNotarization.IsBlockOneNotarization())))
        {
            if (priorAgreedNotarization.IsBlockOneNotarization())
            {
                foundNotarization = cnd.vtx[cnd.lastConfirmed].second;
                priorNotarizationIdx = cnd.lastConfirmed;
            }
            else
            {
                foundNotarization = priorAgreedNotarization;
                CUTXORef foundOut(foundOutput.first.txhash, foundOutput.first.index);
                int j;
                for (j = 0; j < cnd.vtx.size(); j++)
                {
                    if (cnd.vtx[j].first == foundOut)
                    {
                        break;
                    }
                }
                priorNotarizationIdx = j < cnd.vtx.size() ? j : 0;
            }
            break;
        }
        priorAgreedNotarization = CPBaaSNotarization();
    }

    if (!priorAgreedNotarization.IsValid())
    {
        // will this get hit one block 1 proof?
        LogPrint("notarization", "%s: cannot find prior notarization for notarization: %s\n", __func__, newNotarization.ToUniValue().write().c_str());
        return state.Error(errorPrefix + "insufficient or invalid cryptographic evidence to confirm notarization 2");
    }

    if (!foundNotarization.IsValid())
    {
        for (priorNotarizationIdx = cnd.vtx.size() - 1; priorNotarizationIdx >= 0; priorNotarizationIdx--)
        {
            if (cnd.vtx[priorNotarizationIdx].first.hash == foundOutput.first.txhash)
            {
                if (outTx.vout.size() > cnd.vtx[priorNotarizationIdx].first.n &&
                    outTx.vout[cnd.vtx[priorNotarizationIdx].first.n].nValue >= 0 &&
                    (foundNotarization = CPBaaSNotarization(outTx.vout[cnd.vtx[priorNotarizationIdx].first.n].scriptPubKey)).IsValid())
                {
                    if (!foundNotarization.SetMirror(false) ||
                        ::AsVector(foundNotarization) != ::AsVector(priorAgreedNotarization))
                    {
                        return state.Error(errorPrefix + "invalid or mismatched prior notarization found");
                    }
                    break;
                }
                else
                {
                    return state.Error(errorPrefix + "invalid prior notarization proof 1");
                }
            }
        }
        if (!foundNotarization.IsValid())
        {
            return state.Error(errorPrefix + "invalid prior notarization proof 3");
        }
    }

    // we've found the priorAgreedNotarization on the chain, if the one we are trying to add is already on-chain or in mempool,
    // do not add another instance
    CNativeHashWriter hwCheck;
    hwCheck << newNotarization;
    uint256 objHashCheck = hwCheck.GetHash();
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> memResults;
    std::vector<CAddressIndexDbEntry> addressIndex;
    uint160 notarizationIdxKey = CCrossChainRPCData::GetConditionID(newNotarization.currencyID, CPBaaSNotarization::EarnedNotarizationKey(), objHashCheck);
    if ((mempool.getAddressIndex({{notarizationIdxKey, CScript::P2IDX}}, memResults) && memResults.size()) ||
        GetAddressIndex(notarizationIdxKey, CScript::P2IDX, addressIndex) && addressIndex.size())
    {
        return state.Error(errorPrefix + " Cannot create accepted notarization. Notarization already present on chain.");
    }

    // challenge roots must include all UTXOs between our last agreed index and the end
    int numChallenges = cnd.vtx.size() - (priorNotarizationIdx + 1);
    bool isChallengeStronger = false;
    CProofRoot strongestRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);
    if (numChallenges)
    {
        if (challengeRoots.chainObjects.size() != ((numChallenges << 1) + 1))
        {
            LogPrint("notarization", "%s\n", (errorPrefix + "invalid challenge response proofs number: " + std::to_string(challengeRoots.chainObjects.size()) + ", expected: " + std::to_string((numChallenges << 1) + 1)).c_str());
            LogPrint("notarization", "%s\n", challengeRoots.ToUniValue().write(1,2).c_str());
            return state.Error(errorPrefix + "invalid challenge response proofs number: " + std::to_string(challengeRoots.chainObjects.size()) + ", expected: " + std::to_string((numChallenges << 1) + 1));
        }

        CPrimaryProofDescriptor proofDescr(((CChainObject<CEvidenceData> *)challengeRoots.chainObjects[0])->object.dataVec);

        if (!proofDescr.IsValid() ||
            proofDescr.challengeOutputs.size() != (cnd.vtx.size() - (priorNotarizationIdx + 1)) ||
            challengeRoots.chainObjects.size() < ((proofDescr.challengeOutputs.size() << 1) + 1))
        {
            return state.Error(errorPrefix + "invalid challenge response proofs");
        }
        for (int i = priorNotarizationIdx + 1; i < cnd.vtx.size(); i++)
        {
            if (proofDescr.challengeOutputs[i - (priorNotarizationIdx + 1)] != cnd.vtx[i].first ||
                challengeRoots.chainObjects[1 + ((i - (priorNotarizationIdx + 1)) << 1)]->objectType != CHAINOBJ_PROOF_ROOT)
            {
                LogPrint("notarization", "%s\n", challengeRoots.ToUniValue().write(1,2).c_str());
                return state.Error(errorPrefix + "invalid challenge response proofs 1");
            }
            if (!strongestRoot.IsValid() ||
                CChainPower::ExpandCompactPower(
                    ((CChainObject<CProofRoot> *)challengeRoots.chainObjects[1 + ((i - (priorNotarizationIdx + 1)) << 1)])->object.compactPower) >
                  CChainPower::ExpandCompactPower(strongestRoot.compactPower))
            {
                strongestRoot = ((CChainObject<CProofRoot> *)challengeRoots.chainObjects[1 + ((i - (priorNotarizationIdx + 1)) << 1)])->object;
            }
            if (CChainPower::ExpandCompactPower(
                    ((CChainObject<CProofRoot> *)challengeRoots.chainObjects[1 + ((i - (priorNotarizationIdx + 1)) << 1)])->object.compactPower) >
                  CChainPower::ExpandCompactPower(newNotarization.proofRoots[newNotarization.currencyID].compactPower))
            {
                isChallengeStronger = true;
            }
        }
    }

    // any notarization submitted must include a proof root of this chain that is later than the last confirmed
    // notarization
    uint32_t lastHeight;

    if (!cnd.IsConfirmed())
    {
        return state.Error(errorPrefix + "earned notarization proof root cannot be verified without at least one prior confirmed for this chain");
    }

    CPBaaSNotarization lastConfirmedNotarization = cnd.vtx[cnd.lastConfirmed].second;

    lastHeight = lastConfirmedNotarization.IsPreLaunch() ?
                            lastConfirmedNotarization.notarizationHeight :
                            lastConfirmedNotarization.proofRoots.count(ASSETCHAINS_CHAINID) ?
                                lastConfirmedNotarization.proofRoots.find(ASSETCHAINS_CHAINID)->second.rootHeight :
                                UINT32_MAX;

    // all notarization protocols in Verus do the heavy lifting on the Verus side
    // as a result, the hash is currently assumed to be the default
    CNativeHashWriter hw;
    std::vector<unsigned char> notarizationVec = ::AsVector(earnedNotarization);
    uint256 objHash = hw.write((const char *)&(notarizationVec[0]), notarizationVec.size()).GetHash();

    uint32_t decisionHeight;
    std::map<CIdentityID, CIdentitySignature> notarySetRejects;
    std::map<CIdentityID, CIdentitySignature> notarySetConfirms;

    CNotaryEvidence::EStates confirmationState = notaryEvidence.CheckSignatureConfirmation(objHash, hw.GetHashType(), notarySet, minimumNotariesConfirm, height, &decisionHeight, &notarySetRejects, &notarySetConfirms);
    if (confirmationState != CNotaryEvidence::EStates::STATE_CONFIRMED && !additionalEvidenceRequired)
    {
        return state.Error(errorPrefix + "insufficient signature evidence to confirm notarization");
    }

    CPBaaSNotarization notarizationToConfirm;
    int notarizationIdxToConfirm = -1;

    BlockMap::iterator lastConfirmedBlockIt = mapBlockIndex.find(txes[cnd.lastConfirmed].second);
    if (lastConfirmedBlockIt == mapBlockIndex.end())
    {
        return state.Error(errorPrefix + "invalid confirmed notarization");
    }

    // even if we don't have a valid signature, we may still be able to autonotarize
    // auto notarization operates more quickly when evidence is signed by
    // a quorum of notary witnesses, but can also confirm with a preponderance of cryptographic.
    // evidence, time to elicit validity challenges, and no signatures
    // if we have a prior > 1, this acceptance may approve a prior notarization.
    // we'll assume the submission is not malicious via the RPC interface, and if we have conflicting
    // or not enough evidence, even a signed notarization won't get approved.
    if (additionalEvidenceRequired)
    {
        uint256 entropyHash;
        if (!IsValidPrimaryChainEvidence(externalSystem,
                                         notaryEvidence,
                                         newNotarization,
                                         lastConfirmedBlockIt->second->GetHeight(),
                                         height,
                                         &entropyHash,
                                         strongestRoot).IsValid())
        {
            return state.Error(errorPrefix + "insufficient proof to verify unchallenged notarization");
        }

        // our new notarization establishes a proof of the prior that it agrees with, which is now found if forkIdx != -1
        // if so and forkPos > notary confirms required, we can finalize as confirmed the one at the necessary level of
        // confirmation depth. the number of confirms required depends on whether or not this is signed.
        bool isSignNotarized = confirmationState == CNotaryEvidence::EStates::STATE_CONFIRMED;
        int confirmsRequired = (isSignNotarized ? CPBaaSNotarization::MIN_EARNED_FOR_SIGNED : CPBaaSNotarization::MIN_EARNED_FOR_AUTO) - 1;
        int blocksRequired = isSignNotarized ? pNotaryCurrency->GetMinBlocksToSignNotarize() : pNotaryCurrency->GetMinBlocksToAutoNotarize();
        int blockSpacing = pNotaryCurrency->GetMinBlocksToSignNotarize();

        // we want to accept only enough notarizations to get us to a confirmed state
        // if we are signed for confirmation, allow the normal block notarization modulo as a frequency
        // otherwise, reduce the frequency by extending the length between
        //
        // first, determine if we will accept this at all,
        if (height - foundOutput.first.blockHeight < blockSpacing)
        {
            LogPrint("notarization", "too early to accept notarization waiting for block %u\n", foundOutput.first.blockHeight + blockSpacing);
            return state.Error(errorPrefix + "not enough blocks have passed to create accepted notarization yet");
        }

        // if we have a more powerful challenge, we can't confirm
        if (!isChallengeStronger)
        {
            // if we are on the best fork and there are enough confirmations and blocks since any
            // unconfirmed notarization in our fork, we can confirm
            notarizationIdxToConfirm = cnd.forks[cnd.bestChain].back() == priorNotarizationIdx ?
                                        cnd.BestConfirmedNotarization(*pNotaryCurrency, confirmsRequired - 1, blocksRequired, height, lastConfirmedBlockIt->second->GetHeight(), txes) :
                                        -1;

            if (notarizationIdxToConfirm >= 0)
            {
                notarizationToConfirm = cnd.vtx[notarizationIdxToConfirm].second;
            }
        }
    }
    else
    {
        notarizationIdxToConfirm = priorNotarizationIdx;
        notarizationToConfirm = cnd.vtx[notarizationIdxToConfirm].second;
    }

    uint32_t priorNotarizationHeight = mapBlockIndex[txes[priorNotarizationIdx].second]->GetHeight();

    // all core proof roots that are in a prior, agreed notarization, must be present in the new one,
    // and we must have moved far enough forward from any there that we agree with, or early out
    for (auto &oneProofRoot : notarizationToConfirm.proofRoots)
    {
        if (oneProofRoot.first == ASSETCHAINS_CHAINID)
        {
            if (!newNotarization.proofRoots.count(oneProofRoot.first) ||
                newNotarization.proofRoots[oneProofRoot.first].rootHeight <= oneProofRoot.second.rootHeight)
            {
                return state.Error(errorPrefix + "insufficient progress in this chain " + EncodeDestination(CIdentityID(oneProofRoot.first)) + " to accept notarization");
            }
        }
        else if (oneProofRoot.first == SystemID &&
                    (!newNotarization.proofRoots.count(oneProofRoot.first) ||
                     (newNotarization.proofRoots[oneProofRoot.first].rootHeight - oneProofRoot.second.rootHeight) < externalSystem.blockNotarizationModulo))
        {
            return state.Error(errorPrefix + "insufficient progress in chain " + EncodeDestination(CIdentityID(oneProofRoot.first)) + " to accept notarization");
        }
    }

    auto mmv = chainActive.GetMMV();
    mmv.resize(ourRoot.rootHeight + 1);

    // we only create accepted notarizations for notarizations that are earned for this chain on another system
    // currently, we support ethereum and PBaaS types.
    if (!newNotarization.proofRoots.count(SystemID) ||
        !newNotarization.proofRoots.count(ASSETCHAINS_CHAINID) ||
        !(ourRoot = newNotarization.proofRoots[ASSETCHAINS_CHAINID]).IsValid() ||
        ourRoot.rootHeight > height ||
        ourRoot.blockHash != chainActive[ourRoot.rootHeight]->GetBlockHash() ||
        ourRoot.stateRoot != mmv.GetRoot() ||
        ourRoot.type != ourRoot.TYPE_PBAAS)
    {
        return state.Error(errorPrefix + "can only create accepted notarization from notarization with valid proof root of this chain");
    }

    // ensure that the data present is valid, as of the height
    CCoinbaseCurrencyState oldCurState = ConnectedChains.GetCurrencyState(ASSETCHAINS_CHAINID, ourRoot.rootHeight);
    if (!oldCurState.IsValid() ||
        ::GetHash(oldCurState) != ::GetHash(earnedNotarization.currencyState))
    {
        return state.Error(errorPrefix + "currency state is invalid in accepted notarization. is:\n" +
                                            newNotarization.currencyState.ToUniValue().write(1,2) +
                                            "\nshould be:\n" +
                                            oldCurState.ToUniValue().write(1,2) + "\n");
    }

    // ensure that all locally provable info is valid as of our root height
    // and determine if the new notarization should be already finalized or not
    for (auto &oneCur : newNotarization.currencyStates)
    {
        if (oneCur.first == SystemID)
        {
            return state.Error(errorPrefix + "cannot accept redundant currency state in notarization for " + EncodeDestination(CIdentityID(SystemID)));
        }
        else if (oneCur.first != ASSETCHAINS_CHAINID)
        {
            // see if this currency is on our chain, and if so, it must be correct as of the proof root of this chain
            CCurrencyDefinition curDef = ConnectedChains.GetCachedCurrency(oneCur.first);
            // we must have all currencies
            if (!curDef.IsValid())
            {
                return state.Error(errorPrefix + "all currencies in accepted notarizatoin must be registered on this chain");
            }
            // if the currency is not from this chain, we cannot validate it
            if (curDef.systemID != ASSETCHAINS_CHAINID)
            {
                continue;
            }
            // ensure that the data present is valid, as of the height
            oldCurState = ConnectedChains.GetCurrencyState(oneCur.first, ourRoot.rootHeight);
            if (!oldCurState.IsValid() ||
                ::GetHash(oldCurState) != ::GetHash(oneCur.second))
            {
                return state.Error(errorPrefix + "currency state is invalid in accepted notarization. is:\n" +
                                                 oneCur.second.ToUniValue().write(1,2) +
                                                 "\nshould be:\n" +
                                                 oldCurState.ToUniValue().write(1,2) + "\n");
            }
        }
        else
        {
            // already checked above
            continue;
        }
    }

    for (auto &oneRoot : newNotarization.proofRoots)
    {
        if (oneRoot.first == SystemID)
        {
            continue;
        }
        else
        {
            // see if this currency is on our chain, and if so, it must be correct as of the proof root of this chain
            CCurrencyDefinition curDef = ConnectedChains.GetCachedCurrency(oneRoot.first);
            // we must have all currencies in this notarization registered
            if (!curDef.IsValid())
            {
                return state.Error(errorPrefix + "all currencies in accepted notarizatoin must be registered on this chain");
            }
            uint160 curDefID = curDef.GetID();

            // only check other currencies on this chain, not the main chain itself
            if (curDefID != ASSETCHAINS_CHAINID && curDef.systemID == ASSETCHAINS_CHAINID)
            {
                return state.Error(errorPrefix + "proof roots are not accepted for token currencies");
            }
        }
    }

    // now create the new notarization, add the proof, finalize if appropriate, and finish

    // add spend of prior notarization and then outputs
    CPBaaSNotarization lastUnspentNotarization;
    uint256 lastTxId;
    int32_t lastTxOutNum;
    CTransaction lastTx;
    if (!lastUnspentNotarization.GetLastUnspentNotarization(SystemID, lastTxId, lastTxOutNum, &lastTx) ||
        (lastUnspentNotarization.proofRoots[ASSETCHAINS_CHAINID] == newNotarization.proofRoots[ASSETCHAINS_CHAINID] ||
         lastUnspentNotarization.proofRoots[SystemID] == newNotarization.proofRoots[SystemID]))
    {
        return state.Error(errorPrefix + "invalid new notarization");
    }

    // add prior unspent accepted notarization as our input
    txBuilder.AddTransparentInput(CUTXORef(lastTxId, lastTxOutNum), lastTx.vout[lastTxOutNum].scriptPubKey, lastTx.vout[lastTxOutNum].nValue);

    uint32_t adjustedNotarizationModulo = CPBaaSNotarization::GetAdjustedNotarizationModulo(ConnectedChains.ThisChain().blockNotarizationModulo,
                                                                                            mapBlockIndex[txes[cnd.lastConfirmed].second]->GetHeight(),
                                                                                            height);

    if ((height - priorNotarizationHeight) < adjustedNotarizationModulo)
    {
        LogPrint("notarization", "%s: cannot create accepted notarization earlier than %u blocks since the prior notarization it confirms\n",
                 adjustedNotarizationModulo);
        return state.Error(errorPrefix + "cannot create accepted notarization earlier than " +
                                            std::to_string(adjustedNotarizationModulo) +
                                            " blocks since the prior notarization it confirms");
    }

    {
        LOCK(mempool.cs);
        std::list<CTransaction> removed;
        // eliminate any conflict with ourselves or someone else doing the same thing
        mempool.removeConflicts(txBuilder.mtx, removed);
    }

    std::vector<std::vector<CInputDescriptor>> spendsToClose(cnd.vtx.size());
    std::vector<CInputDescriptor> extraSpends;

    // now, figure out which elements we spend, whether confirming or invalidating
    std::set<int> confirmedOutputNums;
    std::set<int> invalidatedOutputNums;

    // if we expect to confirm a new notarization, prepare for spends
    if (notarizationIdxToConfirm > 0)
    {
        std::vector<std::vector<CNotaryEvidence>> evidenceVec;
        if (!cnd.CorrelatedFinalizationSpends(txes, spendsToClose, extraSpends, &evidenceVec))
        {
            return state.Error(errorPrefix + "error correlating spends");
        }

        if (!cnd.CalculateConfirmation(notarizationIdxToConfirm, confirmedOutputNums, invalidatedOutputNums))
        {
            return state.Error(errorPrefix + "error calculating confirmation");
        }

        // spend closed/confirmed outputs
        for (auto oneConfirmedIdx : confirmedOutputNums)
        {
            if (oneConfirmedIdx != notarizationIdxToConfirm)
            {
                for (auto &oneInput : spendsToClose[oneConfirmedIdx])
                {
                    txBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
                }
            }
        }

        // spend invalidated nums
        for (auto oneInvalidatedIdx : invalidatedOutputNums)
        {
            for (auto &oneInput : spendsToClose[oneInvalidatedIdx])
            {
                txBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
            }
        }
    }

    CCcontract_info CC;
    CCcontract_info *cp;
    std::vector<CTxDestination> dests;

    // make the accepted notarization output
    cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

    txBuilder.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &newNotarization)), 0);

    // now add the notary evidence and finalization that uses it to assert validity
    // make the evidence notarization output
    cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

    std::vector<int32_t> evidenceOuts;
    std::vector<int32_t> confirmedEvidenceIns;

    COptCCParams chkP;
    if (!MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &notaryEvidence)).IsPayToCryptoCondition(chkP, false))
    {
        LogPrintf("%s: failed to package evidence script from system %s\n", __func__, EncodeDestination(CIdentityID(SystemID)).c_str());
        return false;
    }

    // the value should be considered for reduction
    if (chkP.AsVector().size() >= CScript::MAX_SCRIPT_ELEMENT_SIZE)
    {
        CNotaryEvidence emptyEvidence;
        int baseOverhead = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &emptyEvidence)).size() + 128;
        auto evidenceVec = notaryEvidence.BreakApart(CScript::MAX_SCRIPT_ELEMENT_SIZE - baseOverhead);
        if (!evidenceVec.size())
        {
            LogPrintf("%s: failed to package evidence from system %s\n", __func__, EncodeDestination(CIdentityID(SystemID)).c_str());
            return false;
        }
        for (auto &oneProof : evidenceVec)
        {
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            evidenceOuts.push_back(txBuilder.mtx.vout.size());
            txBuilder.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &oneProof)), 0);
        }
    }
    else
    {
        evidenceOuts.push_back(txBuilder.mtx.vout.size());
        txBuilder.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &notaryEvidence)), 0);
    }

    // now make 1 or 2 finalization outputs
    cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

    // create the pending finalization for our new notarization first
    CObjectFinalization of = CObjectFinalization(CObjectFinalization::FINALIZE_NOTARIZATION, newNotarization.currencyID, uint256(), txBuilder.mtx.vout.size() - (1 + evidenceOuts.size()), height + 1);

    of.evidenceOutputs = evidenceOuts;
    txBuilder.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &of)), 0);

    int numEvalOutputs = evidenceOuts.size();

    // if we have nothing or agree with 0, which is always already confirmed for accepted notarizations,
    // we do not need to spend evidence or finalizations, nor do we need to make new finalization outputs
    if (notarizationIdxToConfirm > 0 || ((notarizationIdxToConfirm == -1 || !notarizationIdxToConfirm) && lastUnspentNotarization.IsPreLaunch()))
    {
        if (notarizationIdxToConfirm == -1 || !notarizationIdxToConfirm)
        {
            notarizationIdxToConfirm = 0;
        }

        // if there are outputs to close for this entry, it will first be
        // a finalization, then evidence

        // we have no valid finalization to close for this list of spends
        // spend whatever we have and make an output finalization
        of = CObjectFinalization(CObjectFinalization::FINALIZE_NOTARIZATION + CObjectFinalization::FINALIZE_CONFIRMED,
                                    newNotarization.currencyID,
                                    cnd.vtx[notarizationIdxToConfirm].first.hash,
                                    cnd.vtx[notarizationIdxToConfirm].first.n,
                                    height);

        if (!cnd.vtx[notarizationIdxToConfirm].second.IsPreLaunch())
        {
            std::set<COutPoint> inputSet;
            std::vector<CInputDescriptor> nonInputEvidenceSpends;
            std::vector<CInputDescriptor> nonEvidenceSpends;

            for (auto &oneInput : spendsToClose[notarizationIdxToConfirm])
            {
                COptCCParams tP;
                if (oneInput.scriptPubKey.IsPayToCryptoCondition(tP) &&
                    tP.IsValid() &&
                    tP.evalCode == EVAL_FINALIZE_NOTARIZATION)
                {
                    // if our evidence include an already confirmed finalization for the same output,
                    // abort with nothing to do
                    CObjectFinalization tPOF;
                    if (tP.vData.size() &&
                        (tPOF = CObjectFinalization(tP.vData[0])).IsValid() &&
                        tPOF.output == of.output &&
                        tPOF.IsConfirmed())
                    {
                        return state.Error(errorPrefix + "target notarization already confirmed");
                    }
                    if (inputSet.count(oneInput.txIn.prevout))
                    {
                        if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                        {
                            printf("%s: skipping duplicate input: %s\n", __func__, oneInput.txIn.prevout.ToString().c_str());
                            LogPrintf("%s: skipping duplicate input: %s\n", __func__, oneInput.txIn.prevout.ToString().c_str());
                        }
                        continue;
                    }
                    of.evidenceInputs.push_back(txBuilder.mtx.vin.size());
                    inputSet.insert(oneInput.txIn.prevout);
                    txBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
                }
                else
                {
                    nonEvidenceSpends.push_back(oneInput);
                }
            }
            for (auto &oneInput : nonEvidenceSpends)
            {
                if (!inputSet.count(oneInput.txIn.prevout) && !IsScriptTooLargeToSpend(oneInput.scriptPubKey))
                {
                    inputSet.insert(oneInput.txIn.prevout);
                    txBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
                }
            }

            numEvalOutputs++;

            cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

            CNotaryEvidence ne(ASSETCHAINS_CHAINID, of.output, CNotaryEvidence::STATE_CONFIRMING);
            CCrossChainProof tipData(CCrossChainProof::VERSION_CURRENT);
            tipData << CEvidenceData(CNotaryEvidence::NotarizationTipKey(),
                                            ::AsVector(CPrimaryProofDescriptor(std::vector<CUTXORef>({cnd.vtx[priorNotarizationIdx].first}))));
            ne.evidence << tipData;
            of.evidenceOutputs.push_back(txBuilder.mtx.vout.size());
            txBuilder.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &ne)), 0);
        }
        cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
        txBuilder.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &of)), 0);
    }

    txBuilder.SetFee(numEvalOutputs ?
                     CPBaaSNotarization::DEFAULT_ACCEPTED_EVIDENCE_FEE * numEvalOutputs :
                     CPBaaSNotarization::DEFAULT_NOTARIZATION_FEE);

    if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
    {
        UniValue univTx(UniValue::VOBJ);
        TxToUniv(txBuilder.mtx, uint256(), univTx);
        printf("%s: txBuilder returning:\n%s\n", __func__, univTx.write(1,2).c_str());
    }

    return true;
}

extern void CopyNodeStats(std::vector<CNodeStats>& vstats);

std::vector<CNodeData> GetGoodNodes(int maxNum)
{
    // good nodes ordered by time connected
    std::map<int64_t, CNode *> goodNodes;
    std::vector<CNodeData> retVal;

    LOCK(cs_vNodes);
    for (auto oneNode : vNodes)
    {
        if (!oneNode->fInbound)
        {
            if (oneNode->fWhitelisted)
            {
                goodNodes.insert(std::make_pair(oneNode->nTimeConnected, oneNode));
            }
            else if (oneNode->GetTotalBytesRecv() > (1024 * 1024))
            {
                goodNodes.insert(std::make_pair(oneNode->nTimeConnected, oneNode));
            }
        }
    }
    if (goodNodes.size() > 1)
    {
        seed_insecure_rand();
        for (auto &oneNode : goodNodes)
        {
            if (insecure_rand() & 1)
            {
                retVal.push_back(CNodeData(oneNode.second->addr.ToStringIPPort(), oneNode.second->hashPaymentAddress));
                if (retVal.size() >= maxNum)
                {
                    break;
                }
            }
        }
        if (!retVal.size())
        {
            retVal.push_back(CNodeData(goodNodes.begin()->second->addr.ToStringIPPort(), goodNodes.begin()->second->hashPaymentAddress));
        }
    }
    else if (goodNodes.size())
    {
        retVal.push_back(CNodeData(goodNodes.begin()->second->addr.ToStringIPPort(), goodNodes.begin()->second->hashPaymentAddress));
    }
    return retVal;
}

bool CPBaaSNotarization::CheckEntropyHashMatch(const uint256 &entropyHash,
                                               const CHashCommitments &commitments,
                                               const uint160 &currencyID,
                                               uint32_t startingHeight,
                                               uint32_t endHeight)
{
    uint32_t rangeLen = endHeight - startingHeight;

    std::vector<__uint128_t> checkCommitments;
    uint256 blockTypes = commitments.GetSmallCommitments(checkCommitments);
    auto commitmentRanges = CPBaaSNotarization::GetBlockCommitmentRanges(startingHeight, endHeight, entropyHash);

    int checkIndex = 0;
    bool mismatchIndex = false;
    int consecPoS = 0;
    static const int MAX_CONSEC_POS = 5;

    for (auto &oneRange : commitmentRanges)
    {
        for (uint32_t loop = oneRange.first; loop <= oneRange.second; loop++, checkIndex++)
        {
            if (loop != ((uint32_t)checkCommitments[checkIndex]) >> 1)
            {
                LogPrintf("%s: Invalid entropy for PBaaS protocol proof - currencyID: %s\n", __func__, EncodeDestination(CIdentityID(currencyID)).c_str());
                mismatchIndex = true;
                break;
            }
            if ((uint32_t)checkCommitments[checkIndex] & 1)
            {
                if (++consecPoS > MAX_CONSEC_POS)
                {
                    LogPrintf("%s: Invalid consecutive PoS blocks for PBaaS protocol - currencyID: %s\n", __func__, EncodeDestination(CIdentityID(currencyID)).c_str());
                    mismatchIndex = true;
                    break;
                }
            }
            else
            {
                consecPoS = 0;
            }
        }
        if (mismatchIndex)
        {
            break;
        }
    }
    return !mismatchIndex;
}

std::vector<std::pair<uint32_t, uint32_t>>
CPBaaSNotarization::GetBlockCommitmentRanges(uint32_t fromHeight, uint32_t toHeight, uint256 entropy)
{
    int numBlocksPerCommitmentRange = MAX_BLOCKS_PER_COMMITMENT_RANGE;
    if (toHeight < numBlocksPerCommitmentRange + 1)
    {
        return std::vector<std::pair<uint32_t, uint32_t>>({{std::make_pair(std::max(fromHeight, (uint32_t)1), toHeight)}});
    }

    std::vector<std::pair<uint32_t, uint32_t>> retVal;

    int priorHeight = std::max((int)fromHeight - NUM_COMMITMENT_BLOCKS_START_OFFSET, 1);
    int startingHeight = std::max((int)fromHeight, 1);

    if ((toHeight - priorHeight) < numBlocksPerCommitmentRange)
    {
        numBlocksPerCommitmentRange = (toHeight - priorHeight);
    }

    // if our range is larger than 256, break it into up to 5, 256 block ranges and
    // spread them randomly over the target proof space
    if ((toHeight - priorHeight) > numBlocksPerCommitmentRange)
    {
        int totalRange = toHeight - priorHeight;
        int rangeLeft = totalRange;
        int numBlockRanges = std::max(std::min((int)((rangeLeft >> 1) / numBlocksPerCommitmentRange), (int)MAX_BLOCK_RANGES_PER_PROOF), 1);
        int blocksPerSection = (toHeight - priorHeight) / numBlockRanges;

        CNativeHashWriter hw;
        hw << RangeSelectEntropyKey();
        hw << entropy;
        entropy = hw.GetHash();

        // take off blocks per section at a time until we have no more whole blocks per section left
        while (rangeLeft)
        {
            int blocksThisSection = blocksPerSection;
            rangeLeft -= blocksPerSection;
            if (rangeLeft && rangeLeft < blocksPerSection)
            {
                blocksThisSection += rangeLeft;
                rangeLeft = 0;
            }
            // we need room for the range we will prove, hence the subtraction of at least the blocks needed after
            // the chosen start block
            uint32_t rangeStart = priorHeight + (UintToArith256(entropy).GetLow64() %
                    (blocksThisSection - std::min(blocksThisSection, (int)numBlocksPerCommitmentRange)));

            // last is inclusive in proof, so subtract 1 to get a total of numBlocksPerCommitmentRange
            retVal.push_back(std::make_pair(rangeStart, rangeStart + (numBlocksPerCommitmentRange - 1)));
        }
    }
    else if ((toHeight - priorHeight) == numBlocksPerCommitmentRange && numBlocksPerCommitmentRange > 1)
    {
        retVal.push_back(std::make_pair(priorHeight, priorHeight + (numBlocksPerCommitmentRange - 1)));
    }
    return retVal;
}

std::vector<__uint128_t> GetBlockCommitments(uint32_t fromHeight, uint32_t toHeight, const uint256 &entropy)
{
    std::vector<__uint128_t> blockCommitmentsSmall;
    if (chainActive.Height() >= toHeight)
    {
        auto blockRanges = CPBaaSNotarization::GetBlockCommitmentRanges(fromHeight, toHeight, entropy);

        // commit to prior blocks nTime, nBits, stakeBits, & work or stake power component for up to 256 blocks prior or back,
        // to the last notarization, whichever comes first, enabling later random verification of subset
        for (auto &oneRange : blockRanges)
        {
            int currentOffset = blockCommitmentsSmall.size() + (oneRange.second - oneRange.first);
            blockCommitmentsSmall.resize(currentOffset + 1);

            // needed for some compilers
            int64_t loopLimit = oneRange.first;
            for (int64_t blockNum = oneRange.second; blockNum >= loopLimit; (blockNum--, currentOffset--))
            {
                bool isPosBlock = chainActive[blockNum]->IsVerusPOSBlock();
                __uint128_t bigCommitmentNum((uint32_t)chainActive[blockNum]->nTime);
                bigCommitmentNum = (bigCommitmentNum << 32) | (uint32_t)chainActive[blockNum]->nBits;
                bigCommitmentNum = (bigCommitmentNum << 32) | (uint32_t)chainActive[blockNum]->GetVerusPOSTarget();
                bigCommitmentNum = (bigCommitmentNum << 32) | ((uint32_t)(blockNum << 1) | (uint32_t)isPosBlock);
                blockCommitmentsSmall[currentOffset] = bigCommitmentNum;

                if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                {
                    LogPrintf("%s: reading small commitments\n", __func__);
                    auto commitmentVec = UnpackBlockCommitment(blockCommitmentsSmall[currentOffset]);
                    arith_uint256 powTarget, posTarget;
                    powTarget.SetCompact(commitmentVec[1]);
                    posTarget.SetCompact(commitmentVec[2]);
                    LogPrintf("nHeight: %u, nTime: %u, PoW target: %s, PoS target: %s, isPoS: %u\n",
                                commitmentVec[3] >> 1,
                                commitmentVec[0],
                                powTarget.GetHex().c_str(),
                                posTarget.GetHex().c_str(),
                                commitmentVec[3] & 1);
                }
            }
        }
    }
    return blockCommitmentsSmall;
}

bool ProvePosBlock(uint32_t lastProofRootHeight, const CBlockIndex *pindex, CNotaryEvidence &evidence, CValidationState &state, int32_t *proofSize)
{
    // if this is a PoS block, add the entire spending transaction && a coinbase stakeguard output, which
    // will enable full PoS and signature verification, preventing any form of "fake stake" attack that
    // might exaggerate power of an attacking chain
    CBlock posBlock;

    if (!ReadBlockFromDisk(posBlock, pindex, Params().GetConsensus(), false))
    {
        LogPrintf("%s: ERROR: could not read PoS block from disk, LIKELY DUE TO CORRUPT LOCAL STATE, BOOTSTRAP OR RESYNC RECOMMENDED\n", __func__);
        return state.Error("invalid crosschain notarization data");
    }

    // get the proof in the header and use it
    std::vector<unsigned char> streamVec;
    posBlock.GetExtraData(streamVec);

    CDataStream ds(streamVec, SER_NETWORK, PROTOCOL_VERSION);
    CPartialTransactionProof sourceTxProof;

    try
    {
        ds >> sourceTxProof;
    }
    catch (...)
    {
        sourceTxProof = CPartialTransactionProof();
    }

    uint256 entropyHash;
    bool isNewFormatBlock = CConstVerusSolutionVector::GetVersionByHeight(pindex->GetHeight()) >= CActivationHeight::ACTIVATE_PBAAS;
    if (isNewFormatBlock)
    {
        entropyHash = pindex->GetVerusEntropyHashComponent();
    }

    int posh, powh, alth, firstHeight, secondHeight;
    uint256 pastHash = chainActive.GetVerusEntropyHash(pindex->GetHeight(), &posh, &powh, &alth, &firstHeight, &secondHeight);

    if (!sourceTxProof.IsValid() || pindex->GetHeight() < (firstHeight + 100))
    {
        LogPrintf("%s: ERROR: Invalid PoS header\n", __func__);
        return state.Error("Invalid PoS header for proof");
    }

    uint32_t heightAfterFirstEntropy = firstHeight + 1;
    if (!(CConstVerusSolutionVector::Version(chainActive[heightAfterFirstEntropy]->nSolution.nSolution()) >= CActivationHeight::ACTIVATE_PBAAS))
    {
        heightAfterFirstEntropy++;
    }

    if (LogAcceptCategory("notarization"))
    {
        LogPrintf("%s: pastHash: %s, firstHeight: %u, secondHeight: %u\n", __func__, pastHash.GetHex().c_str(), firstHeight, secondHeight);
        LogPrintf("proveblockheight: %u, proofheight: %u\nproofrootAtHeight: %s\nproofrootAtHeight - 1: %s\nproofrootAtHeight + 1: %s\n", heightAfterFirstEntropy, pindex->GetHeight() - 1, CProofRoot::GetProofRoot(pindex->GetHeight() - 1).ToUniValue().write(1,2).c_str(), CProofRoot::GetProofRoot(pindex->GetHeight() - 2).ToUniValue().write(1,2).c_str(), CProofRoot::GetProofRoot(pindex->GetHeight()).ToUniValue().write(1,2).c_str());
    }

    // get what's needed to prove the preheader of the block after closest entropy header
    // to get a proven MMR root of that height from the prev MMR root
    CBlock blockAfterEntropy;
    if (!ReadBlockFromDisk(blockAfterEntropy, chainActive[heightAfterFirstEntropy], Params().GetConsensus(), false))
    {
        LogPrintf("%s: ERROR: could not read block after entropy height from disk, LIKELY DUE TO CORRUPT LOCAL STATE, BOOTSTRAP OR RESYNC RECOMMENDED\n", __func__);
        return state.Error("Invalid post entropy block data");
    }

    // prove block header ref just in front of our first entropy block, so we can get the prev value as a root to prove
    // the rest that is in the block header, while connecting it to our current state
    uint32_t preHeaderProofHeight = pindex->GetHeight() - (isNewFormatBlock ? 1 : 2);

    CPartialTransactionProof afterEntropyProof = chainActive.GetPreHeaderProof(blockAfterEntropy, heightAfterFirstEntropy, preHeaderProofHeight);
    if (LogAcceptCategory("notarization"))
    {
        CPBaaSPreHeader proofPreHeader;
        LogPrintf("%s: afterEntropyProof.CheckBlockPreHeader(proofPreHeader): %s\n", __func__, afterEntropyProof.CheckBlockPreHeader(proofPreHeader).GetHex().c_str());
        LogPrintf("%s: afterEntropyProof.CheckBlockPreHeader(proofPreHeader, false): %s\n", __func__, afterEntropyProof.CheckBlockPreHeader(proofPreHeader, false).GetHex().c_str());
        LogPrintf("proofPreHeader: %s\n", proofPreHeader.ToUniValue().write(1,2).c_str());
        LogPrintf("prevMMRRoot: %s\n", pindex->GetBlockHeader().GetPrevMMRRoot().GetHex().c_str());
        LogPrintf("proofroot at height %u: %s\n", preHeaderProofHeight, pindex->GetBlockHeader().GetPrevMMRRoot().GetHex().c_str());
    }
    if (!afterEntropyProof.IsValid())
    {
        LogPrintf("%s: ERROR: failed to create proof of header after entropy height\n", __func__);
        return state.Error("Unable to create post entropy proof");
    }
    evidence.evidence << afterEntropyProof;

    // now prove:
    //
    // 1) the entire last transaction in the block - proven by the block Merkle root, which is available in the proven header
    CPartialTransactionProof stakeTxProof = posBlock.GetPartialTransactionProof(posBlock.vtx.back(),
                                                             posBlock.vtx.size() - 1,
                                                             std::vector<std::pair<int16_t, int16_t>>(),
                                                             entropyHash);
    evidence.evidence << stakeTxProof;

    if (LogAcceptCategory("notarization"))
    {
        CTransaction checkTx;
        if (stakeTxProof.CheckPartialTransaction(checkTx) == posBlock.hashMerkleRoot)
        {
            LogPrintf("MATCH proof and merkle branch:\nhashMerkleRoot: %s\n", posBlock.hashMerkleRoot.GetHex().c_str());
        }
        else
        {
            LogPrintf("MISMATCH proof and merkle branch:\nhashMerkleRoot: %s\ncalculated: %s\n", posBlock.hashMerkleRoot.GetHex().c_str(), stakeTxProof.CheckPartialTransaction(checkTx).GetHex().c_str());
        }
    }

    if (proofSize)
    {
        CDataStream ds(SER_DISK, PROTOCOL_VERSION);
        *proofSize += GetSerializeSize(ds, *(CChainObject<CBlockHeaderAndProof> *)evidence.evidence.chainObjects.back());
    }

    if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
    {
        CTransaction checkTx;

        auto checkProof = posBlock.GetPartialTransactionProof(posBlock.vtx.back(), posBlock.vtx.size() - 1, std::vector<std::pair<int16_t, int16_t>>(), entropyHash);
        uint256 txHash = checkProof.GetPartialTransaction(checkTx);
        uint256 merkleRoot = checkProof.CheckPartialTransaction(checkTx);

        uint32_t shiftIndex = ((CBTCMerkleBranch *)(checkProof.txProof.proofSequence[0]))->nIndex;
        LogPrintf("%s: Checking stake transaction proof\nMerkle branch:\nindex: %d\n", __func__, shiftIndex);

        for (auto oneHash : ((CBTCMerkleBranch *)(checkProof.txProof.proofSequence[0]))->branch)
        {
            LogPrintf("hash on %s: %s\n", shiftIndex & 1 ? "left" : "right", oneHash.GetHex().c_str());
            shiftIndex >>= 1;
        }

        uint256 checkMerkle =
            SafeCheckMerkleBranch(txHash, ((CBTCMerkleBranch *)(checkProof.txProof.proofSequence[0]))->branch, ((CBTCMerkleBranch *)(checkProof.txProof.proofSequence[0]))->nIndex);

        LogPrintf("CBlockIndex: %s\nProofRoot: %s\n", pindex->ToString().c_str(), CProofRoot::GetProofRoot(pindex->GetHeight()).ToUniValue().write(1,2).c_str());
        LogPrintf("txhash: %s\ncheckTx.GetHash(): %s\ncalculated merkle: %s\ncheckMerkle: %s\n", txHash.GetHex().c_str(), checkTx.GetHash().GetHex().c_str(), merkleRoot.GetHex().c_str(), checkMerkle.GetHex().c_str());
    }

    // 2) any ID outputs from the past needed to verify keys for a signature, and
    COptCCParams stakeOutP;
    std::map<uint160, std::tuple<CIdentity, CTxIn, uint32_t>> idsToProve;
    std::set<uint160> idsWithAddressInSig;
    if (posBlock.vtx.back().vout[0].scriptPubKey.IsPayToCryptoCondition(stakeOutP) && stakeOutP.IsValid())
    {
        for (auto &oneDest : stakeOutP.vKeys)
        {
            if (oneDest.which() == COptCCParams::ADDRTYPE_ID)
            {
                uint32_t idHeight = 0;
                CTxIn idTxIn;
                CIdentity lookupID = CIdentity::LookupIdentity(GetDestinationID(oneDest), pindex->GetHeight() - 1, &idHeight, &idTxIn);
                if (!lookupID.IsValid())
                {
                    return state.Error("invalid identity lookup, LIKELY DUE TO CORRUPT LOCAL STATE, BOOTSTRAP OR RESYNC RECOMMENDED");
                }
                idsToProve.insert(std::make_pair(GetDestinationID(oneDest), std::make_tuple(lookupID, idTxIn, idHeight)));
            }
        }
        CSmartTransactionSignatures smartSigs;
        std::vector<unsigned char> ffVec = GetFulfillmentVector(posBlock.vtx.back().vin[0].scriptSig);
        if (ffVec.size() && (smartSigs = CSmartTransactionSignatures(std::vector<unsigned char>(ffVec.begin(), ffVec.end()))).IsValid())
        {
            // determine if any ID lookups are needed to verify the signature, and if so, prove the necessary ID outputs
            for (auto &oneID : idsToProve)
            {
                for (auto &oneAddr : std::get<0>(oneID.second).primaryAddresses)
                {
                    uint160 addrId = GetDestinationID(oneAddr);
                    if (smartSigs.signatures.count(addrId))
                    {
                        idsWithAddressInSig.insert(oneID.first);
                    }
                }
            }
        }
        // prove IDs
        for (auto &oneIDToProve : idsWithAddressInSig)
        {
            std::tuple<CIdentity, CTxIn, uint32_t> &idTuple = idsToProve[oneIDToProve];
            CTransaction idTx;
            uint256 blockHash;
            if (!myGetTransaction(std::get<1>(idTuple).prevout.hash, idTx, blockHash) ||
                !mapBlockIndex.count(blockHash) ||
                !chainActive.Contains(mapBlockIndex[blockHash]))
            {
                return state.Error("invalid ID transaction for stake - cannot make proof");
            }
            CBlockIndex *pIDBlockIdx = mapBlockIndex[blockHash];

            // if the ID was modified before the starting height, prove it at the starting height
            // to connect the evidence to prior parts of the chain
            evidence.evidence << CPartialTransactionProof(idTx,
                                                          std::vector<int>(),
                                                          std::vector<int>({(int)std::get<1>(idTuple).prevout.n}),
                                                          pIDBlockIdx,
                                                          lastProofRootHeight != 1 && pIDBlockIdx->GetHeight() <= lastProofRootHeight ?
                                                            lastProofRootHeight :
                                                            pindex->GetHeight() - 1);

            if (proofSize)
            {
                CDataStream ds(SER_DISK, PROTOCOL_VERSION);
                *proofSize += GetSerializeSize(ds, *(CChainObject<CPartialTransactionProof> *)evidence.evidence.chainObjects.back());
            }
        }
    }

    // 3) one stakeguard output from the coinbase
    int cbOutNum;
    for (cbOutNum = 0; cbOutNum < posBlock.vtx[0].vout.size(); cbOutNum++)
    {
        const CTxOut &cbOut = posBlock.vtx[0].vout[cbOutNum];
        COptCCParams cboP;
        if (cbOut.scriptPubKey.IsPayToCryptoCondition(cboP) &&
            cboP.IsValid() &&
            cboP.evalCode == EVAL_STAKEGUARD)
        {
            break;
        }
    }
    if (cbOutNum >= posBlock.vtx[0].vout.size())
    {
        return state.Error("invalid proof of stake coinbase at block height " + std::to_string(pindex->GetHeight()));
    }

    evidence.evidence <<
        posBlock.GetPartialTransactionProof(posBlock.vtx[0],
                                            0,
                                            std::vector<std::pair<int16_t, int16_t>>(
                                                {{(int16_t)CTransactionHeader::TX_HEADER, (int16_t)0},
                                                    {(int16_t)CTransactionHeader::TX_OUTPUT, (int16_t)cbOutNum}}),
                                            entropyHash);
    if (proofSize)
    {
        CDataStream ds(SER_DISK, PROTOCOL_VERSION);
        *proofSize += GetSerializeSize(ds, *(CChainObject<CPartialTransactionProof> *)evidence.evidence.chainObjects.back());
    }

    return true;
}


bool CPBaaSNotarization::CheckCrossNotarizationProgression(const CCurrencyDefinition &curDef, CPBaaSNotarization &priorNotarization, uint32_t newHeight, CValidationState &state) const
{
    // ensure that this notarization does not skip any valid notarization behind us
    // whether or not this block alternates PoS and PoW is not checked here
    CTransaction priorNotTx;
    uint256 hashBlock;
    COptCCParams priorP;

    // if there is a proof root in this accepted notarization, it must be as part of an import
    // and the proof root should match the evidence notarization reference used to prove the
    // import.
    if (prevNotarization.IsNull() ||
        !myGetTransaction(prevNotarization.hash, priorNotTx, hashBlock) ||
        hashBlock.IsNull() ||
        !mapBlockIndex.count(hashBlock) ||
        priorNotTx.vout.size() <= prevNotarization.n ||
        !priorNotTx.vout[prevNotarization.n].scriptPubKey.IsPayToCryptoCondition(priorP) ||
        !priorP.IsValid() ||
        (priorP.evalCode != EVAL_ACCEPTEDNOTARIZATION && priorP.evalCode != EVAL_EARNEDNOTARIZATION) ||
        priorP.vData.size() < 1 ||
        !(priorNotarization = CPBaaSNotarization(priorP.vData[0])).IsValid() ||
        (priorP.evalCode == EVAL_ACCEPTEDNOTARIZATION &&
            !priorNotarization.IsBlockOneNotarization() &&
            !priorNotarization.IsDefinitionNotarization()) ||
        (hashPrevCrossNotarization.IsNull() && !curDef.IsGateway()))
    {
        return state.Error("Invalid prior for earned notarization");
    }

    std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> lastConfirmedNotarization = GetLastConfirmedNotarization(currencyID, newHeight - 1);

    if (!std::get<0>(lastConfirmedNotarization))
    {
        return state.Error("Cannot get last confirmed notarization");
    }

    CObjectFinalization confirmedOf(CObjectFinalization::VERSION_INVALID);
    CAddressIndexDbEntry localConfirmedIndex;

    uint160 notarizationIdxKey = CCrossChainRPCData::GetConditionID(currencyID,
                                                                    CPBaaSNotarization::EarnedNotarizationKey(),
                                                                    hashPrevCrossNotarization);

    CObjectFinalization lastConfirmedF;
    CAddressIndexDbEntry lastConfirmedAddressIndexKey;

    // if we can't find the prev cross on this chain, it means that when this was made, we were
    // not notarized on the notary chain yet. That means our latest known last confirmed as of this
    // notarization was the block 1 notarization
    bool foundLocalCrossConfirmed =
        CPBaaSNotarization::FindFinalizedIndexByVDXFKey(notarizationIdxKey, lastConfirmedF, lastConfirmedAddressIndexKey);

    // confirm that we're never backsliding, and once one is found, they must move forward
    notarizationIdxKey = CCrossChainRPCData::GetConditionID(priorNotarization.currencyID,
                                                            CPBaaSNotarization::EarnedNotarizationKey(),
                                                            priorNotarization.hashPrevCrossNotarization);

    CObjectFinalization priorLastConfirmedF;
    CAddressIndexDbEntry priorLastConfirmedAddressIndexKey;

    bool foundPriorLocalCrossConfirmed =
        CPBaaSNotarization::FindFinalizedIndexByVDXFKey(notarizationIdxKey, priorLastConfirmedF, priorLastConfirmedAddressIndexKey);

    // ensure that we can always find one after the first and that we have not moved backwards in the one we find
    // any cross confirmed notarization also must have first been confirmed on this chain, so verify that as well
    if (foundPriorLocalCrossConfirmed &&
        (!foundLocalCrossConfirmed ||
            lastConfirmedAddressIndexKey.first.blockHeight < priorLastConfirmedAddressIndexKey.first.blockHeight))
    {
        if (LogAcceptCategory("notarization"))
        {
            // the last confirmed notarization on this chain, which must be either the same or more recent on this
            // chain than any notarization we agree with on the alternate chain, refers to an older prior finalization
            // output than the one we are about to confirm on our notary chain
            LogPrintf("%s: Last confirmed notarization points to an older finalization\nlastconfirmedcrossfinalization: %s\nnewconfirmedcrossfinalization: %s\n\n",
                        __func__,
                        CUTXORef(priorLastConfirmedAddressIndexKey.first.txhash, priorLastConfirmedAddressIndexKey.first.index).ToString().c_str(),
                        CUTXORef(lastConfirmedAddressIndexKey.first.txhash, lastConfirmedAddressIndexKey.first.index).ToString().c_str());
        }
        return state.Error("Invalid progression of prior cross-notarization hash");
    }
    return true;
}

// create a notarization that is validated as part of the block, statistically benefiting the miner or staker if the
// cross notarization is valid
bool CPBaaSNotarization::CreateEarnedNotarization(const CRPCChainData &externalSystem,
                                                  const CTransferDestination &Proposer,
                                                  bool isStake,
                                                  CValidationState &state,
                                                  std::vector<CTxOut> &txOutputs,
                                                  CPBaaSNotarization &notarization)
{
    std::string errorPrefix(strprintf("%s: ", __func__));

    // if we are paused on cross-chain, return error until enabled
    if (ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableDeFiKey()) ||
        ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisablePBaaSCrossChainKey()))
    {
        return state.Error(errorPrefix + "cross-chain functions temporarily disabled for security alert by notification oracle " + PBAAS_DEFAULT_NOTIFICATION_ORACLE);
    }

    uint32_t height;
    uint32_t curChainTipTime;
    uint160 SystemID;
    const CCurrencyDefinition &systemDef = externalSystem.chainDefinition;
    SystemID = systemDef.GetID();

    CChainNotarizationData cnd;
    std::vector<std::pair<CTransaction, uint256>> txes;
    std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>>> localCounterEvidence;

    {
        LOCK2(cs_main, mempool.cs);
        height = chainActive.Height();
        curChainTipTime = chainActive[height]->nTime;

        // we can only create an earned notarization for a notary chain, so there must be a notary chain and a network connection to it
        // we also need to ensure that our notarization would be the first notarization in this notary block period  with which we agree.
        if (!externalSystem.IsValid() || externalSystem.rpcHost.empty())
        {
            // technically not a real error
            return state.Error("no-notary");
        }

        if (!GetNotarizationData(SystemID, cnd, &txes, &localCounterEvidence) || !cnd.IsConfirmed())
        {
            return state.Error(errorPrefix + "no prior confirmed notarization found");
        }
    }

    bool isGatewayFirstContact = systemDef.IsGateway() && cnd.vtx[cnd.lastConfirmed].second.IsDefinitionNotarization();

    // we really want the system proof roots for each notarization to make the JSON for the API smaller
    UniValue proofRootsUni(UniValue::VARR);
    for (auto &oneNot : cnd.vtx)
    {
        auto rootIt = oneNot.second.proofRoots.find(SystemID);
        if (rootIt != oneNot.second.proofRoots.end())
        {
            proofRootsUni.push_back(rootIt->second.ToUniValue());
        }
    }
    if (!proofRootsUni.size() && !isGatewayFirstContact)
    {
        return state.Error(errorPrefix + "no valid prior state root found");
    }

    // call notary to determine the prior notarization that we agree with
    UniValue params(UniValue::VARR);
    UniValue oneParam(UniValue::VOBJ);
    oneParam.push_back(Pair("proofroots", proofRootsUni));
    if (!isGatewayFirstContact && proofRootsUni.size())
    {
        oneParam.push_back(Pair("lastconfirmed", cnd.lastConfirmed));
    }
    params.push_back(oneParam);

    bool logNotarization = LogAcceptCategory("earnednotarizations");

    UniValue bestProofRootResult;
    try
    {
        if (logNotarization)
        {
            LogPrintf("calling getbestproofroot with params: %s\n", params.write(1,2).c_str());
            printf("calling getbestproofroot with params: %s\n", params.write(1,2).c_str());
        }
        bestProofRootResult = find_value(RPCCallRoot("getbestproofroot", params), "result");
        if (logNotarization)
        {
            LogPrintf("result from getbestproofroot: %s\n", bestProofRootResult.write(1,2).c_str());
            printf("result from getbestproofroot: %s\n", bestProofRootResult.write(1,2).c_str());
        }
    } catch (exception e)
    {
        if (logNotarization)
        {
            LogPrintf("exception from getbestproofroot: %s\n", e.what());
        }
        bestProofRootResult = NullUniValue;
    }

    UniValue notarizationResult;
    params = UniValue(UniValue::VARR);
    params.push_back(EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)));
    params.push_back(true);
    params.push_back(true);
    try
    {
        notarizationResult = find_value(RPCCallRoot("getnotarizationdata", params), "result");
        if (logNotarization)
        {
            LogPrintf("result from getnotarizationdata: %s\n", notarizationResult.write(1,2).c_str());
        }
    } catch (exception e)
    {
        if (logNotarization)
        {
            LogPrintf("exception from getnotarizationdata: %s\n", e.what());
        }
        notarizationResult = NullUniValue;
    }

    CChainNotarizationData crosschainCND;
    std::vector<uint256> blockHashes;
    std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>>> crossChainCounterEvidence;
    std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence>>> crossChainEvidence;

    {
        LOCK2(cs_main, mempool.cs);
        if (notarizationResult.isNull() ||
            !(crosschainCND = CChainNotarizationData(notarizationResult, true, &blockHashes, &crossChainCounterEvidence, &crossChainEvidence)).IsValid() ||
            (!externalSystem.chainDefinition.IsGateway() && !crosschainCND.IsConfirmed()))
        {
            LogPrint("notarization", "Unable to get notarization data from %s\n", EncodeDestination(CIdentityID(externalSystem.GetID())).c_str());
            return state.Error("invalid crosschain notarization data");
        }
    }

    // look for the following things to challenge:
    // 1) pending notarizations on the notary chain that we disagree with
    // 2) pending notarizations that agree with a prior notarization in a different notarization fork
    // 3) local notarizations that disagree with the notary chain we see
    // 4) pending notarization that we agree with, but that is not yet confirmed on our chain, meaning that
    //    we should force proof of the future root, as we see it as too early.
    //
    // if we find any of the above, we first look to see if they have counter-evidence already.
    // if not, post counter evidence and spend the last pending finalization in doing so to prevent
    // duplicates.
    //
    // we could combine the posting of challenges and submitting an accepted notarization if we
    // determine we will submit. this would be an optimization, but is not critical for function.
    //
    // once we determine that we have something to do, take the following action for each case:
    //
    // 1) submit a challenge with supporting evidence from this chain. if the chain is longer than ours,
    //    attempt to connect to the published nodes
    // 2) create a fraud proof and finalize the earliest notarization of each fork as rejected, rejecting
    //    any dependents automatically
    // 3) get a challenge from the notary chain for the specified range and with the specified
    //    entropy hash, then submit it to this chain with our own notarization or independently
    //    if we don't qualify to notarize.
    //
    std::set<int> validCrossChainIndexSet;
    std::set<int> invalidCrossChainIndexSet;
    {
        // for GetProofRoot
        LOCK(cs_main);
        for (int i = 0; i < crossChainEvidence.size(); i++)
        {
            // though we should agree with the data, also make sure that if it required proof,
            // it is proven with a future root we agree with, ensuring that it is not forking off from or trying to front run this chain
            // and also that it does not refer to a cross notarization more recent than our current confirmed
            bool isValid = true;
            for (auto &oneEvidenceItem : crossChainEvidence[i])
            {
                // we'll be looking for evidence that is confirmed, which should have come with the
                // notarization. we need to agree with the future root used, or we will issue a tip challenge
                // to prevent front running with invalid tips.
                if (std::get<1>(oneEvidenceItem).IsValid() &&
                    std::get<1>(oneEvidenceItem).IsConfirmed())
                {
                    std::set<int> evidenceTypes;
                    evidenceTypes.insert(CHAINOBJ_PROOF_ROOT);
                    evidenceTypes.insert(CHAINOBJ_TRANSACTION_PROOF);

                    CCrossChainProof autoProof = std::get<1>(oneEvidenceItem).GetSelectEvidence(evidenceTypes);
                    if (autoProof.chainObjects.size() >= 3 &&
                        autoProof.chainObjects[0]->objectType == CHAINOBJ_TRANSACTION_PROOF &&
                        autoProof.chainObjects[1]->objectType == CHAINOBJ_PROOF_ROOT &&
                        autoProof.chainObjects[2]->objectType == CHAINOBJ_TRANSACTION_PROOF)
                    {
                        CProofRoot futureRoot = ((CChainObject<CProofRoot> *)autoProof.chainObjects[1])->object;
                        if (futureRoot.rootHeight > chainActive.Height() ||
                            (futureRoot != CProofRoot::GetProofRoot(futureRoot.rootHeight)))
                        {
                            // we don't agree with this one because of the proof root, so we will ignore its existence
                            isValid = false;
                            continue;
                        }
                        // if we do agree, move on
                        isValid = true;
                        break;
                    }
                }
            }
            if (isValid)
            {
                CPBaaSNotarization localPriorNotarization;
                if (i &&
                    !crosschainCND.vtx[i].second.CheckCrossNotarizationProgression(systemDef, localPriorNotarization, height + 1, state))
                {
                    isValid = false;
                }
            }
            if (!isValid)
            {
                invalidCrossChainIndexSet.insert(i);
            }
            else
            {
                validCrossChainIndexSet.insert(i);
            }
        }
    }

    // as we identify notarizations to challenge, we will prune the chain notarization data that we use
    // to determine best chain of any provably invalid forks
    CChainNotarizationData prunedCND = cnd;

    UniValue validIndexesUni = find_value(bestProofRootResult, "validindexes");
    if (LogAcceptCategory("earnednotarizations") &&
        validIndexesUni.size() != proofRootsUni.size())
    {
        LogPrintf("%s: not all indexes are valid\n", __func__);
    }

    // now, we have the index for the transaction and notarization we agree with, a list of those we consider invalid,
    // and the most recent notarization to use when creating the new one
    //
    // we need to potentially make transactions for the challenges or add them to notarizations
    //

    if (!isGatewayFirstContact && (!validIndexesUni.isArray() || !validIndexesUni.size()))
    {
        if (LogAcceptCategory("earnednotarizations"))
        {
            LogPrintf("%s: No notarizations on notary chain agree\n", __func__);
        }
        return state.Error("no-valid-proofroots");
    }

    std::set<int> challengedIndexes;
    UniValue challengeRequests(UniValue::VARR);
    UniValue challengeRoots(UniValue::VARR);
    UniValue validityChallenges(UniValue::VARR);

    std::set<int> validIndexSet;

    if (externalSystem.chainDefinition.IsPBaaSChain())
    {
        // all challenges we make will require requesting challenge data from the notary chain
        // so we batch them up for one call
        if (validIndexesUni.isArray() && validIndexesUni.size())
        {
            for (int i = 0; i < validIndexesUni.size(); i++)
            {
                validIndexSet.insert(uni_get_int(validIndexesUni[i], -1));
            }
            std::vector<std::vector<int>> unchallengedForks = cnd.forks;
            for (int i = 1; i < cnd.vtx.size(); i++)
            {
                auto proofRootIT = cnd.vtx[i].second.proofRoots.find(SystemID);
                if (proofRootIT == cnd.vtx[i].second.proofRoots.end())
                {
                    continue;
                }

                // find this entry's first location, k, in fork j
                int j, k;
                for (j = 0; j < unchallengedForks.size(); j++)
                {
                    for (k = 1; k < unchallengedForks[j].size(); k++)
                    {
                        if (unchallengedForks[j][k] == i)
                        {
                            break;
                        }
                    }
                    if (k < unchallengedForks[j].size())
                    {
                        break;
                    }
                }

                // if we didn't find this entry in the pruned forks, nothing to do
                if (j >= unchallengedForks.size())
                {
                    continue;
                }

                // now, ensure that it follows all notarizationmodulo and alternate stake/work rules,
                // or remove it from the valid set before testing
                CBlockIndex *pCurNotarizationIndex = mapBlockIndex[txes[unchallengedForks[j][k]].second];
                CBlockIndex *pPriorNotarizationIndex = mapBlockIndex[txes[unchallengedForks[j][k - 1]].second];
                if (pCurNotarizationIndex->GetHeight() > CPBaaSNotarization::BlocksBeforeAlternateStakeEnforcement() &&
                    pCurNotarizationIndex->IsVerusPOSBlock() == pPriorNotarizationIndex->IsVerusPOSBlock())
                {
                    validIndexSet.erase(unchallengedForks[j][k]);
                }

                CBlockIndex *pConfirmedNotarizationIndex = mapBlockIndex[txes[0].second];

                uint32_t adjustedNotarizationModulo = CPBaaSNotarization::GetAdjustedNotarizationModulo(ConnectedChains.ThisChain().blockNotarizationModulo,
                                                                                  pConfirmedNotarizationIndex->GetHeight(),
                                                                                  pCurNotarizationIndex->GetHeight());

                int blockPeriodNumber = cnd.vtx[unchallengedForks[j][k]].second.proofRoots.count(ASSETCHAINS_CHAINID) ?
                        cnd.vtx[unchallengedForks[j][k]].second.proofRoots[ASSETCHAINS_CHAINID].rootHeight / adjustedNotarizationModulo :
                        0;

                int priorBlockPeriod = cnd.vtx[unchallengedForks[j][k - 1]].second.proofRoots.count(ASSETCHAINS_CHAINID) ?
                        cnd.vtx[unchallengedForks[j][k - 1]].second.proofRoots[ASSETCHAINS_CHAINID].rootHeight / adjustedNotarizationModulo :
                        0;

                if (priorBlockPeriod >= blockPeriodNumber)
                {
                    validIndexSet.erase(unchallengedForks[j][k]);
                }

                // if valid, use it to eliminate remaining forks and collect remaining challenges
                if (validIndexSet.count(i))
                {
                    // we found the first valid fork with this entry
                    // all forks that do not have the same value in the k'th entry
                    // should be challenged, either because we don't agree,
                    // or because they skipped this valid one and did not reference it
                    // if their entry is not the same, but valid, they are provably
                    // rejectable, otherwise just to be challenged
                    for (int forkToChallenge = 0; forkToChallenge < unchallengedForks.size(); forkToChallenge++)
                    {
                        if (forkToChallenge == j)
                        {
                            continue;
                        }
                        if (unchallengedForks[forkToChallenge].size() > k &&
                            unchallengedForks[forkToChallenge][k] != unchallengedForks[j][k])
                        {
                            for (int challengeNum = k; challengeNum < unchallengedForks[forkToChallenge].size(); challengeNum++)
                            {
                                challengedIndexes.insert(i);

                                // is there already counter evidence for this entry?
                                // 1) if there is a fraud proof, prune and move on
                                // 2) if there is a validity challenge, only add one if we intend to
                                //    expand its range
                                bool moveToNext = false;
                                for (auto &oneChallenge : localCounterEvidence[unchallengedForks[forkToChallenge][k]])
                                {
                                    if (!std::get<1>(oneChallenge).evidence.chainObjects.size() ||
                                        std::get<1>(oneChallenge).evidence.chainObjects[0]->objectType != CHAINOBJ_PROOF_ROOT)
                                    {
                                        continue;
                                    }
                                    // if the challenge root is the same as the root being challenged, it is a skip challenge
                                    // and would not be on-chain or in mempool if not valid. we can ignore the rest of this fork.
                                    if (((CChainObject<CProofRoot> *)std::get<1>(oneChallenge).evidence.chainObjects[0])->object ==
                                        cnd.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID])
                                    {
                                        unchallengedForks[forkToChallenge].erase(unchallengedForks[forkToChallenge].begin() + challengeNum, unchallengedForks[forkToChallenge].end());
                                        continue;
                                    }
                                    // TODO: POST HARDENING - right now, we actually don't break down ranges to a lower level of
                                    // granularity, based on checkpoints, so until we do, just consider this one covered and move
                                    // on to the next
                                    moveToNext = true;
                                    break;
                                }
                                if (moveToNext)
                                {
                                    continue;
                                }

                                // if it's valid and not behind the prior valid one, then it skipped a valid notarization and can be proven false
                                if (validIndexSet.count(unchallengedForks[forkToChallenge][k]))
                                {
                                    // prove the root on the j fork with this root and submit the proof along with a rejection
                                    // finalization
                                    CNotaryEvidence fraudProof;
                                    fraudProof.output = cnd.vtx[unchallengedForks[forkToChallenge][k]].first;
                                    fraudProof.state = CNotaryEvidence::STATE_REJECTED;

                                    // create evidence in this order
                                    // EXPECT_ALTERNATE_PROOF_ROOT  // give it the same root as it has, indicating fraud proof
                                    fraudProof.evidence << cnd.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID];

                                    // EXPECT_SKIPPED_NOTARIZATION_REF - this is the notarization it should not have skipped
                                    fraudProof.evidence << CEvidenceData(CVDXF_Data::UTXORefKey(), ::AsVector(cnd.vtx[unchallengedForks[j][k]].first));

                                    int64_t proveHeight = cnd.vtx[unchallengedForks[j][k]].second.proofRoots[SystemID].rootHeight;
                                    int64_t atHeight = cnd.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID].rootHeight;

                                    // if the one to prove is greater than the one to prove from, the one to prove from may have been made by
                                    // one out of sync or it may just not agree with the other's fork
                                    if (proveHeight <= atHeight)
                                    {
                                        UniValue challengeRequest(UniValue::VOBJ);
                                        challengeRequest.pushKV("type", EncodeDestination(CIdentityID(CNotaryEvidence::SkipChallengeKey())));
                                        challengeRequest.pushKV("evidence", fraudProof.ToUniValue());
                                        challengeRequest.pushKV("proveheight", proveHeight);
                                        challengeRequest.pushKV("atheight", atHeight);
                                        challengeRequest.pushKV("entropyhash", txes[unchallengedForks[forkToChallenge][k]].second.GetHex());
                                        challengeRequests.push_back(challengeRequest);

                                        // once we've created an invalidation proof, which a skipped proof is,
                                        // the entire fork will be automatically invalidated
                                        unchallengedForks[forkToChallenge].erase(unchallengedForks[forkToChallenge].begin() + challengeNum, unchallengedForks[forkToChallenge].end());
                                    }
                                }
                                else
                                {
                                    // this challenge will be incorporated into
                                    // our notarization
                                    UniValue challengeRequest(UniValue::VOBJ);
                                    challengeRequest.pushKV("txout", cnd.vtx[unchallengedForks[forkToChallenge][k]].first.ToUniValue());
                                    challengeRequest.pushKV("proofroot", cnd.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID].ToUniValue());
                                    challengeRoots.push_back(challengeRequest);
                                }
                            }
                            unchallengedForks[forkToChallenge].erase(unchallengedForks[forkToChallenge].begin() + k, unchallengedForks[forkToChallenge].end());
                        }
                    }
                }

                // check again, as we may have removed an entry due to its proof
                if (!validIndexSet.count(i))
                {
                    // all descendents of this entry are invalid according to our perspective
                    // look for the first fork that agrees and create challenges until the end
                    // then look for the next
                    challengedIndexes.insert(i);
                    int invalidIndex = unchallengedForks[j][k];
                    for (int forkToChallenge = 0; forkToChallenge < unchallengedForks.size(); forkToChallenge++)
                    {
                        if (unchallengedForks[forkToChallenge].size() > k &&
                            unchallengedForks[forkToChallenge][k] == invalidIndex)
                        {
                            for (int challengeNum = k; challengeNum < unchallengedForks[forkToChallenge].size(); challengeNum++)
                            {
                                bool moveToNext = false;
                                for (auto &oneChallenge : localCounterEvidence[unchallengedForks[forkToChallenge][k]])
                                {
                                    if (!std::get<1>(oneChallenge).evidence.chainObjects.size() ||
                                        std::get<1>(oneChallenge).evidence.chainObjects[0]->objectType != CHAINOBJ_PROOF_ROOT)
                                    {
                                        continue;
                                    }
                                    // if the challenge root is the same as the root being challenged, it is a skip challenge
                                    // and would not be on-chain or in mempool if not valid. we can ignore the rest of this fork.
                                    if (((CChainObject<CProofRoot> *)std::get<1>(oneChallenge).evidence.chainObjects[0])->object ==
                                        cnd.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID])
                                    {
                                        unchallengedForks[forkToChallenge].erase(unchallengedForks[forkToChallenge].begin() + challengeNum, unchallengedForks[forkToChallenge].end());
                                        continue;
                                    }
                                    // TODO: POST HARDENING - right now, we actually don't break down ranges to a lower level of
                                    // granularity, based on checkpoints, so until we do, just consider this one covered and move
                                    // on to the next
                                    moveToNext = true;
                                    break;
                                }
                                if (moveToNext)
                                {
                                    continue;
                                }

                                // this challenge will be incorporated into
                                // our notarization
                                UniValue challengeRequest(UniValue::VOBJ);
                                challengeRequest.pushKV("txout", cnd.vtx[unchallengedForks[forkToChallenge][k]].first.ToUniValue());
                                challengeRequest.pushKV("proofroot", cnd.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID].ToUniValue());
                                challengeRoots.push_back(challengeRequest);
                            }
                            unchallengedForks[forkToChallenge].erase(unchallengedForks[forkToChallenge].begin() + k, unchallengedForks[forkToChallenge].end());
                        }
                    }
                }
            }
            prunedCND.forks = unchallengedForks;
            prunedCND.SetBestChain(systemDef, txes);
        }

        // we challenge any notarizations about a chain that is not us
        // we also challenge and finalize as rejected notarizations that skip over a prior notarization
        // which they actually should agree with
        UniValue challenges(UniValue::VARR);
        {
            LOCK2(cs_main, mempool.cs);

            std::vector<std::vector<int>> unchallengedForks = crosschainCND.forks;
            std::set<int> validIndexes;
            for (int i = 0; i < crosschainCND.vtx.size(); i++)
            {
                auto proofRootIT = crosschainCND.vtx[i].second.proofRoots.find(ASSETCHAINS_CHAINID);
                if (proofRootIT == crosschainCND.vtx[i].second.proofRoots.end())
                {
                    continue;
                }

                if (proofRootIT->second == CProofRoot::GetProofRoot(proofRootIT->second.rootHeight))
                {
                    validIndexes.insert(i);
                }
            }
            for (int i = 1; i < crosschainCND.vtx.size(); i++)
            {
                auto proofRootIT = crosschainCND.vtx[i].second.proofRoots.find(SystemID);
                if (proofRootIT == crosschainCND.vtx[i].second.proofRoots.end())
                {
                    continue;
                }

                // find this entry's first location, k, in fork j
                int j, k;
                for (j = 0; j < unchallengedForks.size(); j++)
                {
                    for (k = 0; k < unchallengedForks[j].size(); k++)
                    {
                        if (unchallengedForks[j][k] == i)
                        {
                            break;
                        }
                    }
                    if (k < unchallengedForks[j].size())
                    {
                        break;
                    }
                }

                // if we didn't find this entry in the pruned forks, nothing to do
                if (j >= unchallengedForks.size())
                {
                    continue;
                }

                // if valid, use it to eliminate remaining forks and collect remaining challenges
                if (validIndexes.count(i))
                {
                    // we found the first valid fork with this entry
                    // all forks that do not have the same value in the k'th entry
                    // should be challenged, either because we don't agree,
                    // or because they skipped this valid one and did not reference it
                    // if their entry is not the same, but valid, they are provably
                    // rejectable, otherwise just to be challenged
                    for (int forkToChallenge = 0; forkToChallenge < unchallengedForks.size(); forkToChallenge++)
                    {
                        if (forkToChallenge == j)
                        {
                            continue;
                        }
                        if (unchallengedForks[forkToChallenge].size() > k &&
                            unchallengedForks[forkToChallenge][k] != unchallengedForks[j][k])
                        {
                            for (int challengeNum = k; challengeNum < unchallengedForks[forkToChallenge].size(); challengeNum++)
                            {
                                // is there already counter evidence for this entry?
                                // 1) if there is a fraud proof, prune and move on
                                // 2) if there is a validity challenge, only add one if we intend to
                                //    expand its range
                                bool moveToNext = false;
                                for (auto &oneChallenge : crossChainCounterEvidence[unchallengedForks[forkToChallenge][k]])
                                {
                                    if (!std::get<1>(oneChallenge).evidence.chainObjects.size() ||
                                        std::get<1>(oneChallenge).evidence.chainObjects[0]->objectType != CHAINOBJ_PROOF_ROOT)
                                    {
                                        continue;
                                    }
                                    // if the challenge root is the same as the root being challenged, it is a skip challenge
                                    // and would not be on-chain or in mempool if not valid. we can ignore the rest of this fork.
                                    if (((CChainObject<CProofRoot> *)std::get<1>(oneChallenge).evidence.chainObjects[0])->object ==
                                        crosschainCND.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID])
                                    {
                                        unchallengedForks[forkToChallenge].erase(unchallengedForks[forkToChallenge].begin() + challengeNum, unchallengedForks[forkToChallenge].end());
                                        continue;
                                    }
                                    // TODO: POST HARDENING - right now, we actually don't break down ranges to a lower level of
                                    // granularity, based on checkpoints, so until we do, just consider this one covered and move
                                    // on to the next
                                    moveToNext = true;
                                    break;
                                }
                                if (moveToNext)
                                {
                                    continue;
                                }

                                // if it's valid, then it skipped a valid notarization and can be proven false
                                if (validIndexes.count(unchallengedForks[forkToChallenge][k]))
                                {
                                    // prove the root on the j fork with this root and submit the proof along with a rejection
                                    // finalization
                                    CNotaryEvidence fraudProof;
                                    fraudProof.output = crosschainCND.vtx[unchallengedForks[forkToChallenge][k]].first;
                                    fraudProof.state = CNotaryEvidence::STATE_REJECTED;

                                    // create evidence in this order
                                    // EXPECT_ALTERNATE_PROOF_ROOT  // give it the same root as it has, indicating fraud proof
                                    fraudProof.evidence << crosschainCND.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID];

                                    // EXPECT_SKIPPED_NOTARIZATION_REF - this is the notarization it should not have skipped
                                    fraudProof.evidence << CEvidenceData(CVDXF_Data::UTXORefKey(), ::AsVector(crosschainCND.vtx[unchallengedForks[j][k]].first));

                                    int64_t proveHeight = std::min(crosschainCND.vtx[unchallengedForks[j][k]].second.proofRoots[SystemID].rootHeight,
                                                                    crosschainCND.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID].rootHeight);

                                    int64_t atHeight = std::max(crosschainCND.vtx[unchallengedForks[j][k]].second.proofRoots[SystemID].rootHeight,
                                                                    crosschainCND.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID].rootHeight);

                                    UniValue challengeRequest(UniValue::VOBJ);
                                    challengeRequest.pushKV("type", EncodeDestination(CIdentityID(CNotaryEvidence::SkipChallengeKey())));
                                    challengeRequest.pushKV("evidence", fraudProof.ToUniValue());
                                    challengeRequest.pushKV("proveheight", proveHeight);
                                    challengeRequest.pushKV("atheight", atHeight);
                                    challengeRequest.pushKV("entropyhash", blockHashes[unchallengedForks[forkToChallenge][k]].GetHex());
                                    challenges.push_back(challengeRequest);

                                    // once we've created an invalidation proof, which a skipped proof is,
                                    // the entire fork will be automatically invalidated
                                    unchallengedForks[forkToChallenge].erase(unchallengedForks[forkToChallenge].begin() + challengeNum, unchallengedForks[forkToChallenge].end());
                                }
                                else
                                {

                                    // we should take care of this in SubmitFinalizedNotarizations, not here
                                    continue;



                                    // we need to get the challenge from the notary chain, and it should only need
                                    // to challenge and prove from the last agreed entry forward, using entropy hash
                                    // of the block of the notarization that we are challenging

                                    CNotaryEvidence challengeEvidence;
                                    challengeEvidence.output = crosschainCND.vtx[i].first;
                                    challengeEvidence.state = CNotaryEvidence::STATE_REJECTED;

                                    // create evidence to either use when notarizing, or for a challenge
                                    int64_t fromHeight = crosschainCND.vtx[unchallengedForks[j][k - 1]].second.IsBlockOneNotarization() ?
                                                            1 :
                                                            crosschainCND.vtx[unchallengedForks[j][k - 1]].second.proofRoots[SystemID].rootHeight;

                                    int64_t toHeight = crosschainCND.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID].rootHeight;

                                    UniValue challengeRequest(UniValue::VOBJ);
                                    challengeRequest.pushKV("type", EncodeDestination(CIdentityID(CNotaryEvidence::ValidityChallengeKey())));
                                    challengeRequest.pushKV("evidence", challengeEvidence.ToUniValue());
                                    challengeRequest.pushKV("fromheight", fromHeight);
                                    challengeRequest.pushKV("toheight", toHeight);
                                    challengeRequest.pushKV("challengedroot", crosschainCND.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID].ToUniValue());
                                    challengeRequest.pushKV("confirmroot", crosschainCND.vtx[unchallengedForks[j][k - 1]].second.proofRoots[SystemID].ToUniValue());
                                    challengeRequest.pushKV("entropyhash", blockHashes[unchallengedForks[forkToChallenge][k]].GetHex());
                                    challenges.push_back(challengeRequest);
                                }
                            }
                            unchallengedForks[forkToChallenge].erase(unchallengedForks[forkToChallenge].begin() + k, unchallengedForks[forkToChallenge].end());
                        }
                    }
                }
                else
                {
                    // all descendents of this entry are invalid according to our perspective
                    // look for the first fork that agrees and create challenges until the end
                    // then look for the next
                    int invalidIndex = unchallengedForks[j][k];
                    for (int forkToChallenge = 0; forkToChallenge < unchallengedForks.size(); forkToChallenge++)
                    {

                        // we should take care of this in SubmitFinalizedNotarizations, not here
                        // just by submitting an alternative, we will be challenging
                        break;

                        if (unchallengedForks[forkToChallenge].size() > k &&
                            unchallengedForks[forkToChallenge][k] == invalidIndex)
                        {
                            for (int challengeNum = k; challengeNum < unchallengedForks[forkToChallenge].size(); challengeNum++)
                            {
                                bool moveToNext = false;
                                for (auto &oneChallenge : crossChainCounterEvidence[unchallengedForks[forkToChallenge][k]])
                                {
                                    if (!std::get<1>(oneChallenge).evidence.chainObjects.size() ||
                                        std::get<1>(oneChallenge).evidence.chainObjects[0]->objectType != CHAINOBJ_PROOF_ROOT)
                                    {
                                        continue;
                                    }
                                    // if the challenge root is the same as the root being challenged, it is a skip challenge
                                    // and would not be on-chain or in mempool if not valid. we can ignore the rest of this fork.
                                    if (((CChainObject<CProofRoot> *)std::get<1>(oneChallenge).evidence.chainObjects[0])->object ==
                                        crosschainCND.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID])
                                    {
                                        unchallengedForks[forkToChallenge].erase(unchallengedForks[forkToChallenge].begin() + challengeNum, unchallengedForks[forkToChallenge].end());
                                        continue;
                                    }
                                    // TODO: POST HARDENING - right now, we actually don't break down ranges to a lower level of
                                    // granularity, based on checkpoints, so until we do, just consider this one covered and move
                                    // on to the next
                                    moveToNext = true;
                                    break;
                                }
                                if (moveToNext)
                                {
                                    continue;
                                }

                                CNotaryEvidence challengeEvidence;
                                challengeEvidence.output = crosschainCND.vtx[i].first;
                                challengeEvidence.state = CNotaryEvidence::STATE_REJECTED;

                                // create evidence to either use when notarizing, or for a challenge
                                int64_t fromHeight = crosschainCND.vtx[cnd.lastConfirmed].second.IsPreLaunch() ?
                                                        1 :
                                                        crosschainCND.vtx[cnd.lastConfirmed].second.proofRoots[SystemID].rootHeight;

                                int64_t toHeight = crosschainCND.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID].rootHeight;

                                UniValue challengeRequest(UniValue::VOBJ);
                                challengeRequest.pushKV("type", EncodeDestination(CIdentityID(CNotaryEvidence::ValidityChallengeKey())));
                                challengeRequest.pushKV("evidence", challengeEvidence.ToUniValue());
                                challengeRequest.pushKV("fromheight", fromHeight);
                                challengeRequest.pushKV("toheight", toHeight);
                                challengeRequest.pushKV("challengedroot", crosschainCND.vtx[unchallengedForks[forkToChallenge][k]].second.proofRoots[SystemID].ToUniValue());
                                challengeRequest.pushKV("confirmnotarization", crosschainCND.vtx[cnd.lastConfirmed].second.ToUniValue());
                                challengeRequest.pushKV("entropyhash", blockHashes[unchallengedForks[forkToChallenge][k]].GetHex());
                                challenges.push_back(challengeRequest);
                            }
                            unchallengedForks[forkToChallenge].erase(unchallengedForks[forkToChallenge].begin() + k, unchallengedForks[forkToChallenge].end());
                        }
                    }
                }
            }

            // if we have challenge requests, get them to either submit rejections or add to our notarization, if it challenges
            // a pre-existing notarization. we decide which later on
            if (challenges.size())
            {
                LogPrint("notarization", "Getting challenge proofs from local chain %s\n", challenges.write(1,2).c_str());
                params = UniValue(UniValue::VARR);
                params.push_back(challenges);
                try
                {
                    challenges = getnotarizationproofs(params, false);
                } catch (exception e)
                {
                    challenges = NullUniValue;
                }
                LogPrint("notarization", "Challenge proofs returned from local chain %s\n", challenges.write(1,2).c_str());
            }

            // if we have challenges, submit them
            if (challenges.size())
            {
                UniValue submitParams(UniValue::VARR);
                for (int i = 0; i < challenges.size(); i++)
                {
                    if (find_value(challenges[i], "error").isNull())
                    {
                        UniValue resultUni = find_value(challenges[i], "result");
                        if (resultUni.isObject())
                        {
                            submitParams.push_back(resultUni);
                        }
                    }
                    else
                    {
                        LogPrint("notarization", "Error getting challenge evidence %s\n", submitParams.write(1,2).c_str());
                    }
                }
                if (submitParams.size())
                {
                    LogPrint("notarization", "Submitting challenges %s\n", submitParams.write(1,2).c_str());
                    UniValue challengeResult;
                    params = UniValue(UniValue::VARR);
                    params.push_back(submitParams);
                    try
                    {
                        challengeResult = find_value(RPCCallRoot("submitchallenges", params), "result");
                    } catch (exception e)
                    {
                        challengeResult = NullUniValue;
                    }
                    LogPrint("notarization", "Response from challenges %s\n", challengeResult.write(1,2).c_str());
                }
            }
        }
    }

    // get our best index to update next notarization's proof root
    int32_t notaryIdx = prunedCND.forks[prunedCND.bestChain].back();

    UniValue lastConfirmedUni = find_value(bestProofRootResult, "lastconfirmedproofroot");
    CProofRoot lastConfirmedProofRoot;
    if (!lastConfirmedUni.isNull())
    {
        lastConfirmedProofRoot = CProofRoot(lastConfirmedUni);
    }

    if (bestProofRootResult.isNull() || notaryIdx == -1)
    {
        return state.Error(bestProofRootResult.isNull() ? "no-notary" : "no-matching-proof-roots-found");
    }

    CProofRoot lastStableProofRoot(find_value(bestProofRootResult, "laststableproofroot"));

    // if last confirmed is valid, we can't select a later height for our notaryIdx than that or last stable
    uint32_t earliestHeight = lastConfirmedProofRoot.IsValid() ? lastConfirmedProofRoot.rootHeight : lastStableProofRoot.rootHeight;
    if (lastConfirmedProofRoot.IsValid() &&
        prunedCND.vtx[notaryIdx].second.proofRoots[SystemID].rootHeight > earliestHeight)
    {
        // we need to go backwards in the best chain fork to a height as early or earlier
        int i;
        for (i = prunedCND.forks[prunedCND.bestChain].size() - 2; i > 0; i--)
        {
            auto rootIt = prunedCND.vtx[prunedCND.forks[prunedCND.bestChain][i]].second.proofRoots.find(SystemID);
            if (rootIt != prunedCND.vtx[prunedCND.forks[prunedCND.bestChain][i]].second.proofRoots.end() &&
                rootIt->second.rootHeight <= earliestHeight)
            {
                break;
            }
        }
        notaryIdx = prunedCND.forks[prunedCND.bestChain][i];
    }

    // if the notarization we are planning to confirm has counter evidence, then
    // don't try if hopeless
    for (auto &oneChallenge : localCounterEvidence[notaryIdx])
    {
        if (!std::get<1>(oneChallenge).evidence.chainObjects.size() ||
            std::get<1>(oneChallenge).evidence.chainObjects[0]->objectType != CHAINOBJ_PROOF_ROOT)
        {
            continue;
        }
        // if the challenge root is the same as the root being challenged, it is a skip challenge
        // and would not be on-chain or in mempool if not valid. we cannot confirm this notarization
        if (((CChainObject<CProofRoot> *)std::get<1>(oneChallenge).evidence.chainObjects[0])->object ==
            cnd.vtx[notaryIdx].second.proofRoots[SystemID])
        {
            continue;
        }
        break;
    }

    // if we have challenge requests, get them to either submit rejections or add to our notarization, if it challenges
    // a pre-existing notarization. we decide which later
    CNotaryEvidence notarizationEvidence(CNotaryEvidence::TYPE_NOTARY_EVIDENCE, CNotaryEvidence::VERSION_INVALID);

    // get the latest notarization information for the new, earned notarization
    // one system may provide one proof root and multiple currency states
    CProofRoot latestProofRoot = lastConfirmedProofRoot.IsValid() ? lastConfirmedProofRoot : lastStableProofRoot;
    if (externalSystem.chainDefinition.IsPBaaSChain() && cnd.vtx[notaryIdx].second.proofRoots.count(SystemID))
    {
        notarizationEvidence = CNotaryEvidence(CNotaryEvidence::TYPE_NOTARY_EVIDENCE,
                                                CNotaryEvidence::VERSION_CURRENT,
                                                CNotaryEvidence::STATE_CONFIRMED,
                                                SystemID);

        notarizationEvidence.output = cnd.vtx[notaryIdx].first;

        auto lastConfirmedRootIt = cnd.vtx[cnd.lastConfirmed].second.proofRoots.find(SystemID);
        if (lastConfirmedRootIt != cnd.vtx[cnd.lastConfirmed].second.proofRoots.end() &&
            latestProofRoot.rootHeight <= lastConfirmedRootIt->second.rootHeight)
        {
            // if there is no change in proof root, we need no evidence to support a new notarization
            latestProofRoot = lastConfirmedRootIt->second;
        }
        if (latestProofRoot.IsValid())
        {
            // if we have challenge roots, add them to our
            // request for proof along with challenges
            UniValue newProofRequest(UniValue::VOBJ);

            newProofRequest.pushKV("type", EncodeDestination(CIdentityID(CNotaryEvidence::PrimaryProofKey())));
            newProofRequest.pushKV("priorroot", cnd.vtx[notaryIdx].second.proofRoots[SystemID].ToUniValue());
            if (challengeRoots.size())
            {
                newProofRequest.pushKV("challengeroots", challengeRoots);
            }
            newProofRequest.pushKV("evidence", notarizationEvidence.ToUniValue());
            newProofRequest.pushKV("confirmroot", latestProofRoot.ToUniValue());
            newProofRequest.pushKV("entropyhash", txes[notaryIdx].second.GetHex());
            newProofRequest.pushKV("fromheight", (int64_t)cnd.vtx[cnd.lastConfirmed].second.proofRoots[SystemID].rootHeight);
            newProofRequest.pushKV("toheight", (int64_t)latestProofRoot.rootHeight);
            challengeRequests.push_back(newProofRequest);
        }

        if (challengeRequests.size())
        {
            LogPrint("notarization", "Getting notarization proofs %s\n", challengeRequests.write(1,2).c_str());
            params = UniValue(UniValue::VARR);
            params.push_back(challengeRequests);
            try
            {
                challengeRequests = find_value(RPCCallRoot("getnotarizationproofs", params), "result");
            } catch (exception e)
            {
                challengeRequests = NullUniValue;
            }
            LogPrint("notarization", "Challenge notarization returned %s\n", challengeRequests.write(1,2).c_str());
        }

        // separate out skip challenges and submit those now to ensure they just get removed from the equation
        UniValue skipChallenges(UniValue::VARR);
        for (int j = 0; j < challengeRequests.size(); j++)
        {
            UniValue oneChallengeUni;
            if (find_value(challengeRequests[j], "error").isNull() &&
                (oneChallengeUni = find_value(challengeRequests[j], "result")).isObject())
            {
                if (ParseVDXFKey(uni_get_str(find_value(oneChallengeUni, "type"))) == CNotaryEvidence::SkipChallengeKey())
                {
                    skipChallenges.push_back(oneChallengeUni);
                }
                else if (ParseVDXFKey(uni_get_str(find_value(oneChallengeUni, "type"))) == CNotaryEvidence::PrimaryProofKey())
                {
                    // primary proof will be used to support our notarization
                    notarizationEvidence = CNotaryEvidence(find_value(oneChallengeUni, "evidence"));
                }
            }
            else if (LogAcceptCategory("notarization") && !find_value(challengeRequests[j], "error").isNull())
            {
                LogPrintf("%s: cross-chain API error: %s\n", find_value(challengeRequests[j], "error").write().c_str());
            }
        }

        if (!notarizationEvidence.IsValid())
        {
            return state.Error("cannot-get-valid-evidence");
        }

        if (skipChallenges.size())
        {
            LogPrint("notarization", "Submitting skip challenges to local chain %s\n", skipChallenges.write(1,2).c_str());
            params = UniValue(UniValue::VARR);
            params.push_back(skipChallenges);
            try
            {
                UniValue submitchallenges(const UniValue& params, bool fHelp);
                skipChallenges = submitchallenges(params, false);
            } catch (exception e)
            {
                skipChallenges = NullUniValue;
            }
            LogPrint("notarization", "Results of submissions returned from local chain %s\n", skipChallenges.write(1,2).c_str());
        }
    }

    if (!latestProofRoot.IsValid() || notarization.proofRoots[latestProofRoot.systemID].rootHeight > latestProofRoot.rootHeight)
    {
        return state.Error("cannot-regress-stable-proof-root");
    }

    {
        // take the lock again, now that we're back from calling out
        LOCK2(cs_main, mempool.cs);

        // if height changed, we need to fail and possibly try again
        if (height != chainActive.Height())
        {
            return state.Error("stale-block");
        }

        const CTransaction &priorNotarizationTx = txes[notaryIdx].first;
        uint256 priorBlkHash = txes[notaryIdx].second;
        const CUTXORef &priorUTXO = cnd.vtx[notaryIdx].first;
        const CPBaaSNotarization &priorNotarization = cnd.vtx[notaryIdx].second;

        // get block index holding the last notarization we agree with
        auto mapBlockIt = mapBlockIndex.find(priorBlkHash);
        if (mapBlockIt == mapBlockIndex.end() || !chainActive.Contains(mapBlockIt->second))
        {
            return state.Error(errorPrefix + "prior notarization not in blockchain");
        }

        // first determine if the prior notarization we agree with would make this one moot, given the current
        // block notarization modulo
        uint32_t adjustedNotarizationModulo = CPBaaSNotarization::GetAdjustedNotarizationModulo(ConnectedChains.ThisChain().blockNotarizationModulo,
                                                                                                mapBlockIndex[txes[cnd.lastConfirmed].second]->GetHeight(),
                                                                                                (height + 1));

        int blockPeriodNumber = height / adjustedNotarizationModulo;
        int priorBlockPeriod = priorNotarization.proofRoots.count(ASSETCHAINS_CHAINID) ?
                                priorNotarization.proofRoots.find(ASSETCHAINS_CHAINID)->second.rootHeight / adjustedNotarizationModulo :
                                0;

        // for decentralized notarization, we must alternate between proof of stake and proof of work blocks
        // to confirm a prior earned notarization
        if (blockPeriodNumber <= priorBlockPeriod ||
            (height >= CPBaaSNotarization::BlocksBeforeAlternateStakeEnforcement() &&
             ((ConnectedChains.ThisChain().notarizationProtocol == CCurrencyDefinition::NOTARIZATION_AUTO ||
               ConnectedChains.ThisChain().notarizationProtocol == CCurrencyDefinition::NOTARIZATION_NOTARY_CONFIRM ||
               ConnectedChains.ThisChain().notarizationProtocol == CCurrencyDefinition::NOTARIZATION_NOTARY_CHAINID) &&
              isStake == mapBlockIt->second->IsVerusPOSBlock())))
        {
            if (LogAcceptCategory("notarization"))
            {
                LogPrintf("%s: block period #%d, prior block period #%d, height: %u, notarization protocol: %d, isPoS: %s, is last notarization PoS: %s\n",
                        __func__,
                        blockPeriodNumber,
                        priorBlockPeriod,
                        height,
                        ConnectedChains.ThisChain().notarizationProtocol,
                        isStake ? "true" : "false",
                        mapBlockIt->second->IsVerusPOSBlock() ? "true" : "false");
                if (LogAcceptCategory("verbose"))
                {
                    printf("%s: block period #%d, prior block period #%d, height: %u, notarization protocol: %d, isPoS: %s, is last notarization PoS: %s\n",
                            __func__,
                            blockPeriodNumber,
                            priorBlockPeriod,
                            height,
                            ConnectedChains.ThisChain().notarizationProtocol,
                            isStake ? "true" : "false",
                            mapBlockIt->second->IsVerusPOSBlock() ? "true" : "false");
                }
            }
            return state.Error("ineligible");
        }

        notarization = priorNotarization;
        notarization.SetBlockOneNotarization(false);
        notarization.SetDefinitionNotarization(false);
        notarization.SetSameChain(false);
        notarization.SetPreLaunch(false);
        notarization.SetLaunchCleared(true);
        notarization.SetLaunchConfirmed(true);
        notarization.proposer = Proposer;
        notarization.prevHeight = priorNotarization.notarizationHeight;

        // remove any proof roots from other cross-chain imports that may have been put into the proof root array
        std::set<uint160> proofRootsToDelete;
        for (auto &oneProofRoot : notarization.proofRoots)
        {
            if (oneProofRoot.first != ASSETCHAINS_CHAINID)
            {
                proofRootsToDelete.insert(oneProofRoot.first);
            }
        }
        for (auto &oneProofRootID : proofRootsToDelete)
        {
            notarization.proofRoots.erase(oneProofRootID);
        }

        notarization.proofRoots[latestProofRoot.systemID] = latestProofRoot;
        notarization.notarizationHeight = latestProofRoot.rootHeight;

        // this is cross-checked to ensure that the correct/consensus gas price
        // is passed through and used at all times
        if (systemDef.proofProtocol == systemDef.PROOF_ETHNOTARIZATION &&
            notarization.currencyState.conversionPrice.size())
        {
            notarization.currencyState.conversionPrice[0] = latestProofRoot.gasPrice;
        }

        UniValue currencyStatesUni = find_value(bestProofRootResult, "currencystates");

        if (!systemDef.IsGateway() && !(currencyStatesUni.isArray() && currencyStatesUni.size()))
        {
            return state.Error(errorPrefix + "invalid or missing currency state data from notary chain");
        }

        if (crosschainCND.vtx.size())
        {
            int prevNotarizationIdx;
            CPBaaSNotarization lastPBN;
            for (prevNotarizationIdx = crosschainCND.vtx.size() - 1; prevNotarizationIdx >= 0; prevNotarizationIdx--)
            {
                if (invalidCrossChainIndexSet.count(prevNotarizationIdx))
                {
                    continue;
                }
                lastPBN = crosschainCND.vtx[prevNotarizationIdx].second;
                std::map<uint160, CProofRoot>::iterator pIT = lastPBN.proofRoots.find(ASSETCHAINS_CHAINID);
                if (pIT != lastPBN.proofRoots.end() &&
                    (!priorNotarization.proofRoots.count(ASSETCHAINS_CHAINID) ||
                     pIT->second.rootHeight <= priorNotarization.proofRoots.find(ASSETCHAINS_CHAINID)->second.rootHeight) &&
                     CProofRoot::GetProofRoot(pIT->second.rootHeight) == pIT->second)
                {
                    break;
                }
                else if ((pIT == lastPBN.proofRoots.end() || !priorNotarization.proofRoots.count(ASSETCHAINS_CHAINID)) &&
                          !prevNotarizationIdx &&
                          (crosschainCND.vtx[prevNotarizationIdx].second.IsDefinitionNotarization() ||
                           (crosschainCND.vtx[prevNotarizationIdx].second.IsPreLaunch() &&
                            crosschainCND.vtx[prevNotarizationIdx].second.IsLaunchConfirmed())))
                {
                    // use the 0th element if no proof root and it is definition or start, since it has no proof root to be wrong
                    break;
                }
            }
            if (prevNotarizationIdx >= 0 &&
                lastPBN.IsValid() &&
                lastPBN.SetMirror(false) &&
                !lastPBN.IsMirror())
            {
                if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                {
                    std::vector<unsigned char> checkHex = ::AsVector(lastPBN);
                    LogPrintf("%s: hex of prior notarization: %s\nnotarization: %s\n", __func__, HexBytes(&(checkHex[0]), checkHex.size()).c_str(), lastPBN.ToUniValue().write(1,2).c_str());
                    printf("%s: prior notarization: %s\n", __func__, lastPBN.ToUniValue().write(1,2).c_str());
                }

                CNativeHashWriter hw;
                hw << lastPBN;
                notarization.hashPrevCrossNotarization = hw.GetHash();
            }
            else
            {
                return state.Error(errorPrefix + "cannot get a valid cross chain prior confirmed notarization to create earned notarization");
            }
        }

        notarization.currencyStates.clear();
        bool useLastCurrencyState = priorNotarization.proofRoots.count(SystemID) &&
                                        latestProofRoot.rootHeight == priorNotarization.proofRoots.find(SystemID)->second.rootHeight ?
                                    true : false;
        for (int i = 0; i < currencyStatesUni.size(); i++)
        {
            CCoinbaseCurrencyState oneCurState(currencyStatesUni[i]);
            CCurrencyDefinition oneCurDef;

            if (useLastCurrencyState &&
                priorNotarization.currencyID != oneCurState.GetID() &&
                !priorNotarization.currencyStates.count(oneCurState.GetID()))
            {
                // don't include new currency states if nothing should change
                continue;
            }
            if (!oneCurState.IsValid())
            {
                return state.Error(errorPrefix + "invalid or missing currency state data from notary");
            }
            if (!(oneCurDef = ConnectedChains.GetCachedCurrency(oneCurState.GetID())).IsValid())
            {
                // if we don't have the currency for the state specified, and it isn't critical, ignore
                if (oneCurDef.GetID() == SystemID)
                {
                    return state.Error(errorPrefix + "system currency invalid - possible corruption");
                }
                continue;
            }
            if (oneCurDef.systemID == SystemID)
            {
                uint160 oneCurDefID = oneCurDef.GetID();
                if (notarization.currencyID == oneCurDefID)
                {
                    notarization.currencyState = useLastCurrencyState ? priorNotarization.currencyState : oneCurState;
                }
                else
                {
                    notarization.currencyStates[oneCurDefID] = useLastCurrencyState ?
                        priorNotarization.currencyStates.find(oneCurDefID)->second :
                        oneCurState;
                }
            }
        }
        notarization.currencyStates[ASSETCHAINS_CHAINID] = ConnectedChains.GetCurrencyState(height);
        if (!systemDef.GatewayConverterID().IsNull())
        {
            notarization.currencyStates[systemDef.GatewayConverterID()] = ConnectedChains.GetCurrencyState(systemDef.GatewayConverterID(), height);
        }

        // add this blockchain's info, based on the requested height
        uint160 thisChainID = ConnectedChains.ThisChain().GetID();
        notarization.proofRoots[thisChainID] = CProofRoot::GetProofRoot(height);

        // add currency states that we should include and then we're done
        // currency states to include are either a gateway currency indicated by the
        // gateway or our gateway converter for our PBaaS chain
        uint160 gatewayConverterID = systemDef.GatewayConverterID();
        if (systemDef.IsGateway() && (!systemDef.GatewayConverterID().IsNull()))
        {
            gatewayConverterID = systemDef.GatewayConverterID();
        }
        else if (SystemID == ConnectedChains.FirstNotaryChain().chainDefinition.GetID() && !ConnectedChains.ThisChain().GatewayConverterID().IsNull())
        {
            gatewayConverterID = ConnectedChains.ThisChain().GatewayConverterID();
        }
        if (!gatewayConverterID.IsNull())
        {
            // get the gateway converter currency from the gateway definition
            CChainNotarizationData gatewayCND;
            if (GetNotarizationData(gatewayConverterID, gatewayCND) && gatewayCND.vtx.size())
            {
                notarization.currencyStates[gatewayConverterID] = gatewayCND.vtx[gatewayCND.lastConfirmed].second.currencyState;
            }
        }

        notarization.nodes = GetGoodNodes(CPBaaSNotarization::MAX_NODES);

        notarization.prevNotarization = cnd.vtx[notaryIdx].first;
        notarization.prevHeight = cnd.vtx[notaryIdx].second.notarizationHeight;

        notarization.SetContractUpgrade(APPROVE_CONTRACT_UPGRADE, APPROVE_CONTRACT_UPGRADE.IsValid() && APPROVE_CONTRACT_UPGRADE.TypeNoFlags() == APPROVE_CONTRACT_UPGRADE.DEST_ETH);

        CCcontract_info CC;
        CCcontract_info *cp;
        std::vector<CTxDestination> dests;

        // make the earned notarization output
        cp = CCinit(&CC, EVAL_EARNEDNOTARIZATION);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

        txOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_EARNEDNOTARIZATION, dests, 1, &notarization))));
        int notarizationOutNum = txOutputs.size() - 1;

        std::vector<int32_t> evidenceOuts;
        if (notarizationEvidence.HasEvidence())
        {
            notarizationEvidence.output = CUTXORef(uint256(), notarizationOutNum);
            // now add the notary evidence and finalization that uses it to assert validity
            // make the evidence notarization output
            cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

            COptCCParams chkP;
            CScript evidenceOutScript = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &notarizationEvidence));
            if (!evidenceOutScript.IsPayToCryptoCondition(chkP, false))
            {
                LogPrintf("%s: failed to package evidence script from system %s\n", __func__, EncodeDestination(CIdentityID(SystemID)).c_str());
                return false;
            }

            // the value should be considered for reduction
            if (evidenceOutScript.size() >= CScript::MAX_SCRIPT_ELEMENT_SIZE)
            {
                CNotaryEvidence emptyEvidence;
                int baseOverhead = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &emptyEvidence)).size() + 128;
                auto evidenceVec = notarizationEvidence.BreakApart(CScript::MAX_SCRIPT_ELEMENT_SIZE - baseOverhead);
                if (!evidenceVec.size())
                {
                    LogPrintf("%s: failed to package evidence from system %s\n", __func__, EncodeDestination(CIdentityID(SystemID)).c_str());
                    return false;
                }
                for (auto &oneProof : evidenceVec)
                {
                    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
                    evidenceOuts.push_back(txOutputs.size());
                    txOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &oneProof))));
                }
            }
            else
            {
                evidenceOuts.push_back(txOutputs.size());
                txOutputs.push_back(CTxOut(0, evidenceOutScript));
            }
        }

        // make the finalization output(s)
        //
        cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);

        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

        // we need to store the input that we confirmed if we spent finalization outputs
        CObjectFinalization of = CObjectFinalization(CObjectFinalization::FINALIZE_NOTARIZATION,
                                                     notarization.currencyID,
                                                     uint256(),
                                                     notarizationOutNum,
                                                     height + 1);
        of.evidenceOutputs = evidenceOuts;
        txOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &of))));
    }
    return true;
}

std::vector<std::pair<uint32_t, CInputDescriptor>> CObjectFinalization::GetUnspentConfirmedFinalizations(const uint160 &currencyID)
{
    LOCK(mempool.cs);
    std::vector<std::pair<uint32_t, CInputDescriptor>> retVal;

    uint160 indexKey = CCrossChainRPCData::GetConditionID(
        CCrossChainRPCData::GetConditionID(currencyID, CObjectFinalization::ObjectFinalizationNotarizationKey()),
        ObjectFinalizationConfirmedKey());

    std::vector<std::pair<CInputDescriptor, uint32_t>> outputs;
    if (ConnectedChains.GetUnspentByIndex(indexKey, outputs))
    {
        for (auto &oneOutput : outputs)
        {
            retVal.push_back(std::make_pair(oneOutput.second, oneOutput.first));
        }
    }
    return retVal;
}

std::vector<std::pair<uint32_t, CInputDescriptor>> CObjectFinalization::GetUnspentPendingFinalizations(const uint160 &currencyID)
{
    LOCK(mempool.cs);
    std::vector<std::pair<uint32_t, CInputDescriptor>> retVal;

    uint160 indexKey = CCrossChainRPCData::GetConditionID(
        CCrossChainRPCData::GetConditionID(currencyID, CObjectFinalization::ObjectFinalizationNotarizationKey()),
        ObjectFinalizationPendingKey());

    std::vector<std::pair<CInputDescriptor, uint32_t>> outputs;
    if (ConnectedChains.GetUnspentByIndex(indexKey, outputs))
    {
        for (auto &oneOutput : outputs)
        {
            retVal.push_back(std::make_pair(oneOutput.second, oneOutput.first));
        }
    }
    return retVal;
}

std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization>>
CObjectFinalization::GetFinalizations(const uint160 &currencyID,
                                      const uint160 &finalizationTypeKey,
                                      uint32_t startHeight,
                                      uint32_t endHeight)
{
    // if we don't have an endHeight, we also check the mempool
    bool checkMempool = false;
    if (!endHeight)
    {
        checkMempool = true;
    }

    std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization>> retVal;
    std::vector<CAddressIndexDbEntry> finalizationIndex;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> mempoolFinalizations;

    uint160 indexKey = CCrossChainRPCData::GetConditionID(
        CCrossChainRPCData::GetConditionID(currencyID, CObjectFinalization::ObjectFinalizationNotarizationKey()),
        finalizationTypeKey);

    LOCK(mempool.cs);

    if (checkMempool)
    {
        mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{indexKey, CScript::P2IDX}}), mempoolFinalizations);
    }
    std::set<COutPoint> spentInMempool;
    auto filteredMempoolOuts = mempool.FilterUnspent(mempoolFinalizations, spentInMempool);

    if (GetAddressIndex(indexKey, CScript::P2IDX, finalizationIndex, startHeight, endHeight) &&
        (finalizationIndex.size() || filteredMempoolOuts.size()))
    {
        std::vector<int> toRemove;
        std::map<COutPoint, int> outputMap;
        for (int i = 0; i < finalizationIndex.size(); i++)
        {
            if (!finalizationIndex[i].first.spending &&
                !spentInMempool.count(COutPoint(finalizationIndex[i].first.txhash, finalizationIndex[i].first.index)))
            {
                CTransaction finalizationTx;
                CObjectFinalization of;
                uint256 blkHash;
                COptCCParams fP;
                if (!myGetTransaction(finalizationIndex[i].first.txhash, finalizationTx, blkHash) ||
                    finalizationIndex[i].first.index >= finalizationTx.vout.size() ||
                    !(finalizationTx.vout[finalizationIndex[i].first.index].scriptPubKey.IsPayToCryptoCondition(fP) &&
                        fP.IsValid() &&
                        fP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                        fP.vData.size() &&
                        (of = CObjectFinalization(fP.vData[0])).IsValid()))
                {
                    LogPrintf("Invalid finalization transaction %s:\n", finalizationIndex[i].first.txhash.GetHex().c_str());
                    printf("Invalid finalization transaction %s:\n", finalizationIndex[i].first.txhash.GetHex().c_str());
                    return retVal;
                }
                retVal.push_back(std::make_tuple((uint32_t)finalizationIndex[i].first.blockHeight,
                                                 COutPoint(finalizationIndex[i].first.txhash,
                                                 finalizationIndex[i].first.index),
                                                 finalizationTx, of));
            }
        }
        for (int i = 0; i < filteredMempoolOuts.size(); i++)
        {
            CTransaction oneTx;
            if (mempool.lookup(filteredMempoolOuts[i].first.txhash, oneTx))
            {
                retVal.push_back(std::make_tuple((uint32_t)0,
                                                  COutPoint(filteredMempoolOuts[i].first.txhash, filteredMempoolOuts[i].first.index),
                                                  oneTx,
                                                  CObjectFinalization(oneTx.vout[filteredMempoolOuts[i].first.index].scriptPubKey)));
            }
        }
    }
    return retVal;
}

std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization>>
CObjectFinalization::GetFinalizations(const CUTXORef &outputRef,
                                      const uint160 &finalizationTypeKey,
                                      uint32_t startHeight,
                                      uint32_t endHeight)
{
    // if we don't have an endHeight, we also check the mempool
    bool checkMempool = false;
    if (!endHeight)
    {
        checkMempool = true;
    }

    std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization>> retVal;
    std::vector<CAddressIndexDbEntry> finalizationIndex;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> mempoolFinalizations;

    uint160 indexKey = CCrossChainRPCData::GetConditionID(finalizationTypeKey, outputRef.hash, outputRef.n);

    LOCK(mempool.cs);

    if (GetAddressIndex(indexKey, CScript::P2IDX, finalizationIndex, startHeight, endHeight) &&
        finalizationIndex.size() &&
        (!checkMempool || mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{indexKey, CScript::P2IDX}}), mempoolFinalizations)) &&
        (finalizationIndex.size() || mempoolFinalizations.size()))
    {
        std::vector<int> toRemove;
        std::map<COutPoint, int> outputMap;
        for (int i = 0; i < finalizationIndex.size(); i++)
        {
            if (!finalizationIndex[i].first.spending)
            {
                CTransaction finalizationTx;
                CObjectFinalization of;
                uint256 blkHash;
                COptCCParams fP;
                if (!myGetTransaction(finalizationIndex[i].first.txhash, finalizationTx, blkHash) ||
                    finalizationIndex[i].first.index >= finalizationTx.vout.size() ||
                    !(finalizationTx.vout[finalizationIndex[i].first.index].scriptPubKey.IsPayToCryptoCondition(fP) &&
                        fP.IsValid() &&
                        fP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                        fP.vData.size() &&
                        (of = CObjectFinalization(fP.vData[0])).IsValid()))
                {
                    LogPrintf("Invalid finalization transaction %s:\n", finalizationIndex[i].first.txhash.GetHex().c_str());
                    printf("Invalid finalization transaction %s:\n", finalizationIndex[i].first.txhash.GetHex().c_str());
                    return retVal;
                }
                retVal.push_back(std::make_tuple((uint32_t)finalizationIndex[i].first.blockHeight,
                                                 COutPoint(finalizationIndex[i].first.txhash,
                                                 finalizationIndex[i].first.index),
                                                 finalizationTx, of));
            }
        }
        for (int i = 0; i < mempoolFinalizations.size(); i++)
        {
            if (mempoolFinalizations[i].first.spending)
            {
                continue;
            }
            CTransaction oneTx;
            if (mempool.lookup(mempoolFinalizations[i].first.txhash, oneTx))
            {
                retVal.push_back(std::make_tuple((uint32_t)0,
                                                  COutPoint(mempoolFinalizations[i].first.txhash, mempoolFinalizations[i].first.index),
                                                  oneTx,
                                                  CObjectFinalization(oneTx.vout[mempoolFinalizations[i].first.index].scriptPubKey)));
            }
        }
    }

    // look for a finalization on the original notarization transaction to add
    CObjectFinalization oneOF;
    CTransaction notarizationTx;
    uint256 blockHash;
    BlockMap::iterator blockIt;
    if (outputRef.GetOutputTransaction(notarizationTx, blockHash) &&
        (blockIt = mapBlockIndex.find(blockHash)) != mapBlockIndex.end() &&
        chainActive.Contains(blockIt->second))
    {
        int i;
        for (i = outputRef.n + 1; i < notarizationTx.vout.size(); i++)
        {
            COptCCParams p;
            if (notarizationTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                (oneOF = CObjectFinalization(p.vData[0])).IsValid() &&
                oneOF.output.hash.IsNull() &&
                oneOF.output.n == outputRef.n)
            {
                break;
            }
        }
        if (i < notarizationTx.vout.size() &&
            ((oneOF.IsPending() && finalizationTypeKey == oneOF.ObjectFinalizationPendingKey()) ||
             (oneOF.IsConfirmed() && (finalizationTypeKey == oneOF.ObjectFinalizationFinalizedKey() ||
                                      finalizationTypeKey == oneOF.ObjectFinalizationConfirmedKey())) ||
             (oneOF.IsRejected() && (finalizationTypeKey == oneOF.ObjectFinalizationFinalizedKey() ||
                                      finalizationTypeKey == oneOF.ObjectFinalizationRejectedKey()))))
        {
            retVal.push_back(std::make_tuple(blockIt->second->GetHeight(),
                                             outputRef,
                                             notarizationTx,
                                             CObjectFinalization(notarizationTx.vout[i].scriptPubKey)));
        }
    }
    return retVal;
}

std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CPBaaSNotarization>>
GetOutputKeyedNotarizations(const CUTXORef &outputRef,
                            const uint160 &typeKey,
                            uint32_t startHeight,
                            uint32_t endHeight)
{
    // if we don't have an endHeight, we also check the mempool
    bool checkMempool = false;
    if (!endHeight)
    {
        checkMempool = true;
    }

    std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CPBaaSNotarization>> retVal;
    std::vector<CAddressIndexDbEntry> finalizationIndex;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> mempoolFinalizations;

    uint160 indexKey = CCrossChainRPCData::GetConditionID(typeKey, outputRef.hash, outputRef.n);

    LOCK(mempool.cs);

    if (GetAddressIndex(indexKey, CScript::P2IDX, finalizationIndex, startHeight, endHeight) &&
        finalizationIndex.size() &&
        (!checkMempool || mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{indexKey, CScript::P2IDX}}), mempoolFinalizations)) &&
        (finalizationIndex.size() || mempoolFinalizations.size()))
    {
        std::vector<int> toRemove;
        std::map<COutPoint, int> outputMap;
        for (int i = 0; i < finalizationIndex.size(); i++)
        {
            if (!finalizationIndex[i].first.spending)
            {
                CTransaction notarizationTx;
                CPBaaSNotarization notarization;
                uint256 blkHash;
                COptCCParams fP;
                if (!myGetTransaction(finalizationIndex[i].first.txhash, notarizationTx, blkHash) ||
                    finalizationIndex[i].first.index >= notarizationTx.vout.size() ||
                    !(notarizationTx.vout[finalizationIndex[i].first.index].scriptPubKey.IsPayToCryptoCondition(fP) &&
                        fP.IsValid() &&
                        (fP.evalCode == EVAL_EARNEDNOTARIZATION || fP.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
                        fP.vData.size() &&
                        (notarization = CPBaaSNotarization(fP.vData[0])).IsValid()))
                {
                    LogPrintf("Invalid notarization transaction %s:\n", finalizationIndex[i].first.txhash.GetHex().c_str());
                    printf("Invalid notarization transaction %s:\n", finalizationIndex[i].first.txhash.GetHex().c_str());
                    return retVal;
                }
                retVal.push_back(std::make_tuple((uint32_t)finalizationIndex[i].first.blockHeight,
                                                  COutPoint(finalizationIndex[i].first.txhash,
                                                  finalizationIndex[i].first.index),
                                                  notarizationTx,
                                                  notarization));
            }
        }
        for (int i = 0; i < mempoolFinalizations.size(); i++)
        {
            if (mempoolFinalizations[i].first.spending)
            {
                continue;
            }
            CTransaction oneTx;
            if (mempool.lookup(mempoolFinalizations[i].first.txhash, oneTx))
            {
                retVal.push_back(std::make_tuple((uint32_t)0,
                                                  COutPoint(mempoolFinalizations[i].first.txhash, mempoolFinalizations[i].first.index),
                                                  oneTx,
                                                  CPBaaSNotarization(oneTx.vout[mempoolFinalizations[i].first.index].scriptPubKey)));
            }
        }
    }
    return retVal;
}

std::vector<std::pair<uint32_t, CInputDescriptor>> CObjectFinalization::GetUnspentEvidence(const uint160 &currencyID,
                                                                                           const uint256 &notarizationTxId,
                                                                                           int32_t notarizationOutNum)
{
    LOCK(mempool.cs);
    std::vector<std::pair<uint32_t, CInputDescriptor>> retVal;
    uint160 indexKey = CCrossChainRPCData::GetConditionID(CNotaryEvidence::NotarySignatureKey(), notarizationTxId, notarizationOutNum);

    std::vector<std::pair<CInputDescriptor, uint32_t>> outputs;
    if (ConnectedChains.GetUnspentByIndex(indexKey, outputs))
    {
        for (auto &oneOutput : outputs)
        {
            retVal.push_back(std::make_pair(oneOutput.second, oneOutput.first));
        }
    }
    return retVal;
}

int CChainNotarizationData::BestConfirmedNotarization(const CCurrencyDefinition &notarizingSystem,
                                                      int minNotaryConfirms,
                                                      int minBlockConfirms,
                                                      uint32_t height,
                                                      uint32_t lastConfirmedHeight,
                                                      const std::vector<std::pair<CTransaction, uint256>> &txAndBlockVec) const
{
    int maxDepth = ((lastConfirmedHeight / notarizingSystem.blockNotarizationModulo) + 1) * notarizingSystem.blockNotarizationModulo;

    uint160 notarizingSystemID = notarizingSystem.GetID();

    BlockMap::iterator blockIt;
    if (!vtx.size() ||
        (!IsConfirmed() && !vtx[0].second.IsDefinitionNotarization()) ||
        forks[bestChain].size() <= minNotaryConfirms ||
        !((blockIt = mapBlockIndex.find(txAndBlockVec[forks[bestChain].back()].second)) != mapBlockIndex.end() &&
          (height - blockIt->second->GetHeight()) > 0 &&
          (height - blockIt->second->GetHeight()) <= maxDepth))
    {
        return -1;
    }

    if (notarizingSystem.IsPBaaSChain())
    {
        // no conflict from greater work chain since last notarization
        if (!(vtx.size() >= 1 &&
              *forks[bestChain].rbegin() == (vtx.size() - 1)))
        {
            // if we do have a conflict, make sure it's not a chain with more power, and if so, can't confirm
            int nIdx;
            for (nIdx = *forks[bestChain].rbegin(); nIdx < vtx.size(); nIdx++)
            {
                if (CChainPower::ExpandCompactPower(vtx[nIdx].second.proofRoots.find(notarizingSystemID)->second.compactPower) >
                    CChainPower::ExpandCompactPower(vtx[*forks[bestChain].rbegin()].second.proofRoots.find(notarizingSystemID)->second.compactPower))
                {
                    break;
                }
            }
            if (nIdx < vtx.size())
            {
                LogPrintf("%s: must have last period unchallenged by more powerful chain to confirm notarization for system: %s\n", __func__, ConnectedChains.GetFriendlyCurrencyName(notarizingSystemID).c_str());
                return -1;
            }
        }
        auto targetIt = forks[bestChain].rbegin() + minNotaryConfirms;
        for (;
             targetIt != forks[bestChain].rend();
             targetIt++)
        {
            blockIt = mapBlockIndex.find(txAndBlockVec[*targetIt].second);
            if (blockIt == mapBlockIndex.end())
            {
                LogPrintf("%s: invalid block hash in notarization data for system: %s\n", __func__, ConnectedChains.GetFriendlyCurrencyName(notarizingSystemID).c_str());
                return -1;
            }
            if ((height - blockIt->second->GetHeight()) >= minBlockConfirms)
            {
                break;
            }
        }
        if (targetIt == forks[bestChain].rend())
        {
            return -1;
        }

        return *targetIt;
    }
    else
    {
        // if notarizing a gateway or non-PBaaS chain, don't assume
        // the concept of "more power" is enough
        uint160 currencyID = vtx[0].second.currencyID;

        std::vector<int> bestFork;
        if (forks.size() > 1)
        {
            // need to get most recent forks. if we have
            // no conflict for the past 3 earned notarizations,
            // we are good to confirm, otherwise after 10 blocks, the one
            // that ends up > 2 longer can be notarized/finalized.
            std::multimap<int, std::pair<int, int>> forkAndIndexByBlock;
            for (int i = 0; i < forks.size(); i++)
            {
                auto &oneFork = forks[i];
                for (auto &oneRoot : oneFork)
                {
                    if (vtx[oneRoot].second.proofRoots.count(currencyID))
                    {
                        forkAndIndexByBlock.insert(std::make_pair(vtx[oneRoot].second.proofRoots.find(currencyID)->second.rootHeight, std::make_pair(i, oneRoot)));
                    }
                }
            }

            int forkNum = -1;
            int elemCount = 0;
            for (auto firstIt = forkAndIndexByBlock.rbegin(); firstIt != forkAndIndexByBlock.rend(); firstIt++)
            {
                if (forkNum == -1 || forkNum == firstIt->second.first)
                {
                    elemCount++;
                    forkNum = firstIt->second.first;
                }
                else
                {
                    break;
                }
            }
            if (elemCount >= minNotaryConfirms)
            {
                bestFork = forks[forkNum];
            }
        }
        else if (forks.size() &&
                (forks[0].size() > std::max(minNotaryConfirms, 1) || ConnectedChains.ThisChain().notarizationProtocol != CCurrencyDefinition::NOTARIZATION_AUTO))
        {
            bestFork = forks[0];
        }

        if (bestFork.size() < minNotaryConfirms || !vtx[lastConfirmed].second.proofRoots.count(currencyID))
        {
            LogPrint("notarization", "insufficient validator confirmations\n");
            return -1;
        }

        // all we really want is the system proof roots for each notarization to make the JSON for the API smaller
        UniValue proofRootsUni(UniValue::VARR);

        proofRootsUni.push_back(vtx[lastConfirmed].second.proofRoots.find(currencyID)->second.ToUniValue());

        for (auto forkIdxIt = bestFork.begin(); forkIdxIt != bestFork.end(); forkIdxIt++)
        {
            // don't enter the confirmed notarization twice
            if (*forkIdxIt != lastConfirmed)
            {
                auto &oneNot = vtx[*forkIdxIt];
                auto rootIt = oneNot.second.proofRoots.find(currencyID);
                if (rootIt != oneNot.second.proofRoots.end())
                {
                    proofRootsUni.push_back(rootIt->second.ToUniValue());
                }
                else
                {
                    proofRootsUni.push_back(CProofRoot().ToUniValue());
                }
            }
        }

        if (!proofRootsUni.size())
        {
            LogPrint("notarization", "no valid prior state root found\n");
            return -1;
        }

        UniValue firstParam(UniValue::VOBJ);
        firstParam.push_back(Pair("proofroots", proofRootsUni));
        firstParam.push_back(Pair("lastconfirmed", 0));

        // call notary to determine the notarization that we should notarize
        UniValue params(UniValue::VARR);
        params.push_back(firstParam);

        //printf("%s: about to getbestproofroot with:\n%s\n", __func__, params.write(1,2).c_str());

        UniValue result;
        try
        {
            result = find_value(RPCCallRoot("getbestproofroot", params), "result");
        } catch (exception e)
        {
            result = NullUniValue;
        }

        CProofRoot lastConfirmedRoot(find_value(result, "lastconfirmedproofroot"));
        int32_t notaryIdx = lastConfirmedRoot.IsValid() ? uni_get_int(find_value(result, "lastconfirmedindex"), -1) :
                                                        uni_get_int(find_value(result, "bestindex"), -1);

        if (result.isNull() || notaryIdx == -1)
        {
            LogPrint("notarization", "no-matching-notarization-found\n");
            return -1;
        }

        // now, assuming that our notarization of the other chain is confirmed, sign the latest valid one on this chain
        UniValue proofRootArr = find_value(result, "validindexes");

        if (!proofRootArr.isArray() || !proofRootArr.size())
        {
            LogPrint("notarization", "no valid notarizations found\n");
            return -1;
        }
        return bestFork[notaryIdx];
    }
}

// this is called to locate any notarizations of a specific system that can be finalized or of called by a notary witness,
// can be signed/witnessed, to determine if we agree with the notarization in question, and to confirm or reject the notarization.
bool CPBaaSNotarization::ConfirmOrRejectNotarizations(CWallet *pWallet,
                                                      const CRPCChainData &externalSystem,
                                                      CValidationState &state,
                                                      std::vector<TransactionBuilder> &txBuilders,
                                                      uint32_t nHeight)
{
    auto txBuilder = TransactionBuilder(Params().GetConsensus(), nHeight, pWallet);

    std::string errorPrefix(strprintf("%s: ", __func__));

    CCurrencyDefinition::EHashTypes hashType = (CCurrencyDefinition::EHashTypes)externalSystem.chainDefinition.proofProtocol;

    uint32_t height, signingHeight;
    uint160 SystemID = externalSystem.chainDefinition.GetID();

    const CCurrencyDefinition *pNotaryCurrency;
    if (IsVerusActive() || !ConnectedChains.notarySystems.count(SystemID))
    {
        pNotaryCurrency = &externalSystem.chainDefinition;
    }
    else
    {
        pNotaryCurrency = &ConnectedChains.ThisChain();
    }

    CChainNotarizationData cnd;
    std::vector<std::pair<CTransaction, uint256>> txes;

    std::set<uint160> notarySet = pNotaryCurrency->GetNotarySet();
    int minimumNotariesConfirm = pNotaryCurrency->MinimumNotariesConfirm();
    int confirmIfSigned;
    int confirmIfAuto;
    uint32_t confirmedNotarizationHeight = externalSystem.chainDefinition.startBlock;

    std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> mine;
    {
        std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> imsigner, watchonly;
        LOCK(pWallet->cs_wallet);
        pWallet->GetIdentities(pNotaryCurrency->notaries, mine, imsigner, watchonly);
    }

    {
        LOCK2(cs_main, mempool.cs);
        signingHeight = height = chainActive.Height();

        // we can only create an earned notarization for a notary chain, so there must be a notary chain and a network connection to it
        // we also need to ensure that our notarization would be the first notarization in this notary block period  with which we agree.
        if (!externalSystem.IsValid() || externalSystem.rpcHost.empty())
        {
            // technically not a real error
            return state.Error("no-notary-chain");
        }

        if (!GetNotarizationData(SystemID, cnd, &txes))
        {
            return state.Error(errorPrefix + "no prior notarization found");
        }

        auto lastConfirmedBlockIt = cnd.vtx.size() ? mapBlockIndex.find(txes[0].second) : mapBlockIndex.end();
        confirmedNotarizationHeight = lastConfirmedBlockIt == mapBlockIndex.end() ?
                                        externalSystem.chainDefinition.startBlock :
                                        lastConfirmedBlockIt->second->GetHeight();

        confirmIfSigned =
            cnd.BestConfirmedNotarization(ConnectedChains.ThisChain(),
                                          CPBaaSNotarization::MIN_EARNED_FOR_SIGNED - 1,
                                          CPBaaSNotarization::MinBlocksToSignedNotarization(ConnectedChains.ThisChain().blockNotarizationModulo),
                                          nHeight,
                                          confirmedNotarizationHeight,
                                          txes);

        confirmIfAuto =
            cnd.BestConfirmedNotarization(ConnectedChains.ThisChain(),
                                          CPBaaSNotarization::MIN_EARNED_FOR_AUTO - 1,
                                          CPBaaSNotarization::MinBlocksToAutoNotarization(ConnectedChains.ThisChain().blockNotarizationModulo),
                                          nHeight,
                                          confirmedNotarizationHeight,
                                          txes);
    }

    if (cnd.IsConfirmed() && cnd.vtx.size() == 1)
    {
        return state.Error("no-unconfirmed");
    }

    if (height <= ConnectedChains.ThisChain().GetMinBlocksToStartNotarization())
    {
        return state.Error(errorPrefix + "too early");
    }

    // spend all outputs we need to, even if there gets to be too many for 1 tx
    // rules to confirm or reject an earned notarization
    // 1) Notaries may confirm an earned notarization if and only if the following is true:
    //   a) There is no previous, valid notarization in the same eligible period with which the notarization agrees and should confirm
    //   b) If auto-notarization and in a staked block, the last entry to confirm was an earned notarization from a mining block
    //   c) If auto-notarization and making a mined block, the last entry to confirm must be an earned notarization from a staked block
    //   d) The miner or staker has entered accurate information about the other system, which must be confirmed by the notary
    //
    // 2) Each earned notarization in a staked block contains a proof of the stake transaction in the header.
    //
    // 3) Each includes a proof of the prior notarization with which it agrees and either a PoW or PoS proof of its own.
    //
    // 4) Once a notarization gets 3 uncontested and agreed notarizations in a row, notaries of an auto-notarized chain
    //    may sign and confirm, also including the proof of each of the confirmation outputs.
    //
    // if we are auto-notarizing, the following conditions must be true to qualify for us to confirm a notarization:
    // 1) the notarization must be agreed to by 2 or greater valid earned notarizations since the next longest fork.
    //

    // post evidence to finalize a notarization if the following is true:
    //
    // 1) We agree with the last finalized or a pending fork of notarizations on the other chain
    //    Said differently, we we can only attempt to submit finalization evidence if there is
    //    no pending notarization on the alternate chain that we agree with, which is more recent
    //    than 10x the block notarization modulo (BNM) of both chains.
    //
    //    If we agree with a pending notarization, do not control a notary, and the notarization
    //    we agree with is less than 10x the (BNM) of both chains, we don't submit anything, as our
    //    notarization can never be finalized if someone proves the alternate notarization that
    //    disqualifies us.
    //
    // 2) the last confirmed notarization on this chain occurred more than 10x our period prior
    //    and the other chain has progressed 10x its BNM period in blocks on the proof root, and we
    //    have 10 or more valid notarizations behind this one that we agree with.
    //
    // If #1 and #2 are true, we package up enough proof to make a transaction that can stand alone with evidence
    // that miners and stakers of this chain agree on and there is no valid challenge as we settled on this finalization.
    // It is then submitted as a finalization on this chain and accepted as a finalization. It will later be submitted
    // as an accepted notarization to the other chain to confirm the last pending and become a pending notarization.
    //

    // if there's no hope even for signed confirmation, we're done
    if (confirmIfSigned == -1)
    {
        return state.Error("insufficient validator confirmations");
    }

    // assume the bestchain algorithm does better than we would here. if we don't agree,
    // we may challenge in other places, but we won't be confirming
    std::vector<int> allRoots = std::vector<int>(cnd.vtx.size());
    for (int i = 0; i < cnd.vtx.size(); i++)
    {
        allRoots[i] = i;
    }

    bool isFirstConfirmedCND = cnd.vtx[cnd.lastConfirmed].second.IsBlockOneNotarization() ||
                               cnd.vtx[cnd.lastConfirmed].second.IsDefinitionNotarization();

    // only the first actual notarization can have a prior without a proof root
    if (!isFirstConfirmedCND && !cnd.vtx[cnd.lastConfirmed].second.proofRoots.count(SystemID))
    {
        return state.Error("invalid prior notarization confirmation");
    }

    // any valid earned notarization that we choose to use for our proof, which will determine
    // the signing height, enabling all of them to match without additional coordination
    uint32_t eligibleHeight = height - ConnectedChains.ThisChain().GetMinBlocksToSignNotarize();

    // all we really want is the system proof roots for each notarization to make the JSON for the API smaller
    UniValue proofRootsUni(UniValue::VARR);
    bool forgiveZeroDisagreement = false;

    // get just the indexes in the fork that we could confirm
    for (auto forkIdxIt = allRoots.begin(); forkIdxIt != allRoots.end(); forkIdxIt++)
    {
        auto rootIt = cnd.vtx[*forkIdxIt].second.proofRoots.find(SystemID);
        if (rootIt != cnd.vtx[*forkIdxIt].second.proofRoots.end())
        {
            proofRootsUni.push_back(rootIt->second.ToUniValue());
        }
        else
        {
            if (forkIdxIt == allRoots.begin() &&
                cnd.vtx[cnd.lastConfirmed].second.IsDefinitionNotarization() &&
                externalSystem.chainDefinition.IsGateway())
            {
                forgiveZeroDisagreement = true;
            }
            proofRootsUni.push_back(CProofRoot().ToUniValue());
        }
    }

    if (!proofRootsUni.size())
    {
        return state.Error(errorPrefix + "no valid prior state root found");
    }
    else if (proofRootsUni.size() == 1 && !uni_get_int64(proofRootsUni[0]))
    {
        return state.Error(errorPrefix + "no valid notarizations to confirm yet");
    }

    UniValue firstParam(UniValue::VOBJ);
    firstParam.push_back(Pair("proofroots", proofRootsUni));
    firstParam.push_back(Pair("lastconfirmed", 0));

    // call notary to determine the notarization that we should notarize
    UniValue params(UniValue::VARR);
    params.push_back(firstParam);

    //printf("%s: about to getbestproofroot with:\n%s\n", __func__, params.write(1,2).c_str());

    UniValue result;
    try
    {
        result = find_value(RPCCallRoot("getbestproofroot", params), "result");
    } catch (exception e)
    {
        result = NullUniValue;
    }

    CProofRoot lastConfirmedRoot(find_value(result, "lastconfirmedproofroot"));
    int32_t notaryIdx = lastConfirmedRoot.IsValid() ? uni_get_int(find_value(result, "lastconfirmedindex"), -1) :
                                                      uni_get_int(find_value(result, "bestindex"), -1);

    if (result.isNull() || notaryIdx == -1)
    {
        return state.Error(result.isNull() ? "no-notary" : "no-matching-notarization-found");
    }

    std::set<CIdentityID> myIDSet;
    for (auto &oneID : mine)
    {
        myIDSet.insert(oneID.first.idID);
    }

    // take the lock again, now that we're back from calling out
    LOCK(cs_main);

    // for us to confirm a notarization, it must be in the best list
    // if we actually see any pending notarization that is considered invalid or not matching from our
    // perspective, we sign to reject it

    // now, assuming that our notarization of the other chain is confirmed, get all considered valid
    UniValue rawProofRootArr = find_value(result, "validindexes");
    UniValue proofRootArr(UniValue::VARR);

    // if not all of the proof roots we have are valid, enter a rejection signature
    // if we have ever signed for one that we believe is not valid, we need to revoke

    std::set<int> disagreements;
    std::vector<int> bestFork = cnd.forks[cnd.bestChain];
    int bestForkIdx = 0;

    for (auto oneIndex : allRoots)
    {
        if (!forgiveZeroDisagreement || oneIndex)
        {
            disagreements.insert(oneIndex);
        }
        else
        {
            proofRootArr.push_back(oneIndex);
            bestForkIdx++;
        }
    }

    for (int i = 0; i < rawProofRootArr.size() && bestForkIdx < bestFork.size(); i++)
    {
        int idx = uni_get_int(rawProofRootArr[i], -1);
        if (idx >= 0)
        {
            disagreements.erase(idx);
        }
        if (idx == bestFork[bestForkIdx])
        {
            proofRootArr.push_back(bestForkIdx);
            bestForkIdx++;
        }
        // if we skip over one in the best fork, we assume none in the best fork will be valid after that
        // keep looping to erase valid entries from disagreements
    }

    // for every disagreement, we need to check to ensure that we haven't signed it already
    // and also sign to reject. if we have signed it, we need to revoke our ID, if we are configured to do that
    std::string notaryRevokeAddr = GetArg("-autonotaryrevoke", "");
    if (disagreements.size() &&
        (!notaryRevokeAddr.empty() || mine.size()))
    {
        CTxDestination notaryRevokeDest = DecodeDestination(notaryRevokeAddr);
        uint160 notaryToRevoke = notaryRevokeDest.which() == COptCCParams::ADDRTYPE_ID ? GetDestinationID(notaryRevokeDest) : uint160();

        std::vector<std::vector<CNotaryEvidence>> evidenceVec;
        std::vector<std::vector<CInputDescriptor>> spendsToClose;
        std::vector<CInputDescriptor> extraSpends;

        // get evidence to determine if we reject or revoke
        if (!cnd.CorrelatedFinalizationSpends(txes, spendsToClose, extraSpends, &evidenceVec))
        {
            return state.Error("invalid-correlated-notarization-outputs");
        }

        for (auto oneD : disagreements)
        {
            CNotaryEvidence mergedEvidence(ASSETCHAINS_CHAINID, cnd.vtx[oneD].first, CNotaryEvidence::STATE_REJECTING);
            CCcontract_info CC;
            CCcontract_info *cp;
            std::vector<CTxDestination> dests;

            COptCCParams p;
            if (!(txes[oneD].first.vout[mergedEvidence.output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode != EVAL_NONE))
            {
                return state.Error(errorPrefix + "invalid output for notarization");
            }

            CNativeHashWriter hw(hashType);
            uint256 objHash = hw.write((const char *)&(p.vData[0][0]), p.vData[0].size()).GetHash();

            // combine signatures
            CNotaryEvidence signatureEvidence = mergedEvidence;
            for (auto &oneEvidenceObj : evidenceVec[oneD])
            {
                for (auto &oneSig : oneEvidenceObj.GetNotarySignatures())
                {
                    signatureEvidence.evidence << oneSig;
                }
            }

            uint32_t decisionHeight;
            std::map<CIdentityID, CIdentitySignature> notarySetRejects;
            std::map<CIdentityID, CIdentitySignature> notarySetConfirms;
            std::map<CIdentityID, CIdentitySignature> newSigMap;

            CNotaryEvidence::EStates confirmationResult = signatureEvidence.CheckSignatureConfirmation(objHash,
                                                                                                        hashType,
                                                                                                        notarySet,
                                                                                                        minimumNotariesConfirm,
                                                                                                        signingHeight,
                                                                                                        &decisionHeight,
                                                                                                        &notarySetRejects,
                                                                                                        &notarySetConfirms);

            // see if it is signed by either a notary we control or the one
            // we should revoke on disagreement, whether or not it is rejected

            if ((!notaryToRevoke.IsNull() &&
                 notarySetConfirms.count(notaryToRevoke)) ||
                mine.size())
            {
                // if necessary, revoke notary on this and the notary chain
                if (!notaryToRevoke.IsNull() &&
                    notarySetConfirms.count(notaryToRevoke))
                {
                    ConnectedChains.SetRevokeID(notaryToRevoke);
                }

                // if we have IDs to sign with, reject the notarizations we do not agree with
                // we will create one rejecting finalization for every disagreement with all signatures we control as evidence
                if (mine.size())
                {
                    LOCK(pWallet->cs_wallet);

                    int newSigCount = 0;

                    for (auto oneOfMine : mine)
                    {
                        CIdentityID oneID = oneOfMine.first.idID;
                        CIdentitySignature::ESignatureVerification signResult = CIdentitySignature::SIGNATURE_EMPTY;
                        confirmationResult = CNotaryEvidence::EStates::STATE_REJECTING;
                        {
                            if (notarySetConfirms.count(oneID))
                            {
                                ConnectedChains.SetRevokeID(oneID);
                            }
                            if (notarySetRejects.count(oneID))
                            {
                                // if we already rejected it, nothing to do
                                continue;
                            }
                            printf("Rejecting notarization (%s:%u) for %s\n", mergedEvidence.output.hash.GetHex().c_str(), mergedEvidence.output.n, EncodeDestination(oneID).c_str());
                            LogPrint("notarization", "Rejecting notarization (%s:%u) for %s\n", mergedEvidence.output.hash.GetHex().c_str(), mergedEvidence.output.n, EncodeDestination(oneID).c_str());

                            CNotaryEvidence newSigEvidence;
                            signResult = mergedEvidence.SignRejected(notarySet, minimumNotariesConfirm, *pWallet, txes[oneD].first, oneID, signingHeight, hashType, &newSigEvidence);

                            if (signResult == CIdentitySignature::SIGNATURE_PARTIAL || signResult == CIdentitySignature::SIGNATURE_COMPLETE)
                            {
                                if (newSigEvidence.evidence.chainObjects.size())
                                {
                                    auto notarySignatures = newSigEvidence.GetNotarySignatures();
                                    if (notarySignatures.size() &&
                                        notarySignatures[0].IsRejected() &&
                                        notarySignatures[0].signatures.size())
                                    {
                                        for (auto &oneSig : notarySignatures[0].signatures)
                                        {
                                            auto it = newSigMap.find(oneSig.first);
                                            if (it == newSigMap.end())
                                            {
                                                newSigMap.insert(std::make_pair(oneID, oneSig.second));
                                            }
                                            else
                                            {
                                                for (auto &oneRawSig : it->second.signatures)
                                                {
                                                    it->second.AddSignature(oneRawSig);
                                                }
                                            }
                                        }
                                    }
                                }

                                // if our signatures altogether have provided a complete validation, we can early out
                                // check to see if this notarization now qualifies with signatures
                                if (signResult == CIdentitySignature::SIGNATURE_COMPLETE)
                                {
                                    newSigCount++;
                                    if ((notarySetRejects.size() + newSigCount) >= minimumNotariesConfirm)
                                    {
                                        for (auto &oneSig : mergedEvidence.GetNotarySignatures())
                                        {
                                            signatureEvidence.evidence << oneSig;
                                        }

                                        // no need to add more
                                        confirmationResult = CNotaryEvidence::EStates::STATE_REJECTED;
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                return state.Error(errorPrefix + "invalid identity signature");
                            }
                        }
                    }

                    CObjectFinalization rejectOf(CObjectFinalization::FINALIZE_NOTARIZATION,
                                                SystemID,
                                                cnd.vtx[oneD].first.hash,
                                                cnd.vtx[oneD].first.n,
                                                height);

                    // if we've added any rejections, make an output
                    if (mergedEvidence.evidence.chainObjects.size())
                    {
                        std::vector<CTxOut> evidenceOutputs;
                        CCcontract_info CC;
                        CCcontract_info *cp;

                        cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
                        std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});

                        CScript finalizeScript = MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &rejectOf));
                        txBuilder.AddTransparentOutput(finalizeScript, 0);

                        cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
                        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
                        CScript evidenceScript = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &mergedEvidence));

                        // the value should be considered for reduction
                        if (evidenceScript.size() >= CScript::MAX_SCRIPT_ELEMENT_SIZE)
                        {
                            CNotaryEvidence emptyEvidence;
                            int baseOverhead = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &emptyEvidence)).size() + 128;
                            auto mergedVec = mergedEvidence.BreakApart(CScript::MAX_SCRIPT_ELEMENT_SIZE - baseOverhead);
                            if (!mergedVec.size())
                            {
                                LogPrintf("%s: failed to package evidence for notarization of system %s\n", __func__, EncodeDestination(CIdentityID(cnd.vtx[0].second.currencyID)).c_str());
                                return state.Error(errorPrefix + "failed to package evidence for notarization");
                            }
                            for (auto &oneProof : mergedVec)
                            {
                                evidenceOutputs.push_back(CTxOut(CNotaryEvidence::DEFAULT_OUTPUT_VALUE, MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &oneProof))));
                            }
                        }
                        else
                        {
                            evidenceOutputs.push_back(CTxOut(CNotaryEvidence::DEFAULT_OUTPUT_VALUE, evidenceScript));
                        }

                        for (auto &oneOut : evidenceOutputs)
                        {
                            txBuilder.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nValue);
                        }
                    }
                }
            }
        }
    }

    // if height changed, we need to fail and possibly try again later
    if (height != chainActive.Height())
    {
        return state.Error("stale-block");
    }

    // if the most recent valid earned notarization is prior to the eligible height,
    // we cannot finalize until a more recent one is mined

    if (!proofRootArr.isArray() || !proofRootArr.size())
    {
        return state.Error("no-valid-unconfirmed");
    }

    bool retVal = false;
    int firstNotarizationIndex = -1;

    LogPrint("notarization", "%s: proofRootArr: %s\n", __func__, proofRootArr.write().c_str());

    // we need to confirm that validated indexes are all in sync with the best chain from its beginning.
    // if we have a shorter best chain than expected because we don't agree with the end, we can move backwards
    // in best chain if there is room, but to be confirmed, no notarization along the stretch being confirmed may have
    // a verified challenge showing a more powerful chain than the range confirming.

    int verifiedSize;
    if (isFirstConfirmedCND &&
        proofRootArr.size() &&
        bestFork.size() > 1 &&
        uni_get_int(proofRootArr[0]) == 1)
    {
        UniValue newProofRootArr(UniValue::VARR);
        newProofRootArr.push_back((int)0);
        for (auto &oneItem : proofRootArr.getValues())
        {
            newProofRootArr.push_back(oneItem);
        }
        proofRootArr = newProofRootArr;
    }
    for (verifiedSize = 0; verifiedSize < proofRootArr.size(); verifiedSize++)
    {
        if (verifiedSize >= bestFork.size() || uni_get_int(proofRootArr[verifiedSize]) != verifiedSize)
        {
            break;
        }
    }

    CChainNotarizationData prunedData = cnd;
    if (verifiedSize < bestFork.size())
    {
        bestFork.resize(verifiedSize);
        prunedData.forks[prunedData.bestChain].resize(verifiedSize);

        confirmIfSigned =
        prunedData.BestConfirmedNotarization(ConnectedChains.ThisChain(),
                                             CPBaaSNotarization::MIN_EARNED_FOR_SIGNED - 1,
                                             CPBaaSNotarization::MinBlocksToSignedNotarization(ConnectedChains.ThisChain().blockNotarizationModulo),
                                             nHeight,
                                             confirmedNotarizationHeight,
                                             txes);

        confirmIfAuto =
        prunedData.BestConfirmedNotarization(ConnectedChains.ThisChain(),
                                             CPBaaSNotarization::MIN_EARNED_FOR_AUTO - 1,
                                             CPBaaSNotarization::MinBlocksToAutoNotarization(ConnectedChains.ThisChain().blockNotarizationModulo),
                                             nHeight,
                                             confirmedNotarizationHeight,
                                             txes);

        if (!pNotaryCurrency->IsPBaaSChain() || confirmIfSigned == -1)
        {
            return state.Error("insufficient validator confirmations after pruning disagreements");
        }
    }

    // we can now confirm either confirmIfSigned or confirmIfAuto
    // ensure that there is no loss of primacy during the confirmation range
    bool attemptAutoConfirm = false;
    int idx = confirmIfSigned;

    std::map<CIdentityID, CIdentitySignature> oldConfirms;
    std::map<CIdentityID, CIdentitySignature> newConfirms;

    while (idx > 0)
    {
        // these are deleted, mutated below, and recreated each iteration
        myIDSet = std::set<CIdentityID>();
        for (auto &oneID : mine)
        {
            myIDSet.insert(oneID.first.idID);
        }

        // before confirming the one we are about to, we want to ensure that it isn't already signed sufficiently
        // if there are enough signatures to confirm it without signature, make our signature, then create a finalization
        CObjectFinalization of = CObjectFinalization(CObjectFinalization::FINALIZE_NOTARIZATION,
                                                        SystemID,
                                                        cnd.vtx[idx].first.hash,
                                                        cnd.vtx[idx].first.n,
                                                        height);

        std::vector<std::pair<CInputDescriptor, CNotaryEvidence>> additionalEvidence;

        std::vector<std::vector<CNotaryEvidence>> evidenceVec;
        std::vector<std::vector<CInputDescriptor>> spendsToClose;
        std::vector<CInputDescriptor> extraSpends;

        std::set<int> confirmedOutputNums;
        std::set<int> invalidatedOutputNums;

        std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> mempoolUnspent;
        std::set<COutPoint> dummyOutPoints;
        if (mempool.getAddressIndex(
                std::vector<std::pair<uint160, int32_t>>({
                    {CCrossChainRPCData::GetConditionID(CObjectFinalization::ObjectFinalizationFinalizedKey(),
                                                        cnd.vtx[idx].first.hash,
                                                        cnd.vtx[idx].first.n),
                        CScript::P2IDX}}),
                mempoolUnspent) &&
            mempoolUnspent.size())
        {
            for (auto &oneUnspent : mempool.FilterUnspent(mempoolUnspent, dummyOutPoints))
            {
                // if we have a confirmed, valid entry in the mempool already, we don't have something to do
                CTransaction oneTx;
                COptCCParams optP;
                CObjectFinalization checkOf;
                if (mempool.lookup(oneUnspent.first.txhash, oneTx) &&
                    oneTx.vout.size() > oneUnspent.first.index &&
                    oneTx.vout[oneUnspent.first.index].scriptPubKey.IsPayToCryptoCondition(optP) &&
                    optP.IsValid() &&
                    optP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                    optP.vData.size() &&
                    (checkOf = CObjectFinalization(optP.vData[0])).IsValid() &&
                    checkOf.currencyID == SystemID &&
                    checkOf.IsConfirmed())
                {
                    return state.Error("notarization confirmed in mempool");
                }
            }
        }

        if (!cnd.CorrelatedFinalizationSpends(txes, spendsToClose, extraSpends, &evidenceVec) ||
            !cnd.CalculateConfirmation(idx, confirmedOutputNums, invalidatedOutputNums))
        {
            return state.Error("invalid-correlated-spends");
        }

        if (LogAcceptCategory("notarization"))
        {
            if (LogAcceptCategory("verbose"))
            {
                for (int j = 0; j < spendsToClose.size(); j++)
                {
                    auto &oneEntrySpends = spendsToClose[j];
                    LogPrintf("%s: index #%d - %s\n", __func__, j, confirmedOutputNums.count(j) ? "confirmed" : invalidatedOutputNums.count(j) ? "rejected" : "pending");
                    for (auto &oneSpend : oneEntrySpends)
                    {
                        UniValue scriptUni(UniValue::VOBJ);
                        ScriptPubKeyToUniv(oneSpend.scriptPubKey, scriptUni, false, false);
                        LogPrintf("txid: %s:%d, nValue: %ld\n", oneSpend.txIn.prevout.hash.GetHex().c_str(), oneSpend.txIn.prevout.n, oneSpend.nValue);
                    }
                }
                for (int j = 0; j < evidenceVec.size(); j++)
                {
                    auto &oneEvidenceVec = evidenceVec[j];
                    LogPrintf("evidence vector: index #%d\n", j);
                    for (auto &oneEvidence : oneEvidenceVec)
                    {
                        LogPrintf("%s\n", oneEvidence.ToUniValue().write(1,2).c_str());
                    }
                }
            }
            else
            {
                LogPrintf("spendsToClose size: %ld\n", spendsToClose.size());
                LogPrintf("evidence vector size: %ld\n", evidenceVec.size());
            }
        }

        CNotaryEvidence mergedEvidence(ASSETCHAINS_CHAINID, cnd.vtx[idx].first, CNotaryEvidence::STATE_CONFIRMING);
        CCcontract_info CC;
        CCcontract_info *cp;
        std::vector<CTxDestination> dests;

        COptCCParams p;
        if (!(txes[idx].first.vout[mergedEvidence.output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
              p.IsValid() &&
              p.evalCode != EVAL_NONE))
        {
            return state.Error(errorPrefix + "invalid output for notarization");
        }

        CNativeHashWriter hw(hashType);
        uint256 objHash = hw.write((const char *)&(p.vData[0][0]), p.vData[0].size()).GetHash();

        // combine signatures
        CNotaryEvidence signatureEvidence = mergedEvidence;
        for (auto &oneEvidenceObj : evidenceVec[idx])
        {
            for (auto &oneSig : oneEvidenceObj.GetNotarySignatures())
            {
                signatureEvidence.evidence << oneSig;
            }
        }

        // add additional evidence
        CCrossChainProof tipProof(CCrossChainProof::VERSION_CURRENT);
        std::vector<CTxOut> evidenceOutputs;

        tipProof << CEvidenceData(CNotaryEvidence::NotarizationTipKey(),
                                        ::AsVector(CPrimaryProofDescriptor(std::vector<CUTXORef>({prunedData.vtx[bestFork.back()].first}))));
        mergedEvidence.evidence << tipProof;

        uint32_t decisionHeight;
        std::map<CIdentityID, CIdentitySignature> notarySetRejects;
        std::map<CIdentityID, CIdentitySignature> notarySetConfirms;
        std::map<CIdentityID, CIdentitySignature> newSigMap;

        CNotaryEvidence::EStates confirmationResult = signatureEvidence.CheckSignatureConfirmation(objHash,
                                                                                                   hashType,
                                                                                                   notarySet,
                                                                                                   minimumNotariesConfirm,
                                                                                                   signingHeight,
                                                                                                   &decisionHeight,
                                                                                                   &notarySetRejects,
                                                                                                   &notarySetConfirms);

        oldConfirms = notarySetConfirms;

        // rejected is irreversible, so we are done
        if (confirmationResult == CNotaryEvidence::EStates::STATE_REJECTED)
        {
            // we should consider different spends to close when rejecting
            // a notarization, only pruning it and all dependent on it, confirming nothing
            // currently, rejected notarizations would get consumed by confirmed notarizations
        }
        else if (confirmationResult != CNotaryEvidence::EStates::STATE_CONFIRMED &&
                 !attemptAutoConfirm)
        {
            int numConfirms = notarySetConfirms.size();

            // if we can still sign, do so and check confirmation
            if (myIDSet.size())
            {
                CIdentitySignature::ESignatureVerification signResult = CIdentitySignature::SIGNATURE_EMPTY;
                confirmationResult = CNotaryEvidence::EStates::STATE_REJECTING;
                {
                    LOCK(pWallet->cs_wallet);
                    // sign with all IDs under our control that are eligible for this currency
                    for (auto &oneID : myIDSet)
                    {
                        if (notarySetConfirms.count(oneID))
                        {
                            // already signed, no need
                            continue;
                        }
                        printf("Signing notarization (%s:%u) to confirm for %s\n", mergedEvidence.output.hash.GetHex().c_str(), mergedEvidence.output.n, EncodeDestination(oneID).c_str());
                        LogPrintf("Signing notarization (%s:%u) to confirm for %s\n", mergedEvidence.output.hash.GetHex().c_str(), mergedEvidence.output.n, EncodeDestination(oneID).c_str());

                        CNotaryEvidence newSigEvidence;
                        signResult = signatureEvidence.SignConfirmed(notarySet, minimumNotariesConfirm, *pWallet, txes[idx].first, oneID, signingHeight, hashType, &newSigEvidence);

                        if (signResult == CIdentitySignature::SIGNATURE_PARTIAL || signResult == CIdentitySignature::SIGNATURE_COMPLETE)
                        {
                            if (newSigEvidence.evidence.chainObjects.size())
                            {
                                auto notarySignatures = newSigEvidence.GetNotarySignatures();
                                if (notarySignatures.size() &&
                                    notarySignatures[0].IsConfirmed() &&
                                    notarySignatures[0].signatures.size())
                                {
                                    for (auto &oneSig : notarySignatures[0].signatures)
                                    {
                                        auto it = newSigMap.find(oneSig.first);
                                        if (it == newSigMap.end())
                                        {
                                            newSigMap.insert(std::make_pair(oneID, oneSig.second));
                                        }
                                        else
                                        {
                                            for (auto &oneRawSig : it->second.signatures)
                                            {
                                                it->second.AddSignature(oneRawSig);
                                            }
                                        }
                                    }
                                }
                            }

                            // if our signatures altogether have provided a complete validation, we can early out
                            // check to see if this notarization now qualifies with signatures
                            if (signResult == CIdentitySignature::SIGNATURE_COMPLETE)
                            {
                                confirmationResult = signatureEvidence.CheckSignatureConfirmation(objHash,
                                                                                                  hashType,
                                                                                                  notarySet,
                                                                                                  minimumNotariesConfirm,
                                                                                                  signingHeight,
                                                                                                  &decisionHeight,
                                                                                                  &notarySetRejects,
                                                                                                  &notarySetConfirms);
                                if (confirmationResult == CNotaryEvidence::EStates::STATE_CONFIRMED)
                                {
                                    break;
                                }
                            }
                        }
                        else
                        {
                            return state.Error(errorPrefix + "invalid identity signature");
                        }
                    }
                }
            }
        }
        else if (attemptAutoConfirm)
        {
            // we should already have eliminated any reason to attempt auto-confirm if
            // we have a valid index here
            confirmationResult = CNotaryEvidence::EStates::STATE_CONFIRMED;
        }
        if (confirmationResult != CNotaryEvidence::EStates::STATE_CONFIRMED &&
            confirmationResult != CNotaryEvidence::EStates::STATE_REJECTED &&
            pNotaryCurrency->notarizationProtocol == pNotaryCurrency->NOTARIZATION_AUTO &&
            pNotaryCurrency->proofProtocol == pNotaryCurrency->PROOF_PBAASMMR &&
            confirmIfAuto > 0) // not confirmed or rejected - see if we can auto-confirm
        {
            idx = confirmIfAuto;
            attemptAutoConfirm = true;
            continue;
        }

        // if we've added any confirmations, add them to our evidence
        if (newSigMap.size())
        {
            // add new signatures needed
            mergedEvidence.evidence << CNotarySignature(mergedEvidence.systemID, mergedEvidence.output, true, newSigMap);

            cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            CScript evidenceScript = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &mergedEvidence));

            // the value should be considered for reduction
            if (evidenceScript.size() >= CScript::MAX_SCRIPT_ELEMENT_SIZE)
            {
                CNotaryEvidence emptyEvidence;
                int baseOverhead = MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &emptyEvidence)).size() + 128;
                auto mergedVec = mergedEvidence.BreakApart(CScript::MAX_SCRIPT_ELEMENT_SIZE - baseOverhead);
                if (!mergedVec.size())
                {
                    LogPrintf("%s: failed to package evidence for notarization of system %s\n", __func__, EncodeDestination(CIdentityID(cnd.vtx[0].second.currencyID)).c_str());
                    return state.Error(errorPrefix + "failed to package evidence for notarization");
                }
                for (auto &oneProof : mergedVec)
                {
                    evidenceOutputs.push_back(CTxOut(CNotaryEvidence::DEFAULT_OUTPUT_VALUE, MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &oneProof))));
                }
            }
            else
            {
                evidenceOutputs.push_back(CTxOut(CNotaryEvidence::DEFAULT_OUTPUT_VALUE, evidenceScript));
            }
            retVal = true;
        }

        // if we have enough to finalize, do so as a combination of pre-existing evidence and this
        if (confirmationResult == CNotaryEvidence::EStates::STATE_CONFIRMED)
        {
            std::set<COutPoint> inputSet;
            std::vector<CInputDescriptor> nonEvidenceSpends;
            std::vector<CInputDescriptor> notarizationSpends;

            for (auto &oneInput : spendsToClose[idx])
            {
                COptCCParams tP;
                if (oneInput.scriptPubKey.IsPayToCryptoCondition(tP) &&
                    tP.IsValid() &&
                    tP.evalCode == EVAL_FINALIZE_NOTARIZATION)
                {
                    // if our evidence include an already confirmed finalization for the same output,
                    // abort with nothing to do
                    CObjectFinalization tPOF;
                    if (tP.vData.size() &&
                        (tPOF = CObjectFinalization(tP.vData[0])).IsValid() &&
                        tPOF.output == of.output &&
                        tPOF.IsConfirmed())
                    {
                        return state.Error(errorPrefix + "target notarization already confirmed");
                    }
                    if (inputSet.count(oneInput.txIn.prevout))
                    {
                        if (LogAcceptCategory("notarization"))
                        {
                            printf("%s: duplicate input 2: %s\n", __func__, oneInput.txIn.prevout.ToString().c_str());
                            LogPrintf("%s: duplicate input 2: %s\n", __func__, oneInput.txIn.prevout.ToString().c_str());
                        }
                        continue;
                    }
                    of.evidenceInputs.push_back(txBuilder.mtx.vin.size());
                    inputSet.insert(oneInput.txIn.prevout);
                    txBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
                }
                else if (tP.IsValid() &&
                         (tP.evalCode == EVAL_EARNEDNOTARIZATION ||
                          tP.evalCode == EVAL_ACCEPTEDNOTARIZATION))
                {
                    notarizationSpends.push_back(oneInput);
                }
                else
                {
                    nonEvidenceSpends.push_back(oneInput);
                }
            }
            for (auto &oneInput : notarizationSpends)
            {
                if (!inputSet.count(oneInput.txIn.prevout) && !IsScriptTooLargeToSpend(oneInput.scriptPubKey))
                {
                    inputSet.insert(oneInput.txIn.prevout);
                    txBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
                }
            }

            int sigCount = 0;

            cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

            CNotaryEvidence ne(ASSETCHAINS_CHAINID, of.output, CNotaryEvidence::STATE_CONFIRMING);
            CCrossChainProof tipData(CCrossChainProof::VERSION_CURRENT);
            tipData << CEvidenceData(CNotaryEvidence::NotarizationTipKey(),
                                            ::AsVector(CPrimaryProofDescriptor(std::vector<CUTXORef>({cnd.vtx[bestFork.back()].first}))));
            ne.evidence << tipData;
            evidenceOutputs.push_back(CTxOut(CNotaryEvidence::DEFAULT_OUTPUT_VALUE, MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &ne))));

            of.SetConfirmed();

            // any fork that does not match the confirmed fork up to the same index will be
            // considered invalid from all of its entries to its end.
            //
            bool makeInputTxes = confirmedOutputNums.size() > 3;
            for (auto oneConfirmedIdx : confirmedOutputNums)
            {
                if (oneConfirmedIdx != idx)
                {
                    bool makeInputTx = (makeInputTxes && spendsToClose[oneConfirmedIdx].size() > 2);
                    // if we are confirming more
                    // than 2 additional pending notarizations (3 total), we break the spends up into one
                    // transaction to close out each pending transaction into a pending finalization, which
                    // then is spent into the main transaction
                    std::vector<int> evidenceInputs;
                    auto newTxBuilder = TransactionBuilder(Params().GetConsensus(), nHeight, pWallet);
                    TransactionBuilder &oneConfirmedBuilder = (oneConfirmedIdx != cnd.lastConfirmed && makeInputTx) ? newTxBuilder : txBuilder;

                    bool isConfirmed = false;
                    std::vector<CInputDescriptor> extraEvidenceSpends;
                    for (auto &oneInput : spendsToClose[oneConfirmedIdx])
                    {
                        COptCCParams tP;
                        CObjectFinalization tPOF;
                        if (oneInput.scriptPubKey.IsPayToCryptoCondition(tP) &&
                            tP.IsValid() &&
                            tP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                            tP.vData.size() &&
                            (tPOF = CObjectFinalization(tP.vData[0])).IsValid() &&
                            tPOF.IsConfirmed() &&
                            ((tPOF.output.hash.IsNull() &&
                                oneInput.txIn.prevout.hash == cnd.vtx[oneConfirmedIdx].first.hash &&
                                tPOF.output.n == cnd.vtx[oneConfirmedIdx].first.n) ||
                                tPOF.output == cnd.vtx[oneConfirmedIdx].first))
                        {
                            // if our evidence include an already confirmed finalization for the same output,
                            // don't make a separate input transaction
                            isConfirmed = true;
                            makeInputTx = false;
                        }

                        if (!inputSet.count(oneInput.txIn.prevout))
                        {
                            inputSet.insert(oneInput.txIn.prevout);
                            if (tP.evalCode == EVAL_NOTARY_EVIDENCE)
                            {
                                extraEvidenceSpends.push_back(oneInput);
                            }
                            else
                            {
                                evidenceInputs.push_back(oneConfirmedBuilder.mtx.vin.size());
                                oneConfirmedBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
                            }
                        }
                        else if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                        {
                            printf("%s: skipping duplicate input: %s\n", __func__, oneInput.txIn.prevout.ToString().c_str());
                            LogPrintf("%s: skipping duplicate input: %s\n", __func__, oneInput.txIn.prevout.ToString().c_str());
                        }
                    }
                    /* for (auto &oneInput : extraEvidenceSpends)
                    {
                        if (!IsScriptTooLargeToSpend(oneInput.scriptPubKey))
                        {
                            // added to inputSet above already, so no need here
                            oneConfirmedBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
                        }
                    } */

                    if (makeInputTx)
                    {
                        CObjectFinalization oneConfirmedFinalization =
                            CObjectFinalization(isConfirmed ?
                                                    CObjectFinalization::FINALIZE_NOTARIZATION + CObjectFinalization::FINALIZE_CONFIRMED :
                                                    CObjectFinalization::FINALIZE_NOTARIZATION,
                                                SystemID,
                                                cnd.vtx[oneConfirmedIdx].first.hash,
                                                cnd.vtx[oneConfirmedIdx].first.n,
                                                height);

                        cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
                        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

                        CScript finalizeScript = MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &oneConfirmedFinalization));
                        oneConfirmedBuilder.AddTransparentOutput(finalizeScript, 0);
                        txBuilders.push_back(oneConfirmedBuilder);
                    }
                }
            }

            makeInputTxes = invalidatedOutputNums.size() > 3;
            for (auto oneInvalidatedIdx : invalidatedOutputNums)
            {
                bool makeInputTx = (makeInputTxes && spendsToClose[oneInvalidatedIdx].size() > 2);

                auto newTxBuilder = TransactionBuilder(Params().GetConsensus(), nHeight, pWallet);
                TransactionBuilder &oneInvalidatedBuilder = makeInputTx ? newTxBuilder : txBuilder;

                for (auto &oneInput : spendsToClose[oneInvalidatedIdx])
                {
                    if (!inputSet.count(oneInput.txIn.prevout))
                    {
                        inputSet.insert(oneInput.txIn.prevout);
                        COptCCParams checkP;
                        if (!IsScriptTooLargeToSpend(oneInput.scriptPubKey) &&
                            oneInput.scriptPubKey.IsPayToCryptoCondition(checkP) &&
                            checkP.IsValid() &&
                            checkP.evalCode != EVAL_NOTARY_EVIDENCE)
                        {
                            oneInvalidatedBuilder.AddTransparentInput(oneInput.txIn.prevout, oneInput.scriptPubKey, oneInput.nValue);
                        }
                    }
                    else if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                    {
                        printf("%s: skipping duplicate input: %s\n", __func__, oneInput.txIn.prevout.ToString().c_str());
                        LogPrintf("%s: skipping duplicate input: %s\n", __func__, oneInput.txIn.prevout.ToString().c_str());
                    }
                }

                if (makeInputTx)
                {
                    CObjectFinalization oneConfirmedFinalization = CObjectFinalization(CObjectFinalization::FINALIZE_NOTARIZATION,
                                                                                        SystemID,
                                                                                        cnd.vtx[oneInvalidatedIdx].first.hash,
                                                                                        cnd.vtx[oneInvalidatedIdx].first.n,
                                                                                        height);

                    cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
                    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

                    CScript finalizeScript = MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &oneConfirmedFinalization));
                    oneInvalidatedBuilder.AddTransparentOutput(finalizeScript, 0);
                    txBuilders.push_back(oneInvalidatedBuilder);
                }
            }

            for (int loop = 1; loop <= evidenceOutputs.size(); loop++)
            {
                of.evidenceOutputs.push_back(txBuilder.mtx.vout.size() + loop);
            }

            retVal = true;
            cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

            CScript finalizeScript = MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &of));
            txBuilder.AddTransparentOutput(finalizeScript, 0);

            for (auto &oneOut : evidenceOutputs)
            {
                txBuilder.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nValue);
            }
            txBuilders.push_back(txBuilder);
        }
        else if (txBuilder.mtx.vout.size() || (evidenceOutputs.size() && of.IsValid()))
        {
            cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

            for (int loop = 1; loop <= evidenceOutputs.size(); loop++)
            {
                of.evidenceOutputs.push_back(txBuilder.mtx.vout.size() + loop);
            }

            CScript finalizeScript = MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &of));
            txBuilder.AddTransparentOutput(finalizeScript, 0);

            for (auto &oneOut : evidenceOutputs)
            {
                txBuilder.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nValue);
            }
            txBuilders.push_back(txBuilder);
        }
        break;
    }
    return retVal;
}

bool CallNotary(const CRPCChainData &notarySystem, std::string command, const UniValue &params, UniValue &result, UniValue &error);

bool CPBaaSNotarization::FindFinalizedIndexByVDXFKey(const uint160 &notarizationIdxKey,
                                                     CObjectFinalization &confirmedFinalization,
                                                     CAddressIndexDbEntry &earnedNotarizationIndex,
                                                     bool selectLast)
{
    bool retVal = false;
    std::vector<CAddressIndexDbEntry> addressIndex;
    if (!GetAddressIndex(notarizationIdxKey, CScript::P2IDX, addressIndex) || !addressIndex.size())
    {
        if (LogAcceptCategory("verbose"))
        {
            LogPrint("notarization", "No transaction data for index key - not necessarily an error\n");
        }
        return retVal;
    }

    if (selectLast)
    {
        for (int i = addressIndex.size() - 1; i >= 0; i--)
        {
            auto &oneIndexEntry = addressIndex[i];
            if (oneIndexEntry.first.spending)
            {
                continue;
            }
            earnedNotarizationIndex = oneIndexEntry;
            break;
        }
    }
    else
    {
        for (auto &oneIndexEntry : addressIndex)
        {
            if (oneIndexEntry.first.spending)
            {
                continue;
            }
            earnedNotarizationIndex = oneIndexEntry;
            break;
        }
    }
    if (!earnedNotarizationIndex.first.blockHeight)
    {
        LogPrint("notarization", "Unable to locate transaction for index key\n");
        return retVal;
    }

    uint160 finalizedNotarizationKey = CCrossChainRPCData::GetConditionID(CObjectFinalization::ObjectFinalizationFinalizedKey(),
                                                                          earnedNotarizationIndex.first.txhash,
                                                                          earnedNotarizationIndex.first.index);

    addressIndex.clear();
    if (!GetAddressIndex(finalizedNotarizationKey, CScript::P2IDX, addressIndex) ||
         !addressIndex.size())
    {
        confirmedFinalization = CObjectFinalization();
        return true;
    }

    CAddressIndexDbEntry finalizationIndex;
    for (auto &oneIndexEntry : addressIndex)
    {
        if (oneIndexEntry.first.spending)
        {
            continue;
        }
        finalizationIndex = oneIndexEntry;
        break;
    }
    if (!finalizationIndex.first.blockHeight)
    {
        LogPrint("notarization", "Unable to locate indexed finalization transaction for index key\n");
        return retVal;
    }

    CTransaction finalizationTx;
    uint256 blkHash;
    COptCCParams fP;
    if (!myGetTransaction(finalizationIndex.first.txhash, finalizationTx, blkHash) ||
        finalizationIndex.first.index >= finalizationTx.vout.size() ||
        !(finalizationTx.vout[finalizationIndex.first.index].scriptPubKey.IsPayToCryptoCondition(fP) &&
            fP.IsValid() &&
            fP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
            fP.vData.size() &&
            (confirmedFinalization = CObjectFinalization(fP.vData[0])).IsValid()))
    {
        LogPrint("notarization", "Invalid finalization transaction for index key, smart transaction is %s, eval code: %u\n", fP.IsValid() ? "VALID" : "INVALID", fP.evalCode);
        return retVal;
    }

    // if the entry is finalized and not confirmed
    if (!confirmedFinalization.IsConfirmed())
    {
        LogPrint("notarization", "Finalization unconfirmed on transaction %s with finalization:\n%s\n", finalizationIndex.first.txhash.GetHex().c_str(), confirmedFinalization.ToUniValue().write(1,2).c_str());
        return false;
    }
    return true;
}

bool CPBaaSNotarization::FindFinalizedIndexesByVDXFKey(const uint160 &notarizationIdxKey,
                                                       std::vector<CObjectFinalization> &confirmedFinalization,
                                                       std::vector<CAddressIndexDbEntry> &earnedNotarizationIndex)
{
    bool retVal = false;
    BlockMap::iterator blockIt;
    std::vector<CAddressIndexDbEntry> addressIndex;
    if (!GetAddressIndex(notarizationIdxKey, CScript::P2IDX, addressIndex) || !addressIndex.size())
    {
        if (LogAcceptCategory("verbose"))
        {
            LogPrint("notarization", "No transaction data for index key - not necessarily an error\n");
        }
        return retVal;
    }

    CTransaction notarizationTx;
    CPBaaSNotarization foundNotarization;
    uint256 nBlkHash;
    COptCCParams nP;

    for (auto &oneIndexEntry : addressIndex)
    {
        if (oneIndexEntry.first.spending)
        {
            continue;
        }
        if (!myGetTransaction(oneIndexEntry.first.txhash, notarizationTx, nBlkHash) ||
            oneIndexEntry.first.index >= notarizationTx.vout.size() ||
            nBlkHash.IsNull() ||
            (blockIt = mapBlockIndex.find(nBlkHash)) == mapBlockIndex.end() ||
            !chainActive.Contains(blockIt->second) ||
            !(notarizationTx.vout[oneIndexEntry.first.index].scriptPubKey.IsPayToCryptoCondition(nP) &&
                nP.IsValid() &&
                (nP.evalCode == EVAL_ACCEPTEDNOTARIZATION || nP.evalCode == EVAL_EARNEDNOTARIZATION) &&
                nP.vData.size() &&
                (foundNotarization = CPBaaSNotarization(nP.vData[0])).IsValid()))
        {
            LogPrint("notarization", "Valid notarization not found for index key\n");
            continue;
        }
        earnedNotarizationIndex.push_back(oneIndexEntry);
    }
    if (!earnedNotarizationIndex.size())
    {
        LogPrint("notarization", "Unable to locate transaction for index key\n");
        return retVal;
    }

    for (int i = 0; i < earnedNotarizationIndex.size(); i++)
    {
        confirmedFinalization.push_back(CObjectFinalization());
        uint160 finalizedNotarizationKey = CCrossChainRPCData::GetConditionID(CObjectFinalization::ObjectFinalizationFinalizedKey(),
                                                                              earnedNotarizationIndex[i].first.txhash,
                                                                              earnedNotarizationIndex[i].first.index);

        addressIndex.clear();
        if (!GetAddressIndex(finalizedNotarizationKey, CScript::P2IDX, addressIndex) ||
            !addressIndex.size())
        {
            continue;
        }

        CTransaction finalizationTx;
        uint256 blkHash;
        COptCCParams fP;

        std::vector<CObjectFinalization> validOfs;
        for (auto &oneIndexEntry : addressIndex)
        {
            if (oneIndexEntry.first.spending)
            {
                continue;
            }
            if (!myGetTransaction(oneIndexEntry.first.txhash, finalizationTx, blkHash) ||
                oneIndexEntry.first.index >= finalizationTx.vout.size() ||
                (!blkHash.IsNull() &&
                 ((blockIt = mapBlockIndex.find(blkHash)) == mapBlockIndex.end() ||
                  !chainActive.Contains(blockIt->second))) ||
                !(finalizationTx.vout[oneIndexEntry.first.index].scriptPubKey.IsPayToCryptoCondition(fP) &&
                    fP.IsValid() &&
                    fP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                    fP.vData.size() &&
                    (confirmedFinalization[i] = CObjectFinalization(fP.vData[0])).IsValid()))
            {
                LogPrint("notarization", "Invalid finalization transaction for index key, smart transaction is %s, eval code: %u\n", fP.IsValid() ? "VALID" : "INVALID", fP.evalCode);
                continue;
            }
            validOfs.push_back(confirmedFinalization[i]);
            break;
        }
        if (validOfs.size())
        {
            confirmedFinalization[i] = validOfs[0];
        }
    }
    return true;
}

bool CPBaaSNotarization::FindEarnedNotarization(CObjectFinalization &confirmedFinalization, CAddressIndexDbEntry *pEarnedNotarizationIndex) const
{
    CAddressIndexDbEntry __earnedNotarizationIndex;
    CAddressIndexDbEntry &earnedNotarizationIndex = pEarnedNotarizationIndex ? *pEarnedNotarizationIndex : __earnedNotarizationIndex;

    bool retVal = false;
    CPBaaSNotarization checkNotarization = *this;
    if (checkNotarization.IsMirror())
    {
        if (!checkNotarization.SetMirror(false))
        {
            LogPrintf("Unable to interpret notarization data for notarization:\n%s\n", checkNotarization.ToUniValue().write(1,2).c_str());
            printf("Unable to interpret notarization data for notarization:\n%s\n", checkNotarization.ToUniValue().write(1,2).c_str());
            return retVal;
        }
    }

    if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
    {
        std::vector<unsigned char> checkHex = ::AsVector(checkNotarization);
        LogPrintf("%s: hex of notarization: %s\n", __func__, HexBytes(&(checkHex[0]), checkHex.size()).c_str());
        printf("%s: hex of notarization: %s\n", __func__, HexBytes(&(checkHex[0]), checkHex.size()).c_str());
    }

    CNativeHashWriter hw;
    hw << checkNotarization;
    uint256 objHash = hw.GetHash();
    uint160 notarizationIdxKey = CCrossChainRPCData::GetConditionID(currencyID, CPBaaSNotarization::EarnedNotarizationKey(), objHash);
    return FindFinalizedIndexByVDXFKey(notarizationIdxKey, confirmedFinalization, earnedNotarizationIndex, true);
}

bool CPBaaSNotarization::FindEarnedNotarizations(std::vector<CObjectFinalization> &confirmedFinalizations, std::vector<CAddressIndexDbEntry> *pEarnedNotarizationIndex) const
{
    std::vector<CAddressIndexDbEntry> __earnedNotarizationIndex;
    std::vector<CAddressIndexDbEntry> &earnedNotarizationIndex = pEarnedNotarizationIndex ? *pEarnedNotarizationIndex : __earnedNotarizationIndex;

    bool retVal = false;
    CPBaaSNotarization checkNotarization = *this;
    if (checkNotarization.IsMirror())
    {
        if (!checkNotarization.SetMirror(false))
        {
            LogPrintf("Unable to interpret notarization data for notarization:\n%s\n", checkNotarization.ToUniValue().write(1,2).c_str());
            printf("Unable to interpret notarization data for notarization:\n%s\n", checkNotarization.ToUniValue().write(1,2).c_str());
            return retVal;
        }
    }

    if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
    {
        std::vector<unsigned char> checkHex = ::AsVector(checkNotarization);
        LogPrintf("%s: hex of notarization: %s\n", __func__, HexBytes(&(checkHex[0]), checkHex.size()).c_str());
        printf("%s: hex of notarization: %s\n", __func__, HexBytes(&(checkHex[0]), checkHex.size()).c_str());
    }

    CNativeHashWriter hw;
    hw << checkNotarization;
    uint256 objHash = hw.GetHash();
    uint160 notarizationIdxKey = CCrossChainRPCData::GetConditionID(currencyID, CPBaaSNotarization::EarnedNotarizationKey(), objHash);
    return FindFinalizedIndexesByVDXFKey(notarizationIdxKey, confirmedFinalizations, earnedNotarizationIndex);
}

// look for finalized notarizations either on chain or in the mempool, which are eligible for submission
// and submit them to the notary chain, referring to the last on the notary chain that we agree with.
std::vector<uint256> CPBaaSNotarization::SubmitFinalizedNotarizations(const CRPCChainData &externalSystem,
                                                                      CValidationState &state)
{
    std::vector<uint256> retVal;

    // look for finalized notarizations for our notary chains in recent blocks
    // if we find any and are connected, submit them
    uint160 systemID = externalSystem.chainDefinition.GetID();

    const CCurrencyDefinition *pNotaryCurrency;
    if (IsVerusActive() || !ConnectedChains.notarySystems.count(systemID))
    {
        pNotaryCurrency = &externalSystem.chainDefinition;
    }
    else
    {
        pNotaryCurrency = &ConnectedChains.ThisChain();
    }

    std::set<uint160> notarySet = pNotaryCurrency->GetNotarySet();

    CChainNotarizationData cnd;
    std::vector<std::pair<CTransaction, uint256>> notarizationTxes;

    uint32_t nHeight;
    int startingNotarizationIdx;
    int autoNotarizationIdx;

    {
        LOCK2(cs_main, mempool.cs);

        nHeight = chainActive.Height();

        // we need to start with a confirmed notarization and one pending after that, which we agree with to move forward
        // this is to ensure that any transaction we intend to finalize has both a minimum number of mining/staking confirmations
        // and a minimum number of notary confirmation signatures
        if (!GetNotarizationData(systemID, cnd, &notarizationTxes))
        {
            return retVal;
        }
    }

    if (cnd.vtx[cnd.lastConfirmed].second.IsBlockOneNotarization())
    {
        if (LogAcceptCategory("verbose"))
        {
            LogPrint("notarization", "Not enough confirmations to submit finalized notarizations for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
        }
        return retVal;
    }

    // if latest confirmed notarization on this chain is not present on notary chain, we need to submit it and reinforce
    // the last matching notarization from the other system, which should correspond to a prior confirmed notarization
    // on this chain
    UniValue params(UniValue::VARR);
    params.push_back(EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)));
    params.push_back(true);
    params.push_back(true);

    UniValue result;
    try
    {
        result = find_value(RPCCallRoot("getnotarizationdata", params), "result");
    } catch (exception e)
    {
        result = NullUniValue;
    }

    CChainNotarizationData crosschainCND;
    std::vector<uint256> blockHashes;
    std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>>> counterEvidence;
    std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence>>> evidence;

    {
        LOCK2(cs_main, mempool.cs);
        if (result.isNull() ||
            !(crosschainCND = CChainNotarizationData(result, true, &blockHashes, &counterEvidence, &evidence)).IsValid() ||
            (!externalSystem.chainDefinition.IsGateway() && !crosschainCND.IsConfirmed()))
        {
            if (LogAcceptCategory("notarization"))
            {
                LogPrintf("Unable to get notarization data from %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                printf("Unable to get notarization data from %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
            }
            return retVal;
        }
    }

    std::set<int> validCrossChainIndexSet;
    std::set<int> invalidCrossChainIndexSet;
    uint160 notaryRevokeID;
    {
        LOCK(cs_main);
        // if the returned data is not confirmed, then it is a gateway that has not yet confirmed its first transaction
        // it may still have unconfirmed notarizations
        // if it is a gateway that is unconfirmed on the other side, we will insert its definition notarization as confirmed,
        // until it is confirmed on its side.
        if (!crosschainCND.IsConfirmed())
        {
            CInputDescriptor notarizationRef;
            CPBaaSNotarization definitionNotarization;
            if (!ConnectedChains.GetDefinitionNotarization(externalSystem.chainDefinition, notarizationRef, definitionNotarization))
            {
                LogPrintf("Unable to get definition notarization for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                printf("Unable to get definition notarization for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                return retVal;
            }
            crosschainCND.lastConfirmed = 0;
            crosschainCND.vtx.insert(crosschainCND.vtx.begin(), std::make_pair(CUTXORef(notarizationRef.txIn.prevout), definitionNotarization));

            if (crosschainCND.vtx.size() == 1)
            {
                crosschainCND.bestChain = 0;
                crosschainCND.forks = std::vector<std::vector<int>>({std::vector<int>({0})});
            }
            else
            {
                // loop through the forks, insert 0, and increment all following indices
                for (auto &oneFork : crosschainCND.forks)
                {
                    for (auto &oneIndex : oneFork)
                    {
                        oneIndex++;
                    }
                    oneFork.insert(oneFork.begin(), 0);
                }
            }
        }
        else
        {
            std::string notaryRevokeAddr = GetArg("-autonotaryrevoke", "");
            if (!notaryRevokeAddr.empty())
            {
                CTxDestination notaryDest = DecodeDestination(notaryRevokeAddr);
                if (notaryDest.which() == COptCCParams::ADDRTYPE_ID)
                {
                    notaryRevokeID = GetDestinationID(notaryDest);
                }
            }
            for (int i = 0; i < evidence.size(); i++)
            {
                // though we should agree with the data, also make sure that if it required proof,
                // it is proven with a future root we agree with, ensuring that it is not forking off from or trying to front run this chain
                bool isValid = true;
                bool isPotentialRevoke = false;
                std::set<uint160> idSigSet;
                auto proofIt = crosschainCND.vtx[i].second.proofRoots.find(ASSETCHAINS_CHAINID);
                if (proofIt != crosschainCND.vtx[i].second.proofRoots.end() &&
                    proofIt->second != CProofRoot::GetProofRoot(proofIt->second.rootHeight))
                {
                    isValid = false;
                    if (pNotaryCurrency->proofProtocol == CCurrencyDefinition::PROOF_ETHNOTARIZATION)
                    {
                        isPotentialRevoke = true;
                    }
                }
                for (auto &oneEvidenceItem : evidence[i])
                {
                    // can't get worse than this
                    if (!isValid && isPotentialRevoke)
                    {
                        break;
                    }
                    // we'll be looking for evidence that is confirmed, which should have come with the
                    // notarization. we need to agree with the future root used, or we will issue a tip challenge
                    // to prevent front running with invalid tips.
                    if (std::get<1>(oneEvidenceItem).IsValid() &&
                        std::get<1>(oneEvidenceItem).IsConfirmed())
                    {
                        if (!notaryRevokeID.IsNull())
                        {
                            std::map<uint32_t, std::map<CIdentityID, CIdentitySignature>> confirmedByHeight;
                            std::vector<CNotarySignature> sigVec = std::get<1>(oneEvidenceItem).GetNotarySignatures(&confirmedByHeight);
                            for (auto &oneConfirmedMap : confirmedByHeight)
                            {
                                if (oneConfirmedMap.second.count(notaryRevokeID))
                                {
                                    isPotentialRevoke = true;
                                }
                            }
                        }
                        std::set<int> evidenceTypes;
                        evidenceTypes.insert(CHAINOBJ_PROOF_ROOT);
                        evidenceTypes.insert(CHAINOBJ_TRANSACTION_PROOF);

                        CCrossChainProof autoProof = std::get<1>(oneEvidenceItem).GetSelectEvidence(evidenceTypes);
                        if (autoProof.chainObjects.size() >= 3 &&
                            autoProof.chainObjects[0]->objectType == CHAINOBJ_TRANSACTION_PROOF &&
                            autoProof.chainObjects[1]->objectType == CHAINOBJ_PROOF_ROOT &&
                            autoProof.chainObjects[2]->objectType == CHAINOBJ_TRANSACTION_PROOF)
                        {
                            uint32_t futureHeight = ((CChainObject<CProofRoot> *)autoProof.chainObjects[1])->object.rootHeight;
                            if (futureHeight > chainActive.Height() ||
                                ((CChainObject<CProofRoot> *)autoProof.chainObjects[1])->object != CProofRoot::GetProofRoot(futureHeight))
                            {
                                // we don't agree with this one because of the proof root, so we will ignore its existence
                                isValid = false;
                                continue;
                            }
                            // if we do agree, move on
                            isValid = true;
                            break;
                        }
                    }
                }
                if (!isValid)
                {
                    invalidCrossChainIndexSet.insert(i);
                    if (isPotentialRevoke)
                    {
                        ConnectedChains.SetRevokeID(notaryRevokeID);
                    }
                }
                else
                {
                    validCrossChainIndexSet.insert(i);
                }
            }
        }
    }

    // our latest confirmed is what we may submit.
    // if it is already on that chain, we have nothing to do
    if (cnd.forks[cnd.bestChain].size() <= 1 ||
        (!cnd.vtx[cnd.forks[cnd.bestChain][1]].second.proofRoots.count(ASSETCHAINS_CHAINID) &&
         !cnd.vtx[cnd.forks[cnd.bestChain][1]].second.IsDefinitionNotarization()))
    {
        LogPrint("notarization", "No confirming notarization with root for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
    }

    // if the alternate chain has knowledge of is prelaunch,
    // we will prove the block 1 coinbase with the new confirmed notarization
    // and the confirmed notarization with the next
    auto pfirstProofIdxIt = mapBlockIndex.find(notarizationTxes[cnd.lastConfirmed].second);
    if (pfirstProofIdxIt == mapBlockIndex.end())
    {
        LogPrintf("%s: ERROR: block for notarization invalid\n", __func__);
        return retVal;
    }

    CPBaaSNotarization newConfirmedNotarization = cnd.vtx[cnd.lastConfirmed].second;
    auto searchVec = ::AsVector(newConfirmedNotarization);

    // we can assume that all transactions we get back agree with us about the alternate chain, since we are
    // getting them from our merge mining/staking daemon and it would not accept notarizations with proof
    // roots that disagree with it.
    //
    // at the same time, it may have notarizations that do not agree with this chain.
    //
    int confirmingIdx;
    for (confirmingIdx = crosschainCND.vtx.size() - 1; confirmingIdx >= 0; confirmingIdx--)
    {
        // if we already know it is on a fork, don't confirm it
        if (invalidCrossChainIndexSet.count(confirmingIdx))
        {
            continue;
        }
        auto &oneNotarization = crosschainCND.vtx[confirmingIdx];

        // all core proof roots that are in a prior, agreed notarization, must be present in the new one,
        // and we must have moved far enough forward from any there that we agree with, or early out
        bool agreed = false;

        if ((oneNotarization.second.IsSameChain() && oneNotarization.second.IsDefinitionNotarization()) ||
             oneNotarization.second.IsPreLaunch())
        {
            agreed = true;
        }
        else
        {
            if (oneNotarization.second.IsMirror() &&
                !oneNotarization.second.SetMirror(false))
            {
                LogPrintf("CROSS-CHAIN ERROR: Failure to unmirror notarization from %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                printf("CROSS-CHAIN ERROR: Failure to unmirror notarization from %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                return retVal;
            }
            if (searchVec == ::AsVector(oneNotarization.second))
            {
                LogPrint("notarization", "No new confirmed notarizations for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                return retVal;
            }
        }

        for (auto &oneProofRoot : oneNotarization.second.proofRoots)
        {
            uint32_t adjustedNotarizationModulo = externalSystem.chainDefinition.IsPBaaSChain() ?
                                                    CPBaaSNotarization::GetAdjustedNotarizationModulo(externalSystem.chainDefinition.blockNotarizationModulo,
                                                                                    oneProofRoot.second.rootHeight,
                                                                                    cnd.vtx[cnd.lastConfirmed].second.proofRoots[oneProofRoot.first].rootHeight) :
                                                    CCurrencyDefinition::BLOCK_NOTARIZATION_MODULO;

            if (oneProofRoot.first == ASSETCHAINS_CHAINID)
            {
                if (oneProofRoot.second != CProofRoot::GetProofRoot(oneProofRoot.second.rootHeight))
                {
                    // if this has already been confirmed, the bridge to this chain cannot be easily repaired, so we fail
                    if (confirmingIdx == 0)
                    {
                        // Unless this is discrepancy from an attack, which is the only other option
                        // besides we are on a non-main fork, we should use the node information from the other chain
                        // to connect to new nodes, set the confirmed root from the other chain, and
                        // stop accepting blocks that disagree.
                        //
                        // If we get here on a chain that is not a local fork (figure out how to differentiate), there
                        // is a high chance it is due to a sophisticated chain attack in progress and should not be
                        // possible in any reasonably anticipated circumstance.
                        //
                        for (auto &oneNode : oneNotarization.second.nodes)
                        {
                            AddOneShot(oneNode.networkAddress);
                        }
                        LogPrintf("CROSS-CHAIN ERROR: Confirmed notarization on %s does not match this chain\n", EncodeDestination(CIdentityID(systemID)).c_str());
                        printf("CROSS-CHAIN ERROR: Confirmed notarization on %s does not match this chain\n", EncodeDestination(CIdentityID(systemID)).c_str());
                        return retVal;
                    }
                    // it is a non-confirmed notarization on the other chain. we don't agree, but that won't deter us
                    continue;
                }
                agreed = true;

                if (!cnd.vtx[cnd.lastConfirmed].second.proofRoots.count(oneProofRoot.first) ||
                    cnd.vtx[cnd.lastConfirmed].second.proofRoots[oneProofRoot.first].rootHeight <= oneProofRoot.second.rootHeight)
                {
                    LogPrint("notarization", "Skip submission - no new confirmed notarizations for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                    return retVal;
                }
            }
            else if (externalSystem.chainDefinition.IsPBaaSChain() &&
                     oneProofRoot.first == systemID &&
                     (!cnd.vtx[cnd.lastConfirmed].second.proofRoots.count(oneProofRoot.first) ||
                      (cnd.vtx[cnd.lastConfirmed].second.proofRoots[oneProofRoot.first].rootHeight - oneProofRoot.second.rootHeight) <
                           adjustedNotarizationModulo))
            {
                LogPrint("notarization", "Skip submission - no new enough confirmed notarizations for %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                return retVal;
            }
        }
        if (agreed)
        {
            break;
        }
    }
    if (confirmingIdx < 0)
    {
        LogPrint("notarization", "No matching notarization on %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
        return retVal;
    }

    // check to see if any of the pending notarizations match either our last confirmed
    // or the one before it
    bool isFirstLaunchingNotarization = crosschainCND.vtx[confirmingIdx].second.IsDefinitionNotarization() ||
                                        crosschainCND.vtx[confirmingIdx].second.IsPreLaunch();

    CPBaaSNotarization lastConfirmedNotarization = cnd.vtx[cnd.lastConfirmed].second;
    CPBaaSNotarization confirmingLocalNotarization;
    CAddressIndexDbEntry crossConfirmedIndexEntry;
    CAddressIndexDbEntry earnedNotarizationIndexEntry;
    CPBaaSNotarization crossConfirmedNotarization;

    std::vector<std::vector<CInputDescriptor>> spendsToClose;
    std::vector<CInputDescriptor> extraSpends;
    std::pair<CInputDescriptor, CPartialTransactionProof> notarizationTxInfo;

    // define here to construct in netsted scope and then access below
    CNotaryEvidence allEvidence(CNotaryEvidence::TYPE_NOTARY_EVIDENCE, CNotaryEvidence::VERSION_CURRENT, CNotaryEvidence::STATE_CONFIRMED);

    {
        LOCK2(cs_main, mempool.cs);

        nHeight = chainActive.Height();

        if (crosschainCND.IsConfirmed() || crosschainCND.vtx.size() == 1)
        {
            // ensure that we at least agree with the last notarization being finalized, or we can't submit
            confirmingIdx = crosschainCND.IsConfirmed() ? crosschainCND.lastConfirmed : 0;
            CObjectFinalization finalizationObj;

            if (crosschainCND.vtx.size() != 1)
            {
                // go backwards until we find one to confirm or fail
                for (int i = crosschainCND.vtx.size() - 1; i >= 0; i--)
                {
                    if ((isFirstLaunchingNotarization && i == 0) || invalidCrossChainIndexSet.count(i))
                    {
                        continue;
                    }
                    CAddressIndexDbEntry tmpIndexEntry;
                    if (crosschainCND.vtx[i].second.proofRoots.count(ASSETCHAINS_CHAINID) &&
                        crosschainCND.vtx[i].second.FindEarnedNotarization(finalizationObj, &tmpIndexEntry) &&
                        finalizationObj.IsConfirmed())
                    {
                        isFirstLaunchingNotarization = false;
                        confirmingIdx = i;
                        earnedNotarizationIndexEntry = crossConfirmedIndexEntry = tmpIndexEntry;
                        confirmingLocalNotarization = crosschainCND.vtx[i].second;
                        confirmingLocalNotarization.SetMirror(false);
                        break;
                    }
                    finalizationObj = CObjectFinalization();
                }
            }

            if (!isFirstLaunchingNotarization)
            {
                if (!confirmingLocalNotarization.IsValid() &&
                    !crosschainCND.vtx[confirmingIdx].second.FindEarnedNotarization(finalizationObj, &crossConfirmedIndexEntry))
                {
                    return retVal;
                }
                else if (!finalizationObj.IsValid() || !finalizationObj.IsConfirmed())
                {
                    // the notarization considered confirmed on the other
                    // chain must be in the same notarization chain as the one confirmed on this chain that would
                    // be true if it is on both chains, accurate on both, and behind this confirmed notarization
                    CTransaction notarizationTx;
                    CPBaaSNotarization checkNotarization1, checkNotarization2 = crosschainCND.vtx[confirmingIdx].second;
                    uint256 blkHash;
                    COptCCParams nP;
                    if (!myGetTransaction(crossConfirmedIndexEntry.first.txhash, notarizationTx, blkHash) ||
                        crossConfirmedIndexEntry.first.index >= notarizationTx.vout.size() ||
                        !(notarizationTx.vout[crossConfirmedIndexEntry.first.index].scriptPubKey.IsPayToCryptoCondition(nP) &&
                          nP.IsValid() &&
                          nP.evalCode == EVAL_EARNEDNOTARIZATION &&
                          nP.vData.size() &&
                          (checkNotarization1 = CPBaaSNotarization(nP.vData[0])).IsValid() &&
                          checkNotarization2.SetMirror(false) &&
                          ::AsVector(checkNotarization1) == ::AsVector(checkNotarization2) &&
                          checkNotarization1.proofRoots.count(ASSETCHAINS_CHAINID) &&
                          cnd.vtx[cnd.lastConfirmed].second.proofRoots.count(ASSETCHAINS_CHAINID) &&
                          checkNotarization1.proofRoots[ASSETCHAINS_CHAINID].rootHeight < cnd.vtx[cnd.lastConfirmed].second.proofRoots[ASSETCHAINS_CHAINID].rootHeight))
                    {
                        LogPrintf("Invalid notarization index entry for txid: %s\n", crossConfirmedIndexEntry.first.txhash.GetHex().c_str());
                        printf("Invalid notarization index entry for txid: %s\n", crossConfirmedIndexEntry.first.txhash.GetHex().c_str());
                        return retVal;
                    }
                    crossConfirmedNotarization = checkNotarization1;
                    crossConfirmedNotarization.SetMirror(true);
                }
            }
        }

        if (isFirstLaunchingNotarization)
        {
            ConnectedChains.GetLaunchNotarization(externalSystem.chainDefinition,
                                                  notarizationTxInfo,
                                                  confirmingLocalNotarization,
                                                  newConfirmedNotarization);

            if (!((confirmingLocalNotarization.IsValid() &&
                   ConnectedChains.ThisChain().launchSystemID == externalSystem.chainDefinition.GetID()) ||
                   ::AsVector(newConfirmedNotarization) == ::AsVector(cnd.vtx[cnd.lastConfirmed].second)))
            {
                if (LogAcceptCategory("notarization"))
                {
                    LogPrintf("Unable to get notarization data from %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                    printf("Unable to get notarization data from %s\n", EncodeDestination(CIdentityID(systemID)).c_str());
                }
                return retVal;
            }
            earnedNotarizationIndexEntry.first.blockHeight = 1;
            earnedNotarizationIndexEntry.first.txhash = notarizationTxInfo.first.txIn.prevout.hash;
            earnedNotarizationIndexEntry.first.index = notarizationTxInfo.first.txIn.prevout.n;
        }

        std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization>>
          finalizationsForSubmission = CObjectFinalization::GetFinalizations(cnd.vtx[cnd.lastConfirmed].first,
                                                                             CObjectFinalization::ObjectFinalizationFinalizedKey());

        std::vector<std::pair<CObjectFinalization, CNotaryEvidence>> evidenceVec;
        for (auto &oneFinalization : finalizationsForSubmission)
        {
            std::vector<std::pair<CObjectFinalization, CNotaryEvidence>> moreEvidenceVec;
            if (std::get<3>(oneFinalization).IsValid() &&
                std::get<3>(oneFinalization).IsConfirmed())
            {
                moreEvidenceVec = std::get<3>(oneFinalization).GetFinalizationEvidence(std::get<2>(oneFinalization),
                                                                                                std::get<1>(oneFinalization).n,
                                                                                                state);
                evidenceVec.insert(evidenceVec.end(), moreEvidenceVec.begin(), moreEvidenceVec.end());
            }
        }

        // if we have a cross-confirmed notarization to prove here, create a proof
        allEvidence.output = cnd.vtx[cnd.lastConfirmed].first;
        CNotaryEvidence signatureEvidence = allEvidence;

        if (!earnedNotarizationIndexEntry.first.txhash.IsNull())
        {
            UniValue proofRequests(UniValue::VARR);
            UniValue proofRequest(UniValue::VOBJ);
            proofRequest.pushKV("type", EncodeDestination(CIdentityID(CNotaryEvidence::PrimaryProofKey())));
            proofRequest.pushKV("priornotarizationref", CUTXORef(earnedNotarizationIndexEntry.first.txhash,
                                                                    earnedNotarizationIndexEntry.first.index).ToUniValue());

            // any roots between our new notarization and the one we are agreeing to/confirming are challenge roots
            UniValue challengeRoots(UniValue::VARR);
            for (int challengeNum = confirmingIdx + 1; challengeNum < crosschainCND.vtx.size(); challengeNum++)
            {
                UniValue challengeRootObj(UniValue::VOBJ);
                challengeRootObj.pushKV("txout", crosschainCND.vtx[challengeNum].first.ToUniValue());
                challengeRootObj.pushKV("proofroot", crosschainCND.vtx[challengeNum].second.proofRoots[ASSETCHAINS_CHAINID].ToUniValue());
                challengeRoots.push_back(challengeRootObj);
            }
            if (challengeRoots.size())
            {
                proofRequest.pushKV("challengeroots", challengeRoots);
            }
            proofRequest.pushKV("evidence", allEvidence.ToUniValue());
            proofRequest.pushKV("confirmnotarizationref", cnd.vtx[cnd.lastConfirmed].first.ToUniValue());
            proofRequest.pushKV("entropyhash", blockHashes[confirmingIdx].GetHex());

            // find which fork the one we are confirming is on, and set from height to the one before us on the same fork or 0
            int fromHeightIdx = 0;
            if (confirmingIdx > 1)
            {
                int forkIdx;
                int sameForkIdx;
                for (forkIdx = 0; forkIdx < crosschainCND.forks.size(); forkIdx++)
                {
                    bool forkBreak = false;
                    for (sameForkIdx = 1; sameForkIdx < crosschainCND.forks[forkIdx].size(); sameForkIdx++)
                    {
                        if (crosschainCND.forks[forkIdx][sameForkIdx] == confirmingIdx)
                        {
                            forkBreak = true;
                            fromHeightIdx = crosschainCND.forks[forkIdx][sameForkIdx - 1];
                            break;
                        }
                    }
                    if (forkBreak)
                    {
                        break;
                    }
                }
            }
            int64_t fromHeight = crosschainCND.vtx[fromHeightIdx].second.proofRoots.count(ASSETCHAINS_CHAINID) ?
                                    crosschainCND.vtx[fromHeightIdx].second.proofRoots[ASSETCHAINS_CHAINID].rootHeight :
                                    1;
            proofRequest.pushKV("fromheight", fromHeight);
            proofRequest.pushKV("toheight", (int64_t)cnd.vtx[cnd.lastConfirmed].second.proofRoots[ASSETCHAINS_CHAINID].rootHeight);
            UniValue challengeRequests(UniValue::VARR);
            challengeRequests.push_back(proofRequest);

            if (LogAcceptCategory("notarization"))
            {
                LogPrintf("%s: Sending proof request: %s\n", __func__, proofRequest.write(1,2).c_str());
            }

            // get primary proof, keep lock, since we're calling to our local function
            params = UniValue(UniValue::VARR);
            params.push_back(challengeRequests);
            try
            {
                proofRequest = getnotarizationproofs(params, false);
            } catch (exception e)
            {
                proofRequest = NullUniValue;
            }
            UniValue proofResult(UniValue::VNULL);
            CNotaryEvidence preparedEvidence(CNotaryEvidence::TYPE_NOTARY_EVIDENCE, CNotaryEvidence::VERSION_INVALID);
            if (proofRequest.isArray() && proofRequest.size())
            {
                proofResult = find_value(proofRequest[0], "result");
                preparedEvidence = CNotaryEvidence(find_value(proofResult, "evidence"));
            }
            if (proofResult.isNull() ||
                !preparedEvidence.IsValid())
            {
                // add valid evidence to submission
                LogPrint("notarization", "Unable to get valid evidence to submit notarization: %s\n", proofRequest[0].write().c_str());
                return retVal;
            }
            allEvidence.MergeEvidence(preparedEvidence);
        }

        // add valid signatures, and we should now have all we need to submit
        for (auto &oneEvidenceObj : evidenceVec)
        {
            auto notarySignatures = oneEvidenceObj.second.GetNotarySignatures();
            for (auto &oneSig : notarySignatures)
            {
                signatureEvidence.evidence << oneSig;
            }
        }
        if (signatureEvidence.evidence.chainObjects.size())
        {
            CCurrencyDefinition::EHashTypes hashType = (CCurrencyDefinition::EHashTypes)externalSystem.chainDefinition.proofProtocol;
            CNativeHashWriter hw(hashType);
            // we are earned notarizations, so it will not be mirrored and can be used as is
            uint256 objHash = (hw << cnd.vtx[cnd.lastConfirmed].second).GetHash();

            uint32_t decisionHeight;
            std::map<CIdentityID, CIdentitySignature> notaryRejects;
            std::map<CIdentityID, CIdentitySignature> notaryConfirms;
            if (signatureEvidence.CheckSignatureConfirmation(objHash,
                                                                hashType,
                                                                pNotaryCurrency->GetNotarySet(),
                                                                pNotaryCurrency->MinimumNotariesConfirm(),
                                                                nHeight,
                                                                &decisionHeight,
                                                                &notaryRejects,
                                                                &notaryConfirms) == CNotaryEvidence::EStates::STATE_CONFIRMED)
            {
                allEvidence.evidence << CNotarySignature(allEvidence.systemID, allEvidence.output, true, notaryConfirms);
            }
        }
    }

    uint32_t blocksBeforeModuloExtension = CPBaaSNotarization::GetBlocksBeforeModuloExtension(externalSystem.chainDefinition.blockNotarizationModulo);
    bool submit = notaryRevokeID.IsNull() &&
                  (GetBoolArg("-alwayssubmitnotarizations", false) ||
                   !GetBoolArg("-allowdelayednotarizations", true) ||
                   (!crosschainCND.IsConfirmed() ||
                    (crosschainCND.vtx[crosschainCND.lastConfirmed].second.IsDefinitionNotarization() &&
                     crosschainCND.vtx[crosschainCND.lastConfirmed].second.IsSameChain())) ||
                   (externalSystem.chainDefinition.proofProtocol != CCurrencyDefinition::PROOF_ETHNOTARIZATION &&
                    (newConfirmedNotarization.proofRoots[systemID].rootHeight - crosschainCND.vtx[crosschainCND.lastConfirmed].second.proofRoots[systemID].rootHeight) >
                     (blocksBeforeModuloExtension - (blocksBeforeModuloExtension >> 2))));

    bool amWitness = externalSystem.chainDefinition.proofProtocol == CCurrencyDefinition::PROOF_ETHNOTARIZATION && notarySet.count(VERUS_NOTARYID);

    if (notaryRevokeID.IsNull() && !submit)
    {
        CPBaaSNotarization unMirrored = crosschainCND.vtx[crosschainCND.lastConfirmed].second;
        if (!unMirrored.SetMirror(false))
        {
            submit = true;
        }
        else
        {
            for (auto &oneCurState : lastConfirmedNotarization.currencyStates)
            {
                if (!unMirrored.currencyStates.count(oneCurState.first) ||
                    (unMirrored.currencyStates[oneCurState.first].IsPrelaunch() &&
                     !oneCurState.second.IsPrelaunch()) ||
                    (!unMirrored.currencyStates[oneCurState.first].IsLaunchCompleteMarker() &&
                     oneCurState.second.IsLaunchCompleteMarker()))
                {
                    submit = true;
                    break;
                }

                // if the relative price of the two sided fee currencies has changed more than 15% since last confirmed
                // notarization, submit
                if (oneCurState.second.IsLaunchCompleteMarker() && oneCurState.second.IsFractional())
                {
                    auto curIdxMap = oneCurState.second.GetReserveMap();
                    uint160 externID = externalSystem.GetID();
                    if (!curIdxMap.count(ASSETCHAINS_CHAINID) || !curIdxMap.count(externID))
                    {
                        continue;
                    }

                    // if we are so far out of range we can't tell, submit
                    if (!(unMirrored.currencyStates[oneCurState.first].PriceInReserve(curIdxMap[externID])) ||
                        !(oneCurState.second.PriceInReserve(curIdxMap[externID])))
                    {
                        submit = true;
                        break;
                    }

                    int64_t firstRatioOfPrice = CCurrencyDefinition::CalculateRatioOfTwoValues(
                                                    unMirrored.currencyStates[oneCurState.first].PriceInReserve(curIdxMap[ASSETCHAINS_CHAINID]),
                                                    unMirrored.currencyStates[oneCurState.first].PriceInReserve(curIdxMap[externID]));
                    int64_t secondRatioOfPrice = CCurrencyDefinition::CalculateRatioOfTwoValues(
                                                    oneCurState.second.PriceInReserve(curIdxMap[ASSETCHAINS_CHAINID]),
                                                    oneCurState.second.PriceInReserve(curIdxMap[externID]));

                    // if second ratio is zero, can't tell, so submit
                    if (!secondRatioOfPrice)
                    {
                        submit = true;
                        break;
                    }

                    int64_t ratioOfPriceChange = CCurrencyDefinition::CalculateRatioOfTwoValues(firstRatioOfPrice, secondRatioOfPrice);

                    // if we go up or down by 10% from the last confirmed notarization, notarize again
                    if (ratioOfPriceChange > (SATOSHIDEN + (SATOSHIDEN / 10)) || ratioOfPriceChange < (SATOSHIDEN - (SATOSHIDEN / 10)))
                    {
                        submit = true;
                        break;
                    }

                    /*
                    if (externalSystem.chainDefinition.proofProtocol == CCurrencyDefinition::PROOF_ETHNOTARIZATION &&
                        unMirrored.proofRoots.count(externID) &&
                        lastConfirmedNotarization.proofRoots.count(externID))
                    {
                        ratioOfPriceChange = CCurrencyDefinition::CalculateRatioOfTwoValues(unMirrored.proofRoots[externID].gasPrice, lastConfirmedNotarization.proofRoots[externID].gasPrice);
                        // if gas goes up or down by 15% from the last confirmed notarization, notarize again
                        if (ratioOfPriceChange > (SATOSHIDEN + (SATOSHIDEN / 15)) || ratioOfPriceChange < (SATOSHIDEN - (SATOSHIDEN / 15)))
                        {
                            submit = true;
                            break;
                        }
                    }*/
                }
            }
        }

        if (!submit && lastConfirmedNotarization.proofRoots.count(ASSETCHAINS_CHAINID))
        {
            // check exports in our range
            // submit notarization only if there are exports pending on this chain and the last submitted notarization
            // is too old to be used to prove the exports
            uint32_t lastCrossHeight = (crosschainCND.IsConfirmed() &&
                                        crosschainCND.vtx[crosschainCND.lastConfirmed].second.proofRoots.count(ASSETCHAINS_CHAINID)) ?
                                            crosschainCND.vtx[crosschainCND.lastConfirmed].second.proofRoots[ASSETCHAINS_CHAINID].rootHeight :
                                            0;

            // get exports since last cross height, and if there are any that would be enabled by this notarization, submit
            UniValue params(UniValue::VARR);
            params = UniValue(UniValue::VARR);
            params.push_back(EncodeDestination(CIdentityID(systemID)));
            params.push_back((int64_t)lastCrossHeight);
            params.push_back((int64_t)lastConfirmedNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight);

            UniValue result = NullUniValue;
            try
            {
                UniValue getexports(const UniValue& params, bool fHelp);
                result = getexports(params, false);
            } catch (exception e)
            {
                LogPrint("notarization", "Could not determine pending exports to external chain %s\n", uni_get_str(params[0]).c_str());
                return retVal;
            }
            if (result.isArray() && result.size())
            {
                submit = true;
            }
            if (amWitness && submit)
            {
                LogPrintf("Witness found %ld pending exports for %s\n", result.size(),
                                                                        externalSystem.chainDefinition.parent == ASSETCHAINS_CHAINID ?
                                                                            externalSystem.chainDefinition.name.c_str() :
                                                                            (externalSystem.chainDefinition.name + "." + ConnectedChains.ThisChain().name).c_str());
                printf("Witness found %ld pending exports for %s\n", result.size(),
                                                                    externalSystem.chainDefinition.parent == ASSETCHAINS_CHAINID ?
                                                                        externalSystem.chainDefinition.name.c_str() :
                                                                        (externalSystem.chainDefinition.name + "." + ConnectedChains.ThisChain().name).c_str());
            }
        }
    }

    LogPrint("notarization", "%s: ready to submit accepted notarization with evidence:\n%s\n", __func__, allEvidence.ToUniValue().write(1,2).c_str());
    if (!submit)
    {
        LogPrint("notarization", "skipping submission due to being revoke node or no pending exports or currency transitions\n");
        return retVal;
    }

    // if this is an ETH protocol, we could get reverted and still have to pay, so if we are a notary,
    // to prevent funds loss, sort notaries and make sure we are in the top 2 before we try to submit
    if (amWitness)
    {
        CNativeHashWriter hw;
        hw << nHeight;
        uint256 prHash = hw.GetHash();
        std::vector<uint160> notaryVec = externalSystem.chainDefinition.notaries;
        auto prandom = std::minstd_rand0(UintToArith256(prHash).GetLow64());
        shuffle(notaryVec.begin(), notaryVec.end(), prandom);
        if (notaryVec[0] != VERUS_NOTARYID)
        {
            LogPrintf("skipping notarization submission - was not selected for submission lottery (%s selected)\n", EncodeDestination(CIdentityID(notaryVec[0])).c_str());
            printf("skipping notarization submission - was not selected for submission lottery (%s selected)\n", EncodeDestination(CIdentityID(notaryVec[0])).c_str());
            return retVal;
        }
    }

    // now, we should have enough evidence to prove
    // the notarization. the API call will ensure that we do
    params = UniValue(UniValue::VARR);
    UniValue error;
    std::string strTxId;
    params.push_back(lastConfirmedNotarization.ToUniValue());
    params.push_back(allEvidence.ToUniValue());
    if (!VERUS_NOTARYID.IsNull())
    {
        params.push_back(EncodeDestination(VERUS_NOTARYID));
    }

    LogPrint("notarization", "submitting notarization with parameters:\n%s\n%s\n", params[0].write(1,2).c_str(), params[1].write(1,2).c_str());

    /*
    printf("%s: initial notarization:\n%s\n", __func__, oneNotarization.first.ToUniValue().write(1,2).c_str());
    std::vector<unsigned char> notVec1 = ::AsVector(oneNotarization.first);
    CPBaaSNotarization checkNotarization(oneNotarization.first.ToUniValue());
    std::vector<unsigned char> notVec2 = ::AsVector(checkNotarization);
    printf("%s: processed notarization:\n%s\n", __func__, checkNotarization.ToUniValue().write(1,2).c_str());
    std::vector<unsigned char> notVec3 = ::AsVector(CPBaaSNotarization(notVec1));
    printf("%s: hex before univalue:\n%s\n", __func__, HexBytes(&(notVec1[0]), notVec1.size()).c_str());
    printf("%s: hex after univalue:\n%s\n", __func__, HexBytes(&(notVec2[0]), notVec2.size()).c_str());
    printf("%s: hex after reserialization:\n%s\n", __func__, HexBytes(&(notVec3[0]), notVec3.size()).c_str()); */

    if (!CallNotary(externalSystem, "submitacceptednotarization", params, result, error) ||
        !error.isNull() ||
        (strTxId = uni_get_str(result)).empty() ||
        !IsHex(strTxId))
    {
        return retVal;
    }
    // store the transaction ID and accepted notariation to prevent redundant submits
    retVal.push_back(uint256S(strTxId));
    return retVal;
}

/*
 * Validates a notarization output spend by ensuring that the spending transaction fulfills all requirements.
 * to accept an accepted notarization as valid on the Verus blockchain, it must prove a transaction on the alternate chain, which is
 * either the original chain definition transaction, which CAN and MUST be proven ONLY in block 1, or the latest notarization transaction
 * on the alternate chain that represents an accurate MMR for this chain.
 * In addition, any accepted notarization must fullfill the following requirements:
 * 1) Must prove either a PoS block from the alternate chain or a merge mined block that is owned by the submitter and in either case,
 *    the block must be exactly 8 blocks behind the submitted MMR used for proof.
 * 2) Must prove a chain definition tx and be block 1 or asserts a previous, valid MMR for the notarizing
 *    chain and properly prove objects using that MMR.
 * 3) Must spend the main notarization thread as well as any finalization outputs of either valid or invalid prior
 *    notarizations, and any unspent notarization contributions for this era. May also spend other inputs.
 * 4) Must output:
 *      a) finalization output of the expected reward amount, which will be sent when finalized
 *      b) normal output of reward from validated/finalized input if present, 50% to recipient / 50% to block miner less miner fee this tx
 *      c) main notarization thread output with remaining funds, no other output or fee deduction
 *
 */
bool ValidateAcceptedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // the spending transaction must be a notarization in the same thread of notarizations
    // check the following things:
    // 1. It represents a valid PoS or merge mined block on the other chain, and contains the header in the opret
    // 2. The MMR and proof provided for the currently asserted block can prove the provided header. The provided
    //    header can prove the last block referenced.
    // 3. This notarization is not a superset of an earlier notarization posted before it that it does not
    //    reference. If that is the case, it is rejected.
    // 4. Has all relevant inputs, including finalizes all necessary transactions, both confirmed and orphaned
    //printf("ValidateAcceptedNotarization\n");

    // first, determine our notarization finalization protocol
    CUTXORef spendingOutput(tx.vin[nIn].prevout.hash, tx.vin[nIn].prevout.n);
    CTransaction sourceTx;
    uint256 blockHash;
    if (!spendingOutput.GetOutputTransaction(sourceTx, blockHash))
    {
        return eval->Error("Unable to retrieve spending transaction for accepted notarization");
    }

    CPBaaSNotarization pbn;
    COptCCParams pN;
    if (!(sourceTx.vout[spendingOutput.n].scriptPubKey.IsPayToCryptoCondition(pN) &&
          pN.IsValid() &&
          pN.evalCode == EVAL_ACCEPTEDNOTARIZATION &&
          pN.vData.size() &&
          (pbn = CPBaaSNotarization(pN.vData[0])).IsValid()))
    {
        return eval->Error("Invalid accepted notarization");
    }

    int i;
    for (i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        CPBaaSNotarization nextPbn;
        CObjectFinalization of;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_ACCEPTEDNOTARIZATION &&
            p.vData.size() &&
            (nextPbn = CPBaaSNotarization(p.vData[0])).IsValid() &&
            nextPbn.currencyID == pbn.currencyID)
        {
            break;
        }
        if (p.IsValid() &&
            p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
            p.vData.size() &&
            (of = CObjectFinalization(p.vData[0])).IsValid() &&
            ConnectedChains.NotarySystems().count(pbn.currencyID) &&
            ConnectedChains.NotarySystems().find(pbn.currencyID)->second.notaryChain.chainDefinition.IsGateway())
        {
            break;
        }
    }

    if (i < tx.vout.size())
    {
        return true;
    }

    return eval->Error("Accepted notarization can only be spent by a transaction containing another valid notarization");
}

bool IsEarnedNotarizationDescendent(const CPBaaSNotarization &checkNotarization,
                                    const CPBaaSNotarization &priorNotarization,
                                    const uint256 &priorHashBlock,
                                    const std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> &lastConfirmedNotarization,
                                    CValidationState &state)
{
    // now, ensure that this still derives from the last confirmed on this chain by traveling backwards
    // from this one until we either pass last confirmed and prove this invalid, or hit last confirmed
    bool isDescendent = checkNotarization.prevNotarization == std::get<1>(lastConfirmedNotarization);
    CTransaction tmpPriorTx;
    uint256 tmpPriorHashBlock;
    COptCCParams tmpPriorP;
    uint32_t lastConfirmedHeight = std::get<0>(lastConfirmedNotarization);
    BlockMap::iterator tmpBlockIt = mapBlockIndex.find(priorHashBlock);
    CPBaaSNotarization tmpPriorNotarization = priorNotarization;
    while (!isDescendent &&
           tmpBlockIt != mapBlockIndex.end() &&
           tmpBlockIt->second->GetHeight() >= lastConfirmedHeight)
    {
        if (tmpPriorNotarization.prevNotarization == std::get<1>(lastConfirmedNotarization))
        {
            isDescendent = true;
            break;
        }
        if (tmpPriorNotarization.prevNotarization.IsNull() ||
            !myGetTransaction(tmpPriorNotarization.prevNotarization.hash, tmpPriorTx, tmpPriorHashBlock) ||
            tmpPriorHashBlock.IsNull() ||
            (tmpBlockIt = mapBlockIndex.find(tmpPriorHashBlock)) == mapBlockIndex.end() ||
            !chainActive.Contains(tmpBlockIt->second) ||
            tmpPriorTx.vout.size() <= tmpPriorNotarization.prevNotarization.n ||
            !tmpPriorTx.vout[tmpPriorNotarization.prevNotarization.n].scriptPubKey.IsPayToCryptoCondition(tmpPriorP) ||
            !tmpPriorP.IsValid() ||
            (tmpPriorP.evalCode != EVAL_ACCEPTEDNOTARIZATION && tmpPriorP.evalCode != EVAL_EARNEDNOTARIZATION) ||
            tmpPriorP.vData.size() < 1 ||
            !(tmpPriorNotarization = CPBaaSNotarization(tmpPriorP.vData[0])).IsValid() ||
            (tmpPriorP.evalCode == EVAL_ACCEPTEDNOTARIZATION &&
            !tmpPriorNotarization.IsBlockOneNotarization() &&
            !tmpPriorNotarization.IsDefinitionNotarization()))
        {
            break;
        }
    }
    if (!isDescendent)
    {
        return state.Error("Invalid earned notarization does not descend from last confirmed");
    }
    return true;
}

bool IsNotarizationDescendent(const CPBaaSNotarization &checkNotarization,
                                      const std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization> &priorNotarizationInfo,
                                      const std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> &lastConfirmedNotarization,
                                      CValidationState &state)
{
    // now, ensure that this still derives from the last confirmed on this chain by traveling backwards
    // from this one until we either pass last confirmed and prove this invalid, or hit last confirmed
    bool isDescendent = false;
    CTransaction tmpPriorTx;
    uint256 tmpPriorHashBlock;
    COptCCParams tmpPriorP;
    uint32_t lastConfirmedHeight = std::get<0>(lastConfirmedNotarization);
    auto tmpPriorNotarizationInfo = priorNotarizationInfo;
    uint32_t lastHeight = std::get<0>(tmpPriorNotarizationInfo);
    while (!isDescendent &&
           std::get<0>(tmpPriorNotarizationInfo) &&
           (!std::get<0>(tmpPriorNotarizationInfo) ||
            std::get<0>(tmpPriorNotarizationInfo) >= lastConfirmedHeight))
    {
        if (std::get<2>(tmpPriorNotarizationInfo) == std::get<1>(lastConfirmedNotarization))
        {
            isDescendent = true;
            break;
        }
        tmpPriorNotarizationInfo = GetPriorReferencedNotarization(std::get<1>(tmpPriorNotarizationInfo),
                                                                  std::get<2>(tmpPriorNotarizationInfo).n,
                                                                  std::get<3>(tmpPriorNotarizationInfo));
        if (!std::get<3>(tmpPriorNotarizationInfo).IsValid())
        {
            break;
        }
        lastHeight = std::get<0>(tmpPriorNotarizationInfo);
    }
    if (!isDescendent)
    {
        return state.Error("Notarization does not derive from last recognized confirmed");
    }
    return true;
}

bool PreCheckAcceptedOrEarnedNotarization(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    if (IsVerusMainnetActive() && height < 1567999)
    {
        return true;
    }

    // though it would fail below, simplify failure messages pre-pbaas
    if (CConstVerusSolutionVector::GetVersionByHeight(height) < CActivationHeight::ACTIVATE_PBAAS)
    {
        return state.Error("Notarizations not supported before PBaaS activation");
    }

    COptCCParams p;
    CPBaaSNotarization currentNotarization;
    if (!(tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
          p.IsValid() &&
          (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
          p.vData.size() &&
          (currentNotarization = CPBaaSNotarization(p.vData[0])).IsValid() &&
          currentNotarization.currencyState.IsValid() &&
          currentNotarization.currencyState.GetID() == currentNotarization.currencyID &&
          p.IsEvalPKOut()))
    {
        return state.Error("Invalid notarization output");
    }

    // check aux destinations if this is an earned notarization, it cannot have auxdests
    // if it is an accepted notarization, it can have 1 auxdest
    if (currentNotarization.proposer.AuxDestCount() > 1)
    {
        return state.Error("Too many auxilliary destinations in notarization proposer");
    }
    else if (currentNotarization.proposer.AuxDestCount() > 0)
    {
        if (p.evalCode == EVAL_ACCEPTEDNOTARIZATION)
        {
            if (currentNotarization.IsContractUpgrade())
            {
                return state.Error("Contract upgrade requests may only be in earned notarizations");
            }
            CTransferDestination auxDest = currentNotarization.proposer.GetAuxDest(0);
            // ensure that all proposer destinations and aux destinations are relevant for the purpose
            bool fail = false;
            switch (auxDest.TypeNoFlags())
            {
                case auxDest.DEST_PK:
                case auxDest.DEST_PKH:
                case auxDest.DEST_ID:
                {
                    break;
                }
                default:
                {
                    fail = true;
                }
            }
            if (fail)
            {
                return state.Error("Accepted notarization beneficiary must be public key, publick key hash, or ID destination");
            }
        }
        else if (!(currentNotarization.IsContractUpgrade() &&
                   currentNotarization.proposer.GetAuxDest(0).TypeNoFlags() == CTransferDestination::DEST_ETH))
        {
            return state.Error("Only contract upgrade specifying earned notarizations may have auxilliary destinations");
        }
    }
    else if (currentNotarization.IsContractUpgrade())
    {
        return state.Error("Contract upgrade request requires that miner/staker provide contract address for upgrade");
    }

    for (int i = 0; i < tx.vout.size(); i++)
    {
        if (i == outNum)
        {
            continue;
        }
        COptCCParams dupP;
        CPBaaSNotarization dupNotarization;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(dupP) &&
            dupP.IsValid() &&
            (dupP.evalCode == EVAL_ACCEPTEDNOTARIZATION || dupP.evalCode == EVAL_EARNEDNOTARIZATION) &&
            dupP.vData.size() &&
            (dupNotarization = CPBaaSNotarization(dupP.vData[0])).IsValid() &&
            dupNotarization.currencyID == currentNotarization.currencyID)
        {
            return state.Error("Duplicate export finalization output");
        }
    }

    // ensure that we never accept an invalid proofroot for this chain in a notarization
    if (currentNotarization.proofRoots.count(ASSETCHAINS_CHAINID))
    {
        CProofRoot notarizationRoot = currentNotarization.proofRoots[ASSETCHAINS_CHAINID];
        if (notarizationRoot.rootHeight >= height)
        {
            return true;
        }
        CProofRoot correctRoot = CProofRoot::GetProofRoot(notarizationRoot.rootHeight);

        if (!correctRoot.IsValid())
        {
            return true;
        }

        if (correctRoot != notarizationRoot)
        {
            return state.Error("Incorrect proof root in notarization transaction");
        }

        // earned notarizations are only supported for
        if (p.evalCode == EVAL_EARNEDNOTARIZATION &&
            !currentNotarization.IsBlockOneNotarization() &&
            !currentNotarization.proofRoots.count(currentNotarization.currencyID))
        {
            return state.Error("Earned notarization besides PBaaS block one must contain proof root of system being notarized");
        }
    }
    else if (p.evalCode == EVAL_EARNEDNOTARIZATION &&
             !currentNotarization.IsBlockOneNotarization())
    {
        return state.Error("Earned notarization must contain proof root of current chain");
    }

    // if this is a notarization for this chain's notary chain or system, and this chain is running an auto-notarization protocol,
    // only earned notarizations may be entered, and those notarizations must alternate between being entered by a staker and
    // then a miner
    uint32_t nHeight = chainActive.Height();

    // do full checks if the chain is in sync behind us
    if (nHeight >= (height - 1))
    {
        CCurrencyDefinition curDef = ConnectedChains.GetCachedCurrency(currentNotarization.currencyID);
        if (!curDef.IsValid())
        {
            // the notarization must indicate that it is block one or definition if the currency definition is on
            // the same transaction
            if (currentNotarization.IsDefinitionNotarization() || currentNotarization.IsBlockOneNotarization())
            {
                if (height == 1)
                {
                    if (currentNotarization.IsPreLaunch())
                    {
                        return state.Error("Block one notarizations may not be in the pre-launch state");
                    }
                }
                COptCCParams defP;
                for (auto &oneOut : tx.vout)
                {
                    if (oneOut.scriptPubKey.IsPayToCryptoCondition(defP) &&
                        defP.IsValid() &&
                        defP.evalCode == EVAL_CURRENCY_DEFINITION &&
                        defP.vData.size() &&
                        (curDef = CCurrencyDefinition(defP.vData[0])).IsValid() &&
                        curDef.IsValid() &&
                        curDef.GetID() == currentNotarization.currencyID)
                    {
                        break;
                    }
                    else
                    {
                        curDef.nVersion = curDef.VERSION_INVALID;
                    }
                }
            }
            if (!curDef.IsValid())
            {
                if (LogAcceptCategory("notarization"))
                {
                    UniValue jsonNTx(UniValue::VOBJ);
                    TxToUniv(tx, uint256(), jsonNTx);
                    LogPrintf("%s: Unable to retrieve notarization currency on tx:\n%s\n", __func__, jsonNTx.write(1,2).c_str());
                }

                return state.Error("Unable to retrieve notarizing currency 1");
            }
        }

        if (currentNotarization.IsContractUpgrade() &&
            (curDef.proofProtocol != curDef.PROOF_ETHNOTARIZATION ||
             !curDef.IsGateway()))
        {
            return state.Error("Invalid currency for contract upgrade request in notarization");
        }

        bool additionalEvidenceRequired = curDef.proofProtocol == curDef.PROOF_PBAASMMR &&
                                            curDef.notarizationProtocol != curDef.NOTARIZATION_NOTARY_CHAINID;

        // ensure that on a chain requiring earned notarizations, we do not enter new chain roots in the form of
        // accepted notarizations. accepted notarizations can be generated on cross-chain imports, and in that case,
        // may only include proof roots from a prior confirmed notarization.

        // if this is one of the recognized notary chains, the notarizations are "earned" by miners and stakers,
        // if not a notary chain, the currency or chain must have been launched by this chain and notarizations are "accepted"
        // either unquestioningly for notarization protocols other than auto notarization or with auto-notarization
        // requirements
        if (ConnectedChains.notarySystems.count(currentNotarization.currencyID) ||
            p.evalCode == EVAL_EARNEDNOTARIZATION)
        {
            CPBaaSNotarization priorNotarization;

            // accepted notarizations may include chain roots from currently confirmed notarizations
            if (p.evalCode == EVAL_ACCEPTEDNOTARIZATION)
            {
                // this should only be present as an accepted notarization for the notary chain in any normal case
                // on an import transaction.
                // ensure that the proof root accurately reflects the last earned and confirmed notarization.
                if (currentNotarization.currencyID != ASSETCHAINS_CHAINID &&
                    currentNotarization.proofRoots.count(currentNotarization.currencyID))
                {
                    CTransaction priorNotTx;
                    uint256 hashBlock;
                    COptCCParams priorP;
                    // if there is a proof root in this accepted notarization, it must be as part of an import
                    // and the proof root should match the evidence notarization reference used to prove the
                    // import.
                    if (currentNotarization.prevNotarization.IsNull() ||
                        !myGetTransaction(currentNotarization.prevNotarization.hash, priorNotTx, hashBlock) ||
                        priorNotTx.vout.size() <= currentNotarization.prevNotarization.n ||
                        !priorNotTx.vout[currentNotarization.prevNotarization.n].scriptPubKey.IsPayToCryptoCondition(priorP) ||
                        !priorP.IsValid() ||
                        (priorP.evalCode != EVAL_ACCEPTEDNOTARIZATION && priorP.evalCode != EVAL_EARNEDNOTARIZATION) ||
                        priorP.vData.size() < 1 ||
                        !(priorNotarization = CPBaaSNotarization(priorP.vData[0])).IsValid() ||
                        priorNotarization.currencyID != currentNotarization.currencyID ||
                        !priorNotarization.proofRoots.count(currentNotarization.currencyID) ||
                        priorNotarization.proofRoots[currentNotarization.currencyID] != currentNotarization.proofRoots[currentNotarization.currencyID])
                    {
                        return state.Error("Invalid prior notarization");
                    }
                }
            }
            else
            {
                // this is an earned notarization, ensure that the proof root of the current chain is correct as of the
                // specified block and that the notarization follows all other rules as well (alt stake/work, etc.)
                if (!tx.IsCoinBase())
                {
                    return state.Error("Earned notarization must be an output on coinbase transaction");
                }

                if ((curDef.IsPBaaSChain() || curDef.IsGateway()) &&
                     curDef.SystemOrGatewayID() != ASSETCHAINS_CHAINID)
                {
                    if (currentNotarization.IsMirror() ||
                        !currentNotarization.proofRoots.count(currentNotarization.currencyID) ||
                        (currentNotarization.IsBlockOneNotarization() &&
                         currentNotarization.proofRoots.count(ASSETCHAINS_CHAINID) &&
                         currentNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight != 0) ||
                        (!currentNotarization.IsBlockOneNotarization() &&
                         (currentNotarization.proofRoots.size() < 2 ||
                         !currentNotarization.proofRoots.count(ASSETCHAINS_CHAINID) ||
                         currentNotarization.proofRoots[ASSETCHAINS_CHAINID] !=
                            CProofRoot::GetProofRoot(currentNotarization.proofRoots[ASSETCHAINS_CHAINID].rootHeight))))
                    {
                        LogPrint("notarization", "%s: Invalid earned notarization:\n%s\n", __func__, currentNotarization.ToUniValue().write(1,2).c_str());
                        return state.Error("Earned notarizations must contain valid, matching proof roots for current chain and notary chain");
                    }

                    if (!currentNotarization.IsBlockOneNotarization() && !currentNotarization.IsDefinitionNotarization())
                    {
                        // ensure that this notarization does not skip any valid notarization behind us
                        // whether or not this block alternates PoS and PoW is not checked here
                        CTransaction priorNotTx;
                        uint256 hashBlock;
                        COptCCParams priorP;

                        // if there is a proof root in this accepted notarization, it must be as part of an import
                        // and the proof root should match the evidence notarization reference used to prove the
                        // import.
                        if (currentNotarization.prevNotarization.IsNull() ||
                            !myGetTransaction(currentNotarization.prevNotarization.hash, priorNotTx, hashBlock) ||
                            hashBlock.IsNull() ||
                            !mapBlockIndex.count(hashBlock) ||
                            priorNotTx.vout.size() <= currentNotarization.prevNotarization.n ||
                            !priorNotTx.vout[currentNotarization.prevNotarization.n].scriptPubKey.IsPayToCryptoCondition(priorP) ||
                            !priorP.IsValid() ||
                            (priorP.evalCode != EVAL_ACCEPTEDNOTARIZATION && priorP.evalCode != EVAL_EARNEDNOTARIZATION) ||
                            priorP.vData.size() < 1 ||
                            !(priorNotarization = CPBaaSNotarization(priorP.vData[0])).IsValid() ||
                            (priorP.evalCode == EVAL_ACCEPTEDNOTARIZATION &&
                             !priorNotarization.IsBlockOneNotarization() &&
                             !priorNotarization.IsDefinitionNotarization()) ||
                            (currentNotarization.hashPrevCrossNotarization.IsNull() && !curDef.IsGateway()))
                        {
                            return state.Error("Invalid prior for earned notarization");
                        }

                        std::tuple<uint32_t, CUTXORef, CPBaaSNotarization> lastConfirmedNotarization =
                            GetLastConfirmedNotarization(currentNotarization.currencyID, height - 1);

                        if (!std::get<0>(lastConfirmedNotarization))
                        {
                            return state.Error("Cannot get last confirmed notarization");
                        }

                        CPBaaSNotarization lastLocalConfirmed = currentNotarization;
                        CObjectFinalization confirmedOf(CObjectFinalization::VERSION_INVALID);
                        CAddressIndexDbEntry localConfirmedIndex;

                        uint160 notarizationIdxKey = CCrossChainRPCData::GetConditionID(currentNotarization.currencyID,
                                                                                        CPBaaSNotarization::EarnedNotarizationKey(),
                                                                                        currentNotarization.hashPrevCrossNotarization);

                        CObjectFinalization lastConfirmedF;
                        CAddressIndexDbEntry lastConfirmedAddressIndexKey;

                        // if we can't find the prev cross on this chain, it means that when this was made, we were
                        // not notarized on the notary chain yet. That means our latest known last confirmed as of this
                        // notarization was the block 1 notarization
                        bool foundLocalCrossConfirmed =
                            CPBaaSNotarization::FindFinalizedIndexByVDXFKey(notarizationIdxKey, lastConfirmedF, lastConfirmedAddressIndexKey);

                        // confirm that we're never backsliding, and once one is found, they must move forward
                        notarizationIdxKey = CCrossChainRPCData::GetConditionID(priorNotarization.currencyID,
                                                                                CPBaaSNotarization::EarnedNotarizationKey(),
                                                                                priorNotarization.hashPrevCrossNotarization);

                        CObjectFinalization priorLastConfirmedF;
                        CAddressIndexDbEntry priorLastConfirmedAddressIndexKey;

                        bool foundPriorLocalCrossConfirmed =
                            CPBaaSNotarization::FindFinalizedIndexByVDXFKey(notarizationIdxKey, priorLastConfirmedF, priorLastConfirmedAddressIndexKey);

                        // ensure that we can always find one after the first and that we have not moved backwards in the one we find
                        // any cross confirmed notarization also must have first been confirmed on this chain, so verify that as well

                        if (foundPriorLocalCrossConfirmed &&
                            (!foundLocalCrossConfirmed ||
                             (lastConfirmedAddressIndexKey.first.blockHeight < priorLastConfirmedAddressIndexKey.first.blockHeight)))
                        {
                            if (LogAcceptCategory("notarization"))
                            {
                                // the last confirmed notarization on this chain, which must be either the same or more recent on this
                                // chain than any notarization we agree with on the alternate chain, refers to an older prior finalization
                                // output than the one we are about to confirm on our notary chain
                                LogPrintf("%s: Last confirmed notarization points to an older finalization\nlastconfirmedcrossfinalization: %s\nnewconfirmedcrossfinalization: %s\n\n",
                                            __func__,
                                            CUTXORef(priorLastConfirmedAddressIndexKey.first.txhash, priorLastConfirmedAddressIndexKey.first.index).ToString().c_str(),
                                            CUTXORef(lastConfirmedAddressIndexKey.first.txhash, lastConfirmedAddressIndexKey.first.index).ToString().c_str());
                            }
                            return state.Error("Invalid progression of prior cross-notarization hash");
                        }

                        // now, ensure that this still derives from the last confirmed on this chain by traveling backwards
                        // from this one until we either pass last confirmed and prove this invalid, or hit last confirmed
                        if (!IsEarnedNotarizationDescendent(currentNotarization,
                                                            priorNotarization,
                                                            hashBlock,
                                                            lastConfirmedNotarization,
                                                            state))
                        {
                            // leave reason in state
                            return false;
                        }

                        int64_t priorHeight = priorNotarization.proofRoots.count(ASSETCHAINS_CHAINID) ?
                                priorNotarization.proofRoots.find(ASSETCHAINS_CHAINID)->second.rootHeight :
                                0;

                        int64_t blockModulo = CPBaaSNotarization::GetAdjustedNotarizationModulo(ConnectedChains.ThisChain().blockNotarizationModulo,
                                                                                                priorHeight,
                                                                                                height);

                        if (height / blockModulo <= priorHeight / blockModulo)
                        {
                            return state.Error("earned notarization entered too early - ineligible");
                        }

                        CBlockIndex *pLastIndex = mapBlockIndex[hashBlock];

                        if (height > CPBaaSNotarization::BlocksBeforeAlternateStakeEnforcement())
                        {
                            // ensure that we alternate between stake and work notarizations
                            // since this is a coinbase, check to see if we have funds protected by stakeguard outputs
                            bool isStake = false;
                            for (int oneOutnum = 0; oneOutnum < tx.vout.size(); oneOutnum++)
                            {
                                auto &oneOutput = tx.vout[oneOutnum];
                                COptCCParams stakeP;
                                if (oneOutput.scriptPubKey.IsPayToCryptoCondition(stakeP) &&
                                    stakeP.IsValid() &&
                                    stakeP.evalCode == EVAL_STAKEGUARD &&
                                    RawPrecheckStakeGuardOutput(tx, oneOutnum, state))
                                {
                                    isStake = true;
                                    break;
                                }
                            }

                            if (pLastIndex->IsVerusPOSBlock() == isStake)
                            {
                                if (LogAcceptCategory("staking"))
                                {
                                    UniValue jsonTx(UniValue::VOBJ);
                                    TxToUniv(tx, uint256(), jsonTx);
                                    LogPrintf("%s: failed stakeguard transaction:\n%s\n", __func__, jsonTx.write(1,2).c_str());
                                }
                                return state.Error("earned notarizations must alternate between work and stake blocks - ineligible");
                            }
                        }

                        // if this refers to a prior notarization, look for any notarizations
                        // between that notarization and the new one that it does not reference
                        // if one or more exist, the tx must prove this notarization with full
                        // evidence randomized by the block hash of the block containing the
                        // notarization it agrees with
                        std::vector<CAddressIndexDbEntry> addresses;
                        CProofRoot challengeProof, startProof;
                        std::vector<CProofRoot> challengingRoots;

                        if (GetAddressIndex(
                                CCrossChainRPCData::GetConditionID(currentNotarization.currencyID, CPBaaSNotarization::NotaryNotarizationKey()),
                                CScript::P2IDX,
                                addresses,
                                priorHeight + 1,
                                height - 1) &&
                            addresses.size())
                        {
                            // if no conflicts, we should have one transaction only, and it should be our prior
                            // if we have more than one, we must also have full proof
                            for (auto &oneOutput : addresses)
                            {
                                CTransaction oneNotarizationTx;
                                uint256 oneBlockHash;
                                CPBaaSNotarization oneNotarization;
                                if (oneOutput.first.spending ||
                                    (oneOutput.first.txhash == currentNotarization.prevNotarization.hash &&
                                     oneOutput.first.index == currentNotarization.prevNotarization.n))
                                {
                                    continue;
                                }
                                if (!myGetTransaction(oneOutput.first.txhash, oneNotarizationTx, oneBlockHash) ||
                                    oneNotarizationTx.vout.size() <= oneOutput.first.index ||
                                    !(oneNotarization = CPBaaSNotarization(oneNotarizationTx.vout[oneOutput.first.index].scriptPubKey)).IsValid() ||
                                    oneNotarization.currencyID != currentNotarization.currencyID)
                                {
                                    return state.Error("ERROR: corrupt local chain data - should not move forward as a node. Bootstrap or resynchonrize blockchain.");
                                }
                                challengingRoots.push_back(oneNotarization.proofRoots[currentNotarization.currencyID]);
                            }
                        }

                        int afterEvidence;
                        CNotaryEvidence evidence(tx, outNum + 1, afterEvidence);
                        if (additionalEvidenceRequired)
                        {
                            // if the alternate chain information has not progressed at all, we do not
                            // need to verify further evidence
                            if (priorNotarization.proofRoots.count(currentNotarization.currencyID) &&
                                priorNotarization.proofRoots[currentNotarization.currencyID].rootHeight ==
                                    currentNotarization.proofRoots[currentNotarization.currencyID].rootHeight)
                            {
                                if (::AsVector(priorNotarization.currencyState) != ::AsVector(currentNotarization.currencyState))
                                {
                                    return state.Error("Currency state changed without proofroot change");
                                }
                                // verify that currency states have also not changed
                                for (auto &oneState : priorNotarization.currencyStates)
                                {
                                    CCurrencyDefinition checkStateDef = ConnectedChains.GetCachedCurrency(oneState.second.GetID());
                                    if (checkStateDef.systemID == currentNotarization.currencyID &&
                                        ::AsVector(priorNotarization.currencyState) != ::AsVector(currentNotarization.currencyState))
                                    {
                                        return state.Error("Currency state changed without proofroot change 1");
                                    }
                                }
                            }
                            else
                            {
                                if (!evidence.IsValid())
                                {
                                    return state.Error("Invalid notary evidence for earned notarization");
                                }

                                // check proof
                                uint256 entropyHash;
                                if (!IsValidPrimaryChainEvidence(curDef,
                                                                 evidence,
                                                                 currentNotarization,
                                                                 std::get<0>(lastConfirmedNotarization),
                                                                 height - 1,
                                                                 &entropyHash,
                                                                 challengingRoots.size() ? challengingRoots[0] : CProofRoot(CProofRoot::TYPE_PBAAS,
                                                                                                                            CProofRoot::VERSION_INVALID)).IsValid())
                                {
                                    return state.Error(std::string("Insufficient notary evidence for ") +
                                                    (challengingRoots.size() ? "challenged" : "unchallenged") + " earned notarization");
                                }
                            }
                        }
                    }
                }
            }
        }
        else
        {
            if (ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableDeFiKey()))
            {
                if (LogAcceptCategory("defi"))
                {
                    LogPrintf("%s: DeFi functions temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
                }
                return state.Error("DeFi functions temporarily disabled for security alert by notification oracle. Notarization rejected " + currentNotarization.ToUniValue().write(1,2));
            }

            // either this is another system entering an accepted notarization or one coming from an import or pre-launch export
            // determine which, based on the tx and presence of an import
            if (currentNotarization.IsPreLaunch())
            {
                // export or launch notarization
                if (p.evalCode == EVAL_EARNEDNOTARIZATION)
                {
                    return state.Error("Earned notarizations cannot be for pre-launch currencies");
                }

                // ensure that this is part of an export transaction
                int exportOutNum = -1;
                CCrossChainExport exportToCheck;
                for (int loop = 0; loop < tx.vout.size(); loop++)
                {
                    if ((exportToCheck = CCrossChainExport(tx.vout[loop].scriptPubKey)).IsValid() &&
                        !exportToCheck.IsSupplemental() &&
                        !exportToCheck.IsSystemThreadExport() &&
                        exportToCheck.destCurrencyID == currentNotarization.currencyID)
                    {
                        exportOutNum = loop;
                        break;
                    }
                    else
                    {
                        exportToCheck = CCrossChainExport();
                    }
                }

                // export or launch notarization
                if (exportOutNum < 0 || !exportToCheck.IsValid() || !exportToCheck.IsPrelaunch())
                {
                    if (LogAcceptCategory("notarization"))
                    {
                        UniValue txUniv(UniValue::VOBJ);
                        TxToUniv(tx, uint256(), txUniv);
                        LogPrintf("%s: notarization without export on transaction:\n%s\n", __func__, txUniv.write(1,2).c_str());
                    }
                    return state.Error("Prelaunch notarization with no export on transaction");
                }
                // precheck on cross chain export will create a new export from transfers and the last export
                // and ensure that it matches
            }
            else
            {
                std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization> priorNotarizationInfo;

                if (!(currentNotarization.IsDefinitionNotarization() ||
                      currentNotarization.IsBlockOneNotarization()))
                {
                    priorNotarizationInfo = GetPriorReferencedNotarization(tx, outNum, currentNotarization);
                    if (!std::get<3>(priorNotarizationInfo).IsValid())
                    {
                        if (LogAcceptCategory("notarization"))
                        {
                            UniValue txUniv(UniValue::VOBJ);
                            TxToUniv(tx, uint256(), txUniv);
                            LogPrintf("%s: Invalid prior notarization for %s\n", __func__, txUniv.write(1,2).c_str());
                            printf("%s: Invalid prior notarization for %s\n", __func__, txUniv.write(1,2).c_str());
                        }
                        return state.Error("Invalid prior notarization 4");
                    }
                }

                if (!currentNotarization.IsRefunding() &&
                    (curDef.IsPBaaSChain() || (curDef.IsGateway() && !currentNotarization.IsDefinitionNotarization())) &&
                     curDef.SystemOrGatewayID() != ASSETCHAINS_CHAINID)
                {
                    // we should only approve accepted notarizations that have the following qualifications
                    // for the following protocols:
                    // NOTARIZATION_AUTO        -   must have evidence to prove that one recent earned notarization
                    //                              from either a PoW or PoS block refers to and proves another alternated
                    //                              and proven PoW or PoS earned notarization, which then alternates and proves
                    //                              the notarization being confirmed. This allows us to post it, but it must mature
                    //                              N blocks without being rejected by the notaries to be considered confirmed.
                    // NOTARIZATION_NOTARY_CONFIRM - requires no evidence beyond notary signatures
                    // NOTARIZATION_NOTARY_CHAINID - requires no evidence beyond chain signature

                    // first get evidence and check signatures
                    int afterEvidence;
                    CNotaryEvidence evidence(tx, outNum + 1, afterEvidence);
                    if (!evidence.IsValid())
                    {
                        return state.Error("Invalid notary evidence for accepted notarization");
                    }

                    auto notarySignatures = evidence.GetNotarySignatures();

                    CCurrencyDefinition::EHashTypes hashType = CCurrencyDefinition::EHashTypes::HASH_BLAKE2BMMR;
                    if (notarySignatures.size() && notarySignatures[0].signatures.size())
                    {
                        hashType = (CCurrencyDefinition::EHashTypes)(notarySignatures[0].signatures.begin()->second.hashType);
                    }

                    if (ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisablePBaaSCrossChainKey()))
                    {
                        if (LogAcceptCategory("defi"))
                        {
                            LogPrintf("%s: Cross-chain functions temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
                        }
                        return state.Error("Cross-chain functions temporarily disabled for security alert by notification oracle. Notarization rejected " + currentNotarization.ToUniValue().write(1,2));
                    }
                    else if (curDef.IsGateway() &&
                             ConnectedChains.activeUpgradesByKey.count(ConnectedChains.DisableGatewayCrossChainKey()))
                    {
                        if (LogAcceptCategory("defi"))
                        {
                            LogPrintf("%s: Non-PBaaS cross-chain functions temporarily disabled for security alert by notification oracle %s\n", PBAAS_DEFAULT_NOTIFICATION_ORACLE.c_str());
                        }
                        return state.Error(" Non-PBaaS cross-chain functions temporarily disabled for security alert by notification oracle. Notarization rejected " + currentNotarization.ToUniValue().write(1,2));
                    }

                    CNativeHashWriter hw(hashType);
                    CPBaaSNotarization normalizedNotarization = currentNotarization;
                    if (!currentNotarization.SetMirror(false))
                    {
                        return state.Error("Notarization cannot be unmirrored");
                    }

                    bool signatureRequired = !curDef.IsPBaaSChain() ||
                                             curDef.notarizationProtocol != curDef.NOTARIZATION_AUTO ||
                                             curDef.proofProtocol != curDef.PROOF_PBAASMMR;

                    hw << currentNotarization;
                    if (evidence.CheckSignatureConfirmation(hw.GetHash(), hashType, curDef.GetNotarySet(), curDef.minNotariesConfirm, height - 1) !=
                            CNotaryEvidence::EStates::STATE_CONFIRMED &&
                        signatureRequired)
                    {
                        if (LogAcceptCategory("notarization"))
                        {
                            LogPrintf("Cannot confirm notary signatures for evidence: %s\n", evidence.ToUniValue().write(1,2).c_str());
                        }
                        return state.Error("Cannot confirm notary signatures for notarization");
                    }

                    if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                    {
                        LogPrintf("checkpoint for evidence: %s\n", evidence.ToUniValue().write(1,2).c_str());
                    }

                    // each PBaaS chain notarization will also include a proof of the notarization
                    // transaction in the case of block 1 of a PBaaS chain launch, it will include a proof of the
                    // entire block 1 coinbase transaction, which can be reconstructed and proven here
                    // and accepted only if all currency definition rules were properly followed
                    if (additionalEvidenceRequired && curDef.IsPBaaSChain())
                    {
                        // if this is the first notarization since block 1, it contains a full proof of the block 1 coinbase transaction
                        // ensure that it does and that a recreation of it results in the exact same outputs, except for miner rewards,
                        // which whould total to the same values, but may have different recipients

                        // get last confirmed notarization if there is one for last confirmed height param
                        auto lastConfirmedNotarizationInfo = GetLastConfirmedNotarization(normalizedNotarization.currencyID, height - 1);
                        if (!std::get<0>(lastConfirmedNotarizationInfo))
                        {
                            lastConfirmedNotarizationInfo = GetLastConfirmedNotarization(normalizedNotarization.currencyID, height - 1);
                            return state.Error("Unable to get prior confirmed accepted notarization");
                        }

                        if (!IsNotarizationDescendent(normalizedNotarization, priorNotarizationInfo, lastConfirmedNotarizationInfo, state))
                        {
                            return false;
                        }

                        vector<CAddressIndexDbEntry> addresses;
                        std::vector<CProofRoot> challengingRoots;
                        if ((std::get<0>(priorNotarizationInfo) + 1) >= (height - 1) &&
                            GetAddressIndex(
                                CCrossChainRPCData::GetConditionID(normalizedNotarization.currencyID, CPBaaSNotarization::NotaryNotarizationKey()),
                                CScript::P2IDX,
                                addresses,
                                std::get<0>(priorNotarizationInfo) + 1,
                                height - 1) &&
                            addresses.size())
                        {
                            // if no conflicts, we should have one transaction only, and it should be our prior
                            // if we have more than one, we must also have full proof
                            for (auto &oneOutput : addresses)
                            {
                                CTransaction oneNotarizationTx;
                                uint256 oneBlockHash;
                                CPBaaSNotarization oneNotarization;
                                if (oneOutput.first.spending ||
                                    (oneOutput.first.txhash == normalizedNotarization.prevNotarization.hash &&
                                     oneOutput.first.index == normalizedNotarization.prevNotarization.n))
                                {
                                    continue;
                                }
                                if (!myGetTransaction(oneOutput.first.txhash, oneNotarizationTx, oneBlockHash) ||
                                    oneNotarizationTx.vout.size() <= oneOutput.first.index ||
                                    !(oneNotarization = CPBaaSNotarization(oneNotarizationTx.vout[oneOutput.first.index].scriptPubKey)).IsValid() ||
                                    oneNotarization.currencyID != normalizedNotarization.currencyID)
                                {
                                    return state.Error("ERROR: corrupt local chain data - should not move forward as a node. Bootstrap or resynchonrize blockchain.");
                                }
                                challengingRoots.push_back(oneNotarization.proofRoots[normalizedNotarization.currencyID]);
                            }
                        }

                        if (LogAcceptCategory("notarization"))
                        {
                            printf("%s: last notarization: %s\n", __func__, std::get<3>(priorNotarizationInfo).ToUniValue().write(1,2).c_str());
                            LogPrintf("%s: last notarization: %s\n", __func__, std::get<3>(priorNotarizationInfo).ToUniValue().write(1,2).c_str());
                        }

                        uint256 entropyHash;
                        if (!IsValidPrimaryChainEvidence(curDef,
                                                         evidence,
                                                         normalizedNotarization,
                                                         std::get<0>(lastConfirmedNotarizationInfo),
                                                         height - 1,
                                                         &entropyHash,
                                                         challengingRoots.size() ?
                                                             challengingRoots[0] :
                                                             CProofRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID)).IsValid())
                        {
                            return state.Error("Unable to verify " + std::string(challengingRoots.size() ? "challenged" : "unchallenged") + " accepted notarization");
                        }
                    }
                }

                // verify transitions
                if (std::get<0>(priorNotarizationInfo))
                {
                    if (std::get<3>(priorNotarizationInfo).IsPreLaunch() &&
                        !((currentNotarization.currencyState.IsLaunchClear() || curDef.systemID != ASSETCHAINS_CHAINID) &&
                          ((currentNotarization.IsLaunchConfirmed() && currentNotarization.currencyState.IsLaunchConfirmed()) ||
                           (currentNotarization.IsRefunding() && (currentNotarization.currencyState.IsRefunding())))))
                    {
                        LogPrintf("%s: Launch clear confirmed or refunding must be first non-prelaunch notarization %s\n", __func__, ConnectedChains.GetFriendlyCurrencyName(currentNotarization.currencyID).c_str());
                        return false;
                    }
                    if (std::get<3>(priorNotarizationInfo).IsRefunding() && !(currentNotarization.currencyState.IsRefunding() && currentNotarization.IsRefunding()))
                    {
                        LogPrintf("%s: Cannot change refunding state for %s\n", __func__, ConnectedChains.GetFriendlyCurrencyName(currentNotarization.currencyID).c_str());
                        return false;
                    }
                    else if (std::get<3>(priorNotarizationInfo).IsLaunchConfirmed() && (currentNotarization.currencyState.IsRefunding() || currentNotarization.IsRefunding()))
                    {
                        LogPrintf("%s: Cannot change refunding state for %s\n", __func__, ConnectedChains.GetFriendlyCurrencyName(currentNotarization.currencyID).c_str());
                        return false;
                    }
                }
            }
        }
    }
    return true;
}

LRUCache<CUTXORef, std::tuple<uint256, CTransaction, std::vector<std::pair<CObjectFinalization, CNotaryEvidence>>>> finalizationEvidenceCache(100, 0.3);

// get and aggregate all evidence from a finalization
std::vector<std::pair<CObjectFinalization, CNotaryEvidence>>
CObjectFinalization::GetFinalizationEvidence(const CTransaction &thisTx, int32_t outNum, CValidationState &state, CTransaction *pOutputTx) const
{
    if (thisTx.GetHash().IsNull())
    {
        printf("%s: BAD PARAMETER\n", __func__);
    }
    std::tuple<uint256, CTransaction, std::vector<std::pair<CObjectFinalization, CNotaryEvidence>>> cachedReturn;
    CUTXORef cacheKey = CUTXORef(thisTx.GetHash(), outNum);

    // don't look it up by block hash, but make sure the block that was tip when it was entered is still on the chain
    if (finalizationEvidenceCache.Get(cacheKey, cachedReturn))
    {
        if (mapBlockIndex.count(std::get<0>(cachedReturn)) &&
            chainActive.Contains(mapBlockIndex[std::get<0>(cachedReturn)]))
        {
            return std::get<2>(cachedReturn);
        }
    }

    CTransaction _outputTx;
    CUTXORef fullOutput(output);
    uint256 outputTxBlockHash;
    CTransaction &finalizedTx = pOutputTx ? *pOutputTx : _outputTx;

    std::vector<std::pair<CObjectFinalization, CNotaryEvidence>> emptyVec;

    if (fullOutput.hash.IsNull())
    {
        fullOutput.hash = thisTx.GetHash();
    }

    if (!GetOutputTransaction(thisTx, finalizedTx, outputTxBlockHash))
    {
        state.Error(std::string(__func__) + ": cannot retrieve output transaction for finalization");
        LogPrint("notarization", "%s: cannot retrieve output transaction for finalization\n", __func__);
        return emptyVec;
    }

    CPBaaSNotarization notarization;
    std::vector<std::pair<CObjectFinalization, CNotaryEvidence>> evidenceVec;

    COptCCParams p;
    if (!(finalizedTx.vout[output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
          p.IsValid() &&
          (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
          p.vData.size() &&
          (notarization = CPBaaSNotarization(p.vData[0])).IsValid()))
    {
        state.Error(std::string(__func__) + ": invalid notarization output for finalization");
        LogPrint("notarization", "%s: Invalid notarization output for finalization\n", __func__);
        return emptyVec;
    }

    // collect all evidence, outputs first
    if (evidenceOutputs.size() || evidenceInputs.size())
    {
        CTransaction evidenceTx;

        // add evidence outs as spends to close this entry as well
        int afterMultiPart = evidenceOutputs.size() ? evidenceOutputs[0] : 0;
        for (int i = 0; i < evidenceOutputs.size(); i++)
        {
            auto oneEvidenceOutN = evidenceOutputs[i];
            if (thisTx.vout.size() <= oneEvidenceOutN)
            {
                state.Error(std::string(__func__) + ": indexing error for finalization evidence");
                LogPrint("notarization", "%s: indexing error for finalization evidence\n", __func__);
                return emptyVec;
            }

            if (oneEvidenceOutN >= afterMultiPart)
            {
                CNotaryEvidence oneEvidenceObj(thisTx, oneEvidenceOutN, afterMultiPart);
                if (oneEvidenceObj.IsValid())
                {
                    if (evidenceVec.size())
                    {
                        evidenceVec[0].second.MergeEvidence(oneEvidenceObj);
                    }
                    else
                    {
                        evidenceVec.push_back(std::make_pair(*this, oneEvidenceObj));
                    }
                }
            }
        }

        CTransaction priorOutputTx;
        CNotaryEvidence oneEvidenceObj;
        std::vector<CNotaryEvidence> evidenceInVec;
        CObjectFinalization priorFinalization;
        for (int i = 0; i < evidenceInputs.size(); i++)
        {
            auto oneIn = evidenceInputs[i];
            uint256 hashBlock;
            if ((priorOutputTx.GetHash().IsNull() ||
                 priorOutputTx.GetHash() != thisTx.vin[oneIn].prevout.hash) &&
                !myGetTransaction(thisTx.vin[oneIn].prevout.hash, priorOutputTx, hashBlock))
            {
                state.Error(std::string(__func__) + ": cannot access transaction " + thisTx.vin[oneIn].prevout.hash.GetHex() + " for notarization evidence");
                LogPrint("notarization", "%s: cannot access transaction %s for notarization evidence\n", __func__, thisTx.vin[oneIn].prevout.hash.GetHex().c_str());
                return emptyVec;
            }

            COptCCParams inP;
            if (priorOutputTx.vout[thisTx.vin[oneIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(inP) &&
                inP.IsValid() &&
                inP.evalCode == EVAL_NOTARY_EVIDENCE &&
                inP.vData.size() &&
                (oneEvidenceObj = CNotaryEvidence(inP.vData[0])).IsValid() &&
                oneEvidenceObj.evidence.chainObjects.size())
            {
                // if we are starting a new object, finish the old one
                if (!oneEvidenceObj.IsMultipartProof() ||
                    ((CChainObject<CEvidenceData> *)oneEvidenceObj.evidence.chainObjects[0])->object.md.index == 0)
                {
                    // if we have a composite evidence object, store it and clear the vector
                    if (evidenceInVec.size())
                    {
                        CNotaryEvidence multiPartEvidence(evidenceInVec);
                        if (multiPartEvidence.IsValid())
                        {
                            if (evidenceVec.size())
                            {
                                evidenceVec[0].second.MergeEvidence(multiPartEvidence);
                            }
                            else
                            {
                                evidenceVec.push_back(std::make_pair(*this, multiPartEvidence));
                            }
                        }
                        evidenceInVec.clear();
                    }
                }

                if (!oneEvidenceObj.IsMultipartProof())
                {
                    evidenceVec.push_back(std::make_pair(*this, oneEvidenceObj));
                }
                else
                {
                    evidenceInVec.push_back(oneEvidenceObj);
                }
            }
            else if (inP.IsValid() &&
                     inP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                     inP.vData.size() &&
                     (priorFinalization = CObjectFinalization(inP.vData[0])).IsValid())
            {
                // cleanup any pending multipart
                if (evidenceInVec.size())
                {
                    CNotaryEvidence multiPartEvidence(evidenceInVec);
                    if (multiPartEvidence.IsValid())
                    {
                        if (evidenceVec.size())
                        {
                            evidenceVec[0].second.MergeEvidence(multiPartEvidence);
                        }
                        else
                        {
                            evidenceVec.push_back(std::make_pair(*this, multiPartEvidence));
                        }
                    }
                    evidenceInVec.clear();
                }

                CTransaction priorFinalizationTx;
                auto priorFinalizationVec = priorFinalization.GetFinalizationEvidence(priorOutputTx, thisTx.vin[oneIn].prevout.n, state, &priorFinalizationTx);
                evidenceVec.insert(evidenceVec.end(), priorFinalizationVec.begin(), priorFinalizationVec.end());
            }
        }

        // if we have a composite evidence object, store it and clear the vector
        if (evidenceInVec.size())
        {
            CNotaryEvidence multiPartEvidence(evidenceInVec);
            if (multiPartEvidence.IsValid())
            {
                if (evidenceVec.size())
                {
                    evidenceVec[0].second.MergeEvidence(multiPartEvidence);
                }
                else
                {
                    evidenceVec.push_back(std::make_pair(*this, multiPartEvidence));
                }
            }
            else
            {
                state.Error(std::string(__func__) + ": invalid multipart evidence on input");
                LogPrint("notarization", "%s: invalid multipart evidence on input\n", __func__);
                return emptyVec;
            }
        }
    }
    if (evidenceVec.size())
    {
        finalizationEvidenceCache.Put(cacheKey, {chainActive.LastTip()->GetBlockHash(), finalizedTx, evidenceVec});
    }
    return evidenceVec;
}

bool PreCheckNotaryEvidence(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    COptCCParams p;
    CNotaryEvidence currentEvidence;
    if (!(tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
          p.IsValid() &&
          p.evalCode == EVAL_NOTARY_EVIDENCE &&
          p.vData.size() &&
          (currentEvidence = CNotaryEvidence(p.vData[0])).IsValid()) &&
          p.IsEvalPKOut())
    {
        return state.Error("Invalid notary evidence output");
    }
    // if multipart data, get the full evidence, and if this is the first
    // output with it, continue verification, otherwise, consider it done
    int32_t afterEvidence = 0;
    if (currentEvidence.type == currentEvidence.TYPE_MULTIPART_DATA)
    {
        if (currentEvidence.evidence.chainObjects.size() != 1 ||
            currentEvidence.evidence.chainObjects[0]->objectType != CHAINOBJ_EVIDENCEDATA)
        {
            return state.Error("Invalid multipart evidence output");
        }
        if (((CChainObject<CEvidenceData> *)(currentEvidence.evidence.chainObjects[0]))->object.type == CEvidenceData::TYPE_MULTIPART_DATA)
        {
            COptCCParams multiP;
            CNotaryEvidence multiEvidence;
            int multiStart = (outNum - ((CChainObject<CEvidenceData> *)(currentEvidence.evidence.chainObjects[0]))->object.md.index);
            if (multiStart >= 0 &&
                tx.vout[multiStart].scriptPubKey.IsPayToCryptoCondition(multiP) &&
                multiP.IsValid() &&
                multiP.evalCode == EVAL_NOTARY_EVIDENCE &&
                multiP.vData.size() &&
                (multiEvidence = CNotaryEvidence(multiP.vData[0])).IsValid() &&
                multiEvidence.type == CEvidenceData::TYPE_MULTIPART_DATA &&
                multiEvidence.evidence.chainObjects.size() == 1 &&
                multiEvidence.evidence.chainObjects[0]->objectType == CHAINOBJ_EVIDENCEDATA &&
                ((CChainObject<CEvidenceData> *)(multiEvidence.evidence.chainObjects[0]))->object.type == CEvidenceData::TYPE_MULTIPART_DATA &&
                ((CChainObject<CEvidenceData> *)(multiEvidence.evidence.chainObjects[0]))->object.md.index == 0 &&
                (multiEvidence = CNotaryEvidence(tx, multiStart, afterEvidence)).IsValid() &&
                afterEvidence > outNum)
            {
                if (multiStart != outNum)
                {
                    return true;
                }
                currentEvidence = multiEvidence;
            }
            else
            {
                return state.Error("Invalid multipart evidence");
            }
        }
    }
    // now verify that the evidence we have has the following properties:
    // 1) if it is import proof evidence, ensure it has one partial transaction proof
    // 2) if notary proof evidence, it should have the following properties:
    //  a) output that references a notarization
    //  b) either rejection based on more powerful chain or rejecting signatures
    //  c) or confirming signatures and if accepted notarization, additional proof evidence
    //
    if (currentEvidence.type != currentEvidence.TYPE_IMPORT_PROOF &&
        currentEvidence.type != currentEvidence.TYPE_NOTARY_EVIDENCE)
    {
        return state.Error("Invalid evidence type");
    }

    bool inSync = height <= (chainActive.Height() + 1);

    // if this is notary evidence, it must reference a notarization and be a confirmation signed by a notary, or a rejection that may either be signed
    // or provide proof of a more powerful chain
    if (currentEvidence.type == currentEvidence.TYPE_NOTARY_EVIDENCE)
    {
        // get notarization
        CTransaction outputTx;
        uint256 blockHash;
        if (currentEvidence.output.IsOnSameTransaction())
        {
            outputTx = tx;
        }
        else
        {
            if (currentEvidence.systemID != ASSETCHAINS_CHAINID || !currentEvidence.output.GetOutputTransaction(outputTx, blockHash))
            {
                if (!inSync || currentEvidence.systemID != ASSETCHAINS_CHAINID)
                {
                    return true;
                }
                else
                {
                    return state.Error("Cannot get underlying notarization");
                }
            }
        }

        COptCCParams notaP;
        CPBaaSNotarization notarizationForEvidence;
        if (!(currentEvidence.output.n < outputTx.vout.size() &&
              outputTx.vout[currentEvidence.output.n].scriptPubKey.IsPayToCryptoCondition(notaP) &&
              notaP.IsValid() &&
              (notaP.evalCode == EVAL_EARNEDNOTARIZATION || notaP.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
              notaP.vData.size() &&
              (notarizationForEvidence = CPBaaSNotarization(notaP.vData[0])).IsValid()))
        {
            return state.Error("Invalid notarization for evidence");
        }

        CCurrencyDefinition notaryCurrency = ConnectedChains.GetCachedCurrency(notarizationForEvidence.currencyID);
        if (!notaryCurrency.IsValid())
        {
            return state.Error("Invalid notary currency");
        }
        std::vector<uint160> *pActiveNotaries;
        if ((notaryCurrency.IsGateway() && notaryCurrency.launchSystemID == ASSETCHAINS_CHAINID) ||
            IsVerusActive())
        {
            pActiveNotaries = &notaryCurrency.notaries;
        }
        else
        {
            pActiveNotaries = &(ConnectedChains.ThisChain().notaries);
        }
        std::vector<CNotarySignature> notarySignatures = currentEvidence.GetNotarySignatures();
        bool notarySigned = false;
        for (auto &oneNotaryID : *pActiveNotaries)
        {
            for (auto &oneSig : notarySignatures)
            {
                if (oneSig.signatures.count(oneNotaryID))
                {
                    notarySigned = true;
                    break;
                }
            }
        }
    }
    return true;
}

bool CObjectFinalization::GetPendingEvidence(const CCurrencyDefinition &externalSystem,
                                             const CUTXORef &notarizationRef,
                                             uint32_t endHeight,
                                             std::vector<std::pair<bool, CProofRoot>> &validCounterRoots,
                                             CProofRoot &challengeStartRoot,
                                             std::vector<CInputDescriptor> &outputs,
                                             bool &invalidates,
                                             CValidationState &state)
{
    invalidates = false;
    uint160 currencyID = externalSystem.GetID();

    CPBaaSNotarization normalizedNotarization;
    CTransaction notarizationTx;
    uint256 blockHash;
    CBlockIndex *pIndex = nullptr;
    if (!(notarizationRef.GetOutputTransaction(notarizationTx, blockHash) &&
          notarizationTx.vout.size() > notarizationRef.n &&
          !blockHash.IsNull() &&
          mapBlockIndex.count(blockHash) &&
          chainActive.Contains(pIndex = mapBlockIndex[blockHash]) &&
          (normalizedNotarization = CPBaaSNotarization(notarizationTx.vout[notarizationRef.n].scriptPubKey)).IsValid() &&
          normalizedNotarization.currencyID == currencyID))
    {
        return state.Error("Cannot get valid notarization from output reference");
    }

    uint32_t startHeight = pIndex->GetHeight();

    std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization>>
        ofsToCheck =
            CObjectFinalization::GetFinalizations(notarizationRef,
                                                  CObjectFinalization::ObjectFinalizationPendingKey(),
                                                  startHeight,
                                                  endHeight);

    for (auto &oneFinalization : ofsToCheck)
    {
        outputs.push_back(CInputDescriptor(std::get<2>(oneFinalization).vout[std::get<1>(oneFinalization).n].scriptPubKey,
                                           std::get<2>(oneFinalization).vout[std::get<1>(oneFinalization).n].nValue,
                                           CTxIn(std::get<1>(oneFinalization))));
        std::vector<std::pair<CObjectFinalization, CNotaryEvidence>> ofEvidence =
            std::get<3>(oneFinalization).GetFinalizationEvidence(std::get<2>(oneFinalization), std::get<1>(oneFinalization).n, state);
        for (auto &oneEItem : ofEvidence)
        {
            // if we find a rejection, check it
            if (oneEItem.second.IsRejected())
            {
                CProofRoot challengeStart(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);
                CProofRoot counterRoot = IsValidChallengeEvidence(externalSystem,
                                                                  normalizedNotarization.proofRoots[currencyID],
                                                                  oneEItem.second,
                                                                  blockHash,
                                                                  invalidates,
                                                                  challengeStart,
                                                                  endHeight);
                if (invalidates)
                {
                    break;
                }
                if (challengeStart.IsValid() && counterRoot.IsValid())
                {
                    bool isMorePowerful = CChainPower::ExpandCompactPower(counterRoot.compactPower) >
                                                CChainPower::ExpandCompactPower(normalizedNotarization.proofRoots[currencyID].compactPower);
                    validCounterRoots.push_back(std::make_pair(isMorePowerful, counterRoot));
                    if (!challengeStartRoot.IsValid() || challengeStart.rootHeight < challengeStartRoot.rootHeight)
                    {
                        challengeStartRoot = challengeStart;
                    }
                }
            }
        }
    }
    return true;
}

std::vector<CAddressIndexDbEntry> FilterUnspent(const std::vector<CAddressIndexDbEntry> &addresses)
{
    std::vector<CAddressIndexDbEntry> retVal;
    std::set<COutPoint> spentTxOuts;
    std::set<COutPoint> txOuts;

    for (auto &oneOut : addresses)
    {
        // get last one in spending list
        if (oneOut.first.spending)
        {
            CTransaction priorOutTx;
            uint256 blockHash;
            CTransaction curTx;

            if (myGetTransaction(oneOut.first.txhash, curTx, blockHash) &&
                curTx.vin.size() > oneOut.first.index)
            {
                spentTxOuts.insert(curTx.vin[oneOut.first.index].prevout);
            }
            else
            {
                LogPrint("crosschainimports","Unable to retrieve data to filter address index\n");
                return retVal;
            }
        }
    }
    for (auto &oneOut : addresses)
    {
        if (!oneOut.first.spending && !spentTxOuts.count(COutPoint(oneOut.first.txhash, oneOut.first.index)))
        {
            retVal.push_back(oneOut);
        }
    }
    return retVal;
}

bool PreCheckFinalizeNotarization(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // ensure that if we are finalizing a notarization, we have followed all rules to do so
    // after we precheck and confirm a notarization finalization for a notary chain of this chain, we record it
    // as the last notarized checkpoint and prevent any unwind of the blockchain from that point

    // Finalizing a notarization does not generally happen without a chain of notarizations, in addition
    // to some set of evidence.
    //
    // Generally, the evidence will include one or more of the following:
    // 1) Minimum number (2 for signed, 4 for auto) of more recent notarization(s) that build on the notarization being finalized
    // 2) Answer to any challenge that has occurred since the notarization was posted
    // 2) A majority of witness signatures
    //

    uint32_t chainHeight = chainActive.Height();
    bool haveFullChain = height <= chainHeight + 1;

    auto upgradeVersion = CConstVerusSolutionVector::GetVersionByHeight(height);
    if (upgradeVersion < CActivationHeight::ACTIVATE_VERUSVAULT)
    {
        return true;
    }
    else if (upgradeVersion < CActivationHeight::ACTIVATE_PBAAS)
    {
        return false;
    }

    // ensure that we never accept an invalid proofroot for this chain in a notarization
    COptCCParams p;
    CObjectFinalization currentFinalization;
    if (!(tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
          p.IsValid() &&
          p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
          p.vData.size() &&
          (currentFinalization = CObjectFinalization(p.vData[0])).IsValid()) &&
          p.IsEvalPKOut() &&
          currentFinalization.FinalizationType() == CObjectFinalization::EFinalizationType::FINALIZE_NOTARIZATION)
    {
        return state.Error("Invalid finalization for notarization output");
    }

    CTransaction finalizedTx;
    uint256 txBlockHash;
    CPBaaSNotarization notarization;
    BlockMap::iterator notaTxBlockIt;

    if (!(currentFinalization.GetOutputTransaction(tx, finalizedTx, txBlockHash, false) &&
          finalizedTx.vout[currentFinalization.output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
          p.IsValid() &&
          (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
          p.vData.size() &&
          (notarization = CPBaaSNotarization(p.vData[0])).IsValid()))
    {
        if (!haveFullChain)
        {
            return true;
        }
        return state.Error("Invalid notarization output for finalization");
    }

    if (currentFinalization.IsConfirmed() &&
         height != 1 &&
         !(!txBlockHash.IsNull() &&
           (notaTxBlockIt = mapBlockIndex.find(txBlockHash)) != mapBlockIndex.end() &&
           chainActive.Contains(notaTxBlockIt->second)))
    {
        return state.Error("Uncommitted notarization output is invalid for finalization");
    }

    for (int i = outNum + 1; i < tx.vout.size(); i++)
    {
        if (i == currentFinalization.output.n)
        {
            continue;
        }
        COptCCParams dupP;
        CObjectFinalization dupOf;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(dupP) &&
            dupP.IsValid() &&
            dupP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
            dupP.vData.size() &&
            (dupOf = CObjectFinalization(dupP.vData[0])).IsValid() &&
            dupOf.output == currentFinalization.output)
        {
            return state.Error("Duplicate notarization finalization output");
        }
    }

    if (p.evalCode == EVAL_EARNEDNOTARIZATION &&
        !ConnectedChains.notarySystems.count(notarization.currencyID))
    {
        if (!haveFullChain)
        {
            return true;
        }
        return state.Error("Earned notarizations are only valid for notary systems");
    }

    CPBaaSNotarization normalizedNotarization = notarization;
    uint160 curID = normalizedNotarization.currencyID;

    CCurrencyDefinition notaryCurrencyDef = ConnectedChains.GetCachedCurrency(curID);
    if (!notaryCurrencyDef.IsValid())
    {
        return state.Error("Cannot get currency definition for notarization");
    }

    const CCurrencyDefinition *pNotaryCurrency;
    if (IsVerusActive() || !ConnectedChains.notarySystems.count(curID))
    {
        pNotaryCurrency = &notaryCurrencyDef;
    }
    else
    {
        pNotaryCurrency = &ConnectedChains.thisChain;
    }

    CNativeHashWriter hw(
        (pNotaryCurrency->IsGateway() &&
        pNotaryCurrency->launchSystemID == ASSETCHAINS_CHAINID &&
        pNotaryCurrency->proofProtocol == pNotaryCurrency->PROOF_ETHNOTARIZATION) ?
            notaryCurrencyDef.PROOF_ETHNOTARIZATION :
            pNotaryCurrency->PROOF_PBAASMMR);

    if (!notarization.SetMirror(false))
    {
        return state.Error("Cannot prepare notarization to validate finalization");
    }

    hw << notarization;
    uint256 objHash = hw.GetHash();

    CTransaction notarizationTx;

    // combine and verify all evidence, primarily to get all signatures in one
    // other evidence is evaluated in its originally submitted bundle
    std::vector<std::pair<CObjectFinalization, CNotaryEvidence>> evidenceVec =
        currentFinalization.GetFinalizationEvidence(tx, outNum, state, &notarizationTx);

    if (state.IsError() || !haveFullChain)
    {
        return !haveFullChain;
    }

    auto pCurNotarizationBlkIndex = txBlockHash.IsNull() ? chainActive[height - 1] :
                                                           mapBlockIndex.count(txBlockHash) ? mapBlockIndex.find(txBlockHash)->second : nullptr;
    if (!pCurNotarizationBlkIndex)
    {
        return state.Error("Notarization from invalid block cannot be finalized");
    }
    if (!chainActive.Contains(pCurNotarizationBlkIndex))
    {
        return state.Error("Block notarization not in active chain cannot be finalized");
    }

    bool confirmNeedsEvidence = !(notarization.IsPreLaunch() ||
                                  notarization.IsBlockOneNotarization() ||
                                  notarization.IsDefinitionNotarization()) &&
                                pNotaryCurrency->proofProtocol == pNotaryCurrency->PROOF_PBAASMMR &&
                                pNotaryCurrency->notarizationProtocol != pNotaryCurrency->PROOF_CHAINID;

    CNotaryEvidence signatureEvidence;
    std::vector<std::pair<CObjectFinalization, CNotaryEvidence>> counterEvidenceVec;

    // combine and verify signatures, segregating by evidence source system, not by finalization system
    std::map<uint160, std::vector<std::pair<CObjectFinalization, CNotaryEvidence>>> evidenceMap;

    for (auto &oneEvidenceChunk : evidenceVec)
    {
        if (oneEvidenceChunk.second.IsRejected())
        {
            counterEvidenceVec.push_back(oneEvidenceChunk);
        }
        if (evidenceMap.count(oneEvidenceChunk.second.systemID))
        {
            // merge signatures into 0th, and add additional evidence after 0th element
            evidenceMap[oneEvidenceChunk.second.systemID][0].second.MergeEvidence(oneEvidenceChunk.second, true, true);
            evidenceMap[oneEvidenceChunk.second.systemID].push_back(oneEvidenceChunk);
        }
        else
        {
            evidenceMap[oneEvidenceChunk.second.systemID].push_back(oneEvidenceChunk);
        }
    }

    auto notarySet = pNotaryCurrency->GetNotarySet();
    int numSignedNeeded = CPBaaSNotarization::MIN_EARNED_FOR_SIGNED;
    int numAutoNeeded = CPBaaSNotarization::MIN_EARNED_FOR_AUTO;
    int numBlocksAutoNeeded = CPBaaSNotarization::MinBlocksToAutoNotarization(ConnectedChains.ThisChain().blockNotarizationModulo);
    int numBlocksSignedNeeded = CPBaaSNotarization::MinBlocksToSignedNotarization(ConnectedChains.ThisChain().blockNotarizationModulo);

    if (!haveFullChain)
    {
        return true;
    }

    // get last confirmed notarization if there is one for last confirmed height param
    auto lastConfirmedNotarizationInfo = GetLastConfirmedNotarization(curID, height - 1);
    if (!std::get<0>(lastConfirmedNotarizationInfo))
    {
        if (LogAcceptCategory("notarization"))
        {
            lastConfirmedNotarizationInfo = GetLastConfirmedNotarization(curID, height - 1);
        }
        return state.Error("unable to get last confirmed notarization");
    }

    if (currentFinalization.IsConfirmed() || currentFinalization.IsRejected())
    {
        CUTXORef finalizationOutput = currentFinalization.output;
        finalizationOutput.hash = finalizedTx.GetHash();

        // if this is already finalized, we can't do it again
        auto priorFinalizations = CObjectFinalization::GetFinalizations(finalizationOutput,
                                                                        CObjectFinalization::ObjectFinalizationFinalizedKey(),
                                                                        pCurNotarizationBlkIndex->GetHeight(),
                                                                        height - 1);
        if (priorFinalizations.size())
        {
            // as long as we're spending it, it's ok
            std::map<CUTXORef, bool> outputSet;
            for (auto &oneFinalization : priorFinalizations)
            {
                if (std::get<3>(oneFinalization).output.hash.IsNull())
                {
                    std::get<3>(oneFinalization).output.hash = std::get<2>(oneFinalization).GetHash();
                }
                outputSet.insert(std::make_pair(std::get<3>(oneFinalization).output, std::get<3>(oneFinalization).IsConfirmed()));
            }

            for (int j = 0; j < tx.vin.size(); j++)
            {
                auto outputIt = outputSet.find(tx.vin[j].prevout);
                if (outputIt != outputSet.end() &&
                    (outputIt->second == currentFinalization.IsConfirmed()))
                {
                    outputSet.erase(tx.vin[j].prevout);
                }
            }
            return outputSet.size() ?
                        state.Error(std::string("already ") + (std::get<3>(priorFinalizations[0]).IsConfirmed() ? "confirmed" : "rejected")) :
                        true;
        }

        std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization>> pendingFinalizations =
            CObjectFinalization::GetFinalizations(currentFinalization.output,
                                                  CObjectFinalization::ObjectFinalizationPendingKey(),
                                                  pCurNotarizationBlkIndex->GetHeight(),
                                                  height - 1);

        std::vector<std::tuple<uint32_t, COutPoint, CTransaction, CObjectFinalization>> &ofsToCheck = pendingFinalizations;

        // in order to confirm the indicated notarization, it must be a descendent of the last confirmed notarization,
        // be in what is the most powerful chain for two notarizations, and also have the requisite number of blocks
        // and notarization confirmations
        //
        // since any notarization is checked to ensure that it is a descendent of the last confirmed notarization when it
        // is entered, we need to ensure that it is still a decendent
        //
        // if it does not have confirmed signatures, it can still be confirmed with auto notarization, but it will take
        // more confirmations and more blocks to ensure a longer period of time to defend against any potential hash, stake, or
        // network attacks

        if (currentFinalization.IsConfirmed())
        {
            LOCK(mempool.cs);
            std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization> priorNotarizationInfo =
                GetPriorReferencedNotarization(finalizedTx, currentFinalization.output.n, normalizedNotarization);

            if (!std::get<0>(priorNotarizationInfo))
            {
                return state.Error("Invalid prior notarization 2");
            }

            // confirm that we are descended from the last confirmed notarization
            CValidationState tempState;
            if (!IsNotarizationDescendent(notarization, priorNotarizationInfo, lastConfirmedNotarizationInfo, tempState) &&
                !(std::get<2>(lastConfirmedNotarizationInfo).IsValid() &&
                  (std::get<2>(lastConfirmedNotarizationInfo).IsPreLaunch() ||
                   std::get<2>(lastConfirmedNotarizationInfo).IsDefinitionNotarization())))
            {
                state = tempState;
                return false;
            }

            // now, as long as:
            // 1) we have no invalidating counter evidence on chain, and
            // 2) we have no more powerful alternative since our first prior notarizations
            //
            // then depending only on signature status and number of confirmations/blocks to tip we can confirm
            //
            uint160 invalidatedKey =
                CCrossChainRPCData::GetConditionID(CObjectFinalization::FinalizationInvalidatesKey(),
                                                   finalizationOutput.hash,
                                                   finalizationOutput.n);

            std::vector<CAddressIndexDbEntry> invalidatedAddresses;
            if (GetAddressIndex(invalidatedKey, CScript::P2IDX, invalidatedAddresses, 0, height - 1) &&
                invalidatedAddresses.size())
            {
                return state.Error("Invalidated notarization cannot be confirmed");
            }

            // on PBaaS chains:
            // for accepted notarization, all finalizations come on another accepted notarization with
            // a proof reference to the prior agreed notarization. we find that and use that as our comparison tip
            //
            // for earned notarizations, the finalization will always include a pending reference to the most
            // recent notarization that is the tip of this confirming chain at this time
            //
            bool tipFound = evidenceVec.size();
            CPrimaryProofDescriptor proofDescr;
            CTransaction tipTx;
            BlockMap::iterator tipTxBlockIt;
            uint256 tipBlockHash;
            CPBaaSNotarization tipNotarization;
            int numNotaryConfirms = (p.evalCode == EVAL_ACCEPTEDNOTARIZATION ? 2 : 1); // starts with prior, so +1, +1 for accepted

            for (int i = 0; i < evidenceVec.size(); i++)
            {
                CNotaryEvidence combinedEvidence;
                if (evidenceVec.size())
                {
                    combinedEvidence = evidenceVec[i].second;
                }

                std::set<int> evidenceTypes;
                evidenceTypes.insert(CHAINOBJ_CROSSCHAINPROOF);
                CCrossChainProof autoProof(combinedEvidence.GetSelectEvidence(evidenceTypes));

                if (autoProof.chainObjects.size() < 1 ||
                    !((CChainObject<CCrossChainProof> *)(autoProof.chainObjects[0]))->object.chainObjects.size() ||
                    ((CChainObject<CCrossChainProof> *)(autoProof.chainObjects[0]))->object.chainObjects[0]->objectType != CHAINOBJ_EVIDENCEDATA ||
                    ((CChainObject<CEvidenceData> *)
                        (((CChainObject<CCrossChainProof> *)(autoProof.chainObjects[0]))->object.chainObjects[0]))->object.vdxfd !=
                            CNotaryEvidence::NotarizationTipKey() ||
                    !(proofDescr = CPrimaryProofDescriptor(((CChainObject<CEvidenceData> *)
                        (((CChainObject<CCrossChainProof> *)(autoProof.chainObjects[0]))->object.chainObjects[0]))->object.dataVec)).IsValid() ||
                    !proofDescr.challengeOutputs.size() ||
                    !proofDescr.challengeOutputs[0].GetOutputTransaction(tipTx, tipBlockHash, false) ||
                    tipBlockHash.IsNull() ||
                    (tipTxBlockIt = mapBlockIndex.find(tipBlockHash)) == mapBlockIndex.end() ||
                    !chainActive.Contains(tipTxBlockIt->second) ||
                    tipTxBlockIt->second->GetHeight() > (height - 1) ||
                    tipTxBlockIt->second->GetHeight() < pCurNotarizationBlkIndex->GetHeight() ||
                    tipTx.vout.size() <= proofDescr.challengeOutputs[0].n ||
                    !(tipNotarization = CPBaaSNotarization(tipTx.vout[proofDescr.challengeOutputs[0].n].scriptPubKey)).IsValid())
                {
                    if (LogAcceptCategory("notarization") && proofDescr.IsValid() && proofDescr.challengeOutputs.size())
                    {
                        LogPrintf("%s: Invalid confirmation evidence for transaction output: %s, tipTxId: %s\n", __func__, proofDescr.challengeOutputs[0].ToString().c_str(), tipTx.GetHash().GetHex().c_str());
                    }
                    if ((i + 1) < evidenceVec.size())
                    {
                        continue;
                    }
                    LogPrint("notarization", "%s: notarization finalization tip transaction not in prior chain at height %u\n", __func__, height);
                    if (confirmNeedsEvidence)
                    {
                        return state.Error("Invalid confirmation evidence 1");
                    }
                    tipFound = false;
                }
                // if we make it through and still true, early out
                if (tipFound)
                {
                    break;
                }
            }

            if (tipFound)
            {
                CUTXORef &tipTxOutput = proofDescr.challengeOutputs[0];

                std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization> priorTipNotarizationInfo =
                    {tipTxBlockIt->second->GetHeight(), tipTx, tipTxOutput, tipNotarization};

                if (!std::get<3>(priorTipNotarizationInfo).IsPreLaunch())
                {
                    std::vector<CAddressIndexDbEntry> addresses;

                    if (GetAddressIndex(
                            CCrossChainRPCData::GetConditionID(notarization.currencyID, CPBaaSNotarization::NotaryNotarizationKey()),
                            CScript::P2IDX,
                            addresses,
                            tipTxBlockIt->second->GetHeight() + 1,
                            height - 1) &&
                        addresses.size())
                    {
                        CChainPower ourPower = CChainPower::ExpandCompactPower(notarization.proofRoots[curID].compactPower);

                        // if no conflicts, we should have one transaction only, and it should be our prior
                        // if we have more than one, we must also have full proof
                        for (auto &oneOutput : addresses)
                        {
                            CTransaction oneNotarizationTx;
                            uint256 oneBlockHash;
                            CPBaaSNotarization oneNotarization;
                            if (oneOutput.first.spending)
                            {
                                continue;
                            }
                            if (!myGetTransaction(oneOutput.first.txhash, oneNotarizationTx, oneBlockHash) ||
                                oneNotarizationTx.vout.size() <= oneOutput.first.index ||
                                !(oneNotarization = CPBaaSNotarization(oneNotarizationTx.vout[oneOutput.first.index].scriptPubKey)).IsValid() ||
                                oneNotarization.currencyID != notarization.currencyID)
                            {
                                return state.Error("ERROR: corrupt local chain data - should not move forward as a node. Bootstrap or resynchonrize blockchain.");
                            }
                            if (CChainPower::ExpandCompactPower(oneNotarization.proofRoots[curID].compactPower) > ourPower)
                            {
                                return state.Error("ERROR: cannot confirm due to evidence of more powerful chain");
                            }
                        }
                    }
                }

                //
                // this can currently handle a long unconfirmed chain,
                // but if it gets too long, it could be a source of attempted DOS attacks,
                // so we should ensure that we lengthen blocknotarizationmodulo appropriately
                // and possibly auto-blacklist broken currencies/chains
                while (std::get<0>(priorTipNotarizationInfo) &&
                        std::get<2>(priorTipNotarizationInfo) != finalizationOutput &&
                        std::get<0>(priorTipNotarizationInfo) > pCurNotarizationBlkIndex->GetHeight())
                {
                    numNotaryConfirms++;
                    priorTipNotarizationInfo =
                        GetPriorReferencedNotarization(std::get<1>(priorTipNotarizationInfo),
                                                        std::get<2>(priorTipNotarizationInfo).n,
                                                        std::get<3>(priorTipNotarizationInfo));
                }

                if (!std::get<0>(priorTipNotarizationInfo))
                {
                    return state.Error("Invalid confirmation evidence 2");
                }

                // if we are on a transaction that also has a confirming notarization, add one to our confirmations
                // that will not be the case unless we are confirming an accepted notarization
                if (p.evalCode == EVAL_ACCEPTEDNOTARIZATION)
                {
                    CPBaaSNotarization freshNotarization;
                    for (auto &oneOut : tx.vout)
                    {
                        if ((freshNotarization = CPBaaSNotarization(oneOut.scriptPubKey)).IsValid() &&
                            freshNotarization.currencyID == curID &&
                            freshNotarization.proofRoots.count(ASSETCHAINS_CHAINID) &&
                            freshNotarization.proofRoots.count(curID))
                        {
                            numNotaryConfirms++;
                            break;
                        }
                    }
                }
            }
            else
            {
                numNotaryConfirms = numSignedNeeded;
                numBlocksAutoNeeded = INT32_MAX;
            }

            if (p.evalCode == EVAL_EARNEDNOTARIZATION)
            {
                if (!ConnectedChains.notarySystems.count(notarization.currencyID))
                {
                    return state.Error("insufficient foundation for proof of notary chain");
                }

                CNotaryEvidence::EStates signatureState = CNotaryEvidence::STATE_REJECTING;

                for (auto &oneEvidenceVec : evidenceMap)
                {
                    for (auto &oneEvidence : oneEvidenceVec.second)
                    {
                        if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                        {
                            LogPrintf("oneEvidence from system %s in map: %s\n", ConnectedChains.GetFriendlyCurrencyName(oneEvidenceVec.first).c_str(),
                                                                                oneEvidence.second.ToUniValue().write(1,2).c_str());
                        }
                        signatureState =
                            oneEvidence.second.CheckSignatureConfirmation(objHash,
                                                                          hw.GetHashType(),
                                                                          notarySet,
                                                                          pNotaryCurrency->minNotariesConfirm,
                                                                          height - 1);
                        if (signatureState == CNotaryEvidence::STATE_CONFIRMED || signatureState == CNotaryEvidence::STATE_REJECTED)
                        {
                            break;
                        }
                    }
                    if (signatureState == CNotaryEvidence::STATE_CONFIRMED || signatureState == CNotaryEvidence::STATE_REJECTED)
                    {
                        break;
                    }
                }

                if (signatureState == CNotaryEvidence::STATE_REJECTED &&
                    (pNotaryCurrency->notarizationProtocol == pNotaryCurrency->NOTARIZATION_NOTARY_CHAINID ||
                    pNotaryCurrency->notarizationProtocol == pNotaryCurrency->NOTARIZATION_NOTARY_CONFIRM))
                {
                    return state.Error("notary witnesses reject notarization, so it cannot be confirmed");
                }

                // fail if not confirmed and no chance for autonotarization
                // if confirmNeedsEvidence is not true, we do not have autonotarization either
                if (signatureState != CNotaryEvidence::STATE_CONFIRMED &&
                        (!confirmNeedsEvidence ||
                         pNotaryCurrency->proofProtocol != pNotaryCurrency->PROOF_PBAASMMR ||
                         pNotaryCurrency->notarizationProtocol != pNotaryCurrency->NOTARIZATION_AUTO))
                {
                    return state.Error("Insufficient notary witnesses to confirm notarization");
                }

                // if we have enough confirmations and enough blocks, we can confirm
                if (!((signatureState == CNotaryEvidence::STATE_CONFIRMED &&
                       numNotaryConfirms >= numSignedNeeded &&
                       (height - pCurNotarizationBlkIndex->GetHeight()) >= numBlocksSignedNeeded) ||
                      (signatureState != CNotaryEvidence::STATE_CONFIRMED &&
                       numNotaryConfirms >= numAutoNeeded &&
                       (height - pCurNotarizationBlkIndex->GetHeight()) >= numBlocksAutoNeeded)))
                {
                    return state.Error("Insufficient notary confirms and/or blocks to confirm notarization with given evidence");
                }

                // if we get here, store the verified proof root of this chain as notarized
                ConnectedChains.notarySystems[notarization.currencyID].lastConfirmedNotarization = notarization;
                // we should persist this notarization off-chain as a checkpoint
            }
            else
            {
                if (!(notarization.IsPreLaunch() &&
                      notarization.IsSameChain() &&
                      notaryCurrencyDef.launchSystemID == ASSETCHAINS_CHAINID))
                {
                   if (notaryCurrencyDef.SystemOrGatewayID() != ASSETCHAINS_CHAINID &&
                        (notaryCurrencyDef.IsPBaaSChain() || notaryCurrencyDef.IsGateway()) &&
                        !normalizedNotarization.IsPreLaunch() &&
                        (notaryCurrencyDef.launchSystemID != ASSETCHAINS_CHAINID ||
                        !evidenceMap.size()))
                    {
                        if (LogAcceptCategory("notarization"))
                        {
                            LogPrintf("insufficient evidence to finalize: %s\n",
                                        evidenceMap.begin()->second[0].second.ToUniValue().write(1,2).c_str());
                        }

                        // check for sufficient autonotarization evidence
                        if (pNotaryCurrency->notarizationProtocol != pNotaryCurrency->NOTARIZATION_NOTARY_CHAINID &&
                            pNotaryCurrency->notarizationProtocol != pNotaryCurrency->NOTARIZATION_NOTARY_CONFIRM)
                        {

                        }
                        return state.Error("insufficient evidence from notary system to accept finalization");
                    }

                    CNotaryEvidence::EStates signatureState = CNotaryEvidence::EStates::STATE_CONFIRMING;
                    for (auto &oneEvidenceVec : evidenceMap)
                    {
                        for (auto &oneEvidence : oneEvidenceVec.second)
                        {
                            if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                            {
                                LogPrintf("oneEvidence from system %s in map: %s\n", ConnectedChains.GetFriendlyCurrencyName(oneEvidenceVec.first).c_str(),
                                                                                    oneEvidence.second.ToUniValue().write(1,2).c_str());
                            }
                            signatureState =
                                oneEvidence.second.CheckSignatureConfirmation(objHash,
                                                                              hw.GetHashType(),
                                                                              notarySet,
                                                                              pNotaryCurrency->minNotariesConfirm,
                                                                              height - 1);
                            if (signatureState == CNotaryEvidence::STATE_CONFIRMED || signatureState == CNotaryEvidence::STATE_REJECTED)
                            {
                                break;
                            }
                        }
                        if (signatureState == CNotaryEvidence::STATE_CONFIRMED || signatureState == CNotaryEvidence::STATE_REJECTED)
                        {
                            break;
                        }
                    }

                    if (signatureState != CNotaryEvidence::STATE_CONFIRMED &&
                        (!confirmNeedsEvidence ||
                         pNotaryCurrency->proofProtocol != pNotaryCurrency->PROOF_PBAASMMR ||
                         pNotaryCurrency->notarizationProtocol != pNotaryCurrency->NOTARIZATION_AUTO))
                    {
                        return state.Error("Insufficient notary witnesses to confirm accepted notarization");
                    }

                    // if we have enough confirmations and enough blocks, we can confirm
                    if (!((signatureState == CNotaryEvidence::STATE_CONFIRMED &&
                           numNotaryConfirms >= (numSignedNeeded - 1) &&
                           (height - pCurNotarizationBlkIndex->GetHeight()) >= numBlocksSignedNeeded) ||
                          (signatureState != CNotaryEvidence::STATE_CONFIRMED &&
                           numNotaryConfirms >= (numAutoNeeded - 1) &&
                           (height - pCurNotarizationBlkIndex->GetHeight()) >= numBlocksAutoNeeded)))
                    {
                        return state.Error("Insufficient notary confirms and/or blocks to confirm accepted notarization with given evidence");
                    }
                }
             }
        }
        else
        {
            // no pending notarization may be made for a notarization that is not still a descendent of the last
            // confirmed notarization. if the hash is null, it references the same transaction, and if there is a
            // notarization on that transaction, it is also checked, so we are fine to skip
            if (currentFinalization.output.hash.IsNull())
            {
                return state.Error("Can't reject notarization on same transaction");
            }
            else
            {
                std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization> priorNotarizationInfo =
                    GetPriorReferencedNotarization(finalizedTx, currentFinalization.output.n, notarization);

                if (!std::get<3>(priorNotarizationInfo).IsValid())
                {
                    return state.Error("Invalid prior notarization 3");
                }

                // confirm that we are descended from the last confirmed notarization
                CValidationState tempState;
                if (!IsNotarizationDescendent(notarization, priorNotarizationInfo, lastConfirmedNotarizationInfo, tempState) &&
                    !(std::get<2>(lastConfirmedNotarizationInfo).IsValid() &&
                      (std::get<2>(lastConfirmedNotarizationInfo).IsPreLaunch() ||
                       std::get<2>(lastConfirmedNotarizationInfo).IsDefinitionNotarization())))
                {
                    // always OK to reject a notarization that is no longer in the notarization lineage
                    return true;
                }
            }

            // get evidence to see if we can verify a final rejection of this notarization
            //
            // rejecting requires one of the following types of evidence:
            // 1) proof that there is a notarization in conflict with this notarization that
            //    can prove more power since the last confirmed notarization for 10x the block
            //    modulo period on both chains.
            // 2) proof that there is a notarization in conflict with this notarization that
            //    is finalized on our notary chain.
            // 3) notaries signing rejected on a thread of notarizations that cannot respond
            //    to challenges for 3 modulo periods.
            //

            CProofRoot counterRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);
            CProofRoot challengeStartRoot;
            bool invalidates;
            for (auto &oneItem : evidenceVec)
            {
                CProofRoot tmpCounterRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);
                CProofRoot tmpChallengeStartRoot;
                // valid pending finalization evidence for notarizations include:
                // signatures for or against confirmation
                // counter-evidence of a valid, alternate chain
                if (notarization.proofRoots.count(notaryCurrencyDef.SystemOrGatewayID()) && notaryCurrencyDef.SystemOrGatewayID() != ASSETCHAINS_CHAINID)
                {
                    tmpCounterRoot = IsValidChallengeEvidence(notaryCurrencyDef,
                                                              notarization.proofRoots[notaryCurrencyDef.SystemOrGatewayID()],
                                                              oneItem.second,
                                                              txBlockHash,
                                                              invalidates,
                                                              tmpChallengeStartRoot,
                                                              height - 1);
                    if (invalidates)
                    {
                        if (tmpCounterRoot.IsValid())
                        {
                            counterRoot = tmpCounterRoot;
                        }
                        if (tmpChallengeStartRoot.IsValid() &&
                            (!challengeStartRoot.IsValid() || challengeStartRoot.rootHeight < tmpChallengeStartRoot.rootHeight))
                        {
                            challengeStartRoot = tmpChallengeStartRoot;
                        }
                        break;
                    }
                    if (tmpCounterRoot.IsValid() &&
                        tmpChallengeStartRoot.IsValid() &&
                        tmpCounterRoot != notarization.proofRoots[notaryCurrencyDef.SystemOrGatewayID()])
                    {
                        // we may need to keep a vector of these, but we don't have the variability to need that yet
                        if (!counterRoot.IsValid())
                        {
                            counterRoot = tmpCounterRoot;
                        }
                        if (!challengeStartRoot.IsValid() || challengeStartRoot.rootHeight < tmpChallengeStartRoot.rootHeight)
                        {
                            challengeStartRoot = tmpChallengeStartRoot;
                        }
                        continue;
                    }
                }
            }

            if (!invalidates)
            {
                // this is asserting rejection, so we must confirm that it can be rejected and that it only spends
                // inputs that are now invalidated due to the rejection
                if (p.evalCode == EVAL_EARNEDNOTARIZATION)
                {
                    if (!ConnectedChains.notarySystems.count(notarization.currencyID))
                    {
                        return state.Error("insufficient foundation for rejection proof of notarization");
                    }

                    // 1) for earned notarizations:
                    //  a) disagreeing earned notarization between the notarization and the second agreed notarization
                    //  b) other forms of proof that render the to-be-confirmed proof root invalid, such as rejecting signatures
                    //     by the confirming IDs that cancel enough confirming, or proof of a more powerful, provably mined and
                    //     staked chain since the last notarization
                    if (!evidenceMap[ASSETCHAINS_CHAINID].size() ||
                         evidenceMap[ASSETCHAINS_CHAINID][0].second.CheckSignatureConfirmation(objHash,
                                                                                               hw.GetHashType(),
                                                                                               notarySet,
                                                                                               pNotaryCurrency->minNotariesConfirm,
                                                                                               height - 1) != CNotaryEvidence::STATE_REJECTED)
                    {
                        return state.Error("insufficient evidence to reject finalization");
                    }
                }
                else
                {
                    // 2) for accepted notarizations:
                    //  a) Majority on-chain rejection signatures in blocks prior to this one
                    //  b) IDs revoked that result in less than majority for the confirmation
                    //  c) proof of a more powerful, provably mined/staked chain since the last notarization that is different than
                    //     the accepted notarization
                    if (counterRoot.IsValid() ||
                        (notaryCurrencyDef.IsPBaaSChain() || notaryCurrencyDef.IsGateway()) &&
                        !notarization.IsPreLaunch() &&
                        (notaryCurrencyDef.launchSystemID != ASSETCHAINS_CHAINID ||
                        !evidenceMap.size()))
                    {
                        return state.Error("insufficient evidence from notary system to reject finalization");
                    }
                    CNotaryEvidence::EStates signatureState = CNotaryEvidence::EStates::STATE_CONFIRMING;
                    for (auto &oneEvidenceVec : evidenceMap)
                    {
                        for (auto &oneEvidence : oneEvidenceVec.second)
                        {
                            if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
                            {
                                LogPrintf("oneEvidence from system %s in map: %s\n", ConnectedChains.GetFriendlyCurrencyName(oneEvidenceVec.first).c_str(),
                                                                                    oneEvidence.second.ToUniValue().write(1,2).c_str());
                            }
                            signatureState =
                                oneEvidence.second.CheckSignatureConfirmation(objHash,
                                                                              hw.GetHashType(),
                                                                              notarySet,
                                                                              pNotaryCurrency->minNotariesConfirm,
                                                                              height - 1);
                            if (signatureState == CNotaryEvidence::STATE_REJECTED)
                            {
                                break;
                            }
                        }
                    }
                    if (signatureState != CNotaryEvidence::STATE_REJECTED)
                    {
                        return state.Error("insufficient evidence from notary system to reject finalization");
                    }
                }
            }
        }
    }
    else if (notarization.currencyID != ASSETCHAINS_CHAINID)
    {
        // no pending notarization may be made for a notarization that is not still a descendent of the last
        // confirmed notarization. if the hash is null, it references the same transaction, and if there is a
        // notarization on that transaction, it is also checked, so we are fine to skip
        if (currentFinalization.output.hash.IsNull())
        {
            // it must be a reference to a valid notarization on this transaction
            COptCCParams outP;
            CPBaaSNotarization nextPBN;
            if (tx.vout.size() > currentFinalization.output.n &&
                tx.vout[currentFinalization.output.n].scriptPubKey.IsPayToCryptoCondition(outP) &&
                outP.IsValid() &&
                (outP.evalCode == EVAL_EARNEDNOTARIZATION || outP.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
                outP.vData.size() &&
                (nextPBN = CPBaaSNotarization(outP.vData[0])).IsValid() &&
                nextPBN.currencyID == currentFinalization.currencyID)
            {
                // we can only have one such pending finalization on this transaction, so look through the rest of the outputs
                for (int oneOutNum = 0; oneOutNum < tx.vout.size(); oneOutNum++)
                {
                    if (oneOutNum == currentFinalization.output.n || oneOutNum == outNum)
                    {
                        continue;
                    }
                    CTransaction outTx;
                    uint256 blockHash;
                    CObjectFinalization outOF;
                    if (tx.vout[oneOutNum].scriptPubKey.IsPayToCryptoCondition(outP) &&
                        outP.IsValid() &&
                        outP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                        outP.vData.size() &&
                        (outOF = CObjectFinalization(outP.vData[0])).IsValid() &&
                        (outOF.output == currentFinalization.output))
                    {
                        return state.Error("Only one pending finalization allowed for each finalizing output");
                    }
                }
                return true;
            }
        }
        if (currentFinalization.output.hash.IsNull())
        {
            return state.Error("Invalid pending finalization on output " + std::to_string(outNum));
        }
        else
        {
            std::tuple<uint32_t, CTransaction, CUTXORef, CPBaaSNotarization> priorNotarizationInfo =
                GetPriorReferencedNotarization(finalizedTx, currentFinalization.output.n, notarization);

            if (!std::get<0>(priorNotarizationInfo))
            {
                return state.Error("Invalid prior notarization 2");
            }

            // confirm that we are descended from the last confirmed notarization
            CValidationState tempState;
            if (!IsNotarizationDescendent(notarization, priorNotarizationInfo, lastConfirmedNotarizationInfo, tempState) &&
                !(std::get<2>(lastConfirmedNotarizationInfo).IsValid() &&
                  (std::get<2>(lastConfirmedNotarizationInfo).IsPreLaunch() ||
                   std::get<2>(lastConfirmedNotarizationInfo).IsDefinitionNotarization())))
            {
                state = tempState;
                return state.Error("Notarization is not a descendent of confirmed notarization");
            }
        }

        CProofRoot counterRoot(CProofRoot::TYPE_PBAAS, CProofRoot::VERSION_INVALID);
        CProofRoot challengeStartRoot;
        bool hasSignature = false;
        bool invalidates;

        for (auto &oneItem : evidenceVec)
        {
            if (oneItem.second.GetNotarySignatures().size() &&
                oneItem.second.CheckSignatureConfirmation(objHash, hw.GetHashType(), notarySet, pNotaryCurrency->minNotariesConfirm, height - 1) != CNotaryEvidence::EStates::STATE_INVALID)
            {
                hasSignature = true;
                break;
            }
        }
        if (evidenceVec.size() && !hasSignature)
        {
            // if this notarization refers to a pending notarization that we spend on the input, which refers to this same
            // notarization or a pending finalization of it as evidence, we can spend it
            if (currentFinalization.evidenceInputs.size())
            {
                for (auto oneInIdx : currentFinalization.evidenceInputs)
                {
                    if (oneInIdx >= tx.vin.size())
                    {
                        return state.Error("invalid evidence inputs");
                    }
                    auto &oneIn = tx.vin[oneInIdx];
                    CUTXORef inputRef(oneIn.prevout);
                    if (inputRef == currentFinalization.output)
                    {
                        return true;
                    }
                    CTransaction outTx;
                    uint256 blockHash;
                    COptCCParams outP;
                    CObjectFinalization outOF;
                    if (inputRef.GetOutputTransaction(outTx, blockHash) &&
                        outTx.vout.size() > inputRef.n &&
                        outTx.vout[inputRef.n].scriptPubKey.IsPayToCryptoCondition(outP) &&
                        outP.IsValid() &&
                        outP.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                        outP.vData.size() &&
                        (outOF = CObjectFinalization(outP.vData[0])).IsValid() &&
                        ((outOF.output.hash.IsNull() &&
                        outTx.GetHash() == currentFinalization.output.hash &&
                        outOF.output.n == currentFinalization.output.n) ||
                        (outOF.output == currentFinalization.output)) &&
                        outOF.IsPending())
                    {
                        return true;
                    }
                }
            }
            if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
            {
                LogPrintf("%s: invalid pending finalization on transaction: %s\n");
            }
            return state.Error("insufficient evidence to create new pending finalization for notarization");
        }
    }
    return true;
}

bool IsAcceptedNotarizationInput(const CScript &scriptSig)
{
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_ACCEPTEDNOTARIZATION;
}

// earned notarizations can be spent when finalized as either confirmed or invalidated due to a disagreeing,
// confirmed notarization
bool ValidateEarnedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // first, determine our notarization finalization protocol
    CUTXORef spendingOutput(tx.vin[nIn].prevout.hash, tx.vin[nIn].prevout.n);
    CTransaction sourceTx;
    uint256 blockHash;
    if (!spendingOutput.GetOutputTransaction(sourceTx, blockHash))
    {
        return eval->Error("Unable to retrieve spending transaction");
    }

    CPBaaSNotarization pbn;
    COptCCParams pN;
    if (!(sourceTx.vout[spendingOutput.n].scriptPubKey.IsPayToCryptoCondition(pN) &&
          pN.IsValid() &&
          pN.evalCode == EVAL_EARNEDNOTARIZATION &&
          pN.vData.size() &&
          (pbn = CPBaaSNotarization(pN.vData[0])).IsValid()))
    {
        return eval->Error("Invalid earned notarization, unspendable");
    }

    int i;
    for (i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        CObjectFinalization of;
        CPBaaSNotarization nextPbn;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            (p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
            p.vData.size() &&
            (of = CObjectFinalization(p.vData[0])).IsValid() &&
            of.currencyID == pbn.currencyID) ||
            (p.evalCode == EVAL_ACCEPTEDNOTARIZATION &&
             p.vData.size() &&
             (nextPbn = CPBaaSNotarization(p.vData[0])).IsValid() &&
             nextPbn.currencyID == pbn.currencyID))
        {
            break;
        }
    }

    if (i < tx.vout.size())
    {
        return true;
    }
    return eval->Error("Earned notarization can only be spent to a valid finalization");
}

bool IsEarnedNotarizationInput(const CScript &scriptSig)
{
    // this is an output check, and is incorrect. need to change to input
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_EARNEDNOTARIZATION;
}

CObjectFinalization GetOldFinalization(const CTransaction &spendingTx, uint32_t nIn, CTransaction *pSourceTx=nullptr, uint32_t *pHeight=nullptr);
CObjectFinalization GetOldFinalization(const CTransaction &spendingTx, uint32_t nIn, CTransaction *pSourceTx, uint32_t *pHeight)
{
    CTransaction _sourceTx;
    CTransaction &sourceTx(pSourceTx ? *pSourceTx : _sourceTx);

    CObjectFinalization oldFinalization;
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
            (p.evalCode == EVAL_FINALIZE_NOTARIZATION || p.evalCode == EVAL_FINALIZE_EXPORT) &&
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldFinalization = CObjectFinalization(p.vData[0]);
        }
    }
    return oldFinalization;
}


/*
 * Ensures that the finalization, either asserted to be confirmed or rejected, has all signatures and evidence
 * necessary for confirmation.
 */
bool ValidateFinalizeNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // to validate a finalization spend, we need to validate the spender's assertion of confirmation or rejection as proven

    // first, determine our notarization finalization protocol
    CTransaction sourceTx;
    uint32_t oldHeight;
    CObjectFinalization oldFinalization = GetOldFinalization(tx, nIn, &sourceTx, &oldHeight);
    if (!oldFinalization.IsValid())
    {
        return eval->Error("Invalid finalization output");
    }

    // if we are spending a confirmed notarization, then as long as we are being spent by
    // an accepted notarization and have the same confirmation on an output just after a pending output,
    // it is ok
    if (oldFinalization.IsConfirmed())
    {
        int priorPendingFinalization = -1, notarizationOut = -1;
        for (int i = 0; i < tx.vout.size(); i++)
        {
            auto &oneOut = tx.vout[i];

            COptCCParams p;
            CObjectFinalization oneOF;

            if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                p.vData.size() &&
                (oneOF = CObjectFinalization(p.vData[0])).IsValid() &&
                oneOF.IsNotarizationFinalization() &&
                oneOF.currencyID == oldFinalization.currencyID &&
                oneOF.IsConfirmed())
            {
                return true;
            }
        }
        if (LogAcceptCategory("notarization") && LogAcceptCategory("verbose"))
        {
            UniValue jsonNTx(UniValue::VOBJ);
            TxToUniv(tx, uint256(), jsonNTx);
            LogPrintf("%s: Invalid spend of confirmed finalization on transaction:\n%s\n", __func__, jsonNTx.write(1,2).c_str());
        }
        return eval->Error("Invalid spend of confirmed finalization to transaction with no confirmed output");
    }

    // get currency to determine system and notarization method
    CCurrencyDefinition curDef = ConnectedChains.GetCachedCurrency(oldFinalization.currencyID);
    if (!curDef.IsValid())
    {
        return eval->Error("Invalid currency ID in finalization output");
    }
    uint160 SystemID = curDef.GetID();

    // for now, auto notarization uses defined notaries. it can be updated later, while leaving those that
    // select notary confirm explicitly to remain on that protocol
    if (curDef.notarizationProtocol == curDef.NOTARIZATION_NOTARY_CONFIRM || curDef.notarizationProtocol == curDef.NOTARIZATION_AUTO)
    {
        // get the notarization this finalizes and its index output
        int32_t notaryOutNum;
        CTransaction notarizationTx;

        if (oldFinalization.output.IsOnSameTransaction())
        {
            notarizationTx = sourceTx;
            // output needs non-null hash below
            oldFinalization.output.hash = notarizationTx.GetHash();
        }
        else
        {
            uint256 blkHash;
            if (!oldFinalization.GetOutputTransaction(sourceTx, notarizationTx, blkHash))
            {
                return eval->Error("notarization-transaction-not-found");
            }
        }
        if (notarizationTx.vout.size() <= oldFinalization.output.n)
        {
            return eval->Error("invalid-finalization");
        }

        CPBaaSNotarization pbn(notarizationTx.vout[oldFinalization.output.n].scriptPubKey);
        if (!pbn.IsValid())
        {
            return eval->Error("invalid-notarization");
        }

        // now, we have an unconfirmed, non-rejected finalization being spent by a transaction
        // confirm that the spender contains one finalization output either correctly confirming or invalidating
        // the finalization. rejection may be implicit by confirming another, later notarization.

        // First. make sure the oldFinalization is not referring to an earlier notarization than the
        // one most recently confirmed. If so. then it can be spent by anyone.
        CChainNotarizationData cnd;
        if (!GetNotarizationData(SystemID, cnd) || !cnd.IsConfirmed())
        {
            return eval->Error("invalid-notarization");
        }

        CObjectFinalization newFinalization;
        int finalizationOutNum = -1;
        bool foundFinalization = false;
        for (int i = 0; i < tx.vout.size(); i++)
        {
            auto &oneOut = tx.vout[i];
            COptCCParams p;
            // we can accept only one finalization of this notarization as an output, find it and reject more than one

            // ensure that the output of the finalization we are spending is either a confirmed, earlier
            // output or invalidated alternate to the one we are finalizing
            if (oneOut.scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_FINALIZE_NOTARIZATION &&
                p.vData.size() &&
                (newFinalization = CObjectFinalization(p.vData[0])).IsValid() &&
                newFinalization.currencyID == oldFinalization.currencyID &&
                (newFinalization.IsConfirmed() || newFinalization.output == oldFinalization.output))
            {
                if (oldFinalization.IsConfirmed() && !newFinalization.IsConfirmed())
                {
                    LogPrint("notarization", "WARNING: Unconfirmed finalization attempting to spend confirmed finalization.\n old: %s\nnew: %s\n", oldFinalization.ToUniValue().write(1,2).c_str(), newFinalization.ToUniValue().write(1,2).c_str());
                    return eval->Error("unconfirmed-spending-confirmed");
                }
                if (foundFinalization)
                {
                    return eval->Error("duplicate-finalization");
                }
                foundFinalization = true;
                finalizationOutNum = i;
            }
        }

        if (!foundFinalization)
        {
            return eval->Error("invalid-finalization-spend");
        }
    }
    return true;
}

bool IsFinalizeNotarizationInput(const CScript &scriptSig)
{
    // this is an output check, and is incorrect. need to change to input
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_FINALIZE_NOTARIZATION;
}

bool CObjectFinalization::GetOutputTransaction(const CTransaction &initialTx, CTransaction &tx, uint256 &blockHash, bool checkMempool) const
{
    if (output.hash.IsNull())
    {
        tx = initialTx;
        return true;
    }
    else if (myGetTransaction(output.hash, tx, blockHash, checkMempool) && tx.vout.size() > output.n)
    {
        return true;
    }
    return false;
}

bool CUTXORef::GetOutputTransaction(CTransaction &tx, uint256 &blockHash, bool checkMempool) const
{
    if (hash.IsNull())
    {
        return false;
    }
    else if (myGetTransaction(hash, tx, blockHash, checkMempool) && tx.vout.size() > n)
    {
        return true;
    }
    return false;
}

// Sign the output object with an ID or signing authority of the ID from the wallet.
CNotaryEvidence CObjectFinalization::SignConfirmed(const std::set<uint160> &notarySet, int minConfirming, const CWallet *pWallet, const CTransaction &initialTx, const CIdentityID &signatureID, uint32_t signingHeight, CCurrencyDefinition::EHashTypes hashType, CNotaryEvidence *pNewSignatureEvidence) const
{
    CNotaryEvidence retVal = CNotaryEvidence(ASSETCHAINS_CHAINID, output, CNotaryEvidence::STATE_CONFIRMING);

    AssertLockHeld(cs_main);

    CTransaction tx;
    uint256 blockHash;
    if (GetOutputTransaction(initialTx, tx, blockHash))
    {
        retVal.SignConfirmed(notarySet, minConfirming, *pWallet, tx, signatureID, signingHeight, hashType, pNewSignatureEvidence);
    }
    return retVal;
}

CNotaryEvidence CObjectFinalization::SignRejected(const std::set<uint160> &notarySet, int minConfirming, const CWallet *pWallet, const CTransaction &initialTx, const CIdentityID &signatureID, uint32_t signingHeight, CCurrencyDefinition::EHashTypes hashType, CNotaryEvidence *pNewSignatureEvidence) const
{
    CNotaryEvidence retVal = CNotaryEvidence(ASSETCHAINS_CHAINID, output, CNotaryEvidence::STATE_REJECTING);

    AssertLockHeld(cs_main);

    CTransaction tx;
    uint256 blockHash;
    if (GetOutputTransaction(initialTx, tx, blockHash))
    {
        retVal.SignRejected(notarySet, minConfirming, *pWallet, tx, signatureID, signingHeight, hashType, pNewSignatureEvidence);
    }
    return retVal;
}
