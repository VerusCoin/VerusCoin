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

#include <univalue.h>
#include "key_io.h"
#include "CCinclude.h"
#include "StakeGuard.h"
#include "pbaas/crosschainrpc.h"
#include "pbaas/pbaas.h"
#include "pbaas/notarization.h"
#include "pbaas/identity.h"

/*
 CCcustom has most of the functions that need to be extended to create a new CC contract.
 
 A CC scriptPubKey can only be spent if it is properly signed and validated. By constraining the vins and vouts, it is possible to implement a variety of functionality. CC vouts have an otherwise non-standard form, but it is properly supported by the enhanced bitcoin protocol code as a "cryptoconditions" output and the same pubkey will create a different address.
 
 This allows creation of a special address(es) for each contract type, which has the privkey public. That allows anybody to properly sign and spend it, but with the constraints on what is allowed in the validation code, the contract functionality can be implemented.
 
 what needs to be done to add a new contract:
 1. add EVAL_CODE to eval.h
 2. initialize the variables in the CCinit function below
 3. write a Validate function to reject any unsanctioned usage of vin/vout
 4. make helper functions to create rawtx for RPC functions
 5. add rpc calls to rpcserver.cpp and rpcserver.h and in one of the rpc.cpp files
 6. add the new .cpp files to src/Makefile.am
 
 IMPORTANT: make sure that all CC inputs and CC outputs are properly accounted for and reconcile to the satoshi. The built in utxo management will enforce overall vin/vout constraints but it wont know anything about the CC constraints. That is what your Validate function needs to do.
 
 Generally speaking, there will be normal coins that change into CC outputs, CC outputs that go back to being normal coins, CC outputs that are spent to new CC outputs.
 
 Make sure both the CC coins and normal coins are preserved and follow the rules that make sense. It is a good idea to define specific roles for specific vins and vouts to reduce the complexity of validation.
 */

// to create a new CCaddr, add to rpcwallet the CCaddress and start with -pubkey= with the pubkey of the new address, with its wif already imported. set normaladdr and CChexstr. run CCaddress and it will print the privkey along with autocorrect the CCaddress. which should then update the CCaddr here

// StakeGuard - nothing at stake
std::string StakeGuardAddr = "RCG8KwJNDVwpUBcdoa6AoHqHVJsA1uMYMR";
std::string StakeGuardPubKey = "03166b7813a4855a88e9ef7340a692ef3c2decedfdc2c7563ec79537e89667d935";
std::string StakeGuardWIF = "Uw7vRYHGKjyi1FaJ8Lv1USSuj7ntUti8fAhSDiCdbzuV6yDagaTn";

// defines the blockchain parameters of a PBaaS blockchain
std::string PBaaSDefinitionAddr = "RP7id3CzCnwvzNUZesYJM6ekvsxpEzMqB1";
std::string PBaaSDefinitionPubKey = "02a0de91740d3d5a3a4a7990ae22315133d02f33716b339ebce88662d012224ef5";
std::string PBaaSDefinitionWIF = "UwhNWARAQTUvYUEqxGbRjM2BFUneGnFzmaMMiSqJQZFQZTku6xTW";

// Notary evidence output type
std::string NotaryEvidenceAddr = "RQWMeecjGFF3ZAVeSimRbyG9iMDUHPY5Ny";
std::string NotaryEvidencePubKey = "03e1894e9d487125be5a8c6657a8ce01bc81ba7816d698dbfcfb0483754eb5a2d9";
std::string NotaryEvidenceWIF = "Uw5dNvvgz7eyUJGtfi696hYbF9YPXHPHasgZFeQeDu8j4SapPBzd";

// Earned notarization type, created by miners and/or stakers
std::string EarnedNotarizationAddr = "RMYbaxFsCT1xfMmwLCCYAVf2DsxcDTtBmx";
std::string EarnedNotarizationPubKey = "03fb008879b37d644bef929576dda7f5ee31b352c76fc112b4a89838d5b61f52e2";
std::string EarnedNotarizationWIF = "UtzhFWXw24xS2Tf3gCDm9p2Ex7TUnCNt4DFA7r2f5cCKPhPknEqD";

// Accepted notarizations are validated notarizations and proofs of an alternate earned notarization -- these are for the Verus chain
std::string AcceptedNotarizationAddr = "RDTq9qn1Lthv7fvsdbWz36mGp8HK9XaruZ";
std::string AcceptedNotarizationPubKey = "02d85f078815b7a52faa92639c3691d2a640e26c4e06de54dd1490f0e93bcc11c3";
std::string AcceptedNotarizationWIF = "UtgbVEYs2PShTMffbkYh8bgo9DYsXr8JuqWVjAYHRt2ebGPeP5Mf";

// "Finalization" - output that can be spent when a notarization is effectively considered "final"
std::string FinalizeNotarizationAddr = "RRbKYitLH9EhQCvCo4bPZqJx3TWxASadxE";
std::string FinalizeNotarizationPubKey = "02e3154f8122ff442fbca3ff8ff4d4fb2d9285fd9f4d841d58fb8d6b7acefed60f";
std::string FinalizeNotarizationWIF = "UrN1b1hCQc6cUpcUdQD7DFTn2PJneDpKv5pmURPQzJ2zVp9UVM6E";

// Reserve output -- provides flexible Verus reserve currency transaction/utxo support on PBaaS chains only
std::string ReserveOutputAddr = "RMXeZGxxRuABFkT4uLSCeuJHLegBNGZq8D";
std::string ReserveOutputPubKey = "02d3e0f4c308c6e9786a5280ec96ea6d0e07505bae88d28b4b3156c309e2ae5515";
std::string ReserveOutputWIF = "UrCfRxuFKPg3b3HtPFhvL9X8iePfETRZpgymrxzdDZ3vpjSwHrxH";

// Identity advanced name reservation -- output with a versioned identity reservation that includes a parent to make IDs from a currency
std::string AdvancedNameReservationAddr = "REuGNkgunnw1J4Zx6Y9UCp8YHVZqYATe9D";
std::string AdvancedNameReservationPubKey = "02b68492c495d7d63d908fa641fb6215bc56a7de15fb438c78066ec4c173563527";
std::string AdvancedNameReservationWIF = "Uveq2qCQLjaJxdjXBAtBQQjhRDocomeSCtogifMHxwVsLNRCQgqX";

// Reserve transfer -- send reserves from a Verus chain to a PBaaS chain or back with optional conversion, works on Verus or PBaaS chains
std::string ReserveTransferAddr = "RTqQe58LSj2yr5CrwYFwcsAQ1edQwmrkUU";
std::string ReserveTransferPubKey = "0367add5577ca8f5f680ee0adf4cf802584c56ed14956efedd3e18656874614548";
std::string ReserveTransferWIF = "UtbtjjXtNtYroASwDrW63pEK7Fv3ehBRGDc2GRkPPr292DkRTmtB";

// Reserve deposit -- these outputs are spent into the cross chain import thread on the Verus chain when import transactions are created
std::string ReserveDepositAddr = "RFw9AVfgNKcHe2Vp2eyzHrX65aFD9Ky8df";
std::string ReserveDepositPubKey = "03b99d7cb946c5b1f8a54cde49b8d7e0a2a15a22639feb798009f82b519526c050";
std::string ReserveDepositWIF = "UtGtjeGBCUtQPGZp99bnDvQuxvURxdjGRFHuJ7oQyQgpNNCEyyqu";

// Cross chain export -- this is used on an aggregated cross chain export transaction and one unspent output defines the export thread
std::string CrossChainExportAddr = "RGkrs7SndcpsV61oKK2jYdMiU8PgkLU2qP";
std::string CrossChainExportPubKey = "02cbfe54fb371cfc89d35b46cafcad6ac3b7dc9b40546b0f30b2b29a4865ed3b4a";
std::string CrossChainExportWIF = "Uu9P8fa68e2ECar76z4MsSoKtbRV1Dny3WD6DTmMKmeimooeAyAz";

// Cross chain import -- this is used on a cross chain import transaction and one unspent output defines the import thread
std::string CrossChainImportAddr = "RKLN7wFhbrJFkPG8XkKteErAe5CjqoddTm";
std::string CrossChainImportPubKey = "038d259ec6175e192f8417914293dd09203885bc33039080f2a33f08a3fdddc818";
std::string CrossChainImportWIF = "UtAEFiEERMkuZ3cCzbi8DqXRM6fHNAuYcbXU2hy2dc14LgPpkxax";

// Currency state - coinbase output -- currently required on PBaaS chains only
std::string CurrencyStateAddr = "REU1HKkmdwdxKMpfD3QoxeERYd9tfMN6n9";
std::string CurrencyStatePubKey = "0219af977f9a6c3779f1185decee2b77da446040055b912b00e115a52d4786059c";
std::string CurrencyStateWIF = "Ur8YQJQ6guqmD6rXtrUtJ7fWxaEB5FaejCr3MxHAgMEwnjJnuGo5";

// identity primary output
std::string IdentityPrimaryAddr = "RS545EBdK5AzPTaGHNUg78wFuuAzBb74FB";
std::string IdentityPrimaryPubKey = "030b2c39fb8357ca54a56ca3b07a74a6b162addb4d31afaefc9c53bfc17aae052c";
std::string IdentityPrimaryWIF = "UtPq2QgtE9qcukeMA5grsHhr7eDzLo9BVwoN4QQRiv3coZn2ryXF";

// identity revoke output
std::string IdentityRevokeAddr = "RG6My2zwh9hBFSgUhZ5UmmUtxBap57aU4N";
std::string IdentityRevokePubKey = "03098d3fee3585ff42090c9cee5723a718dd27e7854761db4520eb70ade22a7802";
std::string IdentityRevokeWIF = "UuLt6xUQqG74M4Rgm96xEb672DjfkHYEukdUHWfAMBE4Tsc8cBvC";

// identity recover output
std::string IdentityRecoverAddr = "RRw9rJMPwdNqC1wgXn5vryJwMDyBgpXjYT";
std::string IdentityRecoverPubKey = "03a058410b33f893fe182f15336577f3941c28c8cadcfb0395b9c31dd5c07ccd11";
std::string IdentityRecoverWIF = "UuGtno91gaoJgy7nRgaBkWj6So3oBZ24fJWzULfU6LrsN4XZJckC";

// identity commitment output
std::string IdentityCommitmentAddr = "RCySaThHfVBcHZgjJGoBw3un4vcsRJNPYw";
std::string IdentityCommitmentPubKey = "03c4eac0982458644a87458eebe2fdc4e754e15c378b66f16fbd913ae2792d2cb0";
std::string IdentityCommitmentWIF = "Upfbmz3v16NM3zmQujmLSuaWeJ519fUKMqjusFwSDKgpBGMckWCr";

// identity reservation output
std::string IdentityReservationAddr = "RDbzJU8rEv4CkMABNUnKQoKDTfnikSm9fM";
std::string IdentityReservationPubKey = "03974e76f57409197870d4e5539380b2f8468465c2bd374e3610edf1282cd1a304";
std::string IdentityReservationWIF = "UqCXEj8oonBt6p9iDXbsAshCeFX7RsDpL6R62GUhTVRiSKDCQkYi";

// FinalizeExport
std::string FinalizeExportAddr = "REL7oLNeaeoQB1XauiHfcvjKMZC52Uj5xF";
std::string FinalizeExportPubKey = "0391fa230bd2509cbcc165c636c79ff540a8e3615993b16b8e366770bc4261bf10";
std::string FinalizeExportWIF = "UrRwoqyLMNddbASS7XV6rm3Q1JCBmMV9V5oPr92KEFmH5U8Evkf6";

// quantum resistant public key output to keep one copy of a public key and refer to it via its hash on the chain
std::string QuantumKeyOutAddr = "";
std::string QuantumKeyOutPubKey = "";
std::string QuantumKeyOutWIF = "";

// blockchain fee pool output
std::string FeePoolAddr = "RQ55dLQ7uGnLx8scXfkaFV6QS6qVBGyxAG";
std::string FeePoolPubKey = "0231dbadc511bcafdb557faf0b49bea1e2a4ccc0259aeae16c618e1cc4d38f2f4d";
std::string FeePoolWIF = "Ux4w6K5ptuQG4SUEQd1bRV8X1LwzcLrVirApbXvThKYfm6uXEafJ";

// atomic swap condition
std::string AtomicSwapConditionAddr = "";
std::string AtomicSwapConditionPubKey = "";
std::string AtomicSwapConditionWIF = "";

// condition to put time limits on a transaction output
std::string TimeLimitsAddr = "";
std::string TimeLimitsPubKey = "";
std::string TimeLimitsWIF = "";

struct CCcontract_info *CCinit(struct CCcontract_info *cp, uint8_t evalcode)
{
    cp->evalcode = evalcode;
    switch ( evalcode )
    {
        case EVAL_STAKEGUARD:
            strcpy(cp->unspendableCCaddr,StakeGuardAddr.c_str());
            strcpy(cp->normaladdr,StakeGuardAddr.c_str());
            strcpy(cp->CChexstr,StakeGuardPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(StakeGuardWIF).begin(),32);
            cp->validate = StakeGuardValidate;
            cp->ismyvin = IsStakeGuardInput;  // TODO: these input functions are not useful for new CCs
            cp->contextualprecheck = PrecheckStakeGuardOutput;
            break;

        case EVAL_CURRENCY_DEFINITION:
            strcpy(cp->unspendableCCaddr,PBaaSDefinitionAddr.c_str());
            strcpy(cp->normaladdr,PBaaSDefinitionAddr.c_str());
            strcpy(cp->CChexstr,PBaaSDefinitionPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(PBaaSDefinitionWIF).begin(),32);
            cp->validate = ValidateCurrencyDefinition;
            cp->ismyvin = IsCurrencyDefinitionInput;
            cp->contextualprecheck = PrecheckCurrencyDefinition;
            break;

        case EVAL_EARNEDNOTARIZATION:
            strcpy(cp->unspendableCCaddr,EarnedNotarizationAddr.c_str());
            strcpy(cp->normaladdr,EarnedNotarizationAddr.c_str());
            strcpy(cp->CChexstr,EarnedNotarizationPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(EarnedNotarizationWIF).begin(),32);
            cp->validate = ValidateEarnedNotarization;
            cp->ismyvin = IsEarnedNotarizationInput;
            cp->contextualprecheck = PreCheckAcceptedOrEarnedNotarization;
            break;

        case EVAL_ACCEPTEDNOTARIZATION:
            strcpy(cp->unspendableCCaddr,AcceptedNotarizationAddr.c_str());
            strcpy(cp->normaladdr,AcceptedNotarizationAddr.c_str());
            strcpy(cp->CChexstr,AcceptedNotarizationPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(AcceptedNotarizationWIF).begin(),32);
            cp->validate = ValidateAcceptedNotarization;
            cp->ismyvin = IsAcceptedNotarizationInput;
            cp->contextualprecheck = PreCheckAcceptedOrEarnedNotarization;
            break;

        case EVAL_FINALIZE_NOTARIZATION:
            strcpy(cp->unspendableCCaddr,FinalizeNotarizationAddr.c_str());
            strcpy(cp->normaladdr,FinalizeNotarizationAddr.c_str());
            strcpy(cp->CChexstr,FinalizeNotarizationPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(FinalizeNotarizationWIF).begin(),32);
            cp->validate = ValidateFinalizeNotarization;
            cp->ismyvin = IsFinalizeNotarizationInput;
            cp->contextualprecheck = PreCheckFinalizeNotarization;
            break;

        case EVAL_NOTARY_EVIDENCE:
            strcpy(cp->unspendableCCaddr,NotaryEvidenceAddr.c_str());
            strcpy(cp->normaladdr,NotaryEvidenceAddr.c_str());
            strcpy(cp->CChexstr,NotaryEvidencePubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(NotaryEvidenceWIF).begin(),32);
            cp->validate = ValidateNotaryEvidence;
            cp->ismyvin = IsNotaryEvidenceInput;
            cp->contextualprecheck = PreCheckNotaryEvidence;
            break;

        case EVAL_RESERVE_OUTPUT:
            strcpy(cp->unspendableCCaddr, ReserveOutputAddr.c_str());
            strcpy(cp->normaladdr, ReserveOutputAddr.c_str());
            strcpy(cp->CChexstr, ReserveOutputPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(ReserveOutputWIF).begin(),32);
            cp->validate = ValidateReserveOutput;
            cp->ismyvin = IsReserveOutputInput;
            cp->contextualprecheck = DefaultCCContextualPreCheck;
            break;

        case EVAL_IDENTITY_ADVANCEDRESERVATION:
            strcpy(cp->unspendableCCaddr, AdvancedNameReservationAddr.c_str());
            strcpy(cp->normaladdr, AdvancedNameReservationAddr.c_str());
            strcpy(cp->CChexstr, AdvancedNameReservationPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(AdvancedNameReservationWIF).begin(),32);
            cp->validate = ValidateAdvancedNameReservation;
            cp->ismyvin = IsIdentityInput;
            cp->contextualprecheck = PrecheckIdentityReservation;
            break;

        case EVAL_RESERVE_TRANSFER:
            strcpy(cp->unspendableCCaddr, ReserveTransferAddr.c_str());
            strcpy(cp->normaladdr, ReserveTransferAddr.c_str());
            strcpy(cp->CChexstr, ReserveTransferPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(ReserveTransferWIF).begin(),32);
            cp->validate = ValidateReserveTransfer;
            cp->ismyvin = IsReserveTransferInput;
            cp->contextualprecheck = PrecheckReserveTransfer;
            break;

        case EVAL_RESERVE_DEPOSIT:
            strcpy(cp->unspendableCCaddr, ReserveDepositAddr.c_str());
            strcpy(cp->normaladdr, ReserveDepositAddr.c_str());
            strcpy(cp->CChexstr, ReserveDepositPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(ReserveDepositWIF).begin(),32);
            cp->validate = ValidateReserveDeposit;
            cp->ismyvin = IsReserveDepositInput;
            cp->contextualprecheck = PrecheckReserveDeposit;
            break;

        case EVAL_CROSSCHAIN_IMPORT:
            strcpy(cp->unspendableCCaddr, CrossChainImportAddr.c_str());
            strcpy(cp->normaladdr, CrossChainImportAddr.c_str());
            strcpy(cp->CChexstr, CrossChainImportPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(CrossChainImportWIF).begin(),32);
            cp->validate = ValidateCrossChainImport;
            cp->ismyvin = IsCrossChainImportInput;
            cp->contextualprecheck = PrecheckCrossChainImport;
            break;

        case EVAL_CROSSCHAIN_EXPORT:
            strcpy(cp->unspendableCCaddr, CrossChainExportAddr.c_str());
            strcpy(cp->normaladdr, CrossChainExportAddr.c_str());
            strcpy(cp->CChexstr, CrossChainExportPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(CrossChainExportWIF).begin(),32);
            cp->validate = ValidateCrossChainExport;
            cp->ismyvin = IsCrossChainExportInput;
            cp->contextualprecheck = PrecheckCrossChainExport;
            break;

        case EVAL_CURRENCYSTATE:
            strcpy(cp->unspendableCCaddr,CurrencyStateAddr.c_str());
            strcpy(cp->normaladdr,CurrencyStateAddr.c_str());
            strcpy(cp->CChexstr, CurrencyStatePubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(CurrencyStateWIF).begin(),32);
            cp->validate = ValidateCurrencyState;
            cp->ismyvin = IsCurrencyStateInput;
            cp->contextualprecheck = DefaultCCContextualPreCheck;
            break;

        case EVAL_IDENTITY_PRIMARY:
            strcpy(cp->unspendableCCaddr, IdentityPrimaryAddr.c_str());
            strcpy(cp->normaladdr, IdentityPrimaryAddr.c_str());
            strcpy(cp->CChexstr, IdentityPrimaryPubKey.c_str());
            memcpy(cp->CCpriv, DecodeSecret(IdentityPrimaryWIF).begin(),32);
            cp->validate = ValidateIdentityPrimary;
            cp->ismyvin = IsIdentityInput;
            cp->contextualprecheck = &PrecheckIdentityPrimary;
            break;

        case EVAL_IDENTITY_REVOKE:
            strcpy(cp->unspendableCCaddr, IdentityRevokeAddr.c_str());
            strcpy(cp->normaladdr, IdentityRevokeAddr.c_str());
            strcpy(cp->CChexstr, IdentityRevokePubKey.c_str());
            memcpy(cp->CCpriv, DecodeSecret(IdentityRevokeWIF).begin(),32);
            cp->validate = ValidateIdentityRevoke;
            cp->ismyvin = IsIdentityInput;
            cp->contextualprecheck = DefaultCCContextualPreCheck;
            break;

        case EVAL_IDENTITY_RECOVER:
            strcpy(cp->unspendableCCaddr, IdentityRecoverAddr.c_str());
            strcpy(cp->normaladdr, IdentityRecoverAddr.c_str());
            strcpy(cp->CChexstr, IdentityRecoverPubKey.c_str());
            memcpy(cp->CCpriv, DecodeSecret(IdentityRecoverWIF).begin(),32);
            cp->validate = ValidateIdentityRecover;
            cp->ismyvin = IsIdentityInput;
            cp->contextualprecheck = DefaultCCContextualPreCheck;
            break;

        case EVAL_IDENTITY_COMMITMENT:
            strcpy(cp->unspendableCCaddr, IdentityCommitmentAddr.c_str());
            strcpy(cp->normaladdr, IdentityCommitmentAddr.c_str());
            strcpy(cp->CChexstr, IdentityCommitmentPubKey.c_str());
            memcpy(cp->CCpriv, DecodeSecret(IdentityCommitmentWIF).begin(),32);
            cp->validate = ValidateIdentityCommitment;
            cp->ismyvin = IsIdentityInput;
            cp->contextualprecheck = PrecheckIdentityCommitment;
            break;

        case EVAL_IDENTITY_RESERVATION:
            strcpy(cp->unspendableCCaddr, IdentityReservationAddr.c_str());
            strcpy(cp->normaladdr, IdentityReservationAddr.c_str());
            strcpy(cp->CChexstr, IdentityReservationPubKey.c_str());
            memcpy(cp->CCpriv, DecodeSecret(IdentityReservationWIF).begin(),32);
            cp->validate = ValidateIdentityReservation;
            cp->ismyvin = IsIdentityInput;
            cp->contextualprecheck = PrecheckIdentityReservation;
            break;

        case EVAL_FINALIZE_EXPORT:
            strcpy(cp->unspendableCCaddr,FinalizeExportAddr.c_str());
            strcpy(cp->normaladdr,FinalizeExportAddr.c_str());
            strcpy(cp->CChexstr,FinalizeExportPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(FinalizeExportWIF).begin(),32);
            cp->validate = ValidateFinalizeExport;
            cp->ismyvin = IsFinalizeExportInput;  // TODO: these input functions are not useful for new CCs
            cp->contextualprecheck = PreCheckFinalizeExport;
            break;

        case EVAL_FEE_POOL:
            strcpy(cp->unspendableCCaddr, FeePoolAddr.c_str());
            strcpy(cp->normaladdr, FeePoolAddr.c_str());
            strcpy(cp->CChexstr, FeePoolPubKey.c_str());
            memcpy(cp->CCpriv, DecodeSecret(FeePoolWIF).begin(),32);
            cp->validate = ValidateFeePool;
            cp->ismyvin = IsFeePoolInput;
            cp->contextualprecheck = PrecheckFeePool;
            break;

        case EVAL_QUANTUM_KEY:
            strcpy(cp->unspendableCCaddr, QuantumKeyOutAddr.c_str());
            strcpy(cp->normaladdr, QuantumKeyOutAddr.c_str());
            strcpy(cp->CChexstr, QuantumKeyOutPubKey.c_str());     // ironically, this does not need to be a quantum secure public key, since privkey is public
            memcpy(cp->CCpriv, DecodeSecret(QuantumKeyOutWIF).begin(),32);
            cp->validate = ValidateQuantumKeyOut;
            cp->ismyvin = IsQuantumKeyOutInput;
            cp->contextualprecheck = PrecheckQuantumKeyOut;
            break;
    }
    return(cp);
}
