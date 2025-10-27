// Copyright (c) 2019 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VERUS_PBAASRPC_H
#define VERUS_PBAASRPC_H

#include "amount.h"
#include "uint256.h"
#include "sync.h"
#include <stdint.h>
#include <map>
#include "pbaas/notarization.h"
#include "pbaas/reserves.h"

#include <boost/assign/list_of.hpp>

#include <univalue.h>

bool GetCurrencyDefinition(const std::string &name, CCurrencyDefinition &chainDef);
bool GetCurrencyDefinition(const uint160 &chainID, CCurrencyDefinition &chainDef, int32_t *pDefHeight=nullptr, bool checkMempool=false, bool notarizationCheck=false, CUTXORef *pUTXO=nullptr, std::vector<CNodeData> *pGoodNodes=nullptr);

UniValue getnotarizationproofs(const UniValue& params, bool fHelp);

// if pCounterEvidence is non-null, each entry in the returned vector, which can be indexed as vtx is, returns evidence, followed by challenge root and entropy root
bool GetNotarizationData(const uint160 &chainID,
                         CChainNotarizationData &notarizationData,
                         std::vector<std::pair<CTransaction, uint256>> *optionalTxOut=nullptr,
                         std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence, CProofRoot, CProofRoot>>> *pCounterEvidence=nullptr,
                         std::vector<std::vector<std::tuple<CObjectFinalization, CNotaryEvidence>>> *pEvidence=nullptr);

bool GetChainTransfers(std::multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors,
                            uint160 chainFilter = uint160(), int start=0, int end=0, uint32_t flags=CReserveTransfer::VALID);
bool GetChainTransfersUnspentBy(std::multimap<std::pair<uint32_t, uint160>, std::pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors,
                            uint160 chainFilter, uint32_t start, uint32_t end, uint32_t unspentBy, const uint256 &checkingTxHash, uint32_t flags=CReserveTransfer::VALID);
bool GetChainTransfersBetween(std::multimap<std::pair<uint32_t, uint160>, std::pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors,
                            uint160 chainFilter, uint32_t start, uint32_t end, uint32_t flags=CReserveTransfer::VALID);
bool GetUnspentChainTransfers(std::multimap<uint160, ChainTransferData> &inputDescriptors, uint160 chainFilter = uint160());
bool GetUnspentChainTransfers(std::vector<ChainTransferData> &inputDescriptors, uint160 chainID);

std::multimap<std::tuple<int, uint160, uint160, int64_t, int64_t>, std::pair<std::pair<int, CCurrencyValueMap>, std::pair<CInputDescriptor, CTransaction>>>
GetOfferMap(const uint160 &currencyOrId, bool isCurrency, bool acceptOnlyCurrency, bool acceptOnlyId, const std::set<uint160> &currencyOrIdFilter);

bool SelectArbitrageFromOffers(const std::vector<
    std::multimap<std::tuple<int, uint160, uint160, int64_t, int64_t>, std::pair<std::pair<int, CCurrencyValueMap>, std::pair<CInputDescriptor, CTransaction>>>>
                                                        &offers,
                                                        const CPBaaSNotarization &lastNotarization,
                                                        const CCurrencyDefinition &sourceSystem,
                                                        const CCurrencyDefinition &destCurrency,
                                                        uint32_t startHeight,
                                                        uint32_t nextHeight,
                                                        std::vector<CReserveTransfer> &exportTransfers,
                                                        uint256 &transferHash,
                                                        CPBaaSNotarization &newNotarization,
                                                        std::vector<CTxOut> &newOutputs,
                                                        CCurrencyValueMap &importedCurrency,
                                                        CCurrencyValueMap &gatewayDepositsUsed,
                                                        CCurrencyValueMap &spentCurrencyOut,
                                                        const CTransferDestination &rewardDest,
                                                        const CCurrencyValueMap &arbitrageCurrencies,
                                                        std::vector<std::tuple<CInputDescriptor, CReserveTransfer, CTransaction>> &arbitrageInputs);

UniValue getcurrency(const UniValue& params, bool fHelp);
UniValue getnotarizationdata(const UniValue& params, bool fHelp);
UniValue definecurrency(const UniValue& params, bool fHelp);
UniValue addmergedblock(const UniValue& params, bool fHelp);

void RegisterPBaaSRPCCommands(CRPCTable &tableRPC);

std::map<std::string, UniValue> UniObjectToMap(const UniValue &obj);
UniValue MapToUniObject(const std::map<std::string, UniValue> &uniMap);

#endif // VERUS_PBAASRPC_H