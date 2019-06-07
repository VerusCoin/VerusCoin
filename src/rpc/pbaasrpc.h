// Copyright (c) 2019 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VERUS_PBAASRPC_H
#define VERUS_PBAASRPC_H

#include "amount.h"
#include "uint256.h"
#include "sync.h"
#include <stdint.h>
#include "pbaas/notarization.h"

#include <boost/assign/list_of.hpp>

#include <univalue.h>

bool GetChainDefinition(std::string &name, CPBaaSChainDefinition &chainDef);
bool GetNotarizationData(uint160 chainID, uint32_t ecode, CChainNotarizationData &notarizationData, std::vector<std::pair<CTransaction, uint256>> *optionalTxOut = NULL);

UniValue getchaindefinition(const UniValue& params, bool fHelp);
UniValue getnotarizationdata(const UniValue& params, bool fHelp);
UniValue getcrossnotarization(const UniValue& params, bool fHelp);
UniValue definechain(const UniValue& params, bool fHelp);
UniValue addmergedblock(const UniValue& params, bool fHelp);

void RegisterPBaaSRPCCommands(CRPCTable &tableRPC);

#endif // VERUS_PBAASRPC_H