/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for PBaaS cross chain communication.
 * 
 * In merge mining and notarization, Verus acts as a hub that other PBaaS chains
 * call via RPC in order to get information that allows earning and submitting
 * notarizations.
 * 
 */

#ifndef CROSSCHAINRPC_H
#define CROSSCHAINRPC_H

#include <univalue.h>

static const int DEFAULT_RPC_TIMEOUT=900;

class CCrossChainRPCData
{
public:
    std::string host;
    int32_t port;
    std::string credentials;

    CCrossChainRPCData() : port(0) {}

    CCrossChainRPCData(std::string Host, int32_t Port, std::string Credentials) :
        host(Host), port(Port), credentials(Credentials) {}
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(host);
        READWRITE(port);        
        READWRITE(credentials);
    }

    static CCrossChainRPCData LoadFromConfig(std::string fPath="");

    inline static uint160 GetChainID(std::string name)
    {
        const char *chainName = name.c_str();
        uint256 chainHash = Hash(chainName, chainName + strlen(chainName));
        return Hash160(chainHash.begin(), chainHash.end());
    }

    static uint160 GetConditionID(uint160 cid, int32_t condition);
    static uint160 GetConditionID(std::string name, int32_t condition);

    UniValue ToUniValue() const;
};

// credentials for now are "user:password"
UniValue RPCCall(const std::string& strMethod, 
                 const UniValue& params, 
                 const std::string credentials="user:pass", 
                 int port=27486, 
                 const std::string host="127.0.0.1", 
                 int timeout=DEFAULT_RPC_TIMEOUT);

UniValue RPCCallRoot(const std::string& strMethod, const UniValue& params, int timeout=DEFAULT_RPC_TIMEOUT);

int32_t uni_get_int(UniValue uv, int32_t def=0);
int64_t uni_get_int64(UniValue uv, int64_t def =0);
std::string uni_get_str(UniValue uv, std::string def="");
std::vector<UniValue> uni_getValues(UniValue uv, std::vector<UniValue> def=std::vector<UniValue>());

#endif
