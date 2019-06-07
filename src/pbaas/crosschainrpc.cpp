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
 * All PBaaS chains communicate with their primary reserve chain, which is either Verus
 * or the chain that is their reserve coin. The child PBaaS chain initiates all of
 * the communication with the parent / reserve daemon.
 * 
 * Generally, the PBaaS chain will call the Verus chain to either get information needed
 * to create an earned or accepted notarization. If there is no Verus daemon available
 * staking and mining of a PBaaS chain proceeds as usual, but without notarization
 * reward opportunities.
 * 
 */

#include "chainparamsbase.h"
#include "clientversion.h"
#include "rpc/client.h"
#include "rpc/protocol.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/filesystem/operations.hpp>
#include <stdio.h>

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include "support/events.h"

#include <univalue.h>

#include "uint256.h"
#include "hash.h"
#include "pbaas/crosschainrpc.h"

using namespace std;

extern string PBAAS_HOST;
extern string PBAAS_USERPASS;
extern int32_t PBAAS_PORT;

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}

};

/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply(): status(0), error(-1) {}

    int status;
    int error;
    std::string body;
};

const char *http_errorstring(int code)
{
    switch(code) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    case EVREQ_HTTP_TIMEOUT:
        return "timeout reached";
    case EVREQ_HTTP_EOF:
        return "EOF reached";
    case EVREQ_HTTP_INVALID_HEADER:
        return "error while reading header, or invalid header";
    case EVREQ_HTTP_BUFFER_ERROR:
        return "error encountered while reading or writing";
    case EVREQ_HTTP_REQUEST_CANCEL:
        return "request was canceled";
    case EVREQ_HTTP_DATA_TOO_LONG:
        return "response body is larger than allowed";
#endif
    default:
        return "unknown";
    }
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == NULL) {
        /* If req is NULL, it means an error occurred while connecting: the
         * error code will have been passed to http_error_cb.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

#if LIBEVENT_VERSION_NUMBER >= 0x02010300
static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);
    reply->error = err;
}
#endif

UniValue CCrossChainRPCData::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("host", host));
    obj.push_back(Pair("port", port));
    obj.push_back(Pair("credentials", credentials));
    return obj;
}

static CCrossChainRPCData LoadFromConfig(std::string name)
{
    map<string, string> settings;
    map<string, vector<string>> settingsmulti;
    CCrossChainRPCData ret;

    // if we are requested to automatically load the information from the Verus chain, do it if we can find the daemon
    if (ReadConfigFile(name, settings, settingsmulti))
    {
        auto rpcuser = settings.find("-rpcuser");
        auto rpcpwd = settings.find("-rpcpassword");
        auto rpcport = settings.find("-rpcport");
        auto rpchost = settings.find("-rpchost");
        ret.credentials = rpcuser != settings.end() ? rpcuser->second + ":" : "";
        ret.credentials += rpcpwd != settings.end() ? rpcpwd->second : "";
        ret.port = rpcport != settings.end() ? atoi(rpcport->second) : (name == "VRSC" ? 27486 : 0);
        ret.host = rpchost != settings.end() ? rpchost->second : "127.0.0.1";
    }
    return ret;
}

// credentials for now are "user:password"
UniValue RPCCall(const string& strMethod, const UniValue& params, const string credentials, int port, const string host, int timeout)
{
    // Used for inter-daemon communicatoin to enable merge mining and notarization without a client
    //

    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
    evhttp_connection_set_timeout(evcon.get(), timeout);

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == NULL)
        throw std::runtime_error("create http request failed");
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    evhttp_request_set_error_cb(req.get(), http_error_cb);
#endif

    struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(credentials)).c_str());

    // Attach request data
    std::string strRequest = JSONRPCRequest(strMethod, params, 1);
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, "/");
    req.release(); // ownership moved to evcon in above call
    if (r != 0) {
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base.get());

    if (response.status == 0)
        throw CConnectionFailed(strprintf("couldn't connect to server: %s (code %d)\n(make sure server is running and you are connecting to the correct RPC port)", http_errorstring(response.error), response.error));
    else if (response.status == HTTP_UNAUTHORIZED)
        throw std::runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}

UniValue RPCCallRoot(const string& strMethod, const UniValue& params, int timeout)
{
    string host, credentials;
    int port;
    map<string, string> settings;
    map<string, vector<string>> settingsmulti;

    if (PBAAS_HOST != "" && PBAAS_PORT != 0)
    {
        return RPCCall(strMethod, params, PBAAS_USERPASS, PBAAS_PORT, PBAAS_HOST);
    }
    else if (ReadConfigFile(PBAAS_TESTMODE ? "VRSCTEST" : "VRSC", settings, settingsmulti))
    {
        PBAAS_USERPASS = settingsmulti.find("-rpcuser")->second[0] + ":" + settingsmulti.find("-rpcpassword")->second[0];
        PBAAS_PORT = atoi(settingsmulti.find("-rpcport")->second[0]);
        PBAAS_HOST = settingsmulti.find("-rpchost")->second[0];
        if (!PBAAS_HOST.size())
        {
            PBAAS_HOST = "127.0.0.1";
        }
        return RPCCall(strMethod, params, credentials, port, host, timeout);
    }
    return UniValue(UniValue::VNULL);
}

int32_t uni_get_int(UniValue uv, int32_t def)
{
    try
    {
        return uv.get_int();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

int64_t uni_get_int64(UniValue uv, int64_t def)
{
    try
    {
        return uv.get_int64();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

std::string uni_get_str(UniValue uv, std::string def)
{
    try
    {
        return uv.get_str();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

std::vector<UniValue> uni_getValues(UniValue uv, std::vector<UniValue> def)
{
    try
    {
        return uv.getValues();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

uint160 CCrossChainRPCData::GetConditionID(uint160 cid, int32_t condition)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 CCrossChainRPCData::GetConditionID(std::string name, int32_t condition)
{
    uint160 cid = GetChainID(name);

    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}
