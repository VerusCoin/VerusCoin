// Copyright (c) 2012-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

/**
 * network protocol versioning
 */

static const int PROTOCOL_VERSION = 170010;

//! initial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 209;

//! In this version, 'getheaders' was introduced.
static const int GETHEADERS_VERSION = 31800;

//! disconnect from peers older than this proto version
static const int MIN_PEER_PROTO_VERSION = 170009;
static const int MIN_PBAAS_VERSION = 170009;
static const int MIN_VARRR_VERSION = 170010;

//! nTime field added to CAddress, starting with this version;
//! if possible, avoid requesting addresses nodes older than this
static const int CADDR_TIME_VERSION = 31402;

//! BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 60000;

//! "mempool" command, enhanced "getdata" behavior starts with this version
static const int MEMPOOL_GD_VERSION = 60002;

//! "filter*" commands are disabled without NODE_BLOOM after and including this version
static const int NO_BLOOM_VERSION = 170004;

#define KOMODO_VERSION "0.2.1"
#define VERUS_VERSION "1.2.14"

#endif // BITCOIN_VERSION_H
