// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "txdb.h"
#include "startup_guts.h"
#include <chrono>

#include "chainparams.h"
#include "hash.h"
#include "main.h"
#include "pow.h"
#include "uint256.h"
#include "core_io.h"
#include "rpc/protocol.h"
#include "cc/eval.h"
#include "cc/CCinclude.h"
#include "pbaas/crosschainrpc.h"
#include "pbaas/vdxf.h"
#include "pbaas/identity.h"

#include <stdint.h>

#include <boost/thread.hpp>

using namespace std;

// NOTE: Per issue #3277, do not use the prefix 'X' or 'x' as they were
// previously used by DB_SAPLING_ANCHOR and DB_BEST_SAPLING_ANCHOR.
static const char DB_SPROUT_ANCHOR = 'A';
static const char DB_SAPLING_ANCHOR = 'Z';
static const char DB_NULLIFIER = 's';
static const char DB_SAPLING_NULLIFIER = 'S';
static const char DB_COINS = 'c';
static const char DB_BLOCK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_ADDRESSINDEX = 'd';
static const char DB_ADDRESSUNSPENTINDEX = 'u';
static const char DB_TIMESTAMPINDEX = 'S';
static const char DB_BLOCKHASHINDEX = 'z';
static const char DB_SPENTINDEX = 'p';
static const char DB_BLOCK_INDEX = 'b';
static const char DB_ADDRESSRESERVEBALANCE = 'r';

static const char DB_BEST_BLOCK = 'B';
static const char DB_BEST_SPROUT_ANCHOR = 'a';
static const char DB_BEST_SAPLING_ANCHOR = 'z';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';

// Zcash defines are slightly different - commenting rather than removing
// in case there is ever a related error
//static const char DB_TIMESTAMPINDEX = 'T';
//static const char DB_BLOCKHASHINDEX = 'h';

CCoinsViewDB::CCoinsViewDB(std::string dbName, size_t nCacheSize, bool fMemory, bool fWipe) : db(GetDataDir() / dbName, nCacheSize, fMemory, fWipe) {
}

CCoinsViewDB::CCoinsViewDB(size_t nCacheSize, bool fMemory, bool fWipe) : db(GetDataDir() / "chainstate", nCacheSize, fMemory, fWipe) 
{
}


bool CCoinsViewDB::GetSproutAnchorAt(const uint256 &rt, SproutMerkleTree &tree) const {
    if (rt == SproutMerkleTree::empty_root()) {
        SproutMerkleTree new_tree;
        tree = new_tree;
        return true;
    }

    bool read = db.Read(make_pair(DB_SPROUT_ANCHOR, rt), tree);

    return read;
}

bool CCoinsViewDB::GetSaplingAnchorAt(const uint256 &rt, SaplingMerkleTree &tree) const {
    if (rt == SaplingMerkleTree::empty_root()) {
        SaplingMerkleTree new_tree;
        tree = new_tree;
        return true;
    }

    bool read = db.Read(make_pair(DB_SAPLING_ANCHOR, rt), tree);

    return read;
}

bool CCoinsViewDB::GetNullifier(const uint256 &nf, ShieldedType type) const {
    bool spent = false;
    char dbChar;
    switch (type) {
        case SPROUT:
            dbChar = DB_NULLIFIER;
            break;
        case SAPLING:
            dbChar = DB_SAPLING_NULLIFIER;
            break;
        default:
            throw runtime_error("Unknown shielded type");
    }
    return db.Read(make_pair(dbChar, nf), spent);
}

bool CCoinsViewDB::GetCoins(const uint256 &txid, CCoins &coins) const {
    return db.Read(make_pair(DB_COINS, txid), coins);
}

bool CCoinsViewDB::HaveCoins(const uint256 &txid) const {
    return db.Exists(make_pair(DB_COINS, txid));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!db.Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

uint256 CCoinsViewDB::GetBestAnchor(ShieldedType type) const {
    uint256 hashBestAnchor;
    
    switch (type) {
        case SPROUT:
            if (!db.Read(DB_BEST_SPROUT_ANCHOR, hashBestAnchor))
                return SproutMerkleTree::empty_root();
            break;
        case SAPLING:
            if (!db.Read(DB_BEST_SAPLING_ANCHOR, hashBestAnchor))
                return SaplingMerkleTree::empty_root();
            break;
        default:
            throw runtime_error("Unknown shielded type");
    }

    return hashBestAnchor;
}

void BatchWriteNullifiers(CDBBatch& batch, CNullifiersMap& mapToUse, const char& dbChar)
{
    for (CNullifiersMap::iterator it = mapToUse.begin(); it != mapToUse.end();) {
        if (it->second.flags & CNullifiersCacheEntry::DIRTY) {
            if (!it->second.entered)
                batch.Erase(make_pair(dbChar, it->first));
            else
                batch.Write(make_pair(dbChar, it->first), true);
            // TODO: changed++? ... See comment in CCoinsViewDB::BatchWrite. If this is needed we could return an int
        }
        CNullifiersMap::iterator itOld = it++;
        mapToUse.erase(itOld);
    }
}

template<typename Map, typename MapIterator, typename MapEntry, typename Tree>
void BatchWriteAnchors(CDBBatch& batch, Map& mapToUse, const char& dbChar)
{
    for (MapIterator it = mapToUse.begin(); it != mapToUse.end();) {
        if (it->second.flags & MapEntry::DIRTY) {
            if (!it->second.entered)
                batch.Erase(make_pair(dbChar, it->first));
            else {
                if (it->first != Tree::empty_root()) {
                    batch.Write(make_pair(dbChar, it->first), it->second.tree);
                }
            }
            // TODO: changed++?
        }
        MapIterator itOld = it++;
        mapToUse.erase(itOld);
    }
}

bool CCoinsViewDB::BatchWrite(CCoinsMap &mapCoins,
                              const uint256 &hashBlock,
                              const uint256 &hashSproutAnchor,
                              const uint256 &hashSaplingAnchor,
                              CAnchorsSproutMap &mapSproutAnchors,
                              CAnchorsSaplingMap &mapSaplingAnchors,
                              CNullifiersMap &mapSproutNullifiers,
                              CNullifiersMap &mapSaplingNullifiers) {
    CDBBatch batch(db);
    size_t count = 0;
    size_t changed = 0;
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) {
            if (it->second.coins.IsPruned())
                batch.Erase(make_pair(DB_COINS, it->first));
            else
                batch.Write(make_pair(DB_COINS, it->first), it->second.coins);
            changed++;
        }
        count++;
        CCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
    }

    ::BatchWriteAnchors<CAnchorsSproutMap, CAnchorsSproutMap::iterator, CAnchorsSproutCacheEntry, SproutMerkleTree>(batch, mapSproutAnchors, DB_SPROUT_ANCHOR);
    ::BatchWriteAnchors<CAnchorsSaplingMap, CAnchorsSaplingMap::iterator, CAnchorsSaplingCacheEntry, SaplingMerkleTree>(batch, mapSaplingAnchors, DB_SAPLING_ANCHOR);

    ::BatchWriteNullifiers(batch, mapSproutNullifiers, DB_NULLIFIER);
    ::BatchWriteNullifiers(batch, mapSaplingNullifiers, DB_SAPLING_NULLIFIER);

    if (!hashBlock.IsNull())
        batch.Write(DB_BEST_BLOCK, hashBlock);
    if (!hashSproutAnchor.IsNull())
        batch.Write(DB_BEST_SPROUT_ANCHOR, hashSproutAnchor);
    if (!hashSaplingAnchor.IsNull())
        batch.Write(DB_BEST_SAPLING_ANCHOR, hashSaplingAnchor);

    LogPrint("coindb", "Committing %u changed transactions (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return db.WriteBatch(batch);
}

CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe, bool compression, int maxOpenFiles) : CDBWrapper(GetDataDir() / "blocks" / "index", nCacheSize, fMemory, fWipe, compression, maxOpenFiles) {
}

bool CBlockTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo &info) {
    return Read(make_pair(DB_BLOCK_FILES, nFile), info);
}

bool CBlockTreeDB::WriteReindexing(bool fReindexing) {
    if (fReindexing)
        return Write(DB_REINDEX_FLAG, '1');
    else
        return Erase(DB_REINDEX_FLAG);
}

bool CBlockTreeDB::ReadReindexing(bool &fReindexing) {
    fReindexing = Exists(DB_REINDEX_FLAG);
    return true;
}

bool CBlockTreeDB::ReadLastBlockFile(int &nFile) {
    return Read(DB_LAST_BLOCK, nFile);
}

bool CCoinsViewDB::GetStats(CCoinsStats &stats) const {
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    boost::scoped_ptr<CDBIterator> pcursor(const_cast<CDBWrapper*>(&db)->NewIterator());
    pcursor->Seek(DB_COINS);

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    stats.hashBlock = GetBestBlock();
    ss << stats.hashBlock;
    CAmount nTotalAmount = 0;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        CCoins coins;
        if (pcursor->GetKey(key) && key.first == DB_COINS) {
            if (pcursor->GetValue(coins)) {
                stats.nTransactions++;
                for (unsigned int i=0; i<coins.vout.size(); i++) {
                    const CTxOut &out = coins.vout[i];
                    if (!out.IsNull()) {
                        stats.nTransactionOutputs++;
                        ss << VARINT(i+1);
                        ss << out;
                        nTotalAmount += out.nValue;
                    }
                }
                stats.nSerializedSize += 32 + pcursor->GetValueSize();
                ss << VARINT(0);
            } else {
                return error("CCoinsViewDB::GetStats() : unable to read value");
            }
        } else {
            break;
        }
        pcursor->Next();
    }
    {
        LOCK(cs_main);
        stats.nHeight = mapBlockIndex.find(stats.hashBlock)->second->GetHeight();
    }
    stats.hashSerialized = ss.GetHash();
    stats.nTotalAmount = nTotalAmount;
    return true;
}

bool CBlockTreeDB::WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<int, const CBlockFileInfo*> >::const_iterator it=fileInfo.begin(); it != fileInfo.end(); it++) {
        batch.Write(make_pair(DB_BLOCK_FILES, it->first), *it->second);
    }
    batch.Write(DB_LAST_BLOCK, nLastFile);
    for (std::vector<const CBlockIndex*>::const_iterator it=blockinfo.begin(); it != blockinfo.end(); it++) {
        batch.Write(make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()), CDiskBlockIndex(*it));
    }
    return WriteBatch(batch, true);
}

bool CBlockTreeDB::EraseBatchSync(const std::vector<const CBlockIndex*>& blockinfo) {
    CDBBatch batch(*this);
    for (std::vector<const CBlockIndex*>::const_iterator it=blockinfo.begin(); it != blockinfo.end(); it++) {
        batch.Erase(make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()));
    }
    return WriteBatch(batch, true);
}

bool CBlockTreeDB::ReadTxIndex(const uint256 &txid, CDiskTxPos &pos) {
    return Read(make_pair(DB_TXINDEX, txid), pos);
}

bool CBlockTreeDB::WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<uint256,CDiskTxPos> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Write(make_pair(DB_TXINDEX, it->first), it->second);
    return WriteBatch(batch);
}

bool CBlockTreeDB::ReadSpentIndex(CSpentIndexKey &key, CSpentIndexValue &value) {
    return Read(make_pair(DB_SPENTINDEX, key), value);
}

bool CBlockTreeDB::UpdateSpentIndex(const std::vector<CSpentIndexDbEntry> &vect) {
    CDBBatch batch(*this);
    for (std::vector<CSpentIndexDbEntry>::const_iterator it=vect.begin(); it!=vect.end(); it++) {
        if (it->second.IsNull()) {
            batch.Erase(make_pair(DB_SPENTINDEX, it->first));
        } else {
            batch.Write(make_pair(DB_SPENTINDEX, it->first), it->second);
        }
    }
    return WriteBatch(batch);
}

bool CBlockTreeDB::UpdateAddressUnspentIndex(const std::vector<CAddressUnspentDbEntry> &vect) {
    CDBBatch batch(*this);
    for (std::vector<CAddressUnspentDbEntry>::const_iterator it=vect.begin(); it!=vect.end(); it++) {
        if (it->second.IsNull()) {
            batch.Erase(make_pair(DB_ADDRESSUNSPENTINDEX, it->first));
        } else {
            batch.Write(make_pair(DB_ADDRESSUNSPENTINDEX, it->first), it->second);
        }
    }
    return WriteBatch(batch);
}

bool CBlockTreeDB::ReadAddressUnspentIndex(uint160 addressHash, int type, std::vector<CAddressUnspentDbEntry> &unspentOutputs)
{
    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(make_pair(DB_ADDRESSUNSPENTINDEX, CAddressIndexIteratorKey(type, addressHash)));

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            pair<char, CAddressUnspentKey> keyObj;
            pcursor->GetKey(keyObj);
            char chType = keyObj.first;
            CAddressUnspentKey indexKey = keyObj.second;

            if (chType == DB_ADDRESSUNSPENTINDEX && indexKey.hashBytes == addressHash) {
                try {
                    CAddressUnspentValue nValue;
                    pcursor->GetValue(nValue);
                    unspentOutputs.push_back(make_pair(indexKey, nValue));
                    pcursor->Next();
                } catch (const std::exception& e) {
                    return error("failed to get address unspent value");
                }
            } else {
                break;
            }
        } catch (const std::exception& e) {
            break;
        }
    }
    return true;
}

bool CBlockTreeDB::WriteAddressIndex(const std::vector<CAddressIndexDbEntry> &vect) {
    CDBBatch batch(*this);
    for (std::vector<CAddressIndexDbEntry>::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Write(make_pair(DB_ADDRESSINDEX, it->first), it->second);
    return WriteBatch(batch);
}

bool CBlockTreeDB::EraseAddressIndex(const std::vector<CAddressIndexDbEntry> &vect) {
    CDBBatch batch(*this);
    for (std::vector<CAddressIndexDbEntry>::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Erase(make_pair(DB_ADDRESSINDEX, it->first));
    return WriteBatch(batch);
}

bool CBlockTreeDB::ReadAddressIndex(
        uint160 addressHash, int type,
        std::vector<CAddressIndexDbEntry> &addressIndex,
        int start, int end)
{
    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    if (start > 0 && end > 0) {
        pcursor->Seek(make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorHeightKey(type, addressHash, start)));
    } else {
        pcursor->Seek(make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorKey(type, addressHash)));
    }

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            pair<char, CAddressIndexKey> keyObj;
            pcursor->GetKey(keyObj);
            char chType = keyObj.first;
            CAddressIndexKey indexKey = keyObj.second;

            if (chType == DB_ADDRESSINDEX && indexKey.hashBytes == addressHash) {
                if (end > 0 && indexKey.blockHeight > end) {
                    break;
                }
                try {
                    CAmount nValue;
                    pcursor->GetValue(nValue);

                    addressIndex.push_back(make_pair(indexKey, nValue));
                    pcursor->Next();
                } catch (const std::exception& e) {
                    return error("failed to get address index value");
                }
            } else {
                break;
            }
        } catch (const std::exception& e) {
            break;
        }
    }

    return true;
}

bool CBlockTreeDB::UpdateAddressReserveBalance(const std::vector<CAddressReserveBalanceEntry> &vect) {
    CDBBatch batch(*this);
    for (const auto &entry : vect) {
        // Read existing balance if it exists
        CAddressReserveBalanceValue existingValue;
        if (Read(make_pair(DB_ADDRESSRESERVEBALANCE, entry.first), existingValue)) {
            // Update existing balance
            existingValue.balance += entry.second.balance;
            existingValue.received += entry.second.received;
            batch.Write(make_pair(DB_ADDRESSRESERVEBALANCE, entry.first), existingValue);
        } else {
            // Write new balance
            batch.Write(make_pair(DB_ADDRESSRESERVEBALANCE, entry.first), entry.second);
        }
    }
    return WriteBatch(batch);
}

bool CBlockTreeDB::ReadAddressReserveBalance(
    uint160 addressHash, 
    int type, 
    std::map<uint160, CAddressReserveBalanceValue> &balanceMap)
{
    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
    
    // Seek to the first entry for this address
    CAddressReserveBalanceKey seekKey(type, addressHash, uint160());
    pcursor->Seek(make_pair(DB_ADDRESSRESERVEBALANCE, seekKey));

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            pair<char, CAddressReserveBalanceKey> keyObj;
            pcursor->GetKey(keyObj);
            char chType = keyObj.first;
            CAddressReserveBalanceKey key = keyObj.second;

            // Check if we're still on the correct address
            if (chType == DB_ADDRESSRESERVEBALANCE && 
                key.type == type && 
                key.hashBytes == addressHash) {
                try {
                    CAddressReserveBalanceValue value;
                    pcursor->GetValue(value);
                    balanceMap[key.currencyID] = value;
                    pcursor->Next();
                } catch (const std::exception& e) {
                    return error("failed to get reserve balance value");
                }
            } else {
                break;
            }
        } catch (const std::exception& e) {
            break;
        }
    }

    return true;
}

bool getAddressFromIndex(const int &type, const uint160 &hash, std::string &address);

UniValue CBlockTreeDB::Snapshot(int top)
{
    int64_t total = 0; int64_t totalAddresses = 0; std::string address;
    int64_t utxos = 0; int64_t ignoredAddresses;
    boost::scoped_ptr<CDBIterator> iter(NewIterator());
    std::map <std::string, CAmount> addressAmounts;
    std::vector <std::pair<CAmount, std::string>> vaddr;
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("start_time", (int) time(NULL)));

    std::map <std::string,int> ignoredMap = {
	{"RReUxSs5hGE39ELU23DfydX8riUuzdrHAE", 1},
	{"RMUF3UDmzWFLSKV82iFbMaqzJpUnrWjcT4", 1},
	{"RA5imhVyJa7yHhggmBytWuDr923j2P1bxx", 1},
	{"RBM5LofZFodMeewUzoMWcxedm3L3hYRaWg", 1},
	{"RAdcko2d94TQUcJhtFHZZjMyWBKEVfgn4J", 1},
	{"RLzUaZ934k2EFCsAiVjrJqM8uU1vmMRFzk", 1},
	{"RMSZMWZXv4FhUgWhEo4R3AQXmRDJ6rsGyt", 1},
	{"RUDrX1v5toCsJMUgtvBmScKjwCB5NaR8py", 1},
	{"RMSZMWZXv4FhUgWhEo4R3AQXmRDJ6rsGyt", 1},
	{"RRvwmbkxR5YRzPGL5kMFHMe1AH33MeD8rN", 1},
	{"RQLQvSgpPAJNPgnpc8MrYsbBhep95nCS8L", 1},
	{"RK8JtBV78HdvEPvtV5ckeMPSTojZPzHUTe", 1},
	{"RHVs2KaCTGUMNv3cyWiG1jkEvZjigbCnD2", 1},
	{"RE3SVaDgdjkRPYA6TRobbthsfCmxQedVgF", 1},
	{"RW6S5Lw5ZCCvDyq4QV9vVy7jDHfnynr5mn", 1},
	{"RTkJwAYtdXXhVsS3JXBAJPnKaBfMDEswF8", 1},
	{"RD6GgnrMpPaTSMn8vai6yiGA7mN4QGPVMY", 1} //Burnaddress for null privkey
    };

    int64_t startingHeight = chainActive.Height();
    //fprintf(stderr, "Starting snapshot at height %lli\n", startingHeight);
    for (iter->SeekToLast(); iter->Valid(); iter->Prev())
    {
        boost::this_thread::interruption_point();
        try
        {
            std::vector<unsigned char> slKey = std::vector<unsigned char>();
            pair<char, CAddressIndexIteratorKey> keyObj;
            iter->GetKey(keyObj);

            char chType = keyObj.first;
            CAddressIndexIteratorKey indexKey = keyObj.second;

            //fprintf(stderr, "chType=%d\n", chType);
            if (chType == DB_ADDRESSUNSPENTINDEX)
            {
                try {
                    CAmount nValue;
                    iter->GetValue(nValue);

                    getAddressFromIndex(indexKey.type, indexKey.hashBytes, address);

                    std::map <std::string, int>::iterator ignored = ignoredMap.find(address);
                    if (ignored != ignoredMap.end()) {
                    fprintf(stderr,"ignoring %s\n", address.c_str());
                    ignoredAddresses++;
                    continue;
                    }

                    std::map <std::string, CAmount>::iterator pos = addressAmounts.find(address);
                    if (pos == addressAmounts.end()) {
                    // insert new address + utxo amount
                    //fprintf(stderr, "inserting new address %s with amount %li\n", address.c_str(), nValue);
                    addressAmounts[address] = nValue;
                    totalAddresses++;
                    } else {
                    // update unspent tally for this address
                    //fprintf(stderr, "updating address %s with new utxo amount %li\n", address.c_str(), nValue);
                    addressAmounts[address] += nValue;
                    }
                    //fprintf(stderr,"{\"%s\", %.8f},\n",address.c_str(),(double)nValue/COIN);
                    // total += nValue;
                    utxos++;
                } catch (const std::exception& e) {
                    fprintf(stderr, "DONE %s: LevelDB addressindex exception! - %s\n", __func__, e.what());
                    break;
                }
	        }
        } catch (const std::exception& e) {
	        fprintf(stderr, "DONE reading index entries\n");
            break;
        }
    }

    UniValue addresses(UniValue::VARR);
    //fprintf(stderr, "total=%f, totalAddresses=%li, utxos=%li, ignored=%li\n", (double) total / COIN, totalAddresses, utxos, ignoredAddresses);

    for (std::pair<std::string, CAmount> element : addressAmounts) {
	vaddr.push_back( make_pair(element.second, element.first) );
    }
    std::sort(vaddr.rbegin(), vaddr.rend());

    UniValue obj(UniValue::VOBJ);
    UniValue addressesSorted(UniValue::VARR);
    int topN = 0;
    for (std::vector<std::pair<CAmount, std::string>>::iterator it = vaddr.begin(); it!=vaddr.end(); ++it) {
	UniValue obj(UniValue::VOBJ);
	obj.push_back( make_pair("addr", it->second.c_str() ) );
	char amount[32];
	snprintf(amount, sizeof(amount), "%.8f", (double) it->first / COIN);
	obj.push_back( make_pair("amount", amount) );
	total += it->first;
	addressesSorted.push_back(obj);
	topN++;
	// If requested, only show top N addresses in output JSON
 	if (top == topN)
	    break;
    }

    if (top)
	totalAddresses = top;

    if (totalAddresses > 0) {
	// Array of all addreses with balances
        result.push_back(make_pair("addresses", addressesSorted));
	// Total amount in this snapshot, which is less than circulating supply if top parameter is used
        result.push_back(make_pair("total", (double) total / COIN ));
	// Average amount in each address of this snapshot
        result.push_back(make_pair("average",(double) (total/COIN) / totalAddresses ));
    }
    // Total number of utxos processed in this snaphot
    result.push_back(make_pair("utxos", utxos));
    // Total number of addresses in this snaphot
    result.push_back(make_pair("total_addresses", totalAddresses));
    // Total number of ignored addresses in this snaphot
    result.push_back(make_pair("ignored_addresses", ignoredAddresses));
    // The snapshot began at this block height
    result.push_back(make_pair("start_height", startingHeight));
    // The snapshot finished at this block height
    result.push_back(make_pair("ending_height", chainActive.Height()));
    return(result);
}

// can query and return currency definitions for currencies on this system or from a specific system specified in systemIDQualifier
void GetCurrencyDefinitions(const uint160 &systemIDQualifier,
                            std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> &chains,
                            CCurrencyDefinition::EQueryOptions launchStateQuery,
                            CCurrencyDefinition::EQueryOptions systemTypeQuery,
                            const std::set<uint160> &converters,
                            uint32_t startBlock=0,
                            uint32_t endBlock=0);

UniValue getcurrencystate(const UniValue& params, bool fHelp);
UniValue getreservedeposits(const UniValue& params, bool fHelp);
UniValue getaddressutxos(const UniValue& params, bool fHelp);
std::string EncodeDestination(const CTxDestination& dest);
CAmount GetMinRelayFeeForOutputs(const std::vector<SendManyRecipient> &tOutputs, const std::vector<SendManyRecipient> &zOutputs, CAmount identityFeeFactor, bool isIdentity);

// This function goes through all UTXOs and creates transactions for every UTXO that
// contains a currency or derivative of a currency in the currencyAdjustments.
// generated outputs:
//  1) Create a transaction that spends from the UTXO or reserve deposits in some cases
//      to new UTXO(s) that have reduced output of any currencies in currencyAdjustments
//      according to the following rules:
//      a) Direct, non-basket currency - reduce each currency by the specific percentage
//      specified in the currencyAdjustments map, with one SATOSHIDEN being equivalent
//      to 100%.
//
//      b) Direct, basket currency - reduce the currency by the maximum reduction of any
//      currency within the basket, if a contained currency is a basket currency, the
//      process of determining the maximum is extended to contained baskets recursively.
//      For each currency that is contained, but has a lower percentage than the
//      maximum, the difference will be sent from the basket currencies reserve deposits
//      to the address recipient, if there is no recursion.
//
//      c) If there is recursion (ie. one basket currency contained within another), any
//      difference that may be disgorged from contained baskets will be sent to the
//      addresses that had their balance of the container basket reduced, and their
//      portion of the amount of digorgement sent via the container basket, will be
//      proportionate to their percentage of loss of the total loss of basket currency.
//      If the basket to be refunded is on another chain, the amounts in the txes
//      created will be equivalent to the amounts reduced by each specific UTXO of the
//      container basket currency. These transactions will need to have the correct
//      numbers replace the embedded numbers before signing and execution, by prorating
//      the total amounts of the balance on the other chain. Disgorgement transactions
//      will always need to be executed only on the chain that processes their basket
//      currency.
//
//  2) Instead of creating unlimited numbers of transactions, wherever possible, address
//      recipients will have their totals summed and transactions will consolidate
//      multiple UTXOs.
//
//  3) All baskets affected will have a single, exempt import transaction with no
//      reserve transfers and a new currency state entered onto the chain. During the
//      recovery window explicitly, these transactions, if signed by the recovery ID,
//      will be allowed. An import transaction is required, as the protocol considers
//      the latest import notarization to be the definitive currency state of a basket
//      currency.
//
//  4) All chain fee source transactions are transactions that can be provided for all
//      chains, and if there are enough UTXOs for the fees for every new transaction on
//      those provided, they will be used as inpur for all of the transactions created,
//      leaving them ready for signing and submission.
//
// TODO: still need to adjust the bridges by sending bridge refund commands to send gateway
//      reserve deposits to chain address for burning
//
// Enabling sequence on chain operation will be as follows:
//  1) First step: defi enabled with restrictions in specific block window for each chain, and/or controlled by oracles
//      a) All non-prohibited disgorgement reserve transfers will be refunded
//      b) All pending cross-chain transactions will complete and no new ones accepted
//      c) No new reserve transfers will be entered into the chain, except as an output
//          from an import or one that is signed by the adjustment ID
//
//  2) All non-reservedeposit UTXOs that contain any affected currency are under the control of the adjustment IDs for
//      each chain.
//
//  3) All cross chain notarizations will be enabled.
//
//  4) Adjustment transactions will be created. Enough fee UTXOs for exact fees for all transactions will be generated
//      on all chains for the adjustment ID.
//
//  5) All address reduction transactions will be entered
//  6) All currency reduction transactions will be entered and processed
//  7) All non-restitution currency reimbursement transactions will be entered and processed
//  8) Contract upgrade voting will happen simultaneously
//
//  9) After contract upgrade and all transaction completion, window will close, adjustment IDs will be burned, and
//      full DeFi will be reenabled.
//
//
// ADJUSTMENTS SHOULD ONLY INCLUDE PRIMARY CURRENCY REDUCTIONS AND CANNOT INCLUDE NATIVE PBAAS CURRENCIES
// ALL CROSS CHAIN CURRENCIES THAT COMPLETED LAUNCHES MUST BE IN crossChainCurrencies
// ALL FRACTIONAL CROSS CHAIN CURRENCY STATES THAT COMPLETED LAUNCHES MUST BE IN crossChainCurrencyStates
// CURRENCIES AND CURRENCY STATES FROM THIS CHAIN MAY OR MAY NOT BE PRESENT IN crossChainCurrenc*
// ALL DERIVATIVE ADJUSTMENTS WILL BE CALCULATED
//
// Function emits unfunded transactions and information for all chains as follows:
//      All direct address reductions of primary or derivative reduced currencies
//      All currency basket reductions, using unfunded burns or unfunded reserve transfer refunds for all chains
//          this data should be emitted the same across all chains and can be compared. Only one set of these transactions
//          should ever be prepared and entered, even though one set for each chain will be emitted from each chain
//      All reimbursement transactions for all addresses holding any affected baskets on all chains for the direct and
//          indirect reductions that originated on this chain. Each chain will produce a unique list of these transactions.
//      All addresses and an effective lost ETH and TBTC value, both direct and indirect, that is eligible for
//          Verus usage/restitution currency, which will be quantified by an amount both in vETH and tBTC.vETH.
//
//
UniValue CBlockTreeDB::GenerateAdjustmentTransactions(const CCurrencyValueMap &currencyAdjustments,
                                                      const std::map<uint160,CCurrencyDefinition> &crossChainCurrencies,
                                                      const std::map<uint160,CCoinbaseCurrencyState> &crossChainCurrencyStates,
                                                      const std::map<uint160,CTxDestination> &_adjustingDestinations,
                                                      const std::map<uint160,uint32_t> &expiryForAllChains,
                                                      const std::vector<CMutableTransaction> &unfundedTransactionsFromOtherChains,
                                                      const std::vector<CMutableTransaction> &fundedTransactionsForSigning,
                                                      bool sendFullySignedTransactions)
{
    boost::scoped_ptr<CDBIterator> iter(NewIterator());

    bool debugExit = false;

    int utxosProcessed = 0;
    int utxosSpent = 0;
    int reserveOutputsSpent = 0;
    int marketOffersSpent = 0;
    int reserveTransfersSpent = 0;
    int utxosOutput = 0;
    int utxosNeeded = 0;

    std::map<uint160, std::map<uint160, CCurrencyValueMap>> allChainCurrencyAdjustments;
    std::map<uint160, std::map<uint160, CCurrencyValueMap>> allChainCurrencyReimbursements;

    std::map<uint160,CTxDestination> adjustingDestinations = _adjustingDestinations;

    // all transactions made for all chains, including the fees in native currency needed
    std::multimap<uint160,std::pair<CMutableTransaction,CCurrencyValueMap>> transactionsAndFeesNeeded;

    if (!expiryForAllChains.count(ASSETCHAINS_CHAINID) || expiryForAllChains.size() < 4)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction expiration height for all chains must be represented in an adjustment operation");
    }

    // first loop through all defined currencies, and using either those provided or those found on chain,
    // determine all derivatives of the currencies and put them, along with any expected reductions of
    // currencies in them into currenciesByAdjustment and a 1 value to get intersections in allCurrenciesToAdjust

    // first get currencies on this chain, then get currencies on external chains
    std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> chains;

    UniValue result(UniValue::VOBJ);
    UniValue errors(UniValue::VARR);

    std::map<CTxDestination, UniValue> adjustmentsByAddress;                            // all adjustment transactions for address, reimbursements for all chains
    std::map<std::pair<uint160, uint160>, UniValue> bridgeReserveAdjustmentsByChain;    // from chain, to chain, bridge reserve adjustments & transactions
    std::map<std::pair<uint160, uint160>, UniValue> currencyAdjustmentsByChain;         // chain, currency, adjustments and transactions
    std::map<uint160, UniValue> transactionsUni;
    std::map<uint160, UniValue> comparisonTransactionsUni;

    UniValue otherChainOutputsNeededUni(UniValue::VARR);

    CCurrencyValueMap totalReductionsThisChain;

    if (!currencyAdjustments.valueMap.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Valid set of adjustments required");
    }

    result.pushKV("start_time", DateTimeStrFormat("%d.%m.%Y,%H:%M:%S %z", (int64_t)GetTime()));

    std::set<uint160> converters;
    GetCurrencyDefinitions(ASSETCHAINS_CHAINID,
                           chains,
                           CCurrencyDefinition::EQueryOptions::QUERY_LAUNCHSTATE_CONFIRM,
                           CCurrencyDefinition::EQueryOptions::QUERY_SYSTEMTYPE_LOCAL,
                           converters);

    GetCurrencyDefinitions(ASSETCHAINS_CHAINID,
                           chains,
                           CCurrencyDefinition::EQueryOptions::QUERY_NULL,
                           CCurrencyDefinition::EQueryOptions::QUERY_SYSTEMTYPE_IMPORTED,
                           converters);

    std::map<uint160, std::pair<CCurrencyDefinition, CCoinbaseCurrencyState>> allCurrencies;
    for (auto &oneCurrency : crossChainCurrencies)
    {
        auto it = crossChainCurrencyStates.find(oneCurrency.first);
        allCurrencies.insert({oneCurrency.first, {oneCurrency.second, it == crossChainCurrencyStates.end() ? CCoinbaseCurrencyState() : it->second}});
    }
    // add all currencies we retrieved as well

    // find all currencies with either the original currencies or derivatives
    for (auto &oneCurrency : chains)
    {
        CCoinbaseCurrencyState currencyState;
        CCurrencyValueMap adjustments;

        if (!oneCurrency.second.IsFractional())
        {
            adjustments.valueMap[oneCurrency.second.GetID()] = currencyAdjustments.valueMap.find(oneCurrency.second.GetID())->second;
        }
        else if (oneCurrency.second.systemID == ASSETCHAINS_CHAINID &&
                 (!crossChainCurrencies.count(oneCurrency.second.GetID()) || !crossChainCurrencyStates.count(oneCurrency.second.GetID())))
        {
            UniValue params(UniValue::VARR);
            params.push_back(EncodeDestination(CIdentityID(oneCurrency.second.GetID())));
            currencyState = CCoinbaseCurrencyState(find_value(getcurrencystate(params, false), "currencystate"));

            if (!currencyState.IsValid())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to get currency state for: " + uni_get_str(params[0]));
            }
            if (!currencyState.IsLaunchConfirmed())
            {
                continue;
            }
        }

        // we add all fractionals with more than one currency and matching non-fractionals in the adjustment set
        // unless already present
        if (!(allCurrencies.count(oneCurrency.second.GetID()) || (!allCurrencies[oneCurrency.second.GetID()].second.IsValid()) && currencyState.IsValid()) &&
            ((oneCurrency.second.IsFractional() && oneCurrency.second.currencies.size() > 1) || adjustments.valueMap.size()))
        {
            allCurrencies[oneCurrency.second.GetID()] = {oneCurrency.second, currencyState};
        }
    }

    if (debugExit)
    {
        UniValue allCurrenciesUni(UniValue::VARR);
        UniValue allCurrencyStatesUni(UniValue::VARR);
        for (auto &oneCurrency : allCurrencies)
        {
            allCurrenciesUni.push_back(oneCurrency.second.first.ToUniValue());
            if (oneCurrency.second.second.IsValid())
            {
                allCurrencyStatesUni.push_back(oneCurrency.second.second.ToUniValue());
            }
        }
        result.pushKV("allcurrencies", allCurrenciesUni);
        result.pushKV("allcurrencyStates", allCurrencyStatesUni);
        return result;
    }

    // we have all currencies we'll get.
    // if we have all relevant currencies here from all chains, we can trace all reduced currencies by depth
    // and enter any here by reserves.

    // This map contains every currency, including derivatives that need adjusting
    // each currency in the value map may include either an amount to reduce, or an
    // amount to add to increase due to disgorgement from a basket. For this reason,
    // the amounts in this map are signed. negative will be reduced and positive
    // will be an additive adjustment, meaning that transactions will need to be
    // made spending the appropriate source of that currency on the appropriate
    // chain to the required output.
    std::map<uint160, CCurrencyValueMap> currenciesByAdjustment;
    CCurrencyValueMap allCurrenciesToAdjust;

    // go through allCurrencies, which now contains both the specific non-fractional currencies needing adjustment,
    // and all fractionals that may or may not be affected. for each currency, we need to recurse into its reserves
    // if there is any overlap with the reduced currencies, even recursively, all adjustments, including disgorgement
    // are calculated, and the currency, along with a value map of those positive or negative adjustments is put
    // into currenciesByAdjustment
    for (auto oneCurrency : allCurrencies)
    {
        if (oneCurrency.second.first.IsFractional())
        {
            std::vector<std::pair<uint160, std::pair<CCurrencyDefinition, CCoinbaseCurrencyState>>> currencyStack;
            std::vector<int> countStack;
            std::vector<CCurrencyValueMap> adjustmentStack;

            currencyStack.push_back(oneCurrency);
            countStack.push_back(0);
            adjustmentStack.push_back(CCurrencyValueMap());

            // this loop counts past the max allowable index of the currency for a reason
            // in the first lines of the loop, it checks for the end and cleans up any potential
            // recursion, which will happen for each level of recursion
            for (;
                 countStack.back() <= (currencyStack.back().second.first.IsFractional() ? currencyStack.back().second.first.currencies.size() : 1);
                 countStack.back()++)
            {
                if (countStack.back() == (currencyStack.back().second.first.IsFractional() ? currencyStack.back().second.first.currencies.size() : 1))
                {
                    // we have come all the way back. the last item will be left on the adjustment stack and it is our job to
                    // integrate it if we are recursing, then leave it on the stack
                    int64_t largestAdjustment = 0;
                    CCurrencyValueMap lastAdjustment = adjustmentStack.back();
                    auto lastCurrency = currencyStack.back();

                    // we have finished one level of a loop through all of a fractional currencies reserves,
                    // pop recursion stacks and leave update adjustmentStack with both reduction and disgorgement
                    countStack.pop_back();
                    adjustmentStack.pop_back();
                    currencyStack.pop_back();

                    // first, determine maximum adjustment of any currency in the map, since we are looking for negative adjustments
                    // get minimum
                    for (auto &oneAdj : lastAdjustment.valueMap)
                    {
                        largestAdjustment = std::max(largestAdjustment, oneAdj.second);
                    }

                    if (largestAdjustment != 0)
                    {
                        // we remove equivalent of the largest amount from this currency's supply
                        // and add disgorgement adjustments, reductions should be retrieved by allCurrenciesToAdjust
                        lastAdjustment.valueMap[lastCurrency.first] = largestAdjustment;
                        currenciesByAdjustment.insert({lastCurrency.first, lastAdjustment});
                        allCurrenciesToAdjust.valueMap[lastCurrency.first] = largestAdjustment;
                    }

                    // if we are recursing and have a reduction value for this currency, return it
                    if (!adjustmentStack.empty() && largestAdjustment != 0)
                    {
                        // for recursion caller's reserves, this currency is removed by largestAdjustment
                        adjustmentStack.back().valueMap[lastCurrency.first] = largestAdjustment;
                    }

                    if (countStack.empty())
                    {
                        break;
                    }
                    else
                    {
                        continue;
                    }
                }

                // if it's not fractional, it's easier
                if (!currencyStack.back().second.first.IsFractional())
                {
                    if (currencyAdjustments.valueMap.count(currencyStack.back().first))
                    {
                        adjustmentStack.back().valueMap[currencyStack.back().first] = currencyAdjustments.valueMap.find(currencyStack.back().first)->second;
                        currenciesByAdjustment[currencyStack.back().first] =
                            CCurrencyValueMap({currencyStack.back().first},{currencyAdjustments.valueMap.find(currencyStack.back().first)->second});
                        allCurrenciesToAdjust.valueMap[currencyStack.back().first] = currencyAdjustments.valueMap.find(currencyStack.back().first)->second;
                    }
                    continue;
                }
                else
                {
                    // fractional
                    auto curIt = allCurrencies.find(currencyStack.back().second.first.currencies[countStack.back()]);
                    if (curIt != allCurrencies.end())
                    {
                        auto adjCurIt = currenciesByAdjustment.find(curIt->first);
                        if (adjCurIt != currenciesByAdjustment.end())
                        {
                            // we already have the answer. just clean up recursion
                            currencyStack.push_back(*curIt);
                            countStack.push_back((currencyStack.back().second.first.IsFractional() ? currencyStack.back().second.first.currencies.size() - 1 : 0));
                            adjustmentStack.push_back(adjCurIt->second);
                        }
                        else
                        {
                            // recurse, get results, and move to the next in this currency
                            // results of each currency are stored before loop exit
                            currencyStack.push_back(*curIt);
                            countStack.push_back(-1);
                            adjustmentStack.push_back(CCurrencyValueMap());
                        }
                        continue;
                    }
                    else
                    {
                        errors.push_back(std::string("Missing currency definition: ") + EncodeDestination(CIdentityID(currencyStack.back().second.first.currencies[countStack.back()])));
                    }
                }
            }
        }
        else
        {
            auto it = currencyAdjustments.valueMap.find(oneCurrency.first);
            if (it != currencyAdjustments.valueMap.end())
            {
                currenciesByAdjustment[oneCurrency.first] = CCurrencyValueMap({oneCurrency.first},{it->second});
                allCurrenciesToAdjust.valueMap[oneCurrency.first] = it->second;
            }
        }
    }

    UniValue allCurrenciesUni(UniValue::VOBJ);
    for (auto &oneCur : allCurrencies)
    {
        allCurrenciesUni.pushKV(EncodeDestination(CIdentityID(oneCur.first)), oneCur.second.first.name);
    }
    result.pushKV("allcurrencies", allCurrenciesUni);
    result.pushKV("allcurrenciestoadjust", allCurrenciesToAdjust.ToUniValue());

    UniValue currenciesByAdjustmentUni(UniValue::VOBJ);
    for (auto &oneCur : currenciesByAdjustment)
    {
        currenciesByAdjustmentUni.pushKV(EncodeDestination(CIdentityID(oneCur.first)), oneCur.second.ToUniValue());
    }
    result.pushKV("currenciesbyadjustment", currenciesByAdjustmentUni);
    if (debugExit)
    {
        return result;
    }

    // now, all currencies implicated in any adjustment, either negative or positive due to disgorgement
    // are stored in currenciesByAdjustment along with their direct reductions and contained currency
    // disbursement percentages, which are used for each UTXO that contains any affected currency when
    // processing. a UTXO share of any disbursement will first get prorated by the reserve percentage if
    // from a nested fractional, then by the ratio of the amount of original fractional from the total
    // amount lost in the affected currency.

    // disbursements are handled as special case reserve transfers that are only allowed during a specific
    // window and from the adjustment ID on chain. they refund from the currency basket, but do not
    // require a deposit first, and they subtract from the reserve in the basket. Currencies with
    // disgorgement may also be reduced by any amount required as well, which would be the difference
    // between disgorgement and the reduction percentage.

    std::map<CTxDestination,std::map<uint160,CAmount>> aggregateReimbursableOutputs;
    std::map<CTxDestination,std::pair<std::vector<std::tuple<CUTXORef,CScript,CAmount>>, CCurrencyValueMap>> aggregateAddressReduction;
    CAmount aggregateAddressNative = 0;

    CCurrencyValueMap allUTXOTotalCurrency;
    CCurrencyValueMap spendableUTXOTotalCurrency;
    CCurrencyValueMap reserveDepositUTXOTotalCurrency;
    CCurrencyValueMap reserveDepositOffChainTotalCurrency;
    std::map<uint160,CCurrencyValueMap> reserveDepositCurrencyBreakdown;
    std::set<CUTXORef> utxosRead;

    // adjustment transactions relate to PBaaS currencies
    int64_t startingHeight = CConstVerusSolutionVector::activationHeight.GetVersionActivationHeight(CActivationHeight::ACTIVATE_PBAAS);

    if (startingHeight > chainActive.Height())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "PBaaS not yet active or not in sync");
    }

    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    size_t sizeOfUnspentValue = GetSerializeSize(ss, CAddressUnspentValue());
    for (iter->SeekToLast(); iter->Valid(); iter->Prev())
    {
        boost::this_thread::interruption_point();
        try
        {
            if (iter->GetValueSize() < sizeOfUnspentValue)
            {
                continue;
            }
            pair<char, CAddressIndexIteratorKey> keyObj;
            iter->GetKey(keyObj);

            char chType = keyObj.first;
            CAddressIndexIteratorKey indexKey = keyObj.second;

            // if this is a UTXO
            if (chType == DB_ADDRESSUNSPENTINDEX)
            {
                pair<char, CAddressUnspentKey> keyPair;
                CAddressUnspentDbEntry currentEntry;
                iter->GetValue(currentEntry.second);

                if (currentEntry.second.blockHeight < startingHeight)
                {
                    continue;
                }
                iter->GetKey(keyPair);
                currentEntry.first = keyPair.second;

                // determine what type of an output it is. currently only support
                // smart transaction outputs, not P2PKH or P2SH types of outputs, as only
                // tokens can be adjusted. the following is supported:
                // EVAL_RESERVE_OUTPUT
                // EVAL_RESERVE_DEPOSIT
                // EVAL_RESERVE_TRANSFER
                // EVAL_IDENTITY_COMMITMENT

                // outputs that can only have native or Verus are not adjusted
                COptCCParams p;
                CCurrencyValueMap cMap;
                CCurrencyValueMap newMap;

                cMap = currentEntry.second.script.ReserveOutValue(p);
                if (!p.IsValid() || !p.vKeys.size() || !p.vData.size())
                {
                    continue;
                }

                CUTXORef thisUTXO = CUTXORef(currentEntry.first.txhash, currentEntry.first.index);
                if (utxosRead.count(thisUTXO))
                {
                    continue;
                }
                utxosRead.insert(thisUTXO);

                newMap = cMap.IntersectingValues(allCurrenciesToAdjust);

                allUTXOTotalCurrency += cMap;
                allUTXOTotalCurrency.valueMap[ASSETCHAINS_CHAINID] += currentEntry.second.satoshis;

                // newMap holds all currencies that will be affected
                // cMap holds all currencies not affected in this UTXO,

                // ensure that only valid smart transactions with directly or indirectly affected currencies enter
                if (newMap.valueMap.size())
                {
                    utxosProcessed++;

                    // one or more of multiple types of UTXOs may be generated for each UTXO output with affected currencies
                    // for all but reserve deposits, the UTXO is spent and replaced by a reserve output to the same address
                    // minus the reduced currencies

                    // also, for all but reserve deposits, any disgorgement transactions for any directly held or nested basket
                    // currencies need to be generated on the chain that processes the specific basket currency that will
                    // disburse
                    //
                    // if that is on a different chain, there is a decision to make about whether disbursements should be
                    // automatically sent back to the this chain from other chains or not by using reserve transfers

                    CUTXORef utxo(currentEntry.first.txhash, currentEntry.first.index);
                    std::map<uint160, CCurrencyValueMap> reimbursements;
                    CCommitmentHash ch;

                    switch (p.evalCode)
                    {
                        case EVAL_RESERVE_TRANSFER:
                        {
                            aggregateAddressNative = currentEntry.second.satoshis;
                            spendableUTXOTotalCurrency.valueMap[ASSETCHAINS_CHAINID] += aggregateAddressNative;
                            spendableUTXOTotalCurrency += cMap;

                            // we need to spend the reserve transfer to the refund address or worst case, the recipient with adjustment
                            // check for disbursements if fractional
                            CReserveTransfer rt(p.vData[0]);
                            CTxDestination newDestination;
                            if (rt.destination.AuxDestCount() > 0)
                            {
                                newDestination = TransferDestinationToDestination(rt.destination.GetAuxDest(0));
                            }
                            if (newDestination.which() == COptCCParams::ADDRTYPE_INVALID)
                            {
                                newDestination = TransferDestinationToDestination(rt.destination, CCurrencyDefinition::EProofProtocol::PROOF_PBAASMMR);
                            }
                            if (newDestination.which() == COptCCParams::ADDRTYPE_INVALID)
                            {
                                errors.push_back(std::string("No destination address found for UTXO: ") + utxo.ToString());
                                newDestination = adjustingDestinations[ASSETCHAINS_CHAINID];
                            }

                            // add the total amount of currencies subject to reduction in this address, along with UTXO
                            // that has those currencies
                            aggregateAddressReduction[newDestination].first.push_back({utxo,currentEntry.second.script,currentEntry.second.satoshis});
                            aggregateAddressReduction[newDestination].second += cMap;

                            // create a transaction that spends the current UTXO reserve output
                            // to a reserve output with the adjust by reduction currencies and determined destination
                            for (auto &oneCur : newMap.valueMap)
                            {
                                auto curIt = currenciesByAdjustment.find(oneCur.first);
                                if (curIt != currenciesByAdjustment.end())
                                {
                                    // determine how much this currency should be reduced in the output
                                    if (curIt->second.valueMap[oneCur.first] < 0)
                                    {
                                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Attempting to increase currency output without funds");
                                    }
                                    else if (curIt->second.valueMap[oneCur.first] > 0)
                                    {
                                        if (!allCurrencies[oneCur.first].first.IsFractional())
                                        {
                                            continue;
                                        }
                                        aggregateReimbursableOutputs[newDestination][oneCur.first] += oneCur.second;
                                    }
                                }
                            }
                            break;
                        }

                        case EVAL_IDENTITY_COMMITMENT:
                        {
                            ch = CCommitmentHash(p.vData[0]);
                        }

                        case EVAL_RESERVE_OUTPUT:
                        {
                            aggregateAddressNative = currentEntry.second.satoshis;
                            spendableUTXOTotalCurrency.valueMap[ASSETCHAINS_CHAINID] += aggregateAddressNative;
                            spendableUTXOTotalCurrency += cMap;

                            // we treat identity commitments, which are almost certainly marketplace transaction, as normal outputs,
                            // which will have the effect of canceling the order automatically. at the same time,
                            // TODO: confirm this is true. it seems that a marketplace transaction may also be an indexed ID output
                            // so determine that structure and adjust this equivalence as needed
                            //
                            // Common to both reserve outputs and marketplace transactions:
                            //   send to a reserve output
                            //   store in aggregate for later check for disbursements if fractional
                            CTokenOutput to;

                            if (p.evalCode == EVAL_RESERVE_OUTPUT)
                            {
                                to = CTokenOutput(p.vData[0]);
                            }
                            else
                            {
                                to = ch;
                            }

                            if (p.vKeys.size() > 1)
                            {
                                errors.push_back(std::string("UTXO has more than one destination: ") + utxo.ToString());
                            }
                            aggregateAddressReduction[p.vKeys[0]].first.push_back({utxo,currentEntry.second.script,currentEntry.second.satoshis});
                            aggregateAddressReduction[p.vKeys[0]].second += cMap;

                            // account for both reducing and reimbursable values before creating transactions
                            for (auto &oneCur : newMap.valueMap)
                            {
                                auto curIt = currenciesByAdjustment.find(oneCur.first);
                                if (curIt != currenciesByAdjustment.end())
                                {
                                    // determine how much this currency should be reduced in the output
                                    if (curIt->second.valueMap[oneCur.first] < 0)
                                    {
                                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Attempting to increase currency output without funds");
                                    }
                                    else if (curIt->second.valueMap[oneCur.first] > 0)
                                    {
                                        if (!allCurrencies[oneCur.first].first.IsFractional())
                                        {
                                            continue;
                                        }
                                        aggregateReimbursableOutputs[p.vKeys[0]][oneCur.first] += oneCur.second;
                                    }
                                }
                            }
                            break;
                        }
                        case EVAL_RESERVE_DEPOSIT:
                        {
                            CReserveDeposit rd = p.vData[0];
                            reserveDepositUTXOTotalCurrency += cMap;
                            reserveDepositUTXOTotalCurrency.valueMap[ASSETCHAINS_CHAINID] += currentEntry.second.satoshis;
                            reserveDepositCurrencyBreakdown[rd.controllingCurrencyID] += cMap;
                            reserveDepositCurrencyBreakdown[rd.controllingCurrencyID].valueMap[ASSETCHAINS_CHAINID] += currentEntry.second.satoshis;
                            if (adjustingDestinations.count(rd.controllingCurrencyID) && rd.controllingCurrencyID != ASSETCHAINS_CHAINID)
                            {
                                reserveDepositOffChainTotalCurrency += cMap;
                                reserveDepositOffChainTotalCurrency.valueMap[ASSETCHAINS_CHAINID] += currentEntry.second.satoshis;
                            }
                            break;
                        }
                    }
                }
	        }
        } catch (const std::exception& e) {
            throw JSONRPCError(RPC_DATABASE_ERROR, "Database exception");
        }
    }

    UniValue utxoTotals(UniValue::VOBJ);
    utxoTotals.pushKV("totalutxocurrencies", allUTXOTotalCurrency.ToUniValue());
    utxoTotals.pushKV("spendableutxocurrencies", spendableUTXOTotalCurrency.ToUniValue());
    utxoTotals.pushKV("reservedepositutxocurrencies", reserveDepositUTXOTotalCurrency.ToUniValue());
    utxoTotals.pushKV("offchaincurrencies", reserveDepositOffChainTotalCurrency.ToUniValue());
    UniValue reserveDepositBreakdownsUni(UniValue::VOBJ);
    for (auto &oneCur : reserveDepositCurrencyBreakdown)
    {
        reserveDepositBreakdownsUni.pushKV(EncodeDestination(CIdentityID(oneCur.first)), oneCur.second.ToUniValue());
    }
    utxoTotals.pushKV("reservedepositbreakdown", reserveDepositBreakdownsUni);
    UniValue totalByAddress(UniValue::VARR);
    for (const auto &oneReductionAddress : aggregateAddressReduction)
    {
        UniValue oneAddrReserves(UniValue::VOBJ);
        oneAddrReserves.pushKV(EncodeDestination(oneReductionAddress.first),oneReductionAddress.second.second.ToUniValue());
        totalByAddress.push_back(oneAddrReserves);
    }
    utxoTotals.pushKV("totalnonnativebyaddress",totalByAddress);
    result.pushKV("utxototalvalues", utxoTotals);

    if (debugExit)
    {
        result.pushKV("errors",errors);
        return result;
    }

    static const int MAX_UTXOS_PER_TX = 500;

    // now, loop through the addresses and make UTXOs to adjust values in each one at a time. if the UTXOs for an address exceed
    // MAX_UTXOS_PER_TX, we will break them into even groups and adjust each separately. this prevents any significant error due
    // to truncation of the result to 8 decimal places

    std::map<int,int> evalCodePriority({{EVAL_RESERVE_OUTPUT,0}, {EVAL_RESERVE_TRANSFER,1}, {EVAL_IDENTITY_COMMITMENT,2}, {EVAL_RESERVE_DEPOSIT,3}});

    static const CAmount tBTCRestitutionConversionRate = 3666659260;
    std::map<CTxDestination, std::pair<CCurrencyValueMap,CCurrencyValueMap>> thisChainAddressRestitutionCredit;

    // first go through addresses of all UTXOs needing reduction and create the spends and outputs to do so
    // if we can spend fewer than all of the UTXOs to reduce the total of all affected currencies for an address, we do so
    for (const auto &oneReductionAddress : aggregateAddressReduction)
    {
        // put all transactions in order of affected currency and size (smallest first)
        // get totals of each currency and final output amount
        // make fewest transactions necessary to burn enough to equal total reduction of
        // specific currency.
        //
        // For every UTXO, regardless of how we got it (eg. from another currencies smallest > largest), do the math to determine
        // how spending it affects all currencies under the control of the address being processed
        //
        CCurrencyValueMap oneAddressReductionsLeft;
        CCurrencyValueMap currenciesToAdjustForAddress = oneReductionAddress.second.second.IntersectingValues(allCurrenciesToAdjust).CanonicalMap();

        // go through all UTXOs for this address and calculate how much of each currency needs to be reduced
        // we calculate using the remainder after subtracting the percentage from 1, to ensure truncation on the
        // amount left, vs rounding up to potentially a satoshi more than what exists
        for (auto &oneCur : currenciesToAdjustForAddress.valueMap)
        {
            oneAddressReductionsLeft.valueMap[oneCur.first] = oneCur.second -
                CCurrencyState::NativeToReserveRaw(oneCur.second, SATOSHIDEN - allCurrenciesToAdjust.valueMap[oneCur.first]);
        }

        // now, go through UTXOs and order them in two groups:
        // 1) multimap by type, currency, and size in each currency
        // 2) map by UTXO ID
        //
        std::multimap<std::tuple<uint160,int,int64_t>,CUTXORef> UTXOEfficiencyIndex;
        std::map<CUTXORef,std::tuple<CScript, CCurrencyValueMap, CAmount>> UTXODirectIndex;

        for (auto &oneUTXO : oneReductionAddress.second.first)
        {
            // CUTXORef &utxoRef = std::get<0>(oneUTXO);
            // CScript &script = std::get<1>(oneUTXO);
            // CAmount amount = std::get<2>(oneUTXO);

            COptCCParams p;
            CCurrencyValueMap cMap = std::get<1>(oneUTXO).ReserveOutValue(p);
            if (!p.IsValid())
            {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Invalid UTXO data");
            }
            CTokenOutput to;
            CReserveTransfer rt;
            CReserveDeposit rd;
            CCommitmentHash ch;
            switch (p.evalCode)
            {
                case EVAL_RESERVE_TRANSFER:
                {
                    rt = CReserveTransfer(p.vData[0]);
                    to = rt;
                    to.reserveValues = cMap;
                    break;
                }
                case EVAL_RESERVE_OUTPUT:
                {
                    to = CTokenOutput(p.vData[0]);
                    break;
                }
                case EVAL_IDENTITY_COMMITMENT:
                {
                    ch = CCommitmentHash(p.vData[0]);
                    to = ch;
                    break;
                }
            }

            if (!to.IsValid())
            {
                continue;
            }
            CCurrencyValueMap affectedThisUTXO = to.reserveValues.IntersectingValues(currenciesToAdjustForAddress).CanonicalMap();
            UTXODirectIndex.insert({std::get<0>(oneUTXO), {std::get<1>(oneUTXO), to.reserveValues, std::get<2>(oneUTXO)}});
            for (auto &oneCur : affectedThisUTXO.valueMap)
            {
                UTXOEfficiencyIndex.insert({{oneCur.first, evalCodePriority[p.evalCode], std::get<2>(oneUTXO)}, std::get<0>(oneUTXO)});
            }
        }

        thisChainAddressRestitutionCredit[oneReductionAddress.first].first += oneAddressReductionsLeft.IntersectingValues(currencyAdjustments);
        thisChainAddressRestitutionCredit[oneReductionAddress.first].second = thisChainAddressRestitutionCredit[oneReductionAddress.first].first;

        UniValue oneAddrReduction(UniValue::VOBJ);
        UniValue oneDirectReduction(UniValue::VOBJ);
        oneAddrReduction.pushKV("intersectingreserves",oneReductionAddress.second.second.ToUniValue());
        oneAddrReduction.pushKV("intersectingnative",aggregateAddressNative);
        oneAddrReduction.pushKV("totalreduction",oneAddressReductionsLeft.ToUniValue());
        oneAddrReduction.pushKV("directrestitutioncredit", thisChainAddressRestitutionCredit[oneReductionAddress.first].first.ToUniValue());
        oneDirectReduction.pushKV("totaldirectreduction", oneAddrReduction);
        adjustmentsByAddress.insert({oneReductionAddress.first, oneDirectReduction});

        totalReductionsThisChain += oneAddressReductionsLeft;

        // loop through by currency until we get to zero on that currency, all currencies are calculated for each UTXO, and oneAddressReductionsLeft
        // is reduced for all currencies to zero during the process, ensuring that if one currency's adjustment is depleted while looking at another
        // that's fine
        while (oneAddressReductionsLeft.CanonicalMap().valueMap.size())
        {
            CCurrencyValueMap checkTotal;
            CCurrencyValueMap totalOutput;
            CCurrencyValueMap totalReduction;
            CAmount totalNativeOut = 0;
            int utxosThisTransaction = 0;

            // loop through each remaining currency
            // spend UTXOs, first by preferred type, then by smallest to largest for this currency,
            // after completing one currency, move to start the next that remains

            if (debugExit)
            {
                UniValue reductions(UniValue::VARR);
                for (auto &oneReduction : adjustmentsByAddress)
                {
                    reductions.push_back(oneReduction.second);
                }
                result.pushKV("directreductionsbyaddress", reductions);
                result.pushKV("reductiontransactions", transactionsUni[ASSETCHAINS_CHAINID]);
                result.pushKV("errors",errors);
                return result;
            }

            uint160 currentCurrency = oneAddressReductionsLeft.valueMap.begin()->first;
            auto startIter = UTXOEfficiencyIndex.lower_bound({currentCurrency, 0, 0});
            auto endIter = UTXOEfficiencyIndex.upper_bound({currentCurrency, INT_MAX, INT64_MAX});
            std::vector<std::tuple<CUTXORef, CScript, CAmount>> txInputs;

            for (; startIter != endIter; startIter++)
            {
                auto thisElement = *startIter;

                std::map<CUTXORef, std::tuple<CScript, CCurrencyValueMap, CAmount>>::iterator utxoIt = UTXODirectIndex.find(startIter->second);
                if (utxoIt == UTXODirectIndex.end())
                {
                    continue;
                }

                auto thisUTXOElement = *utxoIt;

                checkTotal += std::get<1>(utxoIt->second);

                CCurrencyValueMap reduceBy = std::get<1>(utxoIt->second).IntersectingValues(oneAddressReductionsLeft).CanonicalMap();
                if (!reduceBy.valueMap.size())
                {
                    continue;
                }

                oneAddressReductionsLeft = (oneAddressReductionsLeft - reduceBy).CanonicalMap();

                // if we overshot on any currency, adjust
                if (oneAddressReductionsLeft.HasNegative())
                {
                    // find negative values, adjust our reduction, and remove currency
                    for (auto &oneReduct : oneAddressReductionsLeft.valueMap)
                    {
                        if (oneReduct.second < 0)
                        {
                            reduceBy.valueMap[oneReduct.first] = reduceBy.valueMap[oneReduct.first] + oneReduct.second;
                            oneReduct.second = 0;
                        }
                    }
                    oneAddressReductionsLeft = oneAddressReductionsLeft.CanonicalMap();
                }

                totalOutput += (std::get<1>(utxoIt->second) - reduceBy).CanonicalMap();
                totalReduction += reduceBy;
                totalNativeOut += std::get<2>(utxoIt->second);
                txInputs.push_back({utxoIt->first, std::get<0>(utxoIt->second), std::get<2>(utxoIt->second)});
                UTXODirectIndex.erase(utxoIt);
                utxosSpent++;
                if (std::get<1>(thisElement.first) == 0)
                {
                    reserveOutputsSpent++;
                }
                else if (std::get<1>(thisElement.first) == 1)
                {
                    reserveTransfersSpent++;
                }
                else if (std::get<1>(thisElement.first) == 2)
                {
                    marketOffersSpent++;
                }
                utxosThisTransaction++;

                // if we hit one of our two limits or we completed current currency, make an output and move on
                // otherwise, continue
                if (!oneAddressReductionsLeft.valueMap.count(currentCurrency) || utxosThisTransaction >= MAX_UTXOS_PER_TX)
                {
                    break;
                }
            }

            // make a transaction spending all utxos in txInputs, and output the totalOutput to a UTXO
            // fee input will need to be funded before entry, since no funds are reduced for fee
            if (txInputs.size())
            {
                CMutableTransaction oneReductionTx =
                    CreateNewContextualCMutableTransaction(Params().consensus, expiryForAllChains.find(ASSETCHAINS_CHAINID)->second - DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA);

                for (auto &oneInput : txInputs)
                {
                    oneReductionTx.vin.push_back(CTxIn(std::get<0>(oneInput)));
                }
                CTokenOutput to(totalOutput);
                oneReductionTx.vout.push_back(CTxOut(totalNativeOut, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT,
                                                                            std::vector<CTxDestination>({oneReductionAddress.first}),
                                                                            1,
                                                                            &to))));
                utxosOutput++;

                transactionsAndFeesNeeded.insert({ASSETCHAINS_CHAINID, {oneReductionTx, CCurrencyValueMap()}});

                // we now have one transaction that is burning the necessary amount for these inputs, output and continue
                UniValue txOutput(UniValue::VOBJ);

                txOutput.pushKV("reservesin", checkTotal.ToUniValue());
                txOutput.pushKV("reducedby", totalReduction.ToUniValue());
                txOutput.pushKV("reserveout", totalOutput.ToUniValue());
                txOutput.pushKV("nativeinout",totalNativeOut);
                txOutput.pushKV("txchain",EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)));
                if (!transactionsUni.count(ASSETCHAINS_CHAINID))
                {
                    transactionsUni[ASSETCHAINS_CHAINID] = UniValue(UniValue::VARR);
                }
                txOutput.pushKV("txnumber", (int64_t)transactionsUni[ASSETCHAINS_CHAINID].size());
                adjustmentsByAddress[oneReductionAddress.first].pushKV(std::string("tx_") + std::to_string(transactionsUni[ASSETCHAINS_CHAINID].size()), txOutput);
                transactionsUni[ASSETCHAINS_CHAINID].push_back(EncodeHexTx(oneReductionTx));
            }
        }
    }

    UniValue reductionsUni(UniValue::VARR);
    result.pushKV("totaldirectreductionsforchain", totalReductionsThisChain.ToUniValue());
    result.pushKV("utxosspent", utxosSpent);
    result.pushKV("reserveoutputsspent", reserveOutputsSpent);
    result.pushKV("reservetransfersspent", reserveTransfersSpent);
    result.pushKV("marketoffersspent", marketOffersSpent);
    result.pushKV("utxoscreated", utxosOutput);
    result.pushKV("transactionscreated", (int64_t)transactionsUni.size());

    if (debugExit)
    {
        UniValue adjustmentsByAddressUni(UniValue::VARR);
        for (auto &oneAddress : adjustmentsByAddress)
        {
            oneAddress.second.pushKV("totalrestitutioncredit", thisChainAddressRestitutionCredit[oneAddress.first].second.ToUniValue());
            adjustmentsByAddressUni.push_back(oneAddress.second);
        }
        result.pushKV("adjustmentsbyaddress", adjustmentsByAddressUni);
        result.pushKV("errors",errors);
        return result;
    }

    // now, go through all bridges to PBaaS chains and reduce the balance of the affected currencies in the bridge
    // in order to do so, a transaction will be made to release the amount to burn directly from the bridge to the
    // adjustment ID for Verus, since right now, all adjustment currencies are on Verus. If adjustment currencies
    // were on other chains, the transactions would need to be sent to that chain from the chain holding it in order
    // to release it from the bridge deposits.

    std::vector<std::pair<std::pair<CUTXORef, std::vector<CNodeData>>, CCurrencyDefinition>> pbaasChains;
    GetCurrencyDefinitions(ASSETCHAINS_CHAINID,
                           pbaasChains,
                           CCurrencyDefinition::EQueryOptions::QUERY_NULL,
                           CCurrencyDefinition::EQueryOptions::QUERY_SYSTEMTYPE_PBAAS,
                           converters);

    std::map<uint160, std::pair<CCurrencyValueMap,CMutableTransaction>> bridgeReductionTxes;
    UniValue bridgeReductionOutputUni(UniValue::VARR);

    for (auto &oneChain : pbaasChains)
    {
        // determine the reserve deposits held by the bridges
        if (oneChain.second.GetID() == ASSETCHAINS_CHAINID)
        {
            continue;
        }
        UniValue params(UniValue::VARR);
        params.push_back(EncodeDestination(CIdentityID(oneChain.second.GetID())));
        CCurrencyValueMap oneChainDeposits(getreservedeposits(params, false));
        CCurrencyValueMap oneChainAdjustments = allCurrenciesToAdjust.IntersectingValues(oneChainDeposits);
        CCurrencyValueMap oneChainResults = oneChainDeposits;

        for (auto &oneCurReduction : oneChainAdjustments.valueMap)
        {
            // create a transaction for cross-chain to disgorge the bridge amount into the adjustment address
            // for that chain
            uint32_t flags = flags = CReserveTransfer::VALID + CReserveTransfer::PROHIBITED_DISGORGEMENT + CReserveTransfer::CROSS_SYSTEM;
            //CAmount amountToBurn = oneChainDeposits.valueMap[oneCurReduction.first] -
            //    CCurrencyState::NativeToReserveRaw(oneChainDeposits.valueMap[oneCurReduction.first], SATOSHIDEN - oneCurReduction.second);
            CAmount amountToBurn = CCurrencyState::NativeToReserveRaw(oneChainDeposits.valueMap[oneCurReduction.first], oneCurReduction.second);

            oneChainResults.valueMap[oneCurReduction.first] -= amountToBurn;
            totalReductionsThisChain.valueMap[oneCurReduction.first] += amountToBurn;

            // create a single adjustment reservetransfer for each currency
            // make one transaction for all of the outputs
            CCcontract_info CC;
            CCcontract_info *cp;
            cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
            CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

            CTransferDestination dest = DestinationToTransferDestination(adjustingDestinations[VERUS_CHAINID]);

            CReserveTransfer rt1 = CReserveTransfer(flags,
                                                    oneCurReduction.first,
                                                    amountToBurn,
                                                    ASSETCHAINS_CHAINID,
                                                    allCurrencies[ASSETCHAINS_CHAINID].first.GetTransactionImportFee() << 1,
                                                    ASSETCHAINS_CHAINID,
                                                    dest,
                                                    uint160(),
                                                    ASSETCHAINS_CHAINID);

            dest = CTransferDestination(CTransferDestination::DEST_NESTEDTRANSFER, ::AsVector(rt1));

            // clear refund bit for processing, require it internally
            CReserveTransfer rt2 = CReserveTransfer(flags,
                                    oneCurReduction.first,
                                    0,
                                    ASSETCHAINS_CHAINID,
                                    allCurrencies[ASSETCHAINS_CHAINID].first.GetTransactionImportFee() << 1,
                                    ASSETCHAINS_CHAINID,
                                    dest,
                                    uint160(),
                                    ASSETCHAINS_CHAINID);

            std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

            if (!bridgeReductionTxes.count(oneChain.second.systemID))
            {
                // we need a transaction for the currency's chain in our map, as we will be adding outputs to it
                bridgeReductionTxes.insert({oneChain.second.systemID, {CCurrencyValueMap(),
                    CreateNewContextualCMutableTransaction(Params().consensus,
                                                        expiryForAllChains.find(oneChain.second.systemID)->second - DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA)}});
            }
            CCurrencyValueMap rt2TotalOut = rt2.TotalCurrencyOut();
            CAmount rt2NativeOut = rt2TotalOut.valueMap.count(oneChain.second.GetID()) ? rt2TotalOut.valueMap[oneChain.second.GetID()] : 0;
            bridgeReductionTxes[oneChain.second.systemID].second.vout.push_back(
                CTxOut(rt2NativeOut,
                       MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt2))));
            bridgeReductionTxes[oneChain.second.systemID].first += (rt1.TotalCurrencyOut() - CCurrencyValueMap({{ASSETCHAINS_CHAINID},{rt1.nFees}}));

            utxosOutput++;
        }
        if (bridgeReductionTxes[oneChain.second.systemID].first.valueMap.size())
        {
            transactionsAndFeesNeeded.insert({oneChain.second.systemID, {bridgeReductionTxes[oneChain.second.systemID].second, CCurrencyValueMap()}});

            UniValue oneChainReport(UniValue::VOBJ);
            oneChainReport.pushKV("bridgechain", EncodeDestination(CIdentityID(oneChain.second.systemID)));
            oneChainReport.pushKV("originalholdings", oneChainDeposits.ToUniValue());
            oneChainReport.pushKV("reducedby", (oneChainDeposits - oneChainResults).ToUniValue());
            oneChainReport.pushKV("postadjustment", oneChainResults.ToUniValue());
            oneChainReport.pushKV("txchain", EncodeDestination(CIdentityID(oneChain.second.systemID)));
            if (!transactionsUni.count(oneChain.second.systemID))
            {
                transactionsUni[oneChain.second.systemID] = UniValue(UniValue::VARR);
            }
            oneChainReport.pushKV("txnumber", (int64_t)transactionsUni[oneChain.second.systemID].size());
            bridgeReductionOutputUni.push_back(oneChainReport);
            transactionsUni[oneChain.second.systemID].push_back(EncodeHexTx(bridgeReductionTxes[oneChain.second.systemID].second));
        }
    }

    if (bridgeReductionOutputUni.size())
    {
        result.pushKV("bridgeadjustments", bridgeReductionOutputUni);
    }

    if (debugExit)
    {
        return result;
    }

    // now, go through all affected fractional currencies and disgorge the reduction of any affected reserves
    // by creating an unfunded refund transaction to the adjustment ID for this chain. the adjustment ID
    // will burn these currencies in provable burn transactions

    std::map<uint160, UniValue> allChainCurReductionMapUni;
    for (auto oneCurrency : currenciesByAdjustment)
    {
        if (allCurrencies[oneCurrency.first].first.IsFractional() &&
            allCurrencies[oneCurrency.first].second.IsValid() &&
            oneCurrency.second.valueMap[oneCurrency.first] > 0)
        {
            CCurrencyDefinition &curDef = allCurrencies.find(oneCurrency.first)->second.first;
            CCoinbaseCurrencyState &curState = allCurrencies.find(oneCurrency.first)->second.second;

            CMutableTransaction balancerTx = CreateNewContextualCMutableTransaction(Params().consensus,
                                                        expiryForAllChains.find(curDef.systemID)->second - DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA);

            CCurrencyValueMap reservesMap = CCurrencyValueMap(allCurrencies[oneCurrency.first].second.currencies, allCurrencies[oneCurrency.first].second.reserves);
            CCurrencyValueMap burnedAmounts;

            // loop through all reductions for this currency and create an unfunded reserve transfer for each one
            // sending to this chain's adjusting ID
            for (auto &oneCurReduction : oneCurrency.second.valueMap)
            {
                uint32_t flags = 0;

                // if we need to reduce the primary currency, it is a burn operation
                if (oneCurReduction.first == oneCurrency.first)
                {
                    flags = CReserveTransfer::VALID + CReserveTransfer::BURN_CHANGE_PRICE + CReserveTransfer::IMPORT_TO_SOURCE + CReserveTransfer::PROHIBITED_DISGORGEMENT;
                }
                else
                {
                    flags = CReserveTransfer::VALID + CReserveTransfer::REFUND + CReserveTransfer::PROHIBITED_DISGORGEMENT;
                }

                // CAmount amountToBurn = reservesMap.valueMap[oneCurReduction.first] -
                //    CCurrencyState::NativeToReserveRaw(reservesMap.valueMap[oneCurReduction.first], SATOSHIDEN - oneCurReduction.second);
                CAmount amountToBurn = (oneCurReduction.first == oneCurrency.first) ?
                    CCurrencyState::NativeToReserveRaw(allCurrencies[oneCurrency.first].second.supply, oneCurReduction.second) :
                    reservesMap.valueMap[oneCurReduction.first] -
                        CCurrencyState::NativeToReserveRaw(reservesMap.valueMap[oneCurReduction.first], SATOSHIDEN - oneCurReduction.second);

                burnedAmounts.valueMap[oneCurReduction.first] = amountToBurn;

                allChainCurrencyAdjustments[curDef.systemID][oneCurrency.first].valueMap[oneCurReduction.first] += amountToBurn;

                // create a single adjustment reservetransfer for each currency
                // make one transaction for all of the outputs
                CCcontract_info CC;
                CCcontract_info *cp;
                cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

                CTransferDestination dest = DestinationToTransferDestination(adjustingDestinations[curDef.systemID]);

                CReserveTransfer rt = CReserveTransfer(flags,
                                                       oneCurReduction.first,
                                                       amountToBurn,
                                                       ASSETCHAINS_CHAINID,
                                                       CReserveTransfer::CalculateTransferFee(dest, flags),
                                                       oneCurrency.first,
                                                       dest);

                dest = CTransferDestination(CTransferDestination::DEST_NESTEDTRANSFER, ::AsVector(rt));

                rt = CReserveTransfer(flags & ~(CReserveTransfer::REFUND),
                                      oneCurReduction.first,
                                      0,
                                      ASSETCHAINS_CHAINID,
                                      CReserveTransfer::CalculateTransferFee(dest, flags),
                                      oneCurrency.first,
                                      dest);

                std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

                balancerTx.vout.push_back(CTxOut(rt.nFees, MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt))));
                utxosOutput++;
            }

            if (curDef.systemID == ASSETCHAINS_CHAINID)
            {
                CCurrencyValueMap excludeBasket(burnedAmounts);
                excludeBasket.valueMap.erase(oneCurrency.first);
                totalReductionsThisChain += excludeBasket;
                transactionsAndFeesNeeded.insert({curDef.systemID, {balancerTx, CCurrencyValueMap()}});
            }

            UniValue txOutput(UniValue::VOBJ);
            txOutput.pushKV("currencyreduction", EncodeDestination(CIdentityID(oneCurrency.first)));
            txOutput.pushKV("initialreserves", reservesMap.ToUniValue());
            txOutput.pushKV("reducedby", burnedAmounts.ToUniValue());
            txOutput.pushKV("reducedbymultiple", oneCurrency.second.ToUniValue());
            txOutput.pushKV("txchain", EncodeDestination(CIdentityID(curDef.systemID)));

            if (curDef.systemID == ASSETCHAINS_CHAINID)
            {
                if (!transactionsUni.count(curDef.systemID))
                {
                    transactionsUni[curDef.systemID] = UniValue(UniValue::VARR);
                }
                txOutput.pushKV("txnumber", (int64_t)transactionsUni[curDef.systemID].size());
                transactionsUni[curDef.systemID].push_back(EncodeHexTx(balancerTx));
            }
            else
            {
                if (!comparisonTransactionsUni.count(curDef.systemID))
                {
                    comparisonTransactionsUni[curDef.systemID] = UniValue(UniValue::VARR);
                }
                txOutput.pushKV("comparisontxnumber", (int64_t)comparisonTransactionsUni[curDef.systemID].size());
                comparisonTransactionsUni[curDef.systemID].push_back(EncodeHexTx(balancerTx));
            }
            if (!allChainCurReductionMapUni.count(curDef.systemID))
            {
                allChainCurReductionMapUni[curDef.systemID] = UniValue(UniValue::VARR);
            }
            allChainCurReductionMapUni[curDef.systemID].push_back(txOutput);
        }
    }

    UniValue allChainCurrencyReductionsUni(UniValue::VOBJ);
    for (auto &oneChainReduction : allChainCurReductionMapUni)
    {
        allChainCurrencyReductionsUni.pushKV(std::string(oneChainReduction.first == ASSETCHAINS_CHAINID ? "enter_on_" : "compare_with_") +
            EncodeDestination(CIdentityID(oneChainReduction.first)), oneChainReduction.second);
    }
    result.pushKV("all_chain_basket_adjustments", allChainCurrencyReductionsUni);

    if (debugExit)
    {
        return result;
    }

    for (auto &oneReimbursementAddress : aggregateReimbursableOutputs)
    {
        std::map<uint160, std::pair<CCurrencyValueMap,CMutableTransaction>> reimbursementTxMap;
        std::map<CTxDestination, CTxDestination> crossChainAddressMap;

        // first, we loop through and aggregate all derivative reimbursements to catch potential overlap in currencies
        // to reduce total calculation error to the minimum
        std::map<uint160,CCurrencyValueMap> totalReimbursableOwnershipPercentage;

        // the amount of currency that this address originally controlled before reduction
        std::vector<std::pair<std::map<uint160, int64_t>, std::map<uint160, int64_t>::iterator>> recursionStack = {{oneReimbursementAddress.second, {}}};
        recursionStack.back().second = recursionStack.back().first.begin();

        // we use this odd loop construction to prevent running the condition on a continue
        // this makes recursion via the loop cleaner
        while (true)
        {
            if (debugExit)
            {
                return result;
            }

            // cleanup recursion for this level
            // if at top level, we are done
            if (recursionStack.back().second == recursionStack.back().first.end())
            {
                recursionStack.pop_back();
                if (recursionStack.empty())
                {
                    break;
                }
            }
            else
            {
                CCurrencyDefinition &curDef = allCurrencies.find(recursionStack.back().second->first)->second.first;
                CCoinbaseCurrencyState &curState = allCurrencies.find(recursionStack.back().second->first)->second.second;

                CAmount reductionPercent = allCurrenciesToAdjust.valueMap.count(recursionStack.back().second->first) ?
                                                allCurrenciesToAdjust.valueMap.find(recursionStack.back().second->first)->second :
                                                0;

                CCurrencyValueMap reimbursableReserves;

                if (reductionPercent != 0 && curDef.IsFractional())
                {
                    // this is a fractional that needed reduction, meaning that one or more of its currencies,
                    // at least the native currency in it will be reimbursed
                    //
                    // first, calculate how much of this currency we lost, and reimburse the difference for any less reduced currencies,
                    // then recurse through all qualified currencies, calculate the transitively controlled amount and do the same

                    // loop through and reimburse for any currency that was reduced less than reductionPercent
                    CCurrencyValueMap currencyMap(curState.currencies, curState.reserves);

                    for (auto &oneReserveCur : currencyMap.valueMap)
                    {
                        // what percentage of the actual supply controlled is in the amountStack.back(), and it is the same percentage of each
                        // total reserve digorgement to reimburse. first calculate total disgorgement percent, then total disgorgement
                        CAmount reserveDeduction = allCurrenciesToAdjust.valueMap.count(oneReserveCur.first) ?
                                                        allCurrenciesToAdjust.valueMap[oneReserveCur.first] :
                                                        0;

                        // if reserve was deducted less than basket, refund difference
                        CAmount reimbursePercent = reductionPercent - reserveDeduction;

                        CAmount thisAddressPercent = CCurrencyDefinition::CalculateRatioOfTwoValues(recursionStack.back().second->second, curState.supply);

                        if (reimbursePercent && thisAddressPercent)
                        {
                            totalReimbursableOwnershipPercentage[recursionStack.back().second->first].valueMap[oneReserveCur.first] += thisAddressPercent;
                        }

                        if (allCurrencies[oneReserveCur.first].first.IsFractional() && reserveDeduction > 0)
                        {
                            // if this reserve is a reduced fractional, we should recurse
                            CCurrencyValueMap oneReserveMap(allCurrencies[oneReserveCur.first].second.currencies, allCurrencies[oneReserveCur.first].second.reserves);
                            for (auto &oneCurID : allCurrencies[oneReserveCur.first].second.currencies)
                            {
                                // if it is a reduced fractional, there should be a chance for reimbursement
                                if (allCurrencies[oneCurID].first.IsFractional() &&
                                    allCurrenciesToAdjust.valueMap.count(oneCurID) &&
                                    allCurrenciesToAdjust.valueMap[oneCurID] != 0)
                                {
                                    CAmount derivativeAmount = CCoinbaseCurrencyState::NativeToReserveRaw(oneReserveMap.valueMap[oneCurID], thisAddressPercent);
                                    if (derivativeAmount)
                                    {
                                        reimbursableReserves.valueMap[oneCurID] += derivativeAmount;
                                    }
                                }
                            }
                        }

                        if (currencyAdjustments.valueMap.count(oneReserveCur.first))
                        {
                            CAmount totalRestitution = CCoinbaseCurrencyState::NativeToReserveRaw(oneReserveCur.second, reserveDeduction);
                            // accrue reimbursement via indirect lack of refunds of primary adjusted currencies
                            thisChainAddressRestitutionCredit[oneReimbursementAddress.first].second.valueMap[oneReserveCur.first] +=
                                CCoinbaseCurrencyState::NativeToReserveRaw(totalRestitution, thisAddressPercent);
                        }
                    }

                    // now that we have created reimbursement outputs for all first level currencies,
                    // do the same for all reduced fractionals in the reserves of the reserves of this currency
                    // by recursing, continue with the next currency when that is complete
                    if (reimbursableReserves.valueMap.size())
                    {
                        // using this form of indexing, instead of back(), due to a suspicion of compiler issue
                        recursionStack.push_back({reimbursableReserves.valueMap, {}});
                        recursionStack.back().second = recursionStack.back().first.begin();
                        continue;
                    }
                }
            }
            recursionStack.back().second++;
        }

        for (auto &oneReimbursementData : totalReimbursableOwnershipPercentage)
        {
            CCurrencyDefinition &curDef = allCurrencies.find(oneReimbursementData.first)->second.first;
            CCoinbaseCurrencyState &curState = allCurrencies.find(oneReimbursementData.first)->second.second;
            CCurrencyValueMap curCurMap(curState.currencies, curState.reserves);
            CAmount reductionPercent = allCurrenciesToAdjust.valueMap.count(oneReimbursementData.first) ?
                                allCurrenciesToAdjust.valueMap.find(oneReimbursementData.first)->second :
                                0;

            for (auto &oneReserveCur : oneReimbursementData.second.valueMap)
            {
                // what percentage of the actual supply controlled is in the amountStack.back() is the same percentage of each
                // reserve disgorgement to reimburse. first calculate total disgorgement percent, then total disgorgement
                CAmount reserveDeduction = allCurrenciesToAdjust.valueMap.count(oneReserveCur.first) ?
                                                allCurrenciesToAdjust.valueMap[oneReserveCur.first] :
                                                0;

                // if reserve was deducted less than basket, refund difference
                CAmount reimbursePercent = reductionPercent - reserveDeduction;
                CAmount totalReimbursement = CCoinbaseCurrencyState::NativeToReserveRaw(curCurMap.valueMap[oneReserveCur.first], reimbursePercent);
                CAmount thisReimbursement = CCoinbaseCurrencyState::NativeToReserveRaw(totalReimbursement, oneReserveCur.second);

                // if it's zero or native dust, no output
                if (thisReimbursement && !(oneReserveCur.first == ASSETCHAINS_CHAINID && thisReimbursement <= (DEFAULT_TRANSACTION_FEE << 1)))
                {
                    // create an unfunded refund transaction output and add it to the correct chain's transaction
                    uint32_t flags = CReserveTransfer::VALID + CReserveTransfer::REFUND + CReserveTransfer::PROHIBITED_DISGORGEMENT;

                    // create a single adjustment reservetransfer for each currency
                    // make one transaction for all of the outputs
                    CCcontract_info CC;
                    CCcontract_info *cp;
                    cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                    CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

                    // if our destination is an ID and we are making a transaction on another chain, get a cross chain alternate,
                    // put it in the map, and use it
                    CTxDestination oneDest = oneReimbursementAddress.first;
                    if (oneDest.which() == COptCCParams::ADDRTYPE_ID && curDef.systemID != ASSETCHAINS_CHAINID)
                    {
                        if (!crossChainAddressMap.count(oneDest))
                        {
                            // get the identity, and to avoid forcing users to send their ID cross-chain, use the first address
                            CIdentity destIdentity = CIdentity::LookupIdentity(GetDestinationID(oneDest));
                            if (destIdentity.IsValid())
                            {
                                crossChainAddressMap[oneReimbursementAddress.first] = destIdentity.primaryAddresses[0];
                            }
                        }
                        auto idIt = crossChainAddressMap.find(oneReimbursementAddress.first);
                        oneDest = idIt == crossChainAddressMap.end() ? oneDest : idIt->second;
                    }

                    CTransferDestination dest = DestinationToTransferDestination(oneDest);

                    CReserveTransfer rt = CReserveTransfer(flags,
                                                            oneReserveCur.first,
                                                            thisReimbursement,
                                                            curDef.systemID,
                                                            CReserveTransfer::CalculateTransferFee(dest, flags),
                                                            curDef.GetID(),
                                                            dest);

                    dest = CTransferDestination(CTransferDestination::DEST_NESTEDTRANSFER, ::AsVector(rt));

                    rt = CReserveTransfer(flags & ~(CReserveTransfer::REFUND),
                                            oneReserveCur.first,
                                            0,
                                            curDef.systemID,
                                            CReserveTransfer::CalculateTransferFee(dest, flags),
                                            curDef.GetID(),
                                            dest);

                    allChainCurrencyReimbursements[curDef.systemID][curDef.GetID()].valueMap[oneReserveCur.first] += thisReimbursement;

                    std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});

                    // ensure we can output a transaction for the currency's chain
                    if (!reimbursementTxMap.count(curDef.systemID))
                    {
                        // we need a transaction for the currency's chain in our map, as we will be adding outputs to it
                        reimbursementTxMap.insert({curDef.systemID, {CCurrencyValueMap(),
                            CreateNewContextualCMutableTransaction(Params().consensus,
                                                                expiryForAllChains.find(curDef.systemID)->second - DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA)}});
                    }
                    reimbursementTxMap[curDef.systemID].first.valueMap[oneReserveCur.first] += thisReimbursement;
                    reimbursementTxMap[curDef.systemID].second.vout.push_back(
                        CTxOut(rt.nFees, MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt))));
                    utxosOutput++;
                }
            }
        }
        for (auto &oneAddressReimbursementChain : reimbursementTxMap)
        {
            transactionsAndFeesNeeded.insert({oneAddressReimbursementChain.first, {oneAddressReimbursementChain.second.second, CCurrencyValueMap()}});

            UniValue txOutput(UniValue::VOBJ);
            txOutput.pushKV("address", EncodeDestination(oneReimbursementAddress.first));
            txOutput.pushKV("fromchain", EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)));
            if (oneAddressReimbursementChain.first != ASSETCHAINS_CHAINID && oneReimbursementAddress.first.which() == COptCCParams::ADDRTYPE_ID)
            {
                // display alternate address used to avoid cross-chain ID requirements
                txOutput.pushKV("asaddress", EncodeDestination(crossChainAddressMap[oneReimbursementAddress.first]));
            }
            txOutput.pushKV("reimbursementtotal", oneAddressReimbursementChain.second.first.ToUniValue());
            txOutput.pushKV("indirectrestitutioncredit",
                (thisChainAddressRestitutionCredit[oneReimbursementAddress.first].second -
                    thisChainAddressRestitutionCredit[oneReimbursementAddress.first].first).ToUniValue());

            txOutput.pushKV("txchain", EncodeDestination(CIdentityID(oneAddressReimbursementChain.first)));
            if (!transactionsUni.count(oneAddressReimbursementChain.first))
            {
                transactionsUni[oneAddressReimbursementChain.first] = UniValue(UniValue::VARR);
            }
            txOutput.pushKV("txnumber", (int64_t)transactionsUni[oneAddressReimbursementChain.first].size());

            if (!adjustmentsByAddress.count(oneReimbursementAddress.first))
            {
                adjustmentsByAddress[oneReimbursementAddress.first] = UniValue(UniValue::VOBJ);
            }
            adjustmentsByAddress[oneReimbursementAddress.first].pushKV(
                std::string("reimbursementtx_") + to_string(transactionsUni[oneAddressReimbursementChain.first].size()), txOutput);

            // keep this push down below any output that depends on the size of the transactionsUni array for this chain
            // to determine a transaction number
            transactionsUni[oneAddressReimbursementChain.first].push_back(EncodeHexTx(oneAddressReimbursementChain.second.second));
        }
    }

    UniValue adjustmentsByAddressUni(UniValue::VOBJ);
    uint160 vethID = CVDXF::GetID("veth");
    uint160 tbtcID = CVDXF::GetID("tbtc.veth");
    for (auto &oneAddress : adjustmentsByAddress)
    {
        CAmount totalRestitutionCurrencyCredit = thisChainAddressRestitutionCredit[oneAddress.first].second.valueMap.count(vethID) ?
                                                    thisChainAddressRestitutionCredit[oneAddress.first].second.valueMap[vethID] :
                                                    0;
        totalRestitutionCurrencyCredit += thisChainAddressRestitutionCredit[oneAddress.first].second.valueMap.count(tbtcID) ?
                                                    CCurrencyState::NativeToReserveRaw(thisChainAddressRestitutionCredit[oneAddress.first].second.valueMap[tbtcID],
                                                                                        tBTCRestitutionConversionRate) :
                                                    0;
        oneAddress.second.pushKV("totalrestitutioncredit", thisChainAddressRestitutionCredit[oneAddress.first].second.ToUniValue());
        oneAddress.second.pushKV("restitutioncurrencycredit", ValueFromAmount(totalRestitutionCurrencyCredit));
        adjustmentsByAddressUni.pushKV(EncodeDestination(oneAddress.first), oneAddress.second);
    }
    result.pushKV("adjustmentsbyaddress", adjustmentsByAddressUni);

    UniValue allChainCurrencyAdjustmentsUni(UniValue::VOBJ);
    for (auto &oneChain : allChainCurrencyAdjustments)
    {
        UniValue oneChainCurrencyAdjustmentsUni(UniValue::VARR);
        for (auto &oneCurrency : oneChain.second)
        {
            UniValue oneCurrencyAdjustmentsUni(UniValue::VOBJ);
            oneCurrencyAdjustmentsUni.pushKV("currency", EncodeDestination(CIdentityID(oneCurrency.first)));
            oneCurrencyAdjustmentsUni.pushKV("reductions", oneCurrency.second.ToUniValue());
            oneChainCurrencyAdjustmentsUni.push_back(oneCurrencyAdjustmentsUni);
        }
        allChainCurrencyAdjustmentsUni.pushKV(EncodeDestination(CIdentityID(oneChain.first)), oneChainCurrencyAdjustmentsUni);
    }
    result.pushKV("currencyreductionsbychain", allChainCurrencyAdjustmentsUni);

    UniValue allChainCurrencyReimbursementsUni(UniValue::VOBJ);
    for (auto &oneChain : allChainCurrencyReimbursements)
    {
        UniValue oneChainCurrencyReimbursementsUni(UniValue::VARR);
        for (auto &oneCurrency : oneChain.second)
        {
            UniValue oneCurrencyReimbursementsUni(UniValue::VOBJ);
            oneCurrencyReimbursementsUni.pushKV("currency", EncodeDestination(CIdentityID(oneCurrency.first)));
            oneCurrencyReimbursementsUni.pushKV("reimbursements", oneCurrency.second.ToUniValue());
            oneChainCurrencyReimbursementsUni.push_back(oneCurrencyReimbursementsUni);
        }
        allChainCurrencyReimbursementsUni.pushKV(EncodeDestination(CIdentityID(oneChain.first)), oneChainCurrencyReimbursementsUni);
    }
    result.pushKV("currencyreimbursementsbychain", allChainCurrencyReimbursementsUni);

    // now, go through all our transactions and calculate fees needed
    // for this chain, try to get exactly matching fee outputs for all transactions
    // if we can't, make transactions to fund with all outputs needed, so next time
    // through, we can output funded, ready to sign transactions

    // in order to include funded, ready to sign transactions, we need to have a large number of small native
    // outputs available on the adjusting destination for the current chain. they are kept here until used
    std::multimap<CCurrencyValueMap,CUTXORef> feeUTXOs;

    if (adjustingDestinations.count(ASSETCHAINS_CHAINID))
    {
        UniValue fundedAdjustmentTransactions(UniValue::VARR);
        UniValue unFundedFeeFundingTransactions(UniValue::VARR);

        CCurrencyValueMap chainsToIntersect;
        for (auto &oneChain : adjustingDestinations)
        {
            if (oneChain.first == ASSETCHAINS_CHAINID)
            {
                continue;
            }
            chainsToIntersect.valueMap[oneChain.first] = 1;
        }

        // get all UTXOs under control of the adjusting address and look for exact match for fees
        UniValue params(UniValue::VARR);
        UniValue paramObj(UniValue::VOBJ);
        UniValue addressArray(UniValue::VARR);
        addressArray.push_back(EncodeDestination(adjustingDestinations[ASSETCHAINS_CHAINID]));
        paramObj.pushKV("addresses", addressArray);
        params.push_back(paramObj);
        UniValue allFeeUtxosUni = getaddressutxos(params, false);

        // put spendable outputs with only a small amount of native currency and no other currency into our
        // fee map, and see if we have enough exact matches for our transactions
        // if not, make unfunded transactions to cover all missing fee outputs
        // sign them with this wallet, if it has the ID, and
        // output all of these as sign commands for a second signer.
        if (allFeeUtxosUni.isArray())
        {
            for (int i = 0; i < allFeeUtxosUni.size(); i++)
            {
                if (uni_get_bool(find_value(allFeeUtxosUni[i],"isspendable")))
                {
                    CCurrencyValueMap totalCurrency(find_value(allFeeUtxosUni[i],"currencyvalues"));
                    if ((totalCurrency.valueMap.size() == 1 || totalCurrency.valueMap.size() == 2) &&
                        (totalCurrency.valueMap.count(ASSETCHAINS_CHAINID) || totalCurrency.Intersects(chainsToIntersect)) &&
                        totalCurrency.valueMap[ASSETCHAINS_CHAINID] >= 0 &&
                        totalCurrency.valueMap[ASSETCHAINS_CHAINID] < SATOSHIDEN)
                    {
                        feeUTXOs.insert({totalCurrency, CUTXORef(uint256S(uni_get_str(find_value(allFeeUtxosUni[i],"txid"))),
                                                        uni_get_int(find_value(allFeeUtxosUni[i],"outputIndex")))});
                    }
                }
            }
        }

        std::vector<std::pair<CMutableTransaction, CCurrencyValueMap>> feeFundingTransactions;
        CCurrencyValueMap feeFundingFound;
        CValidationState state;

        auto feeUTXOsScratch = feeUTXOs;

        if (fundedTransactionsForSigning.size())
        {
            for (auto &oneTx : fundedTransactionsForSigning)
            {
                fundedAdjustmentTransactions.push_back(EncodeHexTx(oneTx));
            }
        }
        else
        {
            // add transaactions from other chains before calculating funding
            for (auto &oneTransaction : unfundedTransactionsFromOtherChains)
            {
                transactionsAndFeesNeeded.insert({ASSETCHAINS_CHAINID, {oneTransaction, CCurrencyValueMap()}});
            }

            CCoinsViewCache view(pcoinsTip);

            // figure out the fee needed for each transaction on this chain
            for (auto txIter = transactionsAndFeesNeeded.equal_range(ASSETCHAINS_CHAINID); txIter.first != txIter.second; txIter.first++)
            {
                // if this transaction is already funded, check the next
                bool funded = false;
                bool erased = false;
                for (auto &txin : txIter.first->second.first.vin)
                {
                    CCoins coins;
                    CTxDestination checkDest;
                    if (view.GetCoins(txin.prevout.hash, coins) &&
                        coins.vout.size() > txin.prevout.n &&
                        (coins.vout[txin.prevout.n].nValue > 0 ||
                         coins.vout[txin.prevout.n].scriptPubKey.ReserveOutValue().Intersects(chainsToIntersect)) &&
                        ExtractDestination(coins.vout[txin.prevout.n].scriptPubKey, checkDest) &&
                        checkDest == adjustingDestinations[ASSETCHAINS_CHAINID])
                    {
                        funded = true;

                        // remove this UTXO from the pool,
                        // put this in our funded transactions,
                        // and continue with the next
                        CCurrencyValueMap searchMap;
                        searchMap = coins.vout[txin.prevout.n].scriptPubKey.ReserveOutValue();
                        searchMap.valueMap[ASSETCHAINS_CHAINID] = coins.vout[txin.prevout.n].nValue;

                        for (auto searchRange = feeUTXOsScratch.equal_range(searchMap);
                            searchRange.first != searchRange.second; searchRange.first++)
                        {
                            if (searchRange.first->second == txin.prevout)
                            {
                                feeUTXOsScratch.erase(searchRange.first);
                                erased = true;
                                break;
                            }
                        }
                        if (!erased)
                        {
                            errors.push_back("No UTXO found for spending input: " + txin.prevout.ToString());
                        }
                    }
                }
                if (funded)
                {
                    // save it as funded
                    fundedAdjustmentTransactions.push_back(EncodeHexTx(txIter.first->second.first));
                }
                else
                {
                    CCurrencyValueMap txReserveFeesNeeded;

                    txIter.first->second.second.valueMap[ASSETCHAINS_CHAINID] = GetMinRelayFeeByOutputs(txIter.first->second.first, state, 0);
                    // if the output has a reserve transfer, add the transfer fees as well
                    for (auto &oneOutput : txIter.first->second.first.vout)
                    {
                        COptCCParams checkP;
                        if (oneOutput.scriptPubKey.IsPayToCryptoCondition(checkP) &&
                            checkP.IsValid() &&
                            checkP.evalCode == EVAL_RESERVE_TRANSFER)
                        {
                            // get fees to add
                            CReserveTransfer rt(checkP.vData[0]);
                            if (rt.IsValid())
                            {
                                txIter.first->second.second += rt.TotalTransferFee();
                            }
                        }
                    }

                    std::multimap<CCurrencyValueMap, CUTXORef>::iterator oneFound = feeUTXOsScratch.lower_bound({txIter.first->second.second});

                    if (oneFound != feeUTXOsScratch.end() && oneFound->first == txIter.first->second.second)
                    {
                        txIter.first->second.first.vin.push_back(CTxIn(oneFound->second));
                        feeFundingFound += txIter.first->second.second;
                        fundedAdjustmentTransactions.push_back(EncodeHexTx(txIter.first->second.first));
                        txIter.first->second.second.valueMap.clear();               // needs no more fees
                        feeUTXOsScratch.erase(oneFound);
                    }
                    else
                    {
                        if (feeFundingTransactions.size() == 0 ||
                            feeFundingTransactions.back().first.vout.size() > MAX_UTXOS_PER_TX)
                        {
                            feeFundingTransactions.push_back({CreateNewContextualCMutableTransaction(Params().consensus,
                                                                                                    expiryForAllChains.find(ASSETCHAINS_CHAINID)->second -
                                                                                                        DEFAULT_PRE_BLOSSOM_TX_EXPIRY_DELTA), CCurrencyValueMap()});
                        }
                        feeFundingTransactions.back().second += txIter.first->second.second;
                        if (txIter.first->second.second.valueMap.size() > 1 ||
                            (txIter.first->second.second.valueMap.begin() != txIter.first->second.second.valueMap.end() &&
                             txIter.first->second.second.valueMap.begin()->first != ASSETCHAINS_CHAINID))
                        {
                            // multi-currency output
                            CCurrencyValueMap reservesOut(txIter.first->second.second);
                            CAmount nativeOut = 0;
                            nativeOut = reservesOut.valueMap[ASSETCHAINS_CHAINID];
                            reservesOut.valueMap.erase(ASSETCHAINS_CHAINID);
                            CTokenOutput to(reservesOut);
                            feeFundingTransactions.back().first.vout.push_back(CTxOut(nativeOut,
                                MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, {adjustingDestinations[ASSETCHAINS_CHAINID]}, 1, &to))));
                        }
                        else if (txIter.first->second.second.valueMap.size() != 0)
                        {
                            // only native currency
                            feeFundingTransactions.back().first.vout.push_back(
                                CTxOut(txIter.first->second.second.valueMap.begin()->second, GetScriptForDestination(adjustingDestinations[ASSETCHAINS_CHAINID])));
                        }
                    }
                }
            }
        }

        result.pushKV("totalfeefundingfound", feeFundingFound.ToUniValue());

        for (auto &oneFeeTx : feeFundingTransactions)
        {
            oneFeeTx.second.valueMap[ASSETCHAINS_CHAINID] += GetMinRelayFeeByOutputs(oneFeeTx.first, state, 0);
            UniValue oneFeeObj(UniValue::VOBJ);
            oneFeeObj.pushKV("feefundingneeded", oneFeeTx.second.ToUniValue());
            oneFeeObj.pushKV("hextx",EncodeHexTx(oneFeeTx.first));
            unFundedFeeFundingTransactions.push_back(oneFeeObj);
        }
        result.pushKV("fundingtransactionsneeded",unFundedFeeFundingTransactions);
        result.pushKV("numtransactionsneedingfunding",(int64_t)(transactionsAndFeesNeeded.count(ASSETCHAINS_CHAINID) - fundedAdjustmentTransactions.size()));
        result.pushKV("numtransactionsfunded",(int64_t)fundedAdjustmentTransactions.size());

        UniValue completedTransactions(UniValue::VARR);
        UniValue transactionsToSign(UniValue::VARR);
        bool signSendFailures = false;

        UniValue signrawtransaction(const UniValue& params, bool fHelp);
        UniValue sendrawtransaction(const UniValue& params, bool fHelp);

        if (feeFundingTransactions.size() == 0 &&
            errors.size() == 0 &&
            fundedAdjustmentTransactions.size() > 0)
        {
            // attempt to sign transactions, and emit them signed or
            // if send flag is set, send them

            // loop and sign, record errors, and if send flag is set, send
            for (int i = 0; i < fundedAdjustmentTransactions.size(); i++)
            {
                params = UniValue(UniValue::VARR);
                UniValue signedTxResult;
                params.push_back(fundedAdjustmentTransactions[i]);
                try
                {
                    signedTxResult = signrawtransaction(params, false);
                }
                catch(const std::exception& e)
                {
                    signSendFailures = true;
                    errors.push_back(std::string(e.what()));
                    continue;
                }

                std::string signedTx = uni_get_str(find_value(signedTxResult,"hex"));
                UniValue error = find_value(signedTxResult,"errors");
                if (signedTx.size() &&
                    uni_get_bool(find_value(signedTxResult,"complete")) &&
                    error.size() == 0)
                {
                    // signed and ready to send
                    completedTransactions.push_back(signedTx);
                }
                else
                {
                    // error or incomplete
                    // if incomplete, just return as list of near ready txes
                    if (signedTx.size())
                    {
                        transactionsToSign.push_back(signedTx);
                    }
                    if (error.size())
                    {
                        errors.push_back(error);
                    }
                }
            }
            // now, if all we have a ready to send transactions, do it if asked
            // otherwise, return both
        }

        if (!signSendFailures && completedTransactions.size() > 0 && transactionsToSign.size() == 0)
        {
            if (sendFullySignedTransactions)
            {
                UniValue txids(UniValue::VARR);
                for (int i = 0; i < completedTransactions.size(); i++)
                {
                    params = UniValue(UniValue::VARR);
                    params.push_back(completedTransactions[i]);
                    UniValue sendResult;
                    try
                    {
                        sendResult = sendrawtransaction(params,false);
                    }
                    catch(...)
                    {
                        signSendFailures = true;
                        UniValue errorUni(UniValue::VOBJ);
                        errorUni.pushKV("sendtransactionerror", i);
                        errorUni.pushKV("hex", completedTransactions[i]);
                        errors.push_back(errorUni);
                        continue;
                    }
                    txids.push_back(sendResult);
                }
                if (txids.size())
                {
                    result.pushKV("senttransactionids",txids);
                }
            }
            else
            {
                result.pushKV("alltransactionsreadytosend",completedTransactions);
            }
        }
        else if (transactionsToSign.size() != 0)
        {
            result.pushKV("transactionsreadytosign",transactionsToSign);
            result.pushKV("transactionsreadytosend",completedTransactions);
        }
        else
        {
            result.pushKV("fundedadjustmenttransactions",fundedAdjustmentTransactions);
        }
    }

    // loop through all transactions generate for other chains to post and output those
    UniValue txesForOtherChains(UniValue::VOBJ);
    for (auto &oneChain : transactionsUni)
    {
        if (oneChain.first == ASSETCHAINS_CHAINID)
        {
            continue;
        }
        txesForOtherChains.pushKV(EncodeDestination(CIdentityID(oneChain.first)), oneChain.second);
    }
    result.pushKV("passtorpconotherchains", txesForOtherChains);

    // loop through all transactions generate for other chains to post and output those
    UniValue txesToCompareWithOtherChains(UniValue::VOBJ);
    for (auto &oneChain : comparisonTransactionsUni)
    {
        if (oneChain.first == ASSETCHAINS_CHAINID)
        {
            continue;
        }
        txesToCompareWithOtherChains.pushKV(EncodeDestination(CIdentityID(oneChain.first)), oneChain.second);
    }
    result.pushKV("donotpost_transactionstocompareonly", txesToCompareWithOtherChains);

    result.pushKV("end_time", DateTimeStrFormat("%d.%m.%Y,%H:%M:%S %z", (int64_t)GetTime()));
    result.push_back(make_pair("start_height", startingHeight));
    result.push_back(make_pair("ending_height", chainActive.Height()));
    result.push_back(make_pair("num_utxos_processed", utxosProcessed));
    result.push_back(make_pair("num_utxos_spent", utxosSpent));
    result.push_back(make_pair("num_reserve_outputs_spent", reserveOutputsSpent));
    result.push_back(make_pair("num_reserve_transfers_spent", reserveTransfersSpent));
    result.push_back(make_pair("num_market_offers_spent", marketOffersSpent));
    result.push_back(make_pair("num_utxos_output", utxosOutput));
    result.pushKV("total_currencies_burned", totalReductionsThisChain.ToUniValue());
    result.pushKV("total_currencies_remaining", (allUTXOTotalCurrency - totalReductionsThisChain).ToUniValue());

    result.pushKV("errors", errors);
    return result;
}

bool CBlockTreeDB::WriteTimestampIndex(const CTimestampIndexKey &timestampIndex) {
    CDBBatch batch(*this);
    batch.Write(make_pair(DB_TIMESTAMPINDEX, timestampIndex), 0);
    return WriteBatch(batch);
}

bool CBlockTreeDB::ReadTimestampIndex(const unsigned int &high, const unsigned int &low, const bool fActiveOnly, std::vector<std::pair<uint256, unsigned int> > &hashes)
{
    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(make_pair(DB_TIMESTAMPINDEX, CTimestampIndexIteratorKey(low)));

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            pair<char, CTimestampIndexKey> keyObj;
            pcursor->GetKey(keyObj);
            char chType = keyObj.first;
            CTimestampIndexKey indexKey = keyObj.second;

            if (chType == DB_TIMESTAMPINDEX && indexKey.timestamp < high) {
                if (fActiveOnly) {
                    if (blockOnchainActive(indexKey.blockHash)) {
                        hashes.push_back(std::make_pair(indexKey.blockHash, indexKey.timestamp));
                    }
                } else {
                    hashes.push_back(std::make_pair(indexKey.blockHash, indexKey.timestamp));
                }

                pcursor->Next();
            } else {
                break;
            }
        } catch (const std::exception& e) {
            break;
        }
    }

    return true;
}

bool CBlockTreeDB::WriteTimestampBlockIndex(const CTimestampBlockIndexKey &blockhashIndex, const CTimestampBlockIndexValue &logicalts) {
    CDBBatch batch(*this);
    batch.Write(make_pair(DB_BLOCKHASHINDEX, blockhashIndex), logicalts);
    return WriteBatch(batch);
}

bool CBlockTreeDB::ReadTimestampBlockIndex(const uint256 &hash, unsigned int &ltimestamp) {

    CTimestampBlockIndexValue(lts);
    if (!Read(std::make_pair(DB_BLOCKHASHINDEX, hash), lts))
	    return false;

    ltimestamp = lts.ltimestamp;
    return true;
}

bool CBlockTreeDB::WriteFlag(const std::string &name, bool fValue) {
    return Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CBlockTreeDB::ReadFlag(const std::string &name, bool &fValue) {
    char ch;
    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

bool CBlockTreeDB::blockOnchainActive(const uint256 &hash) {
    BlockMap::const_iterator it = mapBlockIndex.find(hash);
    CBlockIndex* pblockindex = it != mapBlockIndex.end() ? it->second : NULL;

    if (!pblockindex || !chainActive.Contains(pblockindex)) {
	    return false;
    }

    return true;
}

// Startup-only: caller holds chain initialization quiescent. Compression,
// hash dispatch, activation heights and chain ID MUST NOT be reconfigured until
// return. Thread creation publishes these frozen settings and initialized
// Haraka constants. Non-ISA/ARM CLHASH detection writes globals on each call,
// so those builds deliberately retain the serial path (see switch below).
bool CBlockTreeDB::LoadBlockIndexGutsParallel(std::function<CBlockIndex*(const uint256&)> insertBlockIndex)
{
    const uint64_t budget=StartupGutsBufferBudget();
    return LoadBlockIndexGutsParallel(insertBlockIndex,budget);
}

bool CBlockTreeDB::LoadBlockIndexGutsParallel(std::function<CBlockIndex*(const uint256&)> insertBlockIndex, uint64_t maxBufferBytes)
{
    CVerusHash::init();
    CVerusHashV2::init();
    IsCPUVerusOptimized();
    const bool compression = CCompactSolutionVector::IsCompressionOn();
    const auto activation = CConstVerusSolutionVector::activationHeight;
    const auto hashFunction = CBlockHeader::hashFunction;
    const auto chainID = ASSETCHAINS_CHAINID;
    const size_t workers = std::min<size_t>(16,std::max(1u,std::thread::hardware_concurrency()));
    // Each uint256 serializes its 32 raw bytes, not its printed big-endian hex.
    // 'b' + 32 bytes is fixed length. Split the FIRST SERIALIZED hash byte;
    // [floor(i*256/N),floor((i+1)*256/N)) covers all 256 prefixes exactly.
    // LevelDB's comparator compares unsigned bytes; no numeric uint256 compare.
    std::vector<std::string> bounds;
    for(size_t i=0;i<workers;++i) {
        std::string bound(33,'\0');bound[0]=DB_BLOCK_INDEX;
        bound[1]=static_cast<char>(i*256/workers);bounds.push_back(bound);
    }
    // The ledger includes every owned staged record until its destruction after
    // ordered commit (or cancellation). No per-shard cumulative-volume quota.
    std::atomic<uint64_t> liveBytes(0),liveHiwater(0);
    struct Record {
        CDiskBlockIndex disk; uint256 hash;
        std::atomic<uint64_t>* live=nullptr;
        uint64_t accounted=0;
        ~Record() { if(live) live->fetch_sub(accounted,std::memory_order_relaxed); }
    };
    struct SnapshotGuard {
        CBlockTreeDB &db; const leveldb::Snapshot *snapshot;
        explicit SnapshotGuard(CBlockTreeDB &d):db(d),snapshot(d.GetSnapshot()){}
        ~SnapshotGuard(){db.ReleaseSnapshot(snapshot);}
    } snapshot(*this); // common sequence, released only after all iterators join
    using Clock=std::chrono::steady_clock;
    auto start=Clock::now();
    int64_t decodeMs=-1;
    size_t keys=0;
    try {
        StartupGutsMerge<Record>(workers,
            [&](size_t i,const std::function<void(std::string,std::unique_ptr<Record>)>&emit) {
                // LevelDB documents concurrent NewIterator on one DB as safe;
                // never share an Iterator. Create/use/destroy on THIS worker.
                std::unique_ptr<CDBIterator> cursor(NewIterator(snapshot.snapshot));
                cursor->SeekRaw(bounds[i]);
                // All producers finish and join before the first callback.
                // A reservation failure therefore always permits a serial retry.
                while(cursor->Valid()) {
                    auto key=cursor->GetRawKey();
                    if(key.empty()||key[0]!=DB_BLOCK_INDEX) break;
                    if(i+1<workers && leveldb::Slice(key).compare(bounds[i+1])>=0) break;
                    if(key.size()!=33) throw std::runtime_error("malformed block-index key");
                    std::unique_ptr<Record> record(new Record);
                    if(!cursor->GetValue(record->disk)) throw std::runtime_error("failed to read block-index value");
                    record->hash=record->disk.GetBlockHash();
                    record->accounted=sizeof(Record)+128+key.capacity()+
                        record->disk.nSolution.vch.capacity()+record->disk.nSolution._size;
                    auto live=liveBytes.load(std::memory_order_relaxed);
                    do {
                        if(live>maxBufferBytes || record->accounted>maxBufferBytes-live)
                            throw StartupGutsBufferLimit(); // BEFORE any map publication
                    } while(!liveBytes.compare_exchange_weak(live,live+record->accounted,std::memory_order_relaxed));
                    live+=record->accounted;
                    record->live=&liveBytes; // destructor releases a successful reservation
                    auto high=liveHiwater.load(std::memory_order_relaxed);
                    while(high<live && !liveHiwater.compare_exchange_weak(high,live,std::memory_order_relaxed)) {}
                    emit(std::move(key),std::move(record));
                    cursor->Next();
                }
                cursor->CheckStatus(); // invalid must not silently swallow I/O/CRC error
            }, [&](const std::string&,std::unique_ptr<Record> record) {
                if(decodeMs<0) decodeMs=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-start).count();
                auto &diskindex=record->disk;
                // Construct block index object
#ifdef VERUSHASHDEBUG
                if (diskindex.nVersion == CBlockHeader::VERUS_V2)
                {
                    printf("VerusHash 2.0 block header: %s\n", diskindex.ToString().c_str());
                }
#endif
                CBlockIndex* pindexNew    = insertBlockIndex(record->hash);
                pindexNew->pprev          = insertBlockIndex(diskindex.hashPrev);
                pindexNew->SetHeight(diskindex.GetHeight());
                pindexNew->nFile          = diskindex.nFile;
                pindexNew->nDataPos       = diskindex.nDataPos;
                pindexNew->nUndoPos       = diskindex.nUndoPos;
                pindexNew->hashSproutAnchor     = diskindex.hashSproutAnchor;
                pindexNew->nVersion       = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->hashFinalSaplingRoot   = diskindex.hashFinalSaplingRoot;
                pindexNew->nTime          = diskindex.nTime;
                pindexNew->nBits          = diskindex.nBits;
                pindexNew->nNonce         = diskindex.nNonce;
                pindexNew->nSolution      = diskindex.nSolution;
                pindexNew->nStatus        = diskindex.nStatus;
                pindexNew->nCachedBranchId = diskindex.nCachedBranchId;
                pindexNew->nTx            = diskindex.nTx;
                pindexNew->nSproutValue   = diskindex.nSproutValue;
                pindexNew->nSaplingValue  = diskindex.nSaplingValue;

                // Consistency checks
                auto header = pindexNew->GetBlockHeader();
                // GetDiskBlockHeader is EXACTLY the input hashed by the worker.
                // Keep the legacy recomputation on ANY reconstruction mismatch.
                // Thus identity remains computed from bytes, never the disk key;
                // even old behavior for a corrupt key/value pair is unchanged.
                auto original = diskindex.GetDiskBlockHeader();
                const bool identical = header.nVersion == original.nVersion &&
                    header.hashPrevBlock == original.hashPrevBlock &&
                    header.hashMerkleRoot == original.hashMerkleRoot &&
                    header.hashFinalSaplingRoot == original.hashFinalSaplingRoot &&
                    header.nTime == original.nTime && header.nBits == original.nBits &&
                    header.nNonce == original.nNonce && header.nSolution == original.nSolution;
                uint256 hash = identical ? record->hash : header.GetHash();
#ifdef VERUS_GUTS_VERIFY
                if (hash != header.GetHash())
                    throw std::runtime_error("startup guts hash reuse verification failed");
#endif
                if (diskindex.hashPrev.IsNull() && hash != Params().consensus.hashGenesisBlock)
                {
                    throw std::runtime_error(strprintf("LoadBlockIndex(): prior block hash NULL on non-genesis block: %s\n", diskindex.ToString()));
                }

                if (hash != pindexNew->GetBlockHash())
                {
                    printf("Error -- hashes don't match.\nheader.GetHash: %s\nGetBlockHash(): %s\non disk: %s\nin memory: %s\n",
                           hash.GetHex().c_str(), pindexNew->GetBlockHash().GetHex().c_str(), diskindex.ToString().c_str(),  pindexNew->ToString().c_str());
                    throw std::runtime_error(strprintf("LoadBlockIndex(): block header inconsistency detected: on-disk = %s, in-memory = %s",
                                 diskindex.ToString(),  pindexNew->ToString()));
                }

                ++keys;

            });
    } catch(const StartupGutsBufferLimit&) {
        assert(liveBytes.load()==0); // cancelled workers joined, staged payloads freed
        LogPrintf("LoadBlockIndexGuts: buffer budget exceeded; retrying serial\n");
        return LoadBlockIndexGutsSerial(insertBlockIndex);
    } catch(const boost::thread_interrupted&) { throw; }
      catch(const std::exception &e) { return error("LoadBlockIndexGuts: %s",e.what()); }
    // These checks document/enforce the caller's startup-only frozen-state
    // contract; concurrent configuration writes are NOT supported by the node.
    assert(compression==CCompactSolutionVector::IsCompressionOn());
    assert(hashFunction==CBlockHeader::hashFunction && chainID==ASSETCHAINS_CHAINID);
    assert(activation.active==CConstVerusSolutionVector::activationHeight.active);
    for(int i=0;i<CActivationHeight::NUM_VERSIONS;++i)
        assert(activation.heights[i]==CConstVerusSolutionVector::activationHeight.heights[i]);
    const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-start).count();
    if(decodeMs<0) decodeMs=elapsed; // empty database
    const auto commitMs=elapsed-decodeMs;
    assert(liveBytes.load()==0);
    if(GetBoolArg("-printtoconsole",false))
        LogPrintf("LoadBlockIndexGuts: workers=%d keys=%d decode_parallel_ms=%d commit_ms=%d livebuf_hiwater=%d buffer_budget=%d livebuf_final=%d backpressure_waits=0 elapsed_ms=%d\n",
                  workers,keys,decodeMs,commitMs,liveHiwater.load(),maxBufferBytes,liveBytes.load(),elapsed);
    return true;
}

bool CBlockTreeDB::LoadBlockIndexGuts(std::function<CBlockIndex*(const uint256&)> insertBlockIndex)
{
#if defined(ENABLE_VERUS_ISA) && (defined(__x86_64__) || defined(__i386__))
    if(GetBoolArg("-startupguts",true)) return LoadBlockIndexGutsParallel(insertBlockIndex);
#endif
    return LoadBlockIndexGutsSerial(insertBlockIndex);
}

bool CBlockTreeDB::LoadBlockIndexGutsSerial(std::function<CBlockIndex*(const uint256&)> insertBlockIndex)
{
    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(make_pair(DB_BLOCK_INDEX, uint256()));

    // Load mapBlockIndex
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX) {
            CDiskBlockIndex diskindex;
            if (pcursor->GetValue(diskindex)) {
                // Construct block index object
#ifdef VERUSHASHDEBUG
                if (diskindex.nVersion == CBlockHeader::VERUS_V2)
                {
                    printf("VerusHash 2.0 block header: %s\n", diskindex.ToString().c_str());
                }
#endif
                CBlockIndex* pindexNew    = insertBlockIndex(diskindex.GetBlockHash());
                pindexNew->pprev          = insertBlockIndex(diskindex.hashPrev);
                pindexNew->SetHeight(diskindex.GetHeight());
                pindexNew->nFile          = diskindex.nFile;
                pindexNew->nDataPos       = diskindex.nDataPos;
                pindexNew->nUndoPos       = diskindex.nUndoPos;
                pindexNew->hashSproutAnchor     = diskindex.hashSproutAnchor;
                pindexNew->nVersion       = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->hashFinalSaplingRoot   = diskindex.hashFinalSaplingRoot;
                pindexNew->nTime          = diskindex.nTime;
                pindexNew->nBits          = diskindex.nBits;
                pindexNew->nNonce         = diskindex.nNonce;
                pindexNew->nSolution      = diskindex.nSolution;
                pindexNew->nStatus        = diskindex.nStatus;
                pindexNew->nCachedBranchId = diskindex.nCachedBranchId;
                pindexNew->nTx            = diskindex.nTx;
                pindexNew->nSproutValue   = diskindex.nSproutValue;
                pindexNew->nSaplingValue  = diskindex.nSaplingValue;

                // Consistency checks
                auto header = pindexNew->GetBlockHeader();
                uint256 hash = header.GetHash();
                if (diskindex.hashPrev.IsNull() && hash != Params().consensus.hashGenesisBlock)
                {
                    return error("LoadBlockIndex(): prior block hash NULL on non-genesis block: %s\n", diskindex.ToString());
                }

                if (hash != pindexNew->GetBlockHash())
                {
                    printf("Error -- hashes don't match.\nheader.GetHash: %s\nGetBlockHash(): %s\non disk: %s\nin memory: %s\n",
                           hash.GetHex().c_str(), pindexNew->GetBlockHash().GetHex().c_str(), diskindex.ToString().c_str(),  pindexNew->ToString().c_str());
                    return error("LoadBlockIndex(): block header inconsistency detected: on-disk = %s, in-memory = %s",
                                 diskindex.ToString(),  pindexNew->ToString());
                }

                pcursor->Next();
            } else {
                return error("LoadBlockIndex() : failed to read value");
            }
        } else {
            break;
        }
    }

    return true;
}
