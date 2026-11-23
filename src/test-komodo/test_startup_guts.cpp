#include "gtest/gtest.h"
#include "txdb.h"
#include "chainparams.h"
#include "crypto/verus_hash.h"
#include "startup_guts.h"
#include "leveldb/util/crc32c.h"
#include <algorithm>
#include <map>
#include <random>
#include <thread>

TEST(StartupCRC, HardwareTableParity)
{
    using namespace leveldb::crc32c;
    printf("CRC32C runtime hardware=%d\n", HardwareAvailable());
    EXPECT_EQ(0u, Value("", 0));
    EXPECT_EQ(0xe3069283u, Value("123456789", 9));
    EXPECT_EQ(0xc1d04330u, Value("a", 1));
    std::mt19937 rng(0x5005);
    std::vector<char> b(8200);
    const size_t edges[] = {0,1,7,8,15,16,31,32,63,64,4096};
    for (size_t i=0; i<10011; ++i) {
        size_t n=i<11 ? edges[i] : rng()%8193;
        for (char &c:b) c=static_cast<char>(rng());
        size_t offset=i%8;
        uint32_t seed=rng();
        const char *p=b.data()+offset;
        const auto oracle=ExtendTable(seed,p,n);
        EXPECT_EQ(oracle, Extend(seed,p,n));
        if (HardwareAvailable()) EXPECT_EQ(oracle, ExtendHardware(seed,p,n));
        size_t split=n/2;
        EXPECT_EQ(oracle, Extend(Extend(seed,p,split),p+split,n-split));
        EXPECT_EQ(oracle, Unmask(Mask(oracle)));
    }
}

TEST(StartupGuts, MergeRandomKeysAndFailure)
{
    std::mt19937 rng(55);
    std::vector<std::vector<std::string>> shards(16);
    std::vector<std::string> expected,got;
    for (int i=0;i<10000;++i) {
        std::string k(33,'b');
        for(size_t j=1;j<k.size();++j) k[j]=static_cast<char>(rng());
        shards[rng()%shards.size()].push_back(k);
        expected.push_back(k);
    }
    auto less=[](const std::string&a,const std::string&b){return leveldb::Slice(a).compare(b)<0;};
    for(auto &v:shards) std::sort(v.begin(),v.end(),less);
    std::sort(expected.begin(),expected.end(),less);
    StartupGutsMerge<std::string>(shards.size(),
        [&](size_t i,const std::function<void(std::string,std::unique_ptr<std::string>)>& emit) {
            for(const auto&k:shards[i]) emit(k,std::unique_ptr<std::string>(new std::string(k)));
        }, [&](const std::string&key,std::unique_ptr<std::string> item){ EXPECT_EQ(key,*item); got.push_back(key); });
    EXPECT_EQ(expected,got);
    EXPECT_THROW(StartupGutsMerge<int>(4,
        [](size_t i,const std::function<void(std::string,std::unique_ptr<int>)>&emit){
            for(int j=0;j<1000;++j) {
                if(i==2 && j==3) throw std::runtime_error("producer failure");
                emit(std::string(1,char(i)),std::unique_ptr<int>(new int(j)));
            }
        },[](const std::string&,std::unique_ptr<int>){}),std::runtime_error);
    EXPECT_THROW(StartupGutsMerge<int>(4,
        [](size_t i,const std::function<void(std::string,std::unique_ptr<int>)>&emit){
            for(int j=0;j<1000;++j) emit(std::string(1,char(i)),std::unique_ptr<int>(new int(j)));
        },[](const std::string&,std::unique_ptr<int>){throw std::runtime_error("consumer failure");}),std::runtime_error);
}

namespace {
struct OwnedIndex {
    std::map<uint256,CBlockIndex*> blocks;
    std::vector<uint256> calls;
    ~OwnedIndex(){for(auto &p:blocks) delete p.second;}
    CBlockIndex *Insert(const uint256 &hash) {
        calls.push_back(hash);
        if(hash.IsNull()) return nullptr;
        auto it=blocks.find(hash);
        if(it!=blocks.end()) return it->second;
        CBlockIndex *p=new CBlockIndex;
        auto entry=blocks.emplace(hash,p).first;
        p->phashBlock=&entry->first;
        return p;
    }
};
struct RestoreGuts {
    bool compression=CCompactSolutionVector::IsCompressionOn();
    decltype(CBlockHeader::hashFunction) hash=CBlockHeader::hashFunction;
    ~RestoreGuts(){ CCompactSolutionVector::SetCompression(compression); CBlockHeader::hashFunction=hash; mapArgs.erase("-startupguts"); SelectParams(CBaseChainParams::REGTEST); }
};
}

TEST(StartupGuts, SerialParallelDatabaseParity)
{
    RestoreGuts restore;
    CVerusHash::init(); CVerusHashV2::init();
    ASSERT_NE(nullptr,CVerusHash::haraka512Function);
    ASSERT_NE(nullptr,CVerusHashV2::haraka256Function);
    SelectParams(CBaseChainParams::REGTEST);
    CBlockHeader::SetVerusV2Hash();
    for (bool compressed:{false,true}) {
        CCompactSolutionVector::SetCompression(compressed);
        CBlockTreeDB db(1<<20,true);
        // A real genesis plus deterministic descendants. No PoS target construction.
        CBlockHeader header=Params().GenesisBlock().GetBlockHeader();
        uint256 previous;
        for(int i=0;i<1025;++i) {
            if(i) {header.nVersion=CBlockHeader::VERUS_V2; header.hashPrevBlock=previous; header.nTime+=61; header.nNonce=uint256S(strprintf("%064x",i)); header.nSolution.assign(1344,0);}
            CBlockIndex index(header);
            index.SetHeight(i);
            index.nStatus=BLOCK_HAVE_DATA|BLOCK_HAVE_UNDO|BLOCK_VALID_TRANSACTIONS;
            index.nFile=i%7;index.nDataPos=i*3;index.nUndoPos=i*5;index.nTx=i+1;
            index.nSproutValue=i*2;index.nSaplingValue=i*4;
            CDiskBlockIndex disk(&index);disk.hashPrev=header.hashPrevBlock;
            previous=header.GetHash();
            ASSERT_TRUE(db.Write(std::make_pair('b',previous),disk));
        }
        OwnedIndex serial,parallel;
        mapArgs["-startupguts"]="0";
        ASSERT_TRUE(db.LoadBlockIndexGuts([&](const uint256 &h){return serial.Insert(h);}));
        mapArgs["-startupguts"]="1";
        const auto main=std::this_thread::get_id();
        ASSERT_TRUE(db.LoadBlockIndexGutsParallel([&](const uint256 &h){EXPECT_EQ(main,std::this_thread::get_id());return parallel.Insert(h);}));
        OwnedIndex limited;
        ASSERT_TRUE(db.LoadBlockIndexGutsParallel([&](const uint256 &h){return limited.Insert(h);},0));
        EXPECT_EQ(serial.calls,limited.calls); // zero budget: retry before any publication
        EXPECT_EQ(serial.calls,parallel.calls);
        ASSERT_EQ(serial.blocks.size(),parallel.blocks.size());
        for(const auto &entry:serial.blocks) {
            auto found=parallel.blocks.find(entry.first);ASSERT_NE(parallel.blocks.end(),found);
            auto a=entry.second,b=found->second;
            EXPECT_EQ(a->pprev?a->pprev->GetBlockHash():uint256(),b->pprev?b->pprev->GetBlockHash():uint256());
            CDataStream sa(SER_DISK,CLIENT_VERSION),sb(SER_DISK,CLIENT_VERSION);
            sa<<CDiskBlockIndex(a);sb<<CDiskBlockIndex(b);
            EXPECT_EQ(sa.str(),sb.str());
            EXPECT_EQ(a->chainPower.chainWork,b->chainPower.chainWork);
            EXPECT_EQ(a->chainPower.chainStake,b->chainPower.chainStake);
        }
    }
}

TEST(StartupGuts, MalformedValueAndEmptyDatabase)
{
    RestoreGuts restore;
    CBlockTreeDB db(1<<20,true);
    mapArgs["-startupguts"]="1";
    OwnedIndex result;
    EXPECT_TRUE(db.LoadBlockIndexGuts([&](const uint256&h){return result.Insert(h);}));
    EXPECT_TRUE(result.blocks.empty());
    ASSERT_TRUE(db.Write(std::make_pair('b',uint256S("01")),std::string("bad")));
    EXPECT_FALSE(db.LoadBlockIndexGuts([&](const uint256&h){return result.Insert(h);}));
}

TEST(StartupGuts, SharedSnapshotAndSerializedByteRanges)
{
    CDBWrapper db("guts-snapshot",1<<20,true);
    ASSERT_TRUE(db.Write(std::make_pair('b',uint256S("01")),1));
    const auto snapshot=db.GetSnapshot();
    ASSERT_TRUE(db.Write(std::make_pair('b',uint256S("02")),2));
    // Iterator creation and destruction both occur inside each worker.
    std::atomic<int> seen(0);
    std::vector<std::thread> threads;
    for(int i=0;i<16;++i) threads.emplace_back([&,i] {
        std::unique_ptr<CDBIterator> cursor(db.NewIterator(snapshot));
        std::string begin(33,'\0'),end(33,'\0');begin[0]=end[0]='b';
        begin[1]=char(i*16);end[1]=char((i+1)*16);
        cursor->SeekRaw(begin);
        while(cursor->Valid()) {
            const auto key=cursor->GetRawKey();
            if(key.empty()||key[0]!='b'||(i<15&&leveldb::Slice(key).compare(end)>=0)) break;
            ++seen;cursor->Next();
        }
        cursor->CheckStatus();
    });
    for(auto &thread:threads) thread.join();
    db.ReleaseSnapshot(snapshot);
    EXPECT_EQ(1,seen.load());
}

TEST(StartupGuts, ReconstructedMismatchStillRejectedAndDiskKeyNotTrusted)
{
    RestoreGuts restore;
    CVerusHash::init();CVerusHashV2::init();
    SelectParams(CBaseChainParams::REGTEST);CBlockHeader::SetVerusV2Hash();
    CBlockTreeDB db(1<<20,true);
    auto header=Params().GenesisBlock().GetBlockHeader();
    CBlockIndex index(header);
    CDiskBlockIndex disk(&index);
    // Preserve legacy identity: recompute the header, never trust this disk key.
    const uint256 wrong=uint256S("05");
    ASSERT_NE(header.GetHash(),wrong);
    ASSERT_TRUE(db.Write(std::make_pair('b',wrong),disk));
    for(const char *mode:{"0","1"}) {
        mapArgs["-startupguts"]=mode;
        OwnedIndex result;
        EXPECT_TRUE(db.LoadBlockIndexGuts([&](const uint256&h){return result.Insert(h);}));
        ASSERT_EQ(1u,result.blocks.size());
        EXPECT_EQ(header.GetHash(),result.blocks.begin()->first);
    }
    // A non-genesis header with a missing parent must still make a placeholder.
    // Deliberately corrupt that placeholder's identity in the callback; the
    // reconstructed input differs and MUST take the legacy rehash/error path.
    header.hashPrevBlock=uint256S("07");header.nTime+=61;
    CBlockIndex next(header);CDiskBlockIndex child(&next);child.hashPrev=header.hashPrevBlock;
    ASSERT_TRUE(db.Write(std::make_pair('b',header.GetHash()),child));
    for(const char *mode:{"0","1"}) {
        mapArgs["-startupguts"]=mode;
        OwnedIndex result;
        EXPECT_FALSE(db.LoadBlockIndexGuts([&](const uint256&h){
            auto p=result.Insert(h);
            if(h==header.hashPrevBlock) p->phashBlock=&wrong;
            return p;
        }));
    }
}

TEST(StartupGuts, AllWorkersFinishBeforeOrderedCommit)
{
    std::atomic<int> produced(0);
    int committed=0;
    std::atomic<uint64_t> waits(0);
    StartupGutsMerge<int>(4,
        [&](size_t i,const std::function<void(std::string,std::unique_ptr<int>)>& emit) {
            for(int j=0;j<1024;++j) {
                emit(std::string(1,char(i)),std::unique_ptr<int>(new int(j)));
                ++produced;
            }
        },[&](const std::string&,std::unique_ptr<int>) {
            if(committed==0) EXPECT_EQ(produced.load(),4*1024);
            ++committed;
        }, &waits);
    EXPECT_EQ(4096,committed);
    EXPECT_EQ(waits.load(),0u);
}


TEST(StartupGuts, OverOneGiBLiveBudgetFallbackAndNormalBudgetParallelParity)
{
    RestoreGuts restore;
    CCompactSolutionVector::SetCompression(true);
    SelectParams(CBaseChainParams::REGTEST);
    CBlockHeader::SetSHA256DHash();
    CBlockTreeDB db(1<<20,true);
    CBlockHeader header;
    header.nVersion=4;
    header.hashPrevBlock=uint256S("01");
    header.nSolution.assign(65535,0);
    const size_t records=16400;
    ASSERT_GT(uint64_t(records)*header.nSolution.size(),uint64_t(1)<<30);
    for(size_t i=0;i<records;++i) {
        header.nTime=i+1;
        CBlockIndex index(header);index.SetHeight(i+1);index.nTx=i+1;
        CDiskBlockIndex disk(&index);disk.hashPrev=header.hashPrevBlock;
        // All keys belong to the FIRST shard, independent of header identity.
        uint256 key;memcpy(key.begin()+2,&i,sizeof(i));
        ASSERT_TRUE(db.Write(std::make_pair('b',key),disk));
    }
    OwnedIndex serial,parallel,limited;
    ASSERT_TRUE(db.LoadBlockIndexGutsSerial([&](const uint256&h){return serial.Insert(h);}));
    const bool console=fPrintToConsole;
    fPrintToConsole=true;mapArgs["-printtoconsole"]="1";
    testing::internal::CaptureStdout();
    const bool fallback=db.LoadBlockIndexGutsParallel([&](const uint256&h){return limited.Insert(h);},uint64_t(1)<<20);
    const auto fallbackLog=testing::internal::GetCapturedStdout();
    testing::internal::CaptureStdout();
    const bool success=db.LoadBlockIndexGutsParallel([&](const uint256&h){return parallel.Insert(h);});
    const auto log=testing::internal::GetCapturedStdout();
    fPrintToConsole=console;mapArgs.erase("-printtoconsole");
    ASSERT_TRUE(fallback)<<fallbackLog;
    EXPECT_NE(std::string::npos,fallbackLog.find("buffer budget exceeded; retrying serial"))<<fallbackLog;
    EXPECT_EQ(serial.calls,limited.calls); // no partial publication before retry
    ASSERT_TRUE(success);
    EXPECT_EQ(std::string::npos,log.find("retrying serial"))<<log;
    const auto high=log.find("livebuf_hiwater=");
    ASSERT_NE(std::string::npos,high)<<log;
    const auto highBytes=std::stoull(log.substr(high+std::string("livebuf_hiwater=").size()));
    EXPECT_GT(highBytes,uint64_t(1)<<30)<<log;
    const auto budget=log.find("buffer_budget=");
    ASSERT_NE(std::string::npos,budget)<<log;
    const auto budgetBytes=std::stoull(log.substr(budget+std::string("buffer_budget=").size()));
    EXPECT_LE(highBytes,budgetBytes);EXPECT_LE(budgetBytes,uint64_t(32)<<30);
    EXPECT_NE(std::string::npos,log.find("livebuf_final=0"))<<log;
    EXPECT_NE(std::string::npos,log.find("backpressure_waits=0"))<<log;
    printf("Over-1GiB live-budget regression: %s",log.c_str());
    EXPECT_EQ(serial.calls,parallel.calls);
    ASSERT_EQ(serial.blocks.size(),parallel.blocks.size());
    ASSERT_EQ(serial.blocks.size(),limited.blocks.size());
    for(const auto& entry:serial.blocks) {
        auto fallbackEntry=limited.blocks.find(entry.first);ASSERT_NE(limited.blocks.end(),fallbackEntry);
        CDataStream original(SER_DISK,CLIENT_VERSION),retried(SER_DISK,CLIENT_VERSION);
        original<<CDiskBlockIndex(entry.second);retried<<CDiskBlockIndex(fallbackEntry->second);
        EXPECT_EQ(original.str(),retried.str());
        auto found=parallel.blocks.find(entry.first);ASSERT_NE(parallel.blocks.end(),found);
        CDataStream a(SER_DISK,CLIENT_VERSION),b(SER_DISK,CLIENT_VERSION);
        a<<CDiskBlockIndex(entry.second);b<<CDiskBlockIndex(found->second);
        EXPECT_EQ(a.str(),b.str());
        EXPECT_EQ(entry.second->pprev?entry.second->pprev->GetBlockHash():uint256(),
                  found->second->pprev?found->second->pprev->GetBlockHash():uint256());
    }
}
