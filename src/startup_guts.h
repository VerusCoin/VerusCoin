// Copyright (c) 2026 The Verus developers
// Distributed under the MIT software license.
#ifndef VERUS_STARTUP_GUTS_H
#define VERUS_STARTUP_GUTS_H

#include <atomic>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <exception>
#include <functional>
#include <fstream>
#include <sstream>
#include <limits>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <boost/thread.hpp>
#include <leveldb/slice.h>

class StartupGutsBufferLimit : public std::runtime_error {
public:
    StartupGutsBufferLimit():std::runtime_error("startup guts buffer budget exceeded"){}
};

// Read once at entry to the parallel boot load. Missing/unreadable availability
// fails closed (zero budget); this is an accounted-payload limit, not an RSS cap.
inline uint64_t StartupGutsBufferBudget()
{
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    while(std::getline(meminfo,line)) {
        std::istringstream fields(line);
        std::string name,unit; uint64_t kb=0;
        if(!(fields>>name) || name!="MemAvailable:") continue;
        if(!(fields>>kb>>unit) || unit!="kB" ||
           kb>std::numeric_limits<uint64_t>::max()/1024) return 0;
        const uint64_t available=kb*1024;
        const uint64_t sixtyPercent=(available/5)*3+(available%5)*3/5;
        return std::min<uint64_t>(uint64_t(32)<<30,sixtyPercent);
    }
    return 0;
}

// Each producer owns a distinct preallocated buffer and its iterator's ENTIRE
// lifetime. No borrowed Slice/iterator or permanent CBlockIndex crosses threads.
// Produce ALL ranges before committing: small bounded streaming mailboxes would
// stall every later range behind range 0, serializing almost the whole decode.
// The caller must enforce a payload budget and may fall back BEFORE any commit.
// Key comparison is LevelDB byte order, NOT uint256 numeric/display order.
template <typename T, typename Produce, typename Commit>
void StartupGutsMerge(size_t count, Produce produce, Commit commit,
                      std::atomic<uint64_t>* backpressureWaits = nullptr)
{
    if(backpressureWaits) backpressureWaits->store(0); // no producer backpressure
    struct Item { std::string key; std::unique_ptr<T> value; };
    struct Head { std::string key; size_t shard; };
    struct Later {
        bool operator()(const Head&a,const Head&b) const {
            const int c=leveldb::Slice(a.key).compare(b.key);
            return c ? c>0 : a.shard>b.shard;
        }
    };
    std::vector<std::deque<Item>> buffers(count);
    std::atomic<bool> cancel(false);
    std::atomic<size_t> finished(0);
    std::mutex errorMutex,doneMutex;
    std::condition_variable done;
    std::exception_ptr failure;
    std::vector<std::thread> threads;
    threads.reserve(count);
    auto join = [&] { for(auto &thread:threads) if(thread.joinable()) thread.join(); };
    auto check = [&] {
        if(cancel.load()) {
            std::lock_guard<std::mutex> lock(errorMutex);
            if(failure) std::rethrow_exception(failure);
            throw std::runtime_error("startup guts cancelled");
        }
    };
    try {
        for(size_t i=0;i<count;++i) threads.emplace_back([&,i] {
            try {
                produce(i,[&](std::string key,std::unique_ptr<T> value) {
                    if(cancel.load()) throw std::runtime_error("startup guts cancelled");
                    buffers[i].push_back(Item{std::move(key),std::move(value)});
                });
            } catch(...) {
                { std::lock_guard<std::mutex> lock(errorMutex);
                  if(!failure) failure=std::current_exception(); }
                cancel.store(true);
            }
            ++finished;done.notify_one();
        });
        {
            std::unique_lock<std::mutex> lock(doneMutex);
            while(finished.load()!=count) {
                done.wait_for(lock,std::chrono::milliseconds(50));
                boost::this_thread::interruption_point();check();
            }
        }
        join();check(); // publishes owned results; all iterators already destroyed
        std::priority_queue<Head,std::vector<Head>,Later> heap;
        auto next = [&](size_t i) {
            if(!buffers[i].empty()) heap.push(Head{buffers[i].front().key,i});
        };
        for(size_t i=0;i<count;++i) next(i);
        while(!heap.empty()) {
            boost::this_thread::interruption_point();
            auto head=heap.top();heap.pop();
            auto &buffer=buffers[head.shard];
            auto value=std::move(buffer.front().value);buffer.pop_front();
            commit(head.key,std::move(value));
            next(head.shard);
        }
    } catch(...) { cancel.store(true);join();throw; }
}
#endif
