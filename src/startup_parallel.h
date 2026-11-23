// startup_parallel.h — minimal C++11 parallel range executor.
// verus_startup::ParallelForRanges(count, requestedThreads, fn(begin,end))
//
// Contract:
//  - count==0: fn never invoked. requestedThreads<=1 (or count small): ONE
//    serial callback covering [0,count) on the caller thread.
//  - Parallel path: contiguous non-overlapping ranges partitioning [0,count)
//    exactly; workers clamped to count and hard-capped at 32.
//  - fn must be thread-safe and may write DISTINCT slots of an externally
//    pre-sized vector. Join barrier: all workers finish before this returns,
//    so ranges referencing caller-owned data are safe only while that data
//    outlives the call (threads must finish before referenced data destroyed).
//  - Exceptions: all workers are joined first, then the first captured
//    std::exception_ptr is rethrown on the caller. Never swallowed, never
//    std::terminate. If a partial failure occurs, do NOT consume results.
//  - No global state, no queues, no busy waiting, no consensus/db access.
#ifndef VERUS_STARTUP_PARALLEL_H
#define VERUS_STARTUP_PARALLEL_H
#include <cstddef>
#include <exception>
#include <mutex>
#include <thread>
#include <vector>

namespace verus_startup {

static const size_t kMaxWorkers = 32;

template <class Fn>
inline void ParallelForRanges(size_t count, size_t requestedThreads, Fn fn) {
    if (count == 0) return;
    if (requestedThreads <= 1) { fn(0, count); return; }

    size_t workers = requestedThreads < count ? requestedThreads : count;
    if (workers > kMaxWorkers) workers = kMaxWorkers;
    if (workers <= 1) { fn(0, count); return; }

    std::vector<std::thread> threads;
    threads.reserve(workers);
    std::mutex exMutex;
    std::exception_ptr firstException;

    try {
        const size_t per = count / workers;
        const size_t rem = count % workers;
        size_t begin = 0;
        for (size_t w = 0; w < workers; ++w) {
            const size_t len = per + (w < rem ? 1 : 0);
            const size_t end = begin + len;
            threads.push_back(std::thread([begin, end, &fn, &exMutex, &firstException]() {
                try {
                    fn(begin, end);
                } catch (...) {
                    std::lock_guard<std::mutex> lock(exMutex);
                    if (!firstException) firstException = std::current_exception();
                }
            }));
            begin = end;
        }
    } catch (...) {
        // std::thread creation failed: join what we started, propagate.
        for (size_t i = 0; i < threads.size(); ++i)
            if (threads[i].joinable()) threads[i].join();
        throw;
    }

    for (size_t i = 0; i < threads.size(); ++i)
        if (threads[i].joinable()) threads[i].join();

    if (firstException) std::rethrow_exception(firstException);
}

} // namespace verus_startup
#endif
