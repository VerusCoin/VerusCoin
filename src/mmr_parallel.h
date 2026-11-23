// Exact bottom-up append for the in-memory startup MMR.
#ifndef VERUS_MMR_PARALLEL_H
#define VERUS_MMR_PARALLEL_H
#include "mmr.h"
#include <algorithm>
#include <exception>
#include <mutex>
#include <thread>

// No container structural changes occur while workers are running. Propagate
// worker failures after joining, including a partial thread-launch failure.
template <typename F>
void MMRParallelFor(size_t count, size_t workers, F fn)
{
    workers = std::min(count, std::max(size_t(1), workers));
    if (workers <= 1 || count < 1024)
    {
        for (size_t i = 0; i < count; ++i) fn(i);
        return;
    }
    std::vector<std::thread> threads;
    std::exception_ptr failure;
    std::mutex failureMutex;
    try
    {
        for (size_t w = 0; w < workers; ++w)
            threads.emplace_back([&, w] {
                try {
                    for (size_t i = count * w / workers; i < count * (w + 1) / workers; ++i)
                        fn(i);
                } catch (...) {
                    std::lock_guard<std::mutex> lock(failureMutex);
                    if (!failure) failure = std::current_exception();
                }
            });
    }
    catch (...) { for (auto &t : threads) t.join(); throw; }
    for (auto &t : threads) t.join();
    if (failure) std::rethrow_exception(failure);
}

// The unchanged prefix and its parents are retained. Complete pairs only:
// level k contains floor(totalLeaves / 2^(k+1)) nodes, exactly as Add does.
// CChain's layer0 is an OVERLAY, not a CChunkedLayer: pushing only advances
// its size; the temporary leaves prevent hashing modified blocks twice.
template <typename NODE, typename LAYER, typename LEAVES>
void AppendMMRParallel(CMerkleMountainRange<NODE, LAYER, LEAVES> &mmr,
                       const std::vector<NODE> &leaves, size_t workers)
{
    const size_t begin = mmr.size();
    const size_t total = begin + leaves.size();
    for (const auto &leaf : leaves) mmr.layer0.push_back(leaf);
    size_t level = 0;
    for (size_t belowSize = total; belowSize > 1; belowSize >>= 1, ++level)
    {
        if (mmr.upperNodes.size() <= level) mmr.upperNodes.resize(level + 1);
        const size_t oldSize = mmr.upperNodes[level].size();
        const size_t newSize = belowSize >> 1;
        std::vector<NODE> parents(newSize - oldSize);
        MMRParallelFor(parents.size(), workers, [&](size_t i) {
            const size_t left = 2 * (oldSize + i);
            if (level)
                parents[i] = mmr.upperNodes[level - 1][left].CreateParentNode(
                             mmr.upperNodes[level - 1][left + 1]);
            else
            {
                const NODE a = left < begin ? mmr.layer0[left] : leaves[left - begin];
                const NODE b = left + 1 < begin ? mmr.layer0[left + 1] : leaves[left + 1 - begin];
                parents[i] = a.CreateParentNode(b);
            }
        });
        if (!parents.empty())
        {
            // CChunkedLayer::resize shrinks its logical size but can retain
            // stale entries in the last chunk. Never append into that chunk
            // after Truncate: repack the retained prefix into a fresh layer.
            LAYER rebuilt;
            for (size_t i = 0; i < oldSize; ++i) rebuilt.push_back(mmr.upperNodes[level][i]);
            for (const auto &parent : parents) rebuilt.push_back(parent);
            mmr.upperNodes[level] = std::move(rebuilt);
        }
    }
}
#endif
