// StartupChainProof gtest suite: ports the CORRECTED core logic of the dormant
// src/test/pow_tests.cpp startup_chainproof_* cases to the ACTIVE komodo-test
// gtest runner (test-komodo/main.cpp: sodium + ECC init, REGTEST default).
//
// Production function NOT yet implemented. These tests intentionally fail at
// LINK time (undefined reference) = RED build until parent implements it.
//
// Contract: returns PER-BLOCK GetBlockProof(*sorted[begin+i].second) for
// [begin, begin+count); each element has nHeight == 0, NOT cumulative.
// ---------------------------------------------------------------------------
#include <stdexcept>
#include <vector>
#include <utility>

#include "chainparams.h"
#include "gtest/gtest.h"
#include "crypto/verus_hash.h"
#include <mutex>
#include "pow.h"
#include "primitives/block.h"

extern std::vector<CChainPower> ComputeStartupBlockProofs(const std::vector<std::pair<int,CBlockIndex*> >& sorted, size_t begin, size_t count, size_t requestedThreads);

namespace {

// Caller-owned hashes must outlive the blocks (phashBlock points into them):
// allocate BEFORE the blocks and assign stable addresses. nBits cycled through
// {a,b,c} so callers can inject zero/negative/overflow compact targets.
// GetBlockHeader() copies/decompresses the solution; an empty solution is
// valid here (empty CCompactSolutionVector permitted).
void MakeStartupChain(std::vector<CBlockIndex>& blocks, std::vector<uint256>& hashes, int32_t startHeight,
                      uint32_t nBitsA, uint32_t nBitsB, uint32_t nBitsC)
{
    hashes.resize(blocks.size());
    for (size_t i = 0; i < blocks.size(); i++)
    {
        hashes[i].SetHex(strprintf("%064llx", (unsigned long long)i + 1));
        blocks[i].phashBlock = &hashes[i];
        blocks[i].pprev = i ? &blocks[i - 1] : NULL;
        blocks[i].SetHeight(startHeight + (int32_t)i);
        blocks[i].nTime = 1600000000 + 60 * (int32_t)i;
        blocks[i].nVersion = CBlockHeader::CURRENT_VERSION;
        blocks[i].nNonce = uint256();
        blocks[i].nBits = (i % 3 == 0) ? nBitsA : ((i % 3 == 1) ? nBitsB : nBitsC);
        CChainPower cp = CChainPower(&blocks[i]);
        if (i)
            cp += blocks[i - 1].chainPower;
        cp += GetBlockProof(blocks[i]);
        blocks[i].chainPower = cp;
    }
}

void RebuildChainPower(std::vector<CBlockIndex>& blocks)
{
    for (size_t i = 0; i < blocks.size(); i++)
    {
        CChainPower cp = CChainPower(&blocks[i]);
        if (i)
            cp += blocks[i - 1].chainPower;
        cp += GetBlockProof(blocks[i]);
        blocks[i].chainPower = cp;
    }
}

std::vector<std::pair<int,CBlockIndex*> > MakeSorted(std::vector<CBlockIndex>& blocks, int32_t startHeight)
{
    std::vector<std::pair<int,CBlockIndex*> > sorted;
    sorted.reserve(blocks.size());
    for (size_t i = 0; i < blocks.size(); i++)
        sorted.push_back(std::make_pair(startHeight + (int32_t)i, &blocks[i]));
    return sorted;
}

std::vector<CChainPower> SerialExpected(const std::vector<CBlockIndex>& blocks)
{
    std::vector<CChainPower> expected;
    expected.reserve(blocks.size());
    for (size_t i = 0; i < blocks.size(); i++)
        expected.push_back(GetBlockProof(blocks[i]));
    return expected;
}

// Exact scalar comparisons (operator== is ratio-based/lossy), plus nHeight==0.
void CheckMatchesSerial(const std::vector<CChainPower>& got,
                        const std::vector<CChainPower>& expected,
                        size_t begin, size_t count)
{
    ASSERT_LE(count, expected.size());
    ASSERT_LE(begin + count, expected.size());
    ASSERT_EQ(got.size(), count);
    for (size_t i = 0; i < count; i++)
    {
        EXPECT_TRUE(got[i].chainWork == expected[begin + i].chainWork) << "i=" << i;
        EXPECT_TRUE(got[i].chainStake == expected[begin + i].chainStake) << "i=" << i;
        EXPECT_EQ((int)got[i].nHeight, 0) << "i=" << i;
        EXPECT_EQ((int)expected[begin + i].nHeight, 0) << "i=" << i;
    }
}

} // anonymous namespace

static std::once_flag g_verusHashInitFlag;

class StartupChainProof : public ::testing::Test {
protected:
    void SetUp() override
    {
        std::call_once(g_verusHashInitFlag, []() {
            CVerusHash::init();
            CVerusHashV2::init();
        });
        ASSERT_NE(CVerusHash::haraka512Function, nullptr);
        ASSERT_NE(CVerusHashV2::haraka512Function, nullptr);
        ASSERT_NE(CVerusHashV2::haraka512KeyedFunction, nullptr);
        SelectParams(CBaseChainParams::MAIN);
    }
    void TearDown() override { SelectParams(CBaseChainParams::REGTEST); }
};

TEST_F(StartupChainProof, EmptyAndBounds)
{
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> blocks(8);
    MakeStartupChain(blocks, hashes, 10, 0x207fffff, 0x207fffff, 0x207fffff);
    std::vector<std::pair<int,CBlockIndex*> > sorted = MakeSorted(blocks, 10);

    EXPECT_TRUE(ComputeStartupBlockProofs(sorted, 0, 0, 4).empty());
    EXPECT_TRUE(ComputeStartupBlockProofs(sorted, sorted.size(), 0, 4).empty());
    EXPECT_THROW(ComputeStartupBlockProofs(sorted, sorted.size() + 1, 0, 4), std::out_of_range);
    EXPECT_THROW(ComputeStartupBlockProofs(sorted, 3, 6, 4), std::out_of_range); // count > size-begin
    EXPECT_THROW(ComputeStartupBlockProofs(sorted, 7, 2, 4), std::out_of_range);
}

TEST_F(StartupChainProof, ThreadParity)
{
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> blocks(32);
    MakeStartupChain(blocks, hashes, 0, 0x207fffff, 0x1d00ffff, 0x1c05a3f4);
    std::vector<std::pair<int,CBlockIndex*> > sorted = MakeSorted(blocks, 0);
    std::vector<CChainPower> expected = SerialExpected(blocks);

    size_t threads[] = {1, 2, 4, 8, 32};
    for (size_t t = 0; t < 5; t++)
        CheckMatchesSerial(ComputeStartupBlockProofs(sorted, 0, sorted.size(), threads[t]), expected, 0, sorted.size());

    // subranges and count < requestedThreads
    CheckMatchesSerial(ComputeStartupBlockProofs(sorted, 5, 7, 3), expected, 5, 7);
    CheckMatchesSerial(ComputeStartupBlockProofs(sorted, 0, 3, 8), expected, 0, 3);
    CheckMatchesSerial(ComputeStartupBlockProofs(sorted, 15, 1, 4), expected, 15, 1);
}

TEST_F(StartupChainProof, InvalidTargets)
{
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> blocks(12);
    // cycle: valid, overflow (0xffffffff), negative (0x81800000), explicit zero
    MakeStartupChain(blocks, hashes, 1000, 0x207fffff, 0xffffffff, 0x81800000);
    for (size_t i = 3; i < blocks.size(); i += 4)
        blocks[i].nBits = 0x00000000;
    RebuildChainPower(blocks);
    std::vector<std::pair<int,CBlockIndex*> > sorted = MakeSorted(blocks, 1000);
    std::vector<CChainPower> expected = SerialExpected(blocks);

    EXPECT_TRUE(GetBlockProof(blocks[1]).chainWork == arith_uint256(0));
    EXPECT_TRUE(GetBlockProof(blocks[2]).chainWork == arith_uint256(0));
    EXPECT_TRUE(GetBlockProof(blocks[3]).chainWork == arith_uint256(0));
    EXPECT_TRUE(GetBlockProof(blocks[3]).chainStake == arith_uint256(0));
    CheckMatchesSerial(ComputeStartupBlockProofs(sorted, 0, sorted.size(), 4), expected, 0, sorted.size());
}

TEST_F(StartupChainProof, NoMutation)
{
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> blocks(12);
    MakeStartupChain(blocks, hashes, 2000, 0x207fffff, 0x1d00ffff, 0x1c05a3f4);
    std::vector<std::pair<int,CBlockIndex*> > sorted = MakeSorted(blocks, 2000);

    std::vector<int32_t> origHeights;
    std::vector<arith_uint256> origWork, origStake;
    for (size_t i = 0; i < blocks.size(); i++)
    {
        origHeights.push_back(blocks[i].chainPower.nHeight);
        origWork.push_back(blocks[i].chainPower.chainWork);
        origStake.push_back(blocks[i].chainPower.chainStake);
    }
    for (int rep = 0; rep < 3; rep++)
    {
        std::vector<CChainPower> got = ComputeStartupBlockProofs(sorted, 0, sorted.size(), 1 + (size_t)rep);
        ASSERT_EQ(got.size(), blocks.size());
        for (size_t i = 0; i < blocks.size(); i++)
        {
            EXPECT_EQ((int)blocks[i].chainPower.nHeight, (int)origHeights[i]);
            EXPECT_TRUE(blocks[i].chainPower.chainWork == origWork[i]);
            EXPECT_TRUE(blocks[i].chainPower.chainStake == origStake[i]);
        }
    }
}

TEST_F(StartupChainProof, OrderedAccumulation)
{
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> blocks(12);
    MakeStartupChain(blocks, hashes, 2000, 0x207fffff, 0x1d00ffff, 0x1c05a3f4);
    std::vector<std::pair<int,CBlockIndex*> > sorted = MakeSorted(blocks, 2000);
    std::vector<CChainPower> got = ComputeStartupBlockProofs(sorted, 0, sorted.size(), 4);
    ASSERT_EQ(got.size(), blocks.size());

    // same recurrence as production: cp = CChainPower(&block) [+ previous
    // cumulative] += own proof. Consume got[i] (per-block proof), never
    // previous block proof, never reset accumulator without readding previous.
    CChainPower acc = CChainPower(&blocks[0]);
    acc += got[0];
    EXPECT_TRUE(acc.chainWork == blocks[0].chainPower.chainWork);
    EXPECT_TRUE(acc.chainStake == blocks[0].chainPower.chainStake);
    EXPECT_EQ((int)acc.nHeight, (int)blocks[0].chainPower.nHeight);
    for (size_t i = 1; i < got.size(); i++)
    {
        const CChainPower previous = acc;
        acc = CChainPower(&blocks[i]);
        acc += previous;
        acc += got[i];
        EXPECT_TRUE(acc.chainWork == blocks[i].chainPower.chainWork) << "i=" << i;
        EXPECT_TRUE(acc.chainStake == blocks[i].chainPower.chainStake) << "i=" << i;
        EXPECT_EQ((int)acc.nHeight, (int)blocks[i].chainPower.nHeight) << "i=" << i;
    }
}

// RAII: restore SAPLING activation height on every exit (incl. ASSERT return).
class SaplingActivationGuard
{
public:
    SaplingActivationGuard()
        : oldHeight(Params().GetConsensus().vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight) {}
    ~SaplingActivationGuard() { UpdateNetworkUpgradeParameters(Consensus::UPGRADE_SAPLING, oldHeight); }
private:
    int32_t oldHeight;
};

TEST_F(StartupChainProof, PosParity)
{
    SelectParams(CBaseChainParams::REGTEST);
    SaplingActivationGuard saplingGuard;
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_SAPLING, 0); // active from genesis
    const int32_t h0 = 1;
    ASSERT_TRUE(Params().GetConsensus().NetworkUpgradeActive(h0, Consensus::UPGRADE_SAPLING));
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> blocks(8);
    MakeStartupChain(blocks, hashes, h0, 0x207fffff, 0x207fffff, 0x207fffff);

    // real nonce APIs: CPOSNonce version + SetVerusPOSTarget
    size_t posIdx[] = {1, 3, 6};
    for (size_t k = 0; k < 3; k++)
    {
        CBlockHeader hdr = blocks[posIdx[k]].GetBlockHeader();
        hdr.nVersion = CPOSNonce::VERUS_V2;
        hdr.SetVerusPOSTarget(0x2055aa22);
        blocks[posIdx[k]].nVersion = hdr.nVersion;
        blocks[posIdx[k]].nNonce = hdr.nNonce;
    }
    RebuildChainPower(blocks);

    for (size_t k = 0; k < 3; k++)
    {
        ASSERT_TRUE(blocks[posIdx[k]].IsVerusPOSBlock()) << "k=" << k;
        ASSERT_TRUE(GetBlockProof(blocks[posIdx[k]]).chainStake > arith_uint256(0)) << "k=" << k;
    }

    std::vector<std::pair<int,CBlockIndex*> > sorted = MakeSorted(blocks, h0);
    std::vector<CChainPower> expected = SerialExpected(blocks);
    CheckMatchesSerial(ComputeStartupBlockProofs(sorted, 0, sorted.size(), 1), expected, 0, sorted.size());
    CheckMatchesSerial(ComputeStartupBlockProofs(sorted, 0, sorted.size(), 4), expected, 0, sorted.size());
}

// ---------------------------------------------------------------------------
// ChainPowerExact gtest suite (APPENDED below the StartupChainProof tests,
// which are preserved unchanged).
//
// Frozen legacy oracle: an independent, literal re-statement of the ORIGINAL
// CChainPower comparison arithmetic (pre-optimization, original comparison
// policy). This is a semantics-preserving optimization, so equivalence vs the
// oracle is EXPECTED to PASS on the baseline -- no functional RED is
// fabricated.
//
// Coverage: all six relation outcomes (==/!=, </>=, <=/>) across:
//   - 12000 deterministic random fast-domain pairs (<=112-bit domain)
//   - 3000 deterministic random full-256-bit pairs
//   - dense boundary values at bits {0,1,16,32,64,80,96,111,112,113,127,128,
//     239,240,241,255}, max-256, exact ties, zeros, one-apart ratios and
//     rounded ties (differing only below the 16-bit truncation)
//   - the synthetic nontransitive triple A/B/C: production outcomes must
//     equal oracle outcomes exactly (behavior preserved, not "fixed").
//
// Bounded microbenchmark: inputs built OUTSIDE the timed loop, volatile
// checksum prevents elision, fast-path and fallback-path reported separately,
// NO speed threshold assertions (no flaky CI). Fixed seed; runtime/memory
// bounded and small.
// ---------------------------------------------------------------------------
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

#include "chain.h"

namespace {

// ----- frozen legacy oracle (original literal arithmetic) -------------------

arith_uint256 OracleDivisor(const arith_uint256 &a, const arith_uint256 &b)
{
    arith_uint256 bigZero = arith_uint256(0);
    return a > b ? a : (b != bigZero ? b : 1);
}

arith_uint256 OracleSum(const arith_uint256 &work, const arith_uint256 &stake,
                        const arith_uint256 &workDiv, const arith_uint256 &stakeDiv)
{
    return ((work << 16) / workDiv) + ((stake << 16) / stakeDiv);
}

bool OracleEq(const arith_uint256 &w1, const arith_uint256 &s1,
              const arith_uint256 &w2, const arith_uint256 &s2)
{
    arith_uint256 wd = OracleDivisor(w1, w2);
    arith_uint256 sd = OracleDivisor(s1, s2);
    return OracleSum(w1, s1, wd, sd) == OracleSum(w2, s2, wd, sd);
}

bool OracleLt(const arith_uint256 &w1, const arith_uint256 &s1,
              const arith_uint256 &w2, const arith_uint256 &s2)
{
    arith_uint256 wd = OracleDivisor(w1, w2);
    arith_uint256 sd = OracleDivisor(s1, s2);
    return OracleSum(w1, s1, wd, sd) < OracleSum(w2, s2, wd, sd);
}

bool OracleLe(const arith_uint256 &w1, const arith_uint256 &s1,
              const arith_uint256 &w2, const arith_uint256 &s2)
{
    arith_uint256 wd = OracleDivisor(w1, w2);
    arith_uint256 sd = OracleDivisor(s1, s2);
    return OracleSum(w1, s1, wd, sd) <= OracleSum(w2, s2, wd, sd);
}

// ----- helpers --------------------------------------------------------------

CChainPower MakeCP(const arith_uint256 &stake, const arith_uint256 &work)
{
    static CBlockIndex scratch;
    return CChainPower(&scratch, stake, work);
}

// Checks production operators against the oracle for ALL SIX relation
// outcomes of one pair.
void CheckSixRelations(const char *what, const arith_uint256 &w1, const arith_uint256 &s1,
                       const arith_uint256 &w2, const arith_uint256 &s2)
{
    CChainPower p1 = MakeCP(s1, w1);
    CChainPower p2 = MakeCP(s2, w2);
    bool eqO = OracleEq(w1, s1, w2, s2);
    bool ltO = OracleLt(w1, s1, w2, s2);
    bool leO = OracleLe(w1, s1, w2, s2);
    ASSERT_EQ(eqO, p1 == p2) << what;
    ASSERT_EQ(!eqO, p1 != p2) << what;
    ASSERT_EQ(ltO, p1 < p2) << what;
    ASSERT_EQ(leO, p1 <= p2) << what;
    // header defines > as !(p1<=p2) and >= as !(p1<p2)
    ASSERT_EQ(!leO, p1 > p2) << what;
    ASSERT_EQ(!ltO, p1 >= p2) << what;
}

const uint64_t kChainPowerExactSeed = 0x5eed1234abcd9876ull;

arith_uint256 Random256(std::mt19937_64 &rng)
{
    static const char *hex = "0123456789abcdef";
    char buf[65];
    for (int i = 0; i < 64; i++)
        buf[i] = hex[(rng() >> (rng() % 4)) & 15];
    buf[64] = 0;
    arith_uint256 r;
    r.SetHex(buf);
    return r;
}

// Value with exactly nbits bits (bit nbits-1 set, lower bits random), 0
// yields zero. nbits==256 yields all-ones.
arith_uint256 WithBits(unsigned nbits, std::mt19937_64 &rng)
{
    if (nbits == 0)
        return arith_uint256(0);
    if (nbits >= 256)
        return Random256(rng) | ~(arith_uint256(0) ^ arith_uint256(0)); // all ones via OR of self
    arith_uint256 top = arith_uint256(1) << (unsigned int)(nbits - 1);
    arith_uint256 lowMask = top - arith_uint256(1); // 2^(nbits-1)-1
    return top | (Random256(rng) & lowMask);
}

} // anonymous namespace

// ----- tests ----------------------------------------------------------------

class ChainPowerExact : public ::testing::Test
{
protected:
    void TearDown() override { SelectParams(CBaseChainParams::REGTEST); }
};

TEST_F(ChainPowerExact, RandomFastDomainRelations)
{
    std::mt19937_64 rng(kChainPowerExactSeed);
    const size_t kPairs = 12000;
    for (size_t i = 0; i < kPairs; i++)
    {
        arith_uint256 w1((uint64_t)rng()), w2((uint64_t)rng());
        arith_uint256 s1((uint64_t)rng()), s2((uint64_t)rng());
        CheckSixRelations("fast-domain random", w1, s1, w2, s2);
        // also include some 112-bit-boundary domain values
        arith_uint256 b1 = WithBits(112, rng), b2 = WithBits(111, rng);
        arith_uint256 c1 = WithBits(112, rng), c2 = WithBits(1, rng);
        CheckSixRelations("fast-domain 112-bit", b1, c1, b2, c2);
    }
    SUCCEED();
}

TEST_F(ChainPowerExact, RandomFullWidthRelations)
{
    std::mt19937_64 rng(kChainPowerExactSeed ^ 0x9e3779b97f4a7c15ull);
    const size_t kPairs = 3000;
    for (size_t i = 0; i < kPairs; i++)
    {
        arith_uint256 w1 = Random256(rng), w2 = Random256(rng);
        arith_uint256 s1 = Random256(rng), s2 = Random256(rng);
        CheckSixRelations("full-256 random", w1, s1, w2, s2);
    }
    SUCCEED();
}

TEST_F(ChainPowerExact, DenseBoundaryAndTies)
{
    std::mt19937_64 rng(kChainPowerExactSeed ^ 0xd1b54a32d192ed03ull);
    static const unsigned kBits[] = {0, 1, 16, 32, 64, 80, 96, 111, 112, 113,
                                     127, 128, 239, 240, 241, 255, 256};
    std::vector<arith_uint256> cands;
    for (unsigned i = 0; i < sizeof(kBits) / sizeof(kBits[0]); i++)
    {
        unsigned b = kBits[i];
        cands.push_back(WithBits(b, rng));                 // exactly b bits
        if (b > 0 && b < 256)
        {
            cands.push_back(WithBits(b, rng) - arith_uint256(1)); // b-1 bits
            cands.push_back(WithBits(b, rng) + arith_uint256(1)); // b+1 bits
        }
    }
    cands.push_back(arith_uint256(0));

    // all-pairs over dense boundary set (bounded: ~55 candidates => ~3025 pairs x2)
    for (size_t i = 0; i < cands.size(); i++)
        for (size_t j = 0; j < cands.size(); j++)
        {
            CheckSixRelations("dense boundary", cands[i], cands[j], cands[j], cands[i]);
        }

    // exact ties
    for (size_t i = 0; i < cands.size(); i++)
        CheckSixRelations("exact tie", cands[i], cands[i], cands[i], cands[i]);

    // ratios one apart
    for (size_t i = 1; i + 1 < cands.size(); i++)
        CheckSixRelations("one apart", cands[i], cands[i + 1], cands[i] + arith_uint256(1), cands[i + 1]);

    // rounded ties: values differing by less than divisor/65536 truncate to
    // the same quotient (divisor 2^20 => differences < 16 round identically)
    arith_uint256 d = arith_uint256(1) << 20u;
    arith_uint256 base = d * arith_uint256((uint64_t)1234567);
    for (uint64_t delta = 0; delta < 16; delta++)
        CheckSixRelations("rounded tie", base, base,
                          base + arith_uint256(delta), base + arith_uint256(delta));
    // one step past the rounding boundary must NOT be a rounded tie in general
    CheckSixRelations("rounded tie boundary", base, base,
                      base + arith_uint256((uint64_t)16), base);
    SUCCEED();
}

TEST_F(ChainPowerExact, NontransitiveTripleUnchanged)
{
    // Synthetic nontransitive triple; the comparator is nontransitive for
    // these inputs and ALL of that behavior (including A<B, B<C, A<C
    // whatever the oracle says) MUST stay unchanged.
    arith_uint256 wA((uint64_t)1000000), sA((uint64_t)1000000);
    arith_uint256 wB((uint64_t)1000002), sB((uint64_t)999999);
    arith_uint256 wC((uint64_t)1000001), sC((uint64_t)1000001);
    CheckSixRelations("A vs B", wA, sA, wB, sB);
    CheckSixRelations("B vs C", wB, sB, wC, sC);
    CheckSixRelations("A vs C", wA, sA, wC, sC);
    SUCCEED();
}

TEST_F(ChainPowerExact, MicrobenchmarkFastVsFallback)
{
    std::mt19937_64 rng(kChainPowerExactSeed ^ 0x2545f4914f6cdd1dull);

    const size_t kN = 50000;
    std::vector<CChainPower> fastA, fastB, fbA, fbB;
    fastA.reserve(kN); fastB.reserve(kN); fbA.reserve(kN); fbB.reserve(kN);

    for (size_t i = 0; i < kN; i++)
    {
        // fast path: all components <= 112 bits (guard satisfied)
        fastA.push_back(MakeCP(WithBits(64, rng), WithBits(80, rng)));
        fastB.push_back(MakeCP(WithBits(48, rng), WithBits(112, rng)));
        // fallback: full-width values force the original 256-bit expression
        fbA.push_back(MakeCP(Random256(rng), Random256(rng)));
        fbB.push_back(MakeCP(Random256(rng), Random256(rng)));
    }

    volatile uint64_t sink = 0;
    const size_t kIters = 20;

    auto t0 = std::chrono::steady_clock::now();
    for (size_t it = 0; it < kIters; it++)
        for (size_t i = 0; i < kN; i++)
            sink += (uint64_t)((fastA[i] < fastB[i]) ? 1 : 0) +
                    (uint64_t)((fastA[i] == fastB[i]) ? 2 : 0) +
                    (uint64_t)((fastA[i] <= fastB[i]) ? 4 : 0);
    auto t1 = std::chrono::steady_clock::now();
    double fastNs = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count() /
                    (double)(kIters * kN);

    t0 = std::chrono::steady_clock::now();
    for (size_t it = 0; it < kIters; it++)
        for (size_t i = 0; i < kN; i++)
            sink += (uint64_t)((fbA[i] < fbB[i]) ? 1 : 0) +
                    (uint64_t)((fbA[i] == fbB[i]) ? 2 : 0) +
                    (uint64_t)((fbA[i] <= fbB[i]) ? 4 : 0);
    t1 = std::chrono::steady_clock::now();
    double fbNs = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count() /
                  (double)(kIters * kN);

    std::printf("CHAINPOWER_BENCH fast-path: %.1f ns/op (%zu comparisons x3 relations)\n",
                fastNs, kIters * kN);
    std::printf("CHAINPOWER_BENCH fallback-path: %.1f ns/op (%zu comparisons x3 relations)\n",
                fbNs, kIters * kN);
    std::printf("CHAINPOWER_BENCH sink=%llu\n", (unsigned long long)sink);
    SUCCEED(); // informational only: no speed threshold assertion
}
