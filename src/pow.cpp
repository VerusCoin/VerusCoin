// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "pow.h"
#include "consensus/upgrades.h"

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "crypto/equihash.h"
#include "primitives/block.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"

#include "sodium.h"

#ifdef ENABLE_RUST
#include "librustzcash.h"
#endif // ENABLE_RUST
uint32_t komodo_chainactive_timestamp();
int64_t komodo_current_supply(uint32_t nHeight);

extern uint32_t ASSETCHAINS_ALGO, ASSETCHAINS_EQUIHASH, ASSETCHAINS_VERUSHASH, ASSETCHAINS_STAKED, ASSETCHAINS_LWMAPOS, ASSETCHAINS_STARTING_DIFF;
extern char ASSETCHAINS_SYMBOL[65];
extern int32_t VERUS_BLOCK_POSUNITS, VERUS_CONSECUTIVE_POS_THRESHOLD, VERUS_PBAAS_CONSECUTIVE_POS_THRESHOLD, VERUS_NOPOS_THRESHHOLD, VERUS_PBAAS_NOPOS_THRESHHOLD;
unsigned int lwmaGetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params);
unsigned int lwmaCalculateNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    if (ASSETCHAINS_ALGO != ASSETCHAINS_EQUIHASH)
        return lwmaGetNextWorkRequired(pindexLast, pblock, params);

    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    // Genesis block
    if (pindexLast == NULL )
        return nProofOfWorkLimit;

    //{
        // Comparing to pindexLast->nHeight with >= because this function
        // returns the work required for the block after pindexLast.
        //if (params.nPowAllowMinDifficultyBlocksAfterHeight != boost::none &&
        //    pindexLast->nHeight >= params.nPowAllowMinDifficultyBlocksAfterHeight.get())
        //{
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 6 * block interval minutes
            // then allow mining of a min-difficulty block.
        //    if (pblock && pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 6)
        //        return nProofOfWorkLimit;
        //}
    //}

    // Find the first block in the averaging interval
    const CBlockIndex* pindexFirst = pindexLast;
    arith_uint256 bnTot {0};
    for (int i = 0; pindexFirst && i < params.nPowAveragingWindow; i++) {
        arith_uint256 bnTmp;
        bnTmp.SetCompact(pindexFirst->nBits);
        bnTot += bnTmp;
        pindexFirst = pindexFirst->pprev;
    }

    // Check we have enough blocks
    if (pindexFirst == NULL)
        return nProofOfWorkLimit;

    arith_uint256 bnAvg {bnTot / params.nPowAveragingWindow};

    return CalculateNextWorkRequired(bnAvg,
                                     pindexLast->GetMedianTimePast(), pindexFirst->GetMedianTimePast(),
                                     params,
                                     pindexLast->GetHeight() + 1);
}

unsigned int CalculateNextWorkRequired(arith_uint256 bnAvg,
                                       int64_t nLastBlockTime, int64_t nFirstBlockTime,
                                       const Consensus::Params& params,
                                       int nextHeight)
{
    int64_t averagingWindowTimespan = params.AveragingWindowTimespan();
    int64_t minActualTimespan = params.MinActualTimespan();
    int64_t maxActualTimespan = params.MaxActualTimespan();
    // Limit adjustment step
    // Use medians to prevent time-warp attacks
    int64_t nActualTimespan = nLastBlockTime - nFirstBlockTime;
    LogPrint("pow", "  nActualTimespan = %d  before dampening\n", nActualTimespan);
    nActualTimespan = averagingWindowTimespan + (nActualTimespan - averagingWindowTimespan)/4;
    LogPrint("pow", "  nActualTimespan = %d  before bounds\n", nActualTimespan);

    if (nActualTimespan < minActualTimespan) {
        nActualTimespan = minActualTimespan;
    }
    if (nActualTimespan > maxActualTimespan) {
        nActualTimespan = maxActualTimespan;
    }

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew {bnAvg};
    bnNew /= averagingWindowTimespan;
    bnNew *= nActualTimespan;

    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }

    /// debug print
    LogPrint("pow", "GetNextWorkRequired RETARGET\n");
    LogPrint("pow", "params.AveragingWindowTimespan(%d) = %d    nActualTimespan = %d\n", nextHeight, averagingWindowTimespan, nActualTimespan);
    LogPrint("pow", "Current average: %08x  %s\n", bnAvg.GetCompact(), bnAvg.ToString());
    LogPrint("pow", "After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
}

unsigned int lwmaGetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    return lwmaCalculateNextWorkRequired(pindexLast, params);
}

unsigned int lwmaCalculateNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    arith_uint256 nextTarget {0}, sumTarget {0}, bnTmp, bnLimit, bnDefault;
    if (_IsVerusMainnetActive() && pindexLast && pindexLast->GetHeight() <= 1568100 && pindexLast->GetHeight() >= 1567999)
    {
        arith_uint256 maxDiffAdjust = UintToArith256(uint256S("00000000000f0f0f000000000000000000000000000000000000000000000000"));
        return maxDiffAdjust.GetCompact();
    }

    int32_t nHeight = pindexLast ? pindexLast->GetHeight() : 0;
    bool isPBaaS = CConstVerusSolutionVector::activationHeight.ActiveVersion(nHeight + 1) >= CActivationHeight::ACTIVATE_PBAAS;

    if (ASSETCHAINS_ALGO == ASSETCHAINS_EQUIHASH)
    {
        bnLimit = UintToArith256(params.powLimit);
        bnDefault = bnLimit;
    }
    else
    {
        bnLimit = UintToArith256(params.powAlternate);
        if (isPBaaS)
        {
            bnDefault.SetCompact(ASSETCHAINS_STARTING_DIFF);
            bnLimit = UintToArith256(uint256S("000000ff0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"));
        }
        else
        {
            bnDefault = bnLimit;
        }
    }

    // Find the first block in the averaging interval as we total the linearly weighted average
    const CBlockIndex* pindexFirst = pindexLast;
    const CBlockIndex* pindexNext;
    int64_t t = 0, solvetime, k = params.nLwmaAjustedWeight, N = params.nPowAveragingWindow;

    // if changing from VerusHash V1 to V2, shift the last blocks by the same shift as the limit
    int targetShift = 0;
    uint32_t height = pindexLast->GetHeight() + 1;

    if (_IsVerusMainnetActive() && CConstVerusSolutionVector::activationHeight.ActiveVersion(height) >= CConstVerusSolutionVector::activationHeight.SOLUTION_VERUSV2)
    {
        targetShift = VERUSHASH2_SHIFT;
        bnLimit <<= targetShift;
    }

    for (int i = 0, j = N - 1; pindexFirst && i < N; i++, j--) {
        pindexNext = pindexFirst;
        pindexFirst = pindexFirst->pprev;
        if (!pindexFirst)
            break;

        solvetime = pindexNext->GetBlockTime() - pindexFirst->GetBlockTime();

        // weighted sum
        t += solvetime * j;

        // Target sum divided by a factor, (k N^2).
        // The factor is a part of the final equation. However we divide
        // here to avoid potential overflow.
        bnTmp.SetCompact(pindexNext->nBits);
        if (targetShift && !(CConstVerusSolutionVector::activationHeight.ActiveVersion(pindexNext->GetHeight()) > CConstVerusSolutionVector::activationHeight.SOLUTION_VERUSV1))
        {
            bnTmp <<= targetShift;
        }
        sumTarget += bnTmp / (k * N * N);
    }

    // Check we have enough blocks
    if (!pindexFirst)
    {
        if (isPBaaS)
        {
            return bnDefault.GetCompact();
        }
        else
        {
            return bnLimit.GetCompact();
        }
    }

    // Keep t reasonable in case strange solvetimes occurred.
    if (t < N * k / 3)
        t = N * k / 3;

    bnTmp = bnLimit;
    nextTarget = t * sumTarget;
    if (nextTarget > bnTmp)
        nextTarget = bnTmp;

    return nextTarget.GetCompact();
}

// the goal is to keep POS at a solve time that is a ratio of block time units. the low resolution makes a stable solution more challenging
// and requires that the averaging window be quite long.
uint32_t lwmaGetNextPOSRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    arith_uint256 nextTarget {0}, sumTarget {0}, bnTmp, bnLimit;

    int64_t t = 0, solvetime = 0;
    int64_t k = params.nLwmaPOSAjustedWeight;
    int64_t N = params.nPOSAveragingWindow;

    int32_t nHeight = pindexLast->GetHeight();

    int32_t maxConsecutivePos = VERUS_CONSECUTIVE_POS_THRESHOLD;
    int32_t maxConsecutiveNoPos = VERUS_NOPOS_THRESHHOLD;
    int32_t nProofOfWorkBlockPOSUnits = VERUS_BLOCK_POSUNITS;

    bnLimit = UintToArith256(params.posLimit);
    uint32_t nProofOfStakeDefault = bnLimit.GetCompact();

    if (CConstVerusSolutionVector::activationHeight.ActiveVersion(nHeight + 1) >= CActivationHeight::ACTIVATE_PBAAS)
    {
        maxConsecutivePos = VERUS_PBAAS_CONSECUTIVE_POS_THRESHOLD;
        maxConsecutiveNoPos = VERUS_PBAAS_NOPOS_THRESHHOLD;

        // due to constraining maximum consecutive PoS blocks, we use this bias to adjust to 50%
        if (PBAAS_TESTMODE && pindexLast->nTime < PBAAS_TESTFORK_TIME)
        {
            nProofOfWorkBlockPOSUnits += (VERUS_BLOCK_POSUNITS / 20);
        }
        else
        {
            nProofOfWorkBlockPOSUnits += (VERUS_BLOCK_POSUNITS / 10);
        }

        // the default staking difficulty is based on an expectation of 25% of the supply staking, which if facing 100%, will not be catastrophic
        // neither will it be impossible to adapt if only 1/64th or even less is staking, though it will take longer to get to an equilibrium.
        arith_uint256 fiftyPercentPerSatoshi = UintToArith256(uint256S("7f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"));
        uint64_t supplyDivisor = nHeight ? komodo_current_supply(nHeight) : MAX_MONEY;

        // default is if 1/4th of expected max supply is staking
        supplyDivisor = ((supplyDivisor >> 2) == 0) ? 1 : supplyDivisor >> 2;
        nProofOfStakeDefault = ((arith_uint256)(fiftyPercentPerSatoshi / supplyDivisor)).GetCompact();

        // the lowest 50% equilibrium we can achieve is if one millionth of expected max supply is staking,
        // set that as the lower difficulty limit
        supplyDivisor = ((supplyDivisor >> 16) == 0) ? 1 : supplyDivisor >> 16;
        bnLimit = fiftyPercentPerSatoshi / supplyDivisor;
    }
    else if (_IsVerusMainnetActive() && pindexLast && pindexLast->GetHeight() >= 1567999)
    {
        bnLimit = UintToArith256(uint256S("00000000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"));
        nProofOfStakeDefault = bnLimit.GetCompact();
    }

    struct solveSequence {
        int64_t solveTime;
        bool consecutive;
        uint32_t nBits;
        solveSequence()
        {
            consecutive = 0;
            solveTime = 0;
            nBits = 0;
        }
    };

    // Find the first block in the averaging interval as we total the linearly weighted average
    // of POS solve times
    const CBlockIndex* pindexFirst = pindexLast;

    // we need to make sure we have a starting nBits reference, which is either the last POS block, or the default
    // if we have had no POS block in the threshold number of blocks, we must return the default, otherwise, we'll now have
    // a starting point
    uint32_t nBits = nProofOfStakeDefault;
    for (int64_t i = 0; i < maxConsecutiveNoPos; i++)
    {
        if (!pindexFirst)
        {
            return nProofOfStakeDefault;
        }

        CBlockHeader hdr = pindexFirst->GetBlockHeader();

        if (hdr.IsVerusPOSBlock())
        {
            nBits = hdr.GetVerusPOSTarget();
            break;
        }
        pindexFirst = pindexFirst->pprev;
    }

    pindexFirst = pindexLast;
    std::vector<solveSequence> idx = std::vector<solveSequence>();
    idx.resize(N);

    for (int64_t i = N - 1; i >= 0; i--)
    {
        // we measure our solve time in passing of blocks, where one bock == VERUS_BLOCK_POSUNITS units
        // consecutive blocks in either direction have their solve times exponentially multiplied or divided by power of 2
        int x;
        for (x = 0; x < maxConsecutivePos; x++)
        {
            pindexFirst = pindexFirst->pprev;

            if (!pindexFirst)
            {
                return nProofOfStakeDefault;
            }

            CBlockHeader hdr = pindexFirst->GetBlockHeader();
            if (hdr.IsVerusPOSBlock())
            {
                nBits = hdr.GetVerusPOSTarget();
                break;
            }
        }

        if (x)
        {
            idx[i].consecutive = false;
            if (_IsVerusMainnetActive() && nHeight < 67680)
            {
                idx[i].solveTime = nProofOfWorkBlockPOSUnits * (x + 1);
            }
            else
            {
                int64_t lastSolveTime = 0;
                idx[i].solveTime = nProofOfWorkBlockPOSUnits;
                for (int64_t j = 0; j < x; j++)
                {
                    lastSolveTime = nProofOfWorkBlockPOSUnits + (lastSolveTime >> 1);
                    idx[i].solveTime += lastSolveTime;
                }
            }
            idx[i].nBits = nBits;
        }
        else
        {
            idx[i].consecutive = true;
            idx[i].nBits = nBits;
            // go forward and halve the minimum solve time for all consecutive blocks in this run, to get here, our last block is POS,
            // and if there is no POS block in front of it, it gets the normal solve time of one block
            uint32_t st = VERUS_BLOCK_POSUNITS;
            for (int64_t j = i; j < N; j++)
            {
                if (idx[j].consecutive == true)
                {
                    idx[j].solveTime = st;
                    if ((j - i) >= maxConsecutivePos)
                    {
                        // if this is real time, return zero
                        if (j == (N - 1))
                        {
                            // target of 0 (virtually impossible), if we hit max consecutive POS blocks
                            nextTarget.SetCompact(0);
                            return nextTarget.GetCompact();
                        }
                    }
                    st >>= 1;
                }
                else
                    break;
            }
        }
    }

    for (int64_t i = N - 1; i >= 0; i--)
    {
        // weighted sum
        t += idx[i].solveTime * i;

        // Target sum divided by a factor, (k N^2).
        // The factor is a part of the final equation. However we divide
        // here to avoid potential overflow.
        bnTmp.SetCompact(idx[i].nBits);
        sumTarget += bnTmp / (k * N * N);
    }

    // Keep t reasonable in case strange solvetimes occurred.
    if (t < N * k / 3)
        t = N * k / 3;

    nextTarget = t * sumTarget;
    if (nextTarget > bnLimit)
        nextTarget = bnLimit;

    return nextTarget.GetCompact();
}

bool CheckEquihashSolution(const CBlockHeader *pblock, const Consensus::Params& params)
{
    if (ASSETCHAINS_ALGO != ASSETCHAINS_EQUIHASH)
        return true;

    unsigned int n = params.EquihashN();
    unsigned int k = params.EquihashK();

    if ( Params().NetworkIDString() == "regtest" )
        return(true);
    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state);

    // I = the block header minus nonce and solution.
    CEquihashInput I{*pblock};
    // I||V
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;

    // H(I||V||...
    crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

    bool isValid;
    EhIsValidSolution(n, k, state, pblock->nSolution, isValid);

    if (!isValid)
        return error("CheckEquihashSolution(): invalid solution");

    return true;
}

extern int32_t KOMODO_CHOSEN_ONE;
extern char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN];
#define KOMODO_ELECTION_GAP 2000

int32_t KOMODO_LOADINGBLOCKS = 1;

extern std::string NOTARY_PUBKEY;

bool CheckProofOfWork(const CBlockHeader &blkHeader, int32_t height, const Consensus::Params& params)
{
    uint256 hash;
    bool fNegative,fOverflow; 
    uint32_t tiptime, blocktimes[66];
    arith_uint256 bnTarget;

    memset(blocktimes,0,sizeof(blocktimes));
    tiptime = komodo_chainactive_timestamp();
    bnTarget.SetCompact(blkHeader.nBits, &fNegative, &fOverflow);
    arith_uint256 bnLimit;
    if (height <= 1 || ASSETCHAINS_ALGO == ASSETCHAINS_EQUIHASH)
    {
        bnLimit = UintToArith256(params.powLimit);
    }
    else if (ASSETCHAINS_ALGO == ASSETCHAINS_VERUSHASH)
    {
        int32_t verusVersion = CConstVerusSolutionVector::activationHeight.ActiveVersion(height);
        if (verusVersion >= CConstVerusSolutionVector::activationHeight.SOLUTION_VERUSV2)
        {
            int32_t pbaasAdjust = !_IsVerusActive() && height < params.nPowAveragingWindow ? 4 : 0;
            bnLimit = UintToArith256(params.powAlternate) << (VERUSHASH2_SHIFT - pbaasAdjust);
        }
        else
        {
            bnLimit = UintToArith256(params.powAlternate);
        }
    }

    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > bnLimit)
        return error("CheckProofOfWork(): nBits below minimum work");

    if ( ASSETCHAINS_STAKED != 0 )
    {
        arith_uint256 bnMaxPoSdiff;
        bnTarget.SetCompact(KOMODO_MINDIFF_NBITS,&fNegative,&fOverflow);
    }

    // Check proof of work matches claimed amount
    if ( UintToArith256(hash = blkHeader.GetHash()) > bnTarget && !blkHeader.IsVerusPOSBlock() )
    {
        if ( KOMODO_LOADINGBLOCKS != 0 )
            return true;

        if ( ASSETCHAINS_SYMBOL[0] != 0 || height > 792000 )
        {
            if ( Params().NetworkIDString() != "regtest" )
            {
                for (int i=31; i>=0; i--)
                    fprintf(stderr,"%02x",((uint8_t *)&hash)[i]);
                fprintf(stderr," hash vs ");
                for (int i=31; i>=0; i--)
                    fprintf(stderr,"%02x",((uint8_t *)&bnTarget)[i]);
            }
            return false;
        }
    }
    return true;
}

CChainPower GetBlockProof(const CBlockIndex& block)
{
    arith_uint256 bnWorkTarget, bnStakeTarget = arith_uint256(0);

    bool fNegative;
    bool fOverflow;
    bnWorkTarget.SetCompact(block.nBits, &fNegative, &fOverflow);

    if (fNegative || fOverflow || bnWorkTarget == 0)
        return CChainPower(0);

    CBlockHeader header = block.GetBlockHeader();

    // if POS block, add stake
    if (!Params().GetConsensus().NetworkUpgradeActive(block.GetHeight(), Consensus::UPGRADE_SAPLING) || !header.IsVerusPOSBlock())
    {
        return CChainPower(0, bnStakeTarget, (~bnWorkTarget / (bnWorkTarget + 1)) + 1);
    }
    else
    {
        bnStakeTarget.SetCompact(header.GetVerusPOSTarget(), &fNegative, &fOverflow);
        if (fNegative || fOverflow || bnStakeTarget == 0)
            return CChainPower(0);
        // as the nonce has a fixed definition for a POS block, add the random amount of "work" from the nonce, so there will
        // statistically always be a deterministic winner in POS
        arith_uint256 aNonce;

        // random amount of additional stake added is capped to 1/2 the current stake target
        aNonce = UintToArith256(block.nNonce) | (bnStakeTarget << (uint64_t)1);

        // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
        // as it's too large for a arith_uint256. However, as 2**256 is at least as large
        // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
        // or ~bnTarget / (nTarget+1) + 1.
        return CChainPower(0, ((~bnStakeTarget / (bnStakeTarget + 1)) + 1) + ((~aNonce / (aNonce + 1)) + 1),
                        (~bnWorkTarget / (bnWorkTarget + 1)) + 1);
    }
}

int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.chainPower.chainWork > from.chainPower.chainWork) {
        r = to.chainPower.chainWork - from.chainPower.chainWork;
    } else {
        r = from.chainPower.chainWork - to.chainPower.chainWork;
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockProof(tip).chainWork;
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.GetLow64();
}
