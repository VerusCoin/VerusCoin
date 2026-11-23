// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "chain.h"

#include <stdexcept>

using namespace std;

/**
 * CChain implementation
 */
void CChain::SetTip(CBlockIndex *pindex) {
    lastTip = pindex;
    if (pindex == NULL) {
        vChain.clear();
        mmr.Truncate(0);
        return;
    }
    uint32_t modCount = 0;
    vChain.resize(pindex->GetHeight() + 1);
    while (pindex && vChain[pindex->GetHeight()] != pindex) {
        modCount++;
        vChain[pindex->GetHeight()] = pindex;
        pindex = pindex->pprev;
    }
    mmr.Truncate(vChain.size() - modCount);
    for (int i = (vChain.size() - modCount); i < vChain.size(); i++)
    {
        // add this block to the Merkle Mountain Range
        mmr.Add(vChain[i]->GetBlockMMRNode());
    }
}

// returns false if unable to fast calculate the VerusPOSHash from the header.
// if it returns false, value is set to 0, but it can still be calculated from the full block
// in that case. the only difference between this and the POS hash for the contest is that it is not divided by the value out
// this is used as a source of entropy
bool CBlockIndex::GetRawVerusPOSHash(uint256 &ret) const
{
    // if below the required height or no storage space in the solution, we can't get
    // a cached txid value to calculate the POSHash from the header
    if (!(CPOSNonce::NewNonceActive(GetHeight()) && IsVerusPOSBlock()))
    {
        ret = uint256();
        return false;
    }

    // if we can calculate, this assumes the protocol that the POSHash calculation is:
    //    hashWriter << ASSETCHAINS_MAGIC;
    //    hashWriter << nNonce; (nNonce is:
    //                           (high 128 bits == low 128 bits of verus hash of low 128 bits of nonce)
    //                           (low 32 bits == compact PoS difficult)
    //                           (mid 96 bits == low 96 bits of HASH(pastHash, txid, voutnum)
    //                              pastHash is hash of height - 100, either PoW hash of block or PoS hash, if new PoS
    //                          )
    //    hashWriter << height;
    //    return hashWriter.GetHash();
    ret = CBlockHeader::GetRawVerusPOSHash(nVersion, CConstVerusSolutionVector::Version(nSolution.nSolution()), ASSETCHAINS_MAGIC, nNonce, GetHeight());
    return true;
}

// depending on the height of the block and its type, this returns the POS hash or the POW hash
uint256 CBlockIndex::GetVerusEntropyHashComponent() const
{
    uint256 retVal;
    // if we qualify as PoW, use PoW hash, regardless of PoS state
    if (GetRawVerusPOSHash(retVal))
    {
        // POS hash
        return retVal;
    }
    return GetBlockHash();
}

uint256 CChain::CombineForPastHash(const uint256 &firstComponent, const uint256 &secondComponent)
{
    CVerusHashV2Writer hashWriter = CVerusHashV2Writer(SER_GETHASH, 0);
    if (firstComponent.IsNull())
    {
        return firstComponent;
    }
    hashWriter << firstComponent;
    if (!secondComponent.IsNull())
    {
        hashWriter << secondComponent;
    }
    return hashWriter.GetHash();
}

// if pointers are passed for the int output values, two of them will indicate the height that provides one of two
// entropy values. the other will be -1. if pALTheight is not -1, its block type is the same as the other, which is
// not -1.
uint256 CChain::GetVerusEntropyHash(int forHeight, int *pPOSheight, int *pPOWheight, int *pALTheight, int *pProveHeight, int *pSecondHeight) const
{
    uint256 retVal;
    int height = forHeight - 100;

    // we want the last value hashed to be a POW hash to make it difficult to predict at source tx creation, then we hash it with the
    // POS entropy. for old version, we just do what we used to and return the type of hash with the -100 height
    int _posh, _powh, _alth;
    int &posh = pPOSheight ? *pPOSheight : _posh;
    int &powh = pPOWheight ? *pPOWheight : _powh;
    int &alth = pALTheight ? *pALTheight : _alth;
    posh = powh = alth = -1;

    if (!(height >= 0 && height < vChain.size()))
    {
        LogPrint("notarization", "%s: invalid height for entropy hash %d, chain height is %d\n", __func__, height, vChain.size() - 1);
        return retVal;
    }
    if (CConstVerusSolutionVector::GetVersionByHeight(forHeight) < CActivationHeight::ACTIVATE_EXTENDEDSTAKE || height < 11)
    {
        if (vChain[height]->IsVerusPOSBlock())
        {
            posh = height;
        }
        else
        {
            powh = height;
        }
        return vChain[height]->GetVerusEntropyHashComponent();
    }

    int i;
    for (i = 0; i < 10; i++)
    {
        if (posh == -1 && vChain[height - i]->IsVerusPOSBlock())
        {
            posh = height - i;
        }
        else if (powh == -1)
        {
            powh = height - i;
        }
        if (posh != -1 && powh != -1)
        {
            break;
        }
    }

    // only one type of block found, set alt
    if (i == 10)
    {
        alth = height - i;
    }

    CVerusHashV2Writer hashWriter = CVerusHashV2Writer(SER_GETHASH, 0);
    if (posh != -1)
    {
        hashWriter << vChain[posh]->GetVerusEntropyHashComponent();
    }
    if (powh != -1)
    {
        hashWriter << vChain[powh]->GetVerusEntropyHashComponent();
    }
    if (alth != -1)
    {
        hashWriter << vChain[alth]->GetVerusEntropyHashComponent();
    }

    // secondBlockHeight is either less than first or -1 if there isn't one
    if (pProveHeight || pSecondHeight)
    {
        int secondBlockHeight = alth != -1 ?
                                    alth :
                                    posh == -1 ?
                                        posh :
                                        powh == -1 ?
                                            powh :
                                            (posh > powh ?
                                                powh :
                                                posh);

        if (pSecondHeight)
        {
            *pSecondHeight = secondBlockHeight;
        }
        if (pProveHeight)
        {
            *pProveHeight = posh > secondBlockHeight ? posh : ((powh == -1) ? posh : powh);
        }
    }

    return hashWriter.GetHash();
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const {
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);

    if (!pindex)
        pindex = Tip();
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block.
        if (pindex->GetHeight() == 0)
            break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max(pindex->GetHeight() - nStep, 0);
        if (Contains(pindex)) {
            // Use O(1) CChain index if possible.
            pindex = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist.
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10)
            nStep *= 2;
    }

    return CBlockLocator(vHave);
}

const CBlockIndex *CChain::FindFork(const CBlockIndex *pindex) const {
    if ( pindex == 0 )
        return(0);
    if (pindex->GetHeight() > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(pindex))
        pindex = pindex->pprev;
    return pindex;
}

bool CChain::GetBlockProof(ChainMerkleMountainView &view, CMMRProof &retProof, int index) const
{
    CBlockIndex *pindex = (index < 0 || index >= (int)vChain.size()) ? NULL : vChain[index];
    if (pindex)
    {
        retProof << pindex->BlockProofBridge();
        return view.GetProof(retProof, index);
    }
    else
    {
        return false;
    }
}

bool CChain::GetMerkleProof(ChainMerkleMountainView &view, CMMRProof &retProof, int index) const
{
    CBlockIndex *pindex = (index < 0 || index >= (int)vChain.size()) ? NULL : vChain[index];
    if (pindex)
    {
        retProof << pindex->MMRProofBridge();
        return view.GetProof(retProof, index);
    }
    else
    {
        return false;
    }
}

CPartialTransactionProof CChain::GetPreHeaderProof(const CBlock &block, uint32_t blockHeight, uint32_t proofAtHeight) const
{
    CMMRProof txProof;
    uint256 entropyHash;
    if (block.IsAdvancedHeader() != 0)
    {
        std::vector<unsigned char> nSol((*this)[blockHeight]->nSolution.nSolution());
        bool posEntropyInfo = CVerusSolutionVector(nSol).Version() >= CActivationHeight::ACTIVATE_PBAAS;

        if (posEntropyInfo)
        {
            entropyHash = (*this)[blockHeight]->GetVerusEntropyHashComponent();
        }
        BlockMMRange blockMMR(block.GetBlockMMRTree(entropyHash));
        BlockMMView blockMMV(blockMMR);

        if (!blockMMV.GetProof(txProof, block.vtx.size()))
        {
            LogPrintf("%s: Cannot make pre header proof in block\n", __func__);
            printf("%s: Cannot make pre header in block\n", __func__);
            CPartialTransactionProof errorProof;
            errorProof.version = errorProof.VERSION_INVALID;
            return errorProof;
        }
    }
    else
    {
        // invalid proof
        CPartialTransactionProof errorProof;
        errorProof.version = errorProof.VERSION_INVALID;
        return errorProof;
    }

    ChainMerkleMountainView mmv = GetMMV();
    mmv.resize(proofAtHeight + 1);
    GetMerkleProof(mmv, txProof, blockHeight);
    if (LogAcceptCategory("notarization"))
    {
        auto substitutedPreHeader = block.GetSubstitutedPreHeader(entropyHash);
        if (LogAcceptCategory("notarization"))
        {
            LogPrintf("substitutedPreHeader: %s\n", substitutedPreHeader.ToUniValue().write(1,2).c_str());
        }
        return CPartialTransactionProof(txProof, substitutedPreHeader, block.PartialTransactionProofVersion());
    }
    else
    {
        return CPartialTransactionProof(txProof, block.GetSubstitutedPreHeader(entropyHash), block.PartialTransactionProofVersion());
    }
}

uint256 CChainPower::CompactChainPower() const
{
    arith_uint256 compactPower = (chainStake << 128) + chainWork;
    return ArithToUint256(compactPower);
}

CChainPower::CChainPower(CBlockIndex *pblockIndex)
{
     nHeight = pblockIndex->GetHeight();
     chainStake = arith_uint256(0);
     chainWork = arith_uint256(0);
}

CChainPower::CChainPower(CBlockIndex *pblockIndex, const arith_uint256 &stake, const arith_uint256 &work)
{
     nHeight = pblockIndex->GetHeight();
     chainStake = stake;
     chainWork = work;
}


namespace {

// Private exact fast path for the scaled ratio (value<<16)/divisor used by
// the CChainPower comparison operators. Semantics-preserving only:
//  - Guard requires __SIZEOF_INT128__, value.bits()<=112, divisor.bits()<=112,
//    divisor!=0 and value<=divisor (max-divisor invariant), so (value<<16)
//    fits in 128 bits and the quotient is <= 65536.
//  - Any guard failure falls through to the ORIGINAL 256-bit expression
//    (value<<16)/divisor unchanged, preserving uint256 shift-wrap semantics.
//  - No header API change, no counters, no global mutable state, no logging.
// With VERUS_CHAINPOWER_VERIFY defined, the ORIGINAL 256-bit expression is
// recomputed and an explicit std::logic_error is thrown on any mismatch
// (an assert would be compiled out under NDEBUG).
arith_uint256 ScaledRatio16(const arith_uint256 &value, const arith_uint256 &divisor)
{
#ifdef __SIZEOF_INT128__
    const arith_uint256 bigZero(0);
    if (divisor != bigZero && value <= divisor &&
        value.bits() <= 112 && divisor.bits() <= 112)
    {
        arith_uint256 result;
        if (value == divisor)
        {
            result = arith_uint256((uint64_t)65536u);
        }
        else
        {
            // Verified public API limbs: low 64 bits via GetLow64(), limbs 2-3
            // via (x >> 64).GetLow64().
            unsigned __int128 num =
                ((unsigned __int128)((value >> 64).GetLow64()) << 64)
                | (unsigned __int128)value.GetLow64();
            unsigned __int128 den =
                ((unsigned __int128)((divisor >> 64).GetLow64()) << 64)
                | (unsigned __int128)divisor.GetLow64();
            num <<= 16; // (value<<16) fits in 128 bits by the guard
            unsigned __int128 q = num / den; // <= 65536 by the guard
            result = arith_uint256((uint64_t)q);
        }
#ifdef VERUS_CHAINPOWER_VERIFY
        {
            arith_uint256 ref = (value << 16) / divisor;
            if (ref != result)
                throw std::logic_error("VERUS_CHAINPOWER_VERIFY: ChainPowerExact fast path mismatch");
        }
#endif
        return result;
    }
#endif
    return (value << 16) / divisor;
}

} // anonymous namespace

bool operator==(const CChainPower &p1, const CChainPower &p2)
{
    arith_uint256 bigZero = arith_uint256(0);
    arith_uint256 workDivisor = p1.chainWork > p2.chainWork ? p1.chainWork : (p2.chainWork != bigZero ? p2.chainWork : 1);
    arith_uint256 stakeDivisor = p1.chainStake > p2.chainStake ? p1.chainStake : (p2.chainStake != bigZero ? p2.chainStake : 1);

    // use up 16 bits for precision
    return (ScaledRatio16(p1.chainWork, workDivisor) + ScaledRatio16(p1.chainStake, stakeDivisor)) ==
            (ScaledRatio16(p2.chainWork, workDivisor) + ScaledRatio16(p2.chainStake, stakeDivisor));
}

bool operator<(const CChainPower &p1, const CChainPower &p2)
{
    arith_uint256 bigZero = arith_uint256(0);
    arith_uint256 workDivisor = p1.chainWork > p2.chainWork ? p1.chainWork : (p2.chainWork != bigZero ? p2.chainWork : 1);
    arith_uint256 stakeDivisor = p1.chainStake > p2.chainStake ? p1.chainStake : (p2.chainStake != bigZero ? p2.chainStake : 1);

    // use up 16 bits for precision
    return (ScaledRatio16(p1.chainWork, workDivisor) + ScaledRatio16(p1.chainStake, stakeDivisor)) <
            (ScaledRatio16(p2.chainWork, workDivisor) + ScaledRatio16(p2.chainStake, stakeDivisor));
}

bool operator<=(const CChainPower &p1, const CChainPower &p2)
{
    arith_uint256 bigZero = arith_uint256(0);
    arith_uint256 workDivisor = p1.chainWork > p2.chainWork ? p1.chainWork : (p2.chainWork != bigZero ? p2.chainWork : 1);
    arith_uint256 stakeDivisor = p1.chainStake > p2.chainStake ? p1.chainStake : (p2.chainStake != bigZero ? p2.chainStake : 1);

    // use up 16 bits for precision
    return (ScaledRatio16(p1.chainWork, workDivisor) + ScaledRatio16(p1.chainStake, stakeDivisor)) <=
            (ScaledRatio16(p2.chainWork, workDivisor) + ScaledRatio16(p2.chainStake, stakeDivisor));
}

CChainPower CChainPower::ExpandCompactPower(uint256 compactPower, uint32_t height)
{
    return CChainPower(height, UintToArith256(compactPower) >> 128, (UintToArith256(compactPower) << 128) >> 128);
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    if (height > GetHeight() || height < 0)
        return NULL;

    CBlockIndex* pindexWalk = this;
    int heightWalk = GetHeight();
    while ( heightWalk > height && pindexWalk != 0 )
    {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != NULL &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            assert(pindexWalk->pprev);
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex*>(this)->GetAncestor(height);
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
    {
        //printf("building skip - current:\n%s\nprev:\n%s\n", ToString().c_str(), pprev->ToString().c_str());
        pskip = pprev->GetAncestor(GetSkipHeight(GetHeight()));
    }
}
