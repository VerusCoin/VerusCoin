// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_CHAIN_H
#define BITCOIN_CHAIN_H

class CChainPower;

#include "arith_uint256.h"
#include "primitives/block.h"
#include "pow.h"
#include "tinyformat.h"
#include "uint256.h"
#include "mmr.h"

#include <vector>

static const int SPROUT_VALUE_VERSION = 1001400;
static const int SAPLING_VALUE_VERSION = 1010100;

class CBlockFileInfo
{
public:
    unsigned int nBlocks;      //!< number of blocks stored in file
    unsigned int nSize;        //!< number of used bytes of block file
    unsigned int nUndoSize;    //!< number of used bytes in the undo file
    unsigned int nHeightFirst; //!< lowest height of block in file
    unsigned int nHeightLast;  //!< highest height of block in file
    uint64_t nTimeFirst;       //!< earliest time of block in file
    uint64_t nTimeLast;        //!< latest time of block in file

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nBlocks));
        READWRITE(VARINT(nSize));
        READWRITE(VARINT(nUndoSize));
        READWRITE(VARINT(nHeightFirst));
        READWRITE(VARINT(nHeightLast));
        READWRITE(VARINT(nTimeFirst));
        READWRITE(VARINT(nTimeLast));
    }

     void SetNull() {
         nBlocks = 0;
         nSize = 0;
         nUndoSize = 0;
         nHeightFirst = 0;
         nHeightLast = 0;
         nTimeFirst = 0;
         nTimeLast = 0;
     }

     CBlockFileInfo() {
         SetNull();
     }

     std::string ToString() const;

     /** update statistics (does not update nSize) */
     void AddBlock(unsigned int nHeightIn, uint64_t nTimeIn) {
         if (nBlocks==0 || nHeightFirst > nHeightIn)
             nHeightFirst = nHeightIn;
         if (nBlocks==0 || nTimeFirst > nTimeIn)
             nTimeFirst = nTimeIn;
         nBlocks++;
         if (nHeightIn > nHeightLast)
             nHeightLast = nHeightIn;
         if (nTimeIn > nTimeLast)
             nTimeLast = nTimeIn;
     }
};

struct CDiskBlockPos
{
    int nFile;
    unsigned int nPos;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nFile));
        READWRITE(VARINT(nPos));
    }

    CDiskBlockPos() {
        SetNull();
    }

    CDiskBlockPos(int nFileIn, unsigned int nPosIn) {
        nFile = nFileIn;
        nPos = nPosIn;
    }

    friend bool operator==(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return (a.nFile == b.nFile && a.nPos == b.nPos);
    }

    friend bool operator!=(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return !(a == b);
    }

    void SetNull() { nFile = -1; nPos = 0; }
    bool IsNull() const { return (nFile == -1); }

    std::string ToString() const
    {
        return strprintf("CBlockDiskPos(nFile=%i, nPos=%i)", nFile, nPos);
    }

};

enum BlockStatus: uint32_t {
    //! Unused.
    BLOCK_VALID_UNKNOWN      =    0,

    //! Parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
    BLOCK_VALID_HEADER       =    1,

    //! All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
    //! are also at least TREE.
    BLOCK_VALID_TREE         =    2,

    /**
     * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
     * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all
     * parent blocks also have TRANSACTIONS, CBlockIndex::nChainTx will be set.
     */
    BLOCK_VALID_TRANSACTIONS =    3,

    //! Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends, BIP30.
    //! Implies all parents are also at least CHAIN.
    BLOCK_VALID_CHAIN        =    4,

    //! Scripts & signatures ok. Implies all parents are also at least SCRIPTS.
    BLOCK_VALID_SCRIPTS      =    5,

    //! All validity bits.
    BLOCK_VALID_MASK         =   BLOCK_VALID_HEADER | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS |
                                 BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS,

    BLOCK_HAVE_DATA          =    8, //! full block available in blk*.dat
    BLOCK_HAVE_UNDO          =   16, //! undo data available in rev*.dat
    BLOCK_HAVE_MASK          =   BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO,

    BLOCK_FAILED_VALID       =   32, //! stage after last reached validness failed
    BLOCK_FAILED_CHILD       =   64, //! descends from failed block
    BLOCK_FAILED_MASK        =   BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,

    BLOCK_ACTIVATES_UPGRADE  =   128, //! block activates a network upgrade
};

//! Short-hand for the highest consensus validity we implement.
//! Blocks with this validity are assumed to satisfy all consensus rules.
static const BlockStatus BLOCK_VALID_CONSENSUS = BLOCK_VALID_SCRIPTS;

class CBlockIndex;

// This class provides an accumulator for both the chainwork and the chainPOS value
// CChainPower's can be compared, and the comparison ensures that work and proof of stake power
// are both used equally to determine which chain has the most work. This makes an attack
// that involves mining in secret completely ineffective, even before dPOW, unless a large part
// of the staking supply is also controlled. It also enables a faster deterministic convergence,
// aided by both POS and POW.
class CChainPower
{
    public:
        arith_uint256 chainWork;
        arith_uint256 chainStake;
        int32_t nHeight;

        CChainPower() : nHeight(0), chainStake(0), chainWork(0) {}
        CChainPower(CBlockIndex *pblockIndex);
        CChainPower(CBlockIndex *pblockIndex, const arith_uint256 &stake, const arith_uint256 &work);
        CChainPower(int32_t height) : nHeight(height), chainStake(0), chainWork(0) {}
        CChainPower(int32_t height, const arith_uint256 &stake, const arith_uint256 &work) :
                    nHeight(height), chainStake(stake), chainWork(work) {}

        CChainPower &operator=(const CChainPower &chainPower)
        {
            chainWork = chainPower.chainWork;
            chainStake = chainPower.chainStake;
            nHeight = chainPower.nHeight;
            return *this;
        }

        CChainPower &operator+=(const CChainPower &chainPower)
        {
            this->chainWork += chainPower.chainWork;
            this->chainStake += chainPower.chainStake;
            return *this;
        }

        friend CChainPower operator+(const CChainPower &chainPowerA, const CChainPower &chainPowerB)
        {
            CChainPower result = CChainPower(chainPowerA);
            result.chainWork += chainPowerB.chainWork;
            result.chainStake += chainPowerB.chainStake;
            return result;
        }

        friend CChainPower operator-(const CChainPower &chainPowerA, const CChainPower &chainPowerB)
        {
            CChainPower result = CChainPower(chainPowerA);
            result.chainWork -= chainPowerB.chainWork;
            result.chainStake -= chainPowerB.chainStake;
            return result;
        }

        friend CChainPower operator*(const CChainPower &chainPower, int32_t x)
        {
            CChainPower result = CChainPower(chainPower);
            result.chainWork *= x;
            result.chainStake *= x;
            return result;
        }

        CChainPower &addStake(const arith_uint256 &nChainStake)
        {
            chainStake += nChainStake;
            return *this;
        }

        CChainPower &addWork(const arith_uint256 &nChainWork)
        {
            chainWork += nChainWork;
            return *this;
        }

        friend bool operator==(const CChainPower &p1, const CChainPower &p2);

        friend bool operator!=(const CChainPower &p1, const CChainPower &p2)
        {
            return !(p1 == p2);
        }

        friend bool operator<(const CChainPower &p1, const CChainPower &p2);

        friend bool operator<=(const CChainPower &p1, const CChainPower &p2);

        friend bool operator>(const CChainPower &p1, const CChainPower &p2)
        {
            return !(p1 <= p2);
        }

        friend bool operator>=(const CChainPower &p1, const CChainPower &p2)
        {
            return !(p1 < p2);
        }

        uint256 CompactChainPower() const;
        static CChainPower ExpandCompactPower(uint256 compactPower, uint32_t height = 0);
};

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block. A blockindex may have multiple pprev pointing
 * to it, but at most one of them can be part of the currently active branch.
 */
class CBlockIndex
{
public:
    //! pointer to the hash of the block, if any. Memory is owned by this CBlockIndex
    const uint256* phashBlock;

    //! pointer to the index of the predecessor of this block
    CBlockIndex* pprev;

    //! pointer to the index of some further predecessor of this block
    CBlockIndex* pskip;

    int64_t newcoins;
    int64_t zfunds;
    int64_t immature;       // how much in this block is immature
    uint32_t maturity;      // when do the immature funds in this block mature?

    int8_t segid; // jl777 fields

    //! Which # file this block is stored in (blk?????.dat)
    int nFile;

    //! Byte offset within blk?????.dat where this block's data is stored
    unsigned int nDataPos;

    //! Byte offset within rev?????.dat where this block's undo data is stored
    unsigned int nUndoPos;

    //! (memory only) Total amount of work (expected number of hashes) in the chain up to and including this block
    CChainPower chainPower;

    //! Number of transactions in this block.
    //! Note: in a potential headers-first mode, this number cannot be relied upon
    unsigned int nTx;

    //! (memory only) Number of transactions in the chain up to and including this block.
    //! This value will be non-zero only if and only if transactions for this block and all its parents are available.
    //! Change to 64-bit type when necessary; won't happen before 2030
    unsigned int nChainTx;

    //! Verification status of this block. See enum BlockStatus
    unsigned int nStatus;

    //! Branch ID corresponding to the consensus rules used to validate this block.
    //! Only cached if block validity is BLOCK_VALID_CONSENSUS.
    //! Persisted at each activation height, memory-only for intervening blocks.
    boost::optional<uint32_t> nCachedBranchId;

    //! The anchor for the tree state up to the start of this block
    uint256 hashSproutAnchor;

    //! (memory only) The anchor for the tree state up to the end of this block
    uint256 hashFinalSproutRoot;

    //! Change in value held by the Sprout circuit over this block.
    //! Will be boost::none for older blocks on old nodes until a reindex has taken place.
    boost::optional<CAmount> nSproutValue;

    //! (memory only) Total value held by the Sprout circuit up to and including this block.
    //! Will be boost::none for on old nodes until a reindex has taken place.
    //! Will be boost::none if nChainTx is zero.
    boost::optional<CAmount> nChainSproutValue;

    //! Change in value held by the Sapling circuit over this block.
    //! Not a boost::optional because this was added before Sapling activated, so we can
    //! rely on the invariant that every block before this was added had nSaplingValue = 0.
    CAmount nSaplingValue;

    //! (memory only) Total value held by the Sapling circuit up to and including this block.
    //! Will be boost::none if nChainTx is zero.
    boost::optional<CAmount> nChainSaplingValue;

    //! block header
    int nVersion;
    uint256 hashMerkleRoot;
    uint256 hashFinalSaplingRoot;
    unsigned int nTime;
    unsigned int nBits;
    uint256 nNonce;
    CCompactSolutionVector nSolution;

    //! (memory only) Sequential id assigned to distinguish order in which blocks are received.
    uint32_t nSequenceId;

    void SetNull()
    {
        phashBlock = NULL;
        newcoins = zfunds = 0;
        maturity = 0;
        immature = 0;
        segid = -2;
        pprev = NULL;
        pskip = NULL;
        nFile = 0;
        nDataPos = 0;
        nUndoPos = 0;
        chainPower = CChainPower();
        nTx = 0;
        nChainTx = 0;
        nStatus = 0;
        nCachedBranchId = boost::none;
        hashSproutAnchor = uint256();
        hashFinalSproutRoot = uint256();
        nSequenceId = 0;
        nSproutValue = boost::none;
        nChainSproutValue = boost::none;
        nSaplingValue = 0;
        nChainSaplingValue = boost::none;

        nVersion       = 0;
        hashMerkleRoot = uint256();
        hashFinalSaplingRoot   = uint256();
        nTime          = 0;
        nBits          = 0;
        nNonce         = uint256();
        nSolution = CCompactSolutionVector();
    }

    CBlockIndex()
    {
        SetNull();
    }

    CBlockIndex(const CBlockHeader& block)
    {
        SetNull();

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        hashFinalSaplingRoot   = block.hashFinalSaplingRoot;
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;
        nSolution      = block.nSolution;
    }

    void SetHeight(int32_t height)
    {
        this->chainPower.nHeight = height;
    }

    inline int32_t GetHeight() const
    {
        return this->chainPower.nHeight;
    }

    CDiskBlockPos GetBlockPos() const {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_DATA) {
            ret.nFile = nFile;
            ret.nPos  = nDataPos;
        }
        return ret;
    }

    CDiskBlockPos GetUndoPos() const {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_UNDO) {
            ret.nFile = nFile;
            ret.nPos  = nUndoPos;
        }
        return ret;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        if (pprev)
            block.hashPrevBlock = pprev->GetBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.hashFinalSaplingRoot   = hashFinalSaplingRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nSolution      = nSolution.nSolution();
        return block;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    enum { nMedianTimeSpan=11 };

    int64_t GetMedianTimePast() const
    {
        int64_t pmedian[nMedianTimeSpan];
        int64_t* pbegin = &pmedian[nMedianTimeSpan];
        int64_t* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    std::string ToString() const
    {
        return strprintf("CBlockIndex(pprev=%p, nHeight=%d, merkle=%s, hashBlock=%s)",
            pprev, this->chainPower.nHeight,
            hashMerkleRoot.ToString(),
            GetBlockHash().ToString());
    }

    //! Check whether this block index entry is valid up to the passed validity level.
    bool IsValid(enum BlockStatus nUpTo = BLOCK_VALID_TRANSACTIONS) const
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        return ((nStatus & BLOCK_VALID_MASK) >= nUpTo);
    }

    //! Raise the validity level of this block index entry.
    //! Returns true if the validity was changed.
    bool RaiseValidity(enum BlockStatus nUpTo)
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        if ((nStatus & BLOCK_VALID_MASK) < nUpTo) {
            nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo;
            return true;
        }
        return false;
    }

    //! Build the skiplist pointer for this entry.
    void BuildSkip();

    //! Efficiently find an ancestor of this block.
    CBlockIndex* GetAncestor(int height);
    const CBlockIndex* GetAncestor(int height) const;

    int32_t GetVerusPOSTarget() const
    {
        return GetBlockHeader().GetVerusPOSTarget();
    }

    bool IsVerusPOSBlock() const
    {
        return GetBlockHeader().IsVerusPOSBlock();
    }

    bool GetRawVerusPOSHash(uint256 &ret) const;
    uint256 GetVerusEntropyHashComponent() const;

    uint256 BlockMMRRoot() const
    {
        if (nVersion == CBlockHeader::VERUS_V2)
        {
            CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor((nSolution.nSolution()));
            if (descr.version >= CActivationHeight::ACTIVATE_PBAAS)
            {
                return descr.hashBlockMMRRoot;
            }
        }
        return hashMerkleRoot;
    }

    uint256 PrevMMRRoot()
    {
        if (nVersion == CBlockHeader::VERUS_V2)
        {
            CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor(nSolution.nSolution());
            if (descr.version >= CActivationHeight::ACTIVATE_PBAAS)
            {
                return descr.hashPrevMMRRoot;
            }
        }
        return uint256();
    }

    // return a node from this block index as is, including hash of merkle root and block hash as well as compact chain power, to put into an MMR
    ChainMMRNode GetBlockMMRNode() const
    {
        uint256 blockHash = GetBlockHash();

        uint256 preHash = ChainMMRNode::HashObj(BlockMMRRoot(), blockHash);
        uint256 power = ArithToUint256(GetCompactPower(nNonce, nBits, nVersion));

        return ChainMMRNode(ChainMMRNode::HashObj(preHash, power), power);
    }

    CMMRNodeBranch MMRProofBridge()
    {
        // we need to add the block hash on the right, no change to index, as bit is zero
        return CMMRNodeBranch(CMMRNodeBranch::BRANCH_MMRBLAKE_NODE, 2, 0, std::vector<uint256>({GetBlockHash()}));
    }

    CMMRNodeBranch BlockProofBridge()
    {
        // we need to add the merkle root on the left
        return CMMRNodeBranch(CMMRNodeBranch::BRANCH_MMRBLAKE_NODE, 2, 1, std::vector<uint256>({BlockMMRRoot()}));
    }

    bool HasCappedTransactionMap() const
    {
        if (nVersion == CBlockHeader::VERUS_V2)
        {
            return CConstVerusSolutionVector::Version(nSolution.nSolution()) >= CActivationHeight::ACTIVATE_PBAAS_HARDEN1;
        }
        return 0;
    }

    int PartialTransactionProofVersion() const
    {
        return HasCappedTransactionMap() ? CPartialTransactionProof::VERSION_TXHASH_CAP : CPartialTransactionProof::VERSION_CURRENT;
    }

    static std::string BlockEntropyKeyName()
    {
        return "vrsc::random.entropy.defaultkey";
    }

    static uint160 BlockEntropyKey()
    {
        static uint160 nameSpace;
        static uint160 entropyKey = CVDXF::GetDataKey(BlockEntropyKeyName(), nameSpace);
        return entropyKey;
    }
};

/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev;

    CDiskBlockIndex() : CBlockIndex() {
        hashPrev = uint256();
    }

    explicit CDiskBlockIndex(const CBlockIndex* pindex) : CBlockIndex(*pindex) {
        hashPrev = (pprev ? pprev->GetBlockHash() : uint256());
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
#ifdef VERUSHASHDEBUG
        if (!ser_action.ForRead()) printf("Serializing block index %s, stream version: %x\n", ToString().c_str(), nVersion);
#endif
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(VARINT(nVersion));

        if (ser_action.ForRead()) {
            chainPower = CChainPower();
        }
        READWRITE(VARINT(chainPower.nHeight));
        READWRITE(VARINT(nStatus));
        READWRITE(VARINT(nTx));
        if (nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO))
            READWRITE(VARINT(nFile));
        if (nStatus & BLOCK_HAVE_DATA)
            READWRITE(VARINT(nDataPos));
        if (nStatus & BLOCK_HAVE_UNDO)
            READWRITE(VARINT(nUndoPos));
        if (nStatus & BLOCK_ACTIVATES_UPGRADE) {
            if (ser_action.ForRead()) {
                uint32_t branchId;
                READWRITE(branchId);
                nCachedBranchId = branchId;
            } else {
                // nCachedBranchId must always be set if BLOCK_ACTIVATES_UPGRADE is set.
                assert(nCachedBranchId);
                uint32_t branchId = *nCachedBranchId;
                READWRITE(branchId);
            }
        }
        READWRITE(hashSproutAnchor);

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(hashFinalSaplingRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);

        if (CCompactSolutionVector::IsCompressionOn())
        {
            std::vector<unsigned char> tmpSolution;
            if (ser_action.ForRead())
            {
                READWRITE(tmpSolution);
                nSolution = tmpSolution;
            }
            else
            {
                tmpSolution = nSolution.nSolution();
                READWRITE(tmpSolution);
            }
        }
        else
        {
            READWRITE(nSolution.vch);
            nSolution._size = nSolution.vch.size();
        }

        // Only read/write nSproutValue if the client version used to create
        // this index was storing them.
        if ((s.GetType() & SER_DISK) && (nVersion >= SPROUT_VALUE_VERSION)) {
            READWRITE(nSproutValue);
        }

        // Only read/write nSaplingValue if the client version used to create
        // this index was storing them.
        if ((s.GetType() & SER_DISK) && (nVersion >= SAPLING_VALUE_VERSION)) {
            READWRITE(nSaplingValue);
        }

        // If you have just added new serialized fields above, remember to add
        // them to CBlockTreeDB::LoadBlockIndexGuts() in txdb.cpp :)
    }

    CBlockHeader GetDiskBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.hashFinalSaplingRoot    = hashFinalSaplingRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;
        block.nSolution       = nSolution.nSolution();
        return block;
    }

    uint256 GetBlockHash() const { return GetDiskBlockHeader().GetHash(); }

    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex:\n";

        CBlockHeader block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.hashFinalSaplingRoot    = hashFinalSaplingRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;
        block.nSolution       = nSolution.nSolution();
        CPBaaSPreHeader preBlock(block);

        str += strprintf("block.nVersion=%x\npprev=%p\nnHeight=%d\nhashBlock=%s\nblock.hashPrevBlock=%s\nblock.hashMerkleRoot=%s\nblock.nBits=%d\nblock.nNonce=%s\nblock.nSolution=%s\npreBlock.hashPrevMMRRoot=%s\npreBlock.hashBlockMMRRoot=%s\n",
            this->nVersion, pprev, this->chainPower.nHeight, GetBlockHash().ToString(), hashPrev.ToString(), hashMerkleRoot.ToString(), nBits, nNonce.ToString(), HexBytes(nSolution.nSolution().data(), nSolution.size()), preBlock.hashPrevMMRRoot.ToString(), preBlock.hashBlockMMRRoot.ToString());

        return str;
    }
};

class CChain;
typedef CMerkleMountainRange<ChainMMRNode, CChunkedLayer<ChainMMRNode, 9>, COverlayNodeLayer<ChainMMRNode, CChain>> ChainMerkleMountainRange;
typedef CMerkleMountainView<ChainMMRNode, CChunkedLayer<ChainMMRNode, 9>, COverlayNodeLayer<ChainMMRNode, CChain>> ChainMerkleMountainView;

/** An in-memory indexed chain of blocks.
 * With Verus and PBaaS chains, this also provides a complete Merkle Mountain Range (MMR) for the chain at all times,
 * enabling proof of any transaction that can be exported and trusted on any chain that has a trusted oracle or other lite proof of this chain.
*/
class CChain {
private:
    std::vector<CBlockIndex*> vChain;
    ChainMerkleMountainRange mmr;
    CBlockIndex *lastTip;

public:
    CChain() : vChain(), mmr(COverlayNodeLayer<ChainMMRNode, CChain>(*this)) {}

    /** Returns the index entry for the genesis block of this chain, or NULL if none. */
    CBlockIndex *Genesis() const {
        return vChain.size() > 0 ? vChain[0] : NULL;
    }

    /** Returns the index entry for the tip of this chain, or NULL if none. */
    CBlockIndex *Tip() const {
        return vChain.size() > 0 ? vChain[vChain.size() - 1] : NULL;
    }

    /** Returns the last tip of the chain, or NULL if none. */
    CBlockIndex *LastTip() const {
        return vChain.size() > 0 ? lastTip : NULL;
    }

    /** Returns the index entry at a particular height in this chain, or NULL if no such height exists. */
    CBlockIndex *operator[](int nHeight) const {
        if (nHeight < 0 || nHeight >= (int)vChain.size())
            return NULL;
        return vChain[nHeight];
    }

    // Returns the block index at min(height, tip), or nullptr if the chain has no blocks.
    // Safe for height == 0 and for height - 1 having underflowed to UINT32_MAX.
    inline CBlockIndex *ChainIndexAtOrBefore(uint32_t height) const
    {
        if (Height() == -1)
        {
            return nullptr;
        }
        uint32_t nTip = Height();
        return (*this)[height > nTip ? nTip : height];
    }

    // Returns nTime of that block, or 0 when the chain has no blocks.
    inline uint32_t ChainTimeAtOrBefore(uint32_t height) const
    {
        CBlockIndex *pIndex = ChainIndexAtOrBefore(height);
        return pIndex ? pIndex->nTime : 0;
    }

    uint256 GetVerusEntropyHash(int forHeight, int *pPOSheight=nullptr, int *pPOWheight=nullptr, int *pALTheight=nullptr, int *pFirstBlockHeight=nullptr, int *pSecondBlockHeight=nullptr) const;
    static uint256 CombineForPastHash(const uint256 &firstComponent, const uint256 &secondComponent);

    /** Get the Merkle Mountain Range for this chain. */
    const ChainMerkleMountainRange &GetMMR()
    {
        return mmr;
    }

    /** Get a Merkle Mountain Range view for this chain. */
    ChainMerkleMountainView GetMMV() const
    {
        return ChainMerkleMountainView(mmr, mmr.size());
    }

    ChainMMRNode GetMMRNode(int index) const
    {
        return vChain[index]->GetBlockMMRNode();
    }

    bool GetBlockProof(ChainMerkleMountainView &view, CMMRProof &retProof, int index) const;
    bool GetMerkleProof(ChainMerkleMountainView &view, CMMRProof &retProof, int index) const;

    /** Compare two chains efficiently. */
    friend bool operator==(const CChain &a, const CChain &b) {
        return a.vChain.size() == b.vChain.size() &&
               a.vChain[a.vChain.size() - 1] == b.vChain[b.vChain.size() - 1];
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const CBlockIndex *pindex) const {
        return !pindex ? false : (*this)[pindex->GetHeight()] == pindex;
    }

    /** Find the successor of a block in this chain, or NULL if the given index is not found or is the tip. */
    CBlockIndex *Next(const CBlockIndex *pindex) const {
        if (Contains(pindex))
            return (*this)[pindex->GetHeight() + 1];
        else
            return NULL;
    }

    /** Return the maximal height in the chain. Is equal to chain.Tip() ? chain.Tip()->GetHeight() : -1. */
    int Height() const {
        return vChain.size() - 1;
    }

    uint64_t size()
    {
        return vChain.size();
    }

    /** Set/initialize a chain with a given tip. */
    void SetTip(CBlockIndex *pindex);

    /** Return a CBlockLocator that refers to a block in this chain (by default the tip). */
    CBlockLocator GetLocator(const CBlockIndex *pindex = NULL) const;

    /** Find the last common block between this chain and a block index entry. */
    const CBlockIndex *FindFork(const CBlockIndex *pindex) const;

    CPartialTransactionProof GetPreHeaderProof(const CBlock &block, uint32_t blockHeight, uint32_t proofAtHeight) const;
};

#endif // BITCOIN_CHAIN_H
