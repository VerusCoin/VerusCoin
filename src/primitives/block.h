// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "primitives/nonce.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"
#include "arith_uint256.h"
#include "primitives/solutiondata.h"

// does not check for height / sapling upgrade, etc. this should not be used to get block proofs
// on a pre-VerusPoP chain
arith_uint256 GetCompactPower(const uint256 &nNonce, uint32_t nBits, int32_t version=CPOSNonce::VERUS_V2);
class CMMRPowerNode;
class CMerkleBranch;
class CBlockHeader;

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    static const size_t HEADER_SIZE = 4+32+32+32+4+4+32;  // excluding Equihash solution
    static const int32_t CURRENT_VERSION = CPOSNonce::VERUS_V1;
    static const int32_t CURRENT_VERSION_MASK = 0x0000ffff; // for compatibility
    static const int32_t VERUS_V2 = CPOSNonce::VERUS_V2;

    static uint256 (CBlockHeader::*hashFunction)() const;

    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashFinalSaplingRoot;
    uint32_t nTime;
    uint32_t nBits;
    CPOSNonce nNonce;
    std::vector<unsigned char> nSolution;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(hashFinalSaplingRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(nSolution);
    }

    void SetNull()
    {
        nVersion = CBlockHeader::CURRENT_VERSION;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashFinalSaplingRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = uint256();
        nSolution.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    // returns 0 if not PBaaS, 1 if PBaaS PoW, -1 if PBaaS PoS
    int32_t IsPBaaS()
    {
        if (nVersion == VERUS_V2)
        {
            return CVerusSolutionVector(nSolution).IsPBaaS();
        }
        return 0;
    }

    // return a vector of bytes that contains the internal data for this solution vector
    void GetExtraData(std::vector<unsigned char> &dataVec)
    {
        CVerusSolutionVector(nSolution).GetExtraData(dataVec);
    }

    // set the extra data with a pointer to bytes and length
    bool SetExtraData(const unsigned char *pbegin, uint32_t len)
    {
        return CVerusSolutionVector(nSolution).SetExtraData(pbegin, len);
    }

    void ResizeExtraData(uint32_t newSize)
    {
        CVerusSolutionVector(nSolution).ResizeExtraData(newSize);
    }

    uint32_t ExtraDataLen()
    {
        return CVerusSolutionVector(nSolution).ExtraDataLen();
    }

    // returns -1 on failure, upon failure, pbbh is undefined and likely corrupted
    int32_t GetPBaaSHeader(CPBaaSBlockHeader &pbh, const uint160 &cID) const;

    // returns false on failure to read data
    bool GetPBaaSHeader(CPBaaSBlockHeader &pbh, uint32_t idx) const
    {
        // search in the solution for this header index and return it if found
        CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor(nSolution);
        int pbType;
        if (nVersion == VERUS_V2 && CConstVerusSolutionVector::IsPBaaS(nSolution) != 0 && idx < descr.numPBaaSHeaders)
        {
            pbh = *(CConstVerusSolutionVector::GetFirstPBaaSHeader(nSolution) + idx);
            return true;
        }
        return false;
    }

    // returns false on failure to read data
    int32_t NumPBaaSHeaders() const
    {
        // search in the solution for this header index and return it if found
        CPBaaSSolutionDescriptor descr = CConstVerusSolutionVector::GetDescriptor(nSolution);
        return descr.numPBaaSHeaders;
    }

    // this can save a new header into an empty space or update an existing header
    bool SavePBaaSHeader(CPBaaSBlockHeader &pbh, uint32_t idx)
    {
        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader();
        int ix;

        CVerusSolutionVector sv = CVerusSolutionVector(nSolution);

        if (sv.IsPBaaS() && !pbh.IsNull() && idx < sv.GetNumPBaaSHeaders() && (((ix = GetPBaaSHeader(pbbh, pbh.chainID)) == -1) || ix == idx))
        {
            sv.SetPBaaSHeader(pbh, idx);
            return true;
        }
        return false;
    }

    bool UpdatePBaaSHeader(const CPBaaSBlockHeader &pbh)
    {
        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader();
        uint32_t idx;

        // what we are updating, must be present
        if (!pbh.IsNull() && (idx = GetPBaaSHeader(pbbh, pbh.chainID)) != -1)
        {
            CVerusSolutionVector(nSolution).SetPBaaSHeader(pbh, idx);
            return true;
        }
        return false;
    }

    void DeletePBaaSHeader(uint32_t idx)
    {
        CVerusSolutionVector sv = CVerusSolutionVector(nSolution);
        CPBaaSSolutionDescriptor descr = sv.Descriptor();
        if (idx < descr.numPBaaSHeaders)
        {
            CPBaaSBlockHeader pbh;
            // if we weren't last, move the one that was last to our prior space
            if (idx < (descr.numPBaaSHeaders - 1))
            {
                sv.GetPBaaSHeader(pbh, descr.numPBaaSHeaders - 1);
            }
            sv.SetPBaaSHeader(pbh, idx);
            
            descr.numPBaaSHeaders--;
            sv.SetDescriptor(descr);
        }
    }

    // returns the index of the new header if added, otherwise, -1
    int32_t AddPBaaSHeader(const CPBaaSBlockHeader &pbh);

    // add the parts of this block header that can be represented by a PBaaS header to the solution
    int32_t AddPBaaSHeader(uint256 hashPrevMMRRoot, const uint160 &cID)
    {

        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader(cID, CPBaaSPreHeader(*this), hashPrevMMRRoot);
        return AddPBaaSHeader(pbbh);
    }

    bool AddUpdatePBaaSHeader(uint256 mmvRoot);
    bool AddUpdatePBaaSHeader(const CPBaaSBlockHeader &pbh);

    // clears everything except version, time, and solution, which are shared across all merge mined blocks
    void ClearNonCanonicalData()
    {
        hashPrevBlock = uint256();
        hashMerkleRoot = uint256();
        hashFinalSaplingRoot = uint256();
        nBits = 0;
        nNonce = uint256();
    }

    // this confirms that the current header's data matches what would be expected from its preheader hash in the
    // solution
    bool CheckNonCanonicalData() const;
    bool CheckNonCanonicalData(uint160 &cID) const;

    uint256 GetHash() const
    {
        return (this->*hashFunction)();
    }

    // return a node from this block header, including hash of merkle root and block hash as well as compact chain power, to put into an MMR
    CMMRPowerNode GetMMRNode() const;
    void AddMerkleProofBridge(CMerkleBranch &branch) const;
    void AddBlockProofBridge(CMerkleBranch &branch) const;
    uint256 GetPrevMMRRoot() const;

    uint256 GetSHA256DHash() const;
    static void SetSHA256DHash();

    uint256 GetVerusHash() const;
    static void SetVerusHash();

    uint256 GetVerusV2Hash() const;
    static void SetVerusV2Hash();

    bool GetRawVerusPOSHash(uint256 &ret, int32_t nHeight) const;
    bool GetVerusPOSHash(arith_uint256 &ret, int32_t nHeight, CAmount value) const; // value is amount of stake tx
    uint256 GetVerusEntropyHash(int32_t nHeight) const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    uint32_t GetVerusPOSTarget() const
    {
        uint32_t nBits = 0;

        for (const unsigned char *p = nNonce.begin() + 3; p >= nNonce.begin(); p--)
        {
            nBits <<= 8;
            nBits += *p;
        }
        return nBits;
    }

    bool IsVerusPOSBlock() const
    {
        return nNonce.IsPOSNonce(nVersion) && GetVerusPOSTarget() != 0;
    }

    void SetVerusPOSTarget(uint32_t nBits)
    {
        if (nVersion == VERUS_V2)
        {
            CVerusHashV2Writer hashWriter = CVerusHashV2Writer(SER_GETHASH, PROTOCOL_VERSION);

            arith_uint256 arNonce = UintToArith256(nNonce);

            // printf("before svpt: %s\n", ArithToUint256(arNonce).GetHex().c_str());

            arNonce = (arNonce & CPOSNonce::entropyMask) | nBits;

            // printf("after clear: %s\n", ArithToUint256(arNonce).GetHex().c_str());

            hashWriter << ArithToUint256(arNonce);
            nNonce = CPOSNonce(ArithToUint256(UintToArith256(hashWriter.GetHash()) << 128 | arNonce));

            // printf(" after svpt: %s\n", nNonce.GetHex().c_str());
        }
        else
        {
            CVerusHashWriter hashWriter = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);

            arith_uint256 arNonce = UintToArith256(nNonce);

            // printf("before svpt: %s\n", ArithToUint256(arNonce).GetHex().c_str());

            arNonce = (arNonce & CPOSNonce::entropyMask) | nBits;

            // printf("after clear: %s\n", ArithToUint256(arNonce).GetHex().c_str());

            hashWriter << ArithToUint256(arNonce);
            nNonce = CPOSNonce(ArithToUint256(UintToArith256(hashWriter.GetHash()) << 128 | arNonce));

            // printf(" after svpt: %s\n", nNonce.GetHex().c_str());
        }
    }

    bool SetVersionByHeight(uint32_t height)
    {
        CVerusSolutionVector vsv = CVerusSolutionVector(nSolution);
        if (vsv.SetVersionByHeight(height) && vsv.Version() > 0)
        {
            nVersion = VERUS_V2;
        }
    }

    static uint32_t GetVersionByHeight(uint32_t height)
    {
        if (CVerusSolutionVector::GetVersionByHeight(height) > 0)
        {
            return VERUS_V2;
        }
        else
        {
            return CURRENT_VERSION;
        }
    }
};

// this class is used to address the type mismatch that existed between nodes, where block headers
// were being serialized by senders as CBlock and deserialized as CBlockHeader + an assumed extra
// compact value. although it was working, I made this because it did break, and makes the connection
// between CBlock and CBlockHeader more brittle.
// by using this intentionally specified class instead, we remove an instability in the code that could break
// due to unrelated changes, but stay compatible with the old method.
class CNetworkBlockHeader : public CBlockHeader
{
    public:
        std::vector<CTransaction> compatVec;

    CNetworkBlockHeader() : CBlockHeader()
    {
        SetNull();
    }

    CNetworkBlockHeader(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(compatVec);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        compatVec.clear();    
    }
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;

    // memory only
    mutable std::vector<uint256> vMerkleTree;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        vMerkleTree.clear();
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.hashFinalSaplingRoot   = hashFinalSaplingRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nSolution      = nSolution;
        return block;
    }

    // Build the in-memory merkle tree for this block and return the merkle root.
    // If non-NULL, *mutated is set to whether mutation was detected in the merkle
    // tree (a duplication of transactions in the block leading to an identical
    // merkle root).
    uint256 BuildMerkleTree(bool* mutated = NULL) const;

    std::vector<uint256> GetMerkleBranch(int nIndex) const;
    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex);
    std::string ToString() const;
};


uint256 BuildMerkleTree(bool* fMutated, const std::vector<uint256> leaves,
        std::vector<uint256> &vMerkleTree);

std::vector<uint256> GetMerkleBranch(int nIndex, int nLeaves, const std::vector<uint256> &vMerkleTree);


/**
 * Custom serializer for CBlockHeader that omits the nonce and solution, for use
 * as input to Equihash.
 */
class CEquihashInput : private CBlockHeader
{
public:
    CEquihashInput(const CBlockHeader &header)
    {
        CBlockHeader::SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(hashFinalSaplingRoot);
        READWRITE(nTime);
        READWRITE(nBits);
    }
};


/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }

    friend bool operator==(const CBlockLocator& a, const CBlockLocator& b) {
        return (a.vHave == b.vHave);
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
