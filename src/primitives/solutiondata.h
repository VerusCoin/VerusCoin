// Copyright (c) 2018 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_SOLUTIONDATA_H
#define BITCOIN_PRIMITIVES_SOLUTIONDATA_H

#include "serialize.h"
#include "uint256.h"
#include "arith_uint256.h"
#include "hash.h"
#include "nonce.h"
#include "streams.h"
#include <univalue.h>

class CPBaaSBlockHeader;

class CActivationHeight
{
    public:
        enum {
            MAX_HEIGHT = INT_MAX,
            DEFAULT_UPGRADE_HEIGHT = MAX_HEIGHT,
            NUM_VERSIONS = 8,   // NEVER ADD A NEW VERSION WITHOUT UPDATING THE ARRAY BELOW WITH ALL ENTRIES PRESENT
            SOLUTION_VERUSV1 = 0,
            SOLUTION_VERUSV2 = 1,
            SOLUTION_VERUSV3 = 2,
            SOLUTION_VERUSV4 = 3,
            SOLUTION_VERUSV5 = 4,
            SOLUTION_VERUSV5_1 = 5,
            SOLUTION_VERUSV6 = 6,
            SOLUTION_VERUSV7 = 7,
            ACTIVATE_VERUSHASH2 = SOLUTION_VERUSV2,
            ACTIVATE_EXTENDEDSOLUTION = SOLUTION_VERUSV3,
            ACTIVATE_IDENTITY = SOLUTION_VERUSV4,
            ACTIVATE_VERUSHASH2_1 = SOLUTION_VERUSV4,
            ACTIVATE_EXTENDEDSTAKE = SOLUTION_VERUSV5,
            ACTIVATE_IDCONSENSUS2 = SOLUTION_VERUSV5,
            ACTIVATE_VERUSHASH2_2 = SOLUTION_VERUSV5,
            ACTIVATE_PBAAS_HEADER = SOLUTION_VERUSV5_1,
            ACTIVATE_STAKEHEADER = SOLUTION_VERUSV6,
            ACTIVATE_VERUSVAULT = SOLUTION_VERUSV6,
            ACTIVATE_PBAAS = SOLUTION_VERUSV7
        };
        bool active;
        int32_t heights[NUM_VERSIONS];
        CActivationHeight() : heights{0, DEFAULT_UPGRADE_HEIGHT, DEFAULT_UPGRADE_HEIGHT, DEFAULT_UPGRADE_HEIGHT, DEFAULT_UPGRADE_HEIGHT, DEFAULT_UPGRADE_HEIGHT, DEFAULT_UPGRADE_HEIGHT, DEFAULT_UPGRADE_HEIGHT}, active(true) {}

        void SetActivationHeight(int32_t version, int32_t height)
        {
            assert(version < NUM_VERSIONS && version > 0);
            if (height < MAX_HEIGHT)
            {
                active = true;
            }
            heights[version] = height;
        }

        bool IsActivationHeight(int32_t version, int32_t height)
        {
            assert(version < NUM_VERSIONS && version > 0);
            return active && heights[version] == height;
        }

        int32_t ActiveVersion(int32_t height)
        {
            if (!active)
                return 0;

            int32_t ver = 0;
            for (int32_t i = 0; i < NUM_VERSIONS; i++)
            {
                if (heights[i] > height)
                {
                    break;
                }
                ver = i;
            }
            return ver;
        }
};

class CBlockHeader;

class CPBaaSPreHeader
{
public:
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashFinalSaplingRoot;
    uint256 nNonce;
    uint32_t nBits;
    uint256 hashPrevMMRRoot;
    uint256 hashBlockMMRRoot;

    CPBaaSPreHeader() : nBits(0) {}
    CPBaaSPreHeader(const uint256 &prevBlock, const uint256 &merkleRoot, const uint256 &finalSaplingRoot,const uint256 &nonce, uint32_t compactTarget,
                    const uint256 &PrevMMRRoot, const uint256 &TransactionMMRRoot) :
                    hashPrevBlock(prevBlock), hashMerkleRoot(merkleRoot), hashFinalSaplingRoot(finalSaplingRoot), nNonce(nonce), nBits(compactTarget),
                    hashPrevMMRRoot(PrevMMRRoot), hashBlockMMRRoot(TransactionMMRRoot) {}

    CPBaaSPreHeader(const CBlockHeader &bh);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(hashFinalSaplingRoot);
        READWRITE(nNonce);
        READWRITE(nBits);
        READWRITE(hashPrevMMRRoot);
        READWRITE(hashBlockMMRRoot);
    }

    void SetBlockData(CBlockHeader &bh);

    UniValue ToUniValue() const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("hashprevblock", hashPrevBlock.GetHex());
        obj.pushKV("hashmerkleroot", hashMerkleRoot.GetHex());
        obj.pushKV("hashfinalsaplingroot", hashFinalSaplingRoot.GetHex());
        obj.pushKV("nNonce", nNonce.GetHex());
        obj.pushKV("nbits", (int64_t)nBits);
        obj.pushKV("hashprevmmrroot", hashPrevMMRRoot.GetHex());
        obj.pushKV("hashblockmmrroot", hashBlockMMRRoot.GetHex());
        return obj;
    }

    bool IsValid() const
    {
        return !(hashPrevBlock.IsNull() || hashMerkleRoot.IsNull() || hashFinalSaplingRoot.IsNull() || nNonce.IsNull() || !nBits || hashBlockMMRRoot.IsNull());
    }
};

// this class provides a minimal and compact hash pair and identity for a merge mined PBaaS header
class CPBaaSBlockHeader
{
public:
    uint160 chainID;                                                // hash of unique PBaaS symbol on Verus chain
    uint256 hashPreHeader;                                          // hash of block before solution + chain power + block number

    // header
    static const size_t ID_OFFSET = 0;                              // offset of 32 byte ID in serialized stream
    static const int32_t CURRENT_VERSION = CPOSNonce::VERUS_V2;
    static const int32_t CURRENT_VERSION_MASK = 0x0000ffff;         // for compatibility

    CPBaaSBlockHeader()
    {
        SetNull();
    }

    CPBaaSBlockHeader(const uint160 &cID, const uint256 &hashPre) : chainID(cID), hashPreHeader(hashPre) { }

    CPBaaSBlockHeader(const char *pbegin, const char *pend)
    {
        CDataStream s = CDataStream(pbegin, pend, SER_NETWORK, PROTOCOL_VERSION);
        s >> *this;
    }

    CPBaaSBlockHeader(const uint160 &cID, const CPBaaSPreHeader &pbph);

    CPBaaSBlockHeader(const uint160 &cID,
                        const uint256 &hashPrevBlock,
                        const uint256 &hashMerkleRoot,
                        const uint256 &hashFinalSaplingRoot,
                        const uint256 &nNonce,
                        uint32_t nBits,
                        const uint256 &hashPrevMMRRoot,
                        const uint256 &hashBlockMMRRoot)
    {
        CPBaaSPreHeader pbph(hashPrevBlock, hashMerkleRoot, hashFinalSaplingRoot, nNonce, nBits, hashPrevMMRRoot, hashBlockMMRRoot);

        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << pbph;

        hashPreHeader = hw.GetHash();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(chainID);
        READWRITE(hashPreHeader);
    }

    bool operator==(const CPBaaSBlockHeader &right)
    {
        return (chainID == right.chainID && hashPreHeader == right.hashPreHeader);
    }

    bool operator!=(const CPBaaSBlockHeader &right)
    {
        return (chainID != right.chainID || hashPreHeader != right.hashPreHeader);
    }

    void SetNull()
    {
        chainID.SetNull();
        hashPreHeader.SetNull();
    }

    bool IsNull() const
    {
        return chainID.IsNull();
    }
};

enum SolutionConstants
{
    SOLUTION_POW = 0x1,                                                 // if set, this is a PoW solution, otherwise, not
    SOLUTION_PBAAS_HEADER_SIZE = sizeof(CPBaaSBlockHeader)              // size of a processed PBAAS header
};

class CPBaaSSolutionDescriptor
{
    public:
        uint32_t version;
        uint8_t descrBits;
        uint8_t numPBaaSHeaders;                                       // these come right after the base and before the stream
        uint16_t extraDataSize;                                        // in PoS or possibly future blocks, this is a stream after PBaaS headers

        // this is additional data for the block specific header. this is also cleared out
        // when making a canonical header, and the values here are hashed into the pre-header hash
        uint256 hashPrevMMRRoot;                                       // prior block's Merkle Mountain Range
        uint256 hashBlockMMRRoot;                                      // this is the root MMR for transactions in this block
        // end block specific data

        CPBaaSSolutionDescriptor() : version(0), descrBits(0), numPBaaSHeaders(0), extraDataSize(0) {}

        CPBaaSSolutionDescriptor(uint32_t ver, uint8_t descr, uint8_t numSubHeaders, uint16_t sSize, uint256 PrevMMRRoot, uint256 TransactionMMRRoot) :
            version(ver), descrBits(descr), numPBaaSHeaders(numSubHeaders), extraDataSize(sSize), hashPrevMMRRoot(PrevMMRRoot), hashBlockMMRRoot(TransactionMMRRoot)
        {}

        CPBaaSSolutionDescriptor(const std::vector<unsigned char> &vch)
        {
            assert(vch.size() >= sizeof(*this));

            version = vch[0] + (vch[1] << 8) + (vch[2] << 16) + (vch[3] << 24);
            descrBits = vch[4];
            numPBaaSHeaders = vch[5];
            extraDataSize = vch[6] | ((uint16_t)(vch[7]) << 8);

            memcpy(hashPrevMMRRoot.begin(), &(vch[8]), sizeof(hashPrevMMRRoot));
            memcpy(hashBlockMMRRoot.begin(), &(vch[8 + sizeof(hashBlockMMRRoot)]), sizeof(hashBlockMMRRoot));
        }

        void SetVectorBase(std::vector<unsigned char> &vch)
        {
            if (vch.size() >= sizeof(*this))
            {
                vch[0] = version & 0xff;
                vch[1] = (version >> 8) & 0xff;
                vch[2] = (version >> 16) & 0xff;
                vch[3] = (version >> 24) & 0xff;
                vch[4] = descrBits;
                vch[5] = numPBaaSHeaders;
                vch[6] = extraDataSize & 0xff;
                vch[7] = (extraDataSize >> 8) & 0xff;

                memcpy(&(vch[8]), hashPrevMMRRoot.begin(), sizeof(hashPrevMMRRoot));
                memcpy(&(vch[8 + sizeof(hashBlockMMRRoot)]), hashBlockMMRRoot.begin(), sizeof(hashBlockMMRRoot));
            }
        }
};

class CConstVerusSolutionVector
{
    public:
        static const bool SOLUTION_SIZE_FIXED = true;
        static const uint32_t HEADER_BASESIZE = 143;
        static const uint32_t SOLUTION_SIZE = 1344;
        static const uint32_t OVERHEAD_SIZE = sizeof(CPBaaSSolutionDescriptor);

        static CActivationHeight activationHeight;

        CConstVerusSolutionVector() {}

        static uint32_t GetVersionByHeight(uint32_t height)
        {
            return activationHeight.ActiveVersion(height);
        }

        static uint32_t Version(const std::vector<unsigned char> &vch)
        {
            if (activationHeight.ActiveVersion(0x7fffffff) > 0)
            {
                return CPBaaSSolutionDescriptor(vch).version;
            }
            else
            {
                return 0;
            }
        }

        static bool SetVersion(std::vector<unsigned char> &vch, uint32_t v)
        {
            CPBaaSSolutionDescriptor psd = CPBaaSSolutionDescriptor(vch);
            psd.version = v;
            if (activationHeight.active && vch.size() >= sizeof(CPBaaSSolutionDescriptor))
            {
                psd.SetVectorBase(vch);
                return true;
            }
            else
            {
                return false;
            }
        }

        static bool SetVersionByHeight(std::vector<unsigned char> &vch, uint32_t height)
        {
            return SetVersion(vch, activationHeight.ActiveVersion(height));
        }

        static void SetDescriptor(std::vector<unsigned char> &vch, CPBaaSSolutionDescriptor d)
        {
            d.SetVectorBase(vch);
        }

        static CPBaaSSolutionDescriptor GetDescriptor(const std::vector<unsigned char> &vch)
        {
            return CPBaaSSolutionDescriptor(vch);
        }

        static uint32_t DescriptorBits(const std::vector<unsigned char> &vch)
        {
            return GetDescriptor(vch).descrBits;
        }

        static uint32_t GetNumPBaaSHeaders(const std::vector<unsigned char> &vch)
        {
            return GetDescriptor(vch).numPBaaSHeaders;
        }

        static uint32_t MaxPBaaSHeaders(const std::vector<unsigned char> &vch)
        {
            auto descr = GetDescriptor(vch);

            return descr.extraDataSize ? descr.numPBaaSHeaders : descr.numPBaaSHeaders + (uint32_t)(ExtraDataLen(vch) / sizeof(CPBaaSBlockHeader));
        }

        static bool SetDescriptorBits(std::vector<unsigned char> &vch, uint8_t dBits)
        {
            CPBaaSSolutionDescriptor psd = CPBaaSSolutionDescriptor(vch);
            psd.descrBits = dBits;
            if (activationHeight.active && vch.size() >= sizeof(CPBaaSSolutionDescriptor))
            {
                psd.SetVectorBase(vch);
                return true;
            }
            else
            {
                return false;
            }
        }

        // returns 0 if not PBaaS, 1 if PBaaS PoW, -1 if PBaaS PoS
        static int32_t IsAdvancedSolution(const std::vector<unsigned char> &vch)
        {
            if (Version(vch) >= CActivationHeight::ACTIVATE_PBAAS)
            {
                return  (DescriptorBits(vch) & SOLUTION_POW) ? 1 : -1;
            }
            return 0;
        }

        static int32_t HasPBaaSHeader(const std::vector<unsigned char> &vch)
        {
            if (Version(vch) >= CActivationHeight::ACTIVATE_PBAAS_HEADER)
            {
                return  (DescriptorBits(vch) & SOLUTION_POW) ? 1 : -1;
            }
            return 0;
        }

        static const CPBaaSBlockHeader *GetFirstPBaaSHeader(const std::vector<unsigned char> &vch)
        {
            return (CPBaaSBlockHeader *)(&vch[0] + sizeof(CPBaaSSolutionDescriptor)); // any headers present are right after descriptor
        }

        static void SetPBaaSHeader(std::vector<unsigned char> &vch, const CPBaaSBlockHeader &pbh, int32_t idx);

        static uint32_t HeadersOverheadSize(const std::vector<unsigned char> &vch)
        {
            return GetDescriptor(vch).numPBaaSHeaders * sizeof(CPBaaSBlockHeader) + OVERHEAD_SIZE;
        }

        static uint32_t ExtraDataLen(const std::vector<unsigned char> &vch, bool allowPBaaSHeader=false)
        {
            int len;

            if (!(Version(vch) >= CActivationHeight::ACTIVATE_PBAAS || (allowPBaaSHeader && Version(vch) >= CActivationHeight::ACTIVATE_PBAAS_HEADER)))
            {
                len = 0;
            }
            else
            {
                // calculate number of bytes, minus the OVERHEAD_SIZE byte version and extra nonce at the end of the solution
                len = (vch.size() - ((HEADER_BASESIZE + vch.size()) % 32 + HeadersOverheadSize(vch)));
            }

            return len < 0 ? 0 : (uint32_t)len;
        }

        // return a pointer to the bytes that contain the internal data for this solution vector
        const unsigned char *ExtraDataPtr(const std::vector<unsigned char> &vch)
        {
            if (ExtraDataLen(vch))
            {
                return &(vch.data()[OVERHEAD_SIZE]);
            }
            else
            {
                return NULL;
            }
        }
};

class CVerusSolutionVector
{
    private:
        std::vector<unsigned char> &vch;

    public:
        static CConstVerusSolutionVector solutionTools;

        CVerusSolutionVector(std::vector<unsigned char> &_vch) : vch(_vch) { }

        static uint32_t GetVersionByHeight(uint32_t height)
        {
            return solutionTools.GetVersionByHeight(height);
        }

        uint32_t Version()
        {
            return solutionTools.Version(vch);
        }

        bool SetVersion(uint32_t v)
        {
            return solutionTools.SetVersion(vch, v);
        }

        bool SetVersionByHeight(uint32_t height)
        {
            return solutionTools.SetVersionByHeight(vch, height);
        }

        CPBaaSSolutionDescriptor Descriptor()
        {
            return solutionTools.GetDescriptor(vch);
        }

        void SetDescriptor(CPBaaSSolutionDescriptor d)
        {
            solutionTools.SetDescriptor(vch, d);
        }

        uint32_t DescriptorBits()
        {
            return solutionTools.DescriptorBits(vch);
        }

        bool SetDescriptorBits(uint32_t d)
        {
            return solutionTools.SetDescriptorBits(vch, d);
        }

        // returns 0 if not PBaaS, 1 if PBaaS PoW, -1 if PBaaS PoS
        int32_t IsAdvancedSolution()
        {
            return solutionTools.IsAdvancedSolution(vch);
        }

        // returns 0 if not PBaaS, 1 if PBaaS PoW, -1 if PBaaS PoS
        int32_t HasPBaaSHeader()
        {
            return solutionTools.HasPBaaSHeader(vch);
        }

        const CPBaaSBlockHeader *GetFirstPBaaSHeader() const
        {
            return solutionTools.GetFirstPBaaSHeader(vch);
        }

        uint32_t GetNumPBaaSHeaders() const
        {
            return solutionTools.GetNumPBaaSHeaders(vch);
        }

        bool GetPBaaSHeader(CPBaaSBlockHeader &pbh, uint32_t idx) const;

        void SetPBaaSHeader(const CPBaaSBlockHeader &pbh, uint32_t idx)
        {
            solutionTools.SetPBaaSHeader(vch, pbh, idx);
        }

        uint32_t HeadersOverheadSize()
        {
            return Descriptor().numPBaaSHeaders * sizeof(CPBaaSBlockHeader) + solutionTools.OVERHEAD_SIZE;
        }

        // return length of the internal data for this solution vector
        uint32_t ExtraDataLen()
        {
            int len;

            if (Version() < CActivationHeight::ACTIVATE_PBAAS)
            {
                len = 0;
            }
            else
            {
                // calculate number of bytes, minus the OVERHEAD_SIZE byte version and extra nonce at the end of the solution
                len = (vch.size() - ((solutionTools.HEADER_BASESIZE + vch.size()) % 32 + HeadersOverheadSize()));
            }

            return len < 0 ? 0 : (uint32_t)len;
        }

        uint32_t GetRequiredSolutionSize(uint32_t extraDataLen)
        {
            // round up to nearest 32 bytes
            uint32_t overhead = HeadersOverheadSize();

            // make sure we have 15 bytes extra for hashing properly
            return extraDataLen + overhead + (47 - ((extraDataLen + overhead + solutionTools.HEADER_BASESIZE) % 32));
        }

        void ResizeExtraData(uint32_t newSize)
        {
            vch.resize(GetRequiredSolutionSize(newSize));
        }

        // return a pointer to bytes that contain the internal data for this solution vector
        unsigned char *ExtraDataPtr()
        {
            if (ExtraDataLen())
            {
                return &(vch.data()[HeadersOverheadSize()]);
            }
            else
            {
                return NULL;
            }
        }

        // return a vector of bytes that contains the extra data for this solution vector, used for
        // stream data typically and stored after PBaaS headers
        void GetExtraData(std::vector<unsigned char> &dataVec)
        {
            int len = Descriptor().extraDataSize;

            if (len > 0)
            {
                dataVec.resize(len);
                std::memcpy(dataVec.data(), ExtraDataPtr(), len);
            }
            else
            {
                dataVec.clear();
            }
        }

        // set the extra data with a pointer to bytes and length
        bool SetExtraData(const unsigned char *pbegin, uint32_t len)
        {
            if (Version() < CActivationHeight::ACTIVATE_PBAAS || len > ExtraDataLen())
            {
                return false;
            }
            auto descr = Descriptor();
            descr.extraDataSize = len;
            SetDescriptor(descr);
            std::memcpy(ExtraDataPtr(), pbegin, len);
            return true;
        }
};

// Simple RLE compression for solutions to reduce memory footprint of active chain
class CCompactSolutionVector
{
    private:
        static bool useCompression;
        std::vector<std::pair<uint16_t,uint16_t>>  ofsAndRepeat;

        enum Constants {
            MIN_RLE_LEN = 6
        };

    public:
        std::vector<unsigned char> vch;
        uint16_t _size;

        CCompactSolutionVector(const std::vector<unsigned char> &_vch) : _size(_vch.size())
        {
            if (!useCompression)
            {
                vch = _vch;
                return;
            }
            std::vector<unsigned char> tVch;
            if (!_size)
            {
                return;
            }
            tVch.reserve(_size);
            tVch.push_back(_vch[0]);

            int lastPos = 0;
            int i = 0;
            for (i = 1; i < _vch.size(); i++)
            {
                bool isSame = tVch.back() == _vch[i];
                if (isSame && (i - lastPos) == MIN_RLE_LEN)
                {
                    // keep the char we will repeat, remove the rest
                    tVch.resize(tVch.size() - (MIN_RLE_LEN - 1));
                }
                else if ((i - lastPos) > MIN_RLE_LEN)
                {
                    // if we've got a different character, close off the compression
                    if (!isSame)
                    {
                        tVch.push_back(_vch[i]);
                        ofsAndRepeat.push_back({lastPos, (i - lastPos) - 1});
                        lastPos = i;
                    }
                }
                else
                {
                    tVch.push_back(_vch[i]);
                    if (!isSame)
                    {
                        lastPos = i;
                    }
                }
            }
            // if we left a compression open, close it
            if ((i - lastPos) > MIN_RLE_LEN)
            {
                ofsAndRepeat.push_back({lastPos, ((i - lastPos) - 1)});
            }
            vch = tVch;
        }

        CCompactSolutionVector() : _size(0) {}

        CCompactSolutionVector &operator=(const std::vector<unsigned char> &_vch)
        {
            CCompactSolutionVector newVec(_vch);
            *this = newVec;
            // LogPrint("compactsolution", "Original vector:\n%s\nnewVec:\n%s\n", HexBytes(_vch.data(), _vch.size()), HexBytes(this->nSolution().data(), this->nSolution().size()));
            return *this;
        }

        size_t size() const
        {
            return _size;
        }

        std::vector<unsigned char> nSolution() const
        {
            if (!ofsAndRepeat.size())
            {
                return vch;
            }
            std::vector<unsigned char> tVch;
            tVch.reserve(_size);
            tVch.insert(tVch.begin(), vch.begin(), vch.end());
            for (int i = 0; i < ofsAndRepeat.size(); i++)
            {
                tVch.insert(tVch.begin() + (int)(ofsAndRepeat[i].first), ofsAndRepeat[i].second, tVch[ofsAndRepeat[i].first]);
            }
            return tVch;
        }

        static bool IsCompressionOn()
        {
            return useCompression;
        }

        static bool SetCompression(bool setOn)
        {
            useCompression = setOn;
            return useCompression;
        }
};

#endif // BITCOIN_PRIMITIVES_SOLUTIONDATA_H
