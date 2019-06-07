/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This is an implementation of a Merkle Mountain Range that can work on a variety of node types and is optimized for the following uses:
 * 1. Easy append of new elements without invalidate or change of any prior proofs
 * 2. Fast, simple rewind/truncate to previous size
 * 3. Fast, state view into the MMR at any given prior size, making creation of
 *    any proof from any prior, valid state a simple matter
 * 4. Support for additional information to be captured and propagated along with the
 *    MMR through nodes that may have a more complex combination step, for example, to track aggregate work and stake (power) across all
 *    headers in a chain.
 */

#ifndef MMR_H
#define MMR_H

#include <vector>

//#include "CCinclude.h"
#include "streams.h"
#include "script/script.h"
#include "sync.h"
#include "hash.h"
#include "arith_uint256.h"

#ifndef BEGIN
#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))
#define UBEGIN(a)           ((unsigned char*)&(a))
#define UEND(a)             ((unsigned char*)&((&(a))[1]))
#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))
#endif

class CMerkleBranch
{
public:
    uint64_t nIndex;
    std::vector<uint256> branch;

    CMerkleBranch() : nIndex(0) {}
    CMerkleBranch(int i, std::vector<uint256> b) : nIndex(i), branch(b) {}

    CMerkleBranch& operator<<(CMerkleBranch append)
    {
        nIndex += append.nIndex << branch.size();
        branch.insert(branch.end(), append.branch.begin(), append.branch.end());
        return *this;
    }

    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nIndex));
        READWRITE(branch);
    }

    std::string HashAbbrev(uint256 hash) const
    {
        std::string ret;
        for (int i = 0; i < 5; i++)
        {
            ret += " " + std::to_string(*((uint8_t *)&hash + i));
        }
        return ret;
    }

    uint256 SafeCheck(uint256 hash) const
    {
        auto index = nIndex;
        if (index == -1)
            return uint256();

        // printf("start SafeCheck branch.size(): %lu, index: %lu, hash: %s\n", branch.size(), index, HashAbbrev(hash).c_str());
        for (auto it(branch.begin()); it != branch.end(); ++it)
        {
            if (index & 1) 
            {
                if (*it == hash) 
                {
                    // non canonical. hash may be equal to node but never on the right.
                    return uint256();
                }
                // printf("hashing: %s + %s\n", HashAbbrev(*it).c_str(), HashAbbrev(hash).c_str());
                hash = Hash(BEGIN(*it), END(*it), BEGIN(hash), END(hash));
                // printf("after left: %s\n", HashAbbrev(hash).c_str());
            }
            else
            {
                // printf("hashing: %s + %s\n", HashAbbrev(hash).c_str(), HashAbbrev(*it).c_str());
                hash = Hash(BEGIN(hash), END(hash), BEGIN(*it), END(*it));
                // printf("after right: %s\n", HashAbbrev(hash).c_str());
            }
            index >>= 1;
        }
        // printf("end SafeCheck\n");
        return hash;
    }
};

class CMMRNode
{
public:
    uint256 hash;
    CMMRNode() {}
    CMMRNode(uint256 Hash) : hash(Hash) {}

    // add a right to this left and create a parent node
    CMMRNode CreateParentNode(const CMMRNode nRight) const
    {
        return CMMRNode(Hash(BEGIN(hash), END(hash), BEGIN(nRight.hash), END(nRight.hash)));
    }

    void AddProofHash(CMerkleBranch &branch, uint64_t indexBit, const CMMRNode &opposite) const
    {
        branch.nIndex |= (indexBit & 1) << branch.branch.size();
        branch.branch.push_back(hash);
    }

    // leaf nodes that track additional data, such as block power, may need a hash added to the path
    // at the very beginning
    void AddLeafHash(CMerkleBranch &branch) const { }

    uint32_t GetExtraHashCount() const
    {
        // how many extra proof hashes per layer are added with this node
        return 0;
    }
};

class CMMRPowerNode
{
public:
    uint256 hash;
    uint256 power;

    CMMRPowerNode() : hash() {}
    CMMRPowerNode(uint256 Hash, uint256 Power) : hash(Hash), power(Power) {}

    arith_uint256 Work() const
    {
        return (UintToArith256(power) << 128) >> 128;
    }

    arith_uint256 Stake() const
    {
        return UintToArith256(power) >> 128;
    }

    // add a right to this left and create a parent node
    CMMRPowerNode CreateParentNode(const CMMRPowerNode nRight) const
    {
        arith_uint256 work = Work() + nRight.Work();
        arith_uint256 stake = Stake() + nRight.Stake();
        assert(work << 128 >> 128 == work && stake << 128 >> 128 == stake);

        uint256 nodePower = ArithToUint256(stake << 128 | work);
        uint256 preHash = Hash(BEGIN(hash), END(hash), BEGIN(nRight.hash), END(nRight.hash));

        // these separate hashing steps allow the proof to be represented just as a Merkle proof, with steps along the way
        // hashing with nodePower instead of other hashes
        return CMMRPowerNode(Hash(BEGIN(preHash), END(preHash), BEGIN(nodePower), END(nodePower)), nodePower);
    }

    void AddProofHash(CMerkleBranch &branch, uint64_t indexBit, const CMMRPowerNode &proving) const
    {
        branch.nIndex |= (indexBit & 1) << branch.branch.size();
        branch.branch.push_back(hash);                                  // add the hash and get the right shift value for the bit

        arith_uint256 work = Work() + proving.Work();
        arith_uint256 stake = Stake() + proving.Stake();
        branch.branch.push_back(ArithToUint256(stake << 128 | work));   // hash with combined power
    }

    // leaf nodes that track additional data, such as block power, may need a hash added to the path
    // at the very beginning
    void AddLeafHash(CMerkleBranch &branch) const
    {
        branch.branch.push_back(power);      // power on the right as well
    }

    static uint32_t GetExtraHashCount()
    {
        // how many extra proof hashes per layer are added with this node
        return 1;
    }
};

template <typename NODE_TYPE, int CHUNK_SHIFT = 9>
class CChunkedLayer
{
private:
    uint64_t vSize;
    std::vector<std::vector<NODE_TYPE>> nodes;

public:
    CChunkedLayer() : nodes(), vSize(0) {}

    static inline uint64_t chunkSize()
    {
        return 1 << CHUNK_SHIFT;
    }

    static inline uint64_t chunkMask()
    {
        return chunkSize() - 1;
    }

    uint64_t size() const
    {
        return vSize;
    }

    NODE_TYPE operator[](uint64_t idx) const
    {
        if (idx < vSize)
        {
            return nodes[idx >> CHUNK_SHIFT][idx & chunkMask()];
        }
    }

    void push_back(NODE_TYPE node)
    {
        vSize++;

        // if we wrapped around and need more space, we need to allocate a new chunk
        // printf("vSize: %lx, chunkMask: %lx\n", vSize, chunkMask());

        if ((vSize & chunkMask()) == 1)
        {
            nodes.push_back(std::vector<NODE_TYPE>());
            nodes.back().reserve(chunkSize());
        }
        nodes.back().push_back(node);
        // printf("nodes.size(): %lu\n", nodes.size());
    }

    void clear()
    {
        nodes.clear();
        vSize = 0;
    }

    void resize(uint64_t newSize)
    {
        if (newSize == 0)
        {
            clear();
        }
        else
        {
            uint64_t chunksSize = ((newSize - 1) >> CHUNK_SHIFT) + 1;
            nodes.resize(chunksSize);
            for (uint64_t i = size() ? ((size() - 1) >> CHUNK_SHIFT) + 1 : 1; i <= chunksSize; i++)
            {
                if (i < chunksSize)
                {
                    nodes.back().resize(chunkSize());
                }
                else
                {
                    nodes.back().reserve(chunkSize());
                    nodes.back().resize(((newSize - 1) & chunkMask()) + 1);
                }
            }

            vSize = ((nodes.size() - 1) << CHUNK_SHIFT) + ((newSize - 1) & chunkMask()) + 1;
        }
    }

    void Printout() const
    {
        printf("vSize: %lu, first vector size: %lu\n", vSize, vSize ? nodes[0].size() : vSize);
    }
};

// NODE_TYPE must have a default constructor
template <typename NODE_TYPE, typename UNDERLYING>
class COverlayNodeLayer
{
private:
    UNDERLYING *nodeSource;
    uint64_t vSize;

public:
    COverlayNodeLayer() { }
    COverlayNodeLayer(UNDERLYING &NodeSource) : nodeSource(&NodeSource), vSize(0) {}

    uint64_t size() const
    {
        return vSize;
    }

    NODE_TYPE operator[](uint64_t idx) const
    {
        if (idx < vSize)
        {
            return nodeSource->GetMMRNode(idx);
        }
    }

    // node type must be moveable just to be passed here, but the default overlay has no control over the underlying storage
    // and only tracks size changes
    void push_back(NODE_TYPE node) { vSize++; }
    void clear() { vSize = 0; }
    void resize(uint64_t newSize) { vSize = newSize; }
};

// an in memory MMR is represented by a vector of vectors of hashes, each being a layer of nodes of the binary tree, with the lowest layer
// being the leaf nodes, and the layers above representing full layers in a mountain or when less than half the length of the layer below,
// representing a peak.
template <typename NODE_TYPE, typename LAYER_TYPE=CChunkedLayer<NODE_TYPE>, typename LAYER0_TYPE=LAYER_TYPE>
class CMerkleMountainRange
{
public:
    std::vector<LAYER_TYPE> upperNodes;
    LAYER0_TYPE layer0;

    CMerkleMountainRange() { }

    CMerkleMountainRange(LAYER0_TYPE Layer0)
    {
        layer0 = Layer0;
    }

    // add a leaf node and return the new index. this copies the memory of the leaf node, but does not keep the node itself
    // returns the index # of the new item
    uint64_t Add(NODE_TYPE leaf)
    {
        layer0.push_back(leaf);

        uint32_t height = 0;
        uint32_t layerSize;
        for (layerSize = layer0.size(); height <= upperNodes.size() && layerSize > 1; height++)
        {
            uint32_t newSizeAbove = layerSize >> 1;

            // expand vector of vectors if we are adding a new layer
            if (height == upperNodes.size())
            {
                upperNodes.resize(upperNodes.size() + 1);
                // printf("adding2: upperNodes.size(): %lu, upperNodes[%d].size(): %lu\n", upperNodes.size(), height, height && upperNodes.size() ? upperNodes[height-1].size() : 0);
            }

            uint32_t curSizeAbove = upperNodes[height].size();

            // if we need to add an element to the vector above us, do it
            // printf("layerSize: %u, newSizeAbove: %u, curSizeAbove: %u\n", layerSize, newSizeAbove, curSizeAbove);
            if (!(layerSize & 1) && newSizeAbove > curSizeAbove)
            {
                uint32_t idx = layerSize - 2;
                if (height)
                {
                    // printf("upperNodes.size(): %lu, upperNodes[%d].size(): %lu, upperNodes[%d].size(): %lu\n", upperNodes.size(), height, upperNodes[height].size(), height - 1, upperNodes[height - 1].size());
                    // upperNodes[height - 1].Printout();
                    // upperNodes[height].Printout();
                    // printf("upperNodes[%d].size(): %lu, nodep hash: %s\n", height - 1, upperNodes[height - 1].size(), upperNodes[height - 1][idx].hash.GetHex().c_str());
                    // printf("nodep + 1 hash: %p\n", upperNodes[height - 1][idx + 1].hash.GetHex().c_str());
                    upperNodes[height].push_back(upperNodes[height - 1][idx].CreateParentNode(upperNodes[height - 1][idx + 1]));
                }
                else
                {
                    upperNodes[height].push_back(layer0[idx].CreateParentNode(layer0[idx + 1]));
                    // printf("upperNodes.size(): %lu, upperNodes[%d].size(): %lu\n", upperNodes.size(), height, upperNodes[height].size());
                    // upperNodes[height].Printout();
                }
            }
            layerSize = newSizeAbove;
        }
        // return new index
        return layer0.size() - 1;
    }

    // add a default node
    uint64_t Add()
    {
        return Add(NODE_TYPE());
    }

    uint64_t size() const
    {
        return layer0.size();
    }

    uint32_t height() const
    {
        return layer0.size() ? upperNodes.size() + 1 : 0;
    }

    // returns the level 0 node at a particular location, or NULL if not present
    NODE_TYPE operator[](uint64_t pos) const
    {
        if (pos >= size())
        {
            return NULL;
        }
        return layer0[pos];
    }

    NODE_TYPE GetNode(uint32_t Height, uint64_t Index) const
    {
        uint32_t layers = height();
        if (Height < layers)
        {
            if (Height)
            {
                if (Index < upperNodes[Height - 1].size())
                {
                    return upperNodes[Height - 1][Index];
                }
            }
            else
            {
                if (Index < layer0.size())
                {
                    return layer0[Index];
                }
            }
        }
        return NODE_TYPE();
    }

    NODE_TYPE GetNode(uint32_t index) const
    {
        return GetNode(0, index);
    }

    // truncate to a specific size smaller than the current size
    // this has the potential to create catastrophic problems for views of the current
    // mountain range that continue to use the mountain range after it is truncated
    // THIS SHOULD BE SYNCHRONIZED WITH ANY USE OF VIEWS FROM THIS MOUNTAIN RANGE THAT
    // MAY EXTEND BEYOND THE TRUNCATION
    void Truncate(uint64_t newSize)
    {
        std::vector<uint64_t> sizes;

        uint64_t curSize = size();
        if (newSize < curSize)
        {
            uint64_t maxSize = size();
            if (newSize > maxSize)
            {
                newSize = maxSize;
            }
            sizes.push_back(newSize);
            newSize >>= 1;

            while (newSize)
            {
                sizes.push_back(newSize);
                newSize >>= 1;
            }

            upperNodes.resize(sizes.size() - 1);
            layer0.resize(sizes[0]);
            for (int i = 0; i < upperNodes.size(); i++)
            {
                upperNodes[i].resize(sizes[i + 1]);
            }
        }
    }
};

// a view of a merkle mountain range with the size of the range set to a specific position that is less than or equal
// to the size of the underlying range
template <typename NODE_TYPE, typename LAYER_TYPE=CChunkedLayer<NODE_TYPE>, typename LAYER0_TYPE=LAYER_TYPE>
class CMerkleMountainView
{
public:
    const CMerkleMountainRange<NODE_TYPE, LAYER_TYPE, LAYER0_TYPE> &mmr; // the underlying mountain range, which provides the hash vectors
    std::vector<uint64_t> sizes;                    // sizes that we will use as proxies for the size of each vector at each height
    std::vector<NODE_TYPE> peaks;                   // peaks
    std::vector<std::vector<NODE_TYPE>> peakMerkle; // cached layers for the peak merkle if needed

    CMerkleMountainView(const CMerkleMountainRange<NODE_TYPE, LAYER_TYPE, LAYER0_TYPE> &mountainRange, uint64_t viewSize) : mmr(mountainRange), peaks(), peakMerkle()
    {
        uint64_t maxSize = mountainRange.size();
        if (viewSize > maxSize)
        {
            viewSize = maxSize;
        }
        sizes.push_back(viewSize);

        for (viewSize >>= 1; viewSize; viewSize >>= 1)
        {
            sizes.push_back(viewSize);
            /*
            printf("sizes height: %lu, values:\n", sizes.size());
            for (auto s : sizes)
            {
                printf("%lu\n", s);
            }
            */
        }
    }

    CMerkleMountainView(const CMerkleMountainView &mountainView, uint64_t viewSize) : mmr(mountainView.mmr)
    {
        uint64_t maxSize = mountainView.mmr.size();
        if (viewSize > maxSize)
        {
            viewSize = maxSize;
        }
        sizes.push_back(viewSize);
        viewSize >>= 1;

        while (viewSize)
        {
            sizes.push_back(viewSize);
            viewSize >>= 1;
        }
    }

    // how many elements are stored in this view
    uint64_t size()
    {
        // zero if empty or the size of the zeroeth layer
        return sizes.size() == 0 ? 0 : sizes[0];
    }

    void CalcPeaks(bool force = false)
    {
        // if we don't yet have calculated peaks, calculate them
        if (force || (peaks.size() == 0 && size() != 0))
        {
            // reset the peak merkle tree, in case this is forced
            peaks.clear();
            peakMerkle.clear();
            for (int ht = 0; ht < sizes.size(); ht++)
            {
                // if we're at the top or the layer above us is smaller than 1/2 the size of this layer, rounded up, we are a peak
                if (ht == (sizes.size() - 1) || sizes[ht + 1] < ((sizes[ht] + 1) >> 1))
                {
                    peaks.insert(peaks.begin(), mmr.GetNode(ht, sizes[ht] - 1));
                }
            }
        }
    }

    uint64_t resize(uint64_t newSize)
    {
        if (newSize != size())
        {
            sizes.clear();
            peaks.clear();
            peakMerkle.clear();

            uint64_t maxSize = mmr.size();
            if (newSize > maxSize)
            {
                newSize = maxSize;
            }
            sizes.push_back(newSize);
            newSize >>= 1;

            while (newSize)
            {
                sizes.push_back(newSize);
                newSize >>= 1;
            }
        }
        return size();
    }

    uint64_t maxsize()
    {
        return mmr.size() - 1;
    }

    const std::vector<NODE_TYPE> &GetPeaks()
    {
        CalcPeaks();
        return peaks;
    }

    uint256 GetRoot()
    {
        uint256 rootHash;

        if (size() > 0 && peakMerkle.size() == 0)
        {
            // get peaks and hash to a root
            CalcPeaks();

            uint32_t layerNum = 0, layerSize = peaks.size();
            // with an odd number of elements below, the edge passes through
            for (bool passThrough = (layerSize & 1); layerNum == 0 || layerSize > 1; passThrough = (layerSize & 1), layerNum++)
            {
                peakMerkle.push_back(std::vector<NODE_TYPE>());

                uint64_t i;
                uint32_t layerIndex = layerNum ? layerNum - 1 : 0;      // layerNum is base 1

                for (i = 0; i < (layerSize >> 1); i++)
                {
                    if (layerNum)
                    {
                        peakMerkle.back().push_back(peakMerkle[layerIndex][i << 1].CreateParentNode(peakMerkle[layerIndex][(i << 1) + 1]));
                    }
                    else
                    {
                        peakMerkle.back().push_back(peaks[i << 1].CreateParentNode(peaks[(i << 1) + 1]));
                    }
                }
                if (passThrough)
                {
                    if (layerNum)
                    {
                        // pass the end of the prior layer through
                        peakMerkle.back().push_back(peakMerkle[layerIndex].back());
                    }
                    else
                    {
                        peakMerkle.back().push_back(peaks.back());
                    }
                }
                // each entry in the next layer should be either combined two of the prior layer, or a duplicate of the prior layer's end
                layerSize = peakMerkle.back().size();
            }
            rootHash = peakMerkle.back()[0].hash;
        }
        else if (peakMerkle.size() > 0)
        {
            rootHash = peakMerkle.back()[0].hash;
        }
        return rootHash;
    }

    const NODE_TYPE *GetRootNode()
    {
        // ensure merkle tree is calculated
        uint256 root = GetRoot();
        if (!root.IsNull())
        {
            return &(peakMerkle.back()[0]);
        }
        else
        {
            return NULL;
        }
    }

    // return hash of the element at "index"
    uint256 GetHash(uint64_t index)
    {
        if (index < size())
        {
            return mmr.layer0[index].hash;
        }
        else
        {
            return uint256();
        }
    }

    // return a proof of the element at "index"
    bool GetProof(CMerkleBranch &retBranch, uint64_t pos)
    {
        // find a path from the indicated position to the root in the current view
        if (pos < size())
        {
            // just make sure the peakMerkle tree is calculated
            GetRoot();

            mmr.layer0[pos].AddLeafHash(retBranch);

            uint64_t p = pos;
            for (int l = 0; l < sizes.size(); l++)
            {
                if (p & 1)
                {
                    // if we should hash with the element preceding us to get the node above
                    mmr.GetNode(l, p - 1).AddProofHash(retBranch, 1, mmr.GetNode(l, p));
                    p >>= 1;
                }
                else
                {
                    // make sure there is one after us to hash with or we are a peak and should be hashed with the rest of the peaks
                    if (sizes[l] > (p + 1))
                    {
                        mmr.GetNode(l, p + 1).AddProofHash(retBranch, 0, mmr.GetNode(l, p));
                        p >>= 1;
                    }
                    else
                    {
                        // we are at a peak, the alternate peak to us, or the next thing we should be hashed with, if there is one, is next on our path
                        uint256 peakHash = mmr.GetNode(l, p).hash;

                        // linear search to find out which peak we are in the base of the peakMerkle
                        for (p = 0; p < peaks.size(); p++)
                        {
                            if (peaks[p].hash == peakHash)
                            {
                                break;
                            }
                        }

                        // p is the position in the merkle tree of peaks
                        assert(p < peaks.size());

                        // move up to the top, which is always a peak of size 1
                        uint32_t layerNum, layerSize;
                        for (layerNum = 0, layerSize = peaks.size(); layerNum == 0 || layerSize > 1; layerSize = peakMerkle[layerNum++].size())
                        {
                            uint32_t layerIndex = layerNum ? layerNum - 1 : 0;      // layerNum is base 1

                            // we are an odd member on the end (even index) and will not hash with the next layer above, we will propagate to its end
                            if ((p < layerSize - 1) || (p & 1))
                            {
                                if (p & 1)
                                {
                                    // hash with the one before us
                                    if (layerNum)
                                    {
                                        peakMerkle[layerIndex][p - 1].AddProofHash(retBranch, 1, peakMerkle[layerIndex][p]);
                                    }
                                    else
                                    {
                                        peaks[p - 1].AddProofHash(retBranch, 1, peaks[p]);
                                    }
                                }
                                else
                                {
                                    // hash with the one in front of us
                                    if (layerNum)
                                    {
                                        peakMerkle[layerIndex][p + 1].AddProofHash(retBranch, 0, peakMerkle[layerIndex][p]);
                                    }
                                    else
                                    {
                                        peaks[p + 1].AddProofHash(retBranch, 0, peaks[p]);
                                    }
                                }
                            }
                            p >>= 1;
                        }

                        // finished
                        break;
                    }
                }
            }
            return true;
        }
        return false;
    }

    // return a vector of the bits, either 1 or 0 in each byte, to represent both the size
    // of the proof by the size of the vector, and the expected bit in each position for the given
    // position in a Merkle Mountain View of the specified size
    static std::vector<unsigned char> GetProofBits(uint64_t pos, uint64_t mmvSize)
    {
        std::vector<unsigned char> Bits;
        std::vector<uint64_t> Sizes;
        std::vector<unsigned char> PeakIndexes;
        std::vector<uint64_t> MerkleSizes;

        // printf("GetProofBits - pos: %lu, mmvSize: %lu\n", pos, mmvSize);

        // find a path from the indicated position to the root in the current view
        if (pos < mmvSize)
        {
            int extrahashes = NODE_TYPE::GetExtraHashCount();

            Sizes.push_back(mmvSize);
            mmvSize >>= 1;

            while (mmvSize)
            {
                Sizes.push_back(mmvSize);
                mmvSize >>= 1;
            }

            for (uint32_t ht = 0; ht < Sizes.size(); ht++)
            {
                // if we're at the top or the layer above us is smaller than 1/2 the size of this layer, rounded up, we are a peak
                if (ht == ((uint32_t)Sizes.size() - 1) || (Sizes[ht] & 1))
                {
                    PeakIndexes.insert(PeakIndexes.begin(), ht);
                }
            }

            uint64_t layerNum = 0, layerSize = PeakIndexes.size();
            // with an odd number of elements below, the edge passes through
            for (bool passThrough = (layerSize & 1); layerNum == 0 || layerSize > 1; passThrough = (layerSize & 1), layerNum++)
            {
                layerSize = (layerSize >> 1) + passThrough;
                if (layerSize)
                {
                    MerkleSizes.push_back(layerSize);
                }
            }

            // add extra hashes for a node on the right
            for (int i = 0; i < extrahashes; i++)
            {
                Bits.push_back(0);
            }

            uint64_t p = pos;
            for (int l = 0; l < Sizes.size(); l++)
            {
                // printf("GetProofBits - Bits.size: %lu\n", Bits.size());

                if (p & 1)
                {
                    Bits.push_back(1);
                    p >>= 1;

                    for (int i = 0; i < extrahashes; i++)
                    {
                        Bits.push_back(0);
                    }
                }
                else
                {
                    // make sure there is one after us to hash with or we are a peak and should be hashed with the rest of the peaks
                    if (Sizes[l] > (p + 1))
                    {
                        Bits.push_back(0);
                        p >>= 1;

                        for (int i = 0; i < extrahashes; i++)
                        {
                            Bits.push_back(0);
                        }
                    }
                    else
                    {
                        for (p = 0; p < PeakIndexes.size(); p++)
                        {
                            if (PeakIndexes[p] == l)
                            {
                                break;
                            }
                        }

                        // p is the position in the merkle tree of peaks
                        assert(p < PeakIndexes.size());

                        // move up to the top, which is always a peak of size 1
                        uint64_t layerNum;
                        uint64_t layerSize;
                        for (layerNum = -1, layerSize = PeakIndexes.size(); layerNum == -1 || layerSize > 1; layerSize = MerkleSizes[++layerNum])
                        {
                            // printf("GetProofBits - Bits.size: %lu\n", Bits.size());
                            if (p < (layerSize - 1) || (p & 1))
                            {
                                if (p & 1)
                                {
                                    // hash with the one before us
                                    Bits.push_back(1);

                                    for (int i = 0; i < extrahashes; i++)
                                    {
                                        Bits.push_back(0);
                                    }
                                }
                                else
                                {
                                    // hash with the one in front of us
                                    Bits.push_back(0);

                                    for (int i = 0; i < extrahashes; i++)
                                    {
                                        Bits.push_back(0);
                                    }
                                }
                            }
                            p >>= 1;
                        }
                        // finished
                        break;
                    }
                }
            }
        }
        return Bits;
    }
};

#endif // MMR_H
