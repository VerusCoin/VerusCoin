// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include "amount.h"
#include "random.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "arith_uint256.h"
#include "consensus/consensus.h"
#include "hash.h"
#include "nonce.h"
#include "solutiondata.h"
#include "mmr.h"

#ifndef __APPLE__
#include <stdint.h>
#endif

#include <array>

#include <boost/variant.hpp>

#include "zcash/NoteEncryption.hpp"
#include "zcash/Zcash.h"
#include "zcash/JoinSplit.hpp"
#include "zcash/Proof.hpp"

extern uint32_t ASSETCHAINS_MAGIC;
class CCurrencyState;


// Overwinter transaction version
static const int32_t OVERWINTER_TX_VERSION = 3;
static_assert(OVERWINTER_TX_VERSION >= OVERWINTER_MIN_TX_VERSION,
    "Overwinter tx version must not be lower than minimum");
static_assert(OVERWINTER_TX_VERSION <= OVERWINTER_MAX_TX_VERSION,
    "Overwinter tx version must not be higher than maximum");

// Sapling transaction version
static const int32_t SAPLING_TX_VERSION = 4;
static_assert(SAPLING_TX_VERSION >= SAPLING_MIN_TX_VERSION,
    "Sapling tx version must not be lower than minimum");
static_assert(SAPLING_TX_VERSION <= SAPLING_MAX_TX_VERSION,
    "Sapling tx version must not be higher than maximum");

/**
 * A shielded input to a transaction. It contains data that describes a Spend transfer.
 */
class SpendDescription
{
public:
    typedef std::array<unsigned char, 64> spend_auth_sig_t;

    uint256 cv;                    //!< A value commitment to the value of the input note.
    uint256 anchor;                //!< A Merkle root of the Sapling note commitment tree at some block height in the past.
    uint256 nullifier;             //!< The nullifier of the input note.
    uint256 rk;                    //!< The randomized public key for spendAuthSig.
    libzcash::GrothProof zkproof;  //!< A zero-knowledge proof using the spend circuit.
    spend_auth_sig_t spendAuthSig; //!< A signature authorizing this spend.

    SpendDescription() { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(cv);
        READWRITE(anchor);
        READWRITE(nullifier);
        READWRITE(rk);
        READWRITE(zkproof);
        READWRITE(spendAuthSig);
    }

    friend bool operator==(const SpendDescription& a, const SpendDescription& b)
    {
        return (
            a.cv == b.cv &&
            a.anchor == b.anchor &&
            a.nullifier == b.nullifier &&
            a.rk == b.rk &&
            a.zkproof == b.zkproof &&
            a.spendAuthSig == b.spendAuthSig
            );
    }

    friend bool operator!=(const SpendDescription& a, const SpendDescription& b)
    {
        return !(a == b);
    }
};

/**
 * A shielded output to a transaction. It contains data that describes an Output transfer.
 */
class OutputDescription
{
public:
    uint256 cv;                     //!< A value commitment to the value of the output note.
    uint256 cm;                     //!< The note commitment for the output note.
    uint256 ephemeralKey;           //!< A Jubjub public key.
    libzcash::SaplingEncCiphertext encCiphertext; //!< A ciphertext component for the encrypted output note.
    libzcash::SaplingOutCiphertext outCiphertext; //!< A ciphertext component for the encrypted output note.
    libzcash::GrothProof zkproof;   //!< A zero-knowledge proof using the output circuit.

    OutputDescription() { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(cv);
        READWRITE(cm);
        READWRITE(ephemeralKey);
        READWRITE(encCiphertext);
        READWRITE(outCiphertext);
        READWRITE(zkproof);
    }

    friend bool operator==(const OutputDescription& a, const OutputDescription& b)
    {
        return (
            a.cv == b.cv &&
            a.cm == b.cm &&
            a.ephemeralKey == b.ephemeralKey &&
            a.encCiphertext == b.encCiphertext &&
            a.outCiphertext == b.outCiphertext &&
            a.zkproof == b.zkproof
            );
    }

    friend bool operator!=(const OutputDescription& a, const OutputDescription& b)
    {
        return !(a == b);
    }
};

template <typename Stream>
class SproutProofSerializer : public boost::static_visitor<>
{
    Stream& s;
    bool useGroth;

public:
    SproutProofSerializer(Stream& s, bool useGroth) : s(s), useGroth(useGroth) {}

    void operator()(const libzcash::PHGRProof& proof) const
    {
        if (useGroth) {
            throw std::ios_base::failure("Invalid Sprout proof for transaction format (expected GrothProof, found PHGRProof)");
        }
        ::Serialize(s, proof);
    }

    void operator()(const libzcash::GrothProof& proof) const
    {
        if (!useGroth) {
            throw std::ios_base::failure("Invalid Sprout proof for transaction format (expected PHGRProof, found GrothProof)");
        }
        ::Serialize(s, proof);
    }
};

template<typename Stream, typename T>
inline void SerReadWriteSproutProof(Stream& s, const T& proof, bool useGroth, CSerActionSerialize ser_action)
{
    auto ps = SproutProofSerializer<Stream>(s, useGroth);
    boost::apply_visitor(ps, proof);
}

template<typename Stream, typename T>
inline void SerReadWriteSproutProof(Stream& s, T& proof, bool useGroth, CSerActionUnserialize ser_action)
{
    if (useGroth) {
        libzcash::GrothProof grothProof;
        ::Unserialize(s, grothProof);
        proof = grothProof;
    } else {
        libzcash::PHGRProof pghrProof;
        ::Unserialize(s, pghrProof);
        proof = pghrProof;
    }
}

class JSDescription
{
public:
    // These values 'enter from' and 'exit to' the value
    // pool, respectively.
    CAmount vpub_old;
    CAmount vpub_new;

    // JoinSplits are always anchored to a root in the note
    // commitment tree at some point in the blockchain
    // history or in the history of the current
    // transaction.
    uint256 anchor;

    // Nullifiers are used to prevent double-spends. They
    // are derived from the secrets placed in the note
    // and the secret spend-authority key known by the
    // spender.
    std::array<uint256, ZC_NUM_JS_INPUTS> nullifiers;

    // Note commitments are introduced into the commitment
    // tree, blinding the public about the values and
    // destinations involved in the JoinSplit. The presence of
    // a commitment in the note commitment tree is required
    // to spend it.
    std::array<uint256, ZC_NUM_JS_OUTPUTS> commitments;

    // Ephemeral key
    uint256 ephemeralKey;

    // Ciphertexts
    // These contain trapdoors, values and other information
    // that the recipient needs, including a memo field. It
    // is encrypted using the scheme implemented in crypto/NoteEncryption.cpp
    std::array<ZCNoteEncryption::Ciphertext, ZC_NUM_JS_OUTPUTS> ciphertexts = {{ {{0}} }};

    // Random seed
    uint256 randomSeed;

    // MACs
    // The verification of the JoinSplit requires these MACs
    // to be provided as an input.
    std::array<uint256, ZC_NUM_JS_INPUTS> macs;

    // JoinSplit proof
    // This is a zk-SNARK which ensures that this JoinSplit is valid.
    libzcash::SproutProof proof;

    JSDescription(): vpub_old(0), vpub_new(0) { }

    JSDescription(
            ZCJoinSplit& params,
            const uint256& joinSplitPubKey,
            const uint256& rt,
            const std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
            const std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
            CAmount vpub_old,
            CAmount vpub_new,
            bool computeProof = true, // Set to false in some tests
            uint256 *esk = nullptr // payment disclosure
    );

    static JSDescription Randomized(
            ZCJoinSplit& params,
            const uint256& joinSplitPubKey,
            const uint256& rt,
            std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
            std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
            std::array<size_t, ZC_NUM_JS_INPUTS>& inputMap,
            std::array<size_t, ZC_NUM_JS_OUTPUTS>& outputMap,
            CAmount vpub_old,
            CAmount vpub_new,
            bool computeProof = true, // Set to false in some tests
            uint256 *esk = nullptr, // payment disclosure
            std::function<int(int)> gen = GetRandInt
    );

    // Verifies that the JoinSplit proof is correct.
    bool Verify(
        ZCJoinSplit& params,
        libzcash::ProofVerifier& verifier,
        const uint256& joinSplitPubKey
    ) const;

    // Returns the calculated h_sig
    uint256 h_sig(ZCJoinSplit& params, const uint256& joinSplitPubKey) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        // nVersion is set by CTransaction and CMutableTransaction to
        // (tx.fOverwintered << 31) | tx.nVersion
        bool fOverwintered = s.GetVersion() >> 31;
        int32_t txVersion = s.GetVersion() & 0x7FFFFFFF;
        bool useGroth = fOverwintered && txVersion >= SAPLING_TX_VERSION;

        READWRITE(vpub_old);
        READWRITE(vpub_new);
        READWRITE(anchor);
        READWRITE(nullifiers);
        READWRITE(commitments);
        READWRITE(ephemeralKey);
        READWRITE(randomSeed);
        READWRITE(macs);
        ::SerReadWriteSproutProof(s, proof, useGroth, ser_action);
        READWRITE(ciphertexts);
    }

    friend bool operator==(const JSDescription& a, const JSDescription& b)
    {
        return (
            a.vpub_old == b.vpub_old &&
            a.vpub_new == b.vpub_new &&
            a.anchor == b.anchor &&
            a.nullifiers == b.nullifiers &&
            a.commitments == b.commitments &&
            a.ephemeralKey == b.ephemeralKey &&
            a.ciphertexts == b.ciphertexts &&
            a.randomSeed == b.randomSeed &&
            a.macs == b.macs &&
            a.proof == b.proof
            );
    }

    friend bool operator!=(const JSDescription& a, const JSDescription& b)
    {
        return !(a == b);
    }
};

class BaseOutPoint
{
public:
    uint256 hash;
    uint32_t n;

    BaseOutPoint() { SetNull(); }
    BaseOutPoint(uint256 hashIn, uint32_t nIn) { hash = hashIn; n = nIn; }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hash);
        READWRITE(n);
    }

    void SetNull() { hash.SetNull(); n = (uint32_t) -1; }
    bool IsNull() const { return (hash.IsNull() && n == (uint32_t) -1); }

    friend bool operator<(const BaseOutPoint& a, const BaseOutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const BaseOutPoint& a, const BaseOutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const BaseOutPoint& a, const BaseOutPoint& b)
    {
        return !(a == b);
    }
};

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint : public BaseOutPoint
{
public:
    COutPoint() : BaseOutPoint() {};
    COutPoint(uint256 hashIn, uint32_t nIn) : BaseOutPoint(hashIn, nIn) {};
    std::string ToString() const;
};

/** An outpoint - a combination of a transaction hash and an index n into its sapling
 * output description (vShieldedOutput) */
class SaplingOutPoint : public BaseOutPoint
{
public:
    SaplingOutPoint() : BaseOutPoint() {};
    SaplingOutPoint(uint256 hashIn, uint32_t nIn) : BaseOutPoint(hashIn, nIn) {};
    std::string ToString() const;
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;

    CTxIn()
    {
        nSequence = std::numeric_limits<unsigned int>::max();
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=std::numeric_limits<unsigned int>::max());
    CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=std::numeric_limits<uint32_t>::max());

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(prevout);
        READWRITE(*(CScriptBase*)(&scriptSig));
        READWRITE(nSequence);
    }

    bool IsFinal() const
    {
        return (nSequence == std::numeric_limits<uint32_t>::max());
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue;
    CScript scriptPubKey;
    uint64_t interest;
    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, const CScript &scriptPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nValue);
        READWRITE(*(CScriptBase*)(&scriptPubKey));
    }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    uint256 GetHash() const;

    CAmount GetDustThreshold(const CFeeRate &minRelayTxFee) const
    {
        // "Dust" is defined in terms of CTransaction::minRelayTxFee,
        // which has units satoshis-per-kilobyte.
        // If you'd pay more than 1/3 in fees
        // to spend something, then we consider it dust.
        // A typical spendable txout is 34 bytes big, and will
        // need a CTxIn of at least 148 bytes to spend:
        // so dust is a spendable txout less than 54 satoshis
        // with default minRelayTxFee.
        if (scriptPubKey.IsUnspendable())
            return 0;

        size_t nSize = GetSerializeSize(*this, SER_DISK, 0) + 148u;
        return 3*minRelayTxFee.GetFee(nSize);
    }

    bool IsDust(const CFeeRate &minRelayTxFee) const
    {
        return (nValue < GetDustThreshold(minRelayTxFee));
    }

    CCurrencyValueMap ReserveOutValue() const
    {
        return scriptPubKey.ReserveOutValue();
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue == b.nValue && a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

// Overwinter version group id
static constexpr uint32_t OVERWINTER_VERSION_GROUP_ID = 0x03C48270;
static_assert(OVERWINTER_VERSION_GROUP_ID != 0, "version group id must be non-zero as specified in ZIP 202");

// Sapling version group id
static constexpr uint32_t SAPLING_VERSION_GROUP_ID = 0x892F2085;
static_assert(SAPLING_VERSION_GROUP_ID != 0, "version group id must be non-zero as specified in ZIP 202");

struct CMutableTransaction;

typedef CMerkleMountainRange<CDefaultMMRNode, CChunkedLayer<CDefaultMMRNode, 2>> TransactionMMRange;
typedef CMerkleMountainView<CDefaultMMRNode, CChunkedLayer<CDefaultMMRNode, 2>> TransactionMMView;

/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
private:
    /** Memory only. */
    const uint256 hash;
    void UpdateHash() const;

protected:
    /** Developer testing only.  Set evilDeveloperFlag to true.
     * Convert a CMutableTransaction into a CTransaction without invoking UpdateHash()
     */
    CTransaction(const CMutableTransaction &tx, bool evilDeveloperFlag);

public:
    typedef std::array<unsigned char, 64> joinsplit_sig_t;
    typedef std::array<unsigned char, 64> binding_sig_t;

    // Transactions that include a list of JoinSplits are >= version 2.
    static const int32_t SPROUT_MIN_CURRENT_VERSION = 1;
    static const int32_t SPROUT_MAX_CURRENT_VERSION = 2;
    static const int32_t OVERWINTER_MIN_CURRENT_VERSION = 3;
    static const int32_t OVERWINTER_MAX_CURRENT_VERSION = 3;
    static const int32_t SAPLING_MIN_CURRENT_VERSION = 4;
    static const int32_t SAPLING_MAX_CURRENT_VERSION = 4;

    static_assert(SPROUT_MIN_CURRENT_VERSION >= SPROUT_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert(OVERWINTER_MIN_CURRENT_VERSION >= OVERWINTER_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert( (OVERWINTER_MAX_CURRENT_VERSION <= OVERWINTER_MAX_TX_VERSION &&
                    OVERWINTER_MAX_CURRENT_VERSION >= OVERWINTER_MIN_CURRENT_VERSION),
                  "standard rule for tx version should be consistent with network rule");

    static_assert(SAPLING_MIN_CURRENT_VERSION >= SAPLING_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert( (SAPLING_MAX_CURRENT_VERSION <= SAPLING_MAX_TX_VERSION &&
                    SAPLING_MAX_CURRENT_VERSION >= SAPLING_MIN_CURRENT_VERSION),
                  "standard rule for tx version should be consistent with network rule");

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const bool fOverwintered;
    const int32_t nVersion;
    const uint32_t nVersionGroupId;
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const uint32_t nLockTime;
    const uint32_t nExpiryHeight;
    const CAmount valueBalance;
    const std::vector<SpendDescription> vShieldedSpend;
    const std::vector<OutputDescription> vShieldedOutput;
    const std::vector<JSDescription> vJoinSplit;
    const uint256 joinSplitPubKey;
    const joinsplit_sig_t joinSplitSig = {{0}};
    const binding_sig_t bindingSig = {{0}};

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    CTransaction(const CMutableTransaction &tx);
    CTransaction(CMutableTransaction &&tx);

    CTransaction& operator=(const CTransaction& tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        uint32_t header;
        if (ser_action.ForRead()) {
            // When deserializing, unpack the 4 byte header to extract fOverwintered and nVersion.
            READWRITE(header);
            *const_cast<bool*>(&fOverwintered) = header >> 31;
            *const_cast<int32_t*>(&this->nVersion) = header & 0x7FFFFFFF;
        } else {
            header = GetHeader();
            READWRITE(header);
        }
        if (fOverwintered) {
            READWRITE(*const_cast<uint32_t*>(&this->nVersionGroupId));
        }

        bool isOverwinterV3 =
            fOverwintered &&
            nVersionGroupId == OVERWINTER_VERSION_GROUP_ID &&
            nVersion == OVERWINTER_TX_VERSION;
        bool isSaplingV4 =
            fOverwintered &&
            nVersionGroupId == SAPLING_VERSION_GROUP_ID &&
            nVersion == SAPLING_TX_VERSION;
        if (fOverwintered && !(isOverwinterV3 || isSaplingV4)) {
            throw std::ios_base::failure("Unknown transaction format");
        }

        READWRITE(*const_cast<std::vector<CTxIn>*>(&vin));
        READWRITE(*const_cast<std::vector<CTxOut>*>(&vout));
        READWRITE(*const_cast<uint32_t*>(&nLockTime));
        if (isOverwinterV3 || isSaplingV4) {
            READWRITE(*const_cast<uint32_t*>(&nExpiryHeight));
        }
        if (isSaplingV4) {
            READWRITE(*const_cast<CAmount*>(&valueBalance));
            READWRITE(*const_cast<std::vector<SpendDescription>*>(&vShieldedSpend));
            READWRITE(*const_cast<std::vector<OutputDescription>*>(&vShieldedOutput));
        }
        if (nVersion >= 2) {
            auto os = WithVersion(&s, static_cast<int>(header));
            ::SerReadWrite(os, *const_cast<std::vector<JSDescription>*>(&vJoinSplit), ser_action);
            if (vJoinSplit.size() > 0) {
                READWRITE(*const_cast<uint256*>(&joinSplitPubKey));
                READWRITE(*const_cast<joinsplit_sig_t*>(&joinSplitSig));
            }
        }
        if (isSaplingV4 && !(vShieldedSpend.empty() && vShieldedOutput.empty())) {
            READWRITE(*const_cast<binding_sig_t*>(&bindingSig));
        }
        if (ser_action.ForRead())
            UpdateHash();
    }

    template <typename Stream>
    CTransaction(deserialize_type, Stream& s) : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    const uint256& GetHash() const {
        return hash;
    }

    uint32_t GetHeader() const {
        // When serializing v1 and v2, the 4 byte header is nVersion
        uint32_t header = this->nVersion;
        // When serializing Overwintered tx, the 4 byte header is the combination of fOverwintered and nVersion
        if (fOverwintered) {
            header |= 1 << 31;
        }
        return header;
    }

    // returns an MMR node for the block merkle mountain range
    TransactionMMRange GetTransactionMMR() const;
    CDefaultMMRNode GetDefaultMMRNode() const;
    uint256 GetMMRRoot() const;

    /*
     * Context for the two methods below:
     * As at most one of vpub_new and vpub_old is non-zero in every JoinSplit,
     * we can think of a JoinSplit as an input or output according to which one
     * it is (e.g. if vpub_new is non-zero the joinSplit is "giving value" to
     * the outputs in the transaction). Similarly, we can think of the Sapling
     * shielded part of the transaction as an input or output according to
     * whether valueBalance - the sum of shielded input values minus the sum of
     * shielded output values - is positive or negative.
     */

    // Return sum of txouts, (negative valueBalance or zero) and JoinSplit vpub_old.
    CAmount GetValueOut() const;

    // Value out of a transaction in reserve currencies
    CCurrencyValueMap GetReserveValueOut() const;

    // Return sum of (negative valueBalance or zero) and JoinSplit vpub_old.
    CAmount GetShieldedValueOut() const;
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    // Return sum of (positive valueBalance or zero) and JoinSplit vpub_new
    CAmount GetShieldedValueIn() const;

    // Compute priority, given priority of inputs and (optionally) tx size
    double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

    // Compute modified tx size for priority calculation (optionally given tx size)
    unsigned int CalculateModifiedSize(unsigned int nTxSize=0) const;

    bool IsMint() const
    {
        return IsCoinBase();
    }

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    int64_t UnlockTime(uint32_t voutNum) const;

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return a.hash == b.hash;
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return a.hash != b.hash;
    }

    // verus hash will be the same for a given txid, output number, block height, and blockhash from >= 100 blocks past
    static uint256 _GetVerusPOSHash(CPOSNonce *pNonce, const uint256 &txid, int32_t voutNum, int32_t height, const uint256 &pastHash, int64_t value)
    {
        //printf("Nonce:%s\n txid:%s\nnvout:%d\nheight:%d\npastHash:%s\nvalue:%lu\n",
        //       pNonce->GetHex().c_str(),
        //       txid.GetHex().c_str(),
        //       voutNum,
        //       height,
        //       pastHash.GetHex().c_str(),
        //       value);
        if (CVerusSolutionVector::GetVersionByHeight(height) > 0)
        {
            pNonce->SetPOSEntropy(pastHash, txid, voutNum, CPOSNonce::VERUS_V2);
            CVerusHashV2Writer hashWriter  = CVerusHashV2Writer(SER_GETHASH, PROTOCOL_VERSION);

            hashWriter << ASSETCHAINS_MAGIC;

            // we only use the new style of POS hash after changeover and 100 blocks of enforced proper nonce updating
            if (CPOSNonce::NewPOSActive(height))
            {
                hashWriter << *pNonce;
                hashWriter << height;
                return ArithToUint256(UintToArith256(hashWriter.GetHash()) / value);
            }
            else
            {
                hashWriter << pastHash;
                hashWriter << height;
                hashWriter << txid;
                hashWriter << voutNum;
                return ArithToUint256(UintToArith256(hashWriter.GetHash()) / value);
            }
        }
        else
        {
            pNonce->SetPOSEntropy(pastHash, txid, voutNum, CPOSNonce::VERUS_V1);
            CVerusHashWriter hashWriter  = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);

            hashWriter << ASSETCHAINS_MAGIC;

            // we only use the new style of POS hash after changeover and 100 blocks of enforced proper nonce updating
            if (CPOSNonce::NewPOSActive(height))
            {
                hashWriter << *pNonce;
                hashWriter << height;
                return ArithToUint256(UintToArith256(hashWriter.GetHash()) / value);
            }
            else
            {
                hashWriter << pastHash;
                hashWriter << height;
                hashWriter << txid;
                hashWriter << voutNum;
                return ArithToUint256(UintToArith256(hashWriter.GetHash()) / value);
            }
        }
    }

    // Nonce is modified to include the transaction information
    uint256 GetVerusPOSHash(CPOSNonce *pNonce, int32_t voutNum, int32_t height, const uint256 &pastHash) const
    {
        uint256 txid = GetHash();

        if (voutNum >= vout.size())
            return uint256S("ff0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");

        return _GetVerusPOSHash(pNonce, txid, voutNum, height, pastHash, (uint64_t)vout[voutNum].nValue);
    }

    std::string ToString() const;
};

/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    bool fOverwintered;
    int32_t nVersion;
    uint32_t nVersionGroupId;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;
    uint32_t nExpiryHeight;
    CAmount valueBalance;
    std::vector<SpendDescription> vShieldedSpend;
    std::vector<OutputDescription> vShieldedOutput;
    std::vector<JSDescription> vJoinSplit;
    uint256 joinSplitPubKey;
    CTransaction::joinsplit_sig_t joinSplitSig = {{0}};
    CTransaction::binding_sig_t bindingSig = {{0}};

    CMutableTransaction();
    CMutableTransaction(const CTransaction& tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        uint32_t header;
        if (ser_action.ForRead()) {
            // When deserializing, unpack the 4 byte header to extract fOverwintered and nVersion.
            READWRITE(header);
            fOverwintered = header >> 31;
            this->nVersion = header & 0x7FFFFFFF;
        } else {
            // When serializing v1 and v2, the 4 byte header is nVersion
            header = this->nVersion;
            // When serializing Overwintered tx, the 4 byte header is the combination of fOverwintered and nVersion
            if (fOverwintered) {
                header |= 1 << 31;
            }
            READWRITE(header);
        }
        if (fOverwintered) {
            READWRITE(nVersionGroupId);
        }

        bool isOverwinterV3 =
            fOverwintered &&
            nVersionGroupId == OVERWINTER_VERSION_GROUP_ID &&
            nVersion == OVERWINTER_TX_VERSION;
        bool isSaplingV4 =
            fOverwintered &&
            nVersionGroupId == SAPLING_VERSION_GROUP_ID &&
            nVersion == SAPLING_TX_VERSION;
        if (fOverwintered && !(isOverwinterV3 || isSaplingV4)) {
            throw std::ios_base::failure("Unknown transaction format");
        }

        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
        if (isOverwinterV3 || isSaplingV4) {
            READWRITE(nExpiryHeight);
        }
        if (isSaplingV4) {
            READWRITE(valueBalance);
            READWRITE(vShieldedSpend);
            READWRITE(vShieldedOutput);
        }
        if (nVersion >= 2) {
            auto os = WithVersion(&s, static_cast<int>(header));
            ::SerReadWrite(os, vJoinSplit, ser_action);
            if (vJoinSplit.size() > 0) {
                READWRITE(joinSplitPubKey);
                READWRITE(joinSplitSig);
            }
        }
        if (isSaplingV4 && !(vShieldedSpend.empty() && vShieldedOutput.empty())) {
            READWRITE(bindingSig);
        }
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    uint256 GetHash() const;
};

class CTransactionHeader
{
public:
    enum {
        TX_FULL = 0,
        TX_HEADER = 1,
        TX_PREVOUTSEQ = 2,          // prev out and sequence
        TX_SIGNATURE = 3,           // TODO: should include transaction hash but does not yet
        TX_OUTPUT = 4,
        TX_SHIELDEDSPEND = 5,
        TX_SHIELDEDOUTPUT = 6,
        TX_ETH_OBJECT = 7,
        TX_BLOCK_PREHEADER = 8      // virtual transaction added after others to prove block data without VerusHash
    };

    uint256 txHash;
    bool fOverwintered;
    uint32_t nVersion;
    uint32_t nVersionGroupId;
    uint32_t nVins;
    uint32_t nVouts;
    uint32_t nShieldedSpends;
    uint32_t nShieldedOutputs;
    uint32_t nLockTime;
    uint32_t nExpiryHeight;
    uint64_t nValueBalance;

    CTransactionHeader() : fOverwintered(0), nVersion(0), nVersionGroupId(0), nVins(0),
                           nVouts(0), nShieldedSpends(0), nShieldedOutputs(0), nLockTime(0), nExpiryHeight(0), nValueBalance(0) {}

    CTransactionHeader(const uint256 &TxHash,
                       bool Overwintered,
                       uint32_t Version,
                       uint32_t VersionGroupId,
                       uint32_t numVins,
                       uint32_t numVouts,
                       uint32_t numShieldedSpends,
                       uint32_t numShieldedOutputs,
                       uint32_t LockTime,
                       uint32_t ExpiryHeight,
                       uint64_t ValueBalance) :
                       txHash(TxHash),
                       fOverwintered(Overwintered),
                       nVersion(Version),
                       nVersionGroupId(VersionGroupId),
                       nVins(numVins),
                       nVouts(numVouts),
                       nShieldedSpends(numShieldedSpends),
                       nShieldedOutputs(numShieldedOutputs),
                       nLockTime(LockTime),
                       nExpiryHeight(ExpiryHeight),
                       nValueBalance(ValueBalance)
    {}

    CTransactionHeader(const CTransaction &tx) :
                       CTransactionHeader(tx.GetHash(),
                                        tx.fOverwintered,
                                        tx.nVersion,
                                        tx.nVersionGroupId,
                                        (int32_t)tx.vin.size(),
                                        (int32_t)tx.vout.size(),
                                        (int32_t)tx.vShieldedSpend.size(),
                                        (int32_t)tx.vShieldedOutput.size(),
                                        tx.nLockTime,
                                        tx.nExpiryHeight,
                                        tx.valueBalance)
    {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(txHash);
        READWRITE(fOverwintered);
        READWRITE(nVersion);
        READWRITE(nVersionGroupId);
        READWRITE(nVins);
        READWRITE(nVouts);
        READWRITE(nShieldedSpends);
        READWRITE(nShieldedOutputs);
        READWRITE(nLockTime);
        READWRITE(nExpiryHeight);
        READWRITE(nValueBalance);
    }

    CMutableTransaction RehydrateTransactionScaffold()
    {
        CMutableTransaction mtx;
        mtx.fOverwintered = fOverwintered;
        mtx.nVersion = nVersion;
        mtx.nVersionGroupId = nVersionGroupId;
        mtx.vin.resize(nVins);
        mtx.vout.resize(nVouts);
        mtx.vShieldedSpend.resize(nShieldedSpends);
        mtx.vShieldedOutput.resize(nShieldedOutputs);
        mtx.nLockTime = nLockTime;
        mtx.nExpiryHeight = nExpiryHeight;
        return mtx;
    }

    std::map<std::pair<int16_t, int16_t>, int32_t> GetElementHashMap()
    {
        // hash header information and put in MMR and map, followed by all elements in order
        int32_t idx = 0;
        std::map<std::pair<int16_t, int16_t>, int32_t> retVal;
        retVal[std::make_pair((int16_t)CTransactionHeader::TX_HEADER, (int16_t)0)] = idx++;

        for (unsigned int n = 0; n < nVins; n++) {
            retVal[std::make_pair((int16_t)CTransactionHeader::TX_PREVOUTSEQ, (int16_t)n)] = idx++;
        }

        for (unsigned int n = 0; n < nVins; n++) {
            retVal[std::make_pair((int16_t)CTransactionHeader::TX_SIGNATURE, (int16_t)n)] = idx++;
        }

        for (unsigned int n = 0; n < nVouts; n++) {
            retVal[std::make_pair((int16_t)CTransactionHeader::TX_OUTPUT, (int16_t)n)] = idx++;
        }

        for (unsigned int n = 0; n < nShieldedSpends; n++) {
            retVal[std::make_pair((int16_t)CTransactionHeader::TX_SHIELDEDSPEND, (int16_t)n)] = idx++;
        }

        for (unsigned int n = 0; n < nShieldedOutputs; n++) {
            retVal[std::make_pair((int16_t)CTransactionHeader::TX_SHIELDEDOUTPUT, (int16_t)n)] = idx++;
        }
        return retVal;
    }
};

class CTransactionMap
{
public:
    TransactionMMRange transactionMMR;              // this enables us to generate a proof of any sub-element in the transaction that associates with the txid
    std::map<std::pair<int16_t, int16_t>, int32_t> elementHashMap;  // <type,index> for idx num lookup from the element type and sub-index to global index

    CTransactionMap(const CTransaction &tx);

    // returns -1 if element is not found
    int32_t GetElementIndex(int16_t elementType, int16_t indexInType)
    {
        auto it = elementHashMap.find(std::make_pair(elementType, indexInType));
        if (it != elementHashMap.end())
        {
            return it->second;
        }
        else
        {
            return -1;
        }
    }
};

// enable efficient cross-chain, partial transaction proofs
class CTransactionComponentProof
{
public:
    uint16_t elType;
    uint16_t elIdx;
    std::vector<unsigned char> elVchObj;    // serialized object
    CMMRProof elProof;

    CTransactionComponentProof() : elType(0), elIdx(0) {}
    CTransactionComponentProof(const CTransactionComponentProof &obj) : elType(obj.elType), elIdx(obj.elIdx), elVchObj(obj.elVchObj), elProof(obj.elProof) {}
    CTransactionComponentProof(int type, int subIndex, const std::vector<unsigned char> &vch, const CMMRProof &proof) :
        elType(type), elIdx(subIndex), elVchObj(vch), elProof(proof) {}

    template <typename TXCOMPONENTCLASS>
    CTransactionComponentProof(const TXCOMPONENTCLASS &txPart, int index, const CMMRProof &proof) :
        elType(ElementType(txPart)), elIdx(index), elProof(proof)
    {
        elVchObj = ::AsVector(txPart);
    }

    CTransactionComponentProof(TransactionMMView &txView, const CTransactionMap &txMap, const CTransaction &tx, int16_t partType, int16_t subIndex);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(elType);
        READWRITE(elIdx);
        READWRITE(elVchObj);
        READWRITE(elProof);
    }

    template <typename TXCOMPONENTCLASS>
    bool Rehydrate(TXCOMPONENTCLASS &txPart) const
    {
        try
        {
            ::FromVector(elVchObj, txPart);
        }
        catch(const std::exception& e)
        {
            return false;
        }
        return true;
    }

    template <typename TXCOMPONENTCLASS>
    uint256 CheckProof(TXCOMPONENTCLASS &txPart) const
    {
        uint256 hash;
        if (Rehydrate(txPart))
        {
            auto hw = CDefaultMMRNode::GetHashWriter();
            hw << txPart;
            hash = elProof.CheckProof(hw.GetHash());
        }
        return hash;
    }

    // This class is primarily designed to replace a full tx with a sparse tx and proofs of its parts. in this case,
    // we do have the full tx, so this just returns the tx hash of a full tx, which must be validated further through
    // a merkle proof or otherwise
    uint256 CheckFullTxProof(CTransaction &tx) const
    {
        uint256 hash;
        if (Rehydrate(tx))
        {
            hash = tx.GetHash();
        }
        return hash;
    }

    uint256 CheckProof() const
    {
        switch (elType)
        {
            case CTransactionHeader::TX_FULL:
            {
                CTransaction tx;
                return CheckFullTxProof(tx);
            }

            case CTransactionHeader::TX_BLOCK_PREHEADER:
            {
                CPBaaSPreHeader preHeader;
                if (Rehydrate(preHeader))
                {
                    auto hw = CDefaultMMRNode::GetHashWriter();
                    hw << preHeader;
                    return elProof.CheckProof(hw.GetHash());
                }
                break;
            }

            case CTransactionHeader::TX_HEADER:
            {
                CTransactionHeader txPart;
                return CheckProof(txPart);
            }

            case CTransactionHeader::TX_PREVOUTSEQ:
            {
                CTxIn txPart;
                if (Rehydrate(txPart))
                {
                    auto hw = CDefaultMMRNode::GetHashWriter();
                    hw << txPart.prevout;
                    hw << txPart.nSequence;
                    return elProof.CheckProof(hw.GetHash());
                }
                break;
            }

            case CTransactionHeader::TX_SIGNATURE:
            {
                CTxIn txPart;
                return CheckProof(txPart);
            }

            case CTransactionHeader::TX_OUTPUT:
            {
                CTxOut txPart;
                return CheckProof(txPart);
            }

            case CTransactionHeader::TX_SHIELDEDSPEND:
            {
                SpendDescription txPart;
                if (Rehydrate(txPart))
                {
                    auto hw = CDefaultMMRNode::GetHashWriter();
                    hw << txPart.cv;
                    hw << txPart.anchor;
                    hw << txPart.nullifier;
                    hw << txPart.rk;
                    hw << txPart.zkproof;
                    return elProof.CheckProof(hw.GetHash());
                }
                break;
            }

            case CTransactionHeader::TX_SHIELDEDOUTPUT:
            {
                OutputDescription txPart;
                return CheckProof(txPart);
            }
        }
        return uint256();
    }

    static uint16_t ElementType(const CTransaction &tx)
    {
        return CTransactionHeader::TX_FULL;
    }
    static uint16_t ElementType(const CPBaaSPreHeader &preHeader)
    {
        return CTransactionHeader::TX_BLOCK_PREHEADER;
    }
    static uint16_t ElementType(const CTransactionHeader &txHeader)
    {
        return CTransactionHeader::TX_HEADER;
    }
    static uint16_t ElementType(const CTxIn &txIn)
    {
        return CTransactionHeader::TX_PREVOUTSEQ;
    }
    static uint16_t ElementType(const CScript &scriptSig)
    {
        return CTransactionHeader::TX_SIGNATURE;
    }
    static uint16_t ElementType(const CTxOut &txOut)
    {
        return CTransactionHeader::TX_OUTPUT;
    }
    static uint16_t ElementType(const SpendDescription &spend)
    {
        return CTransactionHeader::TX_SHIELDEDSPEND;
    }
    static uint16_t ElementType(const OutputDescription &output)
    {
        return CTransactionHeader::TX_SHIELDEDOUTPUT;
    }
};

// class that enables efficient cross-chain proofs of only parts of a transaction
class CBlockIndex;
class CPartialTransactionProof
{
public:
    enum EVersion {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = 1
    };
    enum EType {
        TYPE_INVALID = 0,
        TYPE_FULLTX = 1,
        TYPE_PBAAS = 2,
        TYPE_ETH = 3,
        TYPE_LAST = 3
    };
    int8_t version;                                     // to enable versioning of this type of proof
    int8_t type;                                        // this may represent transactions from different systems
    CMMRProof txProof;                                  // proof of the transaction in its block, either normal Merkle pre-PBaaS,MMR partial post, or PATRICIA Trie
    std::vector<CTransactionComponentProof> components; // each component (or TX for older blocks) to prove

    CPartialTransactionProof(int8_t Version=VERSION_CURRENT) : version(Version), type(TYPE_PBAAS) {}

    CPartialTransactionProof(const UniValue &uni);

    CPartialTransactionProof(const CPartialTransactionProof &obj) : version(obj.version), type(obj.type), txProof(obj.txProof), components(obj.components) {}

    CPartialTransactionProof(const CMMRProof &proof,
                             const std::vector<CTransactionComponentProof> &Components,
                             int8_t Version=VERSION_CURRENT,
                             int8_t Type=TYPE_PBAAS) :
                             version(Version),
                             type(Type),
                             txProof(proof),
                             components(Components) {}

    CPartialTransactionProof(const CTransaction tx,
                             const std::vector<int32_t> &inputNums,
                             const std::vector<int32_t> &outputNums,
                             const CBlockIndex *pIndex,
                             uint32_t proofAtHeight);

    // This creates a proof for older blocks and full transactions, typically where the root proof is a standard
    // merkle proof
    CPartialTransactionProof(const CMMRProof &txRootProof, const CTransaction &tx) :
        version(VERSION_CURRENT), type(TYPE_FULLTX), txProof(txRootProof), components({CTransactionComponentProof(tx, 0, CMMRProof())}) { }

    // This creates a proof for the pre-header of a block, which enables proof of sapling txes and other things in a block header
    // without requiring an implementation of VerusHash
    CPartialTransactionProof(const CMMRProof &txRootProof, const CPBaaSPreHeader &preHeader) :
        version(VERSION_CURRENT), type(TYPE_PBAAS), txProof(txRootProof), components({CTransactionComponentProof(preHeader, 0, CMMRProof())}) { }

    CPartialTransactionProof(const std::vector<CPartialTransactionProof> &parts)
    {
        std::vector<CMMRProof> chunkVec;
        for (int i = 0; i < parts.size(); i++)
        {
            if (parts[i].txProof.IsMultiPart())
            {
                chunkVec.push_back(parts[i].txProof);
            }
        }
        CMultiPartProof assembled = CMultiPartProof(chunkVec);
        ::FromVector(assembled.vch, *this);
    }

    const CPartialTransactionProof &operator=(const CPartialTransactionProof &operand)
    {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << operand;
        s >> *this;
        return *this;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(type);
        READWRITE(txProof);
        READWRITE(components);
    }

    uint256 TransactionHash() const
    {
        if (components.size())
        {
            CTransaction outTx;
            CTransactionHeader txh;
            CVDXF_Data vdxfObj;
            CPBaaSPreHeader preHeader;
            if (components[0].elType == CTransactionHeader::TX_HEADER && components[0].Rehydrate(txh))
            {
                return txh.txHash;
            }
            else if (components[0].elType == CTransactionHeader::TX_FULL && components[0].Rehydrate(outTx))
            {
                return outTx.GetHash();
            }
            else if (components[0].elType == CTransactionHeader::TX_BLOCK_PREHEADER && components[0].Rehydrate(preHeader))
            {
                auto hw2 = CDefaultMMRNode::GetHashWriter();
                hw2 << preHeader;
                return hw2.GetHash();
            }
            else if (components[0].elType == CTransactionHeader::TX_ETH_OBJECT && components[0].Rehydrate(vdxfObj))
            {
                CDataStream s = CDataStream(vdxfObj.data, SER_NETWORK, PROTOCOL_VERSION);
                uint256 prevtxid;
                CCrossChainExport ccx;

                try
                {
                    s >> ccx;
                    s >> prevtxid;
                }
                catch (const std::runtime_error &e)
                {
                    LogPrintf("Deserialization of ETH type object failed : %s\n", e.what());
                    return uint256();
                }

                CNativeHashWriter hw2(CCurrencyDefinition::EProofProtocol::PROOF_ETHNOTARIZATION);
                hw2 << ccx;
                hw2 << prevtxid;

                return hw2.GetHash();
            }
        }
        return uint256();
    }

    // this validates that all parts of a transaction match and either returns a full transaction
    // and its hash, a partially filled transaction and its MMR root, or NULL
    uint256 GetPartialTransaction(CTransaction &outTx, bool *pIsPartial=nullptr) const;

    // this validates that all parts of a transaction match and either returns a full transaction
    // and its hash, a partially filled transaction and its MMR root, or NULL
    uint256 CheckPartialTransaction(CTransaction &outTx, bool *pIsPartial=nullptr, bool optimizedETH=true) const;

    bool IsBlockPreHeader() const
    {
        return components[0].elType == CTransactionHeader::TX_BLOCK_PREHEADER;
    }

    CPBaaSPreHeader GetBlockPreHeader() const
    {
        CPBaaSPreHeader preHeader;
        if (components[0].elType == CTransactionHeader::TX_BLOCK_PREHEADER && components[0].Rehydrate(preHeader))
        {
            return preHeader;
        }
        return CPBaaSPreHeader();
    }

    // this validates that a preheader is correct according to the block MMR
    // this only validates on the new PoS format, otherwise, the hash of the preheader
    // is fixed and not dependent on the pre-header
    uint256 CheckBlockPreHeader(CPBaaSPreHeader &outPreHeader, bool newPoSFormat=true) const;

    // for PBaaS chain proofs, we can determine the hash, block height, and power, depending on if we are block specific or
    // proven at the blockchain level

    // chain proofs have a tx proof in block, a merkle proof bridge, and a chain proof
    bool IsChainProof() const
    {
        return IsValid() &&
               ((type == TYPE_ETH) ||
                (TYPE_PBAAS == type &&
                 txProof.proofSequence.size() >= 3 &&
                 txProof.proofSequence[1]->branchType == CMerkleBranchBase::BRANCH_MMRBLAKE_NODE &&
                 txProof.proofSequence[2]->branchType == CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE));
    }

    bool IsValid() const
    {
        return version >= VERSION_FIRST && version <= VERSION_LAST && type != TYPE_INVALID && type <= TYPE_LAST;
    }

    bool IsMultipart() const
    {
        return IsValid() && txProof.proofSequence.size() == 1 && txProof.proofSequence[0]->branchType == CMerkleBranchBase::BRANCH_MULTIPART;
    }

    std::vector<CPartialTransactionProof> BreakApart(int maxChunkSize=(CScript::MAX_SCRIPT_ELEMENT_SIZE-256)) const
    {
        CDataStream ds(SER_DISK, PROTOCOL_VERSION);
        // we put our entire self into a multipart proof and return multiple parts that must be reconstructed
        std::vector<unsigned char> serialized = ::AsVector(*this);
        CMultiPartProof allPartProof(CMerkleBranchBase::BRANCH_MULTIPART, serialized);

        CPartialTransactionProof withoutProof(CMMRProof(), components, version, type);

        // we could be more efficient with variable sized chunks
        std::vector<CMMRProof> allParts = allPartProof.BreakToChunks(maxChunkSize - GetSerializeSize(ds, withoutProof));

        std::vector<CPartialTransactionProof> retVal;
        for (auto &onePart : allParts)
        {
            retVal.push_back(CPartialTransactionProof(onePart, std::vector<CTransactionComponentProof>(), version, type));
        }
        return retVal;
    }

    uint256 GetBlockHash() const
    {
        if ((type == TYPE_PBAAS || type == TYPE_FULLTX) && IsChainProof())
        {
            std::vector<uint256> &branch = ((CMMRNodeBranch *)(txProof.proofSequence[1]))->branch;
            if (branch.size() == 1)
            {
                return branch[0];
            }
        }
        return uint256();
    }

    uint256 GetBlockPower() const
    {
        if (type == TYPE_PBAAS && IsChainProof())
        {
            std::vector<uint256> &branch = ((CMMRPowerNodeBranch *)(txProof.proofSequence[2]))->branch;
            if (branch.size() >= 1)
            {
                return branch[0];
            }
        }
        return uint256();
    }

    uint256 GetRootPower() const
    {
        if (type == TYPE_PBAAS && IsChainProof())
        {
            std::vector<uint256> &branch = ((CMMRPowerNodeBranch *)(txProof.proofSequence[2]))->branch;
            if (branch.size() >= 1)
            {
                return branch.back();
            }
        }
        return uint256();
    }

    uint32_t GetBlockHeight() const
    {
        if ((type == TYPE_PBAAS || type == TYPE_FULLTX) && IsChainProof())
        {
            return ((CMMRPowerNodeBranch *)(txProof.proofSequence[2]))->nIndex;
        }
        return 0;
    }

    uint32_t GetProofHeight() const
    {
        if ((type == TYPE_PBAAS || type == TYPE_FULLTX) && IsChainProof())
        {
            return ((CMMRPowerNodeBranch *)(txProof.proofSequence[2]))->nSize - 1;
        }
        return 0;
    }

    UniValue ToUniValue() const;
};

// smart transactions are derived from crypto-conditions, but they are not the same thing. A smart transaction is described
// along with any eval-specific parameters, as an object encoded in the COptCCParams following the OP_CHECK_CRYPTOCONDITION opcode
// of a script. smart transactions are not encoded with ASN.1, but with standard Bitcoin serialization and an object model
// defined in PBaaS. while as of this comment, the cryptocondition code is used to validate crypto-conditions, that is only
// internally to determine thresholds and remain compatible with evals. The protocol contains only PBaaS serialized descriptions,
// and the signatures contain a vector of this object, serialized in one fulfillment that gets updated for multisig.
class CSmartTransactionSignature
{
public:
    enum {
        SIGTYPE_NONE = 0,
        SIGTYPE_SECP256K1 = 1,
        SIGTYPE_SECP256K1_LEN = 64,
        SIGTYPE_FALCON = 2
    };

    uint8_t sigType;
    std::vector<unsigned char> pubKeyData;
    std::vector<unsigned char> signature;

    CSmartTransactionSignature() : sigType(SIGTYPE_NONE) {}
    CSmartTransactionSignature(uint8_t sType, const std::vector<unsigned char> &pkData, const std::vector<unsigned char> &sig) : sigType(sType), pubKeyData(pkData), signature(sig) {}
    CSmartTransactionSignature(uint8_t sType, const CPubKey &pk, const std::vector<unsigned char> &sig) : sigType(sType), pubKeyData(pk.begin(), pk.end()), signature(sig) {}
    CSmartTransactionSignature(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(sigType);
        READWRITE(pubKeyData);
        READWRITE(signature);
    }

    UniValue ToUniValue() const
    {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("signaturetype", (int)sigType));
        obj.push_back(Pair("publickeydata", HexBytes(&pubKeyData[0], pubKeyData.size())));
        obj.push_back(Pair("signature", HexBytes(&signature[0], signature.size())));
        return obj;
    }

    // checks to see if the signature is valid for this hash
    bool CheckSignature(uint256 hash) const
    {
        if (sigType == SIGTYPE_SECP256K1)
        {
            CPubKey pubKey(pubKeyData);
            return pubKey.Verify(hash, signature);
        }
        else
        {
            return false;
        }
    }

    bool IsValid()
    {
        return (sigType == SIGTYPE_SECP256K1 || sigType == SIGTYPE_FALCON) &&
               CPubKey(pubKeyData).IsFullyValid();
    }
};

class CSmartTransactionSignatures
{
public:
    enum {
        FIRST_VERSION = 1,
        LAST_VERSION = 1,
        VERSION = 1
    };
    uint8_t version;
    uint8_t sigHashType;
    std::map<uint160, CSmartTransactionSignature> signatures;

    CSmartTransactionSignatures() : version(VERSION), sigHashType(1) {}
    CSmartTransactionSignatures(uint8_t hashType, const std::map<uint160, CSmartTransactionSignature> &signatureMap, uint8_t ver=VERSION) : version(ver), sigHashType(hashType), signatures(signatureMap) {}
    CSmartTransactionSignatures(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        if (version >= FIRST_VERSION && version <= LAST_VERSION)
        {
            READWRITE(sigHashType);
            std::vector<CSmartTransactionSignature> sigVec;
            if (ser_action.ForRead())
            {
                READWRITE(sigVec);
                for (auto oneSig : sigVec)
                {
                    if (oneSig.sigType == oneSig.SIGTYPE_SECP256K1)
                    {
                        CPubKey pk(oneSig.pubKeyData);
                        if (pk.IsFullyValid())
                        {
                            signatures[pk.GetID()] = oneSig;
                        }
                    }
                }
            }
            else
            {
                for (auto oneSigPair : signatures)
                {
                    sigVec.push_back(oneSigPair.second);
                }
                READWRITE(sigVec);
            }
        }
    }

    bool AddSignature(const CSmartTransactionSignature &oneSig)
    {
        if (oneSig.sigType == oneSig.SIGTYPE_SECP256K1)
        {
            CPubKey pk(oneSig.pubKeyData);
            if (pk.IsFullyValid())
            {
                signatures[pk.GetID()] = oneSig;
		return true;
            }
        }
	return false;
    }

    UniValue ToUniValue() const
    {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("version", (int)version));
        obj.push_back(Pair("signaturehashtype", (int)sigHashType));
        UniValue uniSigs(UniValue::VARR);
        for (auto sig : signatures)
        {
            uniSigs.push_back(sig.second.ToUniValue());
        }
        obj.push_back(Pair("signatures", uniSigs));
        return obj;
    }

    bool IsValid()
    {
        if (!(version >= FIRST_VERSION && version <= LAST_VERSION))
        {
            return false;
        }
        for (auto oneSig : signatures)
        {
            if (oneSig.second.sigType == oneSig.second.SIGTYPE_SECP256K1)
            {
                CPubKey pk(oneSig.second.pubKeyData);
                uint160 pubKeyHash = pk.GetID();
                //printf("pk.IsFullyValid(): %s, pk.GetID(): %s, oneSig.first: %s\n", pk.IsFullyValid() ? "true" : "false", pk.GetID().GetHex().c_str(), oneSig.first.GetHex().c_str());
                if (!pk.IsFullyValid() || pk.GetID() != oneSig.first)
                {
                    return false;
                }
            }
            else if (oneSig.second.sigType == oneSig.second.SIGTYPE_FALCON)
            {
                return false;
            }
            else
            {
                return false;
            }
        }
        return true;
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }
};

class CUTXORef : public COutPoint
{
public:
    CUTXORef() : COutPoint(uint256(), UINT32_MAX) {}
    CUTXORef(const COutPoint &op) : COutPoint(op) {}
    CUTXORef(const UniValue &uni);
    CUTXORef(const uint256 &HashIn, uint32_t nIn=UINT32_MAX) : COutPoint(HashIn, nIn) {}
    CUTXORef(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(COutPoint *)this);
    }

    bool IsValid() const
    {
        return n != UINT32_MAX;
    }

    bool IsOnSameTransaction() const
    {
        return IsValid() && hash.IsNull();
    }

    // returns false if hash is null
    bool GetOutputTransaction(CTransaction &tx, uint256 &blockHash, bool checkMemPool=true) const;

    UniValue ToUniValue() const;
};

struct WTxId
{
    const uint256 hash;
    const uint256 authDigest;

    WTxId() :
        authDigest(LEGACY_TX_AUTH_DIGEST) {}

    WTxId(const uint256& hashIn, const uint256& authDigestIn=LEGACY_TX_AUTH_DIGEST) :
        hash(hashIn), authDigest(authDigestIn) {}

    const std::vector<unsigned char> ToBytes() const {
        std::vector<unsigned char> vData(hash.begin(), hash.end());
        vData.insert(vData.end(), authDigest.begin(), authDigest.end());
        return vData;
    }

    friend bool operator<(const WTxId& a, const WTxId& b)
    {
        return (a.hash < b.hash ||
            (a.hash == b.hash && a.authDigest < b.authDigest));
    }

    friend bool operator==(const WTxId& a, const WTxId& b)
    {
        return a.hash == b.hash && a.authDigest == b.authDigest;
    }

    friend bool operator!=(const WTxId& a, const WTxId& b)
    {
        return a.hash != b.hash || a.authDigest != b.authDigest;
    }
};

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
