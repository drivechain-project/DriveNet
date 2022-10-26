// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAIN_H
#define BITCOIN_SIDECHAIN_H

#include <primitives/transaction.h>
#include <pubkey.h>

#include <array>

// These are the values that will be used in the final release
//static const int SIDECHAIN_VERIFICATION_PERIOD = 26300;
//static const int SIDECHAIN_MIN_WORKSCORE = 13150;
//static const int SIDECHAIN_ACTIVATION_MAX_FAILURES = 201;
//static const int SIDECHAIN_ACTIVATION_PERIOD = 2016;

// These are temporary withdrawal bundle verification values for testing

//! Blocks that a withdrawal bundle has to acheieve minimum work score
static const int SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD = 263;

//! The minimum workscore votes for a withdrawal bundle to be paid out.
static const int SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE = 131;

//! The destination string for the change of a withdrawal bundle
static const std::string SIDECHAIN_WITHDRAWAL_RETURN_DEST = "D";

//! Max number of failures (blocks without commits) for a sidechain to activate
static const int SIDECHAIN_ACTIVATION_MAX_FAILURES = 2;

//! The number of blocks in a sidechain activation period
static const int SIDECHAIN_ACTIVATION_PERIOD = 20;

//! The number of blocks in a sidechain replacement period
static const int SIDECHAIN_REPLACEMENT_PERIOD = SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE;

//! The number of sidechains which may be active at once
static const int SIDECHAIN_ACTIVATION_MAX_ACTIVE = 256;

//! The current sidechain version
static const int SIDECHAIN_VERSION_CURRENT = 0;

//! The max supported sidechain version
static const int SIDECHAIN_VERSION_MAX = 0;

//! The key for sidechain block data in ldb
static const char DB_SIDECHAIN_BLOCK_OP = 'S';

//! The SidechainDB update script version
static const uint8_t SCDB_BYTES_VERSION = 0;
static const uint8_t SCDB_BYTES_MAX_VERSION = 0;

// Custom characters for withdrawal bundle votes
static const char SCDB_UPVOTE = 'u';
static const char SCDB_DOWNVOTE = 'd';
static const char SCDB_ABSTAIN = 'a';

struct Sidechain {
    bool fActive;
    uint8_t nSidechain;
    int32_t nVersion = SIDECHAIN_VERSION_CURRENT;
    std::string title;
    std::string description;
    uint256 hashID1;
    uint160 hashID2;

    Sidechain()
    {
        fActive = false;
        nSidechain = 0;
        nVersion = SIDECHAIN_VERSION_CURRENT;
        title = "";
        description = "";
        hashID1.SetNull();
        hashID2.SetNull();
    }

    bool operator==(const Sidechain& s) const;
    std::string GetSidechainName() const;
    std::string ToString() const;
    uint256 GetSerHash() const;

    // Sidechain proposal script functions
    bool DeserializeFromProposalScript(const CScript& script);
    CScript GetProposalScript() const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(fActive);
        READWRITE(nSidechain);
        READWRITE(nVersion);
        READWRITE(title);
        READWRITE(description);
        READWRITE(hashID1);
        READWRITE(hashID2);
    }

    // This is the same as normal serialization but without fActive
    template <typename Stream>
    inline void SerializeProposal(Stream& s) {
        s << nSidechain;
        s << nVersion;
        s << title;
        s << description;
        s << hashID1;
        s << hashID2;
    }

    // This is the same as normal serialization but without fActive
    template <typename Stream>
    inline void DeserializeProposal(Stream& s) {
        s >> nSidechain;
        s >> nVersion;
        s >> title;
        s >> description;
        s >> hashID1;
        s >> hashID2;
    }
};

struct SidechainActivationStatus
{
    int nAge;
    int nFail;
    Sidechain proposal;

    uint256 GetSerHash() const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nAge);
        READWRITE(nFail);
        READWRITE(proposal);
    }
};

struct SidechainDeposit {
    uint8_t nSidechain;
    std::string strDest;
    CMutableTransaction tx;
    uint32_t nBurnIndex; // The deposit burn output in the deposit transaction
    uint32_t nTx; // The deposit's transaction number in the block
    uint256 hashBlock;

    bool operator==(const SidechainDeposit& a) const;
    std::string ToString() const;
    uint256 GetSerHash() const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSidechain);
        READWRITE(strDest);
        READWRITE(tx);
        READWRITE(nBurnIndex);
        READWRITE(nTx);
        READWRITE(hashBlock);
    }
};

struct SidechainWithdrawalState {
    uint8_t nSidechain;
    uint16_t nBlocksLeft;
    uint16_t nWorkScore;
    uint256 hash;

    uint256 GetSerHash() const;
    bool operator==(const SidechainWithdrawalState& a) const;
    std::string ToString() const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSidechain);
        READWRITE(nBlocksLeft);
        READWRITE(nWorkScore);
        READWRITE(hash);
    }
};

struct SidechainSpentWithdrawal {
    uint8_t nSidechain;
    uint256 hash;
    uint256 hashBlock;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSidechain);
        READWRITE(hash);
        READWRITE(hashBlock);
    }
};

struct SidechainFailedWithdrawal {
    uint8_t nSidechain;
    uint256 hash;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSidechain);
        READWRITE(hash);
    }
};

struct SidechainCTIP {
    COutPoint out;
    CAmount amount;

    uint256 GetSerHash() const;
    std::string ToString() const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(out);
        READWRITE(amount);
    }
};

/**
 * Base object for sidechain related database entries
 */
struct SidechainObj {
    char sidechainop;

    SidechainObj(void) { }
    virtual ~SidechainObj(void) { }

    uint256 GetSerHash(void) const;
    CScript GetScript(void) const;
    virtual std::string ToString(void) const;
};

/**
 * SCDB data for a block - database object
 */
struct SidechainBlockData: public SidechainObj {
    std::vector<std::vector<SidechainWithdrawalState>> vWithdrawalStatus;
    std::vector<SidechainSpentWithdrawal> vSpent;
    std::vector<SidechainActivationStatus> vActivationStatus;
    std::vector<Sidechain> vSidechain;

    SidechainBlockData(void) : SidechainObj() { sidechainop = DB_SIDECHAIN_BLOCK_OP; }
    virtual ~SidechainBlockData(void) { }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(sidechainop);
        READWRITE(vWithdrawalStatus);
        READWRITE(vSpent);
        READWRITE(vActivationStatus);
        READWRITE(vSidechain);
    }

    std::string ToString(void) const;
    uint256 GetSerHash() const;
};

bool ParseDepositAddress(const std::string& strAddressIn, std::string& strAddressOut, unsigned int& nSidechainOut);

#endif // BITCOIN_SIDECHAIN_H
