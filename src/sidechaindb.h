// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAINDB_H
#define BITCOIN_SIDECHAINDB_H

#include <map>
#include <memory> // Required for forward declaration of CTransactionRef typedef
#include <set>
#include <vector>

#include <amount.h>
#include <uint256.h>

class CCriticalData;
class COutPoint;
class CScript;
class CTransaction;
typedef std::shared_ptr<const CTransaction> CTransactionRef;
class CMutableTransaction;
class CTxOut;
class uint256;

struct Sidechain;
struct SidechainActivationStatus;
struct SidechainBlockData;
struct SidechainCTIP;
struct SidechainDeposit;
struct SidechainWithdrawalState;
struct SidechainSpentWithdrawal;
struct SidechainFailedWithdrawal;

class SidechainDB
{
public:
    SidechainDB();

    void ApplyLDBData(const uint256& hashBlockLastSeen, const SidechainBlockData& data);

    /** Add txid of BMM transaction removed from mempool to cache */
    void AddRemovedBMM(const uint256& hashRemoved);

    /** Add txid of removed sidechain deposit transaction */
    void AddRemovedDeposit(const uint256& hashRemoved);

    /** Add deposit(s) to cache */
    void AddDeposits(const std::vector<SidechainDeposit>& vDeposit);

    /** Add a new withdrawal bundle to SCDB */
    bool AddWithdrawal(uint8_t nSidechain, const uint256& hash, bool fDebug = false);

    /** Add spent withdrawals to SCDB */
    void AddSpentWithdrawals(const std::vector<SidechainSpentWithdrawal>& vSpent);

    /** Add failed withdrawals to SCDB */
    void AddFailedWithdrawals(const std::vector<SidechainFailedWithdrawal>& vFailed);

    /** Remove failed BMM request from cache once it has been abandoned */
    void BMMAbandoned(const uint256& txid);

    /** Add active sidechains to the in-memory cache */
    void CacheSidechains(const std::vector<Sidechain>& vSidechainIn);

    /** Add a users custom vote to the in-memory cache */
    bool CacheCustomVotes(const std::vector<std::string>& vote);

    /** Add SidechainActivationStatus to the in-memory cache */
    void CacheSidechainActivationStatus(const std::vector<SidechainActivationStatus>& vActivationStatusIn);

    /** Add proposed sidechain to the in-memory cache */
    void CacheSidechainProposals(const std::vector<Sidechain>& vSidechainProposalIn);

    /** Add sidechain-to-be-activated hash to cache */
    void CacheSidechainHashToAck(const uint256& u);

    /** Add withdrawal transaction to the in-memory cache */
    bool CacheWithdrawalTx(const CTransaction& tx, const uint8_t nSidechain);

    /** Check SCDB withdrawal verification status */
    bool CheckWorkScore(uint8_t nSidechain, const uint256& hash, bool fDebug = false) const;

    /** Clear out the cached list of removed sidechain deposit transactions */
    void ClearRemovedDeposits();

    /** Return number of active sidechains */
    unsigned int GetActiveSidechainCount() const;

    /** Check if the hash of the sidechain is in our hashes of sidechains to
     * activate cache. Return true if it is, or false if not. */
    bool GetAckSidechain(const uint256& u) const;

    /** Get list of currently active sidechains */
    std::vector<Sidechain> GetActiveSidechains() const;

    /** Get list of all sidechains */
    std::vector<Sidechain> GetSidechains() const;

    /** Get list of BMM txid that miner removed from the mempool. */
    std::set<uint256> GetRemovedBMM() const;

    /** Get list of deposit txid that were removed from the mempool. */
    std::vector<uint256> GetRemovedDeposits() const;

    /** Return the CTIP (critical transaction index pair) for nSidechain */
    bool GetCTIP(uint8_t nSidechain, SidechainCTIP& out) const;

    /** Return the CTIP (critical transaction index pair) for all sidechains */
    std::map<uint8_t, SidechainCTIP> GetCTIP() const;

    bool GetCachedWithdrawalTx(const uint256& hash, CMutableTransaction& mtx) const;

    /** Return vector of cached custom withdrawal votes */
    std::vector<std::string> GetVotes() const;

    /** Return vector of cached deposits for nSidechain. */
    std::vector<SidechainDeposit> GetDeposits(uint8_t nSidechain) const;

    /** Return the hash of the last block SCDB processed */
    uint256 GetHashBlockLastSeen();

    /** For testing purposes - return the hash of everything that SCDB is
     * tracking. This includes members used for consensus as well as user
     * data like which sidechain(s) they have set votes for and their own
     * sidechain proposals. */
    uint256 GetTestHash() const;

    /** Get the sidechain that relates to nSidechain if it exists */
    bool GetSidechain(const uint8_t nSidechain, Sidechain& sidechain) const;

    /** Get sidechain activation status */
    std::vector<SidechainActivationStatus> GetSidechainActivationStatus() const;

    /** Get the name of a sidechain */
    std::string GetSidechainName(uint8_t nSidechain) const;

    /** Get list of this node's uncommitted sidechain proposals */
    std::vector<Sidechain> GetSidechainProposals() const;

    /** Get the scriptPubKey that relates to nSidechain if it exists */
    bool GetSidechainScript(const uint8_t nSidechain, CScript& scriptPubKey) const;

    /** Get list of sidechains that we have set to ACK */
    std::vector<uint256> GetSidechainsToActivate() const;

    /** Get a list of withdrawals spent in a given block */
    std::vector<SidechainSpentWithdrawal> GetSpentWithdrawalsForBlock(const uint256& hashBlock) const;

    /** Get status of nSidechain's withdrawals (public for unit tests) */
    std::vector<SidechainWithdrawalState> GetState(uint8_t nSidechain) const;

    std::vector<std::vector<SidechainWithdrawalState>> GetState() const;

    /** Return cached but uncommitted withdrawal transaction hash(s) for nSidechain */
    std::vector<uint256> GetUncommittedWithdrawalCache(uint8_t nSidechain) const;

    /** Return cached withdrawal transaction(s) */
    std::vector<std::pair<uint8_t, CMutableTransaction>> GetWithdrawalTxCache() const;

    /** Return cached spent withdrawals as a vector for dumping to disk */
    std::vector<SidechainSpentWithdrawal> GetSpentWithdrawalCache() const;

    /** Return cached failed withdrawals^ as a vector for dumping to disk */
    std::vector<SidechainFailedWithdrawal> GetFailedWithdrawalCache() const;

    /** Is there anything being tracked by the SCDB? */
    bool HasState() const;

    /** Return true if the deposit transaction is cached */
    bool HaveDepositCached(const uint256& txid) const;

    /** Return true if the withdrawal has been spent */
    bool HaveSpentWithdrawal(const uint256& hash, const uint8_t nSidechain) const;

    /** Return true if the withdrawal failed */
    bool HaveFailedWithdrawal(const uint256& hash, const uint8_t nSidechain) const;

    /** Return true if the withdrawal tx is cached */
    bool HaveWithdrawalTxCached(const uint256& hash) const;

    /** Check if SCDB is tracking the work score of a withdrawal */
    bool HaveWorkScore(const uint256& hash, uint8_t nSidechain) const;

    /** Check if a sidechain slot number has active sidechain */
    bool IsSidechainActive(uint8_t nSidechain) const;

    /** Return true if the sidechain title, KeyID, deposit script hex & private
     * key are all different than the values for every active sidechain and
     * pending sidechain proposal. */
    bool IsSidechainUnique(const Sidechain& sidechain) const;

    /** Remove withdrawals that are too old to pass with their current score */
    void RemoveExpiredWithdrawals();

    /** Remove sidechain-to-be-activated hash from cache, because the user
     * changed their mind */
    void RemoveSidechainHashToAck(const uint256& u);

    /** Reset SCDB and clear out all data tracked by SidechainDB */
    void ResetWithdrawalState();

    /** Clear out the custom vote cache */
    void ResetWithdrawalVotes();

    /** Reset everything */
    void Reset();

    /** Spend a withdrawal bundle (if we can) */
    bool SpendWithdrawal(uint8_t nSidechain, const uint256& hashBlock, const CTransaction& tx, const int nTx, bool fJustCheck = false,  bool fDebug = false);

    /** Get SidechainDeposit from deposit CTransaction. Part of SCDB because
     * we need the list of active sidechains to find deposit outputs. */
    bool TxnToDeposit(const CTransaction& tx, const int nTx, const uint256& hashBlock, SidechainDeposit& deposit);

    /** Print SCDB withdrawal verification status */
    std::string ToString() const;

    /** Check the updates in a block and then apply them */
    bool Update(int nHeight, const uint256& hashBlock, const uint256& hashPrevBlock, const std::vector<CTxOut>& vout, bool fJustCheck = false, bool fDebug = false);

    /** Undo the changes to SCDB of a block - for block is disconnection */
    bool Undo(int nHeight, const uint256& hashBlock, const uint256& hashPrevBlock, const std::vector<CTransactionRef>& vtx, bool fDebug = false);

    /** Update / add multiple withdrawals to SCDB */
    bool UpdateSCDBIndex(const std::vector<std::string>& vVote, bool fDebug = false, const std::map<uint8_t /* nSidechain */, uint256 /* withdrawal hash */>& mapNewWithdrawal = {});

private:
    /**
     * Apply default abstain vote for all sidechain withdrawals. Used when a new
     * block does not contain a valid update. */
    void ApplyDefaultUpdate();

    /** Apply the changes in a block to SCDB */
    bool ApplyUpdate(int nHeight, const uint256& hashBlock, const uint256& hashPrevBlock, const std::vector<CTxOut>& vout, bool fJustCheck = false, bool fDebug = false);

    /** Takes a list of sidechain hashes to upvote */
    void UpdateActivationStatus(const std::vector<uint256>& vHash);

    /** Update CTIP to match the deposit cache - called after sorting / undo */
    bool UpdateCTIP();

    /** Calls SortDeposits for all of SCDB's deposit cache */
    bool SortSCDBDeposits();

    /** All sidechain slots, their activation status, and params if active */
    std::vector<Sidechain> vSidechain;

    /**
     * The CTIP of nSidechain up to the latest connected block (does not include
     * mempool txns). */
    std::map<uint8_t, SidechainCTIP> mapCTIP;

    /** The most recent block that SCDB has processed */
    uint256 hashBlockLastSeen;

    /** Activation status of proposed sidechains */
    std::vector<SidechainActivationStatus> vActivationStatus;

    /** Cache of withdrawal vote settings created by the user */
    std::vector<std::string> vVoteCache;

    /** Cache of deposits for each sidechain. TODO optimize with caching
     * so that we don't have to keep all of these in memory.
     * x = nSidechain
     * y = list of deposits for nSidechain */
    std::vector<std::vector<SidechainDeposit>> vDepositCache;

    /** Cache of sidechain hashes, for sidechains which this node has been
     * configured to activate by the user */
    std::vector<uint256> vSidechainHashAck;

    /** Cache of proposals for new sidechains created by this node,
     * which should be included in the next block that this node mines. */
    std::vector<Sidechain> vSidechainProposal;

    /** Cache of potential withdrawal transactions
     * TODO consider refactoring to use CTransactionRef */
    std::vector<std::pair<uint8_t, CMutableTransaction>> vWithdrawalTxCache;

    /** Tracks verification status of withdrawals
     * x = nSidechain
     * y = state of withdrawals for nSidechain */
    std::vector<std::vector<SidechainWithdrawalState>> vWithdrawalStatus;

    /** Map of spent withdrawals. Key: block hash Value: Spent withdrawals from block */
    std::map<uint256, std::vector<SidechainSpentWithdrawal>> mapSpentWithdrawal;

    /** Map of failed withdrawals. Key: withdrawal hash Value: spent withdrawal */
    std::map<uint256, SidechainFailedWithdrawal> mapFailedWithdrawal;

    /** List of BMM request txid that the miner removed from the mempool. */
    std::set<uint256> setRemovedBMM;

    /** List of deposit txids that are cached by SCDB */
    std::set<uint256> setDepositTXID;

    /** List of sidechain deposits that were removed from the mempool for one
     * of a few reasons. The deposit could have been replaced by another deposit
     * that made it to the mempool first, spending the same CTIP. Or the deposit
     * may have been in the mempool when a withdrawal payout was created,
     * spending the same CTIP as the deposit. */
    std::vector<uint256> vRemovedDeposit;
};

/** Read encoded sum of withdrawal fees output script */
bool DecodeWithdrawalFees(const CScript& script, CAmount& amount);

/** Sort deposits by CTIP UTXO spending order */
bool SortDeposits(const std::vector<SidechainDeposit>& vDeposit, std::vector<SidechainDeposit>& vDepositSorted);

bool ParseSCDBBytes(const CScript& script, const std::vector<std::vector<SidechainWithdrawalState>>& vOldScores, std::vector<std::string>& vVote);

#endif // BITCOIN_SIDECHAINDB_H
