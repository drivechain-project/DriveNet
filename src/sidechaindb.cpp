// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechaindb.h>

#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <clientversion.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sidechain.h>
#include <streams.h>
#include <uint256.h>
#include <util.h>
#include <utilstrencodings.h>

SidechainDB::SidechainDB()
{
    Reset();
}

void SidechainDB::ApplyLDBData(const uint256& hashBlock, const SidechainBlockData& data)
{
    hashBlockLastSeen = hashBlock;
    vWithdrawalStatus = data.vWithdrawalStatus;
    vActivationStatus = data.vActivationStatus;
    vSidechain = data.vSidechain;
}

void SidechainDB::AddRemovedBMM(const uint256& hashRemoved)
{
    setRemovedBMM.insert(hashRemoved);
}

void SidechainDB::AddRemovedDeposit(const uint256& hashRemoved)
{
    vRemovedDeposit.push_back(hashRemoved);
}

void SidechainDB::AddDeposits(const std::vector<SidechainDeposit>& vDeposit)
{
    if (vDeposit.empty())
        return;

    // Split the deposits by nSidechain
    std::vector<std::vector<SidechainDeposit>> vDepositSplit;
    vDepositSplit.resize(vDepositCache.size());
    for (const SidechainDeposit& d : vDeposit) {
        if (!IsSidechainActive(d.nSidechain))
            continue;
        if (HaveDepositCached(d.tx.GetHash()))
            continue;

        // Put deposit into vector based on nSidechain
        vDepositSplit[d.nSidechain].push_back(d);
    }

    // Add the deposits to SCDB
    for (size_t x = 0; x < vDepositSplit.size(); x++) {
        for (size_t y = 0; y < vDepositSplit[x].size(); y++) {
            vDepositCache[x].push_back(vDepositSplit[x][y]);
            setDepositTXID.insert(vDepositSplit[x][y].tx.GetHash());
        }
    }

    // Sort the deposits by CTIP UTXO spend order
    // TODO check return value
    if (!SortSCDBDeposits()) {
        LogPrintf("SCDB %s: Failed to sort SCDB deposits!", __func__);
    }

    // TODO check return value
    // Finally, update the CTIP for each nSidechain and log it
    if (!UpdateCTIP()) {
        LogPrintf("SCDB %s: Failed to update CTIP!", __func__);
    }
}

bool SidechainDB::AddWithdrawal(uint8_t nSidechain, const uint256& hash, bool fDebug)
{
    if (!IsSidechainActive(nSidechain)) {
        LogPrintf("SCDB %s: Rejected Withdrawal: %s. Invalid sidechain number: %u\n",
                __func__,
                hash.ToString());
        return false;
    }

    if (HaveWorkScore(hash, nSidechain)) {
        LogPrintf("SCDB %s: Rejected Withdrawal: %s already known\n",
                __func__,
                hash.ToString());
        return false;
    }

    if (HaveSpentWithdrawal(hash, nSidechain)) {
        LogPrintf("%s: Rejecting Withdrawal: %s - Withdrawal has been spent already!\n",
                __func__, hash.ToString());
        return false;
    }

    if (HaveFailedWithdrawal(hash, nSidechain)) {
        LogPrintf("%s: Rejecting Withdrawal: %s - Withdrawal has failed already!\n",
                __func__, hash.ToString());
        return false;
    }

    SidechainWithdrawalState state;
    state.nSidechain = nSidechain;
    state.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state.nWorkScore = 1;
    state.hash = hash;

    vWithdrawalStatus[nSidechain].push_back(state);

    if (fDebug)
        LogPrintf("SCDB %s: Cached Withdrawal: %s\n", __func__, hash.ToString());

    return true;
}

void SidechainDB::AddSpentWithdrawals(const std::vector<SidechainSpentWithdrawal>& vSpent)
{
    std::map<uint256, std::vector<SidechainSpentWithdrawal>>::iterator it;

    for (const SidechainSpentWithdrawal& spent : vSpent) {
        it = mapSpentWithdrawal.find(spent.hashBlock);
        if (it != mapSpentWithdrawal.end()) {
            it->second.push_back(spent);
        } else {
            mapSpentWithdrawal[spent.hashBlock] = std::vector<SidechainSpentWithdrawal>{ spent };
        }
    }
}

void SidechainDB::AddFailedWithdrawals(const std::vector<SidechainFailedWithdrawal>& vFailed)
{
    std::map<uint256, SidechainFailedWithdrawal>::iterator it;

    for (const SidechainFailedWithdrawal& failed : vFailed)
        mapFailedWithdrawal[failed.hash] = failed;
}

void SidechainDB::BMMAbandoned(const uint256& txid)
{
    setRemovedBMM.erase(txid);
}

void SidechainDB::CacheSidechains(const std::vector<Sidechain>& vSidechainIn)
{
    vSidechain = vSidechainIn;
}

bool SidechainDB::CacheCustomVotes(const std::vector<std::string>& vVote)
{
    if (vVote.size() != SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        return false;

    // Verify votes are valid
    for (const std::string& s : vVote) {
        if (s.empty())
            return false;

        if (s.size() != 64 && s.size() != 1)
            return false;

        if (s.size() == 64 && uint256S(s).IsNull())
            return false;

        if (s.size() == 1 && s.front() != SCDB_DOWNVOTE && s.front() != SCDB_ABSTAIN)
            return false;
    }

    vVoteCache = vVote;

    return true;
}

void SidechainDB::CacheSidechainActivationStatus(const std::vector<SidechainActivationStatus>& vActivationStatusIn)
{
    vActivationStatus = vActivationStatusIn;
}

void SidechainDB::CacheSidechainProposals(const std::vector<Sidechain>& vSidechainProposalIn)
{
    // TODO change container improve performance
    for (const Sidechain& s : vSidechainProposalIn) {
        // Make sure this proposal isn't already cached in our proposals
        bool fFound = false;
        for (const Sidechain& p : vSidechainProposal) {
            if (p == s)
            {
                fFound = true;
                break;
            }
        }
        if (!fFound)
            vSidechainProposal.push_back(s);
    }
}

void SidechainDB::CacheSidechainHashToAck(const uint256& u)
{
    vSidechainHashAck.push_back(u);
}

bool SidechainDB::CacheWithdrawalTx(const CTransaction& tx, uint8_t nSidechain)
{
    if (HaveWithdrawalTxCached(tx.GetHash())) {
        LogPrintf("%s: Rejecting Withdrawal: %s - Already cached!\n",
                __func__, tx.GetHash().ToString());
        return false;
    }

    vWithdrawalTxCache.push_back(std::make_pair(nSidechain, tx));

    return true;
}

bool SidechainDB::CheckWorkScore(uint8_t nSidechain, const uint256& hash, bool fDebug) const
{
    if (!IsSidechainActive(nSidechain))
        return false;

    std::vector<SidechainWithdrawalState> vState = GetState(nSidechain);
    for (const SidechainWithdrawalState& state : vState) {
        if (state.hash == hash) {
            if (state.nWorkScore >= SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE) {
                if (fDebug)
                    LogPrintf("SCDB %s: Approved: %s\n",
                            __func__,
                            hash.ToString());
                return true;
            } else {
                if (fDebug)
                    LogPrintf("SCDB %s: Rejected: %s (insufficient work score)\n",
                            __func__,
                            hash.ToString());
                return false;
            }
        }
    }
    if (fDebug)
        LogPrintf("SCDB %s: Rejected (Withdrawal state not found): %s\n",
                __func__,
                hash.ToString());
    return false;
}

void SidechainDB::ClearRemovedDeposits()
{
    vRemovedDeposit.clear();
}

unsigned int SidechainDB::GetActiveSidechainCount() const
{
    unsigned int i = 0;
    for (const Sidechain& s : vSidechain)  {
        if (s.fActive)
            i++;
    }
    return i;
}

bool SidechainDB::GetAckSidechain(const uint256& u) const
{
    for (const uint256& hash : vSidechainHashAck) {
        if (u == hash) {
            return true;
        }
    }
    return false;
}

std::vector<Sidechain> SidechainDB::GetActiveSidechains() const
{
    std::vector<Sidechain> vActive;
    for (const Sidechain& s : vSidechain)  {
        if (s.fActive)
            vActive.push_back(s);
    }

    return vActive;
}

std::vector<Sidechain> SidechainDB::GetSidechains() const
{
    return vSidechain;
}

std::set<uint256> SidechainDB::GetRemovedBMM() const
{
    return setRemovedBMM;
}

std::vector<uint256> SidechainDB::GetRemovedDeposits() const
{
    return vRemovedDeposit;
}

bool SidechainDB::GetCTIP(uint8_t nSidechain, SidechainCTIP& out) const
{
    if (!IsSidechainActive(nSidechain))
        return false;

    std::map<uint8_t, SidechainCTIP>::const_iterator it = mapCTIP.find(nSidechain);
    if (it != mapCTIP.end()) {
        out = it->second;
        return true;
    }

    return false;
}

bool SidechainDB::GetCachedWithdrawalTx(const uint256& hash, CMutableTransaction& mtx) const
{
    // Find the Withdrawal
    for (const std::pair<uint8_t, CMutableTransaction>& pair : vWithdrawalTxCache) {
        if (pair.second.GetHash() == hash) {
            mtx = pair.second;
            return true;
        }
    }
    return false;
}

std::map<uint8_t, SidechainCTIP> SidechainDB::GetCTIP() const
{
    return mapCTIP;
}

std::vector<std::string> SidechainDB::GetVotes() const
{
    return vVoteCache;
}

std::vector<SidechainDeposit> SidechainDB::GetDeposits(uint8_t nSidechain) const
{
    std::vector<SidechainDeposit> vDeposit;
    if (!IsSidechainActive(nSidechain))
        return vDeposit;

    return vDepositCache[nSidechain];
}

uint256 SidechainDB::GetHashBlockLastSeen()
{
    return hashBlockLastSeen;
}

uint256 SidechainDB::GetTestHash() const
{
    std::vector<uint256> vLeaf;

    // Add mapCTIP
    std::map<uint8_t, SidechainCTIP>::const_iterator it;
    for (it = mapCTIP.begin(); it != mapCTIP.end(); it++) {
        vLeaf.push_back(it->second.GetSerHash());
    }

    uint256 hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with CTIP data: %s\n", __func__, hash.ToString());

    // Add hashBlockLastSeen
    vLeaf.push_back(hashBlockLastSeen);

    hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with hashBlockLastSeen data: %s\n", __func__, hash.ToString());

    // Add vSidechain
    for (const Sidechain& s : vSidechain) {
        vLeaf.push_back(s.GetSerHash());
    }

    hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with vSidechain data: %s\n", __func__, hash.ToString());

    // Add vActivationStatus
    for (const SidechainActivationStatus& s : vActivationStatus) {
        vLeaf.push_back(s.GetSerHash());
    }

    hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with vActivationStatus data: %s\n", __func__, hash.ToString());

    // Add vDepositCache
    for (const std::vector<SidechainDeposit>& v : vDepositCache) {
        for (const SidechainDeposit& d : v) {
            vLeaf.push_back(d.GetSerHash());
        }
    }

    hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with vDepositCache data: %s\n", __func__, hash.ToString());

    // Add vWithdrawalTxCache
    for (const std::pair<uint8_t, CMutableTransaction>& pair : vWithdrawalTxCache) {
        vLeaf.push_back(pair.second.GetHash());
    }

    hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with vWithdrawalTxCache data: %s\n", __func__, hash.ToString());

    // Add vWithdrawalStatus
    for (size_t i = 0; i < SIDECHAIN_ACTIVATION_MAX_ACTIVE; i++) {
        std::vector<SidechainWithdrawalState> vState = GetState(i);
        for (const SidechainWithdrawalState& state : vState) {
            vLeaf.push_back(state.GetSerHash());
        }
    }

    hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with vWithdrawalStatus data (total hash): %s\n", __func__, hash.ToString());

    return ComputeMerkleRoot(vLeaf);
}

bool SidechainDB::GetSidechain(const uint8_t nSidechain, Sidechain& sidechain) const
{
    if (!IsSidechainActive(nSidechain))
        return false;

    sidechain = vSidechain[nSidechain];

    return true;
}

std::vector<SidechainActivationStatus> SidechainDB::GetSidechainActivationStatus() const
{
    return vActivationStatus;
}

std::string SidechainDB::GetSidechainName(uint8_t nSidechain) const
{
    std::string str = "UnknownSidechain";

    Sidechain sidechain;
    if (GetSidechain(nSidechain, sidechain))
        return sidechain.title;

    return str;
}

std::vector<Sidechain> SidechainDB::GetSidechainProposals() const
{
    return vSidechainProposal;
}

bool SidechainDB::GetSidechainScript(const uint8_t nSidechain, CScript& scriptPubKey) const
{
    Sidechain sidechain;
    if (!GetSidechain(nSidechain, sidechain))
        return false;

    scriptPubKey.resize(2);
    scriptPubKey[0] = OP_DRIVECHAIN;
    scriptPubKey[1] = nSidechain;

    return true;
}

std::vector<uint256> SidechainDB::GetSidechainsToActivate() const
{
    return vSidechainHashAck;
}

std::vector<SidechainSpentWithdrawal> SidechainDB::GetSpentWithdrawalsForBlock(const uint256& hashBlock) const
{
    std::map<uint256, std::vector<SidechainSpentWithdrawal>>::const_iterator it;
    it = mapSpentWithdrawal.find(hashBlock);

    if (it != mapSpentWithdrawal.end())
        return it->second;

    return std::vector<SidechainSpentWithdrawal>{};
}

std::vector<SidechainWithdrawalState> SidechainDB::GetState(uint8_t nSidechain) const
{
    if (!HasState() || !IsSidechainActive(nSidechain))
        return std::vector<SidechainWithdrawalState>();

    return vWithdrawalStatus[nSidechain];
}

std::vector<std::vector<SidechainWithdrawalState>> SidechainDB::GetState() const
{
    return vWithdrawalStatus;
}

std::vector<uint256> SidechainDB::GetUncommittedWithdrawalCache(uint8_t nSidechain) const
{
    std::vector<uint256> vHash;
    for (const std::pair<uint8_t, CTransaction>& pair : vWithdrawalTxCache) {
        if (nSidechain != pair.first)
            continue;

        uint256 txid = pair.second.GetHash();
        if (!HaveWorkScore(txid, nSidechain)) {
            vHash.push_back(pair.second.GetHash());
        }
    }
    return vHash;
}

std::vector<std::pair<uint8_t, CMutableTransaction>> SidechainDB::GetWithdrawalTxCache() const
{
    return vWithdrawalTxCache;
}

std::vector<SidechainSpentWithdrawal> SidechainDB::GetSpentWithdrawalCache() const
{
    std::vector<SidechainSpentWithdrawal> vSpent;
    for (auto const& it : mapSpentWithdrawal) {
        for (const SidechainSpentWithdrawal& s : it.second)
            vSpent.push_back(s);
    }
    return vSpent;
}

std::vector<SidechainFailedWithdrawal> SidechainDB::GetFailedWithdrawalCache() const
{
    std::vector<SidechainFailedWithdrawal> vFailed;
    for (auto const& it : mapFailedWithdrawal) {
        vFailed.push_back(it.second);
    }
    return vFailed;
}

bool SidechainDB::HasState() const
{
    // Make sure that SCDB is actually initialized
    if (vWithdrawalStatus.empty() || !GetActiveSidechainCount())
        return false;

    // Check if we have Withdrawal state
    for (auto i : vWithdrawalStatus) {
        if (!i.empty())
            return true;
    }

    return false;
}

bool SidechainDB::HaveDepositCached(const uint256& txid) const
{
    return (setDepositTXID.find(txid) != setDepositTXID.end());
}

bool SidechainDB::HaveSpentWithdrawal(const uint256& hash, const uint8_t nSidechain) const
{
    // TODO change / update container mapSpentWithdrawals so that we can look up
    // Withdrawal(s) by Withdrawal hash instead of looping.
    for (auto const& it : mapSpentWithdrawal) {
        for (const SidechainSpentWithdrawal& s : it.second) {
            if (s.hash == hash && s.nSidechain == nSidechain)
                return true;
        }
    }

    return false;
}

bool SidechainDB::HaveFailedWithdrawal(const uint256& hash, const uint8_t nSidechain) const
{
    std::map<uint256, SidechainFailedWithdrawal>::const_iterator it;
    it = mapFailedWithdrawal.find(hash);
    if (it != mapFailedWithdrawal.end() && it->second.nSidechain == nSidechain)
        return true;

    return false;
}

bool SidechainDB::HaveWithdrawalTxCached(const uint256& hash) const
{
    for (const std::pair<uint8_t, CMutableTransaction>& pair : vWithdrawalTxCache) {
        if (pair.second.GetHash() == hash)
            return true;
    }
    return false;
}

bool SidechainDB::HaveWorkScore(const uint256& hash, uint8_t nSidechain) const
{
    if (!IsSidechainActive(nSidechain))
        return false;

    std::vector<SidechainWithdrawalState> vState = GetState(nSidechain);
    for (const SidechainWithdrawalState& state : vState) {
        if (state.hash == hash)
            return true;
    }
    return false;
}

bool SidechainDB::IsSidechainActive(uint8_t nSidechain) const
{
    if (nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        return false;
    if (nSidechain >= vWithdrawalStatus.size())
        return false;
    if (nSidechain >= vDepositCache.size())
        return false;
    if (nSidechain >= vSidechain.size())
        return false;

    return vSidechain[nSidechain].fActive;
}

void SidechainDB::RemoveExpiredWithdrawals()
{
    for (size_t x = 0; x < vWithdrawalStatus.size(); x++) {
        vWithdrawalStatus[x].erase(std::remove_if(
                    vWithdrawalStatus[x].begin(), vWithdrawalStatus[x].end(),
                    [this](const SidechainWithdrawalState& state)
                    {
                        // If the Withdrawal has 0 blocks remaining, or does not have
                        // enough blocks remaining to gather required work score
                        // then expire it (which will mark it failed) & remove.
                        bool fExpire = false;

                        if (state.nBlocksLeft == 0)
                            fExpire = true;
                        else
                        if (SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE - state.nWorkScore > state.nBlocksLeft)
                            fExpire = true;

                        if (fExpire) {
                            LogPrintf("SCDB RemoveExpiredWithdrawals: Erasing expired Withdrawal: %s\n",
                                    state.ToString());

                            // Add to mapFailedWithdrawals
                            SidechainFailedWithdrawal failed;
                            failed.nSidechain = state.nSidechain;
                            failed.hash = state.hash;
                            AddFailedWithdrawals(std::vector<SidechainFailedWithdrawal>{ failed });

                            // Remove the cached transaction for the failed Withdrawal
                            for (size_t i = 0; i < vWithdrawalTxCache.size(); i++) {
                                if (vWithdrawalTxCache[i].second.GetHash() == state.hash) {
                                    vWithdrawalTxCache[i] = vWithdrawalTxCache.back();
                                    vWithdrawalTxCache.pop_back();
                                    break;
                                }
                            }
                            return true;
                        } else {
                            return false;
                        }
                    }),
                    vWithdrawalStatus[x].end());
    }
}

void SidechainDB::RemoveSidechainHashToAck(const uint256& u)
{
    // TODO change container to make this efficient
    for (size_t i = 0; i < vSidechainHashAck.size(); i++) {
        if (vSidechainHashAck[i] == u) {
            vSidechainHashAck[i] = vSidechainHashAck.back();
            vSidechainHashAck.pop_back();
            break;
        }
    }
}

void SidechainDB::ResetWithdrawalState()
{
    // Clear out Withdrawal state
    vWithdrawalStatus.clear();
    vWithdrawalStatus.resize(SIDECHAIN_ACTIVATION_MAX_ACTIVE);
}

void SidechainDB::ResetWithdrawalVotes()
{
    vVoteCache.clear();
    vVoteCache = std::vector<std::string>(SIDECHAIN_ACTIVATION_MAX_ACTIVE, std::string(1, SCDB_ABSTAIN));
}

void SidechainDB::Reset()
{
    // Clear out CTIP data
    mapCTIP.clear();

    // Reset hashBlockLastSeen
    hashBlockLastSeen.SetNull();

    // Clear out sidechains
    vSidechain.clear();

    // Clear out sidechain activation status
    vActivationStatus.clear();

    // Clear out our cache of sidechain deposits
    vDepositCache.clear();

    // Clear out list of sidechain (hashes) we want to ACK
    vSidechainHashAck.clear();

    // Clear out our cache of proposed sidechains
    vSidechainProposal.clear();

    // Clear out cached Withdrawal serializations
    vWithdrawalTxCache.clear();

    // Clear out Withdrawal state
    ResetWithdrawalState();

    // Clear out custom vote cache
    ResetWithdrawalVotes();

    // Clear out spent Withdrawal cache
    mapSpentWithdrawal.clear();

    // Clear out failed Withdrawal cache
    mapFailedWithdrawal.clear();

    vRemovedDeposit.clear();
    setRemovedBMM.clear();

    // Resize vWithdrawalStatus to keep track of Withdrawal(s)
    vWithdrawalStatus.resize(SIDECHAIN_ACTIVATION_MAX_ACTIVE);

    // Resize vDepositCache to keep track of deposit(s)
    vDepositCache.resize(SIDECHAIN_ACTIVATION_MAX_ACTIVE);

    // Initialize with blank inactive sidechains
    vSidechain.resize(SIDECHAIN_ACTIVATION_MAX_ACTIVE);
    for (size_t i = 0; i < vSidechain.size(); i++)
        vSidechain[i].nSidechain = i;
}

bool SidechainDB::SpendWithdrawal(uint8_t nSidechain, const uint256& hashBlock, const CTransaction& tx, const int nTx, bool fJustCheck, bool fDebug)
{
    fDebug = true;
    if (!IsSidechainActive(nSidechain)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal (txid): %s for sidechain number: %u.\n Invalid sidechain number.\n",
                __func__,
                tx.GetHash().ToString(),
                nSidechain);
        }
        return false;
    }

    if (tx.vout.size() < 3) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal (txid): %s for sidechain number: %u. Missing outputs!.\n",
                __func__,
                tx.GetHash().ToString(),
                nSidechain);
        }
        return false;
    }

    uint256 hashBlind;
    if (!tx.GetBlindHash(hashBlind)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal (txid): %s for sidechain number: %u.\n Cannot get blind hash.\n",
                __func__,
                tx.GetHash().ToString(),
                nSidechain);
        }
        return false;
    }

    if (!CheckWorkScore(nSidechain, hashBlind, fDebug)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal (blind hash): %s for sidechain number: %u. CheckWorkScore() failed.\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
        return false;
    }

    // Find the required change output returning to the sidechain script as well
    // as the required SIDECHAIN_WITHDRAWAL_RETURN_DEST OP_RETURN output.
    bool fChangeOutputFound = false;
    bool fReturnDestFound = false;
    uint32_t nBurnIndex = 0;
    uint8_t nSidechainScript;
    CAmount amountChange = 0;
    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CScript &scriptPubKey = tx.vout[i].scriptPubKey;

        // This would be non-standard but still checking
        if (!scriptPubKey.size())
            continue;

        // The first OP_RETURN output we find must be an encoding of the
        // SIDECHAIN_WITHDRAWAL_RETURN_DEST char. So once we find an OP_RETURN in
        // this loop it must have the correct data encoded. We will return false
        // if it does not and skip this code if we've already found it.
        // Is this the SIDECHAIN_WITHDRAWAL_RETURN_DEST OP_RETURN output?
        if (!fReturnDestFound && scriptPubKey.front() == OP_RETURN) {
            if (scriptPubKey.size() < 3) {
                if (fDebug) {
                    LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. First OP_RETURN output is invalid size for destination. (too small)\n",
                        __func__,
                        hashBlind.ToString(),
                        nSidechain);
                }
                return false;
            }

            CScript::const_iterator pDest = scriptPubKey.begin() + 1;
            opcodetype opcode;
            std::vector<unsigned char> vch;
            if (!scriptPubKey.GetOp(pDest, opcode, vch) || vch.empty()) {
                if (fDebug) {
                    LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. First OP_RETURN output is invalid. (GetOp failed)\n",
                        __func__,
                        hashBlind.ToString(),
                        nSidechain);
                }
                return false;
            }

            std::string strDest((const char*)vch.data(), vch.size());

            if (strDest != SIDECHAIN_WITHDRAWAL_RETURN_DEST) {
                if (fDebug) {
                    LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Missing SIDECHAIN_WITHDRAWAL_RETURN_DEST output.\n",
                        __func__,
                        hashBlind.ToString(),
                        nSidechain);
                }
                return false;
            }
            fReturnDestFound = true;
        }

        if (scriptPubKey.IsDrivechain(nSidechainScript)) {
            if (fChangeOutputFound) {
                // We already found a sidechain script output. This second
                // sidechain output makes the Withdrawal invalid.
                if (fDebug) {
                    LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Multiple sidechain return outputs in Withdrawal.\n",
                        __func__,
                        hashBlind.ToString(),
                        nSidechain);
                }
                return false;
            }

            // Copy output index of sidechain change return deposit
            nBurnIndex = i;
            fChangeOutputFound = true;

            // Copy amount of sidechain change
            amountChange = tx.vout[i].nValue;

            continue;
        }
    }

    // Make sure that the sidechain output was found
    if (!fChangeOutputFound) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. No sidechain return output in Withdrawal.\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
        return false;
    }

    // Make sure that the sidechain output is to the correct sidechain
    if (nSidechainScript != nSidechain) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Return output to incorrect nSidechain: %u in Withdrawal.\n",
                __func__,
                hashBlind.ToString(),
                nSidechain,
                nSidechainScript);
        }
        return false;
    }

    if (nSidechain >= vWithdrawalStatus.size()) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Withdrawal status for sidechain not found.\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
        return false;
    }

    // Get CTIP
    SidechainCTIP ctip;
    if (!GetCTIP(nSidechain, ctip)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. CTIP not found!\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
       return false;
    }

    // Check that Withdrawal input matches CTIP
    if (ctip.out != tx.vin[0].prevout) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. CTIP does not match!\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
       return false;
    }

    // Decode sum of withdrawal fees
    CAmount amountFees = 0;
    if (!DecodeWithdrawalFees(tx.vout[1].scriptPubKey, amountFees)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. failed to decode withdrawal fees!\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
       return false;
    }

    // Get the total value out of the blind Withdrawal
    CAmount amountBlind = tx.GetBlindValueOut();

    CAmount amountInput = ctip.amount;
    CAmount amountOutput = tx.GetValueOut();

    // Check output amount
    if (amountBlind != amountOutput - amountChange) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Invalid output amount!\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
       return false;
    }

    // Check change amount
    if (amountChange != amountInput - (amountBlind + amountFees)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Invalid change amount!\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
       return false;
    }

    if (fJustCheck)
        return true;

    // Create a sidechain deposit object for the return amount
    SidechainDeposit deposit;
    deposit.nSidechain = nSidechain;
    deposit.strDest = SIDECHAIN_WITHDRAWAL_RETURN_DEST;
    deposit.tx = tx;
    deposit.nBurnIndex = nBurnIndex;
    deposit.nTx = nTx;
    deposit.hashBlock = hashBlock;

    // Add deposit to cache, update CTIP
    AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // TODO In the event that the block which spent a Withdrawal is disconnected, a
    // miner will no longer have the raw Withdrawal transaction to create a Withdrawal payout
    // in the block that replaces the disconnected block. They will either have
    // to get it from the sidechain again, or this code can be changed to not
    // removed spent Withdrawal(s) until some number of blocks after it has been spent
    // to avoid this issue. Another option is to cache all received Withdrawal raw txns
    // until the miner manually clears them out with an RPC command or similar.
    //
    // Find the cached transaction for the Withdrawal we spent and remove it
    for (size_t i = 0; i < vWithdrawalTxCache.size(); i++) {
        if (vWithdrawalTxCache[i].second.GetHash() == hashBlind) {
            vWithdrawalTxCache[i] = vWithdrawalTxCache.back();
            vWithdrawalTxCache.pop_back();
            break;
        }
    }

    SidechainSpentWithdrawal spent;
    spent.nSidechain = nSidechain;
    spent.hash = hashBlind;
    spent.hashBlock = hashBlock;

    // Track the spent Withdrawal
    AddSpentWithdrawals(std::vector<SidechainSpentWithdrawal>{ spent });

    // The Withdrawal will be removed from SCDB when SCDB::Update() is called now that
    // it has been marked as spent.

    LogPrintf("%s Withdrawal spent: %s for sidechain number: %u.\n", __func__, hashBlind.ToString(), nSidechain);

    return true;
}

bool SidechainDB::TxnToDeposit(const CTransaction& tx, const int nTx, const uint256& hashBlock, SidechainDeposit& deposit)
{
    // Note that the first OP_RETURN output found in a deposit transaction will
    // be used as the destination. Others are ignored.
    bool fBurnFound = false;
    bool fDestFound = false;
    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CScript &scriptPubKey = tx.vout[i].scriptPubKey;

        if (!scriptPubKey.size())
            continue;

        uint8_t nSidechain;
        if (scriptPubKey.IsDrivechain(nSidechain)) {
            // If we already found a burn output, more make the deposit invalid
            if (fBurnFound) {
                LogPrintf("%s: Invalid - multiple burn outputs.\ntxid: %s\n", __func__, tx.GetHash().ToString());
                return false;
            }

            // We found the burn output, copy the output index & nSidechain
            deposit.nSidechain = nSidechain;
            deposit.nBurnIndex = i;
            fBurnFound = true;
            continue;
        }

        // Move on to looking for the encoded destination string

        if (fDestFound)
            continue;
        if (scriptPubKey.front() != OP_RETURN)
            continue;
        if (scriptPubKey.size() < 3) {
            LogPrintf("%s: Invalid - First OP_RETURN is invalid (too small).\ntxid: %s\n", __func__, tx.GetHash().ToString());
            return false;
        }
        if (scriptPubKey.size() > MAX_DEPOSIT_DESTINATION_BYTES) {
            LogPrintf("%s: Invalid - First OP_RETURN is invalid (too large).\ntxid: %s\n", __func__, tx.GetHash().ToString());
            return false;
        }

        CScript::const_iterator pDest = scriptPubKey.begin() + 1;
        opcodetype opcode;
        std::vector<unsigned char> vch;
        if (!scriptPubKey.GetOp(pDest, opcode, vch) || vch.empty()) {
            LogPrintf("%s: Invalid - First OP_RETURN is invalid (failed GetOp).\ntxid: %s\n", __func__, tx.GetHash().ToString());
            return false;
        }

        std::string strDest((const char*)vch.data(), vch.size());
        if (strDest.empty()) {
            LogPrintf("%s: Invalid - empty dest.\ntxid: %s\n", __func__, tx.GetHash().ToString());
            return false;
        }

        deposit.strDest = strDest;

        fDestFound = true;
    }

    deposit.tx = tx;
    deposit.hashBlock = hashBlock;
    deposit.nTx = nTx;

    return (fBurnFound && fDestFound && CTransaction(deposit.tx) == tx);
}

std::string SidechainDB::ToString() const
{
    std::string str;
    str += "SidechainDB:\n";

    str += "Hash of block last seen: " + hashBlockLastSeen.ToString() + "\n";

    std::vector<Sidechain> vActiveSidechain = GetActiveSidechains();

    str += "Sidechains: ";
    str += std::to_string(vSidechain.size());
    str += "\n";
    for (const Sidechain& s : vActiveSidechain) {
        // Print sidechain name
        str += "Sidechain: " + s.GetSidechainName() + "\n";

        // Print sidechain Withdrawal workscore(s)
        std::vector<SidechainWithdrawalState> vState = GetState(s.nSidechain);
        str += "Withdrawal(s): ";
        str += std::to_string(vState.size());
        str += "\n";
        for (const SidechainWithdrawalState& state : vState) {
            str += "Withdrawal:\n";
            str += state.ToString();
        }
        str += "\n";

        // Print CTIP
        SidechainCTIP ctip;
        str += "CTIP:\n";
        if (GetCTIP(s.nSidechain, ctip)) {
            str += "txid: " + ctip.out.hash.ToString() + "\n";
            str += "n: " + std::to_string(ctip.out.n) + "\n";
            str += "amount: " + std::to_string(ctip.amount) + "\n";
        } else {
            str += "No CTIP found for sidechain.\n";
        }
        str += "\n";
    }

    str += "Sidechain proposal activation status:\n";

    if (!vActivationStatus.size())
        str += "No sidechain proposal status.\n";
    for (const SidechainActivationStatus& s : vActivationStatus) {
        str += s.proposal.ToString();
        str += "age: " + std::to_string(s.nAge) += "\n";
        str += "fails: " + std::to_string(s.nFail) += "\n";
    }
    str += "\n";

    return str;
}

bool SidechainDB::Update(int nHeight, const uint256& hashBlock, const uint256& hashPrevBlock, const std::vector<CTxOut>& vout, bool fJustCheck, bool fDebug)
{
    // Make a copy of SCDB to test update
    SidechainDB scdbCopy = (*this);
    if (scdbCopy.ApplyUpdate(nHeight, hashBlock, hashPrevBlock, vout, fJustCheck, fDebug)) {
        return ApplyUpdate(nHeight, hashBlock, hashPrevBlock, vout, fJustCheck, fDebug);
    } else {
        return false;
    }
}

bool SidechainDB::ApplyUpdate(int nHeight, const uint256& hashBlock, const uint256& hashPrevBlock, const std::vector<CTxOut>& vout, bool fJustCheck, bool fDebug)
{
    if (hashBlock.IsNull()) {
        if (fDebug)
            LogPrintf("SCDB %s: Failed: block hash is null at height: %u\n",
                    __func__,
                    nHeight);
        return false;
    }

    if (!hashBlockLastSeen.IsNull() && hashPrevBlock.IsNull())
    {
        if (fDebug)
            LogPrintf("SCDB %s: Failed: previous block hash null at height: %u\n",
                    __func__,
                    nHeight);
        return false;
    }

    if (!vout.size())
    {
        if (fDebug)
            LogPrintf("SCDB %s: Failed: empty coinbase transaction at height: %u\n",
                    __func__,
                    nHeight);
        return false;
    }


    if (!hashBlockLastSeen.IsNull() && hashPrevBlock != hashBlockLastSeen) {
        if (fDebug)
            LogPrintf("SCDB %s: Failed: previous block hash: %s does not match hashBlockLastSeen: %s at height: %u\n",
                    __func__,
                    hashPrevBlock.ToString(),
                    hashBlockLastSeen.ToString(),
                    nHeight);
        return false;
    }

    /*
     * Look for data relevant to SCDB in this block's coinbase.
     *
     * Scan for new Withdrawal(s) and start tracking them.
     *
     * Scan for SCDB vote bytes, and update withdrawal scores
     *
     * Scan for sidechain proposals & sidechain activation commitments.
     *
     * Update hashBlockLastSeen.
     */

    // Scan for sidechain proposal commitments
    std::vector<Sidechain> vProposal;
    for (const CTxOut& out : vout) {
        const CScript& scriptPubKey = out.scriptPubKey;

        if (!scriptPubKey.IsSidechainProposalCommit())
            continue;

        Sidechain proposal;
        if (!proposal.DeserializeFromProposalScript(scriptPubKey))
            continue;

        vProposal.push_back(proposal);
    }

    // Maximum of 1 sidechain proposal per block
    if (vProposal.size() > 1) {
        if (fDebug)
            LogPrintf("SCDB %s: Invalid: block with multiple sidechain proposals at height: %u\n",
                    __func__,
                    nHeight);
        return false;
    }

    // Track sidechain proposal
    if (!fJustCheck && vProposal.size() == 1) {
        SidechainActivationStatus status;
        status.nFail = 0;
        status.nAge = 0;
        status.proposal = vProposal.front();

        // Start tracking the new sidechain proposal
        vActivationStatus.push_back(status);

        LogPrintf("SCDB %s: Tracking new sidechain proposal:\n%s\n",
                __func__,
                status.proposal.ToString());
    }

    // Scan for sidechain activation commitments
    std::map<uint8_t, uint256> mapActivation;
    std::vector<uint256> vActivationHash;
    for (const CTxOut& out : vout) {
        const CScript& scriptPubKey = out.scriptPubKey;
        uint256 hashSidechain;
        if (!scriptPubKey.IsSidechainActivationCommit(hashSidechain))
            continue;
        if (hashSidechain.IsNull())
            continue;

        // Look up the sidechain number for this activation commitment
        bool fFound = false;
        uint8_t nSidechain = 0;
        for (const SidechainActivationStatus& s : vActivationStatus) {
            if (s.proposal.GetSerHash() == hashSidechain) {
                fFound = true;
                nSidechain = s.proposal.nSidechain;
                break;
            }
        }
        if (!fFound) {
            if (fDebug)
                LogPrintf("SCDB %s: Invalid: Sidechain activation commit for unknown proposal.\nProposal hash: %s\n",
                        __func__,
                        hashSidechain.ToString());
            return false;
        }

        // Check that there is only 1 sidechain activation commit per
        // sidechain slot number per block
        std::map<uint8_t, uint256>::const_iterator it = mapActivation.find(nSidechain);
        if (it == mapActivation.end()) {
            mapActivation[nSidechain] = hashSidechain;
        } else {
            if (fDebug) {
                LogPrintf("SCDB %s: Multiple activation commitments for sidechain number: %u at height: %u\n",
                        __func__,
                        nSidechain,
                        nHeight);
            }
            return false;
        }
        vActivationHash.push_back(hashSidechain);
    }
    if (!fJustCheck)
        UpdateActivationStatus(vActivationHash);

    // Scan for new sidechain withdrawals. Check that there are no more than 1
    // new withdrawal per sidechain per block. Keep track of new withdrawals and
    // add them to SCDB later.
    std::map<uint8_t, uint256> mapNewWithdrawal;
    for (const CTxOut& out : vout) {
        const CScript& scriptPubKey = out.scriptPubKey;
        uint8_t nSidechain;
        uint256 hash;
        if (scriptPubKey.IsWithdrawalHashCommit(hash, nSidechain)) {
            if (!IsSidechainActive(nSidechain)) {
                if (fDebug)
                    LogPrintf("SCDB %s: Skipping new Withdrawal: %s, invalid sidechain number: %u\n",
                            __func__,
                            hash.ToString(),
                            nSidechain);
                continue;
            }

            // Check that there is only 1 new Withdrawal per sidechain per block
            std::map<uint8_t, uint256>::const_iterator it = mapNewWithdrawal.find(nSidechain);
            if (it == mapNewWithdrawal.end()) {
                mapNewWithdrawal[nSidechain] = hash;
            } else {
                if (fDebug) {
                    LogPrintf("SCDB %s: Multiple new withdrawals for sidechain number: %u at height: %u\n",
                            __func__,
                            nSidechain,
                            nHeight);
                }
                return false;
            }
        }
    }

    // Update SCDB withdrawl vote scores and add new withdrawals
    if (!fJustCheck && (HasState() || mapNewWithdrawal.size())) {
        // Check if there are update bytes
        std::vector<CScript> vUpdateBytes;
        for (const CTxOut& out : vout) {
            const CScript scriptPubKey = out.scriptPubKey;
            if (scriptPubKey.IsSCDBBytes())
                vUpdateBytes.push_back(scriptPubKey);
        }
        // There is a maximum of 1 update bytes script
        if (vUpdateBytes.size() > 1) {
            if (fDebug)
                LogPrintf("SCDB %s: Error: multiple update byte scripts at height: %u\n",
                       __func__,
                       nHeight);
            return false;
        }

        // Read SCDB m4 update bytes, or create default abstain votes
        std::vector<std::string> vVote;
        if (vUpdateBytes.size()) {
            // Get old (current) state
            std::vector<std::vector<SidechainWithdrawalState>> vOldState;
            for (const Sidechain& s : vSidechain) {
                std::vector<SidechainWithdrawalState> vWithdrawal = GetState(s.nSidechain);
                if (vWithdrawal.size())
                    vOldState.push_back(vWithdrawal);
            }

            // Parse SCDB update bytes for new withdrawal scores
            if (!ParseSCDBBytes(vUpdateBytes.front(), vOldState, vVote)) {
                if (fDebug)
                    LogPrintf("SCDB %s: Error: Failed to parse update bytes at height: %u\n",
                            __func__,
                            nHeight);
                return false;
            }
            if (fDebug)
                LogPrintf("SCDB %s: Parsed update bytes at height: %u\n",
                        __func__,
                        nHeight);
        } else {
            vVote = std::vector<std::string>(SIDECHAIN_ACTIVATION_MAX_ACTIVE, std::string(1, SCDB_ABSTAIN));
        }

        bool fUpdated = UpdateSCDBIndex(vVote, true /* fDebug */, mapNewWithdrawal);
        if (!fUpdated) {
            if (fDebug)
                LogPrintf("SCDB %s: Failed to update SCDB at height: %u\n",
                        __func__,
                        nHeight);
            return false;
        }
    }

    // Remove any Withdrawal(s) that were spent in this block. This can happen when a
    // new block is connected, re-connected, or during SCDB resync.
    std::vector<SidechainSpentWithdrawal> vSpent;
    vSpent = GetSpentWithdrawalsForBlock(hashBlock);
    for (const SidechainSpentWithdrawal& s : vSpent) {
        if (!IsSidechainActive(s.nSidechain)) {
            if (fDebug) {
                LogPrintf("SCDB %s: Spent Withdrawal has invalid sidechain number: %u at height: %u\n",
                        __func__,
                        s.nSidechain,
                        nHeight);
            }
            return false;
        }
        bool fRemoved = false;
        for (size_t i = 0; i < vWithdrawalStatus[s.nSidechain].size(); i++) {
            const SidechainWithdrawalState state = vWithdrawalStatus[s.nSidechain][i];
            if (state.nSidechain == s.nSidechain && state.hash == s.hash) {
                if (fDebug && !fJustCheck) {
                    LogPrintf("SCDB %s: Removing spent Withdrawal: %s for nSidechain: %u in block %s.\n",
                            __func__,
                            state.hash.ToString(),
                            state.nSidechain,
                            hashBlock.ToString());
                }

                fRemoved = true;
                if (fJustCheck)
                    break;

                // Remove the spent Withdrawal
                vWithdrawalStatus[s.nSidechain][i] = vWithdrawalStatus[s.nSidechain].back();
                vWithdrawalStatus[s.nSidechain].pop_back();
                break;
            }
        }
        if (!fRemoved) {
            if (fDebug) {
                LogPrintf("SCDB %s: Failed to remove spent Withdrawal: %s for sidechain: %u at height: %u\n",
                        __func__,
                        s.hash.ToString(),
                        s.nSidechain,
                        nHeight);
            }
            return false;
        }
    }

    if (fDebug && !fJustCheck) {
        LogPrintf("SCDB %s: Updated from block %s to block %s.\n",
                __func__,
                hashBlockLastSeen.ToString(),
                hashBlock.ToString());
    }

    // Update hashBLockLastSeen
    if (!fJustCheck)
        hashBlockLastSeen = hashBlock;

    return true;
}

bool SidechainDB::Undo(int nHeight, const uint256& hashBlock, const uint256& hashPrevBlock, const std::vector<CTransactionRef>& vtx, bool fDebug)
{
    // Withdrawal workscore is recalculated by ResyncSCDB in validation - not here
    // Sidechain activation is also recalculated by ResyncSCDB not here.

    if (!vtx.size()) {
        LogPrintf("%s: SCDB undo failed for block: %s - vtx is empty!\n", __func__, hashBlock.ToString());
        return false;
    }

    // Remove cached Withdrawal spends from the block that was disconnected
    std::map<uint256, std::vector<SidechainSpentWithdrawal>>::const_iterator it;
    it = mapSpentWithdrawal.find(hashBlock);
    if (it != mapSpentWithdrawal.end())
        mapSpentWithdrawal.erase(it);

    // TODO lookup deposits in cache with setDepositTXID, then std::remove_if
    //
    // Undo deposits
    // Loop through the transactions in the block being disconnected, and if
    // they match a transaction in our deposit cache remove it.
    bool fDepositRemoved = false;
    for (const CTransactionRef& tx : vtx) {
        for (size_t x = 0; x < vDepositCache.size(); x++) {
            std::vector<SidechainDeposit>::iterator it;
            for (it = vDepositCache[x].begin(); it != vDepositCache[x].end();) {
                if (*tx == CTransaction(it->tx)) {
                    setDepositTXID.erase(tx->GetHash());
                    fDepositRemoved = true;
                    it = vDepositCache[x].erase(it);
                } else {
                    it++;
                }
            }
        }
    }

    // If any deposits were removed re-sort deposits and update CTIP
    if (fDepositRemoved) {
        // TODO check return value
        if (!SortSCDBDeposits()) {
            LogPrintf("SCDB %s: Failed to sort SCDB deposits!", __func__);
        }
        // TODO check return value
        if (!UpdateCTIP()) {
            LogPrintf("SCDB %s: Failed to update CTIP!", __func__);
        }
    }

    // Undo hashBlockLastSeen
    hashBlockLastSeen = hashPrevBlock;

    LogPrintf("%s: SCDB undo for block: %s complete!\n", __func__, hashBlock.ToString());

    return true;
}

bool SidechainDB::UpdateSCDBIndex(const std::vector<std::string>& vVote, bool fDebug, const std::map<uint8_t, uint256>& mapNewWithdrawal)
{
    if (vWithdrawalStatus.empty()) {
        if (fDebug)
            LogPrintf("SCDB %s: Update failed: vWithdrawalStatus is empty!\n",
                    __func__);
        return false;
    }

    // Remove expired withdrawals
    RemoveExpiredWithdrawals();

    // Age existing withdrawals
    for (size_t x = 0; x < vWithdrawalStatus.size(); x++) {
        for (size_t y = 0; y < vWithdrawalStatus[x].size(); y++) {
            if (vWithdrawalStatus[x][y].nBlocksLeft > 0)
                vWithdrawalStatus[x][y].nBlocksLeft--;
        }
    }

    if (vVote.size() != vWithdrawalStatus.size()) {
        if (fDebug)
            LogPrintf("SCDB %s: Update failed: vVote size is invalid!\n",
                    __func__);
        return false;
    }

    // Update withdrawal scores
    for (size_t x = 0; x < vWithdrawalStatus.size(); x++) {
        if (vVote[x].empty()) {
            if (fDebug)
                LogPrintf("SCDB %s: Update failed: vote characters invalid!\n",
                        __func__);
            return false;
        }

        // What type of vote do we have for this sidechain?
        uint256 hash = uint256();
        char vote = SCDB_ABSTAIN;
        if (vVote[x].size() == 64) {
            hash = uint256S(vVote[x]);
            if (hash.IsNull()) {
                if (fDebug)
                    LogPrintf("SCDB %s: Update failed: upvote hash invalid!\n",
                            __func__);
                return false;
            }
            vote = SCDB_UPVOTE;
        }
        else
        if (vVote[x].front() == SCDB_DOWNVOTE)
            vote = SCDB_DOWNVOTE;

        // Apply score changes. Do not apply score changes to withdrawals for
        // any sidechain that has added a new withdrawal
        for (size_t y = 0; y < vWithdrawalStatus[x].size(); y++) {
            if (mapNewWithdrawal.find(x) != mapNewWithdrawal.end())
                continue;

            if (vote == SCDB_UPVOTE) {
                if (vWithdrawalStatus[x][y].hash == hash) {
                    if (vWithdrawalStatus[x][y].nWorkScore < 65535)
                        vWithdrawalStatus[x][y].nWorkScore++;
                } else {
                    if (vWithdrawalStatus[x][y].nWorkScore > 0)
                        vWithdrawalStatus[x][y].nWorkScore--;
                }
            }
            else
            if (vote == SCDB_DOWNVOTE) {
                    if (vWithdrawalStatus[x][y].nWorkScore > 0)
                        vWithdrawalStatus[x][y].nWorkScore--;
            }
        }
    }

    // Add new withdrawals
    for (const std::pair<uint8_t, uint256>& p : mapNewWithdrawal) {
        if (!AddWithdrawal(p.first, p.second, true /* fDebug */)) {
            if (fDebug)
                LogPrintf("SCDB %s: Failed to add withdrawal!\n", __func__);
            return false;
        }
    }

    return true;
}

void SidechainDB::ApplyDefaultUpdate()
{
    if (!HasState())
        return;

    // Decrement nBlocksLeft, nothing else changes
    for (size_t x = 0; x < vWithdrawalStatus.size(); x++) {
        for (size_t y = 0; y < vWithdrawalStatus[x].size(); y++) {
            if (vWithdrawalStatus[x][y].nBlocksLeft > 0)
                vWithdrawalStatus[x][y].nBlocksLeft--;
        }
    }

    // Remove expired Withdrawal(s)
    RemoveExpiredWithdrawals();
}

void SidechainDB::UpdateActivationStatus(const std::vector<uint256>& vHash)
{
    // TODO change containers

    // Increment the age of all sidechain proposals and remove expired.
    std::vector<SidechainActivationStatus>::iterator it;
    for (it = vActivationStatus.begin(); it != vActivationStatus.end();) {
        it->nAge++;

        int nPeriod = 0;
        if (IsSidechainActive(it->proposal.nSidechain))
            nPeriod = SIDECHAIN_REPLACEMENT_PERIOD;
        else
            nPeriod = SIDECHAIN_ACTIVATION_PERIOD;

        if (it->nAge > nPeriod) {
            LogPrintf("SCDB %s: Sidechain proposal expired:\n%s\n",
                    __func__,
                    it->proposal.ToString());

            it = vActivationStatus.erase(it);
        } else {
            it++;
        }
    }

    // Calculate failures. Sidechain proposals with activation status will have
    // their activation failure count increased by 1 if a activation commitment
    // for them is not found in the block. New sidechain proposals (age = 1)
    // count as an activation commitment.
    for (size_t i = 0; i < vActivationStatus.size(); i++) {
        // Skip new sidechain proposals
        if (vActivationStatus[i].nAge == 1)
            continue;

        // Search for sidechain activation commitments
        bool fFound = false;
        for (const uint256& u : vHash) {
            if (u == vActivationStatus[i].proposal.GetSerHash()) {
                fFound = true;
                break;
            }
        }
        if (!fFound)
            vActivationStatus[i].nFail++;
    }

    // Remove sidechain proposals with too many failures to activate
    for (it = vActivationStatus.begin(); it != vActivationStatus.end();) {
        if (it->nFail >= SIDECHAIN_ACTIVATION_MAX_FAILURES) {
            LogPrintf("SCDB %s: Sidechain proposal rejected:\n%s\n",
                    __func__,
                    it->proposal.ToString());

            it = vActivationStatus.erase(it);
        } else {
            it++;
        }
    }

    // Search for sidechains that have passed the test and should be activated.
    for (it = vActivationStatus.begin(); it != vActivationStatus.end();) {
        // The required period to be activated is either the normal sidechain
        // activation period for a new sidechain, or the same as the Withdrawal
        // minimum workscore for a proposal that replaces an active sidechain.
        int nPeriodRequired = 0;
        if (IsSidechainActive(it->proposal.nSidechain))
            nPeriodRequired = SIDECHAIN_REPLACEMENT_PERIOD;
        else
            nPeriodRequired = SIDECHAIN_ACTIVATION_PERIOD;

        // If a proposal makes it to the required age without being killed off
        // by failures then it will be activated.
        if (it->nAge == nPeriodRequired) {
            // Create sidechain object from proposal
            Sidechain sidechain;
            sidechain.fActive = true;
            sidechain.nSidechain    = it->proposal.nSidechain;
            sidechain.nVersion      = it->proposal.nVersion;
            sidechain.hashID1       = it->proposal.hashID1;
            sidechain.hashID2       = it->proposal.hashID2;
            sidechain.title         = it->proposal.title;
            sidechain.description   = it->proposal.description;

            // Update nSidechain slot with new sidechain params
            vSidechain[sidechain.nSidechain] = sidechain;

            // Remove from cache of our own proposals
            for (size_t j = 0; j < vSidechainProposal.size(); j++) {
                if (it->proposal == vSidechainProposal[j]) {
                    vSidechainProposal[j] = vSidechainProposal.back();
                    vSidechainProposal.pop_back();
                    break;
                }
            }
            // Remove SCDB proposal activation status
            it = vActivationStatus.erase(it);

            // Reset Withdrawal status for new sidechain
            vWithdrawalStatus[sidechain.nSidechain].clear();

            // Reset deposits for new sidechain
            vDepositCache[sidechain.nSidechain].clear();

            // Reset CTIP for new sidechain
            mapCTIP.erase(sidechain.nSidechain);

            LogPrintf("SCDB %s: Sidechain activated:\n%s\n",
                    __func__,
                    sidechain.ToString());
        } else {
            it++;
        }
    }
}

bool SidechainDB::SortSCDBDeposits()
{
    std::vector<std::vector<SidechainDeposit>> vDepositSorted;

    // Loop through deposits and sort the vector for each sidechain
    for (const std::vector<SidechainDeposit>& v : vDepositCache) {
        std::vector<SidechainDeposit> vDeposit;
        if (!SortDeposits(v, vDeposit)) {
            LogPrintf("%s: Error: Failed to sort deposits!\n", __func__);
            return false;
        }
        vDepositSorted.push_back(vDeposit);
    }

    // Update deposit cache with sorted list
    vDepositCache = vDepositSorted;

    return true;
}

bool SidechainDB::UpdateCTIP()
{
    for (size_t x = 0; x < vDepositCache.size(); x++) {
        if (vDepositCache[x].size()) {
            const SidechainDeposit& d = vDepositCache[x].back();

            if (d.nBurnIndex >= d.tx.vout.size())
                return false;

            const COutPoint out(d.tx.GetHash(), d.nBurnIndex);
            const CAmount amount = d.tx.vout[d.nBurnIndex].nValue;

            SidechainCTIP ctip;
            ctip.out = out;
            ctip.amount = amount;

            mapCTIP[d.nSidechain] = ctip;

            // Log the update
            LogPrintf("SCDB %s: Updated sidechain CTIP for nSidechain: %u. CTIP output: %s CTIP amount: %i.\n",
                __func__,
                d.nSidechain,
                out.ToString(),
                amount);
        } else {
            // If there are no deposits now, remove CTIP for nSidechain
            std::map<uint8_t, SidechainCTIP>::const_iterator it;
            it = mapCTIP.find(x);

            if (it != mapCTIP.end()) {
                mapCTIP.erase(it);
                LogPrintf("SCDB %s: Removed sidechain CTIP.\n",
                    __func__);
            }

        }
    }
    return true;
}

bool DecodeWithdrawalFees(const CScript& script, CAmount& amount)
{
    if (script[0] != OP_RETURN || script.size() != 10) {
        LogPrintf("%s: Error: Invalid script!\n", __func__);
        return false;
    }

    CScript::const_iterator it = script.begin() + 1;
    std::vector<unsigned char> vch;
    opcodetype opcode;

    if (!script.GetOp(it, opcode, vch)) {
        LogPrintf("%s: Error: GetOp failed!\n", __func__);
        return false;
    }

    if (vch.empty()) {
        LogPrintf("%s: Error: Amount bytes empty!\n", __func__);
        return false;
    }

    if (vch.size() > 8) {
        LogPrintf("%s: Error: Amount bytes too large!\n", __func__);
        return false;
    }

    try {
        CDataStream ds(vch, SER_NETWORK, PROTOCOL_VERSION);
        ds >> amount;
    } catch (const std::exception&) {
        LogPrintf("%s: Error: Failed to deserialize amount!\n", __func__);
        return false;
    }

    return true;
}

bool SortDeposits(const std::vector<SidechainDeposit>& vDeposit, std::vector<SidechainDeposit>& vDepositSorted)
{
    if (vDeposit.empty())
        return true;

    if (vDeposit.size() == 1) {
        vDepositSorted = vDeposit;
        return true;
    }

    // Find the first deposit in the list by looking for the deposit which
    // spends a CTIP not in the list. There can only be one. We are also going
    // to check that there is only one missing CTIP input here.
    int nMissingCTIP = 0;
    for (size_t x = 0; x < vDeposit.size(); x++) {
        const SidechainDeposit dx = vDeposit[x];

        // Look for the input of this deposit
        bool fFound = false;
        for (size_t y = 0; y < vDeposit.size(); y++) {
            const SidechainDeposit dy = vDeposit[y];

            // The CTIP output of the deposit that might be the input
            const COutPoint prevout(dy.tx.GetHash(), dy.nBurnIndex);

            // Look for the CTIP output
            for (const CTxIn& in : dx.tx.vin) {
                if (in.prevout == prevout) {
                    fFound = true;
                    break;
                }
            }
            if (fFound)
                break;
        }

        // If we didn't find the CTIP input, this should be the first and only
        // deposit without one.
        if (!fFound) {
            nMissingCTIP++;
            if (nMissingCTIP > 1) {
                LogPrintf("%s: Error: Multiple missing CTIP!\n", __func__);
                return false;
            }
            // Add the first deposit to the result
            vDepositSorted.push_back(dx);
            // We found the first deposit but do not stop the loop here
            // because we are also checking to make sure there aren't any
            // other deposits missing a CTIP input from the list.
        }
    }

    if (vDepositSorted.empty()) {
        LogPrintf("%s: Error: Could not find first deposit in list!\n", __func__);
        return false;
    }

    // Now that we know which deposit is first in the list we can add the rest
    // in CTIP spend order.

    // Track the CTIP output of the latest deposit we have sorted
    COutPoint prevout(vDepositSorted.back().tx.GetHash(), vDepositSorted.back().nBurnIndex);

    // Look for the deposit that spends the last sorted CTIP output and sort it.
    // If we cannot find a deposit spending the CTIP, that should mean we
    // reached the end of sorting.
    std::vector<SidechainDeposit>::const_iterator it = vDeposit.begin();
    while (it != vDeposit.end()) {
        bool fFound = false;
        for (const CTxIn& in : it->tx.vin) {
            if (in.prevout == prevout) {
                // Add the sorted deposit to the list
                vDepositSorted.push_back(*it);

                // Update the CTIP output we are looking for
                const SidechainDeposit deposit = vDepositSorted.back();
                prevout = COutPoint(deposit.tx.GetHash(), deposit.nBurnIndex);

                // Start from begin() again
                fFound = true;
                it = vDeposit.begin();

                break;
            }
        }
        if (!fFound)
            it++;
    }

    if (vDeposit.size() != vDepositSorted.size()) {
        LogPrintf("%s: Error: Invalid result size! In: %u Out: %u\n", __func__,
                vDeposit.size(), vDepositSorted.size());
        return false;
    }

    return true;
}

bool ParseSCDBBytes(const CScript& script, const std::vector<std::vector<SidechainWithdrawalState>>& vOldScores, std::vector<std::string>& vVote)
{
    if (script.size() < 8 || !script.IsSCDBBytes()) {
        LogPrintf("SCDB %s: Error: script not SCDB update bytes!\n", __func__);
        return false;
    }

    if (vOldScores.empty()) {
        LogPrintf("SCDB %s: Error: no old scores!\n", __func__);
        return false;
    }

    uint8_t nVersion = script[5];
    if (nVersion > SCDB_BYTES_MAX_VERSION) {
        LogPrintf("SCDB %s: Error: Invalid version!\n", __func__);
        return false;
    }

    for (const std::vector<SidechainWithdrawalState>& v : vOldScores) {
        if (v.empty()) {
            LogPrintf("SCDB %s: Error: invalid (empty) old scores!\n", __func__);
            return false;
        }
    }

    vVote.clear();
    vVote = std::vector<std::string>(SIDECHAIN_ACTIVATION_MAX_ACTIVE, std::string(1, SCDB_ABSTAIN));

    CScript bytes = CScript(script.begin() + 6, script.end());

    // The score index is the current vector of withdrawal bundle scores
    // we are looping through. This is different than the sidechain number,
    // because a vector of scores will only be passed in for sidechains
    // with pending withdrawals and otherwise skipped.
    size_t nScoreIndex = 0;
    for (size_t i = 0; i < bytes.size(); i += 2) {
        if (nScoreIndex >= vOldScores.size()) {
            LogPrintf("SCDB %s: Error: invalid upvote index - too large!\n", __func__);
            return false;
        }

        // Copy sidechain number from first withdrawal at score index
        size_t nSidechain = vOldScores[nScoreIndex][0].nSidechain;

        if (bytes[i] == 0xFF && bytes[i + 1] == 0xFF) {
            // Abstain bytes
            vVote[nSidechain] = SCDB_ABSTAIN;
        }
        else
        if (bytes[i] == 0xFF && bytes[i + 1] == 0xFE) {
            // Downvote bytes
            vVote[nSidechain] = SCDB_DOWNVOTE;
        }
        else {
            // Upvote index
            uint16_t n = bytes[i] | bytes[i + 1] << 8;

            if (n >= vOldScores[nScoreIndex].size()) {
                LogPrintf("SCDB %s: Error: invalid upvote index - too large!\n", __func__);
                return false;
            }

            // Lookup withdrawal bundle hash and add to votes
            vVote[nSidechain] = vOldScores[nScoreIndex][n].hash.ToString();
        }

        nScoreIndex++;
    }

    return true;
}
