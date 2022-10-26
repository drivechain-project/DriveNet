// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "miner.h"
#include "random.h"
#include "script/script.h"
#include "script/standard.h"
#include "script/sigcache.h"
#include "sidechain.h"
#include "sidechaindb.h"
#include "uint256.h"
#include "utilstrencodings.h"
#include "validation.h"

#include "test/test_drivechain.h"

#include <boost/test/unit_test.hpp>

CScript EncodeWithdrawalFees(const CAmount& amount)
{
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << amount;

    CScript script;
    script << OP_RETURN;
    script << std::vector<unsigned char>(s.begin(), s.end());

    return script;
}

BOOST_FIXTURE_TEST_SUITE(sidechaindb_tests, TestingSetup)

bool ActivateTestSidechain(SidechainDB& scdbTest, int nHeight = 0)
{
    // Activate a test sidechain as sidechain #0

    Sidechain proposal;
    proposal.nSidechain = 0;
    proposal.nVersion = 0;
    proposal.title = "Test";
    proposal.description = "Description";
    proposal.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    return ActivateSidechain(scdbTest, proposal, nHeight);
}

BOOST_AUTO_TEST_CASE(sidechaindb_withdrawal)
{
    // Test creating a withdrawal and approving it with enough workscore
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    uint256 hash = GetRandHash();

    std::vector<std::string> vVote(SIDECHAIN_ACTIVATION_MAX_ACTIVE, std::string(1, SCDB_ABSTAIN));
    vVote[0] = hash.ToString();

    std::map<uint8_t, uint256> mapNewWithdrawal;
    mapNewWithdrawal[0] = hash;

    // Ack withdrawal bundle
    for (int i = 0; i < SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE; i++) {
        if (i == 0)
            BOOST_CHECK(scdbTest.UpdateSCDBIndex(vVote, false, mapNewWithdrawal));
        else
            BOOST_CHECK(scdbTest.UpdateSCDBIndex(vVote));
    }

    // Withdrawal should pass with valid workscore
    BOOST_CHECK(scdbTest.CheckWorkScore(0, hash));
}

BOOST_AUTO_TEST_CASE(sidechaindb_mutli_withdraw_one_expires)
{
    // Let one withdrawal expire and then make another pay out

    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    uint256 hash = GetRandHash();

    std::vector<std::string> vVote(SIDECHAIN_ACTIVATION_MAX_ACTIVE, std::string(1, SCDB_ABSTAIN));

    std::map<uint8_t, uint256> mapNewWithdrawal;
    mapNewWithdrawal[0] = hash;

    // Expire withdrawal bundle
    for (int i = 0; i < SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD; i++) {
        if (i == 0)
            BOOST_CHECK(scdbTest.UpdateSCDBIndex(vVote, false, mapNewWithdrawal));
        else
            BOOST_CHECK(scdbTest.UpdateSCDBIndex(vVote));
    }

    // Verify withdrawal expired
    std::vector<SidechainWithdrawalState> vState = scdbTest.GetState(0);
    BOOST_CHECK(vState.size() == 0);

    // Withdrawal for second period
    hash = GetRandHash();
    mapNewWithdrawal[0] = hash;

    // Give second transaction sufficient workscore and check work score
    vVote[0] = hash.ToString();
    for (int i = 0; i < SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE; i++) {
        if (i == 0)
            BOOST_CHECK(scdbTest.UpdateSCDBIndex(vVote, false, mapNewWithdrawal));
        else
            BOOST_CHECK(scdbTest.UpdateSCDBIndex(vVote));
    }
    BOOST_CHECK(scdbTest.CheckWorkScore(0, hash));
}

BOOST_AUTO_TEST_CASE(sidechaindb_wallet_ctip_create)
{
    // Create a deposit (and CTIP) for a single sidechain
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();

    CKey key;
    CPubKey pubkey;

    key.MakeNewKey(true);
    pubkey = key.GetPubKey();

    // User deposit data script
    CScript dataScript = CScript() << OP_RETURN << ToByteVector(pubkey.GetID());

    mtx.vout.push_back(CTxOut(CAmount(0), dataScript));

    CScript sidechainScript;
    BOOST_CHECK(scdbTest.GetSidechainScript(0, sidechainScript));

    // Add deposit output
    mtx.vout.push_back(CTxOut(50 * CENT, sidechainScript));

    SidechainDeposit deposit;
    deposit.nSidechain = 0;
    deposit.strDest = "";
    deposit.tx = mtx;
    deposit.nBurnIndex = 1;
    deposit.nTx = 1;
    deposit.hashBlock = GetRandHash();

    scdbTest.AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // Check if deposit was cached
    std::vector<SidechainDeposit> vDeposit = scdbTest.GetDeposits(0);
    BOOST_CHECK(vDeposit.size() == 1 && vDeposit.front() == deposit);

    // Check if CTIP was updated
    SidechainCTIP ctip;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctip));
    BOOST_CHECK(ctip.out.hash == deposit.tx.GetHash());
    BOOST_CHECK(ctip.out.n == 1);
}

BOOST_AUTO_TEST_CASE(sidechaindb_wallet_ctip_multi_sidechain)
{
    // Create a deposit (and CTIP) for multiple sidechains
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);
}

BOOST_AUTO_TEST_CASE(sidechaindb_wallet_ctip_multi_deposits)
{
    // Create many deposits and make sure that single valid CTIP results
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // TODO use the wallet function
    // Create deposit
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();

    CKey key;
    CPubKey pubkey;

    key.MakeNewKey(true);
    pubkey = key.GetPubKey();

    // User deposit data script
    CScript dataScript = CScript() << OP_RETURN << ToByteVector(pubkey.GetID());

    mtx.vout.push_back(CTxOut(CAmount(0), dataScript));

    Sidechain sidechain;
    BOOST_CHECK(scdbTest.GetSidechain(0, sidechain));

    CScript sidechainScript;
    BOOST_CHECK(scdbTest.GetSidechainScript(0, sidechainScript));

    // Add deposit output
    mtx.vout.push_back(CTxOut(50 * CENT, sidechainScript));

    SidechainDeposit deposit;
    deposit.nSidechain = 0;
    deposit.strDest = "";
    deposit.tx = mtx;
    deposit.nBurnIndex = 1;
    deposit.nTx = 1;

    scdbTest.AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // Check if we cached it
    std::vector<SidechainDeposit> vDeposit = scdbTest.GetDeposits(0);
    BOOST_CHECK(vDeposit.size() == 1 && vDeposit.front().tx == mtx);

    // Compare with scdbTest CTIP
    SidechainCTIP ctip;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctip));
    BOOST_CHECK(ctip.out.hash == mtx.GetHash());
    BOOST_CHECK(ctip.out.n == 1);

    // Create another deposit
    CMutableTransaction mtx2;
    mtx2.vin.resize(1);
    mtx2.vin[0].prevout.SetNull();

    CKey key2;
    CPubKey pubkey2;

    key2.MakeNewKey(true);
    pubkey2 = key2.GetPubKey();

    // User deposit data script
    CScript dataScript2 = CScript() << OP_RETURN << ToByteVector(pubkey2.GetID());

    mtx2.vout.push_back(CTxOut(CAmount(0), dataScript2));

    // Add deposit output
    mtx2.vout.push_back(CTxOut(25 * CENT, sidechainScript));

    deposit.tx = mtx2;

    scdbTest.AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // Check if we cached it
    vDeposit.clear();
    vDeposit = scdbTest.GetDeposits(0);
    BOOST_CHECK(vDeposit.size() == 2 && vDeposit.back().tx == mtx2);

    // Compare with scdbTest CTIP
    SidechainCTIP ctip2;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctip2));
    BOOST_CHECK(ctip2.out.hash == mtx2.GetHash());
    BOOST_CHECK(ctip2.out.n == 1);
}

BOOST_AUTO_TEST_CASE(sidechaindb_wallet_ctip_spend_withdrawal)
{
    // Create deposit / CTIP for sidechain then withdraw and deposit again.

    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // TODO use the wallet function
    // Create deposit
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();

    CKey key;
    CPubKey pubkey;

    key.MakeNewKey(true);
    pubkey = key.GetPubKey();

    // User deposit data script
    CScript dataScript = CScript() << OP_RETURN << ToByteVector(pubkey.GetID());

    mtx.vout.push_back(CTxOut(CAmount(0), dataScript));

    Sidechain sidechain;
    BOOST_CHECK(scdbTest.GetSidechain(0, sidechain));

    CScript sidechainScript;
    BOOST_CHECK(scdbTest.GetSidechainScript(0, sidechainScript));

    // Add deposit output
    mtx.vout.push_back(CTxOut(50 * CENT, sidechainScript));

    SidechainDeposit deposit;
    deposit.nSidechain = 0;
    deposit.strDest = "";
    deposit.tx = mtx;
    deposit.nBurnIndex = 1;
    deposit.nTx = 1;

    scdbTest.AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // Check if we cached it
    std::vector<SidechainDeposit> vDeposit = scdbTest.GetDeposits(0);
    BOOST_CHECK(vDeposit.size() == 1 && vDeposit.front().tx == mtx);

    // Compare with scdbTest CTIP
    SidechainCTIP ctip;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctip));
    BOOST_CHECK(ctip.out.hash == mtx.GetHash());
    BOOST_CHECK(ctip.out.n == 1);

    // Create a withdrawal that spends the CTIP
    CMutableTransaction wmtx;
    wmtx.nVersion = 2;
    wmtx.vin.push_back(CTxIn(ctip.out.hash, ctip.out.n));
    wmtx.vout.push_back(CTxOut(CAmount(0), CScript() << OP_RETURN << ParseHex(HexStr(SIDECHAIN_WITHDRAWAL_RETURN_DEST) )));
    wmtx.vout.push_back(CTxOut(CAmount(0), EncodeWithdrawalFees(1 * CENT)));
    wmtx.vout.push_back(CTxOut(25 * CENT, GetScriptForDestination(pubkey.GetID())));
    wmtx.vout.push_back(CTxOut(24 * CENT, sidechainScript));

    // Give it sufficient work score
    SidechainWithdrawalState state;
    uint256 hashBlind;
    BOOST_CHECK(CTransaction(wmtx).GetBlindHash(hashBlind));

    // Add withdrawal bundle
    scdbTest.AddWithdrawal(0, hashBlind, 0);

    // Check if withdrawal was added
    std::vector<SidechainWithdrawalState> vState = scdbTest.GetState(0);
    BOOST_CHECK(vState.size() == 1);

    // Create upvote vector
    std::vector<std::string> vVote(SIDECHAIN_ACTIVATION_MAX_ACTIVE, std::string(1, SCDB_ABSTAIN));
    vVote[0] = hashBlind.ToString();

    // Ack withdrawal bundle
    for (int i = 1; i < SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE; i++)
        BOOST_CHECK(scdbTest.UpdateSCDBIndex(vVote));

    // The withdrawal should have valid workscore
    BOOST_CHECK(scdbTest.CheckWorkScore(0, hashBlind));

    // Spend the withdrawal
    BOOST_CHECK(scdbTest.SpendWithdrawal(0, GetRandHash(), wmtx, 1));

    // Check that the CTIP has been updated to the change amount
    SidechainCTIP ctipFinal;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctipFinal));
    BOOST_CHECK(ctipFinal.out.hash == wmtx.GetHash());
    BOOST_CHECK(ctipFinal.out.n == 3);

    // Create another deposit
    CMutableTransaction mtx2;
    mtx2.vin.resize(1);
    mtx2.vin[0].prevout.SetNull();

    CKey key2;
    CPubKey pubkey2;

    key2.MakeNewKey(true);
    pubkey2 = key2.GetPubKey();

    // User deposit data script
    CScript dataScript2 = CScript() << OP_RETURN << ToByteVector(pubkey2.GetID());

    mtx2.vout.push_back(CTxOut(CAmount(0), dataScript2));

    // Add deposit output
    mtx2.vout.push_back(CTxOut(25 * CENT, sidechainScript));

    deposit.tx = mtx2;

    scdbTest.AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // Check if we cached it
    vDeposit.clear();
    vDeposit = scdbTest.GetDeposits(0);
    // Should now have 3 deposits cached (first deposit, withdrawal change,
    // this deposit)
    BOOST_CHECK(vDeposit.size() == 3 && vDeposit.back().tx == mtx2);

    // Compare with scdbTest CTIP
    SidechainCTIP ctip2;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctip2));
    BOOST_CHECK(ctip2.out.hash == mtx2.GetHash());
    BOOST_CHECK(ctip2.out.n == 1);
}

BOOST_AUTO_TEST_CASE(IsWithdrawalHashCommit)
{
    // TODO test invalid
    // Test hash commitments for nSidechain 0-255 with random withdrawal hashes
    for (unsigned int i = 0; i < 256; i++) {
        uint256 hash = GetRandHash();
        uint8_t nSidechain = i;

        CBlock block;
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout.SetNull();
        block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
        GenerateWithdrawalHashCommitment(block, hash, nSidechain);

        uint256 hashFromCommit;
        uint8_t nSidechainFromCommit;
        BOOST_CHECK(block.vtx[0]->vout[0].scriptPubKey.IsWithdrawalHashCommit(hashFromCommit, nSidechainFromCommit));

        BOOST_CHECK(hash == hashFromCommit);
        BOOST_CHECK(nSidechain == nSidechainFromCommit);
    }
}

BOOST_AUTO_TEST_CASE(IsSidechainProposalCommit)
{
    // TODO test more proposals with different data, versions etc
    // TODO test invalid

    // Create sidechain proposal
    Sidechain proposal;
    proposal.nVersion = 0;
    proposal.title = "Test";
    proposal.description = "Description";
    proposal.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Create transaction output with sidechain proposal
    CTxOut out;
    out.scriptPubKey = proposal.GetProposalScript();
    out.nValue = 50 * CENT;

    BOOST_CHECK(out.scriptPubKey.IsSidechainProposalCommit());
}

BOOST_AUTO_TEST_CASE(IsSidechainActivationCommit)
{
    // TODO test more proposals with different data, versions etc
    // TODO test invalid

    // Create sidechain proposal
    Sidechain proposal;
    proposal.nVersion = 0;
    proposal.title = "Test";
    proposal.description = "Description";
    proposal.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Use the function from validation to generate the commit, and then
    // copy it from the block.
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    GenerateSidechainActivationCommitment(block, proposal.GetSerHash());

    uint256 hashSidechain;
    BOOST_CHECK(block.vtx[0]->vout[0].scriptPubKey.IsSidechainActivationCommit(hashSidechain));

    BOOST_CHECK(hashSidechain == proposal.GetSerHash());
}

BOOST_AUTO_TEST_CASE(IsSidechainUpdateBytes)
{
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    CScript script;
    GenerateSCDBByteCommitment(block, script, std::vector<std::vector<SidechainWithdrawalState>>{}, std::vector<std::string>(256, std::string(1, SCDB_ABSTAIN)));

    BOOST_CHECK(block.vtx[0]->vout[0].scriptPubKey.IsSCDBBytes());
}

BOOST_AUTO_TEST_CASE(scdb_bytes_withdrawal_index)
{
    // Test SCDB m4 bytes with many withdrawal indexes.

    // Setup score state for 2 sidechains with 1 withdrawal bundle each

    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    CScript script;

    std::vector<std::vector<SidechainWithdrawalState>> vScores;
    vScores.resize(2);

    SidechainWithdrawalState wt;
    wt.nSidechain = 0;
    wt.hash = GetRandHash();
    wt.nBlocksLeft = 999;
    wt.nWorkScore = 1;
    vScores[0].push_back(wt);

    wt.nSidechain = 1;
    wt.hash = GetRandHash();
    vScores[1].push_back(wt);

    std::vector<std::string> vVote(SIDECHAIN_ACTIVATION_MAX_ACTIVE, std::string(1, SCDB_ABSTAIN));
    vVote[1] = wt.hash.ToString();

    BOOST_CHECK(GenerateSCDBByteCommitment(block, script, vScores, vVote));
    BOOST_CHECK(block.vtx[0]->vout[0].scriptPubKey.IsSCDBBytes());

    std::vector<std::string> vParsedVote;
    BOOST_CHECK(ParseSCDBBytes(script, vScores, vParsedVote));
    BOOST_CHECK(vVote == vParsedVote);

    // Now add more withdrawals and test SCDB byte parsing
    for (size_t i = 0; i < 257; i++) {
        wt.hash = GetRandHash();
        vScores[1].push_back(wt);

        vVote[1] = wt.hash.ToString();

        BOOST_CHECK(GenerateSCDBByteCommitment(block, script, vScores, vVote));
        BOOST_CHECK(block.vtx[0]->vout[0].scriptPubKey.IsSCDBBytes());

        BOOST_CHECK(ParseSCDBBytes(script, vScores, vParsedVote));
        BOOST_CHECK(vVote == vParsedVote);
    }
}

BOOST_AUTO_TEST_CASE(custom_vote_cache)
{
    SidechainDB scdbTest;
    std::vector<std::string> vVote;

    // Incorrect size of vote vector
    BOOST_CHECK(!scdbTest.CacheCustomVotes(vVote));

    // Empty votes
    vVote.resize(SIDECHAIN_ACTIVATION_MAX_ACTIVE);
    BOOST_CHECK(!scdbTest.CacheCustomVotes(vVote));

    // Empty vote
    vVote = std::vector<std::string>(SIDECHAIN_ACTIVATION_MAX_ACTIVE, std::string(1, SCDB_ABSTAIN));
    vVote[86] = "";
    BOOST_CHECK(!scdbTest.CacheCustomVotes(vVote));

    // Invalid vote size
    vVote[86] = std::string(86, '8');
    BOOST_CHECK(!scdbTest.CacheCustomVotes(vVote));

    // Invalid vote
    vVote[86] = "x";
    BOOST_CHECK(!scdbTest.CacheCustomVotes(vVote));

    // Valid votes
    vVote[86] = SCDB_ABSTAIN;
    BOOST_CHECK(scdbTest.CacheCustomVotes(vVote));
}

BOOST_AUTO_TEST_CASE(txn_to_deposit)
{
    // Test of the TxnToDeposit function. This is used by the memory pool and
    // connectBlock to easily decode a SidechainDeposit from a deposit transaction.

    // Activate test sidechain

    SidechainDB scdbTest;

    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);
    BOOST_CHECK(ActivateTestSidechain(scdbTest, 0));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // Serialized transaction
    std::string hex = "02000000024a22bbf6f5ed7e518c751e7d18f7aeb685bbe26922ca78654cbce473fd8aa281000000006b48304502210092f756349ff70ff95fcaef60dd1201f4e03e63e84ab597c3b51563df0d49e62e022040130f8028718c3d26abe0b09cc4d3b2a9b8165dfb3923ba4f8af0fc22ed550b012102307e4c1474628c242532f470ea8bb5ec22c097c3730bd20b789373d550b25af3ffffffff4a22bbf6f5ed7e518c751e7d18f7aeb685bbe26922ca78654cbce473fd8aa2810200000000ffffffff030050a9ab000000001976a914b57b307319a5e598ed104e533f98bac67e5d99da88ac0000000000000000096a077061747269636b00752b7d0000000002d10000000000";

    // Deserialize
    CMutableTransaction mtx;
    BOOST_CHECK(DecodeHexTx(mtx, hex));

    // TxnToDeposit
    SidechainDeposit deposit;
    BOOST_CHECK(scdbTest.TxnToDeposit(mtx, 0, {}, deposit));
}

BOOST_AUTO_TEST_SUITE_END()
