// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/sidechainproposaldialog.h>
#include <qt/forms/ui_sidechainproposaldialog.h>

#include <qt/platformstyle.h>

#include <QMessageBox>

#include <base58.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <key.h>
#include <sidechain.h>
#include <sidechaindb.h>
#include <util.h>
#include <utilstrencodings.h>
#include <validation.h>

SidechainProposalDialog::SidechainProposalDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SidechainProposalDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    ui->toolButtonHelp->setIcon(platformStyle->SingleColorIcon(":/icons/transaction_0"));
    ui->pushButtonCreate->setIcon(platformStyle->SingleColorIcon(":/icons/transaction_confirmed"));
}

SidechainProposalDialog::~SidechainProposalDialog()
{
    delete ui;
}

void SidechainProposalDialog::on_toolButtonHelp_clicked()
{
    QMessageBox::information(this, tr("Drivechain - information"),
        tr("These fields are optional but highly recommended.\n\n"
           "Description:\n"
           "Brief description of the sidechain's purpose and where to find more information.\n\n"
           "Release tarball hash:\n"
           "hash of the original gitian software build of this sidechain.\n"
           "Use the sha256sum utility to generate this hash, or copy the hash "
           "when it is printed to the console after gitian builds complete.\n\n"
           "Example:\n"
           "sha256sum Drivechain-12-0.21.00-x86_64-linux-gnu.tar.gz\n\n"
           "Result:\n"
           "fd9637e427f1e967cc658bfe1a836d537346ce3a6dd0746878129bb5bc646680  Drivechain-12-0.21.00-x86_64-linux-gnu.tar.gz\n\n"
           "Build commit hash (160 bits):\n"
           "If the software was developed using git, the build commit hash "
           "should match the commit hash of the first sidechain release.\n"
           "To verify it later, you can look up this commit in the repository "
           "history.\n\n"
           "These help users find the sidechain full node software. "
           "Only this software can filter out invalid withdrawals."),
        QMessageBox::Ok);
}

void SidechainProposalDialog::on_pushButtonCreate_clicked()
{
    std::string strTitle = ui->lineEditTitle->text().toStdString();
    std::string strDescription = ui->plainTextEditDescription->toPlainText().toStdString();
    std::string strHashID1 = ui->lineEditIDHash1->text().toStdString();
    std::string strHashID2 = ui->lineEditIDHash2->text().toStdString();
    int nVersion = ui->spinBoxVersion->value();
    int nSidechain = ui->lineEditNumber->text().toInt();

    if (nSidechain < 0 || nSidechain > 255) {
        QMessageBox::critical(this, tr("Drivechain - error"),
            tr("Sidechain number must be 0-255!"),
            QMessageBox::Ok);
        return;
    }

    // TODO also check if sidechain number is the same as an existing proposal

    // Check if this sidechain number is already being used and warn them.
    if (scdb.IsSidechainActive(nSidechain)) {
        QString warning = "The sidechain number you have chosen is already in use!\n\n";
        warning += "This would create a sidechain replacement proposal which ";
        warning += "is much slower to activate than a new sidechain.\n\n";
        warning += "Are you sure?\n";
        int nRes = QMessageBox::critical(this, tr("Drivechain - warning"),
            warning,
            QMessageBox::Ok, QMessageBox::Cancel);

        if (nRes == QMessageBox::Cancel)
            return;
    }

    if (strTitle.empty()) {
        QMessageBox::critical(this, tr("Drivechain - error"),
            tr("Sidechain must have a title!"),
            QMessageBox::Ok);
        return;
    }

    if (nVersion > SIDECHAIN_VERSION_MAX) {
        QMessageBox::critical(this, tr("Drivechain - error"),
            tr("This sidechain has an invalid version number (too high)!"),
            QMessageBox::Ok);
        return;
    }

    const uint8_t nSC = nSidechain;
    const unsigned char vchSC[1] = { nSC };

    std::vector<unsigned char> vch256;
    vch256.resize(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(&vchSC[0], 1).Finalize(&vch256[0]);

    CKey key;
    key.Set(vch256.begin(), vch256.end(), false);

    CBitcoinSecret vchSecret(key);

    if (!key.IsValid()) {
        QMessageBox::critical(this, tr("Drivechain - error"),
            tr("Private key outside allowed range!"),
            QMessageBox::Ok);
        return;
    }

    CPubKey pubkey = key.GetPubKey();
    if (!key.VerifyPubKey(pubkey)) {
        QMessageBox::critical(this, tr("Drivechain - error"),
            tr("Failed to verify pubkey!"),
            QMessageBox::Ok);
        return;
    }
    CKeyID vchAddress = pubkey.GetID();

    if (!strHashID1.empty() && strHashID1.size() != 64) {
        QMessageBox::critical(this, tr("Drivechain - error"),
            tr("HashID1 (release tarball hash) invalid size!"),
            QMessageBox::Ok);
        return;
    }
    if (!strHashID2.empty() && strHashID2.size() != 40) {
        QMessageBox::critical(this, tr("Drivechain - error"),
            tr("HashID2 (build commit hash) invalid size!"),
            QMessageBox::Ok);
        return;
    }

    // Generate deposit script
    CScript sidechainScript = CScript() << OP_DUP << OP_HASH160 << ToByteVector(vchAddress) << OP_EQUALVERIFY << OP_CHECKSIG;

    Sidechain proposal;
    proposal.nSidechain = nSidechain;
    proposal.title = strTitle;
    proposal.description = strDescription;
    if (!strHashID1.empty())
        proposal.hashID1 = uint256S(strHashID1);
    if (!strHashID1.empty())
        proposal.hashID2 = uint160S(strHashID2);
    proposal.nVersion = nVersion;

    // Cache proposal so that it can be added to the next block we mine
    scdb.CacheSidechainProposals(std::vector<Sidechain>{proposal});

    // Cache sidechain hash to ACK it
    scdb.CacheSidechainHashToAck(proposal.GetSerHash());

    QString message = QString("Sidechain proposal created!\n\n");
    message += QString("Sidechain Number:\n%1\n\n").arg(nSidechain);
    message += QString("Version:\n%1\n\n").arg(nVersion);
    message += QString("Title:\n%1\n\n").arg(QString::fromStdString(strTitle));
    message += QString("Description:\n%1\n\n").arg(QString::fromStdString(strDescription));
    if (!strHashID1.empty())
        message += QString("Hash ID 1:\n%1\n\n").arg(QString::fromStdString(strHashID1));
    if (!strHashID2.empty())
        message += QString("Hash ID 2:\n%1\n\n").arg(QString::fromStdString(strHashID2));

    message += "Note: you can use the RPC command 'listsidechainproposals' to" \
    " view your pending sidechain proposals or 'listactivesidechains' to view" \
    " active sidechains.\n";

    // Show result message popup
    QMessageBox::information(this, tr("Drivechain - sidechain proposal created!"),
        message,
        QMessageBox::Ok);

    ui->lineEditTitle->clear();
    ui->plainTextEditDescription->clear();
    ui->lineEditIDHash1->clear();
    ui->lineEditIDHash2->clear();
    ui->spinBoxVersion->setValue(0);
}
