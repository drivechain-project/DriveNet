// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/sidechaindetailsdialog.h>
#include <qt/forms/ui_sidechaindetailsdialog.h>

#include <sidechain.h>

SidechainDetailsDialog::SidechainDetailsDialog(const Sidechain& sidechain, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SidechainDetailsDialog)
{
    ui->setupUi(this);

    ui->labelVersion->setText(QString::number(sidechain.nVersion));
    ui->labelNumber->setText(QString::number(sidechain.nSidechain));
    ui->labelTitle->setText(QString::fromStdString(sidechain.title));
    ui->labelDescription->setText(QString::fromStdString(sidechain.description));
    ui->labelID1->setText(QString::fromStdString(sidechain.hashID1.ToString()));
    ui->labelID2->setText(QString::fromStdString(sidechain.hashID2.ToString()));
    ui->labelLDBID->setText(QString::fromStdString(sidechain.GetSerHash().ToString()));
}

SidechainDetailsDialog::~SidechainDetailsDialog()
{
    delete ui;
}
