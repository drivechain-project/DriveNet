// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CREATENEWSDIALOG_H
#define CREATENEWSDIALOG_H

#include <QDialog>

namespace Ui {
class CreateNewsDialog;
}

class CreateNewsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CreateNewsDialog(QWidget *parent = nullptr);
    ~CreateNewsDialog();

private Q_SLOTS:
    void on_pushButtonCreate_clicked();

private:
    Ui::CreateNewsDialog *ui;
};

#endif // CREATENEWSDIALOG_H
