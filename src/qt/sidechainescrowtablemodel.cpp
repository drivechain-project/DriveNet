#include <qt/sidechainescrowtablemodel.h>

#include <qt/guiconstants.h>

#include <base58.h>
#include <pubkey.h>
#include <random.h>
#include <sidechain.h>
#include <sidechaindb.h>
#include <validation.h>

#include <QIcon>
#include <QMetaType>
#include <QTimer>
#include <QVariant>

Q_DECLARE_METATYPE(SidechainEscrowTableObject)

SidechainEscrowTableModel::SidechainEscrowTableModel(QObject *parent) :
    QAbstractTableModel(parent)
{
    // This timer will be fired repeatedly to update the model
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(updateModel()));
    pollTimer->start(MODEL_UPDATE_DELAY);
}

int SidechainEscrowTableModel::rowCount(const QModelIndex & /*parent*/) const
{
    return model.size();
}

int SidechainEscrowTableModel::columnCount(const QModelIndex & /*parent*/) const
{
    return 5;
}

QVariant SidechainEscrowTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return false;
    }

    int col = index.column();
    int row = index.row();

    if (!model.at(row).canConvert<SidechainEscrowTableObject>())
        return QVariant();

    SidechainEscrowTableObject object = model.at(row).value<SidechainEscrowTableObject>();

    switch (role) {
    case Qt::DisplayRole:
    {
        // Escrow Number
        if (col == 0) {
            return object.nSidechain;
        }
        // Active
        if (col == 1) {
            return object.fActive;
        }
        // Escrow Name
        if (col == 2) {
            return object.name;
        }
        // CTIP - TxID
        if (col == 3) {
            return object.CTIPTxID;
        }
        // CTIP - Index
        if (col == 4) {
            return object.CTIPIndex;
        }
    }
    }
    return QVariant();
}

QVariant SidechainEscrowTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole) {
        if (orientation == Qt::Horizontal) {
            switch (section) {
            case 0:
                return QString("#");
            case 1:
                return QString("Active");
            case 2:
                return QString("Name");
            case 3:
                return QString("CTIP TxID");
            case 4:
                return QString("CTIP Index");
            }
        }
    }
    return QVariant();
}

void SidechainEscrowTableModel::updateModel()
{
    // Clear old data
    beginResetModel();
    model.clear();
    endResetModel();

    std::vector<Sidechain> vSidechain = scdb.GetActiveSidechains();

    int nSidechains = vSidechain.size();
    beginInsertRows(QModelIndex(), 0, nSidechains - 1);

    for (const Sidechain& s : vSidechain) {
        SidechainEscrowTableObject object;
        object.nSidechain = s.nSidechain;
        object.fActive = true; // TODO
        object.name = QString::fromStdString(s.GetSidechainName());

        // Get the sidechain CTIP info
        SidechainCTIP ctip;
        if (scdb.GetCTIP(s.nSidechain, ctip)) {
                object.CTIPIndex = QString::number(ctip.out.n);
                object.CTIPTxID = QString::fromStdString(ctip.out.hash.ToString());
        } else {
                object.CTIPIndex = "NA";
                object.CTIPTxID = "NA";
        }
        model.append(QVariant::fromValue(object));
    }

    endInsertRows();
}

void SidechainEscrowTableModel::AddDemoData()
{
    // Stop updating the model with real data
    pollTimer->stop();

    // Clear old data
    beginResetModel();
    model.clear();
    endResetModel();

    std::vector<Sidechain> vSidechain = scdb.GetActiveSidechains();

    int nSidechains = vSidechain.size();
    beginInsertRows(QModelIndex(), 0, nSidechains - 1);

    for (const Sidechain& s : vSidechain) {
        SidechainEscrowTableObject object;
        object.nSidechain = s.nSidechain;
        object.fActive = true; // TODO
        object.name = QString::fromStdString(s.GetSidechainName());

        // Add demo CTIP data
        object.CTIPIndex = QString::number(s.nSidechain % 2 == 0 ? 0 : 1);
        object.CTIPTxID = QString::fromStdString(GetRandHash().ToString());

        model.append(QVariant::fromValue(object));
    }

    endInsertRows();
}

void SidechainEscrowTableModel::ClearDemoData()
{
    // Clear demo data
    beginResetModel();
    model.clear();
    endResetModel();

    // Start updating the model with real data again
    pollTimer->start();
}
