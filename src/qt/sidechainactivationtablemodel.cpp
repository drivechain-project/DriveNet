#include <qt/sidechainactivationtablemodel.h>

#include <sidechain.h>
#include <sidechaindb.h>
#include <util.h>
#include <validation.h>

#include <QIcon>
#include <QMetaType>
#include <QPushButton>
#include <QTimer>
#include <QVariant>

#include <qt/guiconstants.h>
#include <qt/guiutil.h>

Q_DECLARE_METATYPE(SidechainActivationTableObject)

SidechainActivationTableModel::SidechainActivationTableModel(QObject *parent) :
    QAbstractTableModel(parent)
{
    // TODO update only when block connected or sidechain votes changed.

    // This timer will be fired repeatedly to update the model
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(updateModel()));
    pollTimer->start(MODEL_UPDATE_DELAY);
}

int SidechainActivationTableModel::rowCount(const QModelIndex & /*parent*/) const
{
    return model.size();
}

int SidechainActivationTableModel::columnCount(const QModelIndex & /*parent*/) const
{
    return 8;
}

QVariant SidechainActivationTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return false;
    }

    int row = index.row();
    int col = index.column();

    if (!model.at(row).canConvert<SidechainActivationTableObject>())
        return QVariant();

    SidechainActivationTableObject object = model.at(row).value<SidechainActivationTableObject>();

    switch (role) {
    case Qt::DisplayRole:
    {
        // Vote / activation choice
        if (col == 0) {
            return (object.fAck ? "ACK" : "NACK");
        }
        // Sidechain slot number
        if (col == 1) {
            return QString::number(object.nSidechain);
        }
        // Replacement?
        if (col == 2) {
            return object.fReplacement;
        }
        // Sidechain title
        if (col == 3) {
            return object.title;
        }
        // Description
        if (col == 4) {
            return object.description;
        }
        // TODO show replacement period if replacing
        // Age
        if (col == 5) {
            QString str = QString("%1 / %2")
                    .arg(object.nAge)
                    .arg(object.fReplacement ? SIDECHAIN_REPLACEMENT_PERIOD : SIDECHAIN_ACTIVATION_PERIOD);
            return str;
        }
        // Fails
        if (col == 6) {
            QString str = QString("%1 / %2")
                    .arg(object.nFail)
                    .arg(SIDECHAIN_ACTIVATION_MAX_FAILURES);
            return str;
        }
        if (col == 7) {
            return object.hash;
        }
    }
    }
    return QVariant();
}

QVariant SidechainActivationTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole) {
        if (orientation == Qt::Horizontal) {
            switch (section) {
            case 0:
                return QString("Vote");
            case 1:
                return QString("SC #");
            case 2:
                return QString("Replacement");
            case 3:
                return QString("Title");
            case 4:
                return QString("Description");
            case 5:
                return QString("Age");
            case 6:
                return QString("Fails");
            case 7:
                return QString("Hash");
            }
        }
    }
    return QVariant();
}

void SidechainActivationTableModel::updateModel()
{
    // TODO there are many ways to improve the efficiency of this

    std::vector<SidechainActivationStatus> vActivationStatus;
    vActivationStatus = scdb.GetSidechainActivationStatus();

    // Look for updates to sidechain activation status which is already
    // cached by the model and update our model / view.
    //
    // Also look for sidechains which have been removed from the pending list,
    // and remove them from our model / view.
    std::vector<SidechainActivationTableObject> vRemoved;
    for (int i = 0; i < model.size(); i++) {
        if (!model[i].canConvert<SidechainActivationTableObject>())
            return;

        SidechainActivationTableObject object = model[i].value<SidechainActivationTableObject>();

        bool fFound = false;

        // We have an update
        for (const SidechainActivationStatus& s : vActivationStatus) {
            if (s.proposal.GetSerHash() == uint256S(object.hash.toStdString())) {
                // Update nAge
                object.nAge = s.nAge;
                // Update nFail
                object.nFail = s.nFail;
                // Update fAck
                object.fAck = scdb.GetAckSidechain(s.proposal.GetSerHash());
                // Update replacement status
                object.fReplacement = scdb.IsSidechainActive(s.proposal.nSidechain);

                // Emit signal that model data has changed
                QModelIndex topLeft = index(i, 0);
                QModelIndex topRight = index(i, columnCount() - 1);
                Q_EMIT QAbstractItemModel::dataChanged(topLeft, topRight, {Qt::DecorationRole});

                model[i] = QVariant::fromValue(object);

                fFound = true;
            }
        }

        // Add to vector of sidechains to be removed from model / view
        if (!fFound) {
            vRemoved.push_back(object);
        }
    }

    // Loop through the model and remove expired sidechains
    for (int i = 0; i < model.size(); i++) {
        if (!model[i].canConvert<SidechainActivationTableObject>())
            return;

        SidechainActivationTableObject object = model[i].value<SidechainActivationTableObject>();

        for (const SidechainActivationTableObject& s : vRemoved) {
            if (s.hash == object.hash) {
                beginRemoveRows(QModelIndex(), i, i);
                model[i] = model.back();
                model.pop_back();
                endRemoveRows();
            }
        }
    }

    // Check if any new sidechains have been added to the pending list,
    // collect them into a vector.
    std::vector<SidechainActivationStatus> vNew;
    for (const SidechainActivationStatus& s : vActivationStatus) {
        bool fFound = false;

        for (const QVariant& v : model) {
            if (!v.canConvert<SidechainActivationTableObject>())
                return;
            SidechainActivationTableObject object = v.value<SidechainActivationTableObject>();

            if (s.proposal.GetSerHash() == uint256S(object.hash.toStdString()))
                fFound = true;
        }

        if (!fFound)
            vNew.push_back(s);
    }

    size_t nSidechains = vNew.size();
    if (vNew.empty())
        return;

    // Add new sidechains if we need to
    beginInsertRows(QModelIndex(), model.size(), model.size() + nSidechains - 1);
    for (const SidechainActivationStatus& s : vNew) {
        SidechainActivationTableObject object;

        object.fAck = scdb.GetAckSidechain(s.proposal.GetSerHash());
        object.nSidechain = s.proposal.nSidechain;
        object.fReplacement = scdb.IsSidechainActive(s.proposal.nSidechain);
        object.title = QString::fromStdString(s.proposal.title);
        object.description = QString::fromStdString(s.proposal.description);
        object.nAge = s.nAge;
        object.nFail = s.nFail;
        object.hash = QString::fromStdString(s.proposal.GetSerHash().ToString());

        model.append(QVariant::fromValue(object));
    }
    endInsertRows();
}

bool SidechainActivationTableModel::GetHashAtRow(int row, uint256& hash) const
{
    if (row >= model.size())
        return false;

    if (!model[row].canConvert<SidechainActivationTableObject>())
        return false;

    SidechainActivationTableObject object = model[row].value<SidechainActivationTableObject>();

    hash = uint256S(object.hash.toStdString());

    return true;
}
