#pragma once

#include <QWidget>
#include <QJsonObject>
#include <QJsonArray>

class QLineEdit;
class QListWidget;
class QPushButton;
class QLabel;
class GraphCanvas;

class OperationGraphTab : public QWidget
{
    Q_OBJECT
public:
    explicit OperationGraphTab(QWidget* parent = nullptr);

public slots:
    void loadInitialState();
    void applyDelta(const QJsonObject& delta);
    void setLiveMode(bool enabled);

private slots:
    void onSearchChanged(const QString& text);
    void onNodeSelected(const QString& nodeId);
    void onPathToHighValue();

private:
    void buildUi();
    void renderNodeDetails(const QJsonObject& node);
    void renderEvidence(const QJsonArray& evidence);

    GraphCanvas* canvas = nullptr;
    QLineEdit* searchBar = nullptr;
    QListWidget* filterList = nullptr;
    QWidget* detailsPanel = nullptr;
    QLabel* liveIndicator = nullptr;
    QPushButton* pathButton = nullptr;
    bool liveMode = true;
    qint64 cursor = 0;
};
