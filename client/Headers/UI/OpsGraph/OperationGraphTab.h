#ifndef ADAPTIXCLIENT_OPERATIONGRAPHTAB_H
#define ADAPTIXCLIENT_OPERATIONGRAPHTAB_H

#include <QHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QTextEdit>
#include <QWidget>

#include <kddockwidgets/qtwidgets/views/DockWidget.h>

class AuthProfile;
class GraphCanvas;
class QNetworkAccessManager;
class QTreeWidget;
class QTreeWidgetItem;
class QTimer;

class OperationGraphTab final : public QWidget
{
Q_OBJECT

public:
    explicit OperationGraphTab(AuthProfile* profile, QWidget* parent = nullptr);
    ~OperationGraphTab() override = default;

    KDDockWidgets::QtWidgets::DockWidget* dock() const { return dockWidget; }

    void loadInitialState();
    void applyDelta(const QJsonObject& delta);
    void setLiveMode(bool enabled);

private:
    AuthProfile* profile = nullptr;
    QNetworkAccessManager* network = nullptr;
    QTimer* refreshTimer = nullptr;
    KDDockWidgets::QtWidgets::DockWidget* dockWidget = nullptr;

    QLineEdit*   searchBar     = nullptr;
    QLabel*      liveIndicator = nullptr;
    QPushButton* focusButton   = nullptr;
    QPushButton* showAllButton = nullptr;
    QPushButton* tokenGroupsButton = nullptr;
    QPushButton* spnButton = nullptr;
    QPushButton* pathButton    = nullptr;
    QMenu* attackVectorsMenu = nullptr;
    QPushButton* clearButton   = nullptr;
    QPushButton* liveButton = nullptr;
    QPushButton* coreButton = nullptr;
    QPushButton* refreshButton = nullptr;
    QListWidget* filterList    = nullptr;
    QTreeWidget* entityTree = nullptr;
    GraphCanvas* canvas        = nullptr;
    QTextEdit*   detailsPanel  = nullptr;
    QPushButton* evidenceToggleButton = nullptr;

    bool liveMode = true;
    bool focusMode = false;
    bool coreMode = true;
    bool showTokenGroups = false;
    bool showSpnNodes = false;
    bool requestInFlight = false;
    qint64 cursor = 0;
    QString selectedNodeId;
    QString selectedEdgeId;
    QString focusedNodeId;
    QHash<QString, QJsonObject> nodeCache;
    QHash<QString, QJsonObject> edgeCache;
    bool hasLoadedState = false;
    QJsonArray cachedEvidence;
    QString cachedEvidenceText;
    int cachedEvidenceTextCount = 0;
    bool evidenceExpanded = false;
    QString evidenceBaseText;

    void buildUi();
    void applyState(const QJsonObject& state);
    void loadDeltaState();
    void redrawCanvasFromCache();
    bool shouldRenderNodeOnCanvas(const QJsonObject& node) const;
    void renderCoreViewFromCache();
    void renderFocusNeighborhoodFromCache(const QString& nodeId);
    void renderAclLensFromCache(const QString& nodeId);
    void renderAttackLensFromCache(const QString& nodeId);
    QString tokenGroupCategory(const QJsonObject& node) const;
    void clearGraphRemote();
    void rebuildGraphRemote();
    QString apiUrl(const QString& path) const;

private Q_SLOTS:
    void onSearchChanged(const QString& text);
    void onNodeSelected(const QString& nodeId, const QJsonObject& node);
    void onEdgeSelected(const QString& edgeId, const QJsonObject& edge);
    void onEntityTreeItemActivated(QTreeWidgetItem* item, int column);
    void onFocusSelected();
    void onCoreView();
    void onShowAllGraph();
    void onToggleTokenGroups();
    void onToggleSpnNodes();
    void onPathToHighValue();
    void onAttackLens();
    void onClearGraph();
    void onToggleLive();
    void onRefreshGraph();
    void onRefreshTimer();
    void onToggleEvidence();

private:
    void renderNodeDetails(const QJsonObject& node);
    void renderEdgeDetails(const QJsonObject& edge);
    void fetchNodeEvidence(const QString& nodeId);
    void fetchEdgeEvidence(const QString& edgeId);
    QString formatEvidenceDrawer(const QJsonArray& evidence) const;
    void rebuildEntityTree();
    void canonicalizeIdentityAliasesInCache();
    QString entityRootTitle(const QString& type) const;
    QString entityCategory(const QJsonObject& node) const;
    void renderEvidence(const QJsonArray& evidence);
    void updateEvidenceDisplay();
    void resetEvidenceDrawer();
    void captureInlineEvidenceDrawerFromPanel();
};

#endif
