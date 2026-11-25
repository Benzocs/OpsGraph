#include <functional>
#include <QMenu>
#include <QStringList>
#include <QSignalBlocker>
#include <QTreeWidgetItem>
#include <QTreeWidget>
#include <UI/OpsGraph/OperationGraphTab.h>
#include <UI/OpsGraph/GraphCanvas.h>

#include <Client/AuthProfile.h>

#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSslError>
#include <QSplitter>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <algorithm>
#include <QSet>
#include <QDateTime>

#include <QScrollBar>
static bool opsGraphIsLowSignalWindowsGroup(const QJsonObject& node)
{
    if (node.value("type").toString() != "Group")
        return false;

    const QString id = node.value("id").toString().toLower();
    const QString label = node.value("label").toString().toLower();
    const QJsonObject props = node.value("properties").toObject();

    const QString scope = props.value("scope").toString().toLower();
    const QString domain = props.value("domain").toString().toLower();
    const QString name = props.value("name").toString().toLower();
    const QString sid = props.value("sid").toString().toLower();

    if (scope == "local" || scope == "well_known" || scope == "integrity_label")
        return true;

    if (domain == "builtin" || domain == "nt authority" || domain == "mandatory label")
        return true;

    if (label.startsWith("builtin\\") ||
        label.startsWith("nt authority\\") ||
        label.startsWith("mandatory label\\") ||
        label == "everyone" ||
        label == "local" ||
        label == "console logon" ||
        label.endsWith("\\none"))
        return true;

    if (name == "everyone" ||
        name == "local" ||
        name == "console logon" ||
        name == "none")
        return true;

    // Well-known / local / integrity SID ranges.
    if (sid.startsWith("s-1-1-") ||      // Everyone
        sid.startsWith("s-1-2-") ||      // Local / Console Logon family
        sid.startsWith("s-1-5-32-") ||   // BUILTIN groups
        sid.startsWith("s-1-5-4") ||     // Interactive
        sid.startsWith("s-1-5-11") ||    // Authenticated Users
        sid.startsWith("s-1-16-"))       // Mandatory integrity labels
        return true;

    if (id.contains(":builtin:") ||
        id.contains(":nt authority:") ||
        id.contains(":mandatory label:") ||
        id.contains(":everyone") ||
        id.contains(":console logon") ||
        id.contains(":local") ||
        id.endsWith(":none"))
        return true;

    return false;
}

static QString opsGraphEdgeEndpoint(const QJsonObject& edge, const QStringList& keys)
{
    for (const QString& key : keys) {
        const QString value = edge.value(key).toString();
        if (!value.isEmpty())
            return value;
    }

    return QString();
}

static QString opsGraphEdgeSource(const QJsonObject& edge)
{
    return opsGraphEdgeEndpoint(edge, QStringList()
        << "source"
        << "source_id"
        << "src"
        << "from"
        << "from_id"
        << "source_node"
        << "source_node_id");
}

static QString opsGraphEdgeTarget(const QJsonObject& edge)
{
    return opsGraphEdgeEndpoint(edge, QStringList()
        << "target"
        << "target_id"
        << "dst"
        << "to"
        << "to_id"
        << "target_node"
        << "target_node_id");
}


OperationGraphTab::OperationGraphTab(AuthProfile* authProfile, QWidget* parent)
    : QWidget(parent), profile(authProfile)
{
    network = new QNetworkAccessManager(this);

    refreshTimer = new QTimer(this);
    refreshTimer->setInterval(3000);
    connect(refreshTimer, &QTimer::timeout, this, &OperationGraphTab::onRefreshTimer);
    refreshTimer->start();

    dockWidget = new KDDockWidgets::QtWidgets::DockWidget(
        "Operation Graph:Dock",
        KDDockWidgets::DockWidgetOption_None,
        KDDockWidgets::LayoutSaverOption::None
    );
    dockWidget->setTitle("Operation Graph");
    dockWidget->setWidget(this);

    buildUi();
}

void OperationGraphTab::buildUi()
{
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(4, 4, 4, 4);
    root->setSpacing(4);

    auto* top = new QHBoxLayout();
    searchBar = new QLineEdit(this);
    searchBar->setPlaceholderText("Search node, host, user, domain...");

    liveIndicator = new QLabel("LIVE", this);
    coreButton = new QPushButton("Core View", this);
    focusButton = new QPushButton("Focus Selected", this);
    showAllButton = new QPushButton("Show All", this);
    tokenGroupsButton = new QPushButton("Token Groups: Off", this);
    spnButton = new QPushButton("SPNs: Off", this);
    pathButton = new QPushButton("Attack Vectors ▾", this);
    clearButton = new QPushButton("Clear Graph", this);
    liveButton = new QPushButton("Live: On", this);
    refreshButton = new QPushButton("Refresh", this);

    // OPSGRAPH_ATTACK_VECTORS_DROPDOWN_V1_BEGIN
    // Keep the toolbar clean: attack-vector-oriented actions live under one menu.
    attackVectorsMenu = new QMenu(pathButton);
    attackVectorsMenu->addAction("Attack Lens", this, &OperationGraphTab::onAttackLens);
    attackVectorsMenu->addSeparator();
    attackVectorsMenu->addAction("ACL Path Lens", this, &OperationGraphTab::onPathToHighValue);
    attackVectorsMenu->addAction("Toggle SPNs", this, &OperationGraphTab::onToggleSpnNodes);
    pathButton->setMenu(attackVectorsMenu);
    // OPSGRAPH_ATTACK_VECTORS_DROPDOWN_V1_END

    top->addWidget(searchBar, 1);
    top->addWidget(liveIndicator);
    top->addWidget(coreButton);
    top->addWidget(focusButton);
    top->addWidget(showAllButton);
    top->addWidget(tokenGroupsButton);
    spnButton->setVisible(false);
    top->addWidget(pathButton);
    top->addWidget(clearButton);
    top->addWidget(liveButton);
    top->addWidget(refreshButton);
    auto* splitter = new QSplitter(Qt::Horizontal, this);

    filterList = new QListWidget(this);

    filterList->setVisible(false);

    entityTree = new QTreeWidget(this);

    entityTree->setHeaderHidden(true);

    entityTree->setAnimated(true);

    entityTree->setIndentation(14);

    entityTree->setMinimumWidth(180);
    filterList->addItems({
        "Agent",
        "Computer",
        "User",
        "Domain",
        "Credential",
        "Session",
        "Service",
        "Share",
        "Trust"
    });
    filterList->setMaximumWidth(180);

    canvas = new GraphCanvas(this);

    // OPSGRAPH_EVIDENCE_TOGGLE_V1_BEGIN
    auto* rightPane = new QWidget(this);
    auto* rightLayout = new QVBoxLayout(rightPane);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(4);

    evidenceToggleButton = new QPushButton("Evidence: Hidden (0) ▾", rightPane);
    evidenceToggleButton->setEnabled(false);
    evidenceToggleButton->setToolTip("Show or hide the evidence drawer for the selected node/edge.");

    detailsPanel = new QTextEdit(rightPane);
    detailsPanel->setReadOnly(true);
    detailsPanel->setPlaceholderText("Select a node or edge to inspect evidence.");

    rightLayout->addWidget(evidenceToggleButton);
    rightLayout->addWidget(detailsPanel, 1);

    rightPane->setMaximumWidth(390);
    // OPSGRAPH_EVIDENCE_TOGGLE_V1_END

    splitter->addWidget(entityTree);
    splitter->addWidget(canvas);
    splitter->addWidget(rightPane);
    splitter->setStretchFactor(1, 1);

    root->addLayout(top);
    root->addWidget(splitter, 1);

    connect(searchBar, &QLineEdit::textChanged, this, &OperationGraphTab::onSearchChanged);
    connect(canvas, &GraphCanvas::nodeSelected, this, &OperationGraphTab::onNodeSelected);
    connect(canvas, &GraphCanvas::edgeSelected, this, &OperationGraphTab::onEdgeSelected);
    connect(entityTree, &QTreeWidget::itemClicked, this, &OperationGraphTab::onEntityTreeItemActivated);
    connect(entityTree, &QTreeWidget::itemDoubleClicked, this, &OperationGraphTab::onEntityTreeItemActivated);
    connect(coreButton, &QPushButton::clicked, this, &OperationGraphTab::onCoreView);
    connect(focusButton, &QPushButton::clicked, this, &OperationGraphTab::onFocusSelected);
    connect(showAllButton, &QPushButton::clicked, this, &OperationGraphTab::onShowAllGraph);
    connect(tokenGroupsButton, &QPushButton::clicked, this, &OperationGraphTab::onToggleTokenGroups);
    connect(spnButton, &QPushButton::clicked, this, &OperationGraphTab::onToggleSpnNodes);
    // pathButton opens attackVectorsMenu.
    connect(clearButton, &QPushButton::clicked, this, &OperationGraphTab::onClearGraph);
    connect(liveButton, &QPushButton::clicked, this, &OperationGraphTab::onToggleLive);
    connect(refreshButton, &QPushButton::clicked, this, &OperationGraphTab::onRefreshGraph);
    connect(evidenceToggleButton, &QPushButton::clicked, this, &OperationGraphTab::onToggleEvidence);
}

QString OperationGraphTab::apiUrl(const QString& path) const
{
    if (!profile)
        return path;

    QString base = profile->GetURL();
    while (base.endsWith('/'))
        base.chop(1);

    return base + path;
}

void OperationGraphTab::loadInitialState()
{
    if (!profile || !network) {
        detailsPanel->setText("Operation Graph cannot load: missing auth profile.");
        return;
    }

    if (requestInFlight)
        return;

    requestInFlight = true;

    if (!hasLoadedState && selectedNodeId.isEmpty())
        detailsPanel->setText("Loading OpsGraph state...");

    QNetworkRequest request(QUrl(apiUrl("/opsgraph/state")));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", QByteArray("Bearer ") + profile->GetAccessToken().toUtf8());

    QNetworkReply* reply = network->get(request);

    connect(reply, &QNetworkReply::sslErrors, reply, [reply](const QList<QSslError>&) {
        reply->ignoreSslErrors();
    });

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const QByteArray body = reply->readAll();
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

        if (reply->error() != QNetworkReply::NoError) {
            detailsPanel->setText(QString("OpsGraph request failed [%1]:\n%2\n\n%3")
                .arg(status)
                .arg(reply->errorString())
                .arg(QString::fromUtf8(body)));
            requestInFlight = false;
            reply->deleteLater();
            return;
        }

        QJsonParseError parseError;
        const QJsonDocument doc = QJsonDocument::fromJson(body, &parseError);
        if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
            detailsPanel->setText("OpsGraph returned invalid JSON:\n\n" + QString::fromUtf8(body));
            requestInFlight = false;
            reply->deleteLater();
            return;
        }

        const QJsonObject root = doc.object();
        if (!root.value("ok").toBool(false)) {
            detailsPanel->setText("OpsGraph returned error:\n\n" + QString::fromUtf8(body));
            requestInFlight = false;
            reply->deleteLater();
            return;
        }

        applyState(root.value("state").toObject());
        requestInFlight = false;
        reply->deleteLater();
    });
}

void OperationGraphTab::loadDeltaState()
{
    if (!profile || !network) {
        detailsPanel->setText("Operation Graph cannot load delta: missing auth profile.");
        return;
    }

    if (!hasLoadedState || cursor <= 0) {
        loadInitialState();
        return;
    }

    if (requestInFlight)
        return;

    requestInFlight = true;

    const QString path = QString("/opsgraph/delta?since=%1").arg(cursor);
    QNetworkRequest request(QUrl(apiUrl(path)));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", QByteArray("Bearer ") + profile->GetAccessToken().toUtf8());

    QNetworkReply* reply = network->get(request);

    connect(reply, &QNetworkReply::sslErrors, reply, [reply](const QList<QSslError>&) {
        reply->ignoreSslErrors();
    });

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const QByteArray body = reply->readAll();
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

        if (reply->error() != QNetworkReply::NoError) {
            // Do not destroy the operator's current investigation panel unless
            // this is the first load. Delta failures should be non-disruptive.
            if (selectedNodeId.isEmpty() && selectedEdgeId.isEmpty()) {
                detailsPanel->setText(QString("OpsGraph delta request failed [%1]:\n%2\n\n%3")
                    .arg(status)
                    .arg(reply->errorString())
                    .arg(QString::fromUtf8(body)));
            }

            requestInFlight = false;
            reply->deleteLater();
            return;
        }

        QJsonParseError parseError;
        const QJsonDocument doc = QJsonDocument::fromJson(body, &parseError);
        if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
            if (selectedNodeId.isEmpty() && selectedEdgeId.isEmpty())
                detailsPanel->setText("OpsGraph delta returned invalid JSON:\n\n" + QString::fromUtf8(body));

            requestInFlight = false;
            reply->deleteLater();
            return;
        }

        const QJsonObject root = doc.object();
        if (!root.value("ok").toBool(false)) {
            if (selectedNodeId.isEmpty() && selectedEdgeId.isEmpty())
                detailsPanel->setText("OpsGraph delta returned error:\n\n" + QString::fromUtf8(body));

            requestInFlight = false;
            reply->deleteLater();
            return;
        }

        applyDelta(root.value("delta").toObject());

        requestInFlight = false;
        reply->deleteLater();
    });
}


void OperationGraphTab::applyState(const QJsonObject& state)
{
    cursor = state.value("cursor").toInteger(0);

    const QJsonArray nodes = state.value("nodes").toArray();
    const QJsonArray edges = state.value("edges").toArray();

    QSet<QString> hiddenNodeIds;

    // Keep full nodeCache for evidence/details/search decisions, but only render
    // high-signal nodes on the main canvas. This keeps Windows token artifacts
    // from polluting the operator graph.
    for (const QJsonValue& value : nodes) {
        if (!value.isObject())
            continue;

        const QJsonObject node = value.toObject();
        const QString id = node.value("id").toString();

        if (!id.isEmpty())
            nodeCache.insert(id, node);

        if (!showTokenGroups && opsGraphIsLowSignalWindowsGroup(node)) {
            if (!id.isEmpty())
                hiddenNodeIds.insert(id);
            continue;
        }

        canvas->upsertNode(node);
    }

    for (const QJsonValue& value : edges) {
        if (!value.isObject())
            continue;

        const QJsonObject edge = value.toObject();
        const QString edgeId = edge.value("id").toString();
        if (!edgeId.isEmpty())
            edgeCache.insert(edgeId, edge);

        const QString source = opsGraphEdgeSource(edge);
        const QString target = opsGraphEdgeTarget(edge);

        if (!showTokenGroups &&
            ((!source.isEmpty() && hiddenNodeIds.contains(source)) ||
             (!target.isEmpty() && hiddenNodeIds.contains(target))))
            continue;

        canvas->upsertEdge(edge);
    }

    canonicalizeIdentityAliasesInCache();
    rebuildEntityTree();
    // OPSGRAPH_TREE_SEARCH_PERSIST_V1
    // Entity tree is rebuilt after live delta, lens toggles, Core View, etc.
    // Preserve the active search filter instead of snapping the tree back to
    // the default unfiltered state.
    if (searchBar && !searchBar->text().trimmed().isEmpty())
        onSearchChanged(searchBar->text());

    if (focusMode && !focusedNodeId.isEmpty())
        renderFocusNeighborhoodFromCache(focusedNodeId);

    const bool firstLoad = !hasLoadedState;
    hasLoadedState = true;

    // Do not overwrite details while a node is selected.
    // The panel updates when the operator clicks a node, not on every poll.
    if (!selectedNodeId.isEmpty())
        return;

    if (firstLoad) {
        detailsPanel->setText(
            QString("OpsGraph loaded.\n\nNodes: %1\nEdges: %2\nCursor: %3")
                .arg(nodes.size())
                .arg(edges.size())
                .arg(cursor)
        );
    }


    if (coreMode)
        redrawCanvasFromCache();
}

void OperationGraphTab::applyDelta(const QJsonObject& delta)
{
    const qint64 nextCursor = delta.value("cursor").toInteger(
        delta.value("new_cursor").toInteger(cursor)
    );

    if (nextCursor > cursor)
        cursor = nextCursor;

    const QJsonArray nodes = delta.value("nodes").toArray();
    const QJsonArray edges = delta.value("edges").toArray();

    // OPSGRAPH_CORE_VIEW_LIVE_GUARD_V1_BEGIN
    // In scoped operator views, live polling should update the truth cache and
    // smart tree, but it must not expand the canvas like Show All mode.
    //
    // Core View = current operation context only.
    // Focused View = selected node neighborhood only.
    //
    // Without this guard, targeted enumeration can temporarily explode the graph
    // while the operator is working inside Core/Focused mode.
    const bool scopedCanvasMode = coreMode || (focusMode && !focusedNodeId.isEmpty());
    // OPSGRAPH_CORE_VIEW_LIVE_GUARD_V1_END

    QSet<QString> hiddenNodeIds;

    for (const QJsonValue& value : nodes) {
        if (!value.isObject())
            continue;

        const QJsonObject node = value.toObject();
        const QString id = node.value("id").toString();

        if (!id.isEmpty())
            nodeCache.insert(id, node);

        if (!showTokenGroups && opsGraphIsLowSignalWindowsGroup(node)) {
            if (!id.isEmpty())
                hiddenNodeIds.insert(id);
            continue;
        }

        if (!scopedCanvasMode)
            canvas->upsertNode(node);
    }

    for (const QJsonValue& value : edges) {
        if (!value.isObject())
            continue;

        const QJsonObject edge = value.toObject();
        const QString edgeId = edge.value("id").toString();
        if (!edgeId.isEmpty())
            edgeCache.insert(edgeId, edge);

        const QString source = opsGraphEdgeSource(edge);
        const QString target = opsGraphEdgeTarget(edge);

        const QJsonObject sourceNode = nodeCache.value(source);
        const QJsonObject targetNode = nodeCache.value(target);

        if (!showTokenGroups &&
            ((!source.isEmpty() && (hiddenNodeIds.contains(source) || opsGraphIsLowSignalWindowsGroup(sourceNode))) ||
             (!target.isEmpty() && (hiddenNodeIds.contains(target) || opsGraphIsLowSignalWindowsGroup(targetNode)))))
            continue;

        if (!scopedCanvasMode)
            canvas->upsertEdge(edge);
    }

    canonicalizeIdentityAliasesInCache();
    rebuildEntityTree();
    // OPSGRAPH_TREE_SEARCH_PERSIST_V1
    // Entity tree is rebuilt after live delta, lens toggles, Core View, etc.
    // Preserve the active search filter instead of snapping the tree back to
    // the default unfiltered state.
    if (searchBar && !searchBar->text().trimmed().isEmpty())
        onSearchChanged(searchBar->text());

    // OPSGRAPH_LIVE_DELTA_DETAILS_NO_SCROLL_RESET_V1_BEGIN
    // Live delta updates nodeCache/edgeCache and the Smart Tree, but it must not
    // re-render the details panel on every poll. QTextEdit::setText resets the
    // scrollbar to the top, which breaks operator review while reading evidence.
    //
    // Details are refreshed on explicit actions:
    // - selecting a node/edge
    // - toggling a lens
    // - pressing Refresh / Core / Focus / Show All / ACL Lens
    //
    // This preserves right-panel scroll position during live polling.
    // OPSGRAPH_LIVE_DELTA_DETAILS_NO_SCROLL_RESET_V1_END
}

void OperationGraphTab::setLiveMode(bool enabled)
{
    liveMode = enabled;
    liveIndicator->setText(liveMode ? "LIVE" : "PAUSED");
}

void OperationGraphTab::onSearchChanged(const QString& text)
{
    // OPSGRAPH_TREE_SEARCH_V1_BEGIN
    // Search should work across both the visible graph canvas and the left
    // entity tree. This matters in focused/lens views where many relevant
    // objects are stored in the tree/cache but intentionally not rendered on
    // the canvas.
    if (canvas)
        canvas->focusSearch(text);

    if (!entityTree)
        return;

    const QString query = text.trimmed().toLower();
    QTreeWidgetItem* firstMatch = nullptr;

    std::function<bool(QTreeWidgetItem*)> applyFilter = [&](QTreeWidgetItem* item) -> bool {
        if (!item)
            return false;

        bool selfMatches = query.isEmpty();

        if (!query.isEmpty()) {
            for (int col = 0; col < item->columnCount(); ++col) {
                if (item->text(col).toLower().contains(query)) {
                    selfMatches = true;
                    break;
                }
            }

            const QString nodeId = item->data(0, Qt::UserRole).toString();
            if (!selfMatches && !nodeId.isEmpty()) {
                if (nodeId.toLower().contains(query))
                    selfMatches = true;
                else if (nodeCache.contains(nodeId)) {
                    const QJsonObject node = nodeCache.value(nodeId);
                    const QJsonObject props = node.value("properties").toObject();

                    QString haystack;
                    haystack += node.value("id").toString() + "\n";
                    haystack += node.value("label").toString() + "\n";
                    haystack += node.value("normalized_name").toString() + "\n";
                    haystack += node.value("type").toString() + "\n";

                    const QStringList propKeys = {
                        "sam",
                        "name",
                        "cn",
                        "domain",
                        "dns_domain",
                        "dn",
                        "sid",
                        "spn",
                        "service_principal_names",
                        "attack_vector_ids",
                        "category",
                        "severity",
                        "vector_id",
                        "display_name"
                    };

                    for (const QString& key : propKeys) {
                        const QJsonValue v = props.value(key);

                        if (v.isString()) {
                            haystack += v.toString() + "\n";
                        } else if (v.isArray()) {
                            const QJsonArray arr = v.toArray();
                            for (const QJsonValue& av : arr)
                                haystack += av.toVariant().toString() + "\n";
                        }
                    }

                    if (haystack.toLower().contains(query))
                        selfMatches = true;
                }
            }
        }

        bool childMatches = false;

        for (int i = 0; i < item->childCount(); ++i) {
            if (applyFilter(item->child(i)))
                childMatches = true;
        }

        const bool visible = query.isEmpty() || selfMatches || childMatches;
        item->setHidden(!visible);

        if (!query.isEmpty() && childMatches)
            item->setExpanded(true);

        if (!query.isEmpty() && selfMatches && !firstMatch)
            firstMatch = item;

        return visible;
    };

    for (int i = 0; i < entityTree->topLevelItemCount(); ++i)
        applyFilter(entityTree->topLevelItem(i));

    if (query.isEmpty()) {
        entityTree->clearSelection();
        return;
    }

    if (firstMatch) {
        entityTree->setCurrentItem(firstMatch);
        firstMatch->setSelected(true);
        entityTree->scrollToItem(firstMatch, QAbstractItemView::PositionAtCenter);
    }
    // OPSGRAPH_TREE_SEARCH_V1_END
}

void OperationGraphTab::onNodeSelected(const QString& nodeId, const QJsonObject& node)
{
    selectedNodeId = nodeId;
    selectedEdgeId.clear();

    if (!node.isEmpty())
        nodeCache.insert(nodeId, node);

    renderNodeDetails(nodeCache.value(nodeId, node));
    fetchNodeEvidence(nodeId);
}

void OperationGraphTab::onEdgeSelected(const QString& edgeId, const QJsonObject& edge)
{
    selectedEdgeId = edgeId;
    selectedNodeId.clear();

    if (!edge.isEmpty())
        edgeCache.insert(edgeId, edge);

    renderEdgeDetails(edgeCache.value(edgeId, edge));
    fetchEdgeEvidence(edgeId);
}

void OperationGraphTab::onFocusSelected()
{
    QString nodeId = selectedNodeId;

    if (nodeId.isEmpty())
        nodeId = focusedNodeId;

    if (nodeId.isEmpty() || !nodeCache.contains(nodeId))
        return;

    selectedNodeId = nodeId;
    selectedEdgeId.clear();
    focusedNodeId = nodeId;

    focusMode = true;
    coreMode = false;

    const QJsonObject node = nodeCache.value(nodeId);
    const QString label = node.value("label").toString(nodeId);

    if (focusButton)
        focusButton->setText(QString("Focused: %1").arg(label));

    renderFocusNeighborhoodFromCache(nodeId);
    renderNodeDetails(node);
    fetchNodeEvidence(nodeId);
}




void OperationGraphTab::onCoreView()
{
    coreMode = true;
    focusMode = false;
    focusedNodeId.clear();

    if (canvas)
        canvas->clearFocusMode();

    redrawCanvasFromCache();
    rebuildEntityTree();
    // OPSGRAPH_TREE_SEARCH_PERSIST_V1
    // Entity tree is rebuilt after live delta, lens toggles, Core View, etc.
    // Preserve the active search filter instead of snapping the tree back to
    // the default unfiltered state.
    if (searchBar && !searchBar->text().trimmed().isEmpty())
        onSearchChanged(searchBar->text());
}

void OperationGraphTab::onShowAllGraph()
{
    coreMode = false;
    focusMode = false;
    focusedNodeId.clear();

    if (canvas)
        canvas->clearFocusMode();

    redrawCanvasFromCache();
    rebuildEntityTree();
    // OPSGRAPH_TREE_SEARCH_PERSIST_V1
    // Entity tree is rebuilt after live delta, lens toggles, Core View, etc.
    // Preserve the active search filter instead of snapping the tree back to
    // the default unfiltered state.
    if (searchBar && !searchBar->text().trimmed().isEmpty())
        onSearchChanged(searchBar->text());

    QString out;
    out += "Full graph overview\n";
    out += "===================\n\n";
    out += "Full graph mode is explicit because large AD graphs can become noisy.\n";
    out += "Use Core View to return to the current operation context.";
    detailsPanel->setText(out);
}



static bool opsGraphShouldHideTokenGroup(const QJsonObject& node);

bool OperationGraphTab::shouldRenderNodeOnCanvas(const QJsonObject& node) const
{

    // OPSGRAPH_TOKEN_GROUP_FILTER_NODE_GUARD_BEGIN
    if (!showTokenGroups) {
        const QString currentNodeId = node.value("id").toString();

        if (currentNodeId != focusedNodeId && opsGraphShouldHideTokenGroup(node))
            return false;
    }
    // OPSGRAPH_TOKEN_GROUP_FILTER_NODE_GUARD_END

    if (node.isEmpty())
        return false;

    const QString type = node.value("type").toString();

    if (type == "SPN" && !showSpnNodes)
        return false;

    if (!showTokenGroups && opsGraphIsLowSignalWindowsGroup(node))
        return false;

    return true;
}

// OPSGRAPH_TOKEN_GROUP_FILTER_HELPER_BEGIN
static bool opsGraphLooksLikeTokenOnlyGroupText(QString value)
{
    value = value.trimmed().toLower();

    if (value.isEmpty())
        return false;

    // Parser-side categories/scopes.
    if (value == "local" ||
        value == "well_known" ||
        value == "well-known" ||
        value == "well known" ||
        value == "integrity_label" ||
        value == "integrity-label" ||
        value == "integrity label")
        return true;

    if (value.contains("well_known") ||
        value.contains("well-known") ||
        value.contains("integrity_label") ||
        value.contains("integrity-label"))
        return true;

    // Classic token/local groups from whoami /all.
    if (value.startsWith("builtin\\") ||
        value.contains("\\builtin\\") ||
        value.startsWith("nt authority\\") ||
        value.contains("\\nt authority\\") ||
        value.startsWith("mandatory label\\") ||
        value.contains("\\mandatory label\\"))
        return true;

    // SID prefixes:
    // S-1-5-32-* = BUILTIN groups
    // S-1-16-*   = integrity labels
    if (value.startsWith("s-1-5-32-") ||
        value.contains(":s-1-5-32-") ||
        value.startsWith("s-1-16-") ||
        value.contains(":s-1-16-"))
        return true;

    // Common well-known token groups.
    if (value == "everyone" ||
        value == "authenticated users" ||
        value == "interactive" ||
        value == "console logon" ||
        value == "local account" ||
        value == "local account and member of administrators group" ||
        value == "this organization" ||
        value == "nt authority\\interactive" ||
        value == "nt authority\\authenticated users")
        return true;

    return false;
}

static bool opsGraphShouldHideTokenGroup(const QJsonObject& node)
{
    const QString type = node.value("type").toString();

    if (type.compare("Group", Qt::CaseInsensitive) != 0)
        return false;

    const QJsonObject props = node.value("properties").toObject();

    QStringList values;
    values << node.value("id").toString();
    values << node.value("label").toString();
    values << node.value("normalized").toString();

    const QStringList keys = {
        "scope",
        "group_scope",
        "groupScope",
        "category",
        "group_category",
        "groupCategory",
        "kind",
        "sid_type",
        "sidType",
        "sid",
        "objectSid",
        "name",
        "sam",
        "sAMAccountName",
        "domain"
    };

    for (const QString& key : keys) {
        if (props.contains(key))
            values << props.value(key).toString();
    }

    for (const QString& value : values) {
        if (opsGraphLooksLikeTokenOnlyGroupText(value))
            return true;
    }

    return false;
}
// OPSGRAPH_TOKEN_GROUP_FILTER_HELPER_END

void OperationGraphTab::renderFocusNeighborhoodFromCache(const QString& nodeId)
{
    if (!canvas)
        return;

    if (nodeId.isEmpty() || !nodeCache.contains(nodeId))
        return;

    QSet<QString> visibleNodes;
    QSet<QString> visibleEdges;

    visibleNodes.insert(nodeId);

    auto edgeSource = [](const QJsonObject& edge) -> QString {
        return edge.value("source").toString();
    };

    auto edgeTarget = [](const QJsonObject& edge) -> QString {
        return edge.value("target").toString();
    };

    auto edgeType = [](const QJsonObject& edge) -> QString {
        return edge.value("type").toString();
    };

    auto nodeType = [](const QJsonObject& node) -> QString {
        return node.value("type").toString();
    };

    auto isHiddenTokenGroupNode = [&](const QString& id) -> bool {
        if (id == nodeId)
            return false;

        if (showTokenGroups)
            return false;

        if (!nodeCache.contains(id))
            return false;

        return opsGraphShouldHideTokenGroup(nodeCache.value(id));
    };

    // Selected node 1-hop neighborhood.
    // Important: Token Groups: Off bo'lsa local/builtin/well-known/integrity groups
    // edge orqali canvasga kirmasligi kerak.
    for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
        const QString edgeId = it.key();
        const QJsonObject edge = it.value();

        const QString src = edgeSource(edge);
        const QString dst = edgeTarget(edge);
        const QString type = edgeType(edge);

        if (!showSpnNodes && type == "HasSPN")
            continue;

        if (isHiddenTokenGroupNode(src) || isHiddenTokenGroupNode(dst))
            continue;

        if (src == nodeId || dst == nodeId) {
            visibleEdges.insert(edgeId);
            visibleNodes.insert(src);
            visibleNodes.insert(dst);
        }
    }

    // Domain context for visible nodes.
    bool changed = true;
    while (changed) {
        changed = false;

        for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
            const QString edgeId = it.key();
            const QJsonObject edge = it.value();

            const QString src = edgeSource(edge);
            const QString dst = edgeTarget(edge);
            const QString type = edgeType(edge);

            if (type != "InDomain")
                continue;

            if (isHiddenTokenGroupNode(src) || isHiddenTokenGroupNode(dst))
                continue;

            if (visibleNodes.contains(src) && !visibleNodes.contains(dst)) {
                visibleNodes.insert(dst);
                visibleEdges.insert(edgeId);
                changed = true;
            }
        }
    }

    canvas->clearGraph();

    // Add focus node first.
    canvas->upsertNode(nodeCache.value(nodeId));

    for (const QString& id : visibleNodes) {
        if (id == nodeId)
            continue;

        if (!nodeCache.contains(id))
            continue;

        const QJsonObject node = nodeCache.value(id);

        if (!showSpnNodes && nodeType(node).compare("SPN", Qt::CaseInsensitive) == 0)
            continue;

        if (!showTokenGroups && opsGraphShouldHideTokenGroup(node))
            continue;

        canvas->upsertNode(node);
    }

    for (const QString& id : visibleEdges) {
        if (!edgeCache.contains(id))
            continue;

        const QJsonObject edge = edgeCache.value(id);

        const QString src = edgeSource(edge);
        const QString dst = edgeTarget(edge);
        const QString type = edgeType(edge);

        if (!showSpnNodes && type == "HasSPN")
            continue;

        if (isHiddenTokenGroupNode(src) || isHiddenTokenGroupNode(dst))
            continue;

        if (!visibleNodes.contains(src) || !visibleNodes.contains(dst))
            continue;

        if (!nodeCache.contains(src) || !nodeCache.contains(dst))
            continue;

        canvas->upsertEdge(edge);
    }

    canvas->focusNode(nodeId);
}


// OPSGRAPH_RELEVANCE_ENGINE_V1_BEGIN
struct OpsGraphRelevanceResult
{
    int score = 0;
    QString visibility = "hidden_inventory";
    QStringList reasons;
    QStringList badges;
};

static QString opsGraphRelNormText(QString value)
{
    value = value.toLower();

    const QString separators = "\\/_-.()[]{}:;,";
    for (const QChar& c : separators)
        value.replace(c, ' ');

    return QString(" %1 ").arg(value.simplified());
}

static bool opsGraphRelHasToken(const QString& text, const QString& token)
{
    return opsGraphRelNormText(text).contains(QString(" %1 ").arg(token.toLower()));
}

static bool opsGraphRelHasAnyToken(const QString& text, const QStringList& tokens)
{
    for (const QString& token : tokens) {
        if (opsGraphRelHasToken(text, token))
            return true;
    }
    return false;
}

static QString opsGraphRelNodeText(const QJsonObject& node)
{
    const QJsonObject props = node.value("properties").toObject();

    QStringList parts;
    parts << node.value("id").toString();
    parts << node.value("label").toString();
    parts << node.value("normalized_name").toString();
    parts << props.value("name").toString();
    parts << props.value("sam").toString();
    parts << props.value("sAMAccountName").toString();
    parts << props.value("domain").toString();
    parts << props.value("distinguished_name").toString();
    parts << props.value("distinguishedName").toString();
    parts << props.value("description").toString();

    return parts.join(" ");
}

static QString opsGraphRelNodeLabel(const QString& id, const QHash<QString, QJsonObject>& nodeCache)
{
    if (!nodeCache.contains(id))
        return id;

    return nodeCache.value(id).value("label").toString(id);
}

static void opsGraphRelAdd(OpsGraphRelevanceResult& result, int score, const QString& reason, const QString& badge = QString())
{
    result.score += score;

    if (!reason.isEmpty() && !result.reasons.contains(reason))
        result.reasons << reason;

    if (!badge.isEmpty() && !result.badges.contains(badge))
        result.badges << badge;
}

static bool opsGraphRelBoolProp(const QJsonObject& node, const QString& key)
{
    const QJsonObject props = node.value("properties").toObject();

    if (props.contains(key)) {
        const QJsonValue v = props.value(key);
        if (v.isBool())
            return v.toBool();
        if (v.isDouble())
            return v.toInt() != 0;

        const QString s = v.toString().toLower();
        return s == "true" || s == "yes" || s == "1";
    }

    const QJsonObject exposure = props.value("exposure").toObject();
    if (exposure.contains(key)) {
        const QJsonValue v = exposure.value(key);
        if (v.isBool())
            return v.toBool();
        if (v.isDouble())
            return v.toInt() != 0;

        const QString s = v.toString().toLower();
        return s == "true" || s == "yes" || s == "1";
    }

    return false;
}

static QStringList opsGraphRelEdgeRights(const QJsonObject& edge)
{
    QStringList out;

    const QJsonObject props = edge.value("properties").toObject();
    const QJsonValue rightsValue = props.value("rights");

    if (rightsValue.isArray()) {
        const QJsonArray arr = rightsValue.toArray();
        for (const QJsonValue& v : arr) {
            const QString s = v.toString().trimmed();
            if (!s.isEmpty() && !out.contains(s))
                out << s;
        }
    } else if (rightsValue.isString()) {
        const QString raw = rightsValue.toString();
        for (const QString& part : raw.split(",", Qt::SkipEmptyParts)) {
            const QString s = part.trimmed();
            if (!s.isEmpty() && !out.contains(s))
                out << s;
        }
    }

    const QString single = props.value("right").toString().trimmed();
    if (!single.isEmpty() && !out.contains(single))
        out << single;

    return out;
}

static int opsGraphRelAclWeight(const QStringList& rights, QString* bestRight = nullptr)
{
    int best = 0;
    QString bestName;

    auto consider = [&](const QString& name, int score) {
        for (const QString& r : rights) {
            if (r.compare(name, Qt::CaseInsensitive) == 0 && score > best) {
                best = score;
                bestName = name;
            }
        }
    };

    consider("GenericAll", 95);
    consider("WriteDACL", 90);
    consider("WriteOwner", 90);
    consider("GenericWrite", 85);
    consider("ForceChangePassword", 80);
    consider("AddMember", 80);
    consider("AllowedToAct", 85);
    consider("WriteSPN", 80);
    consider("AllExtendedRights", 75);
    consider("WriteProperty", 55);
    consider("ExtendedRight", 45);

    if (bestRight)
        *bestRight = bestName;

    return best;
}

static void opsGraphRelScoreGroupRole(const QJsonObject& group, OpsGraphRelevanceResult& result)
{
    const QString text = opsGraphRelNodeText(group);
    const QString norm = opsGraphRelNormText(text);

    auto hasPhrase = [&](const QString& phrase) -> bool {
        return norm.contains(QString(" %1 ").arg(phrase.toLower()));
    };

    if (hasPhrase("domain admins")) {
        opsGraphRelAdd(result, 100, "member of Domain Admins", "PRIVILEGED");
        return;
    }

    if (hasPhrase("enterprise admins")) {
        opsGraphRelAdd(result, 100, "member of Enterprise Admins", "PRIVILEGED");
        return;
    }

    if (hasPhrase("administrators")) {
        opsGraphRelAdd(result, 95, "member of Administrators", "PRIVILEGED");
        return;
    }

    if (hasPhrase("account operators") || hasPhrase("server operators") || hasPhrase("backup operators")) {
        opsGraphRelAdd(result, 90, "member of operator/admin group", "PRIVILEGED");
        return;
    }

    if (hasPhrase("dnsadmins") || hasPhrase("dns admins") || hasPhrase("key admins") || hasPhrase("enterprise key admins")) {
        opsGraphRelAdd(result, 85, "member of sensitive admin group", "PRIVILEGED");
        return;
    }

    if (hasPhrase("group policy creator owners")) {
        opsGraphRelAdd(result, 80, "member of GPO control group", "GPO");
        return;
    }

    if (hasPhrase("cert publishers") || opsGraphRelHasAnyToken(text, {"ca", "pki", "cert", "certificate"})) {
        opsGraphRelAdd(result, 75, "member of certificate/PKI-related group", "PKI");
    }

    if (opsGraphRelHasAnyToken(text, {"sql", "mssql", "database", "dba", "oracle", "postgres", "mysql"})) {
        opsGraphRelAdd(result, 85, "member of database administration group", "DB");
    }

    if (opsGraphRelHasAnyToken(text, {"web", "iis", "app", "api", "tomcat", "nginx", "apache"})) {
        opsGraphRelAdd(result, 75, "member of web/application administration group", "APP");
    }

    if (opsGraphRelHasAnyToken(text, {"exchange", "mail", "sharepoint"})) {
        opsGraphRelAdd(result, 80, "member of enterprise application admin group", "APP");
    }

    if (opsGraphRelHasAnyToken(text, {"backup", "veeam", "bkp"})) {
        opsGraphRelAdd(result, 75, "member of backup administration group", "BACKUP");
    }

    if (opsGraphRelHasAnyToken(text, {"jenkins", "gitlab", "build", "deploy", "ci", "cd"})) {
        opsGraphRelAdd(result, 70, "member of build/deployment administration group", "CI/CD");
    }

    if (opsGraphRelHasAnyToken(text, {"jump", "rdp", "citrix", "vpn"})) {
        opsGraphRelAdd(result, 65, "member of access/pivot administration group", "LATERAL");
    }
}

static QSet<QString> opsGraphRelGroupClosure(const QString& nodeId,
                                             const QHash<QString, QJsonObject>& nodeCache,
                                             const QHash<QString, QJsonObject>& edgeCache,
                                             int maxDepth = 5)
{
    QSet<QString> groups;
    QSet<QString> frontier;
    QSet<QString> seen;

    frontier.insert(nodeId);
    seen.insert(nodeId);

    for (int depth = 0; depth < maxDepth; depth++) {
        QSet<QString> next;

        for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
            const QJsonObject edge = it.value();

            if (edge.value("type").toString() != "MemberOf")
                continue;

            const QString src = edge.value("source").toString();
            const QString dst = edge.value("target").toString();

            if (!frontier.contains(src))
                continue;

            if (!nodeCache.contains(dst))
                continue;

            if (seen.contains(dst))
                continue;

            const QJsonObject dstNode = nodeCache.value(dst);
            if (dstNode.value("type").toString().compare("Group", Qt::CaseInsensitive) != 0)
                continue;

            groups.insert(dst);
            seen.insert(dst);
            next.insert(dst);
        }

        if (next.isEmpty())
            break;

        frontier = next;
    }

    return groups;
}

static bool opsGraphRelHasSPN(const QString& nodeId,
                              const QJsonObject& node,
                              const QHash<QString, QJsonObject>& edgeCache)
{
    for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
        const QJsonObject edge = it.value();

        if (edge.value("type").toString() == "HasSPN" &&
            edge.value("source").toString() == nodeId)
            return true;
    }

    const QJsonObject props = node.value("properties").toObject();

    if (props.contains("service_principal_names"))
        return true;

    const QJsonObject exposure = props.value("exposure").toObject();
    if (exposure.contains("service_principal_names") || exposure.value("has_spn").toBool(false))
        return true;

    return false;
}

static void opsGraphRelScoreServiceOrAssetRole(const QString& nodeId,
                                               const QJsonObject& node,
                                               const QHash<QString, QJsonObject>& edgeCache,
                                               OpsGraphRelevanceResult& result)
{
    const QString type = node.value("type").toString();
    const QString text = opsGraphRelNodeText(node);

    const bool hasSpn = opsGraphRelHasSPN(nodeId, node, edgeCache);

    if (type.compare("User", Qt::CaseInsensitive) == 0) {
        if (hasSpn) {
            opsGraphRelAdd(result, 80, "user has SPN/service principal evidence", "SPN");
            opsGraphRelAdd(result, 50, "service account candidate by behavior", "SERVICE");
        }

        if (opsGraphRelBoolProp(node, "password_never_expires") && hasSpn)
            opsGraphRelAdd(result, 55, "password never expires with SPN", "SERVICE");

        if (opsGraphRelHasAnyToken(text, {"svc", "service", "app", "web", "sql", "mssql", "db", "backup", "build", "deploy"})) {
            if (hasSpn || result.score >= 50)
                opsGraphRelAdd(result, 25, "service-like naming reinforced by evidence", "SERVICE");
            else
                opsGraphRelAdd(result, 10, "service-like naming only", "LOWCONF");
        }
    }

    if (type.compare("Computer", Qt::CaseInsensitive) == 0) {
        if (opsGraphRelHasAnyToken(text, {"db", "sql", "mssql", "mysql", "postgres", "oracle"}))
            opsGraphRelAdd(result, 45, "database server naming signal", "DB");

        if (opsGraphRelHasAnyToken(text, {"web", "iis", "app", "api", "tomcat", "nginx", "apache"}))
            opsGraphRelAdd(result, 40, "web/application server naming signal", "APP");

        if (opsGraphRelHasAnyToken(text, {"dc", "ad", "ldap", "dns"}))
            opsGraphRelAdd(result, 70, "domain infrastructure naming signal", "INFRA");

        if (opsGraphRelHasAnyToken(text, {"ca", "pki", "cert"}))
            opsGraphRelAdd(result, 65, "certificate infrastructure naming signal", "PKI");

        if (opsGraphRelHasAnyToken(text, {"backup", "bkp", "veeam"}))
            opsGraphRelAdd(result, 55, "backup server naming signal", "BACKUP");

        if (opsGraphRelHasAnyToken(text, {"jump", "rdp", "citrix", "vpn"}))
            opsGraphRelAdd(result, 55, "access/pivot server naming signal", "LATERAL");

        if (opsGraphRelHasAnyToken(text, {"jenkins", "gitlab", "build", "deploy", "ci", "cd"}))
            opsGraphRelAdd(result, 55, "build/deployment server naming signal", "CI/CD");

        if (hasSpn)
            opsGraphRelAdd(result, 35, "computer has SPN evidence", "SPN");
    }
}


// OPSGraph DelegationTarget relevance/category v5
static bool opsGraphIsDelegationTargetNodeV5(const QJsonObject& node)
{
    const QString type = node.value("type").toString();

    if (type.compare("DelegationTarget", Qt::CaseInsensitive) == 0)
        return true;

    const QJsonObject props = node.value("properties").toObject();
    const QString role = props.value("target_role").toString();

    if (role.compare("delegation_target_family", Qt::CaseInsensitive) == 0 ||
        role.compare("delegation_allowed_target", Qt::CaseInsensitive) == 0 ||
        role.compare("direct_delegation_target", Qt::CaseInsensitive) == 0)
        return true;

    return false;
}

static OpsGraphRelevanceResult opsGraphComputeNodeRelevanceV1(const QString& nodeId,
                                                              const QHash<QString, QJsonObject>& nodeCache,
                                                              const QHash<QString, QJsonObject>& edgeCache)
{
    OpsGraphRelevanceResult result;

    if (nodeId.isEmpty() || !nodeCache.contains(nodeId))
        return result;

    const QJsonObject node = nodeCache.value(nodeId);
    const QString type = node.value("type").toString();
    const QString label = node.value("label").toString(nodeId);

    if (type == "Agent") {
        opsGraphRelAdd(result, 100, "active agent context", "CURRENT");
    }

    if (type == "Domain") {
        opsGraphRelAdd(result, 55, "domain context", "DOMAIN");
    }

    if (opsGraphIsDelegationTargetNodeV5(node)) {
        opsGraphRelAdd(result, 72,
                       "delegation target family from msDS-AllowedToDelegateTo evidence",
                       "DELEGATION_TARGET");
        opsGraphRelAdd(result, 35,
                       "candidate delegation path; successful delegated access is not observed",
                       "CANDIDATE");
    }

    for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
        const QJsonObject edge = it.value();

        const QString edgeType = edge.value("type").toString();
        const QString src = edge.value("source").toString();
        const QString dst = edge.value("target").toString();

        if (edgeType == "RunningAs" && dst == nodeId)
            opsGraphRelAdd(result, 100, "current beacon running user", "CURRENT");

        if (edgeType == "RunningOn" && dst == nodeId)
            opsGraphRelAdd(result, 90, "current foothold machine", "CURRENT");

        if ((edgeType == "HasSession" || edgeType == "LoggedOnTo") && (src == nodeId || dst == nodeId))
            opsGraphRelAdd(result, 80, "session/lateral movement evidence", "LATERAL");

        if (edgeType == "Impersonating" && dst == nodeId)
            opsGraphRelAdd(result, 95, "impersonated user context", "CURRENT");
    }

    if (type == "Group") {
        opsGraphRelScoreGroupRole(node, result);
    }

    if (type == "User") {
        const QSet<QString> groups = opsGraphRelGroupClosure(nodeId, nodeCache, edgeCache, 5);

        for (const QString& groupId : groups) {
            if (!nodeCache.contains(groupId))
                continue;

            const int before = result.score;
            opsGraphRelScoreGroupRole(nodeCache.value(groupId), result);

            if (result.score > before) {
                const QString groupLabel = opsGraphRelNodeLabel(groupId, nodeCache);
                const QString reason = QString("transitive member of %1").arg(groupLabel);
                if (!result.reasons.contains(reason))
                    result.reasons << reason;
            }
        }
    }

    opsGraphRelScoreServiceOrAssetRole(nodeId, node, edgeCache, result);

    QSet<QString> effectivePrincipals;
    effectivePrincipals.insert(nodeId);

    if (type == "User") {
        const QSet<QString> groups = opsGraphRelGroupClosure(nodeId, nodeCache, edgeCache, 5);
        for (const QString& g : groups)
            effectivePrincipals.insert(g);
    }

    for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
        const QJsonObject edge = it.value();

        if (edge.value("type").toString() != "ACLRight")
            continue;

        const QString src = edge.value("source").toString();
        const QString dst = edge.value("target").toString();

        QString bestRight;
        const int weight = opsGraphRelAclWeight(opsGraphRelEdgeRights(edge), &bestRight);

        if (weight <= 0)
            continue;

        if (effectivePrincipals.contains(src)) {
            const QString targetLabel = opsGraphRelNodeLabel(dst, nodeCache);
            opsGraphRelAdd(result,
                           weight,
                           QString("effective principal has %1 over %2").arg(bestRight.isEmpty() ? "ACLRight" : bestRight, targetLabel),
                           "ACL");
        }

        // Incoming ACL control is awareness, not an outgoing operator path.
        // Do not boost relevance just because another principal controls this object.
        // The details panel and ACL Lens summarize incoming controllers separately.
    }

    if (opsGraphRelBoolProp(node, "admin_count_1") || opsGraphRelBoolProp(node, "adminCount")) {
        opsGraphRelAdd(result, 90, "adminCount/admin protected object", "PRIVILEGED");
    }

    if (opsGraphRelBoolProp(node, "preauth_not_required")) {
        opsGraphRelAdd(result, 75, "ASREP roastable evidence", "KERBEROS");
    }

    if (opsGraphRelBoolProp(node, "unconstrained_delegation")) {
        opsGraphRelAdd(result, 90, "unconstrained delegation evidence", "DELEGATION");
    }

    if (opsGraphRelBoolProp(node, "constrained_delegation_enabled")) {
        opsGraphRelAdd(result, 80, "constrained delegation evidence", "DELEGATION");
    }

    if (opsGraphRelBoolProp(node, "rbcd_descriptor_present")) {
        opsGraphRelAdd(result, 85, "RBCD descriptor evidence", "RBCD");
    }

    if (opsGraphRelBoolProp(node, "account_disabled")) {
        opsGraphRelAdd(result, -80, "disabled account penalty", "DISABLED");
    }

    if (result.score >= 80)
        result.visibility = "actionable";
    else if (result.score >= 50)
        result.visibility = "relevant";
    else
        result.visibility = "hidden_inventory";

    if (result.reasons.isEmpty())
        result.reasons << QString("inventory-only node: %1").arg(label);

    if (opsGraphIsDelegationTargetNodeV5(node) && result.score > 0) {
        result.visibility = "relevant";
    }

    return result;

}
// OPSGRAPH_RELEVANCE_ENGINE_V1_END

// OPSGRAPH_HIGH_VALUE_SCORING_V1_BEGIN
struct OpsGraphHighValueResult
{
    int score = 0;
    QString tier = "low";
    QStringList reasons;
    QStringList badges;
};

static void opsGraphHVAdd(OpsGraphHighValueResult& result, int score, const QString& reason, const QString& badge = QString())
{
    result.score += score;

    if (!reason.isEmpty() && !result.reasons.contains(reason))
        result.reasons << reason;

    if (!badge.isEmpty() && !result.badges.contains(badge))
        result.badges << badge;
}

static bool opsGraphHVTextHas(const QString& text, const QString& needle)
{
    return text.toLower().contains(needle.toLower());
}

static bool opsGraphHVTextHasAny(const QString& text, const QStringList& needles)
{
    for (const QString& n : needles) {
        if (opsGraphHVTextHas(text, n))
            return true;
    }

    return false;
}

static QString opsGraphHVTierForScore(int score)
{
    if (score >= 140)
        return "critical";

    if (score >= 90)
        return "high";

    if (score >= 60)
        return "interesting";

    return "low";
}

static OpsGraphHighValueResult opsGraphComputeHighValueV1(const QString& nodeId,
                                                          const QHash<QString, QJsonObject>& nodeCache,
                                                          const QHash<QString, QJsonObject>& edgeCache)
{
    OpsGraphHighValueResult result;

    if (nodeId.isEmpty() || !nodeCache.contains(nodeId))
        return result;

    const QJsonObject node = nodeCache.value(nodeId);
    const QString type = node.value("type").toString();
    const QString label = node.value("label").toString(nodeId);
    const QString text = opsGraphRelNodeText(node);
    const QString norm = opsGraphRelNormText(text);
    const QJsonObject props = node.value("properties").toObject();

    auto hasPhrase = [&](const QString& phrase) -> bool {
        return norm.contains(QString(" %1 ").arg(phrase.toLower()));
    };

    auto hasAny = [&](const QStringList& tokens) -> bool {
        return opsGraphHVTextHasAny(text, tokens);
    };

    auto hasAdminWord = [&]() -> bool {
        return hasAny({"admin", "admins", "administrator", "administrators",
                       "operator", "operators", "owner", "owners",
                       "manage", "managers", "maintainer", "maintainers"});
    };

    auto hasAccessOnlyWord = [&]() -> bool {
        return hasAny({"reader", "readers", "read only", "readonly",
                       "users", "viewer", "viewers", "auditor", "auditors"});
    };

    auto addNameOnly = [&](int score, const QString& reason, const QString& badge) {
        opsGraphHVAdd(result, score, reason + " (name-only, low confidence)", badge);
    };

    auto spnTextForNode = [&](const QString& id) -> QString {
        QStringList parts;

        if (!nodeCache.contains(id))
            return QString();

        const QJsonObject n = nodeCache.value(id);
        const QJsonObject p = n.value("properties").toObject();

        const QJsonArray servicePrincipalNames = p.value("service_principal_names").toArray();
        for (const QJsonValue& v : servicePrincipalNames)
            parts << v.toString();

        const QJsonObject exposure = p.value("exposure").toObject();
        const QJsonArray exposureSpns = exposure.value("service_principal_names").toArray();
        for (const QJsonValue& v : exposureSpns)
            parts << v.toString();

        for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
            const QJsonObject edge = it.value();

            if (edge.value("type").toString() != "HasSPN")
                continue;

            const QString src = edge.value("source").toString(edge.value("source_id").toString());
            const QString dst = edge.value("target").toString(edge.value("target_id").toString());

            if (src != id)
                continue;

            if (nodeCache.contains(dst)) {
                const QJsonObject spnNode = nodeCache.value(dst);
                parts << spnNode.value("label").toString();
                parts << spnNode.value("normalized_name").toString();
                parts << opsGraphRelNodeText(spnNode);
            } else {
                parts << dst;
            }
        }

        return parts.join(" ").toLower();
    };

    auto hasAclOrSessionEvidence = [&](const QString& id) -> bool {
        for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
            const QJsonObject edge = it.value();

            const QString et = edge.value("type").toString();
            const QString src = edge.value("source").toString(edge.value("source_id").toString());
            const QString dst = edge.value("target").toString(edge.value("target_id").toString());

            if ((et == "ACLRight" || et == "HasSession" || et == "LoggedOnTo" ||
                 et == "RunningOn" || et == "RunningAs") &&
                (src == id || dst == id)) {
                return true;
            }
        }

        return false;
    };

    const QString spnText = spnTextForNode(nodeId);
    const bool hasSpn = !spnText.trimmed().isEmpty() || opsGraphRelHasSPN(nodeId, node, edgeCache);
    const bool hasEvidence = hasSpn || hasAclOrSessionEvidence(nodeId);

    // ------------------------------------------------------------------
    // Groups: exact privileged semantics are high confidence.
    // App/DB/backup groups need admin/control wording to avoid enterprise noise.
    // ------------------------------------------------------------------
    if (type == "Group") {
        if (hasPhrase("domain admins")) {
            opsGraphHVAdd(result, 160, "Domain Admins group", "DA");
        } else if (hasPhrase("enterprise admins")) {
            opsGraphHVAdd(result, 160, "Enterprise Admins group", "EA");
        } else if (hasPhrase("administrators")) {
            opsGraphHVAdd(result, 130, "Administrators group", "PRIVILEGED");
        } else if (hasPhrase("account operators") || hasPhrase("server operators") || hasPhrase("backup operators")) {
            opsGraphHVAdd(result, 115, "built-in operator group with administrative capability", "PRIVILEGED");
        } else if (hasPhrase("dnsadmins") || hasPhrase("dns admins") || hasPhrase("key admins") || hasPhrase("enterprise key admins")) {
            opsGraphHVAdd(result, 105, "sensitive infrastructure admin group", "PRIVILEGED");
        } else if (hasPhrase("group policy creator owners")) {
            opsGraphHVAdd(result, 100, "GPO control group", "GPO");
        } else if (hasPhrase("cert publishers")) {
            opsGraphHVAdd(result, 45, "certificate publishing group, useful context but not automatically critical", "PKI");
        }

        const bool dbGroup = hasAny({"sql", "mssql", "database", "dba", "oracle", "postgres", "mysql"});
        const bool appGroup = hasAny({"web", "iis", "app", "api", "exchange", "sharepoint", "mail"});
        const bool backupGroup = hasAny({"backup", "veeam", "bkp"});
        const bool cicdGroup = hasAny({"jenkins", "gitlab", "build", "deploy", "ci", "cd"});
        const bool pkiGroup = hasAny({"pki", "certificate", "cert", "adcs", "ca"});

        if (dbGroup) {
            if (hasAdminWord() && !hasAccessOnlyWord())
                opsGraphHVAdd(result, 95, "database administration group", "DB");
            else
                addNameOnly(35, "database-related group", "DB");
        }

        if (appGroup) {
            if (hasAdminWord() && !hasAccessOnlyWord())
                opsGraphHVAdd(result, 85, "enterprise application administration group", "APP");
            else
                addNameOnly(30, "application-related group", "APP");
        }

        if (backupGroup) {
            if (hasAdminWord() && !hasAccessOnlyWord())
                opsGraphHVAdd(result, 90, "backup administration group", "BACKUP");
            else
                addNameOnly(40, "backup-related group", "BACKUP");
        }

        if (cicdGroup) {
            if (hasAdminWord() && !hasAccessOnlyWord())
                opsGraphHVAdd(result, 85, "CI/CD or deployment administration group", "CI/CD");
            else
                addNameOnly(35, "CI/CD-related group", "CI/CD");
        }

        if (pkiGroup && hasAdminWord() && !hasAccessOnlyWord())
            opsGraphHVAdd(result, 90, "PKI/certificate administration group", "PKI");
    }

    // ------------------------------------------------------------------
    // Users: high value comes from privileged membership, adminCount,
    // delegation/RBCD, SPN/service behavior, or special well-known accounts.
    // ------------------------------------------------------------------
    if (type == "User") {
        const QString simple = label.toLower();

        if (simple == "administrator" || simple.endsWith("\\administrator"))
            opsGraphHVAdd(result, 130, "built-in Administrator identity", "PRIVILEGED");

        if (simple == "krbtgt" || simple.endsWith("\\krbtgt"))
            opsGraphHVAdd(result, 160, "KRBTGT account", "KERBEROS");

        if (opsGraphRelBoolProp(node, "admin_count_1") || opsGraphRelBoolProp(node, "adminCount"))
            opsGraphHVAdd(result, 115, "adminCount/admin protected user", "PRIVILEGED");

        if (hasSpn) {
            opsGraphHVAdd(result, 85, "user has SPN/service principal evidence", "SPN");

            if (spnText.contains("mssqlsvc/"))
                opsGraphHVAdd(result, 35, "MSSQL service principal evidence", "DB");

            if (spnText.contains("http/"))
                opsGraphHVAdd(result, 25, "HTTP service principal evidence", "APP");

            if (spnText.contains("cifs/") || spnText.contains("ldap/"))
                opsGraphHVAdd(result, 25, "sensitive service principal evidence", "SPN");
        }

        if (opsGraphRelBoolProp(node, "preauth_not_required"))
            opsGraphHVAdd(result, 75, "ASREP roastable exposure evidence", "KERBEROS");

        if (opsGraphRelBoolProp(node, "unconstrained_delegation"))
            opsGraphHVAdd(result, 115, "unconstrained delegation evidence", "DELEGATION");

        if (opsGraphRelBoolProp(node, "constrained_delegation_enabled"))
            opsGraphHVAdd(result, 95, "constrained delegation evidence", "DELEGATION");

        if (opsGraphRelBoolProp(node, "rbcd_descriptor_present"))
            opsGraphHVAdd(result, 100, "RBCD descriptor evidence", "RBCD");

        if (hasAny({"svc", "service", "sql", "mssql", "web", "app", "backup", "deploy", "build"})) {
            if (hasSpn || opsGraphRelBoolProp(node, "password_never_expires"))
                opsGraphHVAdd(result, 55, "service-like account naming reinforced by evidence", "SERVICE");
            else
                addNameOnly(15, "service-like user naming", "SERVICE");
        }

        const QSet<QString> groups = opsGraphRelGroupClosure(nodeId, nodeCache, edgeCache, 5);
        for (const QString& groupId : groups) {
            if (!nodeCache.contains(groupId))
                continue;

            const QString groupText = opsGraphRelNormText(opsGraphRelNodeText(nodeCache.value(groupId)));

            auto groupHas = [&](const QString& phrase) -> bool {
                return groupText.contains(QString(" %1 ").arg(phrase.toLower()));
            };

            if (groupHas("domain admins"))
                opsGraphHVAdd(result, 150, "transitive member of Domain Admins", "DA");
            else if (groupHas("enterprise admins"))
                opsGraphHVAdd(result, 150, "transitive member of Enterprise Admins", "EA");
            else if (groupHas("administrators"))
                opsGraphHVAdd(result, 120, "transitive member of Administrators", "PRIVILEGED");
            else if (groupHas("account operators") || groupHas("server operators") || groupHas("backup operators"))
                opsGraphHVAdd(result, 105, "transitive member of operator/admin group", "PRIVILEGED");
            else if (groupHas("dnsadmins") || groupHas("dns admins") || groupHas("key admins") || groupHas("enterprise key admins"))
                opsGraphHVAdd(result, 95, "transitive member of sensitive infrastructure admin group", "PRIVILEGED");

            if ((groupText.contains(" sql ") || groupText.contains(" mssql ") ||
                 groupText.contains(" database ") || groupText.contains(" dba ")) &&
                (groupText.contains(" admin ") || groupText.contains(" admins ") ||
                 groupText.contains(" operator ") || groupText.contains(" operators "))) {
                opsGraphHVAdd(result, 90, "transitive member of database admin group", "DB");
            }
        }
    }

    // ------------------------------------------------------------------
    // Computers: name-only is intentionally low. High requires SPN,
    // delegation/RBCD, session/ACL/current operation evidence, or strong DC/PKI signal.
    // ------------------------------------------------------------------
    if (type == "Computer") {
        const bool dbName = hasAny({"db", "sql", "mssql", "mysql", "postgres", "oracle"});
        const bool appName = hasAny({"web", "iis", "app", "api", "tomcat", "nginx", "apache"});
        const bool dcName = hasAny({"dc", "domain controller"});
        const bool pkiName = hasAny({"ca", "pki", "cert", "adcs"});
        const bool backupName = hasAny({"backup", "veeam", "bkp"});
        const bool jumpName = hasAny({"jump", "rdp", "citrix", "vpn"});
        const bool cicdName = hasAny({"jenkins", "gitlab", "build", "deploy", "ci", "cd"});

        const bool dcSpn = spnText.contains("ldap/") || spnText.contains("gc/") ||
                           spnText.contains("kerberos/") || spnText.contains("kadmin/");

        const bool dbSpn = spnText.contains("mssqlsvc/") || spnText.contains("mysql/") ||
                           spnText.contains("postgres/") || spnText.contains("oracle/");

        const bool appSpn = spnText.contains("http/") || spnText.contains("wsman/");

        if (dcSpn) {
            opsGraphHVAdd(result, 140, "directory/DC-like service principal evidence", "DC");
        } else if (dcName && hasEvidence) {
            opsGraphHVAdd(result, 110, "domain controller naming reinforced by evidence", "DC");
        } else if (dcName) {
            addNameOnly(45, "domain controller naming signal", "DC");
        }

        if (pkiName && hasEvidence)
            opsGraphHVAdd(result, 105, "certificate infrastructure naming reinforced by evidence", "PKI");
        else if (pkiName)
            addNameOnly(45, "certificate infrastructure naming signal", "PKI");

        if (dbSpn)
            opsGraphHVAdd(result, 100, "database service principal evidence", "DB");
        else if (dbName && hasEvidence)
            opsGraphHVAdd(result, 85, "database server naming reinforced by evidence", "DB");
        else if (dbName)
            addNameOnly(35, "database server naming signal", "DB");

        if (appSpn && appName)
            opsGraphHVAdd(result, 85, "application server naming plus service principal evidence", "APP");
        else if (appName && hasEvidence)
            opsGraphHVAdd(result, 70, "application server naming reinforced by evidence", "APP");
        else if (appName)
            addNameOnly(30, "application server naming signal", "APP");

        if (backupName && hasEvidence)
            opsGraphHVAdd(result, 90, "backup server naming reinforced by evidence", "BACKUP");
        else if (backupName)
            addNameOnly(40, "backup server naming signal", "BACKUP");

        if (jumpName && hasEvidence)
            opsGraphHVAdd(result, 85, "access/jump/pivot server naming reinforced by evidence", "LATERAL");
        else if (jumpName)
            addNameOnly(35, "access/jump/pivot server naming signal", "LATERAL");

        if (cicdName && hasEvidence)
            opsGraphHVAdd(result, 80, "CI/CD server naming reinforced by evidence", "CI/CD");
        else if (cicdName)
            addNameOnly(30, "CI/CD server naming signal", "CI/CD");

        if (opsGraphRelBoolProp(node, "unconstrained_delegation"))
            opsGraphHVAdd(result, 115, "unconstrained delegation evidence", "DELEGATION");

        if (opsGraphRelBoolProp(node, "constrained_delegation_enabled"))
            opsGraphHVAdd(result, 95, "constrained delegation evidence", "DELEGATION");

        if (opsGraphRelBoolProp(node, "rbcd_descriptor_present"))
            opsGraphHVAdd(result, 100, "RBCD descriptor evidence", "RBCD");
    }

    if (type == "Domain") {
        opsGraphHVAdd(result, 60, "domain object", "DOMAIN");
    }

    if (type == "Trust") {
        opsGraphHVAdd(result, 90, "domain trust relationship", "TRUST");
    }

    if (type == "SPN") {
        if (hasAny({"mssqlsvc", "cifs", "ldap", "termsrv", "wsman"}))
            opsGraphHVAdd(result, 80, "sensitive service principal target", "SPN");
        else if (hasAny({"http"}))
            opsGraphHVAdd(result, 60, "HTTP service principal target", "SPN");
    }

    if (opsGraphRelBoolProp(node, "account_disabled")) {
        opsGraphHVAdd(result, -90, "disabled account penalty", "DISABLED");
    }

    result.tier = opsGraphHVTierForScore(result.score);

    if (result.reasons.isEmpty())
        result.reasons << "not high value by current passive evidence";

    return result;
}
// OPSGRAPH_HIGH_VALUE_SCORING_V1_END




// OPSGRAPH_ATTACK_LENS_V1_BEGIN
void OperationGraphTab::renderAttackLensFromCache(const QString& nodeId)
{
    if (!canvas)
        return;

    if (nodeId.isEmpty() || !nodeCache.contains(nodeId))
        return;

    auto edgeSource = [](const QJsonObject& edge) -> QString {
        return edge.value("source").toString(edge.value("source_id").toString());
    };

    auto edgeTarget = [](const QJsonObject& edge) -> QString {
        return edge.value("target").toString(edge.value("target_id").toString());
    };

    auto edgeType = [](const QJsonObject& edge) -> QString {
        return edge.value("type").toString();
    };

    auto nodeLabel = [&](const QString& id) -> QString {
        if (!nodeCache.contains(id))
            return id;

        return nodeCache.value(id).value("label").toString(id);
    };

    auto isHiddenTokenGroupNode = [&](const QString& id) -> bool {
        if (showTokenGroups)
            return false;

        if (id == nodeId)
            return false;

        if (!nodeCache.contains(id))
            return false;

        return opsGraphShouldHideTokenGroup(nodeCache.value(id));
    };

    QSet<QString> visibleNodes;
    QSet<QString> visibleEdges;
    QSet<QString> vectorNodes;
    QSet<QString> targetNodes;
    QSet<QString> serviceNodes;

    // OPSGRAPH_ATTACK_LENS_CLEAN_ROUTING_V1_BEGIN
    // Direct DelegatesTo edges are valid raw evidence, but they make the
    // Attack Lens visually noisy when a semantic vector hub exists:
    //
    //   svcIIS -> Constrained delegation -> target SPNs
    //
    // is clearer than rendering both that and:
    //
    //   svcIIS -> DelegatesTo -> target SPNs
    //
    // Keep the raw edges in cache/evidence, but hide them by default in this
    // lens unless no semantic attack-vector route exists.
    QSet<QString> directDelegateEdgeIds;
    QSet<QString> directDelegateTargetNodes;
    int hiddenDirectDelegatesToEdges = 0;
    // OPSGRAPH_ATTACK_LENS_CLEAN_ROUTING_V1_END

    const int maxAttackVectors = 30;
    const int maxTargets = 60;

    visibleNodes.insert(nodeId);

    auto addVisibleEdge = [&](const QString& edgeId, const QJsonObject& edge) {
        const QString src = edgeSource(edge);
        const QString dst = edgeTarget(edge);

        if (edgeId.isEmpty() || src.isEmpty() || dst.isEmpty())
            return;

        if (!nodeCache.contains(src) || !nodeCache.contains(dst))
            return;

        visibleEdges.insert(edgeId);
        visibleNodes.insert(src);
        visibleNodes.insert(dst);
    };

    // Direct attack surface from selected/focused anchor.
    for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
        const QString edgeId = it.key();
        const QJsonObject edge = it.value();

        const QString type = edgeType(edge);
        const QString src = edgeSource(edge);
        const QString dst = edgeTarget(edge);

        if (src != nodeId)
            continue;

        if (type == "HasAttackVector") {
            if (vectorNodes.size() >= maxAttackVectors)
                continue;

            addVisibleEdge(edgeId, edge);
            vectorNodes.insert(dst);
            continue;
        }

        if (type == "DelegatesTo") {
            if (targetNodes.size() >= maxTargets)
                continue;

            // OPSGRAPH_ATTACK_LENS_CLEAN_ROUTING_V1
            // Do not render direct DelegatesTo edges by default. The cleaner
            // operator path is:
            //   source -> candidate path -> vector -> target
            directDelegateEdgeIds.insert(edgeId);
            directDelegateTargetNodes.insert(dst);
            targetNodes.insert(dst);
            hiddenDirectDelegatesToEdges++;
            continue;
        }

        if (type == "HasSPN") {
            if (serviceNodes.size() >= maxTargets)
                continue;

            addVisibleEdge(edgeId, edge);
            serviceNodes.insert(dst);
            continue;
        }

        if (type == "InDomain") {
            addVisibleEdge(edgeId, edge);
            continue;
        }
    }

    // AttackVector -> target edges.
    for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
        const QString edgeId = it.key();
        const QJsonObject edge = it.value();

        const QString type = edgeType(edge);
        const QString src = edgeSource(edge);
        const QString dst = edgeTarget(edge);

        if (!vectorNodes.contains(src))
            continue;

        if (type != "RelatedToTarget")
            continue;

        if (targetNodes.size() >= maxTargets && !targetNodes.contains(dst))
            continue;

        addVisibleEdge(edgeId, edge);
        targetNodes.insert(dst);
    }

    // OPSGRAPH_ATTACK_LENS_CLEAN_ROUTING_V1
    // Fallback: if a future parser gives us DelegatesTo without a semantic
    // AttackVector -> RelatedToTarget route, render direct DelegatesTo so the
    // operator still sees the evidence.
    if (vectorNodes.isEmpty() && !directDelegateEdgeIds.isEmpty()) {
        for (const QString& edgeId : directDelegateEdgeIds) {
            if (!edgeCache.contains(edgeId))
                continue;

            addVisibleEdge(edgeId, edgeCache.value(edgeId));
        }

        hiddenDirectDelegatesToEdges = 0;
    }

    // Domain context for attack surface nodes.
    bool changed = true;
    while (changed) {
        changed = false;

        for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
            const QString edgeId = it.key();
            const QJsonObject edge = it.value();

            if (edgeType(edge) != "InDomain")
                continue;

            const QString src = edgeSource(edge);
            const QString dst = edgeTarget(edge);

            if (visibleNodes.contains(src) && !visibleNodes.contains(dst)) {
                addVisibleEdge(edgeId, edge);
                changed = true;
            }
        }
    }


    // OPSGRAPH_ATTACK_PATH_SEMANTICS_V1_BEGIN
    // Evidence-first path classification.
    //
    // CONFIRMED_CONTROL_PATH is intentionally strict:
    // only a complete observed control chain should enter that bucket.
    //
    // LDAP-only attack vectors such as Kerberoast are classified as
    // EXPOSURE_ONLY. Delegation/RBCD relationships are classified as
    // CANDIDATE_ATTACK_PATH unless the graph also proves control of the
    // source identity through observed edges.
    QStringList confirmedControlPaths;
    QStringList candidateAttackPaths;
    QStringList exposureOnlyFindings;
    QStringList contextOnlyFindings;

    auto propString = [](const QJsonObject& props, const QString& key) -> QString {
        const QJsonValue value = props.value(key);

        if (value.isString())
            return value.toString().trimmed();

        if (value.isDouble())
            return QString::number(value.toDouble(), 'f', 2);

        return value.toVariant().toString().trimmed();
    };

    auto vectorNodeProps = [&](const QString& vectorNodeId) -> QJsonObject {
        if (!nodeCache.contains(vectorNodeId))
            return QJsonObject();

        return nodeCache.value(vectorNodeId).value("properties").toObject();
    };

    auto vectorTargets = [&](const QString& vectorNodeId) -> QStringList {
        QStringList targets;

        for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
            const QJsonObject edge = it.value();

            if (edgeType(edge) != "RelatedToTarget")
                continue;

            if (edgeSource(edge) != vectorNodeId)
                continue;

            const QString dst = edgeTarget(edge);
            if (!dst.isEmpty())
                targets << nodeLabel(dst);
        }

        targets.removeDuplicates();
        std::sort(targets.begin(), targets.end(),
                  [](const QString& a, const QString& b) {
                      return a.toLower() < b.toLower();
                  });

        return targets;
    };

    auto semanticClassForVector = [](QString vectorId, QString category) -> QString {
        vectorId = vectorId.toLower().trimmed();
        category = category.toLower().trimmed();

        if (vectorId.contains("delegation") ||
            vectorId == "rbcd" ||
            vectorId.contains("resource_based_constrained_delegation") ||
            category == "delegation" ||
            category == "rbcd") {
            return "CANDIDATE_ATTACK_PATH";
        }

        if (vectorId.contains("kerberoast") ||
            vectorId.contains("asrep") ||
            vectorId.contains("weak_kerberos_crypto") ||
            vectorId.contains("protected_admin_count") ||
            vectorId.contains("admin_count")) {
            return "EXPOSURE_ONLY";
        }

        if (category == "kerberos" || category == "privilege")
            return "EXPOSURE_ONLY";

        return "CONTEXT_ONLY";
    };

    auto classReason = [](const QString& semanticClass) -> QString {
        if (semanticClass == "CONFIRMED_CONTROL_PATH")
            return "full observed control chain is present in the graph";
        if (semanticClass == "CANDIDATE_ATTACK_PATH")
            return "target relationship is observed, but control of the source identity is not proven in current graph";
        if (semanticClass == "EXPOSURE_ONLY")
            return "exposure signal is observed, but no complete control path is proven yet";
        return "contextual relationship, not an attack path by itself";
    };

    for (const QString& vectorNodeId : vectorNodes) {
        const QJsonObject props = vectorNodeProps(vectorNodeId);

        const QString vectorId = propString(props, "vector_id");
        const QString category = propString(props, "category");
        const QString severity = propString(props, "severity");
        const QString semanticClass = semanticClassForVector(vectorId, category);
        const QString labelText = nodeLabel(vectorNodeId);
        const QStringList targets = vectorTargets(vectorNodeId);

        QString decoratedLabel = labelText;
        if (!severity.isEmpty())
            decoratedLabel += " [" + severity + "]";

        if (semanticClass == "CANDIDATE_ATTACK_PATH") {
            if (targets.isEmpty()) {
                candidateAttackPaths << QString("- %1: %2")
                                            .arg(nodeLabel(nodeId))
                                            .arg(decoratedLabel);
            } else {
                for (const QString& target : targets) {
                    candidateAttackPaths << QString("- %1 --[%2]--> %3")
                                                .arg(nodeLabel(nodeId))
                                                .arg(decoratedLabel)
                                                .arg(target);
                }
            }

            continue;
        }

        if (semanticClass == "EXPOSURE_ONLY") {
            exposureOnlyFindings << QString("- %1: %2")
                                        .arg(nodeLabel(nodeId))
                                        .arg(decoratedLabel);
            continue;
        }

        contextOnlyFindings << QString("- %1: %2")
                                   .arg(nodeLabel(nodeId))
                                   .arg(decoratedLabel);
    }

    for (const QString& serviceNodeId : serviceNodes) {
        contextOnlyFindings << QString("- %1 --[HasSPN]--> %2")
                                   .arg(nodeLabel(nodeId))
                                   .arg(nodeLabel(serviceNodeId));
    }

    for (const QString& targetNodeId : targetNodes) {
        bool alreadyCovered = false;

        for (const QString& line : candidateAttackPaths) {
            if (line.contains(nodeLabel(targetNodeId), Qt::CaseInsensitive)) {
                alreadyCovered = true;
                break;
            }
        }

        if (!alreadyCovered) {
            candidateAttackPaths << QString("- %1 --[DelegatesTo]--> %2")
                                        .arg(nodeLabel(nodeId))
                                        .arg(nodeLabel(targetNodeId));
        }
    }

    confirmedControlPaths.removeDuplicates();
    candidateAttackPaths.removeDuplicates();
    exposureOnlyFindings.removeDuplicates();
    contextOnlyFindings.removeDuplicates();

    auto sortLines = [](QStringList& lines) {
        std::sort(lines.begin(), lines.end(),
                  [](const QString& a, const QString& b) {
                      return a.toLower() < b.toLower();
                  });
    };

    sortLines(confirmedControlPaths);
    sortLines(candidateAttackPaths);
    sortLines(exposureOnlyFindings);
    sortLines(contextOnlyFindings);
    // OPSGRAPH_ATTACK_PATH_SEMANTICS_V1_END

    // OPSGRAPH_ATTACK_TRUTH_GATE_V1_BEGIN
    // Strict operator truth gate:
    // - LDAP-derived Kerberos roastability is exposure, not a confirmed path.
    // - Delegation/RBCD is candidate path unless the graph proves source control.
    // - Confirmed path is reserved for full observed control chains.
    QStringList truthGateObservedFacts;
    QStringList truthGateExposureOnly;
    QStringList truthGateCandidatePaths;
    QStringList truthGateConfirmedPaths;
    QStringList truthGateMissingProof;
    QStringList truthGateDecisions;

    auto truthNodeProps = [&](const QString& id) -> QJsonObject {
        if (!nodeCache.contains(id))
            return QJsonObject();

        return nodeCache.value(id).value("properties").toObject();
    };

    auto truthProp = [](const QJsonObject& props, const QString& key) -> QString {
        const QJsonValue value = props.value(key);

        if (value.isString())
            return value.toString().trimmed();

        if (value.isDouble())
            return QString::number(value.toDouble(), 'f', 2);

        if (value.isArray()) {
            QStringList out;
            const QJsonArray arr = value.toArray();

            for (const QJsonValue& v : arr) {
                const QString s = v.toVariant().toString().trimmed();
                if (!s.isEmpty())
                    out << s;
            }

            return out.join(", ");
        }

        return value.toVariant().toString().trimmed();
    };

    auto truthTargetsForVector = [&](const QString& vectorNodeId) -> QStringList {
        QStringList targets;

        for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
            const QJsonObject edge = it.value();

            const QString type = edgeType(edge);
            if (type != "RelatedToTarget")
                continue;

            if (edgeSource(edge) != vectorNodeId)
                continue;

            const QString dst = edgeTarget(edge);
            if (dst.isEmpty())
                continue;

            targets << nodeLabel(dst);
        }

        targets.removeDuplicates();
        std::sort(targets.begin(), targets.end(),
                  [](const QString& a, const QString& b) {
                      return a.toLower() < b.toLower();
                  });

        return targets;
    };

    auto truthClassForVector = [](QString vectorId, QString category) -> QString {
        vectorId = vectorId.toLower().trimmed();
        category = category.toLower().trimmed();

        if (vectorId.contains("delegation") ||
            vectorId == "rbcd" ||
            vectorId.contains("resource_based_constrained_delegation") ||
            category == "delegation" ||
            category == "rbcd") {
            return "CANDIDATE_ATTACK_PATH";
        }

        if (vectorId.contains("kerberoast") ||
            vectorId.contains("asrep") ||
            vectorId.contains("weak_kerberos") ||
            vectorId.contains("admin_count") ||
            vectorId.contains("protected_admin_count") ||
            category == "kerberos" ||
            category == "privilege") {
            return "EXPOSURE_ONLY";
        }

        return "CONTEXT_ONLY";
    };

    auto addMissingProof = [&](const QString& line) {
        if (!line.trimmed().isEmpty())
            truthGateMissingProof << "- " + line.trimmed();
    };

    const QString anchorLabel = nodeLabel(nodeId);

    for (const QString& vectorNodeId : vectorNodes) {
        const QJsonObject props = truthNodeProps(vectorNodeId);

        const QString vectorId = truthProp(props, "vector_id").toLower();
        const QString category = truthProp(props, "category").toLower();
        const QString severity = truthProp(props, "severity").toLower();
        const QString evidence = truthProp(props, "evidence");
        const QString vectorLabel = nodeLabel(vectorNodeId);
        const QString truthClass = truthClassForVector(vectorId, category);
        const QStringList targets = truthTargetsForVector(vectorNodeId);

        QString decorated = vectorLabel;

        if (!severity.isEmpty())
            decorated += " [" + severity + "]";

        if (!evidence.isEmpty())
            truthGateObservedFacts << QString("- %1: %2").arg(decorated).arg(evidence);

        if (truthClass == "EXPOSURE_ONLY") {
            truthGateExposureOnly << QString("- %1: %2").arg(anchorLabel).arg(decorated);

            if (vectorId.contains("kerberoast")) {
                addMissingProof(QString("%1: credential recovery or successful use is not observed").arg(vectorLabel));
                truthGateDecisions << QString("- %1 remains EXPOSURE_ONLY, not a confirmed path.").arg(vectorLabel);
            } else if (vectorId.contains("asrep")) {
                addMissingProof(QString("%1: credential recovery or successful use is not observed").arg(vectorLabel));
                truthGateDecisions << QString("- %1 remains EXPOSURE_ONLY, not a confirmed path.").arg(vectorLabel);
            } else {
                truthGateDecisions << QString("- %1 is exposure/context until a full observed chain exists.").arg(vectorLabel);
            }

            continue;
        }

        if (truthClass == "CANDIDATE_ATTACK_PATH") {
            if (targets.isEmpty()) {
                truthGateCandidatePaths << QString("- %1 --[%2]--> %3")
                                               .arg(anchorLabel)
                                               .arg("candidate")
                                               .arg(decorated);
            } else {
                for (const QString& target : targets) {
                    truthGateCandidatePaths << QString("- %1 --[%2]--> %3 --[allowed target]--> %4")
                                                   .arg(anchorLabel)
                                                   .arg("candidate")
                                                   .arg(decorated)
                                                   .arg(target);
                }
            }

            addMissingProof(QString("control of %1 is not proven in the current graph").arg(anchorLabel));
            addMissingProof(QString("successful use of %1 toward the allowed target is not observed").arg(anchorLabel));
            truthGateDecisions << QString("- %1 remains CANDIDATE_ATTACK_PATH until source control is observed.").arg(vectorLabel);
            continue;
        }

        truthGateDecisions << QString("- %1 is CONTEXT_ONLY unless connected to a proven control path.").arg(vectorLabel);
    }

    // Direct service SPN edges are observed facts, but not paths.
    for (const QString& serviceNodeId : serviceNodes) {
        truthGateObservedFacts << QString("- %1 has service SPN %2")
                                      .arg(anchorLabel)
                                      .arg(nodeLabel(serviceNodeId));
    }

    // Direct delegation targets are observed LDAP facts, but default route is
    // still candidate unless source control is proven.
    for (const QString& targetNodeId : targetNodes) {
        truthGateObservedFacts << QString("- %1 has related/allowed target %2")
                                      .arg(anchorLabel)
                                      .arg(nodeLabel(targetNodeId));
    }

    truthGateObservedFacts.removeDuplicates();
    truthGateExposureOnly.removeDuplicates();
    truthGateCandidatePaths.removeDuplicates();
    truthGateConfirmedPaths.removeDuplicates();
    truthGateMissingProof.removeDuplicates();
    truthGateDecisions.removeDuplicates();

    auto truthSortLines = [](QStringList& lines) {
        std::sort(lines.begin(), lines.end(),
                  [](const QString& a, const QString& b) {
                      return a.toLower() < b.toLower();
                  });
    };

    truthSortLines(truthGateObservedFacts);
    truthSortLines(truthGateExposureOnly);
    truthSortLines(truthGateCandidatePaths);
    truthSortLines(truthGateConfirmedPaths);
    truthSortLines(truthGateMissingProof);
    truthSortLines(truthGateDecisions);
    // OPSGRAPH_ATTACK_TRUTH_GATE_V1_END




    // OPSGRAPH_ATTACK_LENS_OPERATOR_LABELS_V2_BEGIN
    // Operator-facing labels for Attack Lens.
    //
    // Keep server/cache semantics intact, but render edges with labels that
    // explain meaning instead of internal model names.
    auto attackLensVisualEdge = [&](const QJsonObject& edge) -> QJsonObject {
        QJsonObject visual = edge;
        QJsonObject props = visual.value("properties").toObject();

        const QString type = edgeType(edge);
        const QString dst = edgeTarget(edge);

        auto vectorProp = [&](const QString& key) -> QString {
            if (!nodeCache.contains(dst))
                return QString();

            const QJsonObject node = nodeCache.value(dst);
            const QJsonObject nodeProps = node.value("properties").toObject();
            return nodeProps.value(key).toVariant().toString().trimmed();
        };

        auto setOperatorLabel = [&](const QString& label, const QString& visualClass) {
            props["original_type"] = type;
            props["operator_label"] = label;
            props["display_rights"] = label;
            props["display_label"] = label;

            if (!visualClass.isEmpty())
                props["visual_class"] = visualClass;

            visual["type"] = label;
        };

        auto edgeVectorId = [&]() -> QString {
            QString id = props.value("vector_id").toVariant().toString().trimmed();

            if (id.isEmpty())
                id = vectorProp("vector_id");

            return id.toLower().trimmed();
        };

        auto edgeCategory = [&]() -> QString {
            QString category = props.value("category").toVariant().toString().trimmed();

            if (category.isEmpty())
                category = vectorProp("category");

            return category.toLower().trimmed();
        };

        const QString vectorId = edgeVectorId();
        const QString category = edgeCategory();

        const bool isDelegation =
            vectorId.contains("delegation") ||
            category == "delegation";

        const bool isRbcd =
            vectorId == "rbcd" ||
            vectorId.contains("resource_based_constrained_delegation") ||
            category == "rbcd";

        const bool isKerberosExposure =
            vectorId.contains("kerberoast") ||
            vectorId.contains("asrep") ||
            vectorId.contains("weak_kerberos") ||
            vectorId.contains("admin_count") ||
            category == "kerberos" ||
            category == "privilege";

        if (type == "HasAttackVector") {
            const QString severity = vectorProp("severity").toLower().trimmed();
            if (!severity.isEmpty())
                props["severity"] = severity;

            if (isRbcd) {
                setOperatorLabel("RBCD candidate", "candidate");
            } else if (isDelegation) {
                setOperatorLabel("delegation candidate", "candidate");
            } else if (isKerberosExposure) {
                setOperatorLabel("exposure", "exposure");
            } else {
                setOperatorLabel("signal", "context");
            }
        } else if (type == "RelatedToTarget") {
            if (isRbcd || isDelegation) {
                setOperatorLabel("allowed target", "target");
                props["target_role"] = "delegation_allowed_target";
            } else if (isKerberosExposure) {
                setOperatorLabel("service SPN", "service");
                props["target_role"] = "kerberos_service_spn";
            } else {
                setOperatorLabel("related target", "target");
                props["target_role"] = "related_target";
            }
        } else if (type == "HasSPN") {
            setOperatorLabel("service SPN", "service");
            props["target_role"] = "account_service_principal";
        } else if (type == "DelegatesTo") {
            setOperatorLabel("delegates to", "candidate");
            props["target_role"] = "direct_delegation_target";
        } else if (type == "InDomain") {
            setOperatorLabel("domain", "context");
        }

        visual["properties"] = props;
        return visual;
    };
    // OPSGRAPH_ATTACK_LENS_OPERATOR_LABELS_V2_END


    canvas->clearGraph();

    if (nodeCache.contains(nodeId))
        canvas->upsertNode(nodeCache.value(nodeId));

    for (const QString& id : visibleNodes) {
        if (id == nodeId)
            continue;

        if (!nodeCache.contains(id))
            continue;

        if (isHiddenTokenGroupNode(id))
            continue;

        canvas->upsertNode(nodeCache.value(id));
    }

    for (const QString& id : visibleEdges) {
        if (!edgeCache.contains(id))
            continue;

        const QJsonObject edge = edgeCache.value(id);

        const QString src = edgeSource(edge);
        const QString dst = edgeTarget(edge);

        if (!visibleNodes.contains(src) || !visibleNodes.contains(dst))
            continue;

        if (!nodeCache.contains(src) || !nodeCache.contains(dst))
            continue;

        if (isHiddenTokenGroupNode(src) || isHiddenTokenGroupNode(dst))
            continue;

        canvas->upsertEdge(attackLensVisualEdge(edge));
    }

    canvas->focusNode(nodeId);

    if (detailsPanel) {
        QStringList lines;

        lines << "Attack Lens v1";
        lines << "==============";
        lines << "";
        lines << QString("Anchor: %1").arg(nodeLabel(nodeId));
        lines << QString("Attack vectors: %1").arg(vectorNodes.size());
        lines << QString("Delegation / related targets: %1").arg(targetNodes.size());
        lines << QString("Service principals: %1").arg(serviceNodes.size());
        lines << QString("Direct DelegatesTo edges hidden for clarity: %1").arg(hiddenDirectDelegatesToEdges);
        lines << QString("Rendered nodes: %1").arg(visibleNodes.size());
        lines << QString("Rendered edges: %1").arg(visibleEdges.size());
        lines << "";

        lines << "Meaning";
        lines << "-------";
        lines << "- This lens shows passive LDAP-derived attack surface around the selected identity.";
        lines << "- Exposure edges show risk signals such as Kerberoast candidates.";
        lines << "- Delegation/RBCD candidate edges show possible attack paths that still need proof of control.";
        lines << "- Allowed target and service SPN edges explain what the vector points to.";
        lines << "- It does not execute commands or assume exploitation happened.";
        lines << "";

        // OPSGRAPH_ATTACK_PATH_SEMANTICS_PANEL_V1_BEGIN
        lines << "Attack Path Semantics";
        lines << "=====================";
        lines << QString("Confirmed control paths: %1").arg(confirmedControlPaths.size());
        lines << QString("Candidate attack paths: %1").arg(candidateAttackPaths.size());
        lines << QString("Exposure-only findings: %1").arg(exposureOnlyFindings.size());
        lines << QString("Context-only items: %1").arg(contextOnlyFindings.size());
        lines << "";

        lines << "Confirmed control paths";
        lines << "-----------------------";
        if (confirmedControlPaths.isEmpty()) {
            lines << "(none) — no full observed control chain is proven yet.";
        } else {
            for (const QString& line : confirmedControlPaths)
                lines << line;
            lines << "Class: CONFIRMED_CONTROL_PATH";
            lines << "Why: full observed control chain is present in the graph.";
        }
        lines << "";

        lines << "Candidate attack paths";
        lines << "----------------------";
        if (candidateAttackPaths.isEmpty()) {
            lines << "(none)";
        } else {
            const int maxCandidateLines = 30;
            for (int i = 0; i < candidateAttackPaths.size() && i < maxCandidateLines; ++i)
                lines << candidateAttackPaths.at(i);

            if (candidateAttackPaths.size() > maxCandidateLines)
                lines << QString("- ... %1 more candidate path(s)").arg(candidateAttackPaths.size() - maxCandidateLines);

            lines << "Class: CANDIDATE_ATTACK_PATH";
            lines << "Why: " + classReason("CANDIDATE_ATTACK_PATH") + ".";
        }
        lines << "";

        lines << "Exposure-only findings";
        lines << "----------------------";
        if (exposureOnlyFindings.isEmpty()) {
            lines << "(none)";
        } else {
            const int maxExposureLines = 30;
            for (int i = 0; i < exposureOnlyFindings.size() && i < maxExposureLines; ++i)
                lines << exposureOnlyFindings.at(i);

            if (exposureOnlyFindings.size() > maxExposureLines)
                lines << QString("- ... %1 more exposure finding(s)").arg(exposureOnlyFindings.size() - maxExposureLines);

            lines << "Class: EXPOSURE_ONLY";
            lines << "Why: " + classReason("EXPOSURE_ONLY") + ".";
        }
        lines << "";

        lines << "Context-only items";
        lines << "------------------";
        if (contextOnlyFindings.isEmpty()) {
            lines << "(none)";
        } else {
            const int maxContextLines = 20;
            for (int i = 0; i < contextOnlyFindings.size() && i < maxContextLines; ++i)
                lines << contextOnlyFindings.at(i);

            if (contextOnlyFindings.size() > maxContextLines)
                lines << QString("- ... %1 more context item(s)").arg(contextOnlyFindings.size() - maxContextLines);

            lines << "Class: CONTEXT_ONLY";
            lines << "Why: " + classReason("CONTEXT_ONLY") + ".";
        }
        lines << "";
        // OPSGRAPH_ATTACK_PATH_SEMANTICS_PANEL_V1_END

        // OPSGRAPH_ATTACK_TRUTH_GATE_PANEL_V1_BEGIN
        lines << "Truth Gate";
        lines << "==========";
        lines << QString("Confirmed control paths: %1").arg(truthGateConfirmedPaths.size());
        lines << QString("Candidate attack paths: %1").arg(truthGateCandidatePaths.size());
        lines << QString("Exposure-only findings: %1").arg(truthGateExposureOnly.size());
        lines << QString("Observed facts: %1").arg(truthGateObservedFacts.size());
        lines << "";

        lines << "Operator decision";
        lines << "-----------------";
        if (truthGateDecisions.isEmpty()) {
            lines << "- No attack-vector decision available for this node yet.";
        } else {
            const int maxDecisionLines = 12;
            for (int i = 0; i < truthGateDecisions.size() && i < maxDecisionLines; ++i)
                lines << truthGateDecisions.at(i);

            if (truthGateDecisions.size() > maxDecisionLines)
                lines << QString("- ... %1 more decision note(s)").arg(truthGateDecisions.size() - maxDecisionLines);
        }
        lines << "";

        lines << "Missing proof";
        lines << "-------------";
        if (truthGateMissingProof.isEmpty()) {
            lines << "(none)";
        } else {
            const int maxMissingLines = 12;
            for (int i = 0; i < truthGateMissingProof.size() && i < maxMissingLines; ++i)
                lines << truthGateMissingProof.at(i);

            if (truthGateMissingProof.size() > maxMissingLines)
                lines << QString("- ... %1 more missing proof item(s)").arg(truthGateMissingProof.size() - maxMissingLines);
        }
        lines << "";

        lines << "Candidate attack paths";
        lines << "----------------------";
        if (truthGateCandidatePaths.isEmpty()) {
            lines << "(none)";
        } else {
            const int maxCandidateLines = 12;
            for (int i = 0; i < truthGateCandidatePaths.size() && i < maxCandidateLines; ++i)
                lines << truthGateCandidatePaths.at(i);

            if (truthGateCandidatePaths.size() > maxCandidateLines)
                lines << QString("- ... %1 more candidate path(s)").arg(truthGateCandidatePaths.size() - maxCandidateLines);

            lines << "Class: CANDIDATE_ATTACK_PATH";
            lines << "Rule: observed target relationship exists, but source control is not proven.";
        }
        lines << "";

        lines << "Exposure-only findings";
        lines << "----------------------";
        if (truthGateExposureOnly.isEmpty()) {
            lines << "(none)";
        } else {
            const int maxExposureLines = 12;
            for (int i = 0; i < truthGateExposureOnly.size() && i < maxExposureLines; ++i)
                lines << truthGateExposureOnly.at(i);

            if (truthGateExposureOnly.size() > maxExposureLines)
                lines << QString("- ... %1 more exposure finding(s)").arg(truthGateExposureOnly.size() - maxExposureLines);

            lines << "Class: EXPOSURE_ONLY";
            lines << "Rule: risk signal exists, but no complete control path is proven.";
        }
        lines << "";

        lines << "Observed facts";
        lines << "--------------";
        if (truthGateObservedFacts.isEmpty()) {
            lines << "(none)";
        } else {
            const int maxFactLines = 12;
            for (int i = 0; i < truthGateObservedFacts.size() && i < maxFactLines; ++i)
                lines << truthGateObservedFacts.at(i);

            if (truthGateObservedFacts.size() > maxFactLines)
                lines << QString("- ... %1 more observed fact(s)").arg(truthGateObservedFacts.size() - maxFactLines);
        }
        lines << "";
        // OPSGRAPH_ATTACK_TRUTH_GATE_PANEL_V1_END

        lines << "Observed attack vectors";
        lines << "-----------------------";

        if (vectorNodes.isEmpty()) {
            lines << "No attack-vector graph artifacts observed for this node yet.";
        } else {
            QStringList vectorLines;

            for (const QString& id : vectorNodes) {
                if (!nodeCache.contains(id))
                    continue;

                const QJsonObject node = nodeCache.value(id);
                const QJsonObject props = node.value("properties").toObject();

                QString line = "- " + node.value("label").toString(id);

                const QString severity = props.value("severity").toString();
                const QString category = props.value("category").toString();

                if (!severity.isEmpty())
                    line += " [" + severity + "]";

                if (!category.isEmpty())
                    line += " (" + category + ")";

                vectorLines << line;
            }

            std::sort(vectorLines.begin(), vectorLines.end(),
                      [](const QString& a, const QString& b) {
                          return a.toLower() < b.toLower();
                      });

            for (const QString& line : vectorLines)
                lines << line;
        }

        lines << "";
        lines << "Targets";
        lines << "-------";

        if (targetNodes.isEmpty() && serviceNodes.isEmpty()) {
            lines << "No service/delegation target nodes observed yet.";
        } else {
            QStringList targets;

            for (const QString& id : targetNodes)
                targets << "- " + nodeLabel(id);

            for (const QString& id : serviceNodes)
                targets << "- " + nodeLabel(id);

            targets.removeDuplicates();
            std::sort(targets.begin(), targets.end(),
                      [](const QString& a, const QString& b) {
                          return a.toLower() < b.toLower();
                      });

            const int maxLines = 30;
            for (int i = 0; i < targets.size() && i < maxLines; ++i)
                lines << targets.at(i);

            if (targets.size() > maxLines)
                lines << QString("- ... %1 more target(s)").arg(targets.size() - maxLines);
        }

        lines << "";
        lines << "Next data that improves this lens";
        lines << "---------------------------------";
        lines << "- Query group membership for the service account.";
        lines << "- Query ACLs around this account and its target services.";
        lines << "- Query delegation/RBCD attributes on nearby computers.";
        lines << "- Add trust/forest evidence for cross-domain pathing.";

        detailsPanel->setPlainText(lines.join("\n"));
    }
}
// OPSGRAPH_ATTACK_LENS_V1_END


void OperationGraphTab::renderAclLensFromCache(const QString& nodeId)
{
    if (!canvas)
        return;

    if (nodeId.isEmpty() || !nodeCache.contains(nodeId))
        return;

    // OPSGRAPH_ACL_LENS_V3_MULTIHOP_BEGIN
    auto edgeSource = [](const QJsonObject& edge) -> QString {
        return edge.value("source").toString(edge.value("source_id").toString());
    };

    auto edgeTarget = [](const QJsonObject& edge) -> QString {
        return edge.value("target").toString(edge.value("target_id").toString());
    };

    auto edgeType = [](const QJsonObject& edge) -> QString {
        return edge.value("type").toString();
    };

    auto nodeLabel = [&](const QString& id) -> QString {
        if (!nodeCache.contains(id))
            return id;
        return nodeCache.value(id).value("label").toString(id);
    };

    auto rightsText = [](const QJsonObject& edge) -> QString {
        const QJsonObject props = edge.value("properties").toObject();
        const QJsonValue rightsValue = props.value("rights");

        if (rightsValue.isArray()) {
            QStringList out;
            const QJsonArray arr = rightsValue.toArray();

            for (const QJsonValue& v : arr) {
                const QString s = v.toString().trimmed();
                if (!s.isEmpty())
                    out << s;
            }

            return out.join(", ");
        }

        if (rightsValue.isString())
            return rightsValue.toString();

        return props.value("right").toString();
    };

    auto controlWeight = [&](const QString& rights) -> int {
        const QString r = rights.toLower();

        if (r.contains("genericall"))
            return 100;
        if (r.contains("writedacl"))
            return 95;
        if (r.contains("writeowner"))
            return 95;
        if (r.contains("genericwrite"))
            return 90;
        if (r.contains("forcechangepassword"))
            return 88;
        if (r.contains("addmember"))
            return 86;
        if (r.contains("allowedtoact"))
            return 86;
        if (r.contains("writespn"))
            return 82;
        if (r.contains("allextendedrights"))
            return 76;
        if (r.contains("writeproperty"))
            return 55;
        if (r.contains("extendedright"))
            return 45;

        return 0;
    };

    auto isControlRight = [&](const QString& rights) -> bool {
        return controlWeight(rights) >= 45;
    };

    auto isPrincipalType = [&](const QString& id) -> bool {
        if (!nodeCache.contains(id))
            return false;

        const QString t = nodeCache.value(id).value("type").toString();
        return t == "User" || t == "Group";
    };

    auto isHiddenTokenGroupNode = [&](const QString& id) -> bool {
        if (showTokenGroups)
            return false;

        if (id == nodeId)
            return false;

        if (!nodeCache.contains(id))
            return false;

        return opsGraphShouldHideTokenGroup(nodeCache.value(id));
    };

    int totalAclRightEdges = 0;
    for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
        if (it.value().value("type").toString() == "ACLRight")
            totalAclRightEdges++;
    }

    if (totalAclRightEdges == 0) {
        canvas->clearGraph();
        canvas->upsertNode(nodeCache.value(nodeId));
        canvas->focusNode(nodeId);

        if (detailsPanel) {
            QStringList lines;
            lines << "Observed Path Lens v3";
            lines << "=====================";
            lines << "";
            lines << QString("Focus: %1").arg(nodeLabel(nodeId));
            lines << "";
            lines << "No ACLRight edges observed yet.";
            detailsPanel->setPlainText(lines.join("\n"));
        }

        return;
    }

    QSet<QString> visibleNodes;
    QSet<QString> visibleEdges;
    QSet<QString> effectivePrincipals;
    QSet<QString> frontier;
    QSet<QString> expandedPrincipals;
    QSet<QString> incomingControllers;

    int selfObjectAclPaths = 0;

    visibleNodes.insert(nodeId);
    effectivePrincipals.insert(nodeId);
    frontier.insert(nodeId);

    auto addMemberOfClosure = [&](const QSet<QString>& starts, int maxDepth) {
        QSet<QString> current = starts;

        for (int depth = 0; depth < maxDepth; ++depth) {
            QSet<QString> next;

            for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
                const QString edgeId = it.key();
                const QJsonObject edge = it.value();

                if (edgeType(edge) != "MemberOf")
                    continue;

                const QString src = edgeSource(edge);
                const QString dst = edgeTarget(edge);

                if (!current.contains(src))
                    continue;

                if (!nodeCache.contains(dst))
                    continue;

                if (isHiddenTokenGroupNode(dst))
                    continue;

                visibleEdges.insert(edgeId);
                visibleNodes.insert(src);
                visibleNodes.insert(dst);

                if (!effectivePrincipals.contains(dst)) {
                    effectivePrincipals.insert(dst);
                    next.insert(dst);
                }
            }

            if (next.isEmpty())
                break;

            current = next;
        }
    };

    addMemberOfClosure(QSet<QString>{nodeId}, 5);
    frontier = effectivePrincipals;

    struct PathItem {
        QString edgeId;
        QString src;
        QString dst;
        QString rights;
        int depth = 0;
        int weight = 0;
        int highValueScore = 0;
        QString highValueTier;
    };

    QList<PathItem> observedPaths;
    QSet<QString> seenAclEdges;
    QSet<QString> controlledPrincipals;

    const int maxDepth = 4;
    const int maxRenderedPaths = 80;

    for (int depth = 0; depth < maxDepth; ++depth) {
        QSet<QString> nextFrontier;

        for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
            const QString edgeId = it.key();
            const QJsonObject edge = it.value();

            if (edgeType(edge) != "ACLRight")
                continue;

            if (seenAclEdges.contains(edgeId))
                continue;

            const QString src = edgeSource(edge);
            const QString dst = edgeTarget(edge);

            if (!frontier.contains(src) && !effectivePrincipals.contains(src))
                continue;

            const QString rights = rightsText(edge);
            const int weight = controlWeight(rights);
            const QJsonObject edgeProps = edge.value("properties").toObject();
            const QString controlClass = edgeProps.value("control_class").toString();
            const bool attackPathCandidate = edgeProps.value("attack_path_candidate").toBool(false);

            if (controlClass == "self_noise" || controlClass == "read_only" || controlClass == "low_signal_property")
                continue;

            if (!attackPathCandidate && !isControlRight(rights))
                continue;

            if (dst == nodeId) {
                selfObjectAclPaths++;
                seenAclEdges.insert(edgeId);
                continue;
            }

            PathItem item;
            item.edgeId = edgeId;
            item.src = src;
            item.dst = dst;
            item.rights = rights;
            item.depth = depth + 1;
            item.weight = weight;

            const OpsGraphHighValueResult hv = opsGraphComputeHighValueV1(dst, nodeCache, edgeCache);
            item.highValueScore = hv.score;
            item.highValueTier = hv.tier;

            observedPaths.append(item);
            seenAclEdges.insert(edgeId);

            visibleEdges.insert(edgeId);
            visibleNodes.insert(src);
            visibleNodes.insert(dst);

            // If the ACL target is a user/group, treat it as a newly controlled
            // principal for path reasoning. This is an observed path candidate,
            // not automatic exploitation.
            if (isPrincipalType(dst) && !controlledPrincipals.contains(dst)) {
                controlledPrincipals.insert(dst);
                nextFrontier.insert(dst);
                effectivePrincipals.insert(dst);

                QSet<QString> newStart;
                newStart.insert(dst);
                addMemberOfClosure(newStart, 5);
            }
        }

        if (nextFrontier.isEmpty())
            break;

        frontier = nextFrontier;
    }

    // Count incoming controllers, but keep them hidden in Operator Mode.
    for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
        const QJsonObject edge = it.value();

        if (edgeType(edge) != "ACLRight")
            continue;

        const QString src = edgeSource(edge);
        const QString dst = edgeTarget(edge);

        if (dst != nodeId)
            continue;

        if (effectivePrincipals.contains(src))
            continue;

        if (isHiddenTokenGroupNode(src))
            continue;

        incomingControllers.insert(src);
    }

    std::sort(observedPaths.begin(), observedPaths.end(),
              [](const PathItem& a, const PathItem& b) {
                  if (a.highValueScore != b.highValueScore)
                      return a.highValueScore > b.highValueScore;
                  if (a.weight != b.weight)
                      return a.weight > b.weight;
                  if (a.depth != b.depth)
                      return a.depth < b.depth;
                  return a.dst < b.dst;
              });

    // Domain context for visible nodes.
    bool changed = true;
    while (changed) {
        changed = false;

        for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
            const QString edgeId = it.key();
            const QJsonObject edge = it.value();

            if (edgeType(edge) != "InDomain")
                continue;

            const QString src = edgeSource(edge);
            const QString dst = edgeTarget(edge);

            if (visibleNodes.contains(src) && !visibleNodes.contains(dst)) {
                visibleNodes.insert(dst);
                visibleEdges.insert(edgeId);
                changed = true;
            }
        }
    }

    // Optional SPN context for path targets.
    if (showSpnNodes) {
        QSet<QString> pathTargets;
        for (const PathItem& item : observedPaths)
            pathTargets.insert(item.dst);

        for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
            const QString edgeId = it.key();
            const QJsonObject edge = it.value();

            if (edgeType(edge) != "HasSPN")
                continue;

            const QString src = edgeSource(edge);
            const QString dst = edgeTarget(edge);

            if (!pathTargets.contains(src))
                continue;

            visibleEdges.insert(edgeId);
            visibleNodes.insert(src);
            visibleNodes.insert(dst);
        }
    }

    canvas->clearGraph();

    if (nodeCache.contains(nodeId))
        canvas->upsertNode(nodeCache.value(nodeId));

    int renderedPathEdges = 0;
    QSet<QString> allowedPathEdges;

    for (const PathItem& item : observedPaths) {
        if (renderedPathEdges >= maxRenderedPaths)
            break;

        allowedPathEdges.insert(item.edgeId);
        renderedPathEdges++;
    }

    for (const QString& id : visibleNodes) {
        if (id == nodeId)
            continue;

        if (!nodeCache.contains(id))
            continue;

        if (isHiddenTokenGroupNode(id))
            continue;

        canvas->upsertNode(nodeCache.value(id));
    }

    for (const QString& id : visibleEdges) {
        if (!edgeCache.contains(id))
            continue;

        const QJsonObject edge = edgeCache.value(id);
        const QString type = edgeType(edge);

        if (type == "ACLRight" && !allowedPathEdges.contains(id))
            continue;

        if (type == "HasSPN" && !showSpnNodes)
            continue;

        const QString src = edgeSource(edge);
        const QString dst = edgeTarget(edge);

        if (!visibleNodes.contains(src) || !visibleNodes.contains(dst))
            continue;

        if (!nodeCache.contains(src) || !nodeCache.contains(dst))
            continue;

        if (isHiddenTokenGroupNode(src) || isHiddenTokenGroupNode(dst))
            continue;

        canvas->upsertEdge(edge);
    }

    canvas->focusNode(nodeId);

    if (detailsPanel) {
        QStringList lines;

        lines << "Observed Path Lens v3";
        lines << "=====================";
        lines << "";
        lines << QString("Focus: %1").arg(nodeLabel(nodeId));
        lines << QString("Effective principals: %1").arg(effectivePrincipals.size());
        lines << QString("Controlled principals discovered: %1").arg(controlledPrincipals.size());
        lines << QString("Observed control paths: %1").arg(observedPaths.size());
        lines << QString("Rendered path edges: %1").arg(qMin(observedPaths.size(), maxRenderedPaths));
        lines << QString("Self-object ACL paths hidden: %1").arg(selfObjectAclPaths);
        lines << QString("Incoming controllers hidden: %1").arg(incomingControllers.size());
        lines << "";

        lines << "Meaning";
        lines << "-------";
        lines << "- This lens follows observed MemberOf and ACLRight evidence.";
        lines << "- It shows control-path candidates only; it does not assume exploitation happened.";
        lines << "- Self-object and incoming control are hidden by default to reduce noise.";
        lines << "";

        lines << "Top observed control paths";
        lines << "--------------------------";

        if (observedPaths.isEmpty()) {
            lines << "No outgoing multi-hop control path observed from this identity yet.";
        } else {
            const int maxLines = 25;

            for (int i = 0; i < observedPaths.size() && i < maxLines; ++i) {
                const PathItem& item = observedPaths.at(i);

                QString hvText;
                if (item.highValueScore > 0)
                    hvText = QString(" | HV %1/%2").arg(item.highValueScore).arg(item.highValueTier);

                lines << QString("[%1 hop] %2 --[%3]--> %4%5")
                             .arg(item.depth)
                             .arg(nodeLabel(item.src))
                             .arg(item.rights.isEmpty() ? QString("ACLRight") : item.rights)
                             .arg(nodeLabel(item.dst))
                             .arg(hvText);
            }

            if (observedPaths.size() > maxLines)
                lines << QString("... %1 more path edge(s)").arg(observedPaths.size() - maxLines);
        }

        lines << "";
        lines << "Next data that improves this lens";
        lines << "---------------------------------";
        lines << "- More ACLRight edges from targeted ACL collection.";
        lines << "- SPN/delegation/adminCount LDAP attributes.";
        lines << "- Session/local admin evidence from completed task output.";
        lines << "- Trust/forest edges for cross-domain pathing.";

        detailsPanel->setPlainText(lines.join("\n"));
    }
    // OPSGRAPH_ACL_LENS_V3_MULTIHOP_END
}





void OperationGraphTab::renderCoreViewFromCache()
{
    if (!canvas)
        return;

    canvas->clearGraph();

    QSet<QString> visibleNodes;
    QSet<QString> visibleEdges;

    auto addNode = [&](const QString& id) {
        if (id.isEmpty())
            return;

        const QJsonObject node = nodeCache.value(id);
        if (!shouldRenderNodeOnCanvas(node))
            return;

        visibleNodes.insert(id);
    };

    auto addEdge = [&](const QString& edgeId, const QJsonObject& edge) {
        if (edgeId.isEmpty())
            return;

        const QString source = opsGraphEdgeSource(edge);
        const QString target = opsGraphEdgeTarget(edge);

        if (source.isEmpty() || target.isEmpty())
            return;

        addNode(source);
        addNode(target);

        if (visibleNodes.contains(source) && visibleNodes.contains(target))
            visibleEdges.insert(edgeId);
    };

    // 1) Start from live/stored agent context.
    for (auto it = nodeCache.begin(); it != nodeCache.end(); ++it) {
        const QJsonObject node = it.value();
        if (node.value("type").toString() == "Agent") {
            const QString id = node.value("id").toString(it.key());
            addNode(id);
        }
    }

    // 2) Agent -> RunningAs / RunningOn / Impersonating.
    for (auto it = edgeCache.begin(); it != edgeCache.end(); ++it) {
        const QJsonObject edge = it.value();
        const QString edgeId = edge.value("id").toString(it.key());
        const QString type = edge.value("type").toString();
        const QString source = opsGraphEdgeSource(edge);
        const QString target = opsGraphEdgeTarget(edge);

        if (type != "RunningAs" && type != "RunningOn" && type != "Impersonating")
            continue;

        if (visibleNodes.contains(source) || visibleNodes.contains(target))
            addEdge(edgeId, edge);
    }

    // 3) Direct context from visible users/computers/groups:
    //    MemberOf and InDomain only.
    bool changed = true;
    while (changed) {
        changed = false;

        for (auto it = edgeCache.begin(); it != edgeCache.end(); ++it) {
            const QJsonObject edge = it.value();
            const QString edgeId = edge.value("id").toString(it.key());
            const QString type = edge.value("type").toString();
            const QString source = opsGraphEdgeSource(edge);
            const QString target = opsGraphEdgeTarget(edge);

            if (source.isEmpty() || target.isEmpty())
                continue;

            if (!visibleNodes.contains(source))
                continue;

            if (type != "MemberOf" && type != "InDomain")
                continue;

            const int before = visibleNodes.size();
            addEdge(edgeId, edge);
            if (visibleNodes.size() > before)
                changed = true;
        }
    }

    // OPSGRAPH_SPN_LENS_CORE_VIEW_V2_BEGIN
    // Core View SPN Lens: include only SPNs attached to already-visible
    // operation-context users/computers, with a cap to avoid inventory dumps
    // turning Core View into Show All.
    if (showSpnNodes) {
        QSet<QString> coreSpnNodeIds;
        const int maxCoreSpnNodes = 12;

        for (auto it = edgeCache.begin(); it != edgeCache.end(); ++it) {
            const QJsonObject edge = it.value();
            const QString edgeId = edge.value("id").toString(it.key());
            const QString type = edge.value("type").toString();
            const QString source = opsGraphEdgeSource(edge);
            const QString target = opsGraphEdgeTarget(edge);

            if (type != "HasSPN")
                continue;

            if (source.isEmpty() || target.isEmpty())
                continue;

            if (!visibleNodes.contains(source))
                continue;

            const bool targetIsSpn = nodeCache.contains(target) &&
                nodeCache.value(target).value("type").toString()
                    .compare("SPN", Qt::CaseInsensitive) == 0;

            if (targetIsSpn) {
                if (coreSpnNodeIds.contains(target)) {
                    visibleEdges.insert(edgeId);
                    continue;
                }

                if (coreSpnNodeIds.size() >= maxCoreSpnNodes)
                    continue;
            }

            addEdge(edgeId, edge);

            if (targetIsSpn && visibleNodes.contains(target))
                coreSpnNodeIds.insert(target);
        }
    }
    // OPSGRAPH_SPN_LENS_CORE_VIEW_V2_END

    // 4) Render nodes.
    for (const QString& id : visibleNodes) {
        const QJsonObject node = nodeCache.value(id);
        if (!node.isEmpty())
            canvas->upsertNode(node);
    }

    // 5) Render edges.
    for (const QString& id : visibleEdges) {
        const QJsonObject edge = edgeCache.value(id);
        if (!edge.isEmpty())
            canvas->upsertEdge(edge);
    }

    if (detailsPanel && selectedNodeId.isEmpty() && selectedEdgeId.isEmpty()) {
        QString out;
        out += "Core View\n";
        out += "=========\n\n";
        out += "Showing current operation context only:\n";
        out += "- Agent -> RunningAs -> User\n";
        out += "- Agent -> RunningOn -> Computer\n";
        out += "- User -> MemberOf -> Groups\n";
        out += "- Entities -> InDomain -> Domain\n\n";
        out += "Use Show All only for debugging or full overview.";
        detailsPanel->setText(out);
    }
}

QString OperationGraphTab::tokenGroupCategory(const QJsonObject& node) const
{
    const QJsonObject props = node.value("properties").toObject();

    const QString id = node.value("id").toString().toLower();
    const QString label = node.value("label").toString().toLower();
    const QString domain = props.value("domain").toString().toLower();
    const QString name = props.value("name").toString().toLower();
    const QString sid = props.value("sid").toString().toLower();
    const QString groupType = props.value("type").toString().toLower();

    if (domain == "mandatory label" ||
        label.startsWith("mandatory label\\") ||
        sid.startsWith("s-1-16-") ||
        groupType == "label")
        return "Integrity Labels";

    if (domain == "builtin" ||
        label.startsWith("builtin\\") ||
        name == "none" ||
        label.endsWith("\\none") ||
        id.endsWith(":none"))
        return "Local Groups";

    return "Well-known SIDs";
}

void OperationGraphTab::redrawCanvasFromCache()
{
    if (!canvas)
        return;

    if (coreMode) {
        renderCoreViewFromCache();
        return;
    }

    // OPSGRAPH_SPN_CANVAS_EXPLOSION_GUARD_V2_FOCUS_BEGIN
    // Focused view is a scoped lens. Do not briefly render the full graph before
    // rematerializing focus, especially after broad LDAP/SPN inventory queries.
    if (focusMode && !focusedNodeId.isEmpty()) {
        renderFocusNeighborhoodFromCache(focusedNodeId);
        return;
    }
    // OPSGRAPH_SPN_CANVAS_EXPLOSION_GUARD_V2_FOCUS_END

    canvas->clearGraph();

    QSet<QString> renderedNodeIds;

    // OPSGRAPH_SPN_CANVAS_EXPLOSION_GUARD_V2_BEGIN
    // SPN nodes are inventory-heavy. Store and score all SPN evidence, but do
    // not let broad LDAP queries explode the canvas. Generic full graph rendering
    // gets a small deterministic cap; focused/core views handle attached SPNs
    // separately as scoped lenses.
    QSet<QString> permittedSpnNodeIds;

    auto isSpnNodeId = [&](const QString& nodeId) -> bool {
        if (nodeId.isEmpty() || !nodeCache.contains(nodeId))
            return false;

        return nodeCache.value(nodeId).value("type").toString()
            .compare("SPN", Qt::CaseInsensitive) == 0;
    };

    auto includeDirectSpnsForSource = [&](const QString& sourceId, int maxSpns) {
        if (sourceId.isEmpty())
            return;

        for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
            const QJsonObject edge = it.value();

            if (edge.value("type").toString() != "HasSPN")
                continue;

            if (opsGraphEdgeSource(edge) != sourceId)
                continue;

            const QString target = opsGraphEdgeTarget(edge);
            if (!isSpnNodeId(target))
                continue;

            if (permittedSpnNodeIds.size() >= maxSpns)
                return;

            permittedSpnNodeIds.insert(target);
        }
    };

    if (showSpnNodes) {
        includeDirectSpnsForSource(focusedNodeId, 20);
        includeDirectSpnsForSource(selectedNodeId, 20);

        // Explicit Show All mode may include some SPNs, but never all of them.
        // This keeps broad servicePrincipalName=* inventory usable.
        if (!coreMode && !focusMode) {
            QStringList allSpnIds;

            for (auto it = nodeCache.constBegin(); it != nodeCache.constEnd(); ++it) {
                const QJsonObject n = it.value();
                const QString nid = n.value("id").toString(it.key());

                if (n.value("type").toString().compare("SPN", Qt::CaseInsensitive) == 0)
                    allSpnIds << nid;
            }

            std::sort(allSpnIds.begin(), allSpnIds.end(),
                      [](const QString& a, const QString& b) {
                          return a.toLower() < b.toLower();
                      });

            const int maxGenericSpnNodes = 30;
            for (int i = 0; i < allSpnIds.size() && i < maxGenericSpnNodes; ++i)
                permittedSpnNodeIds.insert(allSpnIds.at(i));
        }
    }
    // OPSGRAPH_SPN_CANVAS_EXPLOSION_GUARD_V2_END

    for (auto it = nodeCache.begin(); it != nodeCache.end(); ++it) {
        const QJsonObject node = it.value();
        const QString id = node.value("id").toString(it.key());

        const QString nodeType = node.value("type").toString();

        if (nodeType.compare("SPN", Qt::CaseInsensitive) == 0 &&
            (!showSpnNodes || !permittedSpnNodeIds.contains(id)))
            continue;

        if (!shouldRenderNodeOnCanvas(node))
            continue;

        canvas->upsertNode(node);

        if (!id.isEmpty())
            renderedNodeIds.insert(id);
    }

    for (auto it = edgeCache.begin(); it != edgeCache.end(); ++it) {
        const QJsonObject edge = it.value();
        const QString source = opsGraphEdgeSource(edge);
        const QString target = opsGraphEdgeTarget(edge);

        if (!renderedNodeIds.contains(source) || !renderedNodeIds.contains(target))
            continue;

        canvas->upsertEdge(edge);
    }

    if (focusMode && !focusedNodeId.isEmpty())
        renderFocusNeighborhoodFromCache(focusedNodeId);
}


void OperationGraphTab::onToggleSpnNodes()
{
    showSpnNodes = !showSpnNodes;

    if (spnButton)
        spnButton->setText(showSpnNodes ? "SPNs: On" : "SPNs: Off");

    redrawCanvasFromCache();
    rebuildEntityTree();
    // OPSGRAPH_TREE_SEARCH_PERSIST_V1
    // Entity tree is rebuilt after live delta, lens toggles, Core View, etc.
    // Preserve the active search filter instead of snapping the tree back to
    // the default unfiltered state.
    if (searchBar && !searchBar->text().trimmed().isEmpty())
        onSearchChanged(searchBar->text());

    QString status;
    status += showSpnNodes
        ? "SPN lens enabled.\n\nSPN facts are visible as a scoped/capped lens. Core and Focused views show relevant attached SPNs; broad inventory remains stored in the tree, properties, and evidence without exploding the canvas."
        : "SPN lens hidden.\n\nSPN facts remain stored in node properties/evidence, but graph noise is reduced.";

    if (!selectedNodeId.isEmpty() && nodeCache.contains(selectedNodeId)) {
        renderNodeDetails(nodeCache.value(selectedNodeId));
        QString out = detailsPanel->toPlainText();
        out += "\nView\n";
        out += "----\n";
        out += status + "\n";
        detailsPanel->setText(out);
        return;
    }

    if (!selectedEdgeId.isEmpty() && edgeCache.contains(selectedEdgeId)) {
        renderEdgeDetails(edgeCache.value(selectedEdgeId));
        QString out = detailsPanel->toPlainText();
        out += "\nView\n";
        out += "----\n";
        out += status + "\n";
        detailsPanel->setText(out);
        return;
    }

    detailsPanel->setText(status);
}

void OperationGraphTab::onToggleTokenGroups()
{
    showTokenGroups = !showTokenGroups;

    if (tokenGroupsButton)
        tokenGroupsButton->setText(showTokenGroups ? "Token Groups: On" : "Token Groups: Off");

    redrawCanvasFromCache();
    rebuildEntityTree();
    // OPSGRAPH_TREE_SEARCH_PERSIST_V1
    // Entity tree is rebuilt after live delta, lens toggles, Core View, etc.
    // Preserve the active search filter instead of snapping the tree back to
    // the default unfiltered state.
    if (searchBar && !searchBar->text().trimmed().isEmpty())
        onSearchChanged(searchBar->text());

    QString status;
    status += showTokenGroups
        ? "Token Groups enabled.\n\nBUILTIN, NT AUTHORITY, Everyone and integrity-label token context is visible on the graph."
        : "Token Groups hidden.\n\nToken context remains available in the selected user details and evidence drawer.";

    if (!selectedNodeId.isEmpty() && nodeCache.contains(selectedNodeId)) {
        renderNodeDetails(nodeCache.value(selectedNodeId));
        QString out = detailsPanel->toPlainText();
        out += "\nView\n";
        out += "----\n";
        out += status + "\n";
        detailsPanel->setText(out);
        return;
    }

    if (!selectedEdgeId.isEmpty() && edgeCache.contains(selectedEdgeId)) {
        renderEdgeDetails(edgeCache.value(selectedEdgeId));
        QString out = detailsPanel->toPlainText();
        out += "\nView\n";
        out += "----\n";
        out += status + "\n";
        detailsPanel->setText(out);
        return;
    }

    detailsPanel->setText(status);
}



// OPSGRAPH_ATTACK_LENS_SLOT_V1_BEGIN
void OperationGraphTab::onAttackLens()
{
    QString nodeId = focusedNodeId;

    if (nodeId.isEmpty())
        nodeId = selectedNodeId;

    if (!nodeId.isEmpty() && nodeCache.contains(nodeId)) {
        const QJsonObject selected = nodeCache.value(nodeId);
        if (selected.value("type").toString() == "AttackVector") {
            const QJsonObject props = selected.value("properties").toObject();
            const QString ownerId = props.value("owner_id").toString();

            if (!ownerId.isEmpty() && nodeCache.contains(ownerId))
                nodeId = ownerId;
        }
    }

    if (nodeId.isEmpty()) {
        // No explicit selection: pick the strongest node with attack_vectors.
        int bestScore = -1;
        QString bestId;

        for (auto it = nodeCache.constBegin(); it != nodeCache.constEnd(); ++it) {
            const QJsonObject node = it.value();
            const QJsonObject props = node.value("properties").toObject();
            const QJsonArray vectors = props.value("attack_vectors").toArray();

            if (vectors.isEmpty())
                continue;

            const OpsGraphHighValueResult hv = opsGraphComputeHighValueV1(it.key(), nodeCache, edgeCache);
            const OpsGraphRelevanceResult rel = opsGraphComputeNodeRelevanceV1(it.key(), nodeCache, edgeCache);
            const int score = hv.score + rel.score + (vectors.size() * 20);

            if (score > bestScore) {
                bestScore = score;
                bestId = it.key();
            }
        }

        nodeId = bestId;
    }

    if (nodeId.isEmpty() || !nodeCache.contains(nodeId))
        return;

    selectedNodeId = nodeId;
    selectedEdgeId.clear();
    focusedNodeId = nodeId;

    focusMode = true;
    coreMode = false;

    const QJsonObject node = nodeCache.value(nodeId);
    const QString label = node.value("label").toString(nodeId);

    if (focusButton)
        focusButton->setText(QString("Focused: %1").arg(label));

    if (pathButton)
        pathButton->setText("Attack Vectors ▾");

    renderAttackLensFromCache(nodeId);
    fetchNodeEvidence(nodeId);
}
// OPSGRAPH_ATTACK_LENS_SLOT_V1_END


void OperationGraphTab::onPathToHighValue()
{
    // ACL Lens is a focus/lens view, so prefer the toolbar-focused node.
    // selectedNodeId can point to a canvas/domain node after selection changes.
    QString nodeId = focusedNodeId;

    if (nodeId.isEmpty())
        nodeId = selectedNodeId;

    if (nodeId.isEmpty() || !nodeCache.contains(nodeId))
        return;

    selectedNodeId = nodeId;
    selectedEdgeId.clear();
    focusedNodeId = nodeId;

    focusMode = true;
    coreMode = false;

    const QJsonObject node = nodeCache.value(nodeId);
    const QString label = node.value("label").toString(nodeId);

    if (focusButton)
        focusButton->setText(QString("Focused: %1").arg(label));

    if (pathButton)
        pathButton->setText("Attack Vectors ▾");

    renderAclLensFromCache(nodeId);
}







void OperationGraphTab::onRefreshTimer()
{
    if (!liveMode)
        return;

    if (!hasLoadedState || cursor <= 0)
        loadInitialState();
    else
        loadDeltaState();
}


void OperationGraphTab::onToggleLive()
{
    liveMode = !liveMode;

    if (liveButton)
        liveButton->setText(liveMode ? "Live: On" : "Live: Off");

    if (liveMode) {
        detailsPanel->setText("Live refresh enabled.");
        loadInitialState();
    } else {
        detailsPanel->setText("Live refresh paused. Use Refresh to rebuild/read current task logs.");
    }
}

void OperationGraphTab::onRefreshGraph()
{
    rebuildGraphRemote();
}

void OperationGraphTab::rebuildGraphRemote()
{
    if (!profile || !network) {
        detailsPanel->setText("Cannot refresh OpsGraph: missing auth profile.");
        return;
    }

    detailsPanel->setText("Re-reading completed task logs into OpsGraph...");

    QNetworkRequest request(QUrl(apiUrl("/opsgraph/rebuild")));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", QByteArray("Bearer ") + profile->GetAccessToken().toUtf8());

    QNetworkReply* reply = network->post(request, QByteArray("{}"));

    connect(reply, &QNetworkReply::sslErrors, reply, [reply](const QList<QSslError>&) {
        reply->ignoreSslErrors();
    });

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() != QNetworkReply::NoError) {
            detailsPanel->setText("OpsGraph refresh failed:\n" + reply->errorString());
            reply->deleteLater();
            return;
        }

        const QByteArray body = reply->readAll();
        QJsonParseError parseError;
        const QJsonDocument doc = QJsonDocument::fromJson(body, &parseError);

        if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
            detailsPanel->setText("OpsGraph refresh returned invalid JSON:\n" + QString::fromUtf8(body));
            reply->deleteLater();
            return;
        }

        const QJsonObject root = doc.object();
        const int processed = root.value("processed").toInt(0);

        detailsPanel->setText(QString("OpsGraph refresh complete.\nProcessed completed tasks: %1").arg(processed));

        reply->deleteLater();
        loadInitialState();
    });
}

void OperationGraphTab::onClearGraph()
{
    clearGraphRemote();
}

void OperationGraphTab::clearGraphRemote()
{
    if (!profile || !network) {
        detailsPanel->setText("Cannot clear OpsGraph: missing auth profile.");
        return;
    }

    detailsPanel->setText("Clearing OpsGraph...");

    QNetworkRequest request(QUrl(apiUrl("/opsgraph/clear")));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", QByteArray("Bearer ") + profile->GetAccessToken().toUtf8());

    QNetworkReply* reply = network->post(request, QByteArray("{}"));

    connect(reply, &QNetworkReply::sslErrors, reply, [reply](const QList<QSslError>&) {
        reply->ignoreSslErrors();
    });

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const QByteArray body = reply->readAll();
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

        if (reply->error() != QNetworkReply::NoError) {
            detailsPanel->setText(QString("Clear Graph failed [%1]:\n%2\n\n%3")
                .arg(status)
                .arg(reply->errorString())
                .arg(QString::fromUtf8(body)));
            reply->deleteLater();
            return;
        }

        QJsonParseError parseError;
        const QJsonDocument doc = QJsonDocument::fromJson(body, &parseError);
        if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
            detailsPanel->setText("Clear Graph returned invalid JSON:\n\n" + QString::fromUtf8(body));
            reply->deleteLater();
            return;
        }

        const QJsonObject root = doc.object();
        if (!root.value("ok").toBool(false)) {
            detailsPanel->setText("Clear Graph returned error:\n\n" + QString::fromUtf8(body));
            reply->deleteLater();
            return;
        }

        cursor = 0;
        selectedNodeId.clear();
        nodeCache.clear();
        hasLoadedState = false;
        canvas->clearGraph();
        detailsPanel->setText("OpsGraph cleared.\n\nNodes: 0\nEdges: 0");
        reply->deleteLater();
    });
}


QString OperationGraphTab::entityRootTitle(const QString& type) const
{
    if (type == "Agent") return "Agents";
    if (type == "User") return "Users";
    if (type == "Computer") return "Computers";
    if (type == "Domain") return "Domains";

    // AD/domain groups only.
    if (type == "DomainGroup") return "Groups";

    // Local token/security context.
    if (type == "LocalGroup") return "Local Groups";
    if (type == "WellKnownPrincipal") return "Well-known SIDs";
    if (type == "IntegrityLabel") return "Integrity Labels";

    if (type == "Credential") return "Credentials";
    if (type == "Session") return "Sessions";
    if (type == "Service") return "Services";
    if (type == "Share") return "Shares";
    if (type == "Trust") return "Trusts";
    return type.isEmpty() ? QString("Unknown") : type + "s";
}

QString OperationGraphTab::entityCategory(const QJsonObject& node) const
{

    if (opsGraphIsDelegationTargetNodeV5(node))
        return "Delegation Targets";

    const QString type = node.value("type").toString();

    if (type == "SPN")
        return showSpnNodes ? "SPNs" : QString();

    if (type == "Agent")
        return "Agents";
    if (type == "User")
        return "Users";
    if (type == "Computer")
        return "Computers";
    if (type == "Domain")
        return "Domains";
    if (type == "Credential")
        return "Credentials";
    if (type == "Session")
        return "Sessions";
    if (type == "Service")
        return "Services";
    if (type == "Share")
        return "Shares";
    if (type == "Trust")
        return "Trusts";

    if (type == "Group") {
        if (opsGraphIsLowSignalWindowsGroup(node)) {
            if (!showTokenGroups)
                return QString();

            return tokenGroupCategory(node);
        }

        return "Groups";
    }

    return type.isEmpty() ? QString("Other") : type + "s";
}


// OPSGRAPH_SID_CANONICALIZER_V1_BEGIN
static QString opsGraphIdentitySID(const QJsonObject& node)
{
    const QJsonObject props = node.value("properties").toObject();

    QString sid = props.value("sid").toString().trimmed();
    if (sid.isEmpty())
        sid = props.value("objectSid").toString().trimmed();

    return sid;
}

static bool opsGraphJsonValueEmpty(const QJsonValue& value)
{
    if (value.isUndefined() || value.isNull())
        return true;

    if (value.isString())
        return value.toString().trimmed().isEmpty();

    if (value.isArray())
        return value.toArray().isEmpty();

    if (value.isObject())
        return value.toObject().isEmpty();

    return false;
}

static QJsonArray opsGraphMergeJsonArrays(const QJsonArray& left, const QJsonArray& right)
{
    QJsonArray out;
    QSet<QString> seen;

    auto appendUnique = [&](const QJsonValue& value) {
        const QString key = QString::fromUtf8(QJsonDocument(value.toVariant().toJsonValue().toObject()).toJson(QJsonDocument::Compact));

        QString stableKey = key;
        if (stableKey == "{}")
            stableKey = QString::fromUtf8(QJsonDocument(QJsonArray{value}).toJson(QJsonDocument::Compact));

        if (seen.contains(stableKey))
            return;

        seen.insert(stableKey);
        out.append(value);
    };

    for (const QJsonValue& v : left)
        appendUnique(v);

    for (const QJsonValue& v : right)
        appendUnique(v);

    return out;
}

static QJsonObject opsGraphMergeJsonObjects(const QJsonObject& canonical, const QJsonObject& alias)
{
    QJsonObject out = canonical;

    for (auto it = alias.constBegin(); it != alias.constEnd(); ++it) {
        const QString key = it.key();
        const QJsonValue aliasValue = it.value();
        const QJsonValue canonicalValue = out.value(key);

        if (opsGraphJsonValueEmpty(canonicalValue)) {
            out.insert(key, aliasValue);
            continue;
        }

        if (canonicalValue.isArray() && aliasValue.isArray()) {
            out.insert(key, opsGraphMergeJsonArrays(canonicalValue.toArray(), aliasValue.toArray()));
            continue;
        }

        if (canonicalValue.isObject() && aliasValue.isObject()) {
            out.insert(key, opsGraphMergeJsonObjects(canonicalValue.toObject(), aliasValue.toObject()));
            continue;
        }
    }

    return out;
}

static int opsGraphCanonicalUserPreferenceScore(const QString& id, const QJsonObject& node)
{
    int score = 0;

    const QJsonObject props = node.value("properties").toObject();
    const QString domain = props.value("domain").toString();
    const QString normalized = node.value("normalized_name").toString();
    const QString source = props.value("source").toString();

    if (!id.contains(":unknown:"))
        score += 100;

    if (!domain.trimmed().isEmpty())
        score += 50;

    if (normalized.contains("\\") && !normalized.startsWith("\\"))
        score += 30;

    if (source == "ldap")
        score += 15;

    if (props.contains("distinguished_name") || props.contains("dn"))
        score += 15;

    if (props.contains("groups"))
        score += 10;

    return score;
}


// OPSGRAPH_IDENTITY_CANONICALIZER_V2_HELPERS_BEGIN
static bool opsGraphCanCanonicalizeIdentityType(const QString& type)
{
    return type == "User" || type == "Group" || type == "Computer";
}

static QString opsGraphCanonicalDomainHint(const QString& id, const QJsonObject& node)
{
    const QJsonObject props = node.value("properties").toObject();

    QString domain = props.value("domain").toString().trimmed();
    if (domain.isEmpty())
        domain = props.value("observed_domain").toString().trimmed();

    if (!domain.isEmpty() && domain.toLower() != "unknown")
        return domain.toLower();

    const QString normalized = node.value("normalized_name").toString().trimmed();
    const int slash = normalized.indexOf("\\");
    if (slash > 0) {
        const QString d = normalized.left(slash).trimmed().toLower();
        if (!d.isEmpty() && d != "unknown")
            return d;
    }

    const QStringList parts = id.split(":");
    if (parts.size() >= 3) {
        const QString d = parts.value(1).trimmed().toLower();
        if (!d.isEmpty() && d != "unknown")
            return d;
    }

    return QString();
}

static bool opsGraphDomainsCompatibleForAlias(const QStringList& domains)
{
    QStringList clean;

    for (QString d : domains) {
        d = d.trimmed().toLower();

        if (d.isEmpty() || d == "unknown")
            continue;

        if (!clean.contains(d))
            clean << d;
    }

    if (clean.size() <= 1)
        return true;

    for (int i = 0; i < clean.size(); ++i) {
        for (int j = i + 1; j < clean.size(); ++j) {
            const QString a = clean.at(i);
            const QString b = clean.at(j);

            const QString aShort = a.section(".", 0, 0);
            const QString bShort = b.section(".", 0, 0);

            if (a == b)
                continue;

            if (a == bShort || b == aShort)
                continue;

            return false;
        }
    }

    return true;
}

static QString opsGraphSimpleGroupAliasName(const QString& id, const QJsonObject& node)
{
    QString name = node.value("label").toString().trimmed();

    if (name.isEmpty())
        name = node.value("normalized_name").toString().trimmed();

    if (name.isEmpty()) {
        const QStringList parts = id.split(":");
        if (parts.size() >= 3)
            name = parts.mid(2).join(":");
    }

    if (name.contains("\\"))
        name = name.section("\\", -1, -1);

    name = name.toLower().simplified();

    return name;
}

static QString opsGraphResolveAliasTarget(QString id, const QHash<QString, QString>& aliasToCanonical)
{
    QSet<QString> seen;

    for (int i = 0; i < 16; ++i) {
        if (!aliasToCanonical.contains(id))
            break;

        if (seen.contains(id))
            break;

        seen.insert(id);
        id = aliasToCanonical.value(id);
    }

    return id;
}
// OPSGRAPH_IDENTITY_CANONICALIZER_V2_HELPERS_END


void OperationGraphTab::canonicalizeIdentityAliasesInCache()
{
    QHash<QString, QString> canonicalBySidKey;
    QHash<QString, QString> aliasToCanonical;

    // 1) Choose canonical User/Group/Computer node per SID.
    for (auto it = nodeCache.constBegin(); it != nodeCache.constEnd(); ++it) {
        const QString id = it.key();
        const QJsonObject node = it.value();
        const QString type = node.value("type").toString();

        if (!opsGraphCanCanonicalizeIdentityType(type))
            continue;

        const QString sid = opsGraphIdentitySID(node);
        if (sid.isEmpty())
            continue;

        const QString key = type + "|sid:" + sid;

        if (!canonicalBySidKey.contains(key)) {
            canonicalBySidKey.insert(key, id);
            continue;
        }

        const QString currentCanonical = canonicalBySidKey.value(key);
        const int oldScore = opsGraphCanonicalUserPreferenceScore(currentCanonical, nodeCache.value(currentCanonical));
        const int newScore = opsGraphCanonicalUserPreferenceScore(id, node);

        if (newScore > oldScore)
            canonicalBySidKey.insert(key, id);
    }

    for (auto it = nodeCache.constBegin(); it != nodeCache.constEnd(); ++it) {
        const QString id = it.key();
        const QJsonObject node = it.value();
        const QString type = node.value("type").toString();

        if (!opsGraphCanCanonicalizeIdentityType(type))
            continue;

        const QString sid = opsGraphIdentitySID(node);
        if (sid.isEmpty())
            continue;

        const QString key = type + "|sid:" + sid;
        const QString canonical = canonicalBySidKey.value(key);

        if (!canonical.isEmpty() && canonical != id)
            aliasToCanonical.insert(id, canonical);
    }

    // 2) Group fallback merge by simple group name when domains are compatible.
    // This fixes ACL-resolved groups like "IT Support" and token groups like "ZA\\IT Support".
    QHash<QString, QStringList> groupIdsBySimpleName;

    for (auto it = nodeCache.constBegin(); it != nodeCache.constEnd(); ++it) {
        const QString id = it.key();
        const QJsonObject node = it.value();

        if (node.value("type").toString() != "Group")
            continue;

        const QString simple = opsGraphSimpleGroupAliasName(id, node);
        if (simple.isEmpty())
            continue;

        groupIdsBySimpleName[simple].append(id);
    }

    for (auto it = groupIdsBySimpleName.constBegin(); it != groupIdsBySimpleName.constEnd(); ++it) {
        const QStringList ids = it.value();

        if (ids.size() < 2)
            continue;

        QStringList domains;
        for (const QString& id : ids) {
            if (!nodeCache.contains(id))
                continue;
            domains << opsGraphCanonicalDomainHint(id, nodeCache.value(id));
        }

        if (!opsGraphDomainsCompatibleForAlias(domains))
            continue;

        QString bestId;
        int bestScore = -999999;

        for (const QString& id : ids) {
            if (!nodeCache.contains(id))
                continue;

            const QString resolved = opsGraphResolveAliasTarget(id, aliasToCanonical);
            if (!nodeCache.contains(resolved))
                continue;

            const int score = opsGraphCanonicalUserPreferenceScore(resolved, nodeCache.value(resolved));

            if (bestId.isEmpty() || score > bestScore) {
                bestId = resolved;
                bestScore = score;
            }
        }

        if (bestId.isEmpty())
            continue;

        for (const QString& id : ids) {
            const QString resolved = opsGraphResolveAliasTarget(id, aliasToCanonical);

            if (resolved != bestId)
                aliasToCanonical.insert(resolved, bestId);
        }
    }

    // 3) Resolve alias chains.
    QHash<QString, QString> resolvedAliases;

    for (auto it = aliasToCanonical.constBegin(); it != aliasToCanonical.constEnd(); ++it) {
        const QString alias = it.key();
        const QString canonical = opsGraphResolveAliasTarget(it.value(), aliasToCanonical);

        if (!canonical.isEmpty() && alias != canonical)
            resolvedAliases.insert(alias, canonical);
    }

    aliasToCanonical = resolvedAliases;

    if (aliasToCanonical.isEmpty())
        return;

    // 4) Merge alias node properties into canonical node.
    for (auto it = aliasToCanonical.constBegin(); it != aliasToCanonical.constEnd(); ++it) {
        const QString aliasId = it.key();
        const QString canonicalId = it.value();

        if (!nodeCache.contains(aliasId) || !nodeCache.contains(canonicalId))
            continue;

        QJsonObject canonical = nodeCache.value(canonicalId);
        const QJsonObject alias = nodeCache.value(aliasId);

        QJsonObject mergedProps = opsGraphMergeJsonObjects(
            canonical.value("properties").toObject(),
            alias.value("properties").toObject()
        );

        canonical.insert("properties", mergedProps);

        if (canonical.value("label").toString().isEmpty())
            canonical.insert("label", alias.value("label"));

        if (canonical.value("normalized_name").toString().isEmpty())
            canonical.insert("normalized_name", alias.value("normalized_name"));

        nodeCache.insert(canonicalId, canonical);
        nodeCache.remove(aliasId);
    }

    // 5) Remap edges to canonical identity.
    QHash<QString, QJsonObject> remappedEdges;

    for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
        QJsonObject edge = it.value();

        QString src = edge.value("source").toString(edge.value("source_id").toString());
        QString dst = edge.value("target").toString(edge.value("target_id").toString());

        if (aliasToCanonical.contains(src)) {
            src = aliasToCanonical.value(src);
            edge.insert("source", src);
            edge.insert("source_id", src);
        }

        if (aliasToCanonical.contains(dst)) {
            dst = aliasToCanonical.value(dst);
            edge.insert("target", dst);
            edge.insert("target_id", dst);
        }

        const QString signature = edge.value("type").toString() + "|" + src + "|" + dst;

        if (remappedEdges.contains(signature)) {
            QJsonObject existing = remappedEdges.value(signature);
            existing.insert("properties", opsGraphMergeJsonObjects(
                existing.value("properties").toObject(),
                edge.value("properties").toObject()
            ));
            remappedEdges.insert(signature, existing);
        } else {
            remappedEdges.insert(signature, edge);
        }
    }

    edgeCache.clear();

    for (auto it = remappedEdges.constBegin(); it != remappedEdges.constEnd(); ++it) {
        const QJsonObject edge = it.value();
        QString id = edge.value("id").toString();

        if (id.isEmpty())
            id = it.key();

        edgeCache.insert(id, edge);
    }

    // 6) Keep UI selection/focus stable.
    if (aliasToCanonical.contains(selectedNodeId))
        selectedNodeId = aliasToCanonical.value(selectedNodeId);

    if (aliasToCanonical.contains(focusedNodeId))
        focusedNodeId = aliasToCanonical.value(focusedNodeId);
}
// OPSGRAPH_SID_CANONICALIZER_V1_END


void OperationGraphTab::rebuildEntityTree()
{
    if (!entityTree)
        return;

    // OPSGRAPH_SMART_TREE_V1_BEGIN
    const int __opsgraphTreeScrollY =
        (entityTree && entityTree->verticalScrollBar())
            ? entityTree->verticalScrollBar()->value()
            : 0;

    QStringList expandedCategories;
    const int oldTopCount = entityTree->topLevelItemCount();

    for (int i = 0; i < oldTopCount; ++i) {
        QTreeWidgetItem* root = entityTree->topLevelItem(i);
        if (!root || !root->isExpanded())
            continue;

        QString category = root->data(0, Qt::UserRole + 1).toString();
        if (category.isEmpty())
            category = root->text(0).section(" (", 0, 0);

        if (!category.isEmpty() && !expandedCategories.contains(category))
            expandedCategories << category;
    }

    const bool firstBuild = (oldTopCount == 0);
    const QString selectedBefore = selectedNodeId;

    const bool oldBlocked = entityTree->blockSignals(true);
    entityTree->clear();

    struct SmartTreeEntry {
        QString label;
        QString nodeId;
        int score = 0;
        QStringList badges;
    };

    QMap<QString, QList<SmartTreeEntry>> buckets;
    QMap<QString, int> hiddenCounts;

    auto nodeLabelForTree = [&](const QString& nodeId, const QJsonObject& node) -> QString {
        QString label = node.value("label").toString();
        if (label.isEmpty())
            label = node.value("normalized_name").toString();
        if (label.isEmpty())
            label = nodeId;
        return label;
    };

    auto hasBadge = [](const OpsGraphRelevanceResult& rel, const QString& badge) -> bool {
        return rel.badges.contains(badge);
    };

    auto nodeText = [](const QJsonObject& node) -> QString {
        QStringList parts;
        const QJsonObject props = node.value("properties").toObject();

        parts << node.value("id").toString();
        parts << node.value("label").toString();
        parts << node.value("normalized_name").toString();
        parts << props.value("name").toString();
        parts << props.value("sam").toString();
        parts << props.value("domain").toString();
        parts << props.value("distinguished_name").toString();
        parts << props.value("distinguishedName").toString();

        return parts.join(" ").toLower();
    };

    auto isNoisePrincipal = [&](const QJsonObject& node) -> bool {
        const QString type = node.value("type").toString();
        const QString label = node.value("label").toString().toLower();
        const QString text = nodeText(node);

        if (type != "Group")
            return false;

        const QStringList exactNoise = {
            "self",
            "system",
            "everyone",
            "authenticated users",
            "nt authority\\authenticated users",
            "nt authority\\network",
            "nt authority\\this organization",
            "authentication authority asserted identity",
            "mandatory label\\medium mandatory level",
            "builtin\\users",
            "builtin\\remote desktop users"
        };

        if (exactNoise.contains(label))
            return true;

        const QStringList containsNoise = {
            "mandatory label",
            "nt authority",
            "builtin\\",
            "terminal server license servers",
            "ras and ias servers",
            "windows authorization access group",
            "pre-windows 2000 compatible access"
        };

        for (const QString& s : containsNoise) {
            if (text.contains(s))
                return true;
        }

        return opsGraphShouldHideTokenGroup(node);
    };

    auto compactBadges = [](const QStringList& badges) -> QString {
        QStringList important;

        const QStringList order = {
            "CURRENT",
            "PRIVILEGED",
            "SERVICE",
            "SPN",
            "ACL",
            "DB",
            "APP",
            "PKI",
            "BACKUP",
            "CI/CD",
            "LATERAL",
            "INFRA",
            "RBCD",
            "DELEGATION",
            "KERBEROS"
        };

        for (const QString& b : order) {
            if (badges.contains(b) && !important.contains(b))
                important << b;
        }

        if (important.isEmpty())
            return QString();

        if (important.size() > 3)
            important = important.mid(0, 3);

        return important.join(",");
    };

    auto addEntry = [&](const QString& category,
                        const QString& nodeId,
                        const QJsonObject& node,
                        const OpsGraphRelevanceResult& rel) {
        SmartTreeEntry entry;
        entry.nodeId = nodeId;
        entry.score = rel.score;
        entry.badges = rel.badges;

        const QString badgeText = compactBadges(rel.badges);
        const QString base = nodeLabelForTree(nodeId, node);

        if (!badgeText.isEmpty())
            entry.label = QString("%1  [%2]").arg(base, badgeText);
        else
            entry.label = base;

        buckets[category].append(entry);
    };

    for (auto it = nodeCache.constBegin(); it != nodeCache.constEnd(); ++it) {
        QString nodeId = it.key();
        QJsonObject node = it.value();

        const QString idFromNode = node.value("id").toString();
        if (!idFromNode.isEmpty())
            nodeId = idFromNode;

        const QString type = node.value("type").toString();
        const OpsGraphRelevanceResult rel = opsGraphComputeNodeRelevanceV1(nodeId, nodeCache, edgeCache);
        const OpsGraphHighValueResult hv = opsGraphComputeHighValueV1(nodeId, nodeCache, edgeCache);

        QString category;

        if (hasBadge(rel, "CURRENT") || type == "Agent") {
            category = "Operation Context";
        } else if (hv.score >= 90) {
            category = "High Value Targets";
        } else if (type == "User") {
            if (rel.visibility == "hidden_inventory") {
                hiddenCounts["Users"]++;
                continue;
            }

            if (hasBadge(rel, "PRIVILEGED"))
                category = "Privileged Users";
            else if (hasBadge(rel, "SERVICE") || hasBadge(rel, "SPN"))
                category = "Service / SPN Users";
            else if (hasBadge(rel, "ACL"))
                category = "ACL Actionable";
            else if (hasBadge(rel, "LATERAL"))
                category = "Lateral Movement";
            else
                category = "Other Relevant";
        } else if (type == "Group") {
            if (isNoisePrincipal(node)) {
                hiddenCounts["Groups"]++;
                continue;
            }

            if (hasBadge(rel, "PRIVILEGED"))
                category = "Privileged Access Groups";
            else if (hasBadge(rel, "DB") || hasBadge(rel, "APP") || hasBadge(rel, "BACKUP") || hasBadge(rel, "CI/CD"))
                category = "Application / Server Surface";
            else if (hasBadge(rel, "PKI") || hasBadge(rel, "INFRA"))
                category = "Infrastructure";
            else if (hasBadge(rel, "ACL"))
                category = "ACL Actionable";
            else if (rel.visibility == "hidden_inventory") {
                hiddenCounts["Groups"]++;
                continue;
            } else {
                category = "Other Relevant";
            }
        } else if (type == "Computer") {
            if (hasBadge(rel, "INFRA") || hasBadge(rel, "PKI"))
                category = "Infrastructure";
            else if (hasBadge(rel, "DB") || hasBadge(rel, "APP") || hasBadge(rel, "BACKUP") || hasBadge(rel, "CI/CD"))
                category = "Application / Server Surface";
            else if (hasBadge(rel, "LATERAL"))
                category = "Lateral Movement";
            else if (rel.visibility == "hidden_inventory") {
                hiddenCounts["Computers"]++;
                continue;
            } else {
                category = "Other Relevant";
            }
        } else if (type == "Domain" || type == "Trust" || type == "Listener") {
            category = "Infrastructure";
        } else if (type == "Credential" || type == "Session") {
            category = "Operation Context";
        } else if (type == "SPN" || type == "Service") {
            category = "Service / SPN Users";
        } else if (type == "Share" || type == "Process" || type == "IP" || type == "Subnet") {
            if (rel.visibility == "hidden_inventory") {
                hiddenCounts[type + "s"]++;
                continue;
            }
            category = "Other Relevant";
        } else {
            if (rel.visibility == "hidden_inventory") {
                hiddenCounts[type.isEmpty() ? QString("Other") : type + "s"]++;
                continue;
            }
            category = "Other Relevant";
        }

        if (category.isEmpty())
            continue;

        addEntry(category, nodeId, node, rel);
    }

    QStringList preferredOrder;
    preferredOrder << "Operation Context"
                   << "High Value Targets"
                   << "Privileged Users"
                   << "Privileged Access Groups"
                   << "Service / SPN Users"
                   << "Delegation Targets"
                   << "Application / Server Surface"
                   << "ACL Actionable"
                   << "Lateral Movement"
                   << "Infrastructure"
                   << "Other Relevant"
                   << "Hidden Inventory";

    for (auto it = buckets.constBegin(); it != buckets.constEnd(); ++it) {
        if (!preferredOrder.contains(it.key()))
            preferredOrder << it.key();
    }

    QTreeWidgetItem* selectedItem = nullptr;

    for (const QString& category : preferredOrder) {
        if (!buckets.contains(category))
            continue;

        QList<SmartTreeEntry> entries = buckets.value(category);

        std::sort(entries.begin(), entries.end(),
                  [](const SmartTreeEntry& a, const SmartTreeEntry& b) {
                      if (a.score != b.score)
                          return a.score > b.score;
                      return a.label.toLower() < b.label.toLower();
                  });

        QTreeWidgetItem* root = new QTreeWidgetItem(entityTree);
        root->setText(0, QString("%1 (%2)").arg(category).arg(entries.size()));
        root->setData(0, Qt::UserRole, QString());
        root->setData(0, Qt::UserRole + 1, category);

        const bool shouldExpand =
            expandedCategories.contains(category) ||
            (firstBuild && (category == "Operation Context" ||
                            category == "Privileged Users" ||
                            category == "ACL Actionable"));

        root->setExpanded(shouldExpand);

        for (const SmartTreeEntry& entry : entries) {
            QTreeWidgetItem* child = new QTreeWidgetItem(root);
            child->setText(0, entry.label);
            child->setData(0, Qt::UserRole, entry.nodeId);

            if (!selectedBefore.isEmpty() && entry.nodeId == selectedBefore)
                selectedItem = child;
        }
    }

    int totalHidden = 0;
    for (auto it = hiddenCounts.constBegin(); it != hiddenCounts.constEnd(); ++it)
        totalHidden += it.value();

    if (totalHidden > 0) {
        QTreeWidgetItem* hiddenRoot = new QTreeWidgetItem(entityTree);
        hiddenRoot->setText(0, QString("Hidden Inventory (%1)").arg(totalHidden));
        hiddenRoot->setData(0, Qt::UserRole, QString());
        hiddenRoot->setData(0, Qt::UserRole + 1, QString("Hidden Inventory"));
        hiddenRoot->setExpanded(expandedCategories.contains("Hidden Inventory"));

        for (auto it = hiddenCounts.constBegin(); it != hiddenCounts.constEnd(); ++it) {
            QTreeWidgetItem* child = new QTreeWidgetItem(hiddenRoot);
            child->setText(0, QString("%1 hidden: %2").arg(it.key()).arg(it.value()));
            child->setData(0, Qt::UserRole, QString());
        }
    }

    if (selectedItem)
        entityTree->setCurrentItem(selectedItem);

    entityTree->blockSignals(oldBlocked);

    if (entityTree && entityTree->verticalScrollBar()) {
        const int __restoreY = __opsgraphTreeScrollY;
        QTimer::singleShot(0, this, [this, __restoreY]() {
            if (entityTree && entityTree->verticalScrollBar())
                entityTree->verticalScrollBar()->setValue(__restoreY);
        });
    }
    // OPSGRAPH_SMART_TREE_V1_END
}

void OperationGraphTab::onEntityTreeItemActivated(QTreeWidgetItem* item, int column)
{
    Q_UNUSED(column);

    if (!item)
        return;

    const QString nodeId = item->data(0, Qt::UserRole).toString();

    // Root/category item bo'lsa faqat expand/collapse qilamiz.
    if (nodeId.isEmpty()) {
        item->setExpanded(!item->isExpanded());
        return;
    }

    if (!nodeCache.contains(nodeId))
        return;

    selectedNodeId = nodeId;
    selectedEdgeId.clear();
    focusedNodeId = nodeId;

    focusMode = true;
    coreMode = false;

    const QJsonObject node = nodeCache.value(nodeId);
    const QString label = node.value("label").toString(nodeId);

    if (focusButton)
        focusButton->setText(QString("Focused: %1").arg(label));

    renderFocusNeighborhoodFromCache(nodeId);
    renderNodeDetails(node);
    fetchNodeEvidence(nodeId);
}




// OPSGRAPH_NODE_DETAILS_TRUTH_GATE_V1_BEGIN
static QStringList opsGraphTruthGateStringListV1(const QJsonValue& value)
{
    QStringList out;

    if (value.isArray()) {
        const QJsonArray arr = value.toArray();

        for (const QJsonValue& v : arr) {
            const QString s = v.toVariant().toString().trimmed();
            if (!s.isEmpty())
                out << s;
        }
    } else if (value.isString()) {
        const QStringList parts = value.toString().split(",", Qt::SkipEmptyParts);

        for (const QString& part : parts) {
            const QString s = part.trimmed();
            if (!s.isEmpty())
                out << s;
        }
    }

    out.removeDuplicates();
    return out;
}

static QString opsGraphTruthGateStringV1(const QJsonObject& obj, const QString& key)
{
    const QJsonValue value = obj.value(key);

    if (value.isString())
        return value.toString().trimmed();

    if (value.isDouble())
        return QString::number(value.toDouble(), 'f', 2);

    if (value.isBool())
        return value.toBool() ? "true" : "false";

    if (value.isArray())
        return opsGraphTruthGateStringListV1(value).join(", ");

    return value.toVariant().toString().trimmed();
}

static bool opsGraphTruthGateBoolV1(const QJsonObject& obj, const QString& key)
{
    const QJsonValue value = obj.value(key);

    if (value.isBool())
        return value.toBool(false);

    const QString s = value.toVariant().toString().trimmed().toLower();
    return s == "true" || s == "1" || s == "yes";
}

static QString opsGraphNodeTruthGateSummaryV1(const QJsonObject& node)
{
    const QString nodeLabel = node.value("label").toString(node.value("id").toString());
    const QJsonObject props = node.value("properties").toObject();
    const QJsonObject exposure = props.value("exposure").toObject();
    const QJsonArray vectors = props.value("attack_vectors").toArray();

    if (vectors.isEmpty() &&
        !opsGraphTruthGateBoolV1(props, "has_spn") &&
        !opsGraphTruthGateBoolV1(exposure, "has_spn") &&
        !opsGraphTruthGateBoolV1(props, "constrained_delegation_enabled") &&
        !opsGraphTruthGateBoolV1(exposure, "constrained_delegation_enabled") &&
        !opsGraphTruthGateBoolV1(props, "rbcd_descriptor_present") &&
        !opsGraphTruthGateBoolV1(exposure, "rbcd_descriptor_present")) {
        return QString();
    }

    QStringList observedFacts;
    QStringList exposureOnly;
    QStringList candidatePaths;
    QStringList confirmedPaths;
    QStringList missingProof;
    QStringList decisions;

    auto addUnique = [](QStringList& list, const QString& value) {
        const QString s = value.trimmed();
        if (!s.isEmpty() && !list.contains(s))
            list << s;
    };

    const QStringList spns = !opsGraphTruthGateStringListV1(props.value("service_principal_names")).isEmpty()
        ? opsGraphTruthGateStringListV1(props.value("service_principal_names"))
        : opsGraphTruthGateStringListV1(exposure.value("service_principal_names"));

    for (const QString& spn : spns)
        addUnique(observedFacts, QString("- %1 has service SPN %2").arg(nodeLabel).arg(spn));

    const QStringList delegationTargets = !opsGraphTruthGateStringListV1(props.value("constrained_delegation_targets")).isEmpty()
        ? opsGraphTruthGateStringListV1(props.value("constrained_delegation_targets"))
        : opsGraphTruthGateStringListV1(exposure.value("constrained_delegation_targets"));

    for (const QString& target : delegationTargets)
        addUnique(observedFacts, QString("- %1 has constrained delegation target %2").arg(nodeLabel).arg(target));

    if (opsGraphTruthGateBoolV1(props, "password_never_expires") ||
        opsGraphTruthGateBoolV1(exposure, "password_never_expires")) {
        addUnique(observedFacts, QString("- %1 has password-never-expires signal").arg(nodeLabel));
    }

    if (opsGraphTruthGateBoolV1(props, "preauth_not_required") ||
        opsGraphTruthGateBoolV1(exposure, "preauth_not_required")) {
        addUnique(observedFacts, QString("- %1 has preauth-not-required signal").arg(nodeLabel));
    }

    for (const QJsonValue& value : vectors) {
        if (!value.isObject())
            continue;

        const QJsonObject vector = value.toObject();

        const QString vectorId = opsGraphTruthGateStringV1(vector, "id").toLower();
        const QString category = opsGraphTruthGateStringV1(vector, "category").toLower();
        const QString label = opsGraphTruthGateStringV1(vector, "label");
        const QString severity = opsGraphTruthGateStringV1(vector, "severity").toLower();
        const QString evidence = opsGraphTruthGateStringV1(vector, "evidence");

        QString display = label.isEmpty() ? vectorId : label;
        if (!severity.isEmpty())
            display += " [" + severity + "]";

        const bool isDelegation =
            vectorId.contains("delegation") ||
            category == "delegation";

        const bool isRbcd =
            vectorId == "rbcd" ||
            vectorId.contains("resource_based_constrained_delegation") ||
            category == "rbcd";

        const bool isKerberosExposure =
            vectorId.contains("kerberoast") ||
            vectorId.contains("asrep") ||
            vectorId.contains("weak_kerberos") ||
            vectorId.contains("admin_count") ||
            category == "kerberos" ||
            category == "privilege";

        if (!evidence.isEmpty())
            addUnique(observedFacts, QString("- %1: %2").arg(display).arg(evidence));

        if (isDelegation || isRbcd) {
            const QStringList targets = opsGraphTruthGateStringListV1(vector.value("targets"));

            if (targets.isEmpty()) {
                addUnique(candidatePaths, QString("- %1 --[candidate]--> %2").arg(nodeLabel).arg(display));
            } else {
                for (const QString& target : targets) {
                    addUnique(candidatePaths, QString("- %1 --[candidate]--> %2 --[allowed target]--> %3")
                                         .arg(nodeLabel)
                                         .arg(display)
                                         .arg(target));
                }
            }

            addUnique(missingProof, QString("- control of %1 is not proven in the current graph").arg(nodeLabel));
            addUnique(missingProof, QString("- successful use of %1 toward the allowed target is not observed").arg(nodeLabel));
            addUnique(decisions, QString("- %1 remains CANDIDATE_ATTACK_PATH until source control is observed.").arg(label));
            continue;
        }

        if (isKerberosExposure) {
            addUnique(exposureOnly, QString("- %1: %2").arg(nodeLabel).arg(display));

            if (vectorId.contains("kerberoast") || vectorId.contains("asrep")) {
                addUnique(missingProof, QString("- %1: credential recovery or successful use is not observed").arg(label));
                addUnique(decisions, QString("- %1 remains EXPOSURE_ONLY, not a confirmed path.").arg(label));
            } else {
                addUnique(decisions, QString("- %1 is exposure/context until a full observed chain exists.").arg(label));
            }

            continue;
        }

        addUnique(decisions, QString("- %1 is CONTEXT_ONLY unless connected to a proven control path.").arg(label));
    }

    std::sort(observedFacts.begin(), observedFacts.end(),
              [](const QString& a, const QString& b) { return a.toLower() < b.toLower(); });
    std::sort(exposureOnly.begin(), exposureOnly.end(),
              [](const QString& a, const QString& b) { return a.toLower() < b.toLower(); });
    std::sort(candidatePaths.begin(), candidatePaths.end(),
              [](const QString& a, const QString& b) { return a.toLower() < b.toLower(); });
    std::sort(missingProof.begin(), missingProof.end(),
              [](const QString& a, const QString& b) { return a.toLower() < b.toLower(); });
    std::sort(decisions.begin(), decisions.end(),
              [](const QString& a, const QString& b) { return a.toLower() < b.toLower(); });

    QString out;
    out += "\nTruth Gate\n";
    out += "==========\n";
    out += QString("Confirmed control paths: %1\n").arg(confirmedPaths.size());
    out += QString("Candidate attack paths: %1\n").arg(candidatePaths.size());
    out += QString("Exposure-only findings: %1\n").arg(exposureOnly.size());
    out += QString("Observed facts: %1\n").arg(observedFacts.size());
    out += "\n";

    out += "Operator decision\n";
    out += "-----------------\n";
    if (decisions.isEmpty()) {
        out += "- No attack-vector decision available for this node yet.\n";
    } else {
        const int maxLines = 12;
        for (int i = 0; i < decisions.size() && i < maxLines; ++i)
            out += decisions.at(i) + "\n";
        if (decisions.size() > maxLines)
            out += QString("- ... %1 more decision note(s)\n").arg(decisions.size() - maxLines);
    }
    out += "\n";

    out += "Missing proof\n";
    out += "-------------\n";
    if (missingProof.isEmpty()) {
        out += "(none)\n";
    } else {
        const int maxLines = 12;
        for (int i = 0; i < missingProof.size() && i < maxLines; ++i)
            out += missingProof.at(i) + "\n";
        if (missingProof.size() > maxLines)
            out += QString("- ... %1 more missing proof item(s)\n").arg(missingProof.size() - maxLines);
    }
    out += "\n";

    out += "Candidate attack paths\n";
    out += "----------------------\n";
    if (candidatePaths.isEmpty()) {
        out += "(none)\n";
    } else {
        const int maxLines = 12;
        for (int i = 0; i < candidatePaths.size() && i < maxLines; ++i)
            out += candidatePaths.at(i) + "\n";
        if (candidatePaths.size() > maxLines)
            out += QString("- ... %1 more candidate path(s)\n").arg(candidatePaths.size() - maxLines);
        out += "Class: CANDIDATE_ATTACK_PATH\n";
        out += "Rule: observed target relationship exists, but source control is not proven.\n";
    }
    out += "\n";

    out += "Exposure-only findings\n";
    out += "----------------------\n";
    if (exposureOnly.isEmpty()) {
        out += "(none)\n";
    } else {
        const int maxLines = 12;
        for (int i = 0; i < exposureOnly.size() && i < maxLines; ++i)
            out += exposureOnly.at(i) + "\n";
        if (exposureOnly.size() > maxLines)
            out += QString("- ... %1 more exposure finding(s)\n").arg(exposureOnly.size() - maxLines);
        out += "Class: EXPOSURE_ONLY\n";
        out += "Rule: risk signal exists, but no complete control path is proven.\n";
    }
    out += "\n";

    out += "Observed facts\n";
    out += "--------------\n";
    if (observedFacts.isEmpty()) {
        out += "(none)\n";
    } else {
        const int maxLines = 12;
        for (int i = 0; i < observedFacts.size() && i < maxLines; ++i)
            out += observedFacts.at(i) + "\n";
        if (observedFacts.size() > maxLines)
            out += QString("- ... %1 more observed fact(s)\n").arg(observedFacts.size() - maxLines);
    }
    out += "\n";

    return out;
}
// OPSGRAPH_NODE_DETAILS_TRUTH_GATE_V1_END



// OPSGRAPH_DELEGATION_TARGET_FAMILY_DETAILS_V1_BEGIN
static QStringList opsGraphStringListFromJsonV1(const QJsonValue& value)
{
    QStringList out;

    if (value.isArray()) {
        const QJsonArray arr = value.toArray();

        for (const QJsonValue& v : arr) {
            const QString s = v.toVariant().toString().trimmed();
            if (!s.isEmpty())
                out << s;
        }
    } else if (value.isString()) {
        const QStringList parts = value.toString().split(QRegularExpression("[\\r\\n,;]+"), Qt::SkipEmptyParts);

        for (const QString& part : parts) {
            const QString s = part.trimmed();
            if (!s.isEmpty())
                out << s;
        }
    }

    out.removeDuplicates();

    std::sort(out.begin(), out.end(),
              [](const QString& a, const QString& b) {
                  return a.toLower() < b.toLower();
              });

    return out;
}

static QString opsGraphDelegationTargetFamilySummaryV1(const QJsonObject& node)
{
    const QJsonObject props = node.value("properties").toObject();

    if (props.value("target_role").toString() != "delegation_target_family")
        return QString();

    const QString label = node.value("label").toString(node.value("id").toString());
    const QString hostShort = props.value("host_short").toString();
    const QString host = props.value("host").toString();
    const QStringList services = opsGraphStringListFromJsonV1(props.value("allowed_services"));
    const QStringList rawTargets = opsGraphStringListFromJsonV1(props.value("raw_delegation_targets"));

    QString out;
    out += "\nDelegation Target Family\n";
    out += "========================\n";
    out += QString("Logical target: %1\n").arg(label);

    if (!hostShort.isEmpty())
        out += QString("Short host: %1\n").arg(hostShort);

    if (!host.isEmpty())
        out += QString("Observed host: %1\n").arg(host);

    out += "\nMeaning\n";
    out += "-------\n";
    out += "- This node deduplicates raw msDS-AllowedToDelegateTo SPNs into one host target.\n";
    out += "- It is an allowed delegation target, not proof that delegated access succeeded.\n";
    out += "- Treat it as candidate path context until source-account control is proven.\n";

    out += "\nAllowed services\n";
    out += "----------------\n";

    if (services.isEmpty()) {
        out += "(none parsed)\n";
    } else {
        for (const QString& service : services)
            out += "- " + service + "\n";
    }

    out += "\nRaw delegation SPNs\n";
    out += "-------------------\n";

    if (rawTargets.isEmpty()) {
        out += "(none)\n";
    } else {
        for (const QString& target : rawTargets)
            out += "- " + target + "\n";
    }

    return out;
}
// OPSGRAPH_DELEGATION_TARGET_FAMILY_DETAILS_V1_END


void OperationGraphTab::renderNodeDetails(const QJsonObject& node)
{
    // OPSGRAPH_EVIDENCE_TOGGLE_V1_RESET_NODE
    resetEvidenceDrawer();

    QString out;

    const QString type = node.value("type").toString("Unknown");
    const QString label = node.value("label").toString(node.value("id").toString());
    const QString id = node.value("id").toString();
    const QString normalized = node.value("normalized_name").toString();
    const QJsonObject props = node.value("properties").toObject();

    auto jsonValueToText = [](const QJsonValue& value) -> QString {
        if (value.isUndefined() || value.isNull())
            return QString();

        if (value.isBool())
            return value.toBool() ? "true" : "false";

        if (value.isDouble())
            return QString::number(value.toDouble());

        if (value.isString())
            return value.toString();

        if (value.isArray())
            return QString("[array:%1]").arg(value.toArray().size());

        if (value.isObject())
            return QString("[object]");

        return value.toVariant().toString();
    };

    auto nodeLabel = [&](const QString& nodeId) -> QString {
        if (!nodeCache.contains(nodeId))
            return nodeId;

        return nodeCache.value(nodeId).value("label").toString(nodeId);
    };

    auto edgeSource = [](const QJsonObject& edge) -> QString {
        return edge.value("source").toString(edge.value("source_id").toString());
    };

    auto edgeTarget = [](const QJsonObject& edge) -> QString {
        return edge.value("target").toString(edge.value("target_id").toString());
    };

    auto edgeType = [](const QJsonObject& edge) -> QString {
        return edge.value("type").toString();
    };

    auto rightsText = [](const QJsonObject& edge) -> QString {
        const QJsonObject edgeProps = edge.value("properties").toObject();
        QJsonValue rightsValue = edgeProps.value("display_rights");

        if (rightsValue.isUndefined() || rightsValue.isNull())
            rightsValue = edgeProps.value("rights");

        if (rightsValue.isArray()) {
            QStringList out;
            const QJsonArray arr = rightsValue.toArray();

            for (const QJsonValue& v : arr) {
                const QString s = v.toString().trimmed();
                if (!s.isEmpty())
                    out << s;
            }

            return out.join(", ");
        }

        if (rightsValue.isString())
            return rightsValue.toString();

        return edgeProps.value("right").toString();
    };

    out += "Selected node\n";
    out += "=============\n\n";
    out += "Type: " + type + "\n";
    out += "Label: " + label + "\n";
    out += "ID: " + id + "\n";

    if (!normalized.isEmpty())
        out += "Normalized: " + normalized + "\n";

    if (node.contains("host_state"))
        out += "Host state: " + node.value("host_state").toString() + "\n";

    out += "\n";

    // OPSGRAPH_RELEVANCE_PANEL_V1_BEGIN
    const OpsGraphRelevanceResult rel = opsGraphComputeNodeRelevanceV1(id, nodeCache, edgeCache);

    out += "Ops Relevance\n";
    out += "=============\n";
    out += "Score: " + QString::number(rel.score) + "\n";
    out += "Visibility: " + rel.visibility + "\n";

    if (!rel.badges.isEmpty())
        out += "Badges: " + rel.badges.join(", ") + "\n";
    else
        out += "Badges: none\n";

    out += "\nWhy this matters\n";
    out += "----------------\n";

    if (rel.reasons.isEmpty()) {
        out += "(no relevance reason observed yet)\n";
    } else {
        const int maxReasons = 12;
        for (int i = 0; i < rel.reasons.size() && i < maxReasons; ++i)
            out += "- " + rel.reasons.at(i) + "\n";

        if (rel.reasons.size() > maxReasons)
            out += QString("- ... %1 more reason(s)\n").arg(rel.reasons.size() - maxReasons);
    }

    QSet<QString> effectivePrincipals;
    effectivePrincipals.insert(id);

    if (type == "User") {
        const QSet<QString> groups = opsGraphRelGroupClosure(id, nodeCache, edgeCache, 5);

        for (const QString& groupId : groups) {
            if (nodeCache.contains(groupId) && opsGraphShouldHideTokenGroup(nodeCache.value(groupId)))
                continue;

            effectivePrincipals.insert(groupId);
        }

        out += "\nEffective groups\n";
        out += "----------------\n";

        if (groups.isEmpty()) {
            out += "(none observed through MemberOf edges yet)\n";
        } else {
            QStringList groupLabels;

            for (const QString& groupId : groups) {
                if (nodeCache.contains(groupId) && opsGraphShouldHideTokenGroup(nodeCache.value(groupId)))
                    continue;

                groupLabels << nodeLabel(groupId);
            }

            groupLabels.removeDuplicates();
            std::sort(groupLabels.begin(), groupLabels.end(),
                      [](const QString& a, const QString& b) {
                          return a.toLower() < b.toLower();
                      });

            const int maxGroups = 15;
            for (int i = 0; i < groupLabels.size() && i < maxGroups; ++i)
                out += "- " + groupLabels.at(i) + "\n";

            if (groupLabels.size() > maxGroups)
                out += QString("- ... %1 more group(s)\n").arg(groupLabels.size() - maxGroups);
        }
    }

    struct AclSummaryItem {
        QString source;
        QString target;
        QString rights;
    };

    QList<AclSummaryItem> outgoingAcl;
    QList<AclSummaryItem> selfObjectAcl;
    QSet<QString> incomingControllers;

    for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
        const QJsonObject edge = it.value();

        if (edgeType(edge) != "ACLRight")
            continue;

        const QString src = edgeSource(edge);
        const QString dst = edgeTarget(edge);

        if (effectivePrincipals.contains(src)) {
            AclSummaryItem item;
            item.source = src;
            item.target = dst;
            item.rights = rightsText(edge);

            if (dst == id)
                selfObjectAcl.append(item);
            else
                outgoingAcl.append(item);
        }

        if (dst == id && !effectivePrincipals.contains(src))
            incomingControllers.insert(src);
    }

    std::sort(outgoingAcl.begin(), outgoingAcl.end(),
              [&](const AclSummaryItem& a, const AclSummaryItem& b) {
                  const QString ar = a.rights.toLower();
                  const QString br = b.rights.toLower();

                  auto weight = [](const QString& r) -> int {
                      if (r.contains("genericall")) return 100;
                      if (r.contains("writedacl")) return 95;
                      if (r.contains("writeowner")) return 95;
                      if (r.contains("genericwrite")) return 90;
                      if (r.contains("forcechangepassword")) return 85;
                      if (r.contains("addmember")) return 85;
                      if (r.contains("writeproperty")) return 60;
                      return 10;
                  };

                  const int aw = weight(ar);
                  const int bw = weight(br);

                  if (aw != bw)
                      return aw > bw;

                  return nodeLabel(a.target).toLower() < nodeLabel(b.target).toLower();
              });

    out += "\nACL Summary\n";
    out += "-----------\n";
    out += QString("Outgoing/effective ACL paths: %1\n").arg(outgoingAcl.size());
    out += QString("Self-object ACL paths: %1\n").arg(selfObjectAcl.size());
    out += QString("Incoming controllers: %1\n").arg(incomingControllers.size());

    if (!outgoingAcl.isEmpty()) {
        out += "\nTop outgoing ACL paths\n";
        out += "----------------------\n";

        const int maxAcl = 10;
        for (int i = 0; i < outgoingAcl.size() && i < maxAcl; ++i) {
            const AclSummaryItem& item = outgoingAcl.at(i);

            out += QString("- %1 --[%2]--> %3\n")
                       .arg(nodeLabel(item.source))
                       .arg(item.rights.isEmpty() ? QString("ACLRight") : item.rights)
                       .arg(nodeLabel(item.target));
        }

        if (outgoingAcl.size() > maxAcl)
            out += QString("- ... %1 more ACL path(s)\n").arg(outgoingAcl.size() - maxAcl);
    }

    if (!selfObjectAcl.isEmpty()) {
        out += "\nSelf-object ACL note\n";
        out += "--------------------\n";
        out += "Self-object ACL means one of the selected identity's effective groups has rights over the selected object itself.\n";
        out += "This is not treated as an outgoing lateral movement path by default.\n";
    }

    if (!incomingControllers.isEmpty()) {
        out += "\nIncoming control note\n";
        out += "---------------------\n";
        out += "Incoming controllers are principals that control this object.\n";
        out += "They are hidden by default in ACL Lens v2 because they are not outgoing paths from this identity.\n";
    }

    const OpsGraphHighValueResult hv = opsGraphComputeHighValueV1(id, nodeCache, edgeCache);

    out += "\nHigh Value\n";
    out += "==========\n";
    out += "Score: " + QString::number(hv.score) + "\n";
    out += "Tier: " + hv.tier + "\n";

    if (!hv.badges.isEmpty())
        out += "Badges: " + hv.badges.join(", ") + "\n";
    else
        out += "Badges: none\n";

    out += "\nWhy high value\n";
    out += "--------------\n";

    if (hv.reasons.isEmpty()) {
        out += "(no high-value reason observed yet)\n";
    } else {
        const int maxHvReasons = 10;
        for (int i = 0; i < hv.reasons.size() && i < maxHvReasons; ++i)
            out += "- " + hv.reasons.at(i) + "\n";

        if (hv.reasons.size() > maxHvReasons)
            out += QString("- ... %1 more reason(s)\n").arg(hv.reasons.size() - maxHvReasons);
    }

    // OPSGRAPH_ATTACK_SURFACE_PANEL_V1_BEGIN
    const QJsonArray attackVectors = props.value("attack_vectors").toArray();

    if (!attackVectors.isEmpty()) {
        out += "\nAttack Surface\n";
        out += "==============\n";

        auto vectorString = [](const QJsonObject& vector, const QString& key) -> QString {
            return vector.value(key).toVariant().toString().trimmed();
        };

        auto vectorTargets = [](const QJsonObject& vector) -> QStringList {
            QStringList targets;
            const QJsonValue value = vector.value("targets");

            if (value.isArray()) {
                const QJsonArray arr = value.toArray();
                for (const QJsonValue& v : arr) {
                    const QString s = v.toVariant().toString().trimmed();
                    if (!s.isEmpty())
                        targets << s;
                }
            } else if (value.isString()) {
                const QStringList parts = value.toString().split(QRegularExpression("[\\r\\n,;]+"), Qt::SkipEmptyParts);
                for (const QString& part : parts) {
                    const QString s = part.trimmed();
                    if (!s.isEmpty())
                        targets << s;
                }
            }

            targets.removeDuplicates();
            return targets;
        };

        QStringList categories;
        QHash<QString, QList<QJsonObject>> byCategory;

        for (const QJsonValue& value : attackVectors) {
            if (!value.isObject())
                continue;

            const QJsonObject vector = value.toObject();
            QString category = vectorString(vector, "category").toLower();

            if (category.isEmpty())
                category = "other";

            if (!byCategory.contains(category))
                categories << category;

            byCategory[category].append(vector);
        }

        auto categoryTitle = [](const QString& category) -> QString {
            if (category == "kerberos") return "Kerberos";
            if (category == "delegation") return "Delegation";
            if (category == "rbcd") return "RBCD";
            if (category == "privilege") return "Privilege / Protected Objects";
            if (category == "acl") return "ACL / Object Control";
            return category.left(1).toUpper() + category.mid(1);
        };

        std::sort(categories.begin(), categories.end(),
                  [](const QString& a, const QString& b) {
                      auto rank = [](const QString& c) -> int {
                          if (c == "delegation") return 10;
                          if (c == "rbcd") return 20;
                          if (c == "kerberos") return 30;
                          if (c == "privilege") return 40;
                          if (c == "acl") return 50;
                          return 100;
                      };

                      const int ar = rank(a);
                      const int br = rank(b);

                      if (ar != br)
                          return ar < br;

                      return a < b;
                  });

        for (const QString& category : categories) {
            const QString title = categoryTitle(category);

            out += "\n" + title + "\n";
            out += QString("-").repeated(title.length()) + "\n";

            QList<QJsonObject> vectors = byCategory.value(category);

            std::sort(vectors.begin(), vectors.end(),
                      [&](const QJsonObject& a, const QJsonObject& b) {
                          auto sevRank = [](QString severity) -> int {
                              severity = severity.toLower().trimmed();
                              if (severity == "critical") return 100;
                              if (severity == "high") return 80;
                              if (severity == "medium") return 60;
                              if (severity == "low") return 40;
                              if (severity == "info") return 20;
                              return 10;
                          };

                          const int ar = sevRank(vectorString(a, "severity"));
                          const int br = sevRank(vectorString(b, "severity"));

                          if (ar != br)
                              return ar > br;

                          return vectorString(a, "label").toLower() < vectorString(b, "label").toLower();
                      });

            for (const QJsonObject& vector : vectors) {
                const QString labelText = vectorString(vector, "label");
                const QString severity = vectorString(vector, "severity");
                const QString evidence = vectorString(vector, "evidence");
                const QString confidence = vector.value("confidence").isDouble()
                    ? QString::number(vector.value("confidence").toDouble(), 'f', 2)
                    : vectorString(vector, "confidence");

                out += "- " + (labelText.isEmpty() ? vectorString(vector, "id") : labelText);

                if (!severity.isEmpty())
                    out += " [" + severity + "]";

                if (!confidence.isEmpty())
                    out += QString(" confidence=%1").arg(confidence);

                out += "\n";

                if (!evidence.isEmpty())
                    out += "  Evidence: " + evidence + "\n";

                const QStringList targets = vectorTargets(vector);
                if (!targets.isEmpty()) {
                    out += "  Targets:\n";
                    const int maxTargets = 12;
                    for (int i = 0; i < targets.size() && i < maxTargets; ++i)
                        out += "  - " + targets.at(i) + "\n";

                    if (targets.size() > maxTargets)
                        out += QString("  - ... %1 more target(s)\n").arg(targets.size() - maxTargets);
                }
            }
        }

        out += "\n";
    }
    // OPSGRAPH_ATTACK_SURFACE_PANEL_V1_END

    out += "\n";
    // OPSGRAPH_RELEVANCE_PANEL_V1_END

    // OPSGRAPH_KERBEROS_EXPOSURE_PANEL_V1_BEGIN
    // Passive Kerberos/SPN exposure summary. This does not run commands or
    // suggest exploitation. It only explains LDAP/task evidence already stored
    // on nodes and HasSPN edges.
    if (type == "User" || type == "Computer" || type == "SPN") {
        const QJsonObject exposure = props.value("exposure").toObject();

        auto boolFromPropsOrExposure = [&](const QString& key) -> bool {
            QJsonValue v = props.value(key);
            if (v.isUndefined() || v.isNull())
                v = exposure.value(key);

            if (v.isBool())
                return v.toBool();

            if (v.isDouble())
                return v.toDouble() != 0.0;

            if (v.isString()) {
                const QString s = v.toString().trimmed().toLower();
                return s == "true" || s == "1" || s == "yes" || s == "enabled";
            }

            return false;
        };

        auto stringListFromValue = [](const QJsonValue& value) -> QStringList {
            QStringList items;

            if (value.isArray()) {
                const QJsonArray arr = value.toArray();
                for (const QJsonValue& v : arr) {
                    const QString s = v.toString().trimmed();
                    if (!s.isEmpty())
                        items << s;
                }
            } else if (value.isString()) {
                const QString raw = value.toString();
                const QStringList parts = raw.split(QRegularExpression("[\\r\\n,;]+"), Qt::SkipEmptyParts);
                for (const QString& part : parts) {
                    const QString s = part.trimmed();
                    if (!s.isEmpty())
                        items << s;
                }
            }

            items.removeDuplicates();
            return items;
        };

        auto listFromPropsOrExposure = [&](const QString& key) -> QStringList {
            QStringList items = stringListFromValue(props.value(key));
            items << stringListFromValue(exposure.value(key));
            items.removeDuplicates();
            return items;
        };

        QStringList servicePrincipals = listFromPropsOrExposure("service_principal_names");

        for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
            const QJsonObject edge = it.value();

            if (edgeType(edge) != "HasSPN")
                continue;

            if (edgeSource(edge) != id)
                continue;

            const QJsonObject edgeProps = edge.value("properties").toObject();
            QString spn = edgeProps.value("spn").toString().trimmed();

            if (spn.isEmpty()) {
                const QString targetId = edgeTarget(edge);
                if (nodeCache.contains(targetId)) {
                    const QJsonObject spnNode = nodeCache.value(targetId);
                    const QJsonObject spnProps = spnNode.value("properties").toObject();
                    spn = spnProps.value("spn").toString().trimmed();

                    if (spn.isEmpty())
                        spn = spnNode.value("label").toString(targetId).trimmed();
                }
            }

            if (!spn.isEmpty())
                servicePrincipals << spn;
        }

        if (type == "SPN" && servicePrincipals.isEmpty()) {
            const QString spn = props.value("spn").toString(label).trimmed();
            if (!spn.isEmpty())
                servicePrincipals << spn;
        }

        servicePrincipals.removeDuplicates();
        std::sort(servicePrincipals.begin(), servicePrincipals.end(),
                  [](const QString& a, const QString& b) {
                      return a.toLower() < b.toLower();
                  });

        const QStringList delegationTargets = listFromPropsOrExposure("constrained_delegation_targets");

        const bool hasSpn = !servicePrincipals.isEmpty()
                            || boolFromPropsOrExposure("has_spn")
                            || opsGraphRelHasSPN(id, node, edgeCache);

        const bool preauthNotRequired = boolFromPropsOrExposure("preauth_not_required");
        const bool passwordNeverExpires = boolFromPropsOrExposure("password_never_expires");
        const bool unconstrainedDelegation = boolFromPropsOrExposure("unconstrained_delegation");
        const bool constrainedDelegation = boolFromPropsOrExposure("constrained_delegation_enabled")
                                           || !delegationTargets.isEmpty();
        const bool rbcdPresent = boolFromPropsOrExposure("rbcd_descriptor_present");
        const bool adminCountOne = boolFromPropsOrExposure("admin_count_1")
                                   || props.value("admin_count").toString() == "1"
                                   || exposure.value("admin_count").toString() == "1";
        const bool useDesOnly = boolFromPropsOrExposure("use_des_key_only");
        const bool notDelegated = boolFromPropsOrExposure("not_delegated");

        const bool shouldShowKerberosPanel = hasSpn
                                             || preauthNotRequired
                                             || passwordNeverExpires
                                             || unconstrainedDelegation
                                             || constrainedDelegation
                                             || rbcdPresent
                                             || adminCountOne
                                             || useDesOnly
                                             || notDelegated
                                             || type == "SPN";

        if (shouldShowKerberosPanel) {
            out += "\nKerberos / SPN Exposure\n";
            out += "=======================\n";
            out += "SPN evidence: ";
            out += hasSpn ? "yes\n" : "no\n";

            out += "\nService principals\n";
            out += "------------------\n";

            if (servicePrincipals.isEmpty()) {
                out += "(none observed yet)\n";
            } else {
                const int maxSpns = 20;
                for (int i = 0; i < servicePrincipals.size() && i < maxSpns; ++i)
                    out += "- " + servicePrincipals.at(i) + "\n";

                if (servicePrincipals.size() > maxSpns)
                    out += QString("- ... %1 more SPN(s)\n").arg(servicePrincipals.size() - maxSpns);
            }

            out += "\nExposure signals\n";
            out += "----------------\n";

            QStringList signals;

            if (type == "User" && hasSpn)
                signals << "Kerberoast candidate: user account has SPN evidence";

            if (type == "Computer" && hasSpn)
                signals << "Computer/service endpoint has SPN evidence";

            if (passwordNeverExpires && hasSpn)
                signals << "Password never expires together with SPN evidence";

            if (preauthNotRequired)
                signals << "ASREP roastable evidence: pre-authentication not required";

            if (unconstrainedDelegation)
                signals << "Unconstrained delegation evidence";

            if (constrainedDelegation)
                signals << "Constrained delegation evidence";

            if (rbcdPresent)
                signals << "RBCD descriptor present";

            if (adminCountOne)
                signals << "adminCount=1 evidence";

            if (useDesOnly)
                signals << "DES-only Kerberos key flag observed";

            if (notDelegated)
                signals << "Account is marked sensitive / not delegated";

            if (signals.isEmpty()) {
                out += "(no exposure signals observed yet)\n";
            } else {
                signals.removeDuplicates();
                for (const QString& s : signals)
                    out += "- " + s + "\n";
            }

            if (!delegationTargets.isEmpty()) {
                out += "\nConstrained delegation targets\n";
                out += "------------------------------\n";

                const int maxDelegationTargets = 20;
                for (int i = 0; i < delegationTargets.size() && i < maxDelegationTargets; ++i)
                    out += "- " + delegationTargets.at(i) + "\n";

                if (delegationTargets.size() > maxDelegationTargets)
                    out += QString("- ... %1 more target(s)\n").arg(delegationTargets.size() - maxDelegationTargets);
            }

            out += "\n";
        }
    }
    // OPSGRAPH_KERBEROS_EXPOSURE_PANEL_V1_END

    if (type == "Agent") {
        out += "Agent context\n";
        out += "-------------\n";
        out += "Active: " + props.value("active").toVariant().toString() + "\n";
        out += "Elevated: " + props.value("elevated").toVariant().toString() + "\n";
        out += "Last tick: " + props.value("last_tick").toVariant().toString() + "\n";
    } else if (type == "Computer") {
        out += "Computer context\n";
        out += "----------------\n";
        out += "Computer: " + props.value("computer").toVariant().toString() + "\n";

        const QString domain = props.value("domain").toVariant().toString();
        out += "Domain: " + (domain.isEmpty() ? QString("workgroup / unknown") : domain) + "\n";
    } else if (type == "User") {
        out += "Identity\n";
        out += "--------\n";
        out += "SAM: " + props.value("sam").toVariant().toString() + "\n";

        const QString domain = props.value("domain").toVariant().toString();
        out += "Domain: " + (domain.isEmpty() ? QString("local / unknown") : domain) + "\n";

        const QString sid = props.value("sid").toVariant().toString();
        if (!sid.isEmpty())
            out += "SID: " + sid + "\n";

        const QJsonArray groups = props.value("groups").toArray();

        auto appendGroupsByScope = [&](const QString& title, const QString& wantedScope) {
            out += "\n" + title + "\n";
            out += QString("-").repeated(title.length()) + "\n";

            bool foundAny = false;

            for (const QJsonValue& v : groups) {
                const QJsonObject g = v.toObject();
                const QString scope = g.value("scope").toVariant().toString();

                if (scope != wantedScope)
                    continue;

                foundAny = true;

                const QString gDomain = g.value("domain").toVariant().toString();
                const QString gName = g.value("name").toVariant().toString();
                const QString gType = g.value("type").toVariant().toString();
                const QString gSid = g.value("sid").toVariant().toString();

                QString display = gName;
                if (!gDomain.isEmpty())
                    display = gDomain + "\\" + gName;

                out += "- " + display;

                if (!gType.isEmpty())
                    out += " [" + gType + "]";

                if (!gSid.isEmpty())
                    out += "\n  SID: " + gSid;

                out += "\n";
            }

            // OPSGRAPH_IDENTITY_GROUPS_EDGE_FALLBACK_V1_BEGIN
            // Some nodes are created from LDAP/ACL evidence and may not have the
            // rich whoami /all props.groups array. In that case, do not show a
            // misleading "(none observed yet)" for Domain Groups. Fall back to
            // direct observed MemberOf edges from the selected identity.
            if (!foundAny && wantedScope == "domain") {
                QSet<QString> seenGroupIds;
                QStringList fallbackGroupLabels;

                for (auto it = edgeCache.constBegin(); it != edgeCache.constEnd(); ++it) {
                    const QJsonObject edge = it.value();

                    if (edgeType(edge) != "MemberOf")
                        continue;

                    if (edgeSource(edge) != id)
                        continue;

                    const QString groupId = edgeTarget(edge);
                    if (groupId.isEmpty() || seenGroupIds.contains(groupId))
                        continue;

                    if (!nodeCache.contains(groupId))
                        continue;

                    const QJsonObject groupNode = nodeCache.value(groupId);
                    const QString groupType = groupNode.value("type").toString();

                    if (groupType != "Group")
                        continue;

                    if (opsGraphShouldHideTokenGroup(groupNode))
                        continue;

                    const QString groupLabel = groupNode.value("label").toString(groupId).trimmed();
                    if (groupLabel.isEmpty())
                        continue;

                    seenGroupIds.insert(groupId);
                    fallbackGroupLabels << groupLabel;
                }

                fallbackGroupLabels.removeDuplicates();
                std::sort(fallbackGroupLabels.begin(), fallbackGroupLabels.end(),
                          [](const QString& a, const QString& b) {
                              return a.toLower() < b.toLower();
                          });

                const int maxFallbackGroups = 20;
                for (int i = 0; i < fallbackGroupLabels.size() && i < maxFallbackGroups; ++i) {
                    out += "- " + fallbackGroupLabels.at(i) + " [observed via MemberOf edge]\n";
                    foundAny = true;
                }

                if (fallbackGroupLabels.size() > maxFallbackGroups)
                    out += QString("- ... %1 more group(s)\n").arg(fallbackGroupLabels.size() - maxFallbackGroups);
            }
            // OPSGRAPH_IDENTITY_GROUPS_EDGE_FALLBACK_V1_END

            if (!foundAny)
                out += "(none observed yet)\n";
        };

        appendGroupsByScope("Domain Groups", "domain");
        appendGroupsByScope("Local Groups", "local");
        appendGroupsByScope("Well-known SIDs", "well_known");
        appendGroupsByScope("Integrity Labels", "integrity_label");

        out += "\nPrivileges\n";
        out += "----------\n";

        const QJsonArray privs = props.value("privileges").toArray();
        if (privs.isEmpty()) {
            out += "(none observed yet)\n";
        } else {
            for (const QJsonValue& v : privs) {
                const QJsonObject pr = v.toObject();
                const QString name = pr.value("name").toVariant().toString();
                const QString state = pr.value("state").toVariant().toString();
                const QString desc = pr.value("description").toVariant().toString();

                out += "- " + name;

                if (!state.isEmpty())
                    out += ": " + state;

                if (!desc.isEmpty())
                    out += "\n  " + desc;

                out += "\n";
            }
        }
    } else if (type == "Group") {
        out += "Group\n";
        out += "-----\n";
        out += "Name: " + props.value("name").toVariant().toString() + "\n";

        const QString domain = props.value("domain").toVariant().toString();
        if (!domain.isEmpty())
            out += "Domain: " + domain + "\n";

        const QString scope = props.value("scope").toVariant().toString();
        if (!scope.isEmpty())
            out += "Scope: " + scope + "\n";

        const QString sid = props.value("sid").toVariant().toString();
        if (!sid.isEmpty())
            out += "SID: " + sid + "\n";

        const QString groupType = props.value("type").toVariant().toString();
        if (!groupType.isEmpty())
            out += "Type: " + groupType + "\n";

        const QString attrs = props.value("attributes").toVariant().toString();
        if (!attrs.isEmpty())
            out += "Attributes: " + attrs + "\n";
    } else {
        out += "Properties\n";
        out += "----------\n";

        if (props.isEmpty()) {
            out += "(none)\n";
        } else {
            for (auto it = props.begin(); it != props.end(); ++it)
                out += it.key() + ": " + jsonValueToText(it.value()) + "\n";
        }
    }

        // OPSGRAPH_NODE_DETAILS_TRUTH_GATE_V1_RENDER
    out += opsGraphNodeTruthGateSummaryV1(node);

    // OPSGRAPH_DELEGATION_TARGET_FAMILY_DETAILS_V1_RENDER
    out += opsGraphDelegationTargetFamilySummaryV1(node);

detailsPanel->setText(out);

    // OPSGRAPH_EVIDENCE_TOGGLE_V3_NODE_CAPTURE
    captureInlineEvidenceDrawerFromPanel();


    // OPSGRAPH_EVIDENCE_TOGGLE_V4_ASYNC_CAPTURE_NODE
    QTimer::singleShot(50, this, [this]() {
        captureInlineEvidenceDrawerFromPanel();
    });
    QTimer::singleShot(200, this, [this]() {
        captureInlineEvidenceDrawerFromPanel();
    });

}


void OperationGraphTab::renderEdgeDetails(const QJsonObject& edge)
{
    // OPSGRAPH_EVIDENCE_TOGGLE_V1_RESET_EDGE
    resetEvidenceDrawer();

    QString out;

    const QString id = edge.value("id").toString();
    const QString type = edge.value("type").toString("Related");
    const QString source = opsGraphEdgeSource(edge);
    const QString target = opsGraphEdgeTarget(edge);

    const QJsonObject sourceNode = nodeCache.value(source);
    const QJsonObject targetNode = nodeCache.value(target);

    const QString sourceLabel = sourceNode.value("label").toString(source);
    const QString targetLabel = targetNode.value("label").toString(target);

    out += "Selected edge\n";
    out += "=============\n\n";
    out += "Type: " + type + "\n";
    out += "ID: " + id + "\n\n";

    out += "Source\n";
    out += "------\n";
    out += "Label: " + sourceLabel + "\n";
    out += "ID: " + source + "\n";
    if (!sourceNode.isEmpty())
        out += "Type: " + sourceNode.value("type").toString("Unknown") + "\n";

    out += "\nTarget\n";
    out += "------\n";
    out += "Label: " + targetLabel + "\n";
    out += "ID: " + target + "\n";
    if (!targetNode.isEmpty())
        out += "Type: " + targetNode.value("type").toString("Unknown") + "\n";

    const QJsonObject props = edge.value("properties").toObject();
    if (!props.isEmpty()) {
        out += "\nProperties\n";
        out += "----------\n";
        for (auto it = props.begin(); it != props.end(); ++it)
            out += it.key() + ": " + it.value().toVariant().toString() + "\n";
    }

    detailsPanel->setText(out);

    // OPSGRAPH_EVIDENCE_TOGGLE_V3_EDGE_CAPTURE
    captureInlineEvidenceDrawerFromPanel();


    // OPSGRAPH_EVIDENCE_TOGGLE_V4_ASYNC_CAPTURE_EDGE
    QTimer::singleShot(50, this, [this]() {
        captureInlineEvidenceDrawerFromPanel();
    });
    QTimer::singleShot(200, this, [this]() {
        captureInlineEvidenceDrawerFromPanel();
    });

}


void OperationGraphTab::fetchNodeEvidence(const QString& nodeId)
{
    if (!profile || !network || nodeId.isEmpty())
        return;

    const QString requestNodeId = nodeId;
    const QString encodedId = QString::fromUtf8(QUrl::toPercentEncoding(requestNodeId));
    QNetworkRequest request(QUrl(apiUrl("/opsgraph/node/" + encodedId)));
    request.setRawHeader("Authorization", QByteArray("Bearer ") + profile->GetAccessToken().toUtf8());

    QNetworkReply* reply = network->get(request);

    connect(reply, &QNetworkReply::sslErrors, reply, [reply](const QList<QSslError>&) {
        reply->ignoreSslErrors();
    });

    connect(reply, &QNetworkReply::finished, this, [this, reply, requestNodeId]() {
        reply->deleteLater();

        // Operator may have clicked another node while this request was in flight.
        if (selectedNodeId != requestNodeId)
            return;

        const QByteArray body = reply->readAll();

        if (reply->error() != QNetworkReply::NoError) {
            QString out = detailsPanel->toPlainText();
            out += "\nEvidence\n";
            out += "--------\n";
            out += "Failed to load evidence: " + reply->errorString() + "\n";
            detailsPanel->setText(out);
            return;
        }

        const QJsonDocument doc = QJsonDocument::fromJson(body);
        if (!doc.isObject()) {
            QString out = detailsPanel->toPlainText();
            out += "\nEvidence\n";
            out += "--------\n";
            out += "Invalid evidence response.\n";
            detailsPanel->setText(out);
            return;
        }

        const QJsonObject response = doc.object();
        const QJsonObject freshNode = response.value("node").toObject();
        const QJsonArray evidence = response.value("evidence").toArray();

        if (!freshNode.isEmpty()) {
            nodeCache.insert(requestNodeId, freshNode);
            renderNodeDetails(freshNode);
        }

        QString out = detailsPanel->toPlainText();
        out += formatEvidenceDrawer(evidence);
        detailsPanel->setText(out);
    });

    // OPSGRAPH_EVIDENCE_TOGGLE_V4_ASYNC_CAPTURE_FETCH_NODE_FUNC
    QTimer::singleShot(50, this, [this]() {
        captureInlineEvidenceDrawerFromPanel();
    });
    QTimer::singleShot(200, this, [this]() {
        captureInlineEvidenceDrawerFromPanel();
    });

}

void OperationGraphTab::fetchEdgeEvidence(const QString& edgeId)
{
    if (!profile || !network || edgeId.isEmpty())
        return;

    const QString requestEdgeId = edgeId;
    const QString encodedId = QString::fromUtf8(QUrl::toPercentEncoding(requestEdgeId));
    QNetworkRequest request(QUrl(apiUrl("/opsgraph/edge/" + encodedId + "/evidence")));
    request.setRawHeader("Authorization", QByteArray("Bearer ") + profile->GetAccessToken().toUtf8());

    QNetworkReply* reply = network->get(request);

    connect(reply, &QNetworkReply::sslErrors, reply, [reply](const QList<QSslError>&) {
        reply->ignoreSslErrors();
    });

    connect(reply, &QNetworkReply::finished, this, [this, reply, requestEdgeId]() {
        reply->deleteLater();

        // Operator may have selected another edge/node while this request was in flight.
        if (selectedEdgeId != requestEdgeId)
            return;

        const QByteArray body = reply->readAll();

        if (reply->error() != QNetworkReply::NoError) {
            QString out = detailsPanel->toPlainText();
            out += "\nEvidence\n";
            out += "--------\n";
            out += "Failed to load edge evidence: " + reply->errorString() + "\n";
            detailsPanel->setText(out);
            return;
        }

        const QJsonDocument doc = QJsonDocument::fromJson(body);
        if (!doc.isObject()) {
            QString out = detailsPanel->toPlainText();
            out += "\nEvidence\n";
            out += "--------\n";
            out += "Invalid edge evidence response.\n";
            detailsPanel->setText(out);
            return;
        }

        const QJsonObject response = doc.object();
        const QJsonArray evidence = response.value("evidence").toArray();

        if (edgeCache.contains(requestEdgeId))
            renderEdgeDetails(edgeCache.value(requestEdgeId));

        QString out = detailsPanel->toPlainText();
        out += formatEvidenceDrawer(evidence);
        detailsPanel->setText(out);
    });

    // OPSGRAPH_EVIDENCE_TOGGLE_V4_ASYNC_CAPTURE_FETCH_EDGE_FUNC
    QTimer::singleShot(50, this, [this]() {
        captureInlineEvidenceDrawerFromPanel();
    });
    QTimer::singleShot(200, this, [this]() {
        captureInlineEvidenceDrawerFromPanel();
    });

}


QString OperationGraphTab::formatEvidenceDrawer(const QJsonArray& evidence) const
{
    QString out;
    out += "\nEvidence\n";
    out += "--------\n";

    if (evidence.isEmpty()) {
        out += "(no direct evidence linked yet)\n";
        return out;
    }

    auto pick = [](const QJsonObject& obj, const QStringList& keys) -> QString {
        for (const QString& key : keys) {
            if (!obj.contains(key))
                continue;

            const QJsonValue value = obj.value(key);

            if (value.isString()) {
                const QString s = value.toString().trimmed();
                if (!s.isEmpty())
                    return s;
            }

            if (value.isDouble()) {
                const double d = value.toDouble();
                const qint64 i = static_cast<qint64>(d);

                if (d == static_cast<double>(i))
                    return QString::number(i);

                QString out = QString::number(d, 'f', 2);
                while (out.contains('.') && out.endsWith('0'))
                    out.chop(1);
                if (out.endsWith('.'))
                    out.chop(1);

                return out;
            }

            if (value.isBool())
                return value.toBool() ? "true" : "false";
        }

        return QString();
    };

    auto compact = [](QString text, int maxLen = 600) -> QString {
        text = text.replace("\r\n", "\n").replace("\r", "\n").trimmed();

        if (text.length() <= maxLen)
            return text;

        return text.left(maxLen) + "\n... <truncated>";
    };

    auto formatSeenTime = [](const QString& raw) -> QString {
        const QString value = raw.trimmed();
        if (value.isEmpty())
            return QString();

        bool ok = false;
        qint64 epoch = value.toLongLong(&ok);

        if (!ok)
            return value;

        // OpsGraph stores seconds since Unix epoch.
        // Show local operator time first, keep epoch for exact correlation.
        QDateTime dt = QDateTime::fromSecsSinceEpoch(epoch).toLocalTime();

        if (!dt.isValid())
            return value;

        return dt.toString("yyyy-MM-dd HH:mm:ss t") + QString(" (epoch %1)").arg(epoch);
    };

    int index = 1;

    for (const QJsonValue& value : evidence) {
        if (!value.isObject())
            continue;

        const QJsonObject ev = value.toObject();

        const QString parser = pick(ev, QStringList() << "parser" << "parser_name" << "source" << "source_type");
        const QString agent  = pick(ev, QStringList() << "agent_id" << "agent" << "beacon_id");
        const QString task   = pick(ev, QStringList() << "task_id" << "task" << "job_id");
        const QString cmd    = pick(ev, QStringList() << "command" << "command_line" << "cmd");
        const QString seen   = pick(ev, QStringList() << "timestamp" << "created_at" << "seen_at" << "time");
        const QString conf   = pick(ev, QStringList() << "confidence" << "score");
        QString raw          = pick(ev, QStringList() << "snippet" << "raw_snippet" << "raw" << "output" << "body");

        out += QString("#%1\n").arg(index++);

        if (!parser.isEmpty())
            out += "Parser: " + parser + "\n";
        if (!agent.isEmpty())
            out += "Agent: " + agent + "\n";
        if (!task.isEmpty())
            out += "Task: " + task + "\n";
        if (!cmd.isEmpty())
            out += "Command: " + cmd + "\n";
        if (!seen.isEmpty())
            out += "Seen: " + formatSeenTime(seen) + "\n";
        if (!conf.isEmpty())
            out += "Confidence: " + conf + "\n";

        if (!raw.isEmpty()) {
            out += "Snippet:\n";
            out += compact(raw) + "\n";
        } else {
            const QString fallback = compact(QString::fromUtf8(QJsonDocument(ev).toJson(QJsonDocument::Indented)), 500);
            out += "Raw evidence:\n";
            out += fallback + "\n";
        }

        out += "\n";
    }

    return out;
}



// OPSGRAPH_EVIDENCE_TOGGLE_V3_CAPTURE_INLINE_BEGIN
static int opsGraphEvidenceTextCountV3(const QString& text)
{
    int count = 0;

    const QStringList lines = text.split('\n');
    for (const QString& raw : lines) {
        const QString line = raw.trimmed();

        if (line.size() < 2)
            continue;

        if (!line.startsWith("#"))
            continue;

        bool hasDigit = false;
        for (int i = 1; i < line.size(); ++i) {
            if (line.at(i).isDigit()) {
                hasDigit = true;
                break;
            }

            if (!line.at(i).isSpace())
                break;
        }

        if (hasDigit)
            count++;
    }

    if (count == 0 && !text.trimmed().isEmpty())
        count = 1;

    return count;
}

void OperationGraphTab::captureInlineEvidenceDrawerFromPanel()
{
    // OPSGRAPH_EVIDENCE_TOGGLE_V3_CAPTURE_INLINE
    // Some detail renderers still append:
    //
    //   Evidence
    //   --------
    //
    // directly into the QTextEdit. Capture that block, remove it from the
    // default view, and expose it through the Evidence toggle instead.
    if (!detailsPanel)
        return;

    QString text = detailsPanel->toPlainText();

    const QString marker = "\nEvidence\n--------";
    int markerPos = text.indexOf(marker);

    if (markerPos < 0 && text.startsWith("Evidence\n--------"))
        markerPos = 0;

    if (markerPos < 0)
        return;

    const int evidenceHeaderPos = markerPos == 0 ? 0 : markerPos + 1;
    const QString evidenceHeader = "Evidence\n--------";

    QString base = text.left(markerPos).trimmed();
    QString evidenceText = text.mid(evidenceHeaderPos + evidenceHeader.length()).trimmed();

    evidenceBaseText = base;
    cachedEvidence = QJsonArray();
    cachedEvidenceText = evidenceText;
    cachedEvidenceTextCount = opsGraphEvidenceTextCountV3(evidenceText);
    evidenceExpanded = false;

    updateEvidenceDisplay();
}
// OPSGRAPH_EVIDENCE_TOGGLE_V3_CAPTURE_INLINE_END

void OperationGraphTab::renderEvidence(const QJsonArray& evidence)
{
    // OPSGRAPH_EVIDENCE_TOGGLE_V1_RENDER
    cachedEvidence = evidence;
    cachedEvidenceText.clear();
    cachedEvidenceTextCount = 0;

    // The base text is whatever node/edge summary is currently visible.
    // Evidence is appended only when the drawer is expanded.
    if (detailsPanel && evidenceBaseText.trimmed().isEmpty())
        evidenceBaseText = detailsPanel->toPlainText();

    evidenceExpanded = false;
    updateEvidenceDisplay();
}

void OperationGraphTab::resetEvidenceDrawer()
{
    // OPSGRAPH_EVIDENCE_TOGGLE_V1_RESET
    cachedEvidence = QJsonArray();
    cachedEvidenceText.clear();
    cachedEvidenceTextCount = 0;
    evidenceExpanded = false;
    evidenceBaseText.clear();

    if (evidenceToggleButton) {
        evidenceToggleButton->setText("Evidence: Hidden (0) ▾");
        evidenceToggleButton->setEnabled(false);
    }
}

// OPSGRAPH_EVIDENCE_TOGGLE_HELPER_ORDER_FIX_V1
static QString opsGraphStripInlineEvidenceSectionsV2(QString text)
{
    const QStringList markers = {
        "\nEvidence\n--------",
        "\nEvidence Drawer\n==============="
    };

    int cut = -1;

    for (const QString& marker : markers) {
        const int pos = text.indexOf(marker);
        if (pos >= 0 && (cut < 0 || pos < cut))
            cut = pos;
    }

    if (cut >= 0)
        text = text.left(cut).trimmed();

    return text;
}

void OperationGraphTab::updateEvidenceDisplay()
{
    // OPSGRAPH_EVIDENCE_TOGGLE_V3_UPDATE
    if (!detailsPanel)
        return;

    QString out = opsGraphStripInlineEvidenceSectionsV2(evidenceBaseText);

    if (!out.endsWith("\n") && !out.isEmpty())
        out += "\n";

    out += "\nEvidence Drawer\n";
    out += "===============\n";

    const int count = cachedEvidence.isEmpty()
        ? cachedEvidenceTextCount
        : cachedEvidence.size();

    if (count <= 0) {
        out += "No evidence records returned for this selection yet.\n";

        if (evidenceToggleButton) {
            evidenceToggleButton->setText("Evidence: Hidden (0) ▾");
            evidenceToggleButton->setEnabled(false);
        }

        detailsPanel->setPlainText(out);
        return;
    }

    if (evidenceToggleButton) {
        evidenceToggleButton->setEnabled(true);
        evidenceToggleButton->setText(
            evidenceExpanded
                ? QString("Evidence: Shown (%1) ▴").arg(count)
                : QString("Evidence: Hidden (%1) ▾").arg(count)
        );
    }

    if (!evidenceExpanded) {
        out += QString("Hidden (%1 record(s)). Click the Evidence button to expand.\n").arg(count);
        detailsPanel->setPlainText(out);
        return;
    }

    if (!cachedEvidenceText.trimmed().isEmpty()) {
        out += cachedEvidenceText.trimmed();
        out += "\n";
    } else {
        out += formatEvidenceDrawer(cachedEvidence);
    }

    detailsPanel->setPlainText(out);
}


void OperationGraphTab::onToggleEvidence()
{
    // OPSGRAPH_EVIDENCE_TOGGLE_V1_SLOT
    // OPSGRAPH_EVIDENCE_TOGGLE_TEXT_CACHE_FIX_V1
    // Evidence may be stored either as JSON evidence records from renderEvidence()
    // or as captured inline text from older detail renderers.
    const bool hasJsonEvidence = !cachedEvidence.isEmpty();
    const bool hasTextEvidence = !cachedEvidenceText.trimmed().isEmpty() || cachedEvidenceTextCount > 0;

    if (!hasJsonEvidence && !hasTextEvidence)
        return;

    evidenceExpanded = !evidenceExpanded;
    updateEvidenceDisplay();
}

