#include <QPainterPath>
// OPSGRAPH_DELEGATION_TARGET_VISUAL_V1
#include <QGraphicsPathItem>
#include <QPainter>
#include <QIcon>
#include <UI/OpsGraph/GraphCanvas.h>

#include <QBrush>
#include <QGraphicsEllipseItem>
#include <QGraphicsLineItem>
#include <QGraphicsScene>
#include <QGraphicsTextItem>
#include <QMouseEvent>
#include <QPen>
#include <QScrollBar>
#include <QSet>
#include <QWheelEvent>
#include <QtMath>

#include <QJsonArray>
#include <QStringList>


#include <QGraphicsPixmapItem>
#include <QPixmap>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QList>
#include <Qt>
// OPSGRAPH_ACL_EDGE_LABEL_HELPER_BEGIN
static QString opsGraphEdgeDisplayLabel(const QJsonObject& edge)
{
    const QString type = edge.value("type").toString("Related");
    const QJsonObject props = edge.value("properties").toObject();

    auto joinStringArray = [](const QJsonValue& value) -> QString {
        QStringList out;

        if (value.isArray()) {
            const QJsonArray arr = value.toArray();

            for (const QJsonValue& v : arr) {
                const QString s = v.toVariant().toString().trimmed();
                if (!s.isEmpty() && !out.contains(s))
                    out << s;
            }
        } else {
            const QString s = value.toVariant().toString().trimmed();
            if (!s.isEmpty())
                out << s;
        }

        return out.join(", ");
    };

    if (type == "ACLRight") {
        QString display = joinStringArray(props.value("display_rights"));

        if (display.isEmpty())
            display = joinStringArray(props.value("rights"));

        return display.isEmpty() ? type : display;
    }

    return type;
}
// OPSGRAPH_ACL_EDGE_LABEL_HELPER_END



// OPSGRAPH_NODE_ICON_HELPER_V1_BEGIN
static QString opsGraphIconFileForType(const QString& type)
{
    if (type == "Agent") return "agent.svg";
    if ((type == "Computer" || type == "DelegationTarget")) return "computer.svg";
    if (type == "User") return "user.svg";
    if (type == "Domain") return "domain.svg";
    if (type == "Group") return "group.svg";
    if (type == "SPN") return "spn.svg";
    // OPSGRAPH_DELEGATION_TARGET_CONST_FIX_V1
    if (type == "DelegationTarget")
        return opsGraphIconFileForType(QStringLiteral("Computer"));

    if (type == "Service") return "service.svg";
    if (type == "Session") return "session.svg";
    if (type == "Credential") return "credential.svg";
    if (type == "Trust") return "trust.svg";
    if (type == "Privilege") return "privilege.svg";
    if (type == "IntegrityLevel") return "integrity.svg";
    if (type == "Process") return "process.svg";
    if (type == "Share") return "share.svg";
    if (type == "IP") return "ip.svg";
    if (type == "Subnet") return "subnet.svg";
    if (type == "Listener") return "listener.svg";

    return "default.svg";
}

static QString opsGraphFindIconPath(const QString& fileName)
{
    if (fileName.isEmpty())
        return QString();

    const QString appDir = QCoreApplication::applicationDirPath();
    const QString cwd = QDir::currentPath();

    const QStringList candidates = {
        appDir + "/Assets/OpsGraph/icons/" + fileName,
        appDir + "/../AdaptixClient/Assets/OpsGraph/icons/" + fileName,
        cwd + "/AdaptixClient/Assets/OpsGraph/icons/" + fileName,
        cwd + "/Assets/OpsGraph/icons/" + fileName,
        "/home/kali/Tools/AdaptixC2/AdaptixClient/Assets/OpsGraph/icons/" + fileName
    };

    for (const QString& path : candidates) {
        if (QFileInfo::exists(path))
            return path;
    }

    return QString();
}

static QPixmap opsGraphTintPixmap(const QPixmap& input, const QColor& color)
{
    if (input.isNull())
        return QPixmap();

    QPixmap out(input.size());
    out.fill(Qt::transparent);

    QPainter painter(&out);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setRenderHint(QPainter::SmoothPixmapTransform, true);
    painter.drawPixmap(0, 0, input);
    painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    painter.fillRect(out.rect(), color);
    painter.end();

    return out;
}

static QPixmap opsGraphIconPixmapForType(const QString& type)
{
    QString path = opsGraphFindIconPath(opsGraphIconFileForType(type));

    if (path.isEmpty())
        path = opsGraphFindIconPath("default.svg");

    if (path.isEmpty())
        return QPixmap();

    QIcon svgIcon(path);
    QPixmap pixmap = svgIcon.pixmap(24, 24);

    if (pixmap.isNull())
        return QPixmap();

    // Source SVGs are black. Tint them for Adaptix dark UI.
    return opsGraphTintPixmap(pixmap, QColor(220, 225, 232));
}

static void opsGraphApplyNodeIcon(QGraphicsPixmapItem* icon, const QString& type)
{
    if (!icon)
        return;

    const QPixmap pixmap = opsGraphIconPixmapForType(type);

    if (pixmap.isNull()) {
        icon->hide();
        return;
    }

    icon->setPixmap(pixmap);
    icon->setOffset(-pixmap.width() / 2.0, -pixmap.height() / 2.0);
    icon->setZValue(4);
    icon->show();
}
// OPSGRAPH_NODE_ICON_HELPER_V1_END


static QColor nodeColorForType(const QString& type)
{
    if (type == "Agent") return QColor("#4aa3ff");
    if ((type == "Computer" || type == "DelegationTarget")) return QColor("#57d68d");
    if (type == "User") return QColor("#d6b657");
    if (type == "Domain") return QColor("#b678ff");
    if (type == "Credential") return QColor("#ff8f57");
    if (type == "Session") return QColor("#57d6d6");
    return QColor("#777777");
}

class GraphNodeItem final : public QGraphicsEllipseItem
{
public:
    QString id;
    QString label;
    QString type;
    QGraphicsTextItem* text = nullptr;
    QGraphicsPixmapItem* icon = nullptr;

    GraphNodeItem(const QString& nodeId, const QString& nodeLabel, const QString& nodeType)
        : QGraphicsEllipseItem(-24, -24, 48, 48), id(nodeId), label(nodeLabel), type(nodeType)
    {
        setFlag(QGraphicsItem::ItemIsMovable);
        setFlag(QGraphicsItem::ItemIsSelectable);
        setFlag(QGraphicsItem::ItemSendsGeometryChanges);
        setZValue(2);

        setPen(QPen(QColor("#d0d0d0"), 1.5));
        setBrush(QBrush(QColor(18, 21, 27)));
        setPen(QPen(nodeColorForType(type), 1.6));
        // OPSGRAPH_NODE_ICON_STYLE_V1

        text = new QGraphicsTextItem(this);

        icon = new QGraphicsPixmapItem(this);
        opsGraphApplyNodeIcon(icon, type);
        text->setDefaultTextColor(QColor("#e8e8e8"));
        updateText();

        setToolTip(id);
    }

    void updateFromJson(const QJsonObject& node)
    {
        label = node.value("label").toString(id);
        type = node.value("type").toString(type);
        setBrush(QBrush(QColor(18, 21, 27)));
        setPen(QPen(nodeColorForType(type), 1.6));
        opsGraphApplyNodeIcon(icon, type);
        updateText();

        QString tooltip = QString("%1\n%2").arg(type, id);
        if (node.contains("host_state"))
            tooltip += "\nstate: " + node.value("host_state").toString();
        setToolTip(tooltip);
    }

private:
    void updateText()
    {
        text->setPlainText(label.isEmpty() ? id : label);
        const QRectF r = text->boundingRect();
        text->setPos(-r.width() / 2.0, 26);
    }
};

class GraphEdgeItem final : public QGraphicsPathItem
{
public:
    QString id;
    QString source;
    QString target;
    QString type;
    QGraphicsTextItem* text = nullptr;
    QList<QGraphicsPathItem*> directionSegments;

    GraphEdgeItem(const QString& edgeId, const QString& src, const QString& dst, const QString& edgeType)
        : QGraphicsPathItem(), id(edgeId), source(src), target(dst), type(edgeType)
    {
        setZValue(1);
        setFlag(QGraphicsItem::ItemIsSelectable);

        QPen basePen(QColor("#777777"), 0.45);
        basePen.setCapStyle(Qt::RoundCap);
        basePen.setJoinStyle(Qt::RoundJoin);
        setPen(basePen);
        setBrush(Qt::NoBrush);

        text = new QGraphicsTextItem(this);
        text->setDefaultTextColor(QColor("#aaaaaa"));
        text->setPlainText(type);
        text->setZValue(8);
    }

    ~GraphEdgeItem() override
    {
        qDeleteAll(directionSegments);
        directionSegments.clear();
    }

    void rebuildDirectionSegments(const QPainterPath& visualPath)
    {
        qDeleteAll(directionSegments);
        directionSegments.clear();

        QPen currentPen = pen();
        QColor color = currentPen.color();

        if (!color.isValid())
            color = QColor("#777777");

        // Keep the real selectable path very thin. Direction is shown by
        // child segments that gradually get thicker from source to target.
        QPen basePen(color);
        basePen.setWidthF(0.35);
        basePen.setCapStyle(Qt::RoundCap);
        basePen.setJoinStyle(Qt::RoundJoin);
        QGraphicsPathItem::setPen(basePen);

        const int segmentCount = 10;

        for (int i = 0; i < segmentCount; ++i) {
            const qreal t1 = static_cast<qreal>(i) / static_cast<qreal>(segmentCount);
            const qreal t2 = static_cast<qreal>(i + 1) / static_cast<qreal>(segmentCount);

            QPainterPath segment;
            segment.moveTo(visualPath.pointAtPercent(t1));

            // Use small substeps so curved edges stay smooth.
            const int subSteps = 3;
            for (int s = 1; s <= subSteps; ++s) {
                const qreal t = t1 + (t2 - t1) * (static_cast<qreal>(s) / static_cast<qreal>(subSteps));
                segment.lineTo(visualPath.pointAtPercent(t));
            }

            auto* item = new QGraphicsPathItem(this);
            item->setPath(segment);

            const qreal progress = static_cast<qreal>(i + 1) / static_cast<qreal>(segmentCount);
            const qreal width = 0.75 + (progress * 2.45);

            QPen segmentPen(color);
            segmentPen.setWidthF(width);
            segmentPen.setCapStyle(Qt::RoundCap);
            segmentPen.setJoinStyle(Qt::RoundJoin);

            item->setPen(segmentPen);
            item->setBrush(Qt::NoBrush);
            item->setZValue(2);
            item->setAcceptedMouseButtons(Qt::NoButton);

            directionSegments.append(item);
        }
    }

    void updatePath(const QPointF& a, const QPointF& b, int laneIndex, int laneCount, bool reversePair)
    {
        const QLineF base(a, b);

        if (base.length() < 1.0) {
            QPainterPath emptyPath;
            emptyPath.moveTo(a);
            setPath(emptyPath);
            rebuildDirectionSegments(emptyPath);

            if (text)
                text->setPos(a.x(), a.y());

            return;
        }

        QPointF unit = (b - a) / base.length();
        QPointF normal(-unit.y(), unit.x());

        const double centeredLane = laneIndex - ((laneCount - 1) / 2.0);
        double curveOffset = 0.0;

        // Same-direction parallel edges get moderate lane spacing.
        if (laneCount > 1)
            curveOffset = centeredLane * 52.0;

        // Reverse edge policy:
        // - Identity/context edges stay straight for readability.
        // - ACL/control edges curve away so MemberOf and ACLRight do not overlap.
        if (reversePair) {
            const QString lowerType = type.toLower();

            const bool keepStraight =
                lowerType == "memberof" ||
                lowerType == "indomain" ||
                lowerType == "runningas" ||
                lowerType == "runningon";

            if (keepStraight) {
                curveOffset = 0.0;
            } else {
                const double directionSide = (source < target) ? -1.0 : 1.0;
                curveOffset = directionSide * (86.0 + qAbs(centeredLane) * 22.0);
            }
        }

        const QPointF mid = (a + b) / 2.0;
        const QPointF control = mid + normal * curveOffset;

        QPainterPath p;
        p.moveTo(a);

        if (qAbs(curveOffset) < 0.5) {
            p.lineTo(b);
        } else {
            p.quadTo(control, b);
        }

        setPath(p);
        rebuildDirectionSegments(p);

        if (text) {
            const QPointF labelPos = (qAbs(curveOffset) < 0.5)
                ? mid + normal * 12.0
                : p.pointAtPercent(0.50) + normal * ((curveOffset > 0) ? 22.0 : -30.0);

            const QRectF r = text->boundingRect();
            text->setPos(labelPos.x() - r.width() / 2.0, labelPos.y() - r.height() / 2.0);
        }
    }
};

GraphCanvas::GraphCanvas(QWidget* parent) : QGraphicsView(parent)
{
    scene = new QGraphicsScene(this);
    setScene(scene);

    setRenderHint(QPainter::Antialiasing);
    setDragMode(QGraphicsView::NoDrag);
    setTransformationAnchor(QGraphicsView::AnchorUnderMouse);
    setResizeAnchor(QGraphicsView::AnchorViewCenter);
    setSceneRect(-1000, -1000, 2000, 2000);
}

void GraphCanvas::clearGraph()
{
    scene->clear();
    nodes.clear();
    edges.clear();
    nodeJson.clear();
    edgeJson.clear();
}

void GraphCanvas::upsertNode(const QJsonObject& node)
{
    const QString id = node.value("id").toString();
    if (id.isEmpty())
        return;

    const QString label = node.value("label").toString(id);
    const QString type = node.value("type").toString("Unknown");

    nodeJson.insert(id, node);

    GraphNodeItem* item = nodes.value(id, nullptr);
    if (!item) {
        item = new GraphNodeItem(id, label, type);
        scene->addItem(item);

        const int index = nodes.size();
        const int count = qMax(1, nodes.size() + 1);
        const double radius = qMax(160.0, count * 55.0);
        const double angle = (2.0 * M_PI * index) / count;
        item->setPos(qCos(angle) * radius, qSin(angle) * radius);

        nodes.insert(id, item);
    }

    item->updateFromJson(node);

    if (focusMode)
        applyFocusVisibility();

    updateAllEdges();
}

void GraphCanvas::upsertEdge(const QJsonObject& edge)
{
    const QString id = edge.value("id").toString();
    const QString source = edge.value("source").toString(edge.value("source_id").toString());
    const QString target = edge.value("target").toString(edge.value("target_id").toString());
    const QString type = edge.value("type").toString("Related");
    const QString displayLabel = opsGraphEdgeDisplayLabel(edge);

    if (id.isEmpty() || source.isEmpty() || target.isEmpty())
        return;

    if (!nodes.contains(source) || !nodes.contains(target))
        return;

    edgeJson.insert(id, edge);

    GraphEdgeItem* item = edges.value(id, nullptr);
    if (!item) {
        item = new GraphEdgeItem(id, source, target, type);
        scene->addItem(item);
        edges.insert(id, item);
    }

    item->source = source;
    item->target = target;
    item->type = type; // Keep raw edge type for filtering/focus logic.
    item->text->setPlainText(displayLabel);
    item->setToolTip(QString("%1\n%2 -> %3").arg(displayLabel, source, target));

    if (focusMode)
        applyFocusVisibility();

    updateAllEdges();
}


void GraphCanvas::focusNode(const QString& nodeId)
{
    GraphNodeItem* item = nodes.value(nodeId, nullptr);
    if (!item)
        return;

    if (scene)
        scene->clearSelection();

    item->setSelected(true);
    centerOn(item);

    Q_EMIT nodeSelected(nodeId, nodeJson.value(nodeId));
}


void GraphCanvas::focusNeighborhood(const QString& nodeId)
{
    if (nodeId.isEmpty() || !nodes.contains(nodeId))
        return;

    focusMode = true;
    focusedNodeId = nodeId;

    applyFocusVisibility();

    GraphNodeItem* item = nodes.value(nodeId, nullptr);
    if (!item)
        return;

    if (scene)
        scene->clearSelection();

    item->setSelected(true);
    centerOn(item);
}

void GraphCanvas::clearFocusMode()
{
    focusMode = false;
    focusedNodeId.clear();

    for (auto it = nodes.begin(); it != nodes.end(); ++it)
        it.value()->setVisible(true);

    for (auto it = edges.begin(); it != edges.end(); ++it)
        it.value()->setVisible(true);

    updateAllEdges();
}

void GraphCanvas::applyFocusVisibility()
{
    if (!focusMode || focusedNodeId.isEmpty()) {
        clearFocusMode();
        return;
    }

    if (!nodes.contains(focusedNodeId))
        return;

    QSet<QString> visibleNodes;
    visibleNodes.insert(focusedNodeId);

    // First hop: direct neighbors of the selected node.
    for (auto it = edges.begin(); it != edges.end(); ++it) {
        GraphEdgeItem* edge = it.value();
        if (!edge)
            continue;

        if (edge->source == focusedNodeId) {
            visibleNodes.insert(edge->source);
            visibleNodes.insert(edge->target);
        } else if (edge->target == focusedNodeId) {
            visibleNodes.insert(edge->source);
            visibleNodes.insert(edge->target);
        }
    }

    // Smart bridge: if an Agent is in the focused neighborhood, include its
    // direct user/computer context. This gives:
    //   User -> Agent -> Computer
    //   Computer -> Agent -> User
    //   Agent -> User + Computer
    bool changed = true;
    while (changed) {
        changed = false;

        for (auto it = edges.begin(); it != edges.end(); ++it) {
            GraphEdgeItem* edge = it.value();
            if (!edge)
                continue;

            const bool sourceVisible = visibleNodes.contains(edge->source);
            const bool targetVisible = visibleNodes.contains(edge->target);

            const GraphNodeItem* sourceNode = nodes.value(edge->source, nullptr);
            const GraphNodeItem* targetNode = nodes.value(edge->target, nullptr);

            const bool sourceIsAgent = sourceNode && sourceNode->type == "Agent";
            const bool targetIsAgent = targetNode && targetNode->type == "Agent";

            if (sourceVisible && sourceIsAgent && !visibleNodes.contains(edge->target)) {
                visibleNodes.insert(edge->target);
                changed = true;
            }

            if (targetVisible && targetIsAgent && !visibleNodes.contains(edge->source)) {
                visibleNodes.insert(edge->source);
                changed = true;
            }
        }
    }

    for (auto it = nodes.begin(); it != nodes.end(); ++it)
        it.value()->setVisible(visibleNodes.contains(it.key()));

    for (auto it = edges.begin(); it != edges.end(); ++it) {
        GraphEdgeItem* edge = it.value();
        if (!edge)
            continue;

        const bool visible = visibleNodes.contains(edge->source) &&
                             visibleNodes.contains(edge->target);

        edge->setVisible(visible);
    }

    updateAllEdges();
}

void GraphCanvas::applyFilter(const QStringList& enabledTypes)
{
    for (auto it = nodes.begin(); it != nodes.end(); ++it) {
        const bool visible = enabledTypes.isEmpty() || enabledTypes.contains(it.value()->type);
        it.value()->setVisible(visible);
    }

    for (auto it = edges.begin(); it != edges.end(); ++it) {
        const bool visible = nodes.contains(it.value()->source)
                             && nodes.contains(it.value()->target)
                             && nodes.value(it.value()->source)->isVisible()
                             && nodes.value(it.value()->target)->isVisible();
        it.value()->setVisible(visible);
    }
}

void GraphCanvas::focusSearch(const QString& text)
{
    const QString needle = text.trimmed().toLower();

    for (auto it = nodes.begin(); it != nodes.end(); ++it) {
        GraphNodeItem* node = it.value();
        const bool match = needle.isEmpty()
                           || node->id.toLower().contains(needle)
                           || node->label.toLower().contains(needle)
                           || node->type.toLower().contains(needle);

        node->setOpacity(match ? 1.0 : 0.25);

        if (match && !needle.isEmpty()) {
            centerOn(node);
        }
    }
}

void GraphCanvas::wheelEvent(QWheelEvent* event)
{
    const double scaleFactor = event->angleDelta().y() > 0 ? 1.12 : 0.89;
    scale(scaleFactor, scaleFactor);
}

void GraphCanvas::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::MiddleButton || event->button() == Qt::RightButton) {
        panning = true;
        lastPanPoint = event->pos();
        setCursor(Qt::ClosedHandCursor);
        event->accept();
        return;
    }

    QGraphicsItem* rawItem = itemAt(event->pos());
    if (rawItem && rawItem->parentItem())
        rawItem = rawItem->parentItem();

    if (auto* node = dynamic_cast<GraphNodeItem*>(rawItem)) {
        if (scene)
            scene->clearSelection();

        node->setSelected(true);
        Q_EMIT nodeSelected(node->id, nodeJson.value(node->id));
    } else if (auto* edge = dynamic_cast<GraphEdgeItem*>(rawItem)) {
        if (scene)
            scene->clearSelection();

        edge->setSelected(true);
        Q_EMIT edgeSelected(edge->id, edgeJson.value(edge->id));
    }

    QGraphicsView::mousePressEvent(event);
}

void GraphCanvas::mouseMoveEvent(QMouseEvent* event)
{
    if (panning) {
        const QPoint delta = event->pos() - lastPanPoint;
        lastPanPoint = event->pos();

        horizontalScrollBar()->setValue(horizontalScrollBar()->value() - delta.x());
        verticalScrollBar()->setValue(verticalScrollBar()->value() - delta.y());

        event->accept();
        return;
    }

    QGraphicsView::mouseMoveEvent(event);
    updateAllEdges();
}

void GraphCanvas::mouseReleaseEvent(QMouseEvent* event)
{
    if (event->button() == Qt::MiddleButton || event->button() == Qt::RightButton) {
        panning = false;
        setCursor(Qt::ArrowCursor);
        event->accept();
        return;
    }

    QGraphicsView::mouseReleaseEvent(event);
    updateAllEdges();
}

void GraphCanvas::scheduleLayoutTick()
{
    const int count = nodes.size();
    if (count == 0)
        return;

    const double radius = qMax(160.0, count * 55.0);
    int index = 0;

    for (auto it = nodes.begin(); it != nodes.end(); ++it) {
        const double angle = (2.0 * M_PI * index) / count;
        it.value()->setPos(qCos(angle) * radius, qSin(angle) * radius);
        index++;
    }

    updateAllEdges();
}

void GraphCanvas::updateAllEdges()
{
    struct EdgeLaneInfo {
        int laneIndex = 0;
        int laneCount = 1;
        bool reversePair = false;
    };

    QHash<QString, QList<QString>> pairToEdges;
    QHash<QString, bool> pairHasReverse;

    auto pairKey = [](const QString& a, const QString& b) -> QString {
        if (a < b)
            return a + "|" + b;
        return b + "|" + a;
    };

    for (auto it = edges.constBegin(); it != edges.constEnd(); ++it) {
        GraphEdgeItem* edge = it.value();

        if (!edge)
            continue;

        const QString key = pairKey(edge->source, edge->target);
        pairToEdges[key].append(edge->id);
    }

    for (auto it = pairToEdges.constBegin(); it != pairToEdges.constEnd(); ++it) {
        const QList<QString> edgeIds = it.value();

        bool hasReverse = false;

        for (int i = 0; i < edgeIds.size() && !hasReverse; ++i) {
            GraphEdgeItem* a = edges.value(edgeIds.at(i), nullptr);
            if (!a)
                continue;

            for (int j = i + 1; j < edgeIds.size(); ++j) {
                GraphEdgeItem* b = edges.value(edgeIds.at(j), nullptr);
                if (!b)
                    continue;

                if (a->source == b->target && a->target == b->source) {
                    hasReverse = true;
                    break;
                }
            }
        }

        pairHasReverse[it.key()] = hasReverse;
    }

    QHash<QString, EdgeLaneInfo> laneByEdgeId;

    for (auto it = pairToEdges.constBegin(); it != pairToEdges.constEnd(); ++it) {
        QList<QString> edgeIds = it.value();

        std::sort(edgeIds.begin(), edgeIds.end(),
                  [](const QString& a, const QString& b) {
                      return a < b;
                  });

        const int count = qMax(1, edgeIds.size());

        for (int i = 0; i < edgeIds.size(); ++i) {
            EdgeLaneInfo info;
            info.laneIndex = i;
            info.laneCount = count;
            info.reversePair = pairHasReverse.value(it.key(), false);
            laneByEdgeId.insert(edgeIds.at(i), info);
        }
    }

    for (auto it = edges.begin(); it != edges.end(); ++it) {
        GraphEdgeItem* edge = it.value();

        if (!edge)
            continue;

        GraphNodeItem* src = nodes.value(edge->source, nullptr);
        GraphNodeItem* dst = nodes.value(edge->target, nullptr);

        if (!src || !dst)
            continue;

        const EdgeLaneInfo info = laneByEdgeId.value(edge->id);
        edge->updatePath(src->pos(), dst->pos(), info.laneIndex, info.laneCount, info.reversePair);
    }
}
