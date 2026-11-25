#include "GraphCanvas.h"

#include <QGraphicsScene>
#include <QGraphicsEllipseItem>
#include <QWheelEvent>
#include <QMouseEvent>
#include <QtMath>

class GraphNodeItem : public QGraphicsEllipseItem
{
public:
    QString id;
    QString type;
    explicit GraphNodeItem(const QString& nodeId) : QGraphicsEllipseItem(-18, -18, 36, 36), id(nodeId) {
        setFlag(QGraphicsItem::ItemIsMovable);
        setFlag(QGraphicsItem::ItemIsSelectable);
        setToolTip(nodeId);
    }
};

class GraphEdgeItem : public QGraphicsLineItem
{
public:
    QString id;
    QString source;
    QString target;
};

GraphCanvas::GraphCanvas(QWidget* parent) : QGraphicsView(parent)
{
    scene = new QGraphicsScene(this);
    setScene(scene);
    setRenderHint(QPainter::Antialiasing, true);
    setDragMode(QGraphicsView::NoDrag);
    setTransformationAnchor(QGraphicsView::AnchorUnderMouse);
}

void GraphCanvas::clearGraph()
{
    scene->clear();
    nodes.clear();
    edges.clear();
}

void GraphCanvas::upsertNode(const QJsonObject& node)
{
    const QString id = node.value("id").toString();
    if (id.isEmpty()) return;
    auto* item = nodes.value(id, nullptr);
    if (!item) {
        item = new GraphNodeItem(id);
        item->type = node.value("type").toString();
        const int idx = nodes.size();
        const qreal angle = idx * 0.61803398875 * 6.2831853;
        item->setPos(qCos(angle) * 180, qSin(angle) * 180);
        scene->addItem(item);
        nodes.insert(id, item);
    }
    item->setToolTip(node.value("label").toString() + "\n" + id);
}

void GraphCanvas::upsertEdge(const QJsonObject& edge)
{
    const QString id = edge.value("id").toString();
    const QString source = edge.value("source").toString();
    const QString target = edge.value("target").toString();
    if (!nodes.contains(source) || !nodes.contains(target) || id.isEmpty()) return;
    auto* item = edges.value(id, nullptr);
    if (!item) {
        item = new GraphEdgeItem();
        item->id = id; item->source = source; item->target = target;
        scene->addItem(item);
        edges.insert(id, item);
    }
    item->setLine(QLineF(nodes[source]->pos(), nodes[target]->pos()));
    item->setToolTip(edge.value("type").toString());
}

void GraphCanvas::applyFilter(const QStringList& enabledTypes)
{
    for (auto it = nodes.begin(); it != nodes.end(); ++it) {
        it.value()->setVisible(enabledTypes.contains(it.value()->type));
    }
}

void GraphCanvas::focusSearch(const QString& text)
{
    if (text.trimmed().isEmpty()) return;
    for (auto it = nodes.begin(); it != nodes.end(); ++it) {
        if (it.key().contains(text, Qt::CaseInsensitive)) {
            centerOn(it.value());
            it.value()->setSelected(true);
            return;
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
        return;
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
        return;
    }
    QGraphicsView::mouseMoveEvent(event);
}

void GraphCanvas::scheduleLayoutTick()
{
    // TODO: small force-directed layout worker for smoother graph motion.
}
