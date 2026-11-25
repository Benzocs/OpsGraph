#ifndef ADAPTIXCLIENT_OPSGRAPHCANVAS_H
#define ADAPTIXCLIENT_OPSGRAPHCANVAS_H

#include <QGraphicsView>
#include <QHash>
#include <QJsonObject>
#include <QString>
#include <QStringList>

class QGraphicsScene;
class GraphNodeItem;
class GraphEdgeItem;

class GraphCanvas final : public QGraphicsView
{
Q_OBJECT

public:
    explicit GraphCanvas(QWidget* parent = nullptr);
    ~GraphCanvas() override = default;

    void clearGraph();
    void upsertNode(const QJsonObject& node);
    void upsertEdge(const QJsonObject& edge);
    void applyFilter(const QStringList& enabledTypes);
    void focusSearch(const QString& text);
    void focusNode(const QString& nodeId);
    void focusNeighborhood(const QString& nodeId);
    void clearFocusMode();
    bool isFocusModeEnabled() const { return focusMode; }

Q_SIGNALS:
    void nodeSelected(const QString& nodeId, const QJsonObject& node);
    void edgeSelected(const QString& edgeId, const QJsonObject& edge);

protected:
    void wheelEvent(QWheelEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;

private:
    QGraphicsScene* scene = nullptr;
    QHash<QString, GraphNodeItem*> nodes;
    QHash<QString, GraphEdgeItem*> edges;
    QHash<QString, QJsonObject> nodeJson;
    QHash<QString, QJsonObject> edgeJson;
    QPoint lastPanPoint;
    bool panning = false;
    bool focusMode = false;
    QString focusedNodeId;

    void scheduleLayoutTick();
    void updateAllEdges();
    void applyFocusVisibility();
};

#endif
