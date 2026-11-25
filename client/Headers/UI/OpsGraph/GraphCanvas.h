#pragma once

#include <QGraphicsView>
#include <QHash>
#include <QJsonObject>

class QGraphicsScene;
class GraphNodeItem;
class GraphEdgeItem;

class GraphCanvas : public QGraphicsView
{
    Q_OBJECT
public:
    explicit GraphCanvas(QWidget* parent = nullptr);

    void clearGraph();
    void upsertNode(const QJsonObject& node);
    void upsertEdge(const QJsonObject& edge);
    void applyFilter(const QStringList& enabledTypes);
    void focusSearch(const QString& text);

signals:
    void nodeSelected(const QString& nodeId);

protected:
    void wheelEvent(QWheelEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;

private:
    void scheduleLayoutTick();

    QGraphicsScene* scene = nullptr;
    QHash<QString, GraphNodeItem*> nodes;
    QHash<QString, GraphEdgeItem*> edges;
    QPoint lastPanPoint;
    bool panning = false;
};
