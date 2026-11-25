#include "OperationGraphTab.h"
#include "GraphCanvas.h"

#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QLabel>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

OperationGraphTab::OperationGraphTab(QWidget* parent) : QWidget(parent)
{
    buildUi();
}

void OperationGraphTab::buildUi()
{
    auto* root = new QVBoxLayout(this);
    auto* top = new QHBoxLayout();
    searchBar = new QLineEdit(this);
    searchBar->setPlaceholderText("Search nodes, domains, users, hosts...");
    liveIndicator = new QLabel("Live: ON", this);
    pathButton = new QPushButton("Path to High Value", this);
    top->addWidget(searchBar, 1);
    top->addWidget(liveIndicator);
    top->addWidget(pathButton);

    auto* body = new QHBoxLayout();
    filterList = new QListWidget(this);
    filterList->setMaximumWidth(220);
    filterList->addItems({"Agent", "Computer", "User", "Domain", "Group", "Credential", "Session", "Trust"});

    canvas = new GraphCanvas(this);
    detailsPanel = new QWidget(this);
    detailsPanel->setMinimumWidth(320);
    detailsPanel->setMaximumWidth(420);

    body->addWidget(filterList);
    body->addWidget(canvas, 1);
    body->addWidget(detailsPanel);

    root->addLayout(top);
    root->addLayout(body, 1);

    connect(searchBar, &QLineEdit::textChanged, this, &OperationGraphTab::onSearchChanged);
    connect(canvas, &GraphCanvas::nodeSelected, this, &OperationGraphTab::onNodeSelected);
    connect(pathButton, &QPushButton::clicked, this, &OperationGraphTab::onPathToHighValue);
}

void OperationGraphTab::loadInitialState()
{
    // Wire this to existing Adaptix client HTTP API layer:
    // GET /opsgraph/state -> canvas->upsertNode / canvas->upsertEdge
}

void OperationGraphTab::applyDelta(const QJsonObject& delta)
{
    if (!liveMode) return;
    cursor = delta.value("cursor").toVariant().toLongLong();
    for (const auto& n : delta.value("nodes").toArray()) canvas->upsertNode(n.toObject());
    for (const auto& e : delta.value("edges").toArray()) canvas->upsertEdge(e.toObject());
}

void OperationGraphTab::setLiveMode(bool enabled)
{
    liveMode = enabled;
    liveIndicator->setText(enabled ? "Live: ON" : "Live: PAUSED");
}

void OperationGraphTab::onSearchChanged(const QString& text)
{
    canvas->focusSearch(text);
}

void OperationGraphTab::onNodeSelected(const QString& nodeId)
{
    Q_UNUSED(nodeId);
    // GET /opsgraph/node/:id and render evidence/details.
}

void OperationGraphTab::onPathToHighValue()
{
    // POST /opsgraph/path with selected start/high-value targets.
}

void OperationGraphTab::renderNodeDetails(const QJsonObject& node)
{
    Q_UNUSED(node);
}

void OperationGraphTab::renderEvidence(const QJsonArray& evidence)
{
    Q_UNUSED(evidence);
}
