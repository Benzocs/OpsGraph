package connector

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func (connector *TsConnector) TcOpsGraphState(c *gin.Context) {
	state, err := connector.teamserver.TsOpsGraphState(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "state": state})
}

func (connector *TsConnector) TcOpsGraphDelta(c *gin.Context) {
	cursor := int64(0)
	if raw := c.Query("since"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid since cursor"})
			return
		}
		cursor = parsed
	}

	delta, err := connector.teamserver.TsOpsGraphDeltaSince(c.Request.Context(), cursor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "delta": delta})
}

func (connector *TsConnector) TcOpsGraphSearch(c *gin.Context) {
	query := c.Query("q")
	limit := 50

	if raw := c.Query("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid limit"})
			return
		}
		limit = parsed
	}

	nodes, err := connector.teamserver.TsOpsGraphSearch(c.Request.Context(), query, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "nodes": nodes})
}

func (connector *TsConnector) TcOpsGraphNode(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "missing node id"})
		return
	}

	node, evidence, err := connector.teamserver.TsOpsGraphNode(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "node": node, "evidence": evidence})
}

func (connector *TsConnector) TcOpsGraphEdgeEvidence(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "missing edge id"})
		return
	}

	evidence, err := connector.teamserver.TsOpsGraphEdgeEvidence(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "evidence": evidence})
}

func (connector *TsConnector) TcOpsGraphClear(c *gin.Context) {
	if err := connector.teamserver.TsOpsGraphClear(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (connector *TsConnector) TcOpsGraphRebuild(c *gin.Context) {
	processed, err := connector.teamserver.TsOpsGraphRebuildFromTasks(c.Request.Context(), 5000)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "processed": processed})
}
