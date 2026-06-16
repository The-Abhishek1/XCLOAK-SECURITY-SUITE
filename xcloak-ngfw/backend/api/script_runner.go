package api

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

// DispatchScript — POST /api/scripts/run
func DispatchScript(c *gin.Context) {
	var req struct {
		AgentIDs []int  `json:"agent_ids"`
		Script   string `json:"script"`
		Label    string `json:"label"`
		Shell    string `json:"shell"` // bash | sh | python3 — default bash
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if req.Script == "" {
		c.JSON(400, gin.H{"error": "script is required"})
		return
	}
	if len(req.AgentIDs) == 0 {
		c.JSON(400, gin.H{"error": "agent_ids is required"})
		return
	}
	if req.Shell == "" {
		req.Shell = "bash"
	}

	payload, _ := json.Marshal(map[string]string{
		"script": req.Script,
		"shell":  req.Shell,
		"label":  req.Label,
	})

	username, _ := c.Get("username")
	user := fmt.Sprintf("%v", username)

	type taskRow struct {
		AgentID  int    `json:"agent_id"`
		Hostname string `json:"hostname"`
		TaskID   int    `json:"task_id"`
		Error    string `json:"error,omitempty"`
	}
	var tasks []taskRow

	for _, agentID := range req.AgentIDs {
		var hostname string
		database.DB.QueryRow(`SELECT hostname FROM agents WHERE id=$1`, agentID).Scan(&hostname)

		err := repositories.CreateTask(models.AgentTask{
			AgentID:  agentID,
			TaskType: "execute_script",
			Payload:  payload,
		})
		if err != nil {
			tasks = append(tasks, taskRow{AgentID: agentID, Hostname: hostname, Error: err.Error()})
			continue
		}

		var taskID int
		database.DB.QueryRow(`
			SELECT id FROM agent_tasks
			WHERE agent_id=$1 AND task_type='execute_script'
			ORDER BY id DESC LIMIT 1
		`, agentID).Scan(&taskID)

		tasks = append(tasks, taskRow{AgentID: agentID, Hostname: hostname, TaskID: taskID})
		services.LogEvent("SCRIPT_DISPATCH",
			fmt.Sprintf("agent #%d label=%q by %s", agentID, req.Label, user), user)
	}

	c.JSON(200, gin.H{"tasks": tasks})
}

// GetScriptResult — GET /api/scripts/result/:task_id
// Polls until status == "completed".
func GetScriptResult(c *gin.Context) {
	taskID := c.Param("task_id")
	task, err := repositories.GetTaskByID(taskID)
	if err != nil {
		c.JSON(404, gin.H{"error": "task not found"})
		return
	}
	c.JSON(200, gin.H{
		"task_id":      task.ID,
		"agent_id":     task.AgentID,
		"status":       task.Status,
		"result":       task.Result,
		"created_at":   task.CreatedAt,
		"completed_at": task.CompletedAt,
	})
}

// GetScriptTemplates — GET /api/scripts/templates
func GetScriptTemplates(c *gin.Context) {
	templates := []map[string]any{
		{"id": "netstat",       "label": "Active connections",        "category": "Network",        "shell": "bash", "script": "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null"},
		{"id": "listening",     "label": "Listening ports + process", "category": "Network",        "shell": "bash", "script": "ss -tlnp | awk 'NR>1 {print $4, $6}'"},
		{"id": "arp",           "label": "ARP table",                 "category": "Network",        "shell": "bash", "script": "arp -n 2>/dev/null || ip neigh show"},
		{"id": "dns_check",     "label": "DNS resolution",            "category": "Network",        "shell": "bash", "script": "cat /etc/resolv.conf\ndig +short google.com 2>/dev/null || nslookup google.com"},
		{"id": "top_procs",     "label": "Top CPU processes",         "category": "System",         "shell": "bash", "script": "ps aux --sort=-%cpu | head -20"},
		{"id": "open_files",    "label": "Open files by process",     "category": "System",         "shell": "bash", "script": "lsof -nP 2>/dev/null | head -50"},
		{"id": "env_vars",      "label": "Environment variables",     "category": "System",         "shell": "bash", "script": "env | sort"},
		{"id": "disk_usage",    "label": "Disk usage",                "category": "System",         "shell": "bash", "script": "df -h\ndu -sh /* 2>/dev/null | sort -rh | head -20"},
		{"id": "crontabs",      "label": "All crontabs",              "category": "Persistence",    "shell": "bash", "script": "for u in $(cut -f1 -d: /etc/passwd); do echo \"=== $u ===\"; crontab -u $u -l 2>/dev/null; done\nls -la /etc/cron* 2>/dev/null"},
		{"id": "startup",       "label": "Enabled systemd services",  "category": "Persistence",    "shell": "bash", "script": "systemctl list-units --type=service --state=enabled 2>/dev/null | head -40"},
		{"id": "suid",          "label": "SUID/SGID files",           "category": "Privesc",        "shell": "bash", "script": "find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | head -40"},
		{"id": "logins",        "label": "Recent login history",      "category": "Auth",           "shell": "bash", "script": "last -n 20\necho '--- Failed ---'\nlastb -n 20 2>/dev/null || grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -20"},
		{"id": "tmp_exec",      "label": "Executables in /tmp",       "category": "Malware",        "shell": "bash", "script": "find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null\nls -la /tmp/ /var/tmp/"},
		{"id": "kernel_mods",   "label": "Loaded kernel modules",     "category": "Rootkit",        "shell": "bash", "script": "lsmod | sort"},
		{"id": "bash_history",  "label": "Bash history (root)",       "category": "Forensics",      "shell": "bash", "script": "tail -50 /root/.bash_history 2>/dev/null || echo 'no root history'"},
	}

	byCategory := map[string][]map[string]any{}
	for _, t := range templates {
		cat := t["category"].(string)
		byCategory[cat] = append(byCategory[cat], t)
	}
	c.JSON(200, gin.H{"templates": templates, "by_category": byCategory})
}

// GetScriptHistory — GET /api/scripts/history?agent_id=1
func GetScriptHistory(c *gin.Context) {
	agentID := c.Query("agent_id")

	var rows interface{ Next() bool; Scan(...any) error; Close() error }
	var err error

	if agentID != "" {
		id, _ := strconv.Atoi(agentID)
		rows, err = database.DB.Query(`
			SELECT t.id, t.agent_id, COALESCE(a.hostname,''), COALESCE(t.payload::text,'{}'),
			       t.status, COALESCE(t.result,''), t.created_at, t.completed_at
			FROM agent_tasks t LEFT JOIN agents a ON a.id=t.agent_id
			WHERE t.task_type='execute_script' AND t.agent_id=$1
			ORDER BY t.id DESC LIMIT 50
		`, id)
	} else {
		rows, err = database.DB.Query(`
			SELECT t.id, t.agent_id, COALESCE(a.hostname,''), COALESCE(t.payload::text,'{}'),
			       t.status, COALESCE(t.result,''), t.created_at, t.completed_at
			FROM agent_tasks t LEFT JOIN agents a ON a.id=t.agent_id
			WHERE t.task_type='execute_script'
			ORDER BY t.id DESC LIMIT 100
		`)
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type Row struct {
		ID          int     `json:"id"`
		AgentID     int     `json:"agent_id"`
		Hostname    string  `json:"hostname"`
		Label       string  `json:"label"`
		Script      string  `json:"script"`
		Status      string  `json:"status"`
		Result      string  `json:"result"`
		CreatedAt   string  `json:"created_at"`
		CompletedAt *string `json:"completed_at"`
	}
	var history []Row
	for rows.Next() {
		var r Row
		var payload string
		var completedAt *string
		if err := rows.Scan(&r.ID, &r.AgentID, &r.Hostname, &payload,
			&r.Status, &r.Result, &r.CreatedAt, &completedAt); err == nil {
			var p map[string]string
			json.Unmarshal([]byte(payload), &p)
			r.Label  = p["label"]
			r.Script = p["script"]
			r.CompletedAt = completedAt
			history = append(history, r)
		}
	}
	if history == nil {
		history = []Row{}
	}
	c.JSON(200, history)
}
