import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
});

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

const OPTIONAL_PATTERNS = [
  /\/agents\/\d+$/,
  /\/agents\/\d+\/risk/,
  /\/agents\/\d+\/timeline/,
  /\/agents\/\d+\/vulnerabilities/,
  /\/agents\/\d+\/summary/,
  /\/agents\/\d+\/processes/,
  /\/agents\/\d+\/connections/,
  /\/agents\/\d+\/services/,
  /\/agents\/\d+\/users/,
  /\/agents\/\d+\/packages/,
  /\/threat-feeds/,
  /\/quarantine/,
];

api.interceptors.response.use(
  response => {
    if (response.config.url === '/auth/login' && response.data?.token) {
      document.cookie = `token=${response.data.token}; path=/; max-age=86400; SameSite=Lax`;
    }
    return response;
  },
  error => {
    const url = error.config?.url || '';
    const isOptional = OPTIONAL_PATTERNS.some(p => p.test(url));

    if (error.response?.status === 401 && !isOptional) {
      localStorage.removeItem('token');
      localStorage.removeItem('username');
      document.cookie = 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
      if (typeof window !== 'undefined' && !window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  register: (data: { username: string; email: string; password: string; role: string }) => api.post('/auth/register', data),
  login:    (data: { username: string; password: string })                                => api.post('/auth/login', data),
};

export const agentsAPI = {
  getAll:             ()           => api.get('/agents'),
  getById:            (id: number) => api.get(`/agents/${id}`),
  getSummary:         (id: number) => api.get(`/agents/${id}/summary`).catch(() => ({ data: null })),
  getRisk:            (id: number) => api.get(`/agents/${id}/risk`).catch(() => ({ data: null })),
  getTimeline:        (id: number) => api.get(`/agents/${id}/timeline`).catch(() => ({ data: [] })),
  getVulnerabilities: (id: number) => api.get(`/agents/${id}/vulnerabilities`).catch(() => ({ data: [] })),
  vulnerabilityScan:  (id: number) => api.post(`/agents/${id}/vulnerability-scan`),
  heartbeat:          (data: { agent_id: number }) => api.post('/agents/heartbeat', data),

  // NEW: list endpoints for agent detail tabs
  getProcesses:   (id: number) => api.get(`/agents/${id}/processes`).catch(() => ({ data: [] })),
  getConnections: (id: number) => api.get(`/agents/${id}/connections`).catch(() => ({ data: [] })),
  getServices:    (id: number) => api.get(`/agents/${id}/services`).catch(() => ({ data: [] })),
  getUsers:       (id: number) => api.get(`/agents/${id}/users`).catch(() => ({ data: [] })),
  getPackages:    (id: number) => api.get(`/agents/${id}/packages`).catch(() => ({ data: [] })),
  getAuthLogs:    (id: number) => api.get(`/agents/${id}/auth-logs`).catch(() => ({ data: [] })),
  getFileHashes:  (id: number) => api.get(`/agents/${id}/filehashes`).catch(() => ({ data: [] })),
};

export const alertsAPI = {
  getAll:    () => api.get('/alerts'),
  getPaginated: (page = 1, perPage = 50, severity = '', agentId = '') =>
    api.get('/alerts/paginated', { params: { page, per_page: perPage, severity: severity || undefined, agent_id: agentId || undefined } }),
  getByAgent: async (agentId: number) => {
    const res = await api.get('/alerts');
    const all = res.data || [];
    return { ...res, data: all.filter((a: any) => a.agent_id === agentId) };
  },
};

export const incidentsAPI = {
  getAll:       ()                              => api.get('/incidents'),
  getPaginated: (page = 1, perPage = 25, status = '') =>
    api.get('/incidents/paginated', { params: { page, per_page: perPage, status: status || undefined } }),
  getById:      (id: number)                   => api.get(`/incidents/${id}`),
  getEvents:    (id: number)                   => api.get(`/incidents/${id}/events`).catch(() => ({ data: [] })),
  updateStatus: (id: number, status: string)   => api.put(`/incidents/${id}/status`, { status }),
  addNote:      (id: number, note: string)      => api.post(`/incidents/${id}/notes`, { note }),
};

export const dashboardAPI = {
  getOverview: () => api.get('/dashboard/overview'),
};

export const attackPathAPI = {
  get: () => api.get('/attack-path'),
};

export const networkMapAPI = {
  get: (sinceMinutes = 60, limit = 5000) =>
    api.get('/network-map', { params: { since_minutes: sinceMinutes, limit } }),
};

export const iocsAPI = {
  getAll:     ()                         => api.get('/iocs'),
  getById:    (id: number)               => api.get(`/iocs/${id}`),
  create:     (data: any)                => api.post('/iocs', data),
  update:     (id: number, data: any)    => api.put(`/iocs/${id}`, data),
  delete:     (id: number)               => api.delete(`/iocs/${id}`),
  enable:     (id: number)               => api.patch(`/iocs/${id}/enable`),
  disable:    (id: number)               => api.patch(`/iocs/${id}/disable`),
  bulkImport: (data: any)                => api.post('/iocs/import', data),
};

export const playbooksAPI = {
  getAll:        ()                      => api.get('/playbooks'),
  getById:       (id: number)            => api.get(`/playbooks/${id}`),
  getActions:    (id: number)            => api.get(`/playbooks/${id}/actions`),
  create:        (data: any)             => api.post('/playbooks', data),
  update:        (id: number, data: any) => api.put(`/playbooks/${id}`, data),
  delete:        (id: number)            => api.delete(`/playbooks/${id}`),
  enable:        (id: number)            => api.patch(`/playbooks/${id}/enable`),
  disable:       (id: number)            => api.patch(`/playbooks/${id}/disable`),
  createAction:  (data: any)             => api.post('/playbook-actions', data),
  deleteAction:  (id: number)            => api.delete(`/playbook-actions/${id}`),
  getExecutions: ()                      => api.get('/playbook-executions'),
  getStepResults: (executionId: number) => api.get(`/playbook-executions/${executionId}/steps`),
};

export const sigmaAPI = {
  getAll:   ()                      => api.get('/sigma/rules'),
  create:   (data: any)             => api.post('/sigma/rules', data),
  update:   (id: number, data: any) => api.put(`/sigma/rules/${id}`, data),
  delete:   (id: number)            => api.delete(`/sigma/rules/${id}`),
  enable:   (id: number)            => api.patch(`/sigma/rules/${id}/enable`),
  disable:  (id: number)            => api.patch(`/sigma/rules/${id}/disable`),
  test:     (data: { message: string }) => api.post('/sigma/rules/test', data),
  import:   (form: FormData)        => api.post('/sigma/import', form, { headers: { 'Content-Type': 'multipart/form-data' } }),
  stats:    ()                      => api.get('/sigma/stats'),
};

export const threatAPI = {
  scores:      (agentId?: number, hours = 24)  => api.get('/threat/scores', { params: { agent_id: agentId || 0, hours } }),
  fleet:       ()                               => api.get('/threat/fleet'),
  baselines:   (agentId: number)               => api.get('/threat/baselines', { params: { agent_id: agentId } }),
  scoreNow:    (agentId: number)               => api.post(`/threat/score/${agentId}`),
  acknowledge: (id: number)                    => api.post(`/threat/findings/${id}/acknowledge`),
  findings:    (agentId?: number)              => api.get('/ai/anomalies', { params: agentId ? { agent_id: agentId } : {} }),
  runAI:       (agentId: number)               => api.post(`/ai/anomaly/${agentId}`),
};

export const logSearchAPI = {
  search:          (params: Record<string, string | number | undefined>) => api.get('/logs/search', { params }),
  export:          (params: Record<string, string | number | undefined>, format: 'csv' | 'json') =>
                     api.get('/logs/export', { params: { ...params, format }, responseType: 'blob' }),
  stats:           ()                      => api.get('/logs/stats'),
  getSavedSearches: ()                     => api.get('/logs/searches'),
  saveSearch:      (data: any)             => api.post('/logs/searches', data),
  deleteSearch:    (id: number)            => api.delete(`/logs/searches/${id}`),
  runSaved:        (id: number)            => api.post(`/logs/searches/${id}/run`),
  getRetention:    ()                      => api.get('/logs/retention'),
  setRetention:    (days: number)          => api.put('/logs/retention', { retention_days: days }),
};

export const tasksAPI = {
  create:        (data: { agent_id: number; task_type: string; payload: any }) => api.post('/tasks', data),
  getAgentTasks: (agentId: number)  => api.get(`/tasks/agent/${agentId}`),
  submitResult:  (data: any)        => api.post('/tasks/result', data),
  getPendingApproval: ()                       => api.get('/tasks/pending-approval').catch(() => ({ data: [] })),
  approve:            (id: number)             => api.post(`/tasks/${id}/approve`),
  reject:             (id: number, reason: string) => api.post(`/tasks/${id}/reject`, { reason }),
};

export const quarantineAPI = {
  getAll:     ()          => api.get('/quarantine').catch(() => ({ data: [] })),
  quarantine: (data: any) => api.post('/quarantine', data),
};

export const threatFeedsAPI = {
  getAll:  ()           => api.get('/threat-feeds').catch(() => ({ data: [] })),
  create:  (data: any)  => api.post('/threat-feeds', data),
  sync:    (id: number) => api.post(`/threat-feeds/${id}/sync`),
};

export const yaraAPI = {
  getAll:     ()                      => api.get('/yara/rules'),
  create:     (data: any)             => api.post('/yara/rules', data),
  update:     (id: number, data: any) => api.put(`/yara/rules/${id}`, data),
  delete:     (id: number)            => api.delete(`/yara/rules/${id}`),
  enable:     (id: number)            => api.patch(`/yara/rules/${id}/enable`),
  disable:    (id: number)            => api.patch(`/yara/rules/${id}/disable`),
  getMatches: (agentId?: number)      => api.get('/yara/matches', { params: agentId ? { agent_id: agentId } : {} }),
};

export const firewallAPI = {
  getAll:      (group?: string)         => api.get('/firewall/rules', { params: group ? { group } : {} }),
  getById:     (id: number)             => api.get(`/firewall/rules/${id}`),
  create:      (data: any)              => api.post('/firewall/rules', data),
  update:      (id: number, data: any)  => api.put(`/firewall/rules/${id}`, data),
  delete:      (id: number)             => api.delete(`/firewall/rules/${id}`),
  sync:        (data: any)              => api.post('/firewall/sync', data),
  getSyncLog:  (agentId?: number)       => api.get('/firewall/sync/log', { params: agentId ? { agent_id: agentId } : {} }),
  getGroups:   ()                       => api.get('/firewall/groups'),
  getStats:    ()                       => api.get('/firewall/stats'),
  getConflicts: ()                      => api.get('/firewall/conflicts'),
};

export const auditAPI = {
  getLogs:      ()                                     => api.get('/audit/logs'),
  getPaginated: (page = 1, perPage = 50, action = '') =>
    api.get('/audit/logs/paginated', { params: { page, per_page: perPage, action: action || undefined } }),
  getExportStatus: () => api.get('/audit/export/status'),
};

export const usersAPI = {
  getAll:     ()                             => api.get('/users'),
  updateRole: (id: number, role: string)    => api.put(`/users/${id}/role`, { role }),
  toggle:     (id: number, active: boolean) => api.patch(`/users/${id}/toggle`, { is_active: active }),
  delete:     (id: number)                  => api.delete(`/users/${id}`),
  invite:     (username: string, email: string, role: string) => api.post('/users/invite', { username, email, role }),
};

export const complianceAPI = {
  generate:  (reportType: string)  => api.post('/compliance/reports', { report_type: reportType }),
  getAll:    ()                    => api.get('/compliance/reports'),
  getById:   (id: number)          => api.get(`/compliance/reports/${id}`),
  delete:    (id: number)          => api.delete(`/compliance/reports/${id}`),
  pdfUrl:    (id: number)          => `${api.defaults.baseURL}/compliance/reports/${id}/pdf`,
};

export const exportAPI = {
  alertsCSV:       () => `${api.defaults.baseURL}/export/alerts`,
  incidentsCSV:    () => `${api.defaults.baseURL}/export/incidents`,
  vulnsCSV:        () => `${api.defaults.baseURL}/export/vulnerabilities`,
  auditJSON:       () => `${api.defaults.baseURL}/export/audit`,
};

export const cveAPI = {
  lookup: (cveId: string) => api.get(`/cve/${cveId}`),
};

export const aiAPI = {
  triageAlert:      (alertId: number)                           => api.post(`/ai/triage/${alertId}`),
  summarizeIncident:(id: number)                                => api.post(`/ai/incidents/${id}/summarize`),
  runAnomaly:       (agentId: number)                           => api.post(`/ai/anomaly/${agentId}`),
  getAnomalies:     (agentId?: number)                          => api.get('/ai/anomalies', { params: agentId ? { agent_id: agentId } : {} }),
  chat:             (message: string, history: any[])           => api.post('/ai/chat', { message, history }),
  getChatHistory:   ()                                          => api.get('/ai/chat/history'),
  clearChatHistory: ()                                          => api.delete('/ai/chat/history'),
};

export const fimAPI = {
  getBaseline:    (agentId: number) => api.get(`/agents/${agentId}/fim/baseline`),
  getAlerts:      (agentId: number) => api.get(`/agents/${agentId}/fim/alerts`),
  acceptBaseline: (agentId: number, filePath: string) => api.post(`/agents/${agentId}/fim/baseline/accept`, { file_path: filePath }),
};

export const mitreAPI = {
  getMappings: () => api.get('/mitre/mappings'),
};

// Live log SSE URL — use directly with EventSource
export const liveLogURL = (agentId: number, token: string) =>
  `/api/agents/${agentId}/logs/stream?token=${token}`;


export const integrationsAPI = {
  getAll:          ()                                    => api.get('/integrations'),
  save:            (name: string, enabled: boolean, config: any) => api.put(`/integrations/${name}`, { enabled, config }),
  test:            (name: string)                        => api.post(`/integrations/${name}/test`, {}),
  getDeliveries:   ()                                    => api.get('/integrations/deliveries'),
  getInstallTokens:()                                    => api.get('/integrations/install-tokens'),
  createInstallToken:(label: string)                     => api.post('/integrations/install-tokens', { label }),
};

export const correlationAPI = {
  getAll:     ()                               => api.get('/correlation/rules'),
  create:     (rule: any)                      => api.post('/correlation/rules', rule),
  update:     (id: number, rule: any)          => api.put(`/correlation/rules/${id}`, rule),
  toggle:     (id: number, enabled: boolean)   => api.patch(`/correlation/rules/${id}/toggle`, { enabled }),
  delete:     (id: number)                     => api.delete(`/correlation/rules/${id}`),
  getMatches: (ruleId?: number)                => api.get('/correlation/matches', { params: ruleId ? { rule_id: ruleId } : {} }),
};

export const apiKeysAPI = {
  getAll:  ()                                                     => api.get('/api-keys'),
  create:  (label: string, role: string, expiresInDays?: number)  =>
    api.post('/api-keys', { label, role, expires_in_days: expiresInDays || 0 }),
  revoke:  (id: number)                                           => api.delete(`/api-keys/${id}`),
};

export const customRolesAPI = {
  getAll:        ()                                          => api.get('/custom-roles'),
  getPermissions:()                                          => api.get('/permissions'),
  create:        (name: string, permissions: string[])       => api.post('/custom-roles', { name, permissions }),
  update:        (id: number, permissions: string[])         => api.put(`/custom-roles/${id}`, { permissions }),
  delete:        (id: number)                                => api.delete(`/custom-roles/${id}`),
};

export const platformAPI = {
  getTenants:       ()                                                                            => api.get('/platform/tenants'),
  createTenant:     (name: string, slug: string, adminUsername: string, adminEmail: string)        =>
    api.post('/platform/tenants', { name, slug, admin_username: adminUsername, admin_email: adminEmail }),
  toggleTenant:     (id: number, active: boolean)                                                  => api.patch(`/platform/tenants/${id}/toggle`, { is_active: active }),
  getReleases:      ()                                                                            => api.get('/platform/agent-releases'),
  publishRelease:   (data: { platform: string; version: string; sha256: string; download_url: string }) =>
    api.post('/platform/agent-releases', data),
};

export default api;
