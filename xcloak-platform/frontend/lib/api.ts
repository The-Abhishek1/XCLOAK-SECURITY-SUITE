import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
});

// Session cookie is sent automatically by the browser (withCredentials: true
// above). No Authorization header needed — the backend reads the httpOnly cookie.

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

// Lightweight DOM toast — used by the demo 403 interceptor without needing
// React context (api.ts is not a component).
function showDemoToast() {
  if (typeof document === 'undefined') return;
  const existing = document.getElementById('xcloak-demo-toast');
  if (existing) { existing.remove(); }

  const el = document.createElement('div');
  el.id = 'xcloak-demo-toast';
  el.innerHTML = `
    <span style="font-size:16px">🔒</span>
    <span><strong>Demo mode</strong> — this action is disabled in the live demo.
    <a href="https://xcloak.tech" target="_blank" rel="noopener noreferrer" style="color:#60a5fa;text-decoration:underline;margin-left:6px">Get full access →</a></span>
  `;
  Object.assign(el.style, {
    position:     'fixed',
    bottom:       '24px',
    left:         '50%',
    transform:    'translateX(-50%) translateY(12px)',
    zIndex:       '99999',
    display:      'flex',
    alignItems:   'center',
    gap:          '10px',
    padding:      '12px 18px',
    borderRadius: '10px',
    background:   '#1e293b',
    border:       '1px solid #334155',
    color:        '#e2e8f0',
    fontSize:     '13px',
    fontFamily:   'inherit',
    boxShadow:    '0 8px 32px rgba(0,0,0,0.5)',
    opacity:      '0',
    transition:   'opacity 0.2s ease, transform 0.2s ease',
    maxWidth:     'calc(100vw - 32px)',
    whiteSpace:   'nowrap',
  });
  document.body.appendChild(el);
  requestAnimationFrame(() => {
    el.style.opacity = '1';
    el.style.transform = 'translateX(-50%) translateY(0)';
  });
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transform = 'translateX(-50%) translateY(8px)';
    setTimeout(() => el.remove(), 250);
  }, 3500);
}

api.interceptors.response.use(
  response => response,
  error => {
    const url = error.config?.url || '';
    const isOptional = OPTIONAL_PATTERNS.some(p => p.test(url));

    // In demo mode, swallow ALL 403s so pages never crash.
    // - Mutations blocked by DemoReadOnly middleware → show toast
    // - GET endpoints gated by RBAC (e.g. settings, roles) → silent null so
    //   the component renders an empty state instead of throwing
    if (error.response?.status === 403) {
      const isDemo = typeof document !== 'undefined' &&
        document.cookie.split(';').some(c => c.trim().startsWith('demo_mode='));
      const isDemoMsg = (error.response?.data?.error ?? '').includes('demo mode');
      if (isDemo || isDemoMsg) {
        const method = (error.config?.method ?? 'get').toUpperCase();
        if (method !== 'GET' && method !== 'HEAD') {
          showDemoToast();
        }
        return Promise.resolve({ data: null, status: 403, headers: {}, config: error.config });
      }
    }

    if (error.response?.status === 401 && !isOptional) {
      // Clear the JS-readable presence flag (the httpOnly token cookie is
      // cleared by the backend on an explicit logout call).
      document.cookie = 'logged_in=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
      const publicPaths = ['/login', '/signup', '/reset-password', '/demo'];
      const onPublicPage = publicPaths.some(p => window.location.pathname.startsWith(p));
      if (typeof window !== 'undefined' && !onPublicPage) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  register:       (data: { username: string; email: string; password: string; role: string }) => api.post('/auth/register', data),
  login:          (data: { username: string; password: string })                                => api.post('/auth/login', data),
  getProfile:     ()                                   => api.get('/auth/profile'),
  updateProfile:  (data: any)                          => api.patch('/auth/profile', data),
  changePassword: (data: { current_password: string; new_password: string }) => api.post('/auth/change-password', data),
  setup2FA:       ()                                   => api.post('/auth/2fa/setup'),
  verify2FA:      (code: string)                       => api.post('/auth/2fa/verify', { code }),
  disable2FA:     (code: string)                       => api.delete('/auth/2fa', { data: { code } }),
};
export const notificationsAPI = {
  getEmailRules:    ()              => api.get('/notifications/email'),
  createEmailRule:  (data: any)     => api.post('/notifications/email', data),
  toggleEmailRule:  (id: number, enabled: boolean) => api.patch(`/notifications/email/${id}/toggle`, { enabled }),
  deleteEmailRule:  (id: number)    => api.delete(`/notifications/email/${id}`),
  getSMTPConfig:    ()              => api.get('/settings/smtp'),
  saveSMTPConfig:   (data: any)     => api.put('/settings/smtp', data),
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
  getHealth:         ()           => api.get('/agents/health').catch(() => ({ data: [] })),
  getTasks:          (id: number) => api.get(`/agents/${id}/tasks`).catch(() => ({ data: [] })),
  getStartup:        (id: number) => api.get(`/agents/${id}/startup`).catch(() => ({ data: [] })),
  getUsbHistory:     (id: number) => api.get(`/agents/${id}/usb-history`).catch(() => ({ data: [] })),
  getLoginHistory:   (id: number) => api.get(`/agents/${id}/login-history`).catch(() => ({ data: [] })),
  getScheduledTasks: (id: number) => api.get(`/agents/${id}/scheduled-tasks`).catch(() => ({ data: [] })),
  getDrivers:          (id: number) => api.get(`/agents/${id}/drivers`).catch(() => ({ data: [] })),
  getPolicies:         (id: number) => api.get(`/agents/${id}/policies`).catch(() => ({ data: null })),
  getAgentHealth:      (id: number) => api.get(`/agents/${id}/health`).catch(() => ({ data: null })),
  getRiskBreakdown:    (id: number) => api.get(`/agents/${id}/risk/breakdown`).catch(() => ({ data: null })),
  getSecurityStatus:   (id: number) => api.get(`/agents/${id}/security-status`).catch(() => ({ data: null })),
  getCISFindings:      (id: number) => api.get(`/cis/agents/${id}`).catch(() => ({ data: [] })),
  getCISScore:         (id: number) => api.get(`/cis/agents/${id}/score`).catch(() => ({ data: null })),
  triggerCISScan:      (id: number) => api.post(`/cis/agents/${id}/scan`),
  getNetworkAnomalies: (id: number) => api.get(`/nba/baseline/${id}`).catch(() => ({ data: null })),
  getAuditHistory:   (id: number) => api.get(`/agents/${id}/audit-history`).catch(() => ({ data: [] })),
  bulk:              (data: { agent_ids: number[]; action: string; payload?: any }) => api.post('/agents/bulk', data),
};

export const agentGroupsAPI = {
  getAll:  ()                                                    => api.get('/agent-groups').catch(() => ({ data: [] })),
  create:  (data: { name: string; description?: string })        => api.post('/agent-groups', data),
  remove:  (id: number)                                          => api.delete(`/agent-groups/${id}`),
};

export const alertsAPI = {
  getAll:    () => api.get('/alerts'),
  getPaginated: (page = 1, perPage = 50, severity = '', agentId = '', status = '') =>
    api.get('/alerts/paginated', { params: { page, per_page: perPage, severity: severity || undefined, agent_id: agentId || undefined, status: status || undefined } }),
  getFiltered: (params: Record<string, any>) => api.get('/alerts/paginated', { params }),
  getByAgent: async (agentId: number) => {
    const res = await api.get('/alerts');
    const all = res.data || [];
    return { ...res, data: all.filter((a: any) => a.agent_id === agentId) };
  },
  acknowledge:     (id: number, note = '') => api.post(`/alerts/${id}/acknowledge`, { note }),
  resolve:         (id: number, note = '') => api.post(`/alerts/${id}/resolve`, { note }),
  bulkAcknowledge: (ids: number[], note = '') => api.post('/alerts/bulk-acknowledge', { ids, note }),
  snooze:          (id: number, minutes: number) => api.patch(`/alerts/${id}/snooze`, { minutes }),
  updateNote:      (id: number, note: string)    => api.patch(`/alerts/${id}/note`, { note }),
};

export const incidentsAPI = {
  getAll:         ()                              => api.get('/incidents'),
  getCounts:      ()                              => api.get('/incidents/counts'),
  getPaginated:   (page = 1, perPage = 25, status = '') =>
    api.get('/incidents/paginated', { params: { page, per_page: perPage, status: status || undefined } }),
  getById:        (id: number)                   => api.get(`/incidents/${id}`).catch(() => ({ data: null })),
  getEvents:      (id: number)                   => api.get(`/incidents/${id}/events`).catch(() => ({ data: [] })),
  getAlerts:      (id: number)                   => api.get(`/incidents/${id}/alerts`).catch(() => ({ data: [] })),
  getDeepDive:    (id: number)                   => api.get(`/incidents/${id}/deepdive`).catch(() => ({ data: null })),
  updateStatus:   (id: number, status: string)   => api.put(`/incidents/${id}/status`, { status }),
  updateSeverity: (id: number, severity: string) => api.patch(`/incidents/${id}/severity`, { severity }),
  addNote:        (id: number, note: string)     => api.post(`/incidents/${id}/notes`, { note }),
  // Enterprise additions
  getAnalytics:   ()                                    => api.get('/incidents/analytics').catch(() => ({ data: null })),
  getTasks:       (id: number)                          => api.get(`/incidents/${id}/tasks`).catch(() => ({ data: [] })),
  createTask:     (id: number, text: string)            => api.post(`/incidents/${id}/tasks`, { text }),
  toggleTask:     (id: number, tid: number)             => api.patch(`/incidents/${id}/tasks/${tid}`),
  aiRootCause:    (id: number)                          => api.post(`/incidents/${id}/ai-root-cause`),
  getSimilar:     (id: number)                          => api.get(`/incidents/${id}/similar`).catch(() => ({ data: [] })),
  responseAction: (id: number, action: string, params?: Record<string, unknown>) =>
    api.post(`/incidents/${id}/response-action`, { action, params: params ?? {} }),
};

export const dashboardAPI = {
  getOverview: () => api.get('/dashboard/overview'),
  getMetrics:  (range: string) => api.get('/dashboard/metrics', { params: { range } }),
};

export const attackPathAPI = {
  get: () => api.get('/attack-path'),
};

export const networkMapAPI = {
  get:        (sinceMinutes = 60, limit = 5000) =>
    api.get('/network-map', { params: { since_minutes: sinceMinutes, limit } }),
  getIPInfo:  (ip: string) => api.get('/network-map/ip-info', { params: { ip } }),
  getPortInfo:(port: string) => api.get('/network-map/port-info', { params: { port } }),
};

export const iocsAPI = {
  // unwraps the paginated envelope so existing callers still get an array
  getAll:     ()                         => api.get('/iocs').then(r => ({ ...r, data: r.data?.data ?? r.data ?? [] })),
  getPaged:   (params: { page?: number; limit?: number; search?: string; type?: string }) =>
    api.get('/iocs', { params }),
  getById:    (id: number)               => api.get(`/iocs/${id}`),
  create:     (data: any)                => api.post('/iocs', data),
  update:     (id: number, data: any)    => api.put(`/iocs/${id}`, data),
  delete:     (id: number)               => api.delete(`/iocs/${id}`),
  enable:     (id: number)               => api.patch(`/iocs/${id}/enable`),
  disable:    (id: number)               => api.patch(`/iocs/${id}/disable`),
  bulkImport: (data: any)                => api.post('/iocs/import', data),
  bulkCreate: (data: any)                => api.post('/iocs/bulk', data),
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
  run:           (id: number, agentId: number) => api.post(`/playbooks/${id}/run`, { agent_id: agentId }),
};

export const sigmaAPI = {
  // unwraps the paginated envelope so existing callers still get an array
  getAll:   ()                      => api.get('/sigma/rules').then(r => ({ ...r, data: Array.isArray(r.data?.data) ? r.data.data : [] })),
  getPaged: (params: { page?: number; limit?: number; search?: string; severity?: string }) =>
    api.get('/sigma/rules', { params }),
  create:   (data: any)             => api.post('/sigma/rules', data),
  update:   (id: number, data: any) => api.put(`/sigma/rules/${id}`, data),
  delete:   (id: number)            => api.delete(`/sigma/rules/${id}`),
  enable:   (id: number)            => api.patch(`/sigma/rules/${id}/enable`),
  disable:  (id: number)            => api.patch(`/sigma/rules/${id}/disable`),
  test:     (data: { message: string }) => api.post('/sigma/rules/test', data),
  import:   (form: FormData)        => api.post('/sigma/import', form, { headers: { 'Content-Type': 'multipart/form-data' } }),
  stats:    ()                      => api.get('/sigma/stats'),
  // Enterprise endpoints
  dashboard:     ()                             => api.get('/sigma/dashboard').catch(() => ({ data: null })),
  mitreCoverage: ()                             => api.get('/sigma/mitre-coverage').catch(() => ({ data: null })),
  analytics:     ()                             => api.get('/sigma/analytics').catch(() => ({ data: null })),
  categories:    ()                             => api.get('/sigma/categories').catch(() => ({ data: null })),
  performance:   ()                             => api.get('/sigma/performance').catch(() => ({ data: null })),
  relationships: ()                             => api.get('/sigma/relationships').catch(() => ({ data: null })),
  detail:        (id: number)                   => api.get(`/sigma/rules/${id}/detail`).catch(() => ({ data: null })),
  ai:            (body: { action: string; rule_id?: number; rule_yaml?: string; prompt?: string; target?: string; context?: string }) =>
    api.post('/sigma/ai', body),
  convert:       (body: { rule_id?: number; rule_yaml?: string; target: string }) =>
    api.post('/sigma/convert', body),
  bulk:          (action: string, rule_ids: number[], value?: string) =>
    api.post('/sigma/bulk', { action, rule_ids, value }),
  export:        (format: string, rule_ids?: number[]) =>
    api.post('/sigma/export', { format, rule_ids: rule_ids ?? [] }, { responseType: format === 'yaml' ? 'text' : 'json' }),
};

export const logSourcesAPI = {
  getAll:        ()                        => api.get('/log-sources'),
  create:        (data: any)               => api.post('/log-sources', data),
  update:        (id: number, data: any)   => api.put(`/log-sources/${id}`, data),
  remove:        (id: number)              => api.delete(`/log-sources/${id}`),
  getHealth:     (id: number)              => api.get(`/log-sources/${id}/health`).catch(() => ({ data: null })),
  getStats:      (id: number)              => api.get(`/log-sources/${id}/stats`).catch(() => ({ data: null })),
  getParser:     (id: number)              => api.get(`/log-sources/${id}/parser`).catch(() => ({ data: null })),
  getRecentLogs: (id: number)              => api.get(`/log-sources/${id}/recent-logs`).catch(() => ({ data: { logs: [] } })),
  test:          (id: number)              => api.post(`/log-sources/${id}/test`),
  getMonitoring: ()                        => api.get('/log-sources/monitoring').catch(() => ({ data: null })),
  getMarketplace:()                        => api.get('/log-sources/marketplace').catch(() => ({ data: null })),
  aiInsights:    ()                        => api.post('/log-sources/ai-insights'),
  bulk:          (action: string, ids: number[]) => api.post('/log-sources/bulk', { action, ids }),
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
  search:              (params: Record<string, string | number | undefined>) => api.get('/logs/search', { params }),
  export:              (params: Record<string, string | number | undefined>, format: 'csv' | 'json') =>
                         api.get('/logs/export', { params: { ...params, format }, responseType: 'blob' }),
  stats:               ()                      => api.get('/logs/stats'),
  getSavedSearches:    ()                      => api.get('/logs/searches'),
  saveSearch:          (data: any)             => api.post('/logs/searches', data),
  deleteSearch:        (id: number)            => api.delete(`/logs/searches/${id}`),
  runSaved:            (id: number)            => api.post(`/logs/searches/${id}/run`),
  getRetention:        ()                      => api.get('/logs/retention'),
  setRetention:        (days: number)          => api.put('/logs/retention', { retention_days: days }),
  // enterprise extensions
  getFields:           ()                      => api.get('/logs/fields').catch(() => ({ data: { fields: [], total_docs: 0 } })),
  getTemplates:        ()                      => api.get('/logs/templates').catch(() => ({ data: { templates: [] } })),
  aiQuery:             (question: string, language?: string) => api.post('/logs/ai-query', { question, language: language ?? 'kql' }),
  aiExplain:           (query: string, hit_count: number, samples: string[]) =>
                         api.post('/logs/ai-explain', { query, hit_count, samples }),
  buildDetection:      (type: string, query: string, name: string, samples: string[]) =>
                         api.post('/logs/build-detection', { type, query, name, samples }),
  getScheduled:        ()                      => api.get('/logs/scheduled').catch(() => ({ data: { searches: [] } })),
  createScheduled:     (data: any)             => api.post('/logs/scheduled', data),
  deleteScheduled:     (id: number)            => api.delete(`/logs/scheduled/${id}`),
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
  getAll:     ()                                 => api.get('/quarantine').catch(() => ({ data: [] })),
  quarantine: (data: any)                        => api.post('/quarantine', data),
  remove:     (id: number, restore = false)      => api.delete(`/quarantine/${id}`, { data: { restore } }),
};

export const threatFeedsAPI = {
  getAll:  ()                    => api.get('/threat-feeds').catch(() => ({ data: [] })),
  create:  (data: any)           => api.post('/threat-feeds', data),
  update:  (id: number, data: any) => api.put(`/threat-feeds/${id}`, data),
  delete:  (id: number)          => api.delete(`/threat-feeds/${id}`),
  sync:    (id: number)          => api.post(`/threat-feeds/${id}/sync`),
};

export const intelAPI = {
  getOverview:      (hours = 24)               => api.get('/intel/overview', { params: { hours } }).catch(() => ({ data: null })),
  getAnalytics:     ()                         => api.get('/intel/analytics').catch(() => ({ data: null })),
  getCampaigns:     ()                         => api.get('/intel/campaigns').catch(() => ({ data: null })),
  getMITRE:         ()                         => api.get('/intel/mitre').catch(() => ({ data: null })),
  getRelationships: ()                         => api.get('/intel/relationships').catch(() => ({ data: null })),
  getWatchlist:     ()                         => api.get('/intel/watchlist').catch(() => ({ data: null })),
  getTimeline:      (hours = 168)              => api.get('/intel/timeline', { params: { hours } }).catch(() => ({ data: null })),
  search:           (query: string, type?: string) => api.post('/intel/search', { query, type: type ?? '' }),
  ai:               (action: string, indicator?: string, context?: string) =>
    api.post('/intel/ai', { action, indicator: indicator ?? '', context: context ?? '' }),
};

export const yaraAPI = {
  getAll:     ()                      => api.get('/yara/rules'),
  create:     (data: any)             => api.post('/yara/rules', data),
  update:     (id: number, data: any) => api.put(`/yara/rules/${id}`, data),
  delete:     (id: number)            => api.delete(`/yara/rules/${id}`),
  enable:     (id: number)            => api.patch(`/yara/rules/${id}/enable`),
  disable:    (id: number)            => api.patch(`/yara/rules/${id}/disable`),
  getMatches: (agentId?: number)      => api.get('/yara/matches', { params: agentId ? { agent_id: agentId } : {} }),
  import:     (form: FormData)        => api.post('/yara/import', form, { headers: { 'Content-Type': 'multipart/form-data' } }),
  // Enterprise
  dashboard:     ()                   => api.get('/yara/dashboard').catch(() => ({ data: null })),
  analytics:     ()                   => api.get('/yara/analytics').catch(() => ({ data: null })),
  categories:    ()                   => api.get('/yara/categories').catch(() => ({ data: null })),
  performance:   ()                   => api.get('/yara/performance').catch(() => ({ data: null })),
  relationships: ()                   => api.get('/yara/relationships').catch(() => ({ data: null })),
  detail:        (id: number)         => api.get(`/yara/rules/${id}/detail`).catch(() => ({ data: null })),
  ai:            (body: { action: string; rule_id?: number; rule_content?: string; prompt?: string; context?: string }) =>
    api.post('/yara/ai', body),
  bulk:          (action: string, rule_ids: number[]) =>
    api.post('/yara/bulk', { action, rule_ids }),
  export:        (format: string, rule_ids?: number[], all?: boolean) =>
    api.post('/yara/export', { format, rule_ids: rule_ids ?? [], all: all ?? false }),
};

export const firewallAPI = {
  getAll:       (group?: string)         => api.get('/firewall/rules', { params: group ? { group } : {} }),
  getById:      (id: number)             => api.get(`/firewall/rules/${id}`),
  create:       (data: any)              => api.post('/firewall/rules', data),
  update:       (id: number, data: any)  => api.put(`/firewall/rules/${id}`, data),
  delete:       (id: number)             => api.delete(`/firewall/rules/${id}`),
  sync:         (data: any)              => api.post('/firewall/sync', data),
  getSyncLog:   (agentId?: number)       => api.get('/firewall/sync/log', { params: agentId ? { agent_id: agentId } : {} }),
  getGroups:    ()                       => api.get('/firewall/groups'),
  getStats:     ()                       => api.get('/firewall/stats'),
  getConflicts: ()                       => api.get('/firewall/conflicts'),
  getPolicy:    ()                       => api.get('/firewall/policy'),
  setPolicy:    (action: string)         => api.put('/firewall/policy', { default_action: action }),
  bulk:         (ids: number[], action: string) => api.post('/firewall/rules/bulk', { ids, action }),
  import:       (rules: any[], mode?: string)   => api.post('/firewall/rules/import', { rules, mode: mode || 'append' }),
  getTemplates: ()                       => api.get('/firewall/templates'),
  getExpired:   ()                       => api.get('/firewall/expired'),
  pruneExpired: ()                       => api.delete('/firewall/expired'),
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
  getScores: (id: number)          => api.get(`/compliance/reports/${id}/scores`),
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



export const correlationAPI = {
  getAll:          ()                               => api.get('/correlation/rules'),
  create:          (rule: any)                      => api.post('/correlation/rules', rule),
  update:          (id: number, rule: any)          => api.put(`/correlation/rules/${id}`, rule),
  toggle:          (id: number, enabled: boolean)   => api.patch(`/correlation/rules/${id}/toggle`, { enabled }),
  delete:          (id: number)                     => api.delete(`/correlation/rules/${id}`),
  getMatches:      (ruleId?: number)                => api.get('/correlation/matches', { params: ruleId ? { rule_id: ruleId } : {} }),
  // Enterprise
  getOverview:     (hours = 24)                     => api.get('/correlation/overview', { params: { hours } }).catch(() => ({ data: null })),
  getTrends:       (hours = 24)                     => api.get('/correlation/trends', { params: { hours } }).catch(() => ({ data: null })),
  getAnalytics:    (limit = 50)                     => api.get('/correlation/analytics', { params: { limit } }).catch(() => ({ data: null })),
  getGraph:        (hours = 24)                     => api.get('/correlation/graph', { params: { hours } }).catch(() => ({ data: null })),
  getAlertGrouping:(hours = 24)                     => api.get('/correlation/alert-grouping', { params: { hours } }).catch(() => ({ data: null })),
  getPerformance:  ()                               => api.get('/correlation/performance').catch(() => ({ data: null })),
  aiAnalysis:      (action: string, context?: string) => api.post('/correlation/ai-analysis', { action, context: context ?? '' }),
  simulate:        (chain: string[], windowMinutes = 10) => api.post('/correlation/simulate', { chain, window_minutes: windowMinutes }),
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
  getCapabilities:  ()                                                                            => api.get('/platform/capabilities'),
  getTenants:       ()                                                                            => api.get('/platform/tenants'),
  createTenant:     (name: string, slug: string, adminUsername: string, adminEmail: string)        =>
    api.post('/platform/tenants', { name, slug, admin_username: adminUsername, admin_email: adminEmail }),
  toggleTenant:     (id: number, active: boolean)                                                  => api.patch(`/platform/tenants/${id}/toggle`, { is_active: active }),
  deleteTenant:     (id: number)                                                                   => api.delete(`/platform/tenants/${id}`),
  getReleases:      ()                                                                            => api.get('/platform/agent-releases'),
  publishRelease:   (data: { platform: string; version: string; sha256: string; download_url: string }) =>
    api.post('/platform/agent-releases', data),
  getTenantDomains: (id: number)                       => api.get(`/platform/tenants/${id}/domains`),
  addTenantDomain:  (id: number, domain: string)       => api.post(`/platform/tenants/${id}/domains`, { domain }),
  deleteTenantDomain: (tenantID: number, domainID: number) => api.delete(`/platform/tenants/${tenantID}/domains/${domainID}`),
  // SaaS admin
  getSaasMode:         ()                              => api.get('/platform/saas/mode'),
  setSaasMode:         (enabled: boolean)              => api.post('/platform/saas/mode', { enabled }),
  getSaasStats:        ()                              => api.get('/platform/saas/stats'),
  getAllSubscriptions:  ()                              => api.get('/platform/saas/subscriptions'),
  updateSubscription:  (tenantID: number, data: { plan: string; status: string; notes?: string }) =>
    api.patch(`/platform/saas/subscriptions/${tenantID}`, data),
  getAllPlans:          ()                              => api.get('/platform/saas/plans'),
  // License admin
  getLicenseMode:      ()                              => api.get('/platform/license/mode'),
  setLicenseMode:      (enabled: boolean)              => api.post('/platform/license/mode', { enabled }),
  getLicenseKeys:      ()                              => api.get('/platform/license/keys'),
  generateLicenseKey:  (data: {
    customer_name: string; customer_email: string; tier: string;
    agent_limit: number; user_limit: number; expires_at: string; notes?: string;
  })                                                   => api.post('/platform/license/keys', data),
  revokeLicenseKey:    (keyID: string, reason?: string) =>
    api.delete(`/platform/license/keys/${keyID}${reason ? `?reason=${encodeURIComponent(reason)}` : ''}`),
  regenerateLicenseToken: (keyID: string)              => api.post(`/platform/license/keys/${keyID}/regenerate`, {}),
};

export const billingAPI = {
  getSubscription:   ()                              => api.get('/billing/subscription'),
  getPlans:          ()                              => api.get('/billing/plans'),
  requestUpgrade:    (plan: string, message?: string) => api.post('/billing/request-upgrade', { plan, message: message ?? '' }),
};

export const ssoAPI = {
  discover: (email: string) => api.get(`/auth/sso-discover?email=${encodeURIComponent(email)}`),
};

export const casesAPI = {
  getAll:       (params?: Record<string, any>)  => api.get('/cases', { params }),
  getByID:      (id: number)                    => api.get(`/cases/${id}`),
  create:       (data: any)                     => api.post('/cases', data),
  update:       (id: number, data: any)         => api.put(`/cases/${id}`, data),
  delete:       (id: number)                    => api.delete(`/cases/${id}`),
  addComment:   (id: number, body: string)      => api.post(`/cases/${id}/comments`, { body }),
  addEvidence:  (id: number, data: any)         => api.post(`/cases/${id}/evidence`, data),
  linkAlert:    (id: number, alertID: number)   => api.post(`/cases/${id}/alerts`, { alert_id: alertID }),
  unlinkAlert:  (id: number, alertID: number)   => api.delete(`/cases/${id}/alerts/${alertID}`),
};

export const assetsAPI = {
  getAll:   ()                          => api.get('/assets'),
  getByID:  (id: number)               => api.get(`/assets/${id}`),
  create:   (data: any)                => api.post('/assets', data),
  update:   (id: number, data: any)    => api.put(`/assets/${id}`, data),
  delete:   (id: number)               => api.delete(`/assets/${id}`),
};

export const executiveAPI = {
  getMetrics:     ()    => api.get('/executive/metrics'),
  downloadReport: ()    => api.get('/executive/report/download', { responseType: 'blob' }),
};

export const scheduledReportsAPI = {
  getAll:   ()                          => api.get('/scheduled-reports'),
  create:   (data: any)                => api.post('/scheduled-reports', data),
  update:   (id: number, data: any)    => api.put(`/scheduled-reports/${id}`, data),
  delete:   (id: number)               => api.delete(`/scheduled-reports/${id}`),
};

export const vulnQueueAPI = {
  getQueue:       (params?: Record<string, any>) => api.get('/vulns/priority-queue', { params }),
  updateStatus:   (id: number, status: string, notes: string) => api.patch(`/vulns/${id}/patch-status`, { status, notes }),
  refresh:        () => api.post('/vulns/refresh-priorities'),
};

export const socAPI = {
  getMetrics: (range?: string) => api.get('/soc/metrics', { params: range ? { range } : {} }),
};

export const investigateAPI = {
  getContext: (alertID: number) => api.get(`/alerts/${alertID}/investigate`),
};

export const uebaAPI = {
  getUsers:         (params?: Record<string, any>) => api.get('/ueba/users', { params }),
  getEvents:        (params?: Record<string, any>) => api.get('/ueba/events', { params }),
  analyze:          ()                             => api.post('/ueba/analyze'),
  // Enterprise additions
  getAnalytics:     ()                             => api.get('/ueba/analytics').catch(() => ({ data: null })),
  getUserDetail:    (username: string)             => api.get(`/ueba/users/${encodeURIComponent(username)}`).catch(() => ({ data: null })),
  getUserTimeline:  (username: string)             => api.get(`/ueba/users/${encodeURIComponent(username)}/timeline`).catch(() => ({ data: { events: [] } })),
  getPeerComparison:(username: string)             => api.get(`/ueba/users/${encodeURIComponent(username)}/peer-comparison`).catch(() => ({ data: null })),
  getAIInsights:    (username: string)             => api.post(`/ueba/users/${encodeURIComponent(username)}/ai-insights`),
  responseAction:   (username: string, action: string, params?: Record<string, string>) =>
    api.post(`/ueba/users/${encodeURIComponent(username)}/response-action`, { action, params: params ?? {} }),
  getWatchlist:     ()                             => api.get('/ueba/watchlist').catch(() => ({ data: { watchlist: [] } })),
  addToWatchlist:   (username: string, category: string) => api.post('/ueba/watchlist', { username, category }),
  removeFromWatchlist: (username: string)          => api.delete(`/ueba/watchlist/${encodeURIComponent(username)}`),
};

export const insiderThreatAPI = {
  getScores:      (days: number, minScore: number) =>
    api.get('/insider-threat', { params: { days, min_score: minScore } }),
  getSummary:     () => api.get('/insider-threat/summary'),
  // Enterprise additions
  getAnalytics:   () => api.get('/insider-threat/analytics').catch(() => ({ data: null })),
  getUserDetail:  (username: string) => api.get(`/insider-threat/users/${encodeURIComponent(username)}`).catch(() => ({ data: null })),
  getUserTimeline:(username: string) => api.get(`/insider-threat/users/${encodeURIComponent(username)}/timeline`).catch(() => ({ data: { events: [] } })),
  aiAnalysis:     (username: string) => api.post(`/insider-threat/users/${encodeURIComponent(username)}/ai-analysis`),
  responseAction: (username: string, action: string, params?: Record<string, string>) =>
    api.post(`/insider-threat/users/${encodeURIComponent(username)}/response-action`, { action, params: params ?? {} }),
  getPolicyViolations: (username?: string) =>
    api.get('/insider-threat/policy-violations', { params: username ? { username } : undefined }).catch(() => ({ data: { violations: [] } })),
  getPolicies:    () => api.get('/insider-threat/policies').catch(() => ({ data: { policies: [] } })),
  createPolicy:   (data: any) => api.post('/insider-threat/policies', data),
  getWatchlist:   () => api.get('/insider-threat/watchlist').catch(() => ({ data: { watchlist: [] } })),
  addToWatchlist: (username: string, category: string) => api.post('/insider-threat/watchlist', { username, category }),
  removeFromWatchlist: (username: string) => api.delete(`/insider-threat/watchlist/${encodeURIComponent(username)}`),
};

export const nbaAPI = {
  getAnomalies:         (limit = 200)         => api.get('/nba/anomalies', { params: { limit } }),
  acknowledge:          (id: number)           => api.post(`/nba/anomalies/${id}/acknowledge`),
  getBaseline:          (agentId: number)      => api.get(`/nba/baseline/${agentId}`),
  analyze:              ()                     => api.post('/nba/analyze'),
  getOverview:          (minutes = 60)         => api.get('/nba/overview', { params: { minutes } }).catch(() => ({ data: null })),
  getFlows:             (params?: { proto?: string; ip?: string; host?: string; minutes?: number; limit?: number }) =>
                          api.get('/nba/flows', { params }).catch(() => ({ data: null })),
  getTrafficAnalysis:   (hours = 24)           => api.get('/nba/traffic-analysis', { params: { hours } }).catch(() => ({ data: null })),
  getDnsAnalytics:      (hours = 24)           => api.get('/nba/dns-analytics', { params: { hours } }).catch(() => ({ data: null })),
  getTlsAnalytics:      (hours = 24)           => api.get('/nba/tls-analytics', { params: { hours } }).catch(() => ({ data: null })),
  getBeacons:           ()                     => api.get('/nba/beacons').catch(() => ({ data: null })),
  getLateralMovement:   ()                     => api.get('/nba/lateral-movement').catch(() => ({ data: null })),
  getThreatIntel:       (hours = 24)           => api.get('/nba/threat-intel', { params: { hours } }).catch(() => ({ data: null })),
  aiInsights:           (body: { context?: string; host?: string }) => api.post('/nba/ai-insights', body),
  responseAction:       (action: string, params?: Record<string, unknown>) => api.post('/nba/response-action', { action, ...params }),
  getMitreMapping:      ()                     => api.get('/nba/mitre-mapping').catch(() => ({ data: null })),
  getProtocolBreakdown: (hours = 24)           => api.get('/nba/protocol-breakdown', { params: { hours } }).catch(() => ({ data: null })),
  getHostTimeline:      (host: string, hours = 24) => api.get('/nba/host-timeline', { params: { host, hours } }).catch(() => ({ data: null })),
  getAnalytics:         (hours = 24)           => api.get('/nba/analytics', { params: { hours } }).catch(() => ({ data: null })),
};

export const dpiAPI = {
  getFindings: (params?: {
    agent_id?: number;
    finding_type?: string;
    severity?: string;
    alert_only?: boolean;
    limit?: number;
    offset?: number;
  }) => api.get('/dpi/findings', { params }),
  getSummary:           ()                            => api.get('/dpi/summary'),
  getOverview:          (hours = 24)                  => api.get('/dpi/overview', { params: { hours } }).catch(() => ({ data: null })),
  getSessions:          (params?: { proto?: string; hours?: number; limit?: number }) =>
                          api.get('/dpi/sessions', { params }).catch(() => ({ data: null })),
  getHTTPInspection:    (params?: { q?: string; hours?: number; limit?: number }) =>
                          api.get('/dpi/http-inspection', { params }).catch(() => ({ data: null })),
  getDNSInspection:     (hours = 24)                  => api.get('/dpi/dns-inspection', { params: { hours } }).catch(() => ({ data: null })),
  getTLSInspection:     (hours = 24)                  => api.get('/dpi/tls-inspection', { params: { hours } }).catch(() => ({ data: null })),
  getFiles:             (hours = 24)                  => api.get('/dpi/files', { params: { hours } }).catch(() => ({ data: null })),
  getDLP:               (hours = 24)                  => api.get('/dpi/dlp', { params: { hours } }).catch(() => ({ data: null })),
  getAnalytics:         (hours = 24)                  => api.get('/dpi/analytics', { params: { hours } }).catch(() => ({ data: null })),
  getPerformance:       ()                            => api.get('/dpi/performance').catch(() => ({ data: null })),
  getProtocolAnomalies: (hours = 24)                  => api.get('/dpi/protocol-anomalies', { params: { hours } }).catch(() => ({ data: null })),
  search:               (q: string)                   => api.get('/dpi/search', { params: { q } }).catch(() => ({ data: null })),
  aiInspect:            (body: { context?: string; finding_id?: number; session_key?: string }) =>
                          api.post('/dpi/ai-inspect', body),
  responseAction:       (action: string, params?: Record<string, unknown>) =>
                          api.post('/dpi/response-action', { action, ...params }),
};

export const detectionAPI = {
  getOverview:    (hours = 24)                               => api.get('/detection/overview', { params: { hours } }).catch(() => ({ data: null })),
  getTrends:      (hours = 24)                               => api.get('/detection/trends', { params: { hours } }).catch(() => ({ data: null })),
  getCoverage:    ()                                         => api.get('/detection/coverage').catch(() => ({ data: null })),
  getAnalytics:   (limit = 50)                               => api.get('/detection/analytics', { params: { limit } }).catch(() => ({ data: null })),
  getPerformance: ()                                         => api.get('/detection/performance').catch(() => ({ data: null })),
  aiAssistant:    (action: string, content: string, context?: string) =>
                    api.post('/detection/ai-assistant', { action, content, context: context ?? '' }),
  simulate:       (ruleType: string, ruleId: number, hours = 24) =>
                    api.post('/detection/simulate', { rule_type: ruleType, rule_id: ruleId, hours }),
};

export const sessionsAPI = {
  getMy:          ()          => api.get('/auth/sessions'),
  getAll:         ()          => api.get('/sessions'),
  revoke:         (id: number)=> api.delete(`/sessions/${id}`),
};

export const securityPolicyAPI = {
  get:    ()          => api.get('/security-policy'),
  update: (data: any) => api.put('/security-policy', data),
};

export const feedSyncAPI = {
  getLog: (feedID: number) => api.get(`/threat-feeds/${feedID}/sync-log`),
};

export const mdmAPI = {
  // Devices
  getDevices:     (params?: { platform?: string; status?: string; owner_email?: string }) =>
    api.get('/mdm/devices', { params }),
  getDevice:      (id: number) => api.get(`/mdm/devices/${id}`),
  unenrollDevice: (id: number) => api.delete(`/mdm/devices/${id}`),
  blockDevice:    (id: number) => api.post(`/mdm/devices/${id}/block`),
  unblockDevice:  (id: number) => api.post(`/mdm/devices/${id}/unblock`),
  getCompliance:  (id: number) => api.get(`/mdm/devices/${id}/compliance`).catch(() => ({ data: { results: [] } })),
  getComplianceSummary: ()     => api.get('/mdm/compliance/summary').catch(() => ({ data: null })),
  triggerCompliance: ()        => api.post('/mdm/compliance/run'),

  // Commands
  queueCommand:   (deviceId: number, commandType: string, payload?: Record<string, unknown>) =>
    api.post(`/mdm/devices/${deviceId}/commands`, { command_type: commandType, payload: payload ?? {} }),
  getCommands:    (deviceId: number, limit = 50) =>
    api.get(`/mdm/devices/${deviceId}/commands`, { params: { limit } }).catch(() => ({ data: { commands: [] } })),

  // Enrollment tokens
  getTokens:   () => api.get('/mdm/enrollment-tokens'),
  createToken: (label: string, platform = 'any', maxUses?: number, expiresIn?: number) =>
    api.post('/mdm/enrollment-tokens', { label, platform, max_uses: maxUses, expires_in: expiresIn }),
  revokeToken: (id: number) => api.delete(`/mdm/enrollment-tokens/${id}`),
};

export const clustersAPI = {
  getAll:      (limit = 200)             => api.get('/clusters', { params: { limit } }).catch(() => ({ data: [] })),
  getAlerts:   (id: number)              => api.get(`/clusters/${id}/alerts`).catch(() => ({ data: [] })),
  analyze:     ()                        => api.post('/clusters/analyze'),
  suppress:    (id: number)              => api.post(`/clusters/${id}/suppress`),
  // enterprise
  getOverview:  (hours = 24)             => api.get('/clusters/overview', { params: { hours } }).catch(() => ({ data: null })),
  getList:      (status = '', limit = 100) => api.get('/clusters/list', { params: { status, limit } }).catch(() => ({ data: [] })),
  getAnalytics: ()                       => api.get('/clusters/analytics').catch(() => ({ data: null })),
  getCampaigns: ()                       => api.get('/clusters/campaigns').catch(() => ({ data: null })),
  getDetail:    (id: number)             => api.get(`/clusters/${id}/detail`).catch(() => ({ data: null })),
  getTimeline:  (id: number)             => api.get(`/clusters/${id}/timeline`).catch(() => ({ data: null })),
  getGraph:     (id: number)             => api.get(`/clusters/${id}/graph`).catch(() => ({ data: null })),
  aiAnalysis:   (action: string, clusterId?: number, context?: string) =>
    api.post('/clusters/ai', { action, cluster_id: clusterId ?? 0, context: context ?? '' }),
  bulkAction:   (id: number, action: string, note?: string) =>
    api.post(`/clusters/${id}/bulk-action`, { action, note: note ?? '' }),
  merge:        (id: number, mergeIntoId: number) =>
    api.post(`/clusters/${id}/merge`, { merge_into_id: mergeIntoId }),
};

export const threatActorsAPI = {
  getAll:    ()                       => api.get('/threat-actors').catch(() => ({ data: [] })),
  create:    (data: any)              => api.post('/threat-actors', data),
  remove:    (id: number)             => api.delete(`/threat-actors/${id}`),
  update:    (id: number, data: any)  => api.patch(`/threat-actors/${id}`, data),
  getAlerts: (id: number, limit = 10) =>
    api.get(`/threat-actors/${id}/alerts`, { params: { limit } }).catch(() => ({ data: [] })),
  // enterprise
  getDashboard:         ()                              => api.get('/threat-actors/dashboard').catch(() => ({ data: null })),
  getAnalytics:         ()                              => api.get('/threat-actors/analytics').catch(() => ({ data: null })),
  ai:                   (action: string, actorId?: number, actorName?: string, context?: string) =>
    api.post('/threat-actors/ai', { action, actor_id: actorId ?? 0, actor_name: actorName ?? '', context: context ?? '' }),
  getProfile:           (id: number)                    => api.get(`/threat-actors/${id}/profile`).catch(() => ({ data: null })),
  getCampaigns:         (id: number)                    => api.get(`/threat-actors/${id}/campaigns`).catch(() => ({ data: null })),
  getMalware:           (id: number)                    => api.get(`/threat-actors/${id}/malware`).catch(() => ({ data: null })),
  getInfrastructure:    (id: number)                    => api.get(`/threat-actors/${id}/infrastructure`).catch(() => ({ data: null })),
  getExposure:          (id: number)                    => api.get(`/threat-actors/${id}/exposure`).catch(() => ({ data: null })),
  getDetectionCoverage: (id: number)                    => api.get(`/threat-actors/${id}/detection-coverage`).catch(() => ({ data: null })),
  getRelationships:     (id: number)                    => api.get(`/threat-actors/${id}/relationships`).catch(() => ({ data: null })),
  getTimeline:          (id: number)                    => api.get(`/threat-actors/${id}/timeline`).catch(() => ({ data: null })),
  getIOCs:              (id: number)                    => api.get(`/threat-actors/${id}/iocs`).catch(() => ({ data: null })),
  getMITRE:             (id: number)                    => api.get(`/threat-actors/${id}/mitre`).catch(() => ({ data: null })),
  hunt:                 (id: number, huntType: string)  => api.post(`/threat-actors/${id}/hunt`, { hunt_type: huntType }),
  response:             (id: number, action: string, note?: string) =>
    api.post(`/threat-actors/${id}/response`, { action, note: note ?? '' }),
};

export const ja3API = {
  getAll:       ()            => api.get('/ja3/fingerprints').catch(() => ({ data: [] })),
  create:       (data: any)   => api.post('/ja3/fingerprints', data),
  remove:       (id: number)  => api.delete(`/ja3/fingerprints/${id}`),
  detail:       (hash: string)=> api.get(`/ja3/fingerprints/${hash}/detail`).catch(() => ({ data: null })),
  // enterprise
  dashboard:    ()  => api.get('/ja3/dashboard').catch(() => ({ data: null })),
  analytics:    ()  => api.get('/ja3/analytics').catch(() => ({ data: null })),
  tlsStats:     ()  => api.get('/ja3/tls-stats').catch(() => ({ data: null })),
  behavioral:   ()  => api.get('/ja3/behavioral').catch(() => ({ data: null })),
  relationships:()  => api.get('/ja3/relationships').catch(() => ({ data: null })),
  threatIntel:  ()  => api.get('/ja3/threat-intel').catch(() => ({ data: null })),
  timeline:     ()  => api.get('/ja3/timeline').catch(() => ({ data: null })),
  watchlist:    ()  => api.get('/ja3/watchlist').catch(() => ({ data: [] })),
  addWatchlist: (body: { hash?: string; label: string; watch_type?: string }) => api.post('/ja3/watchlist', body),
  removeWatchlist: (id: number) => api.delete(`/ja3/watchlist/${id}`),
  ai:           (body: { action: string; hash?: string; threat_name?: string; prompt?: string; context?: string }) => api.post('/ja3/ai', body),
  export:       (body: { format: string; ids?: number[] }) => api.post('/ja3/export', body),
  bulk:         (action: string, ids: number[]) => api.post('/ja3/bulk', { action, ids }),
};

export const huntAPI = {
  getSaved:    ()              => api.get('/hunt/queries').catch(() => ({ data: [] })),
  run:         (data: any)     => api.post('/hunt/run', data),
  rerun:       (id: number)    => api.post(`/hunt/queries/${id}/run`, {}),
  deleteSaved: (id: number)    => api.delete(`/hunt/queries/${id}`),
  promote:     (data: any)     => api.post('/sigma/rules/from-hunt', data),
};

export const threatHuntAPI = {
  // Read
  dashboard:   ()            => api.get('/threat-hunt/dashboard').catch(() => ({ data: null })),
  library:     (params?: { category?: string; status?: string }) =>
    api.get('/threat-hunt/library', { params }).catch(() => ({ data: [] })),
  categories:  ()            => api.get('/threat-hunt/categories').catch(() => ({ data: null })),
  findings:    (params?: { hunt_id?: number; severity?: string; status?: string }) =>
    api.get('/threat-hunt/findings', { params }).catch(() => ({ data: [] })),
  metrics:     ()            => api.get('/threat-hunt/metrics').catch(() => ({ data: null })),
  get:         (id: number)  => api.get(`/threat-hunt/${id}`).catch(() => ({ data: null })),
  comments:    (id: number)  => api.get(`/threat-hunt/${id}/comments`).catch(() => ({ data: [] })),
  // Mutate
  create:      (body: any)   => api.post('/threat-hunt', body),
  update:      (id: number, body: any) => api.patch(`/threat-hunt/${id}`, body),
  remove:      (id: number)  => api.delete(`/threat-hunt/${id}`),
  execute:     (id: number)  => api.post(`/threat-hunt/${id}/execute`, {}),
  schedule:    (id: number, body: any) => api.post(`/threat-hunt/${id}/schedule`, body),
  comment:     (id: number, content: string) => api.post(`/threat-hunt/${id}/comment`, { content }),
  ackFinding:  (fid: number, status: string) => api.post(`/threat-hunt/findings/${fid}/ack`, { status }),
  ai:          (body: { action: string; hunt_id?: number; hunt_name?: string; hypothesis?: string; category?: string; prompt?: string; context?: string }) =>
    api.post('/threat-hunt/ai', body),
  export:      (body: { hunt_id: number; format: string }) => api.post('/threat-hunt/export', body),
  response:    (body: { action: string; hunt_id?: number; finding_id?: number; target?: string; reason?: string }) =>
    api.post('/threat-hunt/response', body),
};

export const huntWorkbenchAPI = {
  getTemplates:   ()              => api.get('/hunt/templates').catch(() => ({ data: [] })),
  createTemplate: (data: any)     => api.post('/hunt/templates', data),
  deleteTemplate: (id: number)    => api.delete(`/hunt/templates/${id}`),
  getRuns:        ()              => api.get('/hunt/runs').catch(() => ({ data: [] })),
  getRunDetail:   (id: number)    => api.get(`/hunt/runs/${id}`),
  execute:        (data: any)     => api.post('/hunt/execute', data).catch(() => ({ data: null })),
  updateNotes:    (id: number, notes: string, severity: string) =>
    api.patch(`/hunt/runs/${id}/notes`, { notes, severity }),
  // enterprise
  dashboard:      () => api.get('/hunt/dashboard').catch(() => ({ data: null })),
  analytics:      () => api.get('/hunt/analytics').catch(() => ({ data: null })),
  mitreCoverage:  () => api.get('/hunt/mitre-coverage').catch(() => ({ data: null })),
  ai:             (body: { action: string; query?: string; results?: string; context?: string; prompt?: string; run_id?: number }) =>
    api.post('/hunt/ai', body),
  iocHunt:        (body: { ioc_type: string; value: string; time_range?: string }) =>
    api.post('/hunt/ioc', body),
  ttpHunt:        (body: { ttp: string; time_range?: string }) =>
    api.post('/hunt/ttp', body),
  actorHunt:      (body: { actor: string; time_range?: string }) =>
    api.post('/hunt/actor', body),
  export:         (body: { run_id: number; format: string }) =>
    api.post('/hunt/export', body),
  notebook:       (run_id?: number) =>
    api.get('/hunt/notebook', run_id ? { params: { run_id } } : undefined).catch(() => ({ data: [] })),
  addNote:        (body: { run_id?: number; content: string; content_type?: string }) =>
    api.post('/hunt/notebook', body),
  deleteNote:     (id: number) => api.delete(`/hunt/notebook/${id}`),
  response:       (body: { action: string; agent_id?: number; target?: string; run_id?: number; reason?: string }) =>
    api.post('/hunt/response', body),
};

export const dfirAPI = {
  // Dashboard & analytics
  dashboard:      ()                      => api.get('/dfir/dashboard').catch(() => ({ data: null })),
  analytics:      ()                      => api.get('/dfir/analytics').catch(() => ({ data: null })),
  search:         (q: string)             => api.get('/dfir/search', { params: { q } }).catch(() => ({ data: null })),
  // Investigations CRUD
  investigations: (params?: { status?: string; priority?: string }) =>
    api.get('/dfir/investigations', { params }).catch(() => ({ data: [] })),
  getInvestigation: (id: number)          => api.get(`/dfir/investigations/${id}`).catch(() => ({ data: null })),
  create:         (body: any)             => api.post('/dfir/investigations', body),
  update:         (id: number, body: any) => api.patch(`/dfir/investigations/${id}`, body),
  close:          (id: number)            => api.delete(`/dfir/investigations/${id}`),
  // Evidence
  evidence:       (params?: { investigation_id?: number; type?: string }) =>
    api.get('/dfir/evidence', { params }).catch(() => ({ data: [] })),
  evidenceItem:   (eid: number)           => api.get(`/dfir/evidence/${eid}`).catch(() => ({ data: null })),
  custody:        (eid: number)           => api.get(`/dfir/evidence/${eid}/custody`).catch(() => ({ data: [] })),
  addCustody:     (eid: number, body: any) => api.post(`/dfir/evidence/${eid}/custody`, body),
  // Collection
  collect:        (id: number, body: any) => api.post(`/dfir/investigations/${id}/collect`, body),
  tasks:          (id: number)            => api.get(`/dfir/investigations/${id}/tasks`).catch(() => ({ data: [] })),
  // Timeline
  timeline:       (id: number, params?: { type?: string; limit?: number }) =>
    api.get(`/dfir/investigations/${id}/timeline`, { params }).catch(() => ({ data: [] })),
  addTimelineEvent: (id: number, body: any) => api.post(`/dfir/investigations/${id}/timeline`, body),
  // Forensic analysis
  processTree:    (id: number)            => api.get(`/dfir/investigations/${id}/process-tree`).catch(() => ({ data: null })),
  memoryAnalyze:  (id: number)            => api.post(`/dfir/investigations/${id}/memory`, {}),
  network:        (id: number, params?: { protocol?: string }) =>
    api.get(`/dfir/investigations/${id}/network`, { params }).catch(() => ({ data: [] })),
  artifacts:      (id: number, params?: { platform?: string; artifact?: string }) =>
    api.get(`/dfir/investigations/${id}/artifacts`, { params }).catch(() => ({ data: null })),
  fileAnalysis:   (body: { sha256?: string; file_path?: string; file_name?: string }) =>
    api.post('/dfir/file-analysis', body),
  malwareAnalysis: (body: { evidence_id?: number; sha256?: string; file_name?: string; context?: string }) =>
    api.post('/dfir/malware-analysis', body),
  // AI assistant
  ai:             (id: number, body: { action: string; context?: string; prompt?: string }) =>
    api.post(`/dfir/investigations/${id}/ai`, body),
  // Notebook
  notebook:       (id: number)            => api.get(`/dfir/investigations/${id}/notebook`).catch(() => ({ data: [] })),
  addNote:        (id: number, body: any) => api.post(`/dfir/investigations/${id}/notebook`, body),
  deleteNote:     (nid: number)           => api.delete(`/dfir/notebook/${nid}`),
  // Graph & Intel
  graph:          (id: number)            => api.get(`/dfir/investigations/${id}/graph`).catch(() => ({ data: null })),
  threatIntel:    (id: number)            => api.get(`/dfir/investigations/${id}/threat-intel`).catch(() => ({ data: null })),
  // Response & Reports
  response:       (id: number, body: any) => api.post(`/dfir/investigations/${id}/response`, body),
  report:         (id: number, body: { report_type: string; format?: string }) =>
    api.post(`/dfir/investigations/${id}/report`, body),
};

export const deceptionAPI = {
  getDashboard:       ()                   => api.get('/deception/dashboard').catch(() => ({ data: null })),
  getDecoys:          (params?: any)       => api.get('/deception/decoys', { params }).catch(() => ({ data: [] })),
  createDecoy:        (data: any)          => api.post('/deception/decoys', data),
  updateDecoy:        (id: number, data: any) => api.patch(`/deception/decoys/${id}`, data),
  deleteDecoy:        (id: number)         => api.delete(`/deception/decoys/${id}`),
  deploy:             (data: any)          => api.post('/deception/deploy', data),
  getHoneytokens:     (params?: any)       => api.get('/deception/honeytokens', { params }).catch(() => ({ data: [] })),
  createHoneytoken:   (data: any)          => api.post('/deception/honeytokens', data),
  deleteHoneytoken:   (id: number)         => api.delete(`/deception/honeytokens/${id}`),
  getTriggers:        (params?: any)       => api.get('/deception/triggers', { params }).catch(() => ({ data: [] })),
  getCampaigns:       ()                   => api.get('/deception/campaigns').catch(() => ({ data: [] })),
  getTimeline:        (params?: any)       => api.get('/deception/timeline', { params }).catch(() => ({ data: [] })),
  getGraph:           ()                   => api.get('/deception/graph').catch(() => ({ data: { nodes: [], edges: [] } })),
  getThreatIntel:     (ip: string)         => api.get('/deception/threat-intel', { params: { ip } }),
  analyzeAI:          (data: any)          => api.post('/deception/ai', data),
  getHealth:          ()                   => api.get('/deception/health').catch(() => ({ data: { decoys: [], online: 0, offline: 0, degraded: 0 } })),
  respond:            (data: any)          => api.post('/deception/response', data),
  getAnalytics:       ()                   => api.get('/deception/analytics').catch(() => ({ data: null })),
  getWatchlists:      ()                   => api.get('/deception/watchlists').catch(() => ({ data: [] })),
  createWatchlist:    (data: any)          => api.post('/deception/watchlists', data),
  deleteWatchlist:    (id: number)         => api.delete(`/deception/watchlists/${id}`),
  getPolicies:        ()                   => api.get('/deception/policies').catch(() => ({ data: [] })),
  createPolicy:       (data: any)          => api.post('/deception/policies', data),
  deletePolicy:       (id: number)         => api.delete(`/deception/policies/${id}`),
  generateReport:     (data: any)          => api.post('/deception/report', data),
  getTemplates:       ()                   => api.get('/deception/templates').catch(() => ({ data: [] })),
};

export const cloudSecurityAPI = {
  getDashboard:      ()                   => api.get('/cloud/dashboard').catch(() => ({ data: null })),
  getAccounts:       ()                   => api.get('/cloud/accounts').catch(() => ({ data: [] })),
  createAccount:     (data: any)          => api.post('/cloud/accounts', data),
  deleteAccount:     (id: number)         => api.delete(`/cloud/accounts/${id}`),
  getInventory:      (params?: any)       => api.get('/cloud/inventory', { params }).catch(() => ({ data: [] })),
  getCSPMFindings:   (params?: any)       => api.get('/cloud/cspm/findings', { params }).catch(() => ({ data: [] })),
  getCSPMSummary:    ()                   => api.get('/cloud/cspm/summary').catch(() => ({ data: [] })),
  patchFinding:      (id: number, data: any) => api.patch(`/cloud/cspm/findings/${id}`, data),
  getCIEMIdentities: (params?: any)       => api.get('/cloud/ciem/identities', { params }).catch(() => ({ data: [] })),
  getCIEMRisks:      ()                   => api.get('/cloud/ciem/risks').catch(() => ({ data: null })),
  getThreats:        (params?: any)       => api.get('/cloud/threats', { params }).catch(() => ({ data: [] })),
  getExposure:       ()                   => api.get('/cloud/exposure').catch(() => ({ data: null })),
  getCompliance:     (params?: any)       => api.get('/cloud/compliance', { params }).catch(() => ({ data: [] })),
  getTimeline:       (params?: any)       => api.get('/cloud/timeline', { params }).catch(() => ({ data: [] })),
  getAttackPaths:    ()                   => api.get('/cloud/attack-paths').catch(() => ({ data: { nodes: [], edges: [] } })),
  getDrift:          (params?: any)       => api.get('/cloud/drift', { params }).catch(() => ({ data: [] })),
  patchDrift:        (id: number)         => api.patch(`/cloud/drift/${id}`, {}),
  getVulnerabilities:(params?: any)       => api.get('/cloud/vulnerabilities', { params }).catch(() => ({ data: [] })),
  getThreatIntel:    ()                   => api.get('/cloud/threat-intel').catch(() => ({ data: null })),
  analyzeAI:         (data: any)          => api.post('/cloud/ai', data),
  getAnalytics:      ()                   => api.get('/cloud/analytics').catch(() => ({ data: null })),
  respond:           (data: any)          => api.post('/cloud/response', data),
  generateReport:    (data: any)          => api.post('/cloud/report', data),
};

export const defenseEvasionAPI = {
  getDashboard:       ()             => api.get('/de/dashboard').catch(() => ({ data: null })),
  getControls:        (params?: any) => api.get('/de/controls', { params }).catch(() => ({ data: { controls: [], active: 0, degraded: 0, disabled: 0 } })),
  getTamper:          (params?: any) => api.get('/de/tamper', { params }).catch(() => ({ data: { events: [], total: 0 } })),
  getLogEvasion:      (params?: any) => api.get('/de/log-evasion', { params }).catch(() => ({ data: [] })),
  getEvasionEvents:   (params?: any) => api.get('/de/evasion-events', { params }).catch(() => ({ data: [] })),
  getBehavioral:      ()             => api.get('/de/behavioral').catch(() => ({ data: { detections: [] } })),
  getCorrelation:     ()             => api.get('/de/correlation').catch(() => ({ data: [] })),
  getMITRE:           ()             => api.get('/de/mitre').catch(() => ({ data: null })),
  getThreatIntel:     ()             => api.get('/de/threat-intel').catch(() => ({ data: null })),
  getTimeline:        (params?: any) => api.get('/de/timeline', { params }).catch(() => ({ data: [] })),
  getAnalytics:       ()             => api.get('/de/analytics').catch(() => ({ data: null })),
  getValidation:      ()             => api.get('/de/validation').catch(() => ({ data: null })),
  analyzeAI:          (data: any)   => api.post('/de/ai', data).catch(() => ({ data: null })),
  respond:            (data: any)   => api.post('/de/response', data).catch(() => ({ data: null })),
  generateReport:     (data: any)   => api.post('/de/report', data).catch(() => ({ data: null })),
};

export const processInjectionAPI = {
  getDashboard:    ()             => api.get('/pi/dashboard').catch(() => ({ data: null })),
  getProcesses:    (params?: any) => api.get('/pi/processes', { params }).catch(() => ({ data: [] })),
  getProcessTree:  (params?: any) => api.get('/pi/process-tree', { params }).catch(() => ({ data: [] })),
  getInjections:   (params?: any) => api.get('/pi/injections', { params }).catch(() => ({ data: { injections: [], total: 0, critical: 0 } })),
  getMemory:       (params?: any) => api.get('/pi/memory', { params }).catch(() => ({ data: { regions: [], rwx_pages: 0, shellcode: 0, unbacked: 0 } })),
  getModules:      (params?: any) => api.get('/pi/modules', { params }).catch(() => ({ data: { modules: [] } })),
  getHandles:      (params?: any) => api.get('/pi/handles', { params }).catch(() => ({ data: { handles: [] } })),
  getAPICalls:     (params?: any) => api.get('/pi/api-calls', { params }).catch(() => ({ data: { api_calls: [], monitored_apis: [] } })),
  getBehavioral:   ()             => api.get('/pi/behavioral').catch(() => ({ data: { detections: [] } })),
  getThreatIntel:  ()             => api.get('/pi/threat-intel').catch(() => ({ data: null })),
  getTimeline:     (params?: any) => api.get('/pi/timeline', { params }).catch(() => ({ data: [] })),
  getMITREMap:     ()             => api.get('/pi/mitre').catch(() => ({ data: null })),
  getAnalytics:    ()             => api.get('/pi/analytics').catch(() => ({ data: null })),
  analyzeAI:       (data: any)   => api.post('/pi/ai', data).catch(() => ({ data: null })),
  respond:         (data: any)   => api.post('/pi/response', data).catch(() => ({ data: null })),
  generateReport:  (data: any)   => api.post('/pi/report', data).catch(() => ({ data: null })),
};

export const otICSAPI = {
  getDashboard:      ()              => api.get('/ot/dashboard').catch(() => ({ data: null })),
  getAssets:         (params?: any) => api.get('/ot/assets', { params }).catch(() => ({ data: [] })),
  getTopology:       ()              => api.get('/ot/topology').catch(() => ({ data: null })),
  getProtocols:      ()              => api.get('/ot/protocols').catch(() => ({ data: null })),
  getTraffic:        (params?: any) => api.get('/ot/traffic', { params }).catch(() => ({ data: [] })),
  getAlerts:         (params?: any) => api.get('/ot/alerts', { params }).catch(() => ({ data: null })),
  getDevices:        ()              => api.get('/ot/devices').catch(() => ({ data: null })),
  getThreats:        ()              => api.get('/ot/threats').catch(() => ({ data: null })),
  getDPI:            ()              => api.get('/ot/dpi').catch(() => ({ data: null })),
  getRisk:           ()              => api.get('/ot/risk').catch(() => ({ data: null })),
  getVulnerabilities:()              => api.get('/ot/vulnerabilities').catch(() => ({ data: null })),
  getZones:          ()              => api.get('/ot/zones').catch(() => ({ data: null })),
  getBaseline:       ()              => api.get('/ot/baseline').catch(() => ({ data: null })),
  getThreatIntel:    ()              => api.get('/ot/threat-intel').catch(() => ({ data: null })),
  getTimeline:       ()              => api.get('/ot/timeline').catch(() => ({ data: [] })),
  getCompliance:     ()              => api.get('/ot/compliance').catch(() => ({ data: null })),
  getAttackPaths:    ()              => api.get('/ot/attack-paths').catch(() => ({ data: null })),
  getAnalytics:      ()              => api.get('/ot/analytics').catch(() => ({ data: null })),
  analyzeAI:         (data: any)    => api.post('/ot/ai', data),
  respond:           (data: any)    => api.post('/ot/response', data),
  generateReport:    (data: any)    => api.post('/ot/report', data),
};

export const supplyChainAPI = {
  getDashboard:      ()              => api.get('/supply-chain/dashboard').catch(() => ({ data: null })),
  getRepositories:   ()              => api.get('/supply-chain/repositories').catch(() => ({ data: [] })),
  getDependencies:   (params?: any) => api.get('/supply-chain/dependencies', { params }).catch(() => ({ data: [] })),
  getVulnerabilities:(params?: any) => api.get('/supply-chain/vulnerabilities', { params }).catch(() => ({ data: null })),
  getSBOMs:          ()              => api.get('/supply-chain/sboms').catch(() => ({ data: [] })),
  getPipelines:      ()              => api.get('/supply-chain/pipelines').catch(() => ({ data: [] })),
  getSecrets:        ()              => api.get('/supply-chain/secrets').catch(() => ({ data: null })),
  getCodeIntegrity:  ()              => api.get('/supply-chain/code-integrity').catch(() => ({ data: null })),
  getArtifacts:      ()              => api.get('/supply-chain/artifacts').catch(() => ({ data: [] })),
  getThirdParty:     ()              => api.get('/supply-chain/third-party').catch(() => ({ data: null })),
  getProvenance:     ()              => api.get('/supply-chain/provenance').catch(() => ({ data: null })),
  getThreatIntel:    ()              => api.get('/supply-chain/threat-intel').catch(() => ({ data: null })),
  getTimeline:       (params?: any) => api.get('/supply-chain/timeline', { params }).catch(() => ({ data: [] })),
  getAnalytics:      ()              => api.get('/supply-chain/analytics').catch(() => ({ data: null })),
  getCompliance:     ()              => api.get('/supply-chain/compliance').catch(() => ({ data: null })),
  getPolicies:       ()              => api.get('/supply-chain/policies').catch(() => ({ data: [] })),
  createPolicy:      (data: any)    => api.post('/supply-chain/policies', data),
  updatePolicy:      (id: number, data: any) => api.patch(`/supply-chain/policies/${id}`, data),
  deletePolicy:      (id: number)   => api.delete(`/supply-chain/policies/${id}`),
  analyzeAI:         (data: any)    => api.post('/supply-chain/ai', data),
  respond:           (data: any)    => api.post('/supply-chain/response', data),
  generateReport:    (data: any)    => api.post('/supply-chain/report', data),
};

export const adSecurityAPI = {
  getDashboard:    ()              => api.get('/ad/dashboard').catch(() => ({ data: null })),
  getInventory:    ()              => api.get('/ad/inventory').catch(() => ({ data: null })),
  getIdentityRisk: (params?: any) => api.get('/ad/identity-risk', { params }).catch(() => ({ data: null })),
  getAuthMonitor:  (params?: any) => api.get('/ad/auth-monitor', { params }).catch(() => ({ data: null })),
  getAttacks:      (params?: any) => api.get('/ad/attacks', { params }).catch(() => ({ data: null })),
  getGPOChanges:   ()              => api.get('/ad/gpo-changes').catch(() => ({ data: [] })),
  getChanges:      ()              => api.get('/ad/changes').catch(() => ({ data: [] })),
  getAttackPaths:  ()              => api.get('/ad/attack-paths').catch(() => ({ data: null })),
  getTiering:      ()              => api.get('/ad/tiering').catch(() => ({ data: null })),
  getExposure:     ()              => api.get('/ad/exposure').catch(() => ({ data: null })),
  getThreatIntel:  ()              => api.get('/ad/threat-intel').catch(() => ({ data: null })),
  getTimeline:     (params?: any) => api.get('/ad/timeline', { params }).catch(() => ({ data: [] })),
  getGraph:        ()              => api.get('/ad/graph').catch(() => ({ data: null })),
  getAnalytics:    ()              => api.get('/ad/analytics').catch(() => ({ data: null })),
  getAssessment:   ()              => api.get('/ad/assessment').catch(() => ({ data: null })),
  analyzeAI:       (data: any)    => api.post('/ad/ai', data),
  respond:         (data: any)    => api.post('/ad/response', data),
  generateReport:  (data: any)    => api.post('/ad/report', data),
};

export const containerSecurityAPI = {
  getDashboard:       ()              => api.get('/containers/dashboard').catch(() => ({ data: null })),
  getClusters:        ()              => api.get('/containers/clusters').catch(() => ({ data: [] })),
  getNodes:           (params?: any)  => api.get('/containers/nodes', { params }).catch(() => ({ data: [] })),
  getNamespaces:      ()              => api.get('/containers/namespaces').catch(() => ({ data: [] })),
  getPods:            (params?: any)  => api.get('/containers/pods', { params }).catch(() => ({ data: [] })),
  getImages:          (params?: any)  => api.get('/containers/images', { params }).catch(() => ({ data: [] })),
  getSupplyChain:     ()              => api.get('/containers/supply-chain').catch(() => ({ data: null })),
  getRuntimeAlerts:   (params?: any)  => api.get('/containers/runtime-alerts', { params }).catch(() => ({ data: [] })),
  getRBAC:            ()              => api.get('/containers/rbac').catch(() => ({ data: null })),
  getSecrets:         ()              => api.get('/containers/secrets').catch(() => ({ data: null })),
  getNetworkPolicies: ()              => api.get('/containers/network-policies').catch(() => ({ data: [] })),
  getAdmission:       ()              => api.get('/containers/admission').catch(() => ({ data: [] })),
  getCompliance:      ()              => api.get('/containers/compliance').catch(() => ({ data: null })),
  getThreatIntel:     ()              => api.get('/containers/threat-intel').catch(() => ({ data: null })),
  getTimeline:        (params?: any)  => api.get('/containers/timeline', { params }).catch(() => ({ data: [] })),
  getVulnerabilities: (params?: any)  => api.get('/containers/vulnerabilities', { params }).catch(() => ({ data: [] })),
  getAttackPaths:     ()              => api.get('/containers/attack-paths').catch(() => ({ data: null })),
  getAnalytics:       ()              => api.get('/containers/analytics').catch(() => ({ data: null })),
  respond:            (data: any)     => api.post('/containers/response', data),
  analyzeAI:          (data: any)     => api.post('/containers/ai', data),
  generateReport:     (data: any)     => api.post('/containers/report', data),
};

export const emailSecurityAPI = {
  getDashboard:    ()             => api.get('/email/dashboard').catch(() => ({ data: null })),
  getMailFlow:     ()             => api.get('/email/mail-flow').catch(() => ({ data: null })),
  getMessages:     (params?: any) => api.get('/email/messages', { params }).catch(() => ({ data: [] })),
  getThreats:      (params?: any) => api.get('/email/threats', { params }).catch(() => ({ data: [] })),
  getAttachments:  (params?: any) => api.get('/email/attachments', { params }).catch(() => ({ data: [] })),
  getURLs:         (params?: any) => api.get('/email/urls', { params }).catch(() => ({ data: [] })),
  getAuthResults:  (params?: any) => api.get('/email/auth-results', { params }).catch(() => ({ data: null })),
  getSenderIntel:  (params?: any) => api.get('/email/sender-intel', { params }).catch(() => ({ data: null })),
  getThreatIntel:  ()             => api.get('/email/threat-intel').catch(() => ({ data: null })),
  getCampaigns:    ()             => api.get('/email/campaigns').catch(() => ({ data: [] })),
  getTimeline:     (params?: any) => api.get('/email/timeline', { params }).catch(() => ({ data: [] })),
  getUserRisk:     ()             => api.get('/email/user-risk').catch(() => ({ data: [] })),
  getAnalytics:    ()             => api.get('/email/analytics').catch(() => ({ data: null })),
  getPolicies:     ()             => api.get('/email/policies').catch(() => ({ data: [] })),
  createPolicy:    (data: any)    => api.post('/email/policies', data),
  patchPolicy:     (id: number, data: any) => api.patch(`/email/policies/${id}`, data),
  deletePolicy:    (id: number)   => api.delete(`/email/policies/${id}`),
  getReported:     ()             => api.get('/email/reported').catch(() => ({ data: [] })),
  patchReported:   (id: number, data: any) => api.patch(`/email/reported/${id}`, data),
  analyzeAI:       (data: any)    => api.post('/email/ai', data),
  respond:         (data: any)    => api.post('/email/response', data),
  generateReport:  (data: any)    => api.post('/email/report', data),
};

export const suppressionAPI = {
  getAll:  ()                              => api.get('/suppression/rules').catch(() => ({ data: [] })),
  create:  (data: any)                     => api.post('/suppression/rules', data),
  toggle:  (id: number, enabled: boolean)  => api.patch(`/suppression/rules/${id}/toggle`, { enabled }),
  remove:  (id: number)                    => api.delete(`/suppression/rules/${id}`),
};

export const scriptAPI = {
  getTemplates: ()               => api.get('/scripts/templates').catch(() => ({ data: [] })),
  getHistory:   (params?: any)   => api.get('/scripts/history', { params }).catch(() => ({ data: [] })),
  getResult:    (taskId: string) => api.get(`/scripts/result/${taskId}`),
  run:          (data: any)      => api.post('/scripts/run', data),
};

export const schedulerAPI = {
  getAll:  ()                              => api.get('/scheduler/tasks').catch(() => ({ data: [] })),
  create:  (data: any)                     => api.post('/scheduler/tasks', data),
  toggle:  (id: number, enabled: boolean)  => api.patch(`/scheduler/tasks/${id}/toggle`, { enabled }),
  run:     (id: number)                    => api.post(`/scheduler/tasks/${id}/run`, {}),
  remove:  (id: number)                    => api.delete(`/scheduler/tasks/${id}`),
};

export const frameworkComplianceAPI = {
  getAll:    () => api.get('/framework-compliance').catch(() => ({ data: [] })),
  getByName: (name: string) => api.get(`/framework-compliance/${name}`).catch(() => ({ data: null })),
};

export const integrationsAPI = {
  getAll:          ()          => api.get('/integrations').catch(() => ({ data: [] })),
  getDeliveries:   ()          => api.get('/integrations/deliveries').catch(() => ({ data: [] })),
  getInstallTokens:()          => api.get('/integrations/install-tokens').catch(() => ({ data: [] })),
  createInstallToken: (label: string) => api.post('/integrations/install-tokens', { label }),
  save:            (name: string, data: any) => api.put(`/integrations/${name}`, data),
  test:            (name: string)            => api.post(`/integrations/${name}/test`),
};
export const liveLogAPI = {
  stats: () => api.get('/live-logs/stats').catch(() => ({ data: null })),
  explainLog: (message: string, source: string, fields: any) =>
    api.post('/ai/explain-log', { message, source, fields }),
  summarizeLogs: (messages: string[]) =>
    api.post('/ai/summarize-logs', { messages }),
};

export const timelineAPI = {
  get: (params?: {
    limit?: number;
    offset?: number;
    event_types?: string;
    severity?: string;
    agent_id?: number;
    search?: string;
    from?: string;
    to?: string;
  }) => api.get('/timeline', { params: { limit: 500, ...params } }).catch(() => ({ data: [] })),
  stats: () => api.get('/timeline/stats').catch(() => ({ data: {} })),
};
export const riskPostureAPI = {
  get:     ()  => api.get('/risk-posture').catch(() => ({ data: null })),
  history: (limit = 30) => api.get('/risk-posture/history', { params: { limit } }).catch(() => ({ data: [] })),
  refresh: ()  => api.post('/risk-posture/refresh').catch(() => ({ data: null })),
};
export const elasticAPI = {
  health:   ()                    => api.get('/elastic/health'),
  indices:  ()                    => api.get('/elastic/indices'),
  query:    (data: any)           => api.post('/elastic/query', data),
  mapping:  (index: string)       => api.get(`/elastic/mappings/${index}`),
  explain:  (data: any)           => api.post('/elastic/explain', data),
  aiQuery:  (prompt: string)      => api.post('/ai/es-query', { prompt }),
};
export const alertDetailAPI = {
  getPlaybookRecs:   (id: number) => api.get(`/alerts/${id}/playbook-recommendations`),
  executeRec:        (id: number, recID: number) =>
    api.post(`/alerts/${id}/execute-recommendation`, { recommendation_id: recID }),
  updateNote:        (id: number, note: string) => api.patch(`/alerts/${id}/note`, { note }),
  respond:           (id: number, data: any) => api.post(`/alerts/${id}/respond`, data),
  suppressSigmaRule: ({ rule_name, agent_id, hours }: { rule_name: string; agent_id: number; hours: number }) =>
    api.post('/suppression/rules', {
      name:           `Suppress: ${rule_name}`,
      rule_name,
      agent_id,
      window_minutes: hours * 60,
      enabled:        true,
    }),
};

export default api;
