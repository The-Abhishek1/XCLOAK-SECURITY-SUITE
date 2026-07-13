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
  getHealth:      ()           => api.get('/agents/health').catch(() => ({ data: [] })),
  getTasks:       (id: number) => api.get(`/agents/${id}/tasks`).catch(() => ({ data: [] })),
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
  getAll:        ()                              => api.get('/incidents'),
  getCounts:     ()                              => api.get('/incidents/counts'),
  getPaginated:  (page = 1, perPage = 25, status = '') =>
    api.get('/incidents/paginated', { params: { page, per_page: perPage, status: status || undefined } }),
  getById:       (id: number)                   => api.get(`/incidents/${id}`),
  getEvents:     (id: number)                   => api.get(`/incidents/${id}/events`).catch(() => ({ data: [] })),
  getAlerts:     (id: number)                   => api.get(`/incidents/${id}/alerts`).catch(() => ({ data: [] })),
  updateStatus:  (id: number, status: string)   => api.put(`/incidents/${id}/status`, { status }),
  updateSeverity:(id: number, severity: string) => api.patch(`/incidents/${id}/severity`, { severity }),
  addNote:       (id: number, note: string)     => api.post(`/incidents/${id}/notes`, { note }),
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
};

export const logSourcesAPI = {
  getAll:  ()                   => api.get('/log-sources'),
  create:  (data: any)          => api.post('/log-sources', data),
  update:  (id: number, data: any) => api.put(`/log-sources/${id}`, data),
  remove:  (id: number)         => api.delete(`/log-sources/${id}`),
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

export const yaraAPI = {
  getAll:     ()                      => api.get('/yara/rules'),
  create:     (data: any)             => api.post('/yara/rules', data),
  update:     (id: number, data: any) => api.put(`/yara/rules/${id}`, data),
  delete:     (id: number)            => api.delete(`/yara/rules/${id}`),
  enable:     (id: number)            => api.patch(`/yara/rules/${id}/enable`),
  disable:    (id: number)            => api.patch(`/yara/rules/${id}/disable`),
  getMatches: (agentId?: number)      => api.get('/yara/matches', { params: agentId ? { agent_id: agentId } : {} }),
  import:     (form: FormData)        => api.post('/yara/import', form, { headers: { 'Content-Type': 'multipart/form-data' } }),
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
  getUsers:  (params?: Record<string, any>) => api.get('/ueba/users', { params }),
  getEvents: (params?: Record<string, any>) => api.get('/ueba/events', { params }),
  analyze:   ()                             => api.post('/ueba/analyze'),
};

export const insiderThreatAPI = {
  getScores:  (days: number, minScore: number) =>
    api.get('/insider-threat', { params: { days, min_score: minScore } }),
  getSummary: () => api.get('/insider-threat/summary'),
};

export const nbaAPI = {
  getAnomalies:  (limit = 200)      => api.get('/nba/anomalies', { params: { limit } }),
  acknowledge:   (id: number)        => api.post(`/nba/anomalies/${id}/acknowledge`),
  getBaseline:   (agentId: number)   => api.get(`/nba/baseline/${agentId}`),
  analyze:       ()                  => api.post('/nba/analyze'),
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
  getSummary: () => api.get('/dpi/summary'),
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
  getAll:    (limit = 200)  => api.get('/clusters', { params: { limit } }).catch(() => ({ data: [] })),
  getAlerts: (id: number)   => api.get(`/clusters/${id}/alerts`).catch(() => ({ data: [] })),
  analyze:   ()             => api.post('/clusters/analyze'),
  suppress:  (id: number)   => api.post(`/clusters/${id}/suppress`),
};

export const threatActorsAPI = {
  getAll:    ()                       => api.get('/threat-actors').catch(() => ({ data: [] })),
  create:    (data: any)              => api.post('/threat-actors', data),
  remove:    (id: number)             => api.delete(`/threat-actors/${id}`),
  getAlerts: (id: number, limit = 10) =>
    api.get(`/threat-actors/${id}/alerts`, { params: { limit } }).catch(() => ({ data: [] })),
};

export const ja3API = {
  getAll:  ()           => api.get('/ja3/fingerprints').catch(() => ({ data: [] })),
  create:  (data: any)  => api.post('/ja3/fingerprints', data),
  remove:  (id: number) => api.delete(`/ja3/fingerprints/${id}`),
};

export const huntAPI = {
  getSaved:    ()              => api.get('/hunt/queries').catch(() => ({ data: [] })),
  run:         (data: any)     => api.post('/hunt/run', data),
  rerun:       (id: number)    => api.post(`/hunt/queries/${id}/run`, {}),
  deleteSaved: (id: number)    => api.delete(`/hunt/queries/${id}`),
  promote:     (data: any)     => api.post('/sigma/rules/from-hunt', data),
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
};

export const dfirAPI = {
  getCollections:    (limit = 50)          => api.get('/dfir/collections', { params: { limit } }).catch(() => ({ data: [] })),
  triggerCollection: (data: any)           => api.post('/dfir/collections', data),
  getArtifacts:      (id: number)          => api.get(`/dfir/collections/${id}/artifacts`).catch(() => ({ data: [] })),
  getTimeline:       (incidentId: number)  => api.get(`/dfir/incidents/${incidentId}/timeline`).catch(() => ({ data: [] })),
};

export const deceptionAPI = {
  getTokens:      ()                              => api.get('/canary/tokens').catch(() => ({ data: [] })),
  createToken:    (data: any)                     => api.post('/canary/tokens', data),
  deleteToken:    (id: number)                    => api.delete(`/canary/tokens/${id}`),
  toggleToken:    (id: number, isActive: boolean) => api.patch(`/canary/tokens/${id}/toggle`, { is_active: isActive }),
  getTrips:       (limit = 50)                    => api.get('/canary/trips', { params: { limit } }).catch(() => ({ data: [] })),
  getHoneyports:  ()                              => api.get('/honeyports').catch(() => ({ data: [] })),
  createHoneyport:(data: any)                     => api.post('/honeyports', data),
  deleteHoneyport:(id: number)                    => api.delete(`/honeyports/${id}`),
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
export const timelineAPI = {
  get: (limit = 500) => api.get('/timeline', { params: { limit } }).catch(() => ({ data: [] })),
};
export const riskPostureAPI = {
  get:     ()  => api.get('/risk-posture').catch(() => ({ data: null })),
  history: (limit = 30) => api.get('/risk-posture/history', { params: { limit } }).catch(() => ({ data: [] })),
  refresh: ()  => api.post('/risk-posture/refresh').catch(() => ({ data: null })),
};
export const elasticAPI = {
  health:  ()              => api.get('/elastic/health'),
  indices: ()              => api.get('/elastic/indices'),
  query:   (data: any)     => api.post('/elastic/query', data),
};
export const alertDetailAPI = {
  getPlaybookRecs:   (id: number) => api.get(`/alerts/${id}/playbook-recommendations`),
  executeRec:        (id: number, recID: number) =>
    api.post(`/alerts/${id}/execute-recommendation`, { recommendation_id: recID }),
  updateNote:        (id: number, note: string) => api.patch(`/alerts/${id}/note`, { note }),
  respond:           (id: number, data: any) => api.post(`/alerts/${id}/respond`, data),
  suppressSigmaRule: (data: any) => api.post('/sigma-rules/suppress', data),
};

export default api;
