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
};

export const alertsAPI = {
  getAll:    () => api.get('/alerts'),
  // FIX: /api/alerts/agent/:id does not exist on the backend (404).
  // Fetch all alerts and filter client-side by agent_id instead.
  getByAgent: async (agentId: number) => {
    const res = await api.get('/alerts');
    const all = res.data || [];
    return { ...res, data: all.filter((a: any) => a.agent_id === agentId) };
  },
};

export const incidentsAPI = {
  getAll:       ()                              => api.get('/incidents'),
  getById:      (id: number)                   => api.get(`/incidents/${id}`),
  getEvents:    (id: number)                   => api.get(`/incidents/${id}/events`).catch(() => ({ data: [] })),
  updateStatus: (id: number, status: string)   => api.put(`/incidents/${id}/status`, { status }),
};

export const dashboardAPI = {
  getOverview: () => api.get('/dashboard/overview'),
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
};

export const sigmaAPI = {
  getAll:   ()                      => api.get('/sigma/rules'),
  create:   (data: any)             => api.post('/sigma/rules', data),
  update:   (id: number, data: any) => api.put(`/sigma/rules/${id}`, data),
  delete:   (id: number)            => api.delete(`/sigma/rules/${id}`),
  enable:   (id: number)            => api.patch(`/sigma/rules/${id}/enable`),
  disable:  (id: number)            => api.patch(`/sigma/rules/${id}/disable`),
  test:     (data: { message: string }) => api.post('/sigma/rules/test', data),
};

export const tasksAPI = {
  create:        (data: { agent_id: number; task_type: string; payload: any }) => api.post('/tasks', data),
  getAgentTasks: (agentId: number)  => api.get(`/tasks/agent/${agentId}`),
  submitResult:  (data: any)        => api.post('/tasks/result', data),
};

export const quarantineAPI = {
  getAll:     ()          => api.get('/quarantine').catch(() => ({ data: [] })),
  quarantine: (data: any) => api.post('/agents/quarantine', data),
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
  getAll:   ()                      => api.get('/firewall/rules'),
  getById:  (id: number)            => api.get(`/firewall/rules/${id}`),
  create:   (data: any)             => api.post('/firewall/rules', data),
  update:   (id: number, data: any) => api.put(`/firewall/rules/${id}`, data),
  delete:   (id: number)            => api.delete(`/firewall/rules/${id}`),
};

export const auditAPI = {
  getLogs: () => api.get('/audit/logs'),
};

export default api;
