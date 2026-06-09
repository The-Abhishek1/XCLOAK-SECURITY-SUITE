import axios from 'axios';

const API_BASE_URL = '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Important for cookies
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle errors and set cookie
api.interceptors.response.use(
  (response) => {
    console.log('API Response:', response.config.url, response.status);
    
    // If this is a login response and has a token, also set it as a cookie
    if (response.config.url === '/auth/login' && response.data?.token) {
      // Set cookie for middleware
      document.cookie = `token=${response.data.token}; path=/; max-age=86400`; // 24 hours
    }
    
    return response;
  },
  (error) => {
    console.error('API Error:', error.config?.url, error.response?.status);
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      document.cookie = 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
      if (typeof window !== 'undefined' && !window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);


// Auth API
export const authAPI = {
  register: (data: { username: string; email: string; password: string; role: string }) =>
    api.post('/auth/register', data),
  login: (data: { username: string; password: string }) =>
    api.post('/auth/login', data),
};


// Agents API with error handling
export const agentsAPI = {
  getAll: () => api.get('/agents'),
  getById: (id: number) => api.get(`/agents/${id}`),
  getSummary: (id: number) => api.get(`/agents/${id}/summary`),
  getRisk: (id: number) => api.get(`/agents/${id}/risk`),
  getTimeline: (id: number) => api.get(`/agents/${id}/timeline`).catch(err => {
    console.error('Timeline API error:', err);
    return { data: [] }; // Return empty array on error
  }),
  getVulnerabilities: (id: number) => api.get(`/agents/${id}/vulnerabilities`).catch(err => {
    console.error('Vulnerabilities API error:', err);
    return { data: [] }; // Return empty array on error
  }),
  vulnerabilityScan: (id: number) => api.post(`/agents/${id}/vulnerability-scan`),
  heartbeat: (data: { agent_id: number }) => api.post('/agents/heartbeat', data),
};

// Alerts API
export const alertsAPI = {
  getAll: () => api.get<Alert[]>('/alerts'),
  getByAgent: (agentId: number) => api.get<Alert[]>(`/alerts/agent/${agentId}`),
};

// Incidents API
export const incidentsAPI = {
  getAll: () => api.get<Incident[]>('/incidents'),
  getById: (id: number) => api.get<Incident>(`/incidents/${id}`),
  getEvents: (id: number) => api.get(`/incidents/${id}/events`),
  updateStatus: (id: number, status: string) => api.put(`/incidents/${id}/status`, { status }),
};

// Dashboard API
export const dashboardAPI = {
  getOverview: () => api.get<DashboardOverview>('/dashboard/overview'),
};

// IOCs API
export const iocsAPI = {
  getAll: () => api.get<IOC[]>('/iocs'),
  getById: (id: number) => api.get<IOC>(`/iocs/${id}`),
  create: (data: Partial<IOC>) => api.post('/iocs', data),
  update: (id: number, data: Partial<IOC>) => api.put(`/iocs/${id}`, data),
  delete: (id: number) => api.delete(`/iocs/${id}`),
  enable: (id: number) => api.patch(`/iocs/${id}/enable`),
  disable: (id: number) => api.patch(`/iocs/${id}/disable`),
  bulkImport: (data: { type: string; severity: string; description: string; indicators: string[] }) =>
    api.post('/iocs/import', data),
};

// Playbooks API
export const playbooksAPI = {
  getAll: () => api.get<Playbook[]>('/playbooks'),
  getById: (id: number) => api.get<Playbook>(`/playbooks/${id}`),
  getActions: (id: number) => api.get<PlaybookAction[]>(`/playbooks/${id}/actions`),
  create: (data: { name: string; trigger_type: string; action_type: string; enabled: boolean }) =>
    api.post('/playbooks', data),
  delete: (id: number) => api.delete(`/playbooks/${id}`),
  createAction: (data: { playbook_id: number; step_order: number; action_type: string; payload: string }) =>
    api.post('/playbook-actions', data),
  deleteAction: (id: number) => api.delete(`/playbook-actions/${id}`),
  getExecutions: () => api.get('/playbook-executions'),
};

// Sigma Rules API
export const sigmaAPI = {
  getAll: () => api.get('/sigma/rules'),
  create: (data: any) => api.post('/sigma/rules', data),
  update: (id: number, data: any) => api.put(`/sigma/rules/${id}`, data),
  delete: (id: number) => api.delete(`/sigma/rules/${id}`),
  enable: (id: number) => api.patch(`/sigma/rules/${id}/enable`),
  disable: (id: number) => api.patch(`/sigma/rules/${id}/disable`),
  test: (data: { message: string }) => api.post('/sigma/rules/test', data),
};

// Tasks API
export const tasksAPI = {
  create: (data: { agent_id: number; task_type: string; payload: any }) =>
    api.post('/tasks', data),
  getAgentTasks: (agentId: number) => api.get(`/tasks/agent/${agentId}`),
  submitResult: (data: { task_id: number; result: string }) =>
    api.post('/tasks/result', data),
};

// Quarantine API
export const quarantineAPI = {
  getAll: () => api.get('/quarantine'),
  quarantine: (data: { agent_id: number; original_path: string; quarantine_path: string; file_name: string; reason: string }) =>
    api.post('/agents/quarantine', data),
};

// Threat Feeds API
export const threatFeedsAPI = {
  getAll: () => api.get('/threat-feeds'),
  create: (data: { name: string; source: string; enabled: boolean }) =>
    api.post('/threat-feeds', data),
};

// Firewall Rules API
export const firewallAPI = {
  getAll: () => api.get('/firewall/rules'),
  getById: (id: number) => api.get(`/firewall/rules/${id}`),
  create: (data: any) => api.post('/firewall/rules', data),
  update: (id: number, data: any) => api.put(`/firewall/rules/${id}`, data),
  delete: (id: number) => api.delete(`/firewall/rules/${id}`),
};

// Audit Logs API
export const auditAPI = {
  getLogs: () => api.get('/audit/logs'),
};

export default api;