'use client';

import { useEffect, useState } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { alertsAPI } from '@/lib/api';
import { Alert } from '@/types';
import { formatDate, getSeverityColor } from '@/lib/utils';
import { Search, Filter, AlertTriangle } from 'lucide-react';
import { Checkbox } from '@/components/ui/checkbox';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);

  useEffect(() => {
    fetchAlerts();
  }, []);

  const fetchAlerts = async () => {
    try {
      const response = await alertsAPI.getAll();
      setAlerts(response.data);
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleSeverityFilter = (severity: string) => {
    setSeverityFilter(prev =>
      prev.includes(severity)
        ? prev.filter(s => s !== severity)
        : [...prev, severity]
    );
  };

  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = alert.rule_name.toLowerCase().includes(search.toLowerCase()) ||
      alert.log_message.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter.length === 0 || severityFilter.includes(alert.severity);
    return matchesSearch && matchesSeverity;
  });

  return (
    <RootLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold">Alerts</h1>
          <div className="flex space-x-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <Input
                placeholder="Search alerts..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10 w-80"
              />
            </div>
            <Button variant="outline">
              <Filter className="h-4 w-4 mr-2" />
              Filter
            </Button>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Severity Filters</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex space-x-4">
              {['critical', 'high', 'medium', 'low'].map((severity) => (
                <label key={severity} className="flex items-center space-x-2">
                  <Checkbox
                    checked={severityFilter.includes(severity)}
                    onCheckedChange={() => toggleSeverityFilter(severity)}
                  />
                  <span className="text-sm capitalize">{severity}</span>
                </label>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-0">
            <div className="divide-y">
              {loading ? (
                <div className="p-8 text-center">Loading alerts...</div>
              ) : filteredAlerts.length === 0 ? (
                <div className="p-8 text-center text-gray-500">No alerts found</div>
              ) : (
                filteredAlerts.map((alert) => (
                  <div key={alert.id} className="p-4 hover:bg-gray-50">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <AlertTriangle className="h-4 w-4 text-yellow-500" />
                          <h3 className="font-medium">{alert.rule_name}</h3>
                          <Badge className={getSeverityColor(alert.severity)}>
                            {alert.severity}
                          </Badge>
                          <Badge variant="outline">MITRE: T1078</Badge>
                        </div>
                        <p className="text-sm text-gray-600 mb-2">{alert.log_message}</p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span>Agent ID: {alert.agent_id}</span>
                          <span>{formatDate(alert.created_at)}</span>
                        </div>
                      </div>
                      <Button variant="ghost" size="sm">
                        View Details
                      </Button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </RootLayout>
  );
}