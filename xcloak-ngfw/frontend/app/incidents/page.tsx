'use client';

import { useEffect, useState } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { incidentsAPI } from '@/lib/api';
import { Incident } from '@/types';
import { formatDate, getSeverityColor, getStatusColor } from '@/lib/utils';
import { AlertCircle, Activity, Shield } from 'lucide-react';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIncidents();
  }, []);

  const fetchIncidents = async () => {
    try {
      const response = await incidentsAPI.getAll();
      setIncidents(response.data);
    } catch (error) {
      console.error('Failed to fetch incidents:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <RootLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold">Incidents</h1>
          <Button>
            <Shield className="h-4 w-4 mr-2" />
            Create Incident
          </Button>
        </div>

        <Card>
          <CardContent className="p-0">
            <div className="divide-y">
              {loading ? (
                <div className="p-8 text-center">Loading incidents...</div>
              ) : incidents.length === 0 ? (
                <div className="p-8 text-center text-gray-500">No incidents found</div>
              ) : (
                incidents.map((incident) => (
                  <div key={incident.id} className="p-4 hover:bg-gray-50">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <AlertCircle className="h-4 w-4 text-red-500" />
                          <h3 className="font-medium">{incident.title}</h3>
                          <Badge className={getSeverityColor(incident.severity)}>
                            {incident.severity}
                          </Badge>
                          <Badge className={getStatusColor(incident.status)}>
                            {incident.status}
                          </Badge>
                        </div>
                        <p className="text-sm text-gray-600 mb-2">{incident.description}</p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span>Agent ID: {incident.agent_id}</span>
                          <span>{formatDate(incident.created_at)}</span>
                        </div>
                      </div>
                      <div className="flex space-x-2">
                        <Button variant="outline" size="sm">
                          <Activity className="h-4 w-4 mr-1" />
                          Timeline
                        </Button>
                        <Button variant="outline" size="sm">
                          SOAR Actions
                        </Button>
                      </div>
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