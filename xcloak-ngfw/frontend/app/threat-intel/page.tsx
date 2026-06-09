'use client';

import { useEffect, useState } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { iocsAPI } from '@/lib/api';
import { IOC } from '@/types';
import { formatDate, getSeverityColor } from '@/lib/utils';
import { Plus, Upload, Download, Trash2, Edit } from 'lucide-react';

export default function ThreatIntelPage() {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIOCs();
  }, []);

  const fetchIOCs = async () => {
    try {
      const response = await iocsAPI.getAll();
      setIocs(response.data);
    } catch (error) {
      console.error('Failed to fetch IOCs:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleIOC = async (id: number, enabled: boolean) => {
    try {
      if (enabled) {
        await iocsAPI.disable(id);
      } else {
        await iocsAPI.enable(id);
      }
      fetchIOCs();
    } catch (error) {
      console.error('Failed to toggle IOC:', error);
    }
  };

  return (
    <RootLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold">Threat Intelligence</h1>
          <div className="flex space-x-2">
            <Button variant="outline">
              <Upload className="h-4 w-4 mr-2" />
              Import IOC
            </Button>
            <Button variant="outline">
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Add IOC
            </Button>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Indicators of Compromise (IOCs)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {loading ? (
                <div className="text-center py-8">Loading IOCs...</div>
              ) : iocs.length === 0 ? (
                <div className="text-center py-8 text-gray-500">No IOCs configured</div>
              ) : (
                <div className="divide-y">
                  {iocs.map((ioc) => (
                    <div key={ioc.id} className="py-3 flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-1">
                          <span className="font-mono text-sm font-medium">{ioc.indicator}</span>
                          <Badge variant="outline">{ioc.type}</Badge>
                          <Badge className={getSeverityColor(ioc.severity)}>
                            {ioc.severity}
                          </Badge>
                        </div>
                        <p className="text-sm text-gray-600">{ioc.description}</p>
                        <p className="text-xs text-gray-500 mt-1">
                          Added: {formatDate(ioc.created_at)}
                        </p>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Switch
                          checked={ioc.enabled}
                          onCheckedChange={() => toggleIOC(ioc.id, ioc.enabled)}
                        />
                        <Button variant="ghost" size="sm">
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm">
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </RootLayout>
  );
}