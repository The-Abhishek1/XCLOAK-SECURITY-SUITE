'use client';

import { useEffect, useState } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { playbooksAPI } from '@/lib/api';
import { Playbook } from '@/types';
import { Play, Plus, Trash2, Edit } from 'lucide-react';

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchPlaybooks();
  }, []);

  const fetchPlaybooks = async () => {
    try {
      const response = await playbooksAPI.getAll();
      setPlaybooks(response.data);
    } catch (error) {
      console.error('Failed to fetch playbooks:', error);
    } finally {
      setLoading(false);
    }
  };

  const togglePlaybook = async (id: number, enabled: boolean) => {
    try {
      if (enabled) {
        await playbooksAPI.delete(id);
      } else {
        // Enable logic would go here
      }
      fetchPlaybooks();
    } catch (error) {
      console.error('Failed to toggle playbook:', error);
    }
  };

  return (
    <RootLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold">Playbooks</h1>
          <Button>
            <Plus className="h-4 w-4 mr-2" />
            Create Playbook
          </Button>
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {loading ? (
            <div className="col-span-full text-center py-8">Loading playbooks...</div>
          ) : playbooks.length === 0 ? (
            <div className="col-span-full text-center py-8 text-gray-500">
              No playbooks created yet
            </div>
          ) : (
            playbooks.map((playbook) => (
              <Card key={playbook.id}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg">{playbook.name}</CardTitle>
                    <Switch
                      checked={playbook.enabled}
                      onCheckedChange={() => togglePlaybook(playbook.id, playbook.enabled)}
                    />
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-500">Trigger:</span>
                      <span className="font-medium">{playbook.trigger_type}</span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-500">Action:</span>
                      <span className="font-medium">{playbook.action_type}</span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-500">Status:</span>
                      <Badge className={playbook.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-700'}>
                        {playbook.enabled ? 'Active' : 'Disabled'}
                      </Badge>
                    </div>
                    <div className="flex space-x-2 pt-2">
                      <Button variant="outline" size="sm" className="flex-1">
                        <Edit className="h-3 w-3 mr-1" />
                        Edit
                      </Button>
                      <Button variant="outline" size="sm" className="flex-1">
                        <Play className="h-3 w-3 mr-1" />
                        Run
                      </Button>
                      <Button variant="outline" size="sm" className="flex-1">
                        <Trash2 className="h-3 w-3 mr-1" />
                        Delete
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      </div>
    </RootLayout>
  );
}