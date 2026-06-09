'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { RootLayout } from '@/components/layout/RootLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { agentsAPI } from '@/lib/api';
import { Agent, AgentSummary, Vulnerability, TimelineEvent } from '@/types';
import { formatDate, getStatusColor } from '@/lib/utils';
import { Activity, Database, Network, Package, Users, Clock, Bug, AlertCircle } from 'lucide-react';

export default function AgentDetailPage() {
  const params = useParams();
  const agentId = parseInt(params.id as string);
  
  const [agent, setAgent] = useState<Agent | null>(null);
  const [summary, setSummary] = useState<AgentSummary | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (agentId && !isNaN(agentId)) {
      fetchAgentDetails();
    }
  }, [agentId]);

  const fetchAgentDetails = async () => {
    try {
      setLoading(true);
      setError(null);
      
      console.log('Fetching agent details for ID:', agentId);
      
      // Fetch agent basic info
      const agentRes = await agentsAPI.getById(agentId);
      setAgent(agentRes.data);
      
      // Fetch summary
      try {
        const summaryRes = await agentsAPI.getSummary(agentId);
        setSummary(summaryRes.data);
      } catch (err) {
        console.error('Failed to fetch summary:', err);
        setSummary(null);
      }
      
      // Fetch vulnerabilities (might fail if not implemented)
      try {
        const vulnRes = await agentsAPI.getVulnerabilities(agentId);
        setVulnerabilities(vulnRes.data || []);
      } catch (err) {
        console.error('Failed to fetch vulnerabilities:', err);
        setVulnerabilities([]);
      }
      
      // Fetch timeline (might fail if not implemented)
      try {
        const timelineRes = await agentsAPI.getTimeline(agentId);
        setTimeline(timelineRes.data || []);
      } catch (err) {
        console.error('Failed to fetch timeline:', err);
        setTimeline([]);
      }
      
    } catch (err: any) {
      console.error('Failed to fetch agent details:', err);
      setError(err.response?.data?.error || 'Failed to load agent details');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <RootLayout>
        <div className="flex items-center justify-center h-full min-h-screen">
          <div className="text-lg">Loading agent details...</div>
        </div>
      </RootLayout>
    );
  }

  if (error || !agent) {
    return (
      <RootLayout>
        <div className="flex items-center justify-center h-full min-h-screen">
          <Card className="w-[500px]">
            <CardHeader>
              <CardTitle className="text-red-600 flex items-center gap-2">
                <AlertCircle className="h-5 w-5" />
                Error Loading Agent
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600">{error || 'Agent not found'}</p>
              <button 
                onClick={() => window.location.href = '/agents'}
                className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
              >
                Back to Agents
              </button>
            </CardContent>
          </Card>
        </div>
      </RootLayout>
    );
  }

  return (
    <RootLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">{agent.hostname}</h1>
            <p className="text-gray-500 mt-1">{agent.os} • {agent.ip_address}</p>
          </div>
          <Badge className={getStatusColor(agent.status)}>
            {agent.status}
          </Badge>
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Processes</CardTitle>
              <Activity className="h-4 w-4 text-gray-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{summary?.processes || 0}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Connections</CardTitle>
              <Network className="h-4 w-4 text-gray-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{summary?.connections || 0}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Services</CardTitle>
              <Database className="h-4 w-4 text-gray-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{summary?.services || 0}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Packages</CardTitle>
              <Package className="h-4 w-4 text-gray-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{summary?.packages || 0}</div>
            </CardContent>
          </Card>
        </div>

        <Tabs defaultValue="processes" className="space-y-4">
          <TabsList>
            <TabsTrigger value="processes">Processes</TabsTrigger>
            <TabsTrigger value="connections">Connections</TabsTrigger>
            <TabsTrigger value="services">Services</TabsTrigger>
            <TabsTrigger value="packages">Packages</TabsTrigger>
            <TabsTrigger value="users">Users</TabsTrigger>
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
            <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
          </TabsList>
          
          <TabsContent value="processes">
            <Card>
              <CardHeader>
                <CardTitle>Running Processes</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <p className="text-gray-500">Process collection feature coming soon. Agent data will appear here once collected.</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="connections">
            <Card>
              <CardHeader>
                <CardTitle>Network Connections</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <p className="text-gray-500">Connection data coming soon. Network connections will be displayed here.</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="services">
            <Card>
              <CardHeader>
                <CardTitle>System Services</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <p className="text-gray-500">Service data coming soon. Running services will be displayed here.</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="packages">
            <Card>
              <CardHeader>
                <CardTitle>Installed Packages</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <p className="text-gray-500">Package data coming soon. Installed software packages will be displayed here.</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="users">
            <Card>
              <CardHeader>
                <CardTitle>System Users</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <p className="text-gray-500">User data coming soon. System users will be displayed here.</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="timeline">
            <Card>
              <CardHeader>
                <CardTitle>Attack Timeline</CardTitle>
              </CardHeader>
              <CardContent>
                {timeline && timeline.length > 0 ? (
                  <div className="space-y-4">
                    {timeline.map((event, index) => (
                      <div key={index} className="flex items-start space-x-3 pb-4 border-b last:border-0">
                        <div className="flex-shrink-0">
                          <Clock className="h-5 w-5 text-gray-400" />
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">{event.message}</p>
                          <p className="text-xs text-gray-500">{formatDate(event.created_at)}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500">No timeline events available for this agent.</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="vulnerabilities">
            <Card>
              <CardHeader>
                <CardTitle>Vulnerabilities</CardTitle>
              </CardHeader>
              <CardContent>
                {vulnerabilities && vulnerabilities.length > 0 ? (
                  <div className="space-y-4">
                    {vulnerabilities.map((vuln) => (
                      <div key={vuln.id} className="border-b pb-3 last:border-0">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-medium">{vuln.name}</h4>
                          <Badge
                            variant="outline"
                            className={
                              vuln.severity === 'critical'
                                ? 'border-red-500 text-red-600'
                                : vuln.severity === 'high'
                                ? 'border-orange-500 text-orange-600'
                                : vuln.severity === 'medium'
                                ? 'border-yellow-500 text-yellow-600'
                                : 'border-blue-500 text-blue-600'
                            }
                          >
                            {vuln.severity}
                          </Badge>
                        </div>
                        <p className="text-sm text-gray-600 mb-2">{vuln.description}</p>
                        <p className="text-xs text-gray-500">
                          Remediation: {vuln.remediation}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500">No vulnerabilities found for this agent.</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </RootLayout>
  );
}