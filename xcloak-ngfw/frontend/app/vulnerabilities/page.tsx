'use client';

import { useEffect, useState } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { agentsAPI } from '@/lib/api';
import { Vulnerability } from '@/types';
import { getSeverityColor } from '@/lib/utils';
import { Search, AlertTriangle, Shield } from 'lucide-react';

interface VulnerabilityWithAgent extends Vulnerability {
  agent_hostname?: string;
}

export default function VulnerabilitiesPage() {
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityWithAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    fetchAllVulnerabilities();
  }, []);

  const fetchAllVulnerabilities = async () => {
    try {
      // Fetch all agents first
      const agentsRes = await agentsAPI.getAll();
      const agents = agentsRes.data;
      
      // Fetch vulnerabilities for each agent
      const allVulns: VulnerabilityWithAgent[] = [];
      for (const agent of agents) {
        try {
          const vulnsRes = await agentsAPI.getVulnerabilities(agent.id);
          const vulns = vulnsRes.data.map((v: Vulnerability) => ({
            ...v,
            agent_hostname: agent.hostname,
          }));
          allVulns.push(...vulns);
        } catch (error) {
          console.error(`Failed to fetch vulnerabilities for agent ${agent.id}:`, error);
        }
      }
      
      setVulnerabilities(allVulns);
    } catch (error) {
      console.error('Failed to fetch vulnerabilities:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredVulns = vulnerabilities.filter(vuln =>
    vuln.name.toLowerCase().includes(search.toLowerCase()) ||
    vuln.description.toLowerCase().includes(search.toLowerCase()) ||
    vuln.agent_hostname?.toLowerCase().includes(search.toLowerCase())
  );

  const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
  const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
  const mediumCount = vulnerabilities.filter(v => v.severity === 'medium').length;
  const lowCount = vulnerabilities.filter(v => v.severity === 'low').length;

  return (
    <RootLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold">Vulnerabilities</h1>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
            <Input
              placeholder="Search vulnerabilities..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-10 w-80"
            />
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Critical</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{criticalCount}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">High</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-600">{highCount}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Medium</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-yellow-600">{mediumCount}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Low</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">{lowCount}</div>
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Vulnerability List</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {loading ? (
                <div className="text-center py-8">Loading vulnerabilities...</div>
              ) : filteredVulns.length === 0 ? (
                <div className="text-center py-8 text-gray-500">No vulnerabilities found</div>
              ) : (
                <div className="divide-y">
                  {filteredVulns.map((vuln) => (
                    <div key={vuln.id} className="py-4">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <div className="flex items-center space-x-2 mb-1">
                            <AlertTriangle className="h-4 w-4 text-yellow-500" />
                            <h3 className="font-medium">{vuln.name}</h3>
                            <Badge className={getSeverityColor(vuln.severity)}>
                              {vuln.severity}
                            </Badge>
                          </div>
                          <p className="text-sm text-gray-600">{vuln.description}</p>
                          {vuln.agent_hostname && (
                            <p className="text-xs text-gray-500 mt-1">
                              Affected Agent: {vuln.agent_hostname}
                            </p>
                          )}
                        </div>
                        <Button variant="outline" size="sm">
                          <Shield className="h-3 w-3 mr-1" />
                          Remediate
                        </Button>
                      </div>
                      <div className="bg-gray-50 p-2 rounded text-sm">
                        <span className="font-medium">Remediation:</span> {vuln.remediation}
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