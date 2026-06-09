'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { RootLayout } from '@/components/layout/RootLayout';
import { StatsCards } from '@/components/dashboard/StatsCards';
import { AlertsChart } from '@/components/dashboard/AlertsChart';
import { RiskChart } from '@/components/dashboard/RiskChart';
import { TopThreats } from '@/components/dashboard/TopThreats';
import { RiskTable } from '@/components/dashboard/RiskTable';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const incidentsData = [
  { severity: 'Critical', count: 8 },
  { severity: 'High', count: 15 },
  { severity: 'Medium', count: 22 },
  { severity: 'Low', count: 31 },
];

export default function DashboardPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    // Check both localStorage and cookie
    const localToken = localStorage.getItem('token');
    
    // Also check cookie
    const cookies = document.cookie.split(';');
    let cookieToken = null;
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'token') {
        cookieToken = value;
        break;
      }
    }
    
    const authToken = localToken || cookieToken;
    
    console.log('Dashboard auth check:', {
      localToken: !!localToken,
      cookieToken: !!cookieToken,
      hasToken: !!authToken
    });
    
    if (!authToken) {
      console.log('No token found, redirecting to login');
      router.push('/login');
      return;
    }
    
    setToken(authToken);
    setLoading(false);
  }, [router]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-lg">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <RootLayout>
      <div className="space-y-6">
        <StatsCards 
          data={{
            agents: 13,
            online_agents: 1,
            offline_agents: 12,
            processes: 438,
            connections: 24,
            services: 78,
            packages: 2761,
            users: 57,
            alerts: 1,
            critical_alerts: 0,
            incidents: 21,
            critical_incidents: 21
          }} 
        />
        
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <AlertsChart />
          <Card>
            <CardHeader>
              <CardTitle>Incidents by Severity</CardTitle>
              <CardDescription>Distribution of security incidents</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={incidentsData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="severity" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="count" fill="#8884d8">
                    {incidentsData.map((entry, index) => (
                      <Bar
                        key={index}
                        dataKey="count"
                        fill={
                          entry.severity === 'Critical'
                            ? '#ef4444'
                            : entry.severity === 'High'
                            ? '#f97316'
                            : entry.severity === 'Medium'
                            ? '#eab308'
                            : '#3b82f6'
                        }
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
          <RiskChart />
          <TopThreats />
        </div>
        
        <RiskTable />
      </div>
    </RootLayout>
  );
}