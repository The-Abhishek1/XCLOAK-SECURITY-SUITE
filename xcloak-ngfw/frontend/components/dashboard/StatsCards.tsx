import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Cpu, Wifi, AlertTriangle, Shield, Activity } from 'lucide-react';
import { DashboardOverview } from '@/types';

interface StatsCardsProps {
  data: DashboardOverview;
}

export function StatsCards({ data }: StatsCardsProps) {
  const stats = [
    {
      title: 'Total Agents',
      value: data.agents,
      icon: Cpu,
      color: 'text-blue-600',
      bgColor: 'bg-blue-100',
    },
    {
      title: 'Online Agents',
      value: data.online_agents,
      icon: Wifi,
      color: 'text-green-600',
      bgColor: 'bg-green-100',
    },
    {
      title: 'Critical Alerts',
      value: data.critical_alerts,
      icon: AlertTriangle,
      color: 'text-red-600',
      bgColor: 'bg-red-100',
    },
    {
      title: 'Open Incidents',
      value: data.incidents,
      icon: Activity,
      color: 'text-orange-600',
      bgColor: 'bg-orange-100',
    },
    {
      title: 'Threat Feed IOCs',
      value: '142',
      icon: Shield,
      color: 'text-purple-600',
      bgColor: 'bg-purple-100',
    },
  ];

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
      {stats.map((stat) => {
        const Icon = stat.icon;
        return (
          <Card key={stat.title}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
              <div className={`rounded-full p-2 ${stat.bgColor}`}>
                <Icon className={`h-4 w-4 ${stat.color}`} />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stat.value}</div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}