import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { getRiskColor, getRiskLevel } from '@/lib/utils';

const agents = [
  { name: 'Server-01', risk: 95, status: 'critical' },
  { name: 'Desktop-01', risk: 72, status: 'high' },
  { name: 'Laptop-01', risk: 45, status: 'medium' },
  { name: 'Workstation-03', risk: 38, status: 'low' },
  { name: 'Database-02', risk: 88, status: 'critical' },
];

export function RiskTable() {
  return (
    <Card className="col-span-2">
      <CardHeader>
        <CardTitle>Agent Risk Scores</CardTitle>
        <CardDescription>Real-time risk assessment by agent</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          <div className="grid grid-cols-3 gap-4 pb-2 text-sm font-medium text-gray-500">
            <div>Agent</div>
            <div>Risk Score</div>
            <div>Risk Level</div>
          </div>
          {agents.map((agent) => (
            <div key={agent.name} className="grid grid-cols-3 gap-4 items-center py-2 border-t">
              <div className="font-medium">{agent.name}</div>
              <div className={`font-bold ${getRiskColor(agent.risk)}`}>{agent.risk}</div>
              <div>
                <Badge
                  variant="outline"
                  className={
                    agent.status === 'critical'
                      ? 'border-red-500 text-red-600'
                      : agent.status === 'high'
                      ? 'border-orange-500 text-orange-600'
                      : agent.status === 'medium'
                      ? 'border-yellow-500 text-yellow-600'
                      : 'border-green-500 text-green-600'
                  }
                >
                  {getRiskLevel(agent.risk)}
                </Badge>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}