import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

const threats = [
  { name: 'Suspicious PowerShell', count: 156, severity: 'critical' },
  { name: 'Failed Logins', count: 342, severity: 'high' },
  { name: 'Malicious URL', count: 89, severity: 'critical' },
  { name: 'Privilege Escalation', count: 45, severity: 'high' },
  { name: 'Registry Modification', count: 234, severity: 'medium' },
];

export function TopThreats() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Top Threats</CardTitle>
        <CardDescription>Most frequent security threats detected</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {threats.map((threat) => (
            <div key={threat.name} className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">{threat.name}</p>
                <p className="text-xs text-gray-500">{threat.count} occurrences</p>
              </div>
              <Badge
                variant="outline"
                className={
                  threat.severity === 'critical'
                    ? 'border-red-500 text-red-600'
                    : threat.severity === 'high'
                    ? 'border-orange-500 text-orange-600'
                    : 'border-yellow-500 text-yellow-600'
                }
              >
                {threat.severity}
              </Badge>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}