'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const data = [
  { severity: 'Critical', count: 12 },
  { severity: 'High', count: 28 },
  { severity: 'Medium', count: 45 },
  { severity: 'Low', count: 67 },
];

export function AlertsChart() {
  return (
    <Card className="col-span-2">
      <CardHeader>
        <CardTitle>Alerts by Severity</CardTitle>
        <CardDescription>Distribution of security alerts by severity level</CardDescription>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="severity" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="count" fill="#8884d8">
              {data.map((entry, index) => (
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
  );
}