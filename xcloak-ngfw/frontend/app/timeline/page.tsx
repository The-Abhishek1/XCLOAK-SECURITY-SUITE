'use client';

import { useEffect, useState } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { agentsAPI } from '@/lib/api';
import { TimelineEvent } from '@/types';
import { formatDate } from '@/lib/utils';
import { Search, Clock, AlertTriangle, Play } from 'lucide-react';

export default function TimelinePage() {
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    fetchAllTimelineEvents();
  }, []);

  const fetchAllTimelineEvents = async () => {
    try {
      const agentsRes = await agentsAPI.getAll();
      const agents = agentsRes.data;
      
      const allEvents: TimelineEvent[] = [];
      for (const agent of agents) {
        try {
          const timelineRes = await agentsAPI.getTimeline(agent.id);
          const events = timelineRes.data.map((e: TimelineEvent) => ({
            ...e,
            agent_hostname: agent.hostname,
          }));
          allEvents.push(...events);
        } catch (error) {
          console.error(`Failed to fetch timeline for agent ${agent.id}:`, error);
        }
      }
      
      allEvents.sort((a, b) => 
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      );
      
      setTimeline(allEvents);
    } catch (error) {
      console.error('Failed to fetch timeline:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredEvents = timeline.filter(event =>
    event.message.toLowerCase().includes(search.toLowerCase())
  );

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'alert':
        return <AlertTriangle className="h-5 w-5 text-red-500" />;
      case 'playbook':
        return <Play className="h-5 w-5 text-blue-500" />;
      default:
        return <Clock className="h-5 w-5 text-gray-500" />;
    }
  };

  return (
    <RootLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold">Security Timeline</h1>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
            <Input
              placeholder="Search timeline..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-10 w-80"
            />
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Global Event Timeline</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="relative">
              <div className="absolute left-6 top-0 bottom-0 w-px bg-gray-200"></div>
              <div className="space-y-6">
                {loading ? (
                  <div className="text-center py-8">Loading timeline...</div>
                ) : filteredEvents.length === 0 ? (
                  <div className="text-center py-8 text-gray-500">No events found</div>
                ) : (
                  filteredEvents.map((event, index) => (
                    <div key={index} className="relative flex items-start space-x-4">
                      <div className="relative z-10">
                        <div className="bg-white rounded-full p-1 border-2 border-gray-200">
                          {getEventIcon(event.event_type)}
                        </div>
                      </div>
                      <div className="flex-1">
                        <div className="bg-gray-50 rounded-lg p-4">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-medium text-gray-500 uppercase">
                              {event.event_type}
                            </span>
                            <span className="text-xs text-gray-500">
                              {formatDate(event.created_at)}
                            </span>
                          </div>
                          <p className="text-sm">{event.message}</p>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </RootLayout>
  );
}