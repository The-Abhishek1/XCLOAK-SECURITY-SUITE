'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  Cpu,
  Bell,
  AlertTriangle,
  Clock,
  Play,
  Shield,
  Bug,
  Settings,
  Network,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const menuItems = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/agents', label: 'Agents', icon: Cpu },
  { href: '/alerts', label: 'Alerts', icon: Bell },
  { href: '/incidents', label: 'Incidents', icon: AlertTriangle },
  { href: '/timeline', label: 'Timeline', icon: Clock },
  { href: '/playbooks', label: 'Playbooks', icon: Play },
  { href: '/threat-intel', label: 'Threat Intelligence', icon: Shield },
  { href: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
  { href: '/settings', label: 'Settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 z-40 h-screen w-64 bg-gray-900 text-white">
      <div className="flex h-full flex-col">
        <div className="flex h-16 items-center justify-center border-b border-gray-800">
          <Network className="h-8 w-8 text-blue-500" />
          <span className="ml-2 text-xl font-bold">XCloak SOC</span>
        </div>
        <nav className="flex-1 space-y-1 p-4">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href || pathname?.startsWith(`${item.href}/`);
            
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  'flex items-center space-x-3 rounded-lg px-3 py-2 text-sm font-medium transition-all',
                  isActive
                    ? 'bg-gray-800 text-white'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                )}
              >
                <Icon className="h-5 w-5" />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>
    </aside>
  );
}