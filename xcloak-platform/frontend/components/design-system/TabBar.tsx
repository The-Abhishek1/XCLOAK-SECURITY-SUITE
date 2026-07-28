'use client';

import type { ComponentType, CSSProperties } from 'react';

type IconComponent = ComponentType<{ className?: string; style?: CSSProperties }>;

interface Tab {
  key: string;
  label: string;
  count?: number;
  icon?: IconComponent;
}

interface TabBarProps {
  tabs: Tab[];
  active: string;
  onChange: (key: string) => void;
  className?: string;
}

export function TabBar({ tabs, active, onChange, className = '' }: TabBarProps) {
  return (
    <div className={`flex items-center gap-1.5 flex-wrap ${className}`}>
      {tabs.map(tab => {
        const isActive = tab.key === active;
        const Icon = tab.icon;
        return (
          <button
            key={tab.key}
            onClick={() => onChange(tab.key)}
            className="text-xs font-medium rounded-lg transition-colors inline-flex items-center gap-1.5"
            style={{
              padding: 'var(--space-2) var(--space-3)',
              background: isActive ? 'var(--accent-glow)' : 'transparent',
              color: isActive ? 'var(--accent)' : 'var(--text-2)',
              border: `1px solid ${isActive ? 'var(--accent-border)' : 'transparent'}`,
            }}
          >
            {Icon && <Icon className="h-3.5 w-3.5" />}
            {tab.label}
            {tab.count !== undefined && <span className="ml-1.5 opacity-70">({tab.count})</span>}
          </button>
        );
      })}
    </div>
  );
}
