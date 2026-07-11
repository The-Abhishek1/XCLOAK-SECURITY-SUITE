'use client';

import { useState } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { integrationsAPI, agentsAPI } from '@/lib/api';
import {
  Terminal, Copy, Check, ChevronRight,
  Key, Cpu, CheckCircle, RefreshCw, ArrowLeft,
  FileText, Play, Shield,
} from 'lucide-react';

const STEPS = [
  { id: 1, label: 'Generate Token', icon: Key      },
  { id: 2, label: 'Configure',      icon: FileText },
  { id: 3, label: 'Run',            icon: Play     },
  { id: 4, label: 'Verify',         icon: Shield   },
];

export default function OnboardPage() {
  const [step, setStep]             = useState(1);
  const [token, setToken]           = useState('');
  const [label, setLabel]           = useState('');
  const [serverURL, setServerURL]   = useState('http://localhost:8080');
  const [generating, setGenerating] = useState(false);
  const [copied, setCopied]         = useState<string | null>(null);
  const [checking, setChecking]     = useState(false);
  const [found, setFound]           = useState(false);

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const generate = async () => {
    setGenerating(true);
    try {
      const r = await integrationsAPI.createInstallToken(label);
      setToken(r.data.token);
      setStep(2);
    } catch {
      alert('Failed to generate token — ensure you are logged in as admin.');
    } finally {
      setGenerating(false);
    }
  };

  const checkForAgent = async () => {
    setChecking(true);
    try {
      const r = await agentsAPI.getAll();
      const agents = r.data || [];
      // Look for a recently registered agent (within last 2 minutes)
      const recent = agents.find((a: any) => {
        const created = new Date(a.created_at || a.last_seen).getTime();
        return Date.now() - created < 2 * 60 * 1000;
      });
      if (recent || agents.length > 0) {
        setFound(true);
      }
    } finally {
      setChecking(false);
    }
  };

  function CodeBlock({ code, copyKey }: { code: string; copyKey: string }) {
    return (
      <div className="relative rounded-xl overflow-hidden"
        style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
        <button
          onClick={() => copyText(code, copyKey)}
          className="absolute top-2 right-2 flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg"
          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
          {copied === copyKey
            ? <><Check className="h-3 w-3" style={{ color: 'var(--green)' }} /> Copied</>
            : <><Copy className="h-3 w-3" /> Copy</>}
        </button>
        <pre className="p-4 pt-8 text-[11px] font-mono overflow-x-auto leading-relaxed"
          style={{ color: 'var(--text-1)' }}>
          {code.trim()}
        </pre>
      </div>
    );
  }

  return (
    <RootLayout title="Agent Onboarding" subtitle="Deploy a new XCloak agent"
      actions={
        <a href="/agents" className="g-btn g-btn-ghost text-xs flex items-center gap-1.5">
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Agents
        </a>
      }>
      <div className="max-w-2xl space-y-6">

        {/* Step indicator */}
        <div className="flex items-center">
          {STEPS.map((s, i) => {
            const done   = step > s.id;
            const active = step === s.id;
            const Icon   = s.icon;
            return (
              <div key={s.id} className="flex items-center flex-1 last:flex-none">
                <div className="flex flex-col items-center gap-1.5 shrink-0">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full transition-all"
                    style={{
                      background: done ? 'var(--green)' : active ? 'var(--accent-glow)' : 'var(--glass-bg)',
                      border: `2px solid ${done ? 'var(--green)' : active ? 'var(--accent)' : 'var(--border)'}`,
                    }}>
                    {done
                      ? <Check className="h-4 w-4" style={{ color: 'white' }} />
                      : <Icon className="h-4 w-4" style={{ color: active ? 'var(--accent)' : 'var(--text-3)' }} />}
                  </div>
                  <p className="text-[9px] font-medium whitespace-nowrap"
                    style={{ color: active ? 'var(--accent)' : done ? 'var(--green)' : 'var(--text-3)' }}>
                    {s.label}
                  </p>
                </div>
                {i < STEPS.length - 1 && (
                  <div className="flex-1 h-0.5 mb-4 mx-2"
                    style={{ background: step > s.id ? 'var(--green)' : 'var(--border)' }} />
                )}
              </div>
            );
          })}
        </div>

        {/* ── Step 1: Generate token ────────────────────────── */}
        {step === 1 && (
          <div className="g-card p-6 space-y-4">
            <div>
              <p className="text-sm font-semibold mb-1" style={{ color: 'var(--text-1)' }}>
                Generate an install token
              </p>
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                A one-time token that lets the agent register securely. Expires in 24 hours and can only be used once.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>Agent label</label>
                <input value={label} onChange={e => setLabel(e.target.value)}
                  placeholder="e.g. prod-web-01"
                  className="g-input w-full" />
              </div>
              <div>
                <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>XCloak server URL</label>
                <input value={serverURL} onChange={e => setServerURL(e.target.value)}
                  className="g-input w-full mono" />
              </div>
            </div>

            <button onClick={generate} disabled={generating}
              className="g-btn g-btn-primary w-full justify-center">
              <Key className="h-4 w-4" />
              {generating ? 'Generating…' : 'Generate Install Token'}
            </button>
          </div>
        )}

        {/* ── Step 2: Configure .env ────────────────────────── */}
        {step === 2 && (
          <div className="g-card p-6 space-y-4">
            <div>
              <p className="text-sm font-semibold mb-1" style={{ color: 'var(--text-1)' }}>
                Configure the agent
              </p>
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                Create a <code className="mono">.env</code> file in the agent directory with these values.
                The agent reads this file automatically on startup — no shell exports needed.
              </p>
            </div>

            {/* Token highlight */}
            <div className="rounded-xl p-3 flex items-start gap-2"
              style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
              <Key className="h-4 w-4 shrink-0 mt-0.5" style={{ color: 'var(--accent)' }} />
              <div className="flex-1 min-w-0">
                <p className="text-[10px] font-semibold mb-1" style={{ color: 'var(--accent)' }}>
                  Your install token — shown once, copy it now
                </p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-[11px] font-mono break-all" style={{ color: 'var(--text-1)' }}>
                    {token}
                  </code>
                  <button onClick={() => copyText(token, 'token-raw')}
                    className="shrink-0" style={{ color: 'var(--accent)' }}>
                    {copied === 'token-raw'
                      ? <Check className="h-4 w-4" />
                      : <Copy className="h-4 w-4" />}
                  </button>
                </div>
              </div>
            </div>

            <div>
              <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-2)' }}>
                1. Create <code className="mono">xcloak-agent-desktop/.env</code>
              </p>
              <CodeBlock
                code={`XCLOAK_INSTALL_TOKEN=${token}\nXCLOAK_SERVER_URL=${serverURL}`}
                copyKey="dotenv"
              />
            </div>

            <div className="rounded-xl p-3 text-xs space-y-1"
              style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
              <p className="font-semibold" style={{ color: 'var(--text-1)' }}>How token persistence works:</p>
              <p style={{ color: 'var(--text-3)' }}>
                On first run the agent reads <code className="mono">XCLOAK_INSTALL_TOKEN</code> from <code className="mono">.env</code>,
                registers with the server, then saves a permanent session token to{' '}
                <code className="mono">~/.config/xcloak-agent-desktop/token</code>.
                On every subsequent restart it loads the saved token automatically —
                no <code className="mono">.env</code> or shell exports needed again.
              </p>
            </div>

            <div className="flex gap-3">
              <button onClick={() => setStep(1)} className="g-btn g-btn-ghost flex-1 justify-center">Back</button>
              <button onClick={() => setStep(3)} className="g-btn g-btn-primary flex-1 justify-center">
                Next <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {/* ── Step 3: Build & Run ───────────────────────────── */}
        {step === 3 && (
          <div className="g-card p-6 space-y-4">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
              Build and run the agent
            </p>

            <div>
              <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-2)' }}>
                1. Build from source
              </p>
              <CodeBlock
                code={`cd xcloak-agent-desktop\ngo build -o xcloak-agent-desktop ./main.go`}
                copyKey="build"
              />
            </div>

            <div>
              <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-2)' }}>
                2. Run (first time — reads token from .env and registers)
              </p>
              <CodeBlock code={`./xcloak-agent-desktop`} copyKey="run" />
            </div>

            <div className="rounded-xl p-3 text-xs"
              style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
              <p className="font-semibold mb-1" style={{ color: 'var(--text-1)' }}>Expected output:</p>
              <pre className="font-mono text-[10px] leading-relaxed" style={{ color: 'var(--green)' }}>{
`✓ Agent token saved to ~/.config/xcloak-agent-desktop/token
✓ Registered as agent #2 (hostname: your-machine)
✓ Agent #2 running`
              }</pre>
              <p className="mt-2" style={{ color: 'var(--text-3)' }}>
                On every restart after this, it loads the saved token automatically.
              </p>
            </div>

            <div>
              <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-2)' }}>
                Optional: run as a persistent systemd service
              </p>
              <CodeBlock
                code={`# Create service file
sudo tee /etc/systemd/system/xcloak-agent-desktop.service << EOF
[Unit]
Description=XCloak Security Agent
After=network.target

[Service]
ExecStart=/opt/xcloak-agent-desktop/xcloak-agent-desktop
Restart=always
RestartSec=10
User=${`\${USER}`}
WorkingDirectory=/opt/xcloak-agent-desktop

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now xcloak-agent-desktop
sudo systemctl status xcloak-agent-desktop`}
                copyKey="service"
              />
            </div>

            <div className="flex gap-3">
              <button onClick={() => setStep(2)} className="g-btn g-btn-ghost flex-1 justify-center">Back</button>
              <button onClick={() => setStep(4)} className="g-btn g-btn-primary flex-1 justify-center">
                Next <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {/* ── Step 4: Verify ────────────────────────────────── */}
        {step === 4 && (
          <div className="g-card p-6 space-y-4">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
              Verify the agent is connected
            </p>

            <div className="rounded-xl p-5 text-center"
              style={{ background: found ? 'rgba(52,211,153,0.08)' : 'var(--accent-glow)', border: `1px solid ${found ? 'var(--green)' : 'var(--accent-border)'}` }}>
              {found
                ? <><CheckCircle className="h-10 w-10 mx-auto mb-2" style={{ color: 'var(--green)' }} />
                    <p className="text-sm font-semibold" style={{ color: 'var(--green)' }}>Agent detected!</p>
                    <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>Your agent is registered and running.</p>
                  </>
                : <><Terminal className="h-10 w-10 mx-auto mb-2" style={{ color: 'var(--accent)' }} />
                    <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Waiting for agent…</p>
                    <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>Run the agent on the target machine. It will appear here within 30 seconds.</p>
                  </>
              }
            </div>

            <button onClick={checkForAgent} disabled={checking}
              className="g-btn g-btn-ghost w-full justify-center">
              {checking
                ? <><RefreshCw className="h-4 w-4 animate-spin" /> Checking…</>
                : <><RefreshCw className="h-4 w-4" /> Check Now</>}
            </button>

            <div className="space-y-1.5 text-xs" style={{ color: 'var(--text-2)' }}>
              <p className="font-semibold" style={{ color: 'var(--text-1)' }}>What this agent will collect every 30s:</p>
              {[
                ['Processes', 'Running process list with PIDs'],
                ['Connections', 'Active network connections + remote IPs'],
                ['Packages', 'Installed packages and versions (for CVE scanning)'],
                ['Users', 'Local user accounts and shells'],
                ['Auth logs', '/var/log/auth.log — login attempts, sudo usage'],
                ['File hashes', 'SHA256/MD5 of watched files (FIM)'],
              ].map(([title, desc]) => (
                <div key={title} className="flex items-start gap-2">
                  <Check className="h-3 w-3 shrink-0 mt-0.5" style={{ color: 'var(--green)' }} />
                  <span><span className="font-medium" style={{ color: 'var(--text-1)' }}>{title}</span> — {desc}</span>
                </div>
              ))}
            </div>

            <a href="/agents" className="g-btn g-btn-primary w-full justify-center">
              <Cpu className="h-4 w-4" /> Go to Agents →
            </a>
          </div>
        )}
      </div>
    </RootLayout>
  );
}
