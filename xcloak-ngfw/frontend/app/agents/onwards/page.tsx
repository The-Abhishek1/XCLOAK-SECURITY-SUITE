'use client';

import { useState } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import api from '@/lib/api';
import {
  Terminal, Copy, Check, ChevronRight,
  Download, Key, Cpu, CheckCircle,
} from 'lucide-react';

const STEPS = [
  { id: 1, label: 'Generate Token',   icon: Key },
  { id: 2, label: 'Download Agent',   icon: Download },
  { id: 3, label: 'Configure',        icon: Terminal },
  { id: 4, label: 'Run',              icon: Cpu },
];

export default function OnboardPage() {
  const [step, setStep]           = useState(1);
  const [token, setToken]         = useState('');
  const [label, setLabel]         = useState('');
  const [generating, setGenerating] = useState(false);
  const [copied, setCopied]       = useState<string | null>(null);
  const [serverURL, setServerURL] = useState('http://localhost:8080');

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const generate = async () => {
    setGenerating(true);
    try {
      const r = await api.post('/integrations/install-tokens', { label });
      setToken(r.data.token);
      setStep(2);
    } catch {
      alert('Failed to generate token — ensure you are admin.');
    } finally {
      setGenerating(false);
    }
  };

  const installCmd = `# Linux / macOS
curl -fsSL ${serverURL}/agent/install.sh | bash -s -- --token ${token || '<TOKEN>'} --server ${serverURL}`;

  const manualCmd = `# Or manually:
export SERVER_URL="${serverURL}"
export AGENT_TOKEN="${token || '<TOKEN>'}"
./xcloak-agent`;

  const serviceCmd = `# Install as systemd service (Linux):
sudo systemctl enable xcloak-agent
sudo systemctl start xcloak-agent
sudo systemctl status xcloak-agent`;

  const dockerCmd = `# Or run in Docker:
docker run -d \\
  -e SERVER_URL="${serverURL}" \\
  -e AGENT_TOKEN="${token || '<TOKEN>'}" \\
  --name xcloak-agent \\
  --restart unless-stopped \\
  ghcr.io/xcloak/agent:latest`;

  function CodeBlock({ code, copyKey }: { code: string; copyKey: string }) {
    return (
      <div className="relative rounded-xl overflow-hidden"
        style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
        <button
          onClick={() => copyText(code, copyKey)}
          className="absolute top-2 right-2 flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg transition-all"
          style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
          {copied === copyKey
            ? <><Check className="h-3 w-3" style={{ color: 'var(--green)' }} /> Copied</>
            : <><Copy className="h-3 w-3" /> Copy</>}
        </button>
        <pre className="p-4 text-[11px] mono overflow-x-auto leading-relaxed"
          style={{ color: 'var(--text-1)' }}>
          {code.trim()}
        </pre>
      </div>
    );
  }

  return (
    <RootLayout title="Agent Onboarding" subtitle="Deploy a new XCloak agent in minutes">
      <div className="max-w-2xl space-y-6">

        {/* Step indicator */}
        <div className="flex items-center gap-0">
          {STEPS.map((s, i) => {
            const done    = step > s.id;
            const active  = step === s.id;
            const Icon    = s.icon;
            return (
              <div key={s.id} className="flex items-center">
                <div className="flex flex-col items-center gap-1.5">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full transition-all"
                    style={{
                      background: done ? 'var(--green)' : active ? 'var(--accent-glow)' : 'var(--glass-bg)',
                      border: `2px solid ${done ? 'var(--green)' : active ? 'var(--accent)' : 'var(--border)'}`,
                    }}>
                    {done
                      ? <Check className="h-4 w-4 text-white" />
                      : <Icon className="h-4 w-4" style={{ color: active ? 'var(--accent)' : 'var(--text-3)' }} />}
                  </div>
                  <p className="text-[9px] font-medium whitespace-nowrap"
                    style={{ color: active ? 'var(--accent)' : done ? 'var(--green)' : 'var(--text-3)' }}>
                    {s.label}
                  </p>
                </div>
                {i < STEPS.length - 1 && (
                  <div className="w-12 h-0.5 mb-4 mx-1"
                    style={{ background: step > s.id ? 'var(--green)' : 'var(--border)' }} />
                )}
              </div>
            );
          })}
        </div>

        {/* Step 1: Generate token */}
        {step === 1 && (
          <div className="g-card p-6 space-y-4">
            <div>
              <p className="text-sm font-semibold mb-1" style={{ color: 'var(--text-1)' }}>
                Generate an install token
              </p>
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                A one-time token authenticates the agent's initial registration. It expires after 24 hours.
              </p>
            </div>

            <div>
              <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>
                Agent label (optional)
              </label>
              <input value={label} onChange={e => setLabel(e.target.value)}
                placeholder="e.g. prod-web-01, dev-laptop"
                className="g-input w-full" />
            </div>

            <div>
              <label className="text-xs mb-1 block" style={{ color: 'var(--text-3)' }}>
                XCloak backend URL
              </label>
              <input value={serverURL} onChange={e => setServerURL(e.target.value)}
                placeholder="http://your-server:8080"
                className="g-input w-full mono" />
            </div>

            <button onClick={generate} disabled={generating}
              className="g-btn g-btn-primary w-full justify-center">
              <Key className="h-4 w-4" />
              {generating ? 'Generating…' : 'Generate Install Token'}
            </button>
          </div>
        )}

        {/* Step 2: Download */}
        {step === 2 && (
          <div className="g-card p-6 space-y-4">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
              Download the agent binary
            </p>
            <p className="text-xs" style={{ color: 'var(--text-3)' }}>
              The XCloak agent is a single Go binary. Choose your platform:
            </p>

            <div className="grid grid-cols-2 gap-3">
              {[
                { os: 'Linux (amd64)',   arch: 'linux-amd64',   icon: '🐧' },
                { os: 'Linux (arm64)',   arch: 'linux-arm64',   icon: '🐧' },
                { os: 'macOS (arm64)',   arch: 'darwin-arm64',  icon: '🍎' },
                { os: 'Windows (amd64)', arch: 'windows-amd64', icon: '🪟' },
              ].map(p => (
                <div key={p.arch} className="g-card p-3 flex items-center gap-3">
                  <span className="text-xl">{p.icon}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium" style={{ color: 'var(--text-1)' }}>{p.os}</p>
                    <p className="text-[10px] mono" style={{ color: 'var(--text-3)' }}>xcloak-agent-{p.arch}</p>
                  </div>
                  <button
                    onClick={() => notify?.(`Build from source: GOOS=${p.arch.split('-')[0]} GOARCH=${p.arch.split('-')[1]} go build ./`)}
                    className="g-btn g-btn-ghost text-[11px]" style={{ padding: '4px 8px' }}>
                    <Download className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
            </div>

            <div className="rounded-xl p-3"
              style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
              <p className="text-[10px] mb-2" style={{ color: 'var(--text-3)' }}>Build from source:</p>
              <CodeBlock code={`cd xcloak-agent\ngo build -o xcloak-agent .`} copyKey="build" />
            </div>

            <div className="flex gap-3">
              <button onClick={() => setStep(1)} className="g-btn g-btn-ghost flex-1 justify-center">Back</button>
              <button onClick={() => setStep(3)} className="g-btn g-btn-primary flex-1 justify-center">
                Next <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Configure */}
        {step === 3 && (
          <div className="g-card p-6 space-y-4">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Configure & run the agent</p>

            <div>
              <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-2)' }}>
                Quick install (one-liner):
              </p>
              <CodeBlock code={installCmd} copyKey="install" />
            </div>

            <div>
              <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-2)' }}>
                Manual (environment variables):
              </p>
              <CodeBlock code={manualCmd} copyKey="manual" />
            </div>

            <div>
              <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-2)' }}>
                Docker:
              </p>
              <CodeBlock code={dockerCmd} copyKey="docker" />
            </div>

            <div className="flex gap-3">
              <button onClick={() => setStep(2)} className="g-btn g-btn-ghost flex-1 justify-center">Back</button>
              <button onClick={() => setStep(4)} className="g-btn g-btn-primary flex-1 justify-center">
                Next <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {/* Step 4: Verify */}
        {step === 4 && (
          <div className="g-card p-6 space-y-4">
            <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
              Verify the agent is connected
            </p>

            <div className="rounded-xl p-4 text-center"
              style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
              <CheckCircle className="h-10 w-10 mx-auto mb-2" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Agent should appear in ~30 seconds</p>
              <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
                Go to the Agents page and look for your new agent. It will show as online once it sends its first heartbeat.
              </p>
            </div>

            <div>
              <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-2)' }}>Run as a service:</p>
              <CodeBlock code={serviceCmd} copyKey="service" />
            </div>

            <div className="space-y-2 text-xs" style={{ color: 'var(--text-2)' }}>
              <p className="font-medium" style={{ color: 'var(--text-1)' }}>What the agent collects every 30s:</p>
              {[
                'Running processes (name, PID)',
                'Network connections (local/remote address, state)',
                'Installed packages and versions',
                'System users and shells',
                'Auth log entries (/var/log/auth.log)',
                'File integrity monitoring (SHA256 hashes)',
              ].map(item => (
                <div key={item} className="flex items-center gap-2">
                  <Check className="h-3 w-3 shrink-0" style={{ color: 'var(--green)' }} />
                  {item}
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

function notify(msg: string) {
  console.log(msg);
}
