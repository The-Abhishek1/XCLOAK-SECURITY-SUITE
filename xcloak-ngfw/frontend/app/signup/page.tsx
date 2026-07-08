'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import {
  ShieldCheck, Building2, User, Mail, Lock, Eye, EyeOff,
  AlertCircle, ArrowLeft, ArrowRight, Check, Sun, Moon,
} from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';

type Step = 1 | 2;

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 48);
}

export default function SignupPage() {
  const router = useRouter();
  const { theme, toggle } = useTheme();

  const [step, setStep]         = useState<Step>(1);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState('');
  const [showPass, setShowPass] = useState(false);
  const [showConf, setShowConf] = useState(false);

  // Step 1
  const [orgName, setOrgName]     = useState('');
  const [slug, setSlug]           = useState('');
  const [slugEdited, setSlugEdited] = useState(false);

  // Step 2
  const [username, setUsername]   = useState('');
  const [email, setEmail]         = useState('');
  const [password, setPassword]   = useState('');
  const [confirm, setConfirm]     = useState('');

  useEffect(() => {
    const loggedIn = document.cookie.split(';').some(c => c.trim().startsWith('logged_in='));
    if (loggedIn) router.push('/dashboard');
  }, [router]);

  useEffect(() => {
    if (!slugEdited) setSlug(slugify(orgName));
  }, [orgName, slugEdited]);

  const goNext = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!orgName.trim()) { setError('Organization name is required.'); return; }
    // Derive slug synchronously in case the useEffect hasn't fired yet
    // (can happen when the user submits immediately after typing the org name).
    const effectiveSlug = slug || slugify(orgName.trim());
    if (!effectiveSlug) { setError('Slug is required.'); return; }
    if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(effectiveSlug) && effectiveSlug.length > 1) {
      setError('Slug must be lowercase letters, numbers, and hyphens only.'); return;
    }
    if (!slugEdited) setSlug(effectiveSlug);
    setStep(2);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (password !== confirm) { setError('Passwords do not match.'); return; }
    if (password.length < 8)  { setError('Password must be at least 8 characters.'); return; }

    setLoading(true);
    try {
      const res  = await fetch('/api/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_name: orgName, slug, username, email, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Signup failed');
      window.location.href = '/dashboard';
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden"
      style={{ background: 'var(--bg-0)' }}>
      <div className="bg-mesh" />
      <div className="grid-bg fixed inset-0 z-0 opacity-20" />

      <div className="fixed z-0 pointer-events-none"
        style={{ top: '8%', left: '3%', width: 500, height: 500, borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(34,211,238,0.07) 0%, transparent 70%)',
          filter: 'blur(40px)' }} />
      <div className="fixed z-0 pointer-events-none"
        style={{ bottom: '8%', right: '3%', width: 400, height: 400, borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(14,165,233,0.05) 0%, transparent 70%)',
          filter: 'blur(40px)' }} />

      <button onClick={toggle}
        className="fixed top-4 right-4 z-20 flex h-9 w-9 items-center justify-center rounded-lg transition-colors"
        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
        {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      </button>

      <div className="relative z-10 w-full max-w-[440px] px-4">
        <div className="g-panel p-8">
          {/* Logo */}
          <div className="flex flex-col items-center mb-7">
            <div className="relative mb-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl"
                style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)',
                  boxShadow: '0 0 30px var(--accent-glow)' }}>
                <ShieldCheck className="h-7 w-7" style={{ color: 'var(--accent)' }} />
              </div>
            </div>
            <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-1)' }}>
              XCloak <span style={{ color: 'var(--accent)' }}>SOC</span>
            </h1>
            <p className="text-xs mt-1" style={{ color: 'var(--text-2)' }}>Create your organization</p>
          </div>

          {/* Step indicator */}
          <div className="flex items-center gap-2 mb-6">
            {([1, 2] as Step[]).map((n, i) => (
              <div key={n} className="flex items-center gap-2 flex-1">
                <div className="flex items-center gap-2">
                  <div className="flex h-6 w-6 items-center justify-center rounded-full text-[11px] font-bold shrink-0 transition-all"
                    style={{
                      background: step > n ? 'var(--green)' : step === n ? 'var(--accent)' : 'var(--bg-0)',
                      border: step >= n ? 'none' : '1px solid var(--border)',
                      color: step >= n ? '#fff' : 'var(--text-3)',
                    }}>
                    {step > n ? <Check className="h-3 w-3" /> : n}
                  </div>
                  <span className="text-[11px] font-medium whitespace-nowrap"
                    style={{ color: step === n ? 'var(--text-1)' : 'var(--text-3)' }}>
                    {n === 1 ? 'Organization' : 'Admin Account'}
                  </span>
                </div>
                {i < 1 && <div className="flex-1 h-px mx-1" style={{ background: 'var(--border)' }} />}
              </div>
            ))}
          </div>

          {/* ── Step 1: Org ── */}
          {step === 1 && (
            <form onSubmit={goNext} noValidate className="space-y-4">
              <Field label="Organization name">
                <div className="relative">
                  <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                  <input
                    value={orgName}
                    onChange={e => setOrgName(e.target.value)}
                    placeholder="Acme Security Inc."
                    required
                    autoFocus
                    className="g-input pl-9"
                  />
                </div>
              </Field>

              <Field label="URL slug">
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-xs select-none"
                    style={{ color: 'var(--text-3)' }}>xcloak /</span>
                  <input
                    value={slug}
                    onChange={e => { setSlugEdited(true); setSlug(slugify(e.target.value)); }}
                    placeholder="acme-security"
                    required
                    className="g-input pl-[62px]"
                  />
                </div>
                <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                  Lowercase letters, numbers, hyphens. Used for SSO login.
                </p>
              </Field>

              {error && <ErrMsg msg={error} />}

              <button type="submit"
                className="g-btn g-btn-primary w-full justify-center py-2.5 text-sm font-semibold mt-1">
                Continue <ArrowRight className="h-4 w-4" />
              </button>

              <p className="text-center text-[11px]" style={{ color: 'var(--text-3)' }}>
                Already have an account?{' '}
                <a href="/login" style={{ color: 'var(--accent)' }}>Sign in</a>
              </p>
            </form>
          )}

          {/* ── Step 2: Admin account ── */}
          {step === 2 && (
            <form onSubmit={handleSubmit} noValidate className="space-y-4">
              <div className="rounded-xl p-3 text-xs"
                style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>
                This account will be the admin for <strong>{orgName}</strong>.
              </div>

              <Field label="Username">
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                  <input
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    placeholder="admin-handle"
                    required
                    autoFocus
                    className="g-input pl-9"
                  />
                </div>
              </Field>

              <Field label="Email">
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                  <input
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    placeholder="admin@yourcompany.com"
                    required
                    className="g-input pl-9"
                  />
                </div>
              </Field>

              <Field label="Password">
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                  <input
                    type={showPass ? 'text' : 'password'}
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    placeholder="Min 8 characters"
                    required
                    minLength={8}
                    className="g-input pl-9 pr-10"
                  />
                  <button type="button" onClick={() => setShowPass(p => !p)}
                    className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-3)' }}>
                    {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </Field>

              <Field label="Confirm password">
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                  <input
                    type={showConf ? 'text' : 'password'}
                    value={confirm}
                    onChange={e => setConfirm(e.target.value)}
                    placeholder="Re-enter password"
                    required
                    className="g-input pl-9 pr-10"
                  />
                  <button type="button" onClick={() => setShowConf(p => !p)}
                    className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-3)' }}>
                    {showConf ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </Field>

              {error && <ErrMsg msg={error} />}

              <button type="submit" disabled={loading}
                className="g-btn g-btn-primary w-full justify-center py-2.5 text-sm font-semibold mt-1">
                {loading ? (
                  <span className="flex items-center gap-2">
                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Creating organization…
                  </span>
                ) : (
                  <><ShieldCheck className="h-4 w-4" /> Create Organization</>
                )}
              </button>

              <button type="button" onClick={() => { setStep(1); setError(''); }}
                className="w-full text-xs flex items-center justify-center gap-1"
                style={{ color: 'var(--text-3)' }}>
                <ArrowLeft className="h-3 w-3" /> Back
              </button>
            </form>
          )}

          <p className="mt-5 text-center text-[11px]" style={{ color: 'var(--text-3)' }}>
            XCloak Security Suite · Enterprise Edition
          </p>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-2)' }}>{label}</label>
      {children}
    </div>
  );
}

function ErrMsg({ msg }: { msg: string }) {
  return (
    <div className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm"
      style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
      <AlertCircle className="h-4 w-4 shrink-0" /> {msg}
    </div>
  );
}
