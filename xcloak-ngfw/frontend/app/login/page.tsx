'use client';

import { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldCheck, Eye, EyeOff, Lock, User, AlertCircle, Mail, UserPlus, KeyRound, ArrowLeft, Building2, Loader2 } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';
import { Sun, Moon } from 'lucide-react';
import { ssoAPI } from '@/lib/api';

type Tab = 'login' | 'register' | 'forgot';

export default function LoginPage() {
  return (
    <Suspense>
      <LoginContent />
    </Suspense>
  );
}

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { theme, toggle } = useTheme();
  const [tab, setTab]           = useState<Tab>('login');
  const [showPass, setShowPass]  = useState(false);
  const [error, setError]        = useState(searchParams.get('sso_error') || '');
  const [success, setSuccess]    = useState('');
  const [loading, setLoading]    = useState(false);
  const [showSSO, setShowSSO]       = useState(false);
  const [ssoOrg, setSsoOrg]         = useState('');
  const [ssoEmail, setSsoEmail]     = useState('');
  const [ssoDiscovering, setSsoDiscovering] = useState(false);
  const [ssoDiscovered, setSsoDiscovered]   = useState<{ slug: string; tenant_name: string; button_label: string } | null>(null);

  // Login form
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  // Register form
  const [regForm, setRegForm]     = useState({ username: '', email: '', password: '' });
  // Forgot password
  const [forgotEmail, setForgotEmail] = useState('');

  // 2FA state
  const [needs2FA, setNeeds2FA]   = useState(false);
  const [tempToken, setTempToken] = useState('');
  const [totpCode, setTotpCode]   = useState('');

  useEffect(() => {
    const loggedIn = document.cookie.split(';').some(c => c.trim().startsWith('logged_in='));
    if (loggedIn) router.push('/dashboard');
  }, [router]);

  const startSSO = (e: React.FormEvent) => {
    e.preventDefault();
    const slug = ssoDiscovered?.slug || ssoOrg;
    if (!slug) return;
    window.location.href = `/api/auth/oidc/start?tenant=${encodeURIComponent(slug)}`;
  };

  const discoverSSO = async () => {
    if (!ssoEmail.includes('@')) return;
    setSsoDiscovering(true);
    setSsoDiscovered(null);
    setError('');
    try {
      const r = await ssoAPI.discover(ssoEmail);
      setSsoDiscovered(r.data);
    } catch {
      setSsoDiscovered(null);
      setError('No SSO configured for this email domain. Enter your organization slug below.');
    } finally { setSsoDiscovering(false); }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true); setError('');
    try {
      const res  = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginForm),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Login failed');

      if (data.needs_2fa) {
        setTempToken(data.temp_token);
        setNeeds2FA(true);
        return;
      }

      if (!data.ok) throw new Error('Login failed');
      window.location.href = '/dashboard';
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleTOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true); setError('');
    try {
      const res  = await fetch('/api/auth/login/2fa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ temp_token: tempToken, code: totpCode }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Invalid code');
      window.location.href = '/dashboard';
    } catch (err: any) {
      setError(err.message);
      setTotpCode('');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true); setError(''); setSuccess('');
    try {
      const res  = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(regForm),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Registration failed');
      setSuccess('Account created! You can now sign in.');
      setTab('login');
      setLoginForm(f => ({ ...f, username: regForm.username }));
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleForgot = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true); setError(''); setSuccess('');
    try {
      await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: forgotEmail }),
      });
      // Always show success — prevent email enumeration
      setSuccess('If an account with that email exists, you will receive a reset link shortly.');
    } catch {
      setSuccess('If an account with that email exists, you will receive a reset link shortly.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden"
      style={{ background: 'var(--bg-0)' }}>
      <div className="bg-mesh" />
      <div className="grid-bg fixed inset-0 z-0 opacity-20" />

      <div className="fixed z-0 pointer-events-none" style={{ top: '8%', left: '3%', width: 500, height: 500, borderRadius: '50%', background: 'radial-gradient(circle, rgba(34,211,238,0.07) 0%, transparent 70%)', filter: 'blur(40px)' }} />
      <div className="fixed z-0 pointer-events-none" style={{ bottom: '8%', right: '3%', width: 400, height: 400, borderRadius: '50%', background: 'radial-gradient(circle, rgba(14,165,233,0.05) 0%, transparent 70%)', filter: 'blur(40px)' }} />

      <button onClick={toggle} className="fixed top-4 right-4 z-20 flex h-9 w-9 items-center justify-center rounded-lg transition-colors"
        style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>
        {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      </button>

      <div className="relative z-10 w-full max-w-[420px] px-4">
        <div className="g-panel p-8">
          {/* Logo */}
          <div className="flex flex-col items-center mb-7">
            <div className="relative mb-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl"
                style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', boxShadow: '0 0 30px var(--accent-glow)' }}>
                <ShieldCheck className="h-7 w-7" style={{ color: 'var(--accent)' }} />
              </div>
            </div>
            <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-1)' }}>
              XCloak <span style={{ color: 'var(--accent)' }}>SOC</span>
            </h1>
            <p className="text-xs mt-1" style={{ color: 'var(--text-2)' }}>Enterprise Security Operations</p>
          </div>

          {/* ── 2FA step ── */}
          {needs2FA ? (
            <form onSubmit={handleTOTP} className="space-y-4">
              <div className="text-center mb-2">
                <KeyRound className="h-8 w-8 mx-auto mb-2" style={{ color: 'var(--accent)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Two-Factor Authentication</p>
                <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
                  Enter the 6-digit code from your authenticator app
                </p>
              </div>
              <input
                value={totpCode}
                onChange={e => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                maxLength={6}
                className="g-input w-full text-center text-2xl mono tracking-[0.5em] font-bold"
                autoFocus
              />
              {error && <ErrMsg msg={error} />}
              <SubmitBtn loading={loading} label="Verify Code" />
              <button type="button" onClick={() => { setNeeds2FA(false); setError(''); setTotpCode(''); }}
                className="w-full text-xs flex items-center justify-center gap-1 mt-1"
                style={{ color: 'var(--text-3)' }}>
                <ArrowLeft className="h-3 w-3" /> Back to login
              </button>
            </form>
          ) : tab === 'forgot' ? (
            /* ── Forgot password ── */
            <form onSubmit={handleForgot} className="space-y-4">
              <div className="text-center mb-2">
                <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>Reset Password</p>
                <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>
                  Enter your email and we&apos;ll send a reset link if the account exists.
                </p>
              </div>
              <Field label="Email address">
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                  <input type="email" value={forgotEmail} onChange={e => setForgotEmail(e.target.value)}
                    placeholder="your@email.com" required className="g-input pl-9" />
                </div>
              </Field>
              {error   && <ErrMsg msg={error} />}
              {success && <SuccessMsg msg={success} />}
              <SubmitBtn loading={loading} label="Send Reset Link" />
              <button type="button" onClick={() => { setTab('login'); setError(''); setSuccess(''); }}
                className="w-full text-xs flex items-center justify-center gap-1"
                style={{ color: 'var(--text-3)' }}>
                <ArrowLeft className="h-3 w-3" /> Back to login
              </button>
            </form>
          ) : (
            <>
              {/* Tab switcher */}
              <div className="flex gap-1 p-1 rounded-xl mb-6"
                style={{ background: 'var(--bg-0)', border: '1px solid var(--border)' }}>
                {(['login', 'register'] as Tab[]).map(t => (
                  <button key={t} onClick={() => { setTab(t); setError(''); setSuccess(''); }}
                    className="flex-1 flex items-center justify-center gap-1.5 rounded-lg py-2 text-xs font-medium capitalize transition-all"
                    style={{
                      background: tab === t ? 'var(--accent-glow)' : 'transparent',
                      color:      tab === t ? 'var(--accent)' : 'var(--text-2)',
                      border:     tab === t ? '1px solid var(--accent-border)' : '1px solid transparent',
                    }}>
                    {t === 'login' ? <User className="h-3.5 w-3.5" /> : <UserPlus className="h-3.5 w-3.5" />}
                    {t === 'login' ? 'Sign In' : 'Register'}
                  </button>
                ))}
              </div>

              {success && <SuccessMsg msg={success} />}

              {/* LOGIN */}
              {tab === 'login' && !showSSO && (
                <form onSubmit={handleLogin} className="space-y-4">
                  <Field label="Username">
                    <div className="relative">
                      <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                      <input value={loginForm.username} onChange={e => setLoginForm(f => ({ ...f, username: e.target.value }))}
                        placeholder="Username" required autoComplete="username" className="g-input pl-9" />
                    </div>
                  </Field>
                  <Field label="Password">
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                      <input type={showPass ? 'text' : 'password'}
                        value={loginForm.password} onChange={e => setLoginForm(f => ({ ...f, password: e.target.value }))}
                        placeholder="Password" required autoComplete="current-password" className="g-input pl-9 pr-10" />
                      <button type="button" onClick={() => setShowPass(p => !p)}
                        className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-3)' }}>
                        {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </Field>
                  {error && <ErrMsg msg={error} />}
                  <SubmitBtn loading={loading} label="Sign In" />
                  <button type="button" onClick={() => { setTab('forgot'); setError(''); setSuccess(''); }}
                    className="w-full text-xs text-center mt-1"
                    style={{ color: 'var(--accent)' }}>
                    Forgot password?
                  </button>
                  <button type="button" onClick={() => { setShowSSO(true); setError(''); }}
                    className="w-full text-xs text-center flex items-center justify-center gap-1.5"
                    style={{ color: 'var(--text-3)' }}>
                    <Building2 className="h-3 w-3" /> Sign in with SSO
                  </button>
                </form>
              )}

              {/* SSO */}
              {tab === 'login' && showSSO && (
                <form onSubmit={startSSO} className="space-y-4">
                  {ssoDiscovered ? (
                    <div className="text-center space-y-3">
                      <div className="rounded-xl p-4"
                        style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                        <Building2 className="h-6 w-6 mx-auto mb-2" style={{ color: 'var(--accent)' }} />
                        <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>
                          {ssoDiscovered.tenant_name}
                        </p>
                        <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                          SSO configured · organization found
                        </p>
                      </div>
                      <button type="submit" className="g-btn g-btn-primary w-full justify-center py-2.5 text-sm font-semibold">
                        {ssoDiscovered.button_label}
                      </button>
                      <button type="button" onClick={() => { setSsoDiscovered(null); setSsoEmail(''); setError(''); }}
                        className="w-full text-xs flex items-center justify-center gap-1"
                        style={{ color: 'var(--text-3)' }}>
                        <ArrowLeft className="h-3 w-3" /> Use a different email or org
                      </button>
                    </div>
                  ) : (
                    <>
                      <Field label="Work email">
                        <div className="flex gap-2">
                          <div className="relative flex-1">
                            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                            <input type="email" value={ssoEmail}
                              onChange={e => { setSsoEmail(e.target.value); setSsoDiscovered(null); }}
                              onBlur={() => ssoEmail.includes('@') && discoverSSO()}
                              placeholder="you@yourcompany.com" className="g-input pl-9 w-full"
                              autoFocus />
                          </div>
                          <button type="button" onClick={discoverSSO}
                            disabled={ssoDiscovering || !ssoEmail.includes('@')}
                            className="g-btn g-btn-ghost text-xs px-3 shrink-0">
                            {ssoDiscovering ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Detect'}
                          </button>
                        </div>
                        <p className="text-[10px] mt-1" style={{ color: 'var(--text-3)' }}>
                          We&apos;ll auto-detect your organization from your email domain.
                        </p>
                      </Field>
                      <Field label="Or enter organization slug manually">
                        <div className="relative">
                          <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                          <input value={ssoOrg} onChange={e => setSsoOrg(e.target.value)}
                            placeholder="your-org-slug" className="g-input pl-9 w-full" />
                        </div>
                      </Field>
                      {error && <ErrMsg msg={error} />}
                      <SubmitBtn loading={false} label="Continue with SSO" />
                    </>
                  )}
                  <button type="button" onClick={() => { setShowSSO(false); setError(''); setSsoDiscovered(null); setSsoEmail(''); }}
                    className="w-full text-xs flex items-center justify-center gap-1"
                    style={{ color: 'var(--text-3)' }}>
                    <ArrowLeft className="h-3 w-3" /> Back to password sign-in
                  </button>
                </form>
              )}

              {/* REGISTER */}
              {tab === 'register' && (
                <form onSubmit={handleRegister} className="space-y-4">
                  <div className="rounded-xl p-3 text-xs"
                    style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)', color: 'var(--accent)' }}>
                    The first account created gets admin access. All subsequent accounts are analyst-level.
                  </div>
                  <Field label="Username">
                    <div className="relative">
                      <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                      <input value={regForm.username} onChange={e => setRegForm(f => ({ ...f, username: e.target.value }))}
                        placeholder="Choose a username" required className="g-input pl-9" />
                    </div>
                  </Field>
                  <Field label="Email">
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                      <input type="email" value={regForm.email} onChange={e => setRegForm(f => ({ ...f, email: e.target.value }))}
                        placeholder="your@email.com" required className="g-input pl-9" />
                    </div>
                  </Field>
                  <Field label="Password">
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                      <input type={showPass ? 'text' : 'password'}
                        value={regForm.password} onChange={e => setRegForm(f => ({ ...f, password: e.target.value }))}
                        placeholder="Min 8 characters" required minLength={8} className="g-input pl-9 pr-10" />
                      <button type="button" onClick={() => setShowPass(p => !p)}
                        className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-3)' }}>
                        {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </Field>
                  {error && <ErrMsg msg={error} />}
                  <SubmitBtn loading={loading} label="Create Account" />
                </form>
              )}
            </>
          )}

          {/* Demo entry point */}
          <div className="mt-5 flex items-center gap-3">
            <div className="flex-1 h-px" style={{ background: 'var(--border)' }} />
            <span className="text-[10px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-3)' }}>or</span>
            <div className="flex-1 h-px" style={{ background: 'var(--border)' }} />
          </div>
          <a
            href="/demo"
            className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg border py-2 text-sm font-medium transition-colors hover:opacity-80"
            style={{ border: '1px solid var(--border)', color: 'var(--text-2)', background: 'var(--bg-2)' }}
          >
            <span>Try the live demo</span>
            <span className="rounded-full px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: 'var(--accent-glow)', color: 'var(--accent)' }}>
              No signup
            </span>
          </a>

          <p className="mt-4 text-center text-[11px]" style={{ color: 'var(--text-3)' }}>
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

function SuccessMsg({ msg }: { msg: string }) {
  return (
    <div className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm mb-4"
      style={{ background: 'var(--green-bg)', border: '1px solid var(--green-border)', color: 'var(--green)' }}>
      ✓ {msg}
    </div>
  );
}

function SubmitBtn({ loading, label }: { loading: boolean; label: string }) {
  return (
    <button type="submit" disabled={loading}
      className="g-btn g-btn-primary w-full justify-center py-2.5 text-sm font-semibold mt-1">
      {loading ? (
        <span className="flex items-center gap-2">
          <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Please wait…
        </span>
      ) : label}
    </button>
  );
}
