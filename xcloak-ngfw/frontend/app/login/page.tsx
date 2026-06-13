'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { ShieldCheck, Eye, EyeOff, Lock, User, AlertCircle, Mail, UserPlus } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';
import { Sun, Moon } from 'lucide-react';

type Tab = 'login' | 'register';

export default function LoginPage() {
  const router = useRouter();
  const { theme, toggle } = useTheme();
  const [tab, setTab]         = useState<Tab>('login');
  const [showPass, setShowPass] = useState(false);
  const [error, setError]     = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  // Login form
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  // Register form
  const [regForm, setRegForm] = useState({ username: '', email: '', password: '', role: 'admin' });

  useEffect(() => {
    if (localStorage.getItem('token')) router.push('/dashboard');
  }, [router]);

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
      if (!data.token) throw new Error('No token received');
      localStorage.setItem('token', data.token);
      localStorage.setItem('username', loginForm.username);
      document.cookie = `token=${data.token}; path=/; max-age=86400; SameSite=Lax`;
      window.location.href = '/dashboard';
    } catch (err: any) {
      setError(err.message);
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

  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden"
      style={{ background: 'var(--bg-0)' }}>
      <div className="bg-mesh" />
      <div className="grid-bg fixed inset-0 z-0 opacity-20" />

      {/* Glow blobs */}
      <div className="fixed z-0 pointer-events-none" style={{ top: '8%', left: '3%', width: 500, height: 500, borderRadius: '50%', background: 'radial-gradient(circle, rgba(34,211,238,0.07) 0%, transparent 70%)', filter: 'blur(40px)' }} />
      <div className="fixed z-0 pointer-events-none" style={{ bottom: '8%', right: '3%', width: 400, height: 400, borderRadius: '50%', background: 'radial-gradient(circle, rgba(14,165,233,0.05) 0%, transparent 70%)', filter: 'blur(40px)' }} />

      {/* Theme toggle */}
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

          {/* Success msg */}
          {success && (
            <div className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm mb-4"
              style={{ background: 'var(--green-bg)', border: '1px solid var(--green-border)', color: 'var(--green)' }}>
              ✓ {success}
            </div>
          )}

          {/* LOGIN form */}
          {tab === 'login' && (
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
            </form>
          )}

          {/* REGISTER form */}
          {tab === 'register' && (
            <form onSubmit={handleRegister} className="space-y-4">
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
                    placeholder="admin@xcloak.local" required className="g-input pl-9" />
                </div>
              </Field>
              <Field label="Password">
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-3)' }} />
                  <input type={showPass ? 'text' : 'password'}
                    value={regForm.password} onChange={e => setRegForm(f => ({ ...f, password: e.target.value }))}
                    placeholder="Password@123" required className="g-input pl-9 pr-10" />
                  <button type="button" onClick={() => setShowPass(p => !p)}
                    className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-3)' }}>
                    {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </Field>
              <Field label="Role">
                <select value={regForm.role} onChange={e => setRegForm(f => ({ ...f, role: e.target.value }))} className="g-select">
                  <option value="admin">Admin</option>
                  <option value="analyst">Analyst</option>
                </select>
              </Field>
              {error && <ErrMsg msg={error} />}
              <SubmitBtn loading={loading} label="Create Account" />
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
          {loading ? 'Please wait…' : label}
        </span>
      ) : label}
    </button>
  );
}
