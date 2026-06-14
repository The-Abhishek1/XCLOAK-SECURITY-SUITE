'use client';

import { useEffect, useRef, useState } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { aiAPI } from '@/lib/api';
import { Bot, Send, Trash2, Loader2, User, Sparkles, Zap, Bug, Shield } from 'lucide-react';
import { timeAgo } from '@/lib/utils';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

const QUICK_PROMPTS = [
  { icon: Shield,   label: 'Security posture',  msg: 'Give me a summary of the current security posture of the platform.' },
  { icon: Zap,      label: 'Critical alerts',   msg: 'What are the most critical alerts right now and what should I do first?' },
  { icon: Bug,      label: 'Vulnerabilities',   msg: 'Which agents have the most critical vulnerabilities and what is the recommended remediation?' },
  { icon: Sparkles, label: 'Incident briefing', msg: 'Summarize all open incidents and their current status.' },
];

// Lightweight markdown renderer — no external deps.
// Handles: **bold**, *italic*, `code`, - bullets, numbered lists, blank line paragraphs.
function renderMarkdown(text: string): JSX.Element {
  const lines = text.split('\n');
  const elements: JSX.Element[] = [];
  let i = 0;

  const renderInline = (str: string): JSX.Element => {
    const parts = str.split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g);
    return (
      <>
        {parts.map((part, idx) => {
          if (part.startsWith('**') && part.endsWith('**'))
            return <strong key={idx} style={{ color: 'var(--text-1)', fontWeight: 600 }}>{part.slice(2, -2)}</strong>;
          if (part.startsWith('*') && part.endsWith('*'))
            return <em key={idx}>{part.slice(1, -1)}</em>;
          if (part.startsWith('`') && part.endsWith('`'))
            return <code key={idx} className="mono rounded px-1 py-0.5 text-[10px]"
              style={{ background: 'var(--bg-0)', color: 'var(--accent)', border: '1px solid var(--border)' }}>
              {part.slice(1, -1)}
            </code>;
          return <span key={idx}>{part}</span>;
        })}
      </>
    );
  };

  while (i < lines.length) {
    const line = lines[i];

    // Blank line
    if (line.trim() === '') {
      elements.push(<div key={i} className="h-2" />);
      i++;
      continue;
    }

    // Unordered list
    if (/^[-*•]\s/.test(line.trim())) {
      const listItems: JSX.Element[] = [];
      while (i < lines.length && /^[-*•]\s/.test(lines[i].trim())) {
        listItems.push(
          <li key={i} className="flex items-start gap-2 text-xs leading-relaxed"
            style={{ color: 'var(--text-1)' }}>
            <span className="mt-1.5 h-1.5 w-1.5 rounded-full shrink-0" style={{ background: 'var(--accent)' }} />
            <span>{renderInline(lines[i].trim().replace(/^[-*•]\s/, ''))}</span>
          </li>
        );
        i++;
      }
      elements.push(<ul key={`ul-${i}`} className="space-y-1 my-1">{listItems}</ul>);
      continue;
    }

    // Numbered list
    if (/^\d+\.\s/.test(line.trim())) {
      const listItems: JSX.Element[] = [];
      let num = 1;
      while (i < lines.length && /^\d+\.\s/.test(lines[i].trim())) {
        listItems.push(
          <li key={i} className="flex items-start gap-2 text-xs leading-relaxed"
            style={{ color: 'var(--text-1)' }}>
            <span className="shrink-0 font-bold text-[10px] mt-0.5" style={{ color: 'var(--accent)', minWidth: 16 }}>
              {num++}.
            </span>
            <span>{renderInline(lines[i].trim().replace(/^\d+\.\s/, ''))}</span>
          </li>
        );
        i++;
      }
      elements.push(<ol key={`ol-${i}`} className="space-y-1 my-1">{listItems}</ol>);
      continue;
    }

    // Heading (### or ##)
    if (/^#{1,3}\s/.test(line)) {
      const level = line.match(/^(#{1,3})/)?.[1].length || 1;
      const text  = line.replace(/^#{1,3}\s/, '');
      elements.push(
        <p key={i} className={`font-semibold leading-snug ${level === 1 ? 'text-sm mt-2' : 'text-xs mt-1.5'}`}
          style={{ color: 'var(--text-1)' }}>
          {renderInline(text)}
        </p>
      );
      i++;
      continue;
    }

    // Normal paragraph line
    elements.push(
      <p key={i} className="text-xs leading-relaxed" style={{ color: 'var(--text-1)' }}>
        {renderInline(line)}
      </p>
    );
    i++;
  }

  return <div className="space-y-0.5">{elements}</div>;
}

export default function AIAssistantPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput]       = useState('');
  const [loading, setLoading]   = useState(false);
  const [histLoading, setHistLoading] = useState(true);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => { loadHistory(); }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const loadHistory = async () => {
    setHistLoading(true);
    try {
      const r = await aiAPI.getChatHistory();
      setMessages(r.data?.history || []);
    } catch {
      // history endpoint failed — start fresh
      setMessages([]);
    } finally {
      setHistLoading(false);
    }
  };

  const send = async (msg = input) => {
    if (!msg.trim() || loading) return;
    setInput('');
    setLoading(true);

    const userMsg: ChatMessage = {
      role: 'user',
      content: msg,
      timestamp: new Date().toISOString(),
    };

    // Optimistically show user message immediately
    setMessages(prev => [...prev, userMsg]);

    try {
      // Send current history + new message. Use the state at call time.
      const r = await aiAPI.chat(msg, messages);
      const updated = r.data?.history;
      if (updated && updated.length > 0) {
        setMessages(updated);
      } else {
        // Fallback: append a generic response
        setMessages(prev => [...prev, {
          role: 'assistant' as const,
          content: r.data?.response || 'No response received.',
          timestamp: new Date().toISOString(),
        }]);
      }
    } catch {
      setMessages(prev => [...prev, {
        role: 'assistant' as const,
        content: 'Connection failed. Make sure the backend is running and `OLLAMA_URL` / `ANTHROPIC_API_KEY` is set in your `.env`.',
        timestamp: new Date().toISOString(),
      }]);
    } finally {
      setLoading(false);
    }
  };

  const clear = async () => {
    await aiAPI.clearChatHistory().catch(() => {});
    setMessages([]);
  };

  return (
    <RootLayout title="XCloak AI" subtitle="Security operations assistant">
      <div className="flex flex-col gap-3" style={{ height: 'calc(100vh - 120px)' }}>

        {/* Quick prompts — shown only when no messages */}
        {messages.length === 0 && !histLoading && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Bot className="h-5 w-5" style={{ color: 'var(--accent)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>XCloak AI Assistant</p>
            </div>
            <p className="text-xs mb-4" style={{ color: 'var(--text-3)' }}>
              Ask me anything about your platform's security posture. I have real-time access to agents, alerts, incidents, and vulnerabilities.
            </p>
            <div className="grid grid-cols-2 gap-2">
              {QUICK_PROMPTS.map(q => {
                const Icon = q.icon;
                return (
                  <button key={q.label} onClick={() => send(q.msg)}
                    className="flex items-start gap-2.5 rounded-xl p-3 text-left transition-all"
                    style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = 'var(--accent-border)'; (e.currentTarget as HTMLElement).style.background = 'var(--accent-glow)'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'; (e.currentTarget as HTMLElement).style.background = 'var(--glass-bg)'; }}>
                    <Icon className="h-3.5 w-3.5 mt-0.5 shrink-0" style={{ color: 'var(--accent)' }} />
                    <span className="text-xs" style={{ color: 'var(--text-2)' }}>{q.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Messages */}
        <div className="flex-1 overflow-y-auto space-y-4 pr-1">
          {histLoading ? (
            <div className="flex items-center justify-center h-32">
              <Loader2 className="h-5 w-5 animate-spin" style={{ color: 'var(--text-3)' }} />
            </div>
          ) : messages.map((m, i) => (
            <div key={i} className={`flex gap-3 ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
              {/* Avatar */}
              <div className="h-7 w-7 rounded-xl flex items-center justify-center shrink-0 mt-1"
                style={{
                  background: m.role === 'assistant' ? 'var(--accent-glow)' : 'var(--glass-bg)',
                  border: `1px solid ${m.role === 'assistant' ? 'var(--accent-border)' : 'var(--border)'}`,
                }}>
                {m.role === 'assistant'
                  ? <Bot className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
                  : <User className="h-3.5 w-3.5" style={{ color: 'var(--text-2)' }} />}
              </div>

              {/* Bubble */}
              <div className={`flex-1 max-w-[85%] flex flex-col ${m.role === 'user' ? 'items-end' : 'items-start'}`}>
                <div className="rounded-2xl px-4 py-3"
                  style={{
                    background: m.role === 'assistant' ? 'var(--glass-bg)' : 'var(--accent)',
                    border: m.role === 'assistant' ? '1px solid var(--border)' : 'none',
                  }}>
                  {m.role === 'assistant' ? (
                    renderMarkdown(m.content)
                  ) : (
                    <p className="text-xs leading-relaxed" style={{ color: '#fff' }}>{m.content}</p>
                  )}
                </div>
                <p className="text-[10px] mt-1 px-1" style={{ color: 'var(--text-3)' }}>
                  {m.timestamp ? timeAgo(m.timestamp) : ''}
                </p>
              </div>
            </div>
          ))}

          {/* Typing indicator */}
          {loading && (
            <div className="flex gap-3">
              <div className="h-7 w-7 rounded-xl flex items-center justify-center shrink-0 mt-1"
                style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent-border)' }}>
                <Bot className="h-3.5 w-3.5" style={{ color: 'var(--accent)' }} />
              </div>
              <div className="rounded-2xl px-4 py-3" style={{ background: 'var(--glass-bg)', border: '1px solid var(--border)' }}>
                <div className="flex gap-1 items-center">
                  {[0, 1, 2].map(i => (
                    <span key={i} className="h-1.5 w-1.5 rounded-full animate-bounce"
                      style={{ background: 'var(--accent)', animationDelay: `${i * 150}ms` }} />
                  ))}
                  <span className="text-[10px] ml-2" style={{ color: 'var(--text-3)' }}>Thinking…</span>
                </div>
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        {/* Input bar */}
        <div className="flex items-center gap-2 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
          {messages.length > 0 && (
            <button onClick={clear}
              className="p-2 rounded-xl shrink-0 transition-colors"
              style={{ color: 'var(--text-3)', background: 'var(--glass-bg)', border: '1px solid var(--border)' }}
              title="Clear chat"
              onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--red)'}
              onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-3)'}>
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
          <div className="flex flex-1 gap-2">
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !e.shiftKey && send()}
              placeholder="Ask about alerts, incidents, vulnerabilities…"
              className="g-input flex-1"
              disabled={loading}
            />
            <button
              onClick={() => send()}
              disabled={loading || !input.trim()}
              className="g-btn g-btn-primary shrink-0"
              style={{ padding: '0 14px' }}>
              {loading
                ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                : <Send className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>
      </div>
    </RootLayout>
  );
}
