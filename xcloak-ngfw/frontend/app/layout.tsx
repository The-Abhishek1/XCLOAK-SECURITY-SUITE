import type { Metadata } from 'next';
import './globals.css';
import { ThemeProvider } from '@/context/ThemeContext';
import { NotificationProvider } from '@/context/NotificationContext';
import { UserProvider } from '@/context/UserContext';
import DemoBanner from '@/components/DemoBanner';
import Tour from '@/components/Tour';

export const metadata: Metadata = {
  title: 'XCloak Security Suite',
  description: 'Enterprise Security Operations Platform',
};

// Runs before React hydrates / before first paint, so the correct theme
// is applied immediately — no flash of the wrong theme on refresh.
const THEME_INIT_SCRIPT = `
(function() {
  try {
    var saved = localStorage.getItem('xcloak-theme');
    var theme = saved === 'dark' || saved === 'light' ? saved : 'light';
    document.documentElement.setAttribute('data-theme', theme);
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
})();
`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="light" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body>
        <ThemeProvider>
          <NotificationProvider>
            <UserProvider>
              <DemoBanner />
              <Tour />
              {children}
            </UserProvider>
          </NotificationProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
