'use client';

import { createContext, useContext, useEffect, useState } from 'react';
import api from '@/lib/api';
import { UserProfile } from '@/types';

interface UserCtx {
  profile: UserProfile | null;
  reload: () => void;
}

const Ctx = createContext<UserCtx>({ profile: null, reload: () => {} });

export function UserProvider({ children }: { children: React.ReactNode }) {
  const [profile, setProfile] = useState<UserProfile | null>(null);

  const reload = () => {
    api.get('/auth/profile')
      .then(r => setProfile(r.data))
      .catch(() => setProfile(null));
  };

  useEffect(() => { reload(); }, []);

  return <Ctx.Provider value={{ profile, reload }}>{children}</Ctx.Provider>;
}

export const useUser = () => useContext(Ctx);
