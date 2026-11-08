"use client";

import {
  createContext,
  ReactNode,
  useContext,
  useEffect,
  useRef,
  useState
} from "react";

import {
  AuthToken,
  fetchCurrentUser,
  logoutUser,
  rememberAccountSession,
  UserPublic
} from "@/lib/api";

type AuthContextValue = {
  currentUser: UserPublic | null;
  isLoading: boolean;
  clearSession: () => Promise<void>;
  sessionError: string | null;
  setAuthenticatedSession: (authToken: AuthToken) => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const authVersion = useRef(0);
  const [currentUser, setCurrentUser] = useState<UserPublic | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [sessionError, setSessionError] = useState<string | null>(null);

  useEffect(() => {
    const initialVersion = authVersion.current;
    let active = true;
    async function loadStoredSession() {
      try {
        const user = await fetchCurrentUser();
        if (active && authVersion.current === initialVersion) setCurrentUser(user);
      } catch {
        if (active && authVersion.current === initialVersion) setSessionError("Session could not be checked. Retry when the service is available.");
      } finally {
        if (active) setIsLoading(false);
      }
    }

    const expired = () => {
      authVersion.current += 1;
      setCurrentUser(null);
      setSessionError("Your session expired. Log in again to access account history.");
    };
    window.addEventListener("sentinel:session-expired", expired);
    loadStoredSession();
    return () => { active = false; window.removeEventListener("sentinel:session-expired", expired); };
  }, []);

  async function clearSession() {
    try {
      await logoutUser();
      authVersion.current += 1;
      setCurrentUser(null);
      setSessionError(null);
    } catch {
      setSessionError("Logout could not be confirmed. Please retry.");
    }
  }

  function setAuthenticatedSession(authToken: AuthToken) {
    authVersion.current += 1;
    rememberAccountSession(authToken);
    setSessionError(null);
    setCurrentUser(authToken.user);
  }

  return (
    <AuthContext.Provider
      value={{
        currentUser,
        isLoading,
        sessionError,
        clearSession,
        setAuthenticatedSession
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuthSession() {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuthSession must be used within the AuthProvider.");
  }

  return context;
}
