const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ??
  (typeof window === "undefined" ? "http://127.0.0.1:8000" : `http://${window.location.hostname}:8000`);

export type ScanInputType = "url" | "email" | "message";
export type RiskLevel = "Low" | "Medium" | "High";
export type FeedbackLabel = "Correct" | "False Positive" | "False Negative";
export type ScanFeedbackStatus = "pending" | "reviewed";

export type HealthStatus = {
  status: string;
};

export type ScanRequest = {
  input_type: ScanInputType;
  raw_content: string;
  save_scan?: boolean;
  retention_days?: number | null;
};

export type ScanFinding = {
  category: string;
  severity: RiskLevel;
  message: string;
  matched_text: string | null;
};

export type ScanResult = {
  id: number;
  input_type: ScanInputType;
  raw_content: string;
  risk_score: number;
  confidence_score: number;
  risk_level: RiskLevel;
  summary: string;
  recommendation: string;
  detected_categories: string[];
  findings: string[];
  finding_details: ScanFinding[];
  feedback: FeedbackLabel | null;
  feedback_note: string | null;
  is_saved: boolean;
  expires_at: string | null;
  created_at: string;
};

export type CategoryCount = {
  name: string;
  count: number;
};

export type InputTypeCount = {
  input_type: ScanInputType;
  count: number;
};

export type FeedbackCount = {
  label: FeedbackLabel;
  count: number;
};

export type ScanAnalyticsComparison = {
  previous_total_scans: number;
  previous_high_risk_count: number;
  previous_average_risk_score: number;
  scan_volume_change: number;
  high_risk_change: number;
  average_risk_score_change: number;
};

export type ScanAnalyticsSummary = {
  total_scans: number;
  high_risk_count: number;
  medium_risk_count: number;
  low_risk_count: number;
  feedback_count: number;
  needs_review_count: number;
  high_risk_needing_feedback_count: number;
  average_risk_score: number;
  average_confidence_score: number;
  latest_high_risk_created_at: string | null;
  input_type_counts: InputTypeCount[];
  feedback_breakdown: FeedbackCount[];
  common_categories: CategoryCount[];
  comparison: ScanAnalyticsComparison | null;
};

export type UserPublic = {
  id: number;
  username: string;
  email: string;
  created_at: string;
};

export type RegisterRequest = {
  username: string;
  email: string;
  password: string;
};

export type LoginRequest = {
  login: string;
  password: string;
};

export type AuthToken = {
  token_type: "cookie";
  user: UserPublic;
  csrf_token: string;
  expires_at: number;
};

export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message); }
}

let accountSession: Promise<AuthToken | null> | null = null;

export function rememberAccountSession(session: AuthToken): void {
  accountSession = Promise.resolve(session);
}

async function ensureAccountSession(): Promise<AuthToken | null> {
  if (!accountSession) {
    accountSession = fetch(`${API_BASE_URL}/auth/session`, {credentials: "include"})
      .then(async response => {
        if (response.status === 401) return null;
        if (!response.ok) throw new ApiError("Unable to restore account session.", response.status);
        return await response.json() as AuthToken;
      }).catch(error => { accountSession = null; throw error; });
  }
  return accountSession;
}

export async function logoutUser(): Promise<void> {
  const session = await ensureAccountSession();
  if (session) {
    const response = await apiFetch(`${API_BASE_URL}/auth/logout`, {
      method: "POST", headers: {"X-CSRF-Token": session.csrf_token}
    });
    if (!response.ok && response.status !== 401) {
      throw new ApiError(await readApiError(response, "Logout failed; please retry."), response.status);
    }
  }
  accountSession = Promise.resolve(null);
}

type AnonymousSession = { csrf_token: string; expires_at: number };
let anonymousSession: Promise<AnonymousSession> | null = null;

async function ensureAnonymousSession(): Promise<AnonymousSession> {
  if (!anonymousSession) {
    anonymousSession = fetch(`${API_BASE_URL}/auth/anonymous-session`, {
      method: "POST", credentials: "include"
    }).then(async response => {
      if (!response.ok) throw new Error(await readApiError(response, "Unable to establish anonymous session."));
      return (await response.json()) as AnonymousSession;
    }).catch(error => { anonymousSession = null; throw error; });
  }
  return anonymousSession;
}

async function apiFetch(input: string, options: RequestInit = {}): Promise<Response> {
  const response = await fetch(input, { ...options, credentials: "include" });
  const headers = new Headers(options.headers);
  if (!headers.has("Authorization") && (response.status === 401 || response.status === 403)) {
    const error = await response.clone().json().catch(() => null) as {detail?: string} | null;
    if (response.status === 401 && error?.detail === "Invalid or expired authentication token.") {
      accountSession = Promise.resolve(null);
      if (typeof window !== "undefined") window.dispatchEvent(new Event("sentinel:session-expired"));
    }
    if (error?.detail === "Anonymous session is missing or expired." || error?.detail === "CSRF validation failed.") {
      // Refresh the matching CSRF state after another tab changes a cookie.
      // An account failure must never replay a mutation under guest ownership.
      const account = accountSession ? await accountSession : null;
      if (account) {
        accountSession = null;
        const restored = await ensureAccountSession();
        if (!restored) {
          if (typeof window !== "undefined") window.dispatchEvent(new Event("sentinel:session-expired"));
          return response;
        }
        headers.set("X-CSRF-Token", restored.csrf_token);
      } else {
        anonymousSession = null;
        const session = await ensureAnonymousSession();
        headers.set("X-CSRF-Token", session.csrf_token);
      }
      return fetch(input, { ...options, headers, credentials: "include" });
    }
  }
  return response;
}

export async function fetchHealthStatus(): Promise<HealthStatus> {
  const response = await apiFetch(`${API_BASE_URL}/health`);

  if (!response.ok) {
    throw new Error("Failed to fetch backend health status.");
  }

  return (await response.json()) as HealthStatus;
}

export async function registerUser(
  payload: RegisterRequest
): Promise<UserPublic> {
  const response = await apiFetch(`${API_BASE_URL}/auth/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(await readApiError(response, "Failed to create account."));
  }

  return (await response.json()) as UserPublic;
}

export async function loginUser(payload: LoginRequest): Promise<AuthToken> {
  const response = await apiFetch(`${API_BASE_URL}/auth/login?transport=cookie`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(await readApiError(response, "Failed to log in."));
  }

  const session = await response.json() as AuthToken;
  rememberAccountSession(session);
  return session;
}

export async function fetchCurrentUser(): Promise<UserPublic | null> {
  // Old localStorage JWTs are never read or sent. The approved transition
  // requires re-login; account credentials/data are unchanged.
  const session = await ensureAccountSession();
  return session?.user ?? null;
}

export async function createScan(payload: ScanRequest): Promise<ScanResult> {
  const response = await apiFetch(`${API_BASE_URL}/scans`, {
    method: "POST",
    headers: await buildApiHeaders({ includeJson: true }),
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error("Failed to analyze the submitted content.");
  }

  return (await response.json()) as ScanResult;
}

export async function fetchScanHistory(options?: {
  limit?: number;
  days?: number | null;
  risk_level?: RiskLevel | null;
  feedback_status?: ScanFeedbackStatus | null;
}): Promise<ScanResult[]> {
  const query = new URLSearchParams();

  if (options?.limit) {
    query.set("limit", String(options.limit));
  }

  if (options?.days) {
    query.set("days", String(options.days));
  }

  if (options?.risk_level) {
    query.set("risk_level", options.risk_level);
  }

  if (options?.feedback_status) {
    query.set("feedback_status", options.feedback_status);
  }

  const queryString = query.toString();
  const response = await apiFetch(
    `${API_BASE_URL}/scans${queryString ? `?${queryString}` : ""}`,
    {
      headers: await buildApiHeaders()
    }
  );

  if (!response.ok) {
    throw new Error("Failed to fetch scan history.");
  }

  return (await response.json()) as ScanResult[];
}

export async function fetchScanAnalyticsSummary(
  options?: {
    limit?: number;
    days?: number | null;
    risk_level?: RiskLevel | null;
    feedback_status?: ScanFeedbackStatus | null;
  }
): Promise<ScanAnalyticsSummary> {
  const query = new URLSearchParams();

  if (options?.limit) {
    query.set("limit", String(options.limit));
  }

  if (options?.days) {
    query.set("days", String(options.days));
  }

  if (options?.risk_level) {
    query.set("risk_level", options.risk_level);
  }

  if (options?.feedback_status) {
    query.set("feedback_status", options.feedback_status);
  }

  const queryString = query.toString();
  const response = await apiFetch(
    `${API_BASE_URL}/scans/analytics/summary${queryString ? `?${queryString}` : ""}`,
    {
      headers: await buildApiHeaders()
    }
  );

  if (!response.ok) {
    throw new Error("Failed to fetch scan analytics.");
  }

  return (await response.json()) as ScanAnalyticsSummary;
}

export async function fetchScanById(scanId: string): Promise<ScanResult> {
  const response = await apiFetch(`${API_BASE_URL}/scans/${scanId}`, {
    headers: await buildApiHeaders()
  });

  if (!response.ok) {
    throw new Error(await readApiError(response, "Failed to fetch scan details."));
  }

  return (await response.json()) as ScanResult;
}

export async function submitScanFeedback(
  scanId: number,
  feedback: FeedbackLabel,
  feedbackNote?: string
): Promise<ScanResult> {
  const response = await apiFetch(`${API_BASE_URL}/scans/${scanId}/feedback`, {
    method: "POST",
    headers: await buildApiHeaders({ includeJson: true }),
    body: JSON.stringify({
      feedback,
      feedback_note: feedbackNote?.trim() || null
    })
  });

  if (!response.ok) {
    throw new Error("Failed to submit scan feedback.");
  }

  return (await response.json()) as ScanResult;
}

export async function updateScanStorage(
  scanId: number,
  saveScan: boolean,
  retentionDays?: number
): Promise<ScanResult> {
  const response = await apiFetch(`${API_BASE_URL}/scans/${scanId}/storage`, {
    method: "PATCH",
    headers: await buildApiHeaders({ includeJson: true }),
    body: JSON.stringify({
      save_scan: saveScan,
      retention_days: saveScan ? null : retentionDays ?? 7
    })
  });

  if (!response.ok) {
    throw new Error(await readApiError(response, "Failed to update scan storage."));
  }

  return (await response.json()) as ScanResult;
}

export async function deleteScan(scanId: number): Promise<void> {
  const response = await apiFetch(`${API_BASE_URL}/scans/${scanId}`, {
    method: "DELETE",
    headers: await buildApiHeaders()
  });

  if (!response.ok) {
    throw new Error(await readApiError(response, "Failed to delete scan."));
  }
}

async function buildApiHeaders(options?: { includeJson?: boolean }): Promise<HeadersInit> {
  const headers: Record<string, string> = {};
  const account = await ensureAccountSession();
  if (options?.includeJson) headers["Content-Type"] = "application/json";
  if (account) {
    headers["X-CSRF-Token"] = account.csrf_token;
  } else {
    const session = await ensureAnonymousSession();
    headers["X-CSRF-Token"] = session.csrf_token;
  }
  return headers;
}

async function readApiError(
  response: Response,
  fallbackMessage: string
): Promise<string> {
  try {
    const payload = (await response.json()) as { detail?: unknown };
    if (typeof payload.detail === "string") {
      return payload.detail;
    }
  } catch {
    return fallbackMessage;
  }

  return fallbackMessage;
}
