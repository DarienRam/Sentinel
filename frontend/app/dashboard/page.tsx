"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { SiteHeader } from "@/components/site-header";
import { useAuthSession } from "@/components/auth-provider";
import {
  fetchScanAnalyticsSummary,
  fetchScanHistory,
  RiskLevel,
  ScanFeedbackStatus,
  ScanAnalyticsSummary,
  ScanResult
} from "@/lib/api";
import styles from "../route-shell.module.css";
import dashboardStyles from "./page.module.css";

const SCAN_HISTORY_LIMIT_OPTIONS = [5, 10, 15, 20, 25] as const;
const TIME_WINDOW_OPTIONS = [
  { label: "All time", days: null },
  { label: "Last 7 days", days: 7 },
  { label: "Last 14 days", days: 14 },
  { label: "Last 30 days", days: 30 },
  { label: "Last year", days: 365 }
] as const;
const RISK_FILTER_OPTIONS = [
  { label: "All risk levels", value: "all" },
  { label: "High risk only", value: "High" },
  { label: "Medium risk only", value: "Medium" },
  { label: "Low risk only", value: "Low" }
] as const;
const FEEDBACK_FILTER_OPTIONS = [
  { label: "All review states", value: "all" },
  { label: "Pending review", value: "pending" },
  { label: "Reviewed only", value: "reviewed" }
] as const;
const DASHBOARD_PREFERENCES_KEY = "sentinel.dashboardPreferences";

function getStoredDashboardPreferences() {
  if (typeof window === "undefined") {
    return null;
  }

  const storedPreferences = window.sessionStorage.getItem(
    DASHBOARD_PREFERENCES_KEY
  );

  if (!storedPreferences) {
    return null;
  }

  try {
    return JSON.parse(storedPreferences) as {
      historyLimit?: number;
      historyDays?: number | null;
      riskFilter?: RiskLevel | null;
      feedbackFilter?: ScanFeedbackStatus | null;
    };
  } catch {
    window.sessionStorage.removeItem(DASHBOARD_PREFERENCES_KEY);
    return null;
  }
}

export default function DashboardPage() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [analytics, setAnalytics] = useState<ScanAnalyticsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [historyLimit, setHistoryLimit] = useState<number>(5);
  const [historyDays, setHistoryDays] = useState<number | null>(null);
  const [riskFilter, setRiskFilter] = useState<RiskLevel | null>(null);
  const [feedbackFilter, setFeedbackFilter] = useState<ScanFeedbackStatus | null>(null);
  const [hasLoadedPreferences, setHasLoadedPreferences] = useState(false);
  const { currentUser } = useAuthSession();

  useEffect(() => {
    const storedPreferences = getStoredDashboardPreferences();
    if (storedPreferences) {
      setHistoryLimit(storedPreferences.historyLimit ?? 5);
      setHistoryDays(storedPreferences.historyDays ?? null);
      setRiskFilter(storedPreferences.riskFilter ?? null);
      setFeedbackFilter(storedPreferences.feedbackFilter ?? null);
    }
    setHasLoadedPreferences(true);
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    if (!hasLoadedPreferences) {
      return;
    }

    window.sessionStorage.setItem(
      DASHBOARD_PREFERENCES_KEY,
      JSON.stringify({
        historyLimit,
        historyDays,
        riskFilter,
        feedbackFilter
      })
    );
  }, [feedbackFilter, hasLoadedPreferences, historyDays, historyLimit, riskFilter]);

  useEffect(() => {
    let isActive = true;

    async function loadDashboardData() {
      setIsLoading(true);
      setError(null);
      setScans([]);
      setAnalytics(null);

      try {
        const [scanHistory, analyticsSummary] = await Promise.all([
          fetchScanHistory({
            limit: historyLimit,
            days: historyDays,
            risk_level: riskFilter,
            feedback_status: feedbackFilter
          }),
          fetchScanAnalyticsSummary({
            limit: historyLimit,
            days: historyDays,
            risk_level: riskFilter,
            feedback_status: feedbackFilter
          })
        ]);

        if (!isActive) {
          return;
        }

        setScans(scanHistory);
        setAnalytics(analyticsSummary);
      } catch {
        if (!isActive) {
          return;
        }

        setError("Sentinel could not load dashboard data. Make sure the backend is running.");
      } finally {
        if (isActive) {
          setIsLoading(false);
        }
      }
    }

    loadDashboardData();

    return () => {
      isActive = false;
    };
  }, [currentUser, feedbackFilter, historyDays, historyLimit, riskFilter]);

  const totalScans = analytics?.total_scans ?? scans.length;
  const highRiskCount = analytics?.high_risk_count ?? 0;
  const mediumRiskCount = analytics?.medium_risk_count ?? 0;
  const lowRiskCount = analytics?.low_risk_count ?? 0;
  const feedbackCount = analytics?.feedback_count ?? 0;
  const needsReviewCount = analytics?.needs_review_count ?? 0;
  const highRiskNeedingFeedbackCount = analytics?.high_risk_needing_feedback_count ?? 0;
  const commonCategories = analytics?.common_categories ?? [];
  const activeTimeWindow =
    TIME_WINDOW_OPTIONS.find((option) => option.days === historyDays)?.label ?? "All time";
  const highestRiskScan = getHighestRiskScan(scans);
  const feedbackCoverage = getCoverageRate(feedbackCount, totalScans);
  const highRiskShare = getRiskShare(highRiskCount, totalScans);
  const mediumRiskShare = getRiskShare(mediumRiskCount, totalScans);
  const lowRiskShare = getRiskShare(lowRiskCount, totalScans);
  const topCategory = commonCategories[0] ?? null;
  const currentScopeLabel = currentUser ? `${currentUser.username}'s account` : "this browser session";
  const averageRiskScore = analytics?.average_risk_score ?? 0;
  const averageConfidenceScore = analytics?.average_confidence_score ?? 0;
  const latestHighRiskCreatedAt = analytics?.latest_high_risk_created_at ?? null;
  const inputTypeCounts = analytics?.input_type_counts ?? [];
  const feedbackBreakdown = analytics?.feedback_breakdown ?? [];
  const strongestInputType = getLeadingInputType(inputTypeCounts);
  const mostCommonFeedback = getLeadingFeedback(feedbackBreakdown);
  const comparison = analytics?.comparison ?? null;
  const comparisonWindowLabel = historyDays ? `vs previous ${historyDays} days` : null;
  const activeRiskFilterLabel = RISK_FILTER_OPTIONS.find(
    (option) => option.value === (riskFilter ?? "all")
  )?.label;
  const activeFeedbackFilterLabel = FEEDBACK_FILTER_OPTIONS.find(
    (option) => option.value === (feedbackFilter ?? "all")
  )?.label;

  return (
    <main className={styles.page}>
      <SiteHeader />

      <section className={styles.content}>
        <div className={styles.panel}>
          <div className={dashboardStyles.header}>
            <div>
              <p className={styles.eyebrow}>Dashboard</p>
              <h1 className={styles.title}>Scan history and summary</h1>
            </div>
            <Link className={dashboardStyles.actionLink} href="/analyze">
              New scan
            </Link>
          </div>

          <p className={styles.description}>
            {currentUser
              ? `Review ${currentUser.username}'s recent scan activity, risk distribution, and the most common phishing indicators detected for this account.`
              : "Review recent anonymous scan activity, risk distribution, and the most common phishing indicators detected in this browser session."}
          </p>

          <section className={dashboardStyles.storyGrid}>
            <article className={dashboardStyles.storyCard}>
              <span className={dashboardStyles.storyLabel}>Current scope</span>
              <strong>{activeTimeWindow}</strong>
              <p>
                Sentinel is summarizing up to the last {historyLimit} scans for {currentScopeLabel}, filtered to {activeRiskFilterLabel?.toLowerCase()} and {activeFeedbackFilterLabel?.toLowerCase()}.
              </p>
            </article>
            <article className={dashboardStyles.storyCard}>
              <span className={dashboardStyles.storyLabel}>Primary concern</span>
              <strong>
                {highestRiskScan
                  ? `${highestRiskScan.risk_level} risk / ${highestRiskScan.risk_score}`
                  : "No scans yet"}
              </strong>
              <p>
                {highestRiskScan
                  ? highestRiskScan.summary
                  : "Run an analysis to start building a dashboard story for Sentinel."}
              </p>
            </article>
            <article className={dashboardStyles.storyCard}>
              <span className={dashboardStyles.storyLabel}>Review backlog</span>
              <strong>{needsReviewCount} awaiting review</strong>
              <p>
                {highRiskNeedingFeedbackCount > 0
                  ? `${highRiskNeedingFeedbackCount} high-risk result${highRiskNeedingFeedbackCount === 1 ? "" : "s"} still need analyst feedback in this view.`
                  : "No unreviewed high-risk results are waiting in this filtered view."}
              </p>
            </article>
            <article className={dashboardStyles.storyCard}>
              <span className={dashboardStyles.storyLabel}>Top signal</span>
              <strong>{topCategory ? topCategory.name : "No indicators yet"}</strong>
              <p>
                {topCategory
                  ? `This category appears in ${topCategory.count} saved scan${topCategory.count === 1 ? "" : "s"} in the current filtered view.`
                  : "Common indicator trends will appear after scans with detected signals."}
              </p>
            </article>
            <article className={dashboardStyles.storyCard}>
              <span className={dashboardStyles.storyLabel}>Risk momentum</span>
              <strong>
                {comparison
                  ? `${formatSignedDelta(comparison.average_risk_score_change)} avg risk`
                  : `${averageRiskScore} risk / ${averageConfidenceScore}% heuristic confidence`}
              </strong>
              <p>
                {comparison
                  ? `Compared with the previous ${historyDays}-day window, Sentinel's average risk score is ${describeChangeDirection(comparison.average_risk_score_change)}.`
                  : "Choose a time window to compare this set with an equally long period immediately before it."}
              </p>
            </article>
          </section>

          <div className={dashboardStyles.toolbar}>
            <label className={dashboardStyles.filterGroup}>
              <span>Recent history</span>
              <select
                className={dashboardStyles.filterSelect}
                onChange={(event) => setHistoryLimit(Number(event.target.value))}
                value={historyLimit}
              >
                {SCAN_HISTORY_LIMIT_OPTIONS.map((limit) => (
                  <option key={limit} value={limit}>
                    Last {limit} scans
                  </option>
                ))}
              </select>
            </label>

            <label className={dashboardStyles.filterGroup}>
              <span>Time window</span>
              <select
                className={dashboardStyles.filterSelect}
                onChange={(event) =>
                  setHistoryDays(
                    event.target.value === "all" ? null : Number(event.target.value)
                  )
                }
                value={historyDays ?? "all"}
              >
                {TIME_WINDOW_OPTIONS.map((option) => (
                  <option
                    key={option.label}
                    value={option.days ?? "all"}
                  >
                    {option.label}
                  </option>
                ))}
              </select>
            </label>

            <label className={dashboardStyles.filterGroup}>
              <span>Risk focus</span>
              <select
                className={dashboardStyles.filterSelect}
                onChange={(event) =>
                  setRiskFilter(
                    event.target.value === "all" ? null : (event.target.value as RiskLevel)
                  )
                }
                value={riskFilter ?? "all"}
              >
                {RISK_FILTER_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>

            <label className={dashboardStyles.filterGroup}>
              <span>Review state</span>
              <select
                className={dashboardStyles.filterSelect}
                onChange={(event) =>
                  setFeedbackFilter(
                    event.target.value === "all"
                      ? null
                      : (event.target.value as ScanFeedbackStatus)
                  )
                }
                value={feedbackFilter ?? "all"}
              >
                {FEEDBACK_FILTER_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className={dashboardStyles.metricsGrid}>
            <Metric label="Total scans" value={totalScans} />
            <Metric label="Needs review" value={needsReviewCount} />
            <Metric label="High risk" value={highRiskCount} tone="high" />
            <Metric label="Medium risk" value={mediumRiskCount} tone="medium" />
            <Metric label="Low risk" value={lowRiskCount} tone="low" />
            <Metric label="Feedback" value={feedbackCount} />
          </div>

          <section className={dashboardStyles.comparisonSection}>
            <div className={dashboardStyles.sectionHeader}>
              <div>
                <h2 className={dashboardStyles.sectionTitle}>Window comparison</h2>
                <p className={dashboardStyles.sectionBody}>
                  Compare the current filtered set with an equally long period immediately before it, using the same filters. For example, “Last 7 days” compares with days 8–14 ago.
                </p>
              </div>
              <p className={dashboardStyles.sectionBadge}>
                {comparisonWindowLabel ?? "Pick a time window"}
              </p>
            </div>
            {comparison ? (
              <div className={dashboardStyles.comparisonGrid}>
                <ComparisonCard
                  label="Scan volume"
                  value={formatSignedDelta(comparison.scan_volume_change)}
                  detail={`${totalScans} now vs ${comparison.previous_total_scans} previously`}
                  tone={getDeltaTone(comparison.scan_volume_change)}
                />
                <ComparisonCard
                  label="High-risk count"
                  value={formatSignedDelta(comparison.high_risk_change)}
                  detail={`${highRiskCount} now vs ${comparison.previous_high_risk_count} previously`}
                  tone={getDeltaTone(comparison.high_risk_change)}
                />
                <ComparisonCard
                  label="Average risk score"
                  value={formatSignedDelta(comparison.average_risk_score_change)}
                  detail={`${averageRiskScore} now vs ${comparison.previous_average_risk_score} previously`}
                  tone={getDeltaTone(comparison.average_risk_score_change)}
                />
              </div>
            ) : (
              <p className={dashboardStyles.muted}>
                Choose a 7-day, 14-day, 30-day, or 365-day window to unlock trend comparisons.
              </p>
            )}
          </section>

          {error ? <p className={dashboardStyles.error}>{error}</p> : null}

          <div className={dashboardStyles.dashboardGrid}>
            <section className={dashboardStyles.section}>
              <div className={dashboardStyles.sectionHeader}>
                <div>
                  <h2 className={dashboardStyles.sectionTitle}>Recent scans</h2>
                  <p className={dashboardStyles.sectionBody}>
                    Start with the newest evidence first. Each row links to the full report.
                  </p>
                </div>
                <p className={dashboardStyles.sectionBadge}>
                  {isLoading ? "Refreshing..." : `${scans.length} shown`}
                </p>
              </div>
              {isLoading ? (
                <p className={dashboardStyles.muted}>Loading scan history...</p>
              ) : scans.length > 0 ? (
                <div className={dashboardStyles.scanList}>
                  {scans.map((scan) => (
                    <Link
                      className={dashboardStyles.scanRow}
                      href={`/scans/${scan.id}`}
                      key={scan.id}
                    >
                      <div>
                        <div className={dashboardStyles.scanMeta}>
                          <span>{scan.input_type}</span>
                          <span>{formatDate(scan.created_at)}</span>
                          <span>{scan.is_saved ? "saved" : "temporary"}</span>
                          {scan.feedback ? <span>{scan.feedback}</span> : null}
                        </div>
                        <h3 className={dashboardStyles.scanTitle}>{scan.summary}</h3>
                        <p className={dashboardStyles.scanEvidence}>
                          {scan.detected_categories.length > 0
                            ? scan.detected_categories.slice(0, 3).join(" • ")
                            : "No indicator categories recorded"}
                        </p>
                      </div>
                      <div className={dashboardStyles.scoreCluster}>
                        <span className={dashboardStyles[`risk${scan.risk_level}`]}>
                          {scan.risk_level}
                        </span>
                        <strong>{scan.risk_score}</strong>
                      </div>
                    </Link>
                  ))}
                </div>
              ) : (
                <p className={dashboardStyles.muted}>
                  No scans yet. Run an analysis first, then return here to see
                  the saved history for this {currentUser ? "account" : "browser session"}.
                </p>
              )}
            </section>

            <div className={dashboardStyles.sideColumn}>
              <section className={dashboardStyles.section}>
                <div className={dashboardStyles.sectionHeader}>
                  <div>
                    <h2 className={dashboardStyles.sectionTitle}>Risk distribution</h2>
                    <p className={dashboardStyles.sectionBody}>
                      How the current filtered scans are split across severity levels.
                    </p>
                  </div>
                </div>
                <div className={dashboardStyles.riskStack}>
                  <RiskBand
                    label="High risk"
                    count={highRiskCount}
                    percentage={highRiskShare}
                    tone="high"
                  />
                  <RiskBand
                    label="Medium risk"
                    count={mediumRiskCount}
                    percentage={mediumRiskShare}
                    tone="medium"
                  />
                  <RiskBand
                    label="Low risk"
                    count={lowRiskCount}
                    percentage={lowRiskShare}
                    tone="low"
                  />
                </div>
                <div className={dashboardStyles.coverageCard}>
                  <span>Feedback coverage</span>
                  <strong>{feedbackCoverage}%</strong>
                  <p>
                    {feedbackCount} of {totalScans} filtered scan{totalScans === 1 ? "" : "s"} include analyst feedback.
                  </p>
                </div>
                <div className={dashboardStyles.coverageCard}>
                  <span>High-risk awaiting review</span>
                  <strong>{highRiskNeedingFeedbackCount}</strong>
                  <p>
                    {highRiskNeedingFeedbackCount > 0
                      ? "Prioritize these results before Sentinel's highest-risk queue grows further."
                      : "Every high-risk result in the current filtered view has analyst feedback."}
                  </p>
                </div>
                <div className={dashboardStyles.coverageCard}>
                  <span>Latest high-risk hit</span>
                  <strong>
                    {latestHighRiskCreatedAt ? formatDate(latestHighRiskCreatedAt) : "None yet"}
                  </strong>
                  <p>
                    {latestHighRiskCreatedAt
                      ? "Most recent high-risk result in the current filtered view."
                      : "No high-risk results appear in the current filtered view."}
                  </p>
                </div>
              </section>

              <section className={dashboardStyles.section}>
                <div className={dashboardStyles.sectionHeader}>
                  <div>
                    <h2 className={dashboardStyles.sectionTitle}>Common indicators</h2>
                  <p className={dashboardStyles.sectionBody}>
                      The categories appearing most often in the current filtered view.
                    </p>
                  </div>
                </div>
                {commonCategories.length > 0 ? (
                  <div className={dashboardStyles.categoryStack}>
                    {commonCategories.map((category, index) => (
                      <div className={dashboardStyles.categoryRow} key={category.name}>
                        <div>
                          <span>{category.name}</span>
                          <small>Rank {index + 1}</small>
                        </div>
                        <strong>{category.count}</strong>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className={dashboardStyles.muted}>
                    Indicator trends will appear after scans with detected signals.
                  </p>
                )}
                <div className={dashboardStyles.analyticsNotes}>
                  <div className={dashboardStyles.analyticsNote}>
                    <span>Most common input type</span>
                    <strong>{strongestInputType ?? "No scans yet"}</strong>
                  </div>
                  <div className={dashboardStyles.analyticsNote}>
                    <span>Most common feedback</span>
                    <strong>{mostCommonFeedback ?? "No feedback yet"}</strong>
                  </div>
                </div>
              </section>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}

function Metric({
  label,
  value,
  tone = "neutral"
}: {
  label: string;
  value: number;
  tone?: "neutral" | "high" | "medium" | "low";
}) {
  return (
    <article className={`${dashboardStyles.metric} ${dashboardStyles[tone]}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function RiskBand({
  label,
  count,
  percentage,
  tone
}: {
  label: string;
  count: number;
  percentage: number;
  tone: "high" | "medium" | "low";
}) {
  return (
    <div className={dashboardStyles.riskBand}>
      <div className={dashboardStyles.riskBandHeader}>
        <span>{label}</span>
        <strong>{count}</strong>
      </div>
      <div className={dashboardStyles.riskBarTrack}>
        <div
          className={`${dashboardStyles.riskBarFill} ${dashboardStyles[tone]}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <p>{percentage}% of the current filtered scans</p>
    </div>
  );
}

function ComparisonCard({
  label,
  value,
  detail,
  tone
}: {
  label: string;
  value: string;
  detail: string;
  tone: "up" | "down" | "flat";
}) {
  return (
    <article className={`${dashboardStyles.comparisonCard} ${dashboardStyles[tone]}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <p>{detail}</p>
    </article>
  );
}

function getHighestRiskScan(scans: ScanResult[]) {
  return scans.reduce<ScanResult | null>((highest, scan) => {
    if (!highest) {
      return scan;
    }

    if (scan.risk_score > highest.risk_score) {
      return scan;
    }

    return highest;
  }, null);
}

function getCoverageRate(count: number, total: number) {
  if (total === 0) {
    return 0;
  }

  return Math.round((count / total) * 100);
}

function getRiskShare(count: number, total: number) {
  if (total === 0) {
    return 0;
  }

  return Math.round((count / total) * 100);
}

function getLeadingInputType(
  counts: ScanAnalyticsSummary["input_type_counts"]
) {
  const top = counts.reduce<typeof counts[number] | null>((highest, current) => {
    if (!highest || current.count > highest.count) {
      return current;
    }

    return highest;
  }, null);

  if (!top || top.count === 0) {
    return null;
  }

  return top.input_type.toUpperCase();
}

function getLeadingFeedback(
  counts: ScanAnalyticsSummary["feedback_breakdown"]
) {
  const top = counts.reduce<typeof counts[number] | null>((highest, current) => {
    if (!highest || current.count > highest.count) {
      return current;
    }

    return highest;
  }, null);

  if (!top || top.count === 0) {
    return null;
  }

  return top.label;
}

function getDeltaTone(value: number): "up" | "down" | "flat" {
  if (value === 0) {
    return "flat";
  }

  return value > 0 ? "up" : "down";
}

function formatSignedDelta(value: number) {
  if (value > 0) {
    return `+${value}`;
  }

  return String(value);
}

function describeChangeDirection(value: number) {
  if (value > 0) {
    return "higher";
  }

  if (value < 0) {
    return "lower";
  }

  return "unchanged";
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}
