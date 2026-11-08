"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { useAuthSession } from "@/components/auth-provider";
import { SiteHeader } from "@/components/site-header";
import {
  FeedbackLabel,
  fetchScanById,
  RiskLevel,
  ScanResult,
  submitScanFeedback,
  updateScanStorage,
  deleteScan
} from "@/lib/api";
import styles from "../../route-shell.module.css";
import detailStyles from "./page.module.css";

type ScanDetailPageProps = {
  params: Promise<{
    id: string;
  }>;
};

export default function ScanDetailPage({ params }: ScanDetailPageProps) {
  const { id } = use(params);
  const router = useRouter();
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const { currentUser } = useAuthSession();

  useEffect(() => {
    let isActive = true;

    async function loadScan() {
      setIsLoading(true);
      setError(null);
      setScan(null);

      try {
        const scanResult = await fetchScanById(id);

        if (!isActive) {
          return;
        }

        setScan(scanResult);
      } catch (caughtError) {
        if (!isActive) {
          return;
        }

        setError(buildScanLoadErrorMessage(currentUser, caughtError));
      } finally {
        if (isActive) {
          setIsLoading(false);
        }
      }
    }

    loadScan();

    return () => {
      isActive = false;
    };
  }, [id, currentUser]);

  return (
    <main className={styles.page}>
      <SiteHeader />

      <section className={styles.content}>
        <div className={styles.panel}>
          <div className={detailStyles.topActions}>
            <button
              className={detailStyles.backButton}
              onClick={() => router.push("/dashboard")}
              type="button"
            >
              Back to dashboard
            </button>
            <Link className={detailStyles.secondaryLink} href="/analyze">
              Run another scan
            </Link>
          </div>
          <p className={styles.eyebrow}>Scan Detail</p>
          <h1 className={styles.title}>
            {currentUser ? `Scan ${id}` : "Temporary scan report"}
          </h1>

          {isLoading ? (
            <p className={styles.description}>Loading scan report...</p>
          ) : error ? (
            <ScanLoadError message={error} />
          ) : scan ? (
            <ScanReport scan={scan} canSavePermanently={Boolean(currentUser)} />
          ) : null}
        </div>
      </section>
    </main>
  );
}

function ScanLoadError({ message }: { message: string }) {
  return (
    <div className={detailStyles.error}>
      <p>{message}</p>
      <p>
        <Link href="/dashboard">Return to the dashboard</Link>
      </p>
    </div>
  );
}

function buildScanLoadErrorMessage(
  currentUser: ReturnType<typeof useAuthSession>["currentUser"],
  caughtError: unknown
) {
  const apiMessage =
    caughtError instanceof Error ? caughtError.message : null;

  if (!currentUser) {
    return (
      "This scan is not available in the current anonymous session. " +
      "If it was created while signed in, log back into that account to view it."
    );
  }

  if (apiMessage === "Scan not found.") {
    return "This scan could not be found for the current account.";
  }

  return apiMessage ?? "Sentinel could not load this scan right now.";
}

function ScanReport({
  scan,
  canSavePermanently
}: {
  scan: ScanResult;
  canSavePermanently: boolean;
}) {
  const router = useRouter();
  const [currentScan, setCurrentScan] = useState(scan);
  const [retentionDays, setRetentionDays] = useState(7);
  const [storageError, setStorageError] = useState<string | null>(null);
  const [isUpdatingStorage, setIsUpdatingStorage] = useState(false);
  const [feedbackNote, setFeedbackNote] = useState(scan.feedback_note ?? "");
  const [feedbackError, setFeedbackError] = useState<string | null>(null);
  const [isSubmittingFeedback, setIsSubmittingFeedback] = useState(false);
  const findingCount = currentScan.finding_details.length;
  const topSeverity = getHighestSeverity(currentScan.finding_details);
  const inputTypeLabel = currentScan.input_type.toUpperCase();
  const hasFeedback = currentScan.feedback !== null;
  const feedbackStatusLabel = currentScan.feedback ?? "Pending";

  async function handleFeedback(feedback: FeedbackLabel) {
    setFeedbackError(null);
    setIsSubmittingFeedback(true);

    try {
      const updatedScan = await submitScanFeedback(
        currentScan.id,
        feedback,
        feedbackNote
      );
      setCurrentScan(updatedScan);
      setFeedbackNote(updatedScan.feedback_note ?? "");
    } catch {
      setFeedbackError("Sentinel could not save that feedback. Try again while the backend is running.");
    } finally {
      setIsSubmittingFeedback(false);
    }
  }

  async function handleSaveFeedbackNote() {
    if (!currentScan.feedback) {
      setFeedbackError("Choose Correct, False Positive, or False Negative before saving a note.");
      return;
    }

    await handleFeedback(currentScan.feedback);
  }

  async function handleStorageUpdate(saveScan: boolean) {
    setStorageError(null);
    setIsUpdatingStorage(true);

    try {
      const updatedScan = await updateScanStorage(
        currentScan.id,
        saveScan,
        retentionDays
      );
      setCurrentScan(updatedScan);
    } catch (caughtError) {
      setStorageError(
        caughtError instanceof Error
          ? caughtError.message
          : "Sentinel could not update storage for this scan."
      );
    } finally {
      setIsUpdatingStorage(false);
    }
  }

  async function handleDelete() {
    if (!window.confirm("Delete this scan permanently? This cannot be undone.")) {
      return;
    }

    setStorageError(null);
    setIsUpdatingStorage(true);
    try {
      await deleteScan(currentScan.id);
      router.push("/dashboard");
    } catch (caughtError) {
      setStorageError(
        caughtError instanceof Error
          ? caughtError.message
          : "Sentinel could not delete this scan."
      );
      setIsUpdatingStorage(false);
    }
  }

  return (
    <div className={detailStyles.report}>
      <section className={detailStyles.summary}>
        <div className={detailStyles.scoreBlock}>
          <span className={detailStyles[`risk${currentScan.risk_level}`]}>
            {currentScan.risk_level}
          </span>
          <strong>{currentScan.risk_score}</strong>
          <small>{currentScan.confidence_score}% heuristic confidence</small>
        </div>
        <div>
          <p className={detailStyles.timestamp}>{formatDate(currentScan.created_at)}</p>
          <p className={detailStyles.scanMetaLine}>
            {inputTypeLabel} scan
            <span aria-hidden="true">•</span>
            {findingCount} signal{findingCount === 1 ? "" : "s"}
            <span aria-hidden="true">•</span>
            Highest severity {topSeverity}
          </p>
          <h2 className={detailStyles.summaryTitle}>{currentScan.summary}</h2>
          <p className={detailStyles.recommendation}>{currentScan.recommendation}</p>
        </div>
      </section>

      <section className={detailStyles.overviewGrid}>
        <InsightCard
          label="Risk assessment"
          value={`${currentScan.risk_level} / ${currentScan.risk_score}`}
          body="Sentinel&apos;s current overall judgment for this scan."
          tone={currentScan.risk_level.toLowerCase() as "low" | "medium" | "high"}
        />
        <InsightCard
          label="Rule confidence (heuristic)"
          value={`${currentScan.confidence_score}%`}
          body="How certain the current rule set is about the result."
        />
        <InsightCard
          label="Evidence count"
          value={String(findingCount)}
          body="Distinct signals that contributed to the report."
        />
        <InsightCard
          label="Feedback status"
          value={feedbackStatusLabel}
          body={
            hasFeedback
              ? "An analyst has already reviewed this result."
              : "No analyst feedback has been recorded yet."
          }
        />
      </section>

      <section className={detailStyles.storageCard}>
        <div className={detailStyles.sectionHeader}>
          <div>
            <h2>Storage status</h2>
            <p>{buildStorageDescription(currentScan)}</p>
          </div>
        </div>
        <p className={detailStyles.storageState}>
          {currentScan.is_saved
            ? "This scan is saved in history."
            : "This scan is temporary."}
        </p>
        <div className={detailStyles.storageActions}>
          {!currentScan.is_saved ? (
            <>
              <label>
                <span>Temporary window</span>
                <select
                  disabled={isUpdatingStorage}
                  onChange={(event) => setRetentionDays(Number(event.target.value))}
                  value={retentionDays}
                >
                  {[7, 14, 30].map((days) => (
                    <option key={days} value={days}>Keep for {days} days</option>
                  ))}
                </select>
              </label>
              <button
                disabled={isUpdatingStorage}
                onClick={() => handleStorageUpdate(false)}
                type="button"
              >
                Update temporary window
              </button>
              {canSavePermanently ? (
                <button
                  disabled={isUpdatingStorage}
                  onClick={() => handleStorageUpdate(true)}
                  type="button"
                >
                  Save permanently
                </button>
              ) : null}
            </>
          ) : (
            <>
              <label>
                <span>Make temporary for</span>
                <select
                  disabled={isUpdatingStorage}
                  onChange={(event) => setRetentionDays(Number(event.target.value))}
                  value={retentionDays}
                >
                  {[7, 14, 30].map((days) => (
                    <option key={days} value={days}>{days} days</option>
                  ))}
                </select>
              </label>
              <button
                disabled={isUpdatingStorage}
                onClick={() => handleStorageUpdate(false)}
                type="button"
              >
                Make temporary
              </button>
            </>
          )}
          <button
            className={detailStyles.deleteButton}
            disabled={isUpdatingStorage}
            onClick={handleDelete}
            type="button"
          >
            Delete scan
          </button>
        </div>
        {storageError ? <p className={detailStyles.error}>{storageError}</p> : null}
      </section>

      <section className={detailStyles.rawInput}>
        <div className={detailStyles.sectionHeader}>
          <div>
            <h2>Submitted content</h2>
            <p>The exact text or URL that was sent to Sentinel for analysis.</p>
          </div>
        </div>
        <pre>{currentScan.raw_content}</pre>
      </section>

      <section className={detailStyles.categories}>
        <div className={detailStyles.sectionHeader}>
          <div>
            <h2>Detected categories</h2>
            <p>High-level buckets that describe what kind of suspicious behavior appeared.</p>
          </div>
        </div>
        {currentScan.detected_categories.length > 0 ? (
          <div className={detailStyles.categoryList}>
            {currentScan.detected_categories.map((category) => (
              <span key={category}>{category}</span>
            ))}
          </div>
        ) : (
          <p>No categories detected.</p>
        )}
      </section>

      <section className={detailStyles.findings}>
        <div className={detailStyles.sectionHeader}>
          <div>
            <h2>Finding details</h2>
            <p>Each finding explains one signal that contributed to the final score.</p>
          </div>
        </div>
        {currentScan.finding_details.length > 0 ? (
          <div className={detailStyles.findingList}>
            {currentScan.finding_details.map((finding, index) => (
              <article className={detailStyles.findingCard} key={`${finding.message}-${index}`}>
                <div className={detailStyles.findingTopline}>
                  <div>
                    <span className={detailStyles.findingIndex}>
                      Signal {index + 1}
                    </span>
                    <strong>{finding.category}</strong>
                  </div>
                  <strong className={detailStyles[`severity${finding.severity}`]}>
                    {finding.severity}
                  </strong>
                </div>
                <p>{finding.message}</p>
                {finding.matched_text ? (
                  <p className={detailStyles.findingEvidence}>
                    Triggered by: <code>{finding.matched_text}</code>
                  </p>
                ) : null}
              </article>
            ))}
          </div>
        ) : (
          <p>No detailed findings were returned.</p>
        )}
      </section>

      <section className={detailStyles.feedback}>
        <div className={detailStyles.sectionHeader}>
          <div>
            <h2>Analyst feedback</h2>
            <p>
              Mark whether Sentinel&apos;s result was useful after reviewing the scan
              evidence. Feedback records your review; it does not automatically
              change scoring or scan retention.
            </p>
          </div>
          {currentScan.feedback ? (
            <p className={detailStyles.feedbackStatus}>
              Current feedback: {currentScan.feedback}
            </p>
          ) : (
            <p className={detailStyles.pendingStatus}>Awaiting analyst review</p>
          )}
        </div>
        <div className={detailStyles.feedbackActions}>
          {(["Correct", "False Positive", "False Negative"] as FeedbackLabel[]).map(
            (feedback) => (
              <button
                aria-pressed={currentScan.feedback === feedback}
                disabled={isSubmittingFeedback}
                key={feedback}
                onClick={() => handleFeedback(feedback)}
                type="button"
              >
                {feedback}
              </button>
            )
          )}
        </div>
        <div className={detailStyles.feedbackGuide}>
          <p>
            <strong>Correct:</strong> Sentinel&apos;s judgment matched your review of
            the content.
          </p>
          <p>
            <strong>False Positive:</strong> Sentinel treated benign or routine
            content as riskier than it should have.
          </p>
          <p>
            <strong>False Negative:</strong> Sentinel missed important risk or
            scored the content too low.
          </p>
        </div>
        <div className={detailStyles.feedbackContext}>
          <div>
            <h3>Add context for Sentinel</h3>
            <p>
              Optional: explain why the result was right or wrong. These notes
              are stored with this report for your own review.
            </p>
          </div>
          <label className={detailStyles.feedbackNote}>
            Feedback note
            <textarea
              maxLength={1000}
              onChange={(event) => setFeedbackNote(event.target.value)}
              placeholder="Example: This is risky because it asks for an OTP code, but the score may be too low."
              value={feedbackNote}
            />
            <span>{feedbackNote.length}/1000</span>
          </label>
          <button
            className={detailStyles.saveNoteButton}
            disabled={isSubmittingFeedback || !currentScan.feedback}
            onClick={handleSaveFeedbackNote}
            type="button"
          >
            Save feedback note
          </button>
          {currentScan.feedback_note ? (
            <p className={detailStyles.savedNote}>
              Saved note: {currentScan.feedback_note}
            </p>
          ) : null}
        </div>
        {feedbackError ? <p className={detailStyles.error}>{feedbackError}</p> : null}
      </section>
    </div>
  );
}

function buildStorageDescription(scan: ScanResult) {
  if (scan.is_saved) {
    return "This scan is stored permanently in history.";
  }

  if (scan.expires_at) {
    const expirationDate = new Date(scan.expires_at).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric"
    });
    return `This temporary scan expires on ${expirationDate}.`;
  }

  return "This scan is temporary.";
}

function InsightCard({
  label,
  value,
  body,
  tone = "neutral"
}: {
  label: string;
  value: string;
  body: string;
  tone?: "neutral" | "low" | "medium" | "high";
}) {
  return (
    <article className={`${detailStyles.insightCard} ${detailStyles[tone]}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <p>{body}</p>
    </article>
  );
}

function getHighestSeverity(
  findings: ScanResult["finding_details"]
): RiskLevel {
  if (findings.some((finding) => finding.severity === "High")) {
    return "High";
  }

  if (findings.some((finding) => finding.severity === "Medium")) {
    return "Medium";
  }

  return "Low";
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "full",
    timeStyle: "short"
  }).format(new Date(value));
}
