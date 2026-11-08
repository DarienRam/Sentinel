"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";

import { SiteHeader } from "@/components/site-header";
import { useAuthSession } from "@/components/auth-provider";
import { createScan, ScanInputType, ScanResult } from "@/lib/api";
import styles from "../route-shell.module.css";
import analyzeStyles from "./page.module.css";

const sampleInputs: Record<ScanInputType, string> = {
  url: "http://192.0.2.1/account/login?urgent=verify",
  email: "Dear customer,\n\nVerify your bank password immediately within 24 hours.\n\nSecurity Team",
  message: "Are you available? Send me the OTP code right now"
};

const sampleEmailSubject = "Account notice";
const TEMPORARY_RETENTION_OPTIONS = [7, 14, 30] as const;

export default function AnalyzePage() {
  const [inputType, setInputType] = useState<ScanInputType>("url");
  const [rawContent, setRawContent] = useState(sampleInputs.url);
  const [emailSubject, setEmailSubject] = useState(sampleEmailSubject);
  const [saveScan, setSaveScan] = useState(false);
  const [retentionDays, setRetentionDays] = useState<(typeof TEMPORARY_RETENTION_OPTIONS)[number]>(7);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { currentUser } = useAuthSession();
  const normalizedEmailContent = buildEmailContent(emailSubject, rawContent);
  const submissionContent =
    inputType === "email" ? normalizedEmailContent : rawContent;
  const inputTypeHint = getInputTypeHint(inputType, submissionContent);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setResult(null);
    setIsSubmitting(true);

    try {
      const scanResult = await createScan({
        input_type: inputType,
        raw_content: submissionContent,
        save_scan: saveScan,
        retention_days: saveScan ? null : retentionDays
      });

      setResult(scanResult);
    } catch {
      setError("Sentinel could not analyze that input. Make sure the backend is running.");
    } finally {
      setIsSubmitting(false);
    }
  }

  function handleTypeChange(nextType: ScanInputType) {
    setInputType(nextType);
    setRawContent(sampleInputs[nextType]);
    setEmailSubject(nextType === "email" ? sampleEmailSubject : "");
    setResult(null);
    setError(null);
  }

  return (
    <main className={styles.page}>
      <SiteHeader />

      <section className={styles.content}>
        <div className={styles.panel}>
          <div className={analyzeStyles.header}>
            <div>
              <p className={styles.eyebrow}>Analyze</p>
              <h1 className={styles.title}>Check suspicious content</h1>
            </div>
          </div>

          <p className={styles.description}>
            Submit a URL, email, or message and Sentinel will return a
            transparent phishing-risk score with the signals that triggered it.
            {currentUser
              ? ` By default, scans expire after ${retentionDays} days unless you choose to save them permanently.`
              : " Log in if you want scans tied to an analyst account instead of an anonymous session."}
          </p>

          <div className={analyzeStyles.workspace}>
            <form className={analyzeStyles.form} onSubmit={handleSubmit}>
              <fieldset className={analyzeStyles.fieldGroup}>
                <legend className={analyzeStyles.label}>Input type</legend>
                <div className={analyzeStyles.segmentedControl}>
                  {(["url", "email", "message"] as ScanInputType[]).map((type) => (
                    <button
                      aria-pressed={inputType === type}
                      className={analyzeStyles.segmentButton}
                      key={type}
                      onClick={() => handleTypeChange(type)}
                      type="button"
                    >
                      {type}
                    </button>
                  ))}
                </div>
              </fieldset>

              <label className={analyzeStyles.field}>
                <span className={analyzeStyles.label}>Suspicious content</span>
                {inputType === "email" ? (
                  <div className={analyzeStyles.subjectField}>
                    <span className={analyzeStyles.subjectLabel}>Subject line</span>
                    <input
                      className={analyzeStyles.textInput}
                      maxLength={180}
                      onChange={(event) => setEmailSubject(event.target.value)}
                      placeholder="Add the email subject"
                      type="text"
                      value={emailSubject}
                    />
                  </div>
                ) : null}
                <textarea
                  className={analyzeStyles.textarea}
                  maxLength={5000}
                  minLength={4}
                  onChange={(event) => setRawContent(event.target.value)}
                  placeholder={
                    inputType === "email"
                      ? "Paste the email body..."
                      : "Paste a suspicious URL, email body, or message..."
                  }
                  required
                  rows={9}
                  value={rawContent}
                />
              </label>

              {inputTypeHint ? (
                <p className={analyzeStyles.inputHint}>{inputTypeHint}</p>
              ) : null}

              <details className={analyzeStyles.storageOptions}>
                <summary className={analyzeStyles.storageSummary}>
                  <span className={analyzeStyles.storageSummaryRow}>
                    <span>Storage options</span>
                    <span className={analyzeStyles.storageChevron} aria-hidden="true">
                      ▾
                    </span>
                  </span>
                  <small>
                    {saveScan
                      ? "Currently saving this scan permanently."
                      : `Currently keeping this scan for ${retentionDays} days.`}
                  </small>
                </summary>

                <label className={analyzeStyles.saveOption}>
                  <input
                    checked={saveScan}
                    disabled={!currentUser}
                    onChange={(event) => setSaveScan(event.target.checked)}
                    type="checkbox"
                  />
                  <span>
                    Save this scan in history permanently
                    <small>
                      {saveScan
                        ? "Saved scans stay available until you delete them from the report."
                        : currentUser
                          ? `Temporary scans stay available for ${retentionDays} days. You can change the storage setting later from the full report.`
                          : `Log in to save scans permanently. Anonymous temporary scans are private to this browser session.`}
                    </small>
                  </span>
                </label>
                {!saveScan ? (
                  <label className={analyzeStyles.retentionField}>
                    <span className={analyzeStyles.retentionLabel}>Temporary save window</span>
                    <select
                      className={analyzeStyles.retentionSelect}
                      onChange={(event) =>
                        setRetentionDays(
                          Number(event.target.value) as (typeof TEMPORARY_RETENTION_OPTIONS)[number]
                        )
                      }
                      value={retentionDays}
                    >
                      {TEMPORARY_RETENTION_OPTIONS.map((days) => (
                        <option key={days} value={days}>
                          Keep for {days} days
                        </option>
                      ))}
                    </select>
                  </label>
                ) : null}
              </details>

              <div className={analyzeStyles.formFooter}>
                <span className={analyzeStyles.counter}>
                  {submissionContent.length}/5000
                </span>
                <button
                  className={analyzeStyles.submitButton}
                  disabled={isSubmitting}
                  type="submit"
                >
                  {isSubmitting ? "Analyzing..." : "Analyze content"}
                </button>
              </div>

              {error ? <p className={analyzeStyles.error}>{error}</p> : null}
            </form>

            <section className={analyzeStyles.resultPanel} aria-live="polite">
              {result ? <ScanResultCard result={result} /> : <EmptyResult />}
            </section>
          </div>
        </div>
      </section>
    </main>
  );
}

function buildEmailContent(subject: string, body: string) {
  const normalizedSubject = subject.trim();
  const normalizedBody = body.trim();

  if (normalizedSubject && normalizedBody) {
    return `Subject: ${normalizedSubject}\n\n${normalizedBody}`;
  }

  if (normalizedSubject) {
    return `Subject: ${normalizedSubject}`;
  }

  return normalizedBody;
}

function getInputTypeHint(
  inputType: ScanInputType,
  rawContent: string
): string | null {
  const normalized = rawContent.trim();

  if (!normalized) {
    return null;
  }

  const looksLikeUrl = /^https?:\/\/\S+$/i.test(normalized) || /^[a-z0-9.-]+\.[a-z]{2,}(\/\S*)?$/i.test(normalized);
  const hasWhitespace = /\s/.test(normalized);

  if (inputType === "url" && !looksLikeUrl && hasWhitespace) {
    return "This content looks more like an email or message than a URL. Switch the input type if you want Sentinel to score it correctly.";
  }

  if (inputType !== "url" && looksLikeUrl) {
    return "This content looks like a URL. Switching to URL mode may give you a more accurate result.";
  }

  return null;
}

function EmptyResult() {
  return (
    <div className={analyzeStyles.emptyResult}>
      <p className={analyzeStyles.resultKicker}>Awaiting analysis</p>
      <h2 className={analyzeStyles.resultTitle}>No scan result yet</h2>
      <p className={analyzeStyles.resultText}>
        Results will appear here with a score, risk level, summary, and the
        signals Sentinel found in the submitted content.
      </p>
    </div>
  );
}

function ScanResultCard({ result }: { result: ScanResult }) {
  const riskClassName = `${analyzeStyles.scoreRing} ${
    analyzeStyles[`risk${result.risk_level}`]
  }`;

  return (
    <div className={analyzeStyles.resultCard}>
      <div className={analyzeStyles.resultTopline}>
        <div className={riskClassName}>
          <span>{result.risk_score}</span>
          <small>/100</small>
        </div>
        <div>
          <p className={analyzeStyles.resultKicker}>Risk level</p>
          <h2 className={analyzeStyles.resultTitle}>{result.risk_level}</h2>
          <p className={analyzeStyles.confidence}>
            Rule confidence (heuristic) {result.confidence_score}%
          </p>
        </div>
      </div>

      <p className={analyzeStyles.resultText}>{result.summary}</p>

      <div className={analyzeStyles.recommendation}>
        <p className={analyzeStyles.resultKicker}>Recommended action</p>
        <p>{result.recommendation}</p>
      </div>

      {result.detected_categories.length > 0 ? (
        <div className={analyzeStyles.categoryList}>
          {result.detected_categories.map((category) => (
            <span className={analyzeStyles.categoryPill} key={category}>
              {category}
            </span>
          ))}
        </div>
      ) : null}

      <div className={analyzeStyles.findings}>
        <h3 className={analyzeStyles.findingsTitle}>Detected signals</h3>
        <div className={analyzeStyles.reportLinkRow}>
          <Link
            className={analyzeStyles.reportLink}
            href={`/scans/${result.id}`}
          >
            View full report
          </Link>
        </div>
        <p className={analyzeStyles.resultStorageNote}>
          {buildStorageNote(result)}
        </p>
        {result.finding_details.length > 0 ? (
          <ul className={analyzeStyles.findingCards}>
            {result.finding_details.map((finding) => (
              <li className={analyzeStyles.findingCard} key={finding.message}>
                <div className={analyzeStyles.findingMeta}>
                  <span>{finding.category}</span>
                  <span className={analyzeStyles[`severity${finding.severity}`]}>
                    {finding.severity}
                  </span>
                </div>
                <p>{finding.message}</p>
                {finding.matched_text ? (
                  <p className={analyzeStyles.findingEvidence}>
                    Triggered by: <code>{finding.matched_text}</code>
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <ul className={analyzeStyles.findingsList}>
            {result.findings.map((finding) => (
              <li key={finding}>{finding}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function buildStorageNote(result: ScanResult) {
  if (result.is_saved) {
    return "This scan is saved in history.";
  }

  if (result.expires_at) {
    const expirationDate = new Date(result.expires_at).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric"
    });
    return `This scan is temporary and will expire on ${expirationDate} unless you save it permanently.`;
  }

  return "This scan is temporary. Feedback does not change its expiration.";
}
