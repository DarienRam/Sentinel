"use client";

import Link from "next/link";
import { useState } from "react";
import { SiteHeader } from "@/components/site-header";
import styles from "./page.module.css";

const consumerReports = [
  { year: 2017, amount: 2.7, label: "2.7M" },
  { year: 2018, amount: 3, label: "3.0M" },
  { year: 2019, amount: 3.2, label: "3.2M" },
  { year: 2020, amount: 4.7, label: "4.7M" },
  { year: 2021, amount: 5.7, label: "5.7M" },
  { year: 2022, amount: 5.1, label: "5.1M" },
  { year: 2023, amount: 5.4, label: "5.4M" },
  { year: 2024, amount: 6.5, label: "6.5M" },
];

const chartPoints = consumerReports.map((point, index) => ({
  ...point,
  x: 90 + index * (870 / (consumerReports.length - 1)),
  y: 245 - (point.amount / 7) * 185,
}));

export default function HomePage() {
  const [selectedYear, setSelectedYear] = useState(2024);
  const selectedPoint = consumerReports.find((point) => point.year === selectedYear) ?? consumerReports[consumerReports.length - 1];

  return (
    <main className={styles.page}>
      <SiteHeader />

      <section className={styles.hero}>
        <p className={styles.eyebrow}>Pause. Inspect. Decide with context.</p>
        <h1 className={styles.title}>Sentinel</h1>
        <p className={styles.description}>
          A clearer second opinion before you click, reply, or pay. Sentinel
          analyzes suspicious URLs, emails, and messages, then explains the
          risk signals it found in plain language.
        </p>
        <p className={styles.missionNote}>
          Sentinel is a tool to help you assess suspicious requests and make
          more informed decisions. Always verify unexpected requests through
          an official source and use your own judgment before taking action.
        </p>
        <div className={styles.actions}>
          <Link className={styles.primaryAction} href="/analyze">
            Start Analyzing
          </Link>
          <Link className={styles.secondaryAction} href="/dashboard">
            View Dashboard
          </Link>
        </div>
      </section>

      <section className={styles.workflow} aria-labelledby="how-it-works-title">
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>How Sentinel helps</p>
          <h2 id="how-it-works-title">Turn uncertainty into a safer next step.</h2>
        </div>
        <div className={styles.stepGrid}>
          <article className={styles.stepCard}>
            <span className={styles.stepNumber}>01</span>
            <h3>Share the suspicious content</h3>
            <p>Paste a URL, email, or message without opening a questionable link.</p>
          </article>
          <article className={styles.stepCard}>
            <span className={styles.stepNumber}>02</span>
            <h3>See the signals behind the score</h3>
            <p>Review the patterns Sentinel found instead of relying on an unexplained label.</p>
          </article>
          <article className={styles.stepCard}>
            <span className={styles.stepNumber}>03</span>
            <h3>Verify independently</h3>
            <p>Contact the organization using details you find yourself, not the link, number, or reply address in the message.</p>
          </article>
        </div>
      </section>

      <section className={styles.impactSection} aria-labelledby="impact-title">
        <div className={styles.impactCopy}>
          <p className={styles.eyebrow}>Why the pause matters</p>
          <h2 id="impact-title">Millions of consumer reports reach the FTC each year.</h2>
          <p>
            Select a year to explore reports received by the FTC’s Consumer
            Sentinel Network. It includes fraud, identity theft, and other
            consumer-protection concerns—not a count of every scam attempt.
          </p>
          <a
            className={styles.sourceLink}
            href="https://www.ftc.gov/reports/consumer-sentinel-network-data-book-2024"
            target="_blank"
            rel="noreferrer"
          >
            Source: Federal Trade Commission data ↗
          </a>
        </div>

        <div className={styles.chartCard}>
          <div className={styles.chartSummary} aria-live="polite">
            <span>FTC consumer reports in {selectedPoint.year}</span>
            <strong>{selectedPoint.label}</strong>
          </div>
          <svg className={styles.chart} viewBox="0 0 1000 310" role="img" aria-label="Interactive line chart of FTC Consumer Sentinel Network reports from 2017 to 2024">
            {[0, 2, 4, 6].map((value) => {
              const y = 245 - (value / 7) * 185;
              return (
                <g key={value}>
                  <line className={styles.chartGuide} x1="90" y1={y} x2="960" y2={y} />
                  <text className={styles.chartTickLabel} x="70" y={y + 6} textAnchor="end">
                    {value}M
                  </text>
                </g>
              );
            })}
            <line className={styles.chartAxis} x1="90" y1="45" x2="90" y2="245" />
            <line className={styles.chartAxis} x1="90" y1="245" x2="960" y2="245" />
            <text className={styles.chartAxisTitle} transform="rotate(-90)" x="-145" y="24" textAnchor="middle">
              Reports (millions)
            </text>
            <text className={styles.chartAxisTitle} x="525" y="306" textAnchor="middle">
              Year
            </text>
            <polyline
              className={styles.chartLine}
              points={chartPoints.map((point) => `${point.x},${point.y}`).join(" ")}
            />
            {chartPoints.map((point) => (
              <g key={point.year}>
                <circle
                  className={point.year === selectedYear ? styles.chartPointActive : styles.chartPoint}
                  cx={point.x}
                  cy={point.y}
                  r={point.year === selectedYear ? 13 : 9}
                />
                <text className={styles.chartYearLabel} x={point.x} y="275" textAnchor="middle">
                  {String(point.year).slice(2)}
                </text>
              </g>
            ))}
          </svg>
          <div className={styles.yearButtons}>
            {consumerReports.map((point) => (
              <button
                aria-pressed={point.year === selectedYear}
                className={point.year === selectedYear ? styles.yearButtonActive : styles.yearButton}
                key={point.year}
                onClick={() => setSelectedYear(point.year)}
                type="button"
              >
                {point.year}
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className={styles.featureGrid}>
        <article className={styles.featureCard}>
          <h2 className={styles.featureTitle}>Explainable Scoring</h2>
          <p className={styles.featureBody}>
            Every scan returns a score and plain-language reasoning so the
            result is useful, not mysterious.
          </p>
        </article>
        <article className={styles.featureCard}>
          <h2 className={styles.featureTitle}>Decision Support</h2>
          <p className={styles.featureBody}>
            Each report pairs its signals with a recommended next step, helping
            you decide whether to pause, verify independently, or take no
            immediate action.
          </p>
        </article>
        <article className={styles.featureCard}>
          <h2 className={styles.featureTitle}>Privacy-Conscious</h2>
          <p className={styles.featureBody}>
            Temporary scans expire by default, while signed-in users control
            what stays in their history.
          </p>
        </article>
        <article className={styles.featureCard}>
          <h2 className={styles.featureTitle}>Feedback Matters</h2>
          <p className={styles.featureBody}>
            Mark a result as correct or incorrect and add context. That review
            record stays with the report for your review; it does not automatically change scoring.
          </p>
        </article>
      </section>
    </main>
  );
}
