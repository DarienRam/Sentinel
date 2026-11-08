import Link from "next/link";

import { SiteHeader } from "@/components/site-header";
import styles from "./page.module.css";

const signalGroups = [
  {
    name: "Pressure tactics",
    examples: "Urgent deadlines, threats, secrecy, or a request to act immediately.",
    action: "Pause. A legitimate organization will give you a safe way to verify.",
  },
  {
    name: "Account and credential requests",
    examples: "Requests for passwords, one-time codes, sign-ins, or account recovery details.",
    action: "Never share a password or verification code. Open the real app yourself instead.",
  },
  {
    name: "Link and sender clues",
    examples: "Lookalike domains, unusual endings, plain HTTP, or a sender that does not match the claim.",
    action: "Do not use the link or contact details in the message to verify it.",
  },
  {
    name: "Money and job scams",
    examples: "Unexpected payment changes, gift-card requests, easy remote work, or unusually high pay.",
    action: "Verify through the company’s official careers, billing, or support channel.",
  },
];

const safetySteps = [
  ["1", "Pause", "Urgency is a tactic. Give yourself time before clicking, replying, or paying."],
  ["2", "Inspect", "Look at the sender, destination, request, and the context you already have."],
  ["3", "Verify", "Find an official site, app, or phone number yourself and contact the organization there."],
];

export default function LearnPage() {
  return (
    <main className={styles.page}>
      <SiteHeader />

      <section className={styles.hero}>
        <p className={styles.eyebrow}>Safety guide</p>
        <h1>Know the signals. Choose a safer next step.</h1>
        <p>
          Sentinel is designed to help you spot patterns worth investigating.
          It is not a replacement for context, verification, or your own judgment.
        </p>
        <div className={styles.actions}>
          <Link className={styles.primaryAction} href="/analyze">Analyze suspicious content</Link>
          <a className={styles.secondaryAction} href="#signals">Explore signal categories</a>
        </div>
      </section>

      <section className={styles.process} aria-labelledby="process-title">
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>A safer response</p>
          <h2 id="process-title">Pause, inspect, then verify independently.</h2>
        </div>
        <div className={styles.processFigure} aria-label="Three step verification process">
          {safetySteps.map(([number, title, body], index) => (
            <article className={styles.processStep} key={title}>
              <span>{number}</span>
              <h3>{title}</h3>
              <p>{body}</p>
              {index < safetySteps.length - 1 ? <i aria-hidden="true" /> : null}
            </article>
          ))}
        </div>
      </section>

      <section className={styles.signalSection} id="signals" aria-labelledby="signals-title">
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>What Sentinel looks for</p>
          <h2 id="signals-title">Signals are clues, not proof on their own.</h2>
          <p>Several related clues together deserve more caution than a single generic word or phrase.</p>
        </div>
        <div className={styles.signalGrid}>
          {signalGroups.map((group, index) => (
            <article className={styles.signalCard} key={group.name}>
              <span className={styles.signalNumber}>0{index + 1}</span>
              <h3>{group.name}</h3>
              <p><strong>Examples:</strong> {group.examples}</p>
              <p className={styles.actionText}><strong>Safer next step:</strong> {group.action}</p>
            </article>
          ))}
        </div>
      </section>

      <section className={styles.examples} aria-labelledby="examples-title">
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Practice the pause</p>
          <h2 id="examples-title">A quick way to read a suspicious request.</h2>
        </div>
        <div className={styles.exampleGrid}>
          <article className={styles.exampleCard}>
            <p className={styles.exampleLabel}>Message example</p>
            <blockquote>“Delivery notice: We could not deliver your package. Update your address today to avoid return to sender.”</blockquote>
            <div className={styles.tagRow}><span>Urgency</span><span>Call to action</span><span>Link risk</span></div>
            <p>Do not use the text’s link. Check an expected delivery through the retailer or carrier’s official app or site.</p>
          </article>
          <article className={styles.exampleCard}>
            <p className={styles.exampleLabel}>Email example</p>
            <blockquote>“Your account will be limited today. Sign in now to restore access.”</blockquote>
            <div className={styles.tagRow}><span>Urgency</span><span>Account pressure</span><span>Call to action</span></div>
            <p>Open the service’s official app or type its known address yourself. Do not use the email’s link.</p>
          </article>
        </div>
      </section>

      <aside className={styles.reminder}>
        <div>
          <p className={styles.eyebrow}>Remember</p>
          <h2>A low score is not a guarantee that something is safe.</h2>
          <p>Use Sentinel as one piece of your decision. Unexpected requests should still be verified through an independent, official path.</p>
        </div>
        <Link className={styles.primaryAction} href="/analyze">Start a scan</Link>
      </aside>
    </main>
  );
}
