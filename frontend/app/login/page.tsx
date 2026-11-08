"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import {
  loginUser,
} from "../../lib/api";
import { SiteHeader } from "@/components/site-header";
import { useAuthSession } from "@/components/auth-provider";
import styles from "../route-shell.module.css";

export default function LoginPage() {
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { currentUser, isLoading, setAuthenticatedSession } = useAuthSession();

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      const authToken = await loginUser({
        login,
        password
      });

      setAuthenticatedSession(authToken);
      setLogin("");
      setPassword("");
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : "Sentinel could not log in with those credentials."
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className={styles.page}>
      <SiteHeader />

      <section className={styles.content}>
        <div className={styles.panel}>
          <p className={styles.eyebrow}>Authentication</p>
          <h1 className={styles.title}>Log in to Sentinel</h1>
          <p className={styles.description}>
            Log in to securely access your account, scan history, and feedback.
          </p>

          {isLoading ? (
            <div className={styles.status}>Checking session...</div>
          ) : null}

          {currentUser ? (
            <div className={styles.sessionCard}>
              <span>Current session</span>
              <strong>{currentUser.username}</strong>
              <span>{currentUser.email}</span>
              <Link className={styles.primaryAction} href="/dashboard">
                Open dashboard
              </Link>
            </div>
          ) : (
            <form className={styles.form} onSubmit={handleSubmit}>
              <label className={styles.field}>
                Username or email
                <input
                  autoComplete="username"
                  maxLength={255}
                  onChange={(event) => setLogin(event.target.value)}
                  placeholder="username or name@example.com"
                  required
                  value={login}
                />
              </label>

              <label className={styles.field}>
                Password
                <input
                  autoComplete="current-password"
                  minLength={8}
                  maxLength={128}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Your password"
                  required
                  type="password"
                  value={password}
                />
              </label>

              <button className={styles.submitButton} disabled={isSubmitting}>
                {isSubmitting ? "Logging in..." : "Log in"}
              </button>
            </form>
          )}

          {error ? <p className={styles.error}>{error}</p> : null}
        </div>
      </section>
    </main>
  );
}
