"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { SiteHeader } from "@/components/site-header";
import { useAuthSession } from "@/components/auth-provider";
import { loginUser, registerUser, UserPublic } from "../../lib/api";
import styles from "../route-shell.module.css";

export default function RegisterPage() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [createdUser, setCreatedUser] = useState<UserPublic | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { setAuthenticatedSession } = useAuthSession();

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setCreatedUser(null);
    setIsSubmitting(true);

    try {
      const user = await registerUser({
        username,
        email,
        password
      });
      const authToken = await loginUser({
        login: email,
        password
      });

      setAuthenticatedSession(authToken);
      setCreatedUser(user);
      setUsername("");
      setEmail("");
      setPassword("");
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : "Sentinel could not create that account."
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
          <h1 className={styles.title}>Create an account</h1>
          <p className={styles.description}>
            Register an analyst profile so Sentinel can start connecting scans,
            feedback, and future risk history to a real user account.
          </p>

          <form className={styles.form} onSubmit={handleSubmit}>
            <label className={styles.field}>
              Username
              <input
                autoComplete="username"
                minLength={3}
                maxLength={50}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="your_username"
                required
                value={username}
              />
              <span>Use letters, numbers, underscores, or hyphens.</span>
            </label>

            <label className={styles.field}>
              Email
              <input
                autoComplete="email"
                maxLength={255}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="name@example.com"
                required
                type="email"
                value={email}
              />
            </label>

            <label className={styles.field}>
              Password
              <input
                autoComplete="new-password"
                minLength={8}
                maxLength={128}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="At least 8 characters"
                required
                type="password"
                value={password}
              />
            </label>

            <button className={styles.submitButton} disabled={isSubmitting}>
              {isSubmitting ? "Creating account..." : "Create account"}
            </button>
          </form>

          {error ? <p className={styles.error}>{error}</p> : null}
          {createdUser ? (
            <div className={styles.success}>
              Account created for <strong>{createdUser.username}</strong>. You
              are logged in for this browser session.{" "}
              <Link href="/dashboard">Go to your dashboard.</Link>
            </div>
          ) : null}
        </div>
      </section>
    </main>
  );
}
