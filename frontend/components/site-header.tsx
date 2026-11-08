"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { useAuthSession } from "@/components/auth-provider";
import styles from "@/app/route-shell.module.css";

type NavLink = {
  href: string;
  label: string;
};

const primaryLinks: NavLink[] = [
  { href: "/analyze", label: "Analyze" },
  { href: "/dashboard", label: "Dashboard" },
  { href: "/learn", label: "Safety guide" }
];

const guestLinks: NavLink[] = [
  { href: "/login", label: "Login" },
  { href: "/register", label: "Register" }
];

export function SiteHeader() {
  const pathname = usePathname();
  const { clearSession, currentUser, isLoading, sessionError } = useAuthSession();

  return (
    <header className={styles.nav}>
      <Link className={styles.brand} href="/">
        Sentinel
      </Link>

      <div className={styles.navCluster}>
        <nav className={styles.navLinks} aria-label="Primary navigation">
          {primaryLinks.map((link) => (
            <Link
              aria-current={pathname === link.href ? "page" : undefined}
              className={styles.navLink}
              href={link.href}
              key={link.href}
            >
              {link.label}
            </Link>
          ))}

          {!currentUser
            ? guestLinks.map((link) => (
                <Link
                  aria-current={pathname === link.href ? "page" : undefined}
                  className={styles.navLink}
                  href={link.href}
                  key={link.href}
                >
                  {link.label}
                </Link>
              ))
            : null}
        </nav>

        {isLoading ? (
          <div className={styles.sessionBadge}>Checking session...</div>
        ) : currentUser ? (
          <div className={styles.sessionControls}>
            <div className={styles.sessionBadge}>
              <span>Signed in</span>
              <strong>{currentUser.username}</strong>
            </div>
            <button className={styles.navButton} onClick={clearSession} type="button">
              Log out
            </button>
          </div>
        ) : null}
      </div>
      {sessionError ? <p role="alert" className={styles.error}>{sessionError}</p> : null}
    </header>
  );
}
