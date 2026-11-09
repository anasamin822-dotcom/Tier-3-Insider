# Tier-3 Insider

A student-review demo with moderated submissions and a private admin dashboard.

- Public reviews and senior profiles: read-only projections from Supabase.
- Submissions: a bounded queue; they do not publish themselves.
- Admin: Supabase Auth plus a server-side administrator allowlist.
- Identity documents: private Supabase Storage, with short-lived admin links.
- Payments and private chat are paused. The member email forms are demo preferences, not authentication.

## Backend

The SQL under `supabase/` records the schema and policies. Initial setup order:

1. `migration.sql`
2. `queue-limits.sql`
3. `hardening.sql`
4. `storage.sql`

An administrator must be added to `public.t3i_admins` through a trusted server or the Supabase dashboard. Creating an Auth account does not make it an admin.

Only the public publishable key belongs in the frontend. Never add service keys, database passwords or migration credentials to this repository.

The former JSONBin master key was exposed in the old source and remains in Git history. It must be treated as compromised. This version no longer uses JSONBin.

## Limits

This is not a production paid-membership service. Public submissions and uploads can still attract spam; the queues and file sizes are bounded, but a production launch needs stronger anti-abuse controls. Upvotes are a convenience count, not verified unique votes. Free Supabase projects can pause after inactivity.
