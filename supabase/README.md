# Database and authentication

Production uses Supabase Auth for member email codes and sign-in links. Browser storage is not an identity or an access grant.

Existing database changes are in `migration.sql`, `hardening.sql`, `queue-limits.sql`, and `storage.sql`. The member-auth changes were applied in this order:

1. `member-auth.sql`
2. `member-auth-hardening.sql`

These migrations have already been applied to production. Do not rerun the initial table-creation migration on an existing database.

## Private chat

- All member tables have RLS enabled and deny direct anonymous or member access. Security-definer RPCs check the authenticated caller and participant relationship.
- Registration stamps the verified email and user ID on the server. Admin approval publishes and links the senior account in one transaction.
- A fresher needs an admin-granted `senior_chat` entitlement. A senior can only see and reply to conversations for their linked profile.
- Seed mentor profiles are labeled samples and cannot receive chats until linked to a real account.
- Messages are limited to 2,000 characters and displayed as escaped text.
- Email links are consumed on arrival and authentication tokens are removed from the address bar. Sessions refresh through Supabase Auth and logout clears the local identity immediately.

## Payments

Payments remain paused, including the submission RPC and legacy submission path. The app must not display a receiving UPI ID or invite payment until the receiving account and verification process are ready. Submitting a transaction ID must never grant access. The server-side admin grant/revoke functions exist for authorized administration; they are not payment verification.

## Verification on November 11, 2026

25 backend checks passed, including anonymous and direct-table denial, identity stamping, admin-only approval and grants, entitlement enforcement, cross-user isolation, linked senior replies, input limits, and payment bypass denial.

Headless Chrome checks at 390px width passed: forged localStorage grants no access, verified sessions restore, chat sends and reads, malicious HTML stays plain text, mobile layout has no horizontal page overflow, payment instructions are absent, logout clears state, and no JavaScript errors occur. A real emailed sign-in link was also verified on the deployed GitHub Pages site.

Temporary test accounts, grants, conversations, and mentor profiles were removed after verification. Email delivery uses the existing Gmail SMTP setup, without a paid SMTP plan. Supabase and Gmail limits still apply; this is not an unlimited-email setup.
