# UI repair scope

Baseline: e8550bc. Prior baseline: 8ca7bcb. No backend/auth/crypto changes planned.

Already repaired in baseline: inactive deploy bar display, environment-scoped drafts, cancelled new secret insertion, draft edit/delete controls, secret filter no-match, field labels and basic modal focus trap.

Implemented repair targets:
- Mobile navigation and organisation selector remain reachable at 390px; no page-level horizontal overflow; tables scroll within a labeled region.
- App cards and search are keyboard-native controls; visible focus, sufficient foreground contrast, reduced motion, adequate touch targets.
- Every modal has a name, initial focus, escape and return focus; search overlay has equivalent behavior.
- Failed reads display actionable errors, not empty data. App filtering distinguishes no results. Stale loads cannot overwrite a new scope.
- Clipboard failure reports failure; successful feedback follows completed write.
- Search cannot navigate to the wrong environment. Current API returns names only (main.rs:456-468); do not invent IDs or silently guess an ambiguous result.
- Keep existing security/auth flows and independent UI tests intact.

## Verification

- Node UI suites: 27 passed, 0 failed, 0 skipped. The seven added cases first produced six intended failures and one passing clipboard guard.
- Inline JavaScript syntax and git diff --check passed.
- Independent source review found three additional issues: search could change environment beneath an editor, deploy completion could leave stale data after an away/back navigation, and result resolution could lose palette focus. All three were fixed; the existing suites passed again. Dedicated delayed-response tests were not added.
- Desktop and mobile app-empty-state screenshots passed visual review. Mobile document scrollWidth equaled clientWidth (375px at a 390px viewport), both on apps and the environment page.
- Browser smoke exercised disposable account sign-in, app creation, and opening its default environment. Browser click transport was unreliable; some actions used DOM activation. This does not establish native keyboard behavior.
- Full-page environment capture had a repeated-navigation artifact. Its lower-page visual acceptance remains blocked. Populated tables, every settings/access/integration state, and complete keyboard traversal were not visually accepted.
- Rust build, clippy, and backend suites were not run for this UI-only patch. Preview served the exact UI source with an existing local backend binary, not a freshly compiled full application.
- Changes remain on improve/web-ui-ux in the isolated worktree. No merge, commit, push or deployment was performed.

Competitor reference patterns: Phase staged edits (https://docs.phase.dev/console/secrets), Infisical environment context (https://infisical.com/docs/documentation/platform/secrets-mgmt/project.md), structured audit investigation (https://infisical.com/docs/documentation/platform/audit-logs). Documentation evidence only; no claim of visual parity.
