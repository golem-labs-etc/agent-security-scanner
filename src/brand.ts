/**
 * Glance scanner — the brand mark.
 *
 * WHY THIS FILE IS A DUPLICATE, AND MUST STAY ONE.
 *
 * Its twin is `src/guard/brand.ts` in the private glance-guard repo. The two
 * hold the same constants and cannot share code: this package is public and
 * MIT, that one is private and unlicensed, and importing across the boundary
 * would mean either publishing the guard or vendoring it here. Both are worse
 * than four duplicated lines.
 *
 * So the invariant is social, not mechanical: if the mark changes, it changes
 * in both files, in the same session. There is no build step that will catch a
 * drift, which is exactly why this comment is here.
 *
 * The scanner has no `[Glance]` token to sit in front of. That token is
 * element 1 of the guard's spec 6.4 block format, a machine-checkable contract
 * for text delivered to an agent. Scanner output is a report a person reads,
 * so the mark stands alone here — decoration with nothing to decorate.
 */

/** The mark. U+1F440, Emoji_Presentation, no variation selector wanted. */
export const MARK = '\u{1F440}';

/** Deny tier. Unused in the scanner today; present so the twin files match. */
export const MARK_DENY = '\u{1F440}\u{1F534}';
