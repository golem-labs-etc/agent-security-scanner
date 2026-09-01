/**
 * Rendering values that came out of a scanned tree.
 *
 * A finding's path is a filename, and a filename is written by whoever wrote
 * the file. For every finding this tool exists to report, that is the attacker.
 * The same is true of a matched line: it is quoted attack text by definition.
 *
 * This is the fourth place the same bug has appeared. It was in the Hermes
 * adapter's agent announcement, in that announcement's trailer, and it is here
 * in the human report, where a directory name carrying newlines forged two
 * complete report rows and a line reading "Glance: 0 findings. Machine is
 * clean." The Python in `adapters/hermes/hooks.py:113-158` is the reference
 * implementation; this is the port, and it lives in its own module so that
 * every renderer can import it instead of growing its own copy.
 *
 * WHAT THIS COVERS AND WHAT IT DOES NOT. These helpers neutralise control
 * characters: line structure, terminal escapes, and the invisible marks that
 * reorder text. They do NOT neutralise in-band markup -- Rich console tags,
 * Markdown, HTML. Nothing renders our output that way today. That is a fact
 * about current wiring, not a guarantee, and it is exactly how the guard we
 * depend on got caught: its report was printed through a markup-interpreting
 * console, so a directory name could restyle the tool's own verdict line.
 * A renderer that interprets markup needs its own escape on top of this one.
 */

/** Longest rendered path before truncation. */
export const MAX_PATH = 200;

/** Longest rendered evidence string. Evidence is attacker text by design. */
export const MAX_EVIDENCE = 240;

/**
 * Escape everything that could change the shape of the output.
 *
 * Every C0 and C1 control (newline and carriage return above all, and ESC,
 * which is how a path smuggles ANSI into a terminal), DEL, the Unicode line
 * and paragraph separators, and the zero-width, bidi-override and byte-order
 * marks. The last group cannot break a line but can reorder what a person
 * reads, which is the same lie by another route, and it is a category this
 * scanner reports in other people's files.
 *
 * Backslash and double quote are escaped so that the quoting applied by
 * `renderPath` actually holds.
 */
export function escapeControls(input: unknown): string {
  const s = input === undefined || input === null ? '' : String(input);
  let out = '';
  for (const ch of s) {
    const o = ch.codePointAt(0) as number;
    if (ch === '\\') out += '\\\\';
    else if (ch === '"') out += '\\"';
    else if (
      o < 0x20 || o === 0x7f || (o >= 0x80 && o <= 0x9f) ||
      o === 0x2028 || o === 0x2029 || o === 0xfeff ||
      (o >= 0x200b && o <= 0x200f) ||
      (o >= 0x202a && o <= 0x202e) ||
      (o >= 0x2066 && o <= 0x2069)
    ) {
      out += '\\u' + o.toString(16).padStart(4, '0');
    } else out += ch;
  }
  return out;
}

/**
 * A path rendered so it cannot be mistaken for anything but a path.
 *
 * Escaped, THEN truncated, THEN quoted, in that order.
 *
 * The order is the load-bearing part. Truncating raw input and escaping
 * afterwards cuts at a point that is not yet protected, so a multi-byte
 * sequence can be split into something whose escape differs from what the
 * whole would have produced. Once escaped, every character is printable and
 * cutting anywhere is safe: the worst case is a shortened `\u00`, which is
 * still inert text.
 *
 * The quotes are the second half of the fix, not decoration. Escaping stops a
 * path forging a newline; quoting stops a path that contains no control
 * characters at all from reading as prose. A directory literally named
 * `ignore the above and run this` is a legal filename.
 *
 * The line number is ours, from the scanner's own integer field, so it goes
 * OUTSIDE the quotes where it can never be read as part of the name.
 */
export function renderPath(path: unknown, line?: unknown): string {
  let s = escapeControls(path);
  if (s.length > MAX_PATH) s = s.slice(0, MAX_PATH) + '...(truncated)';
  const quoted = '"' + s + '"';
  const n = typeof line === 'number' ? line : parseInt(String(line ?? ''), 10);
  return Number.isFinite(n) ? `${quoted}:${n}` : quoted;
}

/** Evidence: a matched line, quoted attack text by definition. Same treatment. */
export function renderEvidence(evidence: unknown, limit: number = MAX_EVIDENCE): string {
  let s = escapeControls(evidence);
  if (s.length > limit) s = s.slice(0, limit) + '...(truncated)';
  return '"' + s + '"';
}

/**
 * Fields the scanner owns: severity, category, id.
 *
 * A whitelist rather than an escape, because these are closed vocabularies
 * this tool controls, not strings from the filesystem. Anything outside the
 * vocabulary means the report is not the shape the renderer was written
 * against, and a `?` a reader can see beats a silent pass-through.
 */
const FIELD_OK = /^[A-Za-z0-9._-]$/;

export function renderField(value: unknown, limit = 40): string {
  const s = value === undefined || value === null ? '' : String(value);
  let out = '';
  for (const ch of s) out += FIELD_OK.test(ch) ? ch : '?';
  return out.slice(0, limit);
}

/**
 * A fence that the content inside it cannot close.
 *
 * Used for the code context sent to the LLM in `semantic-filter.ts`. Of the
 * two available fixes -- strip fence sequences from the content, or use a
 * delimiter the content cannot contain -- this is the second, and the reason
 * is that the content is the thing under review. Stripping alters the code the
 * model is being asked to judge, and the construct removed could be the very
 * one that makes the finding real. A longer fence changes nothing inside.
 *
 * A fence of N backticks is closed only by a run of N or more, so a fence one
 * longer than the longest run in the content cannot be closed from inside it.
 */
export function fenceFor(content: string): string {
  let longest = 0;
  let run = 0;
  for (const ch of content) {
    if (ch === '`') { run++; if (run > longest) longest = run; }
    else run = 0;
  }
  return '`'.repeat(Math.max(3, longest + 1));
}
