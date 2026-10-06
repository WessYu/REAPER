import { parse } from "pgsql-ast-parser";
/** Inspect constant SQL only. Parser failures are surfaced, never treated as safe. */
export function unrestrictedMutation(sql: string): {
  broad: boolean;
  unsupported: boolean;
} {
  try {
    const statements = parse(sql);
    return {
      broad: statements.some(
        (s) => (s.type === "update" || s.type === "delete") && !s.where,
      ),
      unsupported: false,
    };
  } catch {
    return { broad: false, unsupported: true };
  }
}
