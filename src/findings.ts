import { createHash } from "node:crypto";
import type { Finding } from "./model.js";
export type FindingInput = Omit<Finding, "id" | "fingerprint" | "status">;
export function finding(input: FindingInput, identity: string): Finding {
  const fingerprint = createHash("sha256")
    .update(
      JSON.stringify([
        input.ruleId,
        input.file,
        input.route ?? "",
        input.resource ?? "",
        identity,
      ]),
    )
    .digest("hex");
  return {
    ...input,
    id: `${input.ruleId}:${fingerprint.slice(0, 12)}`,
    fingerprint,
    status: "new",
  };
}
