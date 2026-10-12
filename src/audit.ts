import { createHash } from "node:crypto";
import type { AttackAuditEvent, ScanResult } from "./model.js";

export interface AttackAuditVerification {
  valid: boolean;
  events: number;
  finalHash: string;
  errors: string[];
}

function eventHash(previousHash: string, event: AttackAuditEvent): string {
  const { hash: _hash, ...base } = event;
  return createHash("sha256")
    .update(previousHash)
    .update(JSON.stringify(base))
    .digest("hex");
}

export function verifyAttackAudit(
  result: ScanResult,
): AttackAuditVerification {
  if (!result.attack)
    return {
      valid: false,
      events: 0,
      finalHash: "",
      errors: ["Report does not contain an active-security audit trail."],
    };
  const errors: string[] = [];
  let previousHash = "";
  for (let index = 0; index < result.attack.audit.length; index++) {
    const event = result.attack.audit[index]!;
    if (event.sequence !== index + 1)
      errors.push(
        `Audit event ${index + 1} has sequence ${event.sequence}; expected ${index + 1}.`,
      );
    if (event.previousHash !== previousHash)
      errors.push(`Audit event ${event.sequence} previousHash does not match.`);
    const expected = eventHash(previousHash, event);
    if (event.hash !== expected)
      errors.push(`Audit event ${event.sequence} hash does not match.`);
    previousHash = event.hash;
  }
  if (result.attack.auditHash !== previousHash)
    errors.push("Attack summary auditHash does not match the final event.");
  return {
    valid: errors.length === 0,
    events: result.attack.audit.length,
    finalHash: previousHash,
    errors,
  };
}
