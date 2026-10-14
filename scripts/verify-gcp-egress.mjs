import assert from "node:assert/strict";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";

function exactIps(cidrs, name) {
  assert.ok(Array.isArray(cidrs) && cidrs.length > 0, name + " must be nonempty");
  assert.equal(new Set(cidrs).size, cidrs.length, name + " has duplicates");
  for (const cidr of cidrs) {
    assert.ok(typeof cidr === "string" && cidr.endsWith("/32"), name + " requires exact /32 entries");
    const ip = cidr.slice(0, -3);
    assert.equal(isIP(ip), 4, name + " requires valid IPv4 addresses");
    const parts = ip.split(".").map(Number);
    assert.ok(
      parts[0] > 0 &&
        parts[0] < 224 &&
        parts[0] !== 10 &&
        parts[0] !== 127 &&
        parts[0] !== 169 &&
        parts[0] !== 192 &&
        !(parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) &&
        !(parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127),
      name + " contains a non-public address",
    );
  }
}

function isApplicable(rule) {
  return (
    rule.direction === "EGRESS" &&
    rule.disabled !== true &&
    (!Array.isArray(rule.targetTags) ||
      rule.targetTags.length === 0 ||
      rule.targetTags.includes("reaper-execution"))
  );
}

function exactRule(rule, name, ips, port) {
  assert.equal(rule.name, name);
  assert.equal(rule.direction, "EGRESS");
  assert.equal(rule.priority, 900);
  assert.deepEqual(rule.targetTags, ["reaper-execution"]);
  assert.deepEqual([...rule.destinationRanges].sort(), [...ips].sort());
  assert.deepEqual(rule.allowed, [{ IPProtocol: "tcp", ports: [port] }]);
  assert.ok(!rule.denied?.length);
}

export function assertCommercialEgressBoundary(
  { runner, dispatcher, firewalls },
  { targetCidrs, databaseCidrs },
) {
  exactIps(targetCidrs, "targetCidrs");
  exactIps(databaseCidrs, "databaseCidrs");
  assert.ok(targetCidrs.every((ip) => !databaseCidrs.includes(ip)));
  const template = runner?.template?.template;
  const dispatcherTemplate = dispatcher?.template?.template;
  assert.ok(template && dispatcherTemplate, "Cloud Run job templates are missing");
  assert.ok(template.serviceAccount && dispatcherTemplate.serviceAccount);
  assert.notEqual(
    template.serviceAccount,
    dispatcherTemplate.serviceAccount,
    "runner and dispatcher must have distinct service accounts",
  );
  const vpc = template.vpcAccess;
  assert.equal(vpc?.egress, "ALL_TRAFFIC", "runner must route ALL_TRAFFIC through VPC");
  assert.equal(vpc.networkInterfaces?.length, 1);
  const nic = vpc.networkInterfaces[0];
  assert.ok(
    nic.network === "reaper-execution" ||
      nic.network?.endsWith("/networks/reaper-execution"),
  );
  assert.ok(
    nic.subnetwork === "reaper-execution" ||
      nic.subnetwork?.endsWith("/subnetworks/reaper-execution"),
  );
  assert.ok(nic.tags?.includes("reaper-execution"));
  const env = Object.fromEntries((template.containers ?? []).flatMap((c) =>
    (c.env ?? []).filter((e) => typeof e.value === "string").map((e) => [e.name, e.value]),
  ));
  assert.equal(env.REAPER_CLOUD_RUN_NETWORK_ENFORCED, "1");
  assert.equal(env.REAPER_CLOUD_RUN_RESOURCE_ENFORCED, "1");
  assert.ok(Array.isArray(firewalls));
  const rules = firewalls.filter(
    (rule) =>
      isApplicable(rule) &&
      (rule.network === "reaper-execution" ||
        rule.network?.endsWith("/networks/reaper-execution")),
  );
  const deny = rules.find((rule) => rule.name === "reaper-runner-egress-deny");
  assert.ok(deny, "network-wide runner egress DENY is absent");
  assert.equal(deny.priority, 1000);
  assert.deepEqual(deny.targetTags, ["reaper-execution"]);
  assert.deepEqual(deny.destinationRanges, ["0.0.0.0/0"]);
  assert.deepEqual(deny.denied, [{ IPProtocol: "all" }]);
  assert.ok(!deny.allowed?.length);
  const target = rules.find((rule) => rule.name === "reaper-runner-target-https");
  const database = rules.find((rule) => rule.name === "reaper-runner-state-postgres");
  assert.ok(target && database, "required exact egress allow rules are absent");
  exactRule(target, "reaper-runner-target-https", targetCidrs, "443");
  exactRule(database, "reaper-runner-state-postgres", databaseCidrs, "5432");
  const approved = new Set([deny.name, target.name, database.name]);
  for (const rule of rules) {
    assert.ok(
      rule.priority > 1000 || approved.has(rule.name),
      "unexpected firewall rule can bypass runner egress DENY: " + rule.name,
    );
  }
  return {
    outcome: "CONFIGURATION_VERIFIED",
    limitation: "Cloud API configuration checks are not proof of packet-level enforcement or an independent security assessment.",
    runnerServiceAccount: template.serviceAccount,
    allowedTargetCount: targetCidrs.length,
    allowedDatabaseCount: databaseCidrs.length,
  };
}

async function cloudJson(url, token) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(url, {
      headers: { authorization: "Bearer " + token },
      redirect: "error",
      signal: controller.signal,
    });
    if (!response.ok) throw new Error("Cloud API request returned HTTP " + response.status);
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function main() {
  const project = process.env.REAPER_GCP_PROJECT_ID;
  const region = process.env.REAPER_GCP_REGION;
  const token = process.env.GOOGLE_OAUTH_ACCESS_TOKEN;
  if (!/^[a-z][a-z0-9-]{4,62}$/.test(project ?? ""))
    throw new Error("REAPER_GCP_PROJECT_ID is invalid");
  if (!/^[a-z0-9-]{2,32}$/.test(region ?? ""))
    throw new Error("REAPER_GCP_REGION is invalid");
  if (!token || token.length < 20)
    throw new Error("GOOGLE_OAUTH_ACCESS_TOKEN is required; cannot claim an offline cloud pass");
  const targetCidrs = (process.env.REAPER_APPROVED_TARGET_CIDRS ?? "").split(",").filter(Boolean);
  const databaseCidrs = (process.env.REAPER_APPROVED_DATABASE_CIDRS ?? "").split(",").filter(Boolean);
  exactIps(targetCidrs, "targetCidrs");
  exactIps(databaseCidrs, "databaseCidrs");
  const jobUrl = "https://run.googleapis.com/v2/projects/" + project + "/locations/" + region + "/jobs/";
  const [runner, dispatcher] = await Promise.all([
    cloudJson(jobUrl + "reaper-runner", token),
    cloudJson(jobUrl + "reaper-dispatcher", token),
  ]);
  const firewalls = [];
  let nextPageToken;
  do {
    const u = new URL("https://compute.googleapis.com/compute/v1/projects/" + project + "/global/firewalls");
    if (nextPageToken) u.searchParams.set("pageToken", nextPageToken);
    const page = await cloudJson(u.toString(), token);
    if (!Array.isArray(page.items) && page.items !== undefined)
      throw new Error("Firewall response is invalid");
    firewalls.push(...(page.items ?? []));
    nextPageToken = page.nextPageToken;
    if (firewalls.length > 10_000) throw new Error("Excessive firewall inventory");
  } while (nextPageToken);
  const evidence = assertCommercialEgressBoundary(
    { runner, dispatcher, firewalls },
    { targetCidrs, databaseCidrs },
  );
  process.stdout.write(JSON.stringify(evidence, null, 2) + "\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error("REAPER cloud preflight FAILED: " + error.message);
    process.exitCode = 2;
  });
}
