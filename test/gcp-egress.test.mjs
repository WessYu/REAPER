import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { assertCommercialEgressBoundary } from "../scripts/verify-gcp-egress.mjs";

const targetCidrs = ["8.8.8.8/32"];
const databaseCidrs = ["1.1.1.1/32"];

function fixture() {
  const runner = {
    template: {
      template: {
        serviceAccount: "runner@reaper.iam.gserviceaccount.com",
        vpcAccess: {
          egress: "ALL_TRAFFIC",
          networkInterfaces: [
            {
              network: "reaper-execution",
              subnetwork: "reaper-execution",
              tags: ["reaper-execution"],
            },
          ],
        },
        containers: [
          {
            env: [
              { name: "REAPER_CLOUD_RUN_NETWORK_ENFORCED", value: "1" },
              { name: "REAPER_CLOUD_RUN_RESOURCE_ENFORCED", value: "1" },
            ],
          },
        ],
      },
    },
  };
  const dispatcher = {
    template: {
      template: {
        serviceAccount: "dispatcher@reaper.iam.gserviceaccount.com",
      },
    },
  };
  const common = {
    direction: "EGRESS",
    network: "reaper-execution",
    targetTags: ["reaper-execution"],
  };
  const firewalls = [
    {
      ...common,
      name: "reaper-runner-egress-deny",
      priority: 1000,
      destinationRanges: ["0.0.0.0/0"],
      denied: [{ IPProtocol: "all" }],
    },
    {
      ...common,
      name: "reaper-runner-target-https",
      priority: 900,
      destinationRanges: targetCidrs,
      allowed: [{ IPProtocol: "tcp", ports: ["443"] }],
    },
    {
      ...common,
      name: "reaper-runner-state-postgres",
      priority: 900,
      destinationRanges: databaseCidrs,
      allowed: [{ IPProtocol: "tcp", ports: ["5432"] }],
    },
  ];
  return { runner, dispatcher, firewalls };
}

function verify(fixtures, expected = { targetCidrs, databaseCidrs }) {
  return assertCommercialEgressBoundary(fixtures, expected);
}

test("GCP preflight accepts only explicitly scoped egress controls", () => {
  const result = verify(fixture());
  assert.equal(result.outcome, "CONFIGURATION_VERIFIED");
  assert.equal(result.allowedTargetCount, 1);
});

test("GCP preflight rejects missing VPC routing and forged attestation", () => {
  const incomplete = fixture();
  delete incomplete.runner.template.template.vpcAccess;
  assert.throws(() => verify(incomplete), /ALL_TRAFFIC/);
  const fake = fixture();
  fake.runner.template.template.containers[0].env[0].value = "0";
  assert.throws(() => verify(fake), /'0'|"0"|1/);
});

test("GCP preflight rejects broad target scope and shared credentials", () => {
  assert.throws(
    () => verify(fixture(), { targetCidrs: ["0.0.0.0/0"], databaseCidrs }),
    /32/,
  );
  const shared = fixture();
  shared.dispatcher.template.template.serviceAccount =
    shared.runner.template.template.serviceAccount;
  assert.throws(() => verify(shared), /distinct service accounts/);
});

test("GCP preflight refuses firewall bypass and disabled deny", () => {
  const override = fixture();
  override.firewalls.push({
    direction: "EGRESS",
    network: "reaper-execution",
    name: "unexpected-allow-all",
    priority: 800,
    allowed: [{ IPProtocol: "all" }],
  });
  assert.throws(() => verify(override), /unexpected firewall rule/);
  const disabled = fixture();
  disabled.firewalls[0].disabled = true;
  assert.throws(() => verify(disabled), /DENY is absent/);
});

test("Terraform defaults to fail-closed until a complete pilot allowlist exists", async () => {
  const root = new URL("../infra/gcp/", import.meta.url);
  const [vars, runner, network] = await Promise.all(
    ["variables.tf", "main.tf", "network.tf"].map((name) =>
      readFile(new URL(name, root), "utf8"),
    ),
  );
  assert.match(vars, /variable "network_egress_enforced"/);
  assert.match(vars, /default\s*= false/);
  assert.match(runner, /egress = "ALL_TRAFFIC"/);
  assert.match(runner, /allowed_runner_database_cidrs/);
  assert.match(runner, /allowed_runner_target_cidrs/);
  assert.match(network, /resource "google_compute_firewall" "runner_deny_all"/);
  assert.match(network, /resource "google_compute_firewall" "runner_target_https"/);
  assert.match(network, /resource "google_compute_firewall" "runner_postgres"/);
});
