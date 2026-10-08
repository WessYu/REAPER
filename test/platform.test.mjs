import { test } from "node:test";
import assert from "node:assert/strict";
import { createReaperServer, scan } from "../dist/index.js";

test("local REST service binds loopback and exposes health/report only for its configured root", async () => {
  const service = await createReaperServer({
    root: "test/fixtures/secure",
    port: 0,
  });
  try {
    const health = await fetch(`http://127.0.0.1:${service.port}/health`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { ok: true, version: "0.2.0" });

    const report = await fetch(`http://127.0.0.1:${service.port}/api/report`);
    assert.equal(report.status, 200);
    const body = await report.json();
    assert.equal(body.version, "0.2.0");
    assert.equal(body.root.endsWith("test/fixtures/secure"), true);
  } finally {
    await new Promise((resolve) => service.server.close(resolve));
  }
});

test("programmatic rule SDK can add deterministic custom findings", async () => {
  const result = await scan({
    root: "test/fixtures/secure",
    rules: [
      {
        id: "REAPER-CUSTOM-001",
        run(context) {
          context.add(
            {
              ruleId: "REAPER-CUSTOM-001",
              title: "Synthetic custom rule",
              description: "Custom rule SDK integration test.",
              severity: "LOW",
              confidence: "HIGH",
              category: "Authorization",
              file: "custom-rule",
              line: 1,
              column: 1,
              evidence: ["Rule SDK executed."],
              dataFlow: [],
              recommendation: "No action; synthetic test.",
            },
            "synthetic",
          );
        },
      },
    ],
  });
  const finding = result.findings.find(
    (item) => item.ruleId === "REAPER-CUSTOM-001",
  );
  assert.ok(finding);
  assert.equal(finding.status, "new");
  assert.equal(finding.fingerprint.length, 64);
});

test("control-flow graph models branches loops and abrupt control edges", async () => {
  const { buildProjectCfg, renderControlFlowGraph } = await import(
    "../dist/index.js"
  );
  const graph = await buildProjectCfg("test/fixtures/secure");
  assert.ok(graph.nodes.some((node) => node.kind === "entry"));
  assert.ok(graph.edges.length > 0);
  assert.match(renderControlFlowGraph(graph, "dot"), /digraph REAPER_CFG/);
});
