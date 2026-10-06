import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { scan, readConfig, report, fails } from "../dist/index.js";
const resources = {
  order: { ownership: ["userId"], tenant: ["organizationId"] },
};
async function source(code, fn, config = { resources }) {
  const root = await mkdtemp(path.join(tmpdir(), "reaper-test-"));
  try {
    await writeFile(path.join(root, "routes.ts"), code);
    return await fn(await scan({ root, config }), root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
const prefix = `import express from 'express'; import {PrismaClient} from '@prisma/client'; import {Pool} from 'pg'; const app=express(); const prisma=new PrismaClient(); const pool=new Pool();\n`;
test("cross-file vulnerable fixture preserves source, propagation and sink", async () => {
  const r = await scan({ root: "test/fixtures/vulnerable" });
  assert.deepEqual(r.findings.map((f) => f.ruleId).sort(), [
    "REAPER-AUTH-001",
    "REAPER-SQL-001",
    "REAPER-TENANT-001",
  ]);
  assert.equal(r.metrics.routes, 2);
  assert.equal(r.metrics.sinks, 2);
  const sql = r.findings.find((f) => f.ruleId === "REAPER-SQL-001");
  assert.equal(sql.dataFlow[0].file, "routes.ts");
  assert.equal(sql.dataFlow.at(-1).file, "repository.ts");
  assert.ok(sql.dataFlow.some((e) => e.kind === "propagation"));
  assert.equal(sql.route, "GET /search");
});
test("secure fixture: principal scopes, bound SQL and tagged SQL", async () => {
  const r = await scan({ root: "test/fixtures/secure" });
  assert.deepEqual(r.findings, []);
  assert.equal(r.metrics.routes, 3);
  assert.equal(r.metrics.sinks, 3);
});
test("request-supplied owner and tenant are not trusted", async () =>
  source(
    prefix +
      `app.get('/a',(req)=>prisma.order.findUnique({where:{id:req.params.id,userId:req.query.user,organizationId:req.query.org}}));`,
    (r) => assert.equal(r.findings.length, 2),
  ));
test("unknown model names do not establish ownership", async () =>
  source(
    prefix +
      `app.get('/a',(req)=>prisma.unknown.findUnique({where:{id:req.params.id}}));`,
    (r) => assert.equal(r.findings.length, 0),
  ));
test("lookalike unrelated query method is not treated as a DB driver", async () =>
  source(
    `import express from 'express';const app=express(); const search={query: x=>x};app.get('/a', req=>search.query(req.query.q));`,
    (r) => assert.equal(r.findings.length, 0),
  ));
test("OR needs all alternatives constrained; AND needs one", async () => {
  await source(
    prefix +
      `app.get('/a',(req)=>prisma.order.findUnique({where:{id:req.params.id,OR:[{userId:req.user.id},{id:req.params.id}]}}));`,
    (r) => assert.ok(r.findings.some((f) => f.category === "Authorization")),
  );
  await source(
    prefix +
      `app.get('/a',(req)=>prisma.order.findUnique({where:{id:req.params.id,AND:[{userId:req.user.id},{organizationId:req.user.organizationId}]}}));`,
    (r) => assert.equal(r.findings.length, 0),
  );
});
test("branch reassignment preserves potential taint", async () =>
  source(
    prefix +
      `app.get('/a',(req)=>{let q='SELECT 1';if(req.query.mode){q=req.query.q;}return pool.query(q);});`,
    (r) =>
      assert.equal(
        r.findings.filter((f) => f.category === "SQL Safety").length,
        1,
      ),
  ));
test("shadowed symbols do not taint outer values", async () =>
  source(
    prefix +
      `app.get('/a',(req)=>{const q='SELECT 1'; {const q=req.query.q;} return pool.query(q);});`,
    (r) => assert.equal(r.findings.length, 0),
  ));
test("dead statements after unconditional return are not analyzed", async () =>
  source(
    prefix + `app.get('/a',(req)=>{return 1; pool.query(req.query.q);});`,
    (r) => assert.equal(r.findings.length, 0),
  ));
test("unsupported control flow produces incomplete diagnostics", async () =>
  source(
    prefix +
      `app.get('/a',(req)=>{while(req.query.q){pool.query(req.query.q);}});`,
    (r) => assert.ok(r.diagnostics.length),
  ));
test("fingerprints survive blank line changes and baseline gates only new findings", async () => {
  const code = prefix + `app.get('/a',(req)=>pool.query(req.query.q));`;
  await source(code, async (first, root) => {
    await writeFile(path.join(root, "routes.ts"), "\n\n" + code);
    const second = await scan({
      root,
      baseline: first.findings.map((f) => f.fingerprint),
    });
    assert.equal(first.findings[0].fingerprint, second.findings[0].fingerprint);
    assert.equal(fails(second.findings, "high"), false);
  });
});
test("suppression requires a rule and meaningful reason", async () =>
  source(
    prefix +
      `app.get('/a',(req)=>{\n// reaper-ignore REAPER-SQL-001 -- reason: reviewed fixture for integration tests\nreturn pool.query(req.query.q);\n});`,
    (r) => assert.equal(r.findings[0].status, "suppressed"),
  ));
test("config is literal data and cannot execute code", async () =>
  source("", async (_r, root) => {
    const file = path.join(root, "reaper.config.ts");
    await writeFile(
      file,
      `export default (()=>{throw new Error('executed')})()`,
    );
    await assert.rejects(() => readConfig(file), /literal data/);
    await writeFile(
      file,
      `export default {resources:{order:{ownership:['userId']}}} as const`,
    );
    assert.deepEqual((await readConfig(file)).resources.order.ownership, [
      "userId",
    ]);
    await writeFile(file, `export default {typo:123}`);
    await assert.rejects(() => readConfig(file), /Unknown config/);
  }));
test("reports contain evidence without raw source snippets or request secrets", async () =>
  source(
    prefix + `app.get('/a',(req)=>pool.query('secret-literal-'+req.query.q));`,
    (r) => {
      assert.ok(!report(r, "json").includes("secret-literal"));
      assert.equal(JSON.parse(report(r, "sarif")).version, "2.1.0");
      assert.ok(report(r, "markdown").startsWith("# REAPER"));
      assert.throws(() => report(r, "xml"));
    },
  ));
test("parsed UPDATE and DELETE without WHERE are review candidates", async () => {
  await source(
    prefix + `app.get('/a',()=>pool.query('DELETE FROM orders'));`,
    (r) => assert.equal(r.findings[0].ruleId, "REAPER-SQL-002"),
  );
  await source(
    prefix +
      `app.get('/a',(req)=>pool.query('DELETE FROM orders WHERE id=$1',[req.params.id]));`,
    (r) => assert.equal(r.findings.length, 0),
  );
});
test("pg query config object binds values separately from text", async () =>
  source(
    prefix +
      `app.get('/a',(req)=>pool.query({text:'SELECT * FROM orders WHERE id=$1',values:[req.params.id]}));`,
    (r) => assert.equal(r.findings.length, 0),
  ));
test("principal from wrong domain does not establish tenant isolation", async () =>
  source(
    prefix +
      `app.get('/a',(req)=>prisma.order.findMany({where:{organizationId:req.user.id}}));`,
    (r) => assert.ok(r.findings.some((f) => f.ruleId === "REAPER-TENANT-001")),
  ));
test("compound string assignment preserves source provenance", async () =>
  source(
    prefix +
      `app.get('/a',(req)=>{let q='SELECT ';q+=req.query.q;return pool.query(q);});`,
    (r) => assert.equal(r.findings[0].ruleId, "REAPER-SQL-001"),
  ));
test("property mutations cannot silently certify downstream constraints", async () =>
  source(
    prefix +
      `app.get('/a',(req)=>{const where={organizationId:req.user.organizationId};where.organizationId=req.query.org;return prisma.order.findMany({where});});`,
    (r) => assert.ok(r.diagnostics.some((d) => d.message.includes("mutation"))),
  ));
test("Fastify request aliases and Knex raw preserve input provenance", async () =>
  source(
    `import fastify from 'fastify';import knex from 'knex';const server=fastify();const db=knex();server.get('/a',(input)=>db.raw('SELECT '+input.query.q));`,
    (r) => {
      assert.equal(r.metrics.routes, 1);
      assert.equal(r.findings[0].ruleId, "REAPER-SQL-001");
    },
  ));
test("Next.js exported handler uses body input and route params", async () =>
  source("", async (_r, root) => {
    await writeFile(
      path.join(root, "route.ts"),
      `import {PrismaClient} from '@prisma/client';const prisma=new PrismaClient();export async function GET(request,{params}){const {id}=await params;return prisma.order.findUnique({where:{id}});}export async function POST(request){const body=await request.json();return prisma.$queryRawUnsafe(body.query);}`,
    );
    const r = await scan({ root, config: { resources } });
    assert.equal(r.metrics.routes, 2);
    assert.deepEqual(r.findings.map((f) => f.ruleId).sort(), [
      "REAPER-AUTH-001",
      "REAPER-SQL-001",
      "REAPER-TENANT-001",
    ]);
  }));

test("post-query throw guard proves direct ownership before resource return", async () =>
  source(
    prefix +
      `app.get('/a',async(req)=>{const order=await prisma.order.findUnique({where:{id:req.params.id}});if(order.userId!==req.user.id){throw new Error('forbidden');}return order;});`,
    (r) =>
      assert.equal(
        r.findings.filter((f) => f.ruleId === "REAPER-AUTH-001").length,
        0,
      ),
    { resources: { order: { ownership: ["userId"] } } },
  ));

test("post-query guard does not trust request-supplied ownership identity", async () =>
  source(
    prefix +
      `app.get('/a',async(req)=>{const order=await prisma.order.findUnique({where:{id:req.params.id}});if(order.userId!==req.query.user){throw new Error('forbidden');}return order;});`,
    (r) =>
      assert.equal(
        r.findings.filter((f) => f.ruleId === "REAPER-AUTH-001").length,
        1,
      ),
    { resources: { order: { ownership: ["userId"] } } },
  ));

test("non-terminating ownership comparison does not certify authorization", async () =>
  source(
    prefix +
      `app.get('/a',async(req)=>{const order=await prisma.order.findUnique({where:{id:req.params.id}});if(order.userId!==req.user.id){const audit='denied';void audit;}return order;});`,
    (r) =>
      assert.equal(
        r.findings.filter((f) => f.ruleId === "REAPER-AUTH-001").length,
        1,
      ),
    { resources: { order: { ownership: ["userId"] } } },
  ));

test("post-query throw guard can prove tenant isolation", async () =>
  source(
    prefix +
      `app.get('/a',async(req)=>{const order=await prisma.order.findUnique({where:{id:req.params.id}});if(order.organizationId!==req.user.organizationId){throw new Error('forbidden');}return order;});`,
    (r) =>
      assert.equal(
        r.findings.filter((f) => f.ruleId === "REAPER-TENANT-001").length,
        0,
      ),
    { resources: { order: { tenant: ["organizationId"] } } },
  ));

test("interprocedural query result retains ownership proof context", async () =>
  source(
    prefix +
      `async function load(id){return prisma.order.findUnique({where:{id}});}app.get('/a',async(req)=>{const order=await load(req.params.id);if(order.userId!==req.user.id){throw new Error('forbidden');}return order;});`,
    (r) =>
      assert.equal(
        r.findings.filter((f) => f.ruleId === "REAPER-AUTH-001").length,
        0,
      ),
    { resources: { order: { ownership: ["userId"] } } },
  ));

test("Supabase service-role credentials are detected without exposing their value", async () =>
  source(
    `"use client";import {createClient} from '@supabase/supabase-js';const client=createClient('https://example.supabase.co',process.env.SUPABASE_SERVICE_ROLE_KEY);`,
    (r) => {
      const finding = r.findings.find((f) => f.ruleId === "REAPER-SUPA-001");
      assert.ok(finding);
      assert.equal(finding.category, "Supabase");
      assert.ok(!JSON.stringify(finding).includes("synthetic-secret-value"));
    },
  ));

test("public anon/publishable Supabase configuration is not treated as a secret", async () =>
  source(
    `"use client";import {createClient} from '@supabase/supabase-js';const client=createClient('https://example.supabase.co',process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);`,
    (r) =>
      assert.equal(
        r.findings.filter((f) => f.ruleId === "REAPER-SUPA-001").length,
        0,
      ),
  ));

test("hardcoded JWT service-role semantics are detected without retaining the token", async () =>
  source(
    `import {createClient} from '@supabase/supabase-js';const client=createClient('https://example.supabase.co','eyJhbGciOiJub25lIn0.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.synthetic');`,
    (r) => {
      const finding = r.findings.find((f) => f.ruleId === "REAPER-SUPA-001");
      assert.ok(finding);
      assert.ok(!JSON.stringify(finding).includes("eyJhbGciOiJub25lIn0"));
    },
  ));

test("Supabase table and RPC calls contribute real data-access graph edges", async () =>
  source(
    `import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.supabase.co',process.env.SUPABASE_ANON_KEY);async function load(){await db.from('orders').select('*').eq('id','1');return db.rpc('recalculate_totals',{});}`,
    (r) => {
      assert.equal(r.metrics.sinks, 2);
      assert.ok(
        r.graph.nodes.some(
          (n) => n.kind === "resource" && n.label === "orders",
        ),
      );
      assert.ok(
        r.graph.nodes.some(
          (n) => n.kind === "resource" && n.label === "rpc:recalculate_totals",
        ),
      );
    },
  ));
