import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import postgres from "npm:postgres@3.4.7";
import { handleFreeRunnerRequest } from "./free-runner.ts";

const DATABASE_URL = Deno.env.get("SUPABASE_DB_URL");
if (!DATABASE_URL) throw new Error("SUPABASE_DB_URL is required.");

const sql = postgres(DATABASE_URL, {
  prepare: false,
  max: 1,
  idle_timeout: 5,
  connect_timeout: 5,
});

type Role = "viewer" | "analyst" | "admin";
type Context = {
  apiKeyId: string;
  workspaceId: string;
  principalId: string;
  role: Role;
};

const ROLE_WEIGHT: Record<Role, number> = {
  viewer: 10,
  analyst: 20,
  admin: 30,
};

const API_KEY_RE =
  /^reaper_live_([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$/i;

const headers = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

function json(status: number, value: unknown): Response {
  return new Response(JSON.stringify(value), { status, headers });
}

function textValue(value: unknown, name: string, max = 200): string {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > max
  ) {
    throw new Error(`${name} is invalid.`);
  }
  return value.trim();
}

function uuid(value: unknown, name: string): string {
  const input = textValue(value, name, 64);
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      input,
    )
  ) {
    throw new Error(`${name} must be a UUID.`);
  }
  return input;
}

function requireRole(context: Context, minimum: Role): void {
  if (ROLE_WEIGHT[context.role] < ROLE_WEIGHT[minimum]) {
    throw new Error(`Role ${minimum} or higher is required.`);
  }
}

function parseBearer(request: Request): string {
  const header = request.headers.get("authorization");
  const match = header ? /^Bearer ([^\s]+)$/.exec(header) : null;
  if (!match?.[1]) throw new Error("Authentication failed.");
  return match[1];
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function authenticate(tx: postgres.TransactionSql, request: Request) {
  const token = parseBearer(request);
  const match = API_KEY_RE.exec(token);
  if (!match?.[1]) throw new Error("Authentication failed.");
  const secretHash = await sha256(token);

  const rows = await tx<
    Array<{
      api_key_id: string;
      workspace_id: string;
      principal_id: string;
      role: Role;
    }>
  >`SELECT * FROM reaper_control.authenticate_api_key(${match[1]}::uuid, ${secretHash}::text)`;

  const row = rows[0];
  if (!row) throw new Error("Authentication failed.");

  const context: Context = {
    apiKeyId: row.api_key_id,
    workspaceId: row.workspace_id,
    principalId: row.principal_id,
    role: row.role,
  };

  await tx`SELECT set_config('reaper.workspace_id', ${context.workspaceId}, true),
                  set_config('reaper.principal_id', ${context.principalId}, true)`;

  return context;
}

async function readBody(request: Request): Promise<Record<string, unknown>> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new Error("Content-Type must be application/json.");
  }
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > 64 * 1024) {
    throw new Error("Request body exceeds 64 KiB.");
  }
  const value = raw ? JSON.parse(raw) : {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("JSON request body must be an object.");
  }
  return value as Record<string, unknown>;
}

function exactOrigin(value: unknown): string {
  const raw = textValue(value, "targetOrigin", 2048);
  const parsed = new URL(raw);
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.origin !== raw ||
    parsed.username ||
    parsed.password
  ) {
    throw new Error("targetOrigin must be an exact HTTP(S) origin.");
  }
  return parsed.origin;
}

function relativePath(value: unknown): string {
  const raw = textValue(value, "configPath", 1024);
  if (
    raw.startsWith("/") ||
    raw.includes("\\") ||
    raw.split("/").some((part) => !part || part === "..")
  ) {
    throw new Error("configPath must be a normalized relative path.");
  }
  return raw;
}

function routePath(url: URL): string {
  const marker = "/reaper-platform";
  const index = url.pathname.indexOf(marker);
  if (index === -1) return url.pathname;
  return url.pathname.slice(index + marker.length) || "/";
}

function pathId(path: string, prefix: string, suffix = ""): string | null {
  if (!path.startsWith(prefix) || !path.endsWith(suffix)) return null;
  const end = suffix ? -suffix.length : undefined;
  const value = path.slice(prefix.length, end);
  return value && !value.includes("/") ? value : null;
}

function apiKeyMaterial(): { id: string; token: string } {
  const id = crypto.randomUUID();
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const secret = btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
  return { id, token: `reaper_live_${id}.${secret}` };
}

const DASHBOARD = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>REAPER Platform Staging</title>
<style>
:root{color-scheme:dark;--bg:#090909;--panel:#111;--line:#262626;--muted:#898989;--text:#f2f2f2;--soft:#181818}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Inter,system-ui,sans-serif}.shell{max-width:1180px;margin:auto;padding:30px}.top{display:flex;gap:24px;justify-content:space-between;align-items:end;margin-bottom:24px}.brand h1{margin:0;font-size:24px;letter-spacing:.17em}.brand p{margin:6px 0 0;color:var(--muted)}input,select,button{background:var(--soft);border:1px solid var(--line);color:var(--text);border-radius:8px;padding:10px 12px}button{cursor:pointer}.auth{display:flex;gap:8px}.auth input{width:360px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}.s4{grid-column:span 4}.s12{grid-column:span 12}.label{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}.metric{font-size:32px;margin-top:8px}.row{display:flex;justify-content:space-between;gap:16px;padding:12px 0;border-top:1px solid var(--line)}.row:first-child{border-top:0}.muted{color:var(--muted)}.pill{border:1px solid var(--line);border-radius:999px;padding:3px 8px;font-size:11px}.hidden{display:none}.error{border-color:#713333;color:#ffbcbc}.toolbar{display:flex;gap:8px;align-items:center}.toolbar strong{margin-right:auto}.freeform{display:grid;grid-template-columns:minmax(180px,.8fr) minmax(260px,1.5fr) auto;gap:8px;margin-top:14px}.freehint{margin-top:10px;color:var(--muted)}@media(max-width:780px){.shell{padding:18px}.top{flex-direction:column;align-items:stretch}.auth input{width:100%}.s4,.s12{grid-column:span 12}.freeform{grid-template-columns:1fr}}
</style>
</head>
<body>
<main class="shell">
<header class="top"><div class="brand"><h1>REAPER</h1><p>Platform staging control plane</p></div><div class="auth"><input id="token" type="password" placeholder="reaper_live_…" autocomplete="off"><button id="connect">Connect</button></div></header>
<div id="notice" class="card error hidden"></div>
<section class="grid">
<article class="card s4"><div class="label">Workspace</div><div id="workspace" class="metric">—</div><div id="principal" class="muted"></div></article>
<article class="card s4"><div class="label">Projects</div><div id="projects" class="metric">—</div></article>
<article class="card s4"><div class="label">Runs</div><div id="runsCount" class="metric">—</div></article>
<article class="card s12"><div class="toolbar"><strong>Free staging assessment</strong><span class="muted">GitHub Actions · read-only</span></div><div class="freeform"><select id="freeProject"><option value="">Choose a project</option></select><input id="freeTarget" type="url" placeholder="https://preview.example.com" autocomplete="off"><button id="queueFree">Queue free scan</button></div><div class="freehint">HTTPS only · max 8 requests · no credentials · no mutations · no private network · picked up automatically by the free runner.</div></article>
<article class="card s12"><div class="toolbar"><strong>Runs</strong><button id="refresh">Refresh</button></div><div id="runs" class="muted" style="padding-top:18px">Connect with an API key.</div></article>
</section>
</main>
<script>
const $=id=>document.getElementById(id);let token=sessionStorage.getItem("reaper.token")||"";$("token").value=token;
const base=location.pathname.replace(/\/$/,"");
async function api(path,options={}){const r=await fetch(base+path,{...options,headers:{authorization:"Bearer "+token,...(options.body?{"content-type":"application/json"}:{}),...(options.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||"Request failed");return d}
function fail(e){$("notice").textContent=e.message||String(e);$("notice").classList.remove("hidden")}
function clear(){ $("notice").classList.add("hidden")}
function row(run){const d=document.createElement("div");d.className="row";const a=document.createElement("div"),t=document.createElement("div"),m=document.createElement("div"),s=document.createElement("span");t.textContent=run.target_origin;m.className="muted";m.textContent=(run.environment||"—")+" · "+new Date(run.created_at).toLocaleString();s.className="pill";s.textContent=run.status;a.append(t,m);d.append(a,s);return d}
function fillProjects(items){const select=$("freeProject");const current=select.value;select.replaceChildren(Object.assign(document.createElement("option"),{value:"",textContent:items.length?"Choose a project":"No projects yet — one will be created automatically"}),...items.map(project=>Object.assign(document.createElement("option"),{value:project.id,textContent:project.name})));if(items.some(project=>project.id===current))select.value=current}
async function refresh(){clear();try{const [me,p,r]=await Promise.all([api("/v1/me"),api("/v1/projects"),api("/v1/runs")]);$("workspace").textContent=me.workspaceId.slice(0,8);$("principal").textContent=me.principalId+" · "+me.role;$("projects").textContent=p.items.length;$("runsCount").textContent=r.items.length;fillProjects(p.items);$("runs").replaceChildren(...(r.items.length?r.items.map(row):[Object.assign(document.createElement("div"),{className:"muted",textContent:"No runs yet."})]))}catch(e){fail(e)}}
$("connect").onclick=()=>{token=$("token").value.trim();sessionStorage.setItem("reaper.token",token);refresh()};
$("refresh").onclick=refresh;
$("queueFree").onclick=async()=>{clear();try{let projectId=$("freeProject").value;const targetOrigin=$("freeTarget").value.trim();if(!targetOrigin)throw new Error("Enter an HTTPS target origin.");$("queueFree").disabled=true;if(!projectId){const project=await api("/v1/projects",{method:"POST",body:JSON.stringify({name:"Free Staging"})});projectId=project.id}await api("/v1/free-runs",{method:"POST",body:JSON.stringify({projectId,targetOrigin})});$("freeTarget").value="";await refresh()}catch(e){fail(e)}finally{$("queueFree").disabled=false}};
if(token)refresh();
</script>
</body></html>`;

function html(): Response {
  return new Response(DASHBOARD, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy":
        "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
    },
  });
}

function clientError(message: string): boolean {
  return /(invalid|required|missing|must|not found|outside|belongs|role|format|content-type|exceeds|future|authentication)/i.test(
    message,
  );
}

Deno.serve(async (request: Request) => {
  const url = new URL(request.url);
  const path = routePath(url);
  const method = request.method.toUpperCase();

  try {
    if (method === "GET" && (path === "/" || path === "/dashboard")) {
      return html();
    }

    if (method === "GET" && path === "/health") {
      const probe = await sql`SELECT 1 AS ok`;
      return json(200, { status: probe[0]?.ok === 1 ? "ok" : "degraded" });
    }

    if (path.startsWith("/runner/")) {
      return await handleFreeRunnerRequest({
        request,
        path,
        method,
        sql,
        json,
      });
    }

    return await sql.begin(async (tx) => {
      const context = await authenticate(tx, request);

      if (method === "GET" && path === "/v1/me") return json(200, context);

      if (method === "GET" && path === "/v1/projects") {
        const items = await tx`
          SELECT id,name,created_at
          FROM reaper_control.projects
          WHERE workspace_id=${context.workspaceId}::uuid
          ORDER BY created_at DESC
          LIMIT 200
        `;
        return json(200, { items });
      }

      if (method === "POST" && path === "/v1/projects") {
        requireRole(context, "analyst");
        const body = await readBody(request);
        const rows = await tx`
          INSERT INTO reaper_control.projects(id,workspace_id,name)
          VALUES (${crypto.randomUUID()}::uuid,${context.workspaceId}::uuid,${textValue(body.name, "name")})
          RETURNING id,name,created_at
        `;
        return json(201, rows[0]);
      }

      if (method === "GET" && path === "/v1/assessments") {
        const items = await tx`
          SELECT id,project_id,reference,created_at
          FROM reaper_control.assessments
          WHERE workspace_id=${context.workspaceId}::uuid
          ORDER BY created_at DESC
          LIMIT 500
        `;
        return json(200, { items });
      }

      if (method === "POST" && path === "/v1/assessments") {
        requireRole(context, "analyst");
        const body = await readBody(request);
        const rows = await tx`
          INSERT INTO reaper_control.assessments(id,workspace_id,project_id,reference)
          VALUES (
            ${crypto.randomUUID()}::uuid,
            ${context.workspaceId}::uuid,
            ${uuid(body.projectId, "projectId")}::uuid,
            ${textValue(body.reference, "reference")}
          )
          RETURNING id,project_id,reference,created_at
        `;
        return json(201, rows[0]);
      }

      if (method === "GET" && path === "/v1/runs") {
        const items = await tx`
          SELECT id,project_id,assessment_id,status,target_origin,environment,
                 created_at,updated_at,error
          FROM reaper_control.runs
          WHERE workspace_id=${context.workspaceId}::uuid
          ORDER BY created_at DESC
          LIMIT 500
        `;
        return json(200, { items });
      }

      if (method === "POST" && path === "/v1/free-runs") {
        requireRole(context, "analyst");
        const body = await readBody(request);
        const projectId = uuid(body.projectId, "projectId");
        const targetOrigin = exactOrigin(body.targetOrigin);
        if (!targetOrigin.startsWith("https://"))
          throw new Error("Free staging assessments require an HTTPS origin.");

        const project = await tx`
          SELECT id
          FROM reaper_control.projects
          WHERE workspace_id=${context.workspaceId}::uuid
            AND id=${projectId}::uuid
        `;
        if (!project[0]) throw new Error("Project not found.");

        const assessmentId = crypto.randomUUID();
        const runId = crypto.randomUUID();
        const jobId = crypto.randomUUID();
        const limits = {
          maxRequests: 8,
          maxCleanupRequests: 1,
          rateLimitPerSecond: 2,
          deadlineMs: 60000,
        };
        const permissions = ["read"];
        const reference = "free-" + runId;

        await tx`
          INSERT INTO reaper_control.assessments(
            id,workspace_id,project_id,reference
          ) VALUES (
            ${assessmentId}::uuid,${context.workspaceId}::uuid,
            ${projectId}::uuid,${reference}
          )
        `;

        const rows = await tx`
          INSERT INTO reaper_control.runs(
            id,workspace_id,project_id,assessment_id,status,target_origin,
            environment,config_path,permissions,limits
          ) VALUES (
            ${runId}::uuid,${context.workspaceId}::uuid,${projectId}::uuid,
            ${assessmentId}::uuid,'PENDING',${targetOrigin},'staging',
            'free-readonly.ts',${tx.json(permissions)},${tx.json(limits)}
          )
          RETURNING id,status,target_origin,environment,created_at,updated_at
        `;

        await tx`
          INSERT INTO reaper_control.jobs(
            id,workspace_id,run_id,status,payload
          ) VALUES (
            ${jobId}::uuid,${context.workspaceId}::uuid,${runId}::uuid,
            'PENDING',${tx.json({
              projectId,
              assessmentId,
              targetOrigin,
              environment: "staging",
              configPath: "free-readonly.ts",
              permissions,
              limits,
            })}
          )
        `;

        return json(202, {
          ...rows[0],
          assessmentId,
          jobId,
          runner: "github-actions-free",
        });
      }

      if (method === "POST" && path === "/v1/runs") {
        requireRole(context, "analyst");
        const body = await readBody(request);
        const projectId = uuid(body.projectId, "projectId");
        const assessmentId = uuid(body.assessmentId, "assessmentId");
        const targetOrigin = exactOrigin(body.targetOrigin);
        const environment = textValue(body.environment, "environment", 20);
        if (
          !["local", "preview", "staging", "production"].includes(environment)
        ) {
          throw new Error("environment is invalid.");
        }
        const configPath = relativePath(body.configPath);
        const permissions = Array.isArray(body.permissions)
          ? body.permissions
          : ["read"];
        const allowed = new Set([
          "read",
          "mutations",
          "syntheticIdentities",
          "internalNetwork",
        ]);
        if (
          permissions.length < 1 ||
          permissions.length > 4 ||
          !permissions.includes("read") ||
          new Set(permissions).size !== permissions.length ||
          !permissions.every(
            (value) => typeof value === "string" && allowed.has(value),
          )
        ) {
          throw new Error("permissions are invalid.");
        }
        const rawLimits =
          body.limits &&
          typeof body.limits === "object" &&
          !Array.isArray(body.limits)
            ? (body.limits as Record<string, unknown>)
            : {};
        const limits = {
          maxRequests: rawLimits.maxRequests ?? 20,
          maxCleanupRequests: rawLimits.maxCleanupRequests ?? 10,
          rateLimitPerSecond: rawLimits.rateLimitPerSecond ?? 5,
          deadlineMs: rawLimits.deadlineMs ?? 120000,
        };
        const bounds = [
          ["maxRequests", 1, 500],
          ["maxCleanupRequests", 1, 200],
          ["rateLimitPerSecond", 1, 20],
          ["deadlineMs", 1000, 1800000],
        ] as const;
        for (const [name, min, max] of bounds) {
          const value = limits[name];
          if (
            !Number.isSafeInteger(value) ||
            Number(value) < min ||
            Number(value) > max
          ) {
            throw new Error(`${name} is outside the supported bounds.`);
          }
        }
        const match = await tx`
          SELECT 1
          FROM reaper_control.assessments
          WHERE id=${assessmentId}::uuid
            AND project_id=${projectId}::uuid
            AND workspace_id=${context.workspaceId}::uuid
        `;
        if (!match[0])
          throw new Error(
            "Assessment does not belong to the selected project.",
          );

        const runId = crypto.randomUUID();
        const jobId = crypto.randomUUID();
        const payload = {
          projectId,
          assessmentId,
          targetOrigin,
          environment,
          configPath,
          permissions,
          limits,
        };
        const rows = await tx`
          INSERT INTO reaper_control.runs(
            id,workspace_id,project_id,assessment_id,status,target_origin,
            environment,config_path,permissions,limits
          ) VALUES (
            ${runId}::uuid,${context.workspaceId}::uuid,${projectId}::uuid,
            ${assessmentId}::uuid,'PENDING',${targetOrigin},${environment},
            ${configPath},${tx.json(permissions)},${tx.json(limits)}
          )
          RETURNING id,status,target_origin,environment,created_at,updated_at
        `;
        await tx`
          INSERT INTO reaper_control.jobs(id,workspace_id,run_id,status,payload)
          VALUES (
            ${jobId}::uuid,${context.workspaceId}::uuid,${runId}::uuid,
            'PENDING',${tx.json(payload)}
          )
        `;
        return json(202, { ...rows[0], jobId });
      }

      const findingsRun = pathId(path, "/v1/runs/", "/findings");
      if (method === "GET" && findingsRun) {
        const items = await tx`
          SELECT id,rule_id,severity,payload,created_at
          FROM reaper_control.findings
          WHERE workspace_id=${context.workspaceId}::uuid
            AND run_id=${uuid(findingsRun, "runId")}::uuid
          ORDER BY created_at,id
          LIMIT 2000
        `;
        return json(200, { items });
      }

      const auditRun = pathId(path, "/v1/runs/", "/audit");
      if (method === "GET" && auditRun) {
        const items = await tx`
          SELECT sequence,previous_hash,event_hash,event_type,payload,created_at
          FROM reaper_control.audit_events
          WHERE workspace_id=${context.workspaceId}::uuid
            AND run_id=${uuid(auditRun, "runId")}::uuid
          ORDER BY sequence
          LIMIT 5000
        `;
        return json(200, { items });
      }

      const runId = pathId(path, "/v1/runs/");
      if (method === "GET" && runId) {
        const rows = await tx`
          SELECT id,project_id,assessment_id,status,target_origin,environment,
                 permissions,limits,report,error,created_at,updated_at
          FROM reaper_control.runs
          WHERE workspace_id=${context.workspaceId}::uuid
            AND id=${uuid(runId, "runId")}::uuid
        `;
        if (!rows[0]) throw new Error("Run not found.");
        return json(200, rows[0]);
      }

      if (method === "GET" && path === "/v1/api-keys") {
        requireRole(context, "admin");
        const items = await tx`
          SELECT id,principal_id,name,expires_at,revoked_at,created_at,last_used_at
          FROM reaper_control.api_keys
          WHERE workspace_id=${context.workspaceId}::uuid
          ORDER BY created_at DESC
          LIMIT 200
        `;
        return json(200, { items });
      }

      if (method === "POST" && path === "/v1/api-keys") {
        requireRole(context, "admin");
        const body = await readBody(request);
        const principalId = textValue(
          body.principalId ?? context.principalId,
          "principalId",
        );
        const name = textValue(body.name, "name");
        const expiresAt =
          body.expiresAt === undefined || body.expiresAt === null
            ? null
            : textValue(body.expiresAt, "expiresAt", 50);
        if (
          expiresAt &&
          (!Number.isFinite(Date.parse(expiresAt)) ||
            Date.parse(expiresAt) <= Date.now())
        ) {
          throw new Error("expiresAt must be a future timestamp.");
        }
        const material = apiKeyMaterial();
        const digest = await sha256(material.token);
        await tx`
          SELECT reaper_control.create_api_key(
            ${material.id}::uuid,${principalId},${name},${digest},${expiresAt}::timestamptz
          )
        `;
        return json(201, { id: material.id, token: material.token, expiresAt });
      }

      const keyId = pathId(path, "/v1/api-keys/");
      if (method === "DELETE" && keyId) {
        requireRole(context, "admin");
        const rows = await tx<Array<{ revoked: boolean }>>`
          SELECT reaper_control.revoke_api_key(${uuid(keyId, "keyId")}::uuid) AS revoked
        `;
        return json(rows[0]?.revoked ? 200 : 404, {
          revoked: rows[0]?.revoked === true,
        });
      }

      return json(404, { error: "Route not found." });
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Request failed.";
    if (
      /authentication failed|runner authentication|github oidc/i.test(message)
    )
      return json(401, { error: "Authentication failed." });
    return json(clientError(message) ? 400 : 500, {
      error: clientError(message) ? message : "Internal server error.",
    });
  }
});
