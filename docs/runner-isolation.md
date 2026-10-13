# Runner isolation and commercial deployment profile

REAPER now distinguishes **standard** runner isolation from **strict** commercial isolation.

## Status

| Control                                   | Status               | Current guarantee                                                                                                                                                                                                          |
| ----------------------------------------- | -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Child-process boundary                    | IMPLEMENTED          | The standard runner executes the trusted engine in a separate Node process with a filtered environment, temporary working directory, deadline, bounded IPC/output and V8 heap limit.                                       |
| Strict capability contract                | IMPLEMENTED          | Strict mode refuses to start unless its injected isolation provider declares process, filesystem, network and enforceable resource-limit capabilities. There is no silent fallback to the standard child-process provider. |
| Persistent journal / replay / audit state | IMPLEMENTED          | A strict worker requires a persistent state directory and uses separate journal, replay and audit stores.                                                                                                                  |
| OS filesystem sandbox                     | DEPLOYMENT-DEPENDENT | A container, VM or equivalent sandbox must enforce the filesystem boundary. The built-in child-process provider does not.                                                                                                  |
| Network egress policy                     | DEPLOYMENT-DEPENDENT | Deployment infrastructure must restrict egress to the approved target path/network. REAPER's application transport still performs exact-origin, address-class, DNS stability and pinned-address checks.                    |
| CPU / RSS / PID limits                    | DEPLOYMENT-DEPENDENT | The built-in V8 heap limit is not a complete OS resource limit. Strict providers must enforce actual CPU, memory and process limits.                                                                                       |
| Kernel/container escape resistance        | DEPLOYMENT-DEPENDENT | Requires a hardened runtime and independent deployment/security review.                                                                                                                                                    |

The isolation provider is a **trusted deployment component**. A provider that lies about its capabilities defeats the strict-mode contract; production code should ship only reviewed provider implementations.

## Required strict sandbox properties

A production strict runner should be started with an external sandbox that enforces at least:

- non-root user;
- read-only root filesystem;
- a small writable ephemeral scratch directory only;
- no privileged mode;
- no Docker/container-runtime socket;
- no arbitrary host filesystem mounts;
- all Linux capabilities dropped unless a reviewed provider proves one is necessary;
- `no-new-privileges`;
- CPU quota;
- memory/RSS limit;
- PID/process limit;
- execution deadline enforced outside the worker as well as inside it;
- outbound network policy restricted to the authorized assessment route;
- no inbound listener unless explicitly required by a future protocol;
- a persistent state mount only for journal/replay/audit data;
- state mount permissions limited to the runner identity.

The target may need DNS and HTTPS access. That does **not** imply general internet egress should be available.

## Example deployment intent

The exact command depends on the chosen runtime, but the security properties should correspond to controls such as:

```text
run as non-root
read-only rootfs
tmpfs /tmp with bounded size
drop all capabilities
no-new-privileges
pids limit
memory limit
cpu quota
egress allowlist/firewall
mount /reaper-state as the only persistent writable path
never mount /var/run/docker.sock
```

A Docker Compose file alone cannot reliably express a hostname-specific, dynamically resolved target egress policy on every platform. That control belongs in the deployment network layer or an isolation provider that can enforce equivalent policy. REAPER must not report network isolation as active merely because the application-level exact-origin checks passed.

## Failure behavior

Standard mode may use `ProcessIsolationProvider` and is explicitly not an OS sandbox.

Strict mode calls `assertRunnerIsolation()`. If filesystem isolation, network isolation or enforceable resource limits are absent, execution is rejected before a job is spawned.

The strict worker also requires a persistent state directory so scope replay records, execution journals and audit chains survive the disposable worker filesystem.

## External provider contract

A deployment-specific `RunnerIsolationProvider` owns worker process creation. It must return a child process compatible with the runner protocol while actually enforcing the capabilities it advertises.

Do not create a provider that simply wraps `ProcessIsolationProvider` and marks capabilities as true in production. Such an adapter is suitable only for unit tests of orchestration, not for a commercial deployment.
