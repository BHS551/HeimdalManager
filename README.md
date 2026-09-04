# HeimdalManager

The control plane for [SkyEye](https://www.skyeyeprotection.com/): the AWS
Lambda that decides when camera-monitoring instances start, stop, and how many
a customer is allowed to run.

The detection worker
([harmsDetection](https://github.com/BHS551/harmsDetection)) knows how to watch
a camera. This service owns everything around that: authenticating the caller,
checking their plan, launching EC2 with the right configuration, and tearing it
down. It is the boundary between a browser toggle and money being spent.

## The problem it solves

A "start monitoring" switch in a web app is a request to spend money on
someone else's infrastructure. Three things go wrong if that switch is
implemented naively:

1. **The browser is not an authority.** A UI check that a user has a plan is
   UX, not enforcement — anyone with a valid token can call the API directly.
   Without a server-side check, a user can run monitoring without paying, and
   run as much of it as they like.
2. **Toggles get double-clicked.** A start that is not idempotent stacks
   duplicate instances on the same camera, and the customer pays twice for the
   same stream.
3. **Credentials leak through configuration.** An RTSP URL contains the camera's
   username and password. Passed through EC2 user data it lands on disk, in
   the instance metadata, and in every log that echoes the launch request.

## How it works

```
                Firebase ID token (Bearer)
Browser ──────────────────────────────────────► HeimdalManager (Lambda)
                                                       │
                                  ┌────────────────────┼────────────────────┐
                                  ▼                    ▼                    ▼
                          verifyIdToken()      DynamoDB               EC2 RunInstances
                          (firebase-admin,     `subscriptions`        LaunchTemplate
                           creds from          plan + maxCameras      + user data
                           Secrets Manager)                           + tags

Motion box ───────────────────────────────────► same Lambda
             X-Internal-Secret header            (machine-to-machine route,
             {"action":"ensureAnalysis"}          resolved before user auth)
```

**Two topologies, one launch template.** A per-camera worker runs all three
detection tiers locally. The cost-optimised topology instead runs one cheap
always-on *motion box* covering many cameras, plus a shared *analysis box* for
CLIP and the VLM that is started on demand and shuts itself down after two idle
hours. Both use the same AMI and launch template — only the instance type and a
`mode` flag in the user data differ, so there is one image to maintain.

**Instances are found by tag, not by a stored id.** `DescribeInstances` filtered
on `Project`, `TaskId`, `OwnerUid` and `Role` is the source of truth for what is
running. There is no instance table to drift out of sync with reality, and a
manually terminated instance simply stops appearing.

## Key technical decisions

**The plan check is server-side and unconditional.** Before any
`RunInstances`, the handler reads the caller's subscription from DynamoDB,
rejects anything that is not `active`, counts their `pending`/`running`
instances by tag, and refuses past `maxCameras`. Both failures return 403 with a
message the UI can show directly. Administrators — identified by a `role=admin`
custom claim signed into the token, never by a request field — bypass it.

**Start is idempotent.** It looks for a live instance tagged with the same
`TaskId` first and returns that one with `alreadyRunning: true`. A double-click
costs nothing. `ensureAnalysis` and `startMotionBox` work the same way, which
matters because the motion box calls `ensureAnalysis` on every burst.

**Camera credentials travel by reference.** The handler replaces whatever the
client sent with `rtsp_secret_id: heimdall/rtsp/<taskId>` and explicitly deletes
any `rtsp_path` from the context. The worker resolves the secret itself at
runtime, so the password is never in user data, never in `context.json` on disk,
and never in a log line.

**Firebase credentials come from Secrets Manager**, with a fallback to
environment variables so a rollback is possible, and the initialisation promise
is cached across warm invocations rather than re-fetched per request.

**A malformed body is a 400, never a default.** `action` defaults to `"start"`,
which makes unparseable input dangerous: a corrupted *stop* would otherwise
launch an instance. Parse failures and unknown actions are rejected outright,
`taskId` is validated against a pattern, and `stop` requires an explicit
`taskId`.

**Stop is forgiving, start is strict.** Stopping a task with no live instances
returns 200 rather than 404 — the user's intent is "make sure this is off", and
the switch should end up off either way.

**Machine-to-machine calls are separated from user calls.** The motion box needs
to wake the analysis box with no user in the loop. That path authenticates with
a shared secret header and is resolved *before* token verification, and it can
reach only two actions. It cannot start a customer worker.

**Errors are classified before they are reported.** Only `auth/*` codes from
firebase-admin produce a 401. An earlier version matched on the word "token" in
the message and turned the AWS SDK's "The security token included in the request
is invalid" — a server credentials problem — into a 401 that told the user to log
in again.

**CORS reflects an allow-list.** The app domain, Vercel previews and localhost
are echoed back; anything else gets the default origin instead of `*`.

## API

All user-facing calls require `Authorization: Bearer <Firebase ID token>`.

```http
POST /
{ "action": "start", "taskId": "1699887766000", "context": { ... } }
→ 200 { "ok": true, "instanceId": "i-0abc…", "taskId": "…" }
→ 403 { "message": "Necesitas un plan activo para encender el monitoreo." }
→ 403 { "message": "Alcanzaste el límite de tu plan (N cámaras…)" }

POST /
{ "action": "stop", "taskId": "1699887766000" }
→ 200 { "ok": true, "terminatedInstanceIds": ["i-0abc…"] }
```

Internal, authenticated with `X-Internal-Secret` instead of a user token:

```http
POST /   { "action": "ensureAnalysis" }
POST /   { "action": "startMotionBox", "cameras": [ { "id": "…", "camera_name": "…" } ] }
```

The repository also contains the sibling Lambdas that share its auth and CORS
pattern: `subscriptions.mjs` (plan activation, admin-only),
`userSettings.mjs` (notification channels), `workerEvents.mjs` (worker
heartbeats and user notifications, restricted to worker identities) and
`notifyAdmin.mjs` (SNS publish).

## Deploying

Node.js 18+ on AWS Lambda, behind API Gateway, with `index.mjs` as the handler.

```bash
npm install firebase-admin @aws-sdk/client-ec2 @aws-sdk/client-dynamodb \
            @aws-sdk/lib-dynamodb @aws-sdk/client-secrets-manager
zip -r function.zip . && aws lambda update-function-code \
  --function-name heimdalManager --zip-file fileb://function.zip
```

The execution role needs `ec2:RunInstances`, `ec2:DescribeInstances`,
`ec2:TerminateInstances`, `ec2:CreateTags`, `dynamodb:GetItem` on
`subscriptions`, and `secretsmanager:GetSecretValue`.

| Variable | Default | Meaning |
|---|---|---|
| `LAUNCH_TEMPLATE_ID` | — | Launch template for all workers (required) |
| `FIREBASE_SECRET_ID` | `heimdall/firebase` | Service account in Secrets Manager |
| `ALLOWED_ORIGINS` | — | Comma-separated CORS allow-list |
| `HEIMDALL_INTERNAL_SECRET` | — | Shared secret for the machine-to-machine route |
| `ANALYSIS_INSTANCE_TYPE` | `m7i-flex.large` | Shared CLIP + VLM box |
| `MOTION_INSTANCE_TYPE` | `t3.small` | Always-on multi-camera motion box |
| `ANALYSIS_IDLE_SECONDS` | `7200` | Idle time before the analysis box self-terminates |
| `HEIMDALL_CANDIDATE_QUEUE_URL` | derived | Tier 0 → tier 1 queue |
| `HEIMDALL_VLM_QUEUE_URL` | derived | Tier 1 → tier 2 queue |

Prerequisites: a DynamoDB `subscriptions` table keyed on `uid` with `status` and
`maxCameras`, one `heimdall/rtsp/<deviceId>` secret per camera (written by
[StoreDevice](https://github.com/BHS551/StoreDevice)), and a launch template
whose AMI carries the worker's Python environment.
