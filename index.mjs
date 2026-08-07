// index.mjs
import admin from "firebase-admin";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import {
  EC2Client,
  RunInstancesCommand,
  DescribeInstancesCommand,
  TerminateInstancesCommand,
} from "@aws-sdk/client-ec2";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";

const ec2 = new EC2Client({ region: process.env.AWS_REGION || "us-east-1" });
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const SUBSCRIPTIONS_TABLE = "subscriptions";

// --- Cascada económica (Fase B): motion box barato 24/7 + analysis box compartida
// que se levanta bajo demanda y se apaga sola tras 2h ociosa. Ambas usan el MISMO
// launch template (misma AMI con venv/opencv/clip); solo cambia el InstanceType y el
// modo de arranque, así no hace falta un template nuevo.
const REGION = process.env.AWS_REGION || "us-east-1";
const ACCOUNT_ID = process.env.ACCOUNT_ID || "780817326479";
const CANDIDATE_QUEUE_URL =
  process.env.HEIMDALL_CANDIDATE_QUEUE_URL ||
  `https://sqs.${REGION}.amazonaws.com/${ACCOUNT_ID}/heimdall-candidates`;
const VLM_QUEUE_URL =
  process.env.HEIMDALL_VLM_QUEUE_URL ||
  `https://sqs.${REGION}.amazonaws.com/${ACCOUNT_ID}/heimdall-vlm`;
const ANALYSIS_INSTANCE_TYPE = process.env.ANALYSIS_INSTANCE_TYPE || "m7i-flex.large";
const MOTION_INSTANCE_TYPE = process.env.MOTION_INSTANCE_TYPE || "t3.small";
// Secreto compartido para acciones máquina-a-máquina (el motion box despierta la
// analysis box). Sin token de usuario; se compara en tiempo constante-ish.
const INTERNAL_SECRET = process.env.HEIMDALL_INTERNAL_SECRET || "";

const headers = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
};

// firebase-admin: la credencial se lee de Secrets Manager (heimdall/firebase)
// en lugar de variables de entorno. Cae a las env vars solo si el secreto no
// está disponible, para permitir un rollback seguro.
const secretsClient = new SecretsManagerClient({
  region: process.env.AWS_REGION || "us-east-1",
});
const FIREBASE_SECRET_ID = process.env.FIREBASE_SECRET_ID || "heimdall/firebase";

let firebaseReady = null;
function ensureFirebase() {
  if (!firebaseReady) {
    firebaseReady = (async () => {
      if (admin.apps.length) return;
      let sa = null;
      try {
        const res = await secretsClient.send(
          new GetSecretValueCommand({ SecretId: FIREBASE_SECRET_ID })
        );
        const secret = JSON.parse(res.SecretString);
        sa = secret.service_account || secret;
      } catch (e) {
        if (!process.env.FIREBASE_PRIVATE_KEY) throw e;
      }
      const credential = sa
        ? admin.credential.cert({
            projectId: sa.project_id,
            clientEmail: sa.client_email,
            privateKey: sa.private_key,
          })
        : admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
          });
      admin.initializeApp({ credential });
    })();
  }
  return firebaseReady;
}

// EC2 tag filters treat * and ? as wildcards; a strict allowlist keeps a
// malicious taskId from matching (and terminating) other tasks' instances.
const TASK_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

// CORS: refleja el origen solo si está permitido (dominio de la app + previews
// de Vercel + localhost). Configurable con ALLOWED_ORIGINS (lista separada por
// comas). Antes se enviaba "*" a cualquier origen.
const STATIC_ALLOWED = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const DEFAULT_ORIGIN =
  STATIC_ALLOWED[0] || "https://harms-detection-landing-ui-seven.vercel.app";
function allowOrigin(event) {
  const origin =
    event?.headers?.origin || event?.headers?.Origin || "";
  const ok =
    STATIC_ALLOWED.includes(origin) ||
    /^https:\/\/([a-z0-9-]+\.)*vercel\.app$/i.test(origin) ||
    /^http:\/\/localhost(:\d+)?$/i.test(origin);
  return ok ? origin : DEFAULT_ORIGIN;
}

function getBearerToken(event) {
  const authHeader =
    event?.headers?.Authorization || event?.headers?.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }

  return authHeader.slice("Bearer ".length).trim();
}

async function findTaskInstances(taskId, ownerUid, states) {
  const filters = [
    { Name: "tag:TaskId", Values: [String(taskId)] },
    { Name: "tag:Project", Values: ["PythonWorkers"] },
    { Name: "instance-state-name", Values: states },
  ];
  // ownerUid null = sin filtro de dueño (administradores operan sobre
  // cualquier instancia; los demás usuarios solo sobre las suyas).
  if (ownerUid) {
    filters.push({ Name: "tag:OwnerUid", Values: [String(ownerUid)] });
  }
  const described = await ec2.send(
    new DescribeInstancesCommand({ Filters: filters })
  );
  return (described.Reservations ?? []).flatMap((r) =>
    (r.Instances ?? []).map((i) => i.InstanceId)
  );
}

// Cuenta los workers vivos (pending/running) de un usuario, para aplicar el
// tope de cámaras del plan del lado del servidor.
async function countOwnerRunningInstances(ownerUid) {
  const described = await ec2.send(
    new DescribeInstancesCommand({
      Filters: [
        { Name: "tag:Project", Values: ["PythonWorkers"] },
        { Name: "tag:OwnerUid", Values: [String(ownerUid)] },
        { Name: "instance-state-name", Values: ["pending", "running"] },
      ],
    })
  );
  return (described.Reservations ?? []).reduce(
    (sum, r) => sum + (r.Instances ?? []).length,
    0
  );
}

async function getSubscription(ownerUid) {
  const res = await ddb.send(
    new GetCommand({ TableName: SUBSCRIPTIONS_TABLE, Key: { uid: ownerUid } })
  );
  return res.Item ?? null;
}

// Construye el UserData común (descarga scripts de S3 + systemd) parametrizado por
// modo de arranque y variables de entorno. `mode`:
//   "local"        -> las 3 capas en un proceso (1 cámara). Cae al monolito si la
//                     cascada no importa (nunca deja una cámara sin detección).
//   "analysis"     -> CLIP+VLM consumiendo SQS (analysis box compartida).
//   "motion-multi" -> capa 0 de N cámaras -> SQS (motion box barato 24/7).
function buildUserData(contextJson, { mode = "local", env = {} } = {}) {
  const envLines = Object.entries(env)
    .map(([k, v]) => `Environment=${k}=${v}`)
    .join("\n");
  // El monolito solo es fallback válido para "local" (worker por cámara). Para las
  // cajas de la cascada, si la cascada no importa, se falla y systemd reintenta.
  const launcher =
    mode === "local"
      ? `if [ -f run_pipeline.py ] && \$PY -c "import vision,transport,common,vlm,tiers,run_pipeline" 2>/tmp/cascade_import.err; then
  echo "engine=cascade mode=local"
  exec \$PY run_pipeline.py local \$APP/context.json
else
  echo "engine=monolith (fallo import cascade):"; cat /tmp/cascade_import.err
  exec \$PY /home/ubuntu/main.py \$APP/context.json
fi`
      : `echo "engine=cascade mode=${mode}"
exec \$PY run_pipeline.py ${mode} \$APP/context.json`;

  return `#!/bin/bash
set -e
cd /home/ubuntu/app/

cat << 'EOF' > /home/ubuntu/app/context.json
${contextJson}
EOF
chown ubuntu:ubuntu /home/ubuntu/app/context.json

# Sync the latest worker scripts from S3 so every instance runs the current
# version pushed from the harmsDetection repo. Both files download to temp
# paths first and only replace the AMI's baked-in copies once both succeed,
# so a failed/partial download can never leave a corrupt worker behind.
mkdir -p /home/ubuntu/app/cascade
/home/ubuntu/app/venv/bin/python3 - << 'SYNC' || echo "worker sync failed, using baked-in scripts"
import boto3, shutil
s3 = boto3.client("s3")
# worker monolítico (fallback local) + firebase_auth
s3.download_file("detection-frames-tests", "worker/heimdall-eye.py", "/tmp/main.py.new")
s3.download_file("detection-frames-tests", "worker/firebase_auth.py", "/tmp/firebase_auth.py.new")
shutil.move("/tmp/main.py.new", "/home/ubuntu/main.py")
shutil.move("/tmp/firebase_auth.py.new", "/home/ubuntu/firebase_auth.py")
# cascada: las capas separadas
for m in ["vision.py", "transport.py", "common.py", "vlm.py", "tiers.py", "run_pipeline.py"]:
    s3.download_file("detection-frames-tests", f"worker/cascade/{m}", f"/tmp/{m}.new")
    shutil.move(f"/tmp/{m}.new", f"/home/ubuntu/app/cascade/{m}")
shutil.copy("/home/ubuntu/firebase_auth.py", "/home/ubuntu/app/cascade/firebase_auth.py")
SYNC
chown -R ubuntu:ubuntu /home/ubuntu/main.py /home/ubuntu/firebase_auth.py /home/ubuntu/app/cascade 2>/dev/null || true

cat << 'LAUNCH' > /home/ubuntu/start-worker.sh
#!/bin/bash
APP=/home/ubuntu/app
PY=\$APP/venv/bin/python3
cd \$APP/cascade
${launcher}
LAUNCH
chmod +x /home/ubuntu/start-worker.sh
chown ubuntu:ubuntu /home/ubuntu/start-worker.sh

cat << 'UNIT' > /etc/systemd/system/heimdall-worker.service
[Unit]
Description=Heimdall detection worker
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/app
Environment=PYTHONUNBUFFERED=1
${envLines}
ExecStart=/home/ubuntu/start-worker.sh
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/worker.log
StandardError=append:/var/log/worker.log

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now heimdall-worker.service
`;
}

async function startInstance(taskId, context, ownerUid, scopeUid, isAdmin) {
  // Idempotent: if this task already has a live worker, return it instead of
  // stacking a duplicate instance.
  const existing = await findTaskInstances(taskId, scopeUid, ["pending", "running"]);
  if (existing.length > 0) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        ok: true,
        action: "start",
        instanceId: existing[0],
        taskId,
        alreadyRunning: true,
      }),
    };
  }

  // Enforcement de plan del lado del servidor. El chequeo del navegador es solo
  // de UX; sin esto, cualquier usuario con token podría encender workers sin
  // plan (saltándose el cobro) y sin límite (disparando la factura de EC2).
  // Los administradores tienen override total.
  if (!isAdmin) {
    const subscription = await getSubscription(ownerUid);
    if (!subscription || subscription.status !== "active") {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({
          message: "Necesitas un plan activo para encender el monitoreo.",
        }),
      };
    }
    const maxCameras = Number(subscription.maxCameras) || 0;
    const running = await countOwnerRunningInstances(ownerUid);
    if (running >= maxCameras) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({
          message: `Alcanzaste el límite de tu plan (${maxCameras} cámaras monitoreadas). Apaga otra cámara o mejora tu plan.`,
        }),
      };
    }
  }

  // El worker obtiene la URL RTSP directamente de Secrets Manager por
  // referencia: pasamos solo el id del secreto, nunca la credencial. Así no
  // queda en el UserData ni en context.json en disco.
  context = { ...context, rtsp_secret_id: `heimdall/rtsp/${taskId}` };
  delete context.rtsp_path; // por si un cliente viejo la envió en el body

  const contextJson = JSON.stringify(context);
  const userDataScript = buildUserData(contextJson, { mode: "local" });

  const res = await ec2.send(
    new RunInstancesCommand({
      LaunchTemplate: {
        LaunchTemplateId: process.env.LAUNCH_TEMPLATE_ID,
        Version: "$Latest",
      },
      MinCount: 1,
      MaxCount: 1,
      UserData: Buffer.from(userDataScript).toString("base64"),
      TagSpecifications: [
        {
          ResourceType: "instance",
          Tags: [
            { Key: "Name", Value: `worker-${taskId}` },
            { Key: "Project", Value: "PythonWorkers" },
            { Key: "TaskId", Value: taskId },
            { Key: "OwnerUid", Value: ownerUid },
          ],
        },
      ],
    })
  );

  const instanceId = res.Instances?.[0]?.InstanceId;

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      ok: true,
      action: "start",
      instanceId,
      taskId,
    }),
  };
}

async function stopInstances(taskId, scopeUid) {
  // Busca las instancias worker de esta tarea que aún no están terminadas
  // (los usuarios normales solo ven las suyas; los admins, todas).
  const instanceIds = await findTaskInstances(taskId, scopeUid, [
    "pending",
    "running",
    "stopping",
    "stopped",
  ]);

  if (instanceIds.length === 0) {
    // Nada que apagar: se considera éxito para que el switch quede apagado.
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        ok: true,
        action: "stop",
        taskId,
        terminatedInstanceIds: [],
        message: "No running instances found for this task",
      }),
    };
  }

  await ec2.send(new TerminateInstancesCommand({ InstanceIds: instanceIds }));

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      ok: true,
      action: "stop",
      taskId,
      terminatedInstanceIds: instanceIds,
    }),
  };
}

function json(statusCode, obj) {
  return { statusCode, headers, body: JSON.stringify(obj) };
}

function parseBody(event) {
  if (event.body == null) return {};
  const raw = event.isBase64Encoded
    ? Buffer.from(event.body, "base64").toString("utf8")
    : event.body;
  return typeof raw === "string" ? JSON.parse(raw) : raw || {};
}

async function findInstancesByRole(role, states) {
  const described = await ec2.send(
    new DescribeInstancesCommand({
      Filters: [
        { Name: "tag:Project", Values: ["PythonWorkers"] },
        { Name: "tag:Role", Values: [role] },
        { Name: "instance-state-name", Values: states },
      ],
    })
  );
  return (described.Reservations ?? []).flatMap((r) =>
    (r.Instances ?? []).map((i) => i.InstanceId)
  );
}

// Levanta la ANALYSIS BOX (CLIP+VLM) si no hay una viva. Idempotente: el motion box
// la llama en cada ráfaga (con debounce), pero nunca se stackea una segunda. La caja
// se apaga sola tras 2h ociosa (watchdog del worker), así que este arranque solo
// ocurre tras un silencio largo.
async function ensureAnalysis() {
  const running = await findInstancesByRole("analysis", ["pending", "running"]);
  if (running.length > 0) {
    return json(200, {
      ok: true,
      action: "ensureAnalysis",
      instanceId: running[0],
      alreadyRunning: true,
    });
  }
  const ctx = {
    idle_shutdown_seconds: Number(process.env.ANALYSIS_IDLE_SECONDS) || 7200,
  };
  const userData = buildUserData(JSON.stringify(ctx), {
    mode: "analysis",
    env: {
      HEIMDALL_CANDIDATE_QUEUE_URL: CANDIDATE_QUEUE_URL,
      HEIMDALL_VLM_QUEUE_URL: VLM_QUEUE_URL,
    },
  });
  const res = await ec2.send(
    new RunInstancesCommand({
      LaunchTemplate: {
        LaunchTemplateId: process.env.LAUNCH_TEMPLATE_ID,
        Version: "$Latest",
      },
      InstanceType: ANALYSIS_INSTANCE_TYPE,
      MinCount: 1,
      MaxCount: 1,
      UserData: Buffer.from(userData).toString("base64"),
      TagSpecifications: [
        {
          ResourceType: "instance",
          Tags: [
            { Key: "Name", Value: "heimdall-analysis" },
            { Key: "Project", Value: "PythonWorkers" },
            { Key: "Role", Value: "analysis" },
          ],
        },
      ],
    })
  );
  return json(200, {
    ok: true,
    action: "ensureAnalysis",
    instanceId: res.Instances?.[0]?.InstanceId,
    started: true,
  });
}

// Levanta el MOTION BOX barato 24/7 con un roster de cámaras. `cameras` = lista de
// {id|device_id, camera_name, client_id, owner_uid, detection_blacklist?}. El RTSP se
// resuelve por referencia al secreto heimdall/rtsp/<id> (nunca viaja la credencial).
async function startMotionBox(cameras) {
  if (!Array.isArray(cameras) || cameras.length === 0) {
    return json(400, { message: "cameras[] requerido" });
  }
  const running = await findInstancesByRole("motion", ["pending", "running"]);
  if (running.length > 0) {
    return json(200, {
      ok: true,
      action: "startMotionBox",
      instanceId: running[0],
      alreadyRunning: true,
    });
  }
  const roster = cameras.map((c) => {
    const id = String(c.id || c.device_id || "");
    return {
      device_id: id,
      camera_name: c.camera_name || c.name || "entrance",
      client_id: c.client_id ?? 1,
      owner_uid: c.owner_uid || "",
      detection_blacklist: c.detection_blacklist || ["persona"],
      rtsp_secret_id: c.rtsp_secret_id || (id ? `heimdall/rtsp/${id}` : undefined),
      rtsp_path: c.rtsp_path,
    };
  });
  const ctx = { cameras: roster, burst_frames: 10, burst_span: 3.0, burst_cooldown: 15.0 };
  const userData = buildUserData(JSON.stringify(ctx), {
    mode: "motion-multi",
    env: {
      HEIMDALL_CANDIDATE_QUEUE_URL: CANDIDATE_QUEUE_URL,
      HEIMDAL_MANAGER_HOST:
        process.env.SELF_HOST || "a2ukt8vyhb.execute-api.us-east-1.amazonaws.com",
      HEIMDALL_INTERNAL_SECRET: INTERNAL_SECRET,
    },
  });
  const res = await ec2.send(
    new RunInstancesCommand({
      LaunchTemplate: {
        LaunchTemplateId: process.env.LAUNCH_TEMPLATE_ID,
        Version: "$Latest",
      },
      InstanceType: MOTION_INSTANCE_TYPE,
      MinCount: 1,
      MaxCount: 1,
      UserData: Buffer.from(userData).toString("base64"),
      TagSpecifications: [
        {
          ResourceType: "instance",
          Tags: [
            { Key: "Name", Value: "heimdall-motion" },
            { Key: "Project", Value: "PythonWorkers" },
            { Key: "Role", Value: "motion" },
          ],
        },
      ],
    })
  );
  return json(200, {
    ok: true,
    action: "startMotionBox",
    instanceId: res.Instances?.[0]?.InstanceId,
    cameras: roster.length,
    started: true,
  });
}

export const handler = async (event) => {
  headers["Access-Control-Allow-Origin"] = allowOrigin(event);
  if (
    event?.requestContext?.http?.method === "OPTIONS" ||
    event?.httpMethod === "OPTIONS"
  ) {
    return {
      statusCode: 200,
      headers,
      body: "",
    };
  }

  console.log("Incoming event:", JSON.stringify(event));

  let action = "start";

  try {
    // Ruta máquina-a-máquina (sin token de usuario): el motion box despierta la
    // analysis box, o un script de cutover levanta la topología. Se autentica con un
    // secreto compartido y se resuelve ANTES del token de usuario.
    const internalSecret =
      event?.headers?.["x-internal-secret"] || event?.headers?.["X-Internal-Secret"];
    if (INTERNAL_SECRET && internalSecret && internalSecret === INTERNAL_SECRET) {
      let ibody = {};
      try {
        ibody = parseBody(event);
      } catch (e) {
        return json(400, { message: "Invalid JSON body" });
      }
      if (ibody.action === "ensureAnalysis") return await ensureAnalysis();
      if (ibody.action === "startMotionBox") return await startMotionBox(ibody.cameras);
      return json(400, { message: `Unknown internal action: ${ibody.action}` });
    }

    const token = getBearerToken(event);

    if (!token) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ message: "Unauthorized: missing token" }),
      };
    }

    await ensureFirebase();
    const decoded = await admin.auth().verifyIdToken(token);
    const ownerUid = decoded.uid;
    const isAdmin = decoded.role === "admin";
    // Los administradores (custom claim role=admin, firmado en el token)
    // pueden apagar instancias de cualquier usuario.
    const scopeUid = isAdmin ? null : ownerUid;

    let taskId = Date.now().toString();
    let context = {
      instance_id: 2,
      client_id: 2,
      camera_name: "entrance_instance",
      detection_blacklist: ["person"],
      rtsp_path: "rtsp://admin551:123456789@4.tcp.ngrok.io:17829/stream1",
    };
    let taskIdProvided = false;

    // Un body que no se puede interpretar es un 400, nunca un fallback a
    // "start": un stop malformado no debe lanzar una instancia nueva.
    let body = {};
    if (event.body != null) {
      try {
        const rawBody = event.isBase64Encoded
          ? Buffer.from(event.body, "base64").toString("utf8")
          : event.body;
        body = typeof rawBody === "string" ? JSON.parse(rawBody) : (rawBody || {});
      } catch (e) {
        console.warn("Could not parse body:", e);
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ message: "Invalid JSON body" }),
        };
      }
    }

    if (body.action) action = body.action;
    if (body.taskId) {
      taskId = String(body.taskId);
      taskIdProvided = true;
      if (!TASK_ID_PATTERN.test(taskId)) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ message: "Invalid taskId" }),
        };
      }
    }
    if (body.context) context = body.context;

    if (action === "stop") {
      if (!taskIdProvided) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ message: "taskId is required to stop instances" }),
        };
      }
      return await stopInstances(taskId, scopeUid);
    }

    if (action !== "start") {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: `Unknown action: ${action}` }),
      };
    }

    return await startInstance(taskId, context, ownerUid, scopeUid, isAdmin);
  } catch (err) {
    // Solo los errores de firebase-admin (code "auth/...") son 401; buscar
    // "token" en el mensaje confundía errores de credenciales del SDK de AWS
    // ("The security token included in the request is invalid") con fallos de
    // autenticación del usuario.
    const isAuthError = err?.code?.startsWith?.("auth/") === true;

    return {
      statusCode: isAuthError ? 401 : 500,
      headers,
      body: JSON.stringify({
        message: isAuthError
          ? "Unauthorized"
          : action === "stop"
            ? "Error stopping instance"
            : "Error starting instance",
        error: err?.message ?? "Unknown error",
      }),
    };
  }
};
