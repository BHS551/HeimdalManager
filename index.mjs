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

  const contextJson = JSON.stringify(context);

  const userDataScript = `#!/bin/bash
cd /home/ubuntu/app/

cat << 'EOF' > /home/ubuntu/app/context.json
${contextJson}
EOF

# Sync the latest worker scripts from S3 so every instance runs the current
# version pushed from the harmsDetection repo. Both files download to temp
# paths first and only replace the AMI's baked-in copies once both succeed,
# so a failed/partial download can never leave a corrupt worker behind.
/home/ubuntu/app/venv/bin/python3 - << 'SYNC' || echo "worker sync failed, using baked-in scripts"
import boto3, shutil
s3 = boto3.client("s3")
s3.download_file("detection-frames-tests", "worker/heimdall-eye.py", "/tmp/main.py.new")
s3.download_file("detection-frames-tests", "worker/firebase_auth.py", "/tmp/firebase_auth.py.new")
shutil.move("/tmp/main.py.new", "/home/ubuntu/main.py")
shutil.move("/tmp/firebase_auth.py.new", "/home/ubuntu/firebase_auth.py")
SYNC

nohup /home/ubuntu/app/venv/bin/python3 /home/ubuntu/main.py > /var/log/worker.log 2>&1 &
`;

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
