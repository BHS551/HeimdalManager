// index.mjs
import admin from "firebase-admin";
import {
  EC2Client,
  RunInstancesCommand,
  DescribeInstancesCommand,
} from "@aws-sdk/client-ec2";

const ec2 = new EC2Client({ region: process.env.AWS_REGION || "us-east-1" });

// --- Límites de capacidad (configurables por variables de entorno) ---
// Por defecto: máx 5 cámaras por usuario y máx 8 usuarios activos => tope global de 40 EC2.
const MAX_CAMERAS_PER_USER = parseInt(
  process.env.MAX_CAMERAS_PER_USER || "5",
  10
);
const MAX_USERS = parseInt(process.env.MAX_USERS || "8", 10);
const MAX_TOTAL_INSTANCES = parseInt(
  process.env.MAX_TOTAL_INSTANCES || String(MAX_CAMERAS_PER_USER * MAX_USERS),
  10
);
// Tag de proyecto con el que se etiquetan (y por el que se cuentan) los workers.
const PROJECT_TAG = process.env.PROJECT_TAG || "PythonWorkers";

const headers = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
};

if (
  !process.env.FIREBASE_PROJECT_ID ||
  !process.env.FIREBASE_CLIENT_EMAIL ||
  !process.env.FIREBASE_PRIVATE_KEY
) {
  throw new Error("Missing Firebase environment variables");
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });
}

function getBearerToken(event) {
  const authHeader =
    event?.headers?.Authorization || event?.headers?.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }

  return authHeader.slice("Bearer ".length).trim();
}

function respond(statusCode, payload) {
  return {
    statusCode,
    headers,
    body: typeof payload === "string" ? payload : JSON.stringify(payload),
  };
}

/**
 * Lista los workers de SkyEye actualmente activos (pending|running),
 * con el uid de su dueño (tag owner_uid). Es la fuente de verdad para el cupo.
 * Pagina por si hubiera muchos resultados.
 */
async function listActiveWorkers() {
  const workers = [];
  let nextToken;

  do {
    const resp = await ec2.send(
      new DescribeInstancesCommand({
        Filters: [
          { Name: "tag:Project", Values: [PROJECT_TAG] },
          { Name: "instance-state-name", Values: ["pending", "running"] },
        ],
        NextToken: nextToken,
      })
    );

    for (const reservation of resp.Reservations || []) {
      for (const inst of reservation.Instances || []) {
        const ownerTag = (inst.Tags || []).find((t) => t.Key === "owner_uid");
        workers.push({
          instanceId: inst.InstanceId,
          ownerUid: ownerTag?.Value || null,
        });
      }
    }

    nextToken = resp.NextToken;
  } while (nextToken);

  return workers;
}

export const handler = async (event) => {
  if (
    event?.requestContext?.http?.method === "OPTIONS" ||
    event?.httpMethod === "OPTIONS"
  ) {
    return respond(200, "");
  }

  console.log("Incoming event:", JSON.stringify(event));

  try {
    const token = getBearerToken(event);

    if (!token) {
      return respond(401, { message: "Unauthorized: missing token" });
    }

    // 1) Verificar identidad (Firebase) y obtener el uid real del request.
    const decoded = await admin.auth().verifyIdToken(token);
    const uid = decoded.uid;

    // 2) Parsear el body / contexto de la cámara.
    let taskId = Date.now().toString();
    let context = {
      instance_id: 2,
      client_id: 2,
      camera_name: "entrance_instance",
      detection_blacklist: ["person"],
      rtsp_path: "rtsp://admin551:123456789@4.tcp.ngrok.io:17829/stream1",
    };

    try {
      const body =
        typeof event.body === "string"
          ? JSON.parse(event.body)
          : event.body || {};
      if (body.taskId) taskId = body.taskId;
      if (body.context) context = body.context;
    } catch (e) {
      console.warn("Could not parse body:", e);
    }

    // 3) Verificar el cupo contra las instancias EC2 realmente activas.
    //    Fail-closed: si no podemos verificar la capacidad, NO arrancamos.
    let activeWorkers;
    try {
      activeWorkers = await listActiveWorkers();
    } catch (e) {
      console.error("Could not describe instances for quota check:", e);
      return respond(503, {
        message:
          "No se pudo verificar la capacidad disponible. Intenta de nuevo.",
      });
    }

    const totalActive = activeWorkers.length;
    const myActive = activeWorkers.filter((w) => w.ownerUid === uid).length;
    const distinctUsers = new Set(
      activeWorkers.filter((w) => w.ownerUid).map((w) => w.ownerUid)
    );

    // 3a) Tope por usuario (máx 5 cámaras).
    if (myActive >= MAX_CAMERAS_PER_USER) {
      return respond(403, {
        message: `Alcanzaste el límite de ${MAX_CAMERAS_PER_USER} cámaras monitoreadas. Apaga otra cámara antes de encender esta.`,
        code: "USER_CAMERA_LIMIT",
        limit: MAX_CAMERAS_PER_USER,
        current: myActive,
      });
    }

    // 3b) Tope de usuarios activos simultáneos (máx 8).
    //     Solo bloquea si este usuario aún NO tiene cámaras encendidas
    //     (si ya es un usuario activo, no consume un nuevo "cupo de usuario").
    if (!distinctUsers.has(uid) && distinctUsers.size >= MAX_USERS) {
      return respond(403, {
        message: `Capacidad máxima alcanzada (${MAX_USERS} usuarios monitoreando al mismo tiempo). Intenta más tarde.`,
        code: "GLOBAL_USER_LIMIT",
        limit: MAX_USERS,
        current: distinctUsers.size,
      });
    }

    // 3c) Tope global de instancias (red de seguridad: 5 x 8 = 40).
    if (totalActive >= MAX_TOTAL_INSTANCES) {
      return respond(403, {
        message: `Capacidad máxima del sistema alcanzada (${MAX_TOTAL_INSTANCES} cámaras activas). Intenta más tarde.`,
        code: "GLOBAL_INSTANCE_LIMIT",
        limit: MAX_TOTAL_INSTANCES,
        current: totalActive,
      });
    }

    // 4) Arrancar el worker. Etiquetamos con owner_uid = uid VERIFICADO
    //    (no el del body) para que el conteo de cupo no se pueda falsear.
    const contextJson = JSON.stringify(context);

    const userDataScript = `#!/bin/bash
cd /home/ubuntu/app/

cat << 'EOF' > /home/ubuntu/app/context.json
${contextJson}
EOF

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
              { Key: "Project", Value: PROJECT_TAG },
              { Key: "TaskId", Value: taskId },
              { Key: "owner_uid", Value: uid },
              ...(context?.client_id != null
                ? [{ Key: "client_id", Value: String(context.client_id) }]
                : []),
            ],
          },
        ],
      })
    );

    const instanceId = res.Instances?.[0]?.InstanceId;

    return respond(200, {
      ok: true,
      instanceId,
      taskId,
      quota: {
        userActive: myActive + 1,
        userLimit: MAX_CAMERAS_PER_USER,
        totalActive: totalActive + 1,
        totalLimit: MAX_TOTAL_INSTANCES,
      },
    });
  } catch (err) {
    const isAuthError =
      err?.code?.startsWith?.("auth/") ||
      err?.message?.toLowerCase?.().includes("token");

    return respond(isAuthError ? 401 : 500, {
      message: isAuthError ? "Unauthorized" : "Error starting instance",
      error: err?.message ?? "Unknown error",
    });
  }
};
