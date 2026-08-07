// workerEvents.mjs — eventos del worker Heimdall y estado para la consola.
//
// action "heartbeat" (worker): registra que el worker sigue vivo (workerStatus).
// action "notify"    (worker): avisa al usuario por sus canales (SMS/email) que
//                              configuró en "Mi cuenta" (userSettings).
// action "status"    (UI):     el dueño consulta el estado en vivo de su cámara.
//
// El token Firebase se verifica siempre. heartbeat/notify toman el owner_uid del
// cuerpo, así que además EXIGEN que quien llama sea el worker (uid de servicio
// WORKER_SERVICE_UID): verificar el token no basta, porque cualquiera puede
// registrarse en la app y poner el uid ajeno que quiera en el body. Para status,
// el uid sale del token y cada usuario solo ve lo suyo.
import admin from "firebase-admin";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const sns = new SNSClient({ region: process.env.AWS_REGION || "us-east-1" });
const ses = new SESv2Client({ region: process.env.AWS_REGION || "us-east-1" });

const STATUS_TABLE = "workerStatus";
const USER_SETTINGS_TABLE = "userSettings";
const SES_SENDER = process.env.SES_SENDER || ""; // remitente verificado en SES
// Canal de email TEMPORAL mientras SES no está configurado: se publica al
// tópico SNS del administrador (entrega a su correo confirmado).
const ADMIN_TOPIC_ARN = process.env.ADMIN_TOPIC_ARN || "";

const headers = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
};

// --- firebase-admin desde Secrets Manager (mismo patrón que el resto) ---
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
        sa = JSON.parse(res.SecretString).service_account;
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
            privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
          });
      admin.initializeApp({ credential });
    })();
  }
  return firebaseReady;
}

// --- CORS: refleja origen permitido (solo importa para "status" desde el navegador) ---
const STATIC_ALLOWED = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map((s) => s.trim()).filter(Boolean);
const DEFAULT_ORIGIN =
  STATIC_ALLOWED[0] || "https://harms-detection-landing-ui-seven.vercel.app";
function allowOrigin(event) {
  const origin = event?.headers?.origin || event?.headers?.Origin || "";
  const ok =
    STATIC_ALLOWED.includes(origin) ||
    /^https:\/\/([a-z0-9-]+\.)*vercel\.app$/i.test(origin) ||
    /^http:\/\/localhost(:\d+)?$/i.test(origin);
  return ok ? origin : DEFAULT_ORIGIN;
}

function getBearerToken(event) {
  const h = event?.headers?.Authorization || event?.headers?.authorization;
  if (!h || !h.startsWith("Bearer ")) return null;
  return h.slice("Bearer ".length).trim();
}
function response(statusCode, payload) {
  return { statusCode, headers, body: JSON.stringify(payload) };
}

// Identidad de servicio del worker: firebase_auth.py firma un custom token para el
// uid "heimdall", así que las acciones que hablan en nombre de un tercero
// (heartbeat y notify llevan owner_uid en el cuerpo) solo pueden venir de ahí.
// Antes bastaba CUALQUIER token válido: como el registro de la app es abierto,
// cualquier cuenta podía mandar SMS y correos al teléfono de otro usuario con solo
// poner su uid en el body, o falsear el estado de sus cámaras.
const WORKER_SERVICE_UID = process.env.WORKER_SERVICE_UID || "heimdall";

function isWorker(decoded) {
  return decoded?.uid === WORKER_SERVICE_UID || decoded?.role === "worker";
}

async function sendUserNotification(ownerUid, info) {
  const res = await ddb.send(
    new GetCommand({ TableName: USER_SETTINGS_TABLE, Key: { uid: ownerUid } })
  );
  const settings = res.Item;
  if (!settings) return { delivered: [], reason: "no settings" };

  const line = `SkyEye: detección "${info.event_type}" en ${info.camera}.`;
  const delivered = [];

  if (settings.notificationPhone) {
    try {
      await sns.send(
        new PublishCommand({ PhoneNumber: settings.notificationPhone, Message: line })
      );
      delivered.push("sms");
    } catch (e) {
      console.warn("SMS falló:", e?.name || e?.message);
    }
  }
  if (settings.notificationEmail) {
    const emailBody =
      `${line}\n\nDestinatario: ${settings.notificationEmail}\n` +
      `Evento: ${info.event_type}\nCámara: ${info.camera}\n` +
      `Confianza: ${info.cosine_sim ?? "-"}\nID: ${info.detection_id ?? "-"}`;
    if (SES_SENDER) {
      try {
        await ses.send(
          new SendEmailCommand({
            FromEmailAddress: SES_SENDER,
            Destination: { ToAddresses: [settings.notificationEmail] },
            Content: {
              Simple: {
                Subject: { Data: `SkyEye: ${info.event_type}` },
                Body: { Text: { Data: emailBody } },
              },
            },
          })
        );
        delivered.push("email");
      } catch (e) {
        console.warn("Email (SES) falló:", e?.name || e?.message);
      }
    } else if (ADMIN_TOPIC_ARN) {
      // Fallback temporal: al no haber SES, se avisa por el tópico del admin.
      try {
        await sns.send(
          new PublishCommand({
            TopicArn: ADMIN_TOPIC_ARN,
            Subject: `SkyEye: ${info.event_type}`.slice(0, 100),
            Message: emailBody,
          })
        );
        delivered.push("email-via-admin-topic");
      } catch (e) {
        console.warn("Email (SNS admin) falló:", e?.name || e?.message);
      }
    }
  }
  return { delivered };
}

export const handler = async (event) => {
  headers["Access-Control-Allow-Origin"] = allowOrigin(event);
  const method =
    event?.requestContext?.http?.method || event?.httpMethod || "POST";
  if (method === "OPTIONS") return { statusCode: 200, headers, body: "" };

  try {
    const token = getBearerToken(event);
    if (!token) return response(401, { message: "Unauthorized: missing token" });
    await ensureFirebase();
    const decoded = await admin.auth().verifyIdToken(token);

    // GET ?device_id= : estado en vivo para el dueño (navegador)
    if (method === "GET") {
      const deviceId = event?.queryStringParameters?.device_id;
      if (!deviceId) return response(400, { message: "device_id requerido" });
      const res = await ddb.send(
        new GetCommand({ TableName: STATUS_TABLE, Key: { device_id: deviceId } })
      );
      const item = res.Item;
      // El usuario solo ve el estado de sus propias cámaras.
      if (!item || item.owner_uid !== decoded.uid) {
        return response(200, { status: null });
      }
      const ageMs = Date.now() - new Date(item.lastSeen).getTime();
      return response(200, {
        status: {
          ...item,
          // "online" si latió en los últimos 90s.
          online: ageMs < 90_000,
        },
      });
    }

    let body = {};
    if (event.body != null) {
      try {
        const raw = event.isBase64Encoded
          ? Buffer.from(event.body, "base64").toString("utf8")
          : event.body;
        body = typeof raw === "string" ? JSON.parse(raw) : (raw || {});
      } catch {
        return response(400, { message: "Invalid JSON body" });
      }
    }

    // heartbeat y notify actúan sobre el owner_uid que viaja en el cuerpo, así que
    // exigen la identidad del worker; el token de un usuario normal no basta.
    if (body.action === "heartbeat" || body.action === "notify") {
      if (!isWorker(decoded)) {
        return response(403, { message: "Solo el worker puede emitir eventos de dispositivo" });
      }
    }

    if (body.action === "heartbeat") {
      const deviceId = String(body.device_id || "");
      if (!deviceId) return response(400, { message: "device_id requerido" });
      await ddb.send(
        new PutCommand({
          TableName: STATUS_TABLE,
          Item: {
            device_id: deviceId,
            owner_uid: String(body.owner_uid || ""),
            camera_name: String(body.camera_name || ""),
            status: String(body.status || "running"),
            lastSeen: new Date().toISOString(),
          },
        })
      );
      return response(200, { ok: true });
    }

    if (body.action === "notify") {
      const ownerUid = String(body.owner_uid || "");
      if (!ownerUid) return response(400, { message: "owner_uid requerido" });
      const result = await sendUserNotification(ownerUid, {
        event_type: String(body.event_type || "detección"),
        camera: String(body.camera || ""),
        cosine_sim: body.cosine_sim,
        detection_id: body.detection_id,
      });
      return response(200, { ok: true, ...result });
    }

    return response(400, { message: `Unknown action: ${body.action}` });
  } catch (err) {
    const isAuthError = err?.code?.startsWith?.("auth/") === true;
    return response(isAuthError ? 401 : 500, {
      message: isAuthError ? "Unauthorized" : "Error handling worker event",
      error: err?.message ?? "Unknown error",
    });
  }
};
