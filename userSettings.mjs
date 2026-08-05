// userSettings.mjs — Lambda de configuración de usuario (panel "Mi cuenta").
//
// GET  -> devuelve la configuración del usuario autenticado (o {} si no hay).
// POST -> guarda { notificationEmail, notificationPhone } para ese usuario.
// El uid sale SIEMPRE del token Firebase verificado, nunca del body.
import admin from "firebase-admin";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";

const client = new DynamoDBClient({});
const ddb = DynamoDBDocumentClient.from(client);

const TABLE_NAME = "userSettings";

const headers = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
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
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  return authHeader.slice("Bearer ".length).trim();
}

function response(statusCode, payload) {
  return { statusCode, headers, body: JSON.stringify(payload) };
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_PATTERN = /^\+?[0-9()\-\s]{7,20}$/;

export const handler = async (event) => {
  headers["Access-Control-Allow-Origin"] = allowOrigin(event);
  const method =
    event?.requestContext?.http?.method || event?.httpMethod || "GET";
  if (method === "OPTIONS") {
    return { statusCode: 200, headers, body: "" };
  }

  try {
    const token = getBearerToken(event);
    if (!token) {
      return response(401, { message: "Unauthorized: missing token" });
    }
    await ensureFirebase();
    const decoded = await admin.auth().verifyIdToken(token);
    const uid = decoded.uid;

    if (method === "GET") {
      const res = await ddb.send(
        new GetCommand({ TableName: TABLE_NAME, Key: { uid } })
      );
      return response(200, { settings: res.Item ?? null });
    }

    if (method === "POST") {
      let body = {};
      if (event.body != null) {
        try {
          const rawBody = event.isBase64Encoded
            ? Buffer.from(event.body, "base64").toString("utf8")
            : event.body;
          body = typeof rawBody === "string" ? JSON.parse(rawBody) : (rawBody || {});
        } catch {
          return response(400, { message: "Invalid JSON body" });
        }
      }

      const notificationEmail =
        typeof body.notificationEmail === "string"
          ? body.notificationEmail.trim().slice(0, 200)
          : "";
      const notificationPhone =
        typeof body.notificationPhone === "string"
          ? body.notificationPhone.trim().slice(0, 30)
          : "";

      if (notificationEmail && !EMAIL_PATTERN.test(notificationEmail)) {
        return response(400, { message: "El correo de notificaciones no es válido" });
      }
      if (notificationPhone && !PHONE_PATTERN.test(notificationPhone)) {
        return response(400, { message: "El teléfono de notificaciones no es válido" });
      }
      if (!notificationEmail && !notificationPhone) {
        return response(400, {
          message: "Configura al menos un canal de notificación (correo o teléfono)",
        });
      }

      const item = {
        uid,
        notificationEmail,
        notificationPhone,
        // Datos de contexto útiles para el admin al mirar la tabla.
        accountEmail: decoded.email || "",
        updatedAt: new Date().toISOString(),
      };
      await ddb.send(new PutCommand({ TableName: TABLE_NAME, Item: item }));
      return response(200, { ok: true, settings: item });
    }

    return response(405, { message: "Method not allowed" });
  } catch (err) {
    const isAuthError = err?.code?.startsWith?.("auth/") === true;
    return response(isAuthError ? 401 : 500, {
      message: isAuthError ? "Unauthorized" : "Error handling user settings",
      error: err?.message ?? "Unknown error",
    });
  }
};
