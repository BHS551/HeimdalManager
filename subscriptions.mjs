// subscriptions.mjs — Lambda de suscripciones (reemplaza Firestore, que no
// existe en el proyecto Firebase).
//
// GET           -> suscripción del usuario autenticado.
// GET ?all=1    -> (solo admin) todas las suscripciones.
// POST activate/deactivate -> (solo admin) activa o desactiva el plan de un
//   usuario identificado por correo o uid. El rol admin viene del custom
//   claim { role: "admin" } firmado dentro del ID token.
import admin from "firebase-admin";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand, ScanCommand } from "@aws-sdk/lib-dynamodb";

const client = new DynamoDBClient({});
const ddb = DynamoDBDocumentClient.from(client);

const TABLE_NAME = "subscriptions";

// Catálogo mínimo; la fuente de verdad de la UI es src/lib/plans.ts.
const PLAN_CAMERAS = { cam5: 5, cam1: 1 };

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

async function resolveUser(identifier) {
  return identifier.includes("@")
    ? admin.auth().getUserByEmail(identifier)
    : admin.auth().getUser(identifier);
}

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
    const isAdmin = decoded.role === "admin";

    if (method === "GET") {
      const wantsAll =
        event?.queryStringParameters?.all === "1" ||
        event?.rawQueryString?.includes("all=1");

      if (wantsAll) {
        if (!isAdmin) {
          return response(403, { message: "Solo administradores" });
        }
        const res = await ddb.send(new ScanCommand({ TableName: TABLE_NAME }));
        return response(200, { subscriptions: res.Items ?? [] });
      }

      const res = await ddb.send(
        new GetCommand({ TableName: TABLE_NAME, Key: { uid: decoded.uid } })
      );
      return response(200, { subscription: res.Item ?? null });
    }

    if (method === "POST") {
      if (!isAdmin) {
        return response(403, { message: "Solo administradores" });
      }

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

      const action = body.action;
      const identifier =
        typeof body.identifier === "string" ? body.identifier.trim() : "";
      if (!identifier) {
        return response(400, { message: "identifier (correo o uid) es requerido" });
      }

      let targetUser;
      try {
        targetUser = await resolveUser(identifier);
      } catch {
        return response(404, { message: `No existe un usuario para "${identifier}"` });
      }

      if (action === "activate") {
        const planId = typeof body.planId === "string" ? body.planId : "";
        if (!PLAN_CAMERAS[planId]) {
          return response(400, { message: "Plan desconocido" });
        }
        const item = {
          uid: targetUser.uid,
          email: targetUser.email || "",
          plan: planId,
          maxCameras: PLAN_CAMERAS[planId],
          status: "active",
          activatedBy: decoded.email || decoded.uid,
          updatedAt: new Date().toISOString(),
        };
        await ddb.send(new PutCommand({ TableName: TABLE_NAME, Item: item }));
        return response(200, { ok: true, subscription: item });
      }

      if (action === "deactivate") {
        const existing = await ddb.send(
          new GetCommand({ TableName: TABLE_NAME, Key: { uid: targetUser.uid } })
        );
        if (!existing.Item) {
          return response(404, { message: "El usuario no tiene suscripción" });
        }
        const item = {
          ...existing.Item,
          status: "canceled",
          activatedBy: decoded.email || decoded.uid,
          updatedAt: new Date().toISOString(),
        };
        await ddb.send(new PutCommand({ TableName: TABLE_NAME, Item: item }));
        return response(200, { ok: true, subscription: item });
      }

      return response(400, { message: `Unknown action: ${action}` });
    }

    return response(405, { message: "Method not allowed" });
  } catch (err) {
    const isAuthError = err?.code?.startsWith?.("auth/") === true;
    return response(isAuthError ? 401 : 500, {
      message: isAuthError ? "Unauthorized" : "Error handling subscriptions",
      error: err?.message ?? "Unknown error",
    });
  }
};
