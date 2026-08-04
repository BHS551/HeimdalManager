// notifyAdmin.mjs — Lambda que notifica al administrador por SNS (email).
//
// Dos tipos de notificación:
//  - {type:"contact", name, email, message}  (formulario público de la landing)
//  - {type:"plan_request", planId}           (requiere token Firebase; reemplaza
//    temporalmente el pago: el admin activa el plan a mano)
import admin from "firebase-admin";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";

const sns = new SNSClient({ region: process.env.AWS_REGION || "us-east-1" });

const headers = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
};

if (
  !process.env.FIREBASE_PROJECT_ID ||
  !process.env.FIREBASE_CLIENT_EMAIL ||
  !process.env.FIREBASE_PRIVATE_KEY ||
  !process.env.TOPIC_ARN
) {
  throw new Error("Missing environment variables");
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

// Catálogo mínimo para armar el correo; la fuente de verdad sigue siendo
// src/lib/plans.ts en la UI.
const PLAN_INFO = {
  cam5: "5 cámaras — $50 USD/mes",
  cam1: "1 cámara — $1 USD/mes (solo administradores)",
};

function getBearerToken(event) {
  const authHeader =
    event?.headers?.Authorization || event?.headers?.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  return authHeader.slice("Bearer ".length).trim();
}

function response(statusCode, payload) {
  return { statusCode, headers, body: JSON.stringify(payload) };
}

const clean = (value, maxLen) =>
  typeof value === "string" ? value.trim().slice(0, maxLen) : "";

async function publish(subject, message) {
  await sns.send(
    new PublishCommand({
      TopicArn: process.env.TOPIC_ARN,
      Subject: subject.slice(0, 100),
      Message: message,
    })
  );
}

export const handler = async (event) => {
  const method =
    event?.requestContext?.http?.method || event?.httpMethod || "POST";
  if (method === "OPTIONS") {
    return { statusCode: 200, headers, body: "" };
  }

  try {
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

    if (body.type === "contact") {
      // Honeypot: los bots rellenan el campo oculto "website"; se responde 200
      // sin publicar nada para no darles señal.
      if (body.website) {
        return response(200, { ok: true });
      }

      const name = clean(body.name, 100);
      const email = clean(body.email, 200);
      const message = clean(body.message, 2000);
      if (!name || !email || !message) {
        return response(400, { message: "name, email y message son requeridos" });
      }

      await publish(
        "SkyEye: nuevo mensaje de contacto",
        [
          "Nuevo mensaje desde el formulario de contacto de SkyEye:",
          "",
          `Nombre: ${name}`,
          `Correo: ${email}`,
          "",
          "Mensaje:",
          message,
        ].join("\n")
      );
      return response(200, { ok: true });
    }

    if (body.type === "plan_request") {
      const token = getBearerToken(event);
      if (!token) {
        return response(401, { message: "Unauthorized: missing token" });
      }
      const decoded = await admin.auth().verifyIdToken(token);

      const planId = clean(body.planId, 50);
      if (!PLAN_INFO[planId]) {
        return response(400, { message: "Plan desconocido" });
      }

      await publish(
        `SkyEye: solicitud de plan ${planId}`,
        [
          "Un usuario quiere contratar un plan (activación manual pendiente):",
          "",
          `Plan: ${planId} (${PLAN_INFO[planId]})`,
          "",
          `UID: ${decoded.uid}`,
          `Correo: ${decoded.email || "(sin correo)"}`,
          `Nombre: ${decoded.name || "(sin nombre)"}`,
          "",
          "Actívalo creando/actualizando su suscripción en Firestore.",
        ].join("\n")
      );
      return response(200, {
        ok: true,
        message:
          "Se ha contactado al administrador para activar tu plan. Te avisaremos en cuanto esté activo.",
      });
    }

    return response(400, { message: "Unknown notification type" });
  } catch (err) {
    const isAuthError = err?.code?.startsWith?.("auth/") === true;
    return response(isAuthError ? 401 : 500, {
      message: isAuthError ? "Unauthorized" : "Error sending notification",
      error: err?.message ?? "Unknown error",
    });
  }
};
