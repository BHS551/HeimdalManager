# Contexto del proyecto SkyEye

**SkyEye** (nombre interno: Heimdall) es una plataforma SaaS de videovigilancia
inteligente: convierte cámaras IP/RTSP existentes en un sistema de detección de
eventos con IA (OpenAI CLIP) y alertas en tiempo real (SMS/correo) con
evidencia. UI en español, mercado inicial Colombia.

**Este repo:** 5 Lambdas de orquestación: start/stop de workers EC2 (index.mjs), suscripciones, ajustes de usuario, eventos del worker (heartbeat/notify) y notificaciones al admin.

**Documento maestro** (arquitectura completa, recursos AWS, flujos, historial y
pendientes): `docs/SKYEYE_PROJECT.md` en el repo `harmsDetectionLandingUi`.

## Los 7 repos del proyecto

- `harmsDetectionLandingUi` — Landing + consola (Next.js 15, Vercel, Firebase Auth).
- `HeimdalManager` — Lambdas de orquestación (start/stop EC2, subscriptions, userSettings, workerEvents, notifyAdmin).
- `StoreDevice` / `ListDevices` — alta y listado de cámaras.
- `StoreDetection` / `ListDetections` — guardado y listado de detecciones.
- `harmsDetection` — worker Python de detección (Heimdall Eye) en EC2.

## Hechos clave

- Auth: Firebase (proyecto `login-69a8a`), Bearer ID token en toda llamada;
  admin = custom claim `{ role: "admin" }`. Solo errores `auth/*` son 401.
- AWS us-east-1. DynamoDB: `detections` (devices + events, GSI `owner-index`,
  TTL 30 días en events), `subscriptions`, `userSettings`, `workerStatus`.
- S3 `detection-frames-tests`: `cameras/` frames de evidencia (caducan a 7
  días), `worker/` código vigente del worker.
- Secrets Manager: `heimdall/firebase` (service account) y
  `heimdall/rtsp/<deviceId>` (URL RTSP con credenciales; nunca al navegador).
- Un worker EC2 por cámara (tags Project=PythonWorkers, TaskId, OwnerUid),
  systemd `heimdall-worker.service`, código sincronizado desde S3 al arrancar.
- Planes: `cam5` (5 cámaras, $50/mes) y `cam1` (1 cámara, $1, solo admin);
  tope de cámaras validado del lado del servidor. Pago hoy: solicitud manual
  al admin vía SNS (`plan_request`); PayU/Stripe integrados pero en pausa.
- CORS restringido en todas las Lambdas (`ALLOWED_ORIGINS` + previews Vercel
  + localhost). SES pendiente: correo al usuario sale por el tópico SNS del
  admin como fallback temporal.
