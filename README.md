# HeimdalManager

Backend de orquestación de **SkyEye** (plataforma de monitoreo de seguridad
con IA). Este repo agrupa las **5 Lambdas Node.js** que gestionan el ciclo de
vida de los workers de detección y los servicios de cuenta/plan del usuario.

> 📚 Contexto completo del proyecto: `docs/SKYEYE_PROJECT.md` en el repo
> `harmsDetectionLandingUi`.

## Lambdas de este repo

| Archivo | Función |
|---|---|
| `index.mjs` | **Start/stop de workers**: lanza (o termina) una instancia EC2 por cámara desde un launch template, con tags `Project=PythonWorkers`, `TaskId`, `OwnerUid`. Idempotente en start; valida plan activo y cupo de cámaras del lado del servidor (los admin tienen override y pueden apagar instancias de cualquier usuario). Pasa al worker solo la **referencia** al secreto RTSP (`heimdall/rtsp/<taskId>`), nunca la credencial, e instala el servicio systemd `heimdall-worker.service` vía UserData (con sincronización del código del worker desde S3). |
| `subscriptions.mjs` | **Suscripciones** (DynamoDB `subscriptions`). `GET` devuelve el plan del usuario; `GET ?all=1` (solo admin) todas; `POST activate/deactivate` (solo admin) activa o cancela el plan de un usuario por correo o uid. |
| `userSettings.mjs` | **Ajustes del usuario** (DynamoDB `userSettings`): canales de notificación (correo/teléfono) del panel "Mi cuenta". El uid sale siempre del token, nunca del body. |
| `workerEvents.mjs` | **Eventos del worker**: `heartbeat` (estado vivo en DynamoDB `workerStatus`; la UI marca "online" si latió hace <90 s), `notify` (avisa al usuario por SMS vía SNS y correo vía SES — con fallback temporal al tópico SNS del admin mientras SES no está configurado) y `GET ?device_id=` (estado en vivo para el dueño). |
| `notifyAdmin.mjs` | **Notificaciones al administrador** por SNS: `type:"contact"` (formulario de la landing, con honeypot anti-bots) y `type:"plan_request"` (solicitud de plan; reemplaza temporalmente el pago automático: el admin activa el plan a mano en `/console/admin`). |

## Patrones comunes

- **Auth**: todas las Lambdas verifican `Authorization: Bearer <ID token>` de
  Firebase; el rol admin es el custom claim `{ role: "admin" }`. Solo errores
  `auth/*` devuelven 401.
- **Credenciales Firebase** desde Secrets Manager (`heimdall/firebase`), con
  fallback a env vars solo para rollback.
- **CORS** restringido: dominio de la app + previews de Vercel + localhost
  (configurable con `ALLOWED_ORIGINS`).

## Variables de entorno

| Variable | Uso |
|---|---|
| `LAUNCH_TEMPLATE_ID` | Launch template EC2 de los workers (`index.mjs`) |
| `FIREBASE_SECRET_ID` | Id del secreto de Firebase (default `heimdall/firebase`) |
| `ALLOWED_ORIGINS` | Lista de orígenes CORS separados por comas |
| `TOPIC_ARN` | Tópico SNS del admin (`notifyAdmin.mjs`) |
| `ADMIN_TOPIC_ARN` | Fallback de correo vía SNS (`workerEvents.mjs`) |
| `SES_SENDER` | Remitente verificado en SES (correo al usuario) |
| `AWS_REGION` | Región (default `us-east-1`) |

## Recursos AWS que toca

EC2 (RunInstances/Describe/Terminate), DynamoDB (`subscriptions`,
`userSettings`, `workerStatus`), Secrets Manager (`heimdall/firebase`,
`heimdall/rtsp/*`), SNS, SES.
