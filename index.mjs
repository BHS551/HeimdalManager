// index.mjs
import admin from "firebase-admin";
import {
  EC2Client,
  RunInstancesCommand,
  DescribeInstancesCommand,
  TerminateInstancesCommand,
} from "@aws-sdk/client-ec2";

const ec2 = new EC2Client({ region: process.env.AWS_REGION || "us-east-1" });

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

async function startInstance(taskId, context) {
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
            { Key: "Project", Value: "PythonWorkers" },
            { Key: "TaskId", Value: taskId },
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

async function stopInstances(taskId) {
  // Busca las instancias worker de esta tarea que aún no están terminadas.
  const described = await ec2.send(
    new DescribeInstancesCommand({
      Filters: [
        { Name: "tag:TaskId", Values: [String(taskId)] },
        { Name: "tag:Project", Values: ["PythonWorkers"] },
        {
          Name: "instance-state-name",
          Values: ["pending", "running", "stopping", "stopped"],
        },
      ],
    })
  );

  const instanceIds = (described.Reservations ?? []).flatMap((r) =>
    (r.Instances ?? []).map((i) => i.InstanceId)
  );

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

    await admin.auth().verifyIdToken(token);

    let taskId = Date.now().toString();
    let context = {
      instance_id: 2,
      client_id: 2,
      camera_name: "entrance_instance",
      detection_blacklist: ["person"],
      rtsp_path: "rtsp://admin551:123456789@4.tcp.ngrok.io:17829/stream1",
    };
    let taskIdProvided = false;

    try {
      const body = typeof event.body === "string" ? JSON.parse(event.body) : (event.body || {});
      if (body.action) action = body.action;
      if (body.taskId) {
        taskId = body.taskId;
        taskIdProvided = true;
      }
      if (body.context) context = body.context;
    } catch (e) {
      console.warn("Could not parse body:", e);
    }

    if (action === "stop") {
      if (!taskIdProvided) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ message: "taskId is required to stop instances" }),
        };
      }
      return await stopInstances(taskId);
    }

    if (action !== "start") {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: `Unknown action: ${action}` }),
      };
    }

    return await startInstance(taskId, context);
  } catch (err) {
    const isAuthError =
      err?.code?.startsWith?.("auth/") ||
      err?.message?.toLowerCase?.().includes("token");

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
