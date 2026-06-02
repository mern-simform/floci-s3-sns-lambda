// index.mjs — Node.js Lambda for Log Processing & Alerting

import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

// ─── AWS Clients pointing to Floci ───────────────────────
const s3 = new S3Client({
  region: 'us-east-1',
//   endpoint: 'http://localhost:4566',
  endpoint: 'http://host.docker.internal:4566',
  forcePathStyle: true,
  credentials: {
    accessKeyId: 'test',
    secretAccessKey: 'test'
  }
});

const sns = new SNSClient({
  region: 'us-east-1',
//   endpoint: 'http://localhost:4566',
  endpoint: 'http://host.docker.internal:4566',
  credentials: {
    accessKeyId: 'test',
    secretAccessKey: 'test'
  }
});

// ─── Config ───────────────────────────────────────────────
const SNS_TOPIC_ARN  = process.env.SNS_TOPIC_ARN  || '';
const ERROR_THRESHOLD = parseInt(process.env.ERROR_THRESHOLD || '5');
const OUTPUT_BUCKET   = process.env.OUTPUT_BUCKET  || 'processed-logs-bucket';
const APP_NAME        = process.env.APP_NAME       || 'MyApp';
const ENVIRONMENT     = process.env.ENVIRONMENT    || 'production';

// ─── Helper: stream S3 body to string ─────────────────────
async function streamToString(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', chunk => chunks.push(chunk));
    stream.on('end',  ()    => resolve(Buffer.concat(chunks).toString('utf-8')));
    stream.on('error', reject);
  });
}

// ─── Helper: parse one log line ───────────────────────────
function parseLine(line) {
  if (!line.trim()) return null;

  const level =
    line.includes('ERROR')    ? 'ERROR'    :
    line.includes('WARN')     ? 'WARN'     :
    line.includes('INFO')     ? 'INFO'     :
    line.includes('DEBUG')    ? 'DEBUG'    :
    line.includes('SECURITY') ? 'SECURITY' : 'UNKNOWN';

  // Extract error code like E500, E404, E403
  const codeMatch = line.match(/\bE\d{3,4}\b/);
  const errorCode = codeMatch ? codeMatch[0] : null;

  // Extract IP address if present
  const ipMatch = line.match(/\b(\d{1,3}\.){3}\d{1,3}\b/);
  const ipAddress = ipMatch ? ipMatch[0] : null;

  return { line, level, errorCode, ipAddress };
}

// ─── Helper: build SNS alert message ──────────────────────
function buildAlertMessage(key, counts, errorCodes, securityEvents) {
  return `
   LOG ALERT — High Severity Events Detected

App         : ${APP_NAME}
Environment : ${ENVIRONMENT}
File        : ${key}
Time        : ${new Date().toISOString()}

── Counts ──────────────────────────
  ERROR    : ${counts.ERROR}
  WARN     : ${counts.WARN}
  SECURITY : ${counts.SECURITY}
  INFO     : ${counts.INFO}

── Error Codes Found ───────────────
  ${[...errorCodes].join(', ') || 'None'}

── Security Events ─────────────────
  ${securityEvents.length > 0
      ? securityEvents.slice(0, 5).join('\n  ')
      : 'None detected'}

Action Required: Check application logs immediately.
  `.trim();
}

// ─── Main Lambda Handler ───────────────────────────────────
export async function handler(event) {
  console.log('Event received:', JSON.stringify(event, null, 2));

  // ── 1. Get S3 object info from event ──────────────────
  const bucket = event.Records[0].s3.bucket.name;
  const key    = decodeURIComponent(
    event.Records[0].s3.object.key.replace(/\+/g, ' ')
  );

  console.log(`Processing: s3://${bucket}/${key}`);

  // ── 2. Read log file from S3 ──────────────────────────
  const s3Response = await s3.send(new GetObjectCommand({
    Bucket: bucket,
    Key: key
  }));

  const content = await streamToString(s3Response.Body);
  const lines   = content.split('\n');

  console.log(`Total lines: ${lines.length}`);

  // ── 3. Parse logs line by line ────────────────────────
  const counts = {
    ERROR: 0, WARN: 0,
    INFO: 0,  DEBUG: 0,
    SECURITY: 0, UNKNOWN: 0
  };

  const errorCodes     = new Set();
  const securityEvents = [];

  for (const line of lines) {
    const parsed = parseLine(line);
    if (!parsed) continue;

    // Count by severity
    counts[parsed.level] = (counts[parsed.level] || 0) + 1;

    // Collect error codes
    if (parsed.errorCode) {
      errorCodes.add(parsed.errorCode);
    }

    // Collect security events
    if (parsed.level === 'SECURITY' || parsed.level === 'ERROR') {
      if (parsed.ipAddress) {
        securityEvents.push(
          `[${parsed.level}] IP: ${parsed.ipAddress} — ${parsed.line.slice(0, 80)}`
        );
      }
    }
  }

  console.log('Counts:', counts);
  console.log('Error codes:', [...errorCodes]);

  // ── 4. Add metadata ───────────────────────────────────
  const metadata = {
    appName     : APP_NAME,
    environment : ENVIRONMENT,
    sourceFile  : key,
    processedAt : new Date().toISOString(),
    counts,
    errorCodes  : [...errorCodes],
    securityEvents: securityEvents.slice(0, 10),
    alertSent   : false
  };

  // ── 5. Send SNS alert if threshold breached ───────────
  const shouldAlert =
    counts.ERROR    >= ERROR_THRESHOLD ||
    counts.SECURITY >  0;

  if (shouldAlert && SNS_TOPIC_ARN) {
    const message = buildAlertMessage(
      key, counts, errorCodes, securityEvents
    );

    await sns.send(new PublishCommand({
      TopicArn : SNS_TOPIC_ARN,
      Subject  : `🚨 [${ENVIRONMENT}] High Error Rate — ${APP_NAME}`,
      Message  : message
    }));

    console.log('SNS alert sent!');
    metadata.alertSent = true;
  } else {
    console.log(
      `No alert. Errors: ${counts.ERROR}, threshold: ${ERROR_THRESHOLD}`
    );
  }

  // ── 6. Save result to processed bucket ───────────────
  const outputKey = `results/${key.replace(/\//g, '_')}_result.json`;

  await s3.send(new PutObjectCommand({
    Bucket      : OUTPUT_BUCKET,
    Key         : outputKey,
    Body        : JSON.stringify(metadata, null, 2),
    ContentType : 'application/json'
  }));

  console.log(`Result saved: s3://${OUTPUT_BUCKET}/${outputKey}`);

  return {
    statusCode : 200,
    body       : JSON.stringify(metadata)
  };
}