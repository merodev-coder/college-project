import { Router, Request, Response } from "express";
import multer from "multer";
import { Ollama } from "ollama";
import Alert from "../models/Alert";
import Threat from "../models/Threat";

const router = Router();
const upload = multer({ storage: multer.memoryStorage() });

const ollama = new Ollama({ host: process.env.OLLAMA_BASE_URL || "http://127.0.0.1:11434" });
const AI_MODEL_NAME = process.env.AI_MODEL_NAME || "aegis-ai";




const SYSTEM_PROMPT = `You are Aegis AI — a SECURITY THREAT ANALYZER. You analyze server logs to detect attacks.

## CRITICAL RULES — READ CAREFULLY:
1. You are an ANALYZER, NOT a parser. DO NOT echo, reformat, or return the raw log input.
2. DO NOT output conversational text, markdown, or code fences.
3. Your job is to EVALUATE each log line and decide if it is a security threat or safe.
4. Your ENTIRE response must be a stream of independent JSON objects (Newline Delimited JSON / NDJSON). Output EXACTLY ONE JSON object per line. DO NOT output a JSON array (no '[' or ']' around them). DO NOT add commas between lines.

## ANTI-HALLUCINATION RULES — MANDATORY:
5. DO NOT hallucinate or assume threats based on IP reputation, geolocation, or gut feeling.
6. DO NOT invent attack payloads that are not explicitly present in the log text.
7. A standard GET or POST request to common endpoints like /about, /contact, /api/v1/status, /index.html, /favicon.ico, /robots.txt, or image/CSS/JS files is ALWAYS "safe" UNLESS a clear, explicit malicious payload is visibly present in the log string.
8. Malicious payloads include ONLY: SQL keywords in URL params (e.g., UNION SELECT, OR 1=1, DROP TABLE), script injection tags (e.g., <script>, javascript:, onerror=), path traversal sequences (e.g., ../, ....
9. If NO malicious payload is visibly present in the text of the log line, you MUST classify it as severity: "safe" and threat_type: "None". This is NON-NEGOTIABLE.
10. When in doubt, classify as "safe". False negatives are acceptable; false positives are NOT.

## REQUIRED OUTPUT FORMAT (Per Line):
{"severity":"safe|low|medium|high|critical","threat_type":"SQL Injection|XSS|Path Traversal|Command Injection|User-Agent Injection|None","source_ip":"<ip>","target_url":"<url>","timestamp":"<iso8601>","log_snippet":"<raw log or snippet>","analysis":"<1-sentence explanation>"}

## 1-SHOT EXAMPLE:

USER INPUT (raw log lines):
185.15.58.20 - - [2026-04-26 04:59:31] "GET /index.php?id=1 UNION SELECT null, version() HTTP/1.1" 403 486 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.19 - - [2026-04-26 03:11:14] "GET /about HTTP/1.1" 200 1651 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
10.0.0.5 - - [2026-04-26 03:12:00] "GET /api/v1/status HTTP/1.1" 200 84 "-" "HealthChecker/1.0"

YOUR CORRECT OUTPUT:
{"severity":"critical","threat_type":"SQL Injection","source_ip":"185.15.58.20","target_url":"/index.php?id=1 UNION SELECT null, version()","timestamp":"2026-04-26T04:59:31Z","log_snippet":"GET /index.php?id=1 UNION SELECT null, version() HTTP/1.1","analysis":"UNION SELECT SQL injection attempt targeting the id parameter."}
{"severity":"safe","threat_type":"None","source_ip":"203.0.113.19","target_url":"/about","timestamp":"2026-04-26T03:11:14Z","log_snippet":"GET /about HTTP/1.1","analysis":"Standard page request with no malicious payload."}
{"severity":"safe","threat_type":"None","source_ip":"10.0.0.5","target_url":"/api/v1/status","timestamp":"2026-04-26T03:12:00Z","log_snippet":"GET /api/v1/status HTTP/1.1","analysis":"Health check endpoint, no payload present."}

Now analyze the logs provided by the user.`;




function mapAiAlert(parsed: any) {
  return {
    severity: parsed.severity || "medium",
    attackType: parsed.threat_type || "Detected Anomaly",
    sourceIp: parsed.source_ip || "Unknown",
    targetUrl: parsed.target_url || "Unknown",
    userAgent: parsed.userAgent || "",
    statusCode: parsed.statusCode || undefined,
    rawLog: parsed.log_snippet || JSON.stringify(parsed),
    time: parsed.timestamp || new Date().toISOString(),
    analysis: parsed.analysis || ""
  };
}




function parseAlertsFromText(aiText: string): any[] {
  if (!aiText || !aiText.trim()) return [];

  const alerts: any[] = [];
  const lines = aiText.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    
    
    const cleanLine = trimmed.replace(/^\[/, '').replace(/\]$/, '').replace(/,$/, '');
    if (!cleanLine.startsWith('{') || !cleanLine.endsWith('}')) continue;

    try {
      const parsed = JSON.parse(cleanLine);
      alerts.push(parsed);
    } catch (e) {
      
    }
  }
  return alerts;
}




async function validateAndSaveAlert(alertData: any, fileName?: string): Promise<any | null> {
  try {
    const mappedAlert = mapAiAlert(alertData);
    
    if (mappedAlert.severity.toLowerCase() === "safe") {
      return null;
    }

    
    if (!mappedAlert.attackType) {
      console.warn("[Validation Warning] Skipping alert without attackType:", alertData);
      return null;
    }

    const alertObj = {
      severity: mappedAlert.severity.toLowerCase() || "medium",
      attackType: mappedAlert.attackType,
      sourceIp: mappedAlert.sourceIp || "Unknown",
      targetUrl: mappedAlert.targetUrl || "Unknown",
      userAgent: mappedAlert.userAgent || "",
      statusCode: mappedAlert.statusCode ? Number(mappedAlert.statusCode) : undefined,
      rawLog: mappedAlert.rawLog || "",
      timestamp: mappedAlert.time ? new Date(mappedAlert.time) : new Date(),
    };

    const newAlert = new Alert(alertObj);
    await newAlert.save();

    // Also save to unified Threat table for AI Training review
    try {
      await new Threat({
        source: "LOG",
        sourceTitle: fileName || "Uploaded Log",
        description: mappedAlert.analysis || `${mappedAlert.attackType} detected from ${mappedAlert.sourceIp}`,
        severity: mappedAlert.severity.toLowerCase(),
        reviewStatus: "PENDING",
        rawSnippet: mappedAlert.rawLog || "",
      }).save();
    } catch (threatErr) {
      console.error("[Threat Save Error]", threatErr);
    }

    return newAlert;
  } catch (saveErr) {
    console.error("[MongoDB Save Error]", saveErr, alertData);
    return null; 
  }
}




function formatAlertForClient(alert: any) {
  return {
    id: alert._id?.toString() || Math.random().toString(36).substring(7),
    severity: alert.severity,
    type: alert.attackType || alert.threat_type,
    sourceIp: alert.sourceIp || alert.source_ip,
    targetUrl: alert.targetUrl || alert.target_url,
    userAgent: alert.userAgent || "",
    statusCode: alert.statusCode,
    timestamp: alert.timestamp ? new Date(alert.timestamp).toISOString().replace("T", " ").substring(0, 19) : new Date().toISOString(),
    analysis: alert.analysis || "",
    logSnippet: alert.rawLog || alert.log_snippet || ""
  };
}




router.post("/upload", upload.single("file"), async (req: Request, res: Response): Promise<void> => {
  try {
    if (!req.file) {
      res.status(400).json({ error: "No file uploaded." });
      return;
    }

    const logContent = req.file.buffer.toString("utf-8");

    const response = await ollama.chat({
      model: AI_MODEL_NAME,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: logContent },
      ],
      format: "json",
    });

    let aiText = response.message.content.trim();

    let parsedAlerts: any[] = [];
    try {
      parsedAlerts = parseAlertsFromText(aiText);
    } catch (parseError) {
      console.error("[Ollama JSON Parse Error]", parseError, "\nRaw Text:", aiText);
      res.status(400).json({ error: "Failed to parse AI response into valid JSON. Please try scanning again." });
      return;
    }

    if (parsedAlerts.length === 0) {
      res.status(200).json({ message: "No threats detected.", alerts: [] });
      return;
    }

    
    const fileName = req.file.originalname || "Uploaded Log";
    const results = await Promise.all(parsedAlerts.map(a => validateAndSaveAlert(a, fileName)));
    const savedAlerts = results.filter((alert) => alert !== null);

    
    const io = req.app.get("io");
    if (io) {
      savedAlerts.forEach((alert) => {
        io.emit("liveAlert", formatAlertForClient(alert));
      });
    }

    res.status(200).json({
      message: `Successfully analyzed file and detected ${savedAlerts.length} threats.`,
      alerts: savedAlerts,
    });
  } catch (error: any) {
    console.error("[Log Upload Error]", error);
    res.status(500).json({ error: "An error occurred during log analysis." });
  }
});




async function processLogStream(logContent: string, req: Request, res: Response, sendEvent: (data: object) => void, fileName?: string) {
  try {
    sendEvent({ type: "status", message: "Initializing AI analysis..." });

    const lines = logContent.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    
    if (lines.length === 0) {
      sendEvent({ type: "error", message: "Log file is empty." });
      res.write("data: [DONE]\n\n");
      res.end();
      return;
    }

    sendEvent({ type: "status", message: `Found ${lines.length} log lines. Starting batch analysis...` });

    const BATCH_SIZE = 3;

    for (let i = 0; i < lines.length; i += BATCH_SIZE) {
      const batch = lines.slice(i, i + BATCH_SIZE);
      const batchContent = batch.join('\n');
      
      sendEvent({ type: "status", message: `Analyzing lines ${i + 1} to ${Math.min(i + BATCH_SIZE, lines.length)} of ${lines.length}...` });

      const messages = [
        { role: "system" as const, content: SYSTEM_PROMPT },
        { role: "user" as const, content: batchContent },
      ];

      const stream = await ollama.chat({
        model: AI_MODEL_NAME,
        messages,
        stream: true,
      });

      let buffer = "";

      for await (const chunk of stream) {
        const text = chunk.message.content;
        buffer += text;
        
        let startIdx = buffer.indexOf('{');
        while (startIdx !== -1) {
          let depth = 0;
          let inString = false;
          let isEscaped = false;
          let endIdx = -1;
          
          for (let j = startIdx; j < buffer.length; j++) {
            const char = buffer[j];
            if (char === '"' && !isEscaped) {
              inString = !inString;
            } else if (char === '\\' && inString) {
              isEscaped = !isEscaped;
            } else {
              isEscaped = false;
            }
            
            if (!inString) {
              if (char === '{') depth++;
              else if (char === '}') depth--;
              
              if (depth === 0) {
                endIdx = j;
                break;
              }
            }
          }
          
          if (endIdx !== -1) {
            const jsonStr = buffer.substring(startIdx, endIdx + 1);
            buffer = buffer.substring(endIdx + 1);
            try {
              const parsedAlert = JSON.parse(jsonStr);
              const mappedAlert = mapAiAlert(parsedAlert);
              
              const clientAlert = {
                id: Math.random().toString(36).substring(7),
                severity: mappedAlert.severity,
                type: mappedAlert.attackType,
                sourceIp: mappedAlert.sourceIp,
                targetUrl: mappedAlert.targetUrl,
                timestamp: new Date(mappedAlert.time).toISOString().replace("T", " ").substring(0, 19),
                analysis: mappedAlert.analysis,
                logSnippet: mappedAlert.rawLog
              };

              sendEvent({ type: "alert", data: clientAlert });

              if (mappedAlert.severity.toLowerCase() !== "safe") {
                validateAndSaveAlert(parsedAlert, fileName).then((saved) => {
                  if (saved) {
                    const io = req.app.get("io");
                    if (io) io.emit("liveAlert", formatAlertForClient(saved));
                  }
                }).catch(err => console.error("[SSE DB Save Error]", err));
              }
            } catch (e) {
              
            }
            startIdx = buffer.indexOf('{');
          } else {
            break;
          }
        }
      }
    }

    sendEvent({ type: "status", message: "Analysis complete." });
    sendEvent({ type: "complete", message: "Analysis finished." });

    res.write("data: [DONE]\n\n");
    res.end();
  } catch (error: any) {
    console.error("[SSE Log Upload Error]", error);
    sendEvent({ type: "error", message: "An error occurred during log analysis." });
    res.write("data: [DONE]\n\n");
    res.end();
  }
}




router.post("/upload-stream", upload.single("file"), async (req: Request, res: Response): Promise<void> => {
  if (!req.file) {
    res.status(400).json({ error: "No file uploaded." });
    return;
  }

  const logContent = req.file.buffer.toString("utf-8");

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const sendEvent = (data: object) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  await processLogStream(logContent, req, res, sendEvent, req.file.originalname);
});




router.post("/scan-url-stream", async (req: Request, res: Response): Promise<void> => {
  const { url } = req.body;
  if (!url) {
    res.status(400).json({ error: "No URL provided." });
    return;
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const sendEvent = (data: object) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  try {
    sendEvent({ type: "status", message: "Fetching remote logs..." });
    const fetchResponse = await fetch(url);
    if (!fetchResponse.ok) {
      throw new Error(`Failed to fetch URL: ${fetchResponse.statusText}`);
    }
    const logContent = await fetchResponse.text();
    await processLogStream(logContent, req, res, sendEvent);
  } catch (error: any) {
    console.error("[Scan URL Error]", error);
    sendEvent({ type: "error", message: `Error fetching URL: ${error.message}` });
    res.write("data: [DONE]\n\n");
    res.end();
  }
});




router.get("/sample", (_req: Request, res: Response) => {
  const sampleData = `
192.168.1.100 - - [10/Oct/2023:13:55:36 -0700] "GET /api/health HTTP/1.1" 200 143 "-" "Mozilla/5.0"
10.0.0.45 - - [10/Oct/2023:13:56:01 -0700] "GET /login HTTP/1.1" 200 4523 "-" "Mozilla/5.0"
192.168.1.100 - - [10/Oct/2023:13:56:05 -0700] "POST /api/auth/login HTTP/1.1" 401 55 "-" "Mozilla/5.0"
45.22.19.112 - - [10/Oct/2023:13:57:22 -0700] "GET /api/users?id=1' OR '1'='1 HTTP/1.1" 500 120 "-" "sqlmap/1.4.11"
45.22.19.112 - - [10/Oct/2023:13:57:25 -0700] "GET /api/users?id=1; DROP TABLE users; HTTP/1.1" 500 120 "-" "sqlmap/1.4.11"
192.168.1.105 - - [10/Oct/2023:13:58:10 -0700] "GET /dashboard HTTP/1.1" 200 3102 "-" "Mozilla/5.0"
88.134.4.99 - - [10/Oct/2023:13:59:02 -0700] "POST /api/upload HTTP/1.1" 403 98 "-" "curl/7.68.0"
88.134.4.99 - - [10/Oct/2023:13:59:05 -0700] "GET /../../../../etc/passwd HTTP/1.1" 403 145 "-" "curl/7.68.0"
10.0.0.45 - - [10/Oct/2023:14:00:15 -0700] "GET /api/settings HTTP/1.1" 200 890 "-" "Mozilla/5.0"
112.45.67.89 - - [10/Oct/2023:14:01:30 -0700] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 2341 "-" "Mozilla/5.0"
`.trim();

  res.setHeader("Content-Type", "text/plain");
  res.send(sampleData);
});

export default router;
