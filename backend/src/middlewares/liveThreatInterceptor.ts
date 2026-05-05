import { Request, Response, NextFunction } from "express";
import { Ollama } from "ollama";
import Alert from "../models/Alert";

const ollama = new Ollama({ host: process.env.OLLAMA_BASE_URL || "http://127.0.0.1:11434" });
const AI_MODEL_NAME = process.env.AI_MODEL_NAME || "aegis-ai";


const EXCLUDED_PATHS = [
  "/api/health",
  "/api/logs",
  "/api/alerts",
  "/socket.io"
];


const SYSTEM_PROMPT = `You are Aegis AI — a SECURITY THREAT ANALYZER. You analyze live incoming HTTP requests to detect attacks.

## CRITICAL RULES:
1. You must evaluate the provided HTTP request details and decide if it is a security threat or safe.
2. DO NOT output conversational text, markdown, or code fences.
3. Your ENTIRE response must be EXACTLY ONE JSON object. DO NOT output a JSON array. DO NOT add trailing commas.

## ANTI-HALLUCINATION RULES:
4. DO NOT hallucinate threats based on IP or gut feeling.
5. A standard request to common endpoints is ALWAYS "safe" UNLESS a clear, explicit malicious payload is visibly present in the URL, User-Agent, or Body.
6. Malicious payloads include: SQL keywords (UNION SELECT, OR 1=1), script injection tags (<script>), path traversal (../), or command injection (; ls).
7. If NO malicious payload is present, you MUST classify it as severity: "safe" and threat_type: "None". False positives are unacceptable.

## REQUIRED OUTPUT FORMAT:
{"severity":"safe|low|medium|high|critical","threat_type":"SQL Injection|XSS|Path Traversal|Command Injection|User-Agent Injection|None","analysis":"<1-sentence explanation>"}

Now analyze the following HTTP request:`;

export const liveThreatInterceptor = (req: Request, res: Response, next: NextFunction) => {
  
  if (EXCLUDED_PATHS.some((path) => req.path.startsWith(path))) {
    return next();
  }

  
  const requestData = {
    method: req.method,
    url: req.originalUrl || req.url,
    ip: req.ip || req.socket.remoteAddress || "Unknown",
    userAgent: req.headers["user-agent"] || "Unknown",
    
    body: req.body ? JSON.stringify(req.body).substring(0, 1000) : "None"
  };

  
  const requestString = `METHOD: ${requestData.method}
URL: ${requestData.url}
IP: ${requestData.ip}
USER-AGENT: ${requestData.userAgent}
BODY: ${requestData.body}`;

  
  next();

  
  (async () => {
    try {
      const response = await ollama.chat({
        model: AI_MODEL_NAME,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: requestString },
        ],
        format: "json",
      });

      const aiText = response.message.content.trim();
      if (!aiText) return;

      
      let parsedAlert;
      try {
        
        const cleanText = aiText.replace(/^```json/, '').replace(/```$/, '').trim();
        parsedAlert = JSON.parse(cleanText);
      } catch (parseErr) {
        console.error("[Live Interceptor] Failed to parse AI JSON:", aiText);
        return;
      }

      
      const severity = (parsedAlert.severity || "safe").toLowerCase();
      if (severity === "safe") {
        return; 
      }

      
      const alertObj = {
        severity: severity,
        attackType: parsedAlert.threat_type || "Detected Anomaly",
        sourceIp: requestData.ip,
        targetUrl: requestData.url,
        userAgent: requestData.userAgent !== "Unknown" ? requestData.userAgent : "",
        statusCode: res.statusCode || undefined, 
        rawLog: requestString,
        timestamp: new Date(),
        analysis: parsedAlert.analysis || ""
      };

      
      const newAlert = new Alert(alertObj);
      await newAlert.save();

      
      const io = req.app.get("io");
      if (io) {
        const clientAlert = {
          id: newAlert._id.toString(),
          severity: newAlert.severity,
          type: newAlert.attackType,
          sourceIp: newAlert.sourceIp,
          targetUrl: newAlert.targetUrl,
          userAgent: newAlert.userAgent,
          statusCode: newAlert.statusCode,
          timestamp: newAlert.timestamp.toISOString().replace("T", " ").substring(0, 19),
          analysis: alertObj.analysis,
          logSnippet: newAlert.rawLog
        };
        io.emit("liveAlert", clientAlert);
      }

    } catch (err) {
      console.error("[Live Interceptor] Async analysis error:", err);
    }
  })();
};
