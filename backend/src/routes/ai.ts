import { Router, Request, Response } from "express";
import { Ollama } from "ollama";
import Threat from "../models/Threat";

const router = Router();

const ollama = new Ollama({ host: process.env.OLLAMA_BASE_URL || "http://127.0.0.1:11434" });
const AI_MODEL_NAME = process.env.AI_MODEL_NAME || "aegis-ai";

type ThreatSeverity = "critical" | "high" | "medium" | "low";

function determineSeverityFromPrompt(prompt: string): ThreatSeverity {
  const lower = prompt.toLowerCase();

  if (/(rce|remote code execution|data breach|exfiltration|sql injection|sqli|privilege escalation|ransomware)/.test(lower)) {
    return "critical";
  }

  if (/(xss|csrf|ssrf|auth bypass|broken access control|command injection|deserialization)/.test(lower)) {
    return "high";
  }

  if (/(misconfig|misconfiguration|weak password|open port|bruteforce|brute force|dos|ddos)/.test(lower)) {
    return "medium";
  }

  return "low";
}

function buildThreatDescription(prompt: string): string {
  const compactPrompt = prompt.replace(/\s+/g, " ").trim();
  const lower = compactPrompt.toLowerCase();

  if (lower.includes("sql injection") || lower.includes("sqli")) {
    return "Potential SQL injection risk identified from user query; requires database-focused validation and remediation.";
  }

  if (lower.includes("xss")) {
    return "Potential cross-site scripting vectors identified from user query; input/output handling should be reviewed.";
  }

  if (lower.includes("csrf")) {
    return "Potential CSRF exposure identified from user query; request authenticity controls should be validated.";
  }

  if (lower.includes("rce") || lower.includes("remote code execution")) {
    return "Potential remote code execution risk identified from user query; immediate containment and patch validation recommended.";
  }

  return `Security threat analysis requested for: ${compactPrompt.slice(0, 140)}`;
}




const PROMPT_STRATEGIES: Record<string, string> = {
  
  "live-alerts": `You are Aegis AI SIEM Agent. Your only job is to analyze this specific real-time alert line for immediate threats. Be concise. Identify the threat type (e.g., SQLi attempt, Bruteforce) and give a 1-sentence risk assessment. DO NOT rewrite code or analyze large logs. Output Format: Threat Type, Severity (Critical/High/Medium/Low), Risk Assessment (1 sentence).`,

  
  "log-analyzer": `You are Aegis AI SIEM Log Analyzer. Analyze the provided log block for security patterns, attack chains, or anomalies. Summarize detected activities. If malicious behavior is found, correlate entries to describe the attack flow. Output should be an analytical report with sections: Executive Summary, Detected Threats, Attack Chain Analysis (if applicable), Recommendations.`,

  
  "code-scanner": `You are Aegis AI Secure Coding Agent. Your goal is to function as an automated secure code reviewer and generator.
STEP 1: Analyze the input code for OWASP Top 10 vulnerabilities (e.g., XSS, SQLi, Prototype Pollution, Insecure Deserialization, Broken Access Control). Clearly list every detected vulnerability with its CWE ID if applicable.
STEP 2: Provide a complete, fully rewritten, secure version of the code snippet. Focus on using secure libraries, input sanitization, parameterized queries, and output encoding.
Output format must be structured Markdown with:
- A "## Vulnerabilities Detected" section listing each issue
- A "## Secure Code" section with the full fixed code in a syntax-highlighted code block
- A "## Changes Made" section summarizing what was fixed and why`,

  "phishing-analyzer": `You are Aegis AI Phishing Expert. Analyze the provided email content for phishing attempts, social engineering, and malicious intent. 
You must strictly return ONLY a JSON response in the following format, with no markdown formatting outside the JSON, and no backticks around the JSON.
{
  "riskScore": <number 0-100>,
  "redFlags": ["<flag 1>", "<flag 2>"],
  "recommendation": "<string>"
}
Do not include any extra text.`,

  
  default: `You are Aegis AI, an expert cybersecurity SIEM assistant. Provide concise, highly technical, and accurate responses. You monitor logs, analyze threats (like SQLi, XSS, etc.), and help the user secure their infrastructure.`,
};




function getSystemPrompt(context: string): string {
  return PROMPT_STRATEGIES[context] || PROMPT_STRATEGIES["default"];
}




router.post("/chat", async (req: Request, res: Response): Promise<void> => {
  try {
    const { message } = req.body;

    if (!message) {
      res.status(400).json({ error: "Message is required." });
      return;
    }

    const userMessage = String(message).trim();
    const severity = determineSeverityFromPrompt(userMessage);
    const sourceTitle = userMessage.slice(0, 50);
    const description = buildThreatDescription(userMessage);

    await new Threat({
      source: "CHAT",
      sourceTitle,
      description,
      severity,
      reviewStatus: "PENDING",
      rawSnippet: userMessage.slice(0, 500),
    }).save();

    const systemPrompt = `You are Aegis AI, a world-class Cybersecurity Expert. Always provide scientifically accurate analysis. For SQL injection, look for database vulnerabilities, NOT Nginx caching issues.
Return your response in clean Markdown with exactly these top-level sections:
## Analysis
## Risk Level
## Remediation
Keep the content technically precise, actionable, and evidence-based.`;

    const messages = [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ];

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    const response = await ollama.chat({
      model: AI_MODEL_NAME,
      messages,
      stream: true,
    });

    let fullResponse = "";

    for await (const chunk of response) {
      if (chunk.message?.content) {
        fullResponse += chunk.message.content;
        res.write(`data: ${JSON.stringify({ content: chunk.message.content })}\n\n`);
      }
    }

    res.write("data: [DONE]\n\n");
    res.end();
  } catch (error: any) {
    console.error("[Ollama Error]", error.message);
    if (!res.headersSent) {
      res.status(500).json({ error: "Failed to communicate with local AI model. Ensure Ollama is running." });
    } else {
      res.write(`data: ${JSON.stringify({ error: "Connection interrupted." })}\n\n`);
      res.end();
    }
  }
});




router.post("/analyze", async (req: Request, res: Response): Promise<void> => {
  try {
    const { input, context } = req.body;

    if (!input || !input.trim()) {
      res.status(400).json({ error: "Input content is required." });
      return;
    }

    const systemPrompt = getSystemPrompt(context || "default");

    
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();

    const sendEvent = (data: object) => {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    sendEvent({ type: "status", message: `Using ${context || "default"} analysis strategy...` });

    const stream = await ollama.chat({
      model: AI_MODEL_NAME,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: input },
      ],
      stream: true,
    });

    let fullResponse = "";

    for await (const chunk of stream) {
      const text = chunk.message.content;
      fullResponse += text;
      sendEvent({ type: "chunk", content: text });
    }

    sendEvent({
      type: "complete",
      message: "Analysis complete.",
      fullResponse,
    });

    res.write("data: [DONE]\n\n");
    res.end();
  } catch (error: any) {
    console.error("[AI Analyze Error]", error.message);

    
    if (res.headersSent) {
      const sendEvent = (data: object) => {
        res.write(`data: ${JSON.stringify(data)}\n\n`);
      };
      sendEvent({ type: "error", message: "AI model connection failed. Ensure Ollama is running." });
      res.write("data: [DONE]\n\n");
      res.end();
    } else {
      res.status(500).json({ error: "Failed to communicate with local AI model." });
    }
  }
});

router.post("/analyze-phishing", async (req: Request, res: Response): Promise<void> => {
  try {
    const { email } = req.body;

    if (!email || !email.trim()) {
      res.status(400).json({ error: "Email content is required." });
      return;
    }

    const systemPrompt = getSystemPrompt("phishing-analyzer");

    const response = await ollama.chat({
      model: AI_MODEL_NAME,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: email },
      ],
      stream: false,
    });

    let jsonString = response.message.content;
    // Clean up potential markdown formatting if the model still outputs it
    if (jsonString.startsWith("\`\`\`json")) {
      jsonString = jsonString.replace(/^\`\`\`json\s*/, "").replace(/\s*\`\`\`$/, "");
    }

    const parsedResponse = JSON.parse(jsonString);

    if (parsedResponse.riskScore >= 50) {
      try {
        await new Threat({
          source: "EMAIL",
          sourceTitle: "Analyzed Email",
          description: `Phishing Score ${parsedResponse.riskScore}/100. Flags: ${parsedResponse.redFlags?.join(", ")}`,
          severity: parsedResponse.riskScore >= 80 ? "critical" : parsedResponse.riskScore >= 65 ? "high" : "medium",
          reviewStatus: "PENDING",
          rawSnippet: email.substring(0, 500)
        }).save();
      } catch (threatErr) {
        console.error("[Threat Save Error]", threatErr);
      }
    }

    res.json(parsedResponse);
  } catch (error: any) {
    console.error("[Phishing Analyze Error]", error.message);
    res.status(500).json({ error: "Failed to analyze email. Ensure Ollama is running and responding with valid JSON." });
  }
});

export default router;
