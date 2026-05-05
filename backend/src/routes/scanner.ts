import { Router, Request, Response } from "express";
import { Ollama } from "ollama";
import ignore from "ignore";
import Threat from "../models/Threat";

const router = Router();
const ollama = new Ollama({ host: process.env.OLLAMA_BASE_URL || "http://127.0.0.1:11434" });
const AI_MODEL_NAME = process.env.AI_MODEL_NAME || "aegis-ai";

interface FilePayload {
  path: string;
  content: string;
}

router.post("/scan-folder", async (req: Request, res: Response): Promise<void> => {
  try {
    const { files, ignoreContent } = req.body as { files: FilePayload[], ignoreContent?: string };

    if (!files || !Array.isArray(files)) {
      res.status(400).json({ error: "Files array is required." });
      return;
    }

    
    const ig = ignore();
    if (ignoreContent) {
      ig.add(ignoreContent);
    }
    
    ig.add([".git", "node_modules", "dist", "build", ".DS_Store"]);

    
    const filteredFiles = files.filter(file => !ig.ignores(file.path));

    
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();

    const sendEvent = (data: object) => {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    sendEvent({ type: "start", total: filteredFiles.length });

    
    for (let i = 0; i < filteredFiles.length; i++) {
      const file = filteredFiles[i];
      
      sendEvent({ 
        type: "progress", 
        current: i + 1, 
        total: filteredFiles.length, 
        fileName: file.path 
      });

      try {
        const systemPrompt = `You are Aegis AI Code Security Auditor. Analyze the following file for security vulnerabilities.
Return ONLY a JSON object matching this schema:
{
  "hasVulnerability": boolean,
  "threatType": string,
  "severity": "Critical" | "High" | "Medium" | "Low" | "None",
  "analysis": string (1-2 sentences summarizing the finding)
}`;

        const response = await ollama.chat({
          model: AI_MODEL_NAME,
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: `File: ${file.path}\n\nContent:\n${file.content}` }
          ],
          format: "json",
          stream: false
        });

        const result = JSON.parse(response.message.content);
        
        if (result.hasVulnerability && result.severity !== "None") {
          sendEvent({
            type: "threat",
            file: file.path,
            threatType: result.threatType,
            severity: result.severity,
            analysis: result.analysis
          });
          
          try {
            await new Threat({
              source: "CODE",
              sourceTitle: file.path,
              description: `${result.threatType}: ${result.analysis}`,
              severity: result.severity.toLowerCase(),
              reviewStatus: "PENDING",
              rawSnippet: file.content.substring(0, 500) // First 500 chars of code as context
            }).save();
          } catch (threatErr) {
            console.error("[Threat Save Error]", threatErr);
          }
        }
      } catch (err: any) {
        console.error(`Error analyzing file ${file.path}:`, err.message);
        sendEvent({
          type: "error",
          file: file.path,
          message: "Failed to analyze file."
        });
      }
    }

    sendEvent({ type: "complete", message: "Folder scan complete." });
    res.write("data: [DONE]\n\n");
    res.end();

  } catch (error: any) {
    console.error("[Scan Folder Error]", error.message);
    if (!res.headersSent) {
      res.status(500).json({ error: "Internal server error during folder scan." });
    } else {
      res.write(`data: ${JSON.stringify({ type: "error", message: "Internal server error." })}\n\n`);
      res.write("data: [DONE]\n\n");
      res.end();
    }
  }
});

export default router;
