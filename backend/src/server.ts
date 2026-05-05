import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import { createServer } from "http";
import { Server } from "socket.io";

import aiRoutes from "./routes/ai";
import logRoutes from "./routes/logs";
import authRoutes from "./routes/auth";
import alertRoutes from "./routes/alerts";
import scannerRoutes from "./routes/scanner";
import trainingRoutes from "./routes/training";
import overviewRoutes from "./routes/overview";
import { liveThreatInterceptor } from "./middlewares/liveThreatInterceptor";
import connectDB from "./config/db";


dotenv.config();


connectDB();

const app = express();
const PORT = process.env.PORT || 5000;




app.use(helmet());
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));


app.use(liveThreatInterceptor);




app.use("/api/ai", aiRoutes);
app.use("/api/logs", logRoutes);
app.use("/api/auth", authRoutes);
app.use("/api/alerts", alertRoutes);
app.use("/api/scanner", scannerRoutes);
app.use("/api/training", trainingRoutes);
app.use("/api/overview", overviewRoutes);


app.get("/api/health", (_req: Request, res: Response) => {
  res.status(200).json({
    status: "operational",
    service: "Aegis AI API",
    timestamp: new Date().toISOString(),
  });
});




app.use((_req: Request, res: Response) => {
  res.status(404).json({ message: "Route not found" });
});




interface AppError extends Error {
  statusCode?: number;
}

app.use((err: AppError, _req: Request, res: Response, _next: NextFunction) => {
  const statusCode = err.statusCode || 500;
  console.error(`[ERROR] ${err.message}`);
  res.status(statusCode).json({
    status: "error",
    statusCode,
    message: err.message || "Internal Server Error",
  });
});




const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    methods: ["GET", "POST"],
    credentials: true,
  },
});

app.set("io", io);

io.on("connection", (socket) => {
  console.log(`[Socket.io] Client connected: ${socket.id}`);

  socket.on("disconnect", () => {
    console.log(`[Socket.io] Client disconnected: ${socket.id}`);
  });
});


httpServer.listen(PORT, () => {
  console.log(`\n⚡ Aegis AI Backend running on http://localhost:${PORT}`);
  console.log(`   Health check: http://localhost:${PORT}/api/health`);
  console.log(`   Socket.io: Ready for connections\n`);
});

export default app;
