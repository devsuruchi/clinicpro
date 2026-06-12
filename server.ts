import express, { Request, Response, NextFunction } from "express";
import path from "path";
import jwt from "jsonwebtoken";
import { createServer as createViteServer } from "vite";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

import { 
  initDatabase, 
  getUserByEmail, 
  createUser, 
  getPatientRecords, 
  createPatientRecord, 
  updatePatientRecord, 
  deletePatientRecord,
  getDBStatus,
  User
} from "./server/db";

// Extend Request type to hold logged in user
interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    name: string;
    role: "ADMIN" | "STAFF";
  };
}

const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || "axis-physio-jwt-core-secret-2026";

async function startServer() {
  // Initialize Database (discover PostgreSQL vs Local Sandbox JSON File)
  await initDatabase();

  const app = express();
  app.use(express.json());

  // CORS headers for flexible API access
  app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    if (req.method === "OPTIONS") {
      return res.sendStatus(200);
    }
    next();
  });

  // JWT Verification Middleware
  function authenticateToken(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Access token required" });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded: any) => {
      if (err) {
        return res.status(403).json({ error: "Invalid or expired token" });
      }
      req.user = decoded;
      next();
    });
  }

  // Admin access-only middleware rule
  function requireAdmin(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    if (!req.user || req.user.role !== "ADMIN") {
      return res.status(403).json({ error: "Access restricted to Administrators only" });
    }
    next();
  }

  // API: Health Check
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", time: new Date() });
  });

  // API: System DB Connection Status
  app.get("/api/system/status", (req, res) => {
    res.json(getDBStatus());
  });

  // API: Register Admin User (Optional / Sandbox convenience)
  app.post("/api/auth/register", async (req, res) => {
    try {
      const { email, password, name, role } = req.body;
      if (!email || !password || !name) {
        return res.status(400).json({ error: "Email, password, and name are required" });
      }

      const existing = await getUserByEmail(email);
      if (existing) {
        return res.status(400).json({ error: "User already exists with this email" });
      }

      const user = await createUser({
        email,
        password,
        name,
        role: role === "STAFF" ? "STAFF" : "ADMIN"
      });

      res.status(201).json({ message: "User registered successfully", user });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // API: Authenticate / Login User (Staff or Admin)
  app.post("/api/auth/login", async (req, res) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
      }

      const user = await getUserByEmail(email);
      if (!user || !user.password) {
        return res.status(401).json({ error: "Invalid email or password" });
      }

      const bcrypt = require("bcryptjs");
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ error: "Invalid email or password" });
      }

      // Generate JWT
      const tokenPayload = {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      };
      
      const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: "24h" });

      res.json({
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role
        }
      });
    } catch (err: any) {
      console.error("Login failure:", err);
      res.status(500).json({ error: "Internal authentication error" });
    }
  });

  // API: Get Current Authenticated Identity
  app.get("/api/auth/me", authenticateToken, (req: AuthenticatedRequest, res) => {
    res.json({ user: req.user });
  });

  // API: Get Patient Records (Admin Only Route)
  app.get("/api/records", authenticateToken, requireAdmin, async (req: AuthenticatedRequest, res) => {
    try {
      const records = await getPatientRecords();
      res.json(records);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // API: Create Clinical Record (Admin Only)
  app.post("/api/records", authenticateToken, requireAdmin, async (req: AuthenticatedRequest, res) => {
    try {
      const { patientName, age, gender, contactNumber, diagnosis, treatment, assignedTherapist, status, nextSession } = req.body;
      
      if (!patientName || !diagnosis || !treatment) {
        return res.status(400).json({ error: "Patient name, primary diagnosis, and treatment plan are required" });
      }

      const newRecord = await createPatientRecord({
        patientName,
        age: parseInt(age) || 0,
        gender: gender || "Not Specified",
        contactNumber: contactNumber || "N/A",
        diagnosis,
        treatment,
        assignedTherapist: assignedTherapist || req.user?.name || "Therapist",
        status: status || "Scheduled",
        nextSession: nextSession || ""
      });

      res.status(201).json(newRecord);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // API: Update Patient Record (Admin Only)
  app.put("/api/records/:id", authenticateToken, requireAdmin, async (req: AuthenticatedRequest, res) => {
    try {
      const { id } = req.params;
      const updated = await updatePatientRecord(id, req.body);
      if (!updated) {
        return res.status(404).json({ error: "Clinical record not found" });
      }
      res.json(updated);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // API: Delete Patient Record (Admin Only)
  app.delete("/api/records/:id", authenticateToken, requireAdmin, async (req: AuthenticatedRequest, res) => {
    try {
      const { id } = req.params;
      const success = await deletePatientRecord(id);
      if (!success) {
        return res.status(404).json({ error: "Record not found" });
      }
      res.json({ success: true, message: "Clinical record successfully removed" });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });


  // React/Vite middleware for single page application (SPA)
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  // Bind to host 0.0.0.0 as required by the platform container
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Axis Physiotherapy server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
  });
}

startServer();
