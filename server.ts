import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { db } from "./src/db/index.ts";
import { users, testAttempts, liveDoubts } from "./src/db/schema.ts";
import { requireAuth, AuthRequest } from "./src/middleware/auth.ts";
import { eq } from "drizzle-orm";

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Middleware to parse JSON request bodies
  app.use(express.json());

  // API Routes: Status / Health check
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", database: "connected" });
  });

  // 1. Sync User Profile (Upsert user on sign-in / signup)
  app.post("/api/users/sync", requireAuth, async (req: AuthRequest, res) => {
    try {
      const { name, email, mobile, rollNumber, centreName, batchNumber, role, isPremium } = req.body;
      const uid = req.user.uid;

      if (!email) {
        return res.status(400).json({ error: "Email is required" });
      }

      // Upsert the user profile in Cloud SQL
      const result = await db
        .insert(users)
        .values({
          uid,
          name: name || "Student",
          email,
          mobile: mobile || "",
          rollNumber: rollNumber || "",
          centreName: centreName || "",
          batchNumber: batchNumber || "",
          role: role || "student",
          isPremium: isPremium !== undefined ? isPremium : false,
        })
        .onConflictDoUpdate({
          target: users.uid,
          set: {
            name: name || "Student",
            email,
            mobile: mobile || "",
            rollNumber: rollNumber || "",
            centreName: centreName || "",
            batchNumber: batchNumber || "",
            role: role || "student",
            isPremium: isPremium !== undefined ? isPremium : false,
          },
        })
        .returning();

      res.json(result[0]);
    } catch (error: any) {
      console.error("Failed to sync user profile:", error);
      res.status(500).json({ error: "Failed to sync user profile in Cloud SQL" });
    }
  });

  // 2. Test Attempts API
  app.get("/api/attempts", requireAuth, async (req: AuthRequest, res) => {
    try {
      const userAttempts = await db
        .select()
        .from(testAttempts)
        .where(eq(testAttempts.userUid, req.user.uid));
      res.json(userAttempts);
    } catch (error: any) {
      console.error("Failed to fetch test attempts:", error);
      res.status(500).json({ error: "Failed to fetch attempts from Cloud SQL" });
    }
  });

  app.post("/api/attempts", requireAuth, async (req: AuthRequest, res) => {
    try {
      const {
        id,
        testId,
        testTitle,
        examCategory,
        userName,
        rollNumber,
        score,
        totalMarks,
        correctAnswers,
        incorrectAnswers,
        unattemptedAnswers,
        sectionDetails,
        timeSpentSeconds,
      } = req.body;

      const result = await db
        .insert(testAttempts)
        .values({
          id,
          testId,
          testTitle,
          examCategory,
          userUid: req.user.uid,
          userName,
          rollNumber,
          score,
          totalMarks,
          correctAnswers,
          incorrectAnswers,
          unattemptedAnswers,
          sectionDetails,
          timeSpentSeconds,
        })
        .returning();

      res.status(201).json(result[0]);
    } catch (error: any) {
      console.error("Failed to save test attempt:", error);
      res.status(500).json({ error: "Failed to save attempt in Cloud SQL" });
    }
  });

  // 3. Live Doubts API
  app.get("/api/doubts", requireAuth, async (req: AuthRequest, res) => {
    try {
      // Find current user's role to determine authorization
      const userRecord = await db
        .select()
        .from(users)
        .where(eq(users.uid, req.user.uid))
        .limit(1);

      const currentUser = userRecord[0];
      const isStaff = currentUser && (currentUser.role === "admin" || currentUser.role === "instructor");

      if (isStaff) {
        // Staff can see all doubts
        const allDoubts = await db.select().from(liveDoubts);
        res.json(allDoubts);
      } else {
        // Students see only their own doubts
        const myDoubts = await db
          .select()
          .from(liveDoubts)
          .where(eq(liveDoubts.studentUid, req.user.uid));
        res.json(myDoubts);
      }
    } catch (error: any) {
      console.error("Failed to fetch doubts:", error);
      res.status(500).json({ error: "Failed to fetch doubts from Cloud SQL" });
    }
  });

  app.post("/api/doubts", requireAuth, async (req: AuthRequest, res) => {
    try {
      const { id, studentName, studentRoll, subject, message } = req.body;

      const result = await db
        .insert(liveDoubts)
        .values({
          id,
          studentUid: req.user.uid,
          studentName,
          studentRoll,
          subject,
          message,
          status: "open",
        })
        .returning();

      res.status(201).json(result[0]);
    } catch (error: any) {
      console.error("Failed to create doubt:", error);
      res.status(500).json({ error: "Failed to submit doubt in Cloud SQL" });
    }
  });

  app.put("/api/doubts/:id", requireAuth, async (req: AuthRequest, res) => {
    try {
      const { reply, repliedBy, status } = req.body;
      const { id } = req.params;

      const result = await db
        .update(liveDoubts)
        .set({
          reply,
          repliedBy,
          status,
          repliedAt: new Date(),
        })
        .where(eq(liveDoubts.id, id))
        .returning();

      res.json(result[0]);
    } catch (error: any) {
      console.error("Failed to update doubt:", error);
      res.status(500).json({ error: "Failed to update doubt in Cloud SQL" });
    }
  });

  // Admin users API
  app.get("/api/admin/users", requireAuth, async (req: AuthRequest, res) => {
    try {
      const userRecord = await db
        .select()
        .from(users)
        .where(eq(users.uid, req.user.uid))
        .limit(1);

      if (!userRecord[0] || userRecord[0].role !== "admin") {
        return res.status(403).json({ error: "Forbidden: Admin access required" });
      }

      const allUsers = await db.select().from(users);
      res.json(allUsers);
    } catch (error: any) {
      console.error("Failed to fetch admin users:", error);
      res.status(500).json({ error: "Failed to fetch registered users" });
    }
  });

  // Vite development middleware vs production static server
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

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
