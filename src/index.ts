import "dotenv/config";
import express, { NextFunction, Request, Response } from "express";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "./generated/prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

const adapter = new PrismaPg({
  connectionString: process.env.DATABASE_URL,
});

const prisma = new PrismaClient({ adapter });

export interface AuthRequest extends Request {
  user?: {
    userId: number;
    role: string;
  };
}

const app = express();
app.use(cookieParser());

app.use(express.json());

app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = await prisma.user.create({
      data: {
        email,
        passwordHash: hashedPassword,
      },
    });

    return res.status(201).send({
      id: newUser.id,
      email: newUser.email,
      createdAt: newUser.createdAt,
      role: newUser.role,
    });
  } catch (error) {
    console.error("Registration error:", error);
    return res
      .status(400)
      .json({ error: "User already exists or registration failed" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user || !process.env.JWT_SECRET) {
      return res.status(401).json({ error: "Email cannot be matched" });
    } else {
      if (await bcrypt.compare(password, user.passwordHash)) {
        const token = jwt.sign(
          { userId: user.id, role: user.role },
          process.env.JWT_SECRET,
          {
            expiresIn: "1h",
          },
        );

        res.cookie("authToken", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production", // true in production (HTTPS)
          sameSite: "strict", // protects against CSRF
          maxAge: 24 * 60 * 60 * 1000,
        });

        return (
          res
            .status(200)
            .json({ success: true, message: "Logged in successfully" })
        );
      } else {
        return res
          .status(401)
          .json({ success: false, message: "Invalid credentials" });
      }
    }
  } catch (error) {
    return res.status(401).send("Invalid credentials");
  }
});

function authenticate(req: AuthRequest, res: Response, next: NextFunction) {
  const token = req.cookies?.authToken;

  if (!token) {
    return res.status(401).json({ error: "Authentication token required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as {
      userId: number;
      role: string;
    };

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token or token expired" });
  }
}

export function requireRole(requiredRole: string) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user || req.user.role !== requiredRole) {
      return res.status(403).json({ error: "Access Denied" });
    }

    next();
  };
}

app.get("/tasks/admin",
  authenticate,
  requireRole("admin"),
  async (req: AuthRequest, res: Response) => {
    try {
      const allTasks = await prisma.task.findMany();
    return res.status(200).json(allTasks);
    } catch (error) {
        return res.status(400).json({error: "Unauthorized"})
    }
    
  },
);

app.get("/test", authenticate, (req: AuthRequest, res: Response) => {
  return res.status(201).json({
    message: "User created successfully",
    user: req.user,
  });
});

app.post("/tasks", authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const { title } = req.body;
    const userId = req.user!.userId;
    const newTask = await prisma.task.create({
      data: {
        title,
        userId,
      },
    });

    return res.status(201).json(newTask);
  } catch (error) {
    return res.status(500).json({ error: "Failed to create task" });
  }
});

app.get("/tasks", authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.userId;

    const tasks = await prisma.task.findMany({
      where: {
        userId,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    res.status(200).json(tasks);
  } catch (error) {
    return res.status(500).json({ error: "Failed to retrieve tasks" });
  }
});

app.get("/tasks/:id", authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const taskId = Number(req.params.id);
    const userId = req.user!.userId;

    const task = await prisma.task.findFirst({
      where: {
        id: taskId,
        userId,
      },
    });

    if (!task) {
      return res.status(404).json({ error: "Task not found" });
    }

    return res.status(200).json(task);
  } catch (error) {
    return res.status(500).json({ error: "Unable to find task" });
  }
});

app.put("/tasks/:id", authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const taskId = Number(req.params.id);
    const userId = req.user!.userId;

    const { title, done } = req.body;

    const updatedTask = await prisma.task.updateMany({
      where: {
        id: taskId,
        userId,
      },
      data: {
        title,
        done
      },
    });

    return res
      .status(200)
      .json({ message: "Task updated successfully", updatedTask });
  } catch (error) {
    res.status(500).json({ error: "Update unsuccessful" });
  }
});

app.delete("/tasks/:id",
  authenticate,
  async (req: AuthRequest, res: Response) => {
    try {
      const taskId = Number(req.params.id);
      const userId = req.user!.userId;

      const deletedTask = await prisma.task.deleteMany({
        where: {
          id: taskId,
          userId,
        },
      });

      if(deletedTask.count === 0){
        return res.status(400).json({error: "Not Found"})
      }

      return res.status(200).json({
        message: "Task successfully deleted",
        deletedTask,
      });
    } catch (error) {
      return res.status(400).json({ error: "Error deleting task." });
    }
  },
);

app.listen(3000, () => {
  console.log("Port is active");
});
