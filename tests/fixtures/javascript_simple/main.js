// Smoke-test fixture — express is used, lodash declared but not imported.
import express from "express";

const app = express();
app.get("/", (_req, res) => res.send("ok"));
