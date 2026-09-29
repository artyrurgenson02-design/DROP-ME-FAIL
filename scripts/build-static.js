"use strict";

const fs = require("node:fs");
const path = require("node:path");

const apiBaseUrl = (process.env.API_BASE_URL || "https://drop-me-fail-backend.onrender.com").replace(/\/$/, "");
if (!/^https:\/\//i.test(apiBaseUrl)) {
  console.error("Set API_BASE_URL to the HTTPS URL of the Render backend before building the Static Site.");
  process.exit(1);
}

const source = path.join(__dirname, "..", "DROP ME FAIL", "index.html");
const outputDir = path.join(__dirname, "..", "dist");
const output = path.join(outputDir, "index.html");
const html = fs.readFileSync(source, "utf8");
const config = "<script>window.API_BASE_URL=" + JSON.stringify(apiBaseUrl).replace(/</g, "\\u003c") + ";</script>";
if (!html.includes("</head>")) throw new Error("Frontend index.html has no closing head element");
fs.mkdirSync(outputDir, { recursive: true });
fs.writeFileSync(output, html.replace("</head>", config + "</head>"));
console.log("Built Static Site frontend to dist/index.html");
