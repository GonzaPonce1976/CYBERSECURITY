#!/usr/bin/env node
/**
 * setup.js — Script de configuración inicial del proyecto
 * Crea el .env desde .env.example si no existe
 *
 * Uso: node scripts/setup.js
 */

import fs from "fs";
import path from "path";
import { execSync } from "child_process";

const ROOT = process.cwd();
const log = (msg) => console.log(`  ${msg}`);
const ok = (msg) => console.log(`  ✅ ${msg}`);
const warn = (msg) => console.log(`  ⚠️  ${msg}`);
const err = (msg) => console.error(`  ❌ ${msg}`);

console.log("╔══════════════════════════════════════════════════╗");
console.log("║   CyberSecurity DApp — Setup Inicial             ║");
console.log("╚══════════════════════════════════════════════════╝\n");

// ── 1. .env ───────────────────────────────────────────────────
log("Verificando archivo .env...");
const envPath = path.join(ROOT, ".env");
const envExamplePath = path.join(ROOT, ".env.example");

if (!fs.existsSync(envPath)) {
  if (fs.existsSync(envExamplePath)) {
    fs.copyFileSync(envExamplePath, envPath);
    ok(".env creado desde .env.example");
    warn("⚠️  Edita .env y rellena las API keys antes de continuar");
  } else {
    err(".env.example no encontrado");
    process.exit(1);
  }
} else {
  ok(".env ya existe");
}

// ── 2. Node modules ────────────────────────────────────────────
log("\nVerificando node_modules...");
if (!fs.existsSync(path.join(ROOT, "node_modules"))) {
  log("Instalando dependencias npm...");
  execSync("npm install", { stdio: "inherit", cwd: ROOT });
  ok("npm install completado");
} else {
  ok("node_modules ya instalado");
}

// ── 3. Compilar contratos ─────────────────────────────────────
log("\nCompilando smart contracts...");
try {
  execSync("npx hardhat compile", { stdio: "inherit", cwd: ROOT });
  ok("Contratos compilados");
} catch (e) {
  err("Error compilando contratos: " + e.message);
}

// ── 4. Verificar Rust toolchain ───────────────────────────────
log("\nVerificando Rust toolchain...");
try {
  const rustVersion = execSync("rustc --version", { encoding: "utf8" }).trim();
  ok(`Rust encontrado: ${rustVersion}`);
} catch {
  err("Rust no instalado — visita https://rustup.rs/");
  process.exit(1);
}

// ── 5. Verificar Docker ───────────────────────────────────────
log("\nVerificando Docker...");
try {
  const dockerVersion = execSync("docker --version", { encoding: "utf8" }).trim();
  ok(`Docker encontrado: ${dockerVersion}`);
} catch {
  warn("Docker no encontrado — necesario para el stack Wazuh");
}

// ── Resumen ────────────────────────────────────────────────────
console.log("\n╔══════════════════════════════════════════════════╗");
console.log("║   Setup completado — Próximos pasos:             ║");
console.log("╠══════════════════════════════════════════════════╣");
console.log("║  1. Edita .env con tus API keys                  ║");
console.log("║  2. npm run dev:contracts  → Hardhat local node  ║");
console.log("║  3. npm run deploy:local   → Deploy contratos    ║");
console.log("║  4. npm run dev:gateway    → Rust gateway        ║");
console.log("║  5. npm run dev:frontend   → Dashboard UI        ║");
console.log("╚══════════════════════════════════════════════════╝\n");
