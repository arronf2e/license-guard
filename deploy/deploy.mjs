/**
 * Deploy helper for LicenseGuard.
 *
 * Dry-run unless GENLAYER_DEPLOY=1. This file does not create a wallet and
 * does not broadcast unless the operator supplies PRIVATE_KEY.
 *
 *   node deploy/deploy.mjs
 *
 * Broadcast (operator machine, after review):
 *
 *   GENLAYER_DEPLOY=1 \
 *   PRIVATE_KEY=0x... \
 *   GENLAYER_NETWORK=studionet \
 *   node deploy/deploy.mjs
 *
 * Optional: GENLAYER_RPC overrides the chain's default endpoint.
 * genlayer-js is pinned to 1.1.8 in package.json. Install with npm install
 * before a real broadcast. A dry run does not import the SDK.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const contractPath = join(root, "contracts", "license_guard.py");
const addressPath = join(root, "deploy", "address.json");
const code = readFileSync(contractPath, "utf8");

const plan = {
  contract: "contracts/license_guard.py",
  sdk: "genlayer-js@1.1.8",
  runtime: 'py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6',
  constructor: "LicenseGuard()",
  args: [],
  note: "No constructor arguments. The deploying account becomes owner and registrar.",
};

if (process.env.GENLAYER_DEPLOY !== "1") {
  console.log(JSON.stringify({ ...plan, address: "PENDING", broadcast: false }, null, 2));
  process.exit(0);
}

const key = process.env.PRIVATE_KEY || "";
if (!/^0x[0-9a-fA-F]{64}$/.test(key)) {
  console.error(
    "PRIVATE_KEY must be a 0x-prefixed 32-byte hex key supplied by the operator. This script does not create a wallet."
  );
  process.exit(1);
}

const networkName = process.env.GENLAYER_NETWORK || "studionet";
const { createAccount, createClient } = await import("genlayer-js");
const chains = await import("genlayer-js/chains");
const chain = chains[networkName];
if (!chain) {
  console.error(`Unknown GENLAYER_NETWORK "${networkName}". Use studionet, localnet, or testnetBradbury.`);
  process.exit(1);
}

const account = createAccount(key);
const client = createClient({
  chain,
  account,
  ...(process.env.GENLAYER_RPC ? { endpoint: process.env.GENLAYER_RPC } : {}),
});

const tx = await client.deployContract({
  account,
  code,
  args: [],
});
const receipt = await client.waitForTransactionReceipt({
  hash: tx,
  status: "ACCEPTED",
  fullTransaction: true,
});
const address =
  receipt?.txDataDecoded?.contractAddress ||
  receipt?.data?.contract_address ||
  receipt?.contract_address ||
  "PENDING";

const record = {
  address,
  network: networkName,
  tx: String(tx),
  note: address === "PENDING"
    ? "Transaction submitted. The receipt did not include a contract address; copy it from the explorer before using the contract."
    : "Filled by deploy/deploy.mjs from the transaction receipt.",
};
writeFileSync(addressPath, JSON.stringify(record, null, 2) + "\n");
console.log(JSON.stringify({ tx: String(tx), address }, null, 2));
if (address === "PENDING") process.exit(2);
