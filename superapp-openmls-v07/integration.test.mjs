import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { DecryptionError, OpenMlsBridgeProvider } from "./openmls_bridge_provider.mjs";

const binaryPath = process.env.OPENMLS_BRIDGE_BIN;
if (!binaryPath) throw new Error("OPENMLS_BRIDGE_BIN is required");

function command(deviceId, text) {
  return { roomId: "room-bridge", actor: { deviceId }, type: "message.sent", content: { text } };
}
function eventFrom(encrypted, id) { return { id, roomId: encrypted.roomId, type: encrypted.type, content: encrypted.content }; }

test("Node CryptoProvider boundary uses persistent OpenMLS groups across process restarts", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "superapp-openmls-v07-"));
  const provider = new OpenMlsBridgeProvider({ binaryPath, stateDir, timeoutMs: 10000 });

  const epoch1 = provider.createGroup({ groupId: "room-bridge", members: [{ deviceId: "alice" }, { deviceId: "bob" }] });
  assert.ok(epoch1 >= 1);

  const first = provider.encryptCommand(command("alice", "epoch-one"));
  assert.equal(provider.decryptEvent(eventFrom(first, "e1"), { deviceId: "bob" }).content.text, "epoch-one");

  const beforeCharlie = provider.encryptCommand(command("alice", "before-charlie"));
  provider.removeMember("room-bridge", "bob", "alice");
  const afterBob = provider.encryptCommand(command("alice", "after-bob-removal"));
  assert.throws(() => provider.decryptEvent(eventFrom(afterBob, "e2"), { deviceId: "bob" }), DecryptionError);

  provider.addMember("room-bridge", { deviceId: "charlie" }, "alice");
  assert.throws(() => provider.decryptEvent(eventFrom(beforeCharlie, "e3"), { deviceId: "charlie" }), DecryptionError);
  const current = provider.encryptCommand(command("alice", "after-charlie"));
  assert.equal(provider.decryptEvent(eventFrom(current, "e4"), { deviceId: "charlie" }).content.text, "after-charlie");

  const info = provider.groupInfo("room-bridge", "alice");
  assert.deepEqual([...info.members].sort(), ["alice", "charlie"]);
  assert.ok(info.epoch >= 3);

  // Constructing a fresh Node provider plus every Rust call being a fresh process
  // proves state is being reloaded from OpenMLS SQLite rather than held in RAM.
  const restarted = new OpenMlsBridgeProvider({ binaryPath, stateDir, timeoutMs: 10000 });
  assert.deepEqual([...restarted.groupInfo("room-bridge", "charlie").members].sort(), ["alice", "charlie"]);
  const postRestart = restarted.encryptCommand(command("alice", "after-restart"));
  assert.equal(restarted.decryptEvent(eventFrom(postRestart, "e5"), { deviceId: "charlie" }).content.text, "after-restart");

  const sqliteFiles = [];
  for (const dir of fs.readdirSync(path.join(stateDir, "devices"))) {
    const candidate = path.join(stateDir, "devices", dir, "openmls.sqlite");
    if (fs.existsSync(candidate)) sqliteFiles.push(candidate);
  }
  assert.ok(sqliteFiles.length >= 3, "expected per-device persistent OpenMLS SQLite state");
  for (const dir of fs.readdirSync(path.join(stateDir, "devices"))) {
    const identity = path.join(stateDir, "devices", dir, "identity.json");
    if (fs.existsSync(identity)) {
      const text = fs.readFileSync(identity, "utf8");
      assert.ok(!text.includes('"private"'), "identity metadata must not duplicate raw private signer material outside OpenMLS storage");
    }
  }
});
