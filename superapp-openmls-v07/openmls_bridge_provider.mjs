import crypto from "node:crypto";
import fs from "node:fs";
import { spawnSync } from "node:child_process";

export const OPENMLS_BRIDGE_ALGORITHM = "mls.rfc9420.openmls.v0.9.0";
export class OpenMlsBridgeError extends Error {}
export class DecryptionError extends Error {}

function stable(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stable(value[k])}`).join(",")}}`;
}
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }

export class OpenMlsBridgeProvider {
  constructor({ binaryPath, stateDir, timeoutMs = 5000 } = {}) {
    if (!binaryPath || !stateDir) throw new TypeError("binaryPath and stateDir are required");
    if (!fs.existsSync(binaryPath)) throw new OpenMlsBridgeError(`OpenMLS bridge binary not found: ${binaryPath}`);
    this.binaryPath = binaryPath;
    this.stateDir = stateDir;
    this.timeoutMs = timeoutMs;
    this.algorithm = OPENMLS_BRIDGE_ALGORITHM;
    this.groups = new Set();
    this.decryptCache = new Map();
  }

  #call(request) {
    const result = spawnSync(this.binaryPath, [this.stateDir], {
      input: JSON.stringify(request), encoding: "utf8", timeout: this.timeoutMs, maxBuffer: 1024 * 1024,
    });
    if (result.error) throw new OpenMlsBridgeError(`OpenMLS bridge process failed: ${result.error.message}`);
    let parsed;
    try { parsed = JSON.parse(result.stdout || "{}"); }
    catch { throw new OpenMlsBridgeError(`OpenMLS bridge emitted invalid JSON: ${result.stdout || result.stderr}`); }
    if (result.status !== 0 || parsed.ok === false) throw new OpenMlsBridgeError(parsed.error || result.stderr || `OpenMLS bridge exited ${result.status}`);
    return parsed;
  }

  createGroup({ groupId, members }) {
    if (!groupId || !Array.isArray(members) || members.length === 0) throw new TypeError("groupId and at least one member are required");
    const response = this.#call({ op: "init", group_id: groupId, members: members.map((m) => m.deviceId) });
    this.groups.add(groupId);
    return response.epoch;
  }

  addMember(groupId, member, actorDeviceId = undefined) {
    const info = this.groupInfo(groupId, actorDeviceId);
    const actor = actorDeviceId ?? info.members[0];
    const response = this.#call({ op: "add_member", group_id: groupId, actor_device_id: actor, new_device_id: member.deviceId });
    this.groups.add(groupId);
    return response.epoch;
  }

  removeMember(groupId, deviceId, actorDeviceId = undefined) {
    const info = this.groupInfo(groupId, actorDeviceId);
    const actor = actorDeviceId ?? info.members.find((id) => id !== deviceId);
    if (!actor) throw new OpenMlsBridgeError("cannot remove the only member without an actor");
    return this.#call({ op: "remove_member", group_id: groupId, actor_device_id: actor, remove_device_id: deviceId }).epoch;
  }

  encryptCommand(command) {
    const senderDeviceId = command?.actor?.deviceId;
    if (!senderDeviceId || !command.roomId) throw new TypeError("MLS encryption requires actor.deviceId and roomId");
    const response = this.#call({
      op: "encrypt", group_id: command.roomId, sender_device_id: senderDeviceId,
      plaintext_base64: Buffer.from(stable(command.content)).toString("base64"),
    });
    this.groups.add(command.roomId);
    return {
      ...structuredClone(command),
      content: { __encrypted: true, algorithm: this.algorithm, groupId: command.roomId, epoch: response.epoch, wireBase64: response.wire_base64 },
    };
  }

  decryptEvent(event, identity) {
    const envelope = event?.content;
    if (!envelope?.__encrypted || envelope.algorithm !== this.algorithm) return structuredClone(event);
    const deviceId = identity?.deviceId;
    if (!deviceId) throw new DecryptionError("MLS decryption requires deviceId");
    const cacheKey = `${deviceId}:${sha256(envelope.wireBase64)}`;
    if (this.decryptCache.has(cacheKey)) return { ...structuredClone(event), content: structuredClone(this.decryptCache.get(cacheKey)) };
    try {
      const response = this.#call({ op: "decrypt", group_id: envelope.groupId, receiver_device_id: deviceId, wire_base64: envelope.wireBase64 });
      const content = JSON.parse(Buffer.from(response.plaintext_base64, "base64").toString("utf8"));
      this.decryptCache.set(cacheKey, content);
      return { ...structuredClone(event), content };
    } catch (error) {
      throw new DecryptionError(`OpenMLS event ${event.id ?? "unknown"} failed decryption: ${error.message}`);
    }
  }

  groupInfo(groupId, deviceId = undefined) {
    const response = this.#call({ op: "group_info", group_id: groupId, device_id: deviceId ?? null });
    this.groups.add(groupId);
    return { groupId, epoch: response.epoch, members: response.members };
  }
}
