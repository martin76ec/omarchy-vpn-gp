.pragma library

var BADGES = { gp: "GP", anyconnect: "Cisco", pulse: "Pulse", openvpn: "OVPN" }
var PENDING = { CONNECTING: true, AUTHENTICATING: true, DISCONNECTING: true }
var ACTIVE = { CONNECTING: true, AUTHENTICATING: true, CONNECTED: true }
var STATE_LABELS = {
  DISCONNECTED: "Disconnected",
  CONNECTING: "Connecting…",
  AUTHENTICATING: "Waiting for credentials…",
  CONNECTED: "Connected",
  DISCONNECTING: "Disconnecting…",
  ERROR: "Error"
}

function formatState(state) {
  return STATE_LABELS[state] || (state ? state.toLowerCase().replace(/_/g, " ") : "unknown")
}

// AUTHENTICATING covers two different waits: a human prompt is up, or the
// panel already auto-answered one and is waiting on the next network round
// trip (portal validation, then the cookie handoff to NetworkManager). The
// static label can't tell those apart; this can, since it has the prompt.
// `verifying` marks the same two waits happening for a "v" (verify-and-save)
// run instead of a real connect — CONNECTING needs its own label there since
// nothing is actually being connected; AUTHENTICATING's copy already reads
// fine either way.
function stateLabel(state, hasPrompt, verifying) {
  if (verifying && state === "CONNECTING") return "Checking credentials…"
  if (state === "AUTHENTICATING" && !hasPrompt) return "Verifying credentials…"
  return formatState(state)
}

function serverCheckLabel(response) {
  if (!response.reachable) return "Server unreachable."
  var latency = response.latency_ms
  return "Server reachable" + (latency !== null && latency !== undefined ? " (" + Math.round(latency) + " ms)" : "") + "."
}

function badge(profile) {
  var protocol = profile && profile.protocol ? String(profile.protocol) : ""
  return BADGES[protocol] || (protocol ? protocol.toUpperCase() : "VPN")
}

function isPending(state) { return PENDING[state] === true }

// True while a tunnel exists or is being built; the one in-flight profile is
// the only one that may be disconnected.
function isActive(state) { return ACTIVE[state] === true }

// The helper always emits one JSON object; anything else means it crashed
// before reaching its own error boundary.
function parseResponse(text) {
  try {
    var parsed = JSON.parse(String(text || ""))
    if (parsed && typeof parsed.ok === "boolean") return parsed
  } catch (e) {}
  return { ok: false, error: { code: "BAD_OUTPUT", message: "The VPN helper returned an unreadable response." } }
}

function errorMessage(response) {
  return response && response.error && response.error.message
    ? String(response.error.message) : "Unknown VPN error."
}

function barLabel(state, profileName, spinner) {
  if (spinner) return spinner
  var icon = "󰖂"
  if (state === "CONNECTED" && profileName) return icon + " " + profileName
  return icon
}

function step(index, delta, count) {
  if (count <= 0) return 0
  return Math.max(0, Math.min(count - 1, index + delta))
}

// Counters are cumulative, so throughput is the delta between two polls.
// A counter that went backwards (interface recreated) reads as zero.
function rates(previous, sample) {
  if (!previous || sample.at <= previous.at) return null
  var seconds = (sample.at - previous.at) / 1000
  return {
    down: Math.max(0, (sample.rx - previous.rx) / seconds),
    up: Math.max(0, (sample.tx - previous.tx) / seconds)
  }
}

function formatRate(bytesPerSecond) {
  var units = ["B/s", "KB/s", "MB/s", "GB/s"]
  var value = bytesPerSecond
  var unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return (unit === 0 ? Math.round(value) : value.toFixed(1)) + " " + units[unit]
}

function telemetryLine(rate, latencyMs) {
  var parts = []
  if (rate) parts.push("↓ " + formatRate(rate.down) + "  ↑ " + formatRate(rate.up))
  if (latencyMs !== null && latencyMs !== undefined) parts.push(Math.round(latencyMs) + " ms")
  return parts.join(" · ")
}

var PROFILE_TYPES = [
  { kind: "gp", label: "GlobalProtect", field: "Portal or gateway", placeholder: "vpn.example.com" },
  { kind: "anyconnect", label: "Cisco AnyConnect", field: "Gateway", placeholder: "vpn.example.com" },
  { kind: "pulse", label: "Juniper Pulse", field: "Gateway", placeholder: "vpn.example.com" },
  { kind: "openvpn", label: "OpenVPN", field: ".ovpn file", placeholder: "~/Downloads/work.ovpn" }
]

// Wraps, unlike step(): the type selector is a ring.
function cycle(index, delta, count) {
  return (index + delta + count) % count
}

// Openvpn takes its name from the file when left blank; the others need one.
function addRequest(typeIndex, name, server) {
  var type = PROFILE_TYPES[typeIndex]
  var request = { kind: type.kind, name: String(name).trim() }
  request[type.kind === "openvpn" ? "path" : "gateway"] = String(server).trim()
  return request
}

function canSubmit(typeIndex, name, server) {
  var needsName = PROFILE_TYPES[typeIndex].kind !== "openvpn"
  return String(server).trim() !== "" && (!needsName || String(name).trim() !== "")
}
