import { execFileSync } from "node:child_process"
import { createHash, randomBytes, randomUUID } from "node:crypto"
import { readFileSync, statSync } from "node:fs"
import { createServer } from "node:http"
import { homedir } from "node:os"
import { join } from "node:path"

export const APP_VERSION = "1.2.4660"
export const DEFAULT_SOCIAL_ISSUER_URL = "https://identitycenter.amazonaws.com/ssoins-7223e642b2afb64c"
export const REFRESH_LEAD_MS = 5 * 60 * 1000
export const KEEP_RENEWED_MS = 60 * 1000
export const SIGN_IN_TIMEOUT_MS = 10 * 60 * 1000
export const DESKTOP_CACHE_MS = 2000
export const DESKTOP_NEGATIVE_CACHE_MS = 45_000
export const MACOS_KEYCHAIN_TIMEOUT_MS = 45_000

const GATEWAY_PROVIDERS = new Set(["gateway", "social_gateway"])
const AIDP_PROVIDERS = new Set(["enterprise", "social"])
const SOCIAL_PROVIDERS = new Set(["social", "social_gateway"])

const PS_CRED_SCRIPT = [
  "$Target = $env:QUICKWORK_CRED_TARGET",
  "$cs = @'",
  "using System;",
  "using System.Runtime.InteropServices;",
  "using System.Text;",
  "public class WinCred {",
  "  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]",
  "  struct CREDENTIAL {",
  "    public int Flags; public int Type; public string TargetName; public string Comment;",
  "    public long LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob;",
  "    public int Persist; public int AttributeCount; public IntPtr Attributes;",
  "    public string TargetAlias; public string UserName;",
  "  }",
  "  [DllImport(\"advapi32.dll\", SetLastError = true, CharSet = CharSet.Unicode)]",
  "  static extern bool CredRead(string target, int type, int flags, out IntPtr credPtr);",
  "  [DllImport(\"advapi32.dll\")] static extern void CredFree(IntPtr cred);",
  "  public static string Read(string target) {",
  "    IntPtr ptr;",
  "    if (!CredRead(target, 1, 0, out ptr)) return null;",
  "    try {",
  "      var c = Marshal.PtrToStructure<CREDENTIAL>(ptr);",
  "      if (c.CredentialBlobSize <= 0 || c.CredentialBlob == IntPtr.Zero) return \"\";",
  "      var bytes = new byte[c.CredentialBlobSize];",
  "      Marshal.Copy(c.CredentialBlob, bytes, 0, bytes.Length);",
  "      return Encoding.Unicode.GetString(bytes);",
  "    } finally { CredFree(ptr); }",
  "  }",
  "}",
  "'@",
  "Add-Type -TypeDefinition $cs -ErrorAction Stop | Out-Null",
  "$raw = [WinCred]::Read($Target)",
  "if ($null -eq $raw) { exit 2 }",
  "try {",
  "  $meta = $raw | ConvertFrom-Json -ErrorAction Stop",
  "  if ($null -ne $meta.__chunks__) {",
  "    $sb = New-Object System.Text.StringBuilder",
  "    for ($i = 0; $i -lt [int]$meta.__chunks__; $i++) {",
  "      $chunk = [WinCred]::Read(\"${Target}_chunk_${i}\")",
  "      if ($null -eq $chunk) { exit 3 }",
  "      [void]$sb.Append($chunk)",
  "    }",
  "    $raw = $sb.ToString()",
  "  }",
  "} catch {}",
  "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
  "[Console]::Write($raw)",
].join("\n")

const PS_CRED_ENCODED = Buffer.from(PS_CRED_SCRIPT, "utf16le").toString("base64")

const str = (v) => (typeof v === "string" ? v.trim() : "")

export function quickworkDir(env = process.env, home = homedir()) {
  return str(env.QUICKWORK_DIR || env.AWS_QUICK_DIR) || join(home, ".quickwork")
}

export function isGatewayProvider(provider) {
  return GATEWAY_PROVIDERS.has(str(provider).toLowerCase())
}

export function isAidpProvider(provider) {
  return AIDP_PROVIDERS.has(str(provider).toLowerCase())
}

export function isSocialProvider(provider) {
  return SOCIAL_PROVIDERS.has(str(provider).toLowerCase())
}

export function regionFromUrl(url, fallback = "") {
  const s = str(url)
  if (!s) return fallback
  const m =
    s.match(/\.([a-z]{2}-[a-z]+-\d+)\.(?:prod|beta|alpha|preprod)\./i) ||
    s.match(/(?:oidc|sso|portal\.sso)\.([a-z]{2}-[a-z]+-\d+)\.amazonaws\.com/i) ||
    s.match(/\.([a-z]{2}-[a-z]+-\d+)\.(?:amazonaws\.com|aws\.dev|quick\.aws\.(?:com|dev))/i)
  return m ? m[1].toLowerCase() : fallback
}

export function hostFromUrl(url) {
  const s = str(url)
  if (!s) return ""
  try {
    return new URL(s.includes("://") ? s : `https://${s}`).host
  } catch {
    return ""
  }
}

export function toMs(ts, fallback = 0) {
  if (typeof ts === "string" && ts.trim() && !/^\d+(\.\d+)?$/.test(ts.trim())) {
    const parsed = Date.parse(ts)
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
  }
  const n = Number(ts)
  if (!Number.isFinite(n) || n <= 0) return fallback
  // Seconds (< 1e12) vs milliseconds (>= 1e12)
  return n < 1e12 ? Math.round(n * 1000) : Math.round(n)
}

export function surfaceTypeForPlatform(platform = process.platform) {
  return platform === "darwin" ? "QUICK_WORK_DESKTOP_MAC" : "QUICK_WORK_DESKTOP_WINDOWS"
}

/**
 * Reassemble chunked UTF-16-LE credential store payloads (as python-keyring writes them on Windows).
 * @param {(name: string) => string | null} readTarget
 * @param {string} targetName
 * @returns {string | null}
 */
export function readChunkedCredential(readTarget, targetName) {
  const raw = readTarget(targetName)
  if (raw == null) return null
  try {
    const parsed = JSON.parse(raw)
    if (parsed && typeof parsed === "object" && Number.isInteger(parsed.__chunks__) && parsed.__chunks__ > 0) {
      let full = ""
      for (let i = 0; i < parsed.__chunks__; i++) {
        const part = readTarget(`${targetName}_chunk_${i}`)
        if (part == null) return null
        full += part
      }
      if (typeof parsed.__sha__ === "string" && parsed.__sha__) {
        const digest = createHash("sha256").update(Buffer.from(full, "utf8")).digest("hex")
        // python-keyring hashes utf-16-le bytes on Windows, or utf-8 on POSIX
        const digestUtf16 = createHash("sha256").update(Buffer.from(full, "utf16le")).digest("hex")
        if (digest !== parsed.__sha__ && digestUtf16 !== parsed.__sha__) return null
      }
      return full
    }
  } catch {
    // Plain unchunked or non-JSON secret
  }
  return raw
}

export function readWindowsCredentialRaw(targetName, execSync = execFileSync) {
  try {
    return execSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", PS_CRED_ENCODED],
      {
        encoding: "utf8",
        windowsHide: true,
        timeout: 8000,
        env: { ...process.env, QUICKWORK_CRED_TARGET: targetName },
        stdio: ["ignore", "pipe", "ignore"],
      },
    )
  } catch {
    return null
  }
}

function classifyDarwinKeychainError(err) {
  if (err?.code === "ETIMEDOUT" || err?.killed) {
    return {
      kind: "timeout",
      message:
        "macOS Keychain authorization timed out while reading Amazon Quick desktop credentials. Enter your macOS login password and click 'Always Allow' in the Keychain dialog, or switch to 'Amazon Quick account (browser)' sign-in to avoid Keychain prompts.",
    }
  }
  const stderr = String(err?.stderr ?? err?.message ?? "").trim()
  if (/user canceled|interaction is not allowed|denied|authfailed|not allowed|-128|-25293|-25308/i.test(stderr)) {
    return {
      kind: "denied",
      message:
        "macOS Keychain denied access to Amazon Quick desktop credentials. Allow access ('Always Allow') with your macOS login password, or switch to 'Amazon Quick account (browser)' sign-in to avoid Keychain prompts.",
    }
  }
  if (/could not be found|-25300/i.test(stderr)) {
    return { kind: "not_found", message: "" }
  }
  return {
    kind: "error",
    message: stderr
      ? `macOS Keychain failed to read Amazon Quick desktop credentials (${stderr.slice(0, 140)}). Try 'Amazon Quick account (browser)' sign-in instead.`
      : "",
  }
}

function readPosixCredentialDetailed(targetName, platform = process.platform, execSync = execFileSync, opts = {}) {
  let lastError = null
  if (platform === "darwin") {
    const timeout = Number(opts.keychainTimeoutMs) > 0 ? Number(opts.keychainTimeoutMs) : MACOS_KEYCHAIN_TIMEOUT_MS
    const value = readChunkedCredential((name) => {
      try {
        return execSync("security", ["find-generic-password", "-s", name, "-w"], {
          encoding: "utf8",
          timeout,
          stdio: ["ignore", "pipe", "pipe"],
        }).replace(/\r?\n$/, "")
      } catch (err) {
        lastError = classifyDarwinKeychainError(err)
        return null
      }
    }, targetName)
    return { value, error: value ? null : lastError }
  }
  const value = readChunkedCredential((name) => {
    try {
      return execSync("secret-tool", ["lookup", "service", name], {
        encoding: "utf8",
        timeout: 5000,
        stdio: ["ignore", "pipe", "pipe"],
      }).replace(/\r?\n$/, "")
    } catch {
      return null
    }
  }, targetName)
  return { value, error: null }
}

export function readPosixCredentialRaw(targetName, platform = process.platform, execSync = execFileSync, opts = {}) {
  return readPosixCredentialDetailed(targetName, platform, execSync, opts).value
}

export function readDesktopProfiles(opts = {}) {
  const dir = opts.dir ?? quickworkDir(opts.env, opts.home)
  const file = join(dir, "profiles.json")
  try {
    const data = JSON.parse((opts.readFileSync ?? readFileSync)(file, "utf8"))
    const entries = Array.isArray(data?.entries) ? data.entries : []
    return {
      file,
      lastActive: str(data?.last_active),
      entries: entries.filter((e) => e && typeof e === "object" && str(e.id)),
    }
  } catch {
    return { file, lastActive: "", entries: [] }
  }
}

export function selectDesktopProfile(profiles, preferredId = "") {
  if (!profiles?.entries?.length) return null
  const want = str(preferredId) || str(profiles.lastActive)
  if (want) {
    const match = profiles.entries.find((e) => str(e.id) === want)
    if (match) return match
  }
  return profiles.entries[0]
}

export function normalizeAuth(cred, profile = null, source = "") {
  const access = str(cred?.access ?? cred?.accessToken ?? cred?.access_token)
  const refresh = str(cred?.refresh ?? cred?.refreshToken ?? cred?.refresh_token)
  const tenantUrl = str(cred?.tenantUrl ?? cred?.tenant_url ?? profile?.login_metadata?.tenant_url).replace(/\/+$/, "")
  const issuerUrl = str(cred?.issuerUrl ?? cred?.issuer_url ?? profile?.login_metadata?.issuer_url).replace(/\/+$/, "")
  const clientId = str(cred?.clientId ?? cred?.client_id ?? profile?.login_metadata?.client_id)
  const clientSecret = str(cred?.clientSecret ?? cred?.client_secret)
  const providerType = str(cred?.providerType ?? cred?.provider ?? profile?.provider) || "social"
  const region = str(cred?.region) || regionFromUrl(issuerUrl) || regionFromUrl(tenantUrl) || "us-east-1"
  const expires =
    toMs(cred?.expires ?? cred?.expiresAt ?? cred?.access_token_expiry) ||
    (Number(cred?.expiresIn ?? cred?.expires_in) > 0 ? Date.now() + Number(cred.expiresIn ?? cred.expires_in) * 1000 : 0)
  const refreshExpiresAt =
    toMs(cred?.refreshExpiresAt ?? cred?.refresh_token_expiry) ||
    (Number(cred?.refreshExpiresIn ?? cred?.refresh_expires_in) > 0
      ? Date.now() + Number(cred.refreshExpiresIn ?? cred.refresh_expires_in) * 1000
      : 0)
  const email = str(cred?.email)
  const displayName = str(cred?.displayName ?? cred?.display_name ?? profile?.display_name)
  const profileId = str(cred?.profileId ?? profile?.id)
  const awsAccountId = str(cred?.awsAccountId ?? cred?.aws_account_id ?? cred?.accountId)
  const accountId = email || displayName || profileId || awsAccountId || "Amazon Quick"
  const id = str(cred?.id)

  return {
    access,
    refresh,
    expires,
    ...(id ? { id } : {}),
    ...(refreshExpiresAt ? { refreshExpiresAt } : {}),
    ...(clientId ? { clientId } : {}),
    ...(clientSecret ? { clientSecret } : {}),
    ...(issuerUrl ? { issuerUrl } : {}),
    ...(tenantUrl ? { tenantUrl } : {}),
    ...(tenantUrl ? { wsHost: hostFromUrl(tenantUrl) } : {}),
    region,
    providerType,
    ...(awsAccountId ? { awsAccountId } : {}),
    ...(profileId ? { profileId } : {}),
    ...(email ? { email } : {}),
    ...(displayName ? { displayName } : {}),
    accountId,
    ...(source ? { source } : {}),
  }
}

let desktopCache = { at: 0, key: "", mtimeMs: -1, value: null, errorKind: "", errorMsg: "" }

export function clearDesktopCache() {
  desktopCache = { at: 0, key: "", mtimeMs: -1, value: null, errorKind: "", errorMsg: "" }
}

function fileMtimeMs(path, statImpl = statSync) {
  try {
    return Number(statImpl(path)?.mtimeMs) || 0
  } catch {
    return 0
  }
}

/**
 * Read Amazon Quick desktop's current signed-in session from ~/.quickwork/profiles.json + Credential Store.
 * Never mutates Quick Desktop's files or keyring entries.
 */
export function readDesktop(opts = {}) {
  const now = opts.now ?? Date.now()
  const dir = opts.dir ?? quickworkDir(opts.env, opts.home)
  const profilesFile = join(dir, "profiles.json")
  const mtimeMs = opts.readFileSync ? -1 : fileMtimeMs(profilesFile, opts.statSync)
  const key = `${opts.profileId || ""}|${dir}|${opts.readKeyring ? "mock" : "os"}`
  const negativeTtl = Number(opts.negativeCacheMs) >= 0 ? Number(opts.negativeCacheMs) : DESKTOP_NEGATIVE_CACHE_MS
  if (!opts.noCache && desktopCache.key === key) {
    if (desktopCache.value) {
      const withinShortTtl = now - desktopCache.at < DESKTOP_CACHE_MS
      const osTokenStillFresh =
        !opts.readKeyring &&
        !opts.readFileSync &&
        mtimeMs > 0 &&
        mtimeMs === desktopCache.mtimeMs &&
        desktopCache.value.expires > 0 &&
        desktopCache.value.expires - REFRESH_LEAD_MS > now
      if (withinShortTtl || osTokenStillFresh) {
        return desktopCache.value
      }
    } else if (
      (desktopCache.errorKind === "timeout" || desktopCache.errorKind === "denied") &&
      now - desktopCache.at < negativeTtl
    ) {
      return null
    }
  }
  const profiles = readDesktopProfiles(opts)
  const profile = selectDesktopProfile(profiles, opts.profileId)
  if (!profile) return null
  const target = `quickwork-${profile.provider}-${profile.id}`
  const platform = opts.platform ?? process.platform
  let raw = null
  let keyringErr = null
  if (opts.readKeyring) {
    raw = opts.readKeyring(target)
  } else if (platform === "win32") {
    raw = readWindowsCredentialRaw(target, opts.execFileSync)
  } else {
    const res = readPosixCredentialDetailed(target, platform, opts.execFileSync, opts)
    raw = res.value
    keyringErr = res.error
  }
  if (!raw) {
    if (keyringErr && (keyringErr.kind === "timeout" || keyringErr.kind === "denied" || keyringErr.kind === "error")) {
      desktopCache = {
        at: now,
        key,
        mtimeMs,
        value: null,
        errorKind: keyringErr.kind,
        errorMsg: keyringErr.message,
      }
    }
    return null
  }
  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch {
    return null
  }
  const auth = normalizeAuth(parsed, profile, "desktop")
  if (!auth.access || !auth.tenantUrl) return null
  if (!opts.noCache) desktopCache = { at: now, key, mtimeMs, value: auth, errorKind: "", errorMsg: "" }
  return auth
}

export function notDesktop(opts = {}) {
  const dir = opts.dir ?? quickworkDir(opts.env, opts.home)
  const key = `${opts.profileId || ""}|${dir}|${opts.readKeyring ? "mock" : "os"}`
  if (desktopCache.key === key && !desktopCache.value && desktopCache.errorMsg) {
    return desktopCache.errorMsg
  }
  const profiles = readDesktopProfiles(opts)
  if (!profiles.entries.length) return "Amazon Quick desktop isn't signed in (no profiles found in ~/.quickwork/profiles.json)"
  return "Amazon Quick desktop credential isn't available or is signed out; sign in to Amazon Quick desktop again or use browser/file import"
}

export function desktopSignIn(opts = {}) {
  const isMac = (opts.platform ?? process.platform) === "darwin"
  return {
    url: "",
    instructions: isMac
      ? "Uses Amazon Quick desktop's signed-in session (macOS may prompt for your login Keychain password when Quick refreshes its session; browser sign-in avoids Keychain prompts)."
      : "Uses the account Amazon Quick desktop is signed in to.",
    method: "auto",
    async callback() {
      const d = readDesktop({ ...opts, noCache: true })
      if (!d) return { type: "failed", error: notDesktop(opts) }
      return {
        type: "success",
        refresh: "",
        access: "",
        expires: 0,
        source: "desktop",
        accountId: d.accountId,
        profileId: d.profileId,
        providerType: d.providerType,
        region: d.region,
        ...(d.tenantUrl ? { tenantUrl: d.tenantUrl } : {}),
        ...(d.issuerUrl ? { issuerUrl: d.issuerUrl } : {}),
        ...(d.clientId ? { clientId: d.clientId } : {}),
      }
    },
  }
}

export const stale = (a, lead = REFRESH_LEAD_MS, now = Date.now()) => !a?.expires || a.expires - lead <= now

export const refreshable = (a, now = Date.now()) =>
  !!(a?.refresh && a?.clientId && (!a.refreshExpiresAt || a.refreshExpiresAt > now))

const renewQueue = new Map()
const recentRenewed = new Map()

function rememberRenewed(key, next) {
  recentRenewed.set(key, { a: next, at: Date.now() })
  if (recentRenewed.size > 64) {
    const first = recentRenewed.keys().next().value
    if (first !== undefined) recentRenewed.delete(first)
  }
}

/**
 * Refresh an AWS IAM Identity Center OIDC access token via sso-oidc CreateToken (`grantType: "refresh_token"`).
 * Deduplicates concurrent callers using the same refresh token so rotating tokens aren't double-spent.
 */
export async function renewOidc(a, persist, opts = {}) {
  const region = a.region || regionFromUrl(a.issuerUrl) || regionFromUrl(a.tenantUrl) || "us-east-1"
  const key = `${region}|${a.clientId}|${a.refresh}`
  const hit = recentRenewed.get(key)
  if (hit && Date.now() - hit.at < KEEP_RENEWED_MS) return hit.a
  if (renewQueue.has(key)) return renewQueue.get(key)

  const run = (async () => {
    const fetchImpl = opts.fetch ?? fetch
    const endpoint = `https://oidc.${region}.amazonaws.com/token`
    const payload = {
      clientId: a.clientId,
      grantType: "refresh_token",
      refreshToken: a.refresh,
      ...(a.clientSecret ? { clientSecret: a.clientSecret } : {}),
    }
    const res = await fetchImpl(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
    const text = await res.text()
    let body = {}
    try {
      body = JSON.parse(text)
    } catch {}
    if (!res.ok || !body?.accessToken) {
      const code = body?.error || body?.__type || `HTTP_${res.status}`
      const msg = body?.error_description || body?.message || text || res.statusText
      const err = new Error(`OIDC token refresh failed (${code}): ${msg}`)
      err.status = res.status
      err.code = code
      err.refreshRefused = /invalid_grant|unauthorized|expired|revoked/i.test(`${code} ${msg}`)
      throw err
    }
    const expiresIn = Number(body.expiresIn) > 0 ? Number(body.expiresIn) : 3600
    const next = {
      ...a,
      access: str(body.accessToken),
      refresh: str(body.refreshToken) || a.refresh,
      expires: (opts.now ?? Date.now()) + expiresIn * 1000,
    }
    rememberRenewed(key, next)
    if (persist) {
      try {
        await persist(next)
      } catch {}
    }
    return next
  })()

  renewQueue.set(key, run)
  try {
    return await run
  } finally {
    if (renewQueue.get(key) === run) renewQueue.delete(key)
  }
}

export async function currentAuth(client, auth, opts = {}) {
  if (auth?.source === "desktop") {
    const d = readDesktop({ ...opts, profileId: auth.profileId })
    if (!d) throw new Error(notDesktop(opts))
    return d
  }
  const a = normalizeAuth(auth, null, auth?.source || "")
  if (!a.access || !a.tenantUrl) throw new Error("Amazon Quick isn't signed in cleanly (missing token or tenantUrl)")
  if (!stale(a, REFRESH_LEAD_MS, opts.now) || !refreshable(a, opts.now)) return a
  try {
    return await renewOidc(a, async (next) => {
      await client?.auth?.set?.({ path: { id: a.id || "amazon-quick" }, body: next })
    }, opts)
  } catch (e) {
    if (!e?.refreshRefused && a.expires > (opts.now ?? Date.now())) return a
    throw e
  }
}

export async function reissuedAuth(client, getAuth, a, beganAccess, opts = {}) {
  if (a.source === "desktop") {
    clearDesktopCache()
    const d = readDesktop({ ...opts, profileId: a.profileId, noCache: true })
    if (!d) return { why: notDesktop(opts), kind: "unknown" }
    if (d.access !== a.access) return { a: d }
    return { why: "Amazon Quick desktop's current token was refused", kind: "unknown" }
  }
  const checkNewer = async () => {
    const latest = await getAuth().catch(() => null)
    return latest?.type === "oauth" && latest.source !== "desktop" && latest.access && latest.access !== beganAccess && latest.access !== a.access
      ? normalizeAuth(latest, null, latest.source || "")
      : null
  }
  const saved = await checkNewer()
  if (saved) return { a: saved }
  if (!refreshable(a, opts.now)) {
    return {
      why: a.refresh ? "its refresh token has expired or clientId is missing" : "there is no refresh token to renew it with",
      kind: "nothing to renew with",
    }
  }
  try {
    const next = await renewOidc(a, async (n) => {
      await client?.auth?.set?.({ path: { id: a.id || "amazon-quick" }, body: n })
    }, opts)
    return next.access !== a.access ? { a: next } : { why: "renewing gave the same access token", kind: "unknown" }
  } catch (e) {
    if (e?.refreshRefused) {
      const savedAfter = await checkNewer()
      if (savedAfter) return { a: savedAfter }
      return { why: `OIDC refused the refresh token (${e.message})`, kind: "refresh refused" }
    }
    return { why: `renewing failed: ${e?.message ?? e}`, kind: "unknown" }
  }
}

export function refreshHook(auth, opts = {}) {
  if (auth?.type !== "oauth" || auth?.source === "desktop") return undefined
  const a = normalizeAuth(auth, null, auth?.source || "")
  if (!refreshable(a, opts.now)) return undefined
  return renewOidc(a, null, opts).then((next) => ({
    access: next.access,
    refresh: next.refresh,
    expires: next.expires,
    ...(next.refreshExpiresAt ? { refreshExpiresAt: next.refreshExpiresAt } : {}),
  }))
}

// ---- Import from JSON file ----

export const IMPORT_FROM = {
  en: "Choose a JSON copy of your Amazon Quick credentials (with access_token/access, refresh_token/refresh, client_id, issuer_url, and tenant_url).",
  froms: {
    zh: "选择导出的 Amazon Quick 登录凭证 JSON 文件（包含 access_token/access、refresh_token/refresh、client_id、issuer_url 和 tenant_url）。",
    "zh-TW": "選擇匯出的 Amazon Quick 登入憑證 JSON 檔案（包含 access_token/access、refresh_token/refresh、client_id、issuer_url 與 tenant_url）。",
  },
}

export function signInsIn(text) {
  let root
  try {
    root = JSON.parse(text)
  } catch {
    return [{ error: "not JSON" }]
  }
  const out = []
  const seen = new Set()
  const walk = (node, depth) => {
    if (!node || typeof node !== "object" || depth > 4 || seen.has(node)) return
    seen.add(node)
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1)
      return
    }
    const hasToken = !!(str(node.access ?? node.accessToken ?? node.access_token) || str(node.refresh ?? node.refreshToken ?? node.refresh_token))
    if (hasToken) {
      out.push(normalizeAuth(node))
      return
    }
    for (const v of Object.values(node)) walk(v, depth + 1)
  }
  walk(root, 0)
  return out.length ? out : [{ error: "no Amazon Quick credentials found in file" }]
}

export async function importSignIns(texts, opts = {}) {
  const results = []
  let successCount = 0
  for (const text of texts) {
    for (const item of signInsIn(text)) {
      if (item.error) {
        results.push({ type: "failed", error: item.error })
        continue
      }
      try {
        let a = item
        if (refreshable(a, opts.now)) {
          a = await renewOidc(a, null, opts)
        } else if (!a.access || (a.expires > 0 && a.expires <= (opts.now ?? Date.now()))) {
          throw new Error("the credentials have expired and cannot be refreshed")
        }
        if (!a.tenantUrl) throw new Error("missing tenant_url in imported Amazon Quick credentials")
        // 为每个导入的账号分配独立 auth ID 和唯一 accountId
        // accountId 决定 Magpie 的账号去重（settle）：两个号 accountId 相同会被合并
        const acctId = a.tenantUrl
          ? `amazon-quick-${createHash("sha256").update(a.tenantUrl).digest("hex").slice(0, 12)}`
          : `amazon-quick-${++successCount}`
        const acctLabel = a.tenantUrl ? hostFromUrl(a.tenantUrl) : `Amazon Quick ${successCount}`
        results.push({
          ...a,
          id: acctId,
          accountId: acctLabel,
          type: "success",
        })
        successCount++
      } catch (e) {
        results.push({
          type: "failed",
          error: e?.message ?? String(e),
          ...(item.accountId ? { accountId: item.accountId } : {}),
        })
      }
    }
  }
  return results
}

// ---- Browser OAuth PKCE & Device Code (AWS IAM Identity Center sso-oidc) ----

function base64Url(buf) {
  return Buffer.from(buf).toString("base64url")
}

function normalizeHttpsUrl(value) {
  const s = str(value).replace(/\/+$/, "")
  if (!s) return ""
  return /^https?:\/\//i.test(s) ? s : `https://${s}`
}

function resolveOidcContext(inputs = {}, opts = {}) {
  const desktopHint = readDesktopProfiles(opts)
  const hintedProfile = selectDesktopProfile(desktopHint)
  const issuerUrl = normalizeHttpsUrl(inputs?.issuerUrl || hintedProfile?.login_metadata?.issuer_url || DEFAULT_SOCIAL_ISSUER_URL)
  const tenantUrl = normalizeHttpsUrl(inputs?.tenantUrl || hintedProfile?.login_metadata?.tenant_url)
  const tenantHost = hostFromUrl(tenantUrl)
  const looksGateway = /\.(?:desktop\.)?(?:enterprise\.)?quick\.aws\.(?:com|dev)$/i.test(tenantHost)
  const providerType =
    str(inputs?.providerType) ||
    (looksGateway
      ? "gateway"
      : isSocialProvider(hintedProfile?.provider) || issuerUrl === DEFAULT_SOCIAL_ISSUER_URL || /\/ssoins-/i.test(issuerUrl)
        ? "social"
        : "enterprise")
  const region = str(inputs?.region) || regionFromUrl(issuerUrl) || regionFromUrl(tenantUrl) || "us-east-1"
  return { issuerUrl, tenantUrl, providerType, region }
}

function sleepAbortable(ms, signal) {
  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve()
      return
    }
    const onAbort = () => {
      clearTimeout(t)
      resolve()
    }
    const t = setTimeout(() => {
      signal?.removeEventListener?.("abort", onAbort)
      resolve()
    }, ms)
    t.unref?.()
    signal?.addEventListener?.("abort", onAbort, { once: true })
  })
}

export async function browserSignIn(inputs = {}, opts = {}) {
  const { issuerUrl, tenantUrl, providerType, region } = resolveOidcContext(inputs, opts)
  if (!tenantUrl) {
    throw new Error(
      'Missing Amazon Quick Tenant URL (qbs-...plato.ai.aws.dev): sign in on Amazon Quick desktop once on this machine, or for VPS / remote / headless setups use "Amazon Quick Device Code (VPS / Remote / Headless)" or "Import accounts from a file…".',
    )
  }
  const fetchImpl = opts.fetch ?? fetch
  const oidcBase = `https://oidc.${region}.amazonaws.com`

  // Start loopback HTTP server for authorization code redirect
  let resolveCode, rejectCode
  const codePromise = new Promise((resolve, reject) => {
    resolveCode = resolve
    rejectCode = reject
  })
  const server = createServer((req, res) => {
    try {
      const u = new URL(req.url || "/", "http://127.0.0.1")
      if (u.pathname === "/favicon.ico") {
        res.writeHead(204)
        res.end()
        return
      }
      if (u.pathname !== "/" && u.pathname !== "/callback") {
        res.writeHead(404)
        res.end("Not found")
        return
      }
      const err = u.searchParams.get("error")
      const errDesc = u.searchParams.get("error_description")
      const code = u.searchParams.get("code")
      const state = u.searchParams.get("state")
      if (!err && !code) {
        res.writeHead(400)
        res.end("Missing code")
        return
      }
      res.writeHead(err ? 400 : 200, { "Content-Type": "text/html; charset=utf-8" })
      res.end(
        err
          ? `<html><body><h3>Amazon Quick sign-in failed</h3><p>${err}: ${errDesc || ""}</p></body></html>`
          : `<html><body><h3>AWS Quick — Signed In</h3><p>You can close this window and return to Magpie / OpenCode.</p></body></html>`,
      )
      if (err) rejectCode(new Error(`${err}: ${errDesc || "authorization failed"}`))
      else resolveCode({ code, state })
    } catch (e) {
      rejectCode(e)
    }
  })
  await new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", () => resolve())
  })
  server.unref?.()
  const abandonMs = Number(opts.abandonMs) > 0 ? Number(opts.abandonMs) : (opts.timeoutMs ?? SIGN_IN_TIMEOUT_MS) + 30_000
  const abandonTimer = setTimeout(() => {
    try { server.close() } catch {}
    rejectCode(new Error("Timed out waiting for Amazon Quick browser sign-in"))
  }, abandonMs)
  abandonTimer.unref?.()
  const addr = server.address()
  const redirectUri = `http://127.0.0.1:${addr.port}`

  let regRes
  try {
    regRes = await fetchImpl(`${oidcBase}/client/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        clientName: "Amazon Quick",
        clientType: "public",
        scopes: ["quicksight:read_write"],
        grantTypes: ["authorization_code", "refresh_token"],
        redirectUris: [redirectUri],
        issuerUrl,
      }),
    })
  } catch (e) {
    clearTimeout(abandonTimer)
    server.close()
    throw e
  }
  const regJson = await regRes.json().catch(() => ({}))
  if (!regRes.ok || !regJson?.clientId) {
    clearTimeout(abandonTimer)
    server.close()
    throw new Error(`OIDC client registration failed (${regRes.status}): ${regJson?.error_description || regJson?.message || regRes.statusText}`)
  }

  const codeVerifier = base64Url(randomBytes(32))
  const codeChallenge = base64Url(createHash("sha256").update(codeVerifier).digest())
  const expectedState = base64Url(randomBytes(16))

  const authUrl = new URL(`${oidcBase}/authorize`)
  authUrl.searchParams.set("response_type", "code")
  authUrl.searchParams.set("client_id", regJson.clientId)
  authUrl.searchParams.set("redirect_uri", redirectUri)
  authUrl.searchParams.set("scope", "quicksight:read_write")
  authUrl.searchParams.set("state", expectedState)
  authUrl.searchParams.set("code_challenge", codeChallenge)
  authUrl.searchParams.set("code_challenge_method", "S256")
  authUrl.searchParams.set("prompt", "login")

  return {
    url: authUrl.toString(),
    instructions: "Complete AWS IAM Identity Center sign-in in the browser; this completes automatically.",
    method: "auto",
    async callback() {
      const timer = setTimeout(() => rejectCode(new Error("Timed out waiting for Amazon Quick browser sign-in")), opts.timeoutMs ?? SIGN_IN_TIMEOUT_MS)
      try {
        const { code, state } = await codePromise
        if (!code || state !== expectedState) return { type: "failed", error: "OAuth state mismatch or missing code" }
        const tokRes = await fetchImpl(`${oidcBase}/token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            clientId: regJson.clientId,
            ...(regJson.clientSecret ? { clientSecret: regJson.clientSecret } : {}),
            grantType: "authorization_code",
            code,
            redirectUri,
            codeVerifier,
          }),
        })
        const tok = await tokRes.json().catch(() => ({}))
        if (!tokRes.ok || !tok?.accessToken) {
          return { type: "failed", error: `OIDC token exchange failed: ${tok?.error_description || tok?.message || tokRes.status}` }
        }
        const expiresIn = Number(tok.expiresIn) > 0 ? Number(tok.expiresIn) : 3600
        return {
          ...normalizeAuth({
            access: tok.accessToken,
            refresh: tok.refreshToken || "",
            expires: Date.now() + expiresIn * 1000,
            clientId: regJson.clientId,
            clientSecret: regJson.clientSecret || "",
            issuerUrl,
            tenantUrl,
            region,
            providerType,
            accountId: hostFromUrl(tenantUrl) || "Amazon Quick",
          }),
          type: "success",
        }
      } catch (e) {
        return { type: "failed", error: e?.message ?? String(e) }
      } finally {
        clearTimeout(timer)
        clearTimeout(abandonTimer)
        server.close()
      }
    },
  }
}

/**
 * Discover the Amazon Quick tenant URL from an OIDC access token.
 * Called after a device-code sign-in when no tenantUrl was provided.
 * Tries quick.aws.com endpoints (following redirects) and the OIDC userinfo endpoint.
 */
export async function discoverTenantUrl(a, fetchImpl = fetch) {
  const headers = { Authorization: `Bearer ${a.access}` }
  // 1) quick.aws.com/v1/discovery — may redirect to tenant URL or return tenant info
  try {
    const res = await fetchImpl("https://quick.aws.com/v1/discovery", {
      headers,
      redirect: "follow",
      signal: AbortSignal.timeout(10000),
    })
    const finalUrl = str(res.url)
    if (finalUrl && !finalUrl.startsWith("https://quick.aws.com/")) {
      return normalizeHttpsUrl(finalUrl)
    }
    const body = await res.json().catch(() => ({}))
    const t = str(body?.tenantUrl || body?.tenant_url || body?.tenant)
    if (t) return normalizeHttpsUrl(t)
  } catch {}
  // 2) quick.aws.com/v1/models — may redirect to tenant URL
  try {
    const res = await fetchImpl("https://quick.aws.com/v1/models", {
      headers,
      redirect: "follow",
      signal: AbortSignal.timeout(10000),
    })
    const finalUrl = str(res.url)
    if (finalUrl && !finalUrl.startsWith("https://quick.aws.com/")) {
      return normalizeHttpsUrl(finalUrl)
    }
    const body = await res.json().catch(() => ({}))
    const t = str(body?.tenantUrl || body?.tenant_url || body?.tenant)
    if (t) return normalizeHttpsUrl(t)
  } catch {}
  // 3) OIDC userinfo — may include tenant claims
  if (a.region) {
    try {
      const res = await fetchImpl(`https://oidc.${a.region}.amazonaws.com/userinfo`, {
        headers,
        signal: AbortSignal.timeout(10000),
      })
      if (res.ok) {
        const body = await res.json().catch(() => ({}))
        const t = str(body?.tenantUrl || body?.tenant_url || body?.tenant)
        if (t) return normalizeHttpsUrl(t)
      }
    } catch {}
  }
  return ""
}

/**
 * OAuth 2.0 Device Authorization Grant flow (`urn:ietf:params:oauth:grant-type:device_code`)
 * for VPS, Docker, SSH, and remote web-UI deployments where localhost callbacks cannot reach the server.
 */
export async function deviceCodeSignIn(inputs = {}, opts = {}) {
  const { issuerUrl, tenantUrl: providedTenantUrl, providerType, region } = resolveOidcContext(inputs, opts)
  // tenantUrl 现在可以缺省：OIDC 设备码流程本身只需要 issuerUrl，
  // 拿到 token 后再通过 discoverTenantUrl 自动探测
  const tenantUrl = providedTenantUrl
  const fetchImpl = opts.fetch ?? fetch
  const oidcBase = `https://oidc.${region}.amazonaws.com`

  const regRes = await fetchImpl(`${oidcBase}/client/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      clientName: "Amazon Quick",
      clientType: "public",
      scopes: ["quicksight:read_write"],
      grantTypes: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
      issuerUrl,
    }),
  })
  const regJson = await regRes.json().catch(() => ({}))
  if (!regRes.ok || !regJson?.clientId) {
    throw new Error(`OIDC client registration failed (${regRes.status}): ${regJson?.error_description || regJson?.message || regRes.statusText}`)
  }

  const devRes = await fetchImpl(`${oidcBase}/device_authorization`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      clientId: regJson.clientId,
      ...(regJson.clientSecret ? { clientSecret: regJson.clientSecret } : {}),
      startUrl: issuerUrl,
    }),
  })
  const devJson = await devRes.json().catch(() => ({}))
  const authUrl = str(devJson?.verificationUriComplete || devJson?.verificationUri)
  if (!devRes.ok || !devJson?.deviceCode || !authUrl) {
    throw new Error(`OIDC device authorization failed (${devRes.status}): ${devJson?.error_description || devJson?.message || devRes.statusText}`)
  }

  const userCode = str(devJson.userCode)
  const defaultIntervalMs = Math.max(1000, (Number(devJson.interval) || 2) * 1000)
  const expiresMs = (Number(devJson.expiresIn) > 0 ? Number(devJson.expiresIn) : 600) * 1000

  return {
    url: authUrl,
    instructions: userCode
      ? `Open the link on any device (local PC or phone) and confirm code ${userCode} to sign in — no localhost callback needed.`
      : "Open the link on any device (local PC or phone) to complete AWS sign-in — no localhost callback needed.",
    method: "auto",
    async callback(_code, cbOpts = {}) {
      const signal = cbOpts?.signal ?? opts.signal
      const getNow = typeof opts.now === "function" ? opts.now : () => Date.now()
      const maxWaitMs = Math.min(expiresMs, opts.timeoutMs ?? SIGN_IN_TIMEOUT_MS)
      const deadline = getNow() + maxWaitMs
      let intervalMs = Number(opts.pollIntervalMs) > 0 ? Number(opts.pollIntervalMs) : defaultIntervalMs
      const slowDownStepMs = Number(opts.slowDownStepMs) > 0 ? Number(opts.slowDownStepMs) : 5000
      let netFailures = 0

      while (getNow() < deadline) {
        if (signal?.aborted) return { type: "failed", error: "Amazon Quick device sign-in cancelled" }
        const remaining = deadline - getNow()
        if (remaining <= 0) break
        await sleepAbortable(Math.min(intervalMs, remaining), signal)
        if (signal?.aborted) return { type: "failed", error: "Amazon Quick device sign-in cancelled" }

        let tokRes
        try {
          tokRes = await fetchImpl(`${oidcBase}/token`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              clientId: regJson.clientId,
              ...(regJson.clientSecret ? { clientSecret: regJson.clientSecret } : {}),
              grantType: "urn:ietf:params:oauth:grant-type:device_code",
              deviceCode: devJson.deviceCode,
            }),
            ...(signal ? { signal } : {}),
          })
          netFailures = 0
        } catch (e) {
          if (signal?.aborted) return { type: "failed", error: "Amazon Quick device sign-in cancelled" }
          netFailures++
          if (netFailures >= 3) {
            return { type: "failed", error: `OIDC token poll failed: ${e?.message ?? String(e)}` }
          }
          continue
        }

        const tok = await tokRes.json().catch(() => ({}))
        if (tokRes.ok && tok?.accessToken) {
          const expiresIn = Number(tok.expiresIn) > 0 ? Number(tok.expiresIn) : 3600
          // 如果用户没有提供 tenantUrl，拿到 token 后自动探测
          let resolvedTenantUrl = tenantUrl
          if (!resolvedTenantUrl) {
            resolvedTenantUrl = await discoverTenantUrl(
              { access: tok.accessToken, region },
              fetchImpl,
            )
          }
          if (!resolvedTenantUrl) {
            return {
              type: "failed",
              error:
                "Could not discover Amazon Quick Tenant URL automatically. Please provide it in the Tenant URL field (format: https://qbs-...plato.ai.aws.dev).",
            }
          }
          return {
            ...normalizeAuth({
              access: tok.accessToken,
              refresh: tok.refreshToken || "",
              expires: getNow() + expiresIn * 1000,
              clientId: regJson.clientId,
              clientSecret: regJson.clientSecret || "",
              issuerUrl,
              tenantUrl: resolvedTenantUrl,
              region,
              providerType,
              accountId: hostFromUrl(resolvedTenantUrl) || "Amazon Quick",
            }),
            type: "success",
          }
        }

        const errCode = str(tok?.error || tok?.__type || "")
        if (/authorization_pending|AuthorizationPendingException/i.test(errCode)) continue
        if (/slow_down|SlowDownException/i.test(errCode)) {
          intervalMs = Math.min(intervalMs + slowDownStepMs, 15_000)
          continue
        }
        if (/expired_token|ExpiredTokenException/i.test(errCode)) {
          return { type: "failed", error: "Device authorization expired; please retry sign-in." }
        }
        if (/access_denied|AccessDeniedException/i.test(errCode)) {
          return { type: "failed", error: "Amazon Quick sign-in was denied or cancelled." }
        }
        const msg = str(tok?.error_description || tok?.message) || tokRes.statusText || String(tokRes.status)
        return { type: "failed", error: `OIDC token exchange failed (${errCode || tokRes.status}): ${msg}` }
      }

      return { type: "failed", error: "Timed out waiting for Amazon Quick device sign-in" }
    },
  }
}

// ---- QBS / Gateway HTTP RPC helpers ----

const gatewayCellCache = new Map()

async function resolveGatewayHost(a, fetchImpl) {
  if (gatewayCellCache.has(a.tenantUrl)) return gatewayCellCache.get(a.tenantUrl)
  try {
    const res = await fetchImpl(`${a.tenantUrl}/v1/discovery`, {
      headers: { Authorization: `Bearer ${a.access}` },
      signal: AbortSignal.timeout(10000),
    })
    if (res.ok) {
      const body = await res.json().catch(() => null)
      if (str(body?.cellHost)) {
        gatewayCellCache.set(a.tenantUrl, str(body.cellHost))
        return str(body.cellHost)
      }
    }
  } catch {}
  return hostFromUrl(a.tenantUrl)
}

export function unwrapInvokeAgentBody(rawText) {
  let outer
  try {
    outer = JSON.parse(rawText)
  } catch {
    return null
  }
  let inner =
    outer?.eventResponse?.invokeAgentResponse ??
    outer?.invokeAgentResponse ??
    outer?.result ??
    outer
  if (typeof inner === "string") {
    try {
      inner = JSON.parse(inner)
    } catch {
      return { statusCode: 200, body: inner }
    }
  }
  if (inner && typeof inner === "object" && "body" in inner && typeof inner.body === "string") {
    try {
      return { ...inner, parsedBody: JSON.parse(inner.body) }
    } catch {
      return { ...inner, parsedBody: inner.body }
    }
  }
  return { statusCode: 200, parsedBody: inner }
}

/**
 * Invoke an Amazon Quick agent backend RPC path (such as `profile/usage` or `api/ws-rpc`).
 */
export async function invokeQbsApi(a, path, method = "GET", body = {}, opts = {}) {
  const fetchImpl = opts.fetch ?? fetch
  const cleanPath = String(path || "").replace(/^\/+/, "")
  let url
  let reqBody
  if (isGatewayProvider(a.providerType)) {
    const cellHost = await resolveGatewayHost(a, fetchImpl)
    const acct = encodeURIComponent(a.awsAccountId || "default")
    const qs = new URLSearchParams({ innerPath: cleanPath, _method: method })
    url = `https://${cellHost}/accounts/${acct}/invocations/rpc?${qs.toString()}`
    reqBody = JSON.stringify(body ?? {})
  } else {
    url = `${a.tenantUrl}/integration/quick-work/qbs-event`
    reqBody = JSON.stringify({
      eventType: "invokeAgent",
      eventBody: {
        invokeAgent: {
          path: cleanPath,
          queryParams: { _method: method },
          body: body ?? {},
        },
      },
    })
  }
  const res = await fetchImpl(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${a.access}`,
      "x-amzn-qs-internal-trace-id": randomUUID(),
    },
    body: reqBody,
    signal: opts.signal ?? AbortSignal.timeout(15000),
  })
  const text = await res.text()
  if (res.status === 401 || res.status === 403) {
    const err = new Error(`Amazon Quick rejected authentication (${res.status})`)
    err.status = res.status
    err.invalidToken = res.status === 401
    throw err
  }
  if (!res.ok) {
    const err = new Error(`Amazon Quick API failed (${res.status}): ${text.slice(0, 200)}`)
    err.status = res.status
    throw err
  }
  const unwrapped = unwrapInvokeAgentBody(text)
  const payload = unwrapped?.parsedBody ?? unwrapped
  if (unwrapped?.statusCode >= 400) {
    const err = new Error(`Amazon Quick inner error (${unwrapped.statusCode})`)
    err.status = unwrapped.statusCode
    err.invalidToken = unwrapped.statusCode === 401
    throw err
  }
  return payload
}

const settingsCache = new Map()
const SETTINGS_CACHE_MS = 2 * 60 * 1000

export async function fetchQuickSettings(a, opts = {}) {
  const key = `${a?.tenantUrl || ""}|${a?.awsAccountId || ""}|${a?.accountId || ""}`
  const canCache = opts.noCache !== true && (!opts.fetch || opts.cache === true)
  const now = opts.now ?? Date.now()
  if (canCache) {
    const hit = settingsCache.get(key)
    if (hit && now - hit.at < SETTINGS_CACHE_MS) return hit.value
  }
  const res = await invokeQbsApi(a, "api/ws-rpc", "POST", { type: "get_settings", payload: {} }, opts)
  const frames = Array.isArray(res?.frames) ? res.frames : []
  const settings = frames.find((f) => f?.type === "settings")?.payload ?? res?.payload ?? res ?? null
  if (canCache && settings) {
    settingsCache.set(key, { at: now, value: settings })
    if (settingsCache.size > 32) {
      const oldest = settingsCache.keys().next().value
      if (oldest !== undefined) settingsCache.delete(oldest)
    }
  }
  return settings
}

/**
 * Upload an attachment (`Uint8Array` / `Buffer`) to Amazon Quick (`AIDP` or `Gateway`),
 * poll its DLP scan verdict when required, and deliver it to `threadId` so it can be referenced in `user_message.attachments`.
 */
export async function uploadQuickAttachment(a, file, opts = {}) {
  const fetchImpl = opts.fetch ?? fetch
  const name = str(file?.name) || "attachment.bin"
  const mimeType = str(file?.mimeType).split(";")[0].trim().toLowerCase() || "application/octet-stream"
  const raw = file?.bytes instanceof Uint8Array ? file.bytes : new Uint8Array(file?.bytes || 0)
  if (!raw.byteLength) throw new Error("Cannot upload empty attachment")
  const contentSha256 = createHash("sha256").update(raw).digest("hex")
  const gateway = isGatewayProvider(a.providerType)
  const surface = surfaceTypeForPlatform(opts.platform)

  let attachmentId = ""
  let dlpJobId = ""
  let cellHost = ""

  if (gateway) {
    cellHost = await resolveGatewayHost(a, fetchImpl)
    const acct = encodeURIComponent(a.awsAccountId || "")
    if (!acct) throw new Error("Missing awsAccountId for Gateway attachment upload")
    const qs = new URLSearchParams({
      Operation: "ConversationServiceFileAttachmentProxy",
      awsAccountId: a.awsAccountId,
      name,
      contentLength: String(raw.byteLength),
      contentType: mimeType,
      surfaceType: surface,
    })
    const upRes = await fetchImpl(`https://${cellHost}/uploads/accounts/${acct}/attachments/presigned-url?${qs.toString()}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${a.access}`, "Content-Type": mimeType },
      body: raw,
      signal: opts.signal ?? AbortSignal.timeout(60000),
    })
    const upBody = await upRes.json().catch(() => ({}))
    if (!upRes.ok || !upBody?.attachmentId) {
      const err = new Error(`Gateway attachment upload failed (${upRes.status})`)
      err.status = upRes.status
      err.invalidToken = upRes.status === 401
      throw err
    }
    attachmentId = str(upBody.attachmentId)
    dlpJobId = str(upBody.dlpJobId ?? upBody.DlpJobId)
  } else {
    const qs = new URLSearchParams({
      name,
      contentType: mimeType,
      contentLength: String(raw.byteLength),
    })
    const upRes = await fetchImpl(`${a.tenantUrl}/integration/quick-work/upload-attachment?${qs.toString()}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${a.access}`, "Content-Type": "application/octet-stream" },
      body: raw,
      signal: opts.signal ?? AbortSignal.timeout(60000),
    })
    const upBody = await upRes.json().catch(() => ({}))
    if (!upRes.ok || !upBody?.attachmentId) {
      const err = new Error(`AIDP attachment upload failed (${upRes.status})`)
      err.status = upRes.status
      err.invalidToken = upRes.status === 401
      throw err
    }
    attachmentId = str(upBody.attachmentId)
  }

  const maxPolls = Number(opts.maxDlpPolls) > 0 ? Number(opts.maxDlpPolls) : 15
  const pollMs = Number(opts.dlpPollMs) >= 0 ? Number(opts.dlpPollMs) : 800
  for (let i = 0; i < maxPolls; i++) {
    let dlpRes
    if (gateway) {
      const acct = encodeURIComponent(a.awsAccountId)
      dlpRes = await fetchImpl(`https://${cellHost}/dlp/internal/${acct}/data-loss-prevention/job/describe-user-aware`, {
        method: "POST",
        headers: { Authorization: `Bearer ${a.access}`, "Content-Type": "application/json" },
        body: JSON.stringify(dlpJobId ? { DlpJobId: dlpJobId } : { ClientReferenceId: attachmentId }),
        signal: opts.signal ?? AbortSignal.timeout(15000),
      })
    } else {
      const qs = new URLSearchParams({ attachmentId })
      dlpRes = await fetchImpl(`${a.tenantUrl}/integration/quick-work/attachment-dlp-status?${qs.toString()}`, {
        method: "GET",
        headers: { Authorization: `Bearer ${a.access}` },
        signal: opts.signal ?? AbortSignal.timeout(15000),
      })
    }
    if (dlpRes.ok) {
      const dlp = await dlpRes.json().catch(() => ({}))
      const status = str(dlp.dlpJobStatus ?? dlp.DlpJobStatus).toUpperCase()
      const action = str(dlp.policyAction ?? dlp.PolicyAction).toUpperCase()
      if (status === "COMPLETED" || status === "SKIPPED" || status === "NOT_APPLICABLE") {
        if (action && action !== "ALLOW" && action !== "WARN") {
          throw new Error(`Attachment blocked by DLP policy (${action})`)
        }
        break
      }
      if (status === "FAILED" || status === "ERROR") {
        throw new Error(`Attachment DLP scan failed (${status})`)
      }
    }
    if (i + 1 < maxPolls && pollMs > 0) {
      await new Promise((r) => setTimeout(r, pollMs))
    }
  }

  let deliveredPath = ""
  if (file?.threadId) {
    const delivered = await invokeQbsApi(a, `files/upload/${encodeURIComponent(file.threadId)}`, "POST", { attachmentId }, opts)
    deliveredPath = str(delivered?.path || delivered?.files?.[0]?.path)
  }

  return {
    type: mimeType.startsWith("image/") ? "image" : "file",
    name,
    size: raw.byteLength,
    mimeType,
    path: deliveredPath || name,
    attachmentId,
    contentSha256,
    boundOutOfBand: true,
  }
}

function windowFromQuota(name, q) {
  if (!q || typeof q !== "object") return null
  const limit = Number(q.limit) || 0
  const usedAmount = Number(q.used) || 0
  const percent =
    limit > 0
      ? (100 * usedAmount) / limit
      : Number.isFinite(Number(q.percent))
        ? Number(q.percent)
        : 0
  if (limit <= 0 && !Number.isFinite(Number(q.percent))) return null
  let resetsAt = ""
  if (str(q.resets_at)) {
    const t = Date.parse(q.resets_at)
    if (Number.isFinite(t)) resetsAt = new Date(t).toISOString()
  } else if (Number(q.resume_in_minutes) > 0) {
    resetsAt = new Date(Date.now() + Number(q.resume_in_minutes) * 60000).toISOString()
  }
  const rawLabel = str(q.label)
  const display =
    limit > 0
      ? `${usedAmount} / ${limit}`
      : rawLabel || `${Math.round(percent)}%`
  return {
    name,
    used: Math.max(0, Math.min(100, percent)),
    display,
    ...(limit > 0 ? { amount: usedAmount, limit, unit: "credits" } : {}),
    ...(resetsAt ? { resetsAt } : {}),
  }
}

export function usageFromProfile(raw) {
  const subType = str(raw?.subscription?.subscription_type)
  const planMap = {
    QUICK_LITE_FREE_TRIAL: "Free Trial",
    FREE_TRIAL: "Free Trial",
    FREE: "Free",
    PRO: "Pro",
    ENTERPRISE: "Enterprise",
    TEAM: "Team",
  }
  const plan = planMap[subType.toUpperCase()] || (subType ? subType : "Amazon Quick")
  const windows = []
  const monthly = windowFromQuota("Monthly usage", raw?.monthly)
  if (monthly) windows.push(monthly)
  const session = windowFromQuota("Session usage", raw?.session)
  if (session) windows.push(session)
  const overage = windowFromQuota("Monthly overage", raw?.overage_monthly)
  if (overage && (overage.limit > 0 || overage.used > 0)) windows.push(overage)
  return { plan, windows }
}
