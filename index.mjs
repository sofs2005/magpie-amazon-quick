import {
  browserSignIn,
  currentAuth,
  desktopSignIn,
  deviceCodeSignIn,
  fetchQuickSettings,
  IMPORT_FROM,
  importSignIns,
  invokeQbsApi,
  REFRESH_LEAD_MS,
  refreshHook,
  reissuedAuth,
  usageFromProfile,
} from "./credentials.mjs"
import { configModels, DEFAULT_API_URL, executeSncsChat, modelsFromSettings } from "./bridge.mjs"

export const PROVIDER_ID = "amazon-quick"
export const PROVIDER_NAME = "Amazon Quick"
export const NPM_PACKAGE = "@ai-sdk/openai-compatible"
const SESSION_HEADER = "x-amazon-quick-session"

function decodeBodyText(body) {
  if (typeof body === "string") return body
  if (body instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(body))
  if (ArrayBuffer.isView(body)) return new TextDecoder().decode(body)
  return ""
}

function signedOutResponse(a, why, expired, note = "") {
  const hint =
    a?.source === "desktop"
      ? "Sign in to Amazon Quick desktop again (or open it so it refreshes its session); magpie reads its sign-in on the next request."
      : "Sign in to Amazon Quick again in Magpie: Providers → Amazon Quick → Sign in again."
  const message = `${PROVIDER_NAME} refused this account's sign-in (401)${why ? `; ${why}` : ""}. ${note ? note + " " : ""}${hint}`
  return new Response(JSON.stringify({ error: { message, type: "authentication_error", code: 401 } }), {
    status: 401,
    statusText: "Unauthorized",
    headers: {
      "content-type": "application/json",
      "X-Magpie-Sign-In": expired ? "expired" : "kept",
    },
  })
}

function withSignInHeader(res, value) {
  const headers = new Headers(res.headers)
  headers.set("X-Magpie-Sign-In", value)
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers,
  })
}

function isGone(a, reissued, tokenRefused) {
  return (
    a?.source !== "desktop" &&
    (reissued?.kind === "refresh refused" || (reissued?.kind === "nothing to renew with" && !!tokenRefused))
  )
}

function refusedReason(a, why) {
  const hint =
    a?.source === "desktop"
      ? "Open or sign in to Amazon Quick desktop again."
      : "Sign in to Amazon Quick again."
  return `${PROVIDER_NAME} refused this sign-in (401)${why ? `; ${why}` : ""}. ${hint}`
}

/**
 * Factory for the Amazon Quick OpenCode / Magpie plugin, supporting dependency injection for unit tests.
 * @param {object} [deps]
 */
export function createAmazonQuickPlugin(deps = {}) {
  const runDesktopSignIn = deps.desktopSignIn ?? desktopSignIn
  const runBrowserSignIn = deps.browserSignIn ?? browserSignIn
  const runDeviceCodeSignIn = deps.deviceCodeSignIn ?? deviceCodeSignIn
  const runImportSignIns = deps.importSignIns ?? importSignIns
  const getCurrentAuth = deps.currentAuth ?? currentAuth
  const getReissuedAuth = deps.reissuedAuth ?? reissuedAuth
  const runRefreshHook = deps.refreshHook ?? refreshHook
  const runInvokeQbsApi = deps.invokeQbsApi ?? invokeQbsApi
  const runFetchQuickSettings = deps.fetchQuickSettings ?? fetchQuickSettings
  const runExecuteSncsChat = deps.executeSncsChat ?? executeSncsChat

  return async function AmazonQuickAuthPlugin(ctx = {}) {
    const client = ctx?.client
    return {
      config: async (config) => {
        config.provider ??= {}
        config.provider[PROVIDER_ID] ??= {}
        const p = config.provider[PROVIDER_ID]
        p.name ??= PROVIDER_NAME
        p.npm ??= NPM_PACKAGE
        if (!p.api) p.api = DEFAULT_API_URL
        p.models = { ...configModels(PROVIDER_ID, p.api), ...(p.models ?? {}) }
      },
      "chat.headers": async (input, output) => {
        const id = input?.model?.providerID ?? input?.provider?.info?.id
        if (id !== PROVIDER_ID || !input?.sessionID) return
        output.headers[SESSION_HEADER] = String(input.sessionID).slice(0, 128)
      },
      provider: {
        id: PROVIDER_ID,
        async models(provider, { auth } = {}) {
          const fallbackUrl = provider?.api || DEFAULT_API_URL
          const base = provider?.models && Object.keys(provider.models).length ? provider.models : configModels(PROVIDER_ID, fallbackUrl)
          if (auth?.type !== "oauth" || !(auth.access || auth.source)) return base
          try {
            const a = await getCurrentAuth(client, auth, deps)
            const url = a?.tenantUrl || fallbackUrl
            const settings = await runFetchQuickSettings(a, deps)
            return settings ? modelsFromSettings(PROVIDER_ID, settings, url) : base
          } catch {
            return base
          }
        },
      },
      auth: {
        provider: PROVIDER_ID,
        refreshLead: REFRESH_LEAD_MS,
        rotating: true,
        refresh: (auth) => runRefreshHook(auth, deps),
        async usage(getAuth) {
          const auth = await getAuth()
          if (auth?.type !== "oauth" || !(auth.access || auth.source)) {
            return { error: "not signed in", signIn: "kept" }
          }
          let signInState = "kept"
          try {
            let a = await getCurrentAuth(client, auth, deps)
            let raw
            try {
              raw = await runInvokeQbsApi(a, "profile/usage", "GET", {}, deps)
            } catch (e) {
              if (e?.status !== 401) throw e
              const r = await getReissuedAuth(client, getAuth, a, auth.access, deps)
              if (!r.a) {
                return { error: refusedReason(a, r.why), signIn: isGone(a, r, e.invalidToken) ? "expired" : "kept" }
              }
              a = r.a
              try {
                raw = await runInvokeQbsApi(a, "profile/usage", "GET", {}, deps)
              } catch (e2) {
                if (e2?.status !== 401) throw e2
                return {
                  error: refusedReason(a, "it refused the renewed token too"),
                  signIn: a.source !== "desktop" && e2.invalidToken ? "expired" : "kept",
                }
              }
              signInState = "renewed"
            }
            return { ...usageFromProfile(raw), signIn: signInState }
          } catch (e) {
            return { error: e?.message ?? String(e), signIn: "kept" }
          }
        },
        importFrom: IMPORT_FROM.en,
        importFroms: IMPORT_FROM.froms,
        import: (texts) => runImportSignIns(Array.isArray(texts) ? texts : [texts], deps),
        methods: [
          {
            type: "oauth",
            label: `${PROVIDER_NAME} 浏览器登录（推荐）`,
            authorize: () => runBrowserSignIn({}, deps),
          },
          {
            type: "oauth",
            label:
              (deps.platform ?? process.platform) === "darwin"
                ? `复用 ${PROVIDER_NAME} 桌面端登录（macOS 需钥匙串密码）`
                : `复用 ${PROVIDER_NAME} 桌面端登录`,
            authorize: async () => runDesktopSignIn(deps),
          },
          {
            type: "oauth",
            label: `${PROVIDER_NAME} 设备码登录（VPS / 远程网页端推荐）`,
            prompts: [
              {
                type: "text",
                key: "tenantUrl",
                message: "Amazon Quick Tenant URL（留空则自动探测；也可从 ~/.quickwork/profiles.json 复制 tenant_url）",
                placeholder: "https://qbs-...dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
                required: false,
              },
              {
                type: "text",
                key: "issuerUrl",
                message: "AWS IAM Identity Center Issuer URL（从 ~/.quickwork/profiles.json 复制 issuer_url；留空使用默认值）",
                placeholder: "https://identitycenter.amazonaws.com/ssoins-...",
                required: false,
              },
            ],
            authorize: (inputs) => runDeviceCodeSignIn(inputs, deps),
          },
          {
            type: "oauth",
            label: `${PROVIDER_NAME} 企业版 / 自定义 OIDC（浏览器）`,
            prompts: [
              {
                type: "text",
                key: "issuerUrl",
                message: "AWS IAM Identity Center Issuer URL（留空使用默认 Social SSO）",
                placeholder: "https://identitycenter.amazonaws.com/ssoins-...",
                required: false,
              },
              {
                type: "text",
                key: "tenantUrl",
                message: "Amazon Quick Tenant URL（例如 https://qbs-....dp.appintegrations.us-east-1.prod.plato.ai.aws.dev）",
                placeholder: "https://qbs-...plato.ai.aws.dev",
              },
            ],
            authorize: (inputs) => runBrowserSignIn(inputs, deps),
          },
        ],
        async loader(getAuth) {
          const auth = await getAuth()
          if (auth?.type !== "oauth") return {}
          let resolvedBaseUrl = auth?.tenantUrl || DEFAULT_API_URL
          if (!auth?.tenantUrl && auth?.source === "desktop") {
            try {
              const a = await getCurrentAuth(client, auth, deps)
              if (a?.tenantUrl) resolvedBaseUrl = a.tenantUrl
            } catch {}
          }
          return {
            baseURL: resolvedBaseUrl,
            apiKey: "",
            async fetch(input, init) {
              const req = input instanceof Request ? input : null
              const urlStr = req ? req.url : String(input || "")
              if (/\/models(?:$|\?)/.test(urlStr)) {
                const list = Object.values(configModels(PROVIDER_ID, resolvedBaseUrl)).map((m) => ({
                  id: m.id,
                  object: "model",
                  owned_by: "amazon-quick",
                }))
                return new Response(JSON.stringify({ object: "list", data: list }), {
                  status: 200,
                  headers: { "content-type": "application/json" },
                })
              }
              const stored = await getAuth()
              if (stored?.type !== "oauth" || !(stored.access || stored.source)) {
                throw new Error(`${PROVIDER_NAME} isn't signed in`)
              }
              let a
              try {
                a = await getCurrentAuth(client, stored, deps)
              } catch (e) {
                if (e?.refreshRefused) {
                  return signedOutResponse(stored, e.message, stored.source !== "desktop")
                }
                throw e
              }
              let renewed = !!(stored.access && a.access !== stored.access)
              let bodyRaw = init?.body
              if (bodyRaw === undefined && req) bodyRaw = await req.clone().text()
              const bodyText = decodeBodyText(bodyRaw)
              let body = {}
              try {
                body = bodyText ? JSON.parse(bodyText) : {}
              } catch {
                return new Response(JSON.stringify({ error: { message: "Invalid JSON request body", type: "invalid_request_error" } }), {
                  status: 400,
                  headers: { "content-type": "application/json" },
                })
              }

              const headers = new Headers(init?.headers ?? req?.headers)
              const sessionId = headers.get(SESSION_HEADER) || ""
              const signal = init?.signal ?? req?.signal

              try {
                const res = await runExecuteSncsChat(a, body, { ...deps, sessionId, signal })
                return withSignInHeader(res, renewed ? "renewed" : "kept")
              } catch (err) {
                if (err?.status !== 401) {
                  const status = Number(err?.status) >= 400 && Number(err?.status) < 600 ? Number(err.status) : 502
                  return new Response(
                    JSON.stringify({ error: { message: err?.message ?? String(err), type: "upstream_error", code: status } }),
                    { status, headers: { "content-type": "application/json" } },
                  )
                }
                const r = await getReissuedAuth(client, getAuth, a, stored.access, deps)
                if (!r.a) return signedOutResponse(a, r.why, isGone(a, r, err.invalidToken))
                a = r.a
                try {
                  const res2 = await runExecuteSncsChat(a, body, { ...deps, sessionId, signal })
                  return withSignInHeader(res2, "renewed")
                } catch (err2) {
                  if (err2?.status === 401) {
                    return signedOutResponse(
                      a,
                      "it refused the renewed token too",
                      a.source !== "desktop" && !!err2.invalidToken,
                    )
                  }
                  const status = Number(err2?.status) >= 400 && Number(err2?.status) < 600 ? Number(err2.status) : 502
                  return new Response(
                    JSON.stringify({ error: { message: err2?.message ?? String(err2), type: "upstream_error", code: status } }),
                    { status, headers: { "content-type": "application/json" } },
                  )
                }
              }
            },
          }
        },
      },
    }
  }
}

export const AmazonQuickAuthPlugin = createAmazonQuickPlugin()
export default AmazonQuickAuthPlugin
