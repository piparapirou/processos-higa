// Porteiro de senha do site Processos Higa.
// A senha NAO fica no código: vem do segredo SENHA configurado na Cloudflare
// (Worker > Settings > Variables and Secrets).
const COOKIE = "ph_acesso";
const DIAS = 30;

async function token(senha) {
  const data = new TextEncoder().encode("processos-higa:" + senha);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function lerCookie(req, nome) {
  const c = req.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + nome + "=([^;]+)"));
  return m ? m[1] : null;
}

function telaLogin(msg = "", status = 200) {
  const html = `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Processos Higa · Acesso</title>
<meta name="robots" content="noindex">
<style>
:root{--bg:#f4f6f5;--surface:#fff;--line:#dce2df;--ink:#111614;--muted:#4a5550;--accent:#0e6b5c;--err:#a23b25}
@media (prefers-color-scheme:dark){:root{--bg:#0e1211;--surface:#161b19;--line:#29312e;--ink:#edf2ef;--muted:#b1bbb6;--accent:#43b59f;--err:#ef8a72;color-scheme:dark}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
form{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:28px 24px;width:100%;max-width:340px;display:flex;flex-direction:column;gap:12px}
h1{font-size:1.3rem;margin:0}p{margin:0;color:var(--muted);font-size:.92rem}
input{font:inherit;padding:12px;border:1.5px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)}
input:focus{outline:2px solid var(--accent);outline-offset:1px}
button{font:inherit;font-weight:600;padding:12px;border:0;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;min-height:44px}
.err{color:var(--err);font-size:.9rem}
</style></head><body>
<form method="post" action="/__entrar">
<h1>Processos Higa</h1><p>Digite a senha da equipe para entrar.</p>
<label for="s" style="font-size:.9rem;font-weight:600">Senha</label>
<input id="s" name="senha" type="password" inputmode="numeric" autocomplete="current-password" required autofocus>
${msg ? `<span class="err" role="alert">${msg}</span>` : ""}
<button type="submit">Entrar</button>
</form></body></html>`;
  return new Response(html, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

export default {
  async fetch(req, env) {
    if (!env.SENHA) return new Response("Acesso nao configurado: falta o segredo SENHA na Cloudflare.", { status: 503 });
    const url = new URL(req.url);
    const esperado = await token(env.SENHA);

    if (url.pathname === "/__entrar" && req.method === "POST") {
      const form = await req.formData();
      const senha = String(form.get("senha") || "");
      if ((await token(senha)) !== esperado) {
        await new Promise((r) => setTimeout(r, 800)); // freia tentativas em sequencia
        return telaLogin("Senha incorreta. Tente de novo.", 401);
      }
      return new Response(null, {
        status: 303,
        headers: {
          Location: "/",
          "Set-Cookie": `${COOKIE}=${esperado}; Path=/; Max-Age=${DIAS * 86400}; HttpOnly; Secure; SameSite=Lax`,
        },
      });
    }
    if (url.pathname === "/__sair") {
      return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` } });
    }
    if (lerCookie(req, COOKIE) !== esperado) return telaLogin();
    const res = await env.ASSETS.fetch(req);
    const out = new Response(res.body, res);
    out.headers.set("Cache-Control", "private, no-store");
    return out;
  },
};
