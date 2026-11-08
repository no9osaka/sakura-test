// Basic authentication in front of the static assets in ./docs.
// The user name and password come from the BASIC_USER and BASIC_PASS
// variables set on the Worker (as secrets); they are never stored in this repository.

const encoder = new TextEncoder();

function unauthorized() {
  return new Response("Unauthorized", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="sakura-test", charset="UTF-8"',
      "Content-Type": "text/plain; charset=UTF-8",
      "Cache-Control": "no-store",
    },
  });
}

// Compare two strings without returning early on the first differing byte.
function safeEqual(a, b) {
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  }
  return diff === 0;
}

function parseBasicAuth(header) {
  if (!header) return null;
  const [scheme, encoded] = header.split(" ");
  if (!scheme || scheme.toLowerCase() !== "basic" || !encoded) return null;
  let decoded;
  try {
    const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
    decoded = new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
  const sep = decoded.indexOf(":");
  if (sep < 0) return null;
  return { user: decoded.slice(0, sep), pass: decoded.slice(sep + 1) };
}

export default {
  async fetch(request, env) {
    const expectedUser = env.BASIC_USER;
    const expectedPass = env.BASIC_PASS;
    if (!expectedUser || !expectedPass) return unauthorized();

    const creds = parseBasicAuth(request.headers.get("Authorization"));
    if (!creds) return unauthorized();

    const userOk = safeEqual(creds.user, expectedUser);
    const passOk = safeEqual(creds.pass, expectedPass);
    if (!userOk || !passOk) return unauthorized();

    return env.ASSETS.fetch(request);
  },
};
