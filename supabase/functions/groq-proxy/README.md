# groq-proxy Edge Function

Server-side proxy to Groq so the API key never ships in the extension. Only
authenticated SecTest Pro users can call it (Supabase verifies the JWT; the
handler also requires the `authenticated` role).

## One-time setup

1. **Install the Supabase CLI** (if needed):
   ```bash
   brew install supabase/tap/supabase     # macOS
   supabase --version
   ```

2. **Log in** (opens a browser):
   ```bash
   supabase login
   ```

3. **Get a free Groq API key** at https://console.groq.com → API Keys.

## Deploy (run from the chrome-boiler/ directory)

```bash
# 1. Store the Groq key as a server-side secret (never in the extension)
supabase secrets set GROQ_API_KEY=gsk_your_key_here --project-ref yohvxqjdqbbkrclxyeqd

# 2. Deploy the function (verify_jwt stays ON via config.toml)
supabase functions deploy groq-proxy --project-ref yohvxqjdqbbkrclxyeqd
```

The deployed URL is:
`https://yohvxqjdqbbkrclxyeqd.supabase.co/functions/v1/groq-proxy`
(already set as `EDGE_FN_URL` in `src/config.js`).

## Manual verification

Get a user access token (sign in via the extension, or from the Supabase
dashboard → Authentication → Users → a user → access token), then:

```bash
TOKEN="<a logged-in user's access_token>"
ANON="<your anon public key>"
BASE="https://yohvxqjdqbbkrclxyeqd.supabase.co/functions/v1/groq-proxy"

# Should return { "models": [...] }
curl -s "$BASE/models" -H "apikey: $ANON" -H "Authorization: Bearer $TOKEN"

# Should return { "payload": "...", "explanation": "...", "model": "..." }
curl -s "$BASE" -H "apikey: $ANON" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"context":{"elementType":"input","elementName":"email","testType":"Payload Generation","vulnerability":"XSS"},"model":"llama-3.3-70b-versatile"}'

# Should return 401 (no valid user token)
curl -s -o /dev/null -w "%{http_code}\n" "$BASE/models" -H "apikey: $ANON"
```
