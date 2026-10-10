// shelf-api: the only door to the Shelf database.
// Every request carries Telegram WebApp initData in the X-Telegram-Init-Data header.
// We verify its signature with the bot token, take the Telegram user id from it,
// and run the query with the service role key scoped to that user.
//
// Secrets (Supabase → Edge Functions → Secrets):
//   TELEGRAM_BOT_TOKEN   token from @BotFather
//   ALLOWED_ORIGIN       optional, e.g. https://katherineksk.github.io (defaults to *)
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided by Supabase automatically.

import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const BOT_TOKEN = Deno.env.get("TELEGRAM_BOT_TOKEN") ?? "";
const ALLOWED_ORIGIN = Deno.env.get("ALLOWED_ORIGIN") ?? "*";
const MAX_AGE_SECONDS = 7 * 24 * 60 * 60; // a Mini App can stay open for a long time

const STATUSES = new Set(["want", "reading", "finished", "not_finished"]);

class BadRequest extends Error {}

const cors = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "content-type, x-telegram-init-data, authorization, apikey",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

async function hmac(key: BufferSource, data: string): Promise<ArrayBuffer> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", k, new TextEncoder().encode(data));
}

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
export async function verifyInitData(initData: string, botToken: string, now = Date.now() / 1000): Promise<number | null> {
  if (!initData || !botToken) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash) return null;
  params.delete("hash");
  const dataCheckString = [...params.entries()]
    .map(([k, v]) => `${k}=${v}`)
    .sort()
    .join("\n");
  const secret = await hmac(new TextEncoder().encode("WebAppData"), botToken);
  const expected = toHex(await hmac(secret, dataCheckString));
  if (expected.length !== hash.length) return null;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ hash.charCodeAt(i);
  if (diff !== 0) return null;

  const authDate = Number(params.get("auth_date"));
  if (!Number.isFinite(authDate) || now - authDate > MAX_AGE_SECONDS) return null;
  try {
    const user = JSON.parse(params.get("user") ?? "null");
    return typeof user?.id === "number" ? user.id : null;
  } catch {
    return null;
  }
}

// App field names <-> table columns
function bookFromRow(r: Record<string, unknown>) {
  return {
    id: r.id,
    title: r.title,
    authors: r.authors,
    cover: r.cover,
    coverColor: r.cover_color,
    status: r.status,
    progressPages: r.progress_pages,
    totalPages: r.total_pages,
    volumeId: r.volume_id,
    addedAt: r.added_at,
  };
}

function rowFromBook(b: Record<string, unknown>) {
  const row: Record<string, unknown> = {};
  if ("title" in b) row.title = String(b.title ?? "").slice(0, 500);
  if ("authors" in b) row.authors = String(b.authors ?? "").slice(0, 500);
  if ("cover" in b) row.cover = String(b.cover ?? "").slice(0, 2000);
  if ("coverColor" in b) row.cover_color = b.coverColor == null ? null : String(b.coverColor).slice(0, 32);
  if ("status" in b) {
    if (!STATUSES.has(String(b.status))) throw new BadRequest("bad_status");
    row.status = b.status;
  }
  if ("progressPages" in b) row.progress_pages = Math.max(0, Math.floor(Number(b.progressPages) || 0));
  if ("totalPages" in b) {
    const n = Math.floor(Number(b.totalPages));
    row.total_pages = Number.isFinite(n) && n > 0 ? n : null;
  }
  if ("volumeId" in b) row.volume_id = b.volumeId == null ? null : String(b.volumeId).slice(0, 100);
  if ("addedAt" in b && b.addedAt) row.added_at = String(b.addedAt);
  return row;
}

const ISO_DAY = /^\d{4}-\d{2}-\d{2}$/;

if (import.meta.main) Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  const userId = await verifyInitData(req.headers.get("x-telegram-init-data") ?? "", BOT_TOKEN);
  if (userId == null) return json({ error: "unauthorized" }, 401);

  const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false },
  });

  let body: Record<string, any>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "bad_json" }, 400);
  }

  try {
    switch (body.action) {
      case "load": {
        const [books, logs] = await Promise.all([
          db.from("books").select("*").eq("tg_user_id", userId).order("added_at", { ascending: false }).limit(1000),
          db.from("reading_logs").select("day, amount, unit").eq("tg_user_id", userId),
        ]);
        if (books.error) throw books.error;
        if (logs.error) throw logs.error;
        const logsByDate: Record<string, unknown> = {};
        for (const l of logs.data) logsByDate[l.day] = { amount: l.amount, unit: l.unit };
        return json({ books: books.data.map(bookFromRow), logsByDate });
      }
      case "addBooks": {
        const list = Array.isArray(body.books) ? body.books.slice(0, 500) : [];
        if (!list.length) return json({ books: [] });
        const rows = list.map((b: Record<string, unknown>) => ({ ...rowFromBook(b), tg_user_id: userId }));
        if (rows.some((r: Record<string, unknown>) => !r.title)) return json({ error: "title_required" }, 400);
        const { data, error } = await db.from("books").insert(rows).select("*");
        if (error) throw error;
        return json({ books: data.map(bookFromRow) });
      }
      case "updateBook": {
        const patch = rowFromBook(body.patch ?? {});
        const { error } = await db.from("books").update(patch).eq("id", body.id).eq("tg_user_id", userId);
        if (error) throw error;
        return json({ ok: true });
      }
      case "deleteBook": {
        const { error } = await db.from("books").delete().eq("id", body.id).eq("tg_user_id", userId);
        if (error) throw error;
        return json({ ok: true });
      }
      case "saveLogs": {
        const entries = Object.entries(body.logsByDate ?? {}).filter(([day]) => ISO_DAY.test(day));
        const rows = entries.map(([day, v]: [string, any]) => ({
          tg_user_id: userId,
          day,
          amount: Math.max(0, Math.floor(Number(v?.amount) || 0)),
          unit: v?.unit === "time" ? "time" : "pages",
        }));
        if (!rows.length) return json({ ok: true });
        const { error } = await db.from("reading_logs").upsert(rows);
        if (error) throw error;
        return json({ ok: true });
      }
      default:
        return json({ error: "unknown_action" }, 400);
    }
  } catch (e) {
    if (e instanceof BadRequest) return json({ error: e.message }, 400);
    console.error(e);
    return json({ error: "server_error" }, 500);
  }
});
