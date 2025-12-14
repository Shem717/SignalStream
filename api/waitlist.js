import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Basic email validation (good enough for waitlists)
function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export default async function handler(req, res) {
  // Only allow POST
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ ok: false, error: "Server not configured" });
  }

  try {
    // Supports either JSON posts or HTML form posts
    const contentType = req.headers["content-type"] || "";
    let body = req.body;

    // If your form sends application/x-www-form-urlencoded, Vercel usually parses it.
    // If not, you can switch your client to JSON (recommended below).
    const email = (body?.email || "").toString().trim();

    // Honeypot field (add a hidden input named "company" in your form)
    const honeypot = (body?.company || "").toString().trim();
    if (honeypot) {
      // Bots often fill hidden fields
      return res.status(200).json({ ok: true });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ ok: false, error: "Invalid email" });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    const referrer = (req.headers["referer"] || "").toString().slice(0, 500);
    const userAgent = (req.headers["user-agent"] || "").toString().slice(0, 500);

    // IP address: Vercel sets x-forwarded-for
    const xff = (req.headers["x-forwarded-for"] || "").toString();
    const ip = xff.split(",")[0]?.trim() || "";
    const ip_hash = ip ? sha256(ip) : null;

    // UTM params can be passed from client if you want (see snippet below)
    const utm_source = (body?.utm_source || "").toString().slice(0, 200) || null;
    const utm_medium = (body?.utm_medium || "").toString().slice(0, 200) || null;
    const utm_campaign = (body?.utm_campaign || "").toString().slice(0, 200) || null;
    const utm_term = (body?.utm_term || "").toString().slice(0, 200) || null;
    const utm_content = (body?.utm_content || "").toString().slice(0, 200) || null;

    // Insert (upsert means repeated signups won't error)
    const { error } = await supabase
      .from("waitlist_signups")
      .upsert(
        {
          email,
          referrer,
          utm_source,
          utm_medium,
          utm_campaign,
          utm_term,
          utm_content,
          ip_hash,
          user_agent: userAgent,
        },
        { onConflict: "email" }
      );

    if (error) {
      return res.status(500).json({ ok: false, error: "Insert failed" });
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "Unexpected error" });
  }
}
