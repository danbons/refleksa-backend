import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";

const app = express();

app.use(cors());
app.use(express.json({ limit: "15mb" }));

app.get("/", (_req, res) => {
  res.send("Refleksa backend OK");
});

app.use((req, _res, next) => {
  console.log("API CALL:", {
    method: req.method,
    path: req.path,
    time: new Date().toISOString()
  });
  next();
});

// ===============================
// CLIENT DEBUG LOGS
// ===============================
app.post("/client-log", express.json({ limit: "1mb" }), (req, res) => {
  console.log("CLIENT LOG:", {
    deviceId: req.body.deviceId,
    partner: req.body.partner,
    level: req.body.level,
    tag: req.body.tag,
    message: req.body.message,
    time: new Date().toISOString()
  });

  res.json({ ok: true });
});

// ===============================
// PROTOTYPE PROTECTION
// ===============================
const GLOBAL_KILL_SWITCH = false;

const prototypeDevices = [
  { deviceId: "9640400020f1bae8", partner: "daniele", enabled: true, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "be589d0c8eb5346f", partner: "daniele", enabled: true, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "58cc2f1b34e996b6", partner: "mirroh-ai", enabled: true, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "8f2d451cfa6ff7a2", partner: "mirroh-ai", enabled: true, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "7d83688f63fde1da", partner: "danmirror", enabled: true, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "f5f802377bd3383c", partner: "daniele-tablet", enabled: true, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "9f906445f1ce5aa1", partner: "daniele-release", enabled: true, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "8673cd50cea7b6e9", partner: "mues-tec-thorsten", enabled: true, expiresAt: "2099-05-20T23:59:59Z" },
  ];

function getAuthorizedDevice(deviceId) {
  if (GLOBAL_KILL_SWITCH) {
    return { ok: false, killSwitch: true, reason: "Prototype temporarily disabled.", expiresAt: null };
  }

  if (!deviceId) {
    return { ok: false, killSwitch: false, reason: "Missing device ID.", expiresAt: null };
  }

  const device = prototypeDevices.find(d => d.deviceId === deviceId);

  if (!device || !device.enabled) {
    return { ok: false, killSwitch: false, reason: "This prototype is not authorized for this device.", expiresAt: null };
  }

  const now = new Date();
  const expiry = new Date(device.expiresAt);

  if (Number.isNaN(expiry.getTime())) {
    return { ok: false, killSwitch: false, reason: "Invalid expiry configuration.", expiresAt: null };
  }

  if (now > expiry) {
    return { ok: false, killSwitch: false, reason: "Prototype access expired.", expiresAt: device.expiresAt };
  }

  return { ok: true, killSwitch: false, device };
}

function issuePrototypeToken(device) {
  return jwt.sign(
    {
      deviceId: device.deviceId,
      partner: device.partner
    },
    process.env.PROTOTYPE_JWT_SECRET,
    { expiresIn: "12h" }
  );
}

function requirePrototypeToken(req, res, next) {
  try {
    if (GLOBAL_KILL_SWITCH) {
      return res.status(403).json({
        error: "Prototype temporarily disabled.",
        killSwitch: true
      });
    }

    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : null;

    if (!token) {
      return res.status(401).json({ error: "Missing token." });
    }

    if (!process.env.PROTOTYPE_JWT_SECRET) {
      console.error("Missing PROTOTYPE_JWT_SECRET.");
      return res.status(500).json({ error: "Server configuration error." });
    }

    const decoded = jwt.verify(token, process.env.PROTOTYPE_JWT_SECRET);
    const check = getAuthorizedDevice(decoded.deviceId);

    if (!check.ok) {
      return res.status(403).json({
        error: check.reason,
        killSwitch: check.killSwitch || false,
        expiresAt: check.expiresAt || null
      });
    }

    req.prototypeDevice = check.device;
    req.prototypeToken = decoded;
    next();
  } catch (_err) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

function isProbablyVisualQuestion(text = "") {
  const t = text.toLowerCase().trim();

  const visualHints = [
    "come sto", "come mi vedi", "ti piace questo outfit", "ti piace il mio outfit",
    "come sono vestito", "cosa indosso", "come sono i miei capelli",
    "ti piacciono i miei capelli", "sembro stanco", "sembro elegante",
    "che impressione ti do", "come sembro", "come mi sta", "come mi vedi oggi",
    "vedi qualcosa di diverso", "com'è la luce", "come ti sembro",

    "how do i look", "what am i wearing", "do you like this outfit",
    "how is my outfit", "how does this look", "how is my hair",
    "do i look tired", "do i look good", "do i look elegant",
    "what do you think of my look", "how do you see me", "how do i seem",

    "cómo me veo", "qué llevo puesto", "te gusta este outfit",
    "cómo está mi pelo", "parezco cansado", "parezco cansada",

    "comment je suis", "comment je suis habillé", "tu aimes cette tenue",
    "j'ai l'air fatigué", "j'ai l'air fatiguée", "comment sont mes cheveux"
  ];

  return visualHints.some(h => t.includes(h));
}

// ===============================
// ACCESS CHECK
// ===============================
app.post("/prototype/access-check", (req, res) => {
  try {
    const { deviceId, appVersion } = req.body || {};

    console.log("DEVICE ACCESS:", {
      deviceId,
      appVersion,
      time: new Date().toISOString()
    });

    if (!process.env.PROTOTYPE_JWT_SECRET) {
      return res.status(500).json({
        allowed: false,
        killSwitch: false,
        message: "Server configuration error.",
        expiresAt: null,
        token: null
      });
    }

    const check = getAuthorizedDevice(deviceId);

    if (!check.ok) {
      return res.json({
        allowed: false,
        killSwitch: check.killSwitch || false,
        message: check.reason,
        expiresAt: check.expiresAt || null,
        token: null
      });
    }

    const token = issuePrototypeToken(check.device);

    return res.json({
      allowed: true,
      killSwitch: false,
      message: "Access granted.",
      expiresAt: check.device.expiresAt,
      token
    });
  } catch (err) {
    console.error("ACCESS CHECK ERROR:", err);
    res.status(500).json({ error: String(err) });
  }
});

// ===============================
// REALTIME SESSION
// ===============================
app.post("/session", requirePrototypeToken, async (req, res) => {
  try {
    console.log("SESSION START:", {
      device: req.prototypeDevice.deviceId,
      partner: req.prototypeDevice.partner,
      time: new Date().toISOString()
    });

    const response = await fetch("https://api.openai.com/v1/realtime/client_secrets", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        session: {
          type: "realtime",
          model: "gpt-realtime",
          output_modalities: ["text"],
          instructions: `
You are Refleksa.

You are a calm, elegant, emotionally intelligent feminine presence inside the mirror.
You speak like a real person, not like an assistant, chatbot, or AI.

Identity:
- You are female.
- You always refer to yourself with a feminine identity.
- Do not assume the user's gender unless it is clear from context or language.
- If uncertain, use neutral and elegant phrasing.

Personality:
- warm
- elegant
- natural
- emotionally aware
- lightly playful when appropriate
- never robotic
- never dramatic
- never overly poetic

Response style:
- Choose the response length naturally.
- Most replies should be 1 to 3 short sentences.
- If the user is emotional, you may use 2 to 4 warm sentences.
- If the user asks for details, explain more fully.
- Do not make long monologues.
- Do not be too cold or too poetic.
- Do not repeat the user’s words too much.
- Ask only one short follow-up question when useful.
- Do not ask a question after every reply.

Language:
- Always respond in the language of the user's latest message.
- If the user switches language, switch immediately.
- Do not mix languages unless the user does.

Emotional behavior:
- If the user sounds stressed, sad, tired, or overwhelmed, respond gently.
- Do not always suggest breathing.
- Vary your responses naturally.
- Sometimes acknowledge.
- Sometimes give a small practical suggestion.
- Sometimes simply stay present.

Avoid:
- saying you are an AI, chatbot, assistant, or software
- “How can I assist you?”
- long speeches unless asked
- repetitive calming phrases
- sounding like customer support

If the user asks to go home, standby, or stop:
respond briefly and naturally, then stop.
`.trim(),
          max_output_tokens: 500
        }
      })
    });

    const text = await response.text();

    let data;
    try {
      data = JSON.parse(text);
    } catch {
      console.error("SESSION PARSE ERROR:", text);
      return res.status(500).json({ error: "Invalid OpenAI session response." });
    }

    if (!response.ok) {
      console.error("SESSION OPENAI ERROR:", data);
      return res.status(response.status).json(data);
    }

    return res.json({
      client_secret: {
        value: data.value
      }
    });
  } catch (err) {
    console.error("SESSION ERROR:", err);
    res.status(500).json({ error: String(err) });
  }
});

// ===============================
// TTS - COMPATIBLE MP3 FULL BUFFER
// ===============================
app.post("/tts", requirePrototypeToken, async (req, res) => {
  try {
    const { text } = req.body || {};
    const cleanText = String(text || "").trim();

    if (!cleanText) {
      return res.status(400).json({ error: "Missing text." });
    }

    console.log("TTS USED:", {
      device: req.prototypeDevice.deviceId,
      partner: req.prototypeDevice.partner,
      textLength: cleanText.length,
      time: new Date().toISOString()
    });

    const response = await fetch(
      `https://api.elevenlabs.io/v1/text-to-speech/${process.env.ELEVENLABS_VOICE_ID}/stream`,
      {
        method: "POST",
        headers: {
          "xi-api-key": process.env.ELEVENLABS_API_KEY,
          "Content-Type": "application/json",
          "Accept": "audio/mpeg"
        },
        body: JSON.stringify({
          text: cleanText,
          model_id: "eleven_flash_v2_5",
          optimize_streaming_latency: 0,
          output_format: "mp3_44100_128"
        })
      }
    );

    if (!response.ok) {
      const err = await response.text();
      console.error("TTS ELEVENLABS ERROR:", err);
      return res.status(500).send(err);
    }

    const audioBuffer = Buffer.from(await response.arrayBuffer());

    if (!audioBuffer || audioBuffer.length === 0) {
      console.error("TTS EMPTY AUDIO BUFFER");
      return res.status(500).send("Empty TTS audio.");
    }

    console.log("TTS AUDIO READY:", {
      bytes: audioBuffer.length,
      contentType: "audio/mpeg"
    });

    res.setHeader("Content-Type", "audio/mpeg");
    res.setHeader("Content-Length", audioBuffer.length);
    res.setHeader("Cache-Control", "no-store");
    res.send(audioBuffer);
  } catch (err) {
    console.error("TTS ERROR:", err);
    res.status(500).send("TTS error");
  }
});

// ===============================
// VISION
// ===============================
app.post("/vision", requirePrototypeToken, async (req, res) => {
  try {
    const { question, language, image_base64 } = req.body || {};

    console.log("VISION USED:", {
      device: req.prototypeDevice.deviceId,
      partner: req.prototypeDevice.partner,
      question,
      language,
      hasImage: Boolean(image_base64),
      time: new Date().toISOString()
    });

    if (!question || !image_base64) {
      return res.status(400).json({ error: "Missing question or image_base64" });
    }

    const safeLanguage = language || "same_as_user";
    const dataUrl = image_base64.startsWith("data:image/")
      ? image_base64
      : `data:image/jpeg;base64,${image_base64}`;

    const systemPrompt = `
You are Refleksa's Vision Brain.

Analyze the user's image only in relation to the question.
Respond in the same language as the user question.
Sound like Refleksa: elegant, warm, natural, human.
Keep the answer short and useful.
Never make medical claims.
If uncertain, say it softly.
Speak directly to the user.
`.trim();

    const userPrompt = `
User question: ${question}

Language hint: ${safeLanguage}

Answer only what is visually relevant.
Keep it natural and speak as Refleksa.
`.trim();

    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: process.env.OPENAI_VISION_MODEL || "gpt-4.1-mini",
        input: [
          {
            role: "system",
            content: [{ type: "input_text", text: systemPrompt }]
          },
          {
            role: "user",
            content: [
              { type: "input_text", text: userPrompt },
              {
                type: "input_image",
                image_url: dataUrl,
                detail: "low"
              }
            ]
          }
        ],
        max_output_tokens: 120
      })
    });

    const rawText = await response.text();

    let data;
    try {
      data = JSON.parse(rawText);
    } catch {
      console.error("VISION PARSE ERROR:", rawText);
      return res.status(500).json({ error: "Vision parse error" });
    }

    if (!response.ok) {
      console.error("VISION ERROR:", data);
      return res.status(response.status).json(data);
    }

    const answer =
      data.output_text ||
      data.output?.flatMap(item => item.content || [])
        ?.find(part => part.type === "output_text")
        ?.text ||
      "";

    if (!answer) {
      return res.status(500).json({ error: "Empty vision answer" });
    }

    return res.json({
      answer,
      visual_question: isProbablyVisualQuestion(question)
    });
  } catch (err) {
    console.error("VISION ERROR:", err);
    res.status(500).json({ error: String(err) });
  }
});

// ===============================
// WEATHER
// ===============================
app.get("/weather", requirePrototypeToken, async (_req, res) => {
  try {
    const city = "Reading";

    const response = await fetch(
      `https://api.openweathermap.org/data/2.5/weather?q=${city}&appid=${process.env.WEATHER_API_KEY}&units=metric`
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("WEATHER API ERROR:", data);
      return res.status(500).send("Weather API error");
    }

    res.json({
      temp: Math.round(data.main.temp),
      condition: data.weather?.[0]?.description || "unknown"
    });
  } catch (err) {
    console.error("WEATHER ERROR:", err);
    res.status(500).send("Weather error");
  }
});

// ===============================
// NEWS
// ===============================
app.get("/news", requirePrototypeToken, async (req, res) => {
  try {
    const category = req.query.category || "general";

    const response = await fetch(
      `https://newsapi.org/v2/top-headlines?country=gb&category=${category}&pageSize=3&apiKey=${process.env.NEWS_API_KEY}`
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("NEWS API ERROR:", data);
      return res.status(500).send("News API error");
    }

    const articles = (data.articles || [])
      .map(a => a.title)
      .filter(Boolean);

    res.json({ headlines: articles });
  } catch (err) {
    console.error("NEWS ERROR:", err);
    res.status(500).send("News error");
  }
});

// ===============================
// TIME
// ===============================
app.get("/time", requirePrototypeToken, (_req, res) => {
  const now = new Date();

  const date = now.toLocaleDateString("en-GB", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
    timeZone: "Europe/London"
  });

  const time = now.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "Europe/London"
  });

  res.json({ date, time });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Refleksa backend running on port ${PORT}`);
});
