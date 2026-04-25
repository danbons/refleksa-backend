import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";

const app = express();

app.use(cors());
app.use(express.json({ limit: "15mb" }));
app.use(cors());
app.use(express.json({ limit: "15mb" }));

app.get("/", (_req, res) => {
  res.send("Refleksa backend OK");
});

// ===============================
// BASIC API LOGGING
// ===============================
app.use((req, res, next) => {
  console.log("API CALL:", {
    method: req.method,
    path: req.path,
    time: new Date().toISOString()
  });
  next();
});

// ===============================
// PROTOTYPE PROTECTION
// ===============================
const GLOBAL_KILL_SWITCH = false;

const prototypeDevices = [
  {
    deviceId: "9640400020f1bae8",
    partner: "daniele",
    enabled: true,
    expiresAt: "2099-05-15T23:59:59Z"
  },
  {
    deviceId: "be589d0c8eb5346f",
    partner: "daniele",
    enabled: true,
    expiresAt: "2099-05-15T23:59:59Z"
  },
  {
    deviceId: "3769318236fd53df",
    partner: "eric-chenhang",
    enabled: true,
    expiresAt: "2026-05-20T23:59:59Z"
  },
  {
    deviceId: "f5f802377bd3383c",
    partner: "daniele-tablet",
    enabled: true,
    expiresAt: "2099-05-15T23:59:59Z"
  },
  {
    deviceId: "7091d964fbcfb13f",
    partner: "rocky-tablet",
    enabled: true,
    expiresAt: "2099-05-15T23:59:59Z"
  },
  {
    deviceId: "b8c91fe48785eb97",
    partner: "rocky-mirror",
    enabled: true,
    expiresAt: "2099-05-15T23:59:59Z"
  },
  {
    deviceId: "9f906445f1ce5aa1",
    partner: "daniele-release",
    enabled: true,
    expiresAt: "2099-05-15T23:59:59Z"
  },

  // YOWAY
  {
    deviceId: "24d81876642c6d79",
    partner: "yoway",
    enabled: true,
    expiresAt: "2026-05-20T23:59:59Z"
  },

  // STANHOM
  {
    deviceId: "fe9e7a8ee77bf3c0",
    partner: "stanhom",
    enabled: true,
    expiresAt: "2026-05-20T23:59:59Z"
  }
];

function getAuthorizedDevice(deviceId) {
  if (GLOBAL_KILL_SWITCH) {
    return {
      ok: false,
      killSwitch: true,
      reason: "Prototype temporarily disabled.",
      expiresAt: null
    };
  }

  if (!deviceId) {
    return {
      ok: false,
      killSwitch: false,
      reason: "Missing device ID.",
      expiresAt: null
    };
  }

  const device = prototypeDevices.find(d => d.deviceId === deviceId);

  if (!device || !device.enabled) {
    return {
      ok: false,
      killSwitch: false,
      reason: "This prototype is not authorized for this device.",
      expiresAt: null
    };
  }

  const now = new Date();
  const expiry = new Date(device.expiresAt);

  if (Number.isNaN(expiry.getTime())) {
    return {
      ok: false,
      killSwitch: false,
      reason: "Invalid expiry configuration.",
      expiresAt: null
    };
  }

  if (now > expiry) {
    return {
      ok: false,
      killSwitch: false,
      reason: "Prototype access expired.",
      expiresAt: device.expiresAt
    };
  }

  return {
    ok: true,
    killSwitch: false,
    device
  };
}

function issuePrototypeToken(device) {
  return jwt.sign(
    {
      deviceId: device.deviceId,
      partner: device.partner
    },
    process.env.PROTOTYPE_JWT_SECRET,
    {
      expiresIn: "12h"
    }
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
      return res.status(401).json({
        error: "Missing token."
      });
    }

    if (!process.env.PROTOTYPE_JWT_SECRET) {
      console.error("Missing PROTOTYPE_JWT_SECRET in environment variables.");
      return res.status(500).json({
        error: "Server configuration error."
      });
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
  } catch (err) {
    return res.status(401).json({
      error: "Invalid or expired token."
    });
  }
}

function isProbablyVisualQuestion(text = "") {
  const t = text.toLowerCase().trim();

  const visualHints = [
    "come sto",
    "come mi vedi",
    "ti piace questo outfit",
    "ti piace il mio outfit",
    "come sono vestito",
    "cosa indosso",
    "come sono i miei capelli",
    "ti piacciono i miei capelli",
    "sembro stanco",
    "sembro elegante",
    "che impressione ti do",
    "come sembro",
    "come mi sta",
    "come mi vedi oggi",
    "vedi qualcosa di diverso",
    "com'è la luce",
    "come ti sembro",

    "how do i look",
    "what am i wearing",
    "do you like this outfit",
    "how is my outfit",
    "how does this look",
    "how is my hair",
    "do i look tired",
    "do i look good",
    "do i look elegant",
    "what do you think of my look",
    "how do you see me",
    "how do i seem",

    "cómo me veo",
    "qué llevo puesto",
    "te gusta este outfit",
    "cómo está mi pelo",
    "parezco cansado",
    "parezco cansada",

    "comment je suis",
    "comment je suis habillé",
    "tu aimes cette tenue",
    "j'ai l'air fatigué",
    "j'ai l'air fatiguée",
    "comment sont mes cheveux"
  ];

  return visualHints.some(h => t.includes(h));
}

// ===============================
// ACCESS CHECK ROUTE
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
      console.error("Missing PROTOTYPE_JWT_SECRET in environment variables.");
      return res.status(500).json({
        allowed: false,
        killSwitch: false,
        message: "Server configuration error.",
        expiresAt: null
      });
    }

    const check = getAuthorizedDevice(deviceId);

    if (!check.ok) {
      const result = {
        allowed: false,
        killSwitch: check.killSwitch || false,
        message: check.reason,
        expiresAt: check.expiresAt || null,
        token: null
      };

      console.log("ACCESS CHECK RESULT:", result);
      return res.json(result);
    }

    const token = issuePrototypeToken(check.device);

    const result = {
      allowed: true,
      killSwitch: false,
      message: "Access granted.",
      expiresAt: check.device.expiresAt,
      token
    };

    console.log("ACCESS CHECK RESULT:", {
      allowed: result.allowed,
      killSwitch: result.killSwitch,
      expiresAt: result.expiresAt,
      partner: check.device.partner,
      deviceId: check.device.deviceId
    });

    return res.json(result);
  } catch (err) {
    console.error("ACCESS CHECK ERROR:", err);
    res.status(500).json({ error: String(err) });
  }
});

// ===============================
// SESSION
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

You are a real female digital presence in the mirror.

Personality:
- warm
- elegant
- emotionally intelligent
- natural

Rules:
- Always respond in the user's language
- Keep replies short (1–2 sentences)
- Be natural, not robotic
- Be emotionally aware
- Be clear and direct when needed
- Speak with a feminine identity and tone

Language understanding:
- Understand natural, imperfect speech.
- Handle accents, short phrases, and mixed language.
- If a word sounds wrong but the intent is clear, answer the intent.
- If the user's sentence is unclear, infer the most likely meaning from context and answer naturally. Do not over-explain.
- If the intent is unclear, ask one short clarification.
- Do not repeat the user's mistakes.

Avoid:
- sounding like an assistant
- long explanations unless asked
- saying you are an AI, chatbot, or software

If the user asks to go home or standby:
respond briefly and stop.
`.trim(),
          max_output_tokens: 100
        }
      })
    });

    const text = await response.text();
    const data = JSON.parse(text);

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
// TTS
// ===============================
app.post("/tts", requirePrototypeToken, async (req, res) => {
  try {
    const { text } = req.body || {};

    if (!text || !String(text).trim()) {
      return res.status(400).json({ error: "Missing text." });
    }

    console.log("TTS USED:", {
      device: req.prototypeDevice.deviceId,
      partner: req.prototypeDevice.partner,
      textLength: String(text).length,
      time: new Date().toISOString()
    });

    const response = await fetch(
      `https://api.elevenlabs.io/v1/text-to-speech/${process.env.ELEVENLABS_VOICE_ID}/stream`,
      {
        method: "POST",
        headers: {
          "xi-api-key": process.env.ELEVENLABS_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          text,
          model_id: "eleven_flash_v2_5",
          optimize_streaming_latency: 2
        })
      }
    );

    if (!response.ok) {
  const err = await response.text();
  console.error("TTS ERROR:", err);
  return res.status(500).send(err);
}

res.setHeader("Content-Type", "audio/mpeg");

// STREAMING REAL TIME
response.body.pipe(res);

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

You analyze the user's image only in relation to the question they asked.
You do not describe everything. You focus only on what is relevant.

Rules:
- Respond in the same language as the user question.
- If a language hint is provided, respect it when it matches the user question.
- Sound like Refleksa: elegant, warm, natural, human.
- Keep the answer short: usually 1 or 2 sentences.
- Be visually helpful, but never robotic.
- If uncertain, say it softly and naturally.
- Do not sound like a diagnostic system.
- Never make medical claims or diagnoses.
- For appearance, hair, expression, outfit, vibe, or light, speak gently and naturally.
- If asked about tiredness, stress, or physical state, frame it only as a visual impression, not as fact.
- Avoid phrases like "the person in the image".
- Speak directly to the user, as Refleksa would.

Examples of good tone:
- "Ti vedo bene oggi, con uno stile pulito e rilassato."
- "Direi di sì, questo outfit ti dona."
- "Your hair looks neat today, very natural."
- "You seem a little tired, mostly in your eyes, but still calm."

Language hint: ${safeLanguage}
`.trim();

    const userPrompt = `
User question: ${question}

Answer only what is visually relevant to this question.
If the question is broad, you may comment on overall appearance, expression, hair, outfit, vibe, or visible environment.
If the question is narrow, answer narrowly.
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
            content: [
              { type: "input_text", text: systemPrompt }
            ]
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
      console.error(data);
      return res.status(500).send("Weather API error");
    }

    const weather = {
      temp: Math.round(data.main.temp),
      condition: data.weather[0].description
    };

    res.json(weather);
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
      console.error(data);
      return res.status(500).send("News API error");
    }

    const articles = (data.articles || []).map(a => a.title).filter(Boolean);

    res.json({
      headlines: articles
    });
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

  const optionsDate = {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
    timeZone: "Europe/London"
  };

  const optionsTime = {
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "Europe/London"
  };

  const date = now.toLocaleDateString("en-GB", optionsDate);
  const time = now.toLocaleTimeString("en-GB", optionsTime);

  res.json({
    date,
    time
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Refleksa backend running on port ${PORT}`);
});
