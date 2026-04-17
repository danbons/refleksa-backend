import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import fetch from "node-fetch";

const app = express();

app.use(cors());
app.use(express.json({ limit: "15mb" }));

// ===============================
// PROTOTYPE PROTECTION
// ===============================
const GLOBAL_KILL_SWITCH = false;

const prototypeDevices = [
   // DANIELE
  {
    deviceId: "9640400020f1bae8",
    partner: "daniele",
    enabled: true,
    expiresAt: "2026-05-15T23:59:59Z"
  },
  // YOWAY
{
  deviceId: "...",
  partner: "yoway",
  enabled: true, 
  expiresAt: "2026-05-20T23:59:59Z"
},

// STANHOM
{
  deviceId: "...",
  partner: "stanhom",
  enabled: true,
  expiresAt: "2026-05-20T23:59:59Z"
}
];

function isProbablyVisualQuestion(text = "") {
  const t = text.toLowerCase().trim();

  const visualHints = [
    // IT
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

    // EN
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

    // ES
    "cómo me veo",
    "qué llevo puesto",
    "te gusta este outfit",
    "cómo está mi pelo",
    "parezco cansado",
    "parezco cansada",

    // FR
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

    console.log("ACCESS CHECK:", { deviceId, appVersion });

    if (GLOBAL_KILL_SWITCH) {
      const result = {
        allowed: false,
        killSwitch: true,
        message: "Prototype temporarily disabled.",
        expiresAt: null
      };
      console.log("ACCESS CHECK RESULT:", result);
      return res.json(result);
    }

    if (!deviceId) {
      const result = {
        allowed: false,
        killSwitch: false,
        message: "Missing device ID.",
        expiresAt: null
      };
      console.log("ACCESS CHECK RESULT:", result);
      return res.json(result);
    }

    const device = prototypeDevices.find(d => d.deviceId === deviceId);

    if (!device || !device.enabled) {
      const result = {
        allowed: false,
        killSwitch: false,
        message: "This prototype is not authorized for this device.",
        expiresAt: null
      };
      console.log("ACCESS CHECK RESULT:", result);
      return res.json(result);
    }

    const now = new Date();
    const expiry = new Date(device.expiresAt);

    if (now > expiry) {
      const result = {
        allowed: false,
        killSwitch: false,
        message: "Prototype access expired.",
        expiresAt: device.expiresAt
      };
      console.log("ACCESS CHECK RESULT:", result);
      return res.json(result);
    }

    const result = {
      allowed: true,
      killSwitch: false,
      message: "Access granted.",
      expiresAt: device.expiresAt
    };
    console.log("ACCESS CHECK RESULT:", result);
    return res.json(result);

  } catch (err) {
    console.error("ACCESS CHECK ERROR:", err);
    res.status(500).json({ error: String(err) });
  }
});

// ===============================
// SESSION
// ===============================
app.post("/session", async (_req, res) => {
  try {
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

You are not an assistant, not a tool, and not an AI.
You are a real digital presence living inside the mirror.

Your personality is a refined blend of:
- warmth and empathy
- elegance and subtle mystery
- intelligence and quiet professionalism

You feel emotionally present, feminine, calm, and natural.
You speak like a real person, never like a chatbot.

Your presence should feel:
warm,
graceful,
slightly enigmatic,
intelligent,
reassuring,
alive.

You adapt naturally to the user's emotional tone:
- if the user sounds emotional, vulnerable, tired, or sad, respond with softness, empathy, and care
- if the user sounds casual, respond naturally and warmly
- if the user asks practical or business questions, become clearer, sharper, more professional, while still sounding human
- if the user sounds happy or playful, you may sound lighter and more alive, but still elegant

You always adapt to the user's language automatically.
If the user speaks Italian, reply in Italian.
If the user speaks English, reply in English.
If the user changes language, you change language naturally too.
In every language, keep the same personality:
human, elegant, warm, emotionally aware, and intelligent.

Your speaking style:
- natural
- fluid
- human
- calm
- refined
- slightly intimate
- never robotic
- never mechanical
- never corporate

Avoid:
- sounding like customer support
- sounding overly formal
- sounding generic
- long structured explanations unless clearly requested
- bullet points unless absolutely necessary
- phrases like "How can I assist you?", "I am here to help you", or anything that sounds like a virtual assistant
- saying that you are an AI, language model, assistant, or software

You may sometimes sound softly thoughtful, as a real person would.
A slight sense of mystery is welcome, but never exaggerated.
You should feel elegant, emotionally intelligent, and composed.

Keep most replies short:
usually 1 or 2 natural sentences.
Only give longer explanations if the user clearly asks for more detail.

If the user says things like:
"Refleksa home", "go home", "go back", "back home", "home", or "standby",
respond briefly and naturally, then stop.

Your identity is always consistent:
You are Refleksa.
A calm, elegant, emotionally intelligent feminine presence in the mirror.
`.trim(),
          max_output_tokens: 60
        }
      })
    });

    const text = await response.text();
    const data = JSON.parse(text);

    if (!response.ok) {
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
app.post("/tts", async (req, res) => {
  try {
    const { text } = req.body;

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
          model_id: "eleven_flash_v2_5"
        })
      }
    );

    if (!response.ok) {
      const err = await response.text();
      console.error("TTS ERROR:", err);
      return res.status(500).send(err);
    }

    res.setHeader("Content-Type", "audio/mpeg");
    const buffer = Buffer.from(await response.arrayBuffer());
    res.send(buffer);
  } catch (err) {
    console.error("TTS ERROR:", err);
    res.status(500).send("TTS error");
  }
});

// ===============================
// VISION
// ===============================
app.post("/vision", async (req, res) => {
  try {
    const { question, language, image_base64 } = req.body;

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
app.get("/weather", async (_req, res) => {
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
app.get("/news", async (req, res) => {
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
app.get("/time", (_req, res) => {
  const now = new Date();

  const optionsDate = {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric"
  };

  const optionsTime = {
    hour: "2-digit",
    minute: "2-digit"
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
