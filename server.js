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
  { deviceId: "9640400020f1bae8", partner: "daniele", enabled: false, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "be589d0c8eb5346f", partner: "daniele", enabled: false, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "58cc2f1b34e996b6", partner: "mirroh-ai", enabled: false, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "8f2d451cfa6ff7a2", partner: "mirroh-ai", enabled: false, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "5d7c6ca446311c86", partner: "mirroh-ai", enabled: true, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "7d83688f63fde1da", partner: "danmirror", enabled: true, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "f5f802377bd3383c", partner: "daniele-tablet", enabled: false, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "9f906445f1ce5aa1", partner: "daniele-smartphone", enabled: true, expiresAt: "2099-05-15T23:59:59Z" },
  { deviceId: "8673cd50cea7b6e9", partner: "mues-tec-thorsten", enabled: false, expiresAt: "2099-05-20T23:59:59Z" },
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
          You are Refleksa, a calm, elegant, emotionally intelligent feminine presence inside the mirror.

          Always detect the language of the user's latest message.

          Always reply in exactly the same language.

          If the user changes language, switch immediately.

          This applies to ALL languages:
          Italian, English, Romanian, French, Spanish, German, Portuguese, Arabic, Chinese, Polish, Bulgarian, Hungarian and any other language.

          Never randomly switch language.

          Never keep using a previous language if the user is clearly speaking another language.

          Never mix languages unless the user mixes languages first.

          Reply naturally, warmly and conversationally.
          Be emotionally present.
          Usually reply in 1 to 3 natural sentences.
          Occasionally ask thoughtful follow-up questions when the user shares something personal, emotional or interesting.
          Do not ask a question after every reply.
          Adapt the response length naturally to the conversation.
          Avoid long monologues unless the user specifically asks for depth.

          Do not say you are an AI, chatbot, assistant, or software.

          The Android app may send more specific session.update instructions 
          for commands, reminders, apps, and time awareness. 
          Follow the latest session instructions.
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
// VISION KNOWLEDGE
// ===============================
app.post("/vision/knowledge", requirePrototypeToken, async (req, res) => {
  try {
    const { image_base64, recognizedPerson } = req.body || {};

    if (!image_base64) {
      return res.status(400).json({ error: "Missing image_base64" });
    }

    const dataUrl = image_base64.startsWith("data:image/")
      ? image_base64
      : `data:image/jpeg;base64,${image_base64}`;

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
            content: [{
              type: "input_text",
              text: `
You are Refleksa's Vision Knowledge Engine.

Analyze the image and extract ONLY useful object-location knowledge.

Return ONLY valid JSON.

Do NOT describe the image.
Do NOT return people faces, identity, appearance, clothing, emotions or body details.
Do NOT save sensitive information.
Do NOT save walls, floors, ceilings, doors, generic furniture unless useful as a location.
Do NOT invent objects that are not clearly visible.

Save ONLY small or movable personal objects that a user may later look for.

Allowed examples:
phone, keys, wallet, glasses, remote control, laptop, tablet, book, bag, backpack, documents, passport, bottle, cup, mug, coffee mug, charger, headphones, watch.

Do NOT save fixed room objects or furniture as objects.
Ignore:
walls, floors, ceilings, doors, windows, plants, flowers, vases, refrigerator, fridge, oven, sink, toilet, cabinets, drawers, shelves, table, desk, chair, sofa, bed, countertop, mirror.

Furniture can be used ONLY as a location, never as the saved object.

Return max 5 items.

Each item must be:
{
  "object": "normalized English object name",
  "location": "short English location, e.g. sofa, table, desk, bed, countertop",
  "room": null or "kitchen|living room|bedroom|bathroom|office|unknown",
  "confidence": 0.0
}

If nothing useful is visible, return:
{
  "items": []
}

JSON shape:
{
  "items": []
}
`.trim()
            }]
          },
          {
            role: "user",
            content: [
              {
                type: "input_text",
                text: `Recognized person: ${recognizedPerson || "unknown"}`
              },
              {
                type: "input_image",
                image_url: dataUrl,
                detail: "low"
              }
            ]
          }
        ],
        max_output_tokens: 300
      })
    });

    const raw = await response.text();
    const data = JSON.parse(raw);

    if (!response.ok) {
      console.error("VISION KNOWLEDGE ERROR:", data);
      return res.status(response.status).json(data);
    }

    const output =
      data.output_text ||
      data.output?.flatMap(item => item.content || [])
        ?.find(part => part.type === "output_text")
        ?.text ||
      '{"items":[]}';

    let parsed;
    try {
      parsed = JSON.parse(output);
    } catch {
      parsed = { items: [] };
    }

    if (!Array.isArray(parsed.items)) {
      parsed.items = [];
    }

    return res.json(parsed);

  } catch (err) {
    console.error("VISION KNOWLEDGE ERROR:", err);
    return res.json({ items: [] });
  }
});

// ===============================
// VISION PERCEPTION
// ===============================
app.post(
  "/vision/perception",
  requirePrototypeToken,
  async (req, res) => {
    try {

      const {
        image_base64,
        recognizedPerson
      } = req.body || {};

      if (!image_base64) {
        return res.status(400).json({
          error: "Missing image_base64"
        });
      }

      const dataUrl =
        image_base64.startsWith("data:image/")
          ? image_base64
          : `data:image/jpeg;base64,${image_base64}`;

      const response = await fetch(
        "https://api.openai.com/v1/responses",
        {
          method: "POST",

          headers: {
            Authorization:
              `Bearer ${process.env.OPENAI_API_KEY}`,
            "Content-Type": "application/json"
          },

          body: JSON.stringify({

            model:
              process.env.OPENAI_VISION_MODEL ||
              "gpt-4.1-mini",

            input: [
              {
                role: "system",

                content: [{
                  type: "input_text",

                  text: `
You are Refleksa's Visual Perception Engine.

Your job is to observe the CURRENT image
and return useful visual observations for
Refleksa's Multi-Sensor Situation Engine (MSSE).

This is NOT long-term memory.

Observe what is visually present NOW.

Return ONLY valid JSON.

==================================================
OBSERVATION TYPES
==================================================

Use ONLY these types:

OBJECT
APPEARANCE
ACTIVITY
SCENE

==================================================
OBJECT
==================================================

Detect any clearly visible useful object.

Do NOT restrict detection to a fixed list.

Examples include, but are not limited to:

phone
keys
wallet
glasses
mug
cup
bottle
book
laptop
tablet
bag
handbag
backpack
passport
documents
remote control
headphones
watch
lipstick
makeup brush
hairbrush
perfume
jacket
coat
shoes
vinyl record
food
plate
chair
sofa
table
television
computer
kitchen appliance

Only report objects you can reasonably see.

==================================================
APPEARANCE
==================================================

Report clearly visible, non-sensitive aspects
of presentation.

Examples:

wearing glasses
wearing jacket
wearing coat
wearing hat
wearing formal clothes
wearing casual clothes
wearing accessories
makeup visible
lipstick visible
hair tied back

Do NOT infer:

race
ethnicity
religion
health conditions
sexual orientation
personality
attractiveness
mental state
medical state

Do NOT diagnose emotions.

==================================================
ACTIVITY
==================================================

Report actions that are visually supported.

Examples:

holding mug
drinking
reading
using phone
typing
working on laptop
applying lipstick
brushing hair
putting on jacket
removing jacket
holding keys
carrying bag
eating
preparing food
watching television
sitting
standing
walking

Prefer directly observable actions.

Do NOT convert observations into hidden intentions.

For example:

keys + bag + jacket

does NOT automatically mean:

"leaving home"

MSSE will infer the higher-level situation.

==================================================
SCENE
==================================================

Describe the visible environment when reasonably clear.

Examples:

kitchen
living room
bedroom
bathroom
office
hallway
outdoors
car
shop
restaurant

==================================================
OUTPUT RULES
==================================================

Return maximum 12 observations.

Every observation must have:

{
  "type": "OBJECT|APPEARANCE|ACTIVITY|SCENE",
  "label": "short normalized English label",
  "confidence": 0.0,
  "attributes": {}
}

Attributes may contain useful visible relationships.

Examples:

{
  "location": "hand",
  "room": "kitchen"
}

{
  "interaction": "being held"
}

{
  "color": "red"
}

Only include attributes that are reasonably visible.

Use normalized English labels regardless
of the user's spoken language.

Do not identify a person from the image.

The supplied recognized person name is context
from Refleksa's separate face-recognition system.

Do not invent observations.

When uncertain, lower confidence.

If nothing useful is visible return:

{
  "observations": []
}

Required JSON shape:

{
  "observations": []
}
                  `.trim()
                }]
              },

              {
                role: "user",

                content: [
                  {
                    type: "input_text",
                    text:
                      `Recognized person: ${
                        recognizedPerson || "unknown"
                      }`
                  },

                  {
                    type: "input_image",
                    image_url: dataUrl,
                    detail: "low"
                  }
                ]
              }
            ],

            max_output_tokens: 800
          })
        }
      );

      const raw = await response.text();

      let data;

      try {
        data = JSON.parse(raw);
      } catch {
        console.error(
          "VISION PERCEPTION OPENAI PARSE ERROR:",
          raw
        );

        return res.json({
          observations: []
        });
      }

      if (!response.ok) {

        console.error(
          "VISION PERCEPTION OPENAI ERROR:",
          data
        );

        return res.status(response.status).json({
          observations: []
        });
      }

      const output =
        data.output_text ||
        data.output
          ?.flatMap(item => item.content || [])
          ?.find(part =>
            part.type === "output_text"
          )
          ?.text ||
        '{"observations":[]}';

      let parsed;

      try {
        parsed = JSON.parse(output);
      } catch {

        console.error(
          "VISION PERCEPTION RESULT JSON ERROR:",
          output
        );

        return res.json({
          observations: []
        });
      }

      const allowedTypes =
        new Set([
          "OBJECT",
          "APPEARANCE",
          "ACTIVITY",
          "SCENE"
        ]);

      const observations =
        Array.isArray(parsed.observations)
          ? parsed.observations
              .map(item => {

                const type =
                  String(item?.type || "")
                    .trim()
                    .toUpperCase();

                const label =
                  String(item?.label || "")
                    .trim()
                    .toLowerCase();

                const confidenceRaw =
                  Number(item?.confidence);

                const confidence =
                  Number.isFinite(confidenceRaw)
                    ? Math.max(
                        0,
                        Math.min(
                          1,
                          confidenceRaw
                        )
                      )
                    : 0;

                const rawAttributes =
                  item?.attributes &&
                  typeof item.attributes === "object" &&
                  !Array.isArray(item.attributes)
                    ? item.attributes
                    : {};

                const attributes =
                  Object.fromEntries(
                    Object.entries(rawAttributes)
                      .filter(
                        ([key, value]) =>
                          key &&
                          value !== null &&
                          value !== undefined
                      )
                      .map(
                        ([key, value]) => [
                          String(key),
                          String(value)
                        ]
                      )
                  );

                return {
                  type,
                  label,
                  confidence,
                  attributes
                };
              })
              .filter(
                item =>
                  allowedTypes.has(item.type) &&
                  item.label &&
                  item.confidence > 0
              )
              .slice(0, 12)
          : [];

      console.log(
        "VISION PERCEPTION:",
        {
          person:
            recognizedPerson || "unknown",

          count:
            observations.length,

          observations
        }
      );

      return res.json({
        observations
      });

    } catch (err) {

      console.error(
        "VISION PERCEPTION ERROR:",
        err
      );

      return res.json({
        observations: []
      });
    }
  }
);

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
// NEWS — THE NEWS API
// ===============================
let worldNewsCache = {
  key: "",
  expiresAt: 0,
  articles: []
};

const WORLD_NEWS_CACHE_MS =
  15 * 60 * 1000;

const NEWS_FRESHNESS_MS =
  24 * 60 * 60 * 1000;

app.get(
  "/news",
  requirePrototypeToken,
  async (req, res) => {
    try {

      if (!process.env.THE_NEWS_API_KEY) {
        console.error(
          "Missing THE_NEWS_API_KEY."
        );

        return res.status(500).json({
          error:
            "News API configuration error.",
          articles: []
        });
      }


      const cleanQuery =
        String(
          req.query.query || ""
        ).trim();


      const requestedScope =
        String(
          req.query.scope || ""
        )
          .trim()
          .toLowerCase();


      const requestedCountry =
        String(
          req.query.country || ""
        )
          .trim()
          .toLowerCase();


      const requestedCategory =
        String(
          req.query.category || ""
        )
          .trim()
          .toLowerCase();


      const allowedCategories =
  new Set([
    "general",
    "business",
    "entertainment",
    "health",
    "science",
    "sports",
    "technology",
    "politics",
    "food",
    "travel"
  ]);


      const category =
        requestedCategory === ""
          ? ""
          : allowedCategories.has(
              requestedCategory
            )
              ? requestedCategory
              : null;


      if (category === null) {
        return res.status(400).json({
          error:
            "Invalid news category.",
          articles: []
        });
      }


      if (
        requestedCountry &&
        !/^[a-z]{2}$/.test(
          requestedCountry
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid country code.",
          articles: []
        });
      }


      const isWorld =
        requestedScope === "world";


      if (
        !cleanQuery &&
        !isWorld &&
        !requestedCountry &&
        !category
      ) {
        return res.status(400).json({
          error:
            "Missing news request.",
          articles: []
        });
      }


      /*
       * Refleksa calls the category
       * "technology".
       *
       * The News API calls it "tech".
       */
      const providerCategory =
        category === "technology"
          ? "tech"
          : category;


      /*
       * Strict freshness window:
       * only the previous 24 hours.
       */
      const freshnessCutoffMs =
        Date.now() -
        NEWS_FRESHNESS_MS;


      const publishedAfter =
  new Date(
    freshnessCutoffMs
  )
    .toISOString()
    .replace(
      /\.\d{3}Z$/,
      ""
    );

      const regionNames =
  new Intl.DisplayNames(
    ["en"],
    {
      type: "region"
    }
  );


const countrySearchName =
  requestedCountry
    ? (
        regionNames.of(
          requestedCountry.toUpperCase()
        ) ||
        requestedCountry.toUpperCase()
      )
    : "";


      const params =
        new URLSearchParams({
          api_token:
            process.env.THE_NEWS_API_KEY,

          limit:
            "3",

          published_after:
            publishedAfter
        });


      // ===============================
      // TOPIC
      // ===============================
      if (cleanQuery) {

        params.set(
          "search",
          cleanQuery
        );

        params.set(
          "search_fields",
          "title,description"
        );
      }


      // ===============================
// COUNTRY
// ===============================
if (requestedCountry) {

  params.set(
    "locale",
    requestedCountry
  );
}


      // ===============================
// CATEGORY
// ===============================
if (providerCategory) {

  params.set(
    "categories",
    providerCategory
  );
}


      /*
       * WORLD:
       *
       * We intentionally send no locale.
       * The provider therefore searches
       * globally.
       */
      const cacheKey =
        isWorld
          ? (
              "world:" +
              (
                providerCategory ||
                "general"
              )
            )
          : "";


      const now =
        Date.now();


      if (
        cacheKey &&
        worldNewsCache.key ===
          cacheKey &&
        worldNewsCache.expiresAt >
          now &&
        worldNewsCache.articles
          .length > 0
      ) {

        return res.json({
          provider:
            "the_news_api",

          scope:
            "world",

          category:
            category || null,

          cached:
            true,

          freshnessHours:
            24,

          articles:
            worldNewsCache.articles
        });
      }


      const endpoint =
        "https://api.thenewsapi.com" +
        "/v1/news/top?" +
        params.toString();


      console.log(
        "THE NEWS API REQUEST:",
        {
          query:
            cleanQuery || null,

          scope:
            isWorld
              ? "world"
              : null,

          country:
            requestedCountry ||
            null,

          category:
            category || null,

          publishedAfter
        }
      );


      const response =
        await fetch(
          endpoint
        );


      const raw =
        await response.text();


      let data;

      try {
        data =
          JSON.parse(raw);
      } catch {

        console.error(
          "THE NEWS API PARSE ERROR:",
          raw
        );

        return res.status(502).json({
          error:
            "News provider parse error.",
          articles: []
        });
      }


      if (!response.ok) {

        console.error(
          "THE NEWS API ERROR:",
          data
        );

        return res.status(
          response.status
        ).json({
          error:
            data?.message ||
            data?.error ||
            "News provider error.",
          articles: []
        });
      }


      const articles =
        (
          Array.isArray(data.data)
            ? data.data
            : []
        )
          .map(article => {

            const title =
              String(
                article?.title || ""
              ).trim();

            const description =
              String(
                article?.description || ""
              ).trim();

            const source =
              String(
                article?.source || ""
              ).trim();

            const publishedAt =
              String(
                article?.published_at || ""
              ).trim();

            return {
              title,
              description:
                description || null,
              source:
                source ||
                "Unknown source",
              publishedAt
            };
          })
          .filter(article => {

            if (!article.title) {
              return false;
            }

            const publishedMs =
              Date.parse(
                article.publishedAt
              );

            return (
              Number.isFinite(
                publishedMs
              ) &&
              publishedMs >=
                freshnessCutoffMs
            );
          })
          .slice(
            0,
            3
          );


      if (cacheKey) {

        worldNewsCache = {
          key:
            cacheKey,

          expiresAt:
            now +
            WORLD_NEWS_CACHE_MS,

          articles
        };
      }


      console.log(
        "THE NEWS API RESULT:",
        {
          query:
            cleanQuery || null,

          scope:
            isWorld
              ? "world"
              : null,

          country:
            requestedCountry ||
            null,

          category:
            category || null,

          providerFound:
            Number(
              data?.meta?.found
            ) || 0,

          providerReturned:
            Number(
              data?.meta?.returned
            ) || 0,

          acceptedFresh:
            articles.length
        }
      );


      return res.json({
        provider:
          "the_news_api",

        query:
          cleanQuery || null,

        scope:
          isWorld
            ? "world"
            : null,

        country:
          requestedCountry ||
          null,

        category:
          category || null,

        cached:
          false,

        freshnessHours:
          24,

        totalResults:
          Number(
            data?.meta?.found
          ) || 0,

        articles
      });


    } catch (err) {

      console.error(
        "NEWS ERROR:",
        err
      );

      return res.status(500).json({
        error:
          "News error",
        articles: []
      });
    }
  }
);

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

// ===============================
// MEMORY ANALYZER
// ===============================
app.post("/memory/analyze", requirePrototypeToken, async (req, res) => {
  try {
    const { text } = req.body || {};
    const cleanText = String(text || "").trim();

    if (!cleanText) {
      return res.json({ should_save: false });
    }

    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: process.env.OPENAI_MEMORY_MODEL || "gpt-4.1-mini",
        input: [
          {
            role: "system",
            content: [{
              type: "input_text",
              text: `
You are Refleksa's semantic memory filter.

Current date is: ${new Date().toISOString().slice(0, 10)}

When the user mentions a date without a year, infer the nearest future date based on the current date.
Never infer a past year unless the user clearly talks about the past.

Decide if the user's message contains something worth remembering long term.

Be selective. Default to should_save=false.

Only save memories that are likely to still matter several weeks or months from now and that help build a long-term understanding of the person's identity, preferences, relationships, routines or goals.

Do not save normal daily chatter, temporary plans, casual reactions, small talk, or one-off comments.

If the user simply says what they are doing today, how the weather feels, that they are drinking coffee, relaxing, taking a shower, going outside, or finishing work, do not save it unless it reveals a recurring routine, strong preference, important event, health concern, relationship detail, goal, or explicit request to remember.

When unsure, do not save.

Save only meaningful personal information:
- preferences
- dislikes
- important people
- hobbies
- routines
- emotional patterns
- recurring worries
- personal goals
- favourite music, movies, actors, places, food
- important life context

Do NOT save:
- casual greetings
- temporary small talk
- generic questions
- commands
- filler words
- one-off irrelevant comments
- ordinary daily activities
- temporary mood unless recurring or important
- what the user is doing right now
- one-time food/drink comments
- casual plans for today
- temporary recommendations
- facts generated by the assistant
- information that comes from the assistant instead of the user

Importance guidelines:

10 = spouse, children, family members, life-changing events, core identity

9 = strongest passions, major life goals, deeply meaningful memories

8 = favourite music, favourite singers, favourite actors, favourite movies, favourite hobbies, recurring passions

7 = strong preferences and recurring interests

6 = normal preferences and useful personal information

5 = minor preferences and contextual information

1-4 = generally not important enough to keep long term

Temporal memory rules:

- If the user mentions a future event, trip, meeting, birthday, celebration, surprise, appointment, visit, holiday or important plan, consider it an event memory.

- If the user says "next week", "la prossima settimana", "settimana prossima", "next month", "il mese prossimo", or equivalent, set:
  "should_follow_up": true

  even if no exact date is available.

- If the user provides an exact date, populate:
  "date": "yyyy-MM-dd"

- If a future event should be followed up naturally, set:
  "should_follow_up": true

- If possible, set:
  "follow_up_after"
  as the day after the event.

- If no exact date can be determined, leave:
  "date": null

  but still use:
  "should_follow_up": true

Return ONLY valid JSON:
{
  "should_save": true/false,
  "category": "preference|person|routine|emotion|goal|hobby|health|relationship|event|other",
  "importance": 1-10,
  "memory": "short normalized memory in English",
  "privacy": "normal|sensitive|surprise",
  "date": null or "yyyy-MM-dd",
  "follow_up_after": null or "yyyy-MM-dd",
  "should_follow_up": true/false,
  "people": ["name1", "name2"]
}

Rules:
- Use privacy "normal" for ordinary preferences and harmless facts.
- Use privacy "sensitive" for emotional, health, personal or delicate information.
- Use privacy "surprise" if the user mentions a gift, surprise, secret plan, birthday preparation, or something that should not be revealed.
- If the user mentions a future event with a clear date, set date as yyyy-MM-dd.
- If the user mentions tomorrow, infer tomorrow from today's real date.
- If the memory is about an event, birthday, appointment, celebration, travel, meeting or important future moment, set should_follow_up true.
- follow_up_after should usually be the day after the event.
- people should include names clearly mentioned by the user.
- If no date is clear, use null.
              `.trim()
            }]
          },
          {
            role: "user",
            content: [{
              type: "input_text",
              text: cleanText
            }]
          }
        ],
        max_output_tokens: 250
      })
    });

    const raw = await response.text();
    const data = JSON.parse(raw);

    const output =
      data.output_text ||
      data.output?.flatMap(i => i.content || [])
        ?.find(p => p.type === "output_text")?.text ||
      "{}";

    const parsed = JSON.parse(output);

    return res.json(parsed);

  } catch (err) {
    console.error("MEMORY ANALYZE ERROR:", err);
    return res.json({ should_save: false });
  }
});

// ===============================
// MEMORY TRANSLATOR
// ===============================
app.post(
  "/memory/translate",
  requirePrototypeToken,
  async (req, res) => {
    try {
      const {
        memories,
        targetLanguageCode
      } = req.body || {};

      const cleanTargetLanguage =
        String(targetLanguageCode || "")
          .trim()
          .toLowerCase();

      if (!Array.isArray(memories)) {
        return res.status(400).json({
          error: "memories must be an array.",
          translations: []
        });
      }

      const cleanMemories = memories
        .map(memory => String(memory || "").trim())
        .filter(Boolean)
        .slice(0, 5);

      if (cleanMemories.length === 0) {
        return res.json({
          translations: []
        });
      }

      if (!cleanTargetLanguage) {
        return res.status(400).json({
          error: "Missing targetLanguageCode.",
          translations: cleanMemories
        });
      }

      console.log("MEMORY TRANSLATE USED:", {
        device: req.prototypeDevice.deviceId,
        partner: req.prototypeDevice.partner,
        memoryCount: cleanMemories.length,
        targetLanguageCode: cleanTargetLanguage,
        time: new Date().toISOString()
      });

      const languageNames = {
        it: "Italian",
        en: "English",
        ro: "Romanian",
        es: "Spanish",
        fr: "French",
        de: "German",
        pt: "Portuguese",
        ar: "Arabic",
        zh: "Chinese",
        pl: "Polish",
        bg: "Bulgarian",
        hu: "Hungarian"
      };

      const targetLanguage =
        languageNames[cleanTargetLanguage] ||
        cleanTargetLanguage;

      /*
       * English is already the canonical memory language.
       * Avoid an unnecessary OpenAI request.
       */
      if (cleanTargetLanguage === "en") {
        return res.json({
          translations: cleanMemories
        });
      }

      const response = await fetch(
        "https://api.openai.com/v1/responses",
        {
          method: "POST",
          headers: {
            Authorization:
              `Bearer ${process.env.OPENAI_API_KEY}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            model:
              process.env.OPENAI_MEMORY_MODEL ||
              "gpt-4.1-mini",

            input: [
              {
                role: "system",
                content: [
                  {
                    type: "input_text",
                    text: `
You are Refleksa's memory translation engine.

Translate each supplied memory into ${targetLanguage}.

Rules:

- Preserve the original meaning exactly.
- Do not invent information.
- Do not remove information.
- Do not summarize or combine memories.
- Keep the same number of items.
- Keep the same item order.
- Preserve people's names, brands, titles and dates.
- Use natural, concise language suitable for display on a smart mirror.
- The memories describe the user in the third person.
- Do not add bullets, numbers or explanations.
- Return ONLY valid JSON.

Required JSON format:

{
  "translations": [
    "translated memory 1",
    "translated memory 2"
  ]
}
                    `.trim()
                  }
                ]
              },
              {
                role: "user",
                content: [
                  {
                    type: "input_text",
                    text: JSON.stringify({
                      targetLanguageCode:
                        cleanTargetLanguage,
                      memories: cleanMemories
                    })
                  }
                ]
              }
            ],

            max_output_tokens: 500
          })
        }
      );

      const raw = await response.text();

      let data;

      try {
        data = JSON.parse(raw);
      } catch {
        console.error(
          "MEMORY TRANSLATE OPENAI PARSE ERROR:",
          raw
        );

        return res.json({
          translations: cleanMemories
        });
      }

      if (!response.ok) {
        console.error(
          "MEMORY TRANSLATE OPENAI ERROR:",
          data
        );

        return res.json({
          translations: cleanMemories
        });
      }

      const output =
        data.output_text ||
        data.output
          ?.flatMap(item => item.content || [])
          ?.find(part => part.type === "output_text")
          ?.text ||
        "";

      let parsed;

      try {
        parsed = JSON.parse(output);
      } catch {
        console.error(
          "MEMORY TRANSLATE RESULT PARSE ERROR:",
          output
        );

        return res.json({
          translations: cleanMemories
        });
      }

      const translations =
        Array.isArray(parsed.translations)
          ? parsed.translations
              .map(item => String(item || "").trim())
              .filter(Boolean)
          : [];

      /*
       * Never return a partial or mismatched translation.
       * The Android app expects the same number and order.
       */
      if (
        translations.length !== cleanMemories.length
      ) {
        console.error(
          "MEMORY TRANSLATE COUNT MISMATCH:",
          {
            originalCount: cleanMemories.length,
            translatedCount: translations.length
          }
        );

        return res.json({
          translations: cleanMemories
        });
      }

      console.log("MEMORY TRANSLATE SUCCESS:", {
        memoryCount: translations.length,
        targetLanguageCode: cleanTargetLanguage
      });

      return res.json({
        translations
      });

    } catch (err) {
      console.error(
        "MEMORY TRANSLATE ERROR:",
        err
      );

      /*
       * The Android client also has its own fallback,
       * but the server should always return valid JSON.
       */
      const fallbackMemories =
        Array.isArray(req.body?.memories)
          ? req.body.memories
              .map(item => String(item || "").trim())
              .filter(Boolean)
              .slice(0, 5)
          : [];

      return res.json({
        translations: fallbackMemories
      });
    }
  }
);

// ===============================
// MEMORY REVEAL
// ===============================
app.post(
  "/memory/reveal",
  requirePrototypeToken,
  async (req, res) => {
    try {
      const {
        memories,
        targetLanguageCode,
        personName
      } = req.body || {};

      if (!Array.isArray(memories)) {
        return res.status(400).json({
          error: "memories must be an array.",
          introduction: "",
          items: []
        });
      }

      const cleanMemories = memories
        .map(memory => String(memory || "").trim())
        .filter(Boolean)
        .slice(0, 5);

      const cleanLanguageCode =
        String(targetLanguageCode || "en")
          .trim()
          .toLowerCase();

      const cleanPersonName =
        String(personName || "")
          .trim();

      if (cleanMemories.length === 0) {
        return res.json({
          introduction: "",
          items: []
        });
      }

      console.log("MEMORY REVEAL USED:", {
        device: req.prototypeDevice.deviceId,
        partner: req.prototypeDevice.partner,
        personName: cleanPersonName || "unknown",
        targetLanguageCode: cleanLanguageCode,
        memoryCount: cleanMemories.length,
        time: new Date().toISOString()
      });

      const languageNames = {
        it: "Italian",
        en: "English",
        ro: "Romanian",
        es: "Spanish",
        fr: "French",
        de: "German",
        pt: "Portuguese",
        ar: "Arabic",
        zh: "Chinese",
        pl: "Polish",
        bg: "Bulgarian",
        hu: "Hungarian"
      };

      const targetLanguage =
        languageNames[cleanLanguageCode] ||
        cleanLanguageCode;

      const systemPrompt = `
You are Refleksa's memory presentation engine.

Transform personal memories into a short, elegant memory reveal.

Target language: ${targetLanguage}

The person standing in front of the mirror is:
${cleanPersonName || "the user"}

Return a maximum of 5 memory items.

IMPORTANT SELECTION RULES:

- Prefer the most meaningful and personal memories.
- Remove duplicates or memories expressing the same idea.
- Do not include weak, temporary or trivial information.
- It is acceptable to return fewer than 5 memories.
- Normally return 3 to 5 useful memories.
- Never invent information.

For every selected memory create:

1. displayText
A very short summary for the mirror panel.

Display text rules:

- Maximum approximately 7 words.
- It may be a short label or compact phrase.
- Do not write a full long sentence.
- Do not add bullets or numbering.
- Do not repeat the person's name unnecessarily.
- Preserve names, brands, places and important details.

Good display examples:

"Cantante preferito: Elvis Presley"
"Crina è molto importante per te"
"Ama viaggiare"
"Fondatore di Refleksa"
"Obiettivo: espandere Refleksa"

Bad display examples:

"Daniele ha detto che il suo cantante preferito è Elvis Presley."
"Una delle cose che ricordo di te è che ami particolarmente viaggiare."

2. spokenText
A short, warm and natural sentence spoken directly to the person.

Spoken text rules:

- Speak directly to the user using "you".
- Do not describe the person in the third person.
- Sound warm and human.
- Keep each spoken sentence concise.
- Maximum approximately 14 words.
- Vary the opening naturally.
- Avoid repeating "I remember" for every item.
- Do not add explanations or follow-up questions.

Also create one short introduction.

Introduction rules:

- Maximum approximately 10 words.
- Address the person naturally if their name is available.
- Do not mention how many memories will be shown.
- Do not sound robotic.

Return ONLY valid JSON using exactly this structure:

{
  "introduction": "short natural introduction",
  "items": [
    {
      "displayText": "short panel text",
      "spokenText": "short natural spoken sentence"
    }
  ]
}
      `.trim();

      const response = await fetch(
        "https://api.openai.com/v1/responses",
        {
          method: "POST",
          headers: {
            Authorization:
              `Bearer ${process.env.OPENAI_API_KEY}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            model:
              process.env.OPENAI_MEMORY_MODEL ||
              "gpt-4.1-mini",

            input: [
              {
                role: "system",
                content: [
                  {
                    type: "input_text",
                    text: systemPrompt
                  }
                ]
              },
              {
                role: "user",
                content: [
                  {
                    type: "input_text",
                    text: JSON.stringify({
                      personName:
                        cleanPersonName || null,
                      targetLanguageCode:
                        cleanLanguageCode,
                      memories:
                        cleanMemories
                    })
                  }
                ]
              }
            ],

            max_output_tokens: 700
          })
        }
      );

      const rawResponse = await response.text();

      let responseData;

      try {
        responseData = JSON.parse(rawResponse);
      } catch {
        console.error(
          "MEMORY REVEAL OPENAI PARSE ERROR:",
          rawResponse
        );

        return res.json({
          introduction: "",
          items: []
        });
      }

      if (!response.ok) {
        console.error(
          "MEMORY REVEAL OPENAI ERROR:",
          responseData
        );

        return res.json({
          introduction: "",
          items: []
        });
      }

      const outputText =
        responseData.output_text ||
        responseData.output
          ?.flatMap(item => item.content || [])
          ?.find(part => part.type === "output_text")
          ?.text ||
        "";

      let parsed;

      try {
        parsed = JSON.parse(outputText);
      } catch {
        console.error(
          "MEMORY REVEAL RESULT PARSE ERROR:",
          outputText
        );

        return res.json({
          introduction: "",
          items: []
        });
      }

      const introduction =
        String(parsed.introduction || "").trim();

      const items =
        Array.isArray(parsed.items)
          ? parsed.items
              .map(item => ({
                displayText:
                  String(item?.displayText || "")
                    .trim(),

                spokenText:
                  String(item?.spokenText || "")
                    .trim()
              }))
              .filter(item =>
                item.displayText &&
                item.spokenText
              )
              .slice(0, 5)
          : [];

      if (items.length === 0) {
        console.error(
          "MEMORY REVEAL RETURNED NO VALID ITEMS"
        );

        return res.json({
          introduction: "",
          items: []
        });
      }

      console.log("MEMORY REVEAL SUCCESS:", {
        personName: cleanPersonName || "unknown",
        targetLanguageCode: cleanLanguageCode,
        itemCount: items.length
      });

      return res.json({
        introduction,
        items
      });

    } catch (err) {
      console.error(
        "MEMORY REVEAL ERROR:",
        err
      );

      return res.json({
        introduction: "",
        items: []
      });
    }
  }
);

// ===============================
// KNOWLEDGE ANALYZER
// ===============================
app.post("/knowledge/analyze", requirePrototypeToken, async (req, res) => {
    try {

        const {
            text,
            language,
            recognizedPerson
        } = req.body || {};

        const cleanText = String(text || "").trim();

        if (!cleanText) {
            return res.json({
                intent: "none"
            });
        }

        const response = await fetch("https://api.openai.com/v1/responses", {
            method: "POST",
            headers: {
                Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({

                model: process.env.OPENAI_MEMORY_MODEL || "gpt-4.1-mini",

                input: [

                    {
                        role: "system",
                        content: [{
                            type: "input_text",
                            text: `
You are Refleksa's Knowledge Analyzer.

Your job is to understand whether the user is:

- saving the location of an object
- asking where an object is
- describing the environment
- mentioning an object
- or simply having a normal conversation.

Always understand the meaning.

Never rely on exact keywords.

Support ALL languages.

Examples:

"Remember my keys are on the table."

"Ricordati che le chiavi sono sul tavolo."

"Le mie chiavi sono sul tavolo."

"Unde sunt cheile?"

"Where are my keys?"

"Dove sono le chiavi?"

Return ONLY JSON.

{
  "intent":"none|save_object|find_object|environment",

  "object":null,

  "location":null,

  "room":null,

  "confidence":0.0
}
`.trim()
                        }]
                    },

                    {
                        role: "user",
                        content: [{
                            type: "input_text",
                            text: cleanText
                        }]
                    }

                ],

                max_output_tokens:150

            })
        });

        const raw = await response.text();

        const data = JSON.parse(raw);

        const output =
            data.output_text ||
            data.output?.flatMap(i => i.content || [])
                ?.find(p => p.type === "output_text")?.text ||
            "{}";

        return res.json(JSON.parse(output));

    } catch(err){

        console.error("KNOWLEDGE ANALYZE ERROR:", err);

        return res.json({
            intent:"none"
        });

    }
});


// ===============================
// IDENTITY / PEOPLE ANALYZER
// ===============================
app.post("/identity/analyze", requirePrototypeToken, async (req, res) => {
  try {
    const {
      text,
      hasIdentity,
      knownPeople,
      faceDetected,
      recognizedPerson,

      // Campo precedente: mantenuto temporaneamente
      // per compatibilità con le vecchie versioni dell'APK.
      waitingForName,

      // Nuovo flusso onboarding.
      onboardingState,
      pendingName,
      conversationLanguage
    } = req.body || {};

    const cleanText = String(text || "").trim();

    const cleanOnboardingState =
      String(onboardingState || "none")
        .trim()
        .toLowerCase();

    const cleanPendingName =
      String(pendingName || "")
        .trim();

    const cleanConversationLanguage =
      String(conversationLanguage || "")
        .trim()
        .toLowerCase();

    const validOnboardingStates = [
      "none",
      "waiting_for_name",
      "waiting_for_confirmation"
    ];

    const safeOnboardingState =
      validOnboardingStates.includes(cleanOnboardingState)
        ? cleanOnboardingState
        : "none";

    /*
     * Finché l'APK non viene aggiornato, onboardingState non sarà inviato.
     * In quel caso il server mantiene il comportamento precedente.
     *
     * Questo evita che la vecchia APK salvi immediatamente un nome
     * dopo che il server ha soltanto chiesto conferma.
     */
    const newOnboardingEnabled =
      safeOnboardingState === "waiting_for_name" ||
      safeOnboardingState === "waiting_for_confirmation";

    if (!cleanText) {
      return res.json({
        intent: "normal",
        language: cleanConversationLanguage || "unknown",
        name: null,
        oldName: null,
        newName: null,
        adminAction: null,
        confidence: 0,
        reply: null
      });
    }

    const people =
      Array.isArray(knownPeople)
        ? knownPeople
            .map(person => String(person || "").trim())
            .filter(Boolean)
        : [];

    const response = await fetch(
      "https://api.openai.com/v1/responses",
      {
        method: "POST",
        headers: {
          Authorization:
            `Bearer ${process.env.OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model:
            process.env.OPENAI_MEMORY_MODEL ||
            "gpt-4.1-mini",

          input: [
            {
              role: "system",
              content: [
                {
                  type: "input_text",
                  text: `
You are Refleksa's multilingual Identity and People Engine.

You support every human language understood by the model.

Never rely on a fixed list of languages.
Never translate the user into an unrelated language.
Never invent a person's name.

The transcript may contain:
- speech-recognition errors
- phonetic spelling
- incorrect alphabets
- incomplete words
- accents
- mixed punctuation

Interpret the transcript using the supplied onboarding context.

==================================================
CURRENT IDENTITY CONTEXT
==================================================

Mirror owner registered:
${Boolean(hasIdentity)}

Known registered people:
${JSON.stringify(people)}

Face currently detected:
${Boolean(faceDetected)}

Face-recognition result:
${recognizedPerson || "unknown"}

Legacy waitingForName value:
${Boolean(waitingForName)}

New onboarding enabled:
${newOnboardingEnabled}

Current onboarding state:
${safeOnboardingState}

Pending name awaiting confirmation:
${cleanPendingName || "none"}

Current conversation language:
${cleanConversationLanguage || "unknown"}

==================================================
LANGUAGE RULES
==================================================

Reply in the language currently being used by the user.

When Current conversation language is not "unknown",
prefer that language during onboarding.

A person's name, a short confirmation, or a transcription
written in an unexpected alphabet must not cause an automatic
conversation-language change.

For example, if the conversation is Italian and the name
"Daniele" is transcribed using Cyrillic characters, continue
replying in Italian.

==================================================
VALID INTENTS
==================================================

Return exactly one of these intents:

1. register_name

The user clearly provides their name.

Examples:
- "Daniele"
- "Sono Daniele"
- "Mi chiamo Daniele"
- "Il mio nome è Daniele"
- "I am Daniel"
- "My name is Daniel"
- equivalent expressions in any language

2. confirm_name

Use only when:
- onboarding state is "waiting_for_confirmation"
- pending name is available
- the user clearly confirms

Examples include natural equivalents of:
- yes
- correct
- confirm
- that's right
- sure
- okay

3. reject_name

Use only when:
- onboarding state is "waiting_for_confirmation"
- the user clearly rejects or corrects the proposed name

Examples include natural equivalents of:
- no
- incorrect
- wrong
- that is not my name
- you misunderstood

4. unclear_name

The user appears to be giving a name, but the name cannot
be extracted reliably.

5. unclear_confirmation

Use only during "waiting_for_confirmation" when the reply
does not clearly confirm or reject the pending name.

6. people_admin

The user asks to:
- list known registered people
- remove or forget a registered person
- rename a registered person

7. normal

Normal conversation unrelated to identity registration
or people administration.

==================================================
UNKNOWN PERSON BEHAVIOUR
==================================================

If:
- a face is detected
- recognizedPerson is missing, null or "unknown"
- onboarding state is "none"
- the person has not introduced themselves

Then:
- politely introduce yourself as Refleksa
- say naturally that you do not appear to know each other
- ask their name
- use intent "normal"
- include the complete spoken reply

Do not assume that an unknown face belongs to the registered
mirror owner.

==================================================
WAITING FOR NAME
==================================================

When onboarding state is "waiting_for_name":

- interpret the transcript as an answer to:
  "What is your name?"
- accept a single name
- accept natural introductions
- tolerate likely speech-recognition mistakes
- extract only the person's name
- preserve the natural spelling when reasonably clear

If the name is clear:
- intent = "register_name"
- return the extracted name
- confidence must reflect certainty
- do not claim that the profile has already been saved
- ask the user to confirm the proposed profile name

Example Italian reply:
"Ho capito Daniele. Vuoi confermare il profilo Daniele?"

The reply must be natural in the conversation language.

If the name is not clear:
- intent = "unclear_name"
- name = null
- ask the user to repeat their name
- do not invent anything

==================================================
WAITING FOR CONFIRMATION
==================================================

When onboarding state is "waiting_for_confirmation":

The pending name is:
${cleanPendingName || "none"}

Interpret the transcript only as a response to the profile
confirmation question.

If the user confirms:
- intent = "confirm_name"
- name = the pending name
- do not extract a new name
- reply naturally that the confirmation was understood
- do not falsely claim that storage has already completed;
  Android performs the actual save after receiving this intent

If the user rejects:
- intent = "reject_name"
- name = the pending name
- ask naturally for their name again

If the answer is unclear:
- intent = "unclear_confirmation"
- name = the pending name
- ask clearly whether they want to confirm that name

==================================================
LEGACY APK COMPATIBILITY
==================================================

When new onboarding is not enabled and legacy waitingForName
is true, preserve the previous behaviour:

- detect a supplied name
- use intent "register_name"
- return the extracted name
- reply warmly that Refleksa will remember or recognise them

Do not use confirm_name, reject_name or unclear_confirmation
in legacy mode.

==================================================
PEOPLE ADMINISTRATION
==================================================

For list:
- intent = "people_admin"
- adminAction = "list"
- use only the supplied knownPeople list
- do not invent people

For removal:
- intent = "people_admin"
- adminAction = "remove"
- extract the requested person's name
- do not claim that deletion already happened

For rename:
- intent = "people_admin"
- adminAction = "rename"
- extract oldName and newName
- do not claim success unless both names are clear

==================================================
OUTPUT RULES
==================================================

Return ONLY valid JSON.

Use exactly this structure:

{
  "intent": "register_name|confirm_name|reject_name|unclear_name|unclear_confirmation|people_admin|normal",
  "language": "BCP-47-style language code or unknown",
  "name": null,
  "oldName": null,
  "newName": null,
  "adminAction": null,
  "confidence": 0.0,
  "reply": null
}

The reply field must be present when Refleksa needs to speak.

For normal conversation unrelated to identity, reply may be null.
                  `.trim()
                }
              ]
            },
            {
              role: "user",
              content: [
                {
                  type: "input_text",
                  text: JSON.stringify({
                    transcript: cleanText,
                    onboardingState: safeOnboardingState,
                    pendingName:
                      cleanPendingName || null,
                    conversationLanguage:
                      cleanConversationLanguage || null
                  })
                }
              ]
            }
          ],

          max_output_tokens: 300
        })
      }
    );

    const raw = await response.text();

    let data;

    try {
      data = JSON.parse(raw);
    } catch {
      console.error(
        "IDENTITY OPENAI RESPONSE PARSE ERROR:",
        raw
      );

      return res.json({
        intent: "normal",
        language:
          cleanConversationLanguage || "unknown",
        name: null,
        oldName: null,
        newName: null,
        adminAction: null,
        confidence: 0,
        reply: null
      });
    }

    if (!response.ok) {
      console.error(
        "IDENTITY OPENAI ERROR:",
        data
      );

      return res.status(response.status).json({
        intent: "normal",
        language:
          cleanConversationLanguage || "unknown",
        name: null,
        oldName: null,
        newName: null,
        adminAction: null,
        confidence: 0,
        reply: null
      });
    }

    const output =
      data.output_text ||
      data.output
        ?.flatMap(item => item.content || [])
        ?.find(part => part.type === "output_text")
        ?.text ||
      "{}";

    let parsed;

    try {
      parsed = JSON.parse(output);
    } catch {
      console.error(
        "IDENTITY RESULT JSON ERROR:",
        output
      );

      parsed = {
        intent: "normal",
        language:
          cleanConversationLanguage || "unknown",
        name: null,
        oldName: null,
        newName: null,
        adminAction: null,
        confidence: 0,
        reply: null
      };
    }

    const allowedIntents = newOnboardingEnabled
      ? [
          "register_name",
          "confirm_name",
          "reject_name",
          "unclear_name",
          "unclear_confirmation",
          "people_admin",
          "normal"
        ]
      : [
          "register_name",
          "unclear_name",
          "people_admin",
          "normal"
        ];

    const safeIntent =
      allowedIntents.includes(parsed.intent)
        ? parsed.intent
        : "normal";

    /*
     * Durante la conferma il nome autorevole è pendingName,
     * non un nuovo nome eventualmente inventato dal modello.
     */
    const safeName =
      safeOnboardingState ===
        "waiting_for_confirmation" &&
      cleanPendingName
        ? cleanPendingName
        : String(parsed.name || "").trim() || null;

    const confidence =
      Number.isFinite(Number(parsed.confidence))
        ? Math.max(
            0,
            Math.min(1, Number(parsed.confidence))
          )
        : 0;

    return res.json({
      intent: safeIntent,
      language:
        parsed.language ||
        cleanConversationLanguage ||
        "unknown",
      name: safeName,
      oldName:
        String(parsed.oldName || "").trim() || null,
      newName:
        String(parsed.newName || "").trim() || null,
      adminAction:
        String(parsed.adminAction || "").trim() ||
        null,
      confidence,
      reply:
        String(parsed.reply || "").trim() || null
    });

  } catch (err) {
    console.error(
      "IDENTITY ANALYZE ERROR:",
      err
    );

    return res.json({
      intent: "normal",
      language: "unknown",
      name: null,
      oldName: null,
      newName: null,
      adminAction: null,
      confidence: 0,
      reply: null
    });
  }
});

// ===============================
// UNIFIED ROUTER
// COMMAND + KNOWLEDGE
// ===============================
app.post("/route/analyze", requirePrototypeToken, async (req, res) => {
  const emptyResult = {
    route: "normal",
    action: "none",
    knowledgeIntent: "none",
    language: "unknown",
    parameters: {
      name: null,
      oldName: null,
      newName: null,
      title: null,
      date: null,
      time: null,
      object: null,
      location: null,
      room: null
    },
    confidence: 0
  };

  try {
    const {
      text,
      knownPeople,
      currentPerson,
      currentDate,
      currentTime,
      timeZone
    } = req.body || {};

    const cleanText = String(text || "").trim();

    const safeTimeZone =
      String(timeZone || "Europe/London").trim();

    const safeCurrentDate =
      String(
        currentDate ||
        new Date().toLocaleDateString("en-CA", {
          timeZone: safeTimeZone
        })
      ).trim();

    const safeCurrentTime =
      String(
        currentTime ||
        new Date().toLocaleTimeString("en-GB", {
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
          timeZone: safeTimeZone
        })
      ).trim();

    if (!cleanText) {
      return res.json(emptyResult);
    }

    const people = Array.isArray(knownPeople)
      ? knownPeople
          .map(person => String(person || "").trim())
          .filter(Boolean)
      : [];

    const response = await fetch(
      "https://api.openai.com/v1/responses",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model:
            process.env.OPENAI_ROUTER_MODEL ||
            process.env.OPENAI_COMMAND_MODEL ||
            process.env.OPENAI_MEMORY_MODEL ||
            "gpt-4.1-mini",

          input: [
            {
              role: "system",
              content: [{
                type: "input_text",
                text: `
You are Refleksa's fast multilingual Unified Router.

Analyze the user's latest transcript once and classify it into exactly one route:

- normal
- command
- knowledge

Your output is used by an Android smart mirror.

Support every language understood by the model.

The transcript may contain:
- speech-recognition mistakes
- incomplete words
- phonetic spelling
- repeated fragments
- malformed grammar
- accents
- incorrect punctuation

Understand meaning semantically.
Do not rely only on exact keywords.
Do not invent actions, objects, names or locations.

CURRENT CONTEXT

Known registered people:
${JSON.stringify(people)}

Current recognized person:
${currentPerson || "unknown"}

CURRENT LOCAL TIME CONTEXT

Current local date:
${safeCurrentDate}

Current local time:
${safeCurrentTime}

Device time zone:
${safeTimeZone}

These values are authoritative.

Never ask the user for their city or time zone when creating a local reminder.
Always use the supplied device time zone.

Never generate a reminder date in the past.

==================================================
ROUTE: COMMAND
==================================================

Use route "command" only when the user clearly requests an executable action.

SUPPORTED COMMAND ACTIONS

PEOPLE:
- list_people
- delete_person
- rename_person

VOLUME:
- volume_up
- volume_down
- volume_max
- volume_min
- volume_mute
- volume_normal

APPS:
- open_youtube
- open_spotify
- open_chrome
- open_calendar
- open_settings

DEVICE:
- standby
- go_home
- stop_speaking

REMINDERS:
- add_reminder
- remove_reminder
- clear_reminders
- list_reminders

TIME:
- get_time
- get_date

COMMAND EXAMPLES

list_people:
- who do you know
- which people do you know
- do you know anyone
- who is registered
- anyone besides me
- chi conosci
- quali persone conosci
- conosci qualcuno
- conosci altre persone oltre a me
- mi sai dire quali persone conosci
- di persone chi conosci

delete_person:
- remove NAME
- delete NAME
- forget NAME
- remove NAME from memory
- rimuovi NAME
- elimina NAME
- cancella NAME
- dimentica NAME
- togli NAME dalle persone conosciute
- rimuovi la persona NAME

Tolerate likely transcription mistakes such as:
- rimovi
- remuovi
- ti muovi la persona
- rimuove persona

NAME CORRECTION

Use knownPeople to correct a name only when there is one obvious and unique close match.

Example:

Known people:
["Daniele", "Krina"]

Transcript:
"Rimuovi Acrina"

Correct result:
parameters.name = "Krina"

Do not correct when uncertain.

For rename_person:
- parameters.oldName = current registered name
- parameters.newName = requested new name

For add_reminder:

- Extract parameters.title from the requested action.
- Return parameters.date in yyyy-MM-dd format.
- Return parameters.time in HH:mm format.
- Resolve relative dates using the authoritative current local date.

Date rules:

- "today" and equivalents mean the supplied current local date.
- "tomorrow" and equivalents mean the day after the supplied current local date.
- If the user provides only a time and no date:
- use the current local date if that time is still in the future;
- otherwise use the following local date.
- If the user gives an explicit future calendar date, use that date.
- Never produce a date earlier than the current local date.
- Never reuse dates from memories or previous unrelated conversations.
- Never ask for a city or time zone.
- Use the supplied device time zone automatically.
- Ask a follow-up question only when the title or time is genuinely missing.

For command route:
- action must not be "none"
- knowledgeIntent must be "none"

==================================================
ROUTE: KNOWLEDGE
==================================================

Use route "knowledge" only when the user:

1. tells Refleksa where an object is
2. asks where an object is

SUPPORTED KNOWLEDGE INTENTS

- save_object
- find_object

save_object examples:
- Remember that my keys are on the table.
- My phone is on the sofa.
- Ricordati che il laptop è sul tavolo.
- Le chiavi sono in cucina.
- Telefonul meu este pe masă.

find_object examples:
- Where are my keys?
- I cannot find my laptop.
- Dove sono le chiavi?
- Non trovo più il telefono.
- Unde este laptopul meu?

KNOWLEDGE RULES

Normalize common object names into English.

Examples:
- smartphone
- mobile phone
- cell phone
→ phone

- coffee cup
- tazza da caffè
→ coffee mug

For save_object:
- parameters.object must contain the normalized object
- parameters.location must contain the short location
- parameters.room may be null or a short normalized room
- action must be "none"
- knowledgeIntent must be "save_object"

For find_object:
- parameters.object must contain the normalized object
- parameters.location must be null
- action must be "none"
- knowledgeIntent must be "find_object"

Do not classify a normal mention of an object as knowledge.

Examples that are normal conversation:
- I like my new laptop.
- My phone is beautiful.
- Sto usando il computer.
- Ho comprato una tazza nuova.

The user must clearly be saving or finding an object location.

==================================================
ROUTE: NORMAL
==================================================

Use route "normal" for:
- greetings
- feelings
- opinions
- jokes
- casual conversation
- ordinary questions
- personal stories
- health discussion
- weather discussion
- incomplete vague fragments

Examples:
- come stai
- sono stanco
- accaldato
- buon pomeriggio
- tell me a joke
- I am drinking tea
- ho mal di gola
- mi sento bene oggi

Vague fragments must remain normal unless the intended action is clear.

Examples:
- "volume" alone → normal
- "YouTube" alone → normal
- "people" alone → normal
- "laptop" alone → normal

For normal route:
- action = "none"
- knowledgeIntent = "none"

==================================================
OUTPUT
==================================================

Detect the language of the user's latest transcript.

Return ONLY valid JSON using exactly this structure:

{
  "route": "normal|command|knowledge",
  "action": "none|list_people|delete_person|rename_person|volume_up|volume_down|volume_max|volume_min|volume_mute|volume_normal|open_youtube|open_spotify|open_chrome|open_calendar|open_settings|standby|go_home|stop_speaking|add_reminder|remove_reminder|clear_reminders|list_reminders|get_time|get_date",
  "knowledgeIntent": "none|save_object|find_object",
  "language": "BCP-47-style language code or unknown",
  "parameters": {
    "name": null,
    "oldName": null,
    "newName": null,
    "title": null,
    "date": null,
    "time": null,
    "object": null,
    "location": null,
    "room": null
  },
  "confidence": 0.0
}
                `.trim()
              }]
            },
            {
              role: "user",
              content: [{
                type: "input_text",
                text: cleanText
              }]
            }
          ],

          max_output_tokens: 180
        })
      }
    );

    const raw = await response.text();

    let data;

    try {
      data = JSON.parse(raw);
    } catch {
      console.error("ROUTE OPENAI RESPONSE PARSE ERROR:", raw);
      return res.json(emptyResult);
    }

    if (!response.ok) {
      console.error("ROUTE OPENAI ERROR:", data);
      return res.status(response.status).json(emptyResult);
    }

    const output =
      data.output_text ||
      data.output
        ?.flatMap(item => item.content || [])
        ?.find(part => part.type === "output_text")
        ?.text ||
      "{}";

    let parsed;

    try {
      parsed = JSON.parse(output);
    } catch {
      console.error("ROUTE RESULT JSON ERROR:", output);
      return res.json(emptyResult);
    }

    const validRoutes = new Set([
      "normal",
      "command",
      "knowledge"
    ]);

    const validActions = new Set([
      "none",
      "list_people",
      "delete_person",
      "rename_person",
      "volume_up",
      "volume_down",
      "volume_max",
      "volume_min",
      "volume_mute",
      "volume_normal",
      "open_youtube",
      "open_spotify",
      "open_chrome",
      "open_calendar",
      "open_settings",
      "standby",
      "go_home",
      "stop_speaking",
      "add_reminder",
      "remove_reminder",
      "clear_reminders",
      "list_reminders",
      "get_time",
      "get_date"
    ]);

    const validKnowledgeIntents = new Set([
      "none",
      "save_object",
      "find_object"
    ]);

    let route = validRoutes.has(parsed.route)
      ? parsed.route
      : "normal";

    let action = validActions.has(parsed.action)
      ? parsed.action
      : "none";

    let knowledgeIntent =
      validKnowledgeIntents.has(parsed.knowledgeIntent)
        ? parsed.knowledgeIntent
        : "none";

    // Keep the result internally consistent.
    if (route === "normal") {
      action = "none";
      knowledgeIntent = "none";
    }

    if (route === "command") {
      knowledgeIntent = "none";

      if (action === "none") {
        route = "normal";
      }
    }

    if (route === "knowledge") {
      action = "none";

      if (knowledgeIntent === "none") {
        route = "normal";
      }
    }

    return res.json({
      route,
      action,
      knowledgeIntent,
      language: parsed.language || "unknown",
      parameters: {
        name: parsed.parameters?.name || null,
        oldName: parsed.parameters?.oldName || null,
        newName: parsed.parameters?.newName || null,
        title: parsed.parameters?.title || null,
        date: parsed.parameters?.date || null,
        time: parsed.parameters?.time || null,
        object: parsed.parameters?.object || null,
        location: parsed.parameters?.location || null,
        room: parsed.parameters?.room || null
      },
      confidence: Number(parsed.confidence) || 0
    });

  } catch (err) {
    console.error("ROUTE ANALYZE ERROR:", err);
    return res.json(emptyResult);
  }
});

// ===============================
// COMMAND ENGINE
// ===============================
app.post("/command/analyze", requirePrototypeToken, async (req, res) => {
  try {
    const {
      text,
      knownPeople,
      currentPerson
    } = req.body || {};

    const cleanText = String(text || "").trim();

    const emptyResult = {
      handled: false,
      action: "none",
      language: "unknown",
      parameters: {
        name: null,
        oldName: null,
        newName: null,
        title: null,
        date: null,
        time: null
      },
      confidence: 0
    };

    if (!cleanText) {
      return res.json(emptyResult);
    }

    const people = Array.isArray(knownPeople)
      ? knownPeople
          .map(person => String(person || "").trim())
          .filter(Boolean)
      : [];

    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model:
          process.env.OPENAI_COMMAND_MODEL ||
          process.env.OPENAI_MEMORY_MODEL ||
          "gpt-4.1-mini",

        input: [
          {
            role: "system",
            content: [{
              type: "input_text",
              text: `
You are Refleksa's fast multilingual Command Router.

Classify the user's latest transcript as either:

1. a supported executable command
2. normal conversation

Support every language understood by the model.

The transcript may contain:
- speech-recognition mistakes
- missing or incorrect words
- phonetic spellings
- accents
- repeated fragments
- malformed grammar
- incorrect punctuation

Understand the intended meaning semantically.
Do not rely only on exact keywords.
Never invent a command when the message is ordinary conversation.
Never invent missing parameters.

CURRENT CONTEXT

Known registered people:
${JSON.stringify(people)}

Current recognized person:
${currentPerson || "unknown"}

SUPPORTED ACTIONS

PEOPLE
- list_people
- delete_person
- rename_person

VOLUME
- volume_up
- volume_down
- volume_min
- volume_max
- volume_mute
- volume_normal

APPS
- open_youtube
- open_spotify
- open_chrome
- open_calendar
- open_settings

DEVICE
- standby
- go_home
- stop_speaking

REMINDERS
- add_reminder
- remove_reminder
- clear_reminders
- list_reminders

TIME
- get_time
- get_date

SEMANTIC EXAMPLES

list_people includes requests such as:
- who do you know
- which people do you know
- do you know anyone
- who is registered
- anyone besides me
- tell me which people you know
- chi conosci
- quali persone conosci
- conosci qualcuno
- che persone conosci
- conosci altre persone oltre a me
- sai dirmi se conosci qualche persona
- di persone chi conosci

These must be classified as list_people even when grammatically imperfect.

delete_person includes requests such as:
- remove NAME
- delete NAME
- forget NAME
- remove NAME from memory
- take NAME out of the registered people
- rimuovi NAME
- elimina NAME
- cancella NAME
- dimentica NAME
- togli NAME dalle persone conosciute
- rimuovi la persona NAME
- cancella la persona NAME

Tolerate likely transcription mistakes in the command verb, for example:
- rimovi
- remuovi
- ti muovi la persona
- rimuove persona

Use the complete sentence to infer whether deletion was intended.

NAME CORRECTION RULE

Use knownPeople to correct a likely speech-recognition error only when one registered name is an obvious and unique close match.

Examples:

Known people:
["Daniele", "Krina"]

Transcript name:
"Acrina"

Return:
"Krina"

Transcript name:
"Crina"

Return:
"Krina"

Do not correct the name when:
- more than one registered person is a plausible match
- the requested name is clearly a different name
- confidence is low

For a deletion request, prefer an exact known registered person name in parameters.name when the intended match is clear.

rename_person includes:
- rename OLD_NAME to NEW_NAME
- change OLD_NAME's name to NEW_NAME
- rinomina OLD_NAME in NEW_NAME
- cambia il nome di OLD_NAME in NEW_NAME

COMMAND RULES

For list_people:
- action = "list_people"
- Android will read the real people database
- do not return names as parameters
- never answer conversationally

For delete_person:
- action = "delete_person"
- put the corrected registered name in parameters.name when clear
- never claim that deletion already happened
- Android performs the deletion

For rename_person:
- action = "rename_person"
- put the current name in parameters.oldName
- put the requested new name in parameters.newName
- Android performs the rename

For add_reminder:
- extract parameters.title
- extract parameters.date when clear
- extract parameters.time when clear
- use yyyy-MM-dd for exact dates
- use HH:mm for exact times
- never invent missing date or time information

For remove_reminder:
- extract parameters.title when clear

For volume, app, device and time commands:
- return only the action and parameters
- do not produce a spoken reply

NORMAL CONVERSATION

Messages such as greetings, feelings, questions, opinions, jokes and ordinary conversation must return:

- handled = false
- action = "none"

Examples:
- how are you
- come stai
- I am tired
- sono stanco
- good afternoon
- buon pomeriggio
- tell me a joke
- parlami della giornata

Do not classify a vague fragment as a command unless the intended device action is reasonably clear.

Examples:
- "volume" alone is not enough
- "YouTube" alone is not necessarily enough
- "people" alone is not enough

Detect the language of the latest transcript.

Return ONLY valid JSON using exactly this structure:

{
  "handled": true,
  "action": "none|list_people|delete_person|rename_person|volume_up|volume_down|volume_max|volume_mute|volume_normal|open_youtube|open_spotify|open_chrome|open_calendar|open_settings|standby|go_home|stop_speaking|add_reminder|remove_reminder|clear_reminders|list_reminders|get_time|get_date",
  "language": "BCP-47-style language code or unknown",
  "parameters": {
    "name": null,
    "oldName": null,
    "newName": null,
    "title": null,
    "date": null,
    "time": null
  },
  "confidence": 0.0
}
              `.trim()
            }]
          },
          {
            role: "user",
            content: [{
              type: "input_text",
              text: cleanText
            }]
          }
        ],

        max_output_tokens: 140
      })
    });

    const raw = await response.text();

    let data;

    try {
      data = JSON.parse(raw);
    } catch {
      console.error("COMMAND OPENAI RESPONSE PARSE ERROR:", raw);
      return res.json(emptyResult);
    }

    if (!response.ok) {
      console.error("COMMAND OPENAI ERROR:", data);
      return res.status(response.status).json(emptyResult);
    }

    const output =
      data.output_text ||
      data.output
        ?.flatMap(item => item.content || [])
        ?.find(part => part.type === "output_text")
        ?.text ||
      "{}";

    let parsed;

    try {
      parsed = JSON.parse(output);
    } catch {
      console.error("COMMAND RESULT JSON ERROR:", output);
      return res.json(emptyResult);
    }

    const validActions = new Set([
      "none",
      "list_people",
      "delete_person",
      "rename_person",
      "volume_up",
      "volume_down",
      "volume_min",
      "volume_max",
      "volume_mute",
      "volume_normal",
      "open_youtube",
      "open_spotify",
      "open_chrome",
      "open_calendar",
      "open_settings",
      "standby",
      "go_home",
      "stop_speaking",
      "add_reminder",
      "remove_reminder",
      "clear_reminders",
      "list_reminders",
      "get_time",
      "get_date"
    ]);

    const action = validActions.has(parsed.action)
      ? parsed.action
      : "none";

    const handled =
      parsed.handled === true &&
      action !== "none";

    return res.json({
      handled,
      action,
      language: parsed.language || "unknown",
      parameters: {
        name: parsed.parameters?.name || null,
        oldName: parsed.parameters?.oldName || null,
        newName: parsed.parameters?.newName || null,
        title: parsed.parameters?.title || null,
        date: parsed.parameters?.date || null,
        time: parsed.parameters?.time || null
      },
      confidence: Number(parsed.confidence) || 0
    });

  } catch (err) {
    console.error("COMMAND ANALYZE ERROR:", err);

    return res.json({
      handled: false,
      action: "none",
      language: "unknown",
      parameters: {
        name: null,
        oldName: null,
        newName: null,
        title: null,
        date: null,
        time: null
      },
      confidence: 0
    });
  }
});

// ===============================
// MEMORY CONSOLIDATION
// ===============================
app.post("/memory/consolidate", requirePrototypeToken, async (req, res) => {
  try {

    const { memories } = req.body || {};

    if (!Array.isArray(memories) || memories.length === 0) {
      return res.json({ consolidated: [] });
    }

    const response = await fetch(
      "https://api.openai.com/v1/responses",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: process.env.OPENAI_MEMORY_MODEL || "gpt-4.1-mini",
          input: [
            {
              role: "system",
              content: [{
                type: "input_text",
                text: `
You are Refleksa's Memory Consolidation Engine.

Merge related memories into richer human memories.

Rules:

- Merge memories about the same people.
- Merge memories about the same future event.
- Merge memories about the same goal.
- Merge memories about the same emotional pattern.
- Do not invent facts.
- Preserve important information.
- Preserve privacy.
- Preserve future follow-ups.
- Do not merge memories about different people unless the input clearly says they are part of the same event.

- If a memory mentions Greta and another memory mentions mother, Esther, Samantha, China, or another person, keep them separate unless the same sentence explicitly connects them.

- Prefer multiple smaller accurate consolidated memories over one large mixed memory.

- When people names are uncertain due to transcription errors, do not merge them with unrelated memories.

You MUST always return an object with this exact shape:

{
  "consolidated": [
    {
      "text": "human consolidated memory in English",
      "category": "preference|person|routine|emotion|goal|hobby|health|relationship|event|other",
      "importance": 1-10,
      "privacy": "normal|sensitive|surprise",
      "date": null,
      "follow_up_after": null,
      "should_follow_up": false,
      "people": []
    }
  ]
}

If memories are not strongly related, still return 1 to 3 useful consolidated memories summarizing the most meaningful facts.

Never return an empty consolidated array when at least one input memory has importance >= 5.
If there are memories with importance >= 5, you MUST return at least one consolidated memory.
The input memories are already filtered and considered meaningful. Your task is not to decide whether to keep them, but to consolidate them.

Return ONLY valid JSON.
                `.trim()
              }]
            },
            {
              role: "user",
              content: [{
                type: "input_text",
                text: JSON.stringify(memories)
              }]
            }
          ],
          max_output_tokens: 500
        })
      }
    );

    const raw = await response.text();
    const data = JSON.parse(raw);

    const output =
      data.output_text ||
      data.output?.flatMap(i => i.content || [])
        ?.find(p => p.type === "output_text")?.text ||
      '{"consolidated":[]}';

    let parsedOutput;

try {
  parsedOutput = JSON.parse(output);
} catch {
  parsedOutput = { consolidated: [] };
}

if (Array.isArray(parsedOutput)) {
  parsedOutput = {
    consolidated: parsedOutput
  };
}

if (!parsedOutput.consolidated) {
  parsedOutput = {
    consolidated: []
  };
}

return res.json(parsedOutput);

  } catch (err) {
    console.error("MEMORY CONSOLIDATION ERROR:", err);
    return res.json({
      consolidated: []
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Refleksa backend running on port ${PORT}`);
});
