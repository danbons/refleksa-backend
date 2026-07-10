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
      waitingForName
    } = req.body || {};

    const cleanText = String(text || "").trim();

    if (!cleanText) {
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

    const people = Array.isArray(knownPeople)
      ? knownPeople.filter(Boolean)
      : [];

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
You are Refleksa's multilingual Identity and People Engine.

You support every human language that the model understands.

Never rely on a fixed list of languages.
Never translate the user into a different spoken language.
Detect the language from the user's latest transcript and write the complete reply only in that language.

The transcript may contain speech-recognition errors, incomplete words, accents, phonetic spelling or mixed punctuation.
Interpret meaning carefully and tolerate likely transcription mistakes.
Never invent a person's name when uncertain.

CURRENT IDENTITY CONTEXT

Mirror owner registered:
${Boolean(hasIdentity)}

Known registered people:
${JSON.stringify(people)}

Face currently detected:
${Boolean(faceDetected)}

Face-recognition result:
${recognizedPerson || "unknown"}

Refleksa is currently waiting for the person's name:
${Boolean(waitingForName)}

YOUR TASK

Determine exactly one intent:

1. register_name
The person clearly introduces themselves or gives their name.

2. unclear_name
The person appears to be giving their name, but the name cannot be extracted reliably.

3. people_admin
The user asks to:
- list known registered people
- remove or forget a registered person
- rename a registered person

4. normal
Normal conversation unrelated to identity administration or name registration.

UNKNOWN PERSON BEHAVIOUR

If faceDetected is true and recognizedPerson is missing, null or "unknown", the person is visually unknown.

If the visually unknown person has not introduced themselves:
- politely introduce yourself as Refleksa
- say naturally that you do not appear to know each other yet
- ask their name
- reply entirely in the user's detected language

Do not assume the unknown person is the registered mirror owner.

If waitingForName is true:
- interpret short answers such as a single name as a possible self-introduction
- tolerate imperfect transcription
- return register_name when the name is sufficiently clear
- return unclear_name when it is not sufficiently clear

REGISTERING A NAME

When a name is confidently detected:
- intent must be "register_name"
- return the extracted name
- confidence must reflect certainty
- reply warmly in the user's language
- confirm that Refleksa will remember or recognise them

If confidence is below 0.75:
- use intent "unclear_name"
- do not invent a name
- ask the person to repeat it naturally in the same language

PEOPLE ADMINISTRATION

For list:
- adminAction = "list"
- do not invent people
- use only the supplied knownPeople list
- reply naturally in the user's language

For remove:
- adminAction = "remove"
- extract the requested registered person's name
- do not claim the person has already been removed
- say that the removal request has been understood
- the Android app will perform the actual deletion

For rename:
- adminAction = "rename"
- extract oldName and newName
- do not claim success unless both names are clear
- the Android app will perform the actual rename

NORMAL CONVERSATION

Normal conversation must return:
- intent = "normal"
- adminAction = null
- no invented identity action

OUTPUT RULES

Return ONLY valid JSON.

The "reply" field must always be present for:
- register_name
- unclear_name
- people_admin
- an unknown visible person who should be asked their name

For normal conversation, reply may be null.

Use this exact structure:

{
  "intent": "register_name|unclear_name|people_admin|normal",
  "language": "detected BCP-47-style language code or unknown",
  "name": null,
  "oldName": null,
  "newName": null,
  "adminAction": null,
  "confidence": 0.0,
  "reply": null
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
        max_output_tokens: 260
      })
    });

    const raw = await response.text();

    let data;

    try {
      data = JSON.parse(raw);
    } catch {
      console.error("IDENTITY OPENAI RESPONSE PARSE ERROR:", raw);

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

    if (!response.ok) {
      console.error("IDENTITY OPENAI ERROR:", data);

      return res.status(response.status).json({
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
      console.error("IDENTITY RESULT JSON ERROR:", output);

      parsed = {
        intent: "normal",
        language: "unknown",
        name: null,
        oldName: null,
        newName: null,
        adminAction: null,
        confidence: 0,
        reply: null
      };
    }

    return res.json({
      intent: parsed.intent || "normal",
      language: parsed.language || "unknown",
      name: parsed.name || null,
      oldName: parsed.oldName || null,
      newName: parsed.newName || null,
      adminAction: parsed.adminAction || null,
      confidence: Number(parsed.confidence) || 0,
      reply: parsed.reply || null
    });

  } catch (err) {
    console.error("IDENTITY ANALYZE ERROR:", err);

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
      currentPerson
    } = req.body || {};

    const cleanText = String(text || "").trim();

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

For reminders:
- extract title, date and time only when clear
- use yyyy-MM-dd for exact dates
- use HH:mm for exact times
- do not invent missing information

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
