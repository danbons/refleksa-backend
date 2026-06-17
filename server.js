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
// IDENTITY / PEOPLE ANALYZER
// ===============================
app.post("/identity/analyze", requirePrototypeToken, async (req, res) => {
  try {
    const { text, hasIdentity, knownPeople } = req.body || {};
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
You are Refleksa's multilingual Identity and People command analyzer.

Analyze the user's transcript, even if it contains speech recognition mistakes.

Your job:
1. Detect the language.
2. Detect if the user is trying to say their name.
3. Extract the most likely person name.
4. Detect people admin commands:
   - list known people
   - remove/delete person
   - rename person
5. Return a natural reply in the same language as the user.

Important:
- Be tolerant of pronunciation/transcription mistakes.
- Example: "ma numes Crina" probably means Romanian "mă numesc Crina".
- Example: "mi amo Daniele" may mean Italian "mi chiamo Daniele".
- Example: "my nam is John" means "my name is John".
- Do not invent a name if uncertain.
- If confidence is below 0.75 for name registration, use intent "unclear_name".
- If it is normal conversation, use intent "normal".
Never return action=remove unless the user explicitly asks
to remove, delete, forget or cancel a person.

Normal conversation must always return intent=normal.

Known people:
${JSON.stringify(knownPeople || [])}

Mirror already has owner identity: ${Boolean(hasIdentity)}

Return ONLY valid JSON:
{
  "intent": "register_name|unclear_name|people_admin|normal",
  "language": "it|en|ro|es|fr|de|pt|pl|hu|bg|zh|ar|unknown",
  "name": null or "Name",
  "oldName": null or "OldName",
  "newName": null or "NewName",
  "adminAction": null or "list|remove|rename",
  "confidence": 0.0,
  "reply": null or "natural reply in the user's language"
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
        max_output_tokens: 220
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
