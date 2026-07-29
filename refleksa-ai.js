import fetch from "node-fetch";

/*
======================================================
 Refleksa AI Engine
------------------------------------------------------

Central AI Engine for Refleksa.

The Android app never knows which AI provider
is being used.

All provider selection, fallback, monitoring,
retry and routing happen here.

Current providers:

- OpenAI
- Qwen (coming next)

======================================================
*/

const AI_PROVIDER =
    (process.env.AI_PROVIDER || "AUTO")
        .trim()
        .toUpperCase();

const DEFAULT_TIMEOUT = 15000;

/* ========================================= */
/* PROVIDER SELECTION                        */
/* ========================================= */

function getProvider() {

    switch (AI_PROVIDER) {

        case "OPENAI":
            return "OPENAI";

        case "QWEN":
            return "QWEN";

        case "AUTO":
        default:
            return "OPENAI";

    }

}

/* ========================================= */
/* LOGGING                                   */
/* ========================================= */

function logEngine(message, extra = {}) {

    console.log("");

    console.log("========================================");
    console.log("REFLEKSA AI ENGINE");
    console.log("========================================");

    console.log(message);

    if (Object.keys(extra).length > 0) {
        console.log(extra);
    }

    console.log("========================================");
    console.log("");

}

/* ========================================= */
/* FETCH WITH TIMEOUT                        */
/* ========================================= */

async function fetchWithTimeout(url, options = {}) {

    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort();
    }, DEFAULT_TIMEOUT);

    try {

        return await fetch(url, {
            ...options,
            signal: controller.signal
        });

    } catch (error) {

        if (error?.name === "AbortError") {
            throw new Error(
                `AI provider request timed out after ${DEFAULT_TIMEOUT} ms.`
            );
        }

        throw error;

    } finally {

        clearTimeout(timeout);

    }

}

/* ========================================= */
/* SAFE JSON PARSER                          */
/* ========================================= */

function parseJsonResponse(text, provider, operation) {

    try {

        return JSON.parse(text);

    } catch {

        logEngine("Invalid JSON received from AI provider.", {
            provider,
            operation,
            responsePreview: String(text || "").slice(0, 300)
        });

        throw new Error(
            `Invalid ${provider} ${operation} response.`
        );

    }

}

/* ========================================= */
/* OPENAI REALTIME                           */
/* ========================================= */

async function createRealtimeOpenAI(body) {

    const startedAt = Date.now();

    try {

        if (!process.env.OPENAI_API_KEY) {
            throw new Error("Missing OPENAI_API_KEY.");
        }

        const response = await fetchWithTimeout(
            "https://api.openai.com/v1/realtime/client_secrets",
            {
                method: "POST",
                headers: {
                    Authorization:
                        `Bearer ${process.env.OPENAI_API_KEY}`,

                    "Content-Type": "application/json"
                },
                body: JSON.stringify(body)
            }
        );

        const text = await response.text();

        const data = parseJsonResponse(
            text,
            "OpenAI",
            "realtime"
        );

        if (!response.ok) {

            throw new Error(
                data?.error?.message ||
                `OpenAI realtime failed with status ${response.status}.`
            );

        }

        logEngine("OpenAI realtime session created.", {
            provider: "OPENAI",
            status: response.status,
            durationMs: Date.now() - startedAt
        });

        return data;

    } catch (error) {

        logEngine("OpenAI realtime session failed.", {
            provider: "OPENAI",
            durationMs: Date.now() - startedAt,
            error: error?.message || String(error)
        });

        throw error;

    }

}

/* ========================================= */
/* QWEN REALTIME                             */
/* ========================================= */

async function createRealtimeQwen(_body) {

    throw new Error(
        "Qwen realtime provider not implemented yet."
    );

}

/* ========================================= */
/* OPENAI RESPONSES API                      */
/* ========================================= */

async function callResponsesOpenAI(body) {

    const startedAt = Date.now();

    try {

        if (!process.env.OPENAI_API_KEY) {
            throw new Error("Missing OPENAI_API_KEY.");
        }

        const response = await fetchWithTimeout(
            "https://api.openai.com/v1/responses",
            {
                method: "POST",
                headers: {
                    Authorization:
                        `Bearer ${process.env.OPENAI_API_KEY}`,

                    "Content-Type": "application/json"
                },
                body: JSON.stringify(body)
            }
        );

        const text = await response.text();

        const data = parseJsonResponse(
            text,
            "OpenAI",
            "responses"
        );

        if (!response.ok) {

            throw new Error(
                data?.error?.message ||
                `OpenAI Responses failed with status ${response.status}.`
            );

        }

        logEngine("OpenAI Responses completed.", {
            provider: "OPENAI",
            model: body?.model || "unknown",
            status: response.status,
            durationMs: Date.now() - startedAt
        });

        return data;

    } catch (error) {

        logEngine("OpenAI Responses failed.", {
            provider: "OPENAI",
            model: body?.model || "unknown",
            durationMs: Date.now() - startedAt,
            error: error?.message || String(error)
        });

        throw error;

    }

}

/* ========================================= */
/* QWEN RESPONSES API                        */
/* ========================================= */

async function callResponsesQwen(_body) {

    throw new Error(
        "Qwen Responses provider not implemented yet."
    );

}

/* ========================================= */
/* PUBLIC REALTIME API                       */
/* ========================================= */

export async function createRealtimeSession(body) {

    const provider = getProvider();

    logEngine("Realtime session requested.", {
        configuredProvider: AI_PROVIDER,
        selectedProvider: provider
    });

    switch (provider) {

        case "QWEN":
            return createRealtimeQwen(body);

        case "OPENAI":
        default:
            return createRealtimeOpenAI(body);

    }

}

/* ========================================= */
/* PUBLIC RESPONSES API                      */
/* ========================================= */

export async function callResponses(body) {

    const provider = getProvider();

    logEngine("Responses request.", {
        configuredProvider: AI_PROVIDER,
        selectedProvider: provider,
        model: body?.model || "unknown"
    });

    switch (provider) {

        case "QWEN":
            return callResponsesQwen(body);

        case "OPENAI":
        default:
            return callResponsesOpenAI(body);

    }

}

/* ========================================= */
/* STARTUP LOG                               */
/* ========================================= */

logEngine("AI Engine initialized.", {
    configuredProvider: AI_PROVIDER,
    selectedProvider: getProvider(),
    timeoutMs: DEFAULT_TIMEOUT,
    openAIConfigured: Boolean(process.env.OPENAI_API_KEY),
    qwenConfigured: Boolean(process.env.QWEN_API_KEY)
});
