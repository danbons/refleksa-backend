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

function logEngine(message, extra = {}) {

    console.log("");

    console.log("========================================");
    console.log("REFLEKSA AI ENGINE");
    console.log("========================================");

    console.log(message);

    if (Object.keys(extra).length) {
        console.log(extra);
    }

    console.log("========================================");
    console.log("");

}

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

    } finally {

        clearTimeout(timeout);

    }

}

/* ========================================= */
/* OPENAI REALTIME                           */
/* ========================================= */

async function createRealtimeOpenAI(body) {

    const response = await fetchWithTimeout(
        "https://api.openai.com/v1/realtime/client_secrets",
        {
            method: "POST",
            headers: {
                Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify(body)
        }
    );

    const text = await response.text();

    let data;

    try {
        data = JSON.parse(text);
    } catch {
        throw new Error("Invalid OpenAI realtime response.");
    }

    if (!response.ok) {
        throw new Error(
            data.error?.message || "OpenAI realtime failed."
        );
    }

    logEngine("OpenAI realtime session created.", {
        provider: "OPENAI"
    });

    return data;
}

/* ========================================= */
/* QWEN REALTIME                             */
/* ========================================= */

async function createRealtimeQwen(body) {

    throw new Error(
        "Qwen realtime provider not implemented yet."
    );

}

/* ========================================= */
/* OPENAI RESPONSES API                      */
/* ========================================= */

async function callResponsesOpenAI(body) {

    const response = await fetchWithTimeout(
        "https://api.openai.com/v1/responses",
        {
            method: "POST",
            headers: {
                Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify(body)
        }
    );

    const text = await response.text();

    let data;

    try {
        data = JSON.parse(text);
    } catch {
        throw new Error("Invalid OpenAI responses response.");
    }

    if (!response.ok) {
        throw new Error(
            data.error?.message || "OpenAI responses failed."
        );
    }

    logEngine("OpenAI Responses completed.", {
        provider: "OPENAI"
    });

    return data;

}

/* ========================================= */
/* QWEN RESPONSES API                        */
/* ========================================= */

async function callResponsesQwen(body) {

    throw new Error(
        "Qwen Responses provider not implemented yet."
    );

}

/* ========================================= */
/* PUBLIC API                                */
/* ========================================= */

export async function createRealtimeSession(body) {

    const provider = getProvider();

    logEngine("Realtime session requested.", {
        provider
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
/* RESPONSES API                             */
/* ========================================= */

export async function callResponses(body) {

    const provider = getProvider();

    logEngine("Responses request.", {
        provider
    });

    switch (provider) {

        case "QWEN":
            return callResponsesQwen(body);

        case "OPENAI":
        default:
            return callResponsesOpenAI(body);

    }

}

