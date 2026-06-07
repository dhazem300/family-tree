const fs = require("fs");
const path = require("path");

/**
 * Optimized Assistant Knowledge Engine
 * - Loads dictionaries once and caches them.
 * - Reads data/assistant-dictionary.json + every .json inside data/assistant-dictionaries.
 * - Pre-normalizes questions/keywords at startup instead of every request.
 * - Builds a token index so each user question checks a small candidate set, not all 10k+ entries.
 */

const ROOT_DIR = __dirname;
const MAIN_DICTIONARY = path.join(ROOT_DIR, "data", "assistant-dictionary.json");
const EXTRA_DICTIONARIES_DIR = path.join(ROOT_DIR, "data", "assistant-dictionaries");

const MAX_CANDIDATES = 300;
const MIN_SCORE = 18;
const CACHE_TTL_MS = 60 * 1000; // checks modified files max once per minute

let cache = {
  loadedAt: 0,
  signature: "",
  items: [],
  tokenIndex: new Map(),
};

function arabicDigitsToEnglish(value) {
  return String(value || "")
    .replace(/[٠-٩]/g, (d) => String("٠١٢٣٤٥٦٧٨٩".indexOf(d)))
    .replace(/[۰-۹]/g, (d) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(d)));
}

function normalizeText(value) {
  return arabicDigitsToEnglish(value)
    .toLowerCase()
    .replace(/[أإآٱ]/g, "ا")
    .replace(/ى/g, "ي")
    .replace(/ة/g, "ه")
    .replace(/ؤ/g, "و")
    .replace(/ئ/g, "ي")
    .replace(/[ًٌٍَُِّْـ]/g, "")
    .replace(/[^a-z0-9\u0600-\u06FF]+/g, " ")
    .replace(/\b(من|عن|على|علي|في|الى|إلى|ل|ال|يا|لو|سمحت|ممكن|please|can|you|the|a|an|to|for|of)\b/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function getTokens(value) {
  const normalized = normalizeText(value);
  if (!normalized) return [];
  return normalized
    .split(" ")
    .map((t) => t.trim())
    .filter((t) => t.length >= 2)
    .slice(0, 18);
}

function collectJsonFiles() {
  const files = [];
  if (fs.existsSync(MAIN_DICTIONARY)) files.push(MAIN_DICTIONARY);

  function walk(dir) {
    if (!fs.existsSync(dir)) return;
    for (const name of fs.readdirSync(dir)) {
      const full = path.join(dir, name);
      const stat = fs.statSync(full);
      if (stat.isDirectory()) walk(full);
      else if (/\.json$/i.test(name)) files.push(full);
    }
  }

  walk(EXTRA_DICTIONARIES_DIR);
  return files;
}

function filesSignature(files) {
  return files
    .map((file) => {
      try {
        const st = fs.statSync(file);
        return `${file}:${st.size}:${st.mtimeMs}`;
      } catch (_) {
        return `${file}:missing`;
      }
    })
    .join("|");
}

function safeReadJson(file) {
  try {
    const raw = fs.readFileSync(file, "utf8");
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed;
    if (Array.isArray(parsed.items)) return parsed.items;
    return [];
  } catch (e) {
    console.error("Assistant dictionary JSON error:", file, e.message || e);
    return [];
  }
}

function prepareItem(raw, sourceFile, index) {
  const questions = Array.isArray(raw.questions) ? raw.questions : [];
  const keywords = Array.isArray(raw.keywords) ? raw.keywords : [];
  const answer = raw.answer || "";
  const answers = Array.isArray(raw.answers) ? raw.answers.filter(Boolean) : null;

  const normalizedQuestions = questions.map(normalizeText).filter(Boolean);
  const normalizedKeywords = keywords.map(normalizeText).filter(Boolean);

  const tokenSet = new Set();
  for (const text of normalizedQuestions) getTokens(text).forEach((t) => tokenSet.add(t));
  for (const text of normalizedKeywords) getTokens(text).forEach((t) => tokenSet.add(t));

  return {
    id: raw.id || `${path.basename(sourceFile)}_${index}`,
    category: raw.category || "general",
    answer,
    answers,
    link: raw.link || "",
    linkLabel: raw.linkLabel || "",
    questions,
    keywords,
    normalizedQuestions,
    normalizedKeywords,
    tokens: [...tokenSet],
    sourceFile,
  };
}

function rebuildCache() {
  const files = collectJsonFiles();
  const signature = filesSignature(files);

  if (cache.signature === signature && cache.items.length) return cache;

  const items = [];
  for (const file of files) {
    const arr = safeReadJson(file);
    arr.forEach((raw, idx) => {
      const prepared = prepareItem(raw, file, idx);
      if (prepared.answer || prepared.answers || prepared.link) {
        items.push(prepared);
      }
    });
  }

  const tokenIndex = new Map();
  items.forEach((it, idx) => {
    for (const token of it.tokens) {
      if (!tokenIndex.has(token)) tokenIndex.set(token, []);
      tokenIndex.get(token).push(idx);
    }
  });

  cache = {
    loadedAt: Date.now(),
    signature,
    items,
    tokenIndex,
  };

  console.log(`Assistant dictionaries optimized: ${files.length} files, ${items.length} items, ${tokenIndex.size} indexed tokens.`);
  return cache;
}

function getCache() {
  const now = Date.now();
  if (!cache.items.length || now - cache.loadedAt > CACHE_TTL_MS) {
    const files = collectJsonFiles();
    const signature = filesSignature(files);
    if (!cache.items.length || signature !== cache.signature) {
      return rebuildCache();
    }
    cache.loadedAt = now;
  }
  return cache;
}

function chooseAnswer(item) {
  if (item.answers && item.answers.length) {
    return item.answers[Math.floor(Math.random() * item.answers.length)];
  }
  return item.answer || "";
}

function scoreItem(queryNorm, queryTokens, item) {
  let score = 0;

  for (const q of item.normalizedQuestions) {
    if (!q) continue;
    if (q === queryNorm) score = Math.max(score, 100);
    else if (q.includes(queryNorm) || queryNorm.includes(q)) score = Math.max(score, 75);
  }

  for (const kw of item.normalizedKeywords) {
    if (!kw) continue;
    if (queryNorm.includes(kw)) score += 14;
  }

  const itemTokens = new Set(item.tokens);
  let shared = 0;
  for (const token of queryTokens) {
    if (itemTokens.has(token)) shared += 1;
  }

  score += shared * 8;

  // Penalize weak matches on very short questions
  if (queryTokens.length <= 2 && score < 75) score -= 10;

  return score;
}

async function answerFromAssistantKnowledge(question) {
  const queryNorm = normalizeText(question);
  if (!queryNorm) return null;

  const queryTokens = getTokens(question);
  if (!queryTokens.length) return null;

  const { items, tokenIndex } = getCache();

  const candidateCounts = new Map();
  for (const token of queryTokens) {
    const indices = tokenIndex.get(token);
    if (!indices) continue;
    for (const idx of indices) {
      candidateCounts.set(idx, (candidateCounts.get(idx) || 0) + 1);
    }
  }

  let candidateIndices = [...candidateCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, MAX_CANDIDATES)
    .map(([idx]) => idx);

  // If no indexed candidates, only then fallback to a limited linear scan.
  if (!candidateIndices.length) {
    candidateIndices = items.slice(0, 250).map((_, idx) => idx);
  }

  let best = null;
  for (const idx of candidateIndices) {
    const it = items[idx];
    if (!it) continue;
    const score = scoreItem(queryNorm, queryTokens, it);
    if (!best || score > best.score) best = { item: it, score };
  }

  if (!best || best.score < MIN_SCORE) return null;

  const answer = chooseAnswer(best.item);
  if (!answer && !best.item.link) return null;

  const response = { answer };
  if (best.item.link) response.link = best.item.link;
  if (best.item.linkLabel) response.linkLabel = best.item.linkLabel;

  return response;
}

function reloadAssistantKnowledge() {
  cache = { loadedAt: 0, signature: "", items: [], tokenIndex: new Map() };
  return rebuildCache();
}

module.exports = {
  answerFromAssistantKnowledge,
  reloadAssistantKnowledge,
  normalizeText,
};