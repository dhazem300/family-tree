const fs = require("fs");
const path = require("path");

const ENTERTAINMENT_FILE = path.join(__dirname, "data", "assistant-entertainment.json");

let entertainmentCache = null;

function normalizeEntertainmentText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[أإآٱ]/g, "ا")
    .replace(/ى/g, "ي")
    .replace(/ة/g, "ه")
    .replace(/ظ/g, "ز")
    .replace(/[ًٌٍَُِّْـ]/g, "")
    .replace(/[^a-z0-9\u0600-\u06FF]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function loadEntertainment() {
  if (entertainmentCache) return entertainmentCache;
  try {
    const raw = fs.readFileSync(ENTERTAINMENT_FILE, "utf8");
    const parsed = JSON.parse(raw);
    entertainmentCache = {
      jokes: Array.isArray(parsed.jokes) ? parsed.jokes : [],
      riddles: Array.isArray(parsed.riddles) ? parsed.riddles : [],
    };
  } catch (e) {
    console.error("assistant entertainment load error:", e.message || e);
    entertainmentCache = { jokes: [], riddles: [] };
  }
  return entertainmentCache;
}

function pickNonRepeating(list, used = []) {
  if (!Array.isArray(list) || !list.length) return null;
  const usedSet = new Set(used || []);
  let available = list.map((x, i) => ({ x, i })).filter(({ i }) => !usedSet.has(i));
  if (!available.length) {
    used.length = 0;
    available = list.map((x, i) => ({ x, i }));
  }
  const picked = available[Math.floor(Math.random() * available.length)];
  used.push(picked.i);
  if (used.length > 50) used.splice(0, used.length - 50);
  return picked.x;
}

function isJokeRequest(n) {
  return /(نكت|نكته|نكتة|ضحكني|هزار|joke|laugh)/i.test(n);
}

function isRiddleRequest(n) {
  return /(فزور|فزوره|فزورة|فظور|لغز|riddle)/i.test(n);
}

function isMoreRequest(n) {
  return /^(كمان|تاني|واحده كمان|واحدة كمان|قول كمان|مرة كمان|مره كمان|more|again|another one)$/.test(n);
}

function isLikelyWrongRiddleAnswer(n) {
  return n.length > 0 && n.length <= 80;
}

function answerFromEntertainment(question, req) {
  const n = normalizeEntertainmentText(question);
  if (!n) return null;

  const data = loadEntertainment();
  req.session.assistantEntertainment = req.session.assistantEntertainment || {};
  const st = req.session.assistantEntertainment;
  st.usedJokes = Array.isArray(st.usedJokes) ? st.usedJokes : [];
  st.usedRiddles = Array.isArray(st.usedRiddles) ? st.usedRiddles : [];

  // If a riddle is pending, any next short answer should receive the punchline.
  if (st.pendingRiddle && isLikelyWrongRiddleAnswer(n) && !isJokeRequest(n) && !isRiddleRequest(n)) {
    const r = st.pendingRiddle;
    st.pendingRiddle = null;
    const intro = (r.wrong_replies && r.wrong_replies.length)
      ? r.wrong_replies[Math.floor(Math.random() * r.wrong_replies.length)]
      : "لا 😄";
    return { answer: `${intro}\n${r.answer}` };
  }

  if (isJokeRequest(n) || (isMoreRequest(n) && st.lastMode === "joke")) {
    const joke = pickNonRepeating(data.jokes, st.usedJokes);
    st.lastMode = "joke";
    return { answer: joke || "حاضر 😄 بس ملف النكت مش متحمّل عندي." };
  }

  if (isRiddleRequest(n) || (isMoreRequest(n) && st.lastMode === "riddle")) {
    const r = pickNonRepeating(data.riddles, st.usedRiddles);
    if (!r) return { answer: "حاضر 😄 بس ملف الفوازير مش متحمّل عندي." };
    st.lastMode = "riddle";
    st.pendingRiddle = r;
    return { answer: r.question };
  }

  if (isMoreRequest(n)) {
    const joke = pickNonRepeating(data.jokes, st.usedJokes);
    st.lastMode = "joke";
    return { answer: joke || "قولّي تحب نكتة ولا فزورة؟ 😄" };
  }

  return null;
}

module.exports = {
  answerFromEntertainment,
};