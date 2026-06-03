/* File: /app.js */

async function fetchTree() {
  const r = await fetch("/api/tree");
  return r.json();
}

async function fetchPerson(id) {
  const r = await fetch(`/api/person/${id}`);
  return r.json();
}

async function fetchStats() {
  const r = await fetch("/api/stats");
  return r.json();
}

/* ===== Theme (Light/Dark) ===== */
(function themeInit() {
  const btn = document.getElementById("themeToggle");
  const saved = localStorage.getItem("theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
  document.documentElement.classList.toggle("dark", saved === "dark");

  if (btn) {
    btn.textContent = saved === "light" ? "الوضع: فاتح" : "الوضع: داكن";
  }

  btn?.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    document.documentElement.classList.toggle("dark", next === "dark");
    localStorage.setItem("theme", next);
    btn.textContent = next === "light" ? "الوضع: فاتح" : "الوضع: داكن";
  });
})();

/* ===== Modal ===== */
function openModal(html) {
  const modal = document.getElementById("modal");
  const body = document.getElementById("modalBody");
  if (!modal || !body) return;
  body.innerHTML = html;
  modal.classList.remove("hidden");
}

function closeModal() {
  document.getElementById("modal")?.classList.add("hidden");
}

document.getElementById("closeModal")?.addEventListener("click", closeModal);
document.getElementById("modal")?.addEventListener("click", (e) => {
  if (e.target.id === "modal") closeModal();
});

/* ===== Drawer (Overlay) ===== */
const drawer = document.getElementById("drawer");

function openDrawer() {
  drawer?.classList.add("isOpen");
}

function closeDrawer() {
  drawer?.classList.remove("isOpen");
}

document.getElementById("toggleDetails")?.addEventListener("click", () => {
  drawer?.classList.toggle("isOpen");
});

document.getElementById("closeDrawer")?.addEventListener("click", closeDrawer);

/* ===== Public Stats ===== */
function ensureStatsContainer() {
  let box = document.getElementById("publicStats");
  if (box) return box;

  box = document.createElement("section");
  box.id = "publicStats";
  box.style.marginTop = "18px";
  box.style.padding = "16px";
  box.style.borderRadius = "18px";
  box.style.background = "var(--cardFill, #fff)";
  box.style.border = "1px solid rgba(0,0,0,.08)";
  box.style.boxShadow = "0 8px 24px rgba(0,0,0,.05)";
  box.style.width = "100%";
  box.style.display = "block";
  box.style.clear = "both";

  const tree = document.getElementById("tree");

  // الأفضل: ضع الإحصائيات بعد أقرب section يحتوي الشجرة
  const treeSection =
    tree?.closest("section") ||
    document.querySelector(".tree-viewport")?.closest("section") ||
    document.querySelector(".tree-viewport") ||
    tree?.parentElement;

  if (treeSection?.parentNode) {
    treeSection.parentNode.insertBefore(box, treeSection.nextSibling);
    return box;
  }

  // fallback أخير
  document.querySelector("main")?.appendChild(box);
  return box;
}

function renderPublicStats(stats) {
  const box = ensureStatsContainer();
  if (!box) return;

  const total = Number(stats?.total || 0);
  const males = Number(stats?.males || 0);
  const females = Number(stats?.females || 0);

  box.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
      <div style="font-weight:800;font-size:18px;">إحصائيات العائلة</div>
      <div style="font-size:13px;opacity:.7;">إحصائيات عامة من بيانات الشجرة</div>
    </div>

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;">
      <div style="padding:14px;border-radius:14px;background:rgba(255,255,255,.65);border:1px solid rgba(0,0,0,.06);">
        <div style="font-size:13px;opacity:.7;margin-bottom:6px;">عدد الرجال</div>
        <div style="font-size:28px;font-weight:900;">${males}</div>
      </div>

      <div style="padding:14px;border-radius:14px;background:rgba(255,255,255,.65);border:1px solid rgba(0,0,0,.06);">
        <div style="font-size:13px;opacity:.7;margin-bottom:6px;">عدد النساء</div>
        <div style="font-size:28px;font-weight:900;">${females}</div>
      </div>

      <div style="padding:14px;border-radius:14px;background:rgba(255,255,255,.65);border:1px solid rgba(0,0,0,.06);">
        <div style="font-size:13px;opacity:.7;margin-bottom:6px;">إجمالي الأفراد</div>
        <div style="font-size:28px;font-weight:900;">${total}</div>
      </div>
    </div>
  `;
}

/* ===== Details ===== */
function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function makePersonLinkBlock(label, personObj) {
  if (!personObj || !personObj.id) {
    return `<div><b>${label}:</b> -</div>`;
  }

  return `
    <div>
      <b>${label}:</b>
      <button
        type="button"
        class="person-nav-btn"
        data-person-id="${personObj.id}"
        style="margin-inline-start:6px;padding:5px 10px;border:none;border-radius:999px;cursor:pointer;background:#0f766e;color:#fff;font-weight:700;"
      >
        ${escapeHtml(personObj.name || "عرض")}
      </button>
    </div>
  `;
}

function showDetailsInSide(person) {
  const details = document.getElementById("details");
  if (!details) return;

  const childrenCount = person.children ? person.children.length : 0;
  const photo = (person.photo_url && String(person.photo_url).trim())
    ? String(person.photo_url).trim()
    : "/images/default.png";

  const spousesText = (person.spouses && person.spouses.length)
    ? person.spouses
        .map((s) => `${s.ord ? s.ord + ") " : ""}${escapeHtml(s.spouse_name)}`)
        .join("<br>")
    : "-";

  const childrenHtml = (person.children && person.children.length)
    ? person.children.map((c) => `
        <button
          type="button"
          class="person-nav-btn"
          data-person-id="${c.id}"
          style="margin:4px 4px 0 0;padding:5px 10px;border:none;border-radius:999px;cursor:pointer;background:#0f766e;color:#fff;font-weight:700;"
        >
          ${escapeHtml(c.name)}
        </button>
      `).join("")
    : "-";

  const statusLabel = Number(person.is_deceased || 0) === 1 ? "متوفى" : "حي";
  const genderLabel =
    person.gender === "male" || person.gender === "ذكر"
      ? "ذكر"
      : person.gender === "female" || person.gender === "أنثى" || person.gender === "انثى"
      ? "أنثى"
      : "-";

  const hasBio = Boolean(
    (person.short_bio && String(person.short_bio).trim()) ||
    (person.full_bio && String(person.full_bio).trim()) ||
    (person.notes && String(person.notes).trim())
  );

  const ribbonHtml = Number(person.is_deceased || 0) === 1
    ? `<span style="position:absolute;top:8px;right:-28px;width:90px;height:20px;background:rgba(0,0,0,.88);transform:rotate(45deg);"></span>`
    : "";

  details.innerHTML = `
    <div style="display:grid;gap:14px;">
      <div style="display:flex;gap:14px;align-items:flex-start;flex-wrap:wrap;">
        <div style="position:relative;width:116px;height:116px;border-radius:18px;overflow:hidden;border:1px solid rgba(0,0,0,.08);background:#f3f4f6;flex:0 0 auto;">
          ${ribbonHtml}
          <img
            src="${escapeHtml(photo)}"
            alt="${escapeHtml(person.name || "")}"
            style="width:100%;height:100%;object-fit:cover;display:block;"
            onerror="this.src='/images/default.png'"
          />
        </div>

        <div style="flex:1;min-width:220px;">
          <div style="font-size:24px;font-weight:900;margin-bottom:6px;">${escapeHtml(person.name || "-")}</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <span style="padding:6px 10px;border-radius:999px;background:#eef2ff;font-size:12px;font-weight:800;">${statusLabel}</span>
            <span style="padding:6px 10px;border-radius:999px;background:#f3f4f6;font-size:12px;font-weight:800;">${genderLabel}</span>
          </div>
        </div>
      </div>

      <div class="kvs" style="display:grid;gap:10px;line-height:1.9;">
        <div><b>تاريخ الميلاد:</b> ${escapeHtml(person.birth_date || "-")}</div>
        <div><b>مكان الميلاد:</b> ${escapeHtml(person.birth_place || "-")}</div>
        <div><b>العمل:</b> ${escapeHtml(person.job || "-")}</div>

        ${makePersonLinkBlock("الأب", person.father)}
        ${makePersonLinkBlock("الأم", person.mother)}

        <div>
          <b>الزوج/الزوجة:</b>
          <div style="margin-top:6px;line-height:1.8">${spousesText}</div>
        </div>

        <div>
          <b>الأبناء:</b> ${childrenCount}
          <div style="margin-top:6px;">${childrenHtml}</div>
        </div>

        ${
          Number(person.is_deceased || 0) === 1
            ? `<div><b>تاريخ الوفاة:</b> ${escapeHtml(person.death_date || "-")}</div>
               <div><b>مكان الوفاة:</b> ${escapeHtml(person.death_place || "-")}</div>`
            : ""
        }

        ${
          person.short_bio
            ? `<div><b>نبذة مختصرة:</b><div style="margin-top:6px;line-height:1.9">${escapeHtml(person.short_bio)}</div></div>`
            : ""
        }

        ${
          person.notes
            ? `<div><b>ملاحظات:</b><div style="margin-top:6px;line-height:1.9">${escapeHtml(person.notes)}</div></div>`
            : ""
        }
      </div>

      ${
        hasBio
          ? `
            <div style="padding-top:8px;">
              <a
                href="/honor?personId=${encodeURIComponent(person.id)}"
                style="display:inline-flex;align-items:center;justify-content:center;padding:10px 16px;border-radius:12px;background:#0f766e;color:#fff;text-decoration:none;font-weight:800;"
              >
                اقرأ النبذة
              </a>
            </div>
          `
          : ""
      }
    </div>
  `;

  details.querySelectorAll(".person-nav-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-person-id");
      if (!id) return;
      try {
        const p = await fetchPerson(id);
        showDetailsInSide(p);
        openDrawer();
      } catch (err) {
        console.error("Person navigation error:", err);
      }
    });
  });
}

/* ===== Frame (SVG) ===== */
function starPath(cx, cy, outerR, innerR, points) {
  let path = "";
  const step = Math.PI / points;
  for (let i = 0; i < 2 * points; i++) {
    const r = i % 2 === 0 ? outerR : innerR;
    const a = i * step - Math.PI / 2;
    const x = cx + r * Math.cos(a);
    const y = cy + r * Math.sin(a);
    path += (i === 0 ? "M" : "L") + x + " " + y + " ";
  }
  return path + "Z";
}

function addFrame(g, w, h) {
  g.append("rect")
    .attr("x", -w / 2).attr("y", -h / 2)
    .attr("width", w).attr("height", h)
    .attr("rx", 18).attr("ry", 18)
    .attr("fill", "var(--cardFill)")
    .attr("stroke", "#c7a24b")
    .attr("stroke-width", 2.6);

  g.append("rect")
    .attr("x", -w / 2 + 9).attr("y", -h / 2 + 9)
    .attr("width", w - 18).attr("height", h - 18)
    .attr("rx", 16).attr("ry", 16)
    .attr("fill", "var(--cardInner)")
    .attr("stroke", "#e5e7eb")
    .attr("stroke-width", 1.2);

  const corners = [
    { x: -w / 2 + 20, y: -h / 2 + 20 },
    { x:  w / 2 - 20, y: -h / 2 + 20 },
    { x: -w / 2 + 20, y:  h / 2 - 20 },
    { x:  w / 2 - 20, y:  h / 2 - 20 },
  ];

  corners.forEach((c) => {
    g.append("circle")
      .attr("cx", c.x).attr("cy", c.y).attr("r", 8)
      .attr("fill", "none")
      .attr("stroke", "#c7a24b")
      .attr("stroke-width", 1.8);

    g.append("path")
      .attr("d", starPath(c.x, c.y, 7, 3.4, 8))
      .attr("fill", "#c7a24b")
      .attr("opacity", 0.55);
  });

  g.append("path")
    .attr("d", `M ${-w / 2 + 26} ${22} Q 0 ${10} ${w / 2 - 26} ${22}`)
    .attr("stroke", "#e3c46a")
    .attr("stroke-width", 2)
    .attr("fill", "none")
    .attr("opacity", 0.7);
}

/* ===== Focus Mode ===== */
function getAncestors(node) {
  const arr = [];
  let p = node.parent;
  while (p) {
    arr.push(p);
    p = p.parent;
  }
  return arr;
}

function getChildren(node) {
  return node.children || [];
}

function focusOnNode(clickedNode, allNodesSel, allLinksSel) {
  const visible = new Set([clickedNode, ...getAncestors(clickedNode), ...getChildren(clickedNode)]);

  allNodesSel
    .attr("opacity", (d) => visible.has(d) ? 1 : 0.07)
    .attr("pointer-events", (d) => visible.has(d) ? "auto" : "none");

  allLinksSel
    .attr("opacity", (d) => (visible.has(d.source) && visible.has(d.target)) ? 1 : 0.04);

  return visible;
}

function resetFocus(allNodesSel, allLinksSel) {
  allNodesSel.attr("opacity", 1).attr("pointer-events", "auto");
  allLinksSel.attr("opacity", 1);
  allNodesSel.classed("nodeSelected", false);
}

/* ===== Pan/Zoom + Fit ===== */
let svg, mainG, zoomBehavior;

const __treeState = {
  rootData: null,
  nodesSel: null,
  linksSel: null,
  containerEl: null,
  didInitialView: false,
};

/* ===== Tuning ===== */
const NODE_W = 170;
const NODE_H = 190;
const GAP_X = 90;
const GAP_Y = 110;
const ZOOM_MIN = 0.01;
const ZOOM_MAX = 6;

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function syncSvgSize(containerEl) {
  if (!containerEl || !svg) return;
  const width = containerEl.clientWidth || 1;
  const height = containerEl.clientHeight || 1;
  svg.attr("width", width).attr("height", height).attr("viewBox", [0, 0, width, height]);
}

function fitToScreen(containerEl, padding = 110) {
  if (!containerEl || !mainG || !svg || !zoomBehavior) return;

  const bounds = mainG.node().getBBox();
  const w = containerEl.clientWidth || 1;
  const h = containerEl.clientHeight || 1;

  const fullW = Math.max(1, bounds.width + padding * 2);
  const fullH = Math.max(1, bounds.height + padding * 2);

  const scale = clamp(Math.min(w / fullW, h / fullH), ZOOM_MIN, ZOOM_MAX);
  const tx = (w - bounds.width * scale) / 2 - bounds.x * scale;
  const ty = (h - bounds.height * scale) / 2 - bounds.y * scale;

  const t = d3.zoomIdentity.translate(tx, ty).scale(scale);
  svg.transition().duration(320).call(zoomBehavior.transform, t);
}

function centerNodeInView(node, containerEl, preferredScale = 1.25, duration = 450) {
  if (!node || !containerEl || !svg || !zoomBehavior) return;

  const w = containerEl.clientWidth || 1;
  const h = containerEl.clientHeight || 1;
  const currentTransform = d3.zoomTransform(svg.node());
  const isSmallScreen = window.matchMedia ? window.matchMedia("(max-width: 700px)").matches : window.innerWidth <= 700;

  // على الهاتف نستخدم زووم ثابت ومريح بدل الاعتماد على الزووم الحالي،
  // لأن الزووم الابتدائي قد يكون صغيراً جداً فيجعل الأسماء تبدو فوق بعضها.
  const targetScale = isSmallScreen ? Math.max(preferredScale, 1.55) : preferredScale;
  const scale = clamp(Math.max(currentTransform.k || 1, targetScale), ZOOM_MIN, ZOOM_MAX);

  const tx = (w / 2) - (node.x * scale);
  const ty = (h / 2) - (node.y * scale);
  const t = d3.zoomIdentity.translate(tx, ty).scale(scale);

  svg.transition().duration(duration).call(zoomBehavior.transform, t);
}

function flashTreeNode(targetNode) {
  if (!targetNode || !__treeState.nodesSel) return;

  const domNode = __treeState.nodesSel.filter(n => n === targetNode).node();
  if (!domNode) return;

  const card = d3.select(domNode).select(".svg-node-card");
  if (card.empty()) return;

  card.select(".node-svg-namebox")
    .transition().duration(180)
    .attr("fill", "#FFF5D6")
    .attr("stroke", "#E5B869")
    .attr("stroke-width", 3);

  card.select(".node-svg-portrait-bg")
    .transition().duration(180)
    .attr("stroke", "#E5B869")
    .attr("stroke-width", 4);

  setTimeout(() => updateNodesTheme(), 1400);
}

function normalizeSearchText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[أإآ]/g, "ا")
    .replace(/ى/g, "ي")
    .replace(/ة/g, "ه")
    .replace(/ؤ/g, "و")
    .replace(/ئ/g, "ي")
    .replace(/[ًٌٍَُِّْـ]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function pickBestSearchMatch(allNodes, q) {
  const normalizedQ = normalizeSearchText(q);
  if (!normalizedQ) return null;

  const matches = allNodes
    .map((node) => {
      const name = normalizeSearchText(node.data.name);
      if (!name.includes(normalizedQ)) return null;

      let score = 3;
      if (name === normalizedQ) score = 0;
      else if (name.startsWith(normalizedQ)) score = 1;
      else if (name.split(" ").some((part) => part.startsWith(normalizedQ))) score = 2;

      return { node, score, nameLength: name.length };
    })
    .filter(Boolean)
    .sort((a, b) => a.score - b.score || a.nameLength - b.nameLength);

  return matches.length ? matches[0].node : null;
}

function initialRootAndChildrenView(containerEl, rootHierarchy, padding = 120) {
  if (!containerEl || !svg || !zoomBehavior) return;

  const w = containerEl.clientWidth || 1;
  const h = containerEl.clientHeight || 1;

  const nodes = rootHierarchy.descendants().filter((n) => n.depth === 0 || n.depth === 1);
  if (!nodes.length) return;

  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const n of nodes) {
    const x0 = n.x - NODE_W / 2;
    const x1 = n.x + NODE_W / 2;
    const y0 = n.y - 90;
    const y1 = n.y + (NODE_H - 70);

    minX = Math.min(minX, x0);
    maxX = Math.max(maxX, x1);
    minY = Math.min(minY, y0);
    maxY = Math.max(maxY, y1);
  }

  const bw = Math.max(1, maxX - minX);
  const bh = Math.max(1, maxY - minY);
  const fullW = bw + padding * 2;
  const fullH = bh + padding * 2;

  const scale = clamp(Math.min(w / fullW, h / fullH) * 1.06, ZOOM_MIN, ZOOM_MAX);
  const tx = (w - bw * scale) / 2 - minX * scale;
  const ty = (h - bh * scale) / 2 - minY * scale;

  const t = d3.zoomIdentity.translate(tx, ty).scale(scale);
  svg.transition().duration(420).call(zoomBehavior.transform, t);
}

/* ===== Helpers: Theme + Node HTML ===== */
function getCurrentTheme() {
  const isDark = document.documentElement.classList.contains("dark")
    || document.documentElement.getAttribute("data-theme") === "dark";
  return isDark ? "dark" : "light";
}

function normalizeImageUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) return "/images/default.png";
  if (/^https?:\/\//i.test(raw)) return raw;
  const normalized = raw.startsWith("/") ? raw : "/" + raw;
  // Keep slashes readable while safely encoding Arabic/spaces for SVG image hrefs.
  return encodeURI(normalized);
}

// أضفنا خصائص `person-node` و `data-id` هنا
function buildNodeHtml({ id, photo, name, sub, isDeceased }, theme, nodeW, nodeH) {
  const safePhoto = String(photo || "/images/default.png").replace(/"/g, "%22");
  const safeName = String(name || "").replace(/"/g, "%22");
  const ribbon = isDeceased
    ? `<span style="position:absolute;top:10px;right:-30px;width:94px;height:18px;background:rgba(0,0,0,.9);transform:rotate(45deg);z-index:3;"></span>`
    : "";

  if (theme === "light") {
    return `
      <div class="flex flex-col items-center person-node" data-id="${id}" style="width:${nodeW}px;height:${nodeH}px;">
        <div class="node-portrait" style="position:relative;overflow:hidden;">
          ${ribbon}
          <img class="w-full h-full object-cover"
               src="${safePhoto}"
               alt="${safeName}"
               onerror="this.src='/images/default.png'"/>
        </div>
        <div class="name-box">
          <div class="node-label-text font-bold text-lg leading-tight">${name}</div>
          ${sub ? `<div class="node-label-text text-[10px] opacity-60">${sub}</div>` : ``}
        </div>
      </div>
    `;
  }

  const boxBg = "#16191E";
  const boxBd = "rgba(212,175,55,.55)";
  const nameCol = "#FDFBF7";
  const subCol = "rgba(253,251,247,.70)";
  const photoBg = "#0F1115";
  const photoBd = "#D4AF37";

  return `
    <div class="flex flex-col items-center person-node" data-id="${id}" style="width:${nodeW}px;height:${nodeH}px;">
      <div class="node-portrait" style="position:relative;overflow:hidden;background:${photoBg}; border-color:${photoBd};">
        ${ribbon}
        <img
          style="width:100%;height:100%;object-fit:contain;display:block;padding:6px;background:${photoBg};"
          src="${safePhoto}"
          alt="${safeName}"
          onerror="this.src='/images/default.png'"
        />
      </div>
      <div class="name-box" style="background:${boxBg}; border-color:${boxBd};">
        <div class="node-label-text font-bold text-lg leading-tight" style="color:${nameCol};">${name}</div>
        ${sub ? `<div class="node-label-text text-[10px]" style="color:${subCol};">${sub}</div>` : ``}
      </div>
    </div>
  `;
}

function truncateNodeText(value, max = 16) {
  const txt = String(value || "").trim();
  if (txt.length <= max) return txt;
  return txt.slice(0, max - 1) + "…";
}

function updateNodesTheme() {
  if (!__treeState.nodesSel) return;

  const theme = getCurrentTheme();

  __treeState.nodesSel.each(function (d) {
    const g = d3.select(this);
    const fo = g.select("foreignObject");
    if (fo.empty()) return;

    const id = d.data.id;
    const photo = normalizeImageUrl(d.data.photo_url);
    const name = (d.data.name || "").toString();
    const sub = d.data.birth_date ? String(d.data.birth_date) : "";
    const isDeceased = Number(d.data.is_deceased || 0) === 1;

    const div = fo.select("div");
    const html = buildNodeHtml({ id, photo, name, sub, isDeceased }, theme, NODE_W, NODE_H);

    if (!div.empty()) {
      div.html(html);
    } else {
      fo.append("xhtml:div").html(html);
    }
  });
}

(function watchThemeChanges() {
  const root = document.documentElement;
  let last = getCurrentTheme();

  const obs = new MutationObserver(() => {
    const now = getCurrentTheme();
    if (now === last) return;
    last = now;
    updateNodesTheme();
  });

  obs.observe(root, { attributes: true, attributeFilter: ["data-theme", "class"] });
})();

/* ===== Render ===== */
function renderTree(rootData) {
  const container = document.getElementById("tree");
  if (!container) return;

  container.innerHTML = "";

  const width = container.clientWidth || 1;
  const height = container.clientHeight || 1;

  svg = d3.select(container).append("svg")
    .attr("width", width)
    .attr("height", height)
    .attr("viewBox", [0, 0, width, height]);

  mainG = svg.append("g").attr("class", "mainG");

  zoomBehavior = d3.zoom()
    .scaleExtent([ZOOM_MIN, ZOOM_MAX])
    .on("zoom", (event) => mainG.attr("transform", event.transform));

  svg.call(zoomBehavior);

  const root = d3.hierarchy(rootData);

  const treeLayout = d3.tree()
    .nodeSize([NODE_W + GAP_X, NODE_H + GAP_Y])
    .separation((a, b) => (a.parent === b.parent ? 1.0 : 1.15));

  treeLayout(root);

  function curvedLink(d) {
    const sx = d.source.x;
    const sy = d.source.y + 80;
    const tx = d.target.x;
    const ty = d.target.y - 10;
    const midY = (sy + ty) / 2;
    return `M${sx},${sy} C${sx},${midY} ${tx},${midY} ${tx},${ty}`;
  }

  const links = mainG.append("g")
    .selectAll("path")
    .data(root.links())
    .join("path")
    .attr("class", "link")
    .attr("d", curvedLink)
    .attr("fill", "none")
    .attr("stroke", "#8B5E3C")
    .attr("stroke-width", 3)
    .attr("stroke-linecap", "round")
    .attr("opacity", 0.85);

  const nodes = mainG.append("g")
    .selectAll("g")
    .data(root.descendants())
    .join("g")
    .attr("class", "nodeCard")
    .attr("transform", (d) => `translate(${d.x},${d.y})`);

  nodes.each(function (d) {
    const g = d3.select(this);

    const id = d.data.id;
    const photo = normalizeImageUrl(d.data.photo_url);
    const name = (d.data.name || "").toString();
    const sub = d.data.birth_date ? String(d.data.birth_date) : "";
    const isDeceased = Number(d.data.is_deceased || 0) === 1;

    const fo = g.append("foreignObject")
      .attr("x", -NODE_W / 2)
      .attr("y", -70)
      .attr("width", NODE_W)
      .attr("height", NODE_H)
      .style("overflow", "visible")
      .style("pointer-events", "all");

    const theme = getCurrentTheme();
    fo.append("xhtml:div").html(
      buildNodeHtml({ id, photo, name, sub, isDeceased }, theme, NODE_W, NODE_H)
    );
  });

  let lastNodeActivationAt = 0;
  async function activateNode(event, d) {
    event?.stopPropagation?.();
    if (event?.type === "touchend") event.preventDefault?.();

    const now = Date.now();
    if (now - lastNodeActivationAt < 320) return;
    lastNodeActivationAt = now;

    try {
      const p = await fetchPerson(d.data.id);
      showDetailsInSide(p);
      openDrawer();

      resetFocus(nodes, links);
      nodes.classed("nodeSelected", (n) => n === d);
      focusOnNode(d, nodes, links);
    } catch (err) {
      console.error("node details error:", err);
    }
  }

  nodes
    .style("pointer-events", "all")
    .on("click", activateNode)
    .on("touchend", activateNode);

  function focusTreePersonById(personId, options = {}) {
    if (!personId) return false;

    const targetNode = root.descendants().find(node => String(node.data.id) === String(personId));
    if (!targetNode) return false;

    resetFocus(nodes, links);
    focusOnNode(targetNode, nodes, links);
    nodes.classed("nodeSelected", node => node === targetNode);

    centerNodeInView(
      targetNode,
      container,
      options.preferredScale || 1.45,
      options.duration || 650
    );

    flashTreeNode(targetNode);

    if (options.openDetails !== false) {
      fetchPerson(targetNode.data.id).then(person => {
        showDetailsInSide(person);
        openDrawer();
      }).catch(err => console.error("focusTreePersonById fetch error:", err));
    }

    return true;
  }

  // تستخدمها أزرار السير الذاتية أو أي رابط خارجي يريد فتح مكان الشخص مباشرة.
  window.__focusTreePersonById = focusTreePersonById;

  // إضافة معالجة تحديد الشخص عبر الرابط (focus أو highlight URL parameter)
  const params = new URLSearchParams(window.location.search);
  const focusId = params.get("focus") || params.get("highlight");

  if (focusId) {
    setTimeout(() => {
      focusTreePersonById(focusId, { preferredScale: 1.55, duration: 750, openDetails: true });
    }, 520);
  }

  svg.on("click", (event) => {
    const target = event?.target;
    if (!target) return;
    if (target.closest?.(".nodeCard")) return;
    resetFocus(nodes, links);
  });

  document.getElementById("resetView").onclick = () => {
    resetFocus(nodes, links);
    fitToScreen(container, 110);
  };

  document.getElementById("zoomIn").onclick = () => {
    svg.transition().duration(150).call(zoomBehavior.scaleBy, 1.18);
  };

  document.getElementById("zoomOut").onclick = () => {
    svg.transition().duration(150).call(zoomBehavior.scaleBy, 0.85);
  };

  document.getElementById("fit").onclick = () => {
    fitToScreen(container, 110);
  };

  document.getElementById("focusMode").onclick = () => {
    openModal(`
      <h3 style="margin:0 0 10px 0">وضع التركيز</h3>
      <p>اضغط على شخص: يظهر الشخص + الآباء + الأبناء المباشرين، ويخفي الإخوة وباقي الفروع.</p>
      <p>اضغط خارج الأشخاص أو على "عرض الشجرة كاملة" للعودة.</p>
    `);
  };

  const searchInput = document.getElementById("search");
  if (searchInput) {
    const suggestionsBox = document.getElementById("searchSuggestions");
    const emptyMessageBox = document.getElementById("searchEmptyMessage");
    const clearSearchBtn = document.getElementById("clearSearch");
    let lastMatchedId = null;
    let searchTimer = null;

    const hideSearchUi = () => {
      suggestionsBox?.classList.add("hidden");
      if (suggestionsBox) suggestionsBox.innerHTML = "";
      emptyMessageBox?.classList.add("hidden");
      if (emptyMessageBox) emptyMessageBox.textContent = "";
    };

    const setClearButtonState = () => {
      clearSearchBtn?.classList.toggle("is-visible", Boolean(searchInput.value.trim()));
    };

    const showSearchEmptyMessage = () => {
      suggestionsBox?.classList.add("hidden");
      if (suggestionsBox) suggestionsBox.innerHTML = "";
      if (emptyMessageBox) {
        emptyMessageBox.textContent = "هذا الفرد غير موجود أو لم تتم إضافته بعد.";
        emptyMessageBox.classList.remove("hidden");
      }
    };

    const applySearchHighlight = (matchedNodes, targetNode) => {
      const matchedSet = new Set(matchedNodes);
      nodes
        .attr("opacity", (d) => matchedSet.has(d) ? 1 : 0.12)
        .attr("pointer-events", (d) => matchedSet.has(d) ? "auto" : "none")
        .classed("nodeSelected", (d) => d === targetNode);
      links.attr("opacity", 0.08);
    };

    const renderSearchSuggestions = (matchedNodes, targetNode) => {
      if (!suggestionsBox || matchedNodes.length < 1) {
        suggestionsBox?.classList.add("hidden");
        if (suggestionsBox) suggestionsBox.innerHTML = "";
        return;
      }

      suggestionsBox.innerHTML = matchedNodes.slice(0, 8).map((node, index) => `
        <button class="search-suggestion-item ${node === targetNode ? "is-active" : ""}" type="button" data-person-id="${String(node.data.id).replace(/"/g, "&quot;")}">
          <span>${escapeHtml(node.data.name || "بدون اسم")}</span>
          <span class="search-suggestion-count">${index + 1}</span>
        </button>
      `).join("");

      suggestionsBox.classList.remove("hidden");
      suggestionsBox.querySelectorAll(".search-suggestion-item").forEach((btn) => {
        btn.addEventListener("click", () => {
          const personId = btn.getAttribute("data-person-id");
          const selectedNode = root.descendants().find(node => String(node.data.id) === String(personId));
          if (!selectedNode) return;
          searchInput.value = selectedNode.data.name || "";
          setClearButtonState();
          hideSearchUi();
          lastMatchedId = selectedNode.data.id;
          applySearchHighlight([selectedNode], selectedNode);
          centerNodeInView(selectedNode, container, 1.45, 520);
          flashTreeNode(selectedNode);
          fetchPerson(selectedNode.data.id).then(person => {
            showDetailsInSide(person);
            openDrawer();
          }).catch(err => console.error("search suggestion fetch error:", err));
        });
      });
    };

    const clearSearch = () => {
      clearTimeout(searchTimer);
      searchInput.value = "";
      lastMatchedId = null;
      setClearButtonState();
      hideSearchUi();
      resetFocus(nodes, links);
    };

    clearSearchBtn?.addEventListener("click", clearSearch);

    searchInput.oninput = () => {
      const q = searchInput.value.trim();
      const normalizedQ = normalizeSearchText(q);
      setClearButtonState();
      clearTimeout(searchTimer);

      if (!normalizedQ) {
        lastMatchedId = null;
        hideSearchUi();
        resetFocus(nodes, links);
        return;
      }

      const allTreeNodes = root.descendants();
      const matchedNodes = allTreeNodes.filter((d) => {
        return normalizeSearchText(d.data.name).includes(normalizedQ);
      }).sort((a, b) => normalizeSearchText(a.data.name).length - normalizeSearchText(b.data.name).length);

      if (!matchedNodes.length) {
        lastMatchedId = null;
        nodes.attr("opacity", 0.18).attr("pointer-events", "auto").classed("nodeSelected", false);
        links.attr("opacity", 0.08);
        showSearchEmptyMessage();
        return;
      }

      emptyMessageBox?.classList.add("hidden");
      const targetNode = pickBestSearchMatch(allTreeNodes, q) || matchedNodes[0];
      applySearchHighlight(matchedNodes, targetNode);
      renderSearchSuggestions(matchedNodes, targetNode);

      // الانتقال التلقائي لموقع الشخص فقط بدون فتح تبويبة التفاصيل.
      // تبويبة التفاصيل تفتح فقط عند الضغط على اسم نتيجة البحث أو الضغط على الشخص داخل الشجرة.
      if (targetNode && String(targetNode.data.id) !== String(lastMatchedId)) {
        lastMatchedId = targetNode.data.id;
        searchTimer = setTimeout(() => {
          applySearchHighlight(matchedNodes, targetNode);
          centerNodeInView(targetNode, container, 1.42, 520);
          flashTreeNode(targetNode);
        }, 180);
      }
    };

    searchInput.addEventListener("keydown", (event) => {
      if (event.key === "Escape") clearSearch();
      if (event.key === "Enter") {
        event.preventDefault();
        const firstResult = suggestionsBox?.querySelector(".search-suggestion-item");
        firstResult?.click();
      }
    });

    document.addEventListener("click", (event) => {
      if (!event.target.closest?.("#search") && !event.target.closest?.("#searchSuggestions") && !event.target.closest?.("#clearSearch")) {
        suggestionsBox?.classList.add("hidden");
      }
    });
  }

  if (!__treeState.didInitialView) {
    __treeState.didInitialView = true;
    setTimeout(() => initialRootAndChildrenView(container, root, 130), 0);
  }

  window.addEventListener("resize", () => {
    clearTimeout(window.__fitTimer);
    window.__fitTimer = setTimeout(() => {
      syncSvgSize(container);
      initialRootAndChildrenView(container, root, 130);
    }, 160);
  });

  __treeState.rootData = rootData;
  __treeState.nodesSel = nodes;
  __treeState.linksSel = links;
  __treeState.containerEl = container;

  updateNodesTheme();
}

/* ===== Init ===== */
(async function init() {
  try {
    const [root, stats] = await Promise.all([
      fetchTree(),
      fetchStats().catch(() => null),
    ]);

    if (stats) {
      renderPublicStats(stats);
    }

    if (!root) {
      const tree = document.getElementById("tree");
      if (tree) {
        tree.innerHTML = "<div style='padding:14px;color:var(--muted)'>لا توجد بيانات بعد.</div>";
      }
      return;
    }

    renderTree(root);
  } catch (e) {
    console.error("Tree render error:", e);
    const tree = document.getElementById("tree");
    if (tree) {
      tree.innerHTML = "<div style='padding:14px;color:var(--muted)'>حدث خطأ أثناء تحميل الشجرة. افتح Console لمعرفة السبب.</div>";
    }
  }
})();