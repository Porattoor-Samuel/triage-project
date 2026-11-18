(() => {
  const ROOT_ID = "triage-extension-root";
  const MAX_HISTORY = 100;
  const TRUSTED_DOMAINS = ["woxsen.edu.in"];
  const FREE_MAIL_DOMAINS = new Set([
    "gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com",
    "rediffmail.com", "proton.me", "protonmail.com", "icloud.com", "aol.com", "mail.com",
  ]);
  const URL_SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rb.gy", "ow.ly", "shorturl.at",
  ]);
  const SUSPICIOUS_TLDS = new Set([
    "xyz", "top", "click", "tk", "ml", "gq", "cf", "ga", "work", "loan", "zip", "country",
  ]);

  const RULES = {
    payment: [
      "registration fee", "processing fee", "security deposit", "refundable", "payment", "pay",
      "deposit", "transfer", "send money", "upi", "bank details", "gift card", "wire",
    ],
    urgency: [
      "urgent", "urgently", "immediately", "act now", "last chance", "asap", "right away",
      "within 24 hours", "within 12 hours", "within 48 hours", "expires today", "final warning", "hurry",
    ],
    promise: [
      "guaranteed", "100% placement", "100% guaranteed", "no interview", "no experience needed",
      "earn from home", "lottery", "you have won", "selected without",
    ],
    credentials: [
      "password", "otp", "one time password", "verify your account", "confirm your credentials",
      "log in", "login", "sign in", "account suspended", "account will be suspended",
      "account will be blocked", "update your details", "cvv", "pin number",
    ],
    officialClaims: [
      "placement cell", "examination cell", "exam cell", "registrar", "university", "dean",
      "head of department", "hod", "admin office", "college administration", "principal",
    ],
    highPriority: [
      "exam*", "hall ticket", "admit card", "end-semester", "mid-semester", "timetable", "datesheet",
      "last date", "deadline", "registration closes", "placement drive", "interview", "shortlisted",
      "result*", "fee due", "mandatory", "attendance shortage", "detained", "viva",
    ],
    urgentPriority: ["urgent*", "immediately", "asap", "action required", "reminder", "last chance", "important", "within"],
    lowPriority: [
      "newsletter", "unsubscribe", "weekly digest", "digest", "promotion*", "discount",
      "no action required", "fyi", "for your information",
    ],
    topics: {
      Academics: [
        "exam*", "timetable", "hall ticket", "assignment*", "syllabus", "lecture*", "class*", "semester",
        "faculty", "course*", "grade*", "marks", "result*", "lab", "quiz*", "attendance", "professor",
        "internal assessment", "viva", "datesheet", "academic*",
      ],
      "Internship/Placement": [
        "internship*", "placement*", "recruit*", "drive", "job*", "offer letter", "stipend", "interview*",
        "resume", "hiring", "shortlisted", "career*", "ctc", "offer",
      ],
      Hostel: ["hostel*", "warden", "mess", "room*", "laundry", "curfew", "roommate*", "accommodation", "inmate*"],
      "Clubs/Events": [
        "club*", "event*", "fest", "festival", "workshop*", "hackathon*", "competition*", "seminar*",
        "cultural", "sports", "volunteer*", "society", "concert", "webinar*", "meetup",
      ],
      Administrative: [
        "fee", "fees", "scholarship*", "certificate*", "id card", "bonafide", "library", "transport",
        "office", "registrar", "admission*", "document*", "form", "enrolment", "enrollment", "refund*", "transcript",
      ],
    },
  };

  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);

  function findTerms(text, terms) {
    const lower = text.toLowerCase();
    return terms.filter((term) => {
      const source = term.endsWith("*") ? term.slice(0, -1) + "\\w*" : escapeRegExp(term) + "(?:s|es)?";
      return new RegExp(`(?<!\\w)${source}(?!\\w)`, "i").test(lower);
    }).map((term) => {
      const source = term.endsWith("*") ? term.slice(0, -1) + "\\w*" : escapeRegExp(term) + "(?:s|es)?";
      return lower.match(new RegExp(`(?<!\\w)${source}(?!\\w)`, "i"))?.[0] ?? term;
    });
  }

  function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function getDomain(sender) {
    const match = sender.match(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/i);
    return match?.[1]?.toLowerCase() ?? "";
  }

  function isTrusted(domain) {
    return TRUSTED_DOMAINS.some((item) => domain === item || domain.endsWith(`.${item}`));
  }

  function isLookalike(domain) {
    return Boolean(domain) && !isTrusted(domain) &&
      TRUSTED_DOMAINS.some((item) => domain.includes(item.split(".")[0]));
  }

  function scoreThreat(email) {
    const text = `${email.subject}\n${email.body}`;
    const evidence = [];
    const amount = /(?:₹|\brs\.?|\binr\b|\busd\b|\$)\s?\d[\d,]*/i.test(text);
    const payment = findTerms(text, RULES.payment);
    if (amount && payment.length) evidence.push({ rule: "Payment request", detail: `Amount with payment wording: ${payment[0]}`, weight: 3 });
    else if (payment.length) evidence.push({ rule: "Mentions payment", detail: payment[0], weight: 1 });

    const urgency = findTerms(text, RULES.urgency);
    if (urgency.length) evidence.push({ rule: "Urgent wording", detail: urgency.slice(0, 3).join(", "), weight: 2 });
    const promises = findTerms(text, RULES.promise);
    if (promises.length) evidence.push({ rule: "Unrealistic promise", detail: promises.slice(0, 3).join(", "), weight: 2 });
    const credentials = findTerms(text, RULES.credentials);
    if (credentials.length) evidence.push({ rule: "Asks for login / account details", detail: credentials.slice(0, 3).join(", "), weight: 3 });

    const linkRules = new Map();
    for (const link of email.links) {
      let host;
      try { host = new URL(link).hostname.toLowerCase(); } catch { continue; }
      const tld = host.split(".").at(-1);
      if (URL_SHORTENERS.has(host)) linkRules.set("Shortened link hides the destination", { detail: link, weight: 2 });
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) linkRules.set("Link points to a raw IP address", { detail: link, weight: 3 });
      if (link.split("//")[1]?.split("/")[0]?.includes("@")) linkRules.set("Link contains '@' (disguised address)", { detail: link, weight: 2 });
      if (host.includes("xn--")) linkRules.set("Link uses punycode (look-alike characters)", { detail: link, weight: 2 });
      if (SUSPICIOUS_TLDS.has(tld)) linkRules.set(`Link uses uncommon '.${tld}' domain`, { detail: link, weight: 2 });
      if ((host.match(/-/g) ?? []).length >= 3) linkRules.set("Link domain has many hyphens", { detail: link, weight: 1 });
      if (isLookalike(host)) linkRules.set("Link imitates the official domain", { detail: link, weight: 3 });
      if (link.toLowerCase().startsWith("http://") && (credentials.length || amount)) {
        linkRules.set("Unencrypted (http) link on a sensitive request", { detail: link, weight: 1 });
      }
    }
    for (const [rule, item] of linkRules) evidence.push({ rule, ...item });

    const domain = getDomain(email.sender);
    if (isLookalike(domain)) evidence.push({ rule: "Sender domain imitates the official domain", detail: domain, weight: 3 });
    else if (FREE_MAIL_DOMAINS.has(domain) && findTerms(text, RULES.officialClaims).length) {
      evidence.push({ rule: "Official-sounding message from a free mail address", detail: domain, weight: 2 });
    } else if (domain && isTrusted(domain)) {
      evidence.push({ rule: "Sender domain matches trusted list (not identity verification)", detail: domain, weight: -2 });
    }

    const score = Math.max(0, evidence.reduce((total, item) => total + item.weight, 0));
    const label = score >= 5 ? "Suspicious" : score >= 2 ? "Needs caution" : "No warning signs found";
    return { label, score, evidence };
  }

  function scorePriority(email, threat) {
    const text = `${email.subject}\n${email.body}`;
    const evidence = [];
    const important = findTerms(text, RULES.highPriority);
    const urgent = findTerms(text, RULES.urgentPriority);
    if (important.length) evidence.push({ rule: `Important keyword: ${important[0]}`, weight: 2 });
    if (urgent.length) evidence.push({ rule: `Urgency keyword: ${urgent[0]}`, weight: 1 });
    if (/\b(today|tomorrow|within\s+(?:12|24|48)\s+hours)\b/i.test(text)) {
      evidence.push({ rule: "Deadline appears very near", weight: important.length || urgent.length ? 3 : 1 });
    }
    if (threat.label === "Suspicious") evidence.push({ rule: "Flagged as suspicious - review promptly", weight: 3 });
    if (findTerms(text, RULES.lowPriority).length) evidence.push({ rule: "Low-importance wording", weight: -2 });
    const score = evidence.reduce((total, item) => total + item.weight, 0);
    return { label: score >= 3 ? "High" : score <= -1 ? "Low" : "Normal", score, evidence };
  }

  function scoreTopic(email) {
    const scores = {};
    for (const [topic, terms] of Object.entries(RULES.topics)) {
      const subjectHits = findTerms(email.subject, terms);
      const bodyHits = findTerms(email.body, terms).filter((hit) => !subjectHits.some((item) => item.toLowerCase() === hit.toLowerCase()));
      const score = subjectHits.length * 2 + bodyHits.length;
      if (score >= 2) scores[topic] = score;
    }
    const order = Object.keys(RULES.topics);
    const topic = Object.keys(scores).sort((a, b) => scores[b] - scores[a] || order.indexOf(a) - order.indexOf(b))[0] ?? "Other";
    return topic;
  }

  function analyze(email) {
    const threat = scoreThreat(email);
    const priority = scorePriority(email, threat);
    return {
      ...email,
      threat: threat.label,
      threatScore: threat.score,
      threatEvidence: threat.evidence,
      priority: priority.label,
      priorityScore: priority.score,
      priorityEvidence: priority.evidence,
      topic: scoreTopic(email),
      analyzedAt: new Date().toISOString(),
    };
  }

  function visible(element) {
    return Boolean(element && element.getClientRects().length);
  }

  function readEmail() {
    const isGmail = location.hostname === "mail.google.com";
    let bodyNode;
    let subject = "";
    let sender = "";

    if (isGmail) {
      const bodies = [...document.querySelectorAll(
        '[role="main"] .a3s, .a3s, [role="main"] .ii.gt',
      )].filter((node) => visible(node) && node.innerText?.trim().length > 20);
      bodyNode = bodies.at(-1);
      subject = document.querySelector('[role="main"] h2.hP, h2.hP, [role="main"] h2')?.innerText?.trim() ?? "";
      const message = bodyNode?.closest(".adn, [role='listitem']") ?? bodyNode?.parentElement;
      sender = message?.querySelector("[email], .gD")?.getAttribute("email") ??
        message?.querySelector(".gD")?.getAttribute("name") ?? "";
    } else {
      const main = document.querySelector('[role="main"], main') ?? document.body;
      const candidates = [
        ...main.querySelectorAll(
          '[data-testid*="message-body"], [aria-label*="Message body" i], [role="document"], [class*="allowTextSelection"]',
        ),
      ].filter((node) => visible(node) && node.innerText?.trim().length > 30 && node.innerText.trim().length < 50000);
      bodyNode = candidates.sort((a, b) => (b.innerText?.length ?? 0) - (a.innerText?.length ?? 0))[0];
      const headings = [...main.querySelectorAll('[role="heading"], h1, h2')].filter(visible);
      subject = headings.at(-1)?.innerText?.trim() ?? "";
      let senderScope = bodyNode;
      for (let depth = 0; depth < 5 && senderScope && !senderScope.querySelector("[email], a[href^='mailto:'], [title*='@']"); depth++) {
        senderScope = senderScope.parentElement;
      }
      const senderNode = senderScope?.querySelector("[email], a[href^='mailto:'], [title*='@']");
      sender = senderNode?.getAttribute("email") ??
        senderNode?.getAttribute("title") ??
        senderNode?.getAttribute("href")?.replace(/^mailto:/i, "") ??
        "";
    }

    if (!bodyNode || !bodyNode.innerText?.trim()) return null;
    const body = bodyNode.innerText.trim();
    const links = [...new Set([...bodyNode.querySelectorAll("a[href]")].map((link) => link.href).filter((url) => /^https?:/i.test(url)))];
    return {
      sender,
      subject,
      body,
      links,
      id: `${location.hostname}:${location.pathname}${location.hash}:${subject}:${sender}:${body.slice(0, 120)}`,
    };
  }

  function buildPanel() {
    if (document.getElementById(ROOT_ID)) return document.getElementById(ROOT_ID).shadowRoot;
    const host = document.createElement("div");
    host.id = ROOT_ID;
    if (location.hostname === "mail.google.com") host.dataset.mailClient = "gmail";
    host.style.cssText = "all:initial;display:block;position:fixed;z-index:2147483647;right:-16px;top:7px;width:330px;";
    document.documentElement.append(host);
    const shadow = host.attachShadow({ mode: "open" });
    shadow.innerHTML = `
      <style>
        :host { all: initial; }
        * { box-sizing: border-box; }
        .toggle { border:0;border-radius:7px;background:#7394ED;color:#17181E;padding:9px 13px;font:600 12px "Segoe UI",Arial,sans-serif;cursor:pointer;box-shadow:0 4px 14px rgba(0,0,0,.32); }
        :host([data-mail-client="gmail"]) .toggle { transform:translateY(4px); }
        .toggle:hover { background:#8AA7F2; }
        .panel { display:none;width:330px;margin:7px 0 0 -16px;padding:14px;border:1px solid #454754;border-radius:8px;background:#202127;color:#F0F1F5;font:13px/1.45 "Segoe UI",Arial,sans-serif;box-shadow:0 12px 32px rgba(0,0,0,.48); }
        .panel.open { display:block; }
        .head { display:flex;justify-content:space-between;align-items:center;margin-bottom:9px;padding-bottom:8px;border-bottom:1px solid #454754; }
        .brand { margin:0;font-size:15px;font-weight:600;color:#86A3F0; }
        .close { width:28px;height:28px;border:0;border-radius:6px;background:#33343F;font-size:20px;cursor:pointer;color:#D9DCE5; }
        .close:hover { background:#454754; }
        .summary { margin:8px 0;padding:9px 10px;border-left:3px solid #7394ED;border-radius:0 5px 5px 0;background:#2C2E37; }
        .review { margin:9px 0;padding:9px 10px;border:1px solid #625033;border-radius:5px;background:#302B21; }
        .review strong { display:block;margin-bottom:3px; }
        .review-button { margin-top:5px;border:1px solid #7394ED;border-radius:4px;background:#33343F;color:#A9BCF5;padding:5px 8px;font:600 11px "Segoe UI",Arial,sans-serif;cursor:pointer; }
        .review-button:hover { background:#414450; }
        .label { font-weight:600;font-size:13px; }
        .suspicious, .high { color:#FF938C; } .caution, .normal { color:#F4C66B; } .safe, .low { color:#70DCA4; }
        .muted { color:#B7BAC5;font-size:11px; }
        .rules { margin:6px 0 0;padding-left:18px; }
        .rules li { margin:3px 0; }
        .note { margin-top:10px;padding-top:8px;border-top:1px solid #454754;color:#A9ADBB;font-size:10px; }
        .status { color:#B7BAC5; }
      </style>
      <button class="toggle" type="button">TRIAGE</button>
      <section class="panel" aria-live="polite">
        <div class="head"><h2 class="brand">Message check</h2><button class="close" type="button" aria-label="Close">×</button></div>
        <div class="content"><p class="status">Open an email to analyze it on this device.</p></div>
        <div class="note">A safe mark records your judgment; it does not change TRIAGE's score or verify the sender. Email content stays in this browser.</div>
      </section>`;
    shadow.querySelector(".toggle").addEventListener("click", () => {
      shadow.querySelector(".panel").classList.toggle("open");
      const email = readEmail();
      if (email) analyzeAndShow(email, shadow);
    });
    shadow.querySelector(".close").addEventListener("click", () => shadow.querySelector(".panel").classList.remove("open"));
    return shadow;
  }

  function renderResult(result, email, shadow) {
    const title = result.subject || "(No subject detected)";
    const evidence = result.threatEvidence.filter((item) => item.weight > 0).slice(0, 5);
    const threatClass = result.threat === "Suspicious" ? "suspicious" :
      result.threat === "Needs caution" ? "caution" : "safe";
    const priorityClass = result.priority.toLowerCase();
    const content = shadow.querySelector(".content");
    content.innerHTML = `
      <div class="muted">${escapeHtml(result.sender || "Sender not detected")}</div>
      <div style="font-weight:600;margin:4px 0 10px">${escapeHtml(title)}</div>
      <div class="summary">
        <div>Threat: <span class="label ${threatClass}">${escapeHtml(result.threat)}</span> <span class="muted">(rule score ${result.threatScore})</span></div>
        <div style="margin-top:5px">Priority: <span class="label ${priorityClass}">${escapeHtml(result.priority)}</span></div>
        <div class="muted" style="margin-top:5px">Topic: ${escapeHtml(result.topic)}</div>
      </div>
      ${result.userMarkedSafe ? `<div class="review"><strong>You marked this email as safe</strong><div class="muted">Automated result remains ${escapeHtml(result.threat)} (rule score ${result.threatScore}).</div><button class="review-button" type="button" data-action="undo-safe">Undo safe mark</button></div>` : result.threat !== "No warning signs found" ? `<div class="review"><strong>Think this is a false alarm?</strong><button class="review-button" type="button" data-action="mark-safe">Mark as safe</button></div>` : ""}
      ${evidence.length ? `<strong>Reasons for this warning</strong><ul class="rules">${evidence.map((item) => `<li>${escapeHtml(item.rule)}</li>`).join("")}</ul>` : `<p class="muted">No warning rules matched.</p>`}
      <p class="muted">Check the sender and links independently before acting.</p>`;
    content.querySelector(".review-button")?.addEventListener("click", async (event) => {
      const markedSafe = event.currentTarget.dataset.action === "mark-safe";
      if (markedSafe) {
        result.userMarkedSafe = true;
        result.userMarkedSafeAt = new Date().toISOString();
      } else {
        delete result.userMarkedSafe;
        delete result.userMarkedSafeAt;
      }
      try {
        const { history: currentHistory = [] } = await chrome.storage.local.get("history");
        const next = [result, ...currentHistory.filter((item) => item.id !== result.id)].slice(0, MAX_HISTORY);
        await chrome.storage.local.set({ history: next });
        renderResult(result, email, shadow);
      } catch (error) {
        console.error("TRIAGE could not update the safe mark.", error);
        content.insertAdjacentHTML("beforeend", '<p class="status">Could not save your change. Please try again.</p>');
      }
    });
  }

  async function analyzeAndShow(email, shadow = buildPanel()) {
    const result = analyze(email);
    renderResult(result, email, shadow);
    let history;
    try {
      ({ history = [] } = await chrome.storage.local.get("history"));
    } catch (error) {
      console.error("TRIAGE could not load local analysis history.", error);
      shadow.querySelector(".content").insertAdjacentHTML("beforeend", '<p class="status">Analysis is shown, but local history could not be loaded.</p>');
      return;
    }
    const previous = history.find((item) => item.id === result.id);
    if (previous?.userMarkedSafe) {
      result.userMarkedSafe = true;
      result.userMarkedSafeAt = previous.userMarkedSafeAt;
      renderResult(result, email, shadow);
    }
    try {
      const next = [result, ...history.filter((item) => item.id !== result.id)].slice(0, MAX_HISTORY);
      await chrome.storage.local.set({ history: next });
    } catch (error) {
      console.error("TRIAGE could not save the local analysis history.", error);
      shadow.querySelector(".content").insertAdjacentHTML("beforeend", '<p class="status">Analysis is shown, but could not be saved to local history.</p>');
    }
  }

  let lastEmailId = "";
  let debounceTimer;
  function analyzeOpenMessage() {
    const email = readEmail();
    if (!email) {
      lastEmailId = "";
      document.getElementById(ROOT_ID)?.shadowRoot?.querySelector(".panel")?.classList.remove("open");
      return;
    }
    if (email.id === lastEmailId) return;
    lastEmailId = email.id;
    const shadow = buildPanel();
    shadow.querySelector(".panel").classList.add("open");
    analyzeAndShow(email, shadow).catch((error) => {
      console.error("TRIAGE could not analyze the automatically detected email.", error);
      shadow.querySelector(".content").insertAdjacentHTML(
        "beforeend",
        '<p class="status">TRIAGE could not finish analyzing this email. Open the extension popup to retry.</p>',
      );
    });
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== "TRIAGE_ANALYZE_CURRENT_EMAIL") return false;
    const email = readEmail();
    if (!email) {
      sendResponse({ ok: false, reason: "No open email message was detected. Open a message and refresh the mail tab." });
      return false;
    }

    lastEmailId = email.id;
    const shadow = buildPanel();
    shadow.querySelector(".panel").classList.add("open");
    analyzeAndShow(email, shadow)
      .then(() => sendResponse({ ok: true, threat: analyze(email).threat }))
      .catch((error) => {
        console.error("TRIAGE could not analyze the open message.", error);
        sendResponse({ ok: false, reason: "The email was detected but could not be saved to the dashboard." });
      });
    return true;
  });

  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(analyzeOpenMessage, 500);
  });
  observer.observe(document.body, { childList: true, subtree: true, characterData: true, attributes: true });
  buildPanel();
  analyzeOpenMessage();
  window.addEventListener("hashchange", analyzeOpenMessage);
  window.addEventListener("popstate", analyzeOpenMessage);
  window.addEventListener("focus", analyzeOpenMessage);
  window.setInterval(() => {
    if (document.visibilityState === "visible") analyzeOpenMessage();
  }, 1200);
})();
