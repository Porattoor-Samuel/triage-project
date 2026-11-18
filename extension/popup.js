const historyNode = document.getElementById("history");
const statusNode = document.getElementById("status");
const SUPPORTED_MAIL_HOSTS = new Set([
  "mail.google.com",
  "outlook.live.com",
  "outlook.office.com",
  "outlook.office365.com",
  "outlook.cloud.microsoft",
]);

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function labelClass(threat) {
  if (threat === "Suspicious") return "risky";
  if (threat === "Needs caution") return "caution";
  return "safe";
}

async function render() {
  const { history = [] } = await chrome.storage.local.get("history");
  const riskyCount = history.filter((email) => !email.userMarkedSafe && email.threat !== "No warning signs found").length;
  const highCount = history.filter((email) => email.priority === "High").length;
  document.getElementById("count").textContent = history.length;
  document.getElementById("risky").textContent = riskyCount;
  document.getElementById("high").textContent = highCount;

  if (!history.length) {
    historyNode.innerHTML = '<div class="empty">No emails checked yet.<br>Open Gmail or Outlook and select a message.</div>';
    return;
  }

  historyNode.innerHTML = history.map((email) => `
    <article class="email-card">
      <h3>${escapeHtml(email.subject || "(No subject)")}</h3>
      <p>${escapeHtml(email.sender || "Sender not detected")} · ${escapeHtml(email.topic)}</p>
      ${email.userMarkedSafe
        ? `<span class="badge user-safe">Marked safe by you</span><p class="review-note">Automated result: ${escapeHtml(email.threat)}</p>`
        : `<span class="badge ${labelClass(email.threat)}">${escapeHtml(email.threat)}</span>`}
      <span class="badge priority-${escapeHtml(email.priority.toLowerCase())}">${escapeHtml(email.priority)} priority</span>
      <span class="badge">Rule score ${Number(email.threatScore) || 0}</span>
    </article>
  `).join("");
}

function sendToActiveTab(tabId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, { type: "TRIAGE_ANALYZE_CURRENT_EMAIL" }, (response) => {
      const error = chrome.runtime.lastError;
      if (error) reject(new Error(error.message));
      else resolve(response);
    });
  });
}

async function analyzeOpenEmail() {
  statusNode.textContent = "Checking the open email…";
  statusNode.classList.remove("error");
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const activeUrl = tab?.url ? new URL(tab.url) : null;
    if (!tab?.id || !activeUrl || activeUrl.protocol !== "https:" || !SUPPORTED_MAIL_HOSTS.has(activeUrl.hostname)) {
      statusNode.textContent = "Open Gmail or Outlook on the web and select an email to analyze it.";
      return;
    }
    const response = await sendToActiveTab(tab.id);
    if (!response?.ok) {
      statusNode.textContent = response?.reason ?? "No open email was detected. Open a message and try again.";
      statusNode.classList.add("error");
      return;
    }
    statusNode.textContent = "Open email analyzed locally. The overlay is shown on the mail page.";
    await render();
  } catch (error) {
    statusNode.textContent = "TRIAGE is not active in this tab. Refresh Gmail/Outlook, reopen an email, then open TRIAGE again.";
    statusNode.classList.add("error");
    console.warn("TRIAGE could not contact its content script.", error);
  }
}

document.getElementById("clear").addEventListener("click", async () => {
  await chrome.storage.local.remove("history");
  await render();
});

Promise.all([render(), analyzeOpenEmail()]).catch((error) => {
  console.error("TRIAGE could not initialize its dashboard.", error);
  historyNode.textContent = "Could not load local analysis history.";
  statusNode.textContent = "Could not initialize TRIAGE.";
  statusNode.classList.add("error");
});
