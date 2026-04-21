type RiskCategory = "SAFE" | "LOW RISK" | "MEDIUM RISK" | "HIGH RISK";

interface CookieAnalysis {
  cookie: chrome.cookies.Cookie;
  hostname: string;
  origin: string;
  pageIsSecure: boolean;
  isThirdParty: boolean;
  isSensitivePage: boolean;
  isLikelySensitiveName: boolean;
  expirationLabel: string;
  riskScore: number;
  riskCategory: RiskCategory;
  reasons: string[];
  analyzedAt: string;
}

interface SummaryStats {
  total: number;
  secure: number;
  insecure: number;
  thirdParty: number;
}

const searchInput = document.querySelector<HTMLInputElement>("#search-input");
const riskToggle = document.querySelector<HTMLInputElement>("#risk-toggle");
const cookieList = document.querySelector<HTMLDivElement>("#cookie-list");
const summaryPanel = document.querySelector<HTMLDivElement>("#summary-panel");
const exportButton = document.querySelector<HTMLButtonElement>("#export-button");
const analysisDomain = document.querySelector<HTMLParagraphElement>("#analysis-domain");
const cookieRowTemplate = document.querySelector<HTMLTemplateElement>("#cookie-row-template");

let allAnalyses: CookieAnalysis[] = [];
let activeOrigin = "";
let activeHostname = "";
let activeTimestamp = "";

const SENSITIVE_NAME_PATTERN = /(session|auth|token|jwt|sid|csrf|xsrf|bearer|refresh)/i;
const SENSITIVE_PATH_PATTERN = /(login|signin|account|auth|checkout|billing|admin|dashboard|settings)/i;

function getActiveTab(): Promise<chrome.tabs.Tab> {
  return new Promise((resolve, reject) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const [tab] = tabs;
      if (chrome.runtime.lastError?.message) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      if (!tab?.url) {
        reject(new Error("No active tab URL was available for analysis."));
        return;
      }

      resolve(tab);
    });
  });
}

function getCookiesForUrl(url: string): Promise<chrome.cookies.Cookie[]> {
  return new Promise((resolve, reject) => {
    chrome.cookies.getAll({ url }, (cookies) => {
      if (chrome.runtime.lastError?.message) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      resolve(cookies);
    });
  });
}

function getDomainVariants(hostname: string): string[] {
  const cleanHost = hostname.replace(/^\.+/, "").toLowerCase();
  const parts = cleanHost.split(".").filter(Boolean);
  const variants = new Set<string>([cleanHost]);

  for (let index = 0; index < parts.length - 1; index += 1) {
    variants.add(parts.slice(index).join("."));
  }

  return [...variants];
}

function getRegistrableDomain(hostname: string): string {
  const parts = hostname.replace(/^\.+/, "").toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) {
    return parts.join(".");
  }

  return parts.slice(-2).join(".");
}

function isThirdPartyCookie(cookieDomain: string, pageHostname: string): boolean {
  const cookieBase = getRegistrableDomain(cookieDomain);
  const pageBase = getRegistrableDomain(pageHostname);
  return cookieBase !== pageBase;
}

function truncateValue(value: string, maxLength = 72): string {
  return value.length > maxLength ? `${value.slice(0, maxLength)}…` : value;
}

function formatSameSite(sameSite?: chrome.cookies.SameSiteStatus): string {
  switch (sameSite) {
    case "lax":
      return "Lax";
    case "strict":
      return "Strict";
    case "no_restriction":
      return "None";
    case "unspecified":
    default:
      return "Unspecified";
  }
}

function formatExpiration(cookie: chrome.cookies.Cookie): string {
  if (cookie.session || !cookie.expirationDate) {
    return "Session cookie";
  }

  return new Date(cookie.expirationDate * 1000).toLocaleString();
}

function classifyRisk(score: number): RiskCategory {
  if (score >= 60) {
    return "HIGH RISK";
  }

  if (score >= 35) {
    return "MEDIUM RISK";
  }

  if (score >= 15) {
    return "LOW RISK";
  }

  return "SAFE";
}

function analyzeCookie(
  cookie: chrome.cookies.Cookie,
  pageUrl: URL,
  analyzedAt: string
): CookieAnalysis {
  const reasons: string[] = [];
  let riskScore = 0;

  const pageIsSecure = pageUrl.protocol === "https:";
  const isThirdParty = isThirdPartyCookie(cookie.domain, pageUrl.hostname);
  const isLikelySensitiveName = SENSITIVE_NAME_PATTERN.test(cookie.name);
  const isSensitivePage = SENSITIVE_PATH_PATTERN.test(pageUrl.pathname);
  const sameSite = formatSameSite(cookie.sameSite);
  const expirationLabel = formatExpiration(cookie);

  if (pageIsSecure && !cookie.secure) {
    riskScore += 35;
    reasons.push("Missing Secure flag on an HTTPS page.");
  }

  if (sameSite === "Unspecified") {
    riskScore += 18;
    reasons.push("SameSite is unspecified, increasing cross-site request exposure.");
  }

  if (isLikelySensitiveName) {
    riskScore += 20;
    reasons.push("Cookie name resembles a session or authentication token.");
  }

  if (cookie.httpOnly) {
    reasons.push("HttpOnly is enabled, which helps reduce script-level access.");
    riskScore = Math.max(0, riskScore - 8);
  } else if (isLikelySensitiveName) {
    riskScore += 10;
    reasons.push("Sensitive-looking cookie is readable by client-side scripts because HttpOnly is off.");
  }

  if (!cookie.session && cookie.expirationDate && isLikelySensitiveName) {
    const ttlDays = (cookie.expirationDate * 1000 - Date.now()) / (1000 * 60 * 60 * 24);
    if (ttlDays > 30) {
      riskScore += 20;
      reasons.push("Authentication-related cookie has a long-lived expiration window.");
    }
  }

  if (isThirdParty) {
    riskScore += 12;
    reasons.push("Cookie appears to be third-party relative to the active site.");
  }

  if (isThirdParty && isSensitivePage) {
    riskScore += 18;
    reasons.push("Third-party cookie is present on a page path that looks sensitive.");
  }

  if (sameSite === "None" && !cookie.secure) {
    riskScore += 25;
    reasons.push("SameSite=None without Secure is a high-risk cross-site configuration.");
  }

  if (riskScore === 0) {
    reasons.push("No immediate cookie hardening issues were detected by the local ruleset.");
  }

  const normalizedScore = Math.max(0, Math.min(100, riskScore));

  return {
    cookie,
    hostname: pageUrl.hostname,
    origin: pageUrl.origin,
    pageIsSecure,
    isThirdParty,
    isSensitivePage,
    isLikelySensitiveName,
    expirationLabel,
    riskScore: normalizedScore,
    riskCategory: classifyRisk(normalizedScore),
    reasons,
    analyzedAt
  };
}

function riskBadgeClass(riskCategory: RiskCategory): string {
  return riskCategory.toLowerCase().replace(/\s+/g, "-");
}

function createSummaryCard(label: string, value: string): HTMLDivElement {
  const card = document.createElement("div");
  card.className = "summary-card";

  const labelElement = document.createElement("span");
  labelElement.className = "summary-label";
  labelElement.textContent = label;

  const valueElement = document.createElement("span");
  valueElement.className = "summary-value";
  valueElement.textContent = value;

  card.append(labelElement, valueElement);
  return card;
}

function computeSummary(analyses: CookieAnalysis[]): SummaryStats {
  return analyses.reduce<SummaryStats>(
    (stats, analysis) => {
      stats.total += 1;
      if (analysis.cookie.secure) {
        stats.secure += 1;
      } else {
        stats.insecure += 1;
      }
      if (analysis.isThirdParty) {
        stats.thirdParty += 1;
      }
      return stats;
    },
    { total: 0, secure: 0, insecure: 0, thirdParty: 0 }
  );
}

function renderSummary(analyses: CookieAnalysis[]): void {
  if (!summaryPanel) {
    return;
  }

  summaryPanel.innerHTML = "";
  const summary = computeSummary(analyses);
  summaryPanel.append(
    createSummaryCard("Total Cookies", String(summary.total)),
    createSummaryCard("Secure vs Insecure", `${summary.secure} / ${summary.insecure}`),
    createSummaryCard("Third-Party", String(summary.thirdParty)),
    createSummaryCard(
      "Risky Cookies",
      String(analyses.filter((analysis) => analysis.riskCategory !== "SAFE").length)
    )
  );
}

function appendReasonItems(reasonList: HTMLUListElement, reasons: string[]): void {
  reasonList.innerHTML = "";
  for (const reason of reasons) {
    const item = document.createElement("li");
    item.textContent = reason;
    reasonList.append(item);
  }
}

function renderEmptyState(message: string): void {
  if (!cookieList) {
    return;
  }

  cookieList.innerHTML = `<div class="empty-state">${message}</div>`;
}

function renderCookies(analyses: CookieAnalysis[]): void {
  if (!cookieList || !cookieRowTemplate) {
    return;
  }

  cookieList.innerHTML = "";

  if (analyses.length === 0) {
    renderEmptyState("No cookies matched the current filters.");
    return;
  }

  const fragment = document.createDocumentFragment();

  for (const analysis of analyses) {
    const node = cookieRowTemplate.content.firstElementChild?.cloneNode(true);
    if (!(node instanceof HTMLElement)) {
      continue;
    }

    const mainButton = node.querySelector<HTMLButtonElement>(".cookie-row-main");
    const details = node.querySelector<HTMLDivElement>(".cookie-row-details");
    const cookieName = node.querySelector<HTMLElement>(".cookie-name");
    const cookieValue = node.querySelector<HTMLElement>(".cookie-value");
    const cookieDomain = node.querySelector<HTMLElement>(".cookie-domain");
    const cookiePath = node.querySelector<HTMLElement>(".cookie-path");
    const secureFlag = node.querySelector<HTMLElement>(".secure-flag");
    const httpOnlyFlag = node.querySelector<HTMLElement>(".http-only-flag");
    const sameSiteFlag = node.querySelector<HTMLElement>(".same-site-flag");
    const riskBadge = node.querySelector<HTMLElement>(".risk-badge");
    const riskScore = node.querySelector<HTMLElement>(".risk-score");
    const thirdPartyPill = node.querySelector<HTMLElement>(".third-party-pill");

    const detailName = node.querySelector<HTMLElement>(".detail-name");
    const detailValue = node.querySelector<HTMLElement>(".detail-value");
    const detailDomain = node.querySelector<HTMLElement>(".detail-domain");
    const detailPath = node.querySelector<HTMLElement>(".detail-path");
    const detailExpiration = node.querySelector<HTMLElement>(".detail-expiration");
    const detailSecure = node.querySelector<HTMLElement>(".detail-secure");
    const detailHttpOnly = node.querySelector<HTMLElement>(".detail-http-only");
    const detailSameSite = node.querySelector<HTMLElement>(".detail-same-site");
    const detailThirdParty = node.querySelector<HTMLElement>(".detail-third-party");
    const reasonList = node.querySelector<HTMLUListElement>(".reason-list");

    if (
      !mainButton ||
      !details ||
      !cookieName ||
      !cookieValue ||
      !cookieDomain ||
      !cookiePath ||
      !secureFlag ||
      !httpOnlyFlag ||
      !sameSiteFlag ||
      !riskBadge ||
      !riskScore ||
      !thirdPartyPill ||
      !detailName ||
      !detailValue ||
      !detailDomain ||
      !detailPath ||
      !detailExpiration ||
      !detailSecure ||
      !detailHttpOnly ||
      !detailSameSite ||
      !detailThirdParty ||
      !reasonList
    ) {
      continue;
    }

    cookieName.textContent = analysis.cookie.name;
    cookieValue.textContent = truncateValue(analysis.cookie.value);
    cookieDomain.textContent = analysis.cookie.domain;
    cookiePath.textContent = `Path ${analysis.cookie.path}`;

    secureFlag.textContent = analysis.cookie.secure ? "Secure enabled" : "Secure missing";
    secureFlag.classList.add(analysis.cookie.secure ? "flag-on" : "flag-off");

    httpOnlyFlag.textContent = analysis.cookie.httpOnly ? "HttpOnly enabled" : "HttpOnly disabled";
    httpOnlyFlag.classList.add(analysis.cookie.httpOnly ? "flag-on" : "flag-off");

    sameSiteFlag.textContent = `SameSite ${formatSameSite(analysis.cookie.sameSite)}`;
    sameSiteFlag.classList.add(
      formatSameSite(analysis.cookie.sameSite) === "Unspecified" ? "flag-off" : "flag-on"
    );

    riskBadge.textContent = analysis.riskCategory;
    riskBadge.classList.add(riskBadgeClass(analysis.riskCategory));
    riskScore.textContent = `Score ${analysis.riskScore}/100`;
    thirdPartyPill.hidden = !analysis.isThirdParty;

    detailName.textContent = analysis.cookie.name;
    detailValue.textContent = analysis.cookie.value;
    detailDomain.textContent = analysis.cookie.domain;
    detailPath.textContent = analysis.cookie.path;
    detailExpiration.textContent = analysis.expirationLabel;
    detailSecure.textContent = analysis.cookie.secure ? "Yes" : "No";
    detailHttpOnly.textContent = analysis.cookie.httpOnly ? "Yes" : "No";
    detailSameSite.textContent = formatSameSite(analysis.cookie.sameSite);
    detailThirdParty.textContent = analysis.isThirdParty ? "Yes" : "No";
    appendReasonItems(reasonList, analysis.reasons);

    mainButton.addEventListener("click", () => {
      const isHidden = details.hidden;
      details.hidden = !isHidden;
      mainButton.setAttribute("aria-expanded", String(isHidden));
    });

    fragment.append(node);
  }

  cookieList.append(fragment);
}

function applyFilters(): void {
  const query = searchInput?.value.trim().toLowerCase() ?? "";
  const riskyOnly = riskToggle?.checked ?? false;

  const filtered = allAnalyses.filter((analysis) => {
    const matchesQuery =
      query.length === 0 ||
      analysis.cookie.name.toLowerCase().includes(query) ||
      analysis.cookie.domain.toLowerCase().includes(query);
    const matchesRisk = !riskyOnly || analysis.riskCategory !== "SAFE";
    return matchesQuery && matchesRisk;
  });

  renderSummary(filtered);
  renderCookies(filtered);
}

async function exportAnalyses(): Promise<void> {
  const payload = {
    domain: activeHostname,
    analyzedAt: activeTimestamp,
    totalCookies: allAnalyses.length,
    cookies: allAnalyses.map((analysis) => ({
      name: analysis.cookie.name,
      value: analysis.cookie.value,
      domain: analysis.cookie.domain,
      path: analysis.cookie.path,
      expirationDate: analysis.cookie.expirationDate ?? null,
      secure: analysis.cookie.secure,
      httpOnly: analysis.cookie.httpOnly,
      sameSite: analysis.cookie.sameSite ?? "unspecified",
      session: analysis.cookie.session,
      storeId: analysis.cookie.storeId,
      thirdParty: analysis.isThirdParty,
      computedRiskScore: analysis.riskScore,
      riskCategory: analysis.riskCategory,
      reasons: analysis.reasons,
      timestamp: analysis.analyzedAt
    }))
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const objectUrl = URL.createObjectURL(blob);

  try {
    const downloadLink = document.createElement("a");
    downloadLink.href = objectUrl;
    downloadLink.download = `cookie-security-analyzer-${activeHostname || "site"}.json`;
    downloadLink.style.display = "none";
    document.body.append(downloadLink);
    downloadLink.click();
    downloadLink.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(objectUrl), 1500);
  }
}

function setStatus(message: string): void {
  if (analysisDomain) {
    analysisDomain.textContent = message;
  }
}

async function initialize(): Promise<void> {
  if (!searchInput || !riskToggle || !exportButton) {
    return;
  }

  searchInput.addEventListener("input", applyFilters);
  riskToggle.addEventListener("change", applyFilters);
  exportButton.addEventListener("click", () => {
    if (allAnalyses.length > 0) {
      void exportAnalyses();
    }
  });

  try {
    const activeTab = await getActiveTab();
    const pageUrl = new URL(activeTab.url as string);
    activeOrigin = pageUrl.origin;
    activeHostname = pageUrl.hostname;
    activeTimestamp = new Date().toISOString();

    setStatus(`Analyzing ${pageUrl.hostname}`);

    const cookies = await getCookiesForUrl(pageUrl.href);
    const variants = new Set(getDomainVariants(pageUrl.hostname));

    allAnalyses = cookies
      .filter((cookie) => variants.has(cookie.domain.replace(/^\./, "").toLowerCase()) || isThirdPartyCookie(cookie.domain, pageUrl.hostname))
      .map((cookie) => analyzeCookie(cookie, pageUrl, activeTimestamp))
      .sort((left, right) => right.riskScore - left.riskScore || left.cookie.name.localeCompare(right.cookie.name));

    setStatus(`${pageUrl.hostname} • ${allAnalyses.length} cookies analyzed locally`);
    renderSummary(allAnalyses);
    renderCookies(allAnalyses);

    if (allAnalyses.length === 0) {
      renderEmptyState("No cookies were found for the active page context.");
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Analysis failed.";
    setStatus("Analysis unavailable");
    renderSummary([]);
    renderEmptyState(message);
  }
}

void initialize();
