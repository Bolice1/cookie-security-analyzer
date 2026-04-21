interface ExportCookieRecord {
  name: string;
  value: string;
  domain: string;
  path: string;
  expirationDate: number | null;
  secure: boolean;
  httpOnly: boolean;
  sameSite: chrome.cookies.SameSiteStatus | "unspecified";
  session: boolean;
  storeId: string;
  thirdParty: boolean;
  computedRiskScore: number;
  riskCategory: string;
  reasons: string[];
  timestamp: string;
}

interface ExportPayload {
  domain: string;
  analyzedAt: string;
  totalCookies: number;
  cookies: ExportCookieRecord[];
}

interface ExportMessage {
  type: "EXPORT_ANALYSES";
  payload: ExportPayload;
}

function sanitizeFilenamePart(value: string): string {
  return value.replace(/[^a-z0-9.-]+/gi, "-").replace(/^-+|-+$/g, "") || "site";
}

function buildJsonDataUrl(payload: ExportPayload): string {
  return `data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(payload, null, 2))}`;
}

chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
  const exportMessage = message as ExportMessage;

  if (exportMessage?.type !== "EXPORT_ANALYSES") {
    return false;
  }

  const safeDomain = sanitizeFilenamePart(exportMessage.payload.domain);
  const downloadUrl = buildJsonDataUrl(exportMessage.payload);

  void chrome.downloads
    .download({
      url: downloadUrl,
      filename: `cookie-security-analyzer-${safeDomain}.json`,
      saveAs: true,
      conflictAction: "uniquify"
    })
    .then(() => {
      sendResponse({ ok: true });
    })
    .catch((error: unknown) => {
      const messageText = error instanceof Error ? error.message : "Download could not be started.";
      sendResponse({ ok: false, error: messageText });
    });

  return true;
});
