import { chromium } from "playwright";

const target = process.argv[2];
if (!target) {
  throw new Error("Usage: node zap/seed-spa.mjs <target-url>");
}

const targetUrl = new URL(target);
const proxy = process.env.ZAP_PROXY || "http://127.0.0.1:8090";
const maxPages = Number(process.env.SPA_MAX_PAGES || "150");
const visited = new Set();
const pending = [targetUrl.href];

const browser = await chromium.launch({
  headless: true,
  proxy: { server: proxy },
});
const context = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await context.newPage();

await page.route("**/*", async route => {
  const requestUrl = new URL(route.request().url());
  if (requestUrl.origin !== targetUrl.origin) {
    await route.abort("blockedbyclient");
    return;
  }
  await route.continue();
});

page.on("request", request => {
  const method = request.method();
  if (method !== "GET" || /\/rest\/|\/api\//i.test(request.url())) {
    console.log(`BROWSER ${method} ${request.url()}`);
  }
});

while (pending.length > 0 && visited.size < maxPages) {
  const next = pending.shift();
  if (visited.has(next)) {
    continue;
  }

  const url = new URL(next);
  if (url.origin !== targetUrl.origin) {
    continue;
  }

  visited.add(next);
  console.log(`VISIT ${visited.size}/${maxPages} ${next}`);

  try {
    await page.goto(next, { waitUntil: "networkidle", timeout: 30000 });
    await page.waitForTimeout(1000);

    const links = await page.locator("a[href]").evaluateAll(anchors =>
      anchors.map(anchor => anchor.href).filter(Boolean)
    );

    for (const link of links) {
      const linkUrl = new URL(link, targetUrl);
      linkUrl.hash = "";
      if (linkUrl.origin === targetUrl.origin && !visited.has(linkUrl.href)) {
        pending.push(linkUrl.href);
      }
    }
  } catch (error) {
    console.log(`BROWSER_ERROR ${next} ${error.message}`);
  }
}

console.log(`BROWSER_SUMMARY visited=${visited.size} pending=${pending.length}`);
await browser.close();
