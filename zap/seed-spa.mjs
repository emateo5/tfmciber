import { chromium } from "playwright";

const target = process.argv[2];
if (!target) {
  throw new Error("Usage: node zap/seed-spa.mjs <target-url>");
}

const targetUrl = new URL(target);
const proxy = process.env.ZAP_PROXY || "http://127.0.0.1:8090";
const maxPages = Number(process.env.SPA_MAX_PAGES || "150");
const testUsername = process.env.TEST_USERNAME;
const testPassword = process.env.TEST_PASSWORD;
const visited = new Set();
const pending = [targetUrl.href];
const workflow = {
  authentication: false,
  cart: false,
  reflectedXss: false,
};

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

async function clickFirstMatchingText(pattern) {
  const candidate = page.getByText(pattern).first();
  if (await candidate.count() === 0) {
    return false;
  }
  await candidate.click({ timeout: 10000 });
  return true;
}

async function runAuthenticatedWorkflow() {
  if (!testUsername || !testPassword) {
    console.log("WORKFLOW authentication=skipped reason=missing_secrets");
    return;
  }

  await page.goto(new URL("/#/login", targetUrl).href, {
    waitUntil: "networkidle",
    timeout: 30000,
  });
  await page.locator('input[name="email"]').fill(testUsername);
  await page.locator('input[name="password"]').fill(testPassword);
  await page.locator('button[type="submit"]').click();
  await page.waitForTimeout(1500);
  workflow.authentication = !page.url().includes("/login");
  console.log(`WORKFLOW authentication=${workflow.authentication}`);

  await page.goto(targetUrl.href, { waitUntil: "networkidle", timeout: 30000 });
  await page.waitForTimeout(1000);
  workflow.cart = await clickFirstMatchingText(/add to basket|add to cart/i);
  console.log(`WORKFLOW cart=${workflow.cart}`);
}

async function runReflectedXssWorkflow() {
  const marker = "tfm-xss-reflected";
  const payload = `<img src=x onerror=alert('${marker}')>`;
  let dialogDetected = false;
  page.once("dialog", async dialog => {
    dialogDetected = dialog.message() === marker;
    await dialog.dismiss();
  });
  const xssUrl = new URL("/#/search", targetUrl);
  xssUrl.searchParams.set("q", payload);
  await page.goto(xssUrl.href, { waitUntil: "networkidle", timeout: 30000 });
  await page.waitForTimeout(1000);
  workflow.reflectedXss = dialogDetected;
  console.log(`WORKFLOW reflected_xss=${workflow.reflectedXss}`);
}

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

await runAuthenticatedWorkflow().catch(error =>
  console.log(`WORKFLOW authentication_error=${error.message}`)
);
await runReflectedXssWorkflow().catch(error =>
  console.log(`WORKFLOW reflected_xss_error=${error.message}`)
);

console.log(`BROWSER_SUMMARY visited=${visited.size} pending=${pending.length}`);
console.log(`WORKFLOW_SUMMARY ${JSON.stringify(workflow)}`);
await browser.close();
