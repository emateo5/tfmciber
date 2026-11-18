import { chromium } from "playwright";
import { writeFile } from "node:fs/promises";

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
  csrfValidation: false,
  csrfVulnerable: false,
  csrfRequestCaptured: false,
  csrfStatus: null,
  csrfEffectObserved: false,
  csrfTokenPresent: false,
  csrfOutcome: "skipped",
  csrfError: null,
  csrfProven: false,
  csrfEvidence: null,
  csrfUsernameBefore: null,
  csrfUsernameAfter: null,
  csrfOrigin: "http://htmledit.squarefree.com",
  authenticationError: null,
  reflectedXss: false,
};
let cartRequest;
let loginToken = null;
let basketIdFromLogin = null;

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
  if (
    ["POST", "PUT", "PATCH"].includes(method) &&
    /\/api\/BasketItems(?:\/\d+)?\/?/i.test(request.url())
  ) {
    const headers = request.headers();
    try {
      const postData = request.postData();
      const payload = postData ? JSON.parse(postData) : {};
      cartRequest = {
        url: request.url(),
        method,
        postData,
        payload,
        contentType: headers["content-type"] || "application/json",
        authorization: headers.authorization,
        csrfTokenPresent: Object.keys(headers).some(name =>
          /^(csrf|x-csrf|x-xsrf|anti-csrf)/i.test(name)
        ),
      };
      workflow.csrfRequestCaptured = Boolean(
        cartRequest.url &&
        cartRequest.method &&
        cartRequest.postData &&
        cartRequest.payload?.BasketId
      );
      if (workflow.csrfRequestCaptured) {
        console.log(
          `CSRF_CAPTURE basket=${cartRequest.payload.BasketId} ` +
          `product=${cartRequest.payload.ProductId} ` +
          `method=${cartRequest.method}`
        );
      }
    } catch (error) {
      workflow.csrfRequestCaptured = false;
      workflow.csrfError = `cart_request_capture_failed=${error.message}`;
    }
  }
  if (method !== "GET" || /\/rest\/|\/api\//i.test(request.url())) {
    console.log(`BROWSER ${method} ${request.url()}`);
  }
});

page.on("response", async response => {
  if (!/\/rest\/user\/login\/?$/.test(new URL(response.url()).pathname)) {
    return;
  }
  try {
    if (!response.ok()) {
      return;
    }
    const body = await response.json();
    loginToken = body?.authentication?.token || null;
    if (!loginToken) {
      return;
    }
    const encodedPayload = loginToken.split(".")[1];
    if (encodedPayload) {
      const claims = JSON.parse(
        Buffer.from(encodedPayload, "base64").toString("utf8")
      );
      basketIdFromLogin = claims.bid ? String(claims.bid) : null;
    }
  } catch (error) {
    console.log(`LOGIN_RESPONSE_ERROR ${error.message}`);
  }
});

async function clickFirstMatchingText(pattern) {
  const candidate = page.getByText(pattern).first();
  if (await candidate.count() === 0 || !(await candidate.isVisible())) {
    return false;
  }
  await candidate.click({ timeout: 10000 });
  return true;
}

async function firstAvailable(selectors) {
  for (const selector of selectors) {
    const candidate = page.locator(selector).first();
    if (await candidate.count() > 0 && await candidate.isVisible()) {
      return candidate;
    }
  }
  return null;
}

async function dismissOverlays() {
  const dismissSelectors = [
    'button[aria-label*="Dismiss" i]',
    'button:has-text("Dismiss")',
    'button:has-text("Me want it")',
    '.cdk-overlay-backdrop',
  ];
  for (const selector of dismissSelectors) {
    const candidates = page.locator(selector);
    const count = await candidates.count();
    for (let index = 0; index < count; index += 1) {
      const candidate = candidates.nth(index);
      if (await candidate.isVisible().catch(() => false)) {
        await candidate.click({ force: true }).catch(() => undefined);
      }
    }
  }
  await page.waitForTimeout(300);
}

async function runAuthenticatedWorkflow() {
  if (!testUsername || !testPassword) {
    workflow.authenticationError = "missing_secrets";
    console.log("WORKFLOW authentication=skipped reason=missing_secrets");
    return;
  }

  try {
    const loginResponse = await context.request.post(
      new URL("/rest/user/login", targetUrl.origin).href,
      {
        data: {
          email: testUsername,
          password: testPassword,
        },
        headers: { "Content-Type": "application/json" },
        timeout: 30000,
      }
    );
    const loginStatus = loginResponse.status();
    const loginBody = await loginResponse.json().catch(() => null);
    loginToken = loginBody?.authentication?.token || null;
    basketIdFromLogin = loginBody?.authentication?.bid
      ? String(loginBody.authentication.bid)
      : null;

    if (loginStatus !== 200 || !loginToken) {
      throw new Error(
        `login_rejected status=${loginStatus} body=${JSON.stringify(loginBody)}`
      );
    }

    await context.addCookies([{
      name: "token",
      value: loginToken,
      url: targetUrl.origin,
      httpOnly: false,
      secure: targetUrl.protocol === "https:",
      sameSite: "Lax",
      path: "/",
    }]);

    await page.goto(new URL("/", targetUrl.origin).href, {
      waitUntil: "domcontentloaded",
      timeout: 30000,
    });
    await page.evaluate(token => {
      localStorage.setItem("token", token);
      localStorage.setItem("bid", String(window.location.href));
    }, loginToken).catch(() => undefined);

    const profileResponse = await page.goto(
      new URL("/profile", targetUrl.origin).href,
      { waitUntil: "networkidle", timeout: 30000 }
    );
    const profileAvailable = await firstAvailable([
      'input[name="username"]',
      'input#username',
    ]);
    workflow.authentication =
      profileResponse?.status() !== 401 &&
      Boolean(profileAvailable);

    if (!workflow.authentication) {
      throw new Error(
        `profile_session_invalid status=${profileResponse?.status() || 0}`
      );
    }

    console.log(
      `WORKFLOW authentication=true login_status=${loginStatus} ` +
      `profile_status=${profileResponse?.status()}`
    );
    await page.goto(targetUrl.href, {
      waitUntil: "networkidle",
      timeout: 30000,
    });
    await page.waitForTimeout(1000);
    workflow.cart = await clickFirstMatchingText(
      /add to basket|add to cart/i
    );
    console.log(`WORKFLOW cart=${workflow.cart}`);
    return;
  } catch (error) {
    workflow.authentication = false;
    workflow.authenticationError = error.message;
    workflow.csrfError = error.message;
    console.log(`WORKFLOW authentication=false error=${error.message}`);
  }

  const loginUrl = new URL(targetUrl.href);
  loginUrl.hash = "/login";
  await page.goto(loginUrl.href, {
    waitUntil: "networkidle",
    timeout: 30000,
  });
  await dismissOverlays();
  const email = await firstAvailable([
    'input[name="email"]',
    'input#email',
    'input[type="email"]',
  ]);
  const password = await firstAvailable([
    'input[name="password"]',
    'input#password',
    'input[type="password"]',
  ]);
  if (!email || !password) {
    throw new Error(`login_fields_not_found url=${page.url()}`);
  }
  await email.fill(testUsername);
  await password.fill(testPassword);
  const loginButtons = await page.locator("button").evaluateAll(buttons =>
    buttons.map(button => ({
      id: button.id,
      type: button.getAttribute("type"),
      text: button.textContent?.trim(),
      disabled: button.disabled,
    }))
  );
  console.log(`LOGIN url=${page.url()} buttons=${JSON.stringify(loginButtons)}`);
  const submit = await firstAvailable([
    'button#loginButton',
    'button[type="submit"]',
    'input[type="submit"]',
  ]);
  if (!submit) {
    throw new Error(`login_submit_not_found url=${page.url()}`);
  }
  await submit.waitFor({ state: "visible", timeout: 10000 });
  await page.waitForFunction(
    element => !element.disabled,
    await submit.elementHandle(),
    { timeout: 10000 }
  );
  await submit.click({ timeout: 10000, force: true });
  await page.waitForTimeout(1500);
  workflow.authentication = !page.url().includes("/login");
  console.log(`WORKFLOW authentication=${workflow.authentication}`);

  await page.goto(targetUrl.href, { waitUntil: "networkidle", timeout: 30000 });
  await page.waitForTimeout(1000);
  workflow.cart = await clickFirstMatchingText(/add to basket|add to cart/i);
  console.log(`WORKFLOW cart=${workflow.cart}`);
  await page.waitForTimeout(1500);

  if (!cartRequest && basketIdFromLogin) {
    const storageToken = await page.evaluate(() =>
      localStorage.getItem("token")
    ).catch(() => null);
    const authorization = loginToken
      ? `Bearer ${loginToken}`
      : (storageToken ? `Bearer ${storageToken}` : null);

    if (authorization) {
      const productsResponse = await page.evaluate(async ({ origin, authorization }) => {
        const response = await fetch(`${origin}/api/Products?limit=1`, {
          headers: { Authorization: authorization },
        });
        if (!response.ok) {
          return null;
        }
        const body = await response.json();
        return Array.isArray(body?.data) ? body.data[0] : null;
      }, { origin: targetUrl.origin, authorization }).catch(() => null);

      if (productsResponse?.id) {
        cartRequest = {
          url: `${targetUrl.origin}/api/BasketItems/`,
          method: "POST",
          postData: JSON.stringify({
            ProductId: productsResponse.id,
            BasketId: basketIdFromLogin,
            quantity: 1,
          }),
          payload: {
            ProductId: productsResponse.id,
            BasketId: basketIdFromLogin,
            quantity: 1,
          },
          contentType: "application/json",
          authorization,
          csrfTokenPresent: false,
        };
        workflow.csrfRequestCaptured = true;
        console.log(
          `CSRF_CAPTURE fallback basket=${basketIdFromLogin} product=${productsResponse.id}`
        );
      }
    }
  }
}

async function runCsrfWorkflow() {
  if (!workflow.authentication) {
    workflow.csrfOutcome = "skipped";
    workflow.csrfError = "authentication_not_completed";
    console.log("WORKFLOW csrf_validation=skipped reason=authentication_not_completed");
    return;
  }

  let usernameBefore = null;
  try {
    await page.goto(new URL("/profile", targetUrl.origin).href, {
      waitUntil: "networkidle",
      timeout: 30000,
    });
    const usernameField = await firstAvailable([
      'input[name="username"]',
      'input#username',
    ]);
    if (!usernameField) {
      throw new Error("csrf_username_field_not_found");
    }
    usernameBefore = await usernameField.inputValue();
  } catch (error) {
    workflow.csrfStatus = 0;
    workflow.csrfOutcome = "failed";
    workflow.csrfError = error.message;
    workflow.csrfValidation = false;
    console.log(`WORKFLOW csrf_validation=failed error=${error.message}`);
    return;
  }

  workflow.csrfUsernameBefore = usernameBefore;
  const csrfUsername = `csrf-proven-${Date.now().toString(36)}`;
  const attackerOrigin = "http://htmledit.squarefree.com";
  workflow.csrfOrigin = attackerOrigin;
  workflow.csrfRequestCaptured = true;

  const attackerContext = await browser.newContext({
    ignoreHTTPSErrors: true,
  });

  try {
    const victimCookies = await context.cookies(targetUrl.origin);
    await attackerContext.addCookies(
      victimCookies.map(cookie => ({
        ...cookie,
        sameSite: "None",
        secure: targetUrl.protocol === "https:",
      }))
    );

    const attackerPage = await attackerContext.newPage();
    await attackerPage.route(`${attackerOrigin}/csrf-test`, route =>
      route.fulfill({
        status: 200,
        contentType: "text/html",
        body: `<!doctype html>
<html>
  <body>
    <form id="csrf-form" action="${targetUrl.origin}/profile" method="POST">
      <input type="hidden" name="username" value="${csrfUsername}">
    </form>
    <script>document.getElementById("csrf-form").submit()</script>
  </body>
</html>`,
      })
    );

    let status = 0;
    const navigation = attackerPage.waitForNavigation({
      waitUntil: "networkidle",
      timeout: 30000,
    }).catch(() => null);
    await attackerPage.goto(`${attackerOrigin}/csrf-test`, {
      waitUntil: "domcontentloaded",
      timeout: 30000,
    });
    const victimResponse = await navigation;
    if (victimResponse) {
      status = victimResponse.status();
    }

    await attackerContext.close();
    await page.goto(new URL("/profile", targetUrl.origin).href, {
      waitUntil: "networkidle",
      timeout: 30000,
    });
    const usernameFieldAfter = await firstAvailable([
      'input[name="username"]',
      'input#username',
    ]);
    const usernameAfter = usernameFieldAfter
      ? await usernameFieldAfter.inputValue()
      : null;

    workflow.csrfStatus = status;
    workflow.csrfUsernameAfter = usernameAfter;
    workflow.csrfEffectObserved =
      usernameAfter !== null && usernameAfter !== usernameBefore;

    if (workflow.csrfEffectObserved) {
      workflow.csrfOutcome = "vulnerable";
      workflow.csrfVulnerable = true;
      workflow.csrfValidation = true;
      workflow.csrfProven = true;
      workflow.csrfEvidence = {
        origin: attackerOrigin,
        endpoint: `${targetUrl.origin}/profile`,
        usernameBefore,
        usernameAfter,
        status,
      };
    } else if (status === 403 || status === 401 || status === 419) {
      workflow.csrfOutcome = "protected";
      workflow.csrfVulnerable = false;
      workflow.csrfValidation = true;
      workflow.csrfEvidence = {
        origin: attackerOrigin,
        endpoint: `${targetUrl.origin}/profile`,
        usernameBefore,
        usernameAfter,
        status,
      };
    } else {
      workflow.csrfOutcome = "indeterminate";
      workflow.csrfVulnerable = false;
      workflow.csrfValidation = false;
      workflow.csrfError = "username_unchanged";
      workflow.csrfEvidence = {
        origin: attackerOrigin,
        endpoint: `${targetUrl.origin}/profile`,
        usernameBefore,
        usernameAfter,
        status,
      };
    }
  } catch (error) {
    workflow.csrfStatus = 0;
    workflow.csrfEffectObserved = false;
    workflow.csrfVulnerable = false;
    workflow.csrfValidation = false;
    workflow.csrfOutcome = "failed";
    workflow.csrfError = error.message;
  } finally {
    await attackerContext.close();
  }

  console.log(
    `WORKFLOW csrf_validation=${workflow.csrfValidation} ` +
    `outcome=${workflow.csrfOutcome} vulnerable=${workflow.csrfVulnerable} ` +
    `status=${workflow.csrfStatus} effect=${workflow.csrfEffectObserved} ` +
    `username_before=${workflow.csrfUsernameBefore} ` +
    `username_after=${workflow.csrfUsernameAfter}`
  );
}

async function runReflectedXssWorkflow() {
  const marker = "tfm-xss-reflected";
  const payload = `<img src=x onerror=alert('${marker}')>`;
  let dialogDetected = false;
  page.once("dialog", async dialog => {
    dialogDetected = dialog.message() === marker;
    await dialog.dismiss();
  });
  const xssUrl = new URL(targetUrl.href);
  xssUrl.hash = `/search?q=${encodeURIComponent(payload)}`;
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
await runCsrfWorkflow().catch(error =>
  console.log(`WORKFLOW csrf_validation_error=${error.message}`)
);
await runReflectedXssWorkflow().catch(error =>
  console.log(`WORKFLOW reflected_xss_error=${error.message}`)
);

console.log(`BROWSER_SUMMARY visited=${visited.size} pending=${pending.length}`);
console.log(`WORKFLOW_SUMMARY ${JSON.stringify(workflow)}`);
await writeFile(
  process.env.BROWSER_WORKFLOW_REPORT || "artifacts/browser-workflow.json",
  `${JSON.stringify(workflow, null, 2)}\n`,
  "utf8"
);
await browser.close();
