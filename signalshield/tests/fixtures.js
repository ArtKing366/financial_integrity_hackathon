// tests/fixtures.js
import { test as base, chromium } from '@playwright/test';
import path from 'path';

// Path to the unpacked extension folder with manifest.json.
const extensionPath = path.join(__dirname, '../browser_extension');

export const test = base.extend({
  context: async ({}, use) => {
    // Extensions require a persistent browser context.
    const context = await chromium.launchPersistentContext('', {
      headless: false,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
      ],
    });

    await use(context);
    await context.close();
  },

  extensionId: async ({ context }, use) => {
    let background = context.serviceWorkers()[0] || context.backgroundPages()[0];

    if (!background) {
      background = await Promise.race([
        context.waitForEvent('serviceworker').catch(() => null),
        context.waitForEvent('backgroundpage').catch(() => null),
        timeoutFallback
      ]);
    }

    const extensionId = background.url().split('/')[2];
    await use(extensionId);
  },
});

export const expect = base.expect;
