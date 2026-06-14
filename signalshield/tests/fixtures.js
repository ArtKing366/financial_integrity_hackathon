import { test as base, chromium } from '@playwright/test';
import path from 'path';

const extensionPath = path.join(__dirname, '../browser_extension'); 

export const test = base.extend({
  context: async ({}, use) => {
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
      // Keep extension-id discovery fast when no service worker is active.
      const timeoutFallback = new Promise(resolve => setTimeout(() => resolve(null), 1500));
      background = await Promise.race([
        context.waitForEvent('serviceworker').catch(() => null),
        context.waitForEvent('backgroundpage').catch(() => null),
        timeoutFallback
      ]);
    }
    
    let extensionId;
    
    if (background) {
      extensionId = background.url().split('/')[2];
    } else {
      // Fallback for sleeping service workers: read the id from chrome://extensions.
      const page = await context.newPage();
      await page.goto('chrome://extensions');
      
      await page.waitForSelector('extensions-item');
      
      extensionId = await page.locator('extensions-item').first().getAttribute('id');
      await page.close();
    }

    await use(extensionId);
  },
});

export const expect = base.expect;
