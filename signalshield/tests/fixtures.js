// tests/fixtures.js
import { test as base, chromium } from '@playwright/test';
import path from 'path';

// Укажи путь к папке с manifest.json
const extensionPath = path.join(__dirname, '../browser_extension'); 

export const test = base.extend({
  context: async ({}, use) => {
    // Расширения работают только в persistent context
    const context = await chromium.launchPersistentContext('', {
      headless: false, // Важно: для расширений исторически нужен headful режим. Для CI можно пробовать args: ['--headless=new']
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
      ],
    });
    
    await use(context);
    await context.close();
  },
  
  // Достаем ID расширения (предполагается Manifest V3 с Service Worker)
  extensionId: async ({ context }, use) => {
    // Проверяем, есть ли уже запущенные Service Worker (MV3) или Background Page (MV2)
    let background = context.serviceWorkers()[0] || context.backgroundPages()[0];
    
    if (!background) {
      // Если сразу не нашли, ждем запуска любого из них
      background = await Promise.race([
        context.waitForEvent('serviceworker'),
        context.waitForEvent('backgroundpage')
      ]);
    }
    
    // Достаем ID расширения из URL (chrome-extension://[ID]/...)
    const extensionId = background.url().split('/')[2];
    await use(extensionId);
  },
});

export const expect = base.expect;