// tests/fixtures.js
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
      // Ждем максимум 1.5 секунды, чтобы не висеть 30 секунд, если Worker'а нет
      const timeoutFallback = new Promise(resolve => setTimeout(() => resolve(null), 1500));
      background = await Promise.race([
        context.waitForEvent('serviceworker').catch(() => null),
        context.waitForEvent('backgroundpage').catch(() => null),
        timeoutFallback
      ]);
    }
    
    let extensionId;
    
    if (background) {
      // Идеальный сценарий: берем ID из URL фонового скрипта
      extensionId = background.url().split('/')[2];
    } else {
      // ФОЛБЭК: Если Service Worker спит или его вообще нет в манифесте
      // Открываем служебную страницу расширений
      const page = await context.newPage();
      await page.goto('chrome://extensions');
      
      // Playwright автоматически пробивает Shadow DOM, поэтому мы можем найти элемент карточки
      await page.waitForSelector('extensions-item');
      
      // ID расширения хранится прямо в атрибуте id этого элемента
      extensionId = await page.locator('extensions-item').first().getAttribute('id');
      await page.close();
    }

    await use(extensionId);
  },
});

export const expect = base.expect;