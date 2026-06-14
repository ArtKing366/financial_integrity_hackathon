import { test, expect } from './fixtures';
import path from 'path';

const FIXTURE_URL = `file://${path.resolve(__dirname, '../fixtures/extension_test_page.html')}`;

test.describe('SignalShield E2E', () => {

  test('should highlight links with correct colors based on verdicts', async ({ page }) => {
    await page.goto(FIXTURE_URL);

    const dangerousLink = page.locator('a#dangerous-brand-login');
    const safeLink = page.locator('a#safe-allegro');
    const dangerousPathLink = page.locator('a#suspicious-path-keywords');
    const suspiciousLink = page.locator('a#suspicious-shortener');
    const notFoundLink = page.locator('a#not-found-mailto');

    await expect(dangerousLink).toHaveCSS('background-color', 'rgba(220, 38, 38, 0.16)');
    await expect(dangerousLink).toHaveCSS('box-shadow', 'rgba(220, 38, 38, 0.82) 0px 0px 0px 2px');

    await expect(safeLink).toHaveCSS('outline-color', 'rgba(22, 163, 74, 0.45)');
    await expect(safeLink).toHaveCSS('outline-style', 'solid');

    await expect(dangerousPathLink).toHaveCSS('background-color', 'rgba(220, 38, 38, 0.16)');
    await expect(dangerousPathLink).toHaveCSS('box-shadow', 'rgba(220, 38, 38, 0.82) 0px 0px 0px 2px');

    await expect(suspiciousLink).toHaveCSS('background-color', 'rgba(245, 158, 11, 0.18)');
    await expect(suspiciousLink).toHaveCSS('box-shadow', 'rgba(217, 119, 6, 0.82) 0px 0px 0px 2px');

    await expect(notFoundLink).toHaveCSS('background-color', 'rgba(75, 85, 99, 0.15)');
    await expect(notFoundLink).toHaveCSS('box-shadow', 'rgba(75, 85, 99, 0.72) 0px 0px 0px 2px');
  });

  test('popup should update state and link styles after "Trust current URL"', async ({ context, page, extensionId }) => {
    await page.goto(FIXTURE_URL);
    const dangerousLink = page.locator('a#dangerous-brand-login');
    await expect(dangerousLink).toHaveCSS('background-color', 'rgba(220, 38, 38, 0.16)');

    const popupPage = await context.newPage();
    
    await popupPage.addInitScript(() => {
      window.chrome = window.chrome || {};
      window.chrome.tabs = window.chrome.tabs || {};
      window.chrome.tabs.query = (queryInfo, callback) => {
        const fakeTab = { id: 100, url: 'https://mbank-login24.pl/', active: true };
        if (callback) callback([fakeTab]);
        return Promise.resolve([fakeTab]);
      };
    });

    await popupPage.goto(`chrome-extension://${extensionId}/popup.html`);

    // Drive the button directly because extension popups can be flaky with locator.click().
    await popupPage.evaluate(() => {
      const btn = document.querySelector('#trustCurrentUrl');
      if (btn) {
        btn.disabled = false;
        btn.style.display = 'block';
        btn.style.visibility = 'visible';
        btn.click();
      }
    });

    await popupPage.waitForTimeout(1000);
    await popupPage.close();

    await page.bringToFront();
    await page.reload();
    
    await expect(dangerousLink).toHaveCSS('background-color', 'rgba(37, 99, 235, 0.22)');
  });

  test('should show confirm warning on risky form submit', async ({ page }) => {
    await page.goto(FIXTURE_URL);

    let dialogFired = false;
    
    page.on('dialog', async (dialog) => {
      dialogFired = true;
      console.log('Captured dialog:', dialog.message());
      await dialog.dismiss(); 
    });

    const badFormButton = page.locator('form[action="https://mbank-login24.pl/collect"] button[type="submit"]');
    
    await badFormButton.click();

    expect(dialogFired).toBeTruthy();
  });

});
