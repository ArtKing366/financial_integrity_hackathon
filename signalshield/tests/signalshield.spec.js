import { test, expect } from './fixtures';
import path from 'path';

const FIXTURE_URL = `file://${path.resolve(__dirname, '../fixtures/extension_test_page.html')}`;

test.describe('SignalShield E2E', () => {

  test('should highlight suspicious links with correct colors', async ({ page }) => {
    await page.goto(FIXTURE_URL);

    const dangerousLink = page.locator('a#dangerous-brand-login');
    const safeLink = page.locator('a#safe-allegro');

    await expect(dangerousLink).toHaveCSS('background-color', 'rgba(220, 38, 38, 0.16)');
    await expect(dangerousLink).toHaveCSS('box-shadow', 'rgba(220, 38, 38, 0.82) 0px 0px 0px 2px');
    await expect(safeLink).not.toHaveCSS('color', 'rgb(255, 0, 0)');
  });

  test('should show confirm warning on form submit', async ({ page }) => {
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

  test.skip('popup should update state after "Trust current URL"', async ({ page, extensionId }) => {
    // Popup flow is skipped until Playwright can reliably resolve the extension ID.
  });

});
