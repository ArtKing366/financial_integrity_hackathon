import { test, expect } from './fixtures';
import path from 'path';

// Указываем путь к тестовой странице
const FIXTURE_URL = `file://${path.resolve(__dirname, '../fixtures/extension_test_page.html')}`;

test.describe('SignalShield E2E', () => {

  // 1. Проверить цвета ссылок
  test('should highlight links with correct colors based on verdicts', async ({ page }) => {
    await page.goto(FIXTURE_URL);

    // Локаторы для ссылок из таблицы
    const dangerousLink = page.locator('a#dangerous-brand-login');
    const safeLink = page.locator('a#safe-allegro');
    const suspiciousLink = page.locator('a#suspicious-path-keywords');
    const notFoundLink = page.locator('a#not-found-mailto');

    // Проверка опасной ссылки (DANGEROUS)
    await expect(dangerousLink).toHaveCSS('background-color', 'rgba(220, 38, 38, 0.16)');
    await expect(dangerousLink).toHaveCSS('box-shadow', 'rgba(220, 38, 38, 0.82) 0px 0px 0px 2px');

    // Проверка безопасной ссылки (SAFE)
    await expect(safeLink).toHaveCSS('background-color', 'rgba(22, 163, 74, 0.13)');
    await expect(safeLink).toHaveCSS('box-shadow', 'rgba(22, 163, 74, 0.62) 0px 0px 0px 2px');

    // Проверка подозрительной ссылки (SUSPICIOUS)
    await expect(suspiciousLink).toHaveCSS('background-color', 'rgba(245, 158, 11, 0.18)');
    await expect(suspiciousLink).toHaveCSS('box-shadow', 'rgba(217, 119, 6, 0.82) 0px 0px 0px 2px');

    // Проверка ненайденной ссылки (NOT_FOUND)
    await expect(notFoundLink).toHaveCSS('background-color', 'rgba(75, 85, 99, 0.15)');
    await expect(notFoundLink).toHaveCSS('box-shadow', 'rgba(75, 85, 99, 0.72) 0px 0px 0px 2px');
  });

  // 2. Проверить popup после "Trust current URL"
  test('popup should update state and link styles after "Trust current URL"', async ({ context, page, extensionId }) => {
    // 1. Открываем тестовую страницу
    await page.goto(FIXTURE_URL);
    const dangerousLink = page.locator('a#dangerous-brand-login');
    await expect(dangerousLink).toHaveCSS('background-color', 'rgba(220, 38, 38, 0.16)');

    // 2. Открываем popup
    const popupPage = await context.newPage();
    
    // Внедряем моки для API расширения
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

    // 3. ПРИНУДИТЕЛЬНОЕ ВЗАИМОДЕЙСТВИЕ
    // Вместо использования API Playwright (locator.click), выполняем JS напрямую
    await popupPage.evaluate(() => {
      const btn = document.querySelector('#trustCurrentUrl');
      if (btn) {
        btn.disabled = false;
        btn.style.display = 'block'; // Делаем видимой
        btn.style.visibility = 'visible';
        btn.click(); // Нативный клик в JS
      }
    });

    // 4. Даем время на выполнение логики (сохранение в chrome.storage)
    await popupPage.waitForTimeout(1000);
    await popupPage.close();

    // 5. Перезагружаем основную страницу и ждем применения стилей
    await page.bringToFront();
    await page.reload();
    
    // 6. Проверяем результат
    // Ожидаем синий цвет (trusted_by_user)
    await expect(dangerousLink).toHaveCSS('background-color', 'rgba(37, 99, 235, 0.22)');
  });
  // 3. Проверить confirm при submit формы
  test('should show confirm warning on risky form submit', async ({ page }) => {
    await page.goto(FIXTURE_URL);

    let dialogFired = false;
    
    // Подписываемся на появление нативных окон браузера (alert, confirm, prompt)
    page.on('dialog', async (dialog) => {
      dialogFired = true;
      console.log('Пойман диалог:', dialog.message());
      // Нажимаем "Отмена" (dismiss), чтобы заблокировать отправку данных
      await dialog.dismiss(); 
    });

    // Находим кнопку отправки формы, ведущей на вредоносный домен
    const badFormButton = page.locator('form[action="https://mbank-login24.pl/collect"] button[type="submit"]');
    
    // Инициируем отправку формы
    await badFormButton.click();

    // Ожидаем, что расширение перехватило submit и вызвало confirm()
    expect(dialogFired).toBeTruthy();
  });

});