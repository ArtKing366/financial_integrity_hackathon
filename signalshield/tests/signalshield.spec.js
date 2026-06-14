import { test, expect } from './fixtures';
import path from 'path';

// Указываем точное название твоего нового файла
const FIXTURE_URL = `file://${path.resolve(__dirname, '../fixtures/extension_test_page.html')}`;

test.describe('SignalShield E2E', () => {

  test('should highlight suspicious links with correct colors', async ({ page }) => {
    await page.goto(FIXTURE_URL);

    // Цепляемся за конкретные ID из твоей таблицы
    const dangerousLink = page.locator('a#dangerous-brand-login');
    const safeLink = page.locator('a#safe-allegro');

    // ВАЖНО: Тебе нужно заменить 'rgb(255, 0, 0)' на тот реальный цвет, 
    // который задается твоим файлом content.css для опасных ссылок!
    // Playwright понимает цвета только в формате rgb() или rgba().
    // Test 1: Check for the background highlight instead of text color
    await expect(dangerousLink).toHaveCSS('background-color', 'rgba(220, 38, 38, 0.16)');
    
    // Optional: You can also verify the box-shadow to be extra sure
    await expect(dangerousLink).toHaveCSS('box-shadow', 'rgba(220, 38, 38, 0.82) 0px 0px 0px 2px');
    
    // Безопасная ссылка не должна краситься в красный
    await expect(safeLink).not.toHaveCSS('color', 'rgb(255, 0, 0)');
  });

  test('should show confirm warning on form submit', async ({ page }) => {
    await page.goto(FIXTURE_URL);

    let dialogFired = false;
    
    // Этот обработчик ловит нативные окна браузера (alert, confirm, prompt)
    page.on('dialog', async (dialog) => {
      dialogFired = true;
      console.log('Пойман диалог:', dialog.message());
      await dialog.dismiss(); // Нажимаем "Отмена", чтобы форма не отправилась
    });

    // Находим кнопку Submit в форме, которая ведет на плохой домен mbank
    const badFormButton = page.locator('form[action="https://mbank-login24.pl/collect"] button[type="submit"]');
    
    // Кликаем и ждем реакцию расширения
    await badFormButton.click();

    // Проверяем, что расширение действительно вызвало окно confirm()
    expect(dialogFired).toBeTruthy();
  });

  // Временно отключаем этот тест. Без ServiceWorker'а Playwright
  // не может легко узнать ID расширения, чтобы открыть страницу popup.html
  test.skip('popup should update state after "Trust current URL"', async ({ page, extensionId }) => {
    // ... логика теста popup ...
  });

});