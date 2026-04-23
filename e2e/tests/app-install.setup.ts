import { test as setup } from '@playwright/test';
import { AppCatalogPage, config } from '@crowdstrike/foundry-playwright';

setup('install app', async ({ page }) => {
  const catalog = new AppCatalogPage(page);
  await catalog.installApp(config.appName, {
    configureSettings: async (page) => {
      await page.getByLabel('Name').fill('Anomali ThreatStream');
      await page.getByLabel('API URL').fill(process.env.ANOMALI_API_URL!);
      await page.getByLabel('API key').fill('test-api-key-12345');
    },
  });
});
