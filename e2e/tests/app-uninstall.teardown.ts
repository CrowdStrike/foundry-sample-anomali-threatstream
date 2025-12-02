import { test as teardown } from '../src/fixtures';

teardown('uninstall Anomali Threatstream app', async ({ appCatalogPage, appName }) => {
  // Clean up by uninstalling the app after all tests complete
  await appCatalogPage.navigateToPath('/foundry/app-catalog', 'App Catalog');
  await appCatalogPage.uninstallApp(appName);
});