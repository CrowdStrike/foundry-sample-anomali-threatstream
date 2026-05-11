import { test, expect } from '../src/fixtures';

test.describe.configure({ mode: 'serial' });

test.describe('Anomali Threatstream E2E Tests', () => {

  test('should install app successfully from catalog', async ({ appCatalogPage, appName }) => {
    const isInstalled = await appCatalogPage.isAppInstalled(appName);
    expect(isInstalled).toBe(true);
  });

  test('should have anomali-ioc-ingest function endpoint available', async ({ appManagerPage }) => {
    await appManagerPage.goto();
  });

  test('should verify "Anomali Threat Intelligence Ingest" workflow exists', async ({ workflowsPage }) => {
    await workflowsPage.navigateToWorkflows();
    await workflowsPage.verifyWorkflowExists('Anomali Threat Intelligence Ingest');
  });

  test('should verify "Anomali Threat Intelligence Ingest" workflow renders properly', async ({ workflowsPage }) => {
    await workflowsPage.navigateToWorkflows();
    await workflowsPage.verifyWorkflowRenders('Anomali Threat Intelligence Ingest');
  });

  test('should verify scheduled workflow details are accessible', async ({ page, workflowsPage }) => {
    await workflowsPage.navigateToWorkflows();
    await workflowsPage.searchWorkflow('Anomali Threat Intelligence Ingest');

    const workflowLink = page.getByRole('link', { name: /Anomali.*Intelligence.*Ingest/i });
    await workflowLink.click();
    await page.waitForLoadState('domcontentloaded');

    const workflowDetailsIndicator = page.getByText(/Schedule|Trigger|Configuration/).first();
    await expect(workflowDetailsIndicator).toBeVisible({ timeout: 10000 });
  });
});
