import { test as baseTest } from '@playwright/test';
import { AppCatalogPage, AppManagerPage, WorkflowsPage, config } from '@crowdstrike/foundry-playwright';

type FoundryFixtures = {
  appCatalogPage: AppCatalogPage;
  appManagerPage: AppManagerPage;
  workflowsPage: WorkflowsPage;
  appName: string;
};

export const test = baseTest.extend<FoundryFixtures>({
  appCatalogPage: async ({ page }, use) => {
    await use(new AppCatalogPage(page));
  },

  appManagerPage: async ({ page }, use) => {
    await use(new AppManagerPage(page));
  },

  workflowsPage: async ({ page }, use) => {
    await use(new WorkflowsPage(page));
  },

  appName: async ({}, use) => {
    await use(config.appName);
  },
});

export { expect } from '@playwright/test';
