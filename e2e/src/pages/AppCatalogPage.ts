/**
 * AppCatalogPage - App installation and management
 */

import { Page } from '@playwright/test';
import { BasePage } from './BasePage';
import { RetryHandler } from '../utils/SmartWaiter';
import { config } from '../config/TestConfig';

export class AppCatalogPage extends BasePage {
  constructor(page: Page) {
    super(page, 'AppCatalogPage');
  }

  protected getPagePath(): string {
    return '/foundry/app-catalog';
  }

  protected async verifyPageLoaded(): Promise<void> {
    await this.waiter.waitForVisible(
      this.page.locator('text=App Catalog').or(this.page.locator('text=Apps')),
      { description: 'App Catalog page' }
    );

    this.logger.success('App Catalog page loaded successfully');
  }

  /**
   * Search for app in catalog and navigate to its page
   */
  private async searchAndNavigateToApp(appName: string): Promise<void> {
    this.logger.info(`Searching for app '${appName}' in catalog`);

    await this.navigateToPath('/foundry/app-catalog', 'App catalog page');

    // Try the "Type to filter" search box on the left side with a partial search
    const filterBox = this.page.getByPlaceholder('Type to filter');
    if (await filterBox.isVisible().catch(() => false)) {
      // Use a shorter search term that's more likely to match
      const searchTerm = appName.includes('anomali') ? 'anomali' : appName;
      await filterBox.fill(searchTerm);
      await this.page.waitForLoadState('networkidle');
    }

    // Look for the app link - try multiple approaches
    let appLink = this.page.getByRole('link', { name: appName, exact: true });

    // If exact match fails, try partial match
    if (!await this.elementExists(appLink, 2000)) {
      appLink = this.page.getByRole('link').filter({ hasText: 'anomali' });
    }

    // If still not found, try looking for any link containing key terms
    if (!await this.elementExists(appLink, 2000)) {
      appLink = this.page.getByRole('link').filter({ hasText: 'threatstream' });
    }

    try {
      await this.waiter.waitForVisible(appLink, {
        description: `App '${appName}' link in catalog`,
        timeout: 10000
      });
      this.logger.success(`Found app '${appName}' in catalog`);
      await this.smartClick(appLink, `App '${appName}' link`);
      await this.page.waitForLoadState('networkidle');
    } catch (error) {
      throw new Error(`Could not find app '${appName}' in catalog. Make sure the app is deployed.`);
    }
  }

  /**
   * Check if app is installed
   */
  async isAppInstalled(appName: string): Promise<boolean> {
    this.logger.step(`Check if app '${appName}' is installed`);

    // Search for and navigate to the app's catalog page
    await this.searchAndNavigateToApp(appName);

    // Check for installation indicators on the app's page
    // Simple check: if "Install now" link exists, app is NOT installed
    const installLink = this.page.getByRole('link', { name: 'Install now' });
    const hasInstallLink = await this.elementExists(installLink, 3000);

    const isInstalled = !hasInstallLink;
    this.logger.info(`App '${appName}' installation status: ${isInstalled ? 'Installed' : 'Not installed'}`);

    return isInstalled;
  }

  /**
   * Install app if not already installed
   */
  async installApp(appName: string): Promise<boolean> {
    this.logger.step(`Install app '${appName}'`);

    const isInstalled = await this.isAppInstalled(appName);
    if (isInstalled) {
      this.logger.info(`App '${appName}' is already installed`);
      return false;
    }

    // Click Install now link
    this.logger.info('App not installed, looking for Install now link');
    const installLink = this.page.getByRole('link', { name: 'Install now' });

    await this.waiter.waitForVisible(installLink, { description: 'Install now link' });
    await this.smartClick(installLink, 'Install now link');
    this.logger.info('Clicked Install now, waiting for install page to load');

    // Wait for URL to change to install page and page to stabilize
    await this.page.waitForURL(/\/foundry\/app-catalog\/[^\/]+\/install$/, { timeout: 10000 });
    await this.page.waitForLoadState('networkidle');

    // Handle permissions dialog
    await this.handlePermissionsDialog();

    // Check for API integration configuration screen
    await this.configureApiIntegrationIfNeeded();

    // Click final Install app button
    await this.clickInstallAppButton();

    // Wait for installation to complete
    await this.waitForInstallation(appName);

    this.logger.success(`App '${appName}' installed successfully`);
    return true;
  }

  /**
   * Handle permissions dialog if present
   */
  private async handlePermissionsDialog(): Promise<void> {
    const acceptButton = this.page.getByRole('button', { name: /accept.*continue/i });

    if (await this.elementExists(acceptButton, 3000)) {
      this.logger.info('Permissions dialog detected, accepting');
      await this.smartClick(acceptButton, 'Accept and continue button');
      await this.waiter.delay(2000);
    }
  }

  /**
   * Configure API integration if configuration form is present
   * This is a generic method that can be overridden for app-specific configuration
   */
  private async configureApiIntegrationIfNeeded(): Promise<void> {
    this.logger.info('Checking if API integration configuration is required...');

    // Check if there are input fields (configuration form)
    const textInputs = this.page.locator('input[type="text"]');
    const passwordInputs = this.page.locator('input[type="password"]');

    try {
      await textInputs.first().waitFor({ state: 'visible', timeout: 15000 });
      const textCount = await textInputs.count();
      const passwordCount = await passwordInputs.count();
      const totalCount = textCount + passwordCount;
      this.logger.info(`API configuration form detected with ${textCount} text fields and ${passwordCount} password fields (${totalCount} total)`);
    } catch (error) {
      this.logger.info('No API configuration required - no input fields found');
      return;
    }

    this.logger.info('API configuration required, filling dummy values');

    // Fill text fields
    const textFieldCount = await textInputs.count();

    if (textFieldCount >= 1) {
      // Field 1: Name/Description
      const nameField = textInputs.nth(0);
      await nameField.fill('Test Configuration');
      this.logger.debug('Filled Name/Description field');
    }

    if (textFieldCount >= 2) {
      // Field 2: API URL/Host
      const apiUrlField = textInputs.nth(1);
      await apiUrlField.fill(config.anomaliApiUrl);
      this.logger.debug('Filled API URL/Host field');
    }

    if (textFieldCount >= 3) {
      // Field 3: Additional text field (username, client ID, etc.)
      const additionalField = textInputs.nth(2);
      await additionalField.fill('test-value');
      this.logger.debug('Filled additional text field');
    }

    // Fill password fields (API key, password, client secret, etc.)
    const passwordFieldCount = await passwordInputs.count();

    if (passwordFieldCount >= 1) {
      // Password field: API key, password, client secret, etc.
      const passwordField = passwordInputs.nth(0);
      await passwordField.fill('test-secret-12345');
      this.logger.debug('Filled password/secret field');
    }

    // Wait for network to settle after filling form
    await this.page.waitForLoadState('networkidle');

    this.logger.success(`API configuration completed (${textFieldCount} text + ${passwordFieldCount} password fields filled)`);
  }

  /**
   * Click the final "Install app" button
   */
  private async clickInstallAppButton(): Promise<void> {
    const installButton = this.page.getByRole('button', { name: 'Install app' });

    await this.waiter.waitForVisible(installButton, { description: 'Install app button' });

    // Wait for button to be enabled
    await installButton.waitFor({ state: 'visible', timeout: 10000 });
    await installButton.waitFor({ state: 'attached', timeout: 5000 });

    // Simple delay for form to enable button
    await this.waiter.delay(1000);

    await this.smartClick(installButton, 'Install app button');
    this.logger.info('Clicked Install app button');
  }

  /**
   * Wait for installation to complete
   */
  private async waitForInstallation(appName: string): Promise<void> {
    this.logger.info('Waiting for installation to complete...');

    // Wait for URL to change or network to settle
    await Promise.race([
      this.page.waitForURL(/\/foundry\/(app-catalog|home)/, { timeout: 15000 }),
      this.page.waitForLoadState('networkidle', { timeout: 15000 })
    ]).catch(() => {});

    // Look for first "installing" message
    const installingMessage = this.page.getByText(/installing/i).first();

    try {
      await installingMessage.waitFor({ state: 'visible', timeout: 30000 });
      this.logger.success('Installation started - "installing" message appeared');
    } catch (error) {
      throw new Error(`Installation failed to start for app '${appName}' - "installing" message never appeared. Installation may have failed immediately.`);
    }

    // Wait for second toast with final status (installed or error)
    // Match exact toast messages using app name
    const installedMessage = this.page.getByText(`${appName} installed`).first();
    const errorMessage = this.page.getByText(`Error installing ${appName}`).first();

    try {
      const result = await Promise.race([
        installedMessage.waitFor({ state: 'visible', timeout: 60000 }).then(() => 'success'),
        errorMessage.waitFor({ state: 'visible', timeout: 60000 }).then(() => 'error')
      ]);

      if (result === 'error') {
        // Get the actual error message from the toast and clean up formatting
        const errorText = await errorMessage.textContent();
        const cleanError = errorText?.replace(/\s+/g, ' ').trim() || 'Unknown error';
        throw new Error(`Installation failed for app '${appName}': ${cleanError}`);
      }
      this.logger.success('Installation completed successfully - "installed" message appeared');
    } catch (error) {
      if (error.message.includes('Installation failed')) {
        throw error;
      }
      throw new Error(`Installation status unclear for app '${appName}' - timed out waiting for "installed" or "error" message after 60 seconds`);
    }
    // Brief catalog status check (5-10s) - "installed" toast is the real signal
    // This is just for logging/verification, not a hard requirement
    this.logger.info('Checking catalog status briefly (installation already confirmed by toast)...');

    // Navigate directly to app catalog with search query
    const baseUrl = new URL(this.page.url()).origin;
    await this.page.goto(`${baseUrl}/foundry/app-catalog?q=${appName}`);
    await this.page.waitForLoadState('networkidle');

    // Check status a couple times (up to 10 seconds)
    const statusText = this.page.locator('[data-test-selector="status-text"]').filter({ hasText: /installed/i });
    const maxAttempts = 2; // 2 attempts = up to 10 seconds

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const isVisible = await statusText.isVisible().catch(() => false);

      if (isVisible) {
        this.logger.success('Catalog status verified - shows Installed');
        return;
      }

      if (attempt < maxAttempts - 1) {
        this.logger.info(`Catalog status not yet updated, waiting 5s before refresh (attempt ${attempt + 1}/${maxAttempts})...`);
        await this.waiter.delay(5000);
        await this.page.reload({ waitUntil: 'domcontentloaded' });
      }
    }

    // Don't fail - the "installed" toast is reliable enough
    this.logger.info(`Catalog status not updated yet after ${maxAttempts * 5}s, but toast confirmed installation - continuing`);
  }

  /**
   * Navigate to app via Custom Apps menu
   */
  async navigateToAppViaCustomApps(appName: string): Promise<void> {
    this.logger.step(`Navigate to app '${appName}' via Custom Apps`);

    return RetryHandler.withPlaywrightRetry(
      async () => {
        // Navigate to Foundry home
        await this.navigateToPath('/foundry/home', 'Foundry home page');

        // Open hamburger menu
        const menuButton = this.page.getByTestId('nav-trigger');
        await this.smartClick(menuButton, 'Menu button');

        // Click Custom apps
        const customAppsButton = this.page.getByRole('button', { name: 'Custom apps' });
        await this.smartClick(customAppsButton, 'Custom apps button');

        // Find and click the app
        const appButton = this.page.getByRole('button', { name: appName, exact: false }).first();
        if (await this.elementExists(appButton, 3000)) {
          await this.smartClick(appButton, `App '${appName}' button`);
          await this.waiter.delay(1000);

          this.logger.success(`Navigated to app '${appName}' via Custom Apps`);
          return;
        }

        throw new Error(`App '${appName}' not found in Custom Apps menu`);
      },
      `Navigate to app via Custom Apps`
    );
  }

  /**
   * Uninstall app
   */
  async uninstallApp(appName: string): Promise<void> {
    this.logger.step(`Uninstall app '${appName}'`);

    try {
      // Search for and navigate to the app's catalog page
      await this.searchAndNavigateToApp(appName);

      // Check if app is actually installed by looking for "Install now" link
      // If "Install now" link exists, app is NOT installed
      const installLink = this.page.getByRole('link', { name: 'Install now' });
      const hasInstallLink = await this.elementExists(installLink, 3000);

      if (hasInstallLink) {
        this.logger.info(`App '${appName}' is already uninstalled`);
        return;
      }

      // Click the 3-dot menu button
      const openMenuButton = this.page.getByRole('button', { name: 'Open menu' });
      await this.waiter.waitForVisible(openMenuButton, { description: 'Open menu button' });
      await this.smartClick(openMenuButton, 'Open menu button');

      // Click "Uninstall app" menuitem
      const uninstallMenuItem = this.page.getByRole('menuitem', { name: 'Uninstall app' });
      await this.waiter.waitForVisible(uninstallMenuItem, { description: 'Uninstall app menuitem' });
      await this.smartClick(uninstallMenuItem, 'Uninstall app menuitem');

      // Confirm uninstallation in modal
      const uninstallButton = this.page.getByRole('button', { name: 'Uninstall' });
      await this.waiter.waitForVisible(uninstallButton, { description: 'Uninstall confirmation button' });
      await this.smartClick(uninstallButton, 'Uninstall button');

      // Wait for success message
      const successMessage = this.page.getByText(/has been uninstalled/i);
      await this.waiter.waitForVisible(successMessage, {
        description: 'Uninstall success message',
        timeout: 30000
      });

      this.logger.success(`App '${appName}' uninstalled successfully`);

    } catch (error) {
      this.logger.warn(`Failed to uninstall app '${appName}': ${error.message}`);
      throw error;
    }
  }
}
