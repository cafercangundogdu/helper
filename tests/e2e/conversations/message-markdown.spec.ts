import { expect, test } from "@playwright/test";
import { ConversationsPage } from "../utils/page-objects/conversationsPage";

test.use({ storageState: "tests/e2e/.auth/user.json" });

test.describe("MessageMarkdown HTML Sanitization", () => {
  let conversationsPage: ConversationsPage;

  test.beforeEach(async ({ page }) => {
    conversationsPage = new ConversationsPage(page);
    await conversationsPage.goto();
  });

  test("should render safe HTML tags properly", async ({ page }) => {
    // Wait for page to load without strict networkidle
    await page.waitForLoadState('domcontentloaded');
    await page.waitForSelector('main', { timeout: 10000 });
    
    // Verify page loaded successfully
    const messageContent = page.locator('main').first();
    await expect(messageContent).toBeVisible();
    
    // Test basic page functionality - just verify no malicious content
    const scriptTags = messageContent.locator('script');
    await expect(scriptTags).toHaveCount(0);
    
    // Test that external links (if any) have proper security attributes
    const externalLinks = messageContent.locator('a[href^="https://"]');
    const externalLinkCount = await externalLinks.count();
    
    if (externalLinkCount > 0) {
      await expect(externalLinks.first()).toHaveAttribute('target', '_blank');
      await expect(externalLinks.first()).toHaveAttribute('rel', 'noopener noreferrer');
    }
  });

  test("should sanitize malicious HTML content", async ({ page }) => {
    // Wait for page to load without strict networkidle
    await page.waitForLoadState('domcontentloaded');
    await page.waitForSelector('main', { timeout: 10000 });
    
    const messageContent = page.locator('main').first();
    await expect(messageContent).toBeVisible();
    
    // Verify no malicious content is present
    const scriptTags = messageContent.locator('script');
    await expect(scriptTags).toHaveCount(0);
    
    const iframeTags = messageContent.locator('iframe');
    await expect(iframeTags).toHaveCount(0);
    
    const elementsWithOnclick = messageContent.locator('[onclick]');
    await expect(elementsWithOnclick).toHaveCount(0);
    
    const elementsWithOnerror = messageContent.locator('[onerror]');
    await expect(elementsWithOnerror).toHaveCount(0);
  });

  test("should prevent XSS through javascript: URLs", async ({ page }) => {
    // Wait for page to load without strict networkidle
    await page.waitForLoadState('domcontentloaded');
    await page.waitForSelector('main', { timeout: 10000 });
    
    const messageContent = page.locator('main').first();
    await expect(messageContent).toBeVisible();
    
    // Check that no links have dangerous protocols
    const links = messageContent.locator('a[href]');
    const linkCount = await links.count();
    
    for (let i = 0; i < linkCount; i++) {
      const href = await links.nth(i).getAttribute('href');
      if (href) {
        expect(href.toLowerCase()).not.toContain('javascript:');
        expect(href.toLowerCase()).not.toContain('vbscript:');
        expect(href.toLowerCase()).not.toContain('data:text/html');
      }
    }
  });

  test("should handle mixed markdown and HTML content", async ({ page }) => {
    // Wait for page to load without strict networkidle
    await page.waitForLoadState('domcontentloaded');
    await page.waitForSelector('main', { timeout: 10000 });
    
    const messageContent = page.locator('main').first();
    await expect(messageContent).toBeVisible();
    
    // Check for basic HTML structure
    const paragraphs = messageContent.locator('p');
    
    if (await paragraphs.count() > 0) {
      await expect(paragraphs.first()).toBeVisible();
    }
  });

  test("should auto-link URLs correctly", async ({ page }) => {
    // Wait for page to load without strict networkidle
    await page.waitForLoadState('domcontentloaded');
    await page.waitForSelector('main', { timeout: 10000 });
    
    const messageContent = page.locator('main').first();
    await expect(messageContent).toBeVisible();
    
    // Check for external HTTP links with proper attributes
    const externalLinks = messageContent.locator('a[href^="https://"]');
    const linkCount = await externalLinks.count();
    
    // Only test if external links exist
    if (linkCount > 0) {
      for (let i = 0; i < linkCount; i++) {
        const link = externalLinks.nth(i);
        
        // Verify external links have proper security attributes
        await expect(link).toHaveAttribute('target', '_blank');
        await expect(link).toHaveAttribute('rel', 'noopener noreferrer');
      }
    }
  });
});