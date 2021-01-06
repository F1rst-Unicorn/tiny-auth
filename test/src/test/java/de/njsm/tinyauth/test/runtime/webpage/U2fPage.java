package de.njsm.tinyauth.test.runtime.webpage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.virtualauthenticator.VirtualAuthenticator;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class U2fPage extends Page {

    private static final Logger LOG = LogManager.getLogger(AuthorisationPage.class);

    private By register;

    private By output;

    private final VirtualAuthenticator authenticator;

    public U2fPage(FirefoxDriver driver, VirtualAuthenticator authenticator) {
        super(driver);
        this.authenticator = authenticator;
    }

    @Override
    void initialise() {
        register = By.id("register");
        output = By.id("output");
    }

    @Override
    void assertDriverIsOnThisPage() {
        waitUntil(ExpectedConditions.presenceOfElementLocated(register));
        assertTrue(driver.findElement(register).isDisplayed(), "registration button not found");
        LOG.info("on this page");
    }

    public U2fPage register() {
        driver.findElement(register).click();
        return this;
    }

    public void assertRegistrationWasSuccessful() {
        assertTrue(driver.findElement(output).isDisplayed(), "no registration output displayed");
    }
}
