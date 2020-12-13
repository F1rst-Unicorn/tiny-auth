/*  tiny-auth: Tiny OIDC Provider
 *  Copyright (C) 2019 The tiny-auth developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package de.njsm.tinyauth.test.runtime.webpage;

import org.openqa.selenium.By;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class RedirectPage extends Page {

    private By result;

    public RedirectPage(FirefoxDriver driver) {
        super(driver);
    }

    public static void assertRedirect(FirefoxDriver driver) {
        new RedirectPage(driver);
    }

    @Override
    void initialise() {
        result = By.id("result");
    }

    @Override
    void assertDriverIsOnThisPage() {
        waitUntil(ExpectedConditions.presenceOfElementLocated(result));
        assertTrue(driver.findElement(result).isDisplayed(), "field <result> not found");
    }
}
