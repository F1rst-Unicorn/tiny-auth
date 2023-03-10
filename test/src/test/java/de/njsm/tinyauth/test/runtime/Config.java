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

package de.njsm.tinyauth.test.runtime;

public class Config {

    static final String BINARY_PATH = "de.njsm.tinyauth.test.config.binary";

    static final String CONFIG_PATH = "de.njsm.tinyauth.test.config.configfile";

    static final String LOG_CONFIG_PATH = "de.njsm.tinyauth.test.config.logconfigfile";

    static final String PROFILE_PATH = "de.njsm.tinyauth.test.selenium.profile";

    static String getBinaryPath() {
        return System.getProperty(BINARY_PATH);
    }

    static String getConfigPath() {
        return System.getProperty(CONFIG_PATH);
    }

    static String getLogConfigPath() {
        return System.getProperty(LOG_CONFIG_PATH);
    }

    static String getProfilePath() {
        return System.getProperty(PROFILE_PATH);
    }
}
