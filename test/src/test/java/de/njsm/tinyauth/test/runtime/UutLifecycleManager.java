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

import de.njsm.tinyauth.test.repository.Endpoints;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.File;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URL;

public class UutLifecycleManager implements BeforeAllCallback, AfterAllCallback {

    private static final Logger LOG = LogManager.getLogger(UutLifecycleManager.class);

    private Process tinyAuth;

    private Thread stdoutForwarder;

    private Thread stderrForwarder;

    @Override
    public void beforeAll(ExtensionContext extensionContext) throws Exception {
        String[] command = new String[] {
                Config.getBinaryPath(),
                "-c",
                Config.getConfigPath(),
                "-l",
                Config.getLogConfigPath()
        };

        tinyAuth = Runtime.getRuntime().exec(command, null, new File(".."));

        stdoutForwarder = new Thread(() -> {
            try {
                tinyAuth.getInputStream().transferTo(System.out);
            } catch (IOException e) {}
        });
        stdoutForwarder.start();

        stderrForwarder = new Thread(() -> {
            try {
                tinyAuth.getErrorStream().transferTo(System.err);
            } catch (IOException e) {}
        });
        stderrForwarder.start();

        waitForStartup();
    }

    private void waitForStartup() {
        while (true) {
            try {
                Thread.sleep(1000);
                URL u = new URL(Endpoints.getJwksUrl());
                u.openConnection();
                LOG.debug("tiny-auth is up");
                return;
            } catch (ConnectException e) {
                LOG.debug("Waiting for tiny-auth...");
            } catch (InterruptedException | IOException e) {
                LOG.error("Failed to connect", e);
            }
        }
    }

    @Override
    public void afterAll(ExtensionContext extensionContext) throws Exception {
        tinyAuth.destroy();
        stdoutForwarder.join();
        stderrForwarder.join();
    }
}