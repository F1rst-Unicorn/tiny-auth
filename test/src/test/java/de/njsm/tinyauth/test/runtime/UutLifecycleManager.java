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

import de.njsm.tinyauth.test.repository.Endpoint;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.*;
import org.junit.jupiter.api.extension.support.TypeBasedParameterResolver;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

public class UutLifecycleManager extends TypeBasedParameterResolver<Endpoint> implements BeforeAllCallback, ExtensionContext.Store.CloseableResource {

    private static final Logger LOG = LogManager.getLogger(UutLifecycleManager.class);

    private boolean started = false;

    private Network network;

    private GenericContainer<?> tinyAuthContainer;

    private Endpoint endpoint;

    @Override
    public void beforeAll(ExtensionContext extensionContext) {
        if (!started) {
            started = true;
            startTinyAuth();
            extensionContext.getStore(ExtensionContext.Namespace.create(extensionContext.getRequiredTestClass()))
                    .put(this.getClass().getCanonicalName(), this);
        }
    }

    private void startTinyAuth() {
        network = Network.newNetwork();
        int port = 34344;
        tinyAuthContainer = new GenericContainer<>(DockerImageName.parse("archlinux:latest"))
                .withNetwork(network)
                .withNetworkAliases("tiny-auth")
                .withFileSystemBind(Config.getRoot(), "/app")
                .withWorkingDirectory("/app")
                .withCommand(
                        "src/rust/target/debug/tiny-auth",
                        "-c",
                        "/app/test/src/test/resources/config.yml",
                        "-l",
                        "/app/test/src/test/resources/log4rs.yml")
                .withExposedPorts(port)
                .waitingFor(Wait.forListeningPorts(port))
                .withLogConsumer(v -> LOG.info(v.getUtf8StringWithoutLineEnding()));

        tinyAuthContainer.start();
        endpoint = new Endpoint(tinyAuthContainer.getHost(), tinyAuthContainer.getFirstMappedPort());
    }

    @Override
    public void close() {
        tinyAuthContainer.close();
        network.close();
        started = false;
    }

    @Override
    public Endpoint resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        return endpoint;
    }

    public Endpoint endpoint() {
        return endpoint;
    }

    public Network network() {
        return network;
    }
}
