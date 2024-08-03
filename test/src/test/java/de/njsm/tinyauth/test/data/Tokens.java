package de.njsm.tinyauth.test.data;

import java.util.Optional;

public record Tokens(Optional<OidcToken> accessToken, Optional<OidcToken> idToken, Optional<OidcToken> refreshToken) {
}
