package de.njsm.tinyauth.test.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import de.njsm.tinyauth.test.data.Client;
import de.njsm.tinyauth.test.data.User;
import de.njsm.tinyauth.test.repository.Endpoints;

import java.net.URL;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TokenAsserter {

    public void verifyAccessToken(String token, Client client, User user, String nonce) throws Exception {
        JWTClaimsSet claims = verifyToken(token);
        verifyTokenClaims(claims.getClaims(), client, user, nonce);
    }

    public void verifyRefreshToken(String token, Client client, User user, String nonce, Set<String> scopes) throws Exception {
        JWTClaimsSet claims = verifyToken(token);
        Map<String, Object> accessTokenClaims = claims.getJSONObjectClaim(ACCESS_TOKEN);
        verifyTokenClaims(accessTokenClaims, client, user, nonce);

        assertEquals(Endpoints.getIssuer(), claims.getStringClaim(ISSUER));
        assertTrue(claims.getExpirationTime().after(new Date()));

        assertEquals(scopes, new HashSet<>(claims.getStringListClaim(SCOPES)));
    }

    private void verifyTokenClaims(Map<String, Object> claims, Client client, User user, String nonce) {
        Date now = new Date();

        assertEquals(nonce, claims.get(NONCE));
        assertEquals(Endpoints.getIssuer(), claims.get(ISSUER));
        assertEquals(client.getClientId(), claims.get(AUTHORIZED_PARTY));
        assertEquals(user.getUsername(), claims.get(SUBJECT));

        Object audience = claims.get(AUDIENCE);
        if (audience instanceof String)
            assertEquals(client.getClientId(), audience);
        else
            assertEquals(singletonList(client.getClientId()), audience);

        Date expirationTime = castToDate(claims.get(EXPIRATION_TIME));
        Date issuanceTime = castToDate(claims.get(ISSUANCE_TIME));
        Date authTime = castToDate(claims.get(AUTH_TIME));

        assertTrue(expirationTime.after(now), expirationTime + " < " + now);
        assertTrue(issuanceTime.before(now), issuanceTime + " > " + now);
        assertTrue(issuanceTime.after(authTime), issuanceTime + " < " + authTime);
    }

    private Date castToDate(Object rawDate) {
        if (rawDate instanceof Date)
            return (Date) rawDate;
        else
            return new Date((Long) rawDate * 1000);
    }

    private static JWTClaimsSet verifyToken(String token) throws Exception {
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new URL(Endpoints.getJwksUrl()));
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.ES384;
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor.process(token, null);
    }
}
