/*
 *
 * Copyright 2025-2026 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */
package de.gematik.ti20.simsvc.server.service;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.ti20.simsvc.server.config.JwkConfiguration;
import de.gematik.ti20.simsvc.server.config.PoppConfig;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class WellKnownServiceTest {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private static final String KEYSTORE_PATH = "keystore.p12";
  private static final String KEYSTORE_PASSWORD = "testpassword";
  private static final String ALIAS = "poppmock";
  private static final String SERVER_URL = "https://popp.example.com";

  private static KeyStore keyStore;

  private PoppConfig poppConfig;
  private JsonWebKeySet publicJwk;

  @BeforeAll
  static void setUpKeystore() throws Exception {
    keyStore = KeyStore.getInstance("PKCS12");
    try (InputStream fis =
        WellKnownServiceTest.class.getClassLoader().getResourceAsStream(KEYSTORE_PATH)) {
      assertNotNull(fis, "Test-Keystore sollte im Classpath vorhanden sein");
      keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
    }
  }

  @BeforeEach
  void setUp() {
    poppConfig = createPoppConfig();
    publicJwk = new JwkConfiguration().jwkSource(keyStore);
  }

  @Test
  void testOpenIdFederationReturnsSignedJwtWithExpectedHeaderAndClaims() throws Exception {
    final WellKnownService service = new WellKnownService(publicJwk, poppConfig, keyStore);

    final String jwt = service.openIdFederation();

    assertNotNull(jwt);
    assertFalse(jwt.isBlank());
    assertEquals(3, jwt.split("\\.").length);

    final JsonWebSignature jws = new JsonWebSignature();
    jws.setCompactSerialization(jwt);
    jws.setKey(keyStore.getCertificate(ALIAS).getPublicKey());
    assertTrue(jws.verifySignature(), "JWT-Signatur sollte mit dem Public Key prüfbar sein");

    final Map<String, Object> header = parseJwtHeader(jwt);
    assertEquals("ES256", header.get("alg"));
    assertEquals("entity-statement+jwt", header.get("typ"));
    assertEquals("YpcZd9WfcJ2hKWbLVQJuvIk23RtDvPzVOtAmG77D-64", header.get("kid"));

    final JwtClaims claims = JwtClaims.parse(readJwtSegment(jwt, 1));
    assertEquals(SERVER_URL, claims.getIssuer());
    assertEquals(SERVER_URL, claims.getSubject());
    assertNotNull(claims.getIssuedAt());
    assertNotNull(claims.getExpirationTime());

    @SuppressWarnings("unchecked")
    final List<String> authorityHints = (List<String>) claims.getClaimValue("authority_hints");
    assertEquals(List.of("https://app-ref.federationmaster.de"), authorityHints);

    @SuppressWarnings("unchecked")
    final Map<String, Object> metadata = (Map<String, Object>) claims.getClaimValue("metadata");
    @SuppressWarnings("unchecked")
    final Map<String, Object> federationEntity =
        (Map<String, Object>) metadata.get("federation_entity");
    @SuppressWarnings("unchecked")
    final Map<String, Object> oauthResource = (Map<String, Object>) metadata.get("oauth_resource");

    assertEquals("Testorganisation", federationEntity.get("organization_name"));
    assertEquals(SERVER_URL + "/.well-known/signed-jwks", oauthResource.get("signed_jwks_uri"));

    @SuppressWarnings("unchecked")
    final Map<String, Object> jwks = (Map<String, Object>) claims.getClaimValue("jwks");
    @SuppressWarnings("unchecked")
    final List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
    final Map<String, Object> firstKey = keys.getFirst();

    assertEquals(1, keys.size());
    assertEquals("YpcZd9WfcJ2hKWbLVQJuvIk23RtDvPzVOtAmG77D-64", firstKey.get("kid"));
    assertNotNull(firstKey.get("kty"));
    assertNotNull(firstKey.get("crv"));
    assertNotNull(firstKey.get("x"));
    assertNotNull(firstKey.get("y"));
  }

  @Test
  void testSignedJwksReturnsSignedJwtWithExpectedHeaderAndClaims() throws Exception {
    final WellKnownService service = new WellKnownService(publicJwk, poppConfig, keyStore);

    final String jwt = service.signedJwks();

    assertNotNull(jwt);
    assertFalse(jwt.isBlank());
    assertEquals(3, jwt.split("\\.").length);

    final JsonWebSignature jws = new JsonWebSignature();
    jws.setCompactSerialization(jwt);
    jws.setKey(keyStore.getCertificate(ALIAS).getPublicKey());
    assertTrue(jws.verifySignature(), "JWT-Signatur sollte mit dem Public Key prüfbar sein");

    final Map<String, Object> header = parseJwtHeader(jwt);
    assertEquals("ES256", header.get("alg"));
    assertEquals("jwk-set+jwt", header.get("typ"));
    assertEquals("YpcZd9WfcJ2hKWbLVQJuvIk23RtDvPzVOtAmG77D-64", header.get("kid"));

    final JwtClaims claims = JwtClaims.parse(readJwtSegment(jwt, 1));
    assertEquals(SERVER_URL, claims.getIssuer());
    assertEquals(SERVER_URL, claims.getSubject());
    assertNotNull(claims.getIssuedAt());
    assertNotNull(claims.getExpirationTime());

    @SuppressWarnings("unchecked")
    final List<Map<String, Object>> keys = (List<Map<String, Object>>) claims.getClaimValue("keys");
    final Map<String, Object> firstKey = keys.getFirst();

    assertEquals(1, keys.size());
    assertEquals("YpcZd9WfcJ2hKWbLVQJuvIk23RtDvPzVOtAmG77D-64", firstKey.get("kid"));
    assertNotNull(firstKey.get("kty"));
    assertNotNull(firstKey.get("crv"));
    assertNotNull(firstKey.get("x"));
    assertNotNull(firstKey.get("y"));
    assertFalse(
        firstKey.containsKey("d"), "Der öffentliche JWK darf kein privates Material enthalten");
  }

  private static PoppConfig createPoppConfig() {
    final PoppConfig.StoreConfig storeConfig = new PoppConfig.StoreConfig();
    storeConfig.setPath(KEYSTORE_PATH);
    storeConfig.setPass(KEYSTORE_PASSWORD);

    final PoppConfig.KeyConfig keyConfig = new PoppConfig.KeyConfig();
    keyConfig.setAlias(ALIAS);
    keyConfig.setPass(KEYSTORE_PASSWORD);

    final PoppConfig.SecurityConfig securityConfig = new PoppConfig.SecurityConfig();
    securityConfig.setStore(storeConfig);
    securityConfig.setKey(keyConfig);

    final PoppConfig poppConfig = new PoppConfig();
    poppConfig.setPoppIssuerUrl(SERVER_URL);
    poppConfig.setSec(securityConfig);
    return poppConfig;
  }

  private static Map<String, Object> parseJwtHeader(final String jwt) throws Exception {
    return OBJECT_MAPPER.readValue(readJwtSegment(jwt, 0), new TypeReference<>() {});
  }

  private static String readJwtSegment(final String jwt, final int segmentIndex) {
    final String[] segments = jwt.split("\\.");
    final byte[] decoded = Base64.getUrlDecoder().decode(segments[segmentIndex]);
    return new String(decoded, StandardCharsets.UTF_8);
  }
}
