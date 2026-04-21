/*
 *
 * Copyright 2025 gematik GmbH
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
import de.gematik.ti20.simsvc.server.config.KeyStoreConfiguration;
import de.gematik.ti20.simsvc.server.config.PoppConfig;
import de.gematik.ti20.simsvc.server.model.SecurityParams;
import de.gematik.ti20.simsvc.server.model.TokenParams;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Base64;
import java.util.Map;
import org.jose4j.jwk.JsonWebKeySet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PoppTokenServiceTest {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private PoppConfig poppConfig;
  private KeyStore keyStore;
  private JsonWebKeySet publicJwk;

  @BeforeEach
  void setUp() {
    PoppConfig.StoreConfig storeConfig = new PoppConfig.StoreConfig();
    storeConfig.setPath("keystore.p12");
    storeConfig.setPass("testpassword");

    PoppConfig.KeyConfig keyConfig = new PoppConfig.KeyConfig();
    keyConfig.setAlias("poppmock");
    keyConfig.setPass("testpassword");

    PoppConfig.SecurityConfig secConfig = new PoppConfig.SecurityConfig();
    secConfig.setKey(keyConfig);
    secConfig.setStore(storeConfig);

    poppConfig = new PoppConfig();
    poppConfig.setSec(secConfig);

    keyStore = new KeyStoreConfiguration().poppKeyStore(poppConfig);
    publicJwk = new JwkConfiguration().jwkSource(keyStore);
  }

  @Test
  void testCreateTokenReturnsJwt() throws Exception {
    PoppTokenService service = new PoppTokenService(poppConfig, keyStore, publicJwk);
    final TokenParams tokenParams = new TokenParams("", "1000", "999", "pid", "iid", "aid", "oid");

    final String jwt = service.createToken(tokenParams, null);

    assertNotNull(jwt);
    assertTrue(jwt.split("\\.").length == 3);
    assertNotNull(parseJwtHeader(jwt));

    assertEquals("YpcZd9WfcJ2hKWbLVQJuvIk23RtDvPzVOtAmG77D-64", parseJwtHeader(jwt).get("kid"));
  }

  @Test
  void testCreateTokenWithSecurityParams() throws Exception {
    PoppTokenService service = new PoppTokenService(poppConfig, keyStore, publicJwk);

    final InputStream fis =
        PoppTokenServiceTest.class.getClassLoader().getResourceAsStream("alt_keystore.p12");
    final byte[] content = fis.readAllBytes();
    final String base64 = java.util.Base64.getEncoder().encodeToString(content);
    final SecurityParams securityParams = new SecurityParams(base64, "00", "alias", "00");

    final TokenParams tokenParams = new TokenParams("", "1000", "999", "pid", "iid", "aid", "oid");

    final String jwt = service.createToken(tokenParams, securityParams);

    assertNotNull(jwt);
    assertTrue(jwt.split("\\.").length == 3);
  }

  private Map<String, Object> parseJwtHeader(final String jwt) throws Exception {
    final String[] segments = jwt.split("\\.");
    final byte[] decodedHeader = Base64.getUrlDecoder().decode(segments[0]);
    final String headerJson = new String(decodedHeader, StandardCharsets.UTF_8);
    return OBJECT_MAPPER.readValue(headerJson, new TypeReference<Map<String, Object>>() {});
  }
}
