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

import de.gematik.ti20.simsvc.server.config.PoppConfig;
import de.gematik.ti20.simsvc.server.model.OpenIdFederationToken;
import de.gematik.ti20.simsvc.server.model.SignedJwksToken;
import java.net.URI;
import java.security.KeyStore;
import org.jose4j.jwk.JsonWebKeySet;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class WellKnownService {

  private final JsonWebKeySet jwk;
  private final PoppConfig poppConfig;
  private final KeyStore keyStore;

  public WellKnownService(
      final @Qualifier("publicJwk") JsonWebKeySet jwk,
      final PoppConfig poppConfig,
      final @Qualifier("poppKeyStore") KeyStore keyStore) {
    this.jwk = jwk;
    this.poppConfig = poppConfig;
    this.keyStore = keyStore;
  }

  public String openIdFederation() throws Exception {
    final String serverUrl = poppConfig.getPoppIssuerUrl();
    final String signedJwksUri =
        URI.create(serverUrl).resolve("/.well-known/signed-jwks").toString();
    final OpenIdFederationToken.Claims claims =
        new OpenIdFederationToken.Claims(serverUrl, signedJwksUri, jwk);

    final String kid = jwk.getJsonWebKeys().getFirst().getKeyId();
    final OpenIdFederationToken.Header header = new OpenIdFederationToken.Header(kid);

    final OpenIdFederationToken token = new OpenIdFederationToken(header, claims);

    return token.toJwt(
        keyStore,
        poppConfig.getSec().getKey().getAlias(),
        poppConfig.getSec().getKey().getPass().toCharArray());
  }

  public String signedJwks() throws Exception {
    final SignedJwksToken.Claims claims =
        new SignedJwksToken.Claims(poppConfig.getPoppIssuerUrl(), jwk);
    final String kid = jwk.getJsonWebKeys().getFirst().getKeyId();
    final SignedJwksToken.Header header = new SignedJwksToken.Header(kid);

    final SignedJwksToken token = new SignedJwksToken(header, claims);
    return token.toJwt(
        keyStore,
        poppConfig.getSec().getKey().getAlias(),
        poppConfig.getSec().getKey().getPass().toCharArray());
  }
}
