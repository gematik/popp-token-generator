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
package de.gematik.ti20.simsvc.server.model;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

public class OpenIdFederationToken {

  @Getter
  public static class Header {
    private String typ = "entity-statement+jwt";
    private String kid;

    public Header(String kid) {
      this.kid = kid;
    }
  }

  @Getter
  public static class Claims {
    private final String iss;
    private final String signedJwksUri;
    /**
     * Key to validate this token with.
     */
    private final JsonWebKeySet publicJwk;

    public Claims(final String iss, final String signedJwksUri, final JsonWebKeySet publicJwk) {
      this.iss = iss;
      this.signedJwksUri = signedJwksUri;
      this.publicJwk = publicJwk;
    }
  }

  private final Header header;
  private final Claims claims;

  public OpenIdFederationToken(final Header header, final Claims claims) {
    this.header = header;
    this.claims = claims;
  }

  public String toJwt(final KeyStore keyStore, final String alias, final char[] keyPassword)
      throws Exception {

    final JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setIssuer(claims.getIss());
    jwtClaims.setSubject(claims.getIss());
    jwtClaims.setIssuedAtToNow();
    jwtClaims.setExpirationTimeMinutesInTheFuture(60);

    jwtClaims.setClaim("authority_hints", new String[] {"https://app-ref.federationmaster.de"});
    jwtClaims.setClaim(
        "metadata",
        Map.of(
            "federation_entity",
            Map.of("organization_name", "Testorganisation"),
            "oauth_resource",
            Map.of("signed_jwks_uri", claims.getSignedJwksUri())));

    final List<Map<String, Object>> keys =
        claims.getPublicJwk().getJsonWebKeys().stream()
            .map(key -> key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))
            .toList();
    jwtClaims.setClaim("jwks", Map.of("keys", keys));

    // create signature
    final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPassword);
    final JsonWebSignature jws = new JsonWebSignature();
    jws.setPayload(jwtClaims.toJson());
    jws.setKey(privateKey);
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
    jws.setHeader("typ", header.getTyp());
    jws.setHeader("kid", header.getKid());

    final String jwt = jws.getCompactSerialization();
    return jwt;
  }
}
