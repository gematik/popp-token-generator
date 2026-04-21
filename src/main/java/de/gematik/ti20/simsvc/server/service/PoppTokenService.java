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

import de.gematik.ti20.simsvc.server.config.PoppConfig;
import de.gematik.ti20.simsvc.server.model.PoppToken;
import de.gematik.ti20.simsvc.server.model.SecurityParams;
import de.gematik.ti20.simsvc.server.model.TokenParams;
import java.io.InputStream;
import java.security.KeyStore;
import org.jose4j.jwk.JsonWebKeySet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class PoppTokenService {

  private static final Logger LOG = LoggerFactory.getLogger(PoppTokenService.class);

  private final PoppConfig poppConfig;
  private final KeyStore keyStore;
  private final JsonWebKeySet jwk;

  public PoppTokenService(
      final PoppConfig poppConfig,
      final @Qualifier("poppKeyStore") KeyStore keyStore,
      final @Qualifier("publicJwk") JsonWebKeySet jwk) {
    this.poppConfig = poppConfig;
    this.keyStore = keyStore;
    this.jwk = jwk;
  }

  public String createToken(final TokenParams tokenParams) throws Exception {
    return createToken(tokenParams, null);
  }

  public String createToken(final TokenParams tokenParams, final SecurityParams securityParams)
      throws Exception {
    LOG.debug(
        "Creating POPP token for patientId: {}, insurerId: {}, actorId: {}, actorProfessionOid: {}",
        tokenParams.getPatientId(),
        tokenParams.getInsurerId(),
        tokenParams.getActorId(),
        tokenParams.getActorProfessionOid());

    final PoppToken.Claims claims =
        new PoppToken.Claims(
            tokenParams.getProofMethod(),
            tokenParams.getPatientProofTime(),
            tokenParams.getIat(),
            tokenParams.getPatientId(),
            tokenParams.getInsurerId(),
            tokenParams.getActorId(),
            tokenParams.getActorProfessionOid());

    if (securityParams == null) {
      final PoppConfig.KeyConfig keyConfig = poppConfig.getSec().getKey();
      final String kid = jwk.getJsonWebKeys().getFirst().getKeyId();

      final PoppToken.Header header = new PoppToken.Header(kid);
      final PoppToken poppToken = new PoppToken(header, claims);

      return poppToken.toJwt(keyStore, keyConfig.getAlias(), keyConfig.getPass().toCharArray());
    }

    PoppToken.Header header = new PoppToken.Header(securityParams.getKeyAlias());
    final PoppToken poppToken = new PoppToken(header, claims);
    final KeyStore tmpKeyStore = buildKeyStore(securityParams);
    return poppToken.toJwt(
        tmpKeyStore, securityParams.getKeyAlias(), securityParams.getKeyPass().toCharArray());
  }

  private KeyStore buildKeyStore(final SecurityParams securityParams) throws Exception {
    final byte[] decoded = java.util.Base64.getDecoder().decode(securityParams.getStoreContent());
    final InputStream kis = new java.io.ByteArrayInputStream(decoded);

    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(kis, securityParams.getKeyPass().toCharArray());

    return keyStore;
  }
}
