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
package de.gematik.ti20.simsvc.server.model;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.X509VerificationKeyResolver;

@Slf4j
public class PoppToken {

  // Header of the PoPP token
  @Getter
  public static class Header {

    private String typ = "vnd.telematik.popp+jwt";
    private String alg = "ES256";
    private String kid;

    public Header(String typ, String alg, String kid) {
      this.typ = typ;
      this.alg = alg;
      this.kid = kid;
    }

    public Header(String kid) {
      this.kid = kid;
    }
  }

  // Claims of the PoPP token
  @Getter
  public static class Claims {

    private String version = "1.0.0";
    private String iss = "https://popp.example.com";

    private String proofMethod;
    private long patientProofTime;
    private long iat;
    private String patientId;
    private String insurerId;
    private String actorId;
    private String actorProfessionOid;

    public Claims(
        final String version,
        final String iss,
        final long iat,
        final String proofMethod,
        final long patientProofTime,
        final String patientId,
        final String insurerId,
        final String actorId,
        final String actorProfessionOid) {
      this.version = version;
      this.iss = iss;
      this.iat = iat;
      this.proofMethod = proofMethod;
      this.patientProofTime = patientProofTime;
      this.patientId = patientId;
      this.insurerId = insurerId;
      this.actorId = actorId;
      this.actorProfessionOid = actorProfessionOid;
    }

    public Claims(
        final String proofMethod,
        final long patientProofTime,
        final long iat,
        final String patientId,
        final String insurerId,
        final String actorId,
        final String actorProfessionOid) {
      this.proofMethod = proofMethod;
      this.patientProofTime = patientProofTime;
      this.iat = iat;
      this.patientId = patientId;
      this.insurerId = insurerId;
      this.actorId = actorId;
      this.actorProfessionOid = actorProfessionOid;
    }
  }

  private Header header;
  private Claims claims;

  // Constructor for data-based token
  public PoppToken(Header header, Claims claims) {
    this.header = header;
    this.claims = claims;
  }

  // Constructor for JWT-based token (private, only accessible via fromJwt())
  private PoppToken() {}

  // Return header and claims
  public Header getHeader() {
    return header;
  }

  public Claims getClaims() {
    return claims;
  }

  // Generate JWT from the given data
  public String toJwt(KeyStore keyStore, String alias, char[] keyPassword) throws Exception {
    log.debug("Starting JWT generation for alias: {}", alias);

    // Extract private key and certificate from the KeyStore
    log.debug("Extracting private key and certificate from the KeyStore...");

    final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPassword);

    // Define JWT claims
    log.debug("Defining JWT claims...");
    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setIssuedAt(NumericDate.fromSeconds(claims.getIat()));

    jwtClaims.setClaim("version", claims.getVersion());
    jwtClaims.setIssuer(claims.getIss());
    jwtClaims.setClaim("proofMethod", claims.getProofMethod());
    jwtClaims.setClaim("patientProofTime", claims.getPatientProofTime());
    jwtClaims.setClaim("patientId", claims.getPatientId());
    jwtClaims.setClaim("insurerId", claims.getInsurerId());
    jwtClaims.setClaim("actorId", claims.getActorId());
    jwtClaims.setClaim("actorProfessionOid", claims.getActorProfessionOid());

    // Create the signature
    log.debug("Creating JWT signature...");
    JsonWebSignature jws = new JsonWebSignature();
    jws.setPayload(jwtClaims.toJson());
    jws.setKey(privateKey);
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
    jws.setHeader("typ", header.getTyp());
    jws.setHeader("kid", header.getKid());

    String jwt = jws.getCompactSerialization();
    log.debug("JWT generation completed successfully.");
    return jwt;
  }

  // Parse JWT and create a PoppToken object
  public static PoppToken fromJwt(String jwt) throws Exception {
    log.debug("Starting JWT parsing and validation...");

    // Extract the certificate chain from the JWT
    JsonWebSignature jws = new JsonWebSignature();
    jws.setCompactSerialization(jwt);

    // Create a JwtConsumer with the resolver
    log.debug("Creating JwtConsumer...");
    JwtConsumer jwtConsumer = new JwtConsumerBuilder().setDisableRequireSignature()
        .setSkipSignatureVerification()
        .build();

    // Verify the JWT and extract the claims
    JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
    log.debug("JWT successfully verified.");

    // Validate required claims
    if (jwtClaims.getStringClaimValue("version") == null) {
      log.error("The claim 'version' is missing in the JWT.");
      throw new RuntimeException("The claim 'version' is missing in the JWT.");
    }
    if (jwtClaims.getIssuer() == null) {
      log.error("The claim 'iss' (Issuer) is missing in the JWT.");
      throw new RuntimeException("The claim 'iss' (Issuer) is missing in the JWT.");
    }

    // Create TokenClaims
    log.debug("Creating TokenClaims...");
    Claims claims =
        new Claims(
            jwtClaims.getStringClaimValue("version"),
            jwtClaims.getIssuer(),
            jwtClaims.getIssuedAt().getValueInMillis(),
            jwtClaims.getStringClaimValue("proofMethod"),
            (Long) jwtClaims.getClaimValue("patientProofTime"),
            jwtClaims.getStringClaimValue("patientId"),
            jwtClaims.getStringClaimValue("insurerId"),
            jwtClaims.getStringClaimValue("actorId"),
            jwtClaims.getStringClaimValue("actorProfessionOid"));

    // Create TokenHeader
    log.debug("Creating TokenHeader...");
    Header header =
        new Header(
            jws.getHeader("typ"),
            jws.getAlgorithmHeaderValue(),
            jws.getKeyIdHeaderValue());

    log.debug("JWT parsing and validation completed successfully.");
    return new PoppToken(header, claims);
  }

  // Validate the certificate chain against trusted certificates in the KeyStore
  private static void validateCertificateChain(List<X509Certificate> certs, KeyStore keyStore)
      throws Exception {
    log.debug("Extracting trusted certificates from the KeyStore...");
    List<X509Certificate> trustedCerts = new ArrayList<>();
    Enumeration<String> aliases = keyStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      Certificate cert = keyStore.getCertificate(alias);
      if (cert instanceof X509Certificate) {
        trustedCerts.add((X509Certificate) cert);
      }
    }

    // Check if at least one certificate in the chain is trusted
    log.debug("Checking if the certificate chain is trusted...");
    boolean isValid = certs.stream().anyMatch(trustedCerts::contains);
    if (!isValid) {
      log.error("The certificate chain in the JWT is not trusted.");
      throw new CertificateException(
          "The certificate chain in the JWT is not trusted. Ensure that the KeyStore contains the appropriate trusted certificates.");
    }
    log.debug("Certificate chain successfully validated.");
  }
}
