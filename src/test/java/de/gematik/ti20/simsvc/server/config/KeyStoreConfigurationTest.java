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
package de.gematik.ti20.simsvc.server.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyStore;
import org.junit.jupiter.api.Test;

class KeyStoreConfigurationTest {

  @Test
  void poppKeyStoreLoadsConfiguredPkcs12Store() throws Exception {
    final PoppConfig.StoreConfig storeConfig = new PoppConfig.StoreConfig();
    storeConfig.setPath("keystore.p12");
    storeConfig.setPass("testpassword");

    final PoppConfig.KeyConfig keyConfig = new PoppConfig.KeyConfig();
    keyConfig.setAlias("poppmock");
    keyConfig.setPass("testpassword");

    final PoppConfig.SecurityConfig securityConfig = new PoppConfig.SecurityConfig();
    securityConfig.setStore(storeConfig);
    securityConfig.setKey(keyConfig);

    final PoppConfig poppConfig = new PoppConfig();
    poppConfig.setSec(securityConfig);

    final KeyStoreConfiguration keyStoreConfiguration = new KeyStoreConfiguration();
    final KeyStore keyStore = keyStoreConfiguration.poppKeyStore(poppConfig);

    assertNotNull(keyStore);
    assertEquals("PKCS12", keyStore.getType());
    assertNotNull(keyStore.getCertificate("poppmock"));
  }
}
