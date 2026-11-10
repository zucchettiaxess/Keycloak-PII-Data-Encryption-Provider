/*
 * Copyright (C) 2025 Muhammad Lukman Nasaruddin <lukman.nasaruddin@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */
package my.unifi.eset.keycloak.piidataencryption.ldap;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import java.util.Map;
import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.component.ComponentModel;
import org.keycloak.config.MetricsOptions;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.ldap.LDAPIdentityStoreRegistry;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;
import org.keycloak.storage.ldap.mappers.LDAPConfigDecorator;

public class EncryptedLDAPStorageProviderFactory extends LDAPStorageProviderFactory {

    // Same config key as LDAPStorageProviderFactory.METRICS_ENABLED, which is private there.
    private static final String METRICS_ENABLED = "metricsEnabled";

    LDAPIdentityStoreRegistry ldapStoreRegistryOverride;
    // Mirrors LDAPStorageProviderFactory#ldapRequestTimer (private there); null when LDAP
    // metrics are disabled. Keycloak 26.8.0 added it as a getLdapStore argument.
    Meter.MeterProvider<Timer> ldapRequestTimerOverride;

    @Override
    public int order() {
        return 1000;
    }

    @Override
    public void init(Config.Scope config) {
        super.init(config);
        this.ldapStoreRegistryOverride = new LDAPIdentityStoreRegistry();

        // Built exactly like LDAPStorageProviderFactory#init does in Keycloak 26.8.
        boolean ldapMetricsFeature = Profile.isFeatureEnabled(Profile.Feature.LDAP_METRICS);
        boolean metricsEnabledConfig = config.getBoolean(METRICS_ENABLED, true);
        boolean globalMetricsEnabled = config.root().getBoolean(MetricsOptions.METRICS_ENABLED.getKey(), false);
        if (ldapMetricsFeature && metricsEnabledConfig && globalMetricsEnabled) {
            this.ldapRequestTimerOverride = Timer.builder("keycloak.ldap.requests")
                    .description("Time taken for LDAP requests")
                    .withRegistry(Metrics.globalRegistry);
        }
    }

    @Override
    public void close() {
        super.close();
        this.ldapStoreRegistryOverride = null;
        this.ldapRequestTimerOverride = null;
    }

    @Override
    public LDAPStorageProvider create(KeycloakSession session, ComponentModel model) {
        Map<ComponentModel, LDAPConfigDecorator> configDecorators = getLDAPConfigDecorators(session, model);
        LDAPIdentityStore ldapIdentityStore = this.ldapStoreRegistryOverride.getLdapStore(session, model, configDecorators, ldapRequestTimerOverride);
        return new EncryptedLDAPStorageProvider(this, session, model, ldapIdentityStore);
    }

}
