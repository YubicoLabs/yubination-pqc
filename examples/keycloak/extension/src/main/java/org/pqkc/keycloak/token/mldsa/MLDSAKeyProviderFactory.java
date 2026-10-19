package org.pqkc.keycloak.token.mldsa;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.pqkc.keycloak.webauthn.mldsa.MLDSAParameterSet;

import java.security.KeyPair;
import java.util.List;

/**
 * Generates and stores an ML-DSA realm signing key.
 *
 * <p>{@link #createFallbackKeys} means an operator only has to select {@code ML-DSA-44} as a realm
 * or client signing algorithm - Keycloak asks for a key of that algorithm, finds none, and this
 * provisions one.
 */
public class MLDSAKeyProviderFactory implements KeyProviderFactory<MLDSAKeyProvider> {

    public static final String ID = "mldsa-generated";

    static final String PRIVATE_KEY = "mldsaPrivateKey";
    static final String PUBLIC_KEY = "mldsaPublicKey";
    static final String DEFAULT_ALGORITHM = "ML-DSA-44";

    private static final ProviderConfigProperty ALGORITHM_PROPERTY = new ProviderConfigProperty(
            Attributes.ALGORITHM_KEY, "Algorithm", "ML-DSA parameter set (FIPS 204 / RFC 9964)",
            ProviderConfigProperty.LIST_TYPE, DEFAULT_ALGORITHM,
            MLDSAParameterSet.ML_DSA_44.jcaName(),
            MLDSAParameterSet.ML_DSA_65.jcaName(),
            MLDSAParameterSet.ML_DSA_87.jcaName());

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property(Attributes.PRIORITY_PROPERTY)
            .property(Attributes.ENABLED_PROPERTY)
            .property(Attributes.ACTIVE_PROPERTY)
            .property(ALGORITHM_PROPERTY)
            .build();

    @Override
    public MLDSAKeyProvider create(KeycloakSession session, ComponentModel model) {
        return new MLDSAKeyProvider(model);
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model)
            throws ComponentValidationException {
        ConfigurationValidationHelper.check(model)
                .checkLong(Attributes.PRIORITY_PROPERTY, false)
                .checkBoolean(Attributes.ENABLED_PROPERTY, false)
                .checkBoolean(Attributes.ACTIVE_PROPERTY, false);

        String algorithm = model.get(Attributes.ALGORITHM_KEY, DEFAULT_ALGORITHM);
        MLDSAParameterSet params = MLDSAParameterSet.fromJcaName(algorithm);
        if (params == null) {
            throw new ComponentValidationException("Unknown ML-DSA parameter set: " + algorithm);
        }

        boolean present = model.contains(PRIVATE_KEY) && model.contains(PUBLIC_KEY);
        boolean matches = present && params == MLDSAKeys.parameterSetOf(
                MLDSAKeys.decodePublic(model.getConfig().getFirst(PUBLIC_KEY)));
        if (!present || !matches) {
            generateInto(model, params);
        }
    }

    private static void generateInto(ComponentModel model, MLDSAParameterSet params) {
        KeyPair pair = MLDSAKeys.generate(params);
        model.put(PRIVATE_KEY, MLDSAKeys.encodePrivate(pair.getPrivate()));
        model.put(PUBLIC_KEY, MLDSAKeys.encodePublic(pair.getPublic()));
        model.put(Attributes.ALGORITHM_KEY, params.jcaName());
    }

    @Override
    public boolean createFallbackKeys(KeycloakSession session, KeyUse keyUse, String algorithm) {
        MLDSAParameterSet params = MLDSAParameterSet.fromJcaName(algorithm);
        if (keyUse != KeyUse.SIG || params == null) {
            return false;
        }
        RealmModel realm = session.getContext().getRealm();
        ComponentModel generated = new ComponentModel();
        generated.setName("fallback-" + algorithm);
        generated.setParentId(realm.getId());
        generated.setProviderId(ID);
        generated.setProviderType(KeyProvider.class.getName());

        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(Attributes.PRIORITY_KEY, "-100");
        config.putSingle(Attributes.ALGORITHM_KEY, params.jcaName());
        generated.setConfig(config);

        KeyPair pair = MLDSAKeys.generate(params);
        config.putSingle(PRIVATE_KEY, MLDSAKeys.encodePrivate(pair.getPrivate()));
        config.putSingle(PUBLIC_KEY, MLDSAKeys.encodePublic(pair.getPublic()));

        realm.addComponentModel(generated);
        return true;
    }

    @Override public String getId() { return ID; }
    @Override public String getHelpText() { return "Generates ML-DSA (FIPS 204) keys for token signing"; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return CONFIG_PROPERTIES; }
}
