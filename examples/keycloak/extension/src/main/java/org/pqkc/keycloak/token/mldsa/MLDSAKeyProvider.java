package org.pqkc.keycloak.token.mldsa;

import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.stream.Stream;

/** Supplies the realm's ML-DSA signing key from the component's stored key material. */
public class MLDSAKeyProvider implements KeyProvider {

    private final KeyWrapper key;

    public MLDSAKeyProvider(ComponentModel model) {
        if (model.hasNote(KeyWrapper.class.getName())) {
            this.key = model.getNote(KeyWrapper.class.getName());
        } else {
            this.key = load(model);
            model.setNote(KeyWrapper.class.getName(), this.key);
        }
    }

    private static KeyWrapper load(ComponentModel model) {
        String algorithm = model.get(Attributes.ALGORITHM_KEY, MLDSAKeyProviderFactory.DEFAULT_ALGORITHM);
        PrivateKey privateKey = MLDSAKeys.decodePrivate(model.getConfig().getFirst(MLDSAKeyProviderFactory.PRIVATE_KEY));
        PublicKey publicKey = MLDSAKeys.decodePublic(model.getConfig().getFirst(MLDSAKeyProviderFactory.PUBLIC_KEY));

        KeyWrapper key = new KeyWrapper();
        key.setProviderId(model.getId());
        key.setProviderPriority(model.get(Attributes.PRIORITY_KEY, 0L));
        key.setKid(MLDSAKeys.keyId(publicKey));
        key.setUse(KeyUse.SIG);
        key.setType(MLDSAKeys.KEY_TYPE_AKP);
        key.setAlgorithm(algorithm);
        key.setStatus(KeyStatus.from(model.get(Attributes.ACTIVE_KEY, true),
                                     model.get(Attributes.ENABLED_KEY, true)));
        key.setPrivateKey(privateKey);
        key.setPublicKey(publicKey);
        return key;
    }

    @Override
    public Stream<KeyWrapper> getKeysStream() {
        return Stream.of(key);
    }
}
