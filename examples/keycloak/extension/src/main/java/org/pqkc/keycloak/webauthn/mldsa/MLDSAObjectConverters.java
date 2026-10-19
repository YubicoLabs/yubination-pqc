package org.pqkc.keycloak.webauthn.mldsa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.util.ObjectConverter;

/**
 * Builds the {@link ObjectConverter} that Keycloak hands to webauthn4j, with COSE
 * {@code kty = 7} (AKP) wired to {@link MLDSACOSEKey}.
 *
 * <p>{@code COSEKey} declares {@code @JsonTypeInfo(use = NAME, property = "1")} plus a static
 * {@code @JsonSubTypes} list. Jackson merges runtime-registered subtypes with the annotated
 * ones, so registering "7" here extends the closed set without touching the interface.
 */
public final class MLDSAObjectConverters {

    private static volatile ObjectConverter shared;

    private MLDSAObjectConverters() {}

    /** A shared converter. Jackson ObjectMappers are thread-safe once configured. */
    public static ObjectConverter shared() {
        if (shared == null) {
            synchronized (MLDSAObjectConverters.class) {
                if (shared == null) shared = create();
            }
        }
        return shared;
    }

    /** A fresh ObjectConverter that understands ML-DSA credentials in addition to the stock ones. */
    public static ObjectConverter create() {
        MLDSAAlgorithms.install();

        ObjectMapper jsonMapper = new ObjectMapper();
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());

        NamedType akp = new NamedType(MLDSACOSEKey.class, String.valueOf(MLDSAParameterSet.COSE_KTY_AKP));
        // attestation objects and stored credentials are CBOR; the JSON mapper is registered too so
        // that any JSON-side COSE key handling stays symmetric.
        cborMapper.registerSubtypes(akp);
        jsonMapper.registerSubtypes(akp);

        return new ObjectConverter(jsonMapper, cborMapper);
    }
}
