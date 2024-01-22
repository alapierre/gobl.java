package io.alapierre.gobl.core.signature;

import lombok.Value;
import lombok.val;
import org.junit.jupiter.api.Test;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2024.01.18
 */
class EcdsaSignerTest {

    @Test
    void testSign() {

        EcdsaSigner signer = new EcdsaSigner();
        KeySupport keySupport = new KeySupport();
        val keys = keySupport.generate();

        val signature = signer.sign(keys.privateKey(), new Model(new Dig("sha256", "b6cd1dab63d786cbc6694e4314c587a2660dd3fed1d8934600fc7c5067b8f893")), "example");
        signer.verify(keys.publicKey(), signature);

    }

    @Value
    private static class Model {
        Dig dig;
    }

}
