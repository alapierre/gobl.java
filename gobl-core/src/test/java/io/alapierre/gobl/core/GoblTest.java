package io.alapierre.gobl.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.alapierre.gobl.core.signature.EcdsaSigner;
import io.alapierre.gobl.core.signature.JsonCanoniser;
import io.alapierre.gobl.core.signature.KeySupport;
import lombok.val;
import org.gobl.model.Envelope;
import org.gobl.model.Invoice;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2024.01.20
 */
class GoblTest {

    final ObjectMapper objectMapper = new ObjectMapper();
    final Gobl gobl = new Gobl();

    @Test
    void sign() throws Exception {

        KeySupport keySupport = new KeySupport();
        val keys = keySupport.generate();

        val envelope = gobl.signInvoice("src/test/resources/invoice.json", keys.privateKey(), UUID.randomUUID());
        System.out.println(envelope);
        assertNotNull(envelope);

        val env = objectMapper.readValue(envelope, Envelope.class);
        assertEquals("b6cd1dab63d786cbc6694e4314c587a2660dd3fed1d8934600fc7c5067b8f893", env.getHead().getDig().getVal());
        assertFalse(env.getSigs().isEmpty());

    }

    @Test
    void signByKeyFromFile() throws Exception {

        KeySupport keySupport = new KeySupport();
        Key key = keySupport.loadKey(Path.of("src/test/resources/id_es256.jwk"));

        val envelope = gobl.signInvoice("src/test/resources/invoice.json", (ECPrivateKey) key, UUID.randomUUID());

        System.out.println(envelope);
        assertNotNull(envelope);
    }

    @Test
    void signInvoiceFromObject() throws Exception {

        KeySupport keySupport = new KeySupport();
        Key key = keySupport.loadKey(Path.of("src/test/resources/id_es256.jwk"));

        val invoice = gobl.parseInvoice("src/test/resources/invoice.json");
        val envelope = gobl.signInvoice(invoice, (ECPrivateKey) key, UUID.randomUUID());

        val env = objectMapper.readValue(envelope, Envelope.class);
        assertEquals("b6cd1dab63d786cbc6694e4314c587a2660dd3fed1d8934600fc7c5067b8f893", env.getHead().getDig().getVal());
        assertFalse(env.getSigs().isEmpty());
    }

    @Test
    void parse() throws Exception {

        val invoice = gobl.parseInvoice("src/test/resources/invoice.json");
        System.out.println(invoice);
        assertNotNull(invoice);

    }

    @Test
    void save() throws Exception {

        Invoice invoice = new Invoice();

        invoice.setCode("standard");
        invoice.setIssueDate("2024-01-01");

        Gobl gobl = new Gobl();

        gobl.saveInvoice(invoice, System.out);
    }

    @Test
    void digestObject() throws Exception {
        val invoice = gobl.parseInvoice("src/test/resources/invoice.json");
        val sig = gobl.digest(invoice);
        System.out.println(sig);
        assertEquals("b6cd1dab63d786cbc6694e4314c587a2660dd3fed1d8934600fc7c5067b8f893", sig);
    }

    @Test
    void digestJson() throws Exception {
        JsonCanoniser canoniser = new JsonCanoniser();
        val canonicalJson = canoniser.parse(Files.readAllBytes(Path.of("src/test/resources/invoice.json")));
        val dig = gobl.digest(canonicalJson);
        assertEquals("b6cd1dab63d786cbc6694e4314c587a2660dd3fed1d8934600fc7c5067b8f893", dig);
    }

    @Test
    void signAndCheckSignature() throws Exception {

        JsonCanoniser jsonCanoniser = new JsonCanoniser();
        EcdsaSigner signer = new EcdsaSigner();
        KeySupport keySupport = new KeySupport();

        Key key = keySupport.loadKey(Path.of("src/test/resources/id_es256.jwk"));

        String canonicalJson = jsonCanoniser.parse(Files.readAllBytes(Path.of("src/test/resources/invoice.json")));

        val header = gobl.makeHeader(gobl.digest(canonicalJson));
        val signature = signer.sign((ECPrivateKey) key, "9d8dba19-d041-409c-a451-74e0df6b548a", header);

        System.out.println(signature);

        Key publicKey = keySupport.loadKey(Path.of("src/test/resources/id_es256.pub.jwk"));
        signer.verify((ECPublicKey) publicKey, signature);

    }

}
