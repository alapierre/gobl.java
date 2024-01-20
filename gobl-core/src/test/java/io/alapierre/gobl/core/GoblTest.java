package io.alapierre.gobl.core;

import io.alapierre.gobl.core.signature.KeySupport;
import lombok.val;
import org.gobl.model.Invoice;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.UUID;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2024.01.20
 */
class GoblTest {

    @Test
    void sign() throws Exception {

        KeySupport keySupport = new KeySupport();
        val keys = keySupport.generate();

        Gobl gobl = new Gobl();

        val envelope = gobl.signInvoice("src/test/resources/invoice.json", keys.privateKey(), UUID.randomUUID());
        System.out.println(envelope);
        Assertions.assertNotNull(envelope);
    }

    @Test
    void parse() throws Exception {

        Gobl gobl = new Gobl();

        val invoice = gobl.parseInvoice("src/test/resources/invoice.json");
        System.out.println(invoice);
        Assertions.assertNotNull(invoice);

    }

    @Test
    void save() throws Exception {

        Invoice invoice = new Invoice();

        invoice.setCode("standard");
        invoice.setIssueDate("2024-01-01");

        Gobl gobl = new Gobl();

        gobl.saveInvoice(invoice, System.out);
    }

}
