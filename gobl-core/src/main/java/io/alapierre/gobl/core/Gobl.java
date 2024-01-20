package io.alapierre.gobl.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.alapierre.gobl.core.signature.EcdsaSigner;
import io.alapierre.gobl.core.signature.KeySupport;
import io.alapierre.ksef.fa.model.gobl.InvoiceSerializer;
import lombok.NonNull;
import lombok.val;
import org.gobl.model.Object;
import org.gobl.model.*;

import java.io.*;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.util.HexFormat;
import java.util.List;
import java.util.TreeMap;
import java.util.UUID;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2024.01.20
 */
public class Gobl {

    private final EcdsaSigner signer = new EcdsaSigner();
    private final KeySupport keySupport = new KeySupport();

    public Gobl() {}

    public void saveInvoice(Invoice invoice, String fileName) throws IOException {
        try (val out = new FileOutputStream(fileName)){
            saveInvoice(invoice, out);
        }
    }

    public void saveInvoice(Invoice invoice, Path path) throws IOException {
        try (val out = new FileOutputStream(path.toFile())){
            saveInvoice(invoice, out);
        }
    }

    public void saveInvoice(Invoice invoice, OutputStream outputStream) throws IOException {
        InvoiceSerializer serializer = new InvoiceSerializer();
        serializer.toStream(outputStream, invoice);
    }

    public Invoice parseInvoice(String invoiceFile) throws IOException {
        try (val is = new FileInputStream(invoiceFile)) {
            return parseInvoice(is);
        }
    }

    public Invoice parseInvoice(Path source) throws IOException {
        try (val is = new FileInputStream(source.toFile())) {
            return parseInvoice(is);
        }
    }

    public Invoice parseInvoice(InputStream source) {
        InvoiceSerializer serializer = new InvoiceSerializer();
        return serializer.fromStream(source);
    }

    public String signInvoice(Path invoiceFile, ECPrivateKey privateKey, UUID kid) throws IOException {
        try (val is = new FileInputStream(invoiceFile.toFile())) {
            return signInvoice(is, privateKey, kid);
        }
    }

    public String signInvoice(String invoiceFile, ECPrivateKey privateKey, UUID kid) throws IOException {
        try (val is = new FileInputStream(invoiceFile)) {
            return signInvoice(is, privateKey, kid);
        }
    }

    public String signInvoice(InputStream source, ECPrivateKey privateKey, UUID kid) throws IOException {

        byte[] content = source.readAllBytes();

        final ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

        JsonNode jsonNode = mapper.readTree(content);

        @SuppressWarnings("unchecked")
        TreeMap<String, Object> map = mapper.convertValue(jsonNode, TreeMap.class);
        String canonicalJson = mapper.writeValueAsString(map);

        val header = digestAndMakeHeader(canonicalJson);

        val sig = signer.sign(privateKey, kid.toString(), header);

        Envelope envelope = new Envelope();
        envelope.set$schema("https://gobl.org/draft-0/envelope");
        envelope.setHead(header);
        envelope.setSigs(List.of(sig));

        mapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, false);

        val invoice = mapper.readValue(content, Invoice.class);
        ObjectNode invoiceNode = mapper.valueToTree(invoice);
        invoiceNode.put("$schema", "https://gobl.org/draft-0/bill/invoice");

        ObjectNode envelopNode = mapper.valueToTree(envelope);
        envelopNode.set("doc", invoiceNode);

        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(envelopNode);
    }

    protected Header digestAndMakeHeader(@NonNull String canonicalJson) {
        try {
            val md = MessageDigest.getInstance("SHA-256");
            val sha = md.digest(canonicalJson.getBytes());
            val str = HexFormat.of().formatHex(sha);

            Header header = new Header();
            Digest digest = new Digest();
            digest.setVal(str);
            digest.setAlg("sha256");

            header.setDig(digest);
            header.setUuid(UUID.randomUUID());
            return header;
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

}
