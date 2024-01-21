package io.alapierre.gobl.core;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.alapierre.gobl.core.signature.EcdsaSigner;
import io.alapierre.gobl.core.signature.JsonCanoniser;
import io.alapierre.ksef.fa.model.gobl.InvoiceSerializer;
import io.jsonwebtoken.security.SignatureException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.gobl.model.Digest;
import org.gobl.model.Envelope;
import org.gobl.model.Header;
import org.gobl.model.Invoice;

import java.io.*;
import java.nio.file.Path;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2024.01.20
 */
@Slf4j
public class Gobl {

    private final EcdsaSigner signer = new EcdsaSigner();
    private final ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private final JsonCanoniser jsonCanoniser = new JsonCanoniser();

    public Gobl() {
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public <T> T extractFromEnvelope(File envelopeFile, Class<T> clazz, Key key) throws IOException {

        val envelopeNode = objectMapper.readValue(envelopeFile, ObjectNode.class);
        val sigsNode = envelopeNode.get("sigs");

        JavaType type = objectMapper.getTypeFactory().constructCollectionType(List.class, String.class);
        List<String> sigs = objectMapper.treeToValue(sigsNode, type);

        val docNode = envelopeNode.get("doc");
        val doc = objectMapper.treeToValue(docNode, clazz);
        val canonizedJson = jsonCanoniser.parse(doc);
        val contentDigest = digest(canonizedJson);

        // TODO: check signature here with proper key
        sigs.forEach(s -> {
            log.debug("checking signature {}", s);
            String digest = signer.verify((ECPublicKey) key, s).get("val"); //TODO make it better

            if (contentDigest.equals(digest))
                log.debug("digest are equals");
            else {
                log.debug("digest form signature {} != {}", digest, contentDigest);
                throw new SignatureException("Digital signature verification failed.");
            }
        });

        return objectMapper.treeToValue(docNode, clazz);

    }

    public <T> T extractFromEnvelope(File envelopeFile, Class<T> clazz) throws IOException {
        val envelopeNode = objectMapper.readValue(envelopeFile, ObjectNode.class);
        val docNode = envelopeNode.get("doc");
        return objectMapper.treeToValue(docNode, clazz);
    }

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

    public String signInvoice(Invoice invoice, ECPrivateKey privateKey, UUID kid) throws IOException {
        String canonicalJson = jsonCanoniser.parse(invoice);
        val header = makeHeader(digest(canonicalJson));
        val signedString = signer.sign(privateKey, kid.toString(), header);
        return prepareEnvelope(header, signedString, invoice);
    }

    public String signInvoice(InputStream source, ECPrivateKey privateKey, UUID kid) throws IOException {
        byte[] content = source.readAllBytes();
        String canonicalJson = jsonCanoniser.parse(content);
        val header = makeHeader(digest(canonicalJson));
        val signedString = signer.sign(privateKey, kid.toString(), header);
        val invoice = objectMapper.readValue(content, Invoice.class);
        return prepareEnvelope(header, signedString, invoice);
    }

    private String prepareEnvelope(Header header, String signedString, Invoice invoice) throws IOException {
        Envelope envelope = new Envelope();
        envelope.set$schema("https://gobl.org/draft-0/envelope");
        envelope.setHead(header);
        envelope.setSigs(List.of(signedString));

        ObjectNode invoiceNode = objectMapper.valueToTree(invoice);
        invoiceNode.put("$schema", "https://gobl.org/draft-0/bill/invoice");
        ObjectNode envelopNode = objectMapper.valueToTree(envelope);
        envelopNode.set("doc", invoiceNode);
        return objectMapper.writeValueAsString(envelopNode);
    }

    public String digest(@NonNull Invoice invoice) throws IOException {
        return digest(jsonCanoniser.parse(invoice));
    }

    public String digest(@NonNull String canonicalJson) {
        try {
            val md = MessageDigest.getInstance("SHA-256");
            val sha = md.digest(canonicalJson.getBytes());
            return HexFormat.of().formatHex(sha);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    protected Header makeHeader(@NonNull String digestString) {

            Header header = new Header();
            Digest digest = new Digest();
            digest.setVal(digestString);
            digest.setAlg("sha256");

            header.setDig(digest);
            header.setUuid(UUID.randomUUID());
            return header;
    }

}
