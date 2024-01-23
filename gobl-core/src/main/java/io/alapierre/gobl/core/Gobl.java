package io.alapierre.gobl.core;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.alapierre.gobl.core.exceptions.NoSuchDigestAlgorithmException;
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

    /**
     * Extracts the document from an envelope JSON file.
     *
     * @param envelopeFile The envelope JSON file from which to extract the document, e.g., Invoice.
     * @param clazz        The class representing the type of the document.
     * @param key          The ECPublicKey used for signature verification.
     * @return The extracted document.
     * @throws IOException          If an I/O error occurs when reading or parsing the envelope file.
     * @throws SignatureException   If the digital signature verification fails.
     */
    public <T> T extractFromEnvelope(File envelopeFile, Class<T> clazz, Key key) throws IOException {

        val envelopeNode = objectMapper.readValue(envelopeFile, ObjectNode.class);
        val sigsNode = envelopeNode.get("sigs");

        JavaType type = objectMapper.getTypeFactory().constructCollectionType(List.class, String.class);
        List<String> sigs = objectMapper.treeToValue(sigsNode, type);

        val docNode = envelopeNode.get("doc");
        if(docNode == null) throw new IllegalArgumentException("Envelop must contains document in 'doc' attribute");

        val doc = objectMapper.treeToValue(docNode, clazz);
        val canonizedJson = jsonCanoniser.parse(doc);

        if(sigs.isEmpty()) {
            throw new SignatureException("No signatures found.");
        } else if (sigs.size() > 1) {
            throw new SignatureException("Multiple signatures are not supported.");
        }

        val s = sigs.get(0);
        log.debug("checking signature {}", s);
        val dig = signer.verify((ECPublicKey) key, s);
        val contentDigest = digest(canonizedJson, dig.alg());

        if (contentDigest.equals(dig.val()))
            log.debug("digest are equals");
        else {
            log.debug("digest form signature {} != {} ({} counted from canonical JSON)", dig.val(), contentDigest, dig.alg());
            throw new SignatureException("Digital signature verification failed.");
        }
        return doc;
    }

    /**
     * Extracts an object of type T from an envelope file without signature verification.
     *
     * @param envelopeFile the envelope JSON file to extract the object from
     * @param clazz the class of the object to be extracted
     * @return The extracted document
     * @throws IOException if an I/O error occurs while reading the envelope file
     */
    public <T> T extractFromEnvelope(File envelopeFile, Class<T> clazz) throws IOException {
        val envelopeNode = objectMapper.readValue(envelopeFile, ObjectNode.class);
        val docNode = envelopeNode.get("doc");
        return objectMapper.treeToValue(docNode, clazz);
    }

    /**
     * Saves the given invoice to the specified file.
     *
     * @param invoice The invoice to be saved.
     * @param fileName The name of the file where the invoice will be saved.
     * @throws IOException If there is an error while saving the invoice to the file.
     */
    public void saveInvoice(Invoice invoice, String fileName) throws IOException {
        try (val out = new FileOutputStream(fileName)){
            saveInvoice(invoice, out);
        }
    }

    /**
     * Save the given invoice to the specified file path.
     *
     * @param invoice the invoice to be saved
     * @param path the file path where the invoice should be saved
     * @throws IOException if there is an error during the saving process
     */
    public void saveInvoice(Invoice invoice, Path path) throws IOException {
        try (val out = new FileOutputStream(path.toFile())){
            saveInvoice(invoice, out);
        }
    }

    /**
     * Saves the given invoice to the specified output stream.
     *
     * @param invoice the invoice to be saved
     * @param outputStream the output stream to save the invoice to
     * @throws IOException if an I/O error occurs while saving the invoice
     */
    public void saveInvoice(Invoice invoice, OutputStream outputStream) throws IOException {
        InvoiceSerializer serializer = new InvoiceSerializer();
        serializer.toStream(outputStream, invoice);
    }

    /**
     * Parses an invoice JSON file and returns the corresponding Invoice object.
     *
     * @param invoiceFile the name and path to the invoice file to be parsed
     * @return the parsed Invoice object
     * @throws IOException if an I/O error occurs while reading the invoice file
     */
    public Invoice parseInvoice(String invoiceFile) throws IOException {
        try (val is = new FileInputStream(invoiceFile)) {
            return parseInvoice(is);
        }
    }

    /**
     * Parses an Invoice from the specified file.
     *
     * @param source the path to the file containing the Invoice data
     * @return the parsed Invoice object
     * @throws IOException if an I/O error occurs while reading the file
     */
    public Invoice parseInvoice(Path source) throws IOException {
        try (val is = new FileInputStream(source.toFile())) {
            return parseInvoice(is);
        }
    }

    /**
     * Parses an invoice from an input stream.
     *
     * @param source the input stream containing the invoice data
     * @return the parsed invoice object
     */
    public Invoice parseInvoice(InputStream source) {
        InvoiceSerializer serializer = new InvoiceSerializer();
        return serializer.fromStream(source);
    }

    /**
     * Signs the invoice JSON file using the provided private key and it ID.
     *
     * @param invoiceFile The path to the invoice file to be signed.
     * @param privateKey The ECPrivateKey object representing the private key.
     * @param kid The key identifier associated with the private key.
     * @return A string representing the signed invoice in JSON format.
     * @throws IOException If an I/O error occurs while reading the invoice file.
     */
    public String signInvoice(Path invoiceFile, ECPrivateKey privateKey, UUID kid) throws IOException {
        try (val is = new FileInputStream(invoiceFile.toFile())) {
            return signInvoice(is, privateKey, kid);
        }
    }

    /**
     * Signs the invoice file with the specified private key and returns the signature as a JSON string.
     *
     * @param invoiceFile The path to the invoice file.
     * @param privateKey The ECPrivateKey used for signing the invoice.
     * @param kid The key identifier associated with the private key.
     * @return A string representing the signed invoice in JSON format.
     * @throws IOException if an I/O error occurs while reading the invoice file.
     */
    public String signInvoice(String invoiceFile, ECPrivateKey privateKey, UUID kid) throws IOException {
        try (val is = new FileInputStream(invoiceFile)) {
            return signInvoice(is, privateKey, kid);
        }
    }

    /**
     * Signs the given invoice instance using the provided private key and its identifier.
     *
     * @param invoice The invoice object to be signed.
     * @param privateKey The private key used for signing the invoice.
     * @param kid The key identifier associated with the private key.
     * @return The signed invoice as an envelope.
     * @throws IOException If an I/O error occurs while signing the invoice.
     */
    public String signInvoice(Invoice invoice, ECPrivateKey privateKey, UUID kid) throws IOException {
        String canonicalJson = jsonCanoniser.parse(invoice);
        val header = makeHeader(digest(canonicalJson));
        val signedString = signer.sign(privateKey, kid.toString(), header);
        return prepareEnvelope(header, signedString, invoice);
    }

    /**
     * Signs an invoice by providing the InputStream, the EC private key and its identifier.
     *
     * @param source    the input stream representing the invoice source JSON file
     * @param privateKey   the EC private key to be used for signing
     * @param kid   The key identifier associated with the private key.
     * @return a string representing the signed invoice
     * @throws IOException if an I/O error occurs while reading the input stream
     */
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

    /**
     * Calculates the SHA-256 digest of the given invoice object using JSON canonicalization.
     *
     * @param invoice The invoice to calculate the digest for. Must not be null.
     * @return The SHA-256 digest of the invoice.
     * @throws IOException If an IO error occurs during the digest calculation.
     */
    public String digest(@NonNull Invoice invoice) throws IOException {
        return digest(jsonCanoniser.parse(invoice));
    }

    /**
     * Computes the SHA-256 digest of the given canonical JSON string.
     *
     * @param canonicalJson the canonical JSON string to compute the digest for
     * @return the hash digest of the canonical JSON as a hexadecimal string
     * @throws IllegalStateException if the SHA-256 algorithm is not available
     */
    public String digest(@NonNull String canonicalJson) {
        try {
            val md = MessageDigest.getInstance("SHA-256");
            val sha = md.digest(canonicalJson.getBytes());
            return HexFormat.of().formatHex(sha);
        } catch (NoSuchAlgorithmException ex) {
            throw new NoSuchDigestAlgorithmException(ex);
        }
    }

    /**
     * Generates a hash digest of the given canonical JSON using the specified algorithm.
     *
     * @param canonicalJson the canonical JSON content to generate the digest from
     * @param algorithm the algorithm to use for generating the digest, one of: MD5, SHA1, SHA256, SHA384, SHA512
     * @return the hash digest of the canonical JSON as a hexadecimal string
     * @throws NoSuchDigestAlgorithmException if the specified algorithm is not supported
     */
    public String digest(@NonNull String canonicalJson, String algorithm) {
        try {
            val md = MessageDigest.getInstance(algorithm);
            val sha = md.digest(canonicalJson.getBytes());
            return HexFormat.of().formatHex(sha);
        } catch (NoSuchAlgorithmException ex) {
            throw new NoSuchDigestAlgorithmException(ex);
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
