package io.alapierre.gobl.core.signature;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import lombok.val;
import org.gobl.model.Header;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2024.01.18
 */
public class EcdsaSigner {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Signs the provided object using the given private key and subject.
     *
     * @param privateKey The ECPrivateKey used for signing.
     * @param object The object to be converted to JSON and signed.
     * @param subject The subject of the JWS.
     * @return The signed JWS string.
     */
    public String sign(ECPrivateKey privateKey, Object object, String subject) {

        Map<String, Object> jsonContent = objectMapper.convertValue(object, new TypeReference<>() {});

        return Jwts.builder()
                .claims(jsonContent)
                .subject(subject)
                .signWith(privateKey, Jwts.SIG.ES256)
                .compact();
    }

    /**
     * Signs the JWS with the provided ECPrivateKey, kid and header information.
     *
     * @param privateKey The ECPrivateKey used for signing.
     * @param kid The Key ID (kid) value to be included in the JWS header.
     * @param header The additional header information for the JWS.
     * @return The signed JWT string.
     */
    public String sign(ECPrivateKey privateKey, String kid, Header header) {

        return Jwts.builder()
                .claim("uuid", header.getUuid())
                .claim("dig", header.getDig())
                .header().add("kid", kid).and()
                .signWith(privateKey, Jwts.SIG.ES256)
                .compact();
    }

    /**
     * Verifies the signature of a compact JWT string using the provided ECPublicKey.
     *
     * @param publicKey The ECPublicKey used to verify the signature.
     * @param jwsString The compact JWT string to be verified.
     * @return The Dig object extracted from the JWT payload.
     * @throws SignatureException If the signature verification fails or the JWT does not contain a "dig" claim.
     */
    public Dig verify(ECPublicKey publicKey, String jwsString) {

        Jws<Claims> jws = Jwts.parser()
                .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(jwsString); //  or parseSignedContent(jwsString)

        val map = jws.getPayload().get("dig", Map.class);

        if(map != null) {
            val dig = objectMapper.convertValue(map, Dig.class);
            if(dig.alg() == null || dig.val() == null) throw new SignatureException("Signature dig claim do not contains val or alg attribute");
            return dig;
        } else throw new SignatureException("Signature do not contains dig claim");
    }
}
