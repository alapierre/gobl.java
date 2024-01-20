package io.alapierre.gobl.core.signature;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
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

    public String sign(ECPrivateKey privateKey, Object object) {

        Map<String, Object> jsonContent = objectMapper.convertValue(object, new TypeReference<>() {});

        System.out.println(jsonContent);

        return Jwts.builder()
                .claims(jsonContent)
                .subject("example")
                .signWith(privateKey, Jwts.SIG.ES256)
                .compact();
    }

    public String sign(ECPrivateKey privateKey, String kid, Header header) {

        return Jwts.builder()
                .claim("uuid", header.getUuid())
                .claim("dig", header.getDig())
                .header().add("kid", kid).and()
                .signWith(privateKey, Jwts.SIG.ES256)
                .compact();
    }



    public void verify(ECPublicKey publicKey, String jwsString) {

        Jws<Claims> jws = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(jwsString); //  or parseSignedContent(jwsString)

    }

}
