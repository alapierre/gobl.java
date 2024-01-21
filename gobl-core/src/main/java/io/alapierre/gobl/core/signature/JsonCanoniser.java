package io.alapierre.gobl.core.signature;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import lombok.NonNull;

import java.io.IOException;
import java.util.TreeMap;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2024.01.21
 */
public class JsonCanoniser {

    private final ObjectMapper canonicalMapper = new ObjectMapper();

    public JsonCanoniser() {
        canonicalMapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    }

    public String parse(@NonNull byte[] content) throws IOException {
        return parse(canonicalMapper.readTree(content));
    }

    public String parse(@NonNull Object object) throws IOException {
        return parse(canonicalMapper.valueToTree(object));
    }

    public String parse(@NonNull JsonNode jsonNode) throws IOException {
        @SuppressWarnings("unchecked")
        TreeMap<String, Object> map = canonicalMapper.convertValue(jsonNode, TreeMap.class);
        return canonicalMapper.writeValueAsString(map);
    }

}
