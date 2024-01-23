package io.alapierre.gobl.core.exceptions;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2024.01.23
 */
public class NoSuchDigestAlgorithmException extends RuntimeException {
    public NoSuchDigestAlgorithmException() {
    }

    public NoSuchDigestAlgorithmException(String message) {
        super(message);
    }

    public NoSuchDigestAlgorithmException(String message, Throwable cause) {
        super(message, cause);
    }

    public NoSuchDigestAlgorithmException(Throwable cause) {
        super(cause);
    }
}
