package com.universalsso.client;

/** Everything that can go wrong while talking to the gateway. */
public class SsoException extends Exception {
    private static final long serialVersionUID = 1L;

    public SsoException(String message) {
        super(message);
    }

    public SsoException(String message, Throwable cause) {
        super(message, cause);
    }

    /** A configuration value is missing or invalid. */
    public static final class ConfigException extends SsoException {
        private static final long serialVersionUID = 1L;

        public ConfigException(String message) {
            super(message);
        }
    }

    /** The gateway or network could not be reached, or the reply was unusable. */
    public static final class TransportException extends SsoException {
        private static final long serialVersionUID = 1L;

        public TransportException(String message) {
            super(message);
        }

        public TransportException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** The login redirect failed the client-side safety policy. */
    public static final class PolicyException extends SsoException {
        private static final long serialVersionUID = 1L;

        public PolicyException(String message) {
            super(message);
        }
    }

    /** The flow needs a browser because a redirect leaves the gateway host. */
    public static final class LeavesGatewayException extends SsoException {
        private static final long serialVersionUID = 1L;

        public LeavesGatewayException() {
            super("redirect leaves the gateway host: open the URL in a browser");
        }
    }

    /** The gateway answered with its structured error body {@code {"code","message"}}. */
    public static final class ApiException extends SsoException {
        private static final long serialVersionUID = 1L;
        private final int status;
        private final String code;

        public ApiException(int status, String code, String message) {
            super("gateway error " + status + " [" + code + "]: " + message);
            this.status = status;
            this.code = code;
        }

        /** HTTP status code. */
        public int status() {
            return status;
        }

        /** Machine-readable code such as {@code PROVIDER_NOT_FOUND}. */
        public String code() {
            return code;
        }
    }
}
