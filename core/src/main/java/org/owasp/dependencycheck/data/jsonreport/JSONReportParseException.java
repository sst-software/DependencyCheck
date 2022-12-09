package org.owasp.dependencycheck.data.jsonreport;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Represents an exception when parsing a dependencies.json file.
 *
 * @author Silas de Graaf
 */
@ThreadSafe
public class JSONReportParseException extends RuntimeException {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 3275208069077840221L;

    /**
     * Creates a JSONReportParseException with default message.
     */
    public JSONReportParseException() {
        super();
    }

    /**
     * Creates a JSONReportParseException with the specified message.
     *
     * @param message the exception message
     */
    public JSONReportParseException(String message) {
        super(message);
    }

    /**
     * Creates a JSONReportParseException with the specified message and cause.
     *
     * @param message the message
     * @param cause the underlying cause
     */
    public JSONReportParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
