package de.cwkr.clamd4j;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import lombok.Data;

@Data
public class SuspiciousFile {
    private final String filename;
    private final InputStream content;

    public static SuspiciousFile of(byte[] bytes) {
        return of(null, bytes);
    }

    public static SuspiciousFile of(String filename, byte[] bytes) {
        return new SuspiciousFile(filename, new ByteArrayInputStream(bytes));
    }
}
