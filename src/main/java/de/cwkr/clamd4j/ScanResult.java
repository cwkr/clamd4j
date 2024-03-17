package de.cwkr.clamd4j;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ScanResult {
    private final String filename;
    private final boolean malwareFound;
    private final String result;
}
