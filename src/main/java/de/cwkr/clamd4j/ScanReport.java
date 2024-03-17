package de.cwkr.clamd4j;

import java.util.Collection;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ScanReport {
    private final String scannerVersion;
    private final Collection<ScanResult> scanResults;

    public boolean isMalwareFound() {
        return scanResults.stream().anyMatch(ScanResult::isMalwareFound);
    }
}
