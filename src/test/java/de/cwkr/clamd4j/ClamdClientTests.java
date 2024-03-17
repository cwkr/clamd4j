package de.cwkr.clamd4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class ClamdClientTests {

    @Test
    void scan_OK() throws IOException {
        String replys = "1: ClamAV/x.y.z\n2: stream: OK\n";
        Socket socketMock = mock(Socket.class);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        when(socketMock.getInputStream()).thenReturn(new ByteArrayInputStream(replys.getBytes()));
        when(socketMock.getOutputStream()).thenReturn(outputStream);

        ClamdClient clamdClient = ClamdClient.builder()
                                             .socketFactory(() -> socketMock)
                                             .build();
        SuspiciousFile input = SuspiciousFile.of("test.pdf", new byte[]{'%', 'P', 'D', 'F'});
        ScanReport report = clamdClient.scan(Collections.singletonList(input));

        assertNotNull(report);
        assertEquals("ClamAV/x.y.z", report.getScannerVersion());
        assertFalse(report.isMalwareFound());
        assertNotNull(report.getScanResults());
        assertEquals(1, report.getScanResults().size());
        ScanResult result = report.getScanResults()
                                  .stream()
                                  .findFirst().orElseGet(ScanResult.builder()::build);
        assertEquals(input.getFilename(), result.getFilename());
        assertEquals("OK", result.getResult());

        verify(socketMock, times(1)).connect(eq(new InetSocketAddress("localhost", 3310)), eq(3000));
    }

    @Test
    void scan_FOUND() throws IOException {
        String replys = "1: ClamAV/x.y.z\n2: stream: Malware123 FOUND\n";
        Socket socketMock = mock(Socket.class);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        when(socketMock.getInputStream()).thenReturn(new ByteArrayInputStream(replys.getBytes()));
        when(socketMock.getOutputStream()).thenReturn(outputStream);

        ClamdClient clamdClient = ClamdClient.builder()
                                             .socketFactory(() -> socketMock)
                                             .build();
        SuspiciousFile input = SuspiciousFile.of(new byte[]{0, 1, 2, 3});
        ScanReport report = clamdClient.scan(Collections.singletonList(input));

        assertNotNull(report);
        assertEquals("ClamAV/x.y.z", report.getScannerVersion());
        assertTrue(report.isMalwareFound());
        assertNotNull(report.getScanResults());
        assertEquals(1, report.getScanResults().size());
        ScanResult result = report.getScanResults()
                                  .stream()
                                  .findFirst().orElseGet(ScanResult.builder()::build);
        assertNull(result.getFilename());
        assertEquals("Malware123 FOUND", result.getResult());

        verify(socketMock, times(1)).connect(eq(new InetSocketAddress("localhost", 3310)), eq(3000));
    }

    @Test
    void ping() throws IOException {
        String replys = "PONG\n";
        Socket socketMock = mock(Socket.class);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        when(socketMock.getInputStream()).thenReturn(new ByteArrayInputStream(replys.getBytes()));
        when(socketMock.getOutputStream()).thenReturn(outputStream);

        ClamdClient clamdClient = ClamdClient.builder()
                                             .socketFactory(() -> socketMock)
                                             .build();

        clamdClient.ping();

        verify(socketMock, times(1)).connect(eq(new InetSocketAddress("localhost", 3310)), eq(3000));
    }

    @Test
    void version() throws IOException {
        String replys = "ClamAV/x.y.z\n";
        Socket socketMock = mock(Socket.class);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        when(socketMock.getInputStream()).thenReturn(new ByteArrayInputStream(replys.getBytes()));
        when(socketMock.getOutputStream()).thenReturn(outputStream);

        ClamdClient clamdClient = ClamdClient.builder()
                                             .socketFactory(() -> socketMock)
                                             .build();

        String version = clamdClient.version();

        assertEquals("ClamAV/x.y.z", version);

        verify(socketMock, times(1)).connect(eq(new InetSocketAddress("localhost", 3310)), eq(3000));
    }
}
