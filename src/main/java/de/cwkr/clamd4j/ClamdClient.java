package de.cwkr.clamd4j;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClamdClient {
    private static final String CMD_END = "nEND\n";
    private static final String CMD_IDSESSION = "nIDSESSION\n";
    private static final String CMD_INSTREAM = "nINSTREAM\n";
    private static final String CMD_PING = "nPING\n";
    private static final String CMD_VERSION = "nVERSION\n";
    private static final String RPL_PONG = "PONG";
    @Builder.Default
    private final String host = "localhost";
    @Builder.Default
    private final int port = 3310;
    @Builder.Default
    private final int connectionTimeout = 3000;
    @Builder.Default
    private final int readTimeout = 30_000;
    @Builder.Default
    private final int chunkSize = 2048;
    @NonNull
    @Builder.Default
    private final Supplier<Socket> socketFactory = Socket::new;

    /**
     * Scan a list of suspicious files for malware using ClamAV Daemon
     *
     * @param suspiciousFiles list of suspicious files to scan
     */
    public ScanReport scan(Collection<SuspiciousFile> suspiciousFiles) throws IOException {
        List<ScanResult> scanResults = new ArrayList<>(suspiciousFiles.size());
        String reply;

        try (Socket socket = connectSocket()) {
            try (DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

                dos.writeBytes(CMD_IDSESSION);
                dos.flush();

                dos.writeBytes(CMD_VERSION);
                dos.flush();
                reply = in.readLine();
                log.trace("{} reply -> {}", CMD_VERSION.trim(), reply);
                String version = strip(reply, 1);

                for (SuspiciousFile sf : suspiciousFiles) {
                    try (InputStream sin = sf.getContent()) {
                        dos.writeBytes(CMD_INSTREAM);
                        dos.flush();

                        byte[] chunk = new byte[chunkSize];
                        int read;

                        while ((read = sin.read(chunk)) >= 0) {
                            dos.writeInt(read);
                            dos.write(chunk, 0, read);
                        }

                        // empty chunk
                        dos.writeInt(0);
                        dos.flush();
                        reply = in.readLine();
                        log.trace("{} reply -> {}", CMD_INSTREAM.trim(), reply);
                        String result = strip(reply, 2);
                        scanResults.add(ScanResult.builder()
                                                  .filename(sf.getFilename())
                                                  .result(result)
                                                  .malwareFound(reply.endsWith("FOUND"))
                                                  .build());
                    }
                }

                dos.writeBytes(CMD_END);
                dos.flush();

                return ScanReport.builder()
                                 .scannerVersion(version)
                                 .scanResults(scanResults)
                                 .build();
            }
        }
    }

    /**
     * Send a PING to ClamAV Daemon
     *
     * @throws IllegalStateException when reply is not PONG
     */
    public void ping() throws IOException {
        try (Socket socket = connectSocket()) {
            try (DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                dos.writeBytes(CMD_PING);
                dos.flush();
                String reply = in.readLine();
                log.trace("{} reply -> {}", CMD_PING.trim(), reply);
                if (!RPL_PONG.equals(reply)) {
                    throw new IllegalStateException("Expected " + RPL_PONG + " as reply");
                }
            }
        }
    }

    /**
     * Get ClamAV Daemon version
     */
    public String version() throws IOException {
        try (Socket socket = connectSocket()) {
            try (DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                dos.writeBytes(CMD_VERSION);
                dos.flush();
                String reply = in.readLine();
                log.trace("{} reply -> {}", CMD_VERSION.trim(), reply);
                return reply;
            }
        }
    }

    private Socket connectSocket() throws IOException {
        Socket socket = socketFactory.get();
        log.debug("Connecting to {} port {} with connection timeout {}ms", host, port, connectionTimeout);
        socket.connect(new InetSocketAddress(host, port), connectionTimeout);
        socket.setSoTimeout(readTimeout);
        return socket;
    }

    private String strip(String reply, int index) {
        if (reply != null) {
            String[] strings = reply.split("[\\s:]+", index + 1);
            if (strings.length > index) {
                return strings[index];
            }
        }
        return null;
    }
}
