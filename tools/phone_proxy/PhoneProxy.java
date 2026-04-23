import java.io.*;
import java.net.*;
import javax.net.ssl.*;

/**
 * Minimal HTTP proxy that runs on Android via app_process.
 * Listens on port 18888, reads X-Target-URL header from incoming requests,
 * fetches that URL using the phone's network (HTTPS), and returns the response.
 *
 * Usage: app_process -Djava.class.path=/data/local/tmp/proxy.dex /system/bin PhoneProxy
 */
public class PhoneProxy {
    static final int PORT = 18888;

    public static void main(String[] args) throws Exception {
        ServerSocket server = new ServerSocket(PORT);
        System.out.println("[proxy] listening on :" + PORT);
        System.out.flush();
        while (true) {
            try {
                Socket client = server.accept();
                // Handle each request in a new thread for concurrency
                new Thread(() -> handle(client)).start();
            } catch (Exception e) {
                System.err.println("[proxy] accept error: " + e);
            }
        }
    }

    static void handle(Socket client) {
        try {
            client.setSoTimeout(30000);
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();

            // --- Parse HTTP request ---
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
            String requestLine = reader.readLine();
            if (requestLine == null || requestLine.isEmpty()) {
                client.close();
                return;
            }
            // e.g. "GET / HTTP/1.1" or "POST / HTTP/1.1"
            String[] parts = requestLine.split(" ", 3);
            String method = parts.length > 0 ? parts[0] : "GET";

            // Read headers
            String targetUrl = null;
            java.util.Map<String, String> headers = new java.util.LinkedHashMap<>();
            int contentLength = 0;
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                int colon = line.indexOf(':');
                if (colon < 0) continue;
                String key = line.substring(0, colon).trim();
                String val = line.substring(colon + 1).trim();
                if (key.equalsIgnoreCase("X-Target-URL")) {
                    targetUrl = val;
                } else if (key.equalsIgnoreCase("Content-Length")) {
                    contentLength = Integer.parseInt(val);
                } else if (key.equalsIgnoreCase("Host") ||
                           key.equalsIgnoreCase("Accept-Encoding")) {
                    // skip — don't forward Host or Accept-Encoding (we want plaintext)
                } else {
                    headers.put(key, val);
                }
            }

            if (targetUrl == null || targetUrl.isEmpty()) {
                String body = "{\"error\":\"Missing X-Target-URL header\"}";
                String resp = "HTTP/1.1 400 Bad Request\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Content-Length: " + body.length() + "\r\n"
                    + "Connection: close\r\n\r\n" + body;
                out.write(resp.getBytes("UTF-8"));
                out.flush();
                client.close();
                return;
            }

            // Read body if present
            byte[] reqBody = null;
            if (contentLength > 0) {
                reqBody = new byte[contentLength];
                int read = 0;
                while (read < contentLength) {
                    char[] buf = new char[contentLength - read];
                    int n = reader.read(buf, 0, buf.length);
                    if (n < 0) break;
                    byte[] chunk = new String(buf, 0, n).getBytes("UTF-8");
                    System.arraycopy(chunk, 0, reqBody, read, chunk.length);
                    read += chunk.length;
                }
            }

            System.out.println("[proxy] " + method + " " + targetUrl
                + (reqBody != null ? " body=" + reqBody.length : ""));
            System.out.flush();

            // --- Forward to target ---
            URL url = new URL(targetUrl);
            HttpURLConnection conn;
            if (targetUrl.startsWith("https")) {
                conn = (HttpsURLConnection) url.openConnection();
            } else {
                conn = (HttpURLConnection) url.openConnection();
            }
            conn.setRequestMethod(method);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(30000);
            conn.setInstanceFollowRedirects(true);

            // Forward headers
            for (java.util.Map.Entry<String, String> e : headers.entrySet()) {
                conn.setRequestProperty(e.getKey(), e.getValue());
            }
            // Ensure we get plaintext
            conn.setRequestProperty("Accept-Encoding", "identity");

            // Send body
            if (reqBody != null && reqBody.length > 0) {
                conn.setDoOutput(true);
                conn.getOutputStream().write(reqBody);
                conn.getOutputStream().flush();
            }

            // --- Read response ---
            int status = conn.getResponseCode();
            InputStream respStream;
            try {
                respStream = conn.getInputStream();
            } catch (IOException ex) {
                respStream = conn.getErrorStream();
            }

            byte[] respBody = new byte[0];
            if (respStream != null) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = respStream.read(buf)) >= 0) {
                    bos.write(buf, 0, n);
                }
                respBody = bos.toByteArray();
                respStream.close();
            }
            conn.disconnect();

            // Get content type from response
            String contentType = conn.getContentType();
            if (contentType == null) contentType = "application/octet-stream";

            // --- Send response back to client ---
            StringBuilder resp = new StringBuilder();
            resp.append("HTTP/1.1 ").append(status).append(" OK\r\n");
            resp.append("Content-Type: ").append(contentType).append("\r\n");
            resp.append("Content-Length: ").append(respBody.length).append("\r\n");
            resp.append("Connection: close\r\n");
            resp.append("Access-Control-Allow-Origin: *\r\n");
            resp.append("\r\n");
            out.write(resp.toString().getBytes("UTF-8"));
            out.write(respBody);
            out.flush();

            System.out.println("[proxy] -> " + status + " " + respBody.length + "B");
            System.out.flush();

            client.close();
        } catch (Exception e) {
            System.err.println("[proxy] error: " + e.getMessage());
            try { client.close(); } catch (Exception ignored) {}
        }
    }
}
