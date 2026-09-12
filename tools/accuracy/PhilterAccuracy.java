import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.net.URI;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Runs inside the same network-disabled container as Philter; no host or remote endpoint. */
public final class PhilterAccuracy {
    private static final URI ENDPOINT = URI.create("http://127.0.0.1:8080/api/explain");
    private static final Map<String, String> TYPES = Map.of(
        "EMAIL_ADDRESS", "Email", "IP_ADDRESS", "IP address", "CREDIT_CARD", "Payment card",
        "PERSON", "Person", "FIRST_NAME", "Person", "SURNAME", "Person",
        "PHONE_NUMBER", "Phone", "SSN", "Social Security number");

    private static HttpRequest request(String text) {
        return HttpRequest.newBuilder(ENDPOINT).timeout(Duration.ofSeconds(60))
            .header("Content-Type", "text/plain; charset=utf-8")
            .POST(HttpRequest.BodyPublishers.ofString(text, StandardCharsets.UTF_8)).build();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("<inputs.jsonl> <new-predictions.jsonl>");
        var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2))
            .followRedirects(HttpClient.Redirect.NEVER).proxy(new ProxySelector() {
                public List<Proxy> select(URI uri) { return List.of(Proxy.NO_PROXY); }
                public void connectFailed(URI uri, SocketAddress address, IOException error) { }
            }).build();
        boolean ready = false;
        for (int attempt = 0; attempt < 60; attempt++) {
            try {
                if (client.send(request("benchmark readiness"), HttpResponse.BodyHandlers.discarding()).statusCode() == 200) {
                    ready = true; break;
                }
            } catch (IOException ignored) { }
            Thread.sleep(250);
        }
        if (!ready) throw new IllegalStateException("Local Philter did not become ready");
        var gson = new Gson();
        var output = Path.of(args[1]).toAbsolutePath();
        if (Files.exists(output)) throw new IllegalArgumentException("Prediction output already exists");
        var temporary = Files.createTempFile(output.getParent(), "philter-accuracy-", ".tmp");
        var ids = new HashSet<String>();
        try {
            try (var reader = Files.newBufferedReader(Path.of(args[0])); var writer = Files.newBufferedWriter(temporary)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    var input = gson.fromJson(line, JsonObject.class);
                    String id = input.get("Id").getAsString(), text = input.get("Text").getAsString();
                    if (id.isEmpty() || !ids.add(id) || text.length() > 100_000)
                        throw new IllegalArgumentException("Invalid or duplicate prediction input");
                    var response = client.send(request(text), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                    if (response.statusCode() != 200) throw new IllegalStateException("Local Philter request failed");
                    var data = gson.fromJson(response.body(), JsonObject.class);
                    var entities = new JsonArray();
                    for (var value : data.getAsJsonObject("explanation").getAsJsonArray("appliedSpans")) {
                        var span = value.getAsJsonObject();
                        int start = span.get("characterStart").getAsInt(), end = span.get("characterEnd").getAsInt();
                        if (start < 0 || end <= start || end > text.length() || !text.substring(start, end).equals(span.get("text").getAsString()))
                            throw new IllegalStateException("Philter span does not identify original input text");
                        var entity = new JsonObject();
                        String type = span.get("filterType").getAsString();
                        entity.addProperty("Type", TYPES.getOrDefault(type, "Philter:" + type));
                        entity.addProperty("Start", start);
                        entity.addProperty("Length", end - start);
                        entities.add(entity);
                    }
                    var prediction = new JsonObject();
                    prediction.addProperty("Id", id);
                    prediction.addProperty("TextSha256", HexFormat.of().formatHex(
                        MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))));
                    prediction.add("Entities", entities);
                    writer.write(gson.toJson(prediction)); writer.newLine();
                }
            }
            if (ids.isEmpty()) throw new IllegalArgumentException("Empty prediction input");
            Files.move(temporary, output);
        } finally { Files.deleteIfExists(temporary); }
    }
}
