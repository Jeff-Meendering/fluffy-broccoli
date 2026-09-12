import ai.philterd.phinder.Phinder;
import ai.philterd.phileas.model.filtering.Span;
import ai.philterd.phileas.policy.Policy;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;

/** Text-only benchmark adapter for Phinder's public findPii(text, policy) API. */
public final class PhinderAccuracy {
    private static final Map<String, String> TYPES = Map.of(
        "EMAIL_ADDRESS", "Email", "IP_ADDRESS", "IP address", "CREDIT_CARD", "Payment card",
        "PERSON", "Person", "FIRST_NAME", "Person", "SURNAME", "Person",
        "PHONE_NUMBER", "Phone", "SSN", "Social Security number");

    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("<inputs.jsonl> <policy.json> <new-predictions.jsonl>");
        var gson = new Gson();
        var policy = gson.fromJson(Files.readString(Path.of(args[1])), Policy.class);
        var engine = new Phinder();
        var output = Path.of(args[2]).toAbsolutePath();
        if (Files.exists(output)) throw new IllegalArgumentException("Prediction output already exists");
        var temporary = Files.createTempFile(output.getParent(), "phinder-accuracy-", ".tmp");
        var ids = new HashSet<String>();
        try {
            try (var reader = Files.newBufferedReader(Path.of(args[0])); var writer = Files.newBufferedWriter(temporary)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    var input = gson.fromJson(line, JsonObject.class);
                    String id = input.get("Id").getAsString(), text = input.get("Text").getAsString();
                    if (id.isEmpty() || !ids.add(id) || text.length() > 100_000)
                        throw new IllegalArgumentException("Invalid or duplicate prediction input");
                    var entities = new JsonArray();
                    for (Span span : engine.findPii(text, policy)) {
                        int start = span.getCharacterStart(), end = span.getCharacterEnd();
                        if (start < 0 || end <= start || end > text.length() || !text.substring(start, end).equals(span.getText()))
                            throw new IllegalStateException("Phinder span does not identify original input text");
                        var entity = new JsonObject();
                        String type = span.getFilterType().name();
                        entity.addProperty("Type", TYPES.getOrDefault(type, "Phinder:" + type));
                        entity.addProperty("Start", start);
                        entity.addProperty("Length", end - start);
                        entities.add(entity);
                    }
                    var prediction = new JsonObject();
                    prediction.addProperty("Id", id);
                    prediction.addProperty("TextSha256", HexFormat.of().formatHex(
                        MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))));
                    prediction.add("Entities", entities);
                    writer.write(gson.toJson(prediction));
                    writer.newLine();
                }
            }
            if (ids.isEmpty()) throw new IllegalArgumentException("Empty prediction input");
            Files.move(temporary, output);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }
}
