import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import com.fasterxml.jackson.databind.*;
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.*;
import org.apache.tika.parser.*;
import org.apache.tika.parser.microsoft.OfficeParserConfig;
import org.apache.tika.parser.ocr.TesseractOCRConfig;
import org.apache.tika.parser.pdf.PDFParserConfig;
import org.apache.tika.sax.*;
import org.xml.sax.*;

public final class ExtractionWorker {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final PrintWriter OUT = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8), true);
    private static final int MAX_CHARS = 8_000_000, MAX_TOTAL_CHARS = 16_000_000, MAX_EMBEDDED = 2000;
    private static String columnLabel(String header) {
        return switch (header.trim().toLowerCase(Locale.ROOT).replace('_', ' ').replace('-', ' ')) {
            case "name", "full name", "fullname" -> "Full name: ";
            case "dob", "date of birth", "dateofbirth", "birthdate", "birth date" -> "DOB: ";
            case "ssn", "social security", "social security number", "socialsecuritynumber" -> "SSN: ";
            case "passport", "passport number", "passport no" -> "Passport number: ";
            case "driver license", "driver's license", "drivers license", "driving licence",
                 "driver license number", "drivers license number", "driving licence number" -> "Driver's license: ";
            case "account number", "account no", "bank account", "bank account number" -> "Account number: ";
            case "tax id", "tax identification number", "tin" -> "Tax ID: ";
            default -> "";
        };
    }
    private static void send(Object value) throws SAXException {
        try { OUT.println(JSON.writeValueAsString(value)); }
        catch (Exception e) { throw new SAXException(e); }
    }
    private static void issue(String source, String resourceId, String reason, String message) throws SAXException {
        send(Map.of("kind", "issue", "source", source, "resourceId", resourceId, "reason", reason, "message", message.substring(0, Math.min(2000, message.length()))));
    }
    private static final class CoverageLimitException extends SAXException {
        CoverageLimitException(String message) { super(message); }
    }
    private static final class TextBudget {
        private long chars;
        void add(int length) throws SAXException {
            chars += length;
            if (chars > MAX_TOTAL_CHARS) throw new CoverageLimitException("Total parsed text limit reached; remaining content unchecked");
        }
    }
    private static final class TableTextHandler extends org.xml.sax.helpers.DefaultHandler {
        private final ContentHandler target;
        private final TextBudget budget;
        private final List<String> cells = new ArrayList<>();
        private List<String> headers = new ArrayList<>();
        private StringBuilder cell;
        private int rowChars;
        private boolean synthesized;
        TableTextHandler(ContentHandler target, TextBudget budget) { this.target = target; this.budget = budget; }
        @Override public void startElement(String uri, String local, String q, Attributes attributes) throws SAXException {
            if (local.equals("table")) headers = new ArrayList<>();
            if (local.equals("tr")) { cells.clear(); rowChars = 0; }
            if (local.equals("td") || local.equals("th")) cell = new StringBuilder();
            target.startElement(uri, local, q, attributes);
        }
        @Override public void characters(char[] ch, int start, int length) throws SAXException {
            budget.add(length);
            if (cell != null) { if (cell.length() + length > MAX_CHARS) throw new CoverageLimitException("Table cell text limit reached"); cell.append(ch, start, length); }
            else target.characters(ch, start, length);
        }
        @Override public void ignorableWhitespace(char[] ch, int start, int length) throws SAXException { characters(ch, start, length); }
        @Override public void startDocument() throws SAXException { target.startDocument(); }
        @Override public void endElement(String uri, String local, String q) throws SAXException {
            if ((local.equals("td") || local.equals("th")) && cell != null) {
                rowChars += cell.length();
                if (rowChars > MAX_CHARS || cells.size() >= 10_000) throw new CoverageLimitException("Table row limit reached; remaining content unchecked");
                cells.add(cell.toString().trim()); cell = null;
            }
            if (local.equals("tr") && !cells.isEmpty()) {
                synthesized = true;
                List<String> labels = cells.stream().map(ExtractionWorker::columnLabel).toList();
                boolean isHeader = labels.stream().anyMatch(v -> !v.isEmpty());
                if (isHeader) headers = labels;
                boolean named = headers.contains("Full name: ");
                StringBuilder line = new StringBuilder(named && !isHeader ? "\n[Table] " : "\n");
                for (int i = 0; i < cells.size(); i++) {
                    String header = i < headers.size() ? headers.get(i) : "";
                    if (!isHeader) line.append(header);
                    line.append(cells.get(i).replace('\n', ' ').replace('\r', ' ')).append(" | ");
                }
                line.append('\n'); char[] text = line.toString().toCharArray(); target.characters(text, 0, text.length);
                cells.clear();
            }
            target.endElement(uri, local, q);
        }
        @Override public void endDocument() throws SAXException { target.endDocument(); }
        @Override public String toString() { return target.toString(); }
    }
    private static final class TextFactory implements ContentHandlerFactory {
        private final TextBudget budget = new TextBudget();
        public ContentHandler getNewContentHandler() { return new TableTextHandler(new WriteOutContentHandler(new ToTextContentHandler(), MAX_CHARS), budget); }
        public ContentHandler getNewContentHandler(OutputStream out, java.nio.charset.Charset charset) {
            return new TableTextHandler(new WriteOutContentHandler(new ToTextContentHandler(new OutputStreamWriter(out, charset)), MAX_CHARS), budget);
        }
    }
    private static final class StreamingHandler extends RecursiveParserWrapperHandler {
        private final boolean ocr;
        private final String resourceName;
        private int total, embeddedOrdinal;
        StreamingHandler(boolean ocr, String resourceName) {
            super(new TextFactory(), MAX_EMBEDDED);
            this.ocr = ocr;
            this.resourceName = resourceName;
        }
        @Override public void endEmbeddedDocument(ContentHandler h, Metadata m) throws SAXException {
            m.set("X-TIKA:piiResourceId", "embedded:" + ++embeddedOrdinal);
            markRepresentation(h, m);
            super.endEmbeddedDocument(h, m); drain();
        }
        @Override public void endDocument(ContentHandler h, Metadata m) throws SAXException {
            m.set("X-TIKA:piiResourceId", "");
            markRepresentation(h, m);
            super.endDocument(h, m); drain();
        }
        private void markRepresentation(ContentHandler h, Metadata m) {
            // Unknown wrappers are conservatively marked: never promise original text
            // when a handler may have inserted table labels or separators.
            m.set("X-TIKA:piiRepresentation", h instanceof TableTextHandler t && !t.synthesized
                ? "ExtractedText" : "SynthesizedText");
        }
        private void drain() throws SAXException {
            for (Metadata m : metadataList) {
                String source = Optional.ofNullable(m.get(TikaCoreProperties.EMBEDDED_RESOURCE_PATH)).orElse("");
                String resourceId = Optional.ofNullable(m.get("X-TIKA:piiResourceId")).orElse("");
                String type = Optional.ofNullable(m.get("Content-Type")).orElse("unknown");
                String text = Optional.ofNullable(m.get(TikaCoreProperties.TIKA_CONTENT)).orElse("");
                if (source.isEmpty() && resourceName.toLowerCase(Locale.ROOT).endsWith(".one") && !type.contains("onenote"))
                    issue(source, resourceId, "ExtractionFailure", "OneNote section was not recognized as OneNote content; review this .one file manually");
                for (String key : m.names()) {
                    String lower = key.toLowerCase(Locale.ROOT);
                    if (lower.contains("exception") || lower.contains("limitreached") || lower.contains("truncated")) {
                        String message = String.join("; ", m.getValues(key)).split("\\R", 2)[0];
                        issue(source, resourceId, lower.contains("limitreached") || lower.contains("truncated") ? "TextLimit" : "ExtractionFailure", "Extraction incomplete: " + message.substring(0, Math.min(350, message.length())));
                    }
                }
                String parsers = String.join(",", m.getValues(TikaCoreProperties.TIKA_PARSED_BY));
                if (parsers.contains("EmptyParser")) issue(source, resourceId, "Unsupported", "Unsupported content: " + type + " (metadata only)");
                if (type.startsWith("audio/") || type.startsWith("video/")) issue(source, resourceId, "UnsupportedRepresentation", "Only metadata was checked; speech and video frames were not transcribed");
                if (!ocr && (type.startsWith("image/") || type.equals("application/pdf"))) issue(source, resourceId, "OcrDisabled", "Image content was not OCR checked (OCR is off)");
                if (text.isBlank() && (type.startsWith("image/") || type.equals("application/pdf") || type.contains("onenote")))
                    issue(source, resourceId, "NoReadableText", "No readable text extracted from " + type + "; review this file manually");
                emit(source, "document text", text, type, resourceId, "body", "Body",
                    Optional.ofNullable(m.get("X-TIKA:piiRepresentation")).orElse("SynthesizedText"));
                String[] keys = m.names(); Arrays.sort(keys);
                for (String key : keys) {
                    if (key.startsWith("X-TIKA") || key.equals("Content-Type") || key.equals("Content-Length")) continue;
                    String[] values = m.getValues(key);
                    for (int i = 0; i < values.length; i++) {
                        String value = values[i];
                        // Exclude the parser's generated temporary filename.
                        if (type.startsWith("image/") && key.equals("File Name") &&
                            value.matches("apache-tika-[0-9]+\\.[A-Za-z0-9]{1,10}")) continue;
                        if (!value.isBlank()) emit(source, "metadata: " + key, value, type, resourceId,
                            "metadata:" + key.length() + ":" + key + ":" + i, "Metadata", "ExtractedText");
                    }
                }
            }
            metadataList.clear();
        }
        private void emit(String source, String location, String text, String type, String resourceId,
                          String streamId, String kind, String representation) throws SAXException {
            if (text.length() > MAX_TOTAL_CHARS - total) throw new CoverageLimitException("Total extracted text limit reached; remaining content not checked");
            total += text.length();
            if (text.isEmpty()) send(Map.of("kind", "segment", "source", source, "location", location,
                "text", "", "contentType", type, "origin", Map.of("resourceId", resourceId,
                "streamId", streamId, "kind", kind, "representation", representation, "start", 0)));
            for (int start = 0; start < text.length();) {
                int end = Math.min(start + 24000, text.length());
                if (end < text.length()) {
                    int line = text.lastIndexOf('\n', end);
                    if (line > start + 12000) end = line + 1;
                    else { int boundary = end; while (boundary > start + 12000 && !Character.isWhitespace(text.charAt(boundary - 1))) boundary--; end = boundary; }
                }
                send(Map.of("kind", "segment", "source", source, "location", location + " · character " + start,
                            "text", text.substring(start, end), "contentType", type,
                            "origin", Map.of("resourceId", resourceId, "streamId", streamId, "kind", kind,
                                "representation", representation, "start", start)));
                if (end == text.length()) break;
                int next = Math.max(start + 1, end - 256);
                int line = text.lastIndexOf('\n', next);
                if (line > start && next - line < 1000) next = line + 1;
                else while (next > Math.max(start + 1, end - 512) && !Character.isWhitespace(text.charAt(next - 1))) next--;
                start = next;
            }
        }
    }
    public static void main(String[] args) throws Exception {
        // Parser logs go to stderr; stdout is a strict JSON-lines protocol.
        System.setOut(new PrintStream(System.err, true, StandardCharsets.UTF_8));
        // Enforce offline XML parsing even when this worker is launched without the .NET client.
        System.setProperty("javax.xml.accessExternalDTD", "");
        System.setProperty("javax.xml.accessExternalSchema", "");
        System.setProperty("javax.xml.accessExternalStylesheet", "");
        AutoDetectParser parser = new AutoDetectParser();
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        for (String line; (line = input.readLine()) != null;) {
            try {
                JsonNode request = JSON.readTree(line);
                Path path = Path.of(request.get("path").asText());
                String resourceName = request.path("resourceName").asText(path.getFileName().toString());
                if (resourceName.toLowerCase(Locale.ROOT).endsWith(".onetoc2")) {
                    issue("", "", "UnsupportedRepresentation", "OneNote notebook index contains no section content; scan the local .one section files. Linked or cloud notebooks were not fetched.");
                    send(Map.of("kind", "done"));
                    continue;
                }
                boolean ocr = request.path("ocr").asBoolean(true);
                ParseContext context = new ParseContext();
                TesseractOCRConfig tess = new TesseractOCRConfig();
                tess.setSkipOcr(!ocr); tess.setTimeoutSeconds(60); tess.setLanguage("eng");
                // Icons and rules cannot hold readable identifiers; skipping them avoids an
                // OCR process per decoration in image-heavy documents.
                tess.setMinFileSizeToOcr(3000);
                context.set(TesseractOCRConfig.class, tess);
                PDFParserConfig pdf = new PDFParserConfig();
                // AUTO renders and OCRs only pages without usable text (scans, outlined or
                // unmapped fonts). Embedded images are extracted and OCR'd at native resolution,
                // so photographs of identifiers on ordinary text pages are still read.
                pdf.setOcrStrategy(ocr ? PDFParserConfig.OCR_STRATEGY.AUTO : PDFParserConfig.OCR_STRATEGY.NO_OCR);
                pdf.setOcrDPI(150); pdf.setExtractAcroFormContent(true); pdf.setExtractAnnotationText(true);
                pdf.setExtractInlineImages(ocr); pdf.setExtractUniqueInlineImagesOnly(true); pdf.setCatchIntermediateIOExceptions(false);
                pdf.setMaxMainMemoryBytes(256L * 1024 * 1024);
                context.set(PDFParserConfig.class, pdf);
                OfficeParserConfig office = new OfficeParserConfig();
                office.setIncludeDeletedContent(true); office.setIncludeHeadersAndFooters(true);
                office.setIncludeShapeBasedContent(true); office.setIncludeSlideNotes(true);
                office.setIncludeSlideMasterContent(true); office.setExtractAllAlternativesFromMSG(true);
                context.set(OfficeParserConfig.class, office);
                StreamingHandler handler = new StreamingHandler(ocr, resourceName);
                Metadata metadata = new Metadata(); metadata.set(TikaCoreProperties.RESOURCE_NAME_KEY, resourceName);
                try (TikaInputStream stream = TikaInputStream.get(path)) {
                    new RecursiveParserWrapper(parser).parse(stream, handler, metadata, context);
                }
            } catch (Throwable e) {
                issue("", "", e instanceof org.apache.tika.exception.EncryptedDocumentException ? "Encrypted" : e instanceof CoverageLimitException ? "TextLimit" : "ExtractionFailure", e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage()));
                if (e instanceof OutOfMemoryError) { send(Map.of("kind", "done")); return; }
            }
            send(Map.of("kind", "done"));
        }
    }
}
