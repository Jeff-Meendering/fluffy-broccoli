using System.Diagnostics;
using System.Globalization;
using System.Text;
using SkiaSharp;

namespace PiiExplorer.Core;

public static class ImageReader
{
    public static async Task<ExtractedPart[]> ReadAsync(string file, string source, RuntimePaths paths, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var input = File.OpenRead(file);
        using var codec = SKCodec.Create(input) ?? throw new IOException("Image decoder could not read this file");
        if ((long)codec.Info.Width * codec.Info.Height > 32_000_000) throw new IOException("Image exceeds 32 megapixel decoding limit");
        using var original = SKBitmap.Decode(codec) ?? throw new IOException("Image pixels could not be decoded");
        token.ThrowIfCancellationRequested();
        string temp = Directory.CreateTempSubdirectory("PiiExplorer-").FullName;
        try {
            (string Text, double Score) best = ("", 0);
            float correction = EstimateSkew(original, token);
            foreach (float angle in new float[] { correction, 90 + correction, 180 + correction, 270 + correction }) {
                token.ThrowIfCancellationRequested();
                using var rendered = Render(original, angle);
                using var image = SKImage.FromBitmap(rendered);
                using var data = image.Encode(SKEncodedImageFormat.Png, 100);
                string raster = Path.Combine(temp, "image.png");
                using (var output = File.Create(raster)) data.SaveTo(output);
                var read = await OcrAsync(raster, paths, token);
                if (read.Score > best.Score || best.Text.Length == 0) best = read;
                if (best.Score >= 65 && best.Text.Length > 5) break;
            }
            var parts = new List<ExtractedPart> { new(source, $"OCR · average word confidence {best.Score:F0}%", best.Text, "text/plain") };
            if (best.Text.Length == 0 || best.Score < 65)
                parts.Add(new(source, "", "", "", "OCR found little or uncertain text. Handwriting, rotation or low resolution may hide PII; review the image."));
            if (codec.FrameCount > 1) parts.Add(new(source, "", "", "", "Only the first animation frame was OCR checked"));
            return parts.ToArray();
        } finally { Directory.Delete(temp, true); }
    }

    private static SKBitmap Render(SKBitmap input, float angle)
    {
        double radians = angle * Math.PI / 180;
        float scale = Math.Min(3, Math.Max(1, 1200f / input.Width));
        if ((long)(input.Width * scale) * (input.Height * scale) > 32_000_000) scale = 1;
        int width = (int)Math.Ceiling((Math.Abs(input.Width * Math.Cos(radians)) + Math.Abs(input.Height * Math.Sin(radians))) * scale);
        int height = (int)Math.Ceiling((Math.Abs(input.Width * Math.Sin(radians)) + Math.Abs(input.Height * Math.Cos(radians))) * scale);
        if ((long)width * height > 40_000_000) throw new IOException("Rotated image exceeds rendering limit");
        var result = new SKBitmap(width, height);
        using var canvas = new SKCanvas(result);
        canvas.Clear(SKColors.White); canvas.Translate(width / 2f, height / 2f); canvas.RotateDegrees(angle); canvas.Scale(scale);
        canvas.DrawBitmap(input, -input.Width / 2f, -input.Height / 2f);
        return result;
    }

    private static float EstimateSkew(SKBitmap bitmap, CancellationToken token)
    {
        // Horizontal projection: aligned text produces stronger row bands than tilted text.
        int step = Math.Max(1, Math.Max(bitmap.Width, bitmap.Height) / 600);
        var points = new List<(float X, float Y)>();
        for (int y = 0; y < bitmap.Height; y += step) {
            token.ThrowIfCancellationRequested();
            for (int x = 0; x < bitmap.Width; x += step) {
                var c = bitmap.GetPixel(x, y);
                if (c.Alpha > 128 && c.Red * .299 + c.Green * .587 + c.Blue * .114 < 150)
                    points.Add(((x - bitmap.Width / 2f) / step, (y - bitmap.Height / 2f) / step));
            }
        }
        if (points.Count < 50) return 0;
        double best = 0, baseline = 0; int selected = 0;
        for (int angle = -15; angle <= 15; angle++) {
            token.ThrowIfCancellationRequested();
            double r = angle * Math.PI / 180, sin = Math.Sin(r), cos = Math.Cos(r);
            var rows = new int[2000];
            foreach (var p in points) { int row = (int)Math.Round(p.X * sin + p.Y * cos) + 1000; if (row >= 0 && row < rows.Length) rows[row]++; }
            double score = 0; foreach (int row in rows) score += (double)row * row;
            if (angle == 0) baseline = score;
            if (score > best) { best = score; selected = angle; }
        }
        return best > baseline * 1.1 ? selected : 0;
    }

    private static async Task<(string Text, double Score)> OcrAsync(string file, RuntimePaths paths, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var start = new ProcessStartInfo(paths.OcrExecutable) { UseShellExecute = false, CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(file)!,
            RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8 };
        foreach (string arg in new[] { file, "stdout", "--tessdata-dir", Path.Combine(paths.OcrDirectory, "tessdata"), "-l", "eng", "--psm", "11", "-c", "tessedit_create_tsv=1" }) start.ArgumentList.Add(arg);
        start.Environment["OMP_THREAD_LIMIT"] = "1";
        foreach (string variable in new[] { "TEMP", "TMP", "TMPDIR" }) start.Environment[variable] = start.WorkingDirectory;
        if (OperatingSystem.IsLinux()) start.Environment["LD_LIBRARY_PATH"] = Path.Combine(paths.OcrDirectory, "lib");
        using var process = Process.Start(start) ?? throw new IOException("Could not start OCR");
        void Kill() { try { if (!process.HasExited) process.Kill(true); } catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { } }
        using var registration = token.Register(Kill);
        var stdout = ReadBoundedAsync(process.StandardOutput, 8_000_000, false, Kill, token);
        var stderr = ReadBoundedAsync(process.StandardError, 4096, true, Kill, token);
        string tsv, error;
        try {
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(token));
            tsv = await stdout; error = await stderr;
            token.ThrowIfCancellationRequested();
        } finally {
            Kill();
            // Give the killed child a bounded opportunity to release its raster before cleanup.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try { await process.WaitForExitAsync(cleanup.Token); } catch (OperationCanceledException) { }
        }
        if (process.ExitCode != 0) throw new IOException("OCR failed: " + error[..Math.Min(300, error.Length)]);
        var text = new StringBuilder(); double score = 0; int weight = 0; string previousLine = "";
        foreach (var line in tsv.Split('\n').Skip(1)) {
            token.ThrowIfCancellationRequested();
            var columns = line.TrimEnd('\r').Split('\t', 12);
            if (columns.Length < 12 || columns[0] != "5" || string.IsNullOrWhiteSpace(columns[11])) continue;
            if (!double.TryParse(columns[10], CultureInfo.InvariantCulture, out double confidence) || confidence < 0) continue;
            string lineKey = string.Join("/", columns.Skip(1).Take(4));
            if (text.Length > 0) text.Append(previousLine == lineKey ? ' ' : '\n');
            text.Append(columns[11]); previousLine = lineKey;
            score += confidence * columns[11].Length; weight += columns[11].Length;
        }
        return (text.ToString(), weight == 0 ? 0 : score / weight);
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, int limit, bool truncate, Action kill, CancellationToken token)
    {
        var result = new StringBuilder(); var buffer = new char[4096];
        while (true) {
            int read = await reader.ReadAsync(buffer.AsMemory(), token);
            if (read == 0) return result.ToString();
            int keep = Math.Min(read, limit - result.Length);
            result.Append(buffer, 0, keep);
            if (keep < read && !truncate) { kill(); throw new IOException("OCR output limit reached; image not fully checked"); }
        }
    }
}
