using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.VisualTree;
using PiiExplorer.App;
using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

public class AppearanceTests
{
    [AvaloniaTheory]
    [InlineData(1280, 840)]
    [InlineData(940, 660)]
    public void ThemesKeepCompactControlsAndSeparateScrollbarFromContent(int width, int height)
    {
        string temp = Path.Combine(Path.GetTempPath(), "PiiAppearanceTests", Guid.NewGuid().ToString("N"));
        string preference = Path.Combine(temp, "theme.txt");
        var window = new MainWindow(TestPaths.Assets, preference) { Width = width, Height = height };
        window.Show();
        try {
            window.FindControl<TextBox>("FolderBox")!.Text = "C:/Sample files/Personnel/Archive records";
            var findings = Enumerable.Range(0, 14).Select(i => (i % 3) switch {
                0 => new Finding("C:/Sample files/team-backup.zip", "hr/payroll.csv", "CSV rows 2-8", "Social Security number", "123-45-6789", "Employee record: Social Security number 123-45-6789.", .75, "Pattern"),
                1 => new Finding("C:/Sample files/contacts.docx", "", "document text", "Email", "maria@example.com", "Contact Maria Hernandez at maria@example.com.", .99, "Pattern"),
                _ => new Finding("C:/Sample files/backup.rar", "hr/contacts.txt", "text", "Person", "David Okonkwo", "Account holder: David Okonkwo", .94, "Local model")
            }).Select((f, i) => f with { Location = f.Location + " · result " + (i + 1) }).ToArray();
            window.ApplyUpdate(new(Discovered: 10, Completed: 10, Findings: findings,
                Issues: [new("C:/Sample files/locked.zip", "", "Password-protected archive; contents were not checked")]));
            var grid = window.FindControl<DataGrid>("FindingsGrid")!;
            grid.SelectedItem = findings[1];
            var choice = window.FindControl<ComboBox>("ThemeChoice")!;
            Color light = default;
            foreach (string mode in new[] { "Light", "Dark" }) {
                choice.SelectedItem = mode;
                Dispatcher.UIThread.RunJobs();
                Assert.Equal(mode == "Dark" ? ThemeVariant.Dark : ThemeVariant.Light, window.ActualThemeVariant);
                Assert.Same(findings[1], grid.SelectedItem);
                Assert.Equal(14, grid.ItemsSource.Cast<Finding>().Count());
                var background = Assert.IsAssignableFrom<ISolidColorBrush>(window.Background).Color;
                if (mode == "Light") light = background;
                else Assert.True(background.R < light.R && background.G < light.G && background.B < light.B);
                var search = window.FindControl<TextBox>("SearchBox")!;
                var export = window.FindControl<Button>("ExportButton")!;
                Assert.Equal(38, search.Bounds.Height);
                Assert.Equal(38, export.Bounds.Height);
                Assert.Equal(search.TranslatePoint(default, window)!.Value.Y, export.TranslatePoint(default, window)!.Value.Y);
                var scroll = window.FindControl<ScrollViewer>("SidebarScrollViewer")!;
                var content = window.FindControl<StackPanel>("SidebarContent")!;
                Assert.False(scroll.AllowAutoHide);
                if (width == 940) {
                    var bar = Assert.Single(scroll.GetVisualDescendants().OfType<ScrollBar>(), s => s.Name == "PART_VerticalScrollBar" && s.TemplatedParent == scroll);
                    Assert.True(bar.IsVisible);
                    double right = content.TranslatePoint(new Point(content.Bounds.Width, 0), window)!.Value.X;
                    double left = bar.TranslatePoint(default, window)!.Value.X;
                    Assert.True(right + 8 <= left, $"Scrollbar overlaps content: content right {right}, bar left {left}");
                    var scan = window.FindControl<Button>("ScanButton")!;
                    double scanY = scan.TranslatePoint(default, window)!.Value.Y;
                    scroll.ScrollToEnd(); Dispatcher.UIThread.RunJobs();
                    Assert.Equal(scanY, scan.TranslatePoint(default, window)!.Value.Y);
                }
                string screenshots = Path.Combine(TestPaths.Root, "test-results"); Directory.CreateDirectory(screenshots);
                using var bitmap = window.CaptureRenderedFrame(); Assert.NotNull(bitmap);
                bitmap.Save(Path.Combine(screenshots, $"appearance-{mode.ToLowerInvariant()}-{width}.png"), Avalonia.Media.Imaging.PngBitmapEncoderOptions.Default);
            }
            Assert.Equal("Dark", File.ReadAllText(preference));
            var restored = new MainWindow(TestPaths.Assets, preference);
            Assert.Equal(ThemeVariant.Dark, restored.RequestedThemeVariant);
            restored.FindControl<ComboBox>("ThemeChoice")!.SelectedItem = "System";
            Assert.Equal(ThemeVariant.Default, restored.RequestedThemeVariant);
            restored.Close();
            Assert.Equal("System", File.ReadAllText(preference));
        } finally { window.Close(); if (Directory.Exists(temp)) Directory.Delete(temp, true); }
    }
}
