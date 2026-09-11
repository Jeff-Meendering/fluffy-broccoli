using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using PiiExplorer.App;
using PiiExplorer.Core;
using Xunit;

[assembly: AvaloniaTestApplication(typeof(PiiExplorer.Tests.TestAppBuilder))]

namespace PiiExplorer.Tests;
public static class TestAppBuilder
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App.App>().UseSkia().WithInterFont()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });
}
public class WindowTests
{
    [AvaloniaFact] public void ConcurrentDiscoveryUpdatesCannotMoveProgressBackwards() {
        var window = new MainWindow();
        try {
            window.ApplyUpdate(new(Discovered: 20, Completed: 5));
            window.ApplyUpdate(new(Discovered: 10, Completed: 3));
            Assert.Equal("5 / 20", window.FindControl<TextBlock>("FileCount")!.Text);
        } finally { window.Close(); }
    }
    [AvaloniaFact] public async Task BatchedUpdatesPreserveSelectionAndSearchClearsHiddenSelection() {
        var window = new MainWindow(); window.Show();
        try {
            var findings = Enumerable.Range(0, 6000).Select(i => new Finding("sample.txt", "", "text", "Email", $"r{i}@example.com", "Test contact", .99, "Pattern")).ToArray();
            window.ApplyUpdate(new(Findings: findings));
            var grid = window.FindControl<DataGrid>("FindingsGrid")!;
            grid.SelectedItem = findings[0];
            window.ApplyUpdate(new(Findings: findings.Take(200).Select(f => f with { FilePath = "second.txt" }).ToArray()));
            Assert.Same(findings[0], grid.SelectedItem);
            var search = window.FindControl<TextBox>("SearchBox")!;
            search.Text = "no match"; Avalonia.Threading.Dispatcher.UIThread.RunJobs();
            search.Text = "r4000@"; Avalonia.Threading.Dispatcher.UIThread.RunJobs();
            for (int i = 0; i < 100 && grid.ItemsSource.Cast<Finding>().Count() != 1; i++) await Task.Delay(25);
            Assert.Single(grid.ItemsSource.Cast<Finding>(), f => f.Value == "r4000@example.com");
            Assert.False(window.FindControl<Button>("CopyButton")!.IsEnabled);
        } finally { window.Close(); }
    }
    [AvaloniaFact] public void LargeResultListsRemainFilterable() {
        var window = new MainWindow(); window.Show();
        try {
            var findings = Enumerable.Range(0, 30000).Select(i => new Finding("sample.txt", "", "text", "Email", $"r{i}@example.com", "Test contact", .99, "Pattern")).ToArray();
            var watch = System.Diagnostics.Stopwatch.StartNew();
            window.ApplyUpdate(new(Findings: findings));
            Avalonia.Threading.Dispatcher.UIThread.RunJobs();
            double loadMs = watch.Elapsed.TotalMilliseconds;
            var grid = window.FindControl<DataGrid>("FindingsGrid")!;
            Assert.Equal(30000, grid.ItemsSource.Cast<Finding>().Count());
            watch.Restart();
            window.FindControl<ComboBox>("TypeFilter")!.SelectedItem = "Email";
            Avalonia.Threading.Dispatcher.UIThread.RunJobs();
            double filterMs = watch.Elapsed.TotalMilliseconds;
            Assert.Equal(30000, grid.ItemsSource.Cast<Finding>().Count());
            window.FindControl<ComboBox>("TypeFilter")!.SelectedItem = "Phone";
            Assert.Empty(grid.ItemsSource.Cast<Finding>());
            string output = Path.Combine(TestPaths.Root, "test-results"); Directory.CreateDirectory(output);
            string label = Environment.GetEnvironmentVariable("PII_BENCHMARK_LABEL") == "before" ? "before" : "after";
            File.WriteAllText(Path.Combine(output, "ui-performance-" + label + ".json"), System.Text.Json.JsonSerializer.Serialize(new { loadMs, filterMs }));
        } finally { window.Close(); }
    }
    [AvaloniaFact] public async Task ScanAndStopButtonsRunTheEngine() {
        string folder = Path.Combine(Path.GetTempPath(), "PiiExplorerUiTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        var window = new MainWindow(TestPaths.Assets); window.Show();
        try {
            File.WriteAllText(Path.Combine(folder, "notes.txt"), "ui.check@example.com");
            window.FindControl<TextBox>("FolderBox")!.Text = folder;
            window.FindControl<CheckBox>("NamesCheck")!.IsChecked = false;
            window.FindControl<CheckBox>("OcrCheck")!.IsChecked = false;
            var scan = window.FindControl<Button>("ScanButton")!;
            Assert.False(window.FindControl<Button>("ExportButton")!.IsEnabled);
            scan.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            for (int i = 0; i < 200 && !scan.IsEnabled; i++) await Task.Delay(25);
            Assert.True(scan.IsEnabled);
            Assert.True(window.FindControl<Button>("ExportButton")!.IsEnabled);
            Assert.Contains(window.FindControl<DataGrid>("FindingsGrid")!.ItemsSource.Cast<Finding>(), f => f.Value == "ui.check@example.com");
            scan.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            Assert.False(window.FindControl<Button>("ExportButton")!.IsEnabled);
            window.FindControl<Button>("StopButton")!.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            for (int i = 0; i < 200 && !scan.IsEnabled; i++) await Task.Delay(25);
            Assert.True(scan.IsEnabled);
            Assert.Contains("Stopped", window.FindControl<TextBlock>("StatusText")!.Text);
            scan.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            window.Close();
            for (int i = 0; i < 200 && window.IsVisible; i++) await Task.Delay(25);
            Assert.False(window.IsVisible);
        } finally { window.Close(); Directory.Delete(folder, true); }
    }
    [AvaloniaFact] public void WindowFiltersSelectsAndShowsAttention() {
        var window = new MainWindow(); window.Show();
        var findings = new Finding[] {
            new("C:/Sample files/contacts.docx", "", "document text", "Email", "maria@example.com", "Contact Maria Hernandez at maria@example.com", .99, "Pattern"),
            new("C:/Sample files/backup.rar", "hr/contacts.txt", "text", "Person", "David Okonkwo", "Account holder: David Okonkwo", .94, "Local model") };
        window.ApplyUpdate(new(Discovered: 3, Completed: 3, Findings: findings,
            Issues: [new("C:/Sample files/locked.zip", "", "Password-protected archive; contents were not checked")]));
        var grid = window.FindControl<DataGrid>("FindingsGrid")!;
        Assert.Equal(2, grid.ItemsSource.Cast<Finding>().Count());
        grid.SelectedItem = findings[0];
        Assert.Contains("maria@example.com", window.FindControl<TextBlock>("ContextText")!.Text);
        Assert.True(window.FindControl<Button>("CopyButton")!.IsEnabled);
        window.FindControl<TextBox>("SearchBox")!.Text = "backup";
        Avalonia.Threading.Dispatcher.UIThread.RunJobs();
        Assert.Single(grid.ItemsSource.Cast<Finding>());
        window.FindControl<TextBox>("SearchBox")!.Text = "";
        Avalonia.Threading.Dispatcher.UIThread.RunJobs();
        window.FindControl<ComboBox>("TypeFilter")!.SelectedItem = "Email";
        Assert.Single(grid.ItemsSource.Cast<Finding>());
        window.FindControl<ComboBox>("TypeFilter")!.SelectedIndex = 0;
        grid.SelectedItem = findings[0];
        string screenshots = Path.Combine(TestPaths.Root, "test-results"); Directory.CreateDirectory(screenshots);
        using var bitmap = window.CaptureRenderedFrame(); Assert.NotNull(bitmap); bitmap.Save(Path.Combine(screenshots, "desktop-window-" + (OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsMacOS() ? "macos" : "linux") + ".png"), Avalonia.Media.Imaging.PngBitmapEncoderOptions.Default);
        Assert.True(window.FindControl<Button>("ScanButton")!.Bounds.Right <= window.FindControl<Button>("StopButton")!.Bounds.Left);
        window.FindControl<TabControl>("ResultsTabs")!.SelectedIndex = 1;
        Avalonia.Threading.Dispatcher.UIThread.RunJobs();
        var issues = window.FindControl<DataGrid>("IssuesGrid")!; issues.SelectedItem = issues.ItemsSource.Cast<ScanIssue>().Single();
        Avalonia.Threading.Dispatcher.UIThread.RunJobs();
        Assert.False(window.FindControl<Button>("CopyButton")!.IsEnabled);
        Assert.Contains("Password", window.FindControl<TextBlock>("ContextText")!.Text);
        window.Close();
    }
}

