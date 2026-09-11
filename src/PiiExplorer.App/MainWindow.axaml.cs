using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Input.Platform;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.Styling;
using PiiExplorer.Core;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace PiiExplorer.App;

public partial class MainWindow : Window
{
    private readonly List<Finding> _all = [];
    private readonly ResultCollection<Finding> _visible = [];
    private readonly ResultCollection<ScanIssue> _issues = [];
    private readonly ResultCollection<ScanIssue> _visibleIssues = [];
    private readonly ConcurrentQueue<ScanUpdate> _pending = new();
    private readonly DispatcherTimer _timer;
    private readonly DispatcherTimer _filterTimer;
    private string _query = "", _type = "All types";
    private CancellationTokenSource? _cancellation;
    private Finding? _selected;
    private string? _sourceFile;
    private bool _scanning;
    private bool _closeRequested;
    private bool _exporting;
    private string? _scanRoot;
    private ScanOptions _scanOptions = new();
    private ScanSummary? _summary;
    private Dictionary<(string, string), string>? _reportSources;
    private int _completed, _discovered;
    private readonly RuntimePaths _paths;
    private readonly string _appearancePath;
    private bool _loadingTheme = true;

    public MainWindow() : this(new RuntimePaths(Program.AssetsOverride)) { }
    public MainWindow(RuntimePaths paths, string? appearancePath = null)
    {
        _paths = paths;
        _appearancePath = appearancePath ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PiiExplorer", "theme.txt");
        InitializeComponent();
        ThemeChoice.ItemsSource = new[] { "System", "Light", "Dark" };
        string theme = "System";
        try { if (File.Exists(_appearancePath)) theme = File.ReadAllText(_appearancePath).Trim(); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        ThemeChoice.SelectedItem = theme is "Light" or "Dark" ? theme : "System";
        _loadingTheme = false;
        _filterTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(150) };
        _filterTimer.Tick += (_, _) => RefreshFilter();
        FindingsGrid.ItemsSource = _visible; IssuesGrid.ItemsSource = _visibleIssues;
        TypeFilter.ItemsSource = new[] { "All types" }.Concat(PiiTypes.All).ToArray();
        TypeFilter.SelectedIndex = 0;
        WorkerCount.Value = ScanOptions.DefaultWorkers;
        _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(80), DispatcherPriority.Background, (_, _) => Drain());
        _timer.Start();
        Closing += (_, e) => {
            if (_scanning || _exporting) {
                e.Cancel = true; _closeRequested = true; _cancellation?.Cancel();
                StatusText.Text = "Stopping before closing…"; return;
            }
            _cancellation?.Dispose(); _timer.Stop(); _filterTimer.Stop();
        };
    }

    private void ThemeChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (ThemeChoice?.SelectedItem is not string theme) return;
        RequestedThemeVariant = theme switch { "Dark" => ThemeVariant.Dark, "Light" => ThemeVariant.Light, _ => ThemeVariant.Default };
        if (_loadingTheme) return;
        try {
            Directory.CreateDirectory(Path.GetDirectoryName(_appearancePath)!);
            File.WriteAllText(_appearancePath, theme);
        } catch (Exception error) when (error is IOException or UnauthorizedAccessException) {
            StatusText.Text = "Theme applied for this session; the preference could not be saved.";
        }
    }

    private async void ChooseFolder(object? sender, RoutedEventArgs e)
    {
        try {
            var selection = await StorageProvider.OpenFolderPickerAsync(new() { Title = "Choose a folder to scan", AllowMultiple = false });
            if (selection.Count > 0) FolderBox.Text = selection[0].TryGetLocalPath();
        } catch (Exception) { StatusText.Text = "The folder picker is unavailable. Paste a folder path into the box to continue."; }
    }

    private async void StartScan(object? sender, RoutedEventArgs e)
    {
        string folder = (FolderBox.Text ?? "").Trim().Trim('"');
        if (!Directory.Exists(folder)) { StatusText.Text = "Choose an existing folder first."; return; }
        _all.Clear(); _visible.Clear(); _issues.Clear(); _visibleIssues.Clear(); _selected = null; _sourceFile = null;
        _scanRoot = Path.GetFullPath(folder); _summary = null; _reportSources = null;
        RevealButton.IsEnabled = CopyButton.IsEnabled = false;
        _completed = _discovered = 0;
        FindingCount.Text = FileCount.Text = IssueCount.Text = "0";
        SourceText.Text = "Findings will appear as files are checked."; ContextText.Text = MethodText.Text = LocationText.Text = "";
        SetScanning(true);
        _cancellation?.Dispose(); _cancellation = new();
        StatusText.Text = "Discovering files and loading local detection…";
        try {
            var engine = new ScanEngine(_paths);
            var options = _scanOptions = new ScanOptions(OcrCheck.IsChecked == true, NamesCheck.IsChecked == true,
                Workers: (int)(WorkerCount.Value ?? ScanOptions.DefaultWorkers), MaxFileBytes: (long)(SizeLimit.Value ?? 100) * 1024 * 1024,
                PhoneRegions: string.IsNullOrWhiteSpace(PhoneRegionsBox.Text) ? "US,GB" : PhoneRegionsBox.Text);
            var summary = _summary = await Task.Run(() => engine.ScanAsync(folder, options,
                new InlineProgress<ScanUpdate>(_pending.Enqueue), _cancellation.Token));
            Drain(all: true);
            StatusText.Text = $"{(summary.Cancelled ? "Stopped" : "Finished")} · {summary.Completed:N0}/{summary.Files:N0} files · {_all.Count:N0} findings · {_issues.Count:N0} attention items · {summary.Elapsed.TotalSeconds:N0}s";
            if (_all.Count == 0) SourceText.Text = "No PII was detected in the checked content. Review any attention items; detection is not exhaustive.";
        } catch (OperationCanceledException) { StatusText.Text = "Stopped. Findings already collected are still available."; }
        catch (Exception error) { StatusText.Text = error.Message; }
        finally {
            Drain(all: true);
            _summary ??= new(_discovered, _completed, _all.Count, _issues.Count, TimeSpan.Zero, true);
            SetScanning(false); if (_closeRequested) Close();
        }
    }

    private void SetScanning(bool value)
    {
        _scanning = value; ScanButton.IsEnabled = ChooseButton.IsEnabled = FolderBox.IsEnabled = OcrCheck.IsEnabled = NamesCheck.IsEnabled = SizeLimit.IsEnabled = WorkerCount.IsEnabled = PhoneRegionsBox.IsEnabled = !value;
        StopButton.IsEnabled = value; ScanProgress.IsIndeterminate = value && _discovered == 0;
        ExportButton.IsEnabled = !value && _summary is not null;
        EmptyState.IsVisible = !value && _all.Count == 0 && _issues.Count == 0;
        if (!value) EmptyState.IsVisible = false;
    }
    private void StopScan(object? sender, RoutedEventArgs e) { _cancellation?.Cancel(); StatusText.Text = "Stopping…"; StopButton.IsEnabled = false; }

    private async void ExportReport(object? sender, RoutedEventArgs e)
    {
        if (_summary is null || _scanRoot is null || _scanning || _exporting) return;
        var report = new ReportSnapshot(_scanRoot, _all.ToArray(), _issues.ToArray(), _summary, _scanOptions,
            new(HideFileNamesCheck.IsChecked == true, ReportContextCheck.IsChecked == true));
        try {
            var file = await StorageProvider.SaveFilePickerAsync(new() {
                Title = "Save PII findings report (choose a new filename)", SuggestedFileName = "pii-findings.pdf", DefaultExtension = "pdf",
                FileTypeChoices = [new("PDF report") { Patterns = ["*.pdf"], MimeTypes = ["application/pdf"] }]
            });
            if (file is null) return;
            using (file) {
                string path = file.TryGetLocalPath() ?? throw new IOException("Choose a local destination for the report.");
                _exporting = true;
                SetScanning(true); _scanning = false;
                HideFileNamesCheck.IsEnabled = ReportContextCheck.IsEnabled = false;
                ScanProgress.IsIndeterminate = true;
                _cancellation?.Dispose(); _cancellation = new();
                StatusText.Text = "Creating PDF report…";
                await Task.Run(() => PdfReport.Save(path, report, _cancellation.Token));
                _reportSources = PdfReport.SourceLabels(report);
                RefreshFilter();
                StatusText.Text = "PDF saved. Identifying metadata omitted; the report contains the detected PII.";
                if (_selected is not null) SourceText.Text = ReportSource(_selected.FilePath, _selected.Source) + _selected.DisplaySource;
            }
        } catch (OperationCanceledException) { StatusText.Text = "Report export stopped. Any existing report was preserved."; }
        catch (Exception error) { StatusText.Text = "Could not save PDF: " + error.Message; }
        finally {
            _exporting = false; SetScanning(false);
            HideFileNamesCheck.IsEnabled = ReportContextCheck.IsEnabled = true;
            if (_closeRequested) Close();
        }
    }

    private string ReportSource(string file, string source) => _reportSources is not null && _reportSources.TryGetValue((file, source), out var label)
        ? "Report: " + label + " · " : "";

    private void Drain(bool all = false)
    {
        if (_pending.IsEmpty) return;
        int updates = 0, discovered = 0, completed = 0;
        string current = "";
        var findings = new List<Finding>(); var issues = new List<ScanIssue>();
        while ((all || updates++ < 200) && _pending.TryDequeue(out var update)) {
            discovered = Math.Max(discovered, update.Discovered); completed = Math.Max(completed, update.Completed);
            if (update.CurrentFile.Length > 0) current = update.CurrentFile;
            if (update.Findings is not null) findings.AddRange(update.Findings);
            if (update.Issues is not null) issues.AddRange(update.Issues);
        }
        if (findings.Count > 0 || issues.Count > 0 || discovered > 0 || current.Length > 0)
            ApplyUpdate(new(current, discovered, completed, findings, issues));
    }

    public void ApplyUpdate(ScanUpdate update)
    {
        _discovered = Math.Max(_discovered, update.Discovered);
        _completed = Math.Max(_completed, update.Completed);
        var selected = FindingsGrid.SelectedItem as Finding;
        if (update.Findings is not null) { _all.AddRange(update.Findings); _visible.Append(update.Findings.Where(Matches).ToArray()); }
        if (selected is not null) FindingsGrid.SelectedItem = selected;
        var selectedIssue = IssuesGrid.SelectedItem as ScanIssue;
        if (update.Issues is not null) { _issues.Append(update.Issues); _visibleIssues.Append(update.Issues.Where(MatchesIssue).ToArray()); }
        if (selectedIssue is not null) IssuesGrid.SelectedItem = selectedIssue;
        FindingCount.Text = _all.Count.ToString("N0"); IssueCount.Text = _issues.Count.ToString("N0");
        FileCount.Text = _discovered > 0 ? $"{_completed:N0} / {_discovered:N0}" : "0";
        ScanProgress.IsIndeterminate = _scanning && _discovered == 0;
        ScanProgress.Maximum = Math.Max(1, _discovered); ScanProgress.Value = _completed;
        if (_all.Count > 0 || _issues.Count > 0 || _scanning) EmptyState.IsVisible = false;
        if (_scanning && update.CurrentFile.Length > 0) StatusText.Text = "Checking " + update.CurrentFile;
    }

    private bool Matches(Finding finding)
    {
        return (_type == "All types" || _type == finding.Type) && (_query.Length == 0 ||
            finding.Value.Contains(_query, StringComparison.OrdinalIgnoreCase) || finding.DisplaySource.Contains(_query, StringComparison.OrdinalIgnoreCase) ||
            ReportSource(finding.FilePath, finding.Source).Contains(_query, StringComparison.OrdinalIgnoreCase));
    }
    private void RefreshFilter()
    {
        if (SearchBox is null || TypeFilter is null) return;
        _filterTimer?.Stop();
        _query = SearchBox.Text?.Trim() ?? ""; _type = TypeFilter.SelectedItem as string ?? "All types";
        var selected = FindingsGrid.SelectedItem as Finding;
        _visible.Replace(_all.Where(Matches));
        var selectedIssue = IssuesGrid.SelectedItem as ScanIssue;
        _visibleIssues.Replace(_issues.Where(MatchesIssue));
        IssuesGrid.SelectedItem = selectedIssue is not null && MatchesIssue(selectedIssue) ? selectedIssue : null;
        FindingsGrid.SelectedItem = selected is not null && Matches(selected) ? selected : null;
    }
    private bool MatchesIssue(ScanIssue issue) => _query.Length == 0 || issue.DisplaySource.Contains(_query, StringComparison.OrdinalIgnoreCase) ||
        issue.Message.Contains(_query, StringComparison.OrdinalIgnoreCase) || ReportSource(issue.FilePath, issue.Source).Contains(_query, StringComparison.OrdinalIgnoreCase);
    private void FilterChanged(object? sender, TextChangedEventArgs e)
    {
        if (_all.Count < 5000) { RefreshFilter(); return; }
        _filterTimer.Stop(); _filterTimer.Start();
    }
    private void TypeChanged(object? sender, SelectionChangedEventArgs e) => RefreshFilter();
    private void FindingSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (FindingsGrid.SelectedItem is not Finding finding) {
            if (ResultsTabs.SelectedIndex == 0) {
                _selected = null; _sourceFile = null; RevealButton.IsEnabled = CopyButton.IsEnabled = false;
                SourceText.Text = "Select a result to see its source and surrounding text.";
                ContextText.Text = MethodText.Text = LocationText.Text = "";
            }
            return;
        }
        _selected = finding; _sourceFile = finding.FilePath;
        SourceText.Text = ReportSource(finding.FilePath, finding.Source) + finding.DisplaySource; ContextText.Text = finding.Context;
        MethodText.Text = finding.Type + " · " + (finding.Method == "Local model" ? "Model score " + finding.Score + " (uncalibrated)" :
            (finding.Method.StartsWith("Pattern (", StringComparison.Ordinal) ? finding.Method[9..].TrimEnd(')') : "Pattern / context match") +
            " · confidence " + finding.Score + (finding.Method.Contains("Unicode normalized", StringComparison.Ordinal) ? " · Unicode normalized; original value shown" : ""));
        LocationText.Text = finding.Location; RevealButton.IsEnabled = CopyButton.IsEnabled = true;
    }
    private void IssueSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (IssuesGrid.SelectedItem is not ScanIssue issue) {
            if (ResultsTabs.SelectedIndex == 1) {
                _selected = null; _sourceFile = null; RevealButton.IsEnabled = CopyButton.IsEnabled = false;
                SourceText.Text = "Select an attention item to see its source.";
                ContextText.Text = MethodText.Text = LocationText.Text = "";
            }
            return;
        }
        _selected = null; _sourceFile = issue.FilePath; SourceText.Text = ReportSource(issue.FilePath, issue.Source) + issue.DisplaySource;
        ContextText.Text = issue.Message; MethodText.Text = "Needs attention"; LocationText.Text = "";
        RevealButton.IsEnabled = true; CopyButton.IsEnabled = false;
    }
    private void RevealFile(object? sender, RoutedEventArgs e)
    {
        if (_sourceFile is null) return;
        try {
            var start = new ProcessStartInfo { UseShellExecute = false, CreateNoWindow = true };
            if (OperatingSystem.IsWindows()) { start.FileName = "explorer.exe"; start.ArgumentList.Add("/select," + _sourceFile); }
            else { start.FileName = "xdg-open"; start.ArgumentList.Add(Directory.Exists(_sourceFile) ? _sourceFile : Path.GetDirectoryName(_sourceFile)!); }
            Process.Start(start);
        } catch (Exception error) { StatusText.Text = "Could not open file manager: " + error.Message; }
    }
    private async void CopyValue(object? sender, RoutedEventArgs e)
    {
        try {
            if (_selected is not null && Clipboard is not null) { await Clipboard.SetTextAsync(_selected.Value); StatusText.Text = "Value copied to your clipboard."; }
        } catch (Exception) { StatusText.Text = "The system clipboard is unavailable."; }
    }
}
