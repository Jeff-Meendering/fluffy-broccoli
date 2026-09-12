namespace PiiExplorer.Core;

// Entries are mutated by their owning file worker; discovery owns excluded entries.
internal sealed class CoverageEntry(string file, string source, string resource)
{
    public HashSet<CoverageReason> Reasons { get; } = [];
    public bool Read { get; set; }
    public bool Finished { get; set; }
    public void Add(CoverageReason reason) => Reasons.Add(reason);
    public InputOutcome Outcome()
    {
        var status = Reasons.Count == 0 ? CoverageStatus.Success
            : Reasons.SetEquals([CoverageReason.Excluded]) ? CoverageStatus.Excluded
            : !Read && (Reasons.Contains(CoverageReason.ExtractionFailure) || Reasons.Contains(CoverageReason.DiscoveryFailure)) ? CoverageStatus.Failed
            : !Finished && !Read ? CoverageStatus.Unchecked
            : CoverageStatus.Partial;
        return new(file, source, resource, status, Reasons.Order().ToArray());
    }
}
