using Xunit;

namespace PiiExplorer.Tests;

public sealed class LicenseReadinessTests
{
    private static string Read(params string[] parts) =>
        File.ReadAllText(Path.Combine([TestPaths.Root, .. parts]));

    [Fact]
    public void SourceCarriesTheCompleteApacheLicense()
    {
        string license = Read("LICENSE");
        Assert.Contains("Apache License", license);
        Assert.Contains("Version 2.0, January 2004", license);
        Assert.Contains("http://www.apache.org/licenses/", license);
        foreach (string section in new[] { "1. Definitions.", "2. Grant of Copyright License.",
            "3. Grant of Patent License.", "4. Redistribution.", "5. Submission of Contributions.",
            "6. Trademarks.", "7. Disclaimer of Warranty.", "8. Limitation of Liability.",
            "9. Accepting Warranty or Additional Liability." }) {
            Assert.Contains(section, license);
        }
        Assert.Contains("APPENDIX: How to apply the Apache License to your work.", license);
        // A truncated or placeholder license is not a license grant.
        Assert.True(license.Length > 10_000, "LICENSE is shorter than the full Apache-2.0 text");
    }

    [Fact]
    public void NoticeNamesTheProjectAndItsOwnLicense()
    {
        string notice = Read("NOTICE");
        Assert.Contains("PII Explorer", notice);
        Assert.Contains("Apache License, Version 2.0", notice);
        Assert.Contains("THIRD-PARTY-NOTICES.md", notice);
    }

    [Fact]
    public void PrivateVulnerabilityReportingIsDocumented()
    {
        string security = Read("SECURITY.md");
        Assert.Contains("/security/advisories/new", security);
        Assert.Contains("Do not open a public issue", security);
    }

    [Fact]
    public void DocumentationAndPackageMetadataIdentifyTheSameLicense()
    {
        string readme = Read("README.md");
        Assert.Contains("Apache License 2.0", readme);
        Assert.Contains("(LICENSE)", readme);
        Assert.Contains("SECURITY.md", readme);
        string contributing = Read("CONTRIBUTING.md");
        Assert.Contains("Apache License 2.0", contributing);
        Assert.DoesNotContain("does not yet declare a license", contributing);
        Assert.Contains("<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>", Read("Directory.Build.props"));
    }

    [Fact]
    public void PackagingCopiesAndChecksTheLicense()
    {
        Assert.Contains("'LICENSE', 'NOTICE', 'SECURITY.md'", Read("scripts", "Publish.ps1"));
        Assert.Contains("'LICENSE', 'NOTICE'", Read("scripts", "Verify-Package.ps1"));
        Assert.Contains("LICENSE NOTICE SECURITY.md", Read("scripts", "publish-macos.sh"));
        Assert.Contains("$project_dir/LICENSE", Read("scripts", "prepare-linux.sh"));
        // Packages are build output, so the runtime content check lives in Verify-Package.ps1,
        // which runs against every published package.
        Assert.Contains("Package is missing $required", Read("scripts", "Verify-Package.ps1"));
    }
}
