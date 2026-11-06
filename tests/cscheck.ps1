param([string]$Path, [string]$RefDir, [switch]$NoFacades, [string]$Block = 'EngineSource',
    [string[]]$Names = @('mscorlib', 'System', 'System.Core', 'System.Security', 'System.Runtime.Serialization', 'System.Xml'))
# Compile C# source as C# 5 against .NET Framework 4.7.2 reference assemblies (what Windows PowerShell 5.1 Add-Type uses).
Add-Type -Path (Join-Path $PSHOME 'Microsoft.CodeAnalysis.dll')
Add-Type -Path (Join-Path $PSHOME 'Microsoft.CodeAnalysis.CSharp.dll')
$code = Get-Content -Raw -LiteralPath $Path
if ($Path -like '*.ps1') {
    # extract the C# here-string between the markers
    if ($code -match "(?s)\`$$Block = @'\r?\n(.*?)\r?\n'@") { $code = $Matches[1] } else { throw "C# block `$$Block not found" }
}
$po = [Microsoft.CodeAnalysis.CSharp.CSharpParseOptions]::new([Microsoft.CodeAnalysis.CSharp.LanguageVersion]::CSharp5)
$tree = [Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree]::ParseText($code, $po)
$refs = foreach ($n in $Names) { [Microsoft.CodeAnalysis.MetadataReference]::CreateFromFile((Join-Path $RefDir "$n.dll")) }
if (-not $NoFacades) { $refs += Get-ChildItem (Join-Path $RefDir 'Facades') -Filter *.dll | ForEach-Object { [Microsoft.CodeAnalysis.MetadataReference]::CreateFromFile($_.FullName) } }
$co = [Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions]::new([Microsoft.CodeAnalysis.OutputKind]::DynamicallyLinkedLibrary)
$comp = [Microsoft.CodeAnalysis.CSharp.CSharpCompilation]::Create('WebInvCheck', [Microsoft.CodeAnalysis.SyntaxTree[]]@($tree), [Microsoft.CodeAnalysis.MetadataReference[]]$refs, $co)
$ms = [IO.MemoryStream]::new()
$res = $comp.Emit($ms)
$diags = $res.Diagnostics | Where-Object { $_.Severity -ge [Microsoft.CodeAnalysis.DiagnosticSeverity]::Warning }
foreach ($d in $diags) { Write-Output ("{0} {1}: {2} @ {3}" -f $d.Severity, $d.Id, $d.GetMessage(), $d.Location.GetLineSpan().StartLinePosition) }
Write-Output ("C#5/net472 compile: success={0} errors={1} warnings={2} bytes={3}" -f $res.Success, @($diags | Where-Object Severity -eq 'Error').Count, @($diags | Where-Object Severity -eq 'Warning').Count, $ms.Length)
