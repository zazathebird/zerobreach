using System.Globalization;
using System.Text;
using ZeroBreach.Formats;
using ZeroBreach.Formats.Pe;

namespace ZeroBreach.Formats.Tests;

internal static class TestParse
{
    /// <summary>Parse under the default budget — the normal path for every non-budget test.</summary>
    public static PeParseResult Run(byte[] file) => PeParser.Parse(file, BudgetDefaults.Default);

    /// <summary>
    /// Canonical text form of a full parse result, for determinism comparison: every field of
    /// every structure and metric, in a fixed order and culture.
    /// </summary>
    public static string Dump(PeParseResult result)
    {
        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture, $"state={result.State} msg={result.Message} off={result.ErrorOffset}\n");
        foreach (string reason in result.IncompleteReasons)
            sb.Append(CultureInfo.InvariantCulture, $"reason={reason}\n");
        if (result.Image is { } img)
        {
            sb.Append(CultureInfo.InvariantCulture, $"dos={img.DosHeader}\nfile={img.FileHeader}\nopt={img.OptionalHeader}\n");
            foreach (var d in img.DataDirectories)
                sb.Append(CultureInfo.InvariantCulture, $"dir={d}\n");
            foreach (var s in img.Sections)
                sb.Append(CultureInfo.InvariantCulture, $"sect={s}\n");
            foreach (var dll in img.Imports)
            {
                sb.Append(CultureInfo.InvariantCulture, $"import={dll.Name}\n");
                foreach (var f in dll.Functions)
                    sb.Append(CultureInfo.InvariantCulture, $"  fn={f}\n");
            }
            if (img.Exports is { } ex)
            {
                sb.Append(CultureInfo.InvariantCulture, $"exports={ex.DllName} base={ex.OrdinalBase} tds={ex.TimeDateStamp}\n");
                foreach (var e in ex.Entries)
                    sb.Append(CultureInfo.InvariantCulture, $"  exp={e}\n");
            }
            DumpResource(sb, img.ResourceRoot, 0);
            sb.Append(CultureInfo.InvariantCulture, $"cert={img.Certificate}\n");
            foreach (var dbg in img.DebugEntries)
                sb.Append(CultureInfo.InvariantCulture, $"debug={dbg}\n");
            if (img.RichHeader is { } rich)
            {
                sb.Append(CultureInfo.InvariantCulture, $"richkey={rich.XorKey:X8}\n");
                foreach (var e in rich.Entries)
                    sb.Append(CultureInfo.InvariantCulture, $"  rich={e}\n");
            }
            if (img.Tls is { } tls)
                sb.Append(CultureInfo.InvariantCulture, $"tls present={tls.Present} callbacks=[{string.Join(",", tls.CallbackAddresses)}]\n");
        }
        if (result.Metrics is { } m)
        {
            sb.Append(CultureInfo.InvariantCulture,
                $"metrics wfe={m.WholeFileEntropy:R} epOut={m.EntryPointOutsideAnySection} epW={m.EntryPointInWritableSection} " +
                $"ovl={m.OverlayPresent}/{m.OverlayOffset}/{m.OverlaySize} dlls={m.ImportedDllCount} fns={m.ImportedFunctionCount} " +
                $"tls={m.TlsCallbacksPresent}/{m.TlsCallbackCount}\n");
            foreach (var s in m.Sections)
                sb.Append(CultureInfo.InvariantCulture, $"smetric idx={s.Index} name={s.Name} e={s.Entropy:R} wx={s.WritableAndExecutable} zrs={s.ZeroRawSizeWithLargeVirtualSize} unc={s.UncommonName}\n");
        }
        return sb.ToString();
    }

    private static void DumpResource(StringBuilder sb, PeResourceNode? node, int depth)
    {
        if (node is null)
            return;
        sb.Append(CultureInfo.InvariantCulture, $"res{new string(' ', depth)} name={node.Name} id={node.Id} data={node.Data}\n");
        foreach (var child in node.Children)
            DumpResource(sb, child, depth + 1);
    }
}
