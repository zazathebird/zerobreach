using System.Globalization;
using System.Text;

namespace Scythe.ShellItems.Tests.Fixtures;

/// <summary>A total, culture-free rendering of every result member, for byte-identical comparison.</summary>
internal static class Dump
{
    internal static string Link(LinkResult<ShellLink> result)
    {
        var sb = new StringBuilder();
        WriteLink(sb, result, string.Empty);
        return sb.ToString();
    }

    internal static string Automatic(LinkResult<AutomaticDestinations> result)
    {
        var sb = new StringBuilder();
        Line(sb, string.Empty, $"state={result.State} reason={Esc(result.Reason)} pos={Num(result.Position)}");
        var v = result.Value;
        if (v is null)
        {
            return sb.ToString();
        }

        Line(sb, string.Empty, $"header version={v.Header.Version} count={v.Header.EntryCount} pinned={v.Header.PinnedEntryCount} float={v.Header.UnknownFloat.ToString("R", CultureInfo.InvariantCulture)} last={v.Header.LastEntryNumber} u1={v.Header.Unknown1} rev={v.Header.LastRevisionNumber}");
        foreach (var e in v.Entries)
        {
            Line(sb, "  ", $"entry off={e.Offset} number={e.EntryNumber} checksum={e.Checksum:X16} nv={e.NewVolumeId:D} no={e.NewObjectId:D} bv={e.BirthVolumeId:D} bo={e.BirthObjectId:D} machine={Esc(e.MachineName.Value)} access={e.LastAccessTime.Ticks} pin={e.PinStatus} pinned={Num(e.PinnedIndex)} count={Num(e.AccessCount)} path={Esc(e.Path.Value)} raw={Hex(e.Path.RawBytes)} stream={Esc(e.LinkStreamName)}");
            if (e.Link is not null)
            {
                WriteLink(sb, e.Link, "    ");
            }
        }

        Line(sb, string.Empty, $"unreferenced={string.Join("|", v.UnreferencedLinkStreams)}");
        Line(sb, string.Empty, $"notes={string.Join("|", v.Notes.Select(Esc))}");
        return sb.ToString();
    }

    internal static string Custom(LinkResult<CustomDestinations> result)
    {
        var sb = new StringBuilder();
        Line(sb, string.Empty, $"state={result.State} reason={Esc(result.Reason)} pos={Num(result.Position)}");
        var v = result.Value;
        if (v is null)
        {
            return sb.ToString();
        }

        Line(sb, string.Empty, $"version={v.Version} u1={v.Unknown1} u2={v.Unknown2} declared={v.DeclaredEntryCount} footer={Num(v.FooterOffset)} skipped={v.SkippedBytes}");
        foreach (var e in v.Entries)
        {
            Line(sb, "  ", $"entry off={e.Offset}");
            WriteLink(sb, e.Link, "    ");
        }

        Line(sb, string.Empty, $"notes={string.Join("|", v.Notes.Select(Esc))}");
        return sb.ToString();
    }

    private static void WriteLink(StringBuilder sb, LinkResult<ShellLink> result, string indent)
    {
        Line(sb, indent, $"link state={result.State} reason={Esc(result.Reason)} pos={Num(result.Position)}");
        var v = result.Value;
        if (v is null)
        {
            return;
        }

        var h = v.Header;
        Line(sb, indent, $"header size={h.HeaderSize} clsid={h.ClassId:D} flags={(uint)h.Flags:X8} attrs={h.FileAttributes:X8} c={h.CreationTime.Ticks}/{h.CreationTime.Presence} a={h.AccessTime.Ticks}/{h.AccessTime.Presence} w={h.WriteTime.Ticks}/{h.WriteTime.Presence} size={h.FileSize} icon={h.IconIndex} show={h.ShowCommand} hotkey={h.HotKey} raw={Hex(h.RawBytes)}");

        if (v.TargetIdList is { } list)
        {
            WriteIdList(sb, list, indent + "  ");
        }

        if (v.LinkInfo is { } info)
        {
            Line(sb, indent, $"linkinfo size={info.Size} hdr={info.HeaderSize} flags={info.Flags} local={Esc(info.LocalPath)} network={Esc(info.NetworkPath)}");
            if (info.VolumeId is { } vol)
            {
                Line(sb, indent + "  ", $"volume size={vol.Size} type={vol.DriveTypeValue}/{vol.DriveType} serial={vol.SerialNumber:X8} labeloff={vol.LabelOffset} ulabeloff={Num(vol.UnicodeLabelOffset)} label={Str(vol.Label)} ulabel={Str(vol.UnicodeLabel)}");
            }

            Line(sb, indent + "  ", $"basepath={Str(info.LocalBasePath)} suffix={Str(info.CommonPathSuffix)} ubasepath={Str(info.LocalBasePathUnicode)} usuffix={Str(info.CommonPathSuffixUnicode)}");
            if (info.NetworkRelativeLink is { } net)
            {
                Line(sb, indent + "  ", $"network size={net.Size} flags={net.Flags} netoff={net.NetNameOffset} devoff={net.DeviceNameOffset} provider={Num(net.NetworkProviderType)} net={Str(net.NetName)} dev={Str(net.DeviceName)} unet={Str(net.NetNameUnicode)} udev={Str(net.DeviceNameUnicode)}");
            }
        }

        Line(sb, indent, $"name={Str(v.Name)} rel={Str(v.RelativePath)} wd={Str(v.WorkingDirectory)} args={Str(v.Arguments)} icon={Str(v.IconLocation)}");
        foreach (var block in v.ExtraData)
        {
            Line(sb, indent + "  ", $"block {block.GetType().Name} sig={block.Signature:X8} size={block.Size} raw={Hex(block.RawBytes)}");
            switch (block)
            {
                case EnvironmentStringsBlock env:
                    Line(sb, indent + "    ", $"ansi={Str(env.AnsiTarget)} unicode={Str(env.UnicodeTarget)} disagree={env.AnsiAndUnicodeDisagree}");
                    break;
                case KnownFolderBlock kf:
                    Line(sb, indent + "    ", $"folder={kf.KnownFolderId:D} off={kf.Offset}");
                    break;
                case SpecialFolderBlock sf:
                    Line(sb, indent + "    ", $"folder={sf.SpecialFolderId} off={sf.Offset}");
                    break;
                case TrackerBlock tr:
                    Line(sb, indent + "    ", $"len={tr.Length} ver={tr.Version} machine={Str(tr.MachineId)} dv={tr.DroidVolume:D} df={tr.DroidFile:D} bv={tr.DroidBirthVolume:D} bf={tr.DroidBirthFile:D}");
                    break;
                case VistaIdListBlock vista:
                    WriteIdList(sb, vista.IdList, indent + "    ");
                    break;
                case RawExtraDataBlock raw:
                    Line(sb, indent + "    ", $"note={Esc(raw.Note)}");
                    break;
            }
        }

        Line(sb, indent, $"disagree={(v.TargetPathsDisagree is null ? "null" : v.TargetPathsDisagree.Value.ToString())} length={v.Length} notes={string.Join("|", v.Notes.Select(Esc))}");
    }

    private static void WriteIdList(StringBuilder sb, LinkTargetIdList list, string indent)
    {
        Line(sb, indent, $"idlist size={list.DeclaredSize} path={Esc(list.Path)} completeness={list.PathCompleteness} notes={string.Join("|", list.Notes.Select(Esc))}");
        foreach (var item in list.Items)
        {
            Line(sb, indent + "  ", $"item class={item.ClassType:X2} kind={item.Kind} known={item.PathSegmentKnown} seg={Esc(item.PathSegment)} sort={Num(item.SortIndex)} root={(item.RootFolderClassId is null ? "null" : item.RootFolderClassId.Value.ToString("D"))} drive={Esc(item.DriveString)} fkind={(item.FileEntryKind is null ? "null" : item.FileEntryKind.ToString())} fsize={Num(item.FileSize)} dos={Num(item.ModifiedDosDateTime)} attrs={Num(item.FileAttributes)} primary={Esc(item.PrimaryName)} netflags={Num(item.NetworkFlags)} net={Esc(item.NetworkLocation)} desc={Esc(item.NetworkDescription)} comments={Esc(item.NetworkComments)} raw={Hex(item.RawData)}");
            if (item.Extension is { } ext)
            {
                Line(sb, indent + "    ", $"beef4 size={ext.Size} ver={ext.Version} c={ext.CreationDosDateTime} a={ext.AccessDosDateTime} ref={Num(ext.FileReference)} long={Esc(ext.LongName)} first={Num(ext.FirstExtensionOffset)} raw={Hex(ext.RawBytes)}");
            }

            foreach (var other in item.OtherExtensionBlocks)
            {
                Line(sb, indent + "    ", $"ext sig={other.Signature:X8} ver={other.Version} size={other.Size} raw={Hex(other.RawBytes)}");
            }
        }
    }

    private static void Line(StringBuilder sb, string indent, string text) => sb.Append(indent).Append(text).Append('\n');

    private static string Str(LinkString? s) => s is null ? "null" : $"{Esc(s.Value)}[{Hex(s.RawBytes)}/{s.Encoding}/{s.AmbiguousEncoding}]";

    private static string Num<T>(T? value) where T : struct => value is null ? "null" : string.Format(CultureInfo.InvariantCulture, "{0}", value.Value);

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes);

    /// <summary>Every code unit outside printable ASCII is rendered as \uXXXX, so lone surrogates and nulls survive.</summary>
    internal static string Esc(string? text)
    {
        if (text is null)
        {
            return "null";
        }

        var sb = new StringBuilder();
        foreach (var c in text)
        {
            if (c is >= ' ' and <= '~' && c != '\\')
            {
                sb.Append(c);
            }
            else
            {
                sb.Append("\\u").Append(((int)c).ToString("X4", CultureInfo.InvariantCulture));
            }
        }

        return sb.ToString();
    }
}
