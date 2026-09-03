using System.Globalization;
using System.Text;

namespace Scythe.Identity.Tests.Fixtures;

/// <summary>
/// Programmatic fixtures for every layout in reference/11.3 §11.3. Everything is constructed from
/// fields so that a malformed variant is one overridden parameter away from the valid one.
/// </summary>
internal static class Fx
{
    // ---- identifiers -------------------------------------------------------------------------

    /// <summary>Binary identifier: revision, count, big-endian 48-bit authority, little-endian sub-authorities.</summary>
    public static byte[] SidOf(byte revision, ulong authority, params uint[] subs)
    {
        var bytes = new byte[8 + 4 * subs.Length];
        bytes[0] = revision;
        bytes[1] = (byte)subs.Length;
        for (var i = 0; i < 6; i++)
        {
            bytes[2 + i] = (byte)(authority >> (8 * (5 - i)));
        }

        for (var i = 0; i < subs.Length; i++)
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(8 + 4 * i, 4), subs[i]);
        }

        return bytes;
    }

    /// <summary>Revision 1, authority 5.</summary>
    public static byte[] Sid(params uint[] subs) => SidOf(1, 5, subs);

    /// <summary>The same layout with a count field that does not match the array — for the lying-count fixtures.</summary>
    public static byte[] SidWithCount(byte count, params uint[] subs)
    {
        var bytes = Sid(subs);
        bytes[1] = count;
        return bytes;
    }

    public static byte[] Everyone => SidOf(1, 1, 0);
    public static byte[] LocalSystem => Sid(18);
    public static byte[] Administrators => Sid(32, 544);
    public static byte[] Guests => Sid(32, 546);
    public static byte[] MediumLabel => SidOf(1, 16, 8192);
    public static byte[] DomainAccount(uint rid) => Sid(21, 1_000_001, 2_000_002, 3_000_003, rid);

    public static SecurityIdentifier Value(byte[] sid) => Unwrap(IdentifierDecoder.Decode(sid));

    // ---- entries -----------------------------------------------------------------------------

    /// <summary>Ordinary body: header, mask, trailer, optional application data, optional zero padding.</summary>
    public static byte[] Entry(byte type, byte flags, uint mask, byte[] sid, byte[]? extra = null, int padding = 0, ushort? declaredSize = null)
    {
        extra ??= Array.Empty<byte>();
        var size = 8 + sid.Length + extra.Length + padding;
        var bytes = new byte[size];
        bytes[0] = type;
        bytes[1] = flags;
        BitConverter.TryWriteBytes(bytes.AsSpan(2, 2), declaredSize ?? (ushort)size);
        BitConverter.TryWriteBytes(bytes.AsSpan(4, 4), mask);
        sid.CopyTo(bytes, 8);
        extra.CopyTo(bytes, 8 + sid.Length);
        return bytes;
    }

    /// <summary>Object body: header, mask, object flags, the type identifiers whose bits are set, trailer, optional extra.</summary>
    public static byte[] ObjectEntry(byte type, byte flags, uint mask, uint objectFlags, Guid? objectType, Guid? inheritedObjectType, byte[] sid, byte[]? extra = null, ushort? declaredSize = null)
    {
        extra ??= Array.Empty<byte>();
        var size = 12 + (objectType is null ? 0 : 16) + (inheritedObjectType is null ? 0 : 16) + sid.Length + extra.Length;
        var bytes = new byte[size];
        bytes[0] = type;
        bytes[1] = flags;
        BitConverter.TryWriteBytes(bytes.AsSpan(2, 2), declaredSize ?? (ushort)size);
        BitConverter.TryWriteBytes(bytes.AsSpan(4, 4), mask);
        BitConverter.TryWriteBytes(bytes.AsSpan(8, 4), objectFlags);
        var at = 12;
        if (objectType is { } ot)
        {
            ot.TryWriteBytes(bytes.AsSpan(at, 16));
            at += 16;
        }

        if (inheritedObjectType is { } iot)
        {
            iot.TryWriteBytes(bytes.AsSpan(at, 16));
            at += 16;
        }

        sid.CopyTo(bytes, at);
        extra.CopyTo(bytes, at + sid.Length);
        return bytes;
    }

    public static byte[] Allow(byte[] sid, uint mask = 0x001F_01FF, byte flags = 0) => Entry(0x00, flags, mask, sid);
    public static byte[] Deny(byte[] sid, uint mask = 0x0001_0000, byte flags = 0) => Entry(0x01, flags, mask, sid);
    public static byte[] Audit(byte[] sid, uint mask = 0x0001_0000, byte flags = 0xC0) => Entry(0x02, flags, mask, sid);

    // ---- lists -------------------------------------------------------------------------------

    /// <summary>List header plus entries back to back, with optional trailing padding inside the declared size.</summary>
    public static byte[] List(byte revision, byte[][] entries, ushort? declaredSize = null, ushort? declaredCount = null, int padding = 0)
    {
        var body = entries.Sum(e => e.Length);
        var size = 8 + body + padding;
        var bytes = new byte[size];
        bytes[0] = revision;
        BitConverter.TryWriteBytes(bytes.AsSpan(2, 2), declaredSize ?? (ushort)size);
        BitConverter.TryWriteBytes(bytes.AsSpan(4, 2), declaredCount ?? (ushort)entries.Length);
        var at = 8;
        foreach (var e in entries)
        {
            e.CopyTo(bytes, at);
            at += e.Length;
        }

        return bytes;
    }

    public static byte[] List(params byte[][] entries) => List(2, entries);

    // ---- descriptors -------------------------------------------------------------------------

    /// <summary>
    /// Lays the header and the four structures out in order, computes the control word from what
    /// is present, and lets any field be overridden to produce the awkward and malformed variants.
    /// </summary>
    public sealed class DescriptorBuilder
    {
        public byte Revision { get; set; } = 1;
        public byte ResourceManagerByte { get; set; }
        public ushort? ControlOverride { get; set; }
        public ushort ExtraControl { get; set; }
        public byte[]? Owner { get; set; }
        public byte[]? Group { get; set; }
        public byte[]? SystemList { get; set; }
        public byte[]? DiscretionaryList { get; set; }
        public uint? OwnerOffsetOverride { get; set; }
        public uint? GroupOffsetOverride { get; set; }
        public uint? SystemOffsetOverride { get; set; }
        public uint? DiscretionaryOffsetOverride { get; set; }
        public bool SwapListOffsets { get; set; }
        public bool ListsFirst { get; set; }
        public int TrailingBytes { get; set; }

        public byte[] Build()
        {
            var control = ControlOverride ?? (ushort)(0x8000
                | (DiscretionaryList is null ? 0 : 0x0004)
                | (SystemList is null ? 0 : 0x0010));
            control |= ExtraControl;

            var parts = ListsFirst
                ? new[] { ("sacl", SystemList), ("dacl", DiscretionaryList), ("owner", Owner), ("group", Group) }
                : new[] { ("owner", Owner), ("group", Group), ("sacl", SystemList), ("dacl", DiscretionaryList) };

            var offsets = new Dictionary<string, uint>(StringComparer.Ordinal);
            var body = new List<byte>();
            var at = 20u;
            foreach (var (name, bytes) in parts)
            {
                if (bytes is null)
                {
                    offsets[name] = 0;
                    continue;
                }

                offsets[name] = at;
                body.AddRange(bytes);
                at += (uint)bytes.Length;
            }

            var owner = OwnerOffsetOverride ?? offsets["owner"];
            var group = GroupOffsetOverride ?? offsets["group"];
            var sacl = SystemOffsetOverride ?? offsets["sacl"];
            var dacl = DiscretionaryOffsetOverride ?? offsets["dacl"];
            if (SwapListOffsets)
            {
                (sacl, dacl) = (dacl, sacl);
            }

            var result = new byte[20 + body.Count + TrailingBytes];
            result[0] = Revision;
            result[1] = ResourceManagerByte;
            BitConverter.TryWriteBytes(result.AsSpan(2, 2), control);
            BitConverter.TryWriteBytes(result.AsSpan(4, 4), owner);
            BitConverter.TryWriteBytes(result.AsSpan(8, 4), group);
            BitConverter.TryWriteBytes(result.AsSpan(12, 4), sacl);
            BitConverter.TryWriteBytes(result.AsSpan(16, 4), dacl);
            body.CopyTo(result, 20);
            return result;
        }
    }

    /// <summary>Owner = administrators, group = local system, a three-entry mixed discretionary list, no system list.</summary>
    public static DescriptorBuilder Ordinary() => new()
    {
        Owner = Administrators,
        Group = LocalSystem,
        DiscretionaryList = List(
            Allow(Everyone, 0x0012_00A9, flags: 0x03),
            Deny(Guests, 0x0001_0000),
            Allow(Administrators, 0x001F_01FF)),
    };

    // ---- helpers -----------------------------------------------------------------------------

    public static T Unwrap<T>(IdentityResult<T> result) where T : class
    {
        if (result.State != IdentityResultState.Ok)
        {
            throw new InvalidOperationException($"expected Ok, got {result.State}: {result.Reason} @ {result.Position}");
        }

        return result.Value!;
    }

    public static SecurityDescriptor Decode(DescriptorBuilder builder, ObjectKind? kind = null) =>
        Unwrap(DescriptorDecoder.Decode(builder.Build(), kind));

    public static string Hex(IReadOnlyList<byte> bytes) => Convert.ToHexString(bytes.ToArray());

    /// <summary>A deterministic, complete textual rendering of the model, for byte-identical comparison.</summary>
    public static string Render(SecurityDescriptor d)
    {
        var sb = new StringBuilder();
        sb.Append("rev=").Append(d.Revision)
          .Append(" rm=").Append(d.ResourceManagerControl?.ToString(CultureInfo.InvariantCulture) ?? "absent")
          .Append(" rmraw=").Append(d.ResourceManagerControlRaw)
          .Append(" ctl=0x").Append(((ushort)d.Control).ToString("X4", CultureInfo.InvariantCulture))
          .Append(" offsets=").Append(d.Offsets.Owner).Append(',').Append(d.Offsets.Group).Append(',')
          .Append(d.Offsets.SystemList).Append(',').Append(d.Offsets.DiscretionaryList)
          .Append(" owner=").Append(d.Owner?.ToCanonicalString() ?? "absent")
          .Append(" group=").Append(d.Group?.ToCanonicalString() ?? "absent")
          .Append(" kind=").Append(d.MaskKind?.ToString() ?? "none");
        RenderList(sb, "sacl", d.SystemList);
        RenderList(sb, "dacl", d.DiscretionaryList);
        return sb.ToString();
    }

    private static void RenderList(StringBuilder sb, string name, AccessControlList list)
    {
        sb.Append('\n').Append(name).Append(": ");
        switch (list)
        {
            case AccessControlList.NotPresent np:
                sb.Append("not-present ").Append(np.Encoding).Append(" ignored=").Append(np.IgnoredOffset);
                break;
            case AccessControlList.Empty e:
                sb.Append("empty ");
                RenderHeader(sb, e.Header);
                break;
            case AccessControlList.Entries en:
                sb.Append("entries ");
                RenderHeader(sb, en.Header);
                foreach (var entry in en.Items)
                {
                    RenderEntry(sb, entry);
                }

                break;
            default:
                sb.Append("?");
                break;
        }
    }

    private static void RenderHeader(StringBuilder sb, ListHeader h) =>
        sb.Append("@").Append(h.Offset).Append(" rev=").Append(h.Revision).Append(" size=").Append(h.DeclaredSize)
          .Append(" count=").Append(h.DeclaredCount).Append(" surplus=").Append(h.SurplusBytes);

    private static void RenderEntry(StringBuilder sb, AccessControlEntry entry)
    {
        sb.Append("\n  @").Append(entry.Offset).Append(" type=0x").Append(entry.TypeByte.ToString("X2", CultureInfo.InvariantCulture))
          .Append(" flags=0x").Append(entry.FlagsRaw.ToString("X2", CultureInfo.InvariantCulture)).Append(" size=").Append(entry.DeclaredSize);
        switch (entry)
        {
            case AccessControlEntry.Decoded de:
                sb.Append(' ').Append(de.Type).Append(' ').Append(de.Flags)
                  .Append(" mask=0x").Append(de.Mask.ToString("X8", CultureInfo.InvariantCulture))
                  .Append(' ').Append(de.MaskInterpretation);
                if (de.Rights is { } r)
                {
                    sb.Append(" high=[").Append(string.Join(",", r.GenericAndStandardRights)).Append(']')
                      .Append(" low=0x").Append(r.SpecificRaw.ToString("X4", CultureInfo.InvariantCulture))
                      .Append(" specific=").Append(r.SpecificRights is null ? "n/a" : "[" + string.Join(",", r.SpecificRights) + "]")
                      .Append(" unnamed=0x").Append(r.UnnamedBits.ToString("X8", CultureInfo.InvariantCulture));
                }

                if (de.LabelPolicy is { } lp)
                {
                    sb.Append(" label=").Append(lp).Append(" level=").Append(de.IntegrityLevel?.ToString(CultureInfo.InvariantCulture) ?? "absent");
                }

                if (de.ObjectTypes is { } ot)
                {
                    sb.Append(" objflags=").Append(ot.Flags).Append(" ot=").Append(ot.ObjectType?.ToString("D") ?? "absent")
                      .Append(" iot=").Append(ot.InheritedObjectType?.ToString("D") ?? "absent");
                }

                sb.Append(" trailer=").Append(de.Trailer.ToCanonicalString());
                if (de.ApplicationData is { } ad)
                {
                    sb.Append(" appdata@").Append(ad.Offset).Append('=').Append(Hex(ad.Bytes));
                }

                sb.Append(" surplus=").Append(de.SurplusBytes);
                break;
            case AccessControlEntry.Unknown un:
                sb.Append(" unknown body@").Append(un.Body.Offset).Append('=').Append(Hex(un.Body.Bytes));
                break;
            default:
                sb.Append(" ?");
                break;
        }
    }
}
