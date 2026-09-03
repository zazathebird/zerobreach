namespace Scythe.ShellItems;

public static partial class ShellLinkReader
{
    private const uint EnvironmentBlockSize = 0x314;
    private const uint KnownFolderBlockSize = 0x1C;
    private const uint SpecialFolderBlockSize = 0x10;
    private const uint TrackerBlockSize = 0x60;
    private const uint VistaIdListMinimumSize = 0x0A;

    private static Problem? ParseExtraData(ByteReader file, ref long offset, Accumulator acc, ParseContext ctx, int depth)
    {
        while (true)
        {
            if (!file.TryU32(offset, out var size))
            {
                return Problem.Incomplete(
                    $"truncated at 0x{offset:X}: the extra-data terminal block is missing ({file.Remaining(offset)} bytes remain, 4 needed)");
            }

            if (size < 4)
            {
                // The terminal block: any size below 4 ends the sequence.
                offset += 4;
                return null;
            }

            if (size < 8)
            {
                return Problem.Incomplete(
                    $"extra-data block at 0x{offset:X} has size {size}, too small to hold a signature; the walk cannot advance");
            }

            if (!file.Has(offset, size))
            {
                return Problem.Incomplete(
                    $"extra-data block at 0x{offset:X} declares {size} bytes but only {file.Remaining(offset)} remain");
            }

            if (acc.Extra.Count >= ctx.Budget.MaxMatches)
            {
                return Problem.Incomplete(ctx.MaxMatchesReason("extra-data blocks"));
            }

            if (ctx.DeadlineExpired)
            {
                return Problem.Incomplete(ctx.DeadlineReason($"before the extra-data block at 0x{offset:X}"));
            }

            file.TryU32(offset + 4, out var signature);
            var problem = DecodeBlock(file.Sub(offset, size), offset, size, signature, ctx, depth, out var block);
            if (problem is not null)
            {
                return problem;
            }

            acc.Extra.Add(block!);
            offset += size;
        }
    }

    private static Problem? DecodeBlock(ByteReader block, long offset, uint size, uint signature, ParseContext ctx, int depth, out ExtraDataBlock? result)
    {
        var raw = block.Span.ToArray();
        result = null;

        switch (signature)
        {
            case ExtraDataSignature.EnvironmentVariable:
            case ExtraDataSignature.IconEnvironment:
                if (size != EnvironmentBlockSize)
                {
                    result = SizeMismatch(offset, size, signature, EnvironmentBlockSize, raw);
                    return null;
                }

                result = new EnvironmentStringsBlock(
                    size,
                    signature,
                    raw,
                    FixedCodePageField(block, 8, 260),
                    FixedUtf16Field(block, 268, 520));
                return null;

            case ExtraDataSignature.KnownFolder:
                if (size != KnownFolderBlockSize)
                {
                    result = SizeMismatch(offset, size, signature, KnownFolderBlockSize, raw);
                    return null;
                }

                block.TryGuid(8, out var folderId);
                block.TryU32(24, out var folderOffset);
                result = new KnownFolderBlock(size, signature, raw, folderId, folderOffset);
                return null;

            case ExtraDataSignature.SpecialFolder:
                if (size != SpecialFolderBlockSize)
                {
                    result = SizeMismatch(offset, size, signature, SpecialFolderBlockSize, raw);
                    return null;
                }

                block.TryU32(8, out var specialId);
                block.TryU32(12, out var specialOffset);
                result = new SpecialFolderBlock(size, signature, raw, specialId, specialOffset);
                return null;

            case ExtraDataSignature.Tracker:
                if (size != TrackerBlockSize)
                {
                    result = SizeMismatch(offset, size, signature, TrackerBlockSize, raw);
                    return null;
                }

                block.TryU32(8, out var length);
                block.TryU32(12, out var version);
                block.TryGuid(32, out var droidVolume);
                block.TryGuid(48, out var droidFile);
                block.TryGuid(64, out var birthVolume);
                block.TryGuid(80, out var birthFile);
                result = new TrackerBlock(size, signature, raw, length, version, FixedCodePageField(block, 16, 16), droidVolume, droidFile, birthVolume, birthFile);
                return null;

            case ExtraDataSignature.VistaAndAboveIdList:
                if (depth + 1 > ctx.Budget.MaxNestingDepth)
                {
                    return Problem.Incomplete(ctx.MaxNestingDepthReason(depth + 1, "the item-ID list inside the Vista-and-above block"));
                }

                if (size < VistaIdListMinimumSize)
                {
                    result = SizeMismatch(offset, size, signature, VistaIdListMinimumSize, raw);
                    return null;
                }

                var problem = ParseItems(block.Sub(8, size - 8), offset + 8, ctx, out var list);
                if (problem is { State: LinkResultState.Incomplete })
                {
                    return problem;
                }

                result = problem is null
                    ? new VistaIdListBlock(size, signature, raw, list!)
                    : new RawExtraDataBlock(size, signature, raw, $"block at 0x{offset:X}: the nested item-ID list is malformed ({problem.Message}); kept raw");
                return null;

            default:
                result = new RawExtraDataBlock(size, signature, raw, null);
                return null;
        }
    }

    private static RawExtraDataBlock SizeMismatch(long offset, uint size, uint signature, uint expected, byte[] raw) =>
        new(size, signature, raw, $"block at 0x{offset:X}: signature 0x{signature:X8} declares {size} bytes, its layout needs 0x{expected:X}; kept raw");

    /// <summary>A fixed-width code-page field, null-terminated inside its extent (or filling it).</summary>
    private static LinkString FixedCodePageField(ByteReader block, int offset, int length)
    {
        var field = block.Sub(offset, length);
        var nul = field.FindNullByte(0);
        return LinkString.FromCodePage(nul < 0 ? field.Span : field.Span[..nul]);
    }

    private static LinkString FixedUtf16Field(ByteReader block, int offset, int length)
    {
        var field = block.Sub(offset, length);
        var nul = field.FindNullChar(0);
        return LinkString.FromUtf16(nul < 0 ? field.Span : field.Span[..nul]);
    }
}
