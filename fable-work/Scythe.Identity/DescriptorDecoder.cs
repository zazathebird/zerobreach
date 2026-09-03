using System.Diagnostics;

namespace Scythe.Identity;

/// <summary>
/// Decodes a self-relative security descriptor (reference/11.3 §11.3) into a
/// <see cref="SecurityDescriptor"/>: owner, group, and the two lists as three-way sum types.
/// </summary>
/// <remarks>
/// Result states: <c>Failed</c> for a structure that lies — an offset outside the buffer or
/// inside the header, two structures claiming the same bytes, a list or entry size that cannot
/// hold what it declares, an entry size that would not advance the walk. <c>Incomplete</c> for a
/// structure read cleanly but not fully understood — an unknown entry type (kept raw, walk
/// continued), an unrecognised revision, a budget trip. The partial descriptor is carried on
/// <c>Incomplete</c> where one exists, and is never promoted to <c>Ok</c>.
/// </remarks>
public static class DescriptorDecoder
{
    /// <summary>The header is twenty bytes: two bytes, a control word, four offsets.</summary>
    public const int HeaderLength = 20;

    /// <summary>The only descriptor revision whose layout this library knows.</summary>
    public const byte RecognisedRevision = 1;

    public const int ListHeaderLength = 8;

    public const int EntryHeaderLength = 4;

    /// <summary>
    /// Decodes <paramref name="bytes"/> as a descriptor starting at offset zero. The buffer may
    /// extend past the descriptor's structures; every offset is validated against the buffer.
    /// </summary>
    /// <param name="kind">The object the descriptor is attached to, which gives the low sixteen mask bits their names. Null decodes only the generic and standard bits and reports the rest raw.</param>
    public static IdentityResult<SecurityDescriptor> Decode(ReadOnlySpan<byte> bytes, ObjectKind? kind = null, ScanBudget? budget = null)
    {
        budget ??= ScanBudget.Default;
        if (bytes.Length > budget.MaxInputBytes)
        {
            return IdentityResult<SecurityDescriptor>.Incomplete(
                null,
                $"input is {bytes.Length} bytes; budget allows {budget.MaxInputBytes}");
        }

        if (bytes.Length < HeaderLength)
        {
            return IdentityResult<SecurityDescriptor>.Failed(
                $"descriptor header needs {HeaderLength} bytes, buffer has {bytes.Length}",
                0);
        }

        var revision = bytes[0];
        if (revision != RecognisedRevision)
        {
            return IdentityResult<SecurityDescriptor>.Incomplete(
                null,
                $"unrecognised descriptor revision {revision}; only revision {RecognisedRevision} has a known layout");
        }

        var resourceManagerRaw = bytes[1];
        ByteReader.TryU16(bytes, 2, out var controlRaw);
        var control = (DescriptorControl)controlRaw;
        if ((control & DescriptorControl.SelfRelative) == 0)
        {
            // The absolute form stores pointers, which cannot mean anything in a file. Rather than
            // attempt a layout that cannot be valid on disk, name the bit.
            return IdentityResult<SecurityDescriptor>.Failed(
                "control bit 0x8000 (self-relative) is clear; only the self-relative form can be stored",
                2);
        }

        ByteReader.TryU32(bytes, 4, out var ownerOffset);
        ByteReader.TryU32(bytes, 8, out var groupOffset);
        // §11.3: the system list's offset precedes the discretionary list's. Not the other way.
        ByteReader.TryU32(bytes, 12, out var systemOffset);
        ByteReader.TryU32(bytes, 16, out var discretionaryOffset);
        var offsets = new DescriptorOffsets(ownerOffset, groupOffset, systemOffset, discretionaryOffset);

        var walk = new Walk(budget, kind);

        SecurityIdentifier? owner = null;
        if (ownerOffset != 0)
        {
            var result = walk.ReadIdentifier(bytes, ownerOffset, "owner identifier", out owner);
            if (result is not null)
            {
                return result;
            }
        }

        SecurityIdentifier? group = null;
        if (groupOffset != 0)
        {
            var result = walk.ReadIdentifier(bytes, groupOffset, "group identifier", out group);
            if (result is not null)
            {
                return result;
            }
        }

        var systemResult = walk.ReadList(
            bytes, "system list", systemOffset, (control & DescriptorControl.SystemListPresent) != 0, out var systemList);
        if (systemResult is not null)
        {
            return systemResult;
        }

        var discretionaryResult = walk.ReadList(
            bytes, "discretionary list", discretionaryOffset, (control & DescriptorControl.DiscretionaryListPresent) != 0, out var discretionaryList);
        if (discretionaryResult is not null)
        {
            return discretionaryResult;
        }

        var resourceManagerValid = (control & DescriptorControl.ResourceManagerControlValid) != 0;
        var descriptor = new SecurityDescriptor(
            revision,
            resourceManagerValid ? resourceManagerRaw : null,
            resourceManagerRaw,
            control,
            offsets,
            owner,
            group,
            systemList!,
            discretionaryList!,
            kind);

        return walk.Reasons.Count == 0
            ? IdentityResult<SecurityDescriptor>.Ok(descriptor)
            : IdentityResult<SecurityDescriptor>.Incomplete(descriptor, string.Join("; ", walk.Reasons));
    }

    /// <summary>
    /// State for one decode: the budget, the byte ranges already claimed by a structure (hazard 2 —
    /// two offsets naming the same bytes is a structure pointing at itself), the entry tally
    /// against <see cref="ScanBudget.MaxMatches"/>, and the reasons that make the result Incomplete.
    /// </summary>
    private sealed class Walk
    {
        private readonly ScanBudget _budget;
        private readonly ObjectKind? _kind;
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private readonly List<(long Start, long End, string Name)> _claimed = new();
        private int _entriesCollected;

        public Walk(ScanBudget budget, ObjectKind? kind)
        {
            _budget = budget;
            _kind = kind;
        }

        public List<string> Reasons { get; } = new();

        /// <summary>Returns a terminal result on failure; null when the read succeeded (possibly adding a reason).</summary>
        public IdentityResult<SecurityDescriptor>? ReadIdentifier(ReadOnlySpan<byte> bytes, uint offset, string name, out SecurityIdentifier? identifier)
        {
            identifier = null;
            var bad = CheckOffset(bytes, offset, name);
            if (bad is not null)
            {
                return bad;
            }

            var decoded = IdentifierDecoder.DecodeUnbudgeted(bytes[(int)offset..]);
            if (decoded.State == IdentityResultState.Failed)
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{name} at 0x{offset:X}: {decoded.Reason}",
                    offset + (decoded.Position ?? 0));
            }

            identifier = decoded.Value!;
            var claim = Claim(offset, identifier.BinaryLength, name);
            if (claim is not null)
            {
                return claim;
            }

            if (decoded.State == IdentityResultState.Incomplete)
            {
                Reasons.Add($"{name} at 0x{offset:X}: {decoded.Reason}");
            }

            return null;
        }

        public IdentityResult<SecurityDescriptor>? ReadList(ReadOnlySpan<byte> bytes, string name, uint offset, bool presentBit, out AccessControlList? list)
        {
            list = null;
            if (!presentBit)
            {
                // The offset is not followed when the bit is clear — the operating system does not
                // either — but it is kept, because a nonzero offset under a clear bit is a fact
                // about the producer that a caller reconciling against a baseline may want.
                list = new AccessControlList.NotPresent(AbsenceEncoding.ControlBitClear, offset);
                return null;
            }

            if (offset == 0)
            {
                list = new AccessControlList.NotPresent(AbsenceEncoding.ControlBitSetOffsetZero, 0);
                return null;
            }

            var bad = CheckOffset(bytes, offset, name);
            if (bad is not null)
            {
                return bad;
            }

            var at = (int)offset;
            if (!ByteReader.Fits(bytes, at, ListHeaderLength))
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{name} at 0x{offset:X}: header needs {ListHeaderLength} bytes, only {bytes.Length - at} remain",
                    offset);
            }

            // Claim the header before trusting anything in it: a list offset landing inside another
            // structure is reported as the overlap it is, not as whatever those bytes say a size is.
            var headerClaim = Claim(offset, ListHeaderLength, name);
            if (headerClaim is not null)
            {
                return headerClaim;
            }

            var revision = bytes[at];
            var reserved1 = bytes[at + 1];
            ByteReader.TryU16(bytes, at + 2, out var declaredSize);
            ByteReader.TryU16(bytes, at + 4, out var declaredCount);
            ByteReader.TryU16(bytes, at + 6, out var reserved2);

            if (declaredSize < ListHeaderLength)
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{name} at 0x{offset:X}: declared size {declaredSize} is smaller than its own {ListHeaderLength}-byte header",
                    offset + 2);
            }

            if (!ByteReader.Fits(bytes, at, declaredSize))
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{name} at 0x{offset:X}: declared size {declaredSize} runs past the end of the descriptor ({bytes.Length} bytes)",
                    offset + 2);
            }

            var claim = Claim(offset + ListHeaderLength, declaredSize - ListHeaderLength, name);
            if (claim is not null)
            {
                return claim;
            }

            if (revision is not (2 or 4))
            {
                // Entry layout is defined for these two only. Returning a list decoded under an
                // assumed layout would be an answer to a question nobody asked.
                return IdentityResult<SecurityDescriptor>.Incomplete(
                    null,
                    $"{name} at 0x{offset:X}: unrecognised list revision {revision}; only revisions 2 and 4 have a known layout");
            }

            var end = at + declaredSize;
            var cursor = at + ListHeaderLength;
            var entries = new List<AccessControlEntry>(Math.Min((int)declaredCount, 64));
            var stoppedEarly = false;

            for (var index = 0; index < declaredCount; index++)
            {
                if (_clock.Elapsed >= _budget.Deadline)
                {
                    Reasons.Add($"{name}: deadline of {_budget.Deadline} reached after {entries.Count} of {declaredCount} entries");
                    stoppedEarly = true;
                    break;
                }

                if (_entriesCollected >= _budget.MaxMatches)
                {
                    Reasons.Add($"{name}: stopped after {entries.Count} of {declaredCount} entries; budget allows {_budget.MaxMatches} entries per descriptor");
                    stoppedEarly = true;
                    break;
                }

                var entryResult = ReadEntry(bytes, name, revision, index, cursor, end, out var entry, out var next);
                if (entryResult is not null)
                {
                    return entryResult;
                }

                entries.Add(entry!);
                _entriesCollected++;
                cursor = next;
            }

            // Surplus between the last entry and the declared end is skipped, never read as an entry.
            var header = new ListHeader(at, revision, reserved1, declaredSize, declaredCount, reserved2, stoppedEarly ? 0 : end - cursor);
            list = declaredCount == 0
                ? new AccessControlList.Empty(header)
                : new AccessControlList.Entries(header, entries);
            return null;
        }

        private IdentityResult<SecurityDescriptor>? ReadEntry(
            ReadOnlySpan<byte> bytes, string listName, byte listRevision, int index, int cursor, int end,
            out AccessControlEntry? entry, out int next)
        {
            entry = null;
            next = cursor;
            var where = $"{listName} entry {index} at 0x{cursor:X}";

            if (end - cursor < EntryHeaderLength)
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{where}: header needs {EntryHeaderLength} bytes, only {end - cursor} remain before the list's declared end",
                    cursor);
            }

            var typeByte = bytes[cursor];
            var flagsRaw = bytes[cursor + 1];
            ByteReader.TryU16(bytes, cursor + 2, out var size);

            if (size == 0)
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{where}: declared size 0 would not advance the walk",
                    cursor + 2);
            }

            if (size % 4 != 0)
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{where}: declared size {size} is not a multiple of 4",
                    cursor + 2);
            }

            if (size < EntryHeaderLength)
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{where}: declared size {size} is smaller than its own {EntryHeaderLength}-byte header",
                    cursor + 2);
            }

            if (size > end - cursor)
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{where}: declared size {size} runs past the list's declared end at 0x{end:X}",
                    cursor + 2);
            }

            next = cursor + size;
            if (next <= cursor)
            {
                // Unreachable with an unsigned size that passed the checks above; kept so that a
                // future change to the arithmetic cannot turn this walk into a loop.
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{where}: walk would step backwards or stand still",
                    cursor + 2);
            }

            var entryEnd = next;

            if (!Enum.IsDefined(typeof(EntryType), typeByte))
            {
                var body = bytes[(cursor + EntryHeaderLength)..entryEnd].ToArray();
                entry = new AccessControlEntry.Unknown(cursor, typeByte, flagsRaw, size, new RawBytes(cursor + EntryHeaderLength, body));
                Reasons.Add($"{listName} entry {index}: unknown entry type 0x{typeByte:X2}, kept raw");
                return null;
            }

            var type = (EntryType)typeByte;
            var isObjectForm = IsObjectForm(type);
            if (isObjectForm && listRevision != 4)
            {
                // §11.3: revision 4 "when object entries are present". A revision-2 list holding
                // one is the list header and its entries disagreeing about what the list is.
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{where}: object-form entry type 0x{typeByte:X2} in a revision-{listRevision} list; object entries require list revision 4",
                    cursor);
            }

            if (size < EntryHeaderLength + 4)
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{where}: declared size {size} has no room for the access mask",
                    cursor + 2);
            }

            ByteReader.TryU32(bytes, cursor + 4, out var mask);
            var bodyCursor = cursor + 8;

            ObjectTypeIdentifiers? objectTypes = null;
            if (isObjectForm)
            {
                if (!ByteReader.TryU32(bytes, bodyCursor, out var objectFlagsRaw) || bodyCursor + 4 > entryEnd)
                {
                    return IdentityResult<SecurityDescriptor>.Failed(
                        $"{where}: declared size {size} has no room for the object flags",
                        cursor + 2);
                }

                bodyCursor += 4;
                var objectFlags = (ObjectTypeFlags)objectFlagsRaw;
                Guid? objectType = null;
                Guid? inheritedObjectType = null;

                // Each identifier is present only when its own bit says so. Reading one whose bit is
                // clear would consume sixteen bytes of the trailer and shift everything after it.
                if ((objectFlags & ObjectTypeFlags.ObjectTypePresent) != 0)
                {
                    if (bodyCursor + 16 > entryEnd || !ByteReader.TryGuid(bytes, bodyCursor, out var guid))
                    {
                        return IdentityResult<SecurityDescriptor>.Failed(
                            $"{where}: object type identifier runs past the entry's declared end at 0x{entryEnd:X}",
                            bodyCursor);
                    }

                    objectType = guid;
                    bodyCursor += 16;
                }

                if ((objectFlags & ObjectTypeFlags.InheritedObjectTypePresent) != 0)
                {
                    if (bodyCursor + 16 > entryEnd || !ByteReader.TryGuid(bytes, bodyCursor, out var guid))
                    {
                        return IdentityResult<SecurityDescriptor>.Failed(
                            $"{where}: inherited object type identifier runs past the entry's declared end at 0x{entryEnd:X}",
                            bodyCursor);
                    }

                    inheritedObjectType = guid;
                    bodyCursor += 16;
                }

                objectTypes = new ObjectTypeIdentifiers(objectFlags, objectType, inheritedObjectType);
            }

            // The trailer is bounded by the entry's own declared end, so it cannot read into the
            // next entry however its count lies.
            var trailerResult = IdentifierDecoder.DecodeUnbudgeted(bytes[bodyCursor..entryEnd]);
            if (trailerResult.State == IdentityResultState.Failed)
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{where}: trailer identifier at 0x{bodyCursor:X} runs past the entry's declared end at 0x{entryEnd:X} ({trailerResult.Reason})",
                    bodyCursor + (trailerResult.Position ?? 0));
            }

            var trailer = trailerResult.Value!;
            if (trailerResult.State == IdentityResultState.Incomplete)
            {
                Reasons.Add($"{listName} entry {index}: trailer identifier: {trailerResult.Reason}");
            }

            bodyCursor += trailer.BinaryLength;
            var remaining = entryEnd - bodyCursor;

            RawBytes? applicationData = null;
            var surplus = 0;
            if (CarriesApplicationData(type))
            {
                applicationData = new RawBytes(bodyCursor, bytes[bodyCursor..entryEnd].ToArray());
            }
            else
            {
                surplus = remaining;
            }

            var interpretation = InterpretationOf(type);
            DecodedAccessMask? rights = null;
            LabelPolicy? labelPolicy = null;
            uint? integrityLevel = null;
            switch (interpretation)
            {
                case MaskInterpretation.AccessRights:
                    rights = AccessMaskDecoder.Decode(mask, _kind);
                    break;
                case MaskInterpretation.MandatoryLabelPolicy:
                    // Policy bits, not rights; the ordinary mask decoder must not run over these.
                    labelPolicy = (LabelPolicy)mask;
                    integrityLevel = trailer.RelativeIdentifier;
                    break;
                default:
                    break;
            }

            entry = new AccessControlEntry.Decoded(
                cursor, typeByte, flagsRaw, size,
                type, (EntryFlags)flagsRaw,
                mask, interpretation, rights, labelPolicy, integrityLevel,
                objectTypes, trailer, applicationData, surplus);
            return null;
        }

        private IdentityResult<SecurityDescriptor>? CheckOffset(ReadOnlySpan<byte> bytes, uint offset, string name)
        {
            if (offset < HeaderLength)
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{name} offset 0x{offset:X} points inside the {HeaderLength}-byte descriptor header",
                    offset);
            }

            if (offset >= bytes.Length)
            {
                return IdentityResult<SecurityDescriptor>.Failed(
                    $"{name} offset 0x{offset:X} points outside the descriptor ({bytes.Length} bytes)",
                    offset);
            }

            return null;
        }

        private IdentityResult<SecurityDescriptor>? Claim(long start, long length, string name)
        {
            var end = start + length;
            foreach (var (otherStart, otherEnd, otherName) in _claimed)
            {
                if (start < otherEnd && otherStart < end)
                {
                    return IdentityResult<SecurityDescriptor>.Failed(
                        $"{name} at 0x{start:X}–0x{end:X} overlaps {otherName} at 0x{otherStart:X}–0x{otherEnd:X}",
                        start);
                }
            }

            _claimed.Add((start, end, name));
            return null;
        }

        private static bool IsObjectForm(EntryType type) => type is
            EntryType.AccessAllowedObject or EntryType.AccessDeniedObject or EntryType.SystemAuditObject
            or EntryType.AccessAllowedCallbackObject or EntryType.AccessDeniedCallbackObject
            or EntryType.SystemAuditCallbackObject;

        // Callback forms per §11.3; resource attribute and access filter carry attribute and
        // condition data after the trailer in the same position. All kept raw, decoded as nothing.
        private static bool CarriesApplicationData(EntryType type) => type is
            EntryType.AccessAllowedCallback or EntryType.AccessDeniedCallback
            or EntryType.AccessAllowedCallbackObject or EntryType.AccessDeniedCallbackObject
            or EntryType.SystemAuditCallback or EntryType.SystemAuditCallbackObject
            or EntryType.ResourceAttribute or EntryType.AccessFilter;

        private static MaskInterpretation InterpretationOf(EntryType type) => type switch
        {
            EntryType.MandatoryLabel => MaskInterpretation.MandatoryLabelPolicy,
            // §11.3 tables these four types but gives their mask no semantics. Raw, not guessed.
            EntryType.ResourceAttribute or EntryType.ScopedPolicyIdentifier
                or EntryType.ProcessTrustLabel or EntryType.AccessFilter => MaskInterpretation.NotInterpreted,
            _ => MaskInterpretation.AccessRights,
        };
    }
}
