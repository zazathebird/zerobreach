namespace ZeroBreach.Baseline;

/// <summary>
/// Validates a check table before anything is evaluated. The table is data, edited by people
/// who are not the author of this library; a defective check must fail loudly here, because a
/// check that cannot be evaluated must never count as compliant — and a check that silently
/// evaluates to something unintended is worse.
/// </summary>
public static class CheckTableValidator
{
    public static IReadOnlyList<CheckTableError> Validate(CheckTable table)
    {
        ArgumentNullException.ThrowIfNull(table);

        var errors = new List<CheckTableError>();
        var seenIds = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < table.Checks.Count; i++)
        {
            var check = table.Checks[i];

            // Errors on a check with a blank id are attributed by table position instead.
            var idForError = string.IsNullOrWhiteSpace(check.Id) ? null : check.Id;
            void Add(string message) => errors.Add(new CheckTableError(idForError, $"checks[{i}]: {message}"));

            if (string.IsNullOrWhiteSpace(check.Id))
                Add("check id is empty");
            else if (!seenIds.Add(check.Id))
                Add($"duplicate check id '{check.Id}'");

            if (string.IsNullOrWhiteSpace(check.Title))
                Add("title is empty");

            if (string.IsNullOrWhiteSpace(check.SettingKey))
                Add("setting key is empty");

            if (string.IsNullOrWhiteSpace(check.Remediation))
                Add("remediation text is empty — a finding without a fix is a puzzle, not a finding");

            if (!Enum.IsDefined(check.ExpectedKind))
                Add($"declared value type {(int)check.ExpectedKind} is outside the permitted set");

            if (!Enum.IsDefined(check.Severity))
                Add($"severity {(int)check.Severity} is outside the permitted set (Low, Medium, High, Critical)");

            ValidateComparison(check, Add);
            ValidateAbsence(check, Add);

            if (check.ExpectedKind == SettingValueKind.String && check.CaseSensitivity is null)
                Add("string check must declare case sensitivity (Sensitive or Insensitive); it is never assumed");
            if (check.CaseSensitivity is { } cs && !Enum.IsDefined(cs))
                Add($"case sensitivity {(int)cs} is outside the permitted set");

            if (!Enum.IsDefined(check.Instancing))
                Add($"instancing {(int)check.Instancing} is outside the permitted set");
            if (check.Instancing == CheckInstancing.MultiInstance)
            {
                if (check.EmptyInstances is null)
                    Add("multi-instance check must declare what an empty instance collection means (EmptyIsCompliant, EmptyIsNonCompliant or EmptyIsUndetermined)");
                else if (!Enum.IsDefined(check.EmptyInstances.Value))
                    Add($"empty-instances rule {(int)check.EmptyInstances.Value} is outside the permitted set");
            }

            if (check.AppliesWhen is { } cond)
            {
                if (string.IsNullOrWhiteSpace(cond.ContextKey))
                    Add("applicability condition has an empty context key");
                if (cond.AnyOf is null || cond.AnyOf.Count == 0)
                    Add("applicability condition has an empty value list — the check would silently never apply");
            }
        }

        return errors;
    }

    private static void ValidateComparison(BaselineCheck check, Action<string> add)
    {
        // Comparison is required-by-construction, but the table is data and `null!` is one
        // typo away in a loader; validate what the type system cannot enforce.
        switch (check.Comparison)
        {
            case null:
                add("comparison is missing");
                break;

            case EqualsComparison e:
                RequireKind(e.Expected, "equals", check, add);
                break;

            case NotEqualsComparison n:
                RequireKind(n.Expected, "not-equals", check, add);
                break;

            case AtLeastComparison:
                if (check.ExpectedKind != SettingValueKind.Integer)
                    add($"at-least is a numeric floor and cannot apply to a {KindName(check.ExpectedKind)} setting");
                break;

            case OneOfComparison o:
                ValidateValueList(o.Values, "one-of", check, add);
                break;

            case NoneOfComparison o:
                // An empty none-of is vacuously always compliant: a check that can never fail
                // is a silently disabled check, which is the failure mode this library rejects.
                ValidateValueList(o.Values, "none-of", check, add);
                break;

            default:
                add($"unknown comparison type {check.Comparison.GetType().Name}");
                break;
        }
    }

    private static void ValidateValueList(
        IReadOnlyList<SettingValue> values, string name, BaselineCheck check, Action<string> add)
    {
        if (values is null || values.Count == 0)
        {
            add($"{name} has an empty value list");
            return;
        }
        foreach (var value in values)
            RequireKind(value, name, check, add);
    }

    private static void ValidateAbsence(BaselineCheck check, Action<string> add)
    {
        switch (check.Absence)
        {
            case null:
                add("absence rule is missing — every check must declare what an unset setting means; there is no global fallback");
                break;

            case AbsenceMeansDefault d:
                if (d.DefaultValue is null)
                    add("absence-means-default has no default value");
                else if (d.DefaultValue.Kind != check.ExpectedKind)
                    add($"absence default is {KindName(d.DefaultValue.Kind)} but the check declares {KindName(check.ExpectedKind)}");
                break;

            case AbsenceIsCompliant:
            case AbsenceIsNonCompliant:
                break;

            default:
                add($"unknown absence rule type {check.Absence.GetType().Name}");
                break;
        }
    }

    private static void RequireKind(SettingValue? value, string where, BaselineCheck check, Action<string> add)
    {
        if (value is null)
            add($"{where} has no expected value");
        else if (value.Kind != check.ExpectedKind)
            add($"{where} expected value is {KindName(value.Kind)} but the check declares {KindName(check.ExpectedKind)}");
    }

    private static string KindName(SettingValueKind kind) => kind switch
    {
        SettingValueKind.Integer => "integer",
        SettingValueKind.Boolean => "boolean",
        SettingValueKind.String => "string",
        _ => $"unknown({(int)kind})",
    };
}
