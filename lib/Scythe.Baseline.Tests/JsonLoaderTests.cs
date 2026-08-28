namespace Scythe.Baseline.Tests;

/// <summary>The JSON loader: a well-formed table round-trips into the in-memory model, and a
/// malformed one fails loudly with position — it never loads as a smaller or different table.</summary>
public sealed class JsonLoaderTests
{
    /// <summary>A minimal valid single-check table; tests derive broken variants from it so
    /// each test's JSON shows exactly the defect under test.</summary>
    private const string ValidTable = """
        {
          "checks": [
            {
              "id": "PWD-001",
              "title": "Minimum password length",
              "settingKey": "Security\\MinimumPasswordLength",
              "type": "integer",
              "comparison": { "kind": "atLeast", "floor": 14 },
              "severity": "high",
              "remediation": "Set the policy to 14 or more.",
              "absence": "nonCompliant"
            }
          ]
        }
        """;

    private static TableLoadResult AssertFails(string json, string messageFragment)
    {
        var result = CheckTableJsonLoader.Load(json);
        Assert.Equal(EvaluationState.Failed, result.State);
        Assert.Null(result.Table);
        Assert.Contains(result.Errors, e =>
            e.Message.Contains(messageFragment, StringComparison.OrdinalIgnoreCase));
        return result;
    }

    private static CheckTable AssertLoads(string json)
    {
        var result = CheckTableJsonLoader.Load(json);
        Assert.Equal(EvaluationState.Ok, result.State);
        Assert.Empty(result.Errors);
        Assert.NotNull(result.Table);
        return result.Table!;
    }

    // ---- happy path ----

    [Fact]
    public void MinimalValidTable_LoadsIntoTheExpectedModel()
    {
        var table = AssertLoads(ValidTable);
        var check = Assert.Single(table.Checks);

        Assert.Equal("PWD-001", check.Id);
        Assert.Equal("Minimum password length", check.Title);
        Assert.Equal("Security\\MinimumPasswordLength", check.SettingKey);
        Assert.Equal(SettingValueKind.Integer, check.ExpectedKind);
        Assert.Equal(new AtLeastComparison(14), check.Comparison);
        Assert.Equal(Severity.High, check.Severity);
        Assert.Equal("Set the policy to 14 or more.", check.Remediation);
        Assert.Same(AbsenceRule.NonCompliant, check.Absence);
        Assert.Equal(CheckInstancing.SingleInstance, check.Instancing);
        Assert.Null(check.EmptyInstances);
        Assert.Null(check.CaseSensitivity);
        Assert.Null(check.AppliesWhen);
    }

    [Fact]
    public void EveryFieldShape_RoundTrips()
    {
        var table = AssertLoads("""
            {
              "checks": [
                {
                  "id": "STR-001",
                  "title": "Audit log path",
                  "settingKey": "Audit\\LogPath",
                  "type": "string",
                  "comparison": { "kind": "equals", "value": "C:\\Logs" },
                  "severity": "low",
                  "remediation": "Point the log at C:\\Logs.",
                  "absence": { "rule": "default", "value": "C:\\Windows\\Logs" },
                  "caseSensitive": true,
                  "appliesWhen": { "contextKey": "Role", "anyOf": ["Server", "DC"] }
                },
                {
                  "id": "NIC-001",
                  "title": "NetBIOS disabled per interface",
                  "settingKey": "Interface\\NetbiosOptions",
                  "type": "integer",
                  "comparison": { "kind": "oneOf", "values": [2] },
                  "severity": "medium",
                  "remediation": "Disable NetBIOS on every interface.",
                  "absence": "nonCompliant",
                  "instancing": "multi",
                  "emptyInstances": "undetermined"
                },
                {
                  "id": "SMB-001",
                  "title": "SMBv1 not installed",
                  "settingKey": "Features\\Smb1",
                  "type": "boolean",
                  "comparison": { "kind": "notEquals", "value": true },
                  "severity": "critical",
                  "remediation": "Remove the SMBv1 feature.",
                  "absence": "compliant"
                },
                {
                  "id": "TLS-001",
                  "title": "Weak TLS disabled",
                  "settingKey": "Tls\\Protocol",
                  "type": "string",
                  "comparison": { "kind": "noneOf", "values": ["Ssl3", "Tls10"] },
                  "severity": "high",
                  "remediation": "Disable legacy protocols.",
                  "absence": "nonCompliant",
                  "caseSensitive": false
                }
              ]
            }
            """);

        Assert.Equal(new[] { "STR-001", "NIC-001", "SMB-001", "TLS-001" },
            table.Checks.Select(c => c.Id));

        var str = table.Checks[0];
        Assert.Equal(new EqualsComparison(SettingValue.OfString("C:\\Logs")), str.Comparison);
        Assert.Equal(AbsenceRule.MeansDefault(SettingValue.OfString("C:\\Windows\\Logs")), str.Absence);
        Assert.Equal(StringCase.Sensitive, str.CaseSensitivity);
        Assert.NotNull(str.AppliesWhen);
        Assert.Equal("Role", str.AppliesWhen!.ContextKey);
        Assert.Equal(new[] { "Server", "DC" }, str.AppliesWhen.AnyOf);

        var nic = table.Checks[1];
        Assert.Equal(CheckInstancing.MultiInstance, nic.Instancing);
        Assert.Equal(EmptyInstancesRule.EmptyIsUndetermined, nic.EmptyInstances);
        var oneOf = Assert.IsType<OneOfComparison>(nic.Comparison);
        Assert.Equal(new[] { SettingValue.OfInteger(2) }, oneOf.Values);

        var smb = table.Checks[2];
        Assert.Equal(new NotEqualsComparison(SettingValue.OfBoolean(true)), smb.Comparison);
        Assert.Same(AbsenceRule.Compliant, smb.Absence);
        Assert.Equal(Severity.Critical, smb.Severity);

        var tls = table.Checks[3];
        var noneOf = Assert.IsType<NoneOfComparison>(tls.Comparison);
        Assert.Equal(new[] { SettingValue.OfString("Ssl3"), SettingValue.OfString("Tls10") }, noneOf.Values);
        Assert.Equal(StringCase.Insensitive, tls.CaseSensitivity);

        // The loaded table is immediately evaluable.
        var evaluation = BaselineEvaluator.Evaluate(table, BaselineObservations.Empty, MachineContext.Empty);
        Assert.Equal(EvaluationState.Ok, evaluation.State);
    }

    [Fact]
    public void CommentsAreAllowed_TheFileIsEditedByHumans()
    {
        var table = AssertLoads(ValidTable.Replace("\"checks\": [",
            "// reviewed 2026-08\n  \"checks\": ["));
        Assert.Single(table.Checks);
    }

    // ---- malformed JSON fails with position ----

    [Fact]
    public void MalformedJson_FailsWithLineAndPosition()
    {
        var result = AssertFails("{\n  \"checks\": [\n    { \"id\": }\n", "malformed JSON");
        var error = Assert.Single(result.Errors);
        // The defect is on line 3; the report is one-based for the technician.
        Assert.Contains("line 3", error.Message, StringComparison.Ordinal);
        Assert.Contains("position", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TrailingComma_IsMalformed() =>
        AssertFails(ValidTable.Replace("\"absence\": \"nonCompliant\"",
            "\"absence\": \"nonCompliant\","), "malformed JSON");

    // ---- structural defects ----

    [Fact]
    public void RootThatIsNotAnObject_Fails() =>
        AssertFails("[]", "root must be an object");

    [Fact]
    public void MissingChecksArray_Fails() =>
        AssertFails("{}", "'checks' array is missing");

    [Fact]
    public void ChecksThatIsNotAnArray_Fails() =>
        AssertFails("""{ "checks": {} }""", "'checks' array is missing");

    [Fact]
    public void EmptyChecksArray_Fails_NeverLoadsAsATableWithNoChecks()
    {
        // A table with zero checks verifies nothing and its output reads like a clean run;
        // an empty file is an authoring mistake and must fail loudly.
        AssertFails("""{ "checks": [] }""", "'checks' array is empty");
    }

    [Fact]
    public void UnknownRootProperty_Fails() =>
        AssertFails(ValidTable.Replace("\"checks\":", "\"cheks2\": 1, \"checks\":"),
            "unknown property 'cheks2' at root");

    [Fact]
    public void CheckThatIsNotAnObject_Fails() =>
        AssertFails("""{ "checks": [ 42 ] }""", "checks[0]: must be an object");

    // ---- per-check defects, each reported at its position ----

    [Fact]
    public void UnknownCheckProperty_Fails_SoATypoCannotDisableAField()
    {
        // "remediaton" is one typo away from "remediation": the unknown name is reported AND
        // the real field is reported missing, instead of the check silently losing its fix text.
        var result = AssertFails(ValidTable.Replace("\"remediation\"", "\"remediaton\""),
            "unknown property 'remediaton'");
        Assert.Contains(result.Errors, e =>
            e.Message.Contains("required property 'remediation' is missing", StringComparison.Ordinal));
    }

    [Fact]
    public void MissingRequiredField_Fails() =>
        AssertFails(ValidTable.Replace("\"id\": \"PWD-001\",", ""),
            "checks[0]: required property 'id' is missing");

    [Fact]
    public void NonStringId_Fails() =>
        AssertFails(ValidTable.Replace("\"PWD-001\"", "17"), "checks[0].id: must be a string");

    [Fact]
    public void UnknownType_Fails() =>
        AssertFails(ValidTable.Replace("\"integer\"", "\"number\""),
            "'number' is not one of integer, boolean, string");

    [Fact]
    public void UnknownSeverity_Fails() =>
        AssertFails(ValidTable.Replace("\"high\"", "\"urgent\""),
            "'urgent' is not one of low, medium, high, critical");

    // ---- comparison defects ----

    [Fact]
    public void UnknownComparisonKind_Fails() =>
        AssertFails(ValidTable.Replace("\"atLeast\"", "\"greaterOrEqual\""),
            "'greaterOrEqual' is not one of equals, notEquals, atLeast, oneOf, noneOf");

    [Fact]
    public void ComparisonMissingItsKind_Fails() =>
        AssertFails(ValidTable.Replace("\"kind\": \"atLeast\", ", ""),
            "comparison: 'kind' string is missing");

    [Fact]
    public void ComparisonThatIsNotAnObject_Fails() =>
        AssertFails(ValidTable.Replace("""{ "kind": "atLeast", "floor": 14 }""", "\"atLeast 14\""),
            "comparison: must be an object");

    [Fact]
    public void EqualsWithoutAValue_Fails() =>
        AssertFails(ValidTable.Replace("""{ "kind": "atLeast", "floor": 14 }""", """{ "kind": "equals" }"""),
            "'equals' requires 'value'");

    [Fact]
    public void AtLeastWithANonIntegerFloor_Fails() =>
        AssertFails(ValidTable.Replace("\"floor\": 14", "\"floor\": \"14\""),
            "'atLeast' requires an integer 'floor'");

    [Fact]
    public void OneOfWithoutAValuesArray_Fails() =>
        AssertFails(ValidTable.Replace("""{ "kind": "atLeast", "floor": 14 }""", """{ "kind": "oneOf" }"""),
            "'oneOf' requires a 'values' array");

    // ---- values must match the declared type, never coerced ----

    [Fact]
    public void QuotedNumberForAnIntegerCheck_Fails_NoSilentCoercion()
    {
        AssertFails(ValidTable.Replace(
                """{ "kind": "atLeast", "floor": 14 }""",
                """{ "kind": "equals", "value": "14" }"""),
            "expected an integer, got the string \"14\"");
    }

    [Fact]
    public void NumberForABooleanCheck_Fails() =>
        AssertFails(ValidTable
                .Replace("\"integer\"", "\"boolean\"")
                .Replace("""{ "kind": "atLeast", "floor": 14 }""", """{ "kind": "equals", "value": 1 }"""),
            "expected true or false, got a number");

    [Fact]
    public void MistypedValueInsideAValuesArray_FailsNamingTheIndex() =>
        AssertFails(ValidTable.Replace(
                """{ "kind": "atLeast", "floor": 14 }""",
                """{ "kind": "oneOf", "values": [1, true, 3] }"""),
            "comparison.values[1]: expected an integer");

    // ---- absence defects ----

    [Fact]
    public void UnknownAbsenceString_Fails() =>
        AssertFails(ValidTable.Replace("\"nonCompliant\"", "\"fail\""),
            "'fail' is not one of compliant, nonCompliant");

    [Fact]
    public void AbsenceObjectWithoutDefaultRule_Fails() =>
        AssertFails(ValidTable.Replace("\"absence\": \"nonCompliant\"",
                "\"absence\": { \"rule\": \"fallback\", \"value\": 3 }"),
            "object form requires \"rule\": \"default\"");

    [Fact]
    public void AbsenceDefaultWithoutAValue_Fails() =>
        AssertFails(ValidTable.Replace("\"absence\": \"nonCompliant\"",
                "\"absence\": { \"rule\": \"default\" }"),
            "'default' requires 'value'");

    [Fact]
    public void AbsenceDefaultOfTheWrongJsonType_Fails() =>
        AssertFails(ValidTable.Replace("\"absence\": \"nonCompliant\"",
                "\"absence\": { \"rule\": \"default\", \"value\": \"three\" }"),
            "absence.value: expected an integer");

    [Fact]
    public void AbsenceOfANonStringNonObjectType_Fails() =>
        AssertFails(ValidTable.Replace("\"absence\": \"nonCompliant\"", "\"absence\": 3"),
            "absence: must be a string or an object");

    [Fact]
    public void MissingAbsence_Fails() =>
        AssertFails(ValidTable.Replace(",\n      \"absence\": \"nonCompliant\"", ""),
            "required property 'absence' is missing");

    // ---- caseSensitive / instancing / appliesWhen defects ----

    [Fact]
    public void NonBooleanCaseSensitive_Fails() =>
        AssertFails(ValidTable.Replace("\"absence\": \"nonCompliant\"",
                "\"absence\": \"nonCompliant\", \"caseSensitive\": \"true\""),
            "caseSensitive: must be true or false");

    [Fact]
    public void StringCheckWithoutCaseSensitive_FailsAtLoad()
    {
        // Semantic validation runs at load, so this fails here rather than at first use.
        AssertFails(ValidTable
                .Replace("\"integer\"", "\"string\"")
                .Replace("""{ "kind": "atLeast", "floor": 14 }""", """{ "kind": "equals", "value": "x" }"""),
            "must declare case sensitivity");
    }

    [Fact]
    public void UnknownInstancing_Fails() =>
        AssertFails(ValidTable.Replace("\"absence\": \"nonCompliant\"",
                "\"absence\": \"nonCompliant\", \"instancing\": \"per-interface\""),
            "instancing: must be 'single' or 'multi'");

    [Fact]
    public void MultiInstancingWithoutEmptyInstances_FailsAtLoad() =>
        AssertFails(ValidTable.Replace("\"absence\": \"nonCompliant\"",
                "\"absence\": \"nonCompliant\", \"instancing\": \"multi\""),
            "must declare what an empty instance collection means");

    [Fact]
    public void UnknownEmptyInstances_Fails() =>
        AssertFails(ValidTable.Replace("\"absence\": \"nonCompliant\"",
                "\"absence\": \"nonCompliant\", \"instancing\": \"multi\", \"emptyInstances\": \"pass\""),
            "emptyInstances: must be one of compliant, nonCompliant, undetermined");

    [Fact]
    public void AppliesWhenMissingItsParts_Fails() =>
        AssertFails(ValidTable.Replace("\"absence\": \"nonCompliant\"",
                "\"absence\": \"nonCompliant\", \"appliesWhen\": { \"contextKey\": \"Role\" }"),
            "requires 'contextKey' string and 'anyOf' array");

    [Fact]
    public void AppliesWhenWithNonStringEntries_Fails() =>
        AssertFails(ValidTable.Replace("\"absence\": \"nonCompliant\"",
                "\"absence\": \"nonCompliant\", \"appliesWhen\": { \"contextKey\": \"Role\", \"anyOf\": [\"Server\", 3] }"),
            "anyOf: entries must be strings");

    [Fact]
    public void AppliesWhenWithAnUnknownProperty_Fails() =>
        AssertFails(ValidTable.Replace("\"absence\": \"nonCompliant\"",
                "\"absence\": \"nonCompliant\", \"appliesWhen\": { \"contextKey\": \"Role\", \"anyOf\": [\"S\"], \"role\": \"x\" }"),
            "appliesWhen: unknown or mistyped property 'role'");

    // ---- semantic validation applies at load ----

    [Fact]
    public void DuplicateIdsInJson_FailAtLoad()
    {
        var duplicated = ValidTable.Replace("""
            "absence": "nonCompliant"
                }
            """, """
            "absence": "nonCompliant"
                },
                {
                  "id": "PWD-001",
                  "title": "Duplicate",
                  "settingKey": "Other\\Key",
                  "type": "integer",
                  "comparison": { "kind": "atLeast", "floor": 1 },
                  "severity": "low",
                  "remediation": "n/a",
                  "absence": "compliant"
                }
            """);
        var result = AssertFails(duplicated, "duplicate check id 'PWD-001'");
        Assert.Equal("PWD-001", Assert.Single(result.Errors).CheckId);
    }

    [Fact]
    public void EveryBrokenCheck_IsReported_NotJustTheFirst()
    {
        var result = CheckTableJsonLoader.Load("""
            {
              "checks": [
                { "id": "A" },
                { "id": "B", "severity": "urgent" }
              ]
            }
            """);
        Assert.Equal(EvaluationState.Failed, result.State);
        // Both checks contribute errors, each at its own index.
        Assert.Contains(result.Errors, e => e.Message.StartsWith("checks[0]:", StringComparison.Ordinal));
        Assert.Contains(result.Errors, e => e.Message.StartsWith("checks[1]", StringComparison.Ordinal));
    }
}
