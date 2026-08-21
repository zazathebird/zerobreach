namespace ZeroBreach.Core.Model;

/// <summary>ATT&amp;CK mapping per spec §5.</summary>
public sealed record MitreRef(string TechniqueId, string TechniqueName, string Tactic)
{
    public override string ToString() => $"{TechniqueId} {TechniqueName} ({Tactic})";
}
