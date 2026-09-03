using System.Text;

namespace Scythe.Correlation;

/// <summary>
/// A fixed line-oriented rendering of a <see cref="CorrelationOutput"/>, one line per chain,
/// census row, rejected target and unchained finding, '\n'-terminated, no host-dependent
/// formatting. It exists so that determinism can be asserted byte for byte and so that a caller
/// can diff two assemblies; it is not the report — rendering for people is Scythe.Reporting's.
/// </summary>
public static class CanonicalWriter
{
    public static string Write(CorrelationOutput output)
    {
        var sb = new StringBuilder();
        sb.Append("chains=").Append(output.Chains.Count).Append('\n');
        foreach (var chain in output.Chains)
        {
            sb.Append("chain first=").Append(chain.FirstFindingId)
              .Append(" members=").AppendJoin('|', chain.MemberFindingIds)
              .Append(" joins=");
            AppendEntities(sb, chain.JoiningEntities);
            sb.Append('\n');
        }

        sb.Append("unchained=").AppendJoin('|', output.UnchainedFindingIds).Append('\n');

        foreach (var entry in output.Census)
        {
            sb.Append("census ").Append(entry.Entity.Kind).Append(':').Append(entry.Entity.Value)
              .Append(" class=").Append(entry.Class)
              .Append(" refs=").AppendJoin('|', entry.FindingIds).Append('\n');
        }

        foreach (var rejected in output.RejectedTargets)
        {
            sb.Append("rejected ").Append(rejected.FindingId).Append(' ').Append(rejected.Kind)
              .Append(" '").Append(rejected.Text).Append("' ").Append(rejected.Message).Append('\n');
        }

        return sb.ToString();
    }

    private static void AppendEntities(StringBuilder sb, IReadOnlyList<Entity> entities)
    {
        for (var i = 0; i < entities.Count; i++)
        {
            if (i > 0) sb.Append('|');
            sb.Append(entities[i].Kind).Append(':').Append(entities[i].Value);
        }
    }
}
