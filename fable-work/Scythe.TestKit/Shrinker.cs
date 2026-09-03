namespace Scythe.TestKit;

/// <summary>
/// Deterministic reduction of a failing input (reference/17.3_property_harness.md): halve the
/// buffer while the failure reproduces, then drop bytes from the tail while it reproduces, then
/// zero individual bytes, keeping each zeroing that still reproduces. Each phase stops at the
/// first reduction that stops reproducing. No randomness, so the same input always reduces to
/// the same counterexample.
/// </summary>
public static class Shrinker
{
    public sealed record Result(byte[] Minimal, int Steps, int Evaluations, bool Capped);

    /// <param name="failing">An input already known to fail.</param>
    /// <param name="stillFails">Must be a pure function of its input.</param>
    /// <param name="maxEvaluations">Ceiling on calls to <paramref name="stillFails"/>; when hit, the result is marked capped.</param>
    public static Result Shrink(byte[] failing, Func<byte[], bool> stillFails, int maxEvaluations)
    {
        ArgumentNullException.ThrowIfNull(failing);
        ArgumentNullException.ThrowIfNull(stillFails);
        byte[] current = (byte[])failing.Clone();
        int steps = 0;
        int evaluations = 0;

        bool Try(byte[] candidate)
        {
            evaluations++;
            if (!stillFails(candidate))
            {
                return false;
            }

            current = candidate;
            steps++;
            return true;
        }

        while (current.Length > 0 && evaluations < maxEvaluations)
        {
            if (!Try(current.AsSpan(0, current.Length / 2).ToArray()))
            {
                break;
            }
        }

        while (current.Length > 0 && evaluations < maxEvaluations)
        {
            if (!Try(current.AsSpan(0, current.Length - 1).ToArray()))
            {
                break;
            }
        }

        for (int i = 0; i < current.Length && evaluations < maxEvaluations; i++)
        {
            if (current[i] == 0)
            {
                continue;
            }

            var candidate = (byte[])current.Clone();
            candidate[i] = 0;
            Try(candidate);
        }

        return new Result(current, steps, evaluations, evaluations >= maxEvaluations);
    }
}
