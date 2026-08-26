namespace ZeroBreach.Rules.Yara.Matching;

/// <summary>
/// Aho-Corasick automaton over bytes: one pass over the buffer finds every occurrence of
/// every pattern, which is what makes scanning thousands of literals per rule set viable
/// (the brief's "multi-pattern approach for the literal set"). Immutable after
/// construction; scanning carries no automaton state between calls.
/// </summary>
internal sealed class AhoCorasick
{
    private readonly Dictionary<byte, int>[] _children;
    private readonly int[] _fail;
    private readonly int[][] _outputs;      // per node: pattern ids ending here (own + fail chain)
    private readonly int[] _patternLengths;

    public int PatternCount { get; }

    public AhoCorasick(IReadOnlyList<byte[]> patterns)
    {
        PatternCount = patterns.Count;
        _patternLengths = new int[patterns.Count];

        var children = new List<Dictionary<byte, int>> { new() };
        var ownOutputs = new List<List<int>> { new List<int>() };

        for (int p = 0; p < patterns.Count; p++)
        {
            var pattern = patterns[p];
            _patternLengths[p] = pattern.Length;
            int node = 0;
            foreach (byte b in pattern)
            {
                if (!children[node].TryGetValue(b, out int next))
                {
                    next = children.Count;
                    children.Add(new Dictionary<byte, int>());
                    ownOutputs.Add([]);
                    children[node][b] = next;
                }
                node = next;
            }
            ownOutputs[node].Add(p);
        }

        _children = children.ToArray();
        _fail = new int[_children.Length];
        var mergedOutputs = new List<int>[_children.Length];

        // BFS in sorted-byte order for deterministic construction.
        var queue = new Queue<int>();
        foreach (var (b, child) in Sorted(_children[0]))
        {
            _fail[child] = 0;
            queue.Enqueue(child);
        }
        mergedOutputs[0] = ownOutputs[0];
        while (queue.Count > 0)
        {
            int node = queue.Dequeue();
            var merged = new List<int>(ownOutputs[node]);
            merged.AddRange(mergedOutputs[_fail[node]] ?? ownOutputs[_fail[node]]);
            mergedOutputs[node] = merged;

            foreach (var (b, child) in Sorted(_children[node]))
            {
                int f = _fail[node];
                while (f != 0 && !_children[f].ContainsKey(b))
                {
                    f = _fail[f];
                }
                _fail[child] = _children[f].TryGetValue(b, out int t) && t != child ? t : 0;
                queue.Enqueue(child);
            }
        }
        _outputs = new int[_children.Length][];
        for (int i = 0; i < _children.Length; i++)
        {
            _outputs[i] = (mergedOutputs[i] ?? ownOutputs[i]).ToArray();
        }

        static IEnumerable<(byte, int)> Sorted(Dictionary<byte, int> d) =>
            d.OrderBy(kv => kv.Key).Select(kv => (kv.Key, kv.Value));
    }

    /// <summary>Advances one byte and returns the new state.</summary>
    public int Step(int state, byte b)
    {
        while (true)
        {
            if (_children[state].TryGetValue(b, out int next))
            {
                return next;
            }
            if (state == 0)
            {
                return 0;
            }
            state = _fail[state];
        }
    }

    /// <summary>Pattern ids ending at the current position, given the state after
    /// <see cref="Step"/>. Empty for most positions.</summary>
    public int[] OutputsAt(int state) => _outputs[state];

    public int PatternLength(int patternId) => _patternLengths[patternId];
}
