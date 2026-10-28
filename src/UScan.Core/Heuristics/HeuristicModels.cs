namespace UScan.Core.Heuristics;

/// <summary>One observed property with its weight and a human-readable justification.</summary>
public sealed record HeuristicFeature(string Id, int Weight, string Reason);

public sealed record HeuristicResult(int Score, bool Suspicious, IReadOnlyList<HeuristicFeature> Features)
{
    public static HeuristicResult None { get; } = new(0, false, []);

    public string Explain() => string.Join("; ", Features.Where(f => f.Weight != 0).Select(f => $"{f.Reason} ({f.Weight:+#;-#;0})"));
}

/// <summary>
/// Combines weighted features. Rules that keep false positives down:
/// a single feature is capped below the threshold, so at least two independent findings are
/// needed; trusted signatures subtract weight; the outcome is at most "suspicious", never "infected".
/// </summary>
public static class HeuristicScorer
{
    public const int Threshold = 60;
    public const int MaxSingleFeature = 40;

    public static HeuristicResult Score(IEnumerable<HeuristicFeature> features)
    {
        var list = features.GroupBy(f => f.Id).Select(g => g.First()).ToList();
        var score = list.Sum(f => Math.Clamp(f.Weight, -100, MaxSingleFeature));
        var positives = list.Count(f => f.Weight > 0);
        return new HeuristicResult(score, score >= Threshold && positives >= 2, list);
    }
}

public interface IHeuristicAnalyzer
{
    /// <summary>Returns true if this analyzer understands the content (decided by name and header bytes).</summary>
    bool CanAnalyze(string path, ReadOnlySpan<byte> header);

    HeuristicResult Analyze(string path, Stream content);
}
