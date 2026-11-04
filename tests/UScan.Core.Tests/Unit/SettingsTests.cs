using UScan.Core.App;

namespace UScan.Core.Tests.Unit;

public class SettingsTests
{
    [Fact]
    public void Parallelism_is_automatic_by_default_and_a_fixed_value_wins()
    {
        var auto = new UScanSettings();
        Assert.Equal(0, auto.Parallelism);
        Assert.Null(auto.Validate());
        Assert.InRange(auto.EffectiveParallelism, 2, 8);
        Assert.True(auto.LowPriorityScan);

        var fixedValue = new UScanSettings { Parallelism = 12 };
        Assert.Equal(12, fixedValue.EffectiveParallelism);
        Assert.NotNull(new UScanSettings { Parallelism = -1 }.Validate());
        Assert.NotNull(new UScanSettings { Parallelism = 17 }.Validate());
    }
}
