using NBitcoin;
using System.Collections.Immutable;

namespace WalletWasabi.WabiSabi.Models.MultipartyTransaction
{
	// This represents parameters all clients must agree on to produce a valid &
	// standard transaction subject to constraints.
	public record Parameters(FeeRate FeeRate, MoneyRange AllowedInputAmounts, MoneyRange AllowedOutputAmounts, Network Network)
	{
		public static int SharedOverhead = 4*(4 + 4 + 3 + 3) + 1 + 1; // version, locktime, two 3 byte varints are non-witness data, marker and flags are witness data

		public int MaxWeight { get; init; } = 400000; // ensure less than 400000?

		public static ImmutableSortedSet<ScriptType> OnlyP2WPKH = ImmutableSortedSet<ScriptType>.Empty.Add(ScriptType.P2WPKH);

		public ImmutableSortedSet<ScriptType> AllowedInputTypes { get; init; } = OnlyP2WPKH;
		public ImmutableSortedSet<ScriptType> AllowedOutputTypes { get; init; } = OnlyP2WPKH;

		public Transaction CreateTransaction()
			// implied:
			// segwit transaction
			// version = 1
			// nLocktime = 0
			=> Transaction.Create(Network);
	}
}
