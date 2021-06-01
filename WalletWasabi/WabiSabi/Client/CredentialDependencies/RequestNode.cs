using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using WalletWasabi.Helpers;

namespace WalletWasabi.WabiSabi.Client.CredentialDependencies
{
	public abstract class RequestNode
	{
		public RequestNode(IEnumerable<long> values, int maxInDegree, int maxOutDegree, int maxZeroOnlyOutDegree)
		{
			Values = Guard.InRange(nameof(values), values, DependencyGraph.CredentialTypes.Count(), DependencyGraph.CredentialTypes.Count()).ToImmutableArray();
			MaxInDegree = maxInDegree;
			MaxOutDegree = maxOutDegree;
			MaxZeroOnlyOutDegree = maxZeroOnlyOutDegree;
		}

		public ImmutableArray<long> Values { get; }

		public int MaxInDegree { get; }

		public int MaxOutDegree { get; }

		public int MaxZeroOnlyOutDegree { get; }

		public long InitialBalance(CredentialType type) => Values[(int)type];
	}
}
