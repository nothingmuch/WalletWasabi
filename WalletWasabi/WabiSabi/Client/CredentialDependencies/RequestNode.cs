using System.Collections.Generic;
using System.Collections.Immutable;
using WalletWasabi.Helpers;

namespace WalletWasabi.WabiSabi.Client.CredentialDependencies
{
	// make private inner class of Graph?
	public class RequestNode
	{
		public RequestNode(IEnumerable<long> values, int inDegree, int outDegree, int zeroOutDegree)
		{
			Values = Guard.InRange(nameof(values), values, DependencyGraph.K, DependencyGraph.K).ToImmutableArray();
			MaxInDegree = inDegree;
			MaxOutDegree = outDegree;
			MaxZeroOutDegree = zeroOutDegree;
		}

		public ImmutableArray<long> Values { get; }

		public long InitialBalance(CredentialType type) => Values[(int)type];

		public int MaxInDegree { get; }

		public int MaxOutDegree { get; }

		public int MaxZeroOutDegree { get; }
	}
}
