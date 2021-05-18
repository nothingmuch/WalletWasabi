using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;

namespace WalletWasabi.WabiSabi.Client.CredentialDependencies
{
	public record CredentialEdgeSet
	{
		public CredentialType CredentialType { get; init; }
		public ImmutableDictionary<RequestNode, ImmutableHashSet<CredentialDependency>> Predecessors { get; init; } = ImmutableDictionary.Create<RequestNode, ImmutableHashSet<CredentialDependency>>();
		public ImmutableDictionary<RequestNode, ImmutableHashSet<CredentialDependency>> Successors { get; init; } = ImmutableDictionary.Create<RequestNode, ImmutableHashSet<CredentialDependency>>();
		public ImmutableDictionary<RequestNode, long> EdgeBalances { get; init; } = ImmutableDictionary.Create<RequestNode, long>();

		public long Balance(RequestNode node) => node.InitialBalance(CredentialType) + EdgeBalances[node];

		public ImmutableHashSet<CredentialDependency> InEdges(RequestNode node) => Predecessors[node];

		public ImmutableHashSet<CredentialDependency> OutEdges(RequestNode node) => Successors[node];

		public int InDegree(RequestNode node) => InEdges(node).Count;

		// TODO rename, it's possibly non zero, or "real"
		public int NonZeroOutDegree(RequestNode node) => OutEdges(node).Where(x => x.Value != 0).Count();

		public int ZeroOutDegree(RequestNode node) => OutEdges(node).Where(x => x.Value == 0).Count();

		public int RemainingInDegree(RequestNode node) => node.MaxInDegree - InDegree(node);

		public int RemainingNonZeroOutDegree(RequestNode node) => node.MaxOutDegree - NonZeroOutDegree(node);

		public int RemainingZeroOutDegree(RequestNode node) => node.MaxZeroOutDegree - ZeroOutDegree(node);

		public int AvailableZeroOutDegree(RequestNode node) => RemainingZeroOutDegree(node) + ( RemainingNonZeroOutDegree(node) - ( Balance(node) > 0 ? 1 : 0 ) );

		public CredentialEdgeSet AddEdge(RequestNode from, RequestNode to, ulong value)
		{
			var edge = new CredentialDependency(from, to, CredentialType, value);

			var predecessors = InEdges(edge.To);
			var successors = OutEdges(edge.From);

			// Maintain degree invariant (subset of K-regular graph, sort of)
			if (RemainingInDegree(edge.To) == 0)
			{
				throw new InvalidOperationException("Can't add more than k in edges per node");
			}

			if (value > 0)
			{
				if (RemainingNonZeroOutDegree(edge.From) == 0)
				{
					throw new InvalidOperationException("Can't add more than k non-zero out edges per node");
				}
			}
			else
			{
				// For reissuance we can utilize all out edges.
				// For input nodes we may need one slot unutilized for the
				// remaining amount
				if (AvailableZeroOutDegree(edge.From) == 0)
				{
					throw new InvalidOperationException("Can't add more than 2k zero/non-zero out edge per node");
				}
			}

			// Maintain balance sum invariant (initial balance and edge values cancel out)
			if (RemainingInDegree(edge.To) == 1)
			{
				// This is the final in edge for the node edge.To
				if (Balance(edge.To) + (long)edge.Value < 0)
				{
					throw new InvalidOperationException("Can't add final in edge without discharging negative value");
				}

				// If it's the final edge overall for that node, the final balance must be 0
				if (RemainingNonZeroOutDegree(edge.To) == 0 && Balance(edge.To) + (long)edge.Value != 0)
				{
					throw new InvalidOperationException("Can't add final in edge without discharging negative value completely");
				}
			}

			if (value > 0)
			{
				if (RemainingNonZeroOutDegree(edge.From) == 1)
				{
					// This is the final out edge for the node edge.From
					if (Balance(edge.From) - (long)edge.Value > 0)
					{
						throw new InvalidOperationException($"Can't add final out edge without discharging positive value (edge value {edge.Value} but node balance is {Balance(edge.From)})");
					}

					// If it's the final edge overall for that node, the final balance must be 0
					if (RemainingInDegree(edge.From) == 0 && Balance(edge.From) - (long)edge.Value != 0)
					{
						throw new InvalidOperationException("Can't add final in edge without discharging negative value completely");
					}
				}
			}

			return this with
			{
				Predecessors = Predecessors.SetItem(edge.To, predecessors.Add(edge)),
				Successors = Successors.SetItem(edge.From, successors.Add(edge)),
				EdgeBalances = EdgeBalances.SetItems(
					new KeyValuePair<RequestNode, long>[]
					{
						new (edge.From, EdgeBalances[edge.From] - (long)edge.Value),
						new (edge.To,   EdgeBalances[edge.To]   + (long)edge.Value),
					}),
			};
		}

		// Find the largest negative or positive balance node for the given
		// credential type, and one or more smaller nodes with a combined total
		// magnitude exceeding that of the largest magnitude node when possible.
		public (RequestNode largestMagnitudeNode, IEnumerable<RequestNode> smallMagnitudeNodes, bool fanIn) MatchNodesToDischarge(IEnumerable<RequestNode> nodesWithRemainingOutDegree, IEnumerable<RequestNode> nodesWithRemainingInDegree)
		{
			ImmutableArray<RequestNode> sources = nodesWithRemainingOutDegree
				.OrderByDescending(v => Balance(v))
				.ThenByDescending(v => RemainingNonZeroOutDegree(v))
				.ThenByDescending(v => AvailableZeroOutDegree(v))
				.ToImmutableArray();

			ImmutableArray<RequestNode> sinks = nodesWithRemainingInDegree
				.OrderBy(v => Balance(v))
				.ThenByDescending(v => RemainingInDegree(v))
				.ToImmutableArray();

			Debug.Assert(sources.All(v => Balance(v) >= 0));
			Debug.Assert(sinks.All(v => Balance(v) <= 0));
			Debug.Assert(sinks.Length > 0);

			var nSources = 1;
			var nSinks = 1;

			long SourcesSum() => sources.Take(nSources).Sum(v => Balance(v));
			long SinksSum() => sinks.Take(nSinks).Sum(v => Balance(v));
			long CompareSums() => SourcesSum().CompareTo(-1 * SinksSum());

			// We want to fully discharge the larger (in absolute magnitude) of
			// the two nodes, so we will add more nodes to the smaller one until
			// we can fully cover. At each step of the iteration we fully
			// discharge at least 2 nodes from the queue.
			var initialComparison = CompareSums();
			var fanIn = initialComparison == -1;

			if (initialComparison != 0 && SinksSum() != 0)
			{
				Action takeOneMore = fanIn ? () => nSources++ : () => nSinks++;

				// Take more nodes until the comparison sign changes or
				// we run out.
				while (initialComparison == CompareSums()
				       && (fanIn ? sources.Length - nSources > 0
				                 : sinks.Length - nSinks > 0))
				{
					takeOneMore();
				}
			}

			var largestMagnitudeNode = (fanIn ? sinks.First() : sources.First());
			var smallMagnitudeNodes = (fanIn ? sources.Take(nSources).Reverse() : sinks.Take(nSinks)); // reverse positive values so we always proceed in order of increasing magnitude

			return (largestMagnitudeNode, smallMagnitudeNodes, fanIn);
		}

		// Drain values into a reissuance request (towards the center of the graph).
		public CredentialEdgeSet DrainReissuance(RequestNode reissuance, IEnumerable<RequestNode> nodes)
			// The amount for the edge is always determined by the dicharged
			// nodes' values, since we only add reissuance nodes to reduce the
			// number of charged nodes overall.
			=> nodes.Aggregate(this, (edgeSet, node) => edgeSet.DrainReissuance(reissuance, node));

		private CredentialEdgeSet DrainReissuance(RequestNode reissuance, RequestNode node)
		{
			// Due to opportunistic draining of lower priority credential
			// types when defining a reissuance node for higher priority
			// ones, the amount is not guaranteed to be zero, avoid adding
			// such edges.
			long value = Balance(node);

			if (value > 0)
			{
				return AddEdge(node, reissuance, (ulong)value);
			}
			else if (value < 0)
			{
				return AddEdge(reissuance, node, (ulong)(-1 * value))
					.AddZeroEdges(reissuance, node);
			}
			else if (InDegree(reissuance) == 0) // true for new fan-out reissuance nodes
			{
				// Always satisfiy zero credential from this reissuance node
				// (it's guaranteed to be possible) to avoid crossing edges,
				// even if there's no balance to discharge.
				return AddZeroEdges(reissuance, node);
			}
			else
			{
				return this;
			}
		}

		public CredentialEdgeSet AddZeroEdges(RequestNode src, RequestNode dst)
		{
			Debug.Assert(Balance(dst) == 0);
			Debug.Assert(RemainingInDegree(dst) >= 0);

			if ( RemainingInDegree(dst) == 0 )
			{
				return this;
			}
			else
			{
				var e = AddZeroEdge(src, dst);
				Debug.Assert(e.InDegree(dst) > InDegree(dst));
				Debug.Assert(e.RemainingInDegree(dst) < RemainingInDegree(dst));
				return e.AddZeroEdges(src, dst);
			}
		}

		public CredentialEdgeSet AddZeroEdge(RequestNode src, RequestNode dst) => AddEdge(src, dst, 0);

		// Drain credential values between terminal nodes, cancelling out
		// opposite values by propagating forwards or backwards corresponding to
		// fan-in and fan-out dependency structure.
		public CredentialEdgeSet DrainTerminal(RequestNode node, IEnumerable<RequestNode> nodes)
			=> nodes.Aggregate(this, (edgeSet, otherNode) => edgeSet.DrainTerminal(node, otherNode));

		private CredentialEdgeSet DrainTerminal(RequestNode node, RequestNode dischargeNode)
		{
			long value = Balance(dischargeNode);

			if (value < 0)
			{
				// Fan out, discharge the entire balance, adding zero edges if
				// needed (might not be if the discharged node has already
				// received an input edge in a previous pass).
				return AddEdge(node, dischargeNode, (ulong)Math.Min(Balance(node), -1 * value));//.DrainZeroCredentials(node, dischargeNode);
			}
			else if (value > 0)
			{
				// Fan in, draining zero credentials is never necessary, either
				// one or both available in-edges of `node` will be used
				var edgeAmount = (ulong)Math.Min(-1 * Balance(node), value);
				if (edgeAmount == (ulong)value || RemainingNonZeroOutDegree(dischargeNode) > 1)
				{
					return AddEdge(dischargeNode, node, edgeAmount);
				}
				else
				{
					// Sometimes the last dischargeNode can't be handled in this
					// iteration because the amount requires a change value but
					// its remaining out degree is already 1, requiring the
					// exact value to be used.
					// Just skip it here and it will eventually become the
					// largest magnitude node if it's required, and get handled
					// by the negative node discharging loop.
					return this;
				}
			}
			else if (value == 0 && ( dischargeNode.InitialBalance(CredentialType) == 0 ))
			{
				// eagerly discharge zero credentials when the child node is a reissuance node
				return DrainZeroCredentials(node, dischargeNode);
			}
			// else if (value == 0 && ( dischargeNode.InitialBalance(CredentialType) < 0 || node.InitialBalance(CredentialType) > 0 ))
			// {
			// 	return DrainZeroCredentials(node, dischargeNode);
			// }
			// else if (value == 0 && ( node.InitialBalance(CredentialType) < 0 || dischargeNode.InitialBalance(CredentialType) > 0 ))
			// {
			// 	return DrainZeroCredentials(dischargeNode, node);
			// }
			else
			{
				return this;
			}
		}

		public CredentialEdgeSet DrainZeroCredentials(RequestNode src, RequestNode dst)
		{
			if ( Balance(dst) != 0 || AvailableZeroOutDegree(src) == 0 || RemainingInDegree(dst) == 0 )
			{
				return this;
			}
			else
			{
				Debug.Assert(ZeroOutDegree(src) < DependencyGraph.K);
				Debug.Assert(RemainingZeroOutDegree(src) > 0);
				Debug.Assert(Balance(src) == 0 || RemainingZeroOutDegree(src) > 1);
				Debug.Assert(AvailableZeroOutDegree(src) > 0);

				var e = AddZeroEdge(src, dst);
				Debug.Assert(e.RemainingInDegree(dst) < RemainingInDegree(dst));
				return e.DrainZeroCredentials(src, dst);
			}
		}
	}
}
