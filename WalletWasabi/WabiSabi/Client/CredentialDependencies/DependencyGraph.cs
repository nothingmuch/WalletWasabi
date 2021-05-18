using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;

namespace WalletWasabi.WabiSabi.Client.CredentialDependencies
{
	public record DependencyGraph
	{
		public const int K = ProtocolConstants.CredentialNumber;

		public ImmutableList<RequestNode> Vertices { get; private set; } = ImmutableList<RequestNode>.Empty;

		// Internal properties used to keep track of effective values and edges
		// TODO private
		public ImmutableSortedDictionary<CredentialType, CredentialEdgeSet> edgeSets { get; private init; } = ImmutableSortedDictionary<CredentialType, CredentialEdgeSet>.Empty
			.Add(CredentialType.Amount, new() { CredentialType = CredentialType.Amount })
			.Add(CredentialType.VirtualBytes, new() { CredentialType = CredentialType.VirtualBytes });

		public long Balance(RequestNode node, CredentialType credentialType) => edgeSets[credentialType].Balance(node);

		public IEnumerable<CredentialDependency> InEdges(RequestNode node, CredentialType credentialType) => edgeSets[credentialType].InEdges(node);

		public IEnumerable<CredentialDependency> OutEdges(RequestNode node, CredentialType credentialType) => edgeSets[credentialType].OutEdges(node);

		public int InDegree(RequestNode node, CredentialType credentialType) => edgeSets[credentialType].InDegree(node);

		public int OutDegree(RequestNode node, CredentialType credentialType) => edgeSets[credentialType].NonZeroOutDegree(node);

		public string Graphviz() {

			var output = "digraph {\n";

			Func<RequestNode,int> id = Vertices.IndexOf;

			foreach (var v in Vertices)
			{
				if (v.InitialBalance(CredentialType.Amount) == 0 && v.InitialBalance(CredentialType.VirtualBytes) == 0)
				{

					output += $"  {id(v)} [label=\"\"];\n";
				}
				else
				{
					output += $"  {id(v)} [label=\"{v.InitialBalance(CredentialType.Amount)}s {v.InitialBalance(CredentialType.VirtualBytes)}b\"];\n";
				}
			}


			for (CredentialType credentialType = 0; credentialType < CredentialType.NumTypes; credentialType++)
			{
				var color = credentialType == 0 ? "blue" : "red";
				var unit = credentialType == 0 ? "s" : "b";

				output += "  {\n";
				output += $"      edge [color={color}, fontcolor={color}];\n";

				foreach (var e in edgeSets[credentialType].Predecessors.Values.Aggregate((a, b) => a.Union(b)).OrderByDescending(e => e.Value).ThenBy(e => id(e.From)).ThenBy(e => id(e.To)))
				{
					output += $"    {id(e.From)} -> {id(e.To)} [label=\"{e.Value}{unit}\"{(e.Value == 0 ? ", style=dashed" : "")}];\n";
				}


				output += "  }\n";
			}


			output += "}\n";
			return output;
		}

		// TODO doc comment
		// Public API: construct a graph from amounts, and resolve the
		// credential dependencies. Should only produce valid graphs.
		// IDs are positive ints assigned in the order of the enumerable, but
		// Vertices will contain more elements if there are reissuance nodes.
		public static DependencyGraph ResolveCredentialDependencies(IEnumerable<IEnumerable<ulong>> inputValues, IEnumerable<IEnumerable<ulong>> outputValues)
		{
			return FromValues(inputValues, outputValues).ResolveCredentials();
		}

		private static DependencyGraph FromValues(IEnumerable<IEnumerable<ulong>> inputValues, IEnumerable<IEnumerable<ulong>> outputValues)
		{
			if (Enumerable.Concat(inputValues, outputValues).Any(x => x.Count() != (int)CredentialType.NumTypes))
			{
				throw new ArgumentException($"Number of credential values must be {CredentialType.NumTypes}");
			}

			for (CredentialType credentialType = 0; credentialType < CredentialType.NumTypes; credentialType++)
			{
				// no Sum(Func<ulong, ulong>)) variant
				long credentialValue(IEnumerable<ulong> x) => (long)x.Skip((int)credentialType).First();

				if (inputValues.Sum(credentialValue) < outputValues.Sum(credentialValue))
				{
					throw new ArgumentException("Overall balance must not be negative");
				}
			}

			// Input nodes actually have indegree K, not 0, which can be used to
			// consolidate inputs early but using it implies connection
			// confirmations may have dependencies, so may pose a privacy leak,
			// but it can reduce the total number of requests. If late
			// regisrations are supported, existing credentials can be modeled
			// as nodes with in degree 0, out degree 1, zero out degree 0.
			var inputNodes = inputValues.Select(x => new RequestNode(x.Select(y => (long)y), inDegree: 0, outDegree: K, zeroOutDegree: K*(K-1)));
			var outputNodes = outputValues.Select(x => new RequestNode(x.Select(y => -1 * (long)y), inDegree: K, outDegree: 0, zeroOutDegree: 0));

			// per node entries created in AddNode, querying nodes not in the
			// graph should result in key errors.
			return new DependencyGraph().AddNodes(Enumerable.Concat(inputNodes, outputNodes));
		}

		private DependencyGraph AddNodes(IEnumerable<RequestNode> nodes) => nodes.Aggregate(this, (g, v) => g.AddNode(v));

		private DependencyGraph AddNode(RequestNode node)
			=> this with
			{
				Vertices = Vertices.Add(node),
				edgeSets = edgeSets.ToImmutableSortedDictionary(
					kvp => kvp.Key,
					kvp => kvp.Value with
					{
						EdgeBalances = kvp.Value.EdgeBalances.Add(node, 0),
						Predecessors = kvp.Value.Predecessors.Add(node, ImmutableHashSet<CredentialDependency>.Empty),
						Successors = kvp.Value.Successors.Add(node, ImmutableHashSet<CredentialDependency>.Empty)
					}
				),
			};

		// TODO doc comment
		// Resolve edges for all credential types
		//
		// We start with a bipartite graph of terminal sources and sinks
		// (corresponding to inputs and outputs or connection confirmation and
		// output registration requests).
		//
		// Nodes are fully discharged when all of their in-edges are accounted
		// for. For output registrations this must exactly cancel out their
		// initial balance, since they make no output registration requests.
		//
		// Outgoing edges represent credential amounts to request and present in
		// a subsequent request, so for positive nodes if there is a left over
		// balance the outgoing dregree is limited to K-1, since an extra
		// credential for the remaining amount must also be requested.
		//
		// At every iteration of the loop a single node of the largest magnitude
		// (source or sink) and one or more nodes of opposite sign are selected.
		// Unless these are the final nodes on the list, the smaller magnitude
		// nodes are selected to fully discharge the largest magnitude node.
		//
		// If the smaller nodes are too numerous K at a time are merged into a
		// reissuance node. When these are output registrations the reissuance
		// node's output edges always fully account for the dependent requests,
		// including the zero credentials required for them. When the smaller
		// nodes appear on the input side, the non-zero values are sufficient to
		// fill the reissuance node's in edge set and requires only one edge to
		// fully drain the (remaining) balance, so there will be an extra zero
		// valued credential (requested normally, incl. range proof).
		//
		// New reissuance nodes fully absorb the value of the nodes they
		// substitute with no additional dependencies required, so each one
		// reduces the bipartite graph problem to a smaller one (by K-1 == 1),
		// since the replaced nodes no longer need to be considered.
		//
		// When the list of nodes has been reduced to the remaining non-zero out
		// degree of the largest magnitude node edges that cancel out positive
		// and negative values are added. This will fully discharge the largest
		// magnitude node, except when it is positive and all of the remaining
		// negative nodes on the graph add up to less than it. Inputs' extra
		// zero credentials are used opportunistically when a single positive
		// valued node is matched with several negative valued nodes, but only
		// for nodes with no remaining balance, the final node may need a
		// non-zero edge from the next largest positive valued node (but in that
		// case it won't need a zero credential).
		//
		// TODO this should leave no nodes with InDegree != 0
		//
		// After no negative value nodes, the remaining in-edges of all nodes
		// must be filled with zero credentials. These are added according to
		// the graph order, by extending new edges from nodes whose in-degree is
		// already maximized but whose out degree is not. This again deals only
		// with a bipartite graph, because reissuance nodes consolidating output
		// nodes leave no zero edges unaccounted for in the nodes they replace,
		// whereas on the input side the structure fans in so necessarily it
		// leaves no nodes with non-maximized in-degrees, it can only increase
		// the available out degree for nodes which are not fully consumed.
		private DependencyGraph ResolveCredentials()
			=> edgeSets.Keys.Aggregate(
				edgeSets.Keys.Aggregate(this, (g, credentialType) => g.ResolveNegativeBalanceNodes(credentialType)),
				(g, credentialType) => g.ResolveZeroCredentials(credentialType));

		private DependencyGraph ResolveNegativeBalanceNodes(CredentialType credentialType)
		{
			var g = ResolveUniformInputSpecialCases(credentialType);

			var edgeSet = g.edgeSets[credentialType];

			var negative = g.Vertices.Where(v => edgeSet.Balance(v) < 0);

			if (negative.Count() == 0)
			{
				return g;
			}

			var positive = g.Vertices.Where(v => edgeSet.Balance(v) > 0);

			(var largestMagnitudeNode, var smallMagnitudeNodes, var fanIn) = edgeSet.MatchNodesToDischarge(positive, negative);

			var maxCount = (fanIn ? edgeSet.RemainingInDegree(largestMagnitudeNode!) : edgeSet.RemainingNonZeroOutDegree(largestMagnitudeNode!));

			if (Math.Abs(edgeSet.Balance(largestMagnitudeNode!)) > Math.Abs(smallMagnitudeNodes.Sum(x => edgeSet.Balance(x))))
			{
				// When we are draining a positive valued node into multiple
				// negative nodes and we can't drain it completely, we need to
				// leave an edge unused for the remaining amount.
				// The corresponding condition can't actually happen for fan-in
				// because the negative balance of the last loop iteration can't
				// exceed the the remaining positive elements, their total sum
				// must be positive as checked in the constructor.
				if (maxCount > 1)
				{
					// when the edge capacity makes it possible, we can just
					// ensure the largest magnitude node ends up with an unused
					// edge by reducing maxCount
					maxCount--;
				}
				else
				{
					// otherwise, drain the largest magnitude node into a new
					// reissuance node which will have room for an unused edge
					// in its out edge set.
					(g, largestMagnitudeNode) = g.AggregateIntoReissuanceNode(new RequestNode[] { largestMagnitudeNode! }, credentialType);
				}
			}

			var preReduceSmallNodes = smallMagnitudeNodes;

			// Reduce the number of small magnitude nodes to the number of edges
			// available for use in the largest magnitude node
			(g, smallMagnitudeNodes) = g.ReduceNodes(smallMagnitudeNodes, maxCount, credentialType);

			// After draining either the last small magnitude node or the
			// largest magnitude node could still have a non-zero value.
			g = g.DrainTerminal(largestMagnitudeNode, smallMagnitudeNodes, credentialType);

			// Debug.Assert(g.edgeSets[credentialType].RemainingInDegree(largestMagnitudeNode) == 0, "larger node has remaining in degree 0");
			// TODO remove these, since zero creds now at later pass
			// Debug.Assert(smallMagnitudeNodes.Where(v => g.edgeSets[credentialType].Balance(v) == 0).All(v => g.edgeSets[credentialType].RemainingInDegree(v) == 0), "smaller nodes have in degree 0 if fully discharged");
			// Debug.Assert(preReduceSmallNodes.Where(v => g.edgeSets[credentialType].Balance(v) == 0).All(v => g.edgeSets[credentialType].RemainingInDegree(v) == 0), "pre reduce small nodes have in degree 0 if fully discharged");
			Debug.Assert(preReduceSmallNodes.Take(preReduceSmallNodes.Count() - 1).All(v => g.edgeSets[credentialType].Balance(v) == 0), "all but last pre-reduce small nodes have 0 balance");

			return g.ResolveNegativeBalanceNodes(credentialType);
		}

		private DependencyGraph ResolveUniformInputSpecialCases(CredentialType credentialType)
		{
			// TODO special case 1: if positive has multiple equal sized in a
			// row and negative has multiple equal sized in a row, more numerous
			// but smaller, Reduce negative breadth wise as a k-ary tree all
			// together until the 1st node is >=, with maxcount == the number of
			// positive value with remaining out degree > 1 (amenable to uneven
			// amount). -- result: over-all fan-in structure, guaranteed to be balanced.
			// when injecting reissuance nodes, opportunistically add zero edges
			// for lower valued credential types.
			// TODO special case 2: if positive.Where(remaining out > 1).Count()
			// > negative.Count() and positive.Where(remaining out >
			// 1).Zip(negative).All((p,n) => p >= n), match them all 1:1

			var edgeSet = edgeSets[credentialType];

			IEnumerable<RequestNode> negative = Vertices.Where(v => edgeSet.Balance(v) < 0).OrderBy(v => edgeSet.Balance(v));

			if (negative.Count() == 0)
			{
				return this;
			}

			var g = this;

			// First special case - uniform input values (as in weight credentials)
			// Unconstrained nodes have a remaining out degree greater than 1, so they can produce arbitary value outputs (final edge must leave balance = 0)
			// The remaining outdegree > 1 condition is equivalent to == K for K=2, so that also implies the positive valued nodes haven't been used for this credential type yet (TODO affinity/avoid crossing?)
			var unconstrainedPositive = Vertices.Where(v => edgeSet.Balance(v) > 0 && edgeSet.RemainingNonZeroOutDegree(v) > 1).OrderByDescending(v => edgeSet.Balance(v));
			if ( unconstrainedPositive.Select(v => edgeSet.Balance(v)).Distinct().Count() == 1)
			{
				if (edgeSet.Balance(negative.First()) * -1 * (negative.Count()/unconstrainedPositive.Count()) < edgeSet.Balance(unconstrainedPositive.First()) )
				{
					// TODO shuffle both?

					if ( negative.Count() > unconstrainedPositive.Count() )
					{
						// TODO consolidate only lowest depth at each iteration
						// (negative height, i.e. max of distance to terminal output
						// nodes derived from the vertex, 0 for such nodes) nodes
						// first
						(g, negative) = g.ReduceNodes(negative, unconstrainedPositive.Count(), credentialType);
					}
				}
			}

			edgeSet = g.edgeSets[credentialType];

			// Second special case, more general to the previous one, when for each
			// negative node there is a satisfactory unconstrained positive node
			// (not necessarily all of equal value), discharge via a 1:1 correspondence
			if ( negative.Count() <= unconstrainedPositive.Count() && Enumerable.Zip(unconstrainedPositive, negative).All(p => edgeSet.Balance(p.First) + edgeSet.Balance(p.Second) >= 0))
			{
				g = Enumerable.Zip(unconstrainedPositive, negative).Aggregate(g, (g,p) => g.DrainTerminal(p.First, new RequestNode[] { p.Second }, credentialType));
			}

			return g;
		}

		// Build a k-ary tree bottom up to reduce a list of nodes to discharge
		// to at most maxCount elements.
		private (DependencyGraph, IEnumerable<RequestNode>) ReduceNodes(IEnumerable<RequestNode> nodes, int maxCount, CredentialType credentialType)
		{
			if (nodes.Count() <= maxCount)
			{
				return (this, nodes);
			}

			// Replace up to k nodes, possibly the entire queue, with a
			// single reissuance node which combines their values. The total
			// number of items might be less than K but still larger than
			// maxCount.
			var take = Math.Min(K, nodes.Count());
			(var g, var reissuance) = AggregateIntoReissuanceNode(nodes.Take(take), credentialType);
			var reduced = nodes.Skip(take).Append(reissuance).ToImmutableArray(); // keep enumerable expr size bounded by evaluating eagerly
			return g.ReduceNodes(reduced, maxCount, credentialType);
		}

		private (DependencyGraph, RequestNode) AggregateIntoReissuanceNode(IEnumerable<RequestNode> nodes, CredentialType credentialType)
		{
			var reissuance = new RequestNode(Enumerable.Repeat(0L, K).ToImmutableArray(), inDegree: K, outDegree: K, zeroOutDegree: K*(K-1));
			var g = AddNode(reissuance).DrainReissuance(reissuance, nodes, credentialType);

			// Kind of a hack, also discharge 0 credentials for *previous*
			// credential type from this reissuance node, which will eliminate
			// it from the subsequent zero credential filling passes.
			// The rationale behind this is that the reissuance node already has
			// to be created and will have zero credentials to spare, so in this
			// way the aggregated nodes are not dependent on any other node for
			// zero credentials.
			if (credentialType > 0) {
				g = nodes.Aggregate(g, (g, v) => g.DrainZeroCredentials(reissuance, v, 0));
			}

			return (g, reissuance);
		}

		private DependencyGraph DrainReissuance(RequestNode reissuance, IEnumerable<RequestNode> nodes, CredentialType credentialType)
		{
			var drainedEdgeSet = edgeSets[credentialType].DrainReissuance(reissuance, nodes);

			var g = this with { edgeSets = edgeSets.SetItem(credentialType, drainedEdgeSet) };

			// TODO zero creds of prior credential types

			// Also drain all subsequent credential types, to minimize
			// dependencies between different requests, weight credentials
			// should often be easily satisfiable with parallel edges to the
			// amount credential edges.
			if (credentialType + 1 < CredentialType.NumTypes)
			{
				// TODO limit up to a certain height in the graph
				return g.DrainReissuance(reissuance, nodes, credentialType + 1);
			}
			else
			{
				return g;
			}
		}

		private DependencyGraph DrainTerminal(RequestNode node, IEnumerable<RequestNode> nodes, CredentialType credentialType)
			// Here we avoid opportunistically adding edges of other types as it
			// provides no benefit with K=2. Stable sorting prevents edge
			// crossing.
			=> this with { edgeSets = edgeSets.SetItem(credentialType, edgeSets[credentialType].DrainTerminal(node, nodes)) };

		private DependencyGraph ResolveZeroCredentials(CredentialType credentialType)
		{
			var edgeSet = edgeSets[credentialType];
			var unresolvedNodes = Vertices.Where(v => edgeSet.RemainingInDegree(v) > 0 && edgeSet.AvailableZeroOutDegree(v) > 0).OrderByDescending(v => edgeSet.AvailableZeroOutDegree(v));

			Debug.Assert(unresolvedNodes.All(v => edgeSet.Balance(v) >= 0), $"unresolved nodes must not have negative value type={credentialType} " + Graphviz());

			if (unresolvedNodes.Count() == 0)
			{
				return ResolveZeroCredentialsForTerminalNodes(credentialType);;
			}

			// Resolve remaining zero credentials by using nodes with no
			// dependencies but remaining out degree (following DAG order)
			var providers = Vertices.Where(v => edgeSet.RemainingInDegree(v) == 0 && edgeSet.AvailableZeroOutDegree(v) > 0)
				.SelectMany(v => Enumerable.Repeat(v, edgeSet.AvailableZeroOutDegree(v)));

			// TODO discharge iteratively by topological layer, each time applying different filters?
			// intersect with successor set of providers of lower credential type edge set?

			Debug.Assert(providers.Count() > 0, "must have donor nodes");

			var reduced = unresolvedNodes.SelectMany(v => Enumerable.Repeat(v, edgeSet.RemainingInDegree(v)))
				.Zip(providers, (t, f) => new { From = f, To = t })
				.Aggregate(this, (g, p) => g.AddZeroCredential(p.From, p.To, credentialType));

			Debug.Assert(reduced.Vertices.Sum(v => reduced.edgeSets[credentialType].RemainingInDegree(v)) < Vertices.Sum(v => edgeSet.RemainingInDegree(v)), "must have reduced some unresolved nodes");

			return reduced.ResolveZeroCredentials(credentialType);
		}

		private DependencyGraph ResolveZeroCredentialsForTerminalNodes(CredentialType credentialType)
		{
			// TODO
			// 3 depth first passes, always discharging from remaining in = 0, available zero > 1:
			// - discharge only to AvailableZeroOutDegree > 1 nodes (should be 1 per)
			// - discharge to direct descendents
			// - discharge by topological order

			// Stop when all nodes have a maxed out in-degree.
			// This termination condition is guaranteed to be possible because
			// connection confirmation and reissuance requests both have an out
			// degree of K^2 when accounting for their extra zero credentials.
			var edgeSet = edgeSets[credentialType];
			var unresolvedNodes = Vertices.Where(v => edgeSet.RemainingInDegree(v) > 0).OrderByDescending(v => edgeSet.AvailableZeroOutDegree(v));

			Debug.Assert(unresolvedNodes.All(v => edgeSet.Balance(v) >= 0), $"unresolved nodes must not have negative value type={credentialType} " + Graphviz());

			if (unresolvedNodes.Count() == 0)
			{
				return this;
			}

			// Resolve remaining zero credentials by using nodes with no
			// dependencies but remaining out degree (following DAG order)
			var providers = Vertices.Where(v => edgeSet.RemainingInDegree(v) == 0 && edgeSet.AvailableZeroOutDegree(v) > 0)
				.SelectMany(v => Enumerable.Repeat(v, edgeSet.AvailableZeroOutDegree(v)));

			// TODO discharge iteratively by topological layer, each time applying different filters?

			Debug.Assert(providers.Count() > 0, "must have donor nodes");

			var reduced = unresolvedNodes.SelectMany(v => Enumerable.Repeat(v, edgeSet.RemainingInDegree(v)))
				.Zip(providers, (t, f) => new { From = f, To = t })
				.Aggregate(this, (g, p) => g.AddZeroCredential(p.From, p.To, credentialType));

			Debug.Assert(reduced.Vertices.Sum(v => reduced.edgeSets[credentialType].RemainingInDegree(v)) < Vertices.Sum(v => edgeSet.RemainingInDegree(v)), "must have reduced some unresolved nodes");

			return reduced.ResolveZeroCredentialsForTerminalNodes(credentialType);
		}

		private DependencyGraph DrainZeroCredentials(RequestNode from, RequestNode to, CredentialType credentialType)
			=> this with { edgeSets = edgeSets.SetItem(credentialType, edgeSets[credentialType].DrainZeroCredentials(from, to)) };

		private DependencyGraph AddZeroCredential(RequestNode from, RequestNode to, CredentialType credentialType)
			=> this with { edgeSets = edgeSets.SetItem(credentialType, edgeSets[credentialType].AddZeroEdge(from, to)) };

	}
}
