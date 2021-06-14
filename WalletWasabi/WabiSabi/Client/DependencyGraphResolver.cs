using NBitcoin;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WalletWasabi.Crypto.ZeroKnowledge;
using WalletWasabi.WabiSabi.Client.CredentialDependencies;

namespace WalletWasabi.WabiSabi.Client
{
	public class DependencyGraphResolver
	{
		public DependencyGraphResolver(DependencyGraph graph)
		{
			Graph = graph;
			var allInEdges = Enum.GetValues<CredentialType>()
				.SelectMany(type => Enumerable.Concat(Graph.Reissuances, Graph.Outputs)
				.SelectMany(node => Graph.EdgeSets[type].InEdges(node)));

			DependencyTasks = allInEdges.ToDictionary(edge => edge, _ => new TaskCompletionSource<Credential>(TaskCreationOptions.RunContinuationsAsynchronously));
		}

		private DependencyGraph Graph { get; }
		private Dictionary<CredentialDependency, TaskCompletionSource<Credential>> DependencyTasks { get; }

		public async Task ResolveAsync(IEnumerable<AliceClient> aliceClients, BobClient bobClient, IEnumerable<TxOut> txOuts, CancellationToken cancellationToken)
		{
			var aliceNodePairs = PairAliceClientAndRequestNodes(aliceClients, Graph);

			// Set the result for credentials issued from connection confirmation.
			foreach ((var aliceClient, var node) in aliceNodePairs)
			{
				Debug.Assert(Graph.OutEdges(node, CredentialType.Amount).Count() <= aliceClient.IssuedAmountCredentials.Count());
				foreach (var (edge, credential) in Enumerable.Zip(Graph.OutEdges(node, CredentialType.Amount), aliceClient.IssuedAmountCredentials))
				{
					DependencyTasks[edge].SetResult(credential);
				}

				Debug.Assert(Graph.OutEdges(node, CredentialType.Vsize).Count() <= aliceClient.IssuedVsizeCredentials.Count());
				foreach (var (edge, credential) in Enumerable.Zip(Graph.OutEdges(node, CredentialType.Vsize), aliceClient.IssuedVsizeCredentials))
				{
					DependencyTasks[edge].SetResult(credential);
				}
			}

			// Build tasks and link them together.
			List<SmartRequestNode> smartRequestNodes = new();
			List<Task> alltask = new();

			foreach (var node in Graph.Reissuances)
			{
				var inputAmountEdgeTasks = Graph.InEdges(node, CredentialType.Amount).Select(edge => DependencyTasks[edge].Task);
				var inputVsizeEdgeTasks = Graph.InEdges(node, CredentialType.Vsize).Select(edge => DependencyTasks[edge].Task);

				// Debug.Assert(Enumerable.Concat(inputAmountEdgeTasks, inputVsizeEdgeTasks).All(t => t.Status == TaskStatus.RanToCompletion));

				var outputAmountEdgeTaskCompSources = Graph.OutEdges(node, CredentialType.Amount).Select(edge => DependencyTasks[edge]);
				var outputVsizeEdgeTaskCompSources = Graph.OutEdges(node, CredentialType.Vsize).Select(edge => DependencyTasks[edge]);

				var requestedAmounts = Graph.OutEdges(node, CredentialType.Amount).Select(edge => (long)edge.Value);
				var requestedVSizes = Graph.OutEdges(node, CredentialType.Vsize).Select(edge => (long)edge.Value);

				SmartRequestNode smartRequestNode = new(
					inputAmountEdgeTasks,
					inputVsizeEdgeTasks,
					outputAmountEdgeTaskCompSources,
					outputVsizeEdgeTaskCompSources);

				var task = smartRequestNode.StartReissueAsync(bobClient, requestedAmounts, requestedVSizes, cancellationToken);
				alltask.Add(task);
			}

			await Task.Delay(5000, cancellationToken);
			// Debug.Assert(alltask.All(t => t.Status == TaskStatus.RanToCompletion));

			await Task.WhenAll(alltask).ConfigureAwait(false);

			alltask = new();

			foreach (var (txOut, node) in Enumerable.Zip(txOuts, Graph.Outputs))
			{
				var inputAmountEdgeTasks = Graph.InEdges(node, CredentialType.Amount).Select(edge => DependencyTasks[edge].Task);
				var inputVsizeEdgeTasks = Graph.InEdges(node, CredentialType.Vsize).Select(edge => DependencyTasks[edge].Task);

				Debug.Assert(!Graph.OutEdges(node, CredentialType.Amount).Any());
				Debug.Assert(!Graph.OutEdges(node, CredentialType.Vsize).Any());

				SmartRequestNode smartRequestNode = new(
					inputAmountEdgeTasks,
					inputVsizeEdgeTasks,
					Array.Empty<TaskCompletionSource<Credential>>(),
					Array.Empty<TaskCompletionSource<Credential>>());

				var task = smartRequestNode.StartRegisterOutputAsync(bobClient, txOut, cancellationToken);
				alltask.Add(task);
			}

			await Task.Delay(5000, cancellationToken);
			// Debug.Assert(alltask.All(t => t.Status == TaskStatus.RanToCompletion));

			await Task.WhenAll(alltask).ConfigureAwait(false);

			Debug.Assert(false, "finished outputregistrations");
		}

		private IEnumerable<(AliceClient AliceClient, RequestNode Node)> PairAliceClientAndRequestNodes(IEnumerable<AliceClient> aliceClients, DependencyGraph graph)
		{
			var inputNodes = graph.Inputs;

			if (aliceClients.Count() != inputNodes.Count)
			{
				throw new InvalidOperationException($"Graph vs Alice inputs mismatch {aliceClients.Count()} != {inputNodes.Count}");
			}

			return aliceClients.Zip(inputNodes);
		}
	}
}
