using NBitcoin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WalletWasabi.Blockchain.Keys;
using WalletWasabi.Crypto.Randomness;
using WalletWasabi.Crypto.ZeroKnowledge;
using WalletWasabi.Logging;
using WalletWasabi.WabiSabi.Backend.PostRequests;
using WalletWasabi.WabiSabi.Backend.Rounds;
using WalletWasabi.WabiSabi.Client.CredentialDependencies;
using WalletWasabi.WabiSabi.Crypto;
using WalletWasabi.WabiSabi.Models;
using WalletWasabi.WabiSabi.Models.MultipartyTransaction;
using WalletWasabi.Wallets;

namespace WalletWasabi.WabiSabi.Client
{
	public class CoinJoinClient
	{
		public CoinJoinClient(
			IWabiSabiApiRequestHandler arenaRequestHandler,
			IEnumerable<Coin> coins,
			Kitchen kitchen,
			KeyManager keymanager,
			RoundStateUpdater roundStatusUpdater)
		{
			ArenaRequestHandler = arenaRequestHandler;
			Kitchen = kitchen;
			Keymanager = keymanager;
			RoundStatusUpdater = roundStatusUpdater;
			SecureRandom = new SecureRandom();
			Coins = coins;
		}

		private ZeroCredentialPool ZeroAmountCredentialPool { get; } = new();
		private ZeroCredentialPool ZeroVsizeCredentialPool { get; } = new();
		private IEnumerable<Coin> Coins { get; set; }
		private SecureRandom SecureRandom { get; } = new SecureRandom();
		private Random Random { get; } = new();
		public IWabiSabiApiRequestHandler ArenaRequestHandler { get; }
		public Kitchen Kitchen { get; }
		public KeyManager Keymanager { get; }
		private RoundStateUpdater RoundStatusUpdater { get; }

		private Dictionary<CredentialDependency, TaskCompletionSource<Credential>> dictionaryOfDependencies { get; } = new();
		private HashSet<SmartRequestNode> smartNodes { get; } = new();

		public async Task StartCoinJoinAsync(CancellationToken cancellationToken)
		{
			var roundState = await RoundStatusUpdater.CreateRoundAwaiter(roundState => roundState.Phase == Phase.InputRegistration, cancellationToken).ConfigureAwait(false);
			var constructionState = roundState.Assert<ConstructionState>();

			// Calculate outputs values
			var outputValues = DecomposeAmounts(roundState.FeeRate);

			// Get all locked internal keys we have and assert we have enough.
			Keymanager.AssertLockedInternalKeysIndexed(howMany: Coins.Count());
			var allLockedInternalKeys = Keymanager.GetKeys(x => x.IsInternal && x.KeyState == KeyState.Locked);
			var outputs = outputValues.Zip(allLockedInternalKeys, (amount, hdPubKey) => new TxOut(amount, hdPubKey.P2wpkhScript));

			var dependencyGraph = DependencyGraph.ResolveCredentialDependencies(Coins, outputs, roundState.FeeRate);

			List<AliceClient> aliceClients = CreateAliceClients(roundState);

			// Register coins.
			// TODO:
			// 1. randomize delays uniformly
			// 2. simulate decomposition of prefixes, ensure sensible result
			//    for all prefixes (introduces some bias, depending on what
			//    "sensible" means)
			aliceClients = await RegisterCoinsAsync(aliceClients, cancellationToken).ConfigureAwait(false);


			// Confirm coins.
			// TODO: move input registrations to the connection confirmation
			// loop of each alice client, to prevent any timing correlations
			// between different alices of the same coinjoin client.
			// As the overall state of which coins have been
			// registered is updated, the credential amounts being requested
			// should be updated by recalculating the graph based on the
			// decomposition only of the registered coins.
			aliceClients = await ConfirmConnectionsAsync(aliceClients, dependencyGraph, roundState.ConnectionConfirmationTimeout, cancellationToken).ConfigureAwait(false);

			foreach ((var aliceClient, var node) in Enumerable.Zip(aliceClients, dependencyGraph.Inputs))
			{
				SetTaskCompletionSources(dependencyGraph, node, (aliceClient.RealAmountCredentials, aliceClient.RealVsizeCredentials));
			}

			roundState = await RoundStatusUpdater.CreateRoundAwaiter(roundState.Id, rs => rs.Phase == Phase.OutputRegistration, cancellationToken).ConfigureAwait(false);

			var bobClient = CreateBobClient(roundState);

			foreach (var edge in dependencyGraph.AllInEdges())
			{
				dictionaryOfDependencies[edge] = new TaskCompletionSource<Credential>();
			}

			foreach (var node in dependencyGraph.Reissuances)
			{
				smartNodes.Add(new SmartRequestNode(
					node,
					dependencyGraph.InEdges(node, CredentialType.Amount).Select(e => dictionaryOfDependencies[e].Task),
					dependencyGraph.InEdges(node, CredentialType.Vsize).Select(e => dictionaryOfDependencies[e].Task),
					async (issuedAmountCredentials, issuedVsizeCredentials) => SetTaskCompletionSources(
						dependencyGraph,
						node,
						await bobClient.ReissueCredentialsAsync( // TODO SetResult() for returned values
							dependencyGraph.OutEdges(node, CredentialType.Amount).Select(e => e.Value).Cast<long>(), // TODO s/u(?=long)//
							dependencyGraph.OutEdges(node, CredentialType.Vsize).Select(e => e.Value).Cast<long>(), // TODO s/u(?=long)//
							issuedAmountCredentials,
							issuedVsizeCredentials,
							cancellationToken))));
			}

			foreach ((var txout, var node) in Enumerable.Zip(outputs, dependencyGraph.Outputs))
			{
				smartNodes.Add(new SmartRequestNode(
					   node,
					   dependencyGraph.InEdges(node, CredentialType.Amount).Select(e => dictionaryOfDependencies[e].Task),
					   dependencyGraph.InEdges(node, CredentialType.Vsize).Select(e => dictionaryOfDependencies[e].Task),
					   (issuedAmountCredentials, issuedVsizeCredentials) => bobClient.RegisterOutputAsync(
						   txout.Value, txout.ScriptPubKey, // TODO refactor to pass in TxOut
						   issuedAmountCredentials,
						   issuedVsizeCredentials,
						   cancellationToken)));
			}

			var outputsWithCredentials = outputs.Zip(aliceClients, (output, alice) => (output, alice.RealAmountCredentials, alice.RealVsizeCredentials));
			await RegisterOutputsAsync(bobClient, outputsWithCredentials, cancellationToken).ConfigureAwait(false);

			roundState = await RoundStatusUpdater.CreateRoundAwaiter(roundState.Id, rs => rs.Phase == Phase.TransactionSigning, cancellationToken).ConfigureAwait(false);
			var signingState = roundState.Assert<SigningState>();
			var unsignedCoinJoin = signingState.CreateUnsignedTransaction();

			// Sanity check.
			var effectiveOutputs = outputs.Select(o => (o.Value - roundState.FeeRate.GetFee(o.ScriptPubKey.EstimateOutputVsize()), o.ScriptPubKey));
			if (!SanityCheck(effectiveOutputs, unsignedCoinJoin))
			{
				throw new InvalidOperationException($"Round ({roundState.Id}): My output is missing.");
			}

			// Send signature.
			await SignTransactionAsync(aliceClients, unsignedCoinJoin, cancellationToken).ConfigureAwait(false);
		}

		private async Task SetTaskCompletionSources( // TODO rename
			DependencyGraph dependencyGraph,
			RequestNode node,
			(IEnumerable<Credential>, IEnumerable<Credential>) pair)
		{
			foreach ((var edge, var credential) in Enumerable.Zip(dependencyGraph.OutEdges(node, CredentialType.Amount), pair.First))
			{
				dictionaryOfDependencies[edge].SetResult(credential);
			}

			foreach ((var edge, var credential) in Enumerable.Zip(dependencyGraph.OutEdges(node, CredentialType.Vsize), pair.Second))
			{
				dictionaryOfDependencies[edge].SetResult(credential);
			}
		}


		private List<AliceClient> CreateAliceClients(RoundState roundState)
		{
			List<AliceClient> aliceClients = new();
			foreach (var coin in Coins)
			{
				var aliceArenaClient = new ArenaClient(
					roundState.CreateAmountCredentialClient(ZeroAmountCredentialPool, SecureRandom),
					roundState.CreateVsizeCredentialClient(ZeroVsizeCredentialPool, SecureRandom),
					ArenaRequestHandler);

				var hdKey = Keymanager.GetSecrets(Kitchen.SaltSoup(), coin.ScriptPubKey).Single();
				var secret = hdKey.PrivateKey.GetBitcoinSecret(Keymanager.GetNetwork());
				aliceClients.Add(new AliceClient(roundState.Id, aliceArenaClient, coin, roundState.FeeRate, secret));
			}
			return aliceClients;
		}

		private async Task<List<AliceClient>> RegisterCoinsAsync(IEnumerable<AliceClient> aliceClients, CancellationToken cancellationToken)
		{
			async Task<AliceClient?> RegisterInputTask(AliceClient aliceClient)
			{
				try
				{
					await aliceClient.RegisterInputAsync(cancellationToken).ConfigureAwait(false);
					return aliceClient;
				}
				catch (Exception e)
				{
					Logger.LogWarning($"Round ({aliceClient.RoundId}), Alice ({aliceClient.AliceId}): {nameof(AliceClient.RegisterInputAsync)} failed, reason:'{e}'.");
					return default;
				}
			}

			var registerRequests = aliceClients.Select(RegisterInputTask);
			var completedRequests = await Task.WhenAll(registerRequests).ConfigureAwait(false);

			return completedRequests.Where(x => x is not null).Cast<AliceClient>().ToList();
		}

		private async Task<List<AliceClient>> ConfirmConnectionsAsync(IEnumerable<AliceClient> aliceClients, DependencyGraph graph, TimeSpan connectionConfirmationTimeout, CancellationToken cancellationToken)
		{
			async Task<AliceClient?> ConfirmConnectionTask(AliceClient aliceClient, RequestNode node)
			{
				// TODO s/u(?=long)//
				// is OrderBy required? hashset does not guarantee order stability
				var amountsToRequest = graph.OutEdges(node, CredentialType.Amount).Select(e => e.Value).Cast<long>();
				var vsizesToRequest = graph.OutEdges(node, CredentialType.Vsize).Select(e => e.Value).Cast<long>();

				try
				{
					await aliceClient.ConfirmConnectionAsync(connectionConfirmationTimeout, amountsToRequest, vsizesToRequest, cancellationToken).ConfigureAwait(false);
					return aliceClient;
				}
				catch (Exception e)
				{
					Logger.LogWarning($"Round ({aliceClient.RoundId}), Alice ({aliceClient.AliceId}): {nameof(AliceClient.ConfirmConnectionAsync)} failed, reason:'{e}'.");
					return default;
				}
			}

			var confirmationRequests = Enumerable.Zip(aliceClients, graph.Inputs, ConfirmConnectionTask);
			var completedRequests = await Task.WhenAll(confirmationRequests).ConfigureAwait(false);

			// TODO re-decompose, and re-resolve dependencies on any failure,
			// since the graph is no longer valid with some edges missing.
			if (completedRequests.Any(x => x is null))
			{
				throw new NotImplementedException("input confirmation failure not yet handled");
			}

			return completedRequests.Cast<AliceClient>().ToList();
		}

		private IEnumerable<Money> DecomposeAmounts(FeeRate feeRate)
		{
			return Coins.Select(c => c.Amount - feeRate.GetFee(c.ScriptPubKey.EstimateInputVsize()));
		}

		private async Task RegisterOutputsAsync(
			IEnumerable<BobClient> bobClients,
			IEnumerable<(TxOut Output, Credential[] RealAmountCredentials, Credential[] RealVsizeCredentials)> outputsWithCredentials,
			CancellationToken cancellationToken)
		{
			async Task<TxOut?> RegisterOutputTask(BobClient bobClient, TxOut output, Credential[] realAmountCredentials, Credential[] realVsizeCredentials)
			{
				try
				{
					await bobClient.RegisterOutputAsync(output.Value, output.ScriptPubKey, realAmountCredentials, realVsizeCredentials, cancellationToken).ConfigureAwait(false);
					return output;
				}
				catch (Exception e)
				{
					Logger.LogWarning($"Round ({bobClient.RoundId}), Bob ({{output.ScriptPubKey}}): {nameof(BobClient.RegisterOutputAsync)} failed, reason:'{e}'.");
					return default;
				}
			}

			var outputRegisterRequests = bobClients.Zip(
					outputsWithCredentials,
					(bobClient, data) => RegisterOutputTask(bobClient, data.Output, data.RealAmountCredentials, data.RealVsizeCredentials));

			await Task.WhenAll(outputRegisterRequests).ConfigureAwait(false);
		}

		private BobClient CreateBobClient(RoundState roundState)
		{
			return new BobClient(
				roundState.Id,
				new(
					roundState.CreateAmountCredentialClient(ZeroAmountCredentialPool, SecureRandom),
					roundState.CreateVsizeCredentialClient(ZeroVsizeCredentialPool, SecureRandom),
					ArenaRequestHandler));
		}

		private bool SanityCheck(IEnumerable<(Money Value, Script ScriptPubKey)> expectedOutputs, Transaction unsignedCoinJoinTransaction)
		{
			var coinJoinOutputs = unsignedCoinJoinTransaction.Outputs.Select(o => (o.Value, o.ScriptPubKey));
			return coinJoinOutputs.IsSuperSetOf(expectedOutputs);
		}

		private async Task SignTransactionAsync(IEnumerable<AliceClient> aliceClients, Transaction unsignedCoinJoinTransaction, CancellationToken cancellationToken)
		{
			async Task<AliceClient?> SignTransactionTask(AliceClient aliceClient)
			{
				try
				{
					await aliceClient.SignTransactionAsync(unsignedCoinJoinTransaction, cancellationToken).ConfigureAwait(false);
					return aliceClient;
				}
				catch (Exception e)
				{
					Logger.LogWarning($"Round ({aliceClient.RoundId}), Alice ({{aliceClient.AliceId}}): {nameof(AliceClient.SignTransactionAsync)} failed, reason:'{e}'.");
					return default;
				}
			}

			var signingRequests = aliceClients.Select(SignTransactionTask);
			await Task.WhenAll(signingRequests).ConfigureAwait(false);
		}
	}
}
