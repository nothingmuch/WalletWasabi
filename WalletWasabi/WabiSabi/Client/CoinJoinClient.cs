using Microsoft.Extensions.Hosting;
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
using WalletWasabi.WabiSabi.Models.Decomposition;
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

		public async Task StartCoinJoinAsync(CancellationToken cancellationToken)
		{
			var roundState = await RoundStatusUpdater.CreateRoundAwaiter(roundState => roundState.Phase == Phase.InputRegistration, cancellationToken).ConfigureAwait(false);
			var constructionState = roundState.Assert<ConstructionState>();

			// Calculate outputs values
			var outputValues = DecomposeAmounts(roundState.FeeRate);

			// Get all locked internal keys we have and assert we have enough.
			Keymanager.AssertLockedInternalKeysIndexed(howMany: Coins.Count());
			var allLockedInternalKeys = Keymanager.GetKeys(x => x.IsInternal && x.KeyState == KeyState.Locked);
			var outputTxOuts = outputValues.Zip(allLockedInternalKeys, (amount, hdPubKey) => new TxOut(amount, hdPubKey.P2wpkhScript));

			List<AliceClient> aliceClients = CreateAliceClients(roundState);

			DependencyGraph dependencyGraph = DependencyGraph.ResolveCredentialDependencies(aliceClients.Select(a => a.Coin), outputTxOuts, roundState.FeeRate, roundState.MaxVsizeAllocationPerAlice);

			// Register coins.
			aliceClients = await RegisterCoinsAsync(aliceClients, cancellationToken).ConfigureAwait(false);

			// Confirm coins.
			var amountsToRequest = dependencyGraph.Inputs.Select(v => dependencyGraph.OutEdges(v, CredentialType.Amount).Select(e => (long)e.Value).Where(x => x != 0));
			var vsizesToRequest = dependencyGraph.Inputs.Select(v => dependencyGraph.OutEdges(v, CredentialType.Vsize).Select(e => (long)e.Value).Where(x => x != 0));
			aliceClients = await ConfirmConnectionsAsync(aliceClients, amountsToRequest, vsizesToRequest, roundState.MaxVsizeAllocationPerAlice, roundState.ConnectionConfirmationTimeout, cancellationToken).ConfigureAwait(false);

			// Re-issuances.
			DependencyGraphResolver dgr = new(dependencyGraph);
			var bobClient = CreateBobClient(roundState);
			var outputCredentials = await dgr.ResolveAsync(aliceClients, bobClient, cancellationToken).ConfigureAwait(false);

			// Output registration.
			roundState = await RoundStatusUpdater.CreateRoundAwaiter(roundState.Id, rs => rs.Phase == Phase.OutputRegistration, cancellationToken).ConfigureAwait(false);
			await RegisterOutputsAsync(bobClient, outputTxOuts, outputCredentials, cancellationToken).ConfigureAwait(false);

			// Signing.
			roundState = await RoundStatusUpdater.CreateRoundAwaiter(roundState.Id, rs => rs.Phase == Phase.TransactionSigning, cancellationToken).ConfigureAwait(false);
			var signingState = roundState.Assert<SigningState>();
			var unsignedCoinJoin = signingState.CreateUnsignedTransaction();

			// Sanity check.
			var effectiveOutputs = outputTxOuts.Select(o => (o.EffectiveCost(roundState.FeeRate), o.ScriptPubKey));
			if (!SanityCheck(effectiveOutputs, unsignedCoinJoin))
			{
				throw new InvalidOperationException($"Round ({roundState.Id}): My output is missing.");
			}

			// Send signature.
			await SignTransactionAsync(aliceClients, unsignedCoinJoin, cancellationToken).ConfigureAwait(false);
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

		private async Task<List<AliceClient>> ConfirmConnectionsAsync(IEnumerable<AliceClient> aliceClients, IEnumerable<IEnumerable<long>> amountsToRequest, IEnumerable<IEnumerable<long>> vsizesToRequest, long vsizeAllocation, TimeSpan connectionConfirmationTimeout, CancellationToken cancellationToken)
		{
			async Task<AliceClient?> ConfirmConnectionTask(AliceClient aliceClient, IEnumerable<long> amountsToRequest, IEnumerable<long> vsizesToRequest)
			{
				try
				{
					await aliceClient.ConfirmConnectionAsync(connectionConfirmationTimeout, amountsToRequest, vsizesToRequest, vsizeAllocation, cancellationToken).ConfigureAwait(false);
					return aliceClient;
				}
				catch (Exception e)
				{
					Logger.LogWarning($"Round ({aliceClient.RoundId}), Alice ({aliceClient.AliceId}): {nameof(AliceClient.ConfirmConnectionAsync)} failed, reason:'{e}'.");
					throw e;
					return default;
				}
			}

			var confirmationRequests = aliceClients.Zip(amountsToRequest, vsizesToRequest, ConfirmConnectionTask);
			var completedRequests = await Task.WhenAll(confirmationRequests).ConfigureAwait(false);

			return completedRequests.Where(x => x is not null).Cast<AliceClient>().ToList();
		}

		private IEnumerable<Money> DecomposeAmounts(FeeRate feeRate)
		{
			var allDenominations = BaseDenominationGenerator.Generate();
			GreedyDecomposer greedyDecomposer = new(allDenominations);
			var amounts = Coins.Select(c => c.EffectiveValue(feeRate));
			var denominations = greedyDecomposer.Decompose(amounts.Sum(), feeRate.GetFee(31)); // TODO constant?
			return denominations;
		}

		private IEnumerable<IEnumerable<(ulong RealAmountCredentialValue, ulong RealVsizeCredentialValue, Money Value)>> CreatePlan(
			IEnumerable<ulong> realAmountCredentialValues,
			IEnumerable<ulong> realVsizeCredentialValues,
			IEnumerable<Money> outputValues)
		{
			yield return realAmountCredentialValues.Zip(realVsizeCredentialValues, outputValues, (a, v, o) => (a, v, o));
		}

		private async Task RegisterOutputsAsync(BobClient bobClient,
			IEnumerable<TxOut> outputTxOuts,
			List<(Money Amount, Credential[] AmounCreds, Credential[] VsizeCreds)> outputCredentials,
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

			List<(TxOut Output, Credential[] RealAmountCredentials, Credential[] RealVsizeCredentials)> outputWithCredentials = new();
			var remainingCredentials = outputCredentials.ToList();

			foreach (var txOut in outputTxOuts)
			{
				var creds = remainingCredentials.First(op => op.Amount == txOut.Value);
				outputWithCredentials.Add((txOut, creds.AmounCreds, creds.VsizeCreds));

				// Make sure to not use the same credentials twice.
				remainingCredentials.Remove(creds);
			}

			var outputRegisterRequests = outputWithCredentials.Select(output => RegisterOutputTask(bobClient, output.Output, output.RealAmountCredentials, output.RealVsizeCredentials));

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
