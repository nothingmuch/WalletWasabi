using NBitcoin;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WalletWasabi.Crypto;
using WalletWasabi.Crypto.ZeroKnowledge;
using WalletWasabi.Helpers;
using WalletWasabi.Logging;
using WalletWasabi.WabiSabi.Backend.Models;

namespace WalletWasabi.WabiSabi.Client
{
	public class AliceClient
	{
		public AliceClient(uint256 roundId, ArenaClient arenaClient, Coin coin, FeeRate feeRate, BitcoinSecret bitcoinSecret)
		{
			AliceId = CalculateHash(coin, bitcoinSecret, roundId);
			RoundId = roundId;
			ArenaClient = arenaClient;
			Coin = coin;
			FeeRate = feeRate;
			BitcoinSecret = bitcoinSecret;
			IssuedAmountCredentials = Array.Empty<Credential>();
			IssuedVsizeCredentials = Array.Empty<Credential>();
		}

		public uint256 AliceId { get; }
		public uint256 RoundId { get; }
		private ArenaClient ArenaClient { get; }
		public Coin Coin { get; }
		private FeeRate FeeRate { get; }
		private BitcoinSecret BitcoinSecret { get; }
		public IEnumerable<Credential> IssuedAmountCredentials { get; private set; }
		public IEnumerable<Credential> IssuedVsizeCredentials { get; private set; }

		public async Task RegisterInputAsync(CancellationToken cancellationToken)
		{
			var response = await ArenaClient.RegisterInputAsync(RoundId, Coin.Outpoint, BitcoinSecret.PrivateKey, cancellationToken).ConfigureAwait(false);
			var remoteAliceId = response.Value;
			if (AliceId != remoteAliceId)
			{
				throw new InvalidOperationException($"Round ({RoundId}), Local Alice ({AliceId}) was computed as {remoteAliceId}");
			}
			IssuedAmountCredentials = response.IssuedAmountCredentials;
			IssuedVsizeCredentials = response.IssuedVsizeCredentials;
			Logger.LogInfo($"Round ({RoundId}), Alice ({AliceId}): Registered an input.");
		}

		public async Task ConfirmConnectionAsync(TimeSpan connectionConfirmationTimeout, IEnumerable<long> amountsToRequest, IEnumerable<long> vsizesToRequest, long vsizeAllocation, CancellationToken cancellationToken)
		{
			while (!await TryConfirmConnectionAsync(amountsToRequest, vsizesToRequest, vsizeAllocation, cancellationToken).ConfigureAwait(false))
			{
				// await Task.Delay(connectionConfirmationTimeout / 2, cancellationToken).ConfigureAwait(false);
				await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
			}
		}

		private async Task<bool> TryConfirmConnectionAsync(IEnumerable<long> amountsToRequest, IEnumerable<long> vsizesToRequest, long vsizeAllocation, CancellationToken cancellationToken)
		{
			var inputVsize = Coin.ScriptPubKey.EstimateInputVsize();

			var totalFeeToPay = FeeRate.GetFee(Coin.ScriptPubKey.EstimateInputVsize());
			var totalAmount = Coin.Amount;
			var effectiveAmount = totalAmount - totalFeeToPay;

			if (effectiveAmount <= Money.Zero)
			{
				throw new InvalidOperationException($"Round({ RoundId }), Alice({ AliceId}): Not enough funds to pay for the fees.");
			}

			// At the protocol level the balance proof may require requesting
			// credentials for any left over amounts.
			var remainingAmount = effectiveAmount.Satoshi - amountsToRequest.Sum();
			var remainingVsize = vsizeAllocation - ( Coin.ScriptPubKey.EstimateInputVsize() + vsizesToRequest.Sum() );

			// Since non-zero credential requests have a range proof and any
			// remainder is non-zero, prepend it so that can it be omitted below.
			if (remainingAmount != 0)
			{
				amountsToRequest = amountsToRequest.Prepend(remainingAmount);
			}
			if (remainingVsize != 0)
			{
				vsizesToRequest = vsizesToRequest.Prepend(remainingVsize);
			}

			Debug.Assert(IssuedAmountCredentials.Count() == 2);
			Debug.Assert(IssuedVsizeCredentials.Count() == 2);

			var response = await ArenaClient
				.ConfirmConnectionAsync(
					RoundId,
					AliceId,
					amountsToRequest.Where(x => x != 0),
					vsizesToRequest.Where(x => x != 0),
					IssuedAmountCredentials,
					IssuedVsizeCredentials,
					cancellationToken)
				.ConfigureAwait(false);

			// Always update issued credentials, final request will contain
			// requested followed by zero credentials, but before confirmation
			// only zero credentials will be issued.
			// TODO if there's an extra credential, save it for re-planning
			// purposes
			IssuedAmountCredentials = response.IssuedAmountCredentials;
			IssuedVsizeCredentials = response.IssuedVsizeCredentials;

			var isConfirmed = response.Value;

			if (isConfirmed)
			{
				Debug.Assert(IssuedAmountCredentials.Count() == 4);
				Debug.Assert(IssuedVsizeCredentials.Count() == 4);
				if (remainingAmount != 0)
				{
					IssuedAmountCredentials = IssuedAmountCredentials.Skip(1);
				}
				if (remainingVsize != 0)
				{
					IssuedVsizeCredentials = IssuedVsizeCredentials.Skip(1);
				}
			}
			else
			{
				Debug.Assert(IssuedAmountCredentials.Count() == 2);
				Debug.Assert(IssuedVsizeCredentials.Count() == 2);
			}

			return isConfirmed;
		}

		public async Task RemoveInputAsync(CancellationToken cancellationToken)
		{
			await ArenaClient.RemoveInputAsync(RoundId, AliceId, cancellationToken).ConfigureAwait(false);
			Logger.LogInfo($"Round ({RoundId}), Alice ({AliceId}): Inputs removed.");
		}

		public async Task SignTransactionAsync(Transaction unsignedCoinJoin, CancellationToken cancellationToken)
		{
			await ArenaClient.SignTransactionAsync(RoundId, Coin, BitcoinSecret, unsignedCoinJoin, cancellationToken).ConfigureAwait(false);

			Logger.LogInfo($"Round ({RoundId}), Alice ({AliceId}): Posted a signature.");
		}

		private static uint256 CalculateHash(Coin coin, BitcoinSecret bitcoinSecret, uint256 roundId)
		{
			var ownershipProof = OwnershipProof.GenerateCoinJoinInputProof(
				bitcoinSecret.PrivateKey,
				new CoinJoinInputCommitmentData("CoinJoinCoordinatorIdentifier", roundId));
			return new Alice(coin, ownershipProof).Id;
		}
	}
}
