using NBitcoin;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WalletWasabi.Crypto.ZeroKnowledge;

namespace WalletWasabi.WabiSabi.Client
{
	public class BobClient
	{
		public BobClient(uint256 roundId, ArenaClient arenaClient)
		{
			RoundId = roundId;
			ArenaClient = arenaClient;
		}

		public uint256 RoundId { get; }
		private ArenaClient ArenaClient { get; }

		public async Task RegisterOutputAsync(
			Money amount,
			Script scriptPubKey,
			IEnumerable<Credential> amountCredentialsTooPresent,
			IEnumerable<Credential> vsizeCredentialsToPresent,
			CancellationToken cancellationToken)
			=> await ArenaClient.RegisterOutputAsync(
				RoundId,
				amount.Satoshi,
				scriptPubKey,
				amountCredentialsTooPresent,
				vsizeCredentialsToPresent,
				cancellationToken).ConfigureAwait(false);

		public async Task<(IEnumerable<Credential> IssuedAmountCredentials, IEnumerable<Credential> IssuedVsizeCredentials)> ReissueCredentialsAsync(
			IEnumerable<long> amountsToRequest,
			IEnumerable<long> vsizesToRequest,
			IEnumerable<Credential> amountCredentialsToPresent,
			IEnumerable<Credential> vsizeCredentialsToPresent,
			CancellationToken cancellationToken)
		{
			// At the protocol level the balance proof may require requesting
			// credentials for any left over amounts.
			var remainingAmount = amountCredentialsToPresent.Sum(x => (long)x.Amount.ToUlong()) - amountsToRequest.Sum();
			var remainingVsize = vsizeCredentialsToPresent.Sum(x => (long)x.Amount.ToUlong()) - vsizesToRequest.Sum();

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

			var response = await ArenaClient.ReissueCredentialAsync(
				RoundId,
				amountsToRequest,
				vsizesToRequest,
				amountCredentialsToPresent,
				vsizeCredentialsToPresent,
				cancellationToken)
				.ConfigureAwait(false);

			return (response.IssuedAmountCredentials.Skip(remainingAmount == 0 ? 0 : 1), response.IssuedVsizeCredentials.Skip(remainingVsize == 0 ? 0 : 1));
		}
	}
}
