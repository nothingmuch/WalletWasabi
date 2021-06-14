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
using WalletWasabi.WabiSabi.Backend.PostRequests;
using WalletWasabi.WabiSabi.Crypto;
using WalletWasabi.WabiSabi.Models;

namespace WalletWasabi.WabiSabi.Client
{
	public class ArenaClient
	{
		public ArenaClient(
			WabiSabiClient amountCredentialClient,
			WabiSabiClient vsizeCredentialClient,
			IWabiSabiApiRequestHandler requestHandler)
		{
			AmountCredentialClient = amountCredentialClient;
			VsizeCredentialClient = vsizeCredentialClient;
			RequestHandler = requestHandler;
		}

		public WabiSabiClient AmountCredentialClient { get; }
		public WabiSabiClient VsizeCredentialClient { get; }
		public IWabiSabiApiRequestHandler RequestHandler { get; }

		public async Task<ArenaResponse<uint256>> RegisterInputAsync(
			uint256 roundId,
			OutPoint outPoint,
			Key key,
			CancellationToken cancellationToken)
		{
			var ownershipProof = OwnershipProof.GenerateCoinJoinInputProof(
				key,
				new CoinJoinInputCommitmentData("CoinJoinCoordinatorIdentifier", roundId));

			var zeroAmountCredentialRequestData = AmountCredentialClient.CreateRequestForZeroAmount();
			var zeroVsizeCredentialRequestData = VsizeCredentialClient.CreateRequestForZeroAmount();

			var inputRegistrationResponse = await RequestHandler.RegisterInputAsync(
				new InputRegistrationRequest(
					roundId,
					outPoint,
					ownershipProof,
					zeroAmountCredentialRequestData.CredentialsRequest,
					zeroVsizeCredentialRequestData.CredentialsRequest),
				cancellationToken).ConfigureAwait(false);

			var zeroAmountCredentials = AmountCredentialClient.HandleResponse(inputRegistrationResponse.AmountCredentials, zeroAmountCredentialRequestData.CredentialsResponseValidation);
			var zeroVsizeCredentials = VsizeCredentialClient.HandleResponse(inputRegistrationResponse.VsizeCredentials, zeroVsizeCredentialRequestData.CredentialsResponseValidation);

			return new(inputRegistrationResponse.AliceId, zeroAmountCredentials, zeroVsizeCredentials);
		}

		public async Task RemoveInputAsync(uint256 roundId, uint256 aliceId, CancellationToken cancellationToken)
		{
			await RequestHandler.RemoveInputAsync(new InputsRemovalRequest(roundId, aliceId), cancellationToken).ConfigureAwait(false);
		}

		public async Task<ArenaResponse> RegisterOutputAsync(
			uint256 roundId,
			long amount,
			Script scriptPubKey,
			IEnumerable<Credential> amountCredentialsToPresent,
			IEnumerable<Credential> vsizeCredentialsToPresent,
			CancellationToken cancellationToken)
		{
			Guard.InRange(nameof(amountCredentialsToPresent), amountCredentialsToPresent, AmountCredentialClient.NumberOfCredentials, AmountCredentialClient.NumberOfCredentials);
			Guard.InRange(nameof(vsizeCredentialsToPresent), vsizeCredentialsToPresent, VsizeCredentialClient.NumberOfCredentials, VsizeCredentialClient.NumberOfCredentials);

			var presentedAmount = amountCredentialsToPresent.Sum(x => (long)x.Amount.ToUlong());
			Debug.Assert(presentedAmount == amount);
			var (realAmountCredentialRequest, realAmountCredentialResponseValidation) = AmountCredentialClient.CreateRequest(
				new[] { presentedAmount - amount }, // TODO remove
				amountCredentialsToPresent,
				cancellationToken);

			var presentedVsize = vsizeCredentialsToPresent.Sum(x => (long)x.Amount.ToUlong());
			var (realVsizeCredentialRequest, realVsizeCredentialResponseValidation) = VsizeCredentialClient.CreateRequest(
				new[] { presentedVsize - scriptPubKey.EstimateOutputVsize() }, // TODO remove
				vsizeCredentialsToPresent,
				cancellationToken);

			var outputRegistrationResponse = await RequestHandler.RegisterOutputAsync(
				new OutputRegistrationRequest(
					roundId,
					scriptPubKey,
					realAmountCredentialRequest,
					realVsizeCredentialRequest),
				cancellationToken).ConfigureAwait(false);

			var realAmountCredentials = AmountCredentialClient.HandleResponse(outputRegistrationResponse.AmountCredentials, realAmountCredentialResponseValidation);
			var realVsizeCredentials = VsizeCredentialClient.HandleResponse(outputRegistrationResponse.VsizeCredentials, realVsizeCredentialResponseValidation);

			// TODO remove
			return new(realAmountCredentials, realVsizeCredentials);
		}

		public async Task<ArenaResponse> ReissueCredentialAsync(
			uint256 roundId,
			IEnumerable<long> amountsToRequest,
			IEnumerable<long> vsizesToRequest,
			IEnumerable<Credential> amountCredentialsToPresent,
			IEnumerable<Credential> vsizeCredentialsToPresent,
			CancellationToken cancellationToken)
		{
			Guard.InRange(nameof(amountCredentialsToPresent), amountCredentialsToPresent, AmountCredentialClient.NumberOfCredentials, AmountCredentialClient.NumberOfCredentials);
			Guard.InRange(nameof(vsizeCredentialsToPresent), vsizeCredentialsToPresent, VsizeCredentialClient.NumberOfCredentials, VsizeCredentialClient.NumberOfCredentials);

			var presentedAmount = amountCredentialsToPresent.Sum(x => (long)x.Amount.ToUlong());
			if (amountsToRequest.Sum() != presentedAmount)
			{
				throw new InvalidOperationException($"Reissuence amounts must equal with the sum of the presented ones.");
			}

			var (realAmountCredentialRequest, realAmountCredentialResponseValidation) = AmountCredentialClient.CreateRequest(
				amountsToRequest,
				amountCredentialsToPresent,
				cancellationToken);

			var presentedVsize = vsizeCredentialsToPresent.Sum(x => (long)x.Amount.ToUlong());
			var (realVsizeCredentialRequest, realVsizeCredentialResponseValidation) = VsizeCredentialClient.CreateRequest(
				vsizesToRequest,
				vsizeCredentialsToPresent,
				cancellationToken);

			var zeroAmountCredentialRequestData = AmountCredentialClient.CreateRequestForZeroAmount();
			var zeroVsizeCredentialRequestData = VsizeCredentialClient.CreateRequestForZeroAmount();

			var reissuanceResponse = await RequestHandler.ReissueCredentialAsync(
				new ReissueCredentialRequest(
					roundId,
					realAmountCredentialRequest,
					realVsizeCredentialRequest,
					zeroAmountCredentialRequestData.CredentialsRequest,
					zeroVsizeCredentialRequestData.CredentialsRequest),
				cancellationToken).ConfigureAwait(false);

			var realAmountCredentials = AmountCredentialClient.HandleResponse(reissuanceResponse.RealAmountCredentials, realAmountCredentialResponseValidation);
			var realVsizeCredentials = VsizeCredentialClient.HandleResponse(reissuanceResponse.RealVsizeCredentials, realVsizeCredentialResponseValidation);

			var zeroAmountCredentials = AmountCredentialClient.HandleResponse(reissuanceResponse.ZeroAmountCredentials, zeroAmountCredentialRequestData.CredentialsResponseValidation);
			var zeroVsizeCredentials = VsizeCredentialClient.HandleResponse(reissuanceResponse.ZeroVsizeCredentials, zeroVsizeCredentialRequestData.CredentialsResponseValidation);

			return new(realAmountCredentials.Concat(zeroAmountCredentials), realVsizeCredentials.Concat(zeroVsizeCredentials));
		}

		public async Task<ArenaResponse<bool>> ConfirmConnectionAsync(
			uint256 roundId,
			uint256 aliceId,
			IEnumerable<long> amountsToRequest,
			IEnumerable<long> vsizesToRequest,
			IEnumerable<Credential> amountCredentialsToPresent,
			IEnumerable<Credential> vsizeCredentialsToPresent,
			CancellationToken cancellationToken)
		{
			Guard.InRange(nameof(amountsToRequest), amountsToRequest.Where(x => x != 0), 1, ProtocolConstants.CredentialNumber);
			Guard.InRange(nameof(vsizesToRequest), vsizesToRequest.Where(x => x != 0), 1, VsizeCredentialClient.NumberOfCredentials);
			Guard.InRange(nameof(amountsToRequest), amountsToRequest.Where(x => x == 0), 0, 0);
			Guard.InRange(nameof(vsizesToRequest), vsizesToRequest.Where(x => x == 0), 0, 0);
			Guard.InRange(nameof(amountCredentialsToPresent), amountCredentialsToPresent, ProtocolConstants.CredentialNumber, ProtocolConstants.CredentialNumber);
			Guard.InRange(nameof(vsizeCredentialsToPresent), vsizeCredentialsToPresent, ProtocolConstants.CredentialNumber, ProtocolConstants.CredentialNumber);

			var realAmountCredentialRequestData = AmountCredentialClient.CreateRequest(
				amountsToRequest,
				amountCredentialsToPresent,
				cancellationToken);

			var realVsizeCredentialRequestData = VsizeCredentialClient.CreateRequest(
				vsizesToRequest,
				vsizeCredentialsToPresent,
				cancellationToken);

			var zeroAmountCredentialRequestData = AmountCredentialClient.CreateRequestForZeroAmount();
			var zeroVsizeCredentialRequestData = VsizeCredentialClient.CreateRequestForZeroAmount();

			var confirmConnectionResponse = await RequestHandler.ConfirmConnectionAsync(
				new ConnectionConfirmationRequest(
					roundId,
					aliceId,
					zeroAmountCredentialRequestData.CredentialsRequest,
					realAmountCredentialRequestData.CredentialsRequest,
					zeroVsizeCredentialRequestData.CredentialsRequest,
					realVsizeCredentialRequestData.CredentialsRequest),
				cancellationToken).ConfigureAwait(false);

			var zeroAmountCredentials = AmountCredentialClient.HandleResponse(confirmConnectionResponse.ZeroAmountCredentials, zeroAmountCredentialRequestData.CredentialsResponseValidation);
			var zeroVsizeCredentials = VsizeCredentialClient.HandleResponse(confirmConnectionResponse.ZeroVsizeCredentials, zeroVsizeCredentialRequestData.CredentialsResponseValidation);
			Debug.Assert(zeroAmountCredentials.Count() == ProtocolConstants.CredentialNumber);
			Debug.Assert(zeroVsizeCredentials.Count() == ProtocolConstants.CredentialNumber);

			if (confirmConnectionResponse is { RealAmountCredentials: { }, RealVsizeCredentials: { } })
			{
				var realAmountCredentials = AmountCredentialClient.HandleResponse(confirmConnectionResponse.RealAmountCredentials, realAmountCredentialRequestData.CredentialsResponseValidation);
				var realVsizeCredentials = VsizeCredentialClient.HandleResponse(confirmConnectionResponse.RealVsizeCredentials, realVsizeCredentialRequestData.CredentialsResponseValidation);

				Debug.Assert(realAmountCredentials.Count() == ProtocolConstants.CredentialNumber);
				Debug.Assert(realVsizeCredentials.Count() == ProtocolConstants.CredentialNumber);
				return new(true, realAmountCredentials.Concat(zeroAmountCredentials), realVsizeCredentials.Concat(zeroVsizeCredentials));
			}

			return new(false, zeroAmountCredentials, zeroVsizeCredentials);
		}

		public async Task SignTransactionAsync(uint256 roundId, Coin coin, BitcoinSecret bitcoinSecret, Transaction unsignedCoinJoin, CancellationToken cancellationToken)
		{
			if (unsignedCoinJoin.Inputs.Count == 0)
			{
				throw new ArgumentException("No inputs to sign.", nameof(unsignedCoinJoin));
			}

			var signedCoinJoin = unsignedCoinJoin.Clone();
			var txInput = signedCoinJoin.Inputs.AsIndexedInputs().FirstOrDefault(input => input.PrevOut == coin.Outpoint);

			if (txInput is null)
			{
				throw new InvalidOperationException($"Missing input.");
			}

			List<InputWitnessPair> signatures = new();

			signedCoinJoin.Sign(bitcoinSecret, coin);

			if (!txInput.VerifyScript(coin, out var error))
			{
				throw new InvalidOperationException($"Witness is missing. Reason {nameof(ScriptError)} code: {error}.");
			}

			signatures.Add(new InputWitnessPair(txInput.Index, txInput.WitScript));

			await RequestHandler.SignTransactionAsync(new TransactionSignaturesRequest(roundId, signatures), cancellationToken).ConfigureAwait(false);
		}

		public async Task<RoundState[]> GetStatusAsync(CancellationToken cancellationToken)
		{
			return await RequestHandler.GetStatusAsync(cancellationToken).ConfigureAwait(false);
		}
	}
}
