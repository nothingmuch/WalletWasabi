using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NBitcoin;
using WalletWasabi.Crypto.ZeroKnowledge;
using WalletWasabi.Helpers;

namespace WalletWasabi.WabiSabi.Client
{
	public class SmartRequestNode
	{
		public SmartRequestNode(
			IEnumerable<Task<Credential>> inputAmountCredentialTasks,
			IEnumerable<Task<Credential>> inputVsizeCredentialTasks,
			IEnumerable<TaskCompletionSource<Credential>> outputAmountCredentialTasks,
			IEnumerable<TaskCompletionSource<Credential>> outputVsizeCredentialTasks)
		{
			InputAmountCredentialTasks = Guard.InRange(nameof(inputAmountCredentialTasks), inputAmountCredentialTasks, 2, 2);
			InputVsizeCredentialTasks = Guard.InRange(nameof(inputVsizeCredentialTasks), inputVsizeCredentialTasks, 2, 2);
			OutputAmountCredentialTasks = Guard.InRange(nameof(outputAmountCredentialTasks), outputAmountCredentialTasks, 0, 4);
			OutputVsizeCredentialTasks = Guard.InRange(nameof(outputVsizeCredentialTasks), outputVsizeCredentialTasks, 0, 4);
		}

		public IEnumerable<Task<Credential>> InputAmountCredentialTasks { get; }
		public IEnumerable<Task<Credential>> InputVsizeCredentialTasks { get; }
		public IEnumerable<TaskCompletionSource<Credential>> OutputAmountCredentialTasks { get; }
		public IEnumerable<TaskCompletionSource<Credential>> OutputVsizeCredentialTasks { get; }

		public async Task StartReissueAsync(BobClient bobClient, IEnumerable<long> amountsToRequest, IEnumerable<long> vsizesToRequest, CancellationToken cancellationToken)
		{
			await Task.WhenAll(InputAmountCredentialTasks.Concat(InputVsizeCredentialTasks)).ConfigureAwait(false);

			IEnumerable<Credential> amountCredentialsToPresent = InputAmountCredentialTasks.Select(x => x.Result);
			IEnumerable<Credential> vsizeCredentialsToPresent = InputVsizeCredentialTasks.Select(x => x.Result);

			(IEnumerable<Credential> issuedAmountCredentials, IEnumerable<Credential> issuedVsizeCredentials) = await bobClient.ReissueCredentialsAsync(
				amountsToRequest,
				vsizesToRequest,
				amountCredentialsToPresent,
				vsizeCredentialsToPresent,
				cancellationToken).ConfigureAwait(false);

			foreach ((TaskCompletionSource<Credential> tcs, Credential credential) in OutputAmountCredentialTasks.Zip(issuedAmountCredentials))
			{
				tcs.SetResult(credential);
			}

			foreach ((TaskCompletionSource<Credential> tcs, Credential credential) in OutputVsizeCredentialTasks.Zip(issuedVsizeCredentials))
			{
				tcs.SetResult(credential);
			}
		}

		public async Task StartRegisterOutputAsync(BobClient bobClient, TxOut txOut, CancellationToken cancellationToken)
		{
			await Task.Delay(3000, cancellationToken);
			throw new NotImplementedException(string.Join(" ", InputAmountCredentialTasks.Concat(InputVsizeCredentialTasks).Select(t => t.Status)));
			await Task.WhenAll(InputAmountCredentialTasks.Concat(InputVsizeCredentialTasks)).ConfigureAwait(false);
			Debug.Assert(false, "should AB");

			IEnumerable<Credential> amountCredentialsToPresent = InputAmountCredentialTasks.Select(x => x.Result);
			IEnumerable<Credential> vsizeCredentialsToPresent = InputVsizeCredentialTasks.Select(x => x.Result);

			await bobClient.RegisterOutputAsync(
				txOut.Value,
				txOut.ScriptPubKey,
				amountCredentialsToPresent,
				vsizeCredentialsToPresent,
				cancellationToken).ConfigureAwait(false);
		}
	}
}
