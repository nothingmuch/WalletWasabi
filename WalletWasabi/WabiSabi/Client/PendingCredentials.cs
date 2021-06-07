using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nito.AsyncEx;
using WalletWasabi.Crypto.ZeroKnowledge;
using WalletWasabi.WabiSabi.Client.CredentialDependencies;

namespace WalletWasabi.WabiSabi.Client
{
	// represents an ordered list of credential dependenciesfor a given request
	// the cancellation token
	// atomic
	public class SmartRequestNode
	{
		public SmartRequestNode(
			RequestNode requestNode,
			IEnumerable<Task<Credential>> amountCredentialTasks,
			IEnumerable<Task<Credential>> vsizeCredentialTasks,
			Func<IEnumerable<Credential>, IEnumerable<Credential>, Task> actionToRunWhenAllCredentialsHaveArrived
		)
		{
			RequestNode = requestNode;
			AmountCredentialTasks = amountCredentialTasks;
			VsizeCredentialTasks = vsizeCredentialTasks;
			ActionToRunWhenAllCredentialsHaveArrived = actionToRunWhenAllCredentialsHaveArrived;
		}

		public RequestNode RequestNode { get; }
		public Func<IEnumerable<Credential>, IEnumerable<Credential>, Task> ActionToRunWhenAllCredentialsHaveArrived { get; } // FIXME rename

		public IEnumerable<Task<Credential>> AmountCredentialTasks { get; }
		public IEnumerable<Task<Credential>> VsizeCredentialTasks { get; }

		public CancellationToken CancellationToken { get; }

		private AsyncLock AsyncLock { get; } = new AsyncLock();
		private bool TooLateToCancel { get; set; }

		public async Task StartTaskWhenReady() // FIXME rename
		{
			Task.WaitAll(Enumerable.Concat(AmountCredentialTasks, VsizeCredentialTasks).ToArray());

			bool canProceed = false;
			using (await AsyncLock.LockAsync())
			{
				if (!TooLateToCancel)
				{
					TooLateToCancel = true;
					canProceed = true;
				}
			}

			if (canProceed)
			{
				await ActionToRunWhenAllCredentialsHaveArrived(
					AmountCredentialTasks.Select(x => x.Result),
					VsizeCredentialTasks.Select(x => x.Result));
			}
			else
			{
				// TODO how does coinjoin client recover the values from the tasks?
			}
		}
	}
}
