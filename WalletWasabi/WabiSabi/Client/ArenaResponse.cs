using System.Collections.Generic;
using System.Linq;
using WalletWasabi.Crypto.ZeroKnowledge;

namespace WalletWasabi.WabiSabi.Client
{
	public class ArenaResponse
	{
		public ArenaResponse(IEnumerable<Credential> issuedAmountCredentials, IEnumerable<Credential> issuedVsizeCredentials)
		{
			IssuedAmountCredentials = issuedAmountCredentials.ToArray();
			IssuedVsizeCredentials = issuedVsizeCredentials.ToArray();
		}
		public IEnumerable<Credential> IssuedAmountCredentials { get; }
		public IEnumerable<Credential> IssuedVsizeCredentials { get; }
	}

	public class ArenaResponse<T> : ArenaResponse
	{
		public ArenaResponse(T value, IEnumerable<Credential> realAmountCredentials, IEnumerable<Credential> realVsizeCredentials)
			: base(realAmountCredentials, realVsizeCredentials)
		{
			Value = value;
		}

		public T Value { get; }
	}
}
