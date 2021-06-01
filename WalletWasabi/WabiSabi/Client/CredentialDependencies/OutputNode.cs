using System.Collections.Generic;
using System.Linq;

namespace WalletWasabi.WabiSabi.Client.CredentialDependencies
{
	public class OutputNode : RequestNode
	{
		public OutputNode(IEnumerable<ulong> values) : base(
			values: values.Select(x => -1 * (long)x),
			maxInDegree: ProtocolConstants.CredentialNumber,
			maxOutDegree: 0,
			maxZeroOnlyOutDegree: 0
		)
		{
		}
	}
}
