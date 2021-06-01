using System.Collections.Generic;
using System.Linq;

namespace WalletWasabi.WabiSabi.Client.CredentialDependencies
{
	public class InputNode : RequestNode
	{
		public InputNode(IEnumerable<ulong> values) : base (
			values: values.Select(x => (long)x),
			maxInDegree: 0,
			maxOutDegree: ProtocolConstants.CredentialNumber,
			maxZeroOnlyOutDegree: ProtocolConstants.CredentialNumber
		)
		{
		}
	}
}
