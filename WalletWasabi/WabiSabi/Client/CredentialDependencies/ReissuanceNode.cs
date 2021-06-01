using System.Linq;

namespace WalletWasabi.WabiSabi.Client.CredentialDependencies
{
	public class ReissuanceNode : RequestNode
	{
		public ReissuanceNode() :base (
			values: Enumerable.Repeat(0L, ProtocolConstants.CredentialNumber),
			maxInDegree: ProtocolConstants.CredentialNumber,
			maxOutDegree: ProtocolConstants.CredentialNumber,
			maxZeroOnlyOutDegree: ProtocolConstants.CredentialNumber * (ProtocolConstants.CredentialNumber - 1)
		)
		{
		}
	}
}
