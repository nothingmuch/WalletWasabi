using NBitcoin.Secp256k1;
using WalletWasabi.Crypto;
using WalletWasabi.Crypto.Groups;
using WalletWasabi.Crypto.Randomness;
using WalletWasabi.Crypto.ZeroKnowledge;
using WalletWasabi.Crypto.ZeroKnowledge.NonInteractive;
using Xunit;

namespace WalletWasabi.Tests.UnitTests.Crypto.ZeroKnowledge
{
	public class CredentialTests
	{
		[Fact]
		public void CredentialIssuance()
		{
			var rnd = new SecureRandom();
			var sk = new CoordinatorSecretKey(rnd);

			var a = Scalar.One;
			var r = rnd.GetScalar();
			var ma = a * Generators.Gg + r * Generators.Gh;
			var t = rnd.GetScalar();
			var (mac, proof) = IssueCredential(sk, ma, t, rnd);
			Assert.True(VerifyCredentialIssuance(sk.ComputeCoordinatorParameters(), ma, mac, proof));
			Assert.False(VerifyCredentialIssuance(sk.ComputeCoordinatorParameters(), ma + Generators.Gg, mac, proof));
		}

		public static (MAC, Proof) IssueCredential(CoordinatorSecretKey sk, GroupElement ma,  Scalar t, WasabiRandom random)
		{
			var mac = MAC.ComputeMAC(sk, ma, t);
			var verifier = Proofs.IssuerParameters(mac, sk.ComputeCoordinatorParameters(), ma);
			var proof = Proofs.CreateProof(verifier, new ScalarVector(sk.W, sk.Wp, sk.X0, sk.X1, sk.Ya), random);
			return (mac, proof);
		}

		public static bool VerifyCredentialIssuance(CoordinatorParameters iparams, GroupElement ma, MAC mac, Proof proof)
			=> Proofs.CheckProof(Proofs.IssuerParameters(mac, iparams, ma), proof);
	}
}
