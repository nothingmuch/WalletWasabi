using NBitcoin.Secp256k1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using WalletWasabi.Crypto.Groups;
using WalletWasabi.Crypto.Randomness;
using WalletWasabi.Crypto.ZeroKnowledge;
using WalletWasabi.Crypto.ZeroKnowledge.Transcripting;
using Xunit;

namespace WalletWasabi.Tests.UnitTests.Crypto.ZeroKnowledge
{
	public class TranscriptTests
	{
		[Fact]
		public void BuildThrows()
		{
			var t = new Transcript();

			// Demonstrate when it shouldn't throw.
			t.CommitToStatement(new Statement(Generators.G, Generators.Ga));
			t.CommitToStatement(new Statement(Generators.G, Generators.Ga, Generators.Gg, Generators.Gh));

			// Infinity cannot pass through.
			Assert.ThrowsAny<ArgumentException>(() => t.CommitToStatement(new Statement(Generators.G, GroupElement.Infinity)));
			Assert.ThrowsAny<ArgumentException>(() => t.CommitToStatement(new Statement(GroupElement.Infinity, Generators.Ga)));
			Assert.ThrowsAny<ArgumentException>(() => t.CommitToStatement(new Statement(GroupElement.Infinity, GroupElement.Infinity)));

			Assert.ThrowsAny<ArgumentException>(() => t.CommitToStatement(new Statement(GroupElement.Infinity, Generators.Ga, Generators.Gg, Generators.Gh)));
			Assert.ThrowsAny<ArgumentException>(() => t.CommitToStatement(new Statement(Generators.G, GroupElement.Infinity, Generators.Gg, Generators.Gh)));
			Assert.ThrowsAny<ArgumentException>(() => t.CommitToStatement(new Statement(Generators.G, Generators.Ga, GroupElement.Infinity, Generators.Gh)));
			Assert.ThrowsAny<ArgumentException>(() => t.CommitToStatement(new Statement(Generators.G, Generators.Ga, Generators.Gg, GroupElement.Infinity)));

			// Hash must be 32 bytes.
			new Transcript(Enumerable.Repeat((byte)0, 32).ToArray());
			Assert.ThrowsAny<ArgumentException>(() => new Transcript(Enumerable.Repeat((byte)0, 33).ToArray()));
			Assert.ThrowsAny<ArgumentException>(() => new Transcript(Enumerable.Repeat((byte)0, 31).ToArray()));
		}

		[Fact]
		public void FiatShamir()
		{
			var p = new Transcript().CommitToStatement(new Statement(Generators.G, Generators.Ga));
			var nonce = p.GenerateNonce(Scalar.One);

			p = p.NonceCommitment(nonce * Generators.Gg);

			var v = new Transcript()
				.CommitToStatement(new Statement(Generators.G, Generators.Ga))
				.NonceCommitment(nonce * Generators.Gg);

			Assert.Equal(p.GenerateChallenge().challenge, v.GenerateChallenge().challenge);
		}

		[Fact]
		public void FiatShamirClone()
		{
			var a = new Transcript().CommitToStatement(new Statement(Generators.G, Generators.Gh)); // set up some initial state

			var b = a.CommitToStatement(new Statement(Generators.G, Generators.Ga));
			var c = a.CommitToStatement(new Statement(Generators.G, Generators.Ga));

			Assert.Equal(c.GenerateChallenge().challenge, b.GenerateChallenge().challenge);
		}

		[Fact]
		public void FiatShamirNonces()
		{
			var a = new Transcript();
			a.CommitToStatement(new Statement(Generators.G, Generators.Ga));

			var mra = new MockRandom();
			var rnd1 = new byte[32];
			rnd1[0] = 42;
			mra.GetBytesResults.Add(rnd1);

			var b = new Transcript();
			b.CommitToStatement(new Statement(Generators.G, Generators.Ga));

			var mrb = new MockRandom();

			var rnd2 = new byte[32];
			rnd2[0] = 43;
			mrb.GetBytesResults.Add(rnd2);

			Assert.NotEqual(a.GenerateNonce(Scalar.One, mra), b.GenerateNonce(Scalar.One, mrb));
			Assert.Equal(a.GenerateChallenge().challenge, b.GenerateChallenge().challenge);
		}

		[Fact]
		public void SyntheticNoncesSecretDependence()
		{
			var a = new Transcript();
			a.CommitToStatement(new Statement(Generators.G, Generators.Ga));

			var mra = new MockRandom();
			mra.GetBytesResults.Add(new byte[32]);
			mra.GetBytesResults.Add(new byte[32]);

			var b = new Transcript();
			b.CommitToStatement(new Statement(Generators.G, Generators.Ga));

			var mrb = new MockRandom();
			mrb.GetBytesResults.Add(new byte[32]);
			mrb.GetBytesResults.Add(new byte[32]);

			Assert.Equal(a.GenerateNonce(Scalar.One, mra), b.GenerateNonce(Scalar.One, mrb));
			Assert.NotEqual(a.GenerateNonce(Scalar.Zero, mra), b.GenerateNonce(Scalar.One, mrb));
		}

		[Fact]
		public void SyntheticNoncesPublicDependence()
		{
			var a = new Transcript().CommitToStatement(new Statement(Generators.G, Generators.Ga));

			var mra = new MockRandom();
			mra.GetBytesResults.Add(new byte[32]);

			var b = new Transcript().CommitToStatement(new Statement(Generators.Gg, Generators.Ga));

			var mrb = new MockRandom();
			mrb.GetBytesResults.Add(new byte[32]);

			Assert.NotEqual(a.GenerateNonce(Scalar.One, mra), b.GenerateNonce(Scalar.One, mrb));
		}

		[Fact]
		public void SyntheticNoncesGeneratorDependence()
		{
			var a = new Transcript().CommitToStatement(new Statement(Generators.G, Generators.Ga));

			var mra = new MockRandom();
			mra.GetBytesResults.Add(new byte[32]);

			var b = new Transcript().CommitToStatement(new Statement(Generators.G, Generators.Gg));

			var mrb = new MockRandom();
			mrb.GetBytesResults.Add(new byte[32]);

			Assert.NotEqual(a.GenerateNonce(Scalar.One, mra), b.GenerateNonce(Scalar.One, mrb));
		}

		[Fact]
		public void SyntheticNoncesStatementDependence()
		{
			var tag1 = Encoding.UTF8.GetBytes("statement tag");
			var tag2 = Encoding.UTF8.GetBytes("statement tga");

			var a = new Transcript().CommitToStatement(tag1, Generators.G, Generators.Ga);

			var mra = new MockRandom();
			mra.GetBytesResults.Add(new byte[32]);

			var b = new Transcript().CommitToStatement(tag2, Generators.G, Generators.Ga);

			var mrb = new MockRandom();
			mrb.GetBytesResults.Add(new byte[32]);

			Assert.NotEqual(a.GenerateNonce(Scalar.One, mra), b.GenerateNonce(Scalar.One, mrb));
		}
	}
}
