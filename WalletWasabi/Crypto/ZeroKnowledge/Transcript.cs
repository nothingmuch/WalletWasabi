using NBitcoin.Secp256k1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using WalletWasabi.Crypto.Groups;
using WalletWasabi.Crypto.Randomness;
using WalletWasabi.Helpers;

namespace WalletWasabi.Crypto.ZeroKnowledge
{
	// High level API for transcripts of compound Sigma protocol style proofs
	// implements synthetic nonces and Fiat-Shamir challenges

	// TODO introduce delegates for the same phases as IFSProver for individual
	// sub-proofs of conjunctions?
	//
	// it's probably overkill but this could ensure each individual sigma
	// protocol's transcript can must proceed in the right order and are
	// phase-locked (e.g. no statement commitments after nonces were generated)
	public class Transcript
	{
		private Strobe128 _strobe;

		public const string DomainSeparator = "WabiSabi_v1.0";
		public const string StatementTag = "statement";
		public const string ChallengeTag = "challenge";
		public const string NonceTag = "nonce_commitment";

		// public constructor always adds domain separator
		public Transcript()
		{
			_strobe = new Strobe128(DomainSeparator);
		}

		// private constructor used for cloning
		private Transcript(Strobe128 strobe)
		{
			_strobe = strobe;
		}

		public Transcript MakeCopy() =>
			new Transcript(_strobe.MakeCopy());

		public void CommitStatement(IStatement statement)
		{
			_strobe.AddMetaAssociatedData(Encoding.UTF8.GetBytes(StatementTag));
			_strobe.AddMetaAssociatedData(Encoding.UTF8.GetBytes(statement.GetType().Name));

			_strobe.AddMetaAssociatedData(BitConverter.GetBytes(statement.PublicPoints.Count())); // FIXME consistent endianness

			foreach (var (publicPoint, generators) in statement.PublicPoints.ZipForceEqualLength(statement.Generators))
			{
				_strobe.AddAssociatedData(publicPoint.ToBytes());

				// commit generators for each point
				// normally these should all be the same length but it doesn't hurt to commit to that too
				_strobe.AddMetaAssociatedData(BitConverter.GetBytes(generators.Count())); // FIXME consistent endianness
				foreach (var generator in generators)
				{
					_strobe.AddAssociatedData(generator.ToBytes());
				}
			}
		}

		// generate synthetic nonce using current state combined with additional randomness
		public IEnumerable<Scalar> GenerateSecretNonces(IEnumerable<Scalar> secrets, WasabiRandom random)
		{
			// to integrate prior inputs for deterministic component of nonce
			// generation, first clone the state at the current point in the
			// transcript, which should already have the statement tag and public
			// inputs committed.
			var forked = _strobe.MakeCopy();

			// add secret inputs as key material
			foreach (var secret in secrets)
			{
				forked.AddKey(secret.ToBytes());
			}

			// add additional randomness
			forked.AddKey(random.GetBytes(32));

			// FIXME for the general case we need publicPoints.Count() * Witness.Length
			// secret nonces per statement.
			// this method should return a delegate here so that the following lines
			// can be used repeatedly, or given the number of public inputs it could
			// just return IEnumerable<IEnumerable<Scalar>> which is probably uglier.

			// generate a new scalar for each secret using this updated state as a seed
			var randomScalars = new List<Scalar>();
			foreach (var secret in secrets)
			{
				var randomScalar = new Scalar(forked.PRF(32));
				randomScalars.Add(randomScalar);
			}

			return randomScalars;
		}

		public void CommitPublicNonces(IEnumerable<GroupElement> nonces)
		{
			// FIXME loop Guard.False($"{nameof(nonce)}.{nameof(nonce.IsInfinity)}", nonce.IsInfinity);
			_strobe.AddAssociatedData(Encoding.UTF8.GetBytes(NonceTag));

			_strobe.AddMetaAssociatedData(BitConverter.GetBytes(nonces.Count())); // FIXME consistent endianness
			foreach (var nonce in nonces)
			{
				_strobe.AddAssociatedData(nonce.ToBytes());
			}
		}

		// generate Fiat Shamir challenges
		public Scalar GenerateChallenge()
		{
			_strobe.AddMetaAssociatedData(Encoding.UTF8.GetBytes(ChallengeTag));
			return new Scalar(_strobe.PRF(32));
		}
	}
}
