using NBitcoin.Secp256k1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using WalletWasabi.Crypto.Groups;
using WalletWasabi.Crypto.Randomness;
using WalletWasabi.Helpers;

// Assumes these additional helper functions/overloads:
// - TResult ZipForceEqualLength(IEnumerable<TSecond>, Func<TFirst,TSecond,TResult>)

// Terminology
// - these needs to be made consistent
//   - secret nonce (k), randomScalar
//   - public nonce (R = kG)
//   - publicPoint -> publicInput? publicParameter? "point" is ECC centric, and
//     inconsistent with NBitcoin's GroupElement
// - "Commit" is overloaded with many related meanings and should be avoided in
//   lieu of something more specific (commit to transcript, commit in the sense
//   of a prover comitting before a challenge)

// FIXME update this description after LinearRelation
// tree structure:
// - statement tree, knowledge tree, proof tree - for every compound proof
//   system these have a parallel structures, knowledge tree is a statement
//   tree, and can produce a proof tree, statement tree can verify a proof tree
// - leaves nodes are based on basic sigma protocols and with generic Fiat
//   Shamir transformation: knowledge of representation, discrete log equality,
//   possibly also message equality of Pedersen commitments (TBD). each has its
//   own Statement, Knowledge and Proof (TODO) classes, satisfying interfaces
// - compound nodes are just combinators (AND, OR), and interact with Fiat
//   Shamir transformation more directly. for starters Abe-Ohkubo-Suzuki OR
//   proofs should be implemented unless there are unforeseen problems with
//   sequential composition in which case Cramer-Damgard can be done (simpler
//   because it's a parallel construction). CompoundProof is generic, and
//   there are no witnesses since only leaf nodes actually contain/prove
//   knowledge (TODO)
// - no variables/binding in first iteration (but may be desirable or even
//   necessary for more efficient proofs later), so public inputs and witnesses
//   may need to be repeated multiple times in the leaves. could be optimized in
//   future iterations (e.g. sharing witnesses or responses between sub-proofs).
// - this is deliberately out of scope for now, but with borromean ring
//   signatures we would probably would probably need some kind of "compiler
//   that processes the whole tree first, and with bulletproofs we will
//   definitely need something like that, but the result would be much smaller
//   proofs (in principle it should be able to compile a whole list trees of
//   down to just one bulletproof covering everything in each request/response).


// Directory tree / namespace structure organization:
//
// ZeroKnowledge
// - WabiSabi
//   - Sigma-Rangeproof
//   - Balance Proof
//   - ProofSystems
//     - Basic
//       - Interfaces - IStatement, IKnowledge
//       - LinearRelation
//         - Statement
//         - Knowledge
//    - FiatShamir
//      - Interfaces - IFSProver, IFSVerifier
//      - Transform
//      - Conjunction/AND
//      - Disjunction/OR. one of:
//        - Sequential (Abe-Ohkubo-Suzuki) - more compact, sequential control flow structure
//        - Parallel (Cramer-Damgard) - simpler prover control flow but trickier serialization, larger proofs


namespace WalletWasabi.Crypto.WabiSabi
{
// Compound Proofs used in WabiSabi
//
// issuer params:
//
//     LinearRelation( (w, wp, x0, x1, t, y),
//                     { Cw, Gv - I, V },
//                     { { Gw, Gwp, _O, _O },
//                       { _O, _O, Gx0, Gx1, _O, Ga },
//                       { Gw, _O, U, t*U, M} } )
//
// Credential request attribute range proof.
//
//     AND(LinearRelation((r, b0, b1,  ... b50, r0, r1, ... r50)
//                        { Ma, A0, A1, ..., A50 },
//                        { { Gh, 2^0*Gg, 2^1*Gg, ..., 2^50*Gg, _O, _O, ... _O },
//                          { _O, 2^0*Gg, _O, ..., _O, Gh, _O, ..., _O },
//                          { _O, _O, 2^1*Gg, ..., _O, _O, Gh, ..., _O },
//                          { _O, _O, _O, ..., 2^50*_O, _O, _O, ..., Gh } })
//         OR(LinearRelation((r0): { A0 }, { r0 * Gh }), LinearRelation((r0): { A0 - Gg }, { r0*Gh })),
//         OR(LinearRelation((r1): { A1 }, { r1 * Gh }), LinearRelation((r1): { A1 - Gg }, { r1*Gh })),
//         ...
//         OR(LinearRelation((r50): { A50 }, { r50 * Gh }), LinearRelation((r50): { A50 - Gg }, { r50*Gh })))
//
// Balance proof (requests - presentations)
//
//     LinearRelation( (z, deltaR), { B }, { { Ga, Gh }  })
//
// Serial number DLEQ:
//
//     LinearRelation( (z, a, r), { C_a, S}, { { Ga, Gg, Gh }, { _O, _O, Gs} } )
//
// MAC show:
//
//     LinearRelation( (z, z0, t), { Z, Cx1 }, { { I, _O, _O }, { Cx0, Gx0, Gx1 } } )
}

namespace WalletWasabi.Crypto.ZeroKnowledge
{
	// interface for basic proof systems
	// a statement represents all information needed to verify or simulate a proof
	// as well as metadata for composing proofs together:
	// - the generators used in the statement
	// - the public inputs
	public interface IStatement : IVerifier { // optionally ISimulator
		IEnumerable<GroupElement> PublicPoints { get; }
		IEnumerable<IEnumerable<GroupElement>> Generators { get; }
	}

	// This interface can be removed if simulators implementations are
	// mandatory, allowing any statement to be used in an OR proof
	public interface ISimulatableStatement : IStatement, ISimulator {}

	// interface for basic proof systems
	// knowledge = (statement, witness)
	// represents all information to generate a proof
	public interface IKnowledge : IProver
	{
		IStatement Statement { get; }
		IEnumerable<Scalar> Witness { get; }
	}

	// given a proof (nonce commitments & responses), verify them against a trusted challenge
	public interface IVerifier
	{
		bool CheckVerificationEquation(IEnumerable<GroupElement> publicNonces, Scalar challenge, IEnumerable<IEnumerable<Scalar>> responses);
	}

	// given a statement, a challenge and a response, simulate a nonce commitment
	public interface ISimulator
	{
		IEnumerable<GroupElement> SimulatePublicNonces(Scalar challenge, IEnumerable<IEnumerable<Scalar>> responses);
	}

	// given a challenge and trusted nonce secrets, generate responses to complete the proof
	public interface IProver
	{
		IEnumerable<Scalar> RespondToChallenge(Scalar challenge, IEnumerable<IEnumerable<Scalar>> secretNonces);
	}

	// proof tree
	public interface IProof {}
	public class CompoundProof : List<IProof>, IProof {}
	public class Proof : IProof {
		public Proof(IEnumerable<GroupElement> publicNonces, IEnumerable<Scalar> responses)
		{
			// TODO generalize to IEnumerable? move these sanity checks to FiatShamirTransform?
			// Guard.False($"{nameof(publicNonces)}.{nameof(publicNonces.IsInfinity)}", publicNonces.IsInfinity);

			Guard.NotNullOrEmpty(nameof(responses), responses);
			foreach (var response in responses)
			{
				Guard.False($"{nameof(response)}.{nameof(response.IsZero)}", response.IsZero);
			}

			PublicNonces = publicNonces;
			Responses = responses;
		}

		public IEnumerable<GroupElement> PublicNonces { get; }
		public IEnumerable<Scalar> Responses { get; }
	}

	//Top level API for compound statements
	public static class Prover {
		public static IProof CreateProof(IFSProver prover, WasabiRandom random) {
			var transcript = new Transcript();

			var transcriptCopy = transcript.Clone();

			var CommitToNonces = prover.CommitToStatements(transcript);
			var RespondToChallenge = CommitToNonces(random);
			var proof = RespondToChallenge();

			// FIXME how to get verifier out of IFSProver?
			if (!(this as IVerifier).Verify(transcriptCopy, proof, prover as IFSVerifier))
			{
				throw new InvalidOperationException($"{nameof(CreateProof)} or {nameof(Verifier.Verify)} is incorrectly implemented. Proof was built, but verification failed.");
			}
			return proof;
		}
	}

	// TODO IFSVerifier

	// IFSProver splits proving in 3 phases
	public interface IFSProver {
		// The first phase is to commit to all the statements, so that synthetic
		// nonce generation for every sub-proof depends on the statement as a whole
		CommitToNonces CommitToStatements(Transcript transcript);
	}

	// The second phase is to generate and commit to all the nonces
	public delegate RespondToChallenge CommitToNonces(WasabiRandom random);

	// The thid phase is to generate challenges and respond to them
	public delegate IProof RespondToChallenge();


	// Implements Fiat-Shamir transform on a Sigma protocol, converting an IKnowledge to an IFSProver
	public class FSTransform : IFSProver
	{
		private IKnowledge knowledge;

		public FSTransform(IKnowledge k) {
			knowledge = k;
		}

		public CommitToNonces CommitToStatements(Transcript transcript)
		{
			transcript.CommitStatement(knowledge.Statement);

			return delegate(WasabiRandom random)
			{
				return this.CommitToNonces(transcript, random);
			};
		}

		private RespondToChallenge CommitToNonces(Transcript transcript,  WasabiRandom random)
		{
			var publicNonces = new List<GroupElement>();
			var secretNonces = new List<IEnumerable<Scalar>>();

			foreach (var (publicPoint, generators) in knowledge.Statement.PublicPoints.ZipForceEqualLength(knowledge.Statement.Generators))
			{
				// FIXME some code duplication with Or::CreteProof, can be refactored (FS base class? use MultiplyGenerators to Statement interface?)
				var publicNonce = GroupElement.Infinity;

				var pointSecretNonces = transcript.GenerateSecretNonces(knowledge.Witness, random);
				secretNonces.Add(pointSecretNonces);

				foreach (var (secretNonce, generator) in pointSecretNonces.ZipForceEqualLength<Scalar, GroupElement>(generators))
				{
					publicNonce += secretNonce * generator;
				}

				publicNonces.Add(publicNonce);
			}

			transcript.CommitPublicNonces(publicNonces);

			return delegate()
			{
				return this.Respond(transcript, publicNonces, secretNonces);
			};
		}

		private Proof Respond(Transcript transcript, IEnumerable<GroupElement> nonces, IEnumerable<IEnumerable<Scalar>> secretNonces)
		{
			var challenge = transcript.GenerateChallenge();

			var responses = knowledge.RespondToChallenge(challenge, secretNonces);

			var proof = new Proof(nonces, responses);

			return proof;
		}
	}

	// Disjunction, Abe-Okhubo-Suzuki OR proof
	// TODO corresponding verifier
	public class Or : IFSProver
	{
		// when constructing disjunction knowlege tree, require 1 prover and n-1 simulators
		IKnowledge Knowledge {get;}
		IEnumerable<ISimulatableStatement> Statements {get;}

		public Or(IKnowledge knowledge, IEnumerable<ISimulatableStatement> statements)
		{
			// check that known.Statement appears in statements exactly once
			// how make sure order of statements does not reveal which statement is
			// known? canonical ordering?
			Guard.Same("knowledge must be about a statement which appears exactly once in the disjunction.", Statements.Select(stmt => System.Object.ReferenceEquals(stmt, Knowledge.Statement)).Count(), 1);

			Knowledge = knowledge;
			Statements = statements;
		}

		public CommitToNonces CommitToStatements(Transcript transcript)
		{
			foreach (var stmt in Statements)
			{
				transcript.CommitStatement(stmt);
			}

			return delegate(WasabiRandom random)
			{
				return this.CreateProof(transcript, random);
			};
		}

		// this proof also sort of breaks the abstraction of the IFSProver
		// interface since challenges are already derived in the nonce phase and do
		// not depend on the public nonces of subsequent proofs in any containing
		// conjunction.
		private RespondToChallenge CreateProof(Transcript transcript, WasabiRandom random)
		{
			// generate secret nonces and derive public nonces for the statement for
			// which there is a witness this is the only nonce that is created before
			// the response, the other statement are simulated instead.
			var realPublicNonces = new List<GroupElement>(); // once public nonce per public input
			var secretNonces = new List<IEnumerable<Scalar>>(); // one secret nonce per witness secret per public input
			foreach (var (publicPoint, generators) in Knowledge.Statement.PublicPoints.ZipForceEqualLength(Knowledge.Statement.Generators))
			{
				// FIXME some code duplication with FSTransform::CommitToNonces, can be refactored (FS base class? use MultiplyGenerators to Statement interface?)
				var publicNonce = GroupElement.Infinity;

				var pointSecretNonces = transcript.GenerateSecretNonces(Knowledge.Witness, random);
				secretNonces.Add(pointSecretNonces);

				foreach (var (secretNonce, generator) in pointSecretNonces.ZipForceEqualLength<Scalar, GroupElement>(generators))
				{
					publicNonce += secretNonce * generator;
				}

				realPublicNonces.Add(publicNonce);
			}

			// These list keeps track of the public nonce points and the responses in
			// the order that the prover generates them. Note that these lists are not
			// aligned, if the statement has 3 alternatives, (a, b, c) and a witness
			// for b is known, the the order will be:
			// - nonces: b, c, a
			// - responses: c, a, b
			var noncesInProverOrder = new List<IEnumera<GroupElement>>(realPublicNonces);
			var responsesInProverOrder = new List<IEnumera<GroupElement>>();

			// split statement list at the point where a witness is known
			var preceding = Statements.TakeWhile(x => !Object.ReferenceEquals(x, Knowledge.Statement));
			var remaining = Statements.SkipWhile(x => !Object.ReferenceEquals(x, Knowledge.Statement));
			var following = remaining.Skip(1);

			// simulate statements beginning after the known statement and looping back around
			foreach (var statement in following.Concat(preceding))
			{
				// AOS proofs have a cyclic dependency structure between the challenges
				// and public nonces of the sub-statements. without knowledge of at
				// least one witness this cycle cannot be created without breaking the
				// hash function. each challenge is derived from the hash of the nonces
				// for a sibling statement. Since the statement with a witness must
				// always be the start point, the transcript must be forked, otherwise
				// the verifier would have to compute the challenges in the same order
				// and would therefore learn which is the real statement.
				var fork = transcript.MakeCopy();
				fork.CommitPublicNonce(noncesInProverOrder.Last());

				// the challenge for each statement is the hash of the previous
				// statement's public nonce.
				var challenge = fork.GenerateChallenge();

				// the responses are simulated as random values
				// TODO rename from GenerateSecretNonces to something more general? add
				// an alias? these are not secret but must be unpredictable
				responsesInProverOrder.Add(fork.GenerateSecretNonces(Knowledge.Witness, random));

				// derive public nonce value without a witness given the challenge and responses
				noncesInProverOrder.Add(statement.SimulatePublicNonces(challenge, simulatedResponses));
			}

			// Finally prove the statement with the real nonce, closing the cycle of
			// challenges and responses.
			var fork = transcript.MakeCopy();
			fork.CommitPublicNonce(allPublicNonces.Last());
			var challenge = fork.GenerateChallenge();
			responsesInProverOrder.Add(Knowledge.RespondToChallenge(challenge, secretNonces));

			// Put the public nonces in the order that the verifier expects them to be.
			// the rotation point for the nonces is one greater because the known
			// statement's nonce is generated before everything and appears first in
			// prover order else but the response is generated after everything else,
			// so it appears last in the response list.
			var offset = following.Count();
			var allPublicNonces = noncesInProverOrder.Skip(1+offset).Concat(noncesInProverOrder.Take(1+offset));
			var allResponses = responsesInProverOrder.Skip(offset).Concat(responsesInProverOrder.Take(offset));

			// Now that all nonces are known, we can finally commit to them.
			// Neither this nor any subsequent commitments has any effect on the
			// challenges for the sub-statements of the OR proof, but will play a part
			// in determining the challenges for any subsequent statements in a
			// containing conjunction (And).
			transcript.CommitPublicNonces(IEnumerable<GroupElement> allPublicNonces);

			return delegate()
			{
				// Note that unlike FSTransform, challenges and responses are not
				// computed step, as they were already computed before. This somewhat
				// violates the FSProver abstractions.
				return allPublicNonces.Zip(allResponses, (nonces, responses) => new Proof(nonces, responses)) as CompoundProof;
			};
		}
	}

	// Conjunction, delegates the phases of IFSProver to a number of IFSProver
	// children so that their challenges are bound together (effectively a single
	// challenge)
	// TODO corresponding verifier
	public class And : IFSProver
	{
		IEnumerable<IFSProver> Components {get;}

		public CommitToNonces CommitToStatements(Transcript transcript)
		{
			var commitDelegates = new List<CommitToNonces>();
			foreach (var e in Components)
			{
				commitDelegates.Add(e.CommitToStatements(transcript));
			}

			// return the Commit delegate
			return delegate (WasabiRandom random)
			{
				return this.Commit(random, commitDelegates);
			};
		}

		private RespondToChallenge Commit(WasabiRandom random, IEnumerable<CommitToNonces> commitDelegates)
		{
			var respondDelegates = new List<RespondToChallenge>();
			foreach(var commit in commitDelegates)
			{
				respondDelegates.Add(commit(random));
			}

			// return the Respond delegate
			return delegate() {
				return this.Respond(respondDelegates);
			};
		}

		private IProof Respond(IEnumerable<RespondToChallenge> respondDelegates)
		{
			var proofs = new CompoundProof();
			foreach (var respond in respondDelegates)
			{
				proofs.Add(respond());
			}

			return proofs;
		}
	}
}

// see 19.5.3 "A Sigma protocol for arbitrary linear relations" from
// "A Graduate Course in Applied Cryptography" by Dan Boneh and Victor Shoup
// p748
// https://toc.cryptobook.us/book.pdf p748
// this same approach used by Signal's zkgroup implementation and is a
// generalization of both knowledge of representation (Okamoto's protocol) and
// discrete log equality (Chaum-Pedersen proofs).
namespace WalletWasabi.Crypto.ZeroKnowledge.LinearRelation
{
	// Each proof of a linear relation has multiple knowledge of representation
	// equations, all sharing a single witness comprised of several secrets.
	// Note that some of the generators can be the point at infinity, when a term
	// in the witness does not play a part in the representation of a point.
	public class Equation
	{
		public Equation(GroupElement publicPoint, IEnumerable<GroupElement> generators)
		{
			Guard.False($"{nameof(publicPoint)}.{nameof(publicPoint.IsInfinity)}", publicPoint.IsInfinity);

			PublicPoint = publicPoint;
			Generators = Guard.NotNullOrEmpty(nameof(generators), generators);
		}

		// Knowledge of representation asserts
		//     P = x_1*G_1 + x_2*G_2 + ...
		// so we need a single public input...
		public GroupElement PublicPoint { get; }

		// ... and multiple generators
		public IEnumerable<GroupElement> Generators { get; }

		// Given a vector of scalars derive a point from the generators
		public GroupElement MultiplyGenerators(IEnumerable<Scalar> scalars)
		{
			return Generators.ZipForceEqualLength(scalars, (g, s) => s * g).Sum();
		}

		// Evaluate the verification equation corresponding to the one in the statement
		public bool Verify(GroupElement publicNonce, IEnumerable<Scalar> responses)
		{
			// the verification equation (for 1 generator case) is:
			//   sG =? R + eP
			// where:
			//   - R = kG is the public nonce, k is the secret nonce
			//   - P = xG is the public input, x is the secret
			//   - e is the challenge
			//   - s is the response
			return (publicNonce + challenge * PublicPoint) == MultiplyGenerators(responses);
		}

		// Simulate a public nonce given a challenge and arbitrary responses (should be random)
		public GroupElement Simulate(Scalar challenge, IEnumerable<Scalar> fakeResponses)
		{
			// The verification equation above can be rearranged as a formula for R
			// given e, P and s by subtracting eP from both sides:
			//   R = sG - eP
			return challenge * PublicPoint - MultiplyGenerators(fakeResponses);
		}

		// Given a witness and secret nonces, respond to a challenge proving the equation holds w.r.t the witness
		public Scalar Respond(IEnumerable<Scalar> witness, IEnumerable<Scalar> secretNonces, Scalar challenge)
		{
			// By canceling G on both sides of the verification equation above we can
			// obtain a formula for the response s given k, e and x:
			//   s = k + ex
			return witness.ZipForceEqualLength(secretNonces, (secret, secretNonce) => secretNonce + challenge * secret);
		}
	}

	public class Statement : ISimulatableStatement
	{
		public IEnumerable<Equation> Equations { get; }

		public Statement(IEnumerable<Equation> equations)
		{
			Guard.True("lengths must be the same", equations.All(e => e.Generators.Count() == equations.First.Generators.Count()));

			Equations = equations;
		}

		public bool CheckVerificationEquation(IEnumerable<GroupElement> publicNonces, Scalar challenge, IEnumerable<IEnumerable<Scalar>> allResponses)
		{
			// FIXME move this sanity check to FSTransform? remove?
			// if (publicPoint == proof.PublicNonce)
			// {
			// 	throw new InvalidOperationException($"{nameof(publicPoint)} and {nameof(proof.PublicNonce)} should not be equal.");
			// }
			Equations.ZipForceEqualLength(publicNonces).ZipForceEqualLength(allResponses).All((eqn, publicNonce, responses) => eqn.Verify(publicNonce, responses));
		}

		public IEnumerable<GroupElement> SimulatePublicNonces(Scalar challenge, IEnumerable<IEnumerable<Scalar>> allFakeResponses)
		{
			return Equations.ZipForceEqualLength(allFakeResponses, (eqn, responses) =>
																					 challenge * eqn.PublicPoint - eqn.Generators.ZipForceEqualLength(responses, (g, r) => r * g).Sum());
		}
	}

	public class Knowledge : IKnowledge
	{
		public Statement Statement { get; }
		public IEnumerable<Scalar> Witness { get; }

		public Knowledge(Statement stmt, IEnumerable<Scalar> secrets) {
			foreach (var equation in stmt.Equations)
			{
				var generators = equation.Generators;
				var generatorsCount = generators.Count();
				var secretsCount = secrets.Count();
				if (secretsCount != generatorsCount)
				{
					const string NameofGenerators = nameof(generators);
					const string NameofSecrets = nameof(secrets);
					throw new InvalidOperationException($"Must provide exactly as many {NameofGenerators} as {NameofSecrets}. {NameofGenerators}: {generatorsCount}, {NameofSecrets}: {secretsCount}.");
				}

				var publicPointSanity = equation.PublicPoint.Negate();

				foreach (var (secret, generator) in secrets.ZipForceEqualLength<Scalar, GroupElement>(generators))
				{
					// TODO move elsewhere... WasabiRandom? FSTransform?
					Guard.False($"{nameof(secret)}.{nameof(secret.IsOverflow)}", secret.IsOverflow);
					Guard.False($"{nameof(secret)}.{nameof(secret.IsZero)}", secret.IsZero);
					Guard.False($"{nameof(generator)}.{nameof(generator.IsInfinity)}", generator.IsInfinity);

					publicPointSanity += secret * generator;
				}

				if (publicPointSanity != GroupElement.Infinity)
				{
					throw new InvalidOperationException($"{nameof(stmt.PublicPoint)} was incorrectly constructed.");
				}
			}

			Statement = stmt;
			Witness = secrets;
		}

		public IEnumerable<IEnumerable<Scalar>> RespondToChallenge(Scalar challenge, IEnumerable<IEnumerable<Scalar>> allSecretNonces)
		{
			return Equations.ZipForceEqualLength(allSecretNonces, (eqn, secretNonces) => eqn.Respond(challenge, Witness, secretNonces));
		}
	}
}
