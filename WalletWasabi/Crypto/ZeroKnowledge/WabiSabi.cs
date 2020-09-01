using NBitcoin.Secp256k1;
using System;
using System.Collections.Generic;
using System.Linq;
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
	// Top level entry point
	public static class Proofs { // TODO rename
		public static IProof Prove(byte[] label, IFSProver prover, WasabiRandom random) {
			var transcript = new Transcript(label); // TODO also accept initialized prover and clone for sanity check?

			var CommitToNonces = prover.CommitToStatements(transcript);
			var RespondToChallenge = CommitToNonces(random);
			var proof = RespondToChallenge();

			// FIXME how to make a compound verifier out of a compound prover?
			if (!Verify(label, prover.ToVerifier(), proof))
			{
				throw new InvalidOperationException($"{nameof(Prove)} or {nameof(Verifier.Verify)} is incorrectly implemented. Proof was built, but verification failed.");
			}
			return proof;
		}

		public static bool Verify(byte[] label, IFSVerifier verifier, IProof proof) {
			var transcript = new Transcript(label);

			var CommitToNonces = verifier.CommitToStatements(transcript);
			var VerifyResponse = CommitToNonces(proof);
			return VerifyResponse();
		}
	}

	// TODO remove? no need for polymorphism given LinearRelation is the only instance
	// interface for basic proof systems
	// a statement represents all information needed to verify or simulate a proof
	// as well as metadata for composing proofs together:
	// - the generators used in the statement
	// - the public inputs
	public interface IStatement : IVerifier { // optionally ISimulator
		GroupElementVector PublicPoints { get; }
		IEnumerable<GroupElementVector> Generators { get; }
	}

	// TODO remove? no need for polymorphism given LinearRelation is the only instance
	// This interface can be removed if simulators implementations are
	// mandatory, allowing any statement to be used in an OR proof
	public interface ISimulatableStatement : IStatement, ISimulator {}

	// TODO remove? no need for polymorphism given LinearRelation is the only instance
	// interface for basic proof systems
	// knowledge = (statement, witness)
	// represents all information to generate a proof
	public interface IKnowledge : IProver
	{
		IStatement Statement { get; }
		ScalarVector Witness { get; }
	}

	// given a proof (nonce commitments & responses), verify them against a trusted challenge
	public interface IVerifier
	{
		bool CheckVerificationEquation(GroupElementVector publicNonces, Scalar challenge, IEnumerable<ScalarVector> responses);
	}

	// given a statement, a challenge and a response, simulate a nonce commitment
	public interface ISimulator
	{
		GroupElementVector SimulatePublicNonces(Scalar challenge, IEnumerable<ScalarVector> responses);
	}

	// given a challenge and trusted nonce secrets, generate responses to complete the proof
	public interface IProver
	{
		IEnumerable<ScalarVector> RespondToChallenge(Scalar challenge, IEnumerable<ScalarVector> secretNonces);
	}

	// proof tree
	public interface IProof {}
	public class CompoundProof : List<IProof>, IProof {}
	public class Proof : IProof {
		public Proof(GroupElementVector publicNonces, IEnumerable<ScalarVector> allResponses)
		{
			// TODO generalize to IEnumerable? move these sanity checks to FiatShamirTransform?
			// Guard.False($"{nameof(publicNonces)}.{nameof(publicNonces.IsInfinity)}", publicNonces.IsInfinity);
			Guard.NotNullOrEmpty(nameof(allResponses), allResponses);

			foreach (var responses in allResponses)
			{
				Guard.NotNullOrEmpty(nameof(responses), responses);
				foreach (var response in responses)
				{
					Guard.False($"{nameof(response)}.{nameof(response.IsZero)}", response.IsZero);
				}
			}

			PublicNonces = publicNonces;
			Responses = allResponses;
		}

		public GroupElementVector PublicNonces { get; }
		public IEnumerable<ScalarVector> Responses { get; }
	}

	// IFSProver splits proving in 3 phases
	public interface IFSProver {
		// The first phase is to commit to all the statements, so that synthetic
		// nonce generation for every sub-proof depends on the statement as a whole
		ProverCommitToNonces CommitToStatements(Transcript transcript);

		// for sanity checking every prover should know how to convert itself to a verifier
		IFSVerifier ToVerifier();
	}

	// The second phase is to generate and commit to all the nonces
	public delegate RespondToChallenge ProverCommitToNonces(WasabiRandom random);

	// The thid phase is to generate challenges and respond to them
	public delegate IProof RespondToChallenge();

	// verification counterpart to IFSProver
	public interface IFSVerifier {
		VerifierCommitToNonces CommitToStatements(Transcript transcript);
	}
	public delegate VerifyResponse VerifierCommitToNonces(IProof proof);
	public delegate bool VerifyResponse();
}

// Implements Fiat-Shamir transform on a Sigma protocol, converting an IKnowledge to an IFSProver
namespace WalletWasabi.Crypto.ZeroKnowledge.FSTransform
{
	public class Prover : IFSProver
	{
		private IKnowledge knowledge;

		public Prover(IKnowledge k)
		{
			knowledge = k;
		}

		public IFSVerifier ToVerifier()
		{
			return new Verifier(knowledge.Statement);
		}

		public ProverCommitToNonces CommitToStatements(Transcript transcript)
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
			var secretNonces = new List<ScalarVector>();

			var secretNonceProvider = transcript.CreateSyntheticNocesProvider(knowledge.Witness, random);

			foreach (var (publicPoint, generators) in knowledge.Statement.PublicPoints.ZipForceEqualLength(knowledge.Statement.Generators))
			{
				var pointSecretNonces = secretNonceProvider();
				secretNonces.Add(pointSecretNonces);
				publicNonces.Add(pointSecretNonces * generators);
			}

			transcript.CommitPublicNonces(publicNonces);

			return delegate()
			{
				return this.Respond(transcript, new GroupElementVector(publicNonces), secretNonces);
			};
		}

		private Proof Respond(Transcript transcript, GroupElementVector nonces, IEnumerable<ScalarVector> secretNonces)
		{
			var challenge = transcript.GenerateChallenge();

			var responses = knowledge.RespondToChallenge(challenge, secretNonces);

			return new Proof(nonces, responses);
		}
	}

	public class Verifier : IFSVerifier
	{
		private IStatement statement;

		public Verifier(IStatement s) {
			statement = s;
		}

		public VerifierCommitToNonces CommitToStatements(Transcript transcript)
		{
			transcript.CommitStatement(statement);

			return delegate(IProof proof)
			{
				return this.CommitToNonces(transcript, (Proof)proof);
			};
		}

		private VerifyResponse CommitToNonces(Transcript transcript,  Proof proof)
		{
			transcript.CommitPublicNonces(proof.PublicNonces);

			return delegate()
			{
				return this.VerifyResponse(transcript, proof);
			};
		}

		private bool VerifyResponse(Transcript transcript, Proof proof)
		{
			var challenge = transcript.GenerateChallenge();
			return statement.CheckVerificationEquation(proof.PublicNonces, challenge, proof.Responses);
		}
	}
}

// Disjunction, Abe-Okhubo-Suzuki OR proof
namespace WalletWasabi.Crypto.ZeroKnowledge.Or
{
	public class Prover : IFSProver
	{
		// when constructing disjunction knowlege tree, require 1 prover and n-1 simulators
		IKnowledge Knowledge {get;}
		IEnumerable<ISimulatableStatement> Statements {get;}

		public Prover(IKnowledge knowledge, IEnumerable<ISimulatableStatement> statements)
		{
			// check that known.Statement appears in statements exactly once
			// how make sure order of statements does not reveal which statement is
			// known? canonical ordering?
			Guard.Same("knowledge must be about a statement which appears exactly once in the disjunction.", Statements.Select(stmt => System.Object.ReferenceEquals(stmt, Knowledge.Statement)).Count(), 1);

			Knowledge = knowledge;
			Statements = statements;
		}

		public IFSVerifier ToVerifier()
		{
			return new Verifier(Statements);
		}


		public ProverCommitToNonces CommitToStatements(Transcript transcript)
		{
			// TODO commit "OR", Conjuncts.Count()

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
			var secretNonces = new List<ScalarVector>(); // one secret nonce per witness secret per public input
			var secretNonceProvider = transcript.CreateSyntheticNocesProvider(Knowledge.Witness, random);
			foreach (var (publicPoint, generators) in Knowledge.Statement.PublicPoints.ZipForceEqualLength(Knowledge.Statement.Generators))
			{
				var pointSecretNonces = secretNonceProvider();
				secretNonces.Add(pointSecretNonces);
				realPublicNonces.Add(pointSecretNonces * generators);
			}

			// These list keeps track of the public nonce points and the responses in
			// the order that the prover generates them. Note that these lists are not
			// aligned, if the statement has 3 alternatives, (a, b, c) and a witness
			// for b is known, the the order will be:
			// - nonces: [ b, c, a ]
			// - responses: [ c, a, b ]
			var noncesInProverOrder = new List<GroupElementVector>();
			var responsesInProverOrder = new List<IEnumerable<ScalarVector>>();
			noncesInProverOrder.Add(new GroupElementVector(realPublicNonces));

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
				fork.CommitPublicNonces(noncesInProverOrder.Last());

				// the challenge for each statement is the hash of the previous
				// statement's public nonce.
				var challenge = fork.GenerateChallenge();

				// the responses are simulated as random values
				// TODO rename from GenerateSecretNonces to something more general? add
				// an alias? these are not secret but must be unpredictable
				var syntheticNonceProvider = fork.CreateSyntheticNocesProvider(Knowledge.Witness, random);
				var simulatedResponses = statement.PublicPoints.Select(_ => syntheticNonceProvider());
				responsesInProverOrder.Add(simulatedResponses);

				// derive public nonce value without a witness given the challenge and responses
				noncesInProverOrder.Add(statement.SimulatePublicNonces(challenge, simulatedResponses));
			}

			// Finally prove the statement with the real nonce, closing the cycle of
			// challenges and responses.
			var realFork = transcript.MakeCopy();
			realFork.CommitPublicNonces(noncesInProverOrder.Last());
			var realChallenge = realFork.GenerateChallenge();
			responsesInProverOrder.Add(Knowledge.RespondToChallenge(realChallenge, secretNonces));

			// Put the public nonces and responses in the order that the verifier
			// expects them to be. the rotation point for the nonces is one greater
			// because the known statement's nonce is generated before everything and
			// appears first in prover order else but the response is generated after
			// everything else, so it appears last in the response list.
			var offset = following.Count();
			var allPublicNonces = noncesInProverOrder.Skip(1+offset).Concat(noncesInProverOrder.Take(1+offset));
			var allResponses = responsesInProverOrder.Skip(offset).Concat(responsesInProverOrder.Take(offset));

			// Now that all nonces are known, we can finally commit to them.
			// Neither this nor any subsequent commitments has any effect on the
			// challenges for the sub-statements of the OR proof, but will play a part
			// in determining the challenges for any subsequent statements in a
			// containing conjunction (And).
			foreach (var publicNonces in allPublicNonces)
			{
				transcript.CommitPublicNonces(publicNonces);
			}

			return delegate()
			{
				// Note that unlike FSTransform, challenges and responses are not
				// computed in the response phase, as they were already computed before
				// during nonce commitment. This somewhat violates the FSProver
				// abstractions, but is a fundamental requirement of OR proofs in
				// general, because if the "real" challenge was deterministic the proof
				// would no longer be witness indistinguishable and all of the simulated
				// nonces have to be calculated after the challenge is known.
				return allPublicNonces.Zip(allResponses, (nonces, responses) => new Proof(nonces, responses)) as CompoundProof;
			};
		}
	}

	public class Verifier : IFSVerifier
	{
		IEnumerable<IStatement> Statements {get;}

		public Verifier(IEnumerable<IStatement> statements)
		{
			Statements = statements;
		}

		public VerifierCommitToNonces CommitToStatements(Transcript transcript)
		{
			// TODO commit "OR", Conjuncts.Count()

			foreach (var stmt in Statements)
			{
				transcript.CommitStatement(stmt);
			}

			return delegate(IProof proof)
			{
				return this.VerifyProof(transcript, (CompoundProof)proof);
			};
		}

		private VerifyResponse VerifyProof(Transcript transcript, CompoundProof proofs)
		{
			var allPublicNonces = proofs.Select(x => ((Proof)x).PublicNonces);

			// rotate the statements list so the nonces are aligned with the statements they challenge
			var rotatedNonces = allPublicNonces.Prepend(allPublicNonces.Last()).Take(allPublicNonces.Count());
			var verificationFailed = false;
			foreach (var ((statement, proof_iface), publicNonces) in Statements.Zip(proofs).Zip(rotatedNonces)) // FIXME yuck!
			{
				var proof = (Proof)proof_iface;  // FIXME yuck! split CompoundProof into a tree variant for And and a list variant for OR, and ditch IProof?

				var fork = transcript.MakeCopy();
				fork.CommitPublicNonces(publicNonces);
				var challenge = fork.GenerateChallenge();

				// FIXME moar linq? this is quite ugly
				if (!statement.CheckVerificationEquation(publicNonces, challenge, proof.Responses))
				{
					verificationFailed = true;
				}
			}

			// commit to public nonces for challenges of any subsequent proofs in a containing conjunction
			foreach (var publicNonces in allPublicNonces)
			{
				transcript.CommitPublicNonces(publicNonces);
			}

			return delegate()
			{
				return !verificationFailed;
			};
		}
	}
}


namespace WalletWasabi.Crypto.ZeroKnowledge.And
{
	// Conjunction, delegates the phases of IFSProver to a number of IFSProver
	// children so that their challenges are bound together (effectively a single
	// challenge)

	public class Prover : IFSProver
	{
		IEnumerable<IFSProver> Conjuncts {get;}

		public Prover(IEnumerable<IFSProver> conjuncts)
		{
			Conjuncts = conjuncts;
		}

		public IFSVerifier ToVerifier()
		{
			return new Verifier(Conjuncts.Select(x => x.ToVerifier()));
		}

		public ProverCommitToNonces CommitToStatements(Transcript transcript)
		{
			// TODO commit "AND", Conjuncts.Count()

			var commitDelegates = new List<ProverCommitToNonces>();
			foreach (var e in Conjuncts)
			{
				commitDelegates.Add(e.CommitToStatements(transcript));
			}

			// return the Commit delegate
			return delegate (WasabiRandom random)
			{
				return this.Commit(random, commitDelegates);
			};
		}

		private RespondToChallenge Commit(WasabiRandom random, IEnumerable<ProverCommitToNonces> commitDelegates)
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

	public class Verifier : IFSVerifier
	{
		IEnumerable<IFSVerifier> Conjuncts {get;}

		public Verifier(IEnumerable<IFSVerifier> conjuncts)
		{
			Conjuncts = conjuncts;
		}

		public VerifierCommitToNonces CommitToStatements(Transcript transcript)
		{
			// TODO commit "AND", Conjuncts.Count()

			var commitDelegates = new List<VerifierCommitToNonces>();
			foreach (var e in Conjuncts)
			{
				commitDelegates.Add(e.CommitToStatements(transcript));
			}

			// return the Commit delegate
			return delegate (IProof proof)
			{
				return this.Commit((CompoundProof)proof, commitDelegates);
			};
		}

		private VerifyResponse Commit(CompoundProof proofs, IEnumerable<VerifierCommitToNonces> commitDelegates)
		{
			var verifyDelegates = new List<VerifyResponse>();
			foreach(var (commit, proof) in commitDelegates.ZipForceEqualLength(proofs))
			{
				verifyDelegates.Add(commit(proof));
			}

			// return the Respond delegate
			return delegate() {
				return this.VerifyResponses(verifyDelegates);
			};
		}

		private bool VerifyResponses(IEnumerable<VerifyResponse> verifyDelegates)
		{
			return verifyDelegates.All(verify => verify());
		}
	}
}

// see 19.5.3 "A Sigma protocol for arbitrary linear relations" from
// "A Graduate Course in Applied Cryptography" by Dan Boneh and Victor Shoup
// https://toc.cryptobook.us/book.pdf p748
// this same approach used by Signal's zkgroup/poksho implementation and is a
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
		public Equation(GroupElement publicPoint, GroupElementVector generators)
		{
			Guard.False($"{nameof(publicPoint)}.{nameof(publicPoint.IsInfinity)}", publicPoint.IsInfinity);

			PublicPoint = publicPoint;
			Generators = (GroupElementVector)Guard.NotNullOrEmpty(nameof(generators), generators);
		}

		// Knowledge of representation asserts
		//     P = x_1*G_1 + x_2*G_2 + ...
		// so we need a single public input and several generators
		public GroupElement PublicPoint { get; }
		public GroupElementVector Generators { get; }

		// Evaluate the verification equation corresponding to the one in the statement
		public bool Verify(GroupElement publicNonce, Scalar challenge, ScalarVector responses)
		{
			// the verification equation (for 1 generator case) is:
			//   sG =? R + eP
			// where:
			//   - R = kG is the public nonce, k is the secret nonce
			//   - P = xG is the public input, x is the secret
			//   - e is the challenge
			//   - s is the response
			return (publicNonce + challenge * PublicPoint) == responses * Generators;
		}

		// Simulate a public nonce given a challenge and arbitrary responses (should be random)
		public GroupElement Simulate(Scalar challenge, ScalarVector fakeResponses)
		{
			// The verification equation above can be rearranged as a formula for R
			// given e, P and s by subtracting eP from both sides:
			//   R = sG - eP
			return challenge * PublicPoint - fakeResponses * Generators;
		}

		// Given a witness and secret nonces, respond to a challenge proving the equation holds w.r.t the witness
		public ScalarVector Respond(ScalarVector witness, ScalarVector secretNonces, Scalar challenge)
		{
			// By canceling G on both sides of the verification equation above we can
			// obtain a formula for the response s given k, e and x:
			//   s = k + ex
			return new ScalarVector(witness.Zip(secretNonces, (secret, secretNonce) => secretNonce + challenge * secret)); // FIXME ZipForceEqualLength
		}
	}

	public class Statement : ISimulatableStatement
	{
		public IEnumerable<Equation> Equations { get; }

		public GroupElementVector PublicPoints {
			get {
				return new GroupElementVector(Equations.Select(x => x.PublicPoint));
			}
		}

		public IEnumerable<GroupElementVector> Generators {
			get {
				return Equations.Select(x => x.Generators);
			}
		}

		public Statement(IEnumerable<Equation> equations)
		{
			var n = equations.First().Generators.Count();
			Guard.True("lengths must be the same", equations.All(e => e.Generators.Count() == n));
			Equations = equations;
		}

		public bool CheckVerificationEquation(GroupElementVector publicNonces, Scalar challenge, IEnumerable<ScalarVector> allResponses)
		{
			// FIXME move this sanity check to FSTransform? remove?
			// if (publicPoint == proof.PublicNonce)
			// {
			// 	throw new InvalidOperationException($"{nameof(publicPoint)} and {nameof(proof.PublicNonce)} should not be equal.");
			// }

			// FIXME why no worky?
			// return Equations.ZipForceEqualLength(publicNonces.ZipForceEqualLength(allResponses)).All((eqn, nonce, responses) => eqn.Verify(nonce, challenge, responses));

			foreach (var (eqn, (nonce, responses)) in Equations.ZipForceEqualLength(publicNonces.ZipForceEqualLength(allResponses)))
			{
				if (!eqn.Verify(nonce, challenge, responses))
				{
					// FIXME short circuiting is not constant time. is this a sidechannel
					// leak from coordinator and Z point? probably not since Z itself is
					// already known to prover and derived beforehand
					return false;
				}
			}
			return true;
		}

		public GroupElementVector SimulatePublicNonces(Scalar challenge, IEnumerable<ScalarVector> allFakeResponses)
		{
			return new GroupElementVector(Equations.Zip(allFakeResponses, (eqn, responses) => eqn.Simulate(challenge, responses))); // FIXME ZipForceEqualLength
		}
	}

	public class Knowledge : IKnowledge
	{
		public Statement TypedStatement { get; }

		// FIXME yuck!
		public IStatement Statement { get {
				return TypedStatement;
			}
		}

		public ScalarVector Witness { get; }

		public Knowledge(Statement stmt, ScalarVector secrets) {
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
					throw new InvalidOperationException($"{nameof(equation.PublicPoint)} was incorrectly constructed.");
				}
			}

			TypedStatement = stmt;
			Witness = secrets;
		}

		public IEnumerable<ScalarVector> RespondToChallenge(Scalar challenge, IEnumerable<ScalarVector> allSecretNonces)
		{
			return TypedStatement.Equations.Zip(allSecretNonces, (eqn, secretNonces) => eqn.Respond(Witness, secretNonces, challenge)); // FIXME ZipForceEqualLength
		}
	}
}
