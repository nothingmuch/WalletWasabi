using NBitcoin;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WalletWasabi.Crypto;
using WalletWasabi.Crypto.Randomness;
using WalletWasabi.Helpers;
using WalletWasabi.Logging;
using WalletWasabi.WabiSabi.Backend.Models;
using WalletWasabi.WabiSabi.Crypto;
using WalletWasabi.WabiSabi.Crypto.CredentialRequesting;
using WalletWasabi.WabiSabi.Models;
using MP = WalletWasabi.WabiSabi.Models.MultipartyTransaction;

namespace WalletWasabi.WabiSabi.Backend.Rounds
{
	public class Round
	{
		public Round(RoundParameters roundParameters)
		{
			RoundParameters = roundParameters;

			AmountCredentialIssuer = new(new(Random), 2, Random, MaxRegistrableAmount);
			WeightCredentialIssuer = new(new(Random), 2, Random, RegistrableWeightCredentials);
			AmountCredentialIssuerParameters = AmountCredentialIssuer.CredentialIssuerSecretKey.ComputeCredentialIssuerParameters();
			WeightCredentialIssuerParameters = WeightCredentialIssuer.CredentialIssuerSecretKey.ComputeCredentialIssuerParameters();

			// TODO allowed input and output amounts should differ by at least
			// the cost of a single p2wpkh input and a single p2wpkh output,
			// otherwise some registrable input balances can result in no output
			// registrations.
			var allowedAmounts = new MoneyRange(roundParameters.MinRegistrableAmount, RoundParameters.MaxRegistrableAmount);
			var txParams = new MP.Parameters(roundParameters.FeeRate, allowedAmounts, allowedAmounts, roundParameters.Network);
			CoinjoinState = new MP.Construction(txParams);

			Hash = new(HashHelpers.GenerateSha256Hash($"{Id}{MaxInputCountByAlice}{MinRegistrableAmount}{MaxRegistrableAmount}{RegistrableWeightCredentials}{AmountCredentialIssuerParameters}{WeightCredentialIssuerParameters}{FeeRate.SatoshiPerByte}"));
		}

		public MP.State CoinjoinState { get; set; }

		// TODO remove
		public Transaction Coinjoin { get => CoinjoinState.AssertSigning().CreateTransaction(); }

		public uint256 Hash { get; }
		public Network Network => RoundParameters.Network;
		public uint MaxInputCountByAlice => RoundParameters.MaxInputCountByAlice;
		public Money MinRegistrableAmount => RoundParameters.MinRegistrableAmount;
		public Money MaxRegistrableAmount => RoundParameters.MaxRegistrableAmount;
		public uint RegistrableWeightCredentials => RoundParameters.RegistrableWeightCredentials;
		public FeeRate FeeRate => RoundParameters.FeeRate;
		public WasabiRandom Random => RoundParameters.Random;
		public CredentialIssuer AmountCredentialIssuer { get; }
		public CredentialIssuer WeightCredentialIssuer { get; }
		public CredentialIssuerParameters AmountCredentialIssuerParameters { get; }
		public CredentialIssuerParameters WeightCredentialIssuerParameters { get; }
		public Guid Id { get; } = Guid.NewGuid();
		public List<Alice> Alices { get; } = new();
		public int InputCount => Alices.Sum(x => x.Coins.Count());
		public List<Bob> Bobs { get; } = new();

		public Round? BlameOf => RoundParameters.BlameOf;
		public bool IsBlameRound => RoundParameters.IsBlameRound;
		public ISet<OutPoint> BlameWhitelist => RoundParameters.BlameWhitelist;

		public TimeSpan ConnectionConfirmationTimeout => RoundParameters.ConnectionConfirmationTimeout;
		public TimeSpan OutputRegistrationTimeout => RoundParameters.OutputRegistrationTimeout;
		public TimeSpan TransactionSigningTimeout => RoundParameters.TransactionSigningTimeout;

		private RoundParameters RoundParameters { get; }
		public Phase Phase { get; private set; } = Phase.InputRegistration;
		public DateTimeOffset InputRegistrationStart { get; } = DateTimeOffset.UtcNow;
		public DateTimeOffset ConnectionConfirmationStart { get; private set; }
		public DateTimeOffset OutputRegistrationStart { get; private set; }
		public DateTimeOffset TransactionSigningStart { get; private set; }
		public DateTimeOffset TransactionBroadcastingStart { get; private set; }

		public void SetPhase(Phase phase)
		{
			if (!Enum.IsDefined<Phase>(phase))
			{
				throw new ArgumentException($"Invalid phase {phase}. This is a bug.", nameof(phase));
			}

			this.LogInfo($"Phase changed: {Phase} -> {phase}");
			Phase = phase;

			if (phase == Phase.ConnectionConfirmation)
			{
				ConnectionConfirmationStart = DateTimeOffset.UtcNow;
			}
			else if (phase == Phase.OutputRegistration)
			{
				OutputRegistrationStart = DateTimeOffset.UtcNow;
			}
			else if (phase == Phase.TransactionSigning)
			{
				TransactionSigningStart = DateTimeOffset.UtcNow;
			}
			else if (phase == Phase.TransactionBroadcasting)
			{
				TransactionBroadcastingStart = DateTimeOffset.UtcNow;
			}
		}

		public bool IsInputRegistrationEnded(uint maxInputCount, TimeSpan inputRegistrationTimeout)
		{
			if (Phase > Phase.InputRegistration)
			{
				return true;
			}

			if (IsBlameRound)
			{
				if (BlameWhitelist.Count <= InputCount)
				{
					return true;
				}
			}
			else if (InputCount >= maxInputCount)
			{
				return true;
			}

			if (InputRegistrationStart + inputRegistrationTimeout < DateTimeOffset.UtcNow)
			{
				return true;
			}

			return false;
		}

		public MP.Construction AddInput(Coin coin)
			=> CoinjoinState.AssertConstruction().AddInput(coin);

		public MP.Construction AddOutput(TxOut output)
			=> CoinjoinState.AssertConstruction().AddOutput(output);

		public MP.Signing AddWitness(int index, WitScript witness)
			=> CoinjoinState.AssertSigning().AddWitness(index, witness);
	}
}
