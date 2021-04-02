using NBitcoin;
using System.Collections.Immutable;
using System.Linq;
using WalletWasabi.Crypto;
using WalletWasabi.WabiSabi.Backend.Models;

namespace WalletWasabi.WabiSabi.Models.MultipartyTransaction
{
	// This class represents actions of the BIP 370 creator and constructor roles
	public record Construction(Parameters Parameters) : State
	{
		public ImmutableList<Coin> Inputs { get; init; } = ImmutableList<Coin>.Empty;
		public ImmutableList<TxOut> Outputs { get; init; } = ImmutableList<TxOut>.Empty;

		public FeeRate EffectiveFeeRate { get => new FeeRate(Balance, EstimatedWeight/4); }

		public Money Balance { get => Inputs.Select(x => x.Amount).Sum() - Outputs.Select(x => x.Value).Sum(); }

		public int EstimatedWeight { get => Parameters.SharedOverhead + EstimatedInputsWeight + OutputsWeight; }
		public int EstimatedInputsWeight { get => Inputs.Select(x => 4 * x.TxOut.ScriptPubKey.EstimateInputVsize()).Sum(); } // FIXME is this conservative? Add EstimateWeight and Weight attributes to NBitcoinExtensions
		public int OutputsWeight { get => Outputs.Select(x => 4 * x.ScriptPubKey.EstimateOutputVsize()).Sum(); }

		// TODO ownership proofs and spend status also in scope
		public Construction AddInput(Coin coin)
		{
			var prevout = coin.TxOut;

			if (prevout.Value < Parameters.AllowedInputAmounts.Min)
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.NotEnoughFunds);
			}
			if (prevout.Value > Parameters.AllowedInputAmounts.Max)
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.TooMuchFunds);
			}

			if (!StandardScripts.IsStandardScriptPubKey(prevout.ScriptPubKey))
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.NonStandardInput);
			}

			if (!Parameters.AllowedInputTypes.Any(x => prevout.ScriptPubKey.IsScriptType(x)))
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.ScriptNotAllowed);
			}

			if (Inputs.Any(x => x.Outpoint == coin.Outpoint))
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.NonUniqueInputs);
			}

			return this with { Inputs = Inputs.Add(coin) };
		}

		public Construction AddOutput(TxOut output)
		{
			if (!StandardScripts.IsStandardScriptPubKey(output.ScriptPubKey))
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.NonStandardOutput);
			}

			if (!Parameters.AllowedOutputTypes.Any(x => output.ScriptPubKey.IsScriptType(x)))
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.ScriptNotAllowed);
			}

			if (output.Value < Parameters.AllowedOutputAmounts.Min)
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.NotEnoughFunds);
			}

			if (output.Value > Parameters.AllowedOutputAmounts.Max)
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.TooMuchFunds);
			}

			return this with { Outputs = Outputs.Add(output) };
		}

		public Signing Finalize()
		{
			var weight = EstimatedWeight;

			if (weight > Parameters.MaxWeight)
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.WeightLimitExceeded);
			}

			if (EffectiveFeeRate < Parameters.FeeRate)
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.InsufficientFees);
			}

			return new Signing(Parameters, Inputs.ToImmutableArray(), Outputs.ToImmutableArray());
		}
	}
}
