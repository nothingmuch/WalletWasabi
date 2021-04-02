using NBitcoin;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using WalletWasabi.WabiSabi.Backend.Models;

namespace WalletWasabi.WabiSabi.Models.MultipartyTransaction
{
	public record Signing(Parameters Parameters, ImmutableArray<Coin> Inputs, ImmutableArray<TxOut> Outputs) : State
	{
		public ImmutableDictionary<int, WitScript> Witnesses { get; init; } = ImmutableDictionary<int, WitScript>.Empty;

		public bool IsFullySigned { get => Witnesses.Count() == Inputs.Length; }

		public IEnumerable<Coin> UnsignedInputs { get => Enumerable.Range(0, Inputs.Length).Where(i => !IsInputSigned(i)).Select(i => Inputs[i]); }

		public bool IsInputSigned(int index)
			=> Witnesses.ContainsKey(index);

		public FeeRate EffectiveFeeRate { get => new FeeRate(Balance, EstimatedWeight/4); }

		public Money Balance { get => Inputs.Select(x => x.Amount).Sum() - Outputs.Select(x => x.Value).Sum(); }

		public int EstimatedWeight { get => Parameters.SharedOverhead + EstimatedInputsWeight + OutputsWeight; }
		public int EstimatedInputsWeight { get => 4 * Inputs.Select(x => x.TxOut.ScriptPubKey.EstimateInputVsize()).Sum(); } // FIXME is this conservative? Add EstimateWeight and Weight attributes to NBitcoinExtensions
		public int OutputsWeight { get => 4 * Outputs.Select(x => x.ScriptPubKey.EstimateOutputVsize()).Sum(); }

		public Signing AddWitness(int index, WitScript witness)
		{
			if (IsInputSigned(index))
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.WitnessAlreadyProvided);
			}

			// Verify witness.
			// 1. Copy UnsignedCoinJoin.
			Transaction cjCopy = CreateUnsignedTransaction();

			// 2. Sign the copy.
			cjCopy.Inputs[index].WitScript = witness;

			// 3. Convert the current input to IndexedTxIn.
			IndexedTxIn currentIndexedInput = cjCopy.Inputs.AsIndexedInputs().Skip(index).First();

			// 4. Find the corresponding registered input.
			Coin registeredCoin = Inputs[index];

			// 5. Verify if currentIndexedInput is correctly signed, if not, return the specific error.
			if (!currentIndexedInput.VerifyScript(registeredCoin, out ScriptError error))
			{
				throw new WabiSabiProtocolException(WabiSabiProtocolErrorCode.WrongCoinjoinSignature); // TODO keep script error
			}

			return this with { Witnesses = Witnesses.Add(index, witness) };
		}

		public Transaction CreateUnsignedTransaction()
		{
			var tx = Parameters.CreateTransaction();

			foreach (var coin in Inputs)
			{
				// implied:
				// nSequence = FINAL
				tx.Inputs.Add(coin.Outpoint);
			}

			foreach (var txout in Outputs)
			{
				tx.Outputs.AddWithOptimize(txout.Value, txout.ScriptPubKey);
			}

			return tx;
		}

		public Transaction CreateTransaction()
		{
			var tx = CreateUnsignedTransaction();

			foreach (var (index, witness) in Witnesses)
			{
				tx.Inputs[index].WitScript = witness;
			}

			return tx;
		}
	}
}
