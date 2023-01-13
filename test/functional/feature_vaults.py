#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test vaults implemented with OP_VAULT.

See the `VaultSpec` class and nearby functions for a general sense of the
transactional structure of vaults.
"""

import copy
import typing as t
from enum import Enum

from test_framework.test_framework import BitcoinTestFramework
from test_framework.p2p import P2PInterface
from test_framework.wallet import MiniWallet, MiniWalletMode
from test_framework.script import CScript, OP_VAULT, OP_UNVAULT, OP_0
from test_framework.messages import CTransaction, COutPoint, CTxOut, CTxIn, COIN
from test_framework.util import assert_equal, assert_raises_rpc_error

from test_framework import script, key, messages


class OutputType(str, Enum):
    """
    Possible forms that the OP_UNVAULT output can take. The latter two conceal
    the unvault process until it is complete.
    """
    Bare = 'bare'
    P2WSH = 'P2WSH'
    P2TR = 'P2TR'



class VaultsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [
            [
                # Use only one script thread to get the exact reject reason for testing
                "-par=1",
                # 0-value outputs, probably among other things in OP_VAULT, are
                # non-standard until transaction v3 policy gets merged.
                "-acceptnonstdtxn=1",
                # TODO: remove when package relay submission becomes a thing.
                "-minrelaytxfee=0",
                "-dustrelayfee=0",
            ]
        ]
        self.setup_clean_chain = True

    def run_test(self):
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_TRUE)
        node = self.nodes[0]
        node.add_p2p_connection(P2PInterface())

        # Generate some matured UTXOs to spend into vaults.
        self.generate(wallet, 200)

        for unvault_type in OutputType:
            def title(name: str):
                self.log.info(f"[unvault type: {unvault_type}] {name}")

            title("testing normal vault spend")
            self.single_vault_test(node, wallet, unvault_type=unvault_type)

            title("testing sweep-to-recovery from the vault")
            self.single_vault_test(
                node, wallet, sweep_from_vault=True, unvault_type=unvault_type)

            title("testing sweep-to-recovery from the unvault trigger")
            self.single_vault_test(
                node, wallet, sweep_from_unvault=True, unvault_type=unvault_type)

            title("testing a batch sweep operation across multiple vaults")
            self.test_batch_sweep(node, wallet, unvault_type=unvault_type)

            title("testing a batch unvault")
            self.test_batch_unvault(node, wallet, unvault_type=unvault_type)

            title("testing revaults")
            self.test_revault(node, wallet, unvault_type=unvault_type)

    def single_vault_test(
        self,
        node,
        wallet,
        sweep_from_vault: bool = False,
        sweep_from_unvault: bool = False,
        unvault_type: OutputType = OutputType.P2TR,
    ):
        """
        Test the creation and spend of a single vault, optionally sweeping at various
        stages of the vault lifecycle.
        """
        assert_equal(node.getmempoolinfo()["size"], 0)

        vault = VaultSpec()
        vault_init_tx = vault.get_initialize_vault_tx(wallet)

        self.assert_broadcast_tx(vault_init_tx, mine_all=True)

        if sweep_from_vault:
            assert vault.vault_outpoint
            sweep_tx = get_sweep_to_recovery_tx({vault: vault.vault_outpoint})
            self.assert_broadcast_tx(sweep_tx, mine_all=True)

            return

        assert vault.total_amount_sats and vault.total_amount_sats > 0
        target_amounts = split_vault_value(vault.total_amount_sats)
        target_keys = [
            key.ECKey(secret=(4 + i).to_bytes(32, "big"))
            for i in range(len(target_amounts))
        ]

        # The final withdrawal destination for the vaulted funds.
        final_target_vout = [
            CTxOut(nValue=amt, scriptPubKey=make_segwit0_spk(key))
            for amt, key in zip(target_amounts, target_keys)
        ]

        target_out_hash = target_outputs_hash(final_target_vout)
        start_unvault_tx = get_trigger_unvault_tx(
            target_out_hash, [vault], unvault_type)

        tx_mutator = TxMutator(vault, unvault_type)

        mutation_to_err = {
            tx_mutator.unvault_with_bad_recovery_spk: 'OP_UNVAULT outputs not compatible',
            tx_mutator.unvault_with_bad_spend_delay: 'OP_UNVAULT outputs not compatible',
            tx_mutator.unvault_with_low_amount: 'OP_UNVAULT outputs not compatible',
            tx_mutator.unvault_with_high_amount: 'bad-txns-in-belowout',
            tx_mutator.unvault_with_bad_opcode: 'OP_UNVAULT outputs not compatible',
        }
        for mutation, err in mutation_to_err.items():
            self.assert_tx_mutation_fails(mutation, start_unvault_tx, err=err)

        start_unvault_txid = self.assert_broadcast_tx(start_unvault_tx)

        unvault_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(start_unvault_txid), byteorder="big"), n=0
        )

        if sweep_from_unvault:
            sweep_tx = get_sweep_to_recovery_tx(
                {vault: unvault_outpoint}, start_unvault_tx)
            self.assert_broadcast_tx(sweep_tx, mine_all=True)
            return

        final_tx = get_final_withdrawal_tx(
            unvault_outpoint, final_target_vout, start_unvault_tx)

        # Broadcasting before start_unvault is confirmed fails.
        self.assert_broadcast_tx(final_tx, err_msg="non-BIP68-final")

        XXX_mempool_fee_hack_for_no_pkg_relay(node, start_unvault_txid)

        # Generate almost past the timelock, but not quite.
        self.generate(wallet, vault.spend_delay - 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        self.assert_broadcast_tx(final_tx, err_msg="non-BIP68-final")

        self.generate(wallet, 1)

        # Generate bad nSequence values.
        final_bad = copy.deepcopy(final_tx)
        final_bad.vin[0].nSequence = final_tx.vin[0].nSequence - 1
        self.assert_broadcast_tx(final_bad, err_msg="timelock has not matured")

        # Generate bad amounts.
        final_bad = copy.deepcopy(final_tx)
        final_bad.vout[0].nValue = final_tx.vout[0].nValue - 1
        self.assert_broadcast_tx(final_bad, err_msg="target hash mismatch")

        # Finally the unvault completes.
        self.assert_broadcast_tx(final_tx, mine_all=True)

    def test_batch_sweep(
        self,
        node,
        wallet,
        unvault_type: OutputType = OutputType.P2TR,
    ):
        """
        Test generating multiple vaults and sweeping them to the recovery path in batch.

        One of the vaults has been triggered for withdrawal while the other two
        are still vaulted.
        """
        # Create some vaults with the same unvaulting key, recovery key, but different
        # spend delays.
        vaults = [
            VaultSpec(spend_delay=i) for i in [10, 11, 12]
        ]

        for v in vaults:
            init_tx = v.get_initialize_vault_tx(wallet)
            self.assert_broadcast_tx(init_tx)

        assert_equal(node.getmempoolinfo()["size"], len(vaults))
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # Start unvaulting the first vault.
        unvault1_tx = get_trigger_unvault_tx(b'\x00' * 32, [vaults[0]], unvault_type)
        unvault1_txid = unvault1_tx.rehash()
        assert_equal(
            node.sendrawtransaction(unvault1_tx.serialize().hex()), unvault1_txid,
        )

        XXX_mempool_fee_hack_for_no_pkg_relay(node, unvault1_txid)
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # So now, 1 vault is in the process of unvaulting and the other two are still
        # vaulted. Sweep them all with one transaction.
        unvault1_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(unvault1_txid), byteorder="big"), n=0
        )

        sweep_tx = get_sweep_to_recovery_tx({
            vaults[0]: unvault1_outpoint,
            vaults[1]: vaults[1].vault_outpoint,
            vaults[2]: vaults[2].vault_outpoint,
        }, unvault1_tx)
        self.assert_broadcast_tx(sweep_tx, mine_all=True)

    def test_batch_unvault(
        self,
        node,
        wallet,
        unvault_type: OutputType = OutputType.P2TR,
    ):
        """
        Test generating multiple vaults and ensure those with compatible parameters
        (spend delay and recovery path) can be unvaulted in batch.
        """
        common_spend_delay = 10
        # Create some vaults with the same spend delay and recovery key, so that they
        # can be unvaulted together, but different unvault keys.
        vaults = [
            VaultSpec(spend_delay=common_spend_delay,
                      unvault_trigger_secret=i) for i in [10, 11, 12]
        ]
        # Create a vault with a different recovery path than the vaults above; cannot
        # be batch unvaulted.
        vault_diff_recovery = VaultSpec(
            spend_delay=10, recovery_secret=(DEFAULT_RECOVERY_SECRET + 1))

        # Create a vault with the same recovery path but a different spend delay;
        # cannot be batch unvaulted.
        vault_diff_delay = VaultSpec(spend_delay=(common_spend_delay - 1))

        for v in vaults + [vault_diff_recovery, vault_diff_delay]:
            init_tx = v.get_initialize_vault_tx(wallet)
            self.assert_broadcast_tx(init_tx)

        assert_equal(node.getmempoolinfo()["size"], len(vaults) + 2)
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # Construct the final unvault target.
        unvault_total_sats = sum(v.total_amount_sats for v in vaults)
        assert unvault_total_sats > 0
        target_key = key.ECKey(secret=(1).to_bytes(32, "big"))

        # The final withdrawal destination for the vaulted funds.
        final_target_vout = [
            CTxOut(nValue=unvault_total_sats,
                   scriptPubKey=make_segwit0_spk(target_key))
        ]
        target_out_hash = target_outputs_hash(final_target_vout)

        # Ensure that we can't batch with incompatible OP_VAULTs.
        for incompat_vaults in [[vault_diff_recovery],
                                [vault_diff_delay],
                                [vault_diff_recovery, vault_diff_delay]]:
            failed_unvault = get_trigger_unvault_tx(
                target_out_hash, vaults + incompat_vaults, unvault_type
            )
            self.assert_broadcast_tx(
                failed_unvault, err_msg="OP_UNVAULT outputs not compatible")

        good_batch_unvault = get_trigger_unvault_tx(
            target_out_hash, vaults, unvault_type)
        good_txid = self.assert_broadcast_tx(good_batch_unvault, mine_all=True)

        unvault_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(good_txid), byteorder="big"), n=0
        )
        final_tx = get_final_withdrawal_tx(
            unvault_outpoint, final_target_vout, good_batch_unvault)

        self.assert_broadcast_tx(final_tx, err_msg="non-BIP68-final")

        self.generate(node, common_spend_delay)

        # Finalize the batch withdrawal.
        self.assert_broadcast_tx(final_tx, mine_all=True)

    def test_revault(
        self,
        node,
        wallet,
        unvault_type: OutputType = OutputType.P2TR,
    ):
        """
        Test that some amount can be "revaulted" during the unvault process. That
        amount is immediately deposited back into the same vault that is currently
        undergoing unvaulting, so that the remaining balance within the vault can
        be managed independent of the timelock that the first unvault process has
        induced.
        """
        common_spend_delay = 10
        # To support revaults when dealing with a batch, each vault must share the
        # same vault sPK.
        vaults = [
            VaultSpec(spend_delay=common_spend_delay, unvault_trigger_secret=10)
            for _ in range(3)
        ]

        for v in vaults:
            init_tx = v.get_initialize_vault_tx(wallet)
            self.assert_broadcast_tx(init_tx)

        assert_equal(node.getmempoolinfo()["size"], len(vaults))
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        revault_amount = COIN
        # Construct the final unvault target; save a coin to peel off in the revault.
        unvault_total_sats = sum(
            v.total_amount_sats for v in vaults) - revault_amount  # type: ignore
        assert unvault_total_sats > 0
        target_key = key.ECKey(secret=(1).to_bytes(32, "big"))

        # The final withdrawal destination for the vaulted funds.
        final_target_vout = [
            CTxOut(nValue=unvault_total_sats,
                   scriptPubKey=make_segwit0_spk(target_key))
        ]
        target_out_hash = target_outputs_hash(final_target_vout)

        unvault_tx = get_trigger_unvault_tx(
            target_out_hash, vaults, unvault_type, revault_amount_sats=revault_amount)

        tx_mutator = TxMutator(vaults[0], unvault_type)
        mutation_to_err = {
            tx_mutator.revault_with_high_amount: 'bad-txns-in-belowout',
            tx_mutator.revault_with_low_amount: 'OP_UNVAULT outputs not compatible',
        }
        for mutation, err in mutation_to_err.items():
            self.assert_tx_mutation_fails(mutation, unvault_tx, err=err)

        txid = self.assert_broadcast_tx(unvault_tx, mine_all=True)

        unvault_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(txid), byteorder="big"), n=0)

        final_tx = get_final_withdrawal_tx(
            unvault_outpoint, final_target_vout, unvault_tx)

        self.assert_broadcast_tx(final_tx, err_msg="non-BIP68-final")

        revault_spec = copy.deepcopy(vaults[0])
        revault_spec.total_amount_sats = revault_amount
        revault_spec.vault_output = unvault_tx.vout[1]
        revault_spec.vault_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(txid), byteorder="big"), n=1)

        revault_unvault_tx = get_trigger_unvault_tx(
            b'\x00' * 32, [revault_spec], unvault_type,
        )
        # The revault output should be immediately spendable into an OP_UNVAULT
        # output.
        self.assert_broadcast_tx(revault_unvault_tx, mine_all=True)

        self.generate(node, common_spend_delay)

        # Finalize the batch withdrawal.
        self.assert_broadcast_tx(final_tx, mine_all=True)

    def assert_broadcast_tx(
        self,
        tx: CTransaction,
        mine_all: bool = False,
        err_msg: t.Optional[str] = None
    ) -> str:
        """
        Broadcast a transaction and facilitate various assertions about how the
        broadcast went.
        """
        node = self.nodes[0]
        txhex = tx.serialize().hex()
        txid = tx.rehash()

        if not err_msg:
            assert_equal(node.sendrawtransaction(txhex), txid)
        else:
            assert_raises_rpc_error(
                -26, err_msg, node.sendrawtransaction, txhex,
            )

        if mine_all:
            XXX_mempool_fee_hack_for_no_pkg_relay(node, txid)
            self.generate(node, 1)
            assert_equal(node.getmempoolinfo()["size"], 0)

        return txid

    def assert_tx_mutation_fails(
        self,
        mutation_func: t.Callable[[CTransaction], None],
        tx_to_mutate: CTransaction,
        *,
        err: str,
        **kwargs,
    ):
        assert mutation_func.__doc__, "Mutation needs a description"
        desc = mutation_func.__doc__[:80]
        self.log.info("  asserting bad tx fails: %s", desc)
        tx_copy = copy.deepcopy(tx_to_mutate)

        mutation_func(tx_copy)
        self.assert_broadcast_tx(tx_copy, err_msg=err)



def XXX_mempool_fee_hack_for_no_pkg_relay(node, txid: str):
    """
    XXX manually prioritizing the 0-fee trigger transaction is necessary because
    we aren't doing package relay here, so the block assembler (rationally?)
    isn't including the 0-fee transaction.
    """
    node.prioritisetransaction(txid=txid, fee_delta=COIN)


DEFAULT_RECOVERY_SECRET = 2
DEFAULT_UNVAULT_SECRET = 3


class VaultSpec:
    """
    A specification for a single vault UTXO that consolidates the context needed to
    unvault or sweep.
    """
    def __init__(
        self,
        recovery_secret: t.Optional[int] = None,
        unvault_trigger_secret: t.Optional[int] = None,
        spend_delay: int = 10,
    ):
        self.recovery_key = key.ECKey(
            secret=(recovery_secret or DEFAULT_RECOVERY_SECRET).to_bytes(32, 'big'))
        # Taproot info for the recovery key.
        self.recovery_tr_info = taproot_from_privkey(self.recovery_key)

        # Use a basic key-path TR spend to trigger an unvault attempt.
        self.unvault_key = key.ECKey(
            secret=(
                unvault_trigger_secret or DEFAULT_UNVAULT_SECRET).to_bytes(32, 'big'))
        self.unvault_tr_info = taproot_from_privkey(self.unvault_key)
        self.unvault_tweaked_privkey = key.tweak_add_privkey(
            self.unvault_key.get_bytes(), self.unvault_tr_info.tweak
        )
        assert isinstance(self.unvault_tweaked_privkey, bytes)

        self.spend_delay = spend_delay

        # The OP_VAULT scriptPubKey that is hidden in the initializing vault
        # outputs's script-path spend.
        self.vault_spk = CScript([
            # <recovery-spk-hash>
            recovery_spk_tagged_hash(self.recovery_tr_info.scriptPubKey),
            # <spend-delay>
            self.spend_delay,
            # <unvault-spk-hash>
            unvault_spk_tagged_hash(self.unvault_tr_info.scriptPubKey),
            OP_VAULT,
        ])

        # The initializing taproot output is either spendable via OP_VAULT
        # (script-path spend) or directly by the recovery key (key-path spend).
        self.init_tr_info = taproot_from_privkey(
            self.recovery_key, scripts=[("opvault", self.vault_spk)],
        )

        # Set when the vault is initialized.
        self.total_amount_sats: t.Optional[int] = None

        # Outpoint for spending the initialized vault.
        self.vault_outpoint: t.Optional[messages.COutPoint] = None
        self.vault_output: t.Optional[CTxOut] = None


    def get_initialize_vault_tx(
        self,
        wallet: MiniWallet,
        fees: t.Optional[int] = None,
    ) -> CTransaction:
        """
        Pull a UTXO from the wallet instance and spend it into the vault.

        The vault is spendable by either the usual means (unvault or sweep) via
        script-path spend, or immediately spendable by the recovery key via
        key-path spend.
        """
        utxo, utxo_in = wallet.get_utxo_as_txin()
        fees = fees if fees is not None else 10_000
        self.total_amount_sats = int(utxo["value"] * COIN) - fees

        self.vault_output = CTxOut(
            nValue=self.total_amount_sats,
            scriptPubKey=self.init_tr_info.scriptPubKey
        )
        vault_init = CTransaction()
        vault_init.nVersion = 2
        vault_init.vin = [utxo_in]
        vault_init.vout = [self.vault_output]

        # Cache the vault outpoint for later use during spending.
        self.vault_outpoint = messages.COutPoint(
            hash=int.from_bytes(bytes.fromhex(vault_init.rehash()), byteorder="big"),
            n=0
        )
        return vault_init


class TxMutator(t.NamedTuple):
    """
    A class that tweaks transactions in various ways to test that invalid vault
    operations fail.

    Each method takes in a transaction copy and modifies it in place.

    For use with `VaultsTest.assert_tx_mutation_fails()`.
    """
    vault: VaultSpec
    unvault_type: OutputType

    def unvault_with_bad_recovery_spk(self, tx: CTransaction):
        """Unvault with wrong recovery path."""
        bad_unvault_spk = CScript([
            # <recovery-spk-hash>
            bytes([0x01] * 32),
            # <spend-delay>
            self.vault.spend_delay,
            # <target-outputs-hash>
            b'\x00' * 32,
            OP_UNVAULT,
        ])

        if self.unvault_type == OutputType.Bare:
            tx.vout[0].scriptPubKey = bad_unvault_spk

        elif self.unvault_type == OutputType.P2WSH:
            tx.vout[0].scriptPubKey = CScript([OP_0, messages.sha256(bad_unvault_spk)])

        elif self.unvault_type == OutputType.P2TR:
            bad_taproot = script.taproot_construct(
                UNVAULT_NUMS_INTERNAL_PUBKEY,
                scripts=[('only-path', bad_unvault_spk, 0xC0)])

            tx.vout[0].scriptPubKey = bad_taproot.scriptPubKey

    def unvault_with_bad_spend_delay(self, tx: CTransaction):
        """Unvault with wrong spend delay."""
        tx.vout[0].scriptPubKey = CScript([
            # <recovery-spk-hash>
            recovery_spk_tagged_hash(self.vault.recovery_tr_info.scriptPubKey),
            # <spend-delay>
            self.vault.spend_delay - 1,
            # <target-outputs-hash>
            b'\x00' * 32,
            OP_UNVAULT,
        ])

    def unvault_with_bad_opcode(self, tx: CTransaction):
        """Unvault with wrong opcode."""
        spk = tx.vout[0].scriptPubKey
        tx.vout[0].scriptPubKey = spk[:-1] + bytes([OP_VAULT])

    def unvault_with_low_amount(self, tx: CTransaction):
        """Unvault with wrong amount (too little)."""
        tx.vout[0].nValue -= 1

    def unvault_with_high_amount(self, tx: CTransaction):
        """Unvault with wrong amount (too much)."""
        tx.vout[0].nValue += 1

    def revault_with_high_amount(self, tx: CTransaction):
        """Revault with wrong amount (too much)."""
        tx.vout[1].nValue += 1

    def revault_with_low_amount(self, tx: CTransaction):
        """Revault with wrong amount (too little)."""
        tx.vout[1].nValue -= 1


class UnvaultTriggerTransaction(CTransaction):
    """
    Used to track metadata about an unvault trigger transaction to make generating
    the final withdrawal transaction easier.
    """
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # These are set after the transaction has been fully generated.
        self.unvault_output_type: t.Optional[OutputType] = None
        self.spend_delay: t.Optional[int] = None

        # Cache the necessary witness stack for later spending.
        self.spend_witness_stack: t.Optional[list] = None



def get_sweep_to_recovery_tx(
    vaults_to_outpoints: t.Dict[VaultSpec, messages.COutPoint],
    unvault_trigger_tx: t.Optional[UnvaultTriggerTransaction] = None,
) -> CTransaction:
    """
    Generate a transaction that sweeps the vaults to their shared recovery path, either
    from an OP_VAULT output (TR) or an OP_UNVAULT output (bare), from the pairing
    outpoints.

    If we're sweeping from an OP_UNVAULT trigger output, we need the TaprootInfo which
    accompanies `unvault_trigger_tx`.
    """
    vaults = list(vaults_to_outpoints.keys())
    total_vaults_amount_sats = sum(v.total_amount_sats for v in vaults)  # type: ignore

    sweep_tx = CTransaction()
    sweep_tx.nVersion = 2
    sweep_tx.vin = [
        CTxIn(vaults_to_outpoints[v]) for v in vaults
    ]
    sweep_tx.vout = [CTxOut(
        nValue=total_vaults_amount_sats,
        scriptPubKey=vaults[0].recovery_tr_info.scriptPubKey,
    )]

    for i, vault in enumerate(vaults):
        sweep_tx.wit.vtxinwit += [messages.CTxInWitness()]

        # If the outpoint we're spending isn't an OP_UNVAULT (i.e. if the unvault
        # process hasn't yet been triggered), then we need to reveal the vault via
        # script-path TR witness.
        if vaults_to_outpoints[vault] == vault.vault_outpoint:
            sweep_tx.wit.vtxinwit[i].scriptWitness.stack = [
                vault.vault_spk,
                (bytes([0xC0 + vault.init_tr_info.negflag])
                 + vault.init_tr_info.internal_pubkey),
            ]
        # Otherwise, we're sweeping away from an OP_UNVAULT trigger transaction.
        elif unvault_trigger_tx:
            if unvault_trigger_tx.unvault_output_type != OutputType.Bare:
                sweep_tx.wit.vtxinwit[i].scriptWitness.stack = (
                    unvault_trigger_tx.spend_witness_stack)
        else:
            raise ValueError(
                "must pass `unvault_trigger_tx` if spending from unvault")

    return sweep_tx


# Used to make the OP_UNVAULT output only script-path spendable.
# See `VAULT_NUMS_INTERNAL_PUBKEY` in script/interpreter.cpp.
UNVAULT_NUMS_INTERNAL_PUBKEY = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def get_trigger_unvault_tx(
    target_hash: bytes,
    vaults: t.List[VaultSpec],
    unvault_output_type: OutputType = OutputType.P2TR,
    revault_amount_sats: t.Optional[int] = None,
) -> UnvaultTriggerTransaction:
    """
    Return a transaction that triggers the withdrawal process to some arbitrary
    target output set.

    Args:
        revault_amount_sats (int): if given, "peel off" this amount from the
            total vault value to be revaulted.
    """
    # Okay to take from the first because we want to error if the vaults don't share
    # a spend delay.
    spend_delay = vaults[0].spend_delay

    unvault_spk = CScript([
        # <recovery-spk-hash>
        recovery_spk_tagged_hash(vaults[0].recovery_tr_info.scriptPubKey),
        # <spend-delay>
        spend_delay,
        # <target-outputs-hash>
        target_hash,
        OP_UNVAULT,
    ])

    trigger_tx = UnvaultTriggerTransaction()
    trigger_tx.unvault_output_type = unvault_output_type
    trigger_tx.spend_delay = spend_delay

    total_vaults_amount_sats = sum(v.total_amount_sats for v in vaults)  # type: ignore
    revault_output = None

    if revault_amount_sats:
        total_vaults_amount_sats -= revault_amount_sats
        vault_output = vaults[0].vault_output
        assert vault_output
        revault_output = CTxOut(
            nValue=revault_amount_sats, scriptPubKey=vault_output.scriptPubKey)

    unvault_txout = CTxOut(nValue=total_vaults_amount_sats, scriptPubKey=unvault_spk)

    if unvault_output_type is OutputType.P2WSH:
        unvault_txout.scriptPubKey = CScript([
            OP_0, messages.sha256(unvault_spk),
        ])
        trigger_tx.spend_witness_stack = [unvault_spk]

    elif unvault_output_type is OutputType.P2TR:
        nums_tr = script.taproot_construct(
            UNVAULT_NUMS_INTERNAL_PUBKEY, scripts=[('only-path', unvault_spk, 0xC0)])

        unvault_txout.scriptPubKey = nums_tr.scriptPubKey
        # Cache the taproot info for later use when constructing a spend.
        trigger_tx.spend_witness_stack = [
            unvault_spk,
            (bytes([0xC0 + nums_tr.negflag]) + nums_tr.internal_pubkey),
        ]

    trigger_tx.nVersion = 2
    trigger_tx.vin = [CTxIn(outpoint=v.vault_outpoint) for v in vaults]
    trigger_tx.vout = [unvault_txout]

    if revault_output:
        trigger_tx.vout.append(revault_output)

    vault_outputs = [v.vault_output for v in vaults]

    # Sign the input for each vault and attach a fitting witness.
    for i, vault in enumerate(vaults):
        unvault_sigmsg = script.TaprootSignatureHash(
            trigger_tx, vault_outputs, input_index=i, hash_type=0
        )

        assert isinstance(vault.unvault_tweaked_privkey, bytes)
        unvault_signature = key.sign_schnorr(
            vault.unvault_tweaked_privkey, unvault_sigmsg)

        trigger_tx.wit.vtxinwit += [messages.CTxInWitness()]

        optional_target_hash_on_stack = None

        if unvault_output_type in [OutputType.P2WSH, OutputType.P2TR]:
            optional_target_hash_on_stack = target_hash

        trigger_tx.wit.vtxinwit[i].scriptWitness.stack = list(filter(None, (
            unvault_signature,
            vault.unvault_tr_info.scriptPubKey,

            # Note this is filtered out if Bare output used
            optional_target_hash_on_stack,

            vault.vault_spk,
            (bytes([0xC0 + vault.init_tr_info.negflag])
             + vault.init_tr_info.internal_pubkey),
        )))

    return trigger_tx





def get_final_withdrawal_tx(
    unvault_outpoint: COutPoint,
    final_target_vout: t.List[CTxOut],
    unvault_trigger_tx: UnvaultTriggerTransaction,
) -> CTransaction:
    """
    Return the final transaction, withdrawing a balance to the specified target.
    """
    assert unvault_trigger_tx.spend_delay is not None

    final_tx = CTransaction()
    final_tx.nVersion = 2
    final_tx.vin = [
        CTxIn(outpoint=unvault_outpoint, nSequence=unvault_trigger_tx.spend_delay)
    ]
    final_tx.vout = final_target_vout

    if unvault_trigger_tx.unvault_output_type in [OutputType.P2WSH, OutputType.P2TR]:
        final_tx.wit.vtxinwit += [messages.CTxInWitness()]
        final_tx.wit.vtxinwit[0].scriptWitness.stack = (
            unvault_trigger_tx.spend_witness_stack)

    return final_tx


def recovery_spk_tagged_hash(script: CScript) -> bytes:
    ser = messages.ser_string(script)
    return key.TaggedHash("VaultRecoverySPK", ser)


def unvault_spk_tagged_hash(script: CScript) -> bytes:
    ser = messages.ser_string(script)
    return key.TaggedHash("VaultUnvaultSPK", ser)


def target_outputs_hash(vout: t.List[CTxOut]) -> bytes:
    """Equivalent to `PrecomputedTransactionData.hashOutputs`."""
    return messages.hash256(b"".join(v.serialize() for v in vout))


def taproot_from_privkey(pk: key.ECKey, scripts=None) -> script.TaprootInfo:
    x_only, _ = key.compute_xonly_pubkey(pk.get_bytes())
    return script.taproot_construct(x_only, scripts=scripts)


def split_vault_value(total_val: int, num: int = 3) -> t.List[int]:
    """
    Return kind-of evenly split amounts that preserve the total value of the vault.
    """
    val_segment = total_val // num
    amts = []
    for _ in range(num - 1):
        amts.append(val_segment)
        total_val -= val_segment
    amts.append(total_val)
    return amts


def make_segwit0_spk(privkey: key.ECKey) -> CScript:
    return CScript([script.OP_0, script.hash160(privkey.get_pubkey().get_bytes())])


if __name__ == "__main__":
    VaultsTest().main()
