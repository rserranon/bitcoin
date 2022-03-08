#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Un ejemplo de como crear transacciones P2SH_P2WPKH, firmarlas y publicarlas
utilizando el framework funcional.
Trabajo en proceso, sin garantía de funcionar, sigo aprendiendo de Bitcoin y
del framework.
"""
# Imports en orden PEP8 std library primero, después de terceros y 
# finalmente locales


# Evitar importaciones wildcard *
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.key import ECKey
from test_framework.messages import (CTransaction, CTxIn, CTxOut, COutPoint,
                                     CTxInWitness, COIN)
from test_framework.script import OP_0, CScript
from test_framework.script_util import (key_to_p2sh_p2wpkh_script,
                                        scripthash_to_p2sh_script,
                                        keyhash_to_p2pkh_script,
                                        script_to_p2wsh_script)

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.address import hash160, byte_to_base58, key_to_p2sh_p2wpkh

# Mi clase de prueba hereda de BitcoinTestFramework
class ExampleTest(BitcoinTestFramework):

    def set_test_params(self):
        """Este método debe ser sobrescrito para setear los parámetros de la
        prueba."""
        # Cadena nueva, 1 solo nodo de bitcoind y no hay parámetros en la línea de
        # comandos para el nodo
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-testactivationheight=segwit@50"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()


    def run_test(self):
        """Main test logic"""
        self.log.info("Prueba iniciando!")
        self.log.info("Crear algunos bloques 101 y hacer que madure el bloque1")        
        blocks = self.generate(self.nodes[0], COINBASE_MATURITY + 1)

        # Después de generar 101 bloques  hay un UTXO del bloque 1 por 50BTC
        utxos = self.nodes[0].listunspent()
        assert len(utxos) == 1
        assert_equal(utxos[0]["amount"], 50) 

        self.log.info("Seleccionar el UTXO que buscamos")
        utxo = utxos[0]
        self.log.info("UTXOs selecionado: {}".format(utxo))

        key = ECKey()
        key.generate() # generate private key
        pubkey = key.get_pubkey().get_bytes()
        pubkey_hash = hash160(pubkey)
        witness_script = keyhash_to_p2pkh_script(pubkey_hash)
        hashed_script = hash160(witness_script)
        
        script_sig = CScript([ OP_0, pubkey_hash ])
        
        script_pubkey = scripthash_to_p2sh_script(hashed_script)
        destination_address = byte_to_base58(hashed_script, 196) # 196, Bitcoin testnet script hash
        
        self.log.info("Witness script: {}".format(repr(witness_script)))
        self.log.info("scriptSig): {}".format(repr(script_sig)))
        self.log.info("scriptPubKey: {}".format(repr(script_pubkey)))
        self.log.info("Destination Address: {}".format(repr(destination_address)))

        # Create transaction
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(utxo['txid'],16), int(utxo['vout'])), scriptSig=script_sig))
        tx.vout.append(CTxOut((int(utxo['amount']) * COIN) - 1000, script_pubkey))
        tx.rehash()
        self.log.info("Transacción: {}".format(tx))

        # Add witnessscript
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = [witness_script]

        self.log.info("Sign transaction")
        tx_hex = self.nodes[0].signrawtransactionwithwallet(tx.serialize().hex())["hex"]
        self.log.info("Transaction HEX: {}".format(tx_hex))

        decrawtx = self.nodes[0].decoderawtransaction(tx_hex, True)
        descriptor = decrawtx['vout'][0]['scriptPubKey']['desc']
        # Get descriptor
        self.log.info("descriptor: {}".format(descriptor))
        self.log.info("Transacción Decodificada: {}".format(decrawtx))

        # Enviar la transacción al nodo para ser incuida en el mempool
        txid = self.nodes[0].sendrawtransaction(tx_hex)
        self.log.info("Id de Transacción: {}".format(txid))
        
        mempool = self.nodes[0].getrawmempool()
        # asegurar que nuestra transacción está en el mempool
        assert_equal(mempool[0], txid)

        self.log.info("Generar un bloque para que se procese nuestra transacción")        
        blocks = self.generate(self.nodes[0], 1)
        
        # Asegurar que nuestra transacción se minó
        mempool = self.nodes[0].getrawmempool()
        assert len(mempool) == 0

        # Verificar que nuestra transacción movió los BTC a la dirección
        # de destino
        transactions = self.nodes[0].listtransactions()
        assert_equal(transactions[8]["address"], destination_address)
        

        # TODO entender porque nuestra transacción no aparece en los UTXOs 
        # de esta wallet
        utxos = self.nodes[0].listunspent(minconf=0)
        assert len(utxos) > 0
        self.log.info("UTXOs disponibles: {}".format(utxos))
        # Sin embargo si aparece al escanear el UTXOs set usando el descriptor
        utxo_esperado = self.nodes[0].scantxoutset(action="start", scanobjects=[{'desc': descriptor}])
        # La dirección de destino coincide con la dirección de descriptor
        self.log.info("UTXO esperado: {}".format(utxo_esperado['unspents'][0]['desc']))

if __name__ == '__main__':
    ExampleTest().main()