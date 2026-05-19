# Copyright (c) 2016-2018, Neil Booth
# Copyright (c) 2018, the ElectrumX authors
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''Deserializer for Firo special transaction types'''

from collections import namedtuple
from dataclasses import dataclass
from typing import Any

from electrumx.lib.tx import Deserializer, Tx, ZERO, MINUS_1
from electrumx.lib.tx_axe import (AxeProUpRegTx, AxeProUpRevTx)
from electrumx.lib.util import (pack_le_uint16, pack_le_int32, pack_le_uint32,
                                pack_le_int64, pack_varint, pack_varbytes,
                                pack_be_uint16)


# https://github.com/dashpay/dips/blob/master/dip-0002.md
@dataclass(kw_only=True, slots=True)
class FiroTx(Tx):
    '''Class representing a Firo transaction'''
    tx_type: int
    extra_payload: Any

    def serialize(self):
        nLocktime = pack_le_uint32(self.locktime)
        txins = (pack_varint(len(self.inputs)) +
                 b''.join(tx_in.serialize() for tx_in in self.inputs))
        txouts = (pack_varint(len(self.outputs)) +
                  b''.join(tx_out.serialize() for tx_out in self.outputs))

        if self.tx_type:
            uVersion = pack_le_uint16(self.version)
            uTxType = pack_le_uint16(self.tx_type)
            vExtra = self._serialize_extra_payload()
            return uVersion + uTxType + txins + txouts + nLocktime + vExtra
        else:
            nVersion = pack_le_int32(self.version)
            return nVersion + txins + txouts + nLocktime

    def _serialize_extra_payload(self):
        extra = self.extra_payload
        spec_tx_class = DeserializerFiro.SPEC_TX_HANDLERS.get(self.tx_type)
        if not spec_tx_class:
            assert isinstance(extra, (bytes, bytearray))
            return pack_varbytes(extra)

        if not isinstance(extra, spec_tx_class):
            raise ValueError('Firo tx_type does not conform with extra'
                             ' payload class: %s, %s' % (self.tx_type, extra))
        return pack_varbytes(extra.serialize())


# Firo-specific extra payload types
# Firo extends Axe DIP2 types with additional version fields

@dataclass(kw_only=True, slots=True)
class FiroProRegTx:
    '''Class representing Firo DIP3 ProRegTx (extends Axe with v2 fields)'''
    version: int
    type: int
    mode: int
    collateralOutpoint: 'TxOutPoint'
    ipAddress: bytes
    port: int
    KeyIdOwner: bytes
    PubKeyOperator: bytes
    KeyIdVoting: bytes
    operatorReward: int
    scriptPayout: bytes
    inputsHash: bytes
    platformNodeID: bytes
    platformP2PPort: int
    platformHTTPPort: int
    payloadSig: bytes

    def serialize(self):
        assert (len(self.ipAddress) == 16
                and len(self.KeyIdOwner) == 20
                and len(self.PubKeyOperator) == 48
                and len(self.KeyIdVoting) == 20
                and len(self.inputsHash) == 32)
        res = (
            pack_le_uint16(self.version) +              # version
            pack_le_uint16(self.type) +                 # type
            pack_le_uint16(self.mode) +                 # mode
            self.collateralOutpoint.serialize() +       # collateralOutpoint
            self.ipAddress +                            # ipAddress
            pack_be_uint16(self.port) +                 # port
            self.KeyIdOwner +                           # KeyIdOwner
            self.PubKeyOperator +                       # PubKeyOperator
            self.KeyIdVoting +                          # KeyIdVoting
            pack_le_uint16(self.operatorReward) +       # operatorReward
            pack_varbytes(self.scriptPayout) +          # scriptPayout
            self.inputsHash)                            # inputsHash
        if self.version >= 2:
            res += (self.platformNodeID +               # platformNodeID
                    pack_le_uint16(self.platformP2PPort) +  # platformP2PPort
                    pack_le_uint16(self.platformHTTPPort))  # platformHTTPPort
        res += pack_varbytes(self.payloadSig)           # payloadSig
        return res

    @classmethod
    def read_tx_extra(cls, deser, extra_payload_lengh=None):
        version = deser._read_le_uint16()               # version
        ntype = deser._read_le_uint16()                 # type
        mode = deser._read_le_uint16()                  # mode
        collateralOutpoint = deser._read_outpoint()     # collateralOutpoint
        ipAddress = deser._read_nbytes(16)              # ipAddress
        port = deser._read_be_uint16()                  # port
        KeyIdOwner = deser._read_nbytes(20)             # KeyIdOwner
        PubKeyOperator = deser._read_nbytes(48)         # PubKeyOperator
        KeyIdVoting = deser._read_nbytes(20)            # KeyIdVoting
        operatorReward = deser._read_le_uint16()        # operatorReward
        scriptPayout = deser._read_varbytes()           # scriptPayout
        inputsHash = deser._read_nbytes(32)             # inputsHash
        platformNodeID = b''
        platformP2PPort = 0
        platformHTTPPort = 0
        if version >= 2 and ntype == 1:
            platformNodeID = deser._read_nbytes(20)     # platformNodeID
            platformP2PPort = deser._read_le_uint16()   # platformP2PPort
            platformHTTPPort = deser._read_le_uint16()  # platformHTTPPort
        payloadSig = deser._read_varbytes()             # payloadSig
        return FiroProRegTx(
            version=version,
            type=ntype,
            mode=mode,
            collateralOutpoint=collateralOutpoint,
            ipAddress=ipAddress,
            port=port,
            KeyIdOwner=KeyIdOwner,
            PubKeyOperator=PubKeyOperator,
            KeyIdVoting=KeyIdVoting,
            operatorReward=operatorReward,
            scriptPayout=scriptPayout,
            inputsHash=inputsHash,
            platformNodeID=platformNodeID,
            platformP2PPort=platformP2PPort,
            platformHTTPPort=platformHTTPPort,
            payloadSig=payloadSig,
        )


@dataclass(kw_only=True, slots=True)
class FiroProUpServTx:
    '''Class representing Firo DIP3 ProUpServTx (extends Axe with v2 fields)'''
    version: int
    type: int
    proTxHash: bytes
    ipAddress: bytes
    port: int
    scriptOperatorPayout: bytes
    inputsHash: bytes
    platformNodeID: bytes
    platformP2PPort: int
    platformHTTPPort: int
    payloadSig: bytes

    def serialize(self):
        assert (len(self.proTxHash) == 32
                and len(self.ipAddress) == 16
                and len(self.inputsHash) == 32
                and len(self.payloadSig) == 96)
        res = pack_le_uint16(self.version)              # version
        if self.version >= 2:
            res += pack_le_uint16(self.type)            # type
        res += (
            self.proTxHash +                            # proTxHash
            self.ipAddress +                            # ipAddress
            pack_be_uint16(self.port) +                 # port
            pack_varbytes(self.scriptOperatorPayout) +  # scriptOperatorPayout
            self.inputsHash)                            # inputsHash
        if self.version >= 2:
            res += (self.platformNodeID +               # platformNodeID
                    pack_le_uint16(self.platformP2PPort) +  # platformP2PPort
                    pack_le_uint16(self.platformHTTPPort))  # platformHTTPPort
        res += self.payloadSig                          # payloadSig
        return res

    @classmethod
    def read_tx_extra(cls, deser, extra_payload_lengh=None):
        version = deser._read_le_uint16()               # version
        ntype = 0
        if version >= 2:
            ntype = deser._read_le_uint16()             # type
        proTxHash = deser._read_nbytes(32)              # proTxHash
        ipAddress = deser._read_nbytes(16)              # ipAddress
        port = deser._read_be_uint16()                  # port
        scriptOperatorPayout = deser._read_varbytes()   # scriptOperatorPayout
        inputsHash = deser._read_nbytes(32)             # inputsHash
        platformNodeID = b''
        platformP2PPort = 0
        platformHTTPPort = 0
        if version >= 2 and ntype == 1:
            platformNodeID = deser._read_nbytes(20)     # platformNodeID
            platformP2PPort = deser._read_le_uint16()   # platformP2PPort
            platformHTTPPort = deser._read_le_uint16()  # platformHTTPPort
        payloadSig = deser._read_nbytes(96)             # payloadSig
        return FiroProUpServTx(
            version=version,
            type=ntype,
            proTxHash=proTxHash,
            ipAddress=ipAddress,
            port=port,
            scriptOperatorPayout=scriptOperatorPayout,
            inputsHash=inputsHash,
            platformNodeID=platformNodeID,
            platformP2PPort=platformP2PPort,
            platformHTTPPort=platformHTTPPort,
            payloadSig=payloadSig,
        )


@dataclass(kw_only=True, slots=True)
class FiroCbTx:
    '''Class representing Firo DIP4 coinbase special tx (extends Axe with v3 fields)'''
    version: int
    height: int
    merkleRootMNList: bytes
    merkleRootQuorums: bytes
    bestCLHeightDiff: int
    bestCLSignature: bytes
    assetLockedAmount: int

    def serialize(self):
        assert len(self.merkleRootMNList) == 32
        res = (
            pack_le_uint16(self.version) +              # version
            pack_le_uint32(self.height) +               # height
            self.merkleRootMNList                       # merkleRootMNList
        )
        if self.version > 1:
            assert len(self.merkleRootQuorums) == 32
            res += self.merkleRootQuorums               # merkleRootQuorums
        if self.version > 2:
            res += pack_varint(self.bestCLHeightDiff)
            res += self.bestCLSignature
            res += pack_le_int64(self.assetLockedAmount)
        return res

    @classmethod
    def read_tx_extra(cls, deser, extra_payload_lengh=None):
        version = deser._read_le_uint16()
        height = deser._read_le_uint32()
        merkleRootMNList = deser._read_nbytes(32)
        merkleRootQuorums = b''
        bestCLHeightDiff = 0
        bestCLSignature = b''
        assetLockedAmount = 0
        if version > 1:
            merkleRootQuorums = deser._read_nbytes(32)
        if version > 2:
            bestCLHeightDiff = deser._read_varint()
            bestCLSignature = deser._read_nbytes(96)
            assetLockedAmount = deser._read_le_uint64()
        return FiroCbTx(
            version=version,
            height=height,
            merkleRootMNList=merkleRootMNList,
            merkleRootQuorums=merkleRootQuorums,
            bestCLHeightDiff=bestCLHeightDiff,
            bestCLSignature=bestCLSignature,
            assetLockedAmount=assetLockedAmount,
        )


@dataclass(kw_only=True, slots=True)
class TxOutPoint:
    '''Class representing tx output outpoint'''
    hash: bytes
    index: int

    def serialize(self):
        assert len(self.hash) == 32
        return (
            self.hash +                                 # hash
            pack_le_uint32(self.index)                  # index
        )

    @classmethod
    def read_outpoint(cls, deser):
        return TxOutPoint(
            hash=deser._read_nbytes(32),
            index=deser._read_le_uint32(),
        )


# Firo Lelantus / Spark tx types
class FiroLelantusTx(namedtuple("FiroLelantusTx", "lelantusData")):
    def serialize(self):
        return self.lelantusData

    @classmethod
    def read_tx_extra(cls, deser, extra_payload_lengh):
        tx = FiroLelantusTx(deser.binary[deser.cursor:deser.cursor + extra_payload_lengh])
        deser.cursor += extra_payload_lengh
        return tx


class FiroSparkSpend(namedtuple("FiroSparkSpend", "sparkData")):
    def serialize(self):
        return self.sparkData

    @classmethod
    def read_tx_extra(cls, deser, extra_payload_lengh):
        tx = FiroSparkSpend(deser.binary[deser.cursor:deser.cursor + extra_payload_lengh])
        deser.cursor += extra_payload_lengh
        return tx


class DeserializerFiro(Deserializer):
    '''Deserializer for Firo special tx types'''

    PRO_REG_TX = 1
    PRO_UP_SERV_TX = 2
    PRO_UP_REG_TX = 3
    PRO_UP_REV_TX = 4
    CB_TX = 5
    LELANTUS_TX = 8
    SPARK_SPEND = 9

    SPEC_TX_HANDLERS = {
        PRO_REG_TX: FiroProRegTx,
        PRO_UP_SERV_TX: FiroProUpServTx,
        PRO_UP_REG_TX: AxeProUpRegTx,
        PRO_UP_REV_TX: AxeProUpRevTx,
        CB_TX: FiroCbTx,
        LELANTUS_TX: FiroLelantusTx,
        SPARK_SPEND: FiroSparkSpend,
    }

    def _read_outpoint(self):
        return TxOutPoint.read_outpoint(self)

    def read_tx(self):
        start = self.cursor
        header = self._read_le_uint32()
        tx_type = header >> 16  # DIP2 tx type
        if tx_type:
            version = header & 0x0000ffff
        else:
            version = header

        if tx_type and version < 3:
            version = header
            tx_type = 0

        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        if tx_type:
            extra_payload_size = self._read_varint()
            end = self.cursor + extra_payload_size
            spec_tx_class = DeserializerFiro.SPEC_TX_HANDLERS.get(tx_type)
            if spec_tx_class:
                read_method = getattr(spec_tx_class, 'read_tx_extra', None)
                extra_payload = read_method(self, extra_payload_size)
                assert isinstance(extra_payload, spec_tx_class)
            else:
                extra_payload = self._read_nbytes(extra_payload_size)
            assert self.cursor == end
        else:
            extra_payload = b''
        txid = self.TX_HASH_FN(self.binary[start:self.cursor])
        tx = FiroTx(
            version=version,
            inputs=inputs,
            outputs=outputs,
            locktime=locktime,
            tx_type=tx_type,
            extra_payload=extra_payload,
            txid=txid,
            wtxid=txid,
        )
        return tx

    def _read_input(self):
        tx_input = TxInputFiro(
            self._read_nbytes(32),   # prev_hash
            self._read_le_uint32(),  # prev_idx
            self._read_varbytes(),   # script
            self._read_le_uint32()   # sequence
        )

        if tx_input.prev_idx == MINUS_1 and tx_input.prev_hash == ZERO:
            return tx_input

        if tx_input.script and tx_input.script[0] == 0xc4:  # Sigma spend - mimic a generation tx
            return TxInputFiro(
                ZERO,
                MINUS_1,
                tx_input.script,
                tx_input.sequence
            )

        return tx_input


class TxInputFiro(namedtuple("TxInput", "prev_hash prev_idx script sequence")):
    def serialize(self):
        return b''.join((
            self.prev_hash,
            pack_le_uint32(self.prev_idx),
            pack_varbytes(self.script),
            pack_le_uint32(self.sequence),
        ))

    def is_generation(self):
        '''Test if an input is generation/coinbase like'''
        return self.prev_hash == ZERO
