from binascii import hexlify
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers
from scapy.fields import *

# enable to debug dissectors
conf.debug_dissector = 1

class _PTPPacketBase(Packet):
    """ base class to be used among all PTP Packet definitions."""
    # use this dictionary to set default values for desired fields (mostly on subclasses
    # where not all fields are defined locally)
    # - key : field_name, value : desired value
    # - it will be used from 'init_fields' function, upon packet initialization
    #
    # example : _defaults = {'field_1_name':field_1_value,'field_2_name':field_2_value}
    _defaults = {}

    def _set_defaults(self):
        """ goes through '_defaults' dict setting field default values (for those that have been defined)."""
        for key in self._defaults.keys():
            try:
                self.get_field(key)
            except KeyError:
                pass
            else:
                self.setfieldval(key, self._defaults[key])

    def init_fields(self):
        """ perform initialization of packet fields with desired values.
            NOTE : this funtion will only be called *once* upon class (or subclass) construction
        """
        Packet.init_fields(self)
        self._set_defaults()


class SixBytesField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, '!Q')

    def addfield(self, pkt, s, val):
        return s + struct.pack(self.fmt, self.i2m(pkt, val))[2:8]

    def getfield(self, pkt, s):
        return s[6:], self.m2i(pkt, struct.unpack(self.fmt, b'\x00\x00' + s[:6])[0])

class ScaledNsField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, '!LQ')

    def addfield(self, pkt, s, val):
        mval = self.i2m(pkt, val)
        return s + struct.pack(self.fmt, (m >> 8) & 0xFFFFFFFF, m & 0xFFFFFFFFFFFFFFFF)

    def getfield(self, pkt, s):
        (u, l) = struct.unpack(self.fmt, s[:12])
        mval = (u << 64) + l
        bits = 96
        if (mval & (1 << (bits - 1))) != 0:
            mval = mval - (1 << bits)        # compute negative value
        return s[12:], self.m2i(pkt, mval)

    def h2i(self, pkt, x):
        """Convert human value to internal value"""
        return int(x * 2**16)

    def i2h(self, pkt, x):
        """Convert internal value to human value"""
        return x * 2**-16

    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        return repr(self.i2h(pkt, x)) + ' ns'

class ieee1588(_PTPPacketBase):
    MSG_TYPE_SYNC = 0
    MSG_TYPE_PDELAY_REQ = 2
    MSG_TYPE_PDELAY_RESP = 3
    MSG_TYPE_FOLLOW_UP = 8
    MSG_TYPE_PDELAY_RESP_FOLLOW_UP = 0xA
    MSG_TYPE_ANNOUNCE = 0xB
    MSG_TYPE_SIGNALING = 0xC

    def guess_payload_class(self, payload):
        """ decode ieee1588 frame depending on its type."""

        # if the payload is not long enough
        if len(payload) <= 4:
            return None

        (byte0, byte1) = struct.unpack('!BB', payload[0:2])
        transportSpecific = byte0 >> 4
        messageType = byte0 & 0xF
        version = byte1 & 0xF

        if version == 2:
            if messageType == self.MSG_TYPE_SYNC:
                return ieee1588v2_Sync
            elif messageType == self.MSG_TYPE_FOLLOW_UP:
                return ieee1588v2_Follow_Up
        return ieee1588v2_Header


class ieee1588v2_Header(ieee1588):
    fields_desc = [
        BitEnumField('transportSpecific', 1, 4, {0: 'Default', 1: '802.1as'}),
        BitEnumField('messageType', 0, 4, {0: 'Sync', 2: 'PDelay_Req', 3: 'PDelay_Resp', 8: 'Follow_Up', 
            0xA: 'PDelay_Resp_Follow_Up', 0xB: 'Announce', 0xC: 'Signaling'}),
        BitField('reserved0', 0, 4),
        BitField('versionPTP', 2, 4),
        LenField('messageLength', 0, fmt='H'),
        ByteField('domainNumber', 0),
        ByteField('reserved1', 0),
        FlagsField('flags', 0, 16, ['PTP_LI_61', 'PTP_LI_59', 'PTP_UTC_REASONABLE', 'PTP_TIMESCALE', 'TIME_TRACEABLE',
            'FREQUENCY_TRACEABLE', 'UNDEF', 'UNDEF', 'PTP_ALTERNATE_MASTER', 'PTP_TWO_STEPS', 'PTP_UNICAST', 'UNDEF',
            'UNDEF', 'PTP_PROFILE_V1', 'PTP_PROFILE_V2', 'PTP_SECURITY']),
        LongField('correctionField', 0),
        IntField('reserved2', 0),
        XLongField('ClockIdentity', 0),
        XShortField('SourcePortId', 0),
        XShortField('sequenceId', 0),
        ByteField('controlField', 0),
        SignedByteField('logMessageInterval', 0)
    ]


class ieee1588v2_TLV_Header(ieee1588):
    fields_desc = [
        ShortEnumField('tlvType', 0, {3: 'Organisation extension', 8: 'Path trace'}),
        ShortField('lengthField', 0),
    ]

class ieee1588v2_TLV_Follow_Up(ieee1588):
    fields_desc = [
        ieee1588v2_TLV_Header,
        X3BytesField('organizationId', 0x0080C2),
        X3BytesField('organizationSubType', 1),
        SignedIntField('cumulativeScaledRateOffset', 0),
        ShortField('gmTimeBaseIndicator', 0),
        ScaledNsField('lastGmPhaseChange', 0),
        SignedIntField('scaledLastGmFreqChange', 0),
    ]

class ieee1588v2_Sync(ieee1588):
    name = 'Precision Time Protocol Sync'

    # default values specification
    _defaults = {'messageId': ieee1588.MSG_TYPE_SYNC}

    fields_desc = [
        ieee1588v2_Header,
        SixBytesField('OriginTimestampSec', 0),
        IntField('OriginTimestampNanoSec', 0),
    ]

class ieee1588v2_Follow_Up(ieee1588):
    name = 'Precision Time Protocol Follow up'

    # default values specification
    _defaults = {'messageId': ieee1588.MSG_TYPE_FOLLOW_UP}

    fields_desc = [
        ieee1588v2_Header,
        SixBytesField('PreciseOriginTimestampSec', 0),
        IntField('PreciseOriginTimestampNanoSec', 0),
        PacketLenField("TLV", None, ieee1588v2_TLV_Follow_Up, length_from = lambda pkt:pkt.messageLength - 44),
    ]

bind_layers(Ether, ieee1588, type=0x88F7)