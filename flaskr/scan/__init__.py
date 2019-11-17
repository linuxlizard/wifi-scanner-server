'''
NL80211 module
==============

TODO
'''
import struct
import datetime
import collections
import logging

from pyroute2.common import map_namespace
from pyroute2.netlink import genlmsg
from pyroute2.netlink.generic import GenericNetlinkSocket
from pyroute2.netlink.nlsocket import Marshal
from pyroute2.netlink import nla
from pyroute2.netlink import nla_base
from pyroute2.common import hexdump
from . import oui

log = logging.getLogger(__name__)

# nl80211 commands

NL80211_CMD_UNSPEC = 0
NL80211_CMD_GET_WIPHY = 1
NL80211_CMD_SET_WIPHY = 2
NL80211_CMD_NEW_WIPHY = 3
NL80211_CMD_DEL_WIPHY = 4
NL80211_CMD_GET_INTERFACE = 5
NL80211_CMD_SET_INTERFACE = 6
NL80211_CMD_NEW_INTERFACE = 7
NL80211_CMD_DEL_INTERFACE = 8
NL80211_CMD_GET_KEY = 9
NL80211_CMD_SET_KEY = 10
NL80211_CMD_NEW_KEY = 11
NL80211_CMD_DEL_KEY = 12
NL80211_CMD_GET_BEACON = 13
NL80211_CMD_SET_BEACON = 14
NL80211_CMD_START_AP = 15
NL80211_CMD_NEW_BEACON = NL80211_CMD_START_AP
NL80211_CMD_STOP_AP = 16
NL80211_CMD_DEL_BEACON = NL80211_CMD_STOP_AP
NL80211_CMD_GET_STATION = 17
NL80211_CMD_SET_STATION = 18
NL80211_CMD_NEW_STATION = 19
NL80211_CMD_DEL_STATION = 20
NL80211_CMD_GET_MPATH = 21
NL80211_CMD_SET_MPATH = 22
NL80211_CMD_NEW_MPATH = 23
NL80211_CMD_DEL_MPATH = 24
NL80211_CMD_SET_BSS = 25
NL80211_CMD_SET_REG = 26
NL80211_CMD_REQ_SET_REG = 27
NL80211_CMD_GET_MESH_CONFIG = 28
NL80211_CMD_SET_MESH_CONFIG = 29
NL80211_CMD_SET_MGMT_EXTRA_IE = 30
NL80211_CMD_GET_REG = 31
NL80211_CMD_GET_SCAN = 32
NL80211_CMD_TRIGGER_SCAN = 33
NL80211_CMD_NEW_SCAN_RESULTS = 34
NL80211_CMD_SCAN_ABORTED = 35
NL80211_CMD_REG_CHANGE = 36
NL80211_CMD_AUTHENTICATE = 37
NL80211_CMD_ASSOCIATE = 38
NL80211_CMD_DEAUTHENTICATE = 39
NL80211_CMD_DISASSOCIATE = 40
NL80211_CMD_MICHAEL_MIC_FAILURE = 41
NL80211_CMD_REG_BEACON_HINT = 42
NL80211_CMD_JOIN_IBSS = 43
NL80211_CMD_LEAVE_IBSS = 44
NL80211_CMD_TESTMODE = 45
NL80211_CMD_CONNECT = 46
NL80211_CMD_ROAM = 47
NL80211_CMD_DISCONNECT = 48
NL80211_CMD_SET_WIPHY_NETNS = 49
NL80211_CMD_GET_SURVEY = 50
NL80211_CMD_NEW_SURVEY_RESULTS = 51
NL80211_CMD_SET_PMKSA = 52
NL80211_CMD_DEL_PMKSA = 53
NL80211_CMD_FLUSH_PMKSA = 54
NL80211_CMD_REMAIN_ON_CHANNEL = 55
NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL = 56
NL80211_CMD_SET_TX_BITRATE_MASK = 57
NL80211_CMD_REGISTER_FRAME = 58
NL80211_CMD_REGISTER_ACTION = NL80211_CMD_REGISTER_FRAME
NL80211_CMD_FRAME = 59
NL80211_CMD_ACTION = NL80211_CMD_FRAME
NL80211_CMD_FRAME_TX_STATUS = 60
NL80211_CMD_ACTION_TX_STATUS = NL80211_CMD_FRAME_TX_STATUS
NL80211_CMD_SET_POWER_SAVE = 61
NL80211_CMD_GET_POWER_SAVE = 62
NL80211_CMD_SET_CQM = 63
NL80211_CMD_NOTIFY_CQM = 64
NL80211_CMD_SET_CHANNEL = 65
NL80211_CMD_SET_WDS_PEER = 66
NL80211_CMD_FRAME_WAIT_CANCEL = 67
NL80211_CMD_JOIN_MESH = 68
NL80211_CMD_LEAVE_MESH = 69
NL80211_CMD_UNPROT_DEAUTHENTICATE = 70
NL80211_CMD_UNPROT_DISASSOCIATE = 71
NL80211_CMD_NEW_PEER_CANDIDATE = 72
NL80211_CMD_GET_WOWLAN = 73
NL80211_CMD_SET_WOWLAN = 74
NL80211_CMD_START_SCHED_SCAN = 75
NL80211_CMD_STOP_SCHED_SCAN = 76
NL80211_CMD_SCHED_SCAN_RESULTS = 77
NL80211_CMD_SCHED_SCAN_STOPPED = 78
NL80211_CMD_SET_REKEY_OFFLOAD = 79
NL80211_CMD_PMKSA_CANDIDATE = 80
NL80211_CMD_TDLS_OPER = 81
NL80211_CMD_TDLS_MGMT = 82
NL80211_CMD_UNEXPECTED_FRAME = 83
NL80211_CMD_PROBE_CLIENT = 84
NL80211_CMD_REGISTER_BEACONS = 85
NL80211_CMD_UNEXPECTED_4ADDR_FRAME = 86
NL80211_CMD_SET_NOACK_MAP = 87
NL80211_CMD_CH_SWITCH_NOTIFY = 88
NL80211_CMD_START_P2P_DEVICE = 89
NL80211_CMD_STOP_P2P_DEVICE = 90
NL80211_CMD_CONN_FAILED = 91
NL80211_CMD_SET_MCAST_RATE = 92
NL80211_CMD_SET_MAC_ACL = 93
NL80211_CMD_RADAR_DETECT = 94
NL80211_CMD_GET_PROTOCOL_FEATURES = 95
NL80211_CMD_UPDATE_FT_IES = 96
NL80211_CMD_FT_EVENT = 97
NL80211_CMD_CRIT_PROTOCOL_START = 98
NL80211_CMD_CRIT_PROTOCOL_STOP = 99
NL80211_CMD_GET_COALESCE = 100
NL80211_CMD_SET_COALESCE = 101
NL80211_CMD_CHANNEL_SWITCH = 102
NL80211_CMD_VENDOR = 103
NL80211_CMD_SET_QOS_MAP = 104
NL80211_CMD_ADD_TX_TS = 105
NL80211_CMD_DEL_TX_TS = 106
NL80211_CMD_GET_MPP = 107
NL80211_CMD_JOIN_OCB = 108
NL80211_CMD_LEAVE_OCB = 109
NL80211_CMD_CH_SWITCH_STARTED_NOTIFY = 110
NL80211_CMD_TDLS_CHANNEL_SWITCH = 111
NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH = 112
NL80211_CMD_WIPHY_REG_CHANGE = 113
NL80211_CMD_MAX = NL80211_CMD_WIPHY_REG_CHANGE
(NL80211_NAMES, NL80211_VALUES) = map_namespace('NL80211_CMD_', globals())

NL80211_BSS_ELEMENTS_SSID = 0
NL80211_BSS_ELEMENTS_SUPPORTED_RATES = 1
NL80211_BSS_ELEMENTS_CHANNEL = 3
NL80211_BSS_ELEMENTS_TIM = 5
NL80211_BSS_ELEMENTS_COUNTRY = 7
NL80211_BSS_ELEMENTS_HT_CAPABILITIES = 45
NL80211_BSS_ELEMENTS_RSN = 48
NL80211_BSS_ELEMENTS_EXTENDED_RATE = 50
NL80211_BSS_ELEMENTS_HT_OPERATION = 61
NL80211_BSS_ELEMENTS_EXT_CAPABILITIES = 127
NL80211_BSS_ELEMENTS_VHT_CAPABILITIES = 191
NL80211_BSS_ELEMENTS_VHT_OPERATION = 192
NL80211_BSS_ELEMENTS_VENDOR = 221
(NL80211_BSS_ELEMENTS_NAMES, NL80211_BSS_ELEMENTS_VALUES) =\
    map_namespace('NL80211_BSS_ELEMENTS_', globals())

BSS_MEMBERSHIP_SELECTOR_HT_PHY = 127
BSS_MEMBERSHIP_SELECTOR_VHT_PHY = 126

# interface types
NL80211_IFTYPE_UNSPECIFIED = 0
NL80211_IFTYPE_ADHOC = 1
NL80211_IFTYPE_STATION = 2
NL80211_IFTYPE_AP = 3
NL80211_IFTYPE_AP_VLAN = 4
NL80211_IFTYPE_WDS = 5
NL80211_IFTYPE_MONITOR = 6
NL80211_IFTYPE_MESH_POINT = 7
NL80211_IFTYPE_P2P_CLIENT = 8
NL80211_IFTYPE_P2P_GO = 9
NL80211_IFTYPE_P2P_DEVICE = 10
NL80211_IFTYPE_OCB = 11
(IFTYPE_NAMES, IFTYPE_VALUES) = map_namespace('NL80211_IFTYPE_',
                                              globals(),
                                              normalize=True)

# channel width
NL80211_CHAN_WIDTH_20_NOHT = 0  # 20 MHz non-HT channel
NL80211_CHAN_WIDTH_20 = 1       # 20 MHz HT channel
NL80211_CHAN_WIDTH_40 = 2       # 40 MHz HT channel
NL80211_CHAN_WIDTH_80 = 3       # 80 MHz channel
NL80211_CHAN_WIDTH_80P80 = 4    # 80+80 MHz channel
NL80211_CHAN_WIDTH_160 = 5      # 160 MHz channel
NL80211_CHAN_WIDTH_5 = 6        # 5 MHz OFDM channel
NL80211_CHAN_WIDTH_10 = 7       # 10 MHz OFDM channel
(CHAN_WIDTH, WIDTH_VALUES) = map_namespace('NL80211_CHAN_WIDTH_',
                                           globals(),
                                           normalize=True)

# BSS "status"
NL80211_BSS_STATUS_AUTHENTICATED = 0  # Authenticated with this BS
NL80211_BSS_STATUS_ASSOCIATED = 1     # Associated with this BSS
NL80211_BSS_STATUS_IBSS_JOINED = 2    # Joined to this IBSS
(BSS_STATUS_NAMES, BSS_STATUS_VALUES) = map_namespace('NL80211_BSS_STATUS_',
                                                      globals(),
                                                      normalize=True)

NL80211_SCAN_FLAG_LOW_PRIORITY = 1 << 0
NL80211_SCAN_FLAG_FLUSH = 1 << 1
NL80211_SCAN_FLAG_AP = 1 << 2
NL80211_SCAN_FLAG_RANDOM_ADDR = 1 << 3
NL80211_SCAN_FLAG_FILS_MAX_CHANNEL_TIME = 1 << 4
NL80211_SCAN_FLAG_ACCEPT_BCAST_PROBE_RESP = 1 << 5
NL80211_SCAN_FLAG_OCE_PROBE_REQ_HIGH_TX_RATE = 1 << 6
NL80211_SCAN_FLAG_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION = 1 << 7
(SCAN_FLAGS_NAMES, SCAN_FLAGS_VALUES) = map_namespace('NL80211_SCAN_FLAG_',
                                                      globals())

NL80211_STA_FLAG_AUTHORIZED = 1
NL80211_STA_FLAG_SHORT_PREAMBLE = 2
NL80211_STA_FLAG_WME = 3
NL80211_STA_FLAG_MFP = 4
NL80211_STA_FLAG_AUTHENTICATED = 5
NL80211_STA_FLAG_TDLS_PEER = 6
NL80211_STA_FLAG_ASSOCIATED = 7
(STA_FLAG_NAMES, STA_FLAG_VALUES) = map_namespace('NL80211_STA_FLAG_',
                                                  globals())


OUI_IEEE = "00-0f-ac"
OUI_MSFT = "00-50-f2"
OUI_WFA = "50-6f-9a"

class IE:
    # note: using the raw integers in the descendents so can keep the hierarchy
    # in numerical order
    ID = -1

    Grammar = collections.namedtuple("Grammar",
                                     ("offset", "mask", "name"))

    Value = collections.namedtuple("Value",
                                   ("name", "value",))

    def __init__(self, data):
        # data is the buffer
        # Caller is responsible for parsing:
        #   id: octet
        #   len: octet
        #   data: octet(s) <-- we get this
        # and sending us the data
        self.data = data

        # array of IE.Value
        self.fields = []

    def __getitem__(self, idx):
        return self.fields[idx]

    def format_oui(self, data):
        return "%02x-%02x-%02x" % (data[0], data[1], data[2])

    def decode_integer(self, grammar, value):
        """An Information element consisting of a bit fields that fits into an
        intrinsic integer type. Straightforward to decode.
        """
        decode = [None] * (grammar[-1].offset + 1)
        for field in grammar:
            num = (value >> field.offset) & field.mask
            log.debug("num=%r name=%r", num, field.name)
            decode[field.offset] = IE.Value(field.name, num)
        return decode

    def decode(self):
        """IE child will decode its contents into self.fields."""
        pass

    def pretty_print(self):
        """IE child will decode its self.fields into a human useful value"""
        return ""


class SSID(IE):
    ID = 0

    def decode(self):
        # Be VERY careful with the SSID. Can contain hostile input.
        # SQL injection. Terminal characters. HTML injection. XSS. etc.
        fmt = '%is' % len(self.data)
        self.fields = IE.Value("SSID", struct.unpack(fmt, self.data)[0])

    def pretty_print(self):
        # TODO utf8 encoding of SSID is optional. Shouldn't be unconditionally 
        # treating as UTF8
        #
        try:
            s = self.fields.value.decode("utf8")
            # TODO check for unprintable chars (how badly will this hose unicode????)
            return s
        except UnicodeDecodeError:
            msg = "(error! SSID is invalid unicode) " + hexdump(self.fields.value)
            log.error(msg)
            return msg

class Supported_Rates(IE):
    ID = 1

    def _decode_byte(self, byte):
        # iw scan.c print_supprates()
        r = byte & 0x7f
        if r == BSS_MEMBERSHIP_SELECTOR_VHT_PHY and byte & 0x80:
            # support for mandatory features required
            rate = "VHT"
        elif r == BSS_MEMBERSHIP_SELECTOR_HT_PHY and byte & 0x80:
            # support for mandatory features required
            rate = "HT"
        else:
            rate = float("%d.%d" % (r / 2, 5 * (r & 1)))

        required = bool(byte & 0x80)

        return (rate,required)
        
    def decode(self):
        # Supported Rates and BSS Membership Selectors
        # 9.4.2.3 80211-2016.pdf
        #
        # "The Supported Rates and BSS Membership Selectors element and
        # Extended Supported Rates and BSS Membership Selectors element in
        # Beacon and Probe Response frames is used by STAs in order to avoid
        # associating with a BSS if they do not support all of the data rates
        # in the BSSBasicRateSet parameter or all of the BSS membership
        # requirements in the BSSMembershipSelectorSet parameter."
        #
        # 11.1.4.6 80211-2016.pdf

        fmt = "%dB" % len(self.data) 
        decoded = [self._decode_byte(b) for b in struct.unpack(fmt, self.data)]

        basic_rate_set = [rate[0] for rate in decoded if rate[1] and not isinstance(rate[0], str)]
        oper_rate_set = [rate[0] for rate in decoded if not rate[1] and not isinstance(rate[0], str)]
        memb_selector_set = [rate[0] for rate in decoded if isinstance(rate[0],str)]

        self.fields = [ IE.Value("BSS Basic Rate Set", basic_rate_set),
                        IE.Value("BSS Operational Rate Set", oper_rate_set),
                        IE.Value("BSS Membership Selector Set", memb_selector_set),
                      ]

    def pretty_print(self):
        string = ""
        fmt = "%dB" % len(self.data) 
        for byte in struct.unpack(fmt, self.data):
            # if byte & 0x80 then it's a required rate
            # following code from iw scan.c print_supprates()
            r = byte & 0x7f
            if r == BSS_MEMBERSHIP_SELECTOR_VHT_PHY and byte & 0x80:
                string += "VHT"
            elif r == BSS_MEMBERSHIP_SELECTOR_HT_PHY and byte & 0x80:
                string += "HT"
            else:
                string += "%d.%d" % (r / 2, 5 * (r & 1))
            string += "%s " % ("*" if byte & 0x80 else "")

        return string


class DSSS_Parameter_Set(IE):
    ID = 3

    def decode(self):
#        self.fields = list(struct.unpack('B', self.data))
        self.fields = IE.Value("channel", struct.unpack('B', self.data)[0])

    def pretty_print(self):
        # single valued field
        return "channel {}".format(self.fields.value)


class TIM(IE):
    # Traffic Indication Map
    ID = 5

    def decode(self):
        (count, period, bitmapc,) = struct.unpack('BBB', self.data[0:3])
        bitmap_hex = hexdump(self.data[3:])

        self.fields = [
            IE.Value("DTIM Count", count),
            IE.Value("DTIM Period", period),
            IE.Value("Bitmap Control", bitmapc),
            IE.Value("Bitmap", bitmap_hex)]

    def pretty_print(self):
        count = self.fields[0].value
        period = self.fields[1].value
        bitmapc = self.fields[2].value
        bitmap = self.fields[3].value

        return ("DTIM Count {0} DTIM Period {1} Bitmap Control 0x{2} "
                "Bitmap {3}".format(count, period, bitmapc, bitmap))


class Country(IE):
    ID = 7

    # iw scan.c print_country()
    IEEE80211_COUNTRY_EXTENSION_ID  = 201 

    def decode(self):
        offset = 0
        # hostile input opportunity: invalid length in country IE
        if len(self.data) < 3:
            log.error("invalid length=%d in country code", len(self.data))
            return

        country_bytes, = struct.unpack("3s", self.data[0:3])

        # dot11CountryString Annex C, page 2787 80211_2016.pdf
        # must be valid ISO-3166-1
        # https://en.wikipedia.org/wiki/ISO_3166-1
        # https://www.iso.org/iso-3166-country-codes.html (US$40? seriously?)
        #
        # beware hostile input; this field is usually treated as a printable
        # string so need to do extra validation
        iso3166_char = lambda byte : chr(byte) if byte >= ord('A') and byte <= ord('Z') else '?'
        country_string = iso3166_char(country_bytes[0]) + iso3166_char(country_bytes[1])

        environment = country_bytes[2]
        if environment == ord(' '):
            environment = "Indoor/Outdoor"
        elif environment == ord('O'):
            environment = "Outdoor only"
        elif environment == ord('I'):
            environment = "Indoor only"
        elif environment == ord('X'):
            environment = "Non-country"
        else:
            environment = "(invalid!)"

        self.fields = [ IE.Value("Country", country_string), 
                        IE.Value("Environment", environment),
                      ]

        if len(self.data) == 3:
            # no country codes so can leave now
            log.debug("No country IE triplets present")
            return

        # now the decode gets weird
        # iw scan.c print_country()
        offset = 3
        subband_triplets = IE.Value("Subbands", [])
        while offset+2 < len(self.data):
            triplet = struct.unpack("BBB", self.data[offset:offset+3])
            if triplet[0] >= self.IEEE80211_COUNTRY_EXTENSION_ID:
                val_triplet = [IE.Value("Extension ID", triplet[0]), 
                               IE.Value("Regulatory Class", triplet[1]),
                               IE.Value("Coverage Class", triplet[2])]
            else:
                val_triplet = [IE.Value("First Channel", triplet[0]), 
                               IE.Value("Number of Channels", triplet[1]),
                               IE.Value("Max TX Power (dBm)", triplet[2])]
            offset += 3

            subband_triplets.value.append(val_triplet)

        self.fields.append(subband_triplets)

class HT_Capabilities(IE):
    # iw scan.c print_ht_capa()
    # iw util. print_ht_capability()
    ID = 45

    # Capability Info bit 1
    channel_width = ("HT20", "HT20/HT40")

    # Capability Info bits 2,3
    power_save = ("Static SM Power Save",
                  "Dynamic SM Power Save",
                  "Reserved",
                  "SM Power Save disabled")

    # Capability Info bits 8,9
    rx_stbc_streams = ("No RX STBC",
                       "RX STBC 1-stream",
                       "RX STBC 2-streams",
                       "RX STBC 3-streams")

    # Capability Info bit 11
    amsdu_length = (3839, 7935)

    # Capability Info
    capa_grammar = (
        IE.Grammar(0, 1, "RX LDPC"),
        IE.Grammar(1, 1, "HT20/HT40"),
        IE.Grammar(2, 3, "SM Power Save"),
        IE.Grammar(4, 1, "RX Greenfield"),
        IE.Grammar(5, 1, "RX HT20 SGI"),
        IE.Grammar(6, 1, "RX HT40 SGI"),
        IE.Grammar(7, 1, "TX STBC"),
        IE.Grammar(8, 3, "RX STBC"),
        IE.Grammar(10, 1, "HT Delayed Block Ack"),
        IE.Grammar(11, 1, "Max AMSDU length"),
        IE.Grammar(12, 1, "DSSS/CCK HT40"),
        # 13 is reserved
        IE.Grammar(14, 1, "40 Mhz Intolerant"),
        IE.Grammar(15, 1, "L-SIG TXOP protection"),
    )

    ampdu_grammar = (
        IE.Grammar(0, 2, "Maximum RX AMPDU length"),
        IE.Grammar(2, 3, "Minimum RX AMPDU time"),
    )

    extended_capa_grammar = (
        IE.Grammar(0, 1, "PCO"),
        IE.Grammar(1, 2, "PCO Transition Time"),
        # bits 3-7 reserved
        IE.Grammar(8, 2, "MCS Feedback"),
        IE.Grammar(10, 1, "HTC-HT Support"),
        IE.Grammar(11, 1, "RD Responder"),
        # bits 12-15 reserved
    )

    tx_beam_form_capabilities_grammar = (
        IE.Grammar(0, 1, "Implicit Tx Beamforming Receive"),
        IE.Grammar(1, 1, "Receive Staggered Sound"),
        IE.Grammar(2, 1, "Transmit Staggered Sound"),
        IE.Grammar(3, 1, "Receive NDP"),
        IE.Grammar(4, 1, "Transmit NDP"),
        IE.Grammar(5, 1, "Implicit Transmit Beamforming"),
        IE.Grammar(6, 2, "Calibration"),
        IE.Grammar(8, 1, "Explicit CSI Transmit Beamform"),
        IE.Grammar(9, 1, "Explicit Noncompressed Steering"),
        IE.Grammar(10, 1, "Explicit Compressed Steering"),
        IE.Grammar(11, 2, "Explicit Transform Beamforming CSI Feedback"),
        IE.Grammar(13, 2, "Explicit Noncompressed Beamforming Feedback"),
        IE.Grammar(15, 2, "Explicit Compressed Beamforming Feedback"),
        IE.Grammar(17, 2, "Minimal Grouping"),
        IE.Grammar(19, 2, "CSI Number of Beamformer Antennae"),
        IE.Grammar(21, 2, "Noncompressed Steering Num of Beamformer Antennae"),
        IE.Grammar(23, 2, "Compressed Steering Number of Beamformer Antennae"),
        IE.Grammar(25, 2, "CSI Max Number of Rows Beamformer"),
        IE.Grammar(27, 2, "Channel Estimation"),
    )

    asel_capabilities = (
        IE.Grammar(0, 1, "Antenna Selection Capable"),
        IE.Grammar(1, 1, "Explicit CSI Feedback Based TX ASEL"),
        IE.Grammar(2, 1, "Antenna Indices Feedback"),
        IE.Grammar(3, 1, "Explicit CSI Feedback"),
        IE.Grammar(4, 1, "Antennae Indices Feedback"),
        IE.Grammar(5, 1, "Receive ASEL"),
        IE.Grammar(6, 1, "Transmit Sounding PPDUs"),
        IE.Grammar(7, 1, "Reserved"),
    )

    # iw util.c compute_ampdu_length()
    #
    # "There are only 4 possible values, we just use a case instead of
    # computing it, but technically this can also be computed through the
    # formula:
    #   Max AMPDU length = (2 ^ (13 + exponent)) - 1 bytes"
    #
    ampdu_length = (8191,   # /* (2 ^(13 + 0)) -1 */
                    16383,  # /* (2 ^(13 + 1)) -1 */
                    32767,  # /* (2 ^(13 + 2)) -1 */
                    65535,  # /* (2 ^(13 + 3)) -1 */
                    )

    # iw util.c print_ampdu_space()
    ampdu_space = (
        "No restriction",
        "1/4 usec",
        "1/2 usec",
        "1 usec",
        "2 usec",
        "4 usec",
        "8 usec",
        "16 usec",
    )

    def decode(self):
        # 9.4.2.56.1. HT Capabilities Information Structure
        # (Section numbers are from 80211-2016.pdf)
        offset = 0

        # 9.4.2.56.2 HT Capability Info Field
        # 2 octets
        num, = struct.unpack_from("<H", self.data, offset)
        self.fields.append(IE.Value('HT Capability Info',
                           self.decode_integer(self.capa_grammar, num)))
        offset += 2

        # 9.4.2.56.3 A-MPDU Parameters
        # 1 octet
        num, = struct.unpack_from("B", self.data, offset)
        self.fields.append(IE.Value('AMPDU Parameters',
                           self.decode_integer(self.ampdu_grammar, num)))
        offset += 1

        # 9.4.2.56.4 Supported MCS Set
        # 16 octets
        # iw util.c print_ht_mcs
        mcs = struct.unpack_from("16B", self.data, offset)
        self.fields.append(IE.Value("Supported MCS Set", mcs))
        # TODO MCS crazy complicated so finish later
        # max_rx_supp_data_rate = (mcs[10] | ((mcs[11] & 0x3) << 8));
        # tx_mcs_set_defined = not(not(mcs[12] & (1 << 0)));
        # tx_mcs_set_equal = not(mcs[12] & (1 << 1));
        # tx_max_num_spatial_streams = ((mcs[12] >> 2) & 3) + 1;
        # tx_unequal_modulation = not(not(mcs[12] & (1 << 4)));
        offset += 16

        # HT Extended Capabilities
        # 2 octets
        num, = struct.unpack_from("<H", self.data, offset)
        self.fields.append(IE.Value("HT Extended Capabilities",
                           self.decode_integer(self.extended_capa_grammar,
                                               num)))
        offset += 2

        # TX beamforming capabilities
        # 4 octets
        num, = struct.unpack_from("<L", self.data, offset)
        val = self.decode_integer(self.tx_beam_form_capabilities_grammar, num)
        self.fields.append(IE.Value("TX Beamforming Capabilities", val))
        offset += 4

        # ASEL capabilities
        # 1 octet
        num, = struct.unpack_from("B", self.data, offset)
        self.fields.append(IE.Value("ASEL Capability",
                           self.decode_integer(self.asel_capabilities, num)))
        offset += 1

    def channel_width_str(self, value):
        return self.channel_width[value]

    def sm_power_save_str(self, value):
        return self.power_save[value]

    def rx_stbc_str(self, value):
        return self.rx_stbc_streams[value]

    def max_amsdu_len(self, value):
        return self.amsdu_length[value]


class RSN(IE):
    # Robust Security Network
    ID = 48

    # table 9-131  "Cipher Suite Selectors" 80211_2016.pdf 
    cipher_suite_selectors = (
        "Use group cipher suite",
        "WEP-40",
        "TKIP", 
        "Reserved",
        "CCMP-128",
        "WEP-104",
        "Group addressed traffic not allowed",
        "GCMP-128",
        "GCMP-256",
        "CCMP-256",
        "BIP-GMAC-128",
        "BIP-GMAC-256")

    auth_type_name_list = (
        "Reserved",
        "IEEE 8021.X",
        "PSK",
        "FT/IEEE 802.1X",
        "FT/PSK",
        "IEEE 802.1X/SHA-256",
        "PSK/SHA-256",
        "TDLS/TPK",
        "SAE",
        "SAE",
        "IEEE 802.1X/SUITE-B",
        "IEEE 802.1X/SUITE-B-192",
        "FT/IEEE 802.1X/SHA-384",
        "FILS/SHA-256",
        "FILS/SHA-384",
        "FT/FILS/SHA-256",
        "FT/FILS/SHA-384",
        "OWE")

    rsn_capabilities = (
        IE.Grammar(0, 1, "Preauth"),
        IE.Grammar(1, 1, "NoPairwise"),
        IE.Grammar(2, 2, "PTKSA-RC"),
        IE.Grammar(4, 2, "GTKSA-RC"),
        IE.Grammar(6, 1, "MFP-required"),
        IE.Grammar(7, 1, "MFP-capable"),
        IE.Grammar(8, 1, "Joint Multi-Band RSNA"),
        IE.Grammar(9, 1, "Peerkey-enabled"),
        IE.Grammar(10, 1, "SPP-AMSDU-capable"),
        IE.Grammar(11, 1, "SPP-AMSDU-required"),
        IE.Grammar(12, 1, "PBAC"),
        IE.Grammar(13, 2, "Ext Key ID"),
        IE.Grammar(14, 2, "Reserved"),
    )

    # 9.4.2.25 RSNE  80211_2016.pdf
    def decode(self):
        # (this one is super messy)
        # iw scan.c print_rsn() -> print_rsn_ie() -> _print_rsn_ie()
        # So _print_rsn_ie() is the best place to start.
        offset = 0
        version = self.data[0] + (self.data[1] << 8)

        self.fields = [IE.Value("Version", version), ]
        offset += 2

        # pretty much optional fields from here on down
        # so have to carefully check len(self.data) after every field

        # Group Data Cipher Suite
        group = struct.unpack("4B", self.data[offset:offset+4])
        self.fields.append( IE.Value("Group Cipher Suite", self._decode_cipher(group)))
        offset += 4
        if offset >= len(self.data): return

        # Pairwise Cipher Suite Count
        pairwise_count, = struct.unpack("<H", self.data[offset:offset+2])
        self.fields.append(IE.Value("Pairwise Count", pairwise_count))
        offset += 2
        if offset >= len(self.data): return

        # Pairwise Cipher Suite List
        length = 4 * pairwise_count
        fmt = "%dB" % length
        pairwise_bytes = struct.unpack(fmt, self.data[offset:offset+length])
        pairwise_list = [self._decode_cipher(pairwise_bytes[n:n+4]) for n in range(0, length, 4)]
        self.fields.append(IE.Value("Pairwise Bytes", pairwise_list))
        offset += length
        if offset >= len(self.data): return

        # AKM Suite Count
        akm_suite_count, = struct.unpack("<H", self.data[offset:offset+2])
        self.fields.append(IE.Value("AKM Suite Count", akm_suite_count))
        offset += 2
        if offset >= len(self.data): return

        # AKM Suite List
        length = 4 * akm_suite_count
        fmt = "%dB" % length
        akm_suite_bytes = struct.unpack(fmt, self.data[offset:offset+length])
        akm_suite_list = [self._decode_auth(akm_suite_bytes[n:n+4]) for n in range(0,length,4)]
        self.fields.append(IE.Value("AKM Suite", akm_suite_list))
        offset += length
        if offset >= len(self.data): return

        # RSN Capabilities
        rsn_capa, = struct.unpack("<H", self.data[offset:offset+2])
        self.fields.append(IE.Value("RSN Capabilities", 
                           self.decode_integer(self.rsn_capabilities, rsn_capa)))
        offset += 2
        if offset >= len(self.data): return

        # PMKID Count
        pmkid_count, = struct.unpack("<H", self.data[offset:offset+2])
        self.fields.append(IE.Value("PMKID Count", pmkid_count))
        offset += 2
        if offset >= len(self.data): return

        # PMKID List

        # Group Management Cipher Suite


    def _decode_cipher(self, bytelist):
        # iw scan.c print_cipher()
        oui = self.format_oui(bytelist[0:3])
        suite_type = bytelist[3]

        meaning = "Vendor-specific"
        if oui == OUI_IEEE:
            try:
                meaning = self.cipher_suite_selectors[suite_type]
            except IndexError:
                meaning = "Reserved"
        elif oui == OUI_MS:
            # TODO
            pass

        return [IE.Value("OUI", oui),
                IE.Value("Suite Type", suite_type), 
                IE.Value("Suite Name", meaning),
               ]

    def _decode_auth(self, bytelist):
        # iw scan.c print_auth()
        oui = self.format_oui(bytelist[0:3])
        suite_type = bytelist[3]

        meaning = "Vendor-specific"
        if oui == OUI_IEEE:
            try:
                meaning = self.auth_type_name_list[suite_type]
            except IndexError:
                meaning = "Reserved"
        elif oui == OUI_MS:
            # TODO
            pass

        return [IE.Value("OUI", oui),
                IE.Value("Suite Type", suite_type), 
                IE.Value("Suite Name", meaning),
               ]

class Extended_Rates(Supported_Rates):
    ID = 50
    # same format as supported rates so this one is easy!


class HT_Operation(IE):
    # iw scan.c print_ht_op()
    ID = 61

    # Note: using the same strings as being used in 'iw' to be as compatible as
    # possible
    info_1_grammar = (
        IE.Grammar(0, 2, "secondary channel offset"),
        IE.Grammar(2, 1, "STA channel width"),
        IE.Grammar(3, 1, "RIFS"),
        IE.Grammar(8, 2, "HT Protection"),
        IE.Grammar(10, 1, "non-GF present"),
        IE.Grammar(12, 1, "OBSS non-GF present"),
        IE.Grammar(13, 2047, "Channel Center Frequency Segment 2"),   # 11 bits
        IE.Grammar(30, 1, "dual beacon"),
        IE.Grammar(31, 1, "dual CTS protection"),
    )

    info_2_grammar = (
        IE.Grammar(0, 1, "STBC Beacon"),
        IE.Grammar(1, 1, "L-SIG TXOP Prot"),
        IE.Grammar(2, 1, "PCO active"),
        IE.Grammar(3, 1, "PCO phase"),
    )

    # iw scan.c ht_secondary_offset[]
    ht_secondary_offset = (
        "no secondary",
        "above",
        "[reserved!]",
        "below",
    )

    # iw scan.c sta_chan_width[]
    sta_chan_width = (
        "20 MHz",
        "any",
    )

    def decode(self):
        # 9.4.2.57 HT Operation element
        offset = 0

        # primary channel
        # 1 octet
        num, = struct.unpack_from("B", self.data, offset)
        self.fields.append(IE.Value("Primary Channel", num))
        offset += 1

        # HT Operation Information
        # 5 octets
        #  - fields are spread unevenly across bytes
        #  - want to be easily compatible with 32-bit systems
        #  - natural break occurs at B31 "Dual CTS Protection"
        # therefore decode into a uint32_t and uint16_t
        info = struct.unpack_from("<LH", self.data, offset)
        info_fields = self.decode_integer(self.info_1_grammar, info[0])
        info_fields.extend(self.decode_integer(self.info_2_grammar, info[1]))
        self.fields.append(IE.Value("Information", info_fields))
        offset += 5

        # Basic MT-MCS Set
        # 16 octets
        mcs = struct.unpack_from("16B", self.data, offset)
        self.fields.append(IE.Value("Basic HT-MCS Set", mcs))
        offset += 16

    def secondary_channel_offset(self, value):
        return self.ht_secondary_offset[value]

    def sta_channel_width(self, value):
        return self.sta_chan_width[value]


class Extended_Capabilities(IE):
    ID = 127

    # iw scan.c print_capabilities()
    bits = (
        (
            "HT Information Exchange Supported",  # 0
            "reserved (On-demand Beacon)",
            "Extended Channel Switching",
            "reserved (Wave Indication)",
            "PSMP Capability",
            "reserved (Service Interval Granularity)",
            "S-PSMP Capability",
            "Event",
        ),
        (
            "Diagnostics",  # 8
            "Multicast Diagnostics",
            "Location Tracking",
            "FMS",
            "Proxy ARP Service",
            "Collocated Interference Reporting",
            "Civic Location",
            "Geospatial Location",
        ),
        (
            "TFS",  # 16
            "WNM-Sleep Mode",
            "TIM Broadcast",
            "BSS Transition",
            "QoS Traffic Capability",
            "AC Station Count",
            "Multiple BSSID",
            "Timing Measurement",
        ),
        (
            "Channel Usage",  # 24
            "SSID List",
            "DMS",
            "UTC TSF Offset",
            "TDLS Peer U-APSD Buffer STA Support",
            "TDLS Peer PSM Support",
            "TDLS channel switching",
            "Interworking",
        ),
        (
            "QoS Map",  # 32
            "EBR",
            "SSPN Interface",
            "Reserved",
            "MSGCF Capability",
            "TDLS Support",
            "TDLS Prohibited",
            "TDLS Channel Switching Prohibited",
        ),
        (
            "Reject Unadmitted Frame",  # 40
            "SI Duration Bit0",
            "SI Duration Bit1",
            "SI Duration Bit2",
            "Identifier Location",
            "U-APSD Coexistence",
            "WNM-Notification",
            "Reserved",
        ),
        (
            "UTF-8 SSID",  # 48
            "QMFActivated",
            "QMFReconfigurationActivated",
            "Robust AV Streaming",
            "Advanced GCR",
            "Mesh GCR",
            "SCS",
            "QLoad Report",
        ),
        (
            "Alternate EDCA",  # 56
            "Unprotected TXOP Negotiation",
            "Protected TXOP egotiation",
            "Reserved",
            "Protected QLoad Report",
            "TDLS Wider Bandwidth",
            "Operating Mode Notification",
            "MAX AMSDU bit0",
        ),
        (
            "MAX AMSDU bit1",
            "Channel Schedule Management",
            "Geodatabase Inband Enabling Signal",
            "Network Channel Control",
            "White Space Map",
            "Channel Availability Query",
            "FTM Responder",
            "FTM Initiator",
        ),
        (
            "Reserved",
            "Extended Spectrum Management Capable",
            "Reserved",
        )
    )

    def decode(self):
        # variable length field

        nums = struct.unpack("%dB" % len(self.data), self.data)

        # TODO use is_vht to decode Max AMSDU (somehow...)
        self.fields = [IE.Value(self.bits[byte][bit], nums[byte] & (1 << bit))
                       for byte in range(min(8, len(nums)))
                       for bit in range(0, 8)]


class VHT_Capabilities(IE):
    # iw scan.c print_vht_capa()
    # iw util.c print_vht_info()
    # iw scan.c print_vht_oper()
    ID = 191

    # -1 for invalid/reserved
    max_mpdu = (3895, 7991, 11454, -1)

    channel_width = ("neither 160 nor 80+80",
                     "160 MHz",
                     "160 Mhz, 80+80 Mhz",
                     "(reserved)")

    capa_grammar = (
        # offset, mask, type, name
        IE.Grammar(0, 2, "Max MPDU length"),
        IE.Grammar(2, 2, "Supported Channel Width"),
        IE.Grammar(4, 1, "RX LDPC"),
        IE.Grammar(5, 1, "short GI (80 MHz)"),
        IE.Grammar(6, 1, "short GI (160/80+80 MHz)"),
        IE.Grammar(7, 1, "TX STBC"),
        # TODO RX STBC bits 8,9,10
        IE.Grammar(11, 1, "SU Beamformer"),
        IE.Grammar(12, 1, "SU Beamformee"),
        # TODO compressed steering bits 13,14,15
        # TODO num of sounding dimensions bits 16,17,18
        IE.Grammar(19, 1, "MU Beamformer"),
        IE.Grammar(20, 1, "MU Beamformee"),
        IE.Grammar(21, 1, "VHT TXOP PS"),
        IE.Grammar(22, 1, "+HTC-VHT"),
        # TODO max A-MPDU bits 23,24,25
        # TODO VHT link adaptation bits 26,27
        IE.Grammar(28, 1, "RX antenna pattern consistency"),
        IE.Grammar(29, 1, "TX antenna pattern consistency")
        # TODO NSS BW Support bits 30,31
    )

    def decode(self):
        offset = 0
        # 4 octets
        num, = struct.unpack_from("<L", self.data, offset)
        self.fields.append(IE.Value("VHT Capability Info",
                           self.decode_integer(self.capa_grammar, num)))
        offset += 4

        # 8 octets
        num = struct.unpack_from("<4H", self.data, offset)
        # TODO decode MCS
        self.fields.append(IE.Value("MCS", num))

    def max_mpdu_len(self, value):
        return self.max_mpdu[value]

    def supported_chan_width_str(self, value):
        return self.channel_width[value]


class VHT_Operation(IE):
    ID = 192

    # note this differs from iw scan.c print_vht_oper()
    # I'm going from 80211_2016.pdf  I think some fields were deprecated.
    channel_width = (
        "20 or 40 Mhz",
        "80, 160, 80+80 MHz",
        "160 MHz (deprecated)",
        "80+80 Mhz (deprecated)"
    )

    def decode(self):
        offset = 0
        oper_info = struct.unpack("3B", self.data[0:3])
        offset += 3
        self.fields.append(IE.Value("Operation Info",
                            [IE.Value("Channel Width", oper_info[0]),
                             IE.Value("Channel Center Frequency Segment 0", oper_info[1]),
                             IE.Value("Channel Center Frequency Segment 1", oper_info[2]),
                            ]))

        # bitmap of 16-bits
        vht_mcs_nss_set, = struct.unpack("<H", self.data[offset:offset+2])
        self.fields.append(IE.Value("VHT-MSS and NSS Set", vht_mcs_nss_set))

        offset += 2

    def channel_width_str(self, value):
        try:
            return self.channel_width[value]
        except IndexError:
            return "Reserved"
        

class Vendor_Specific(IE):
    ID = 221

    def decode(self):
        # raw bytes
        s = self.format_oui(self.data[0:3])
        try:
            vendor = oui.vendor_lookup(s.upper())
        except KeyError:
            vendor = "Unknown"
        self.fields.append(IE.Value("Vendor Specific", 
                                [
                                   IE.Value("OUI", s),
                                   IE.Value("vendor name", vendor),
                                   IE.Value("raw", self.data)
                                ]
                          ))
#        self.fields.append(IE.Value("Vendor Specific", hexdump(self.data)))

class nl80211cmd(genlmsg):
    prefix = 'NL80211_ATTR_'
    nla_map = (('NL80211_ATTR_UNSPEC', 'none'),
               ('NL80211_ATTR_WIPHY', 'uint32'),
               ('NL80211_ATTR_WIPHY_NAME', 'asciiz'),
               ('NL80211_ATTR_IFINDEX', 'uint32'),
               ('NL80211_ATTR_IFNAME', 'asciiz'),
               ('NL80211_ATTR_IFTYPE', 'uint32'),
               ('NL80211_ATTR_MAC', 'l2addr'),
               ('NL80211_ATTR_KEY_DATA', 'hex'),
               ('NL80211_ATTR_KEY_IDX', 'hex'),
               ('NL80211_ATTR_KEY_CIPHER', 'uint32'),
               ('NL80211_ATTR_KEY_SEQ', 'hex'),
               ('NL80211_ATTR_KEY_DEFAULT', 'hex'),
               ('NL80211_ATTR_BEACON_INTERVAL', 'hex'),
               ('NL80211_ATTR_DTIM_PERIOD', 'hex'),
               ('NL80211_ATTR_BEACON_HEAD', 'hex'),
               ('NL80211_ATTR_BEACON_TAIL', 'hex'),
               ('NL80211_ATTR_STA_AID', 'hex'),
               ('NL80211_ATTR_STA_FLAGS', 'hex'),
               ('NL80211_ATTR_STA_LISTEN_INTERVAL', 'hex'),
               ('NL80211_ATTR_STA_SUPPORTED_RATES', 'hex'),
               ('NL80211_ATTR_STA_VLAN', 'hex'),
               ('NL80211_ATTR_STA_INFO', 'STAInfo'),
               ('NL80211_ATTR_WIPHY_BANDS', 'hex'),
               ('NL80211_ATTR_MNTR_FLAGS', 'hex'),
               ('NL80211_ATTR_MESH_ID', 'hex'),
               ('NL80211_ATTR_STA_PLINK_ACTION', 'hex'),
               ('NL80211_ATTR_MPATH_NEXT_HOP', 'hex'),
               ('NL80211_ATTR_MPATH_INFO', 'hex'),
               ('NL80211_ATTR_BSS_CTS_PROT', 'hex'),
               ('NL80211_ATTR_BSS_SHORT_PREAMBLE', 'hex'),
               ('NL80211_ATTR_BSS_SHORT_SLOT_TIME', 'hex'),
               ('NL80211_ATTR_HT_CAPABILITY', 'hex'),
               ('NL80211_ATTR_SUPPORTED_IFTYPES', 'hex'),
               ('NL80211_ATTR_REG_ALPHA2', 'hex'),
               ('NL80211_ATTR_REG_RULES', 'hex'),
               ('NL80211_ATTR_MESH_CONFIG', 'hex'),
               ('NL80211_ATTR_BSS_BASIC_RATES', 'hex'),
               ('NL80211_ATTR_WIPHY_TXQ_PARAMS', 'hex'),
               ('NL80211_ATTR_WIPHY_FREQ', 'uint32'),
               ('NL80211_ATTR_WIPHY_CHANNEL_TYPE', 'hex'),
               ('NL80211_ATTR_KEY_DEFAULT_MGMT', 'hex'),
               ('NL80211_ATTR_MGMT_SUBTYPE', 'hex'),
               ('NL80211_ATTR_IE', 'hex'),
               ('NL80211_ATTR_MAX_NUM_SCAN_SSIDS', 'uint8'),
               ('NL80211_ATTR_SCAN_FREQUENCIES', 'hex'),
               ('NL80211_ATTR_SCAN_SSIDS', '*string'),
               ('NL80211_ATTR_GENERATION', 'uint32'),
               ('NL80211_ATTR_BSS', 'bss'),
               ('NL80211_ATTR_REG_INITIATOR', 'hex'),
               ('NL80211_ATTR_REG_TYPE', 'hex'),
               ('NL80211_ATTR_SUPPORTED_COMMANDS', 'hex'),
               ('NL80211_ATTR_FRAME', 'hex'),
               ('NL80211_ATTR_SSID', 'string'),
               ('NL80211_ATTR_AUTH_TYPE', 'uint32'),
               ('NL80211_ATTR_REASON_CODE', 'uint16'),
               ('NL80211_ATTR_KEY_TYPE', 'hex'),
               ('NL80211_ATTR_MAX_SCAN_IE_LEN', 'uint16'),
               ('NL80211_ATTR_CIPHER_SUITES', 'hex'),
               ('NL80211_ATTR_FREQ_BEFORE', 'hex'),
               ('NL80211_ATTR_FREQ_AFTER', 'hex'),
               ('NL80211_ATTR_FREQ_FIXED', 'hex'),
               ('NL80211_ATTR_WIPHY_RETRY_SHORT', 'uint8'),
               ('NL80211_ATTR_WIPHY_RETRY_LONG', 'uint8'),
               ('NL80211_ATTR_WIPHY_FRAG_THRESHOLD', 'hex'),
               ('NL80211_ATTR_WIPHY_RTS_THRESHOLD', 'hex'),
               ('NL80211_ATTR_TIMED_OUT', 'hex'),
               ('NL80211_ATTR_USE_MFP', 'hex'),
               ('NL80211_ATTR_STA_FLAGS2', 'hex'),
               ('NL80211_ATTR_CONTROL_PORT', 'hex'),
               ('NL80211_ATTR_TESTDATA', 'hex'),
               ('NL80211_ATTR_PRIVACY', 'hex'),
               ('NL80211_ATTR_DISCONNECTED_BY_AP', 'hex'),
               ('NL80211_ATTR_STATUS_CODE', 'hex'),
               ('NL80211_ATTR_CIPHER_SUITES_PAIRWISE', 'hex'),
               ('NL80211_ATTR_CIPHER_SUITE_GROUP', 'hex'),
               ('NL80211_ATTR_WPA_VERSIONS', 'hex'),
               ('NL80211_ATTR_AKM_SUITES', 'hex'),
               ('NL80211_ATTR_REQ_IE', 'hex'),
               ('NL80211_ATTR_RESP_IE', 'hex'),
               ('NL80211_ATTR_PREV_BSSID', 'hex'),
               ('NL80211_ATTR_KEY', 'hex'),
               ('NL80211_ATTR_KEYS', 'hex'),
               ('NL80211_ATTR_PID', 'hex'),
               ('NL80211_ATTR_4ADDR', 'hex'),
               ('NL80211_ATTR_SURVEY_INFO', 'hex'),
               ('NL80211_ATTR_PMKID', 'hex'),
               ('NL80211_ATTR_MAX_NUM_PMKIDS', 'uint8'),
               ('NL80211_ATTR_DURATION', 'hex'),
               ('NL80211_ATTR_COOKIE', 'hex'),
               ('NL80211_ATTR_WIPHY_COVERAGE_CLASS', 'uint8'),
               ('NL80211_ATTR_TX_RATES', 'hex'),
               ('NL80211_ATTR_FRAME_MATCH', 'hex'),
               ('NL80211_ATTR_ACK', 'hex'),
               ('NL80211_ATTR_PS_STATE', 'hex'),
               ('NL80211_ATTR_CQM', 'hex'),
               ('NL80211_ATTR_LOCAL_STATE_CHANGE', 'hex'),
               ('NL80211_ATTR_AP_ISOLATE', 'hex'),
               ('NL80211_ATTR_WIPHY_TX_POWER_SETTING', 'hex'),
               ('NL80211_ATTR_WIPHY_TX_POWER_LEVEL', 'hex'),
               ('NL80211_ATTR_TX_FRAME_TYPES', 'hex'),
               ('NL80211_ATTR_RX_FRAME_TYPES', 'hex'),
               ('NL80211_ATTR_FRAME_TYPE', 'hex'),
               ('NL80211_ATTR_CONTROL_PORT_ETHERTYPE', 'hex'),
               ('NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT', 'hex'),
               ('NL80211_ATTR_SUPPORT_IBSS_RSN', 'hex'),
               ('NL80211_ATTR_WIPHY_ANTENNA_TX', 'hex'),
               ('NL80211_ATTR_WIPHY_ANTENNA_RX', 'hex'),
               ('NL80211_ATTR_MCAST_RATE', 'hex'),
               ('NL80211_ATTR_OFFCHANNEL_TX_OK', 'hex'),
               ('NL80211_ATTR_BSS_HT_OPMODE', 'hex'),
               ('NL80211_ATTR_KEY_DEFAULT_TYPES', 'hex'),
               ('NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION', 'hex'),
               ('NL80211_ATTR_MESH_SETUP', 'hex'),
               ('NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX', 'uint32'),
               ('NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX', 'uint32'),
               ('NL80211_ATTR_SUPPORT_MESH_AUTH', 'hex'),
               ('NL80211_ATTR_STA_PLINK_STATE', 'hex'),
               ('NL80211_ATTR_WOWLAN_TRIGGERS', 'hex'),
               ('NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED', 'hex'),
               ('NL80211_ATTR_SCHED_SCAN_INTERVAL', 'hex'),
               ('NL80211_ATTR_INTERFACE_COMBINATIONS', 'hex'),
               ('NL80211_ATTR_SOFTWARE_IFTYPES', 'hex'),
               ('NL80211_ATTR_REKEY_DATA', 'hex'),
               ('NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS', 'uint8'),
               ('NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN', 'uint16'),
               ('NL80211_ATTR_SCAN_SUPP_RATES', 'hex'),
               ('NL80211_ATTR_HIDDEN_SSID', 'hex'),
               ('NL80211_ATTR_IE_PROBE_RESP', 'hex'),
               ('NL80211_ATTR_IE_ASSOC_RESP', 'hex'),
               ('NL80211_ATTR_STA_WME', 'hex'),
               ('NL80211_ATTR_SUPPORT_AP_UAPSD', 'hex'),
               ('NL80211_ATTR_ROAM_SUPPORT', 'hex'),
               ('NL80211_ATTR_SCHED_SCAN_MATCH', 'hex'),
               ('NL80211_ATTR_MAX_MATCH_SETS', 'uint8'),
               ('NL80211_ATTR_PMKSA_CANDIDATE', 'hex'),
               ('NL80211_ATTR_TX_NO_CCK_RATE', 'hex'),
               ('NL80211_ATTR_TDLS_ACTION', 'hex'),
               ('NL80211_ATTR_TDLS_DIALOG_TOKEN', 'hex'),
               ('NL80211_ATTR_TDLS_OPERATION', 'hex'),
               ('NL80211_ATTR_TDLS_SUPPORT', 'hex'),
               ('NL80211_ATTR_TDLS_EXTERNAL_SETUP', 'hex'),
               ('NL80211_ATTR_DEVICE_AP_SME', 'hex'),
               ('NL80211_ATTR_DONT_WAIT_FOR_ACK', 'hex'),
               ('NL80211_ATTR_FEATURE_FLAGS', 'hex'),
               ('NL80211_ATTR_PROBE_RESP_OFFLOAD', 'hex'),
               ('NL80211_ATTR_PROBE_RESP', 'hex'),
               ('NL80211_ATTR_DFS_REGION', 'hex'),
               ('NL80211_ATTR_DISABLE_HT', 'hex'),
               ('NL80211_ATTR_HT_CAPABILITY_MASK', 'hex'),
               ('NL80211_ATTR_NOACK_MAP', 'hex'),
               ('NL80211_ATTR_INACTIVITY_TIMEOUT', 'hex'),
               ('NL80211_ATTR_RX_SIGNAL_DBM', 'hex'),
               ('NL80211_ATTR_BG_SCAN_PERIOD', 'hex'),
               ('NL80211_ATTR_WDEV', 'uint64'),
               ('NL80211_ATTR_USER_REG_HINT_TYPE', 'hex'),
               ('NL80211_ATTR_CONN_FAILED_REASON', 'hex'),
               ('NL80211_ATTR_SAE_DATA', 'hex'),
               ('NL80211_ATTR_VHT_CAPABILITY', 'hex'),
               ('NL80211_ATTR_SCAN_FLAGS', 'uint32'),
               ('NL80211_ATTR_CHANNEL_WIDTH', 'uint32'),
               ('NL80211_ATTR_CENTER_FREQ1', 'uint32'),
               ('NL80211_ATTR_CENTER_FREQ2', 'uint32'),
               ('NL80211_ATTR_P2P_CTWINDOW', 'hex'),
               ('NL80211_ATTR_P2P_OPPPS', 'hex'),
               ('NL80211_ATTR_LOCAL_MESH_POWER_MODE', 'hex'),
               ('NL80211_ATTR_ACL_POLICY', 'hex'),
               ('NL80211_ATTR_MAC_ADDRS', 'hex'),
               ('NL80211_ATTR_MAC_ACL_MAX', 'hex'),
               ('NL80211_ATTR_RADAR_EVENT', 'hex'),
               ('NL80211_ATTR_EXT_CAPA', 'array(uint8)'),
               ('NL80211_ATTR_EXT_CAPA_MASK', 'array(uint8)'),
               ('NL80211_ATTR_STA_CAPABILITY', 'hex'),
               ('NL80211_ATTR_STA_EXT_CAPABILITY', 'hex'),
               ('NL80211_ATTR_PROTOCOL_FEATURES', 'hex'),
               ('NL80211_ATTR_SPLIT_WIPHY_DUMP', 'hex'),
               ('NL80211_ATTR_DISABLE_VHT', 'hex'),
               ('NL80211_ATTR_VHT_CAPABILITY_MASK', 'array(uint8)'),
               ('NL80211_ATTR_MDID', 'hex'),
               ('NL80211_ATTR_IE_RIC', 'hex'),
               ('NL80211_ATTR_CRIT_PROT_ID', 'hex'),
               ('NL80211_ATTR_MAX_CRIT_PROT_DURATION', 'hex'),
               ('NL80211_ATTR_PEER_AID', 'hex'),
               ('NL80211_ATTR_COALESCE_RULE', 'hex'),
               ('NL80211_ATTR_CH_SWITCH_COUNT', 'hex'),
               ('NL80211_ATTR_CH_SWITCH_BLOCK_TX', 'hex'),
               ('NL80211_ATTR_CSA_IES', 'hex'),
               ('NL80211_ATTR_CSA_C_OFF_BEACON', 'hex'),
               ('NL80211_ATTR_CSA_C_OFF_PRESP', 'hex'),
               ('NL80211_ATTR_RXMGMT_FLAGS', 'hex'),
               ('NL80211_ATTR_STA_SUPPORTED_CHANNELS', 'hex'),
               ('NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES', 'hex'),
               ('NL80211_ATTR_HANDLE_DFS', 'hex'),
               ('NL80211_ATTR_SUPPORT_5_MHZ', 'hex'),
               ('NL80211_ATTR_SUPPORT_10_MHZ', 'hex'),
               ('NL80211_ATTR_OPMODE_NOTIF', 'hex'),
               ('NL80211_ATTR_VENDOR_ID', 'hex'),
               ('NL80211_ATTR_VENDOR_SUBCMD', 'hex'),
               ('NL80211_ATTR_VENDOR_DATA', 'hex'),
               ('NL80211_ATTR_VENDOR_EVENTS', 'hex'),
               ('NL80211_ATTR_QOS_MAP', 'hex'),
               ('NL80211_ATTR_MAC_HINT', 'hex'),
               ('NL80211_ATTR_WIPHY_FREQ_HINT', 'hex'),
               ('NL80211_ATTR_MAX_AP_ASSOC_STA', 'hex'),
               ('NL80211_ATTR_TDLS_PEER_CAPABILITY', 'hex'),
               ('NL80211_ATTR_SOCKET_OWNER', 'hex'),
               ('NL80211_ATTR_CSA_C_OFFSETS_TX', 'hex'),
               ('NL80211_ATTR_MAX_CSA_COUNTERS', 'hex'),
               ('NL80211_ATTR_TDLS_INITIATOR', 'hex'),
               ('NL80211_ATTR_USE_RRM', 'hex'),
               ('NL80211_ATTR_WIPHY_DYN_ACK', 'hex'),
               ('NL80211_ATTR_TSID', 'hex'),
               ('NL80211_ATTR_USER_PRIO', 'hex'),
               ('NL80211_ATTR_ADMITTED_TIME', 'hex'),
               ('NL80211_ATTR_SMPS_MODE', 'hex'),
               ('NL80211_ATTR_OPER_CLASS', 'hex'),
               ('NL80211_ATTR_MAC_MASK', 'hex'),
               ('NL80211_ATTR_WIPHY_SELF_MANAGED_REG', 'hex'),
               ('NUM_NL80211_ATTR', 'hex'))

    class bss(nla):
        class elementsBinary(nla_base):

            def binary_rates(self, offset, length):
                init = offset
                string = ""
                while (offset - init) < length:
                    byte, = struct.unpack_from('B', self.data, offset)
                    r = byte & 0x7f
                    if r == BSS_MEMBERSHIP_SELECTOR_VHT_PHY and byte & 0x80:
                        string += "VHT"
                    elif r == BSS_MEMBERSHIP_SELECTOR_HT_PHY and byte & 0x80:
                        string += "HT"
                    else:
                        string += "%d.%d" % (r / 2, 5 * (r & 1))
                    offset += 1
                    string += "%s " % ("*" if byte & 0x80 else "")
                return string

            def binary_tim(self, offset):
                (count,
                 period,
                 bitmapc,
                 bitmap0) = struct.unpack_from('BBBB',
                                               self.data,
                                               offset)
                return ("DTIM Count {0} DTIM Period {1} Bitmap Control 0x{2} "
                        "Bitmap[0] 0x{3}".format(count,
                                                 period,
                                                 bitmapc,
                                                 bitmap0))

            def decode_nlas(self):
                return

            def decode(self):
                # davep new decode
                nla_base.decode(self)

                self.value = {}

                init = offset = self.offset + 4

                ie_class_map = {
                    NL80211_BSS_ELEMENTS_SSID: SSID,
                    NL80211_BSS_ELEMENTS_SUPPORTED_RATES: Supported_Rates,
                    NL80211_BSS_ELEMENTS_CHANNEL: DSSS_Parameter_Set,
                    NL80211_BSS_ELEMENTS_TIM: TIM,
                    NL80211_BSS_ELEMENTS_COUNTRY: Country,
                    NL80211_BSS_ELEMENTS_HT_CAPABILITIES: HT_Capabilities,
                    NL80211_BSS_ELEMENTS_RSN: RSN,
                    NL80211_BSS_ELEMENTS_EXTENDED_RATE: Extended_Rates,
                    NL80211_BSS_ELEMENTS_HT_OPERATION: HT_Operation,
                    NL80211_BSS_ELEMENTS_EXT_CAPABILITIES:
                        Extended_Capabilities,
                    NL80211_BSS_ELEMENTS_VHT_CAPABILITIES: VHT_Capabilities,
                    NL80211_BSS_ELEMENTS_VHT_OPERATION: VHT_Operation,
                    NL80211_BSS_ELEMENTS_VENDOR: Vendor_Specific,
                }

                while (offset - init) < (self.length - 4):
                    (msg_type, length) = struct.unpack_from('BB',
                                                            self.data,
                                                            offset)

                    # TODO so I can keep keep an eye on what needs to be
                    # decoded
                    try:
                        msg_name = NL80211_BSS_ELEMENTS_VALUES[msg_type]
                    except KeyError:
                        log.warning("unhandled IE element type=%d", msg_type)
                        if "TODO" in self.value:
                            self.value["TODO"].append(msg_type)
                        else:
                            self.value["TODO"] = [msg_type, ]
                        offset += length + 2
                        continue

                    cls = ie_class_map[msg_type]
                    offset += 2
                    val = cls(self.data[offset:offset + length])
                    val.decode()
                    if msg_type == NL80211_BSS_ELEMENTS_VENDOR and msg_name in self.value:
                        # append to existing vendorid
                        self.value[msg_name].fields.extend(val.fields)
                    else:
                        self.value[msg_name] = val
                    offset += length

        class TSF(nla_base):
            """Timing Synchronization Function"""
            def decode(self):
                nla_base.decode(self)

                offset = self.offset + 4
                self.value = {}
                tsf, = struct.unpack_from('Q', self.data, offset)
                self.value["VALUE"] = tsf
                # TSF is in microseconds
                # TODO verify this won't overflow internally
                self.value["TIME"] = datetime.timedelta(microseconds=tsf)

        class SignalMBM(nla_base):
            def decode(self):
                nla_base.decode(self)
                offset = self.offset + 4
                self.value = {}
                ss, = struct.unpack_from('i', self.data, offset)
                self.value["VALUE"] = ss
                self.value["SIGNAL_STRENGTH"] = {"VALUE": ss / 100.0,
                                                 "UNITS": "dBm"}

        class capability(nla_base):
            # iw scan.c
            WLAN_CAPABILITY_ESS = (1 << 0)
            WLAN_CAPABILITY_IBSS = (1 << 1)
            WLAN_CAPABILITY_CF_POLLABLE = (1 << 2)
            WLAN_CAPABILITY_CF_POLL_REQUEST = (1 << 3)
            WLAN_CAPABILITY_PRIVACY = (1 << 4)
            WLAN_CAPABILITY_SHORT_PREAMBLE = (1 << 5)
            WLAN_CAPABILITY_PBCC = (1 << 6)
            WLAN_CAPABILITY_CHANNEL_AGILITY = (1 << 7)
            WLAN_CAPABILITY_SPECTRUM_MGMT = (1 << 8)
            WLAN_CAPABILITY_QOS = (1 << 9)
            WLAN_CAPABILITY_SHORT_SLOT_TIME = (1 << 10)
            WLAN_CAPABILITY_APSD = (1 << 11)
            WLAN_CAPABILITY_RADIO_MEASURE = (1 << 12)
            WLAN_CAPABILITY_DSSS_OFDM = (1 << 13)
            WLAN_CAPABILITY_DEL_BACK = (1 << 14)
            WLAN_CAPABILITY_IMM_BACK = (1 << 15)

#            def decode_nlas(self):
#                return

            def decode(self):
                nla_base.decode(self)

                offset = self.offset + 4
                self.value = {}
                capa, = struct.unpack_from('H', self.data, offset)
                self.value["VALUE"] = capa

                s = []
                if capa & self.WLAN_CAPABILITY_ESS:
                    s.append("ESS")
                if capa & self.WLAN_CAPABILITY_IBSS:
                    s.append("IBSS")
                if capa & self.WLAN_CAPABILITY_CF_POLLABLE:
                    s.append("CfPollable")
                if capa & self.WLAN_CAPABILITY_CF_POLL_REQUEST:
                    s.append("CfPollReq")
                if capa & self.WLAN_CAPABILITY_PRIVACY:
                    s.append("Privacy")
                if capa & self.WLAN_CAPABILITY_SHORT_PREAMBLE:
                    s.append("ShortPreamble")
                if capa & self.WLAN_CAPABILITY_PBCC:
                    s.append("PBCC")
                if capa & self.WLAN_CAPABILITY_CHANNEL_AGILITY:
                    s.append("ChannelAgility")
                if capa & self.WLAN_CAPABILITY_SPECTRUM_MGMT:
                    s.append("SpectrumMgmt")
                if capa & self.WLAN_CAPABILITY_QOS:
                    s.append("QoS")
                if capa & self.WLAN_CAPABILITY_SHORT_SLOT_TIME:
                    s.append("ShortSlotTime")
                if capa & self.WLAN_CAPABILITY_APSD:
                    s.append("APSD")
                if capa & self.WLAN_CAPABILITY_RADIO_MEASURE:
                    s.append("RadioMeasure")
                if capa & self.WLAN_CAPABILITY_DSSS_OFDM:
                    s.append("DSSS-OFDM")
                if capa & self.WLAN_CAPABILITY_DEL_BACK:
                    s.append("DelayedBACK")
                if capa & self.WLAN_CAPABILITY_IMM_BACK:
                    s.append("ImmediateBACK")

                self.value['CAPABILITIES'] = " ".join(s)

        prefix = 'NL80211_BSS_'
        nla_map = (('__NL80211_BSS_INVALID', 'hex'),
                   ('NL80211_BSS_BSSID', 'hex'),
                   ('NL80211_BSS_FREQUENCY', 'uint32'),
                   ('NL80211_BSS_TSF', 'TSF'),
                   ('NL80211_BSS_BEACON_INTERVAL', 'uint16'),
                   ('NL80211_BSS_CAPABILITY', 'capability'),
                   ('NL80211_BSS_INFORMATION_ELEMENTS', 'elementsBinary'),
                   ('NL80211_BSS_SIGNAL_MBM', 'SignalMBM'),
                   ('NL80211_BSS_SIGNAL_UNSPEC', 'uint8'),
                   ('NL80211_BSS_STATUS', 'uint32'),
                   ('NL80211_BSS_SEEN_MS_AGO', 'uint32'),
                   ('NL80211_BSS_BEACON_IES', 'elementsBinary'),
                   ('NL80211_BSS_CHAN_WIDTH', 'uint32'),
                   ('NL80211_BSS_BEACON_TSF', 'uint64'),
                   ('NL80211_BSS_PRESP_DATA', 'hex'),
                   ('NL80211_BSS_MAX', 'hex')
                   )

    class STAInfo(nla):
        class STAFlags(nla_base):
            '''
            Decode the flags that may be set.
            See nl80211.h: struct nl80211_sta_flag_update,
            NL80211_STA_INFO_STA_FLAGS
            '''

            def decode_nlas(self):
                return

            def decode(self):
                nla_base.decode(self)
                self.value = {}
                self.value["AUTHORIZED"] = False
                self.value["SHORT_PREAMBLE"] = False
                self.value["WME"] = False
                self.value["MFP"] = False
                self.value["AUTHENTICATED"] = False
                self.value["TDLS_PEER"] = False
                self.value["ASSOCIATED"] = False

                init = offset = self.offset + 4
                while (offset - init) < (self.length - 4):
                    (msg_type, length) = struct.unpack_from('BB',
                                                            self.data,
                                                            offset)
                    mask, set_ = struct.unpack_from('II',
                                                    self.data,
                                                    offset + 2)

                    if mask & NL80211_STA_FLAG_AUTHORIZED:
                        if set_ & NL80211_STA_FLAG_AUTHORIZED:
                            self.value["AUTHORIZED"] = True

                    if mask & NL80211_STA_FLAG_SHORT_PREAMBLE:
                        if set_ & NL80211_STA_FLAG_SHORT_PREAMBLE:
                            self.value["SHORT_PREAMBLE"] = True

                    if mask & NL80211_STA_FLAG_WME:
                        if set_ & NL80211_STA_FLAG_WME:
                            self.value["WME"] = True

                    if mask & NL80211_STA_FLAG_MFP:
                        if set_ & NL80211_STA_FLAG_MFP:
                            self.value["MFP"] = True

                    if mask & NL80211_STA_FLAG_AUTHENTICATED:
                        if set_ & NL80211_STA_FLAG_AUTHENTICATED:
                            self.value["AUTHENTICATED"] = True

                    if mask & NL80211_STA_FLAG_TDLS_PEER:
                        if set_ & NL80211_STA_FLAG_TDLS_PEER:
                            self.value["TDLS_PEER"] = True

                    if mask & NL80211_STA_FLAG_ASSOCIATED:
                        if set_ & NL80211_STA_FLAG_ASSOCIATED:
                            self.value["ASSOCIATED"] = True

                    offset += length + 2

        prefix = 'NL80211_STA_INFO_'
        nla_map = (('__NL80211_STA_INFO_INVALID', 'hex'),
                   ('NL80211_STA_INFO_INACTIVE_TIME', 'uint32'),
                   ('NL80211_STA_INFO_RX_BYTES', 'uint32'),
                   ('NL80211_STA_INFO_TX_BYTES', 'uint32'),
                   ('NL80211_STA_INFO_LLID', 'uint16'),
                   ('NL80211_STA_INFO_PLID', 'uint16'),
                   ('NL80211_STA_INFO_PLINK_STATE', 'uint8'),
                   ('NL80211_STA_INFO_SIGNAL', 'int8'),
                   ('NL80211_STA_INFO_TX_BITRATE', 'hex'),
                   ('NL80211_STA_INFO_RX_PACKETS', 'uint32'),
                   ('NL80211_STA_INFO_TX_PACKETS', 'uint32'),
                   ('NL80211_STA_INFO_TX_RETRIES', 'uint32'),
                   ('NL80211_STA_INFO_TX_FAILED', 'uint32'),
                   ('NL80211_STA_INFO_SIGNAL_AVG', 'int8'),
                   ('NL80211_STA_INFO_RX_BITRATE', 'hex'),
                   ('NL80211_STA_INFO_BSS_PARAM', 'hex'),
                   ('NL80211_STA_INFO_CONNECTED_TIME', 'uint32'),
                   ('NL80211_STA_INFO_STA_FLAGS', 'STAFlags'),
                   ('NL80211_STA_INFO_BEACON_LOSS', 'uint32'),
                   ('NL80211_STA_INFO_T_OFFSET', 'int64'),
                   ('NL80211_STA_INFO_LOCAL_PM', 'hex'),
                   ('NL80211_STA_INFO_PEER_PM', 'hex'),
                   ('NL80211_STA_INFO_NONPEER_PM', 'hex'),
                   ('NL80211_STA_INFO_RX_BYTES64', 'uint64'),
                   ('NL80211_STA_INFO_TX_BYTES64', 'uint64'),
                   ('NL80211_STA_INFO_CHAIN_SIGNAL', 'string'),
                   ('NL80211_STA_INFO_CHAIN_SIGNAL_AVG', 'string'),
                   ('NL80211_STA_INFO_EXPECTED_THROUGHPUT', 'uint32'),
                   ('NL80211_STA_INFO_RX_DROP_MISC', 'uint32'),
                   ('NL80211_STA_INFO_BEACON_RX', 'uint64'),
                   ('NL80211_STA_INFO_BEACON_SIGNAL_AVG', 'uint8'),
                   ('NL80211_STA_INFO_TID_STATS', 'hex'),
                   ('NL80211_STA_INFO_RX_DURATION', 'uint64'),
                   ('NL80211_STA_INFO_PAD', 'hex'),
                   ('NL80211_STA_INFO_MAX', 'hex')
                   )


class MarshalNl80211(Marshal):
    msg_map = {NL80211_CMD_UNSPEC: nl80211cmd,
               NL80211_CMD_GET_WIPHY: nl80211cmd,
               NL80211_CMD_SET_WIPHY: nl80211cmd,
               NL80211_CMD_NEW_WIPHY: nl80211cmd,
               NL80211_CMD_DEL_WIPHY: nl80211cmd,
               NL80211_CMD_GET_INTERFACE: nl80211cmd,
               NL80211_CMD_SET_INTERFACE: nl80211cmd,
               NL80211_CMD_NEW_INTERFACE: nl80211cmd,
               NL80211_CMD_DEL_INTERFACE: nl80211cmd,
               NL80211_CMD_GET_KEY: nl80211cmd,
               NL80211_CMD_SET_KEY: nl80211cmd,
               NL80211_CMD_NEW_KEY: nl80211cmd,
               NL80211_CMD_DEL_KEY: nl80211cmd,
               NL80211_CMD_GET_BEACON: nl80211cmd,
               NL80211_CMD_SET_BEACON: nl80211cmd,
               NL80211_CMD_START_AP: nl80211cmd,
               NL80211_CMD_NEW_BEACON: nl80211cmd,
               NL80211_CMD_STOP_AP: nl80211cmd,
               NL80211_CMD_DEL_BEACON: nl80211cmd,
               NL80211_CMD_GET_STATION: nl80211cmd,
               NL80211_CMD_SET_STATION: nl80211cmd,
               NL80211_CMD_NEW_STATION: nl80211cmd,
               NL80211_CMD_DEL_STATION: nl80211cmd,
               NL80211_CMD_GET_MPATH: nl80211cmd,
               NL80211_CMD_SET_MPATH: nl80211cmd,
               NL80211_CMD_NEW_MPATH: nl80211cmd,
               NL80211_CMD_DEL_MPATH: nl80211cmd,
               NL80211_CMD_SET_BSS: nl80211cmd,
               NL80211_CMD_SET_REG: nl80211cmd,
               NL80211_CMD_REQ_SET_REG: nl80211cmd,
               NL80211_CMD_GET_MESH_CONFIG: nl80211cmd,
               NL80211_CMD_SET_MESH_CONFIG: nl80211cmd,
               NL80211_CMD_SET_MGMT_EXTRA_IE: nl80211cmd,
               NL80211_CMD_GET_REG: nl80211cmd,
               NL80211_CMD_GET_SCAN: nl80211cmd,
               NL80211_CMD_TRIGGER_SCAN: nl80211cmd,
               NL80211_CMD_NEW_SCAN_RESULTS: nl80211cmd,
               NL80211_CMD_SCAN_ABORTED: nl80211cmd,
               NL80211_CMD_REG_CHANGE: nl80211cmd,
               NL80211_CMD_AUTHENTICATE: nl80211cmd,
               NL80211_CMD_ASSOCIATE: nl80211cmd,
               NL80211_CMD_DEAUTHENTICATE: nl80211cmd,
               NL80211_CMD_DISASSOCIATE: nl80211cmd,
               NL80211_CMD_MICHAEL_MIC_FAILURE: nl80211cmd,
               NL80211_CMD_REG_BEACON_HINT: nl80211cmd,
               NL80211_CMD_JOIN_IBSS: nl80211cmd,
               NL80211_CMD_LEAVE_IBSS: nl80211cmd,
               NL80211_CMD_TESTMODE: nl80211cmd,
               NL80211_CMD_CONNECT: nl80211cmd,
               NL80211_CMD_ROAM: nl80211cmd,
               NL80211_CMD_DISCONNECT: nl80211cmd,
               NL80211_CMD_SET_WIPHY_NETNS: nl80211cmd,
               NL80211_CMD_GET_SURVEY: nl80211cmd,
               NL80211_CMD_NEW_SURVEY_RESULTS: nl80211cmd,
               NL80211_CMD_SET_PMKSA: nl80211cmd,
               NL80211_CMD_DEL_PMKSA: nl80211cmd,
               NL80211_CMD_FLUSH_PMKSA: nl80211cmd,
               NL80211_CMD_REMAIN_ON_CHANNEL: nl80211cmd,
               NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL: nl80211cmd,
               NL80211_CMD_SET_TX_BITRATE_MASK: nl80211cmd,
               NL80211_CMD_REGISTER_FRAME: nl80211cmd,
               NL80211_CMD_REGISTER_ACTION: nl80211cmd,
               NL80211_CMD_FRAME: nl80211cmd,
               NL80211_CMD_ACTION: nl80211cmd,
               NL80211_CMD_FRAME_TX_STATUS: nl80211cmd,
               NL80211_CMD_ACTION_TX_STATUS: nl80211cmd,
               NL80211_CMD_SET_POWER_SAVE: nl80211cmd,
               NL80211_CMD_GET_POWER_SAVE: nl80211cmd,
               NL80211_CMD_SET_CQM: nl80211cmd,
               NL80211_CMD_NOTIFY_CQM: nl80211cmd,
               NL80211_CMD_SET_CHANNEL: nl80211cmd,
               NL80211_CMD_SET_WDS_PEER: nl80211cmd,
               NL80211_CMD_FRAME_WAIT_CANCEL: nl80211cmd,
               NL80211_CMD_JOIN_MESH: nl80211cmd,
               NL80211_CMD_LEAVE_MESH: nl80211cmd,
               NL80211_CMD_UNPROT_DEAUTHENTICATE: nl80211cmd,
               NL80211_CMD_UNPROT_DISASSOCIATE: nl80211cmd,
               NL80211_CMD_NEW_PEER_CANDIDATE: nl80211cmd,
               NL80211_CMD_GET_WOWLAN: nl80211cmd,
               NL80211_CMD_SET_WOWLAN: nl80211cmd,
               NL80211_CMD_START_SCHED_SCAN: nl80211cmd,
               NL80211_CMD_STOP_SCHED_SCAN: nl80211cmd,
               NL80211_CMD_SCHED_SCAN_RESULTS: nl80211cmd,
               NL80211_CMD_SCHED_SCAN_STOPPED: nl80211cmd,
               NL80211_CMD_SET_REKEY_OFFLOAD: nl80211cmd,
               NL80211_CMD_PMKSA_CANDIDATE: nl80211cmd,
               NL80211_CMD_TDLS_OPER: nl80211cmd,
               NL80211_CMD_TDLS_MGMT: nl80211cmd,
               NL80211_CMD_UNEXPECTED_FRAME: nl80211cmd,
               NL80211_CMD_PROBE_CLIENT: nl80211cmd,
               NL80211_CMD_REGISTER_BEACONS: nl80211cmd,
               NL80211_CMD_UNEXPECTED_4ADDR_FRAME: nl80211cmd,
               NL80211_CMD_SET_NOACK_MAP: nl80211cmd,
               NL80211_CMD_CH_SWITCH_NOTIFY: nl80211cmd,
               NL80211_CMD_START_P2P_DEVICE: nl80211cmd,
               NL80211_CMD_STOP_P2P_DEVICE: nl80211cmd,
               NL80211_CMD_CONN_FAILED: nl80211cmd,
               NL80211_CMD_SET_MCAST_RATE: nl80211cmd,
               NL80211_CMD_SET_MAC_ACL: nl80211cmd,
               NL80211_CMD_RADAR_DETECT: nl80211cmd,
               NL80211_CMD_GET_PROTOCOL_FEATURES: nl80211cmd,
               NL80211_CMD_UPDATE_FT_IES: nl80211cmd,
               NL80211_CMD_FT_EVENT: nl80211cmd,
               NL80211_CMD_CRIT_PROTOCOL_START: nl80211cmd,
               NL80211_CMD_CRIT_PROTOCOL_STOP: nl80211cmd,
               NL80211_CMD_GET_COALESCE: nl80211cmd,
               NL80211_CMD_SET_COALESCE: nl80211cmd,
               NL80211_CMD_CHANNEL_SWITCH: nl80211cmd,
               NL80211_CMD_VENDOR: nl80211cmd,
               NL80211_CMD_SET_QOS_MAP: nl80211cmd,
               NL80211_CMD_ADD_TX_TS: nl80211cmd,
               NL80211_CMD_DEL_TX_TS: nl80211cmd,
               NL80211_CMD_GET_MPP: nl80211cmd,
               NL80211_CMD_JOIN_OCB: nl80211cmd,
               NL80211_CMD_LEAVE_OCB: nl80211cmd,
               NL80211_CMD_CH_SWITCH_STARTED_NOTIFY: nl80211cmd,
               NL80211_CMD_TDLS_CHANNEL_SWITCH: nl80211cmd,
               NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH: nl80211cmd,
               NL80211_CMD_WIPHY_REG_CHANGE: nl80211cmd}

    def fix_message(self, msg):
        try:
            msg['event'] = NL80211_VALUES[msg['cmd']]
        except Exception:
            pass


class NL80211(GenericNetlinkSocket):

    def __init__(self):
        GenericNetlinkSocket.__init__(self)
        self.marshal = MarshalNl80211()

    def bind(self, groups=0, **kwarg):
        GenericNetlinkSocket.bind(self, 'nl80211', nl80211cmd,
                                  groups, None, **kwarg)
