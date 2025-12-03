# tests/test_parsers.py
from core.packet import Ethernet

def test_ethernet_parse():
    raw = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    eth = Ethernet(raw)
    assert eth.ethertype == 0x0800
