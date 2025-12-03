# tests/test_filters.py
from core.filters import PacketFilter

def test_filter_src_ip():
    f = PacketFilter(src_ip="192.168.1.10")
    pkt = {"layers":[{"layer":"IPv4","fields":{"src":"192.168.1.10"}}]}
    assert f.match(pkt) is True
