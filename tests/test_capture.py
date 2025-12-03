# tests/test_capture.py
from capture.simulator import PacketSimulator

def test_simulator_generates_packets():
    sim = PacketSimulator()
    pkt = sim.generate_packet()
    assert "src" in pkt
    assert "dst" in pkt
    assert "proto" in pkt
