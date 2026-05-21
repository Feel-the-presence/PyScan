class Payload_Builder:
    def __init__(self):
        self.udp_payloads = {
            53: b'\xaa\xbb\x00\x01',
            123: b'...'
        }
    
