from hashlib import sha256

def b2l(b):
    return int.from_bytes(b, 'big')

cache = {}
class Transcript:
    def __init__(self, label=b""):
        self.label = label
        self.messages = []

    def put(self, message):
        if isinstance(message, str):
            message = message.encode()
        elif isinstance(message, int):
            message = str(message).encode()
        elif isinstance(message, list):
            [self.put(x) for x in message]
            return
        elif not isinstance(message, bytes):
            raise TypeError("Idk ur types")
        self.messages.append(message)

    def get_challenge(self):
        combined = self.label + b''.join(self.messages)
        if combined in cache:
            self.label = cache[combined][0]
            return cache[combined][1]
        self.label = sha256(combined).hexdigest().encode()
        ret = b2l(sha256(combined).digest())
        if len(cache) < 10:
            cache[combined] = (self.label, ret)
        return ret
    
    def reset(self):
        self.messages.clear()
        self.label = b""