from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
import hashlib
import secrets

class Schnorr:
    def __init__(self):
        self.curve = SECP256k1
        self.G = self.curve.generator
        self.n = self.curve.order
        
    def generate_keys(self):
        self.d = secrets.randbelow(self.n - 1) + 1
        self.P = self.d * self.G 
        return self.d, self.P
    
    def sign(self, message):
        k = secrets.randbelow(self.n - 1) + 1 
        R = k * self.G 

        e = self._hash_points_and_message(R, self.P, message)
        
        s = (k + e * self.d) % self.n 
        
        return R, s
    
    def verify(self, message, signature, public_key):
        R, s = signature
        P = public_key

        e = self._hash_points_and_message(R, P, message)

        left_side = s * self.G

        right_side = R + (e * P)
        
        return left_side == right_side
    
    def _hash_points_and_message(self, R, P, message):

        R_bytes = self._point_to_bytes(R)
        P_bytes = self._point_to_bytes(P)

        h = hashlib.sha256(R_bytes + P_bytes + message).digest()
        return int.from_bytes(h, 'big') % self.n
    
    def _point_to_bytes(self, point):
        x = point.x().to_bytes(32, 'big')
        y = point.y().to_bytes(32, 'big')
        return x + y


schnorr = Schnorr()

d, P = schnorr.generate_keys()
print(f"1. Приватный ключ d: {hex(d)}")
print(f"   Публичный ключ P: {P.x()}, {P.y()}")

message = b"Let me go"
R, s = schnorr.sign(message)
print(f"\n2. Сообщение: {message}")
print(f"   Точка R: ({R.x()}, {R.y()})")
print(f"   Подпись s: {hex(s)}")

valid = schnorr.verify(message, (R, s), P)
print(f"\n3. Подпись верна: {valid}")