class X25519:
    # Curve25519 prime field modulus: 2^255 - 19
    P = 2**255 - 19

    # Curve constant A24 = (486662 - 2) / 4
    A24 = 121665

    BASE_U = 9

    def _clamp(self, k_bytes):

        k = bytearray(k_bytes)
        k[0]  &= 0xF8 # clear bottom 3 bits
        k[31] &= 0x7F # clear top bit
        k[31] |= 0x40 # set second-highest bit
        return bytes(k)

    def _decode_u_coordinate(self, u_bytes):
        u = int.from_bytes(u_bytes, byteorder='little')
        u &= (1 << 255) - 1
        return u

    def _decode_scalar(self, scalar_bytes):
        clamped = self._clamp(scalar_bytes)
        return int.from_bytes(clamped, byteorder='little')

    def _encode_u_coordinate(self, u):
        return (u % self.P).to_bytes(32, byteorder='little')

    def _mul(self, k_scalar, u_coord):
        p   = self.P
        a24 = self.A24
        x_1 = u_coord
        x_2 = 1
        z_2 = 0
        x_3 = u_coord
        z_3 = 1
        swap = 0

        for t in range(254, -1, -1):
            k_t = (k_scalar >> t) & 1
            swap ^= k_t
            if swap:
                x_2, x_3 = x_3, x_2
                z_2, z_3 = z_3, z_2
            swap = k_t

            A  = (x_2 + z_2) % p
            AA = (A * A) % p
            B  = (x_2 - z_2) % p
            BB = (B * B) % p
            E  = (AA - BB) % p
            C  = (x_3 + z_3) % p
            D  = (x_3 - z_3) % p
            DA = (D * A) % p
            CB = (C * B) % p
            x_3 = pow(DA + CB, 2, p)
            z_3 = (x_1 * pow(DA - CB, 2, p)) % p
            x_2 = (AA * BB) % p
            z_2 = (E * (AA + a24 * E))% p

        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2

        return (x_2 * pow(z_2, p - 2, p)) % p

    def x25519(self, scalar_bytes, u_bytes):
        k = self._decode_scalar(scalar_bytes)
        u = self._decode_u_coordinate(u_bytes)
        result = self._mul(k, u)
        result_bytes = self._encode_u_coordinate(result)
        if not any(result_bytes):
            raise ValueError("X25519 produced the all-zero output (small-order peer key)")
        return result_bytes

    def generate_public_key(self, private_key_bytes):
        base = self.BASE_U.to_bytes(32, byteorder='little')
        return self.x25519(private_key_bytes, base)

    def compute_shared_secret(self, my_private_key_bytes, their_public_key_bytes):
        return self.x25519(my_private_key_bytes, their_public_key_bytes)
