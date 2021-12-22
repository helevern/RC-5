class RC5:

    def __init__(self, w, r, key):
        self.w = w                  # размерность блока
        self.r = r                  # рануд шифрования
        self.key = key
        self.T = 2 * (r + 1)
        self.w4 = w // 4
        self.w8 = w // 8
        self.mod = 2 ** self.w
        self.mask = self.mod - 1
        self.b = len(key)
        self.__key_align()
        self.__key_extend()
        self.__shuffle()

    def __lshift(self, val, n):
        n %= self.w
        return ((val << n) & self.mask) | ((val & self.mask) >> (self.w - n))

    def __rshift(self, val, n):
        n %= self.w
        return ((val & self.mask) >> n) | (val << (self.w - n) & self.mask)

    def __key_align(self):
        if self.b == 0:  # пустой ключ
            self.c = 1
        elif self.b % self.w8:  # ключ не кратный w / 8
            self.key += b'\x00' * (self.w8 - self.b % self.w8)      # дополняем ключ байтами
            self.b = len(self.key)
            self.c = self.b // self.w8
        else:
            self.c = self.b // self.w8
        L = [0] * self.c
        for i in range(self.b - 1, -1, -1):                         # Заполняем массив
            L[i // self.w8] = (L[i // self.w8] << 8) + self.key[i]
        self.L = L

    def __const(self):                                              # функция генерации констант
        if self.w == 16:
            return (0xB7E1, 0x9E37)                                 # Возвращает значения P и Q соответсвенно
        elif self.w == 32:
            return (0xB7E15163, 0x9E3779B9)
        elif self.w == 64:
            return (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)

    def __key_extend(self):  # Заполняем массив S
        P, Q = self.__const()
        self.S = [(P + i * Q) % self.mod for i in range(self.T)]

    def __shuffle(self):
        i, j, A, B = 0, 0, 0, 0
        for k in range(3 * max(self.c, self.T)):
            A = self.S[i] = self.__lshift((self.S[i] + A + B), 3)
            B = self.L[j] = self.__lshift((self.L[j] + A + B), A + B)
            i = (i + 1) % self.T
            j = (j + 1) % self.c

    def encrypt_block(self, data):
        A = int.from_bytes(data[:self.w8], byteorder='little')
        B = int.from_bytes(data[self.w8:], byteorder='little')
        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod
        for i in range(1, self.r + 1):
            A = (self.__lshift((A ^ B), B) + self.S[2 * i]) % self.mod
            B = (self.__lshift((A ^ B), A) + self.S[2 * i + 1]) % self.mod
        return (A.to_bytes(self.w8, byteorder='little'))

    def encrypt_file(self, inp_file_name,out_file_name):
# в качестве параметров передаётся имя файла и открытым текстом и имя выходного файла
        with open(inp_file_name, 'rb') as inp, open(out_file_name, 'wb') as out:
            run = True
            while run:
                text = inp.read(self.w4)
                if not text:
                    break
                if len(text) != self.w4:
                    text = text.ljust(self.w4,b'\x00')
# последняя строка может быть меньше необходимого размера, поэтому мы дополняем её нулевыми байтами
                    run = False
                text = self.encrypt_block(text)
                out.write(text)

    def decrypt_block(self, data):
        A = int.from_bytes(data[:self.w8], byteorder='little')
        B = int.from_bytes(data[self.w8:], byteorder='little')
        for i in range(self.r, 0, -1):
            B = self.__rshift(B - self.S[2 * i + 1], A) ^ A
            A = self.__rshift(A - self.S[2 * i], B) ^ B
        B = (B - self.S[1]) % self.mod
        A = (A - self.S[0]) % self.mod
        return (A.to_bytes(self.w8, byteorder='little')
                + B.to_bytes(self.w8, byteorder='little'))

    def decrypt_file(self, inp_file_name, out_file_name):
        with open(inp_file_name, 'rb') as inp, open(out_file_name, 'wb') as out:
            run = True
            while run:
                text = inp.read(self.w4)
                if not text:
                    break
                if len(text) != self.w4:
                    run = False
                text = self.decrypt_block(text)
                if not run:
                    text = text.rstrip(b'\x00')
# удаляем добавленные на этапе шифрования b'\x00'
                out.write(text)