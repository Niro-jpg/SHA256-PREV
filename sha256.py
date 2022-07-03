"""This Python module is an implementation of the SHA-256 algorithm.
From https://github.com/keanemind/Python-SHA-256"""

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def generate_hash(message: bytearray) -> bytearray:
    """Return a SHA-256 hash from the message passed.
    The argument should be a bytes, bytearray, or
    string object."""

    mem = []
    result = 0
    a = 0
    b = 0
    c = 0
    d = 0
    e = 0
    f = 0
    g = 0
    h = 0
    t1 = 0
    t2 = 0

    #trasformiamo il messaggio in un messaggio ascii
    if isinstance(message, str):
        message = bytearray(message, 'ascii') 
    elif isinstance(message, bytes):
        message = bytearray(message)
    elif not isinstance(message, bytearray):
        raise TypeError
    

    # Padding
    lunghezzaFinale = 0
    length = len(message) * 8 # len(message) is number of BYTES!!! length però è il numero di bit.
    message.append(0x80) #non costa niente perché è reverssibile.
    y = 0
    print("messaggio all'inizio: ", message)
    while (len(message) * 8 + 64) % 512 != 0: #Questo while può essere implementato reversibilmente.
        y = y + 1
        message.append(0x00)
    mem.append(y)
    print("y: ", y)
    print("messaggio all'inizio ma dopo: ", message)

    message += length.to_bytes(8, 'big') # pad to 8 bytes or 64 bits 7 salvandosi length è reversibile 

    assert (len(message) * 8) % 512 == 0, "Padding did not complete properly!"

    # Parsing
    blocks = [] # contains 512-bit chunks of message
    j = 0
    for i in range(0, len(message), 64): # 64 bytes is 512 bits / for reversibile
        j = j + 1
        blocks.append(message[i:i+64]) #reversibile in quanto riempiamo uno spazio prima vuoto
    mem.append(j)

    # Setting Initial Hash Value
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h5 = 0x9b05688c
    h4 = 0x510e527f
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # SHA-256 Hash Computation
    for message_block in blocks:

        # Prepare message schedule
        message_schedule = []
        for t in range(0, 64): #for reversibile 
            if t <= 15: # if anche esso reversibile
                # adds the t'th 32 bit word of the block,
                # starting from leftmost word
                # 4 bytes at a time
                message_schedule.append(bytes(message_block[t*4:(t*4)+4])) #anche questo reversibile perché prima non conteneva niente
            else:
                #qua devo capire il costo di ogni operazione
                term1 = _sigma1(int.from_bytes(message_schedule[t-2], 'big'))
                term2 = int.from_bytes(message_schedule[t-7], 'big')
                term3 = _sigma0(int.from_bytes(message_schedule[t-15], 'big'))
                term4 = int.from_bytes(message_schedule[t-16], 'big')

                # append a 4-byte byte object
                schedule = ((term1 + term2 + term3 + term4) % 2**32).to_bytes(4, 'big')
                message_schedule.append(schedule)

        assert len(message_schedule) == 64

        # Initialize working variables / dovrebbero essere reversibili perché non costano niet
        mem.append(a)
        a -= mem[len(mem) - 1]
        a += h0

        mem.append(b)
        b -= mem[len(mem) - 1]
        b += h1

        mem.append(c)
        c -= mem[len(mem) - 1]
        c += h2

        mem.append(d)
        d -= mem[len(mem) - 1]
        d += h3

        mem.append(e)
        e -= mem[len(mem) - 1]
        e += h4

        mem.append(f)
        f -= mem[len(mem) - 1]
        f += h5

        mem.append(g)
        g -= mem[len(mem) - 1]
        g += h6

        mem.append(h)
        h -= mem[len(mem) - 1]
        h += h7

        print("il valore di a è: ", a)

        # Iterate for t=0 to 63 / for alquanto reversibile mettendo quel e qua iniziano le beghe
        for t in range(64): 
            #tutte le operazioni qua hanno costo w in quanto eliminano una parola di memoria ma possono essere mantenute con un costo di w in memoria

            mem.append(t1)  
            t1 -= mem[len(mem) - 1]
            t1 += ((h + _capsigma1(e) + _ch(e, f, g) + K[t] +
                   int.from_bytes(message_schedule[t], 'big')) % 2**32)     

            mem.append(t2)  
            t2 -= mem[len(mem) - 1]
            t2 += (_capsigma0(a) + _maj(a, b, c)) % 2**32

            mem.append(h)
            h -= mem[len(mem) - 1]
            h += g

            mem.append(g)
            g -= mem[len(mem) - 1]
            g += f

            mem.append(f)
            f -= mem[len(mem) - 1]
            f += e

            mem.append(e)
            e -= mem[len(mem) - 1]
            e += (d + t1) % 2**32
            
            mem.append(d)
            d -=mem[len(mem) - 1]
            d += c

            mem.append(c)
            c -= mem[len(mem) - 1]
            c += b

            mem.append(b)
            b -= mem[len(mem) - 1]
            b += a

            mem.append(a)
            a -= mem[len(mem) - 1]
            a += (t1 + t2) % 2**32

        # Compute intermediate hash value
        #ognuna di queste operazioni ha costo w in memoria
        mem.append(h0)
        h0 = (h0 + a) % 2**32
        mem.append(h1)
        h1 = (h1 + b) % 2**32
        mem.append(h2)
        h2 = (h2 + c) % 2**32
        mem.append(h3)
        h3 = (h3 + d) % 2**32
        mem.append(h4)
        h4 = (h4 + e) % 2**32
        mem.append(h5)
        h5 = (h5 + f) % 2**32
        mem.append(h6)
        h6 = (h6 + g) % 2**32
        mem.append(h7)
        h7 = (h7 + h) % 2**32

    result = ((h0).to_bytes(4, 'big') + (h1).to_bytes(4, 'big') +
             (h2).to_bytes(4, 'big') + (h3).to_bytes(4, 'big') +
             (h4).to_bytes(4, 'big') + (h5).to_bytes(4, 'big') +
             (h6).to_bytes(4, 'big') + (h7).to_bytes(4, 'big'))

    lunghezzaFinale = len(mem)

    for message_block in blocks:

        h7 -= h7
        h7 += mem[len(mem) - 1]
        mem[len(mem) - 1] -= h7
        mem.pop(len(mem) - 1)

        h6 -= h6
        h6 += mem[len(mem) - 1]
        mem[len(mem) - 1] -= h6
        mem.pop(len(mem) - 1)

        h5 -= h5
        h5 += mem[len(mem) - 1]
        mem[len(mem) - 1] -= h5
        mem.pop(len(mem) - 1)

        h4 -= h4
        h4 += mem[len(mem) - 1]
        mem[len(mem) - 1] -= h4
        mem.pop(len(mem) - 1)

        h3 -= h3
        h3 += mem[len(mem) - 1]
        mem[len(mem) - 1] -= h3
        mem.pop(len(mem) - 1)

        h2 -= h2
        h2 += mem[len(mem) - 1]
        mem[len(mem) - 1] -= h2
        mem.pop(len(mem) - 1)

        h1 -= h1
        h1 += mem[len(mem) - 1]
        mem[len(mem) - 1] -= h1
        mem.pop(len(mem) - 1)

        h0 -= h0
        h0 += mem[len(mem) - 1]
        mem[len(mem) - 1] -= h0
        mem.pop(len(mem) - 1)

        # Iterate for t=0 to 63 / for alquanto reversibile mettendo quel e qua iniziano le beghe
        for t in range(64): 
            #tutte le operazioni qua hanno costo w in quanto eliminano una parola di memoria ma possono essere mantenute con un costo di w in memoria

            a -= a
            a += mem[len(mem) - 1]
            mem[len(mem) - 1] -= a
            mem.pop(len(mem) - 1)

            b -= b
            b += mem[len(mem) - 1]
            mem[len(mem) - 1] -= b
            mem.pop(len(mem) - 1)

            c -= c
            c += mem[len(mem) - 1]
            mem[len(mem) - 1] -= c
            mem.pop(len(mem) - 1)
            
            d -=d
            d += mem[len(mem) - 1]
            mem[len(mem) - 1] -= d
            mem.pop(len(mem) - 1)

            e -= e
            e += mem[len(mem) - 1]
            mem[len(mem) - 1] -= e
            mem.pop(len(mem) - 1)

            f -= f
            f += mem[len(mem) - 1]
            mem[len(mem) - 1] -= f
            mem.pop(len(mem) - 1)

            g -= g
            g += mem[len(mem) - 1]
            mem[len(mem) - 1] -= g
            mem.pop(len(mem) - 1)

            h -= h
            h += mem[len(mem) - 1]
            mem[len(mem) - 1] -= h
            mem.pop(len(mem) - 1)

            t2 -= t2
            t2 += mem[len(mem) - 1]
            mem[len(mem) - 1] -= t2
            mem.pop(len(mem) - 1)

            t1 -= t1
            t1 += mem[len(mem) - 1]
            mem[len(mem) - 1] -= t1
            mem.pop(len(mem) - 1)


        a -= a
        a += mem[len(mem) - 1]
        mem[len(mem) - 1] -= a
        mem.pop(len(mem) - 1)

        b -= b
        b += mem[len(mem) - 1]
        mem[len(mem) - 1] -= b
        mem.pop(len(mem) - 1)

        c -= c
        c += mem[len(mem) - 1]
        mem[len(mem) - 1] -= c
        mem.pop(len(mem) - 1)
            
        d -=d
        d += mem[len(mem) - 1]
        mem[len(mem) - 1] -= d
        mem.pop(len(mem) - 1)

        e -= e
        e += mem[len(mem) - 1]
        mem[len(mem) - 1] -= e
        mem.pop(len(mem) - 1)

        f -= f
        f += mem[len(mem) - 1]
        mem[len(mem) - 1] -= f
        mem.pop(len(mem) - 1)

        g -= g
        g += mem[len(mem) - 1]
        mem[len(mem) - 1] -= g
        mem.pop(len(mem) - 1)

        h -= h
        h += mem[len(mem) - 1]
        mem[len(mem) - 1] -= h
        mem.pop(len(mem) - 1)


    for t in range(0, 64): #for reversibile 

        message_schedule.pop(0)

    h7 -= h7
    h6 -= h6
    h5 -= h5
    h4 -= h4
    h3 -= h3
    h2 -= h2
    h1 -= h1
    h0 -= h1

    q = mem.pop(len(mem) - 1)
    for i in range(q):
        removeBlock = int.from_bytes(blocks.pop(), byteorder='big', signed=False)
        removeBlock -= removeBlock

    for i in range(8):
        message.pop() 

    k = mem.pop(len(mem) - 1)
    for i in range(k):
        message.pop()
    
    abit = message.pop()
    abit -= abit

    print("messaggio iniziale: ", message)
    print("la lunghezza finale è: ", lunghezzaFinale)
    
    
    return result      









def _sigma0(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 7) ^
           _rotate_right(num, 18) ^
           (num >> 3))
    return num

def _sigma1(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 17) ^
           _rotate_right(num, 19) ^
           (num >> 10))
    return num

def _capsigma0(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 2) ^
           _rotate_right(num, 13) ^
           _rotate_right(num, 22))
    return num

def _capsigma1(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 6) ^
           _rotate_right(num, 11) ^
           _rotate_right(num, 25))
    return num

def _ch(x: int, y: int, z: int):
    """As defined in the specification."""
    return (x & y) ^ (~x & z)

def _maj(x: int, y: int, z: int):
    """As defined in the specification."""
    return (x & y) ^ (x & z) ^ (y & z)

def _rotate_right(num: int, shift: int, size: int = 32):
    """Rotate an integer right."""
    return (num >> shift) | (num << size - shift)

def subtract(x, y):
 
    while (y != 0):

        borrow = (~x) & y
        x = x ^ y
        y = borrow << 1
     
    return x    

if __name__ == "__main__":
    print(generate_hash("Hellowwwwwwwwwwwwwssssssssssssdddddddddddddddddddffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffooooooooooooooooo").hex())