#!/usr/bin/env python3

import re

from scapy.all import (
    Ether,
    IntField,
    Packet,
    StrFixedLenField,
    XByteField,
    bind_layers,
    srp1
)


class P4calc(Packet):
    name = "P4calc"
    fields_desc = [ StrFixedLenField("p", "K", length=1),
                    StrFixedLenField("op", "G", length=1),

                    IntField("t_0", 0),
                    IntField("t_1", 0),
                    IntField("t_2", 0),
                    IntField("t_3", 0),
                    IntField("t_4", 0),
                    IntField("t_5", 0),
                    IntField("t_6", 0),
                    IntField("t_7", 0),
                    IntField("t_8", 0),
                    IntField("t_9", 0),

                    IntField("seed", 0),
                    ]

bind_layers(Ether, P4calc, type=0x1234)


def createMatrix(rowCount, colCount, dataList):
    mat = []
    for i in range(rowCount):
        rowList = []
        for j in range(colCount):
            # you need to increment through dataList here, like this:
            rowList.append(dataList[rowCount * i + j])
        mat.append(rowList)

    return mat


def main():

    iface = 'eth0'
    seed = [1234]

    # while True:
    try:
        pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / P4calc(op="G",
                                          seed=seed[0]
                                          )
        pkt = pkt/' '

        pkt.show()
        resp = srp1(pkt, iface=iface, timeout=1, verbose=True)
        if resp:
            p4calc=resp[P4calc]
            if p4calc:
                print(p4calc.show())
            else:
                print("cannot find P4calc header in the packet")
        else:
            print("Didn't receive response")
    except Exception as error:
        print(error)


if __name__ == '__main__':
    main()
