
import sys
import ctypes
import time
from rnm import *


def cb(client, cid, data, size):
    data_p = ctypes.cast(data, ctypes.POINTER(ctypes.c_int)).contents
    data_s = ctypes.cast(cid, ctypes.c_char_p)
    print data_p
    print data_s
    print ("Hello")
    return 0

def main():

    client = rnm("hello", "127.0.0.1", 4444, "udp")
    x = 1
    client.subscribe_event ("int", "mode" , cb , x)
    client.connect_wait(1000)

    while True:
        data = client.getvar_int ("pause")
        print data
        client.setvar_int ("pause", x)
        x+=1
        time.sleep(1)

if __name__ == '__main__':
    main()
