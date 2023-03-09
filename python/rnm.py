#/**************************************************************  
# * Description: Wrapper of library of network variables and channels
# * Copyright (c) 2022 Alexander Krapivniy (a.krapivniy@gmail.com)
# * 
# * This program is free software: you can redistribute it and/or modify  
# * it under the terms of the GNU General Public License as published by  
# * the Free Software Foundation, version 3.
# *
# * This program is distributed in the hope that it will be useful, but 
# * WITHOUT ANY WARRANTY; without even the implied warranty of 
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# * General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License 
# * along with this program. If not, see <http://www.gnu.org/licenses/>.
# ***************************************************************/

import ctypes
import os

#from ctypes import cdll
rnmlib = ctypes.CDLL(os.path.abspath("librnm.so.1.0"))

class rnm(object):
    vartype_int = 0x0200
    callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32)

    def vartype(self, name):
        if name == "int":
            return self.vartype_int

    def __init__(self,  id, addr = "", port = 0, type = "tcp"):
        rnmlib.rnm_connect_simple.restype = ctypes.POINTER(ctypes.c_void_p)
        rnmlib.rnm_udpconnect.restype = ctypes.POINTER(ctypes.c_void_p)
        rnmlib.rnm_connect.restype = ctypes.POINTER(ctypes.c_void_p)
        rnmlib.rnm_subscribe_event.restype = ctypes.c_int
        rnmlib.rnm_isconnect.restype = ctypes.c_int
        rnmlib.rnm_connect_wait.restype = ctypes.c_int
        rnmlib.rnm_subscribe_event.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, self.callback_type ,ctypes.c_void_p)
        if type == "udp":
            self.desc = rnmlib.rnm_udpconnect(addr, port, id)
        else:
            self.desc = rnmlib.rnm_connect_simple(addr, port, id)

    def subscribe_event(self, type, id, cb, args):
        return rnmlib.rnm_subscribe_event(self.desc, ctypes.c_uint32(self.vartype(type)), ctypes.cast(id ,ctypes.c_char_p), self.callback_type(cb), ctypes.cast(id ,ctypes.c_void_p))

    def unsubscribe_event(self, id):
        return rnmlib.rnm_unsubscribe_event(self.desc, ctypes.cast(id ,ctypes.c_char_p))

    def connect_wait(self, timeout = 0):
        return rnmlib.rnm_connect_wait(self.desc, ctypes.c_uint32(timeout))

    def disconnect(self):
        rnmlib.rnm_isconnect(self.desc)
        self.desc = ctypes.POINTER(0)

    def find_server(addr, port):
        addr = ctypes.c_char_p()
        port = ctypes.c_int()
        rnmlib.rnm_find_server(ctypes.POINTER(ctypes.c_char_p)(addr), ctypes.POINTER(ctypes.c_int)(port))
        return addr, port

    def isconnect(self):
        return rnmlib.rnm_isconnect(self.desc)

    def define(self, id, type):
        return _rnm.rnm_define(self.desc, ctypes.c_uint32(self.vartype(type)), ctypes.cast(id ,ctypes.c_char_p))

    def undefine(self, id):
        return _rnm.rnm_undefine(self.desc, ctypes.cast(id ,ctypes.c_char_p))

    def setvar_int(self, id, data, flag = 0):
        return rnmlib.rnm_setvar_int(self.desc, 0, ctypes.cast(id ,ctypes.c_char_p), ctypes.c_int32(data))

    def setvar_long(self, id, data, flag = 0):
        return rnmlib.rnm_setvar_long(self.desc, ctypes.cast(id ,ctypes.c_char_p), ctypes.c_char_p(id), ctypes.c_int64(data))

    def setvar_float(self, id, data, flag = 0):
        return rnmlib.rnm_setvar_float(self.desc, ctypes.cast(id ,ctypes.c_char_p), ctypes.c_char_p(id), ctypes.c_float(data))

    def setvar_double(self, id, data, flag = 0):
        return rnmlib.rnm_setvar_double(self.desc, ctypes.cast(id ,ctypes.c_char_p), ctypes.c_char_p(id), ctypes.c_double(data))

    def setvar_str(self, id, data, flag = 0):
        return rnmlib.rnm_setvar_str(self.desc, ctypes.c_uint32(flags),  ctypes.cast(id ,ctypes.c_char_p), ctypes.c_char_p(data))

    def send_command(self, id, data, data_size, flag = 0):
        return rnmlib.rnm_send_command(self.desc, ctypes.c_uint32(flags),  ctypes.cast(id ,ctypes.c_char_p), ctypes.c_void_p(data), ctypes.c_uint32(data_size))

    def send_response(self, id, data, data_size, flag = 0):
        return rnmlib.rnm_send_response(self.desc, ctypes.c_uint32(flags),  ctypes.cast(id ,ctypes.c_char_p), ctypes.c_void_p(data), ctypes.c_uint32(data_size))

    def event(self, id, flag = 0):
        return rnmlib.rnm_event(self.desc, ctypes.c_uint32(flags), ctypes.cast(id ,ctypes.c_char_p))

    def write(self, id, data, data_size, flag = 0):
        return rnmlib.rnm_write(self.desc, ctypes.c_uint32(flags), ctypes.cast(id ,ctypes.c_char_p), ctypes.c_void_p(data), ctypes.c_uint32(data_size))

    def getvar_int(self, id, flags = 0):
        data = ctypes.c_int()
        status = rnmlib.rnm_getvar_int(self.desc, flags, ctypes.cast(id ,ctypes.c_char_p),  ctypes.POINTER(ctypes.c_int)(data))
        return status, data

    def getvar_long(self, id, flags = 0):
        data = ctypes.c_long()
        status = rnmlib.rnm_getvar_long(self.desc, flags, ctypes.cast(id ,ctypes.c_char_p),  ctypes.POINTER(ctypes.c_long)(data))
        return status, data

    def getvar_float(self, id, flags = 0):
        data = ctypes.c_float()
        status = rnmlib.rnm_getvar_float(self.desc, flags, ctypes.cast(id ,ctypes.c_char_p),  ctypes.POINTER(ctypes.c_float)(data))
        return status, data

    def getvar_double(self, id, flags = 0):
        data = ctypes.c_double()
        status = rnmlib.rnm_getvar_double(self.desc, flags, ctypes.cast(id ,ctypes.c_char_p),  ctypes.POINTER(ctypes.c_double)(data))
        return status, data

    def getvar_str(self, id, size, flags = 0):
        data = ctypes.c_char_p()
        status = rnmlib.rnm_getvar_long(self.desc, flags, ctypes.cast(id ,ctypes.c_char_p),  ctypes.POINTER(ctypes.c_char_p)(data), ctypes.c_int(size))
        return status, data

    def getvar_str(self, id, size, flags = 0):
        data = ctypes.c_void_p()
        status = rnmlib.rnm_getvar_long(self.desc, flags, ctypes.cast(id ,ctypes.c_char_p),  ctypes.POINTER(ctypes.c_char_p)(data), ctypes.c_int(size))
        return status, data

    def getvar_str(self, id, size, flags = 0):
        data = ctypes.c_void_p()
        status = rnmlib.rnm_getvar_long(self.desc, flags, ctypes.cast(id ,ctypes.c_char_p),  ctypes.POINTER(ctypes.c_char_p)(data), ctypes.c_int(size))
        return status, data
