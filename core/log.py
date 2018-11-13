#!/usr/bin/env python
# encoding=utf-8
#codeby     道长且阻
#email      ydhcui@suliu.net/QQ664284092

import logging as logg
import sys
import platform
import datetime
import settings

class Logger(object):
    def __init__(self, logname = __name__, ws = None):
        if platform.system()=='Windows':
            logg.StreamHandler.emit = self.add_coloring_to_emit_windows(logg.StreamHandler.emit)
        else:
            logg.StreamHandler.emit = self.add_coloring_to_emit_ansi(logg.StreamHandler.emit)
        self.logger = logg.getLogger(logname)
        self.setLevel()
        self.formatter = logg.Formatter('[%(levelname)s][%(asctime)s][%(message)s]','%Y-%m-%d %H:%M:%S')
        self.stream_handler = logg.StreamHandler(sys.stderr)
        self.stream_handler.setFormatter(self.formatter)
        self.logger.addHandler(self.stream_handler)
        self.file_handler = None
        self.websocket = ws

    def setLevel(self,loglevel = None):
        loglevel = loglevel if loglevel else logg.DEBUG
        self.logger.setLevel(loglevel)

    def setFormatter(self,*args):
        if args:
            self.formatter = logg.Formatter(*args)
        self.stream_handler.setFormatter(self.formatter)
        if self.file_handler:
            self.file_handler.setFormatter(self.formatter)

    def setFileHandler(self,filepath = None):
        if filepath:
            self.file_handler = logg.FileHandler(filepath)
            self.file_handler.setFormatter(self.formatter)
            self.logger.addHandler(self.file_handler)

    def add_coloring_to_emit_windows(self,fn):
        def _out_handle(self):
            import ctypes
            return ctypes.windll.kernel32.GetStdHandle(self.STD_OUTPUT_HANDLE)
        out_handle = property(_out_handle)
        def _set_color(self, code):
            import ctypes
            self.STD_OUTPUT_HANDLE = -11
            hdl = ctypes.windll.kernel32.GetStdHandle(self.STD_OUTPUT_HANDLE)
            ctypes.windll.kernel32.SetConsoleTextAttribute(hdl, code)
        setattr(logg.StreamHandler, '_set_color', _set_color)
        def new(*args):
            FOREGROUND_BLUE      = 0x0001 # text color contains blue.
            FOREGROUND_GREEN     = 0x0002 # text color contains green.
            FOREGROUND_RED       = 0x0004 # text color contains red.
            FOREGROUND_INTENSITY = 0x0008 # text color is intensified.
            FOREGROUND_WHITE     = FOREGROUND_BLUE|FOREGROUND_GREEN |FOREGROUND_RED
            STD_INPUT_HANDLE     = -10
            STD_OUTPUT_HANDLE    = -11
            STD_ERROR_HANDLE     = -12
            FOREGROUND_BLACK     = 0x0000
            FOREGROUND_BLUE      = 0x0001
            FOREGROUND_GREEN     = 0x0002
            FOREGROUND_CYAN      = 0x0003
            FOREGROUND_RED       = 0x0004
            FOREGROUND_MAGENTA   = 0x0005
            FOREGROUND_YELLOW    = 0x0006
            FOREGROUND_GREY      = 0x0007
            FOREGROUND_INTENSITY = 0x0008 # foreground color is intensified.
            BACKGROUND_BLACK     = 0x0000
            BACKGROUND_BLUE      = 0x0010
            BACKGROUND_GREEN     = 0x0020
            BACKGROUND_CYAN      = 0x0030
            BACKGROUND_RED       = 0x0040
            BACKGROUND_MAGENTA   = 0x0050
            BACKGROUND_YELLOW    = 0x0060
            BACKGROUND_GREY      = 0x0070
            BACKGROUND_INTENSITY = 0x0080 # background color is intensified.
            levelno = args[1].levelno
            if(levelno>=50):
                color = BACKGROUND_YELLOW | FOREGROUND_RED | FOREGROUND_INTENSITY | BACKGROUND_INTENSITY
            elif(levelno>=40):
                color = FOREGROUND_RED | FOREGROUND_INTENSITY
            elif(levelno>=30):
                color = FOREGROUND_YELLOW | FOREGROUND_INTENSITY
            elif(levelno>=20):
                color = FOREGROUND_GREEN
            elif(levelno>=10):
                color = FOREGROUND_MAGENTA
            else:
                color =  FOREGROUND_WHITE
            args[0]._set_color(color)
            ret = fn(*args)
            args[0]._set_color( FOREGROUND_WHITE )
            return ret
        return new

    def add_coloring_to_emit_ansi(self,fn):
        def new(*args):
            levelno = args[1].levelno
            if(levelno>=50):
                color = '\x1b[31m' # red
            elif(levelno>=40):
                color = '\x1b[31m' # red
            elif(levelno>=30):
                color = '\x1b[33m' # yellow
            elif(levelno>=20):
                color = '\x1b[32m' # green
            elif(levelno>=10):
                color = '\x1b[35m' # pink
            else:
                color = '\x1b[0m' # normal
            args[1].msg = color + args[1].msg +  '\x1b[0m'  # normal
            return fn(*args)
        return new

    def debug(self,msg):
        self.logger.debug(str(msg))

    def info(self,msg):
        self.logger.info(str(msg))

    def warn(self,msg):
        self.logger.warn(str(msg))

    def error(self,msg):
        self.logger.error(str(msg))

    def fatal(self,msg):
        self.logger.fatal(str(msg))

    def load(self,msg,n=44):
        '''显示进度'''
        sys.stdout.write(str(msg).ljust(n)+'\r')
        sys.stdout.flush()

logging = Logger()
logging.setFileHandler(settings.LOGSPATH + '/logging.log')
if __name__=="__main__":
    logging.info('info')
    logging.error('error')