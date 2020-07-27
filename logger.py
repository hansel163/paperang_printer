import logging
from logging import handlers

DFT_FMT = '%(asctime)s - %(funcName)s[line:%(lineno)d] - %(levelname)s: %(message)s'


class Logger(object):
    level_relations = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'crit': logging.CRITICAL
    }

    def __init__(self, filename, level='info', fmt=DFT_FMT):
        self.logger = logging.getLogger(filename)
        format_str = logging.Formatter(fmt)
        self.logger.setLevel(self.level_relations.get(level))  
        sh = logging.StreamHandler()  
        sh.setFormatter(format_str)  
        th = logging.FileHandler(
            filename=filename, encoding='utf-8')  
        th.setFormatter(format_str)  
        self.logger.addHandler(sh)  
        self.logger.addHandler(th)
