# -*- coding:utf-8 -*-

import re
import collections

class ConfigHandler(object):
    __comment = "#"
    __dir_delimiter = "="
    __case_delimiter = "/"
    __data = collections.OrderedDict()

    def collect_test_cases(self, filename):
        f = open(filename, "r")
        data = f.readlines()
        f.close()
        for line in data:
            if line.startswith("#"): continue
            if not self.__dir_delimiter in line: continue
            if not self.__case_delimiter in line: continue
            lis = re.split('[{0}{1}]'.format(self.__dir_delimiter, self.__case_delimiter), line)
            if len(lis) == 3:
                case_dir,case_name,case_run = [int(value.strip()) if index==2 else value.strip() for index,value in enumerate(lis)]
                if case_run != 1:
                    continue
                self.__data[case_name] = case_dir
        return self.__data

def cases_from_config(filename):
    obj = ConfigHandler()
    data = obj.collect_test_cases(filename)
    return data

if __name__ == '__main__':
    pass