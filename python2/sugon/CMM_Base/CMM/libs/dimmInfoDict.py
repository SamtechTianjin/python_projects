# -*- coding:utf-8 -*-
__author__ = "Sam"

"""
根据DIMM Type和频率返回值共同获得Max Frequency和Work Frequency
"""

DIMM_INFO_DICT = {
    "0": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "",
        "Unit": "",
        "ModuleType": "",
        "DRAMWidth": ""
    },
    "1": {
        "DimmType": "Volatile",
        "MemType": "DDR",
        "DDR3": "800MHz",
        "DDR4": "800MT/s",
        "Unit": "MB",
        "ModuleType": "RDIMM",
        "DRAMWidth": "x4"
    },
    "2": {
        "DimmType": "DCPMM",
        "MemType": "DDR2",
        "DDR3": "1067MHz",
        "DDR4": "1000MT/s",
        "Unit": "GB",
        "ModuleType": "UDIMM",
        "DRAMWidth": "x8"
    },
    "3": {
        "DimmType": "NVDIMM",
        "MemType": "DDR3",
        "DDR3": "1333MHz",
        "DDR4": "1067MT/s",
        "Unit": "TB",
        "ModuleType": "SO-DIMM",
        "DRAMWidth": "x16"
    },
    "4": {
        "DimmType": "",
        "MemType": "DDR4",
        "DDR3": "1600MHz",
        "DDR4": "1200MT/s",
        "Unit": "",
        "ModuleType": "LRDIMM",
        "DRAMWidth": "x32"
    },
    "5": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "1867MHz",
        "DDR4": "1333MT/s",
        "Unit": "",
        "ModuleType": "Mini-RDIMM",
        "DRAMWidth": ""
    },
    "6": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "2133MHz",
        "DDR4": "1400MT/s",
        "Unit": "",
        "ModuleType": "Mini-UDIMM",
        "DRAMWidth": ""
    },
    "7": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "2400MHz",
        "DDR4": "1600MT/s",
        "Unit": "",
        "ModuleType": "",
        "DRAMWidth": ""
    },
    "8": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "1800MT/s",
        "Unit": "",
        "ModuleType": "72b-SO-RDIMM",
        "DRAMWidth": ""
    },
    "9": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "1867MT/s",
        "Unit": "",
        "ModuleType": "72b-SO-UDIMM",
        "DRAMWidth": ""
    },
    "10": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "2000MT/s",
        "Unit": "",
        "ModuleType": "",
        "DRAMWidth": ""
    },
    "11": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "2133MT/s",
        "Unit": "",
        "ModuleType": "",
        "DRAMWidth": ""
    },
    "12": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "2200MT/s",
        "Unit": "",
        "ModuleType": "16b-SO-DIMM",
        "DRAMWidth": ""
    },
    "13": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "2400MT/s",
        "Unit": "",
        "ModuleType": "32b-SO-DIMM",
        "DRAMWidth": ""
    },
    "14": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "2600MT/s",
        "Unit": "",
        "ModuleType": "",
        "DRAMWidth": ""
    },
    "15": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "2666MT/s",
        "Unit": "",
        "ModuleType": "",
        "DRAMWidth": ""
    },
    "16": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "2800MT/s",
        "Unit": "",
        "ModuleType": "",
        "DRAMWidth": ""
    },
    "17": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "2933MT/s",
        "Unit": "",
        "ModuleType": "",
        "DRAMWidth": ""
    },
    "18": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "3000MT/s",
        "Unit": "",
        "ModuleType": "",
        "DRAMWidth": ""
    },
    "19": {
        "DimmType": "",
        "MemType": "",
        "DDR3": "",
        "DDR4": "3200MT/s",
        "Unit": "",
        "ModuleType": "",
        "DRAMWidth": ""
    }
}


