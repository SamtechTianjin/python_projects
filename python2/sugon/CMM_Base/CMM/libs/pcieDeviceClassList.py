# -*- coding:utf-8 -*-
__author__ = "Sam"

############################################
#              PCIE Device Class           #
############################################
pcieDeviceClassList = {
    "00":{
        "00": "Undefined Device",
        "01": "VGA Card",
        "other": None,
    },
    "01":{
        "00": "SCSI Card",
        "01": "IDE Card",
        "02": "Floopy disk Card",
        "03": "IPI bus Card",
        "04": "Raid Card",
        "05": "ATA Card",
        "06": "Serial ATA Card",
        "07": "SAS Card",
        "08": "Non-volatile memory(NVM)",
        "09": "Universal Flash Storage(UFS)",
        "other": "Mass Storage Controller",
    },
    "02":{
        "00": "Ethernet Card",
        "01": "oken Ring Card",
        "02": "FDDI Card",
        "03": "ATM Card",
        "04": "ISDN Card",
        "05": "WorldFip Card",
        "06": "PICMG 2.14 Multi Computing",
        "07": "InfiniBand* Controller",
        "08": "Host fabric controller",
        "other": "Other network controller",
    },
    "03":{
        "00": "VGA Card",
        "01": "XGA Card",
        "02": "3D Card",
        "other": "Other display controller",
    },
    "04":{
        "00": "Video Card",
        "01": "Audio Card",
        "02": "Computer telephony device",
        "03": "High Definition Audio (HD-A) 1.0 Card",
        "other": "Multimedia Device Card",
    },
    "05":{
        "00": "RAM",
        "01": "Flash",
        "other": "Other memory Card",
    },
    "06":{
        "00": "Host bridge Card",
        "01": "ISA bridge Card",
        "02": "EISA bridge Card",
        "03": "MCA bridge Card",
        "04": "PCI-to-PCI bridge Card",
        "05": "PCMCIA bridge Card",
        "06": "NuBus bridge Card",
        "07": "CardBus bridge Card",
        "08": "RACEway bridge Card",
        "09": "Semi-transparent PCI-to-PCI bridge Card",
        "0a": "InfiniBand-to-PCI host bridge Card",
        "0b": "Advanced Switching to PCI host bridge Card",
        "other": "Other bridge Card",
    },
    "07":{
        "00": "serial controller",
        "01": "Parallel port",
        "02": "Multiport serial controller",
        "03": "Modem interface",
        "04": "GPIB (IEEE 488.1/2) controller",
        "05": "Smart Card",
        "other": "Other communications device",
    },
    "08":{
        "00": "PIC",
        "01": "DMA controller",
        "02": "system timer",
        "03": "RTC controller",
        "04": "Generic PCI Hot-Plug controller",
        "05": "SD Host controller",
        "06": "IOMMU",
        "07": "Root Complex Event Collector",
        "other": "Other system peripheral",
    },
    "09":{
        "00": "Keyboard controller",
        "01": "Digitizer (pen)",
        "02": "Mouse controller",
        "03": "Scanner controller",
        "04": "Gameport controller",
        "other": "Other input controller",
    },
    "0a":{
        "00": "Generic docking station",
        "other": "Other type of docking station",
    },
    "0b":{
        "00": "386",
        "01": "486",
        "02": "Pentium",
        "10": "Alpha",
        "20": "PowerPC",
        "30": "MIPS",
        "40": "Co-processor",
        "other": "Other processors",
    },
    "0c":{
        "00": "IEEE 1394",
        "01": "ACCESS.bus",
        "02": "SSA",
        "03": "Universal Serial Bus (USB)",
        "04": "Fibre Channel",
        "05": "SMBus",
        "06": "InfiniBand–This sub-class is deprecated",
        "07": "IPMI interface",
        "08": "SERCOS Interface Standard (IEC 61491)",
        "09": "CANBus",
        "other": "Serial Bus Controller",
    },
    "0d":{
        "00": "iRDA compatible controller",
        "01": "Consumer IR controller",
        "10": "RF controller",
        "11": "Bluetooth",
        "12": "Broadband",
        "20": "Ethernet (802.11a -5 GHz)",
        "21": "Ethernet (802.11b -2.4 GHz)",
        "40": "Cellular controller/modem",
        "41": "Cellular controller/modem plus Ethernet (802.11)",
        "other": "Other type of wireless controller",
    },
    "0e":"Intelligent I/O Controller",
    "0f":{
        "01": "TV",
        "02": "Audio",
        "03": "Voice",
        "04": "Data",
        "other": "Other Satellite Communication Controller",
    },
    "10":{
        "00": "Network and computing en/decryption",
        "10": "Entertainment en/decryption",
        "other": "Other en/decryption",
    },
    "11":{
        "00": "DPIO modules",
        "01": "Performance counters",
        "10": "Communications synchronization plus time and frequency test/measurement",
        "20": "Management card",
        "other": "Other data acquisition/signal processing controllers",
    },
    "12":{
        "00": "Processing Accelerator",
        "other": None,
    },
    "13":{
        "00": "Non-Essential Instrumentation Function",
        "other": None,
    },
    "other": "Undefined Device",
}

"""
Base Class	Sub Class	The PCIe Device 
00h	00h	Undefined Device
	01h	VGA Card
01h	00h	SCSI Card
	01h	IDE Card
	02h	Floopy disk Card
	03h	IPI bus Card
	04h	Raid Card
	05h	ATA Card
	06h	Serial ATA Card
	07h	SAS Card
	08h	Non-volatile memory(NVM)
	09h	Universal Flash Storage(UFS)
	other	Mass Storage Controller
02h	00h	Ethernet Card
	01h	Token Ring Card
	02h	FDDI Card
	03h	ATM Card
	04h	ISDN Card
	05h	WorldFip Card
	06h	PICMG 2.14 Multi Computing
	07h	InfiniBand* Controller
	08h	Host fabric controller
	Other	Other network controller
03h	00h	VGA Card
	01h	XGA Card
	02h	3D Card
	Other	Other display controller
04h	00h	Video Card
	01h	Audio Card
	02h	Computer telephony device
	03h	High Definition Audio (HD-A) 1.0 Card
	other	Multimedia Device Card
05h	00h	RAM
	01h	Flash
	Other	Other memory Card
06h	00h	Host bridge Card
	01h	ISA bridge Card
	02h	EISA bridge Card
	03h	MCA bridge Card
	04h	PCI-to-PCI bridge Card
	05h	PCMCIA bridge Card
	06h	NuBus bridge Card
	07h	CardBus bridge Card
	08h	RACEway bridge Card
	09h	Semi-transparent PCI-to-PCI bridge Card
	0ah	InfiniBand-to-PCI host bridge Card
	0bh	Advanced Switching to PCI host bridge Card
	other	Other bridge Card
07h	00h	serial controller
	01h	Parallel port
	02h	Multiport serial controller
	03h	Modem interface
	04h	GPIB (IEEE 488.1/2) controller
	05h	Smart Card
	Other	Other communications device
08h	00h	PIC
	01h	 DMA controller
	02h	system timer
	03h	RTC controller
	04h	Generic PCI Hot-Plug controller
	05h	SD Host controller
	06h	IOMMU
	07h	Root Complex Event Collector
	Other	Other system peripheral
09h	00h	Keyboard controller
	01h	Digitizer (pen)
	02h	Mouse controller
	03h	Scanner controller
	04h	Gameport controller
	Other	Other input controller
0ah	00h	Generic docking station
	Other	Other type of docking station
0bh	00h	386
	01h	486
	02h	Pentium
	10h	Alpha
	20h	PowerPC
	30h	MIPS
	40h	Co-processor
	other	Other processors
0ch	00h	IEEE 1394
	01h	ACCESS.bus
	02h	SSA
	03h	Universal Serial Bus (USB)
	04h	Fibre Channel
	05h	SMBus
	06h	InfiniBand–This sub-class is deprecated
	07h	IPMI interface
	08h	SERCOS Interface Standard (IEC 61491)
	09h	CANBus
	other	Serial Bus Controller
0dh	00h	iRDA compatible controller
	01h	Consumer IR controller
	10h	RF controller
	11h	Bluetooth
	12h	Broadband
	20h	Ethernet (802.11a -5 GHz)
	21h	Ethernet (802.11b -2.4 GHz)
	40h	Cellular controller/modem
	41h	Cellular controller/modem plus Ethernet (802.11)
	other	Other type of wireless controller
0eh	~	Intelligent I/O Controller
0fh
	01h	TV
	02h	Audio
	03h	Voice
	04h	Data
	other	Other Satellite Communication Controller
10h	00h	Network and computing en/decryption
	10h	Entertainment en/decryption
	other	Other en/decryption
11h	00h	DPIO modules
	01h	Performance counters
	10h	Communications synchronization plus time and 
frequency test/measurement
	20h	Management card
	other	Other data acquisition/signal processing controllers
12h	00h	Processing Accelerator
13h	00h	Non-Essential Instrumentation Function
other	~	Undefined Device

"""
