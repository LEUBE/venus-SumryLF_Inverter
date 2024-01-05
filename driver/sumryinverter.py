#!/usr/bin/env python

import argparse
from gi.repository import GLib as gobject
import platform
import argparse
import logging
import sys
import os
import time
import datetime
import serial
import math
import struct
import decimal
import traceback

# setup timezone
os.environ['TZ'] = 'Europe/Berlin'
time.tzset()

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.DEBUG, #INFO,
    datefmt='%Y-%m-%d %H:%M:%S')
    # filename='log.txt')


# connect and register to dbus
driver = {
	'name'        : "Sumry Inverter",
	'servicename' : "sumryinverter",
	'instance'    : 1,
	'id'          : 0x01,
	'version'     : 0.0,
	'serial'      : "0000000000",
	'connection'  : "com.victronenergy.multi.ttySMRYINV01"
}

logging.info("Starting Sumry Inverter driver " + str(driver['version']))


parser = argparse.ArgumentParser(description = 'Sumry Inverter driver')
parser.add_argument('--version', action='version', version='%(prog)s v' + str(driver['version']) + ' (' + driver['serial'] + ')')
parser.add_argument('--debug', action="store_true", help='enable debug logging')
parser.add_argument('--test', action="store_true", help='test some stored examples network packets')
parser.add_argument('--victron', action="store_true", help='enable Victron DBUS support for VenusOS')
requiredArguments = parser.add_argument_group('required arguments')
requiredArguments.add_argument('-d', '--device', help='serial device for data (eg /dev/ttyUSB0)', required=True)
args = parser.parse_args()

if args.debug: # switch to debug level
	logger = logging.getLogger()
	logger.setLevel(logging.DEBUG)


# victron stuff should be used
if args.victron:

	# Victron packages
	sys.path.insert(1, os.path.join(os.path.dirname(__file__), './ext/velib_python'))
	from vedbus import VeDbusService


	from dbus.mainloop.glib import DBusGMainLoop
	DBusGMainLoop(set_as_default=True)

	dbusservice = VeDbusService(driver['connection'])

	# Create the management objects, as specified in the ccgx dbus-api document
	dbusservice.add_path('/Mgmt/ProcessName', __file__)
	dbusservice.add_path('/Mgmt/ProcessVersion', 'Unknown and Python ' + platform.python_version())
	dbusservice.add_path('/Mgmt/Connection', driver['connection'])

	# Create the mandatory objects
	dbusservice.add_path('/DeviceInstance',  driver['instance'])
	dbusservice.add_path('/ProductId',       driver['id'])
	dbusservice.add_path('/ProductName',     driver['name'])
	dbusservice.add_path('/FirmwareVersion', driver['version'])
	dbusservice.add_path('/HardwareVersion', driver['version'])
	dbusservice.add_path('/Serial',          driver['serial'])
	dbusservice.add_path('/Connected',       1)

	# Create alarms
	dbusservice.add_path('/Alarms/InternalFailure', 0)

	# Create device list
	dbusservice.add_path('/Devices/0/DeviceInstance',  driver['instance'])
	dbusservice.add_path('/Devices/0/FirmwareVersion', driver['version'])
	dbusservice.add_path('/Devices/0/ProductId',       driver['id'])
	dbusservice.add_path('/Devices/0/ProductName',     driver['name'])
	dbusservice.add_path('/Devices/0/ServiceName',     driver['servicename'])
	dbusservice.add_path('/Devices/0/VregLink',        "(API)")

	# Create the Sumry Inverter paths
	# AC Input measurements
	dbusservice.add_path('/Ac/In/1/L1/V',                     -1)
	dbusservice.add_path('/Ac/In/1/L1/F',                     -1)
	dbusservice.add_path('/Ac/In/1/L1/I',                     -1)
	dbusservice.add_path('/Ac/In/1/L1/P',                     -1)
	# AC Input settings
	dbusservice.add_path('/Ac/In/1/CurrentLimit',             -1)
	#dbusservice.add_path('/Ac/In/1/CurrentLimit GetMin',      -1)
	#dbusservice.add_path('/Ac/In/1/CurrentLimit GetMax',      -1)
	dbusservice.add_path('/Ac/In/1/CurrentLimitIsAdjustable',  0)      # since this is no victron device
	dbusservice.add_path('/Ac/In/1/Type',                     -1)      # AC IN1 type: 0 (Not used), 1 (Grid), 2(Generator), 3(Shore)
	# AC Output measurements
	dbusservice.add_path('/Ac/Out/L1/V',                      -1)
	dbusservice.add_path('/Ac/Out/L1/F',                      -1)
	dbusservice.add_path('/Ac/Out/L1/I',                      -1)
	dbusservice.add_path('/Ac/Out/L1/P',                      -1)
	# ActiveIn paths
	dbusservice.add_path('/Ac/ActiveIn/ActiveInput',          -1)      # Active input: 0 = ACin-1, 1 = ACin-2,
	# Other AC paths:
	dbusservice.add_path('/Ac/NumberOfPhases',                 1)
	dbusservice.add_path('/Ac/NumberOfAcInputs',               1)
	# Generic alarms: (For all alarms: 0=OK; 1=Warning; 2=Alarm)
	dbusservice.add_path('/Alarms/LowSoc',                     -1)      # Low state of charge
	dbusservice.add_path('/Alarms/LowVoltage',                 -1)      # Low battery voltage
	dbusservice.add_path('/Alarms/HighVoltage',                -1)      # High battery voltage
	dbusservice.add_path('/Alarms/LowVoltageAcOut',            -1)      # Low AC Out voltage
	dbusservice.add_path('/Alarms/HighVoltageAcOut',           -1)      # High AC Out voltage
	dbusservice.add_path('/Alarms/HighTemperature',            -1)      # High device temperature
	dbusservice.add_path('/Alarms/Overload',                   -1)      # Inverter overload
	dbusservice.add_path('/Alarms/Ripple',                     -1)      # High DC ripple
	# DC Input measurements
	dbusservice.add_path('/Dc/0/Voltage',                     -1)	
	dbusservice.add_path('/Dc/0/Current',                     -1)
	dbusservice.add_path('/Dc/0/Temperature',                 -1)
	# Operating mode / state
	dbusservice.add_path('/Mode',                             -1)      # Position of the switch  1=Charger Only;2=Inverter Only;3=On;4=Off
	dbusservice.add_path('/State',                            -1)      # Charger state: 0=Off, 2=Fault, 3=Bulk, 4=Absorption, 5=Float, 6=Storage, 7=Equalize, 8=Passthrough, 9=Inverting, 245=Wake-up, 25-=Blocked, 252=External control
	dbusservice.add_path('/Info/UpdateTimestamp',             -1)

	# Create the real values paths
	dbusservice.add_path('/Raw/Ac/In/1/L1/V',                     -1)
	dbusservice.add_path('/Raw/Ac/In/1/L1/F',                     -1)
	dbusservice.add_path('/Raw/Ac/In/1/L1/I',                     -1)
	dbusservice.add_path('/Raw/Ac/In/1/L1/P',                     -1)
	dbusservice.add_path('/Raw/Ac/In/1/CurrentLimit',             -1)
	#dbusservice.add_path('/Raw/Ac/In/1/CurrentLimit GetMin',      -1)
	#dbusservice.add_path('/Raw/Ac/In/1/CurrentLimit GetMax',      -1)
	dbusservice.add_path('/Raw/Ac/In/1/CurrentLimitIsAdjustable',  0)      # since this is no victron device
	dbusservice.add_path('/Raw/Ac/In/1/Type',                     -1)      # AC IN1 type: 0 (Not used), 1 (Grid), 2(Generator), 3(Shore)
	dbusservice.add_path('/Raw/Ac/Out/L1/V',                      -1)
	dbusservice.add_path('/Raw/Ac/Out/L1/F',                      -1)
	dbusservice.add_path('/Raw/Ac/Out/L1/I',                      -1)
	dbusservice.add_path('/Raw/Ac/Out/L1/P',                      -1)
	dbusservice.add_path('/Raw/Ac/ActiveIn/ActiveInput',          -1)      # Active input: 0 = ACin-1, 1 = ACin-2,
	dbusservice.add_path('/Raw/Ac/NumberOfPhases',                 1)
	dbusservice.add_path('/Raw/Ac/NumberOfAcInputs',               1)
	dbusservice.add_path('/Raw/Alarms/LowSoc',                     -1)      # Low state of charge
	dbusservice.add_path('/Raw/Alarms/LowVoltage',                 -1)      # Low battery voltage
	dbusservice.add_path('/Raw/Alarms/HighVoltage',                -1)      # High battery voltage
	dbusservice.add_path('/Raw/Alarms/LowVoltageAcOut',            -1)      # Low AC Out voltage
	dbusservice.add_path('/Raw/Alarms/HighVoltageAcOut',           -1)      # High AC Out voltage
	dbusservice.add_path('/Raw/Alarms/HighTemperature',            -1)      # High device temperature
	dbusservice.add_path('/Raw/Alarms/Overload',                   -1)      # Inverter overload
	dbusservice.add_path('/Raw/Alarms/Ripple',                     -1)      # High DC ripple
	dbusservice.add_path('/Raw/Dc/0/Voltage',                     -1)	
	dbusservice.add_path('/Raw/Dc/0/Current',                     -1)
	dbusservice.add_path('/Raw/Dc/0/Temperature',                 -1)
	dbusservice.add_path('/Raw/Mode',                             -1)      # Position of the switch  1=Charger Only;2=Inverter Only;3=On;4=Off
	dbusservice.add_path('/Raw/State',                            -1)      # Charger state: 0=Off, 2=Fault, 3=Bulk, 4=Absorption, 5=Float, 6=Storage, 7=Equalize, 8=Passthrough, 9=Inverting, 245=Wake-up, 25-=Blocked, 252=External control
	dbusservice.add_path('/Raw/Info/UpdateTimestamp',             -1)


try:

	logging.info("Open serial port " + args.device)
	serial_port = serial.Serial(args.device, 115200, timeout=1)

except Exception as e:
	print(e);
	print(traceback.format_exc())
	
	logging.info("Serial port failed at " + args.device)

	# try /dev/ttyUSB1, if /dev/ttyUSB0 is
	# blocked because of a shutdown
	if (args.device == "/dev/ttyUSB0"):
		try:

			new_device = "/dev/ttyUSB1"
			logging.info("Open serial port " + new_device)
			serial_port = serial.Serial(new_device, 115200, timeout=1)

		except Exception as e:

			print(e);
			print(traceback.format_exc())
	
			logging.info("Serial port failed at " + new_device)

			quit()

		else:
			dbusservice['/Alarms/InternalFailure'] = 1
			
	else:
		quit()


serial_port.flushInput()
logging.info(serial_port.name)
if args.victron:
	dbusservice['/Mgmt/Connection'] = serial_port.name




PACKET_HEADER             = 0x24
#PACKET_STATUS_CELLS       = 0x56
PACKET_STATUS_INV         = 0x57
#PACKET_STATUS_IMPEDANCES  = 0x58

PACKET_LENGTH             = 1 #0
#PACKET_LENGTH_STATUS_CELLS       = [29, 45, 61]
PACKET_LENGTH_STATUS_INV         = [19]

# Special handling here: the impedances packet length is dynamically
# and depends on how many cells are monitored. The minimum length of
# the network packet with headers, command, length, currentmode1, current1
# and checksum is 8 bytes. On 6 monitored cells the packet length will
# be 8+(2*6) = 20 bytes. Therefore, the smallest possible and valid
# impedances network packet will be 10 bytes
#PACKET_LENGTH_STATUS_IMPEDANCES  = 10


#MIN_CELL_VOLTAGE   = 1.0
#MIN_CELL_IMPEDANCE = 0.0

# Again special handling: Negative temperatures will result in
# a buffer overflow we do handle this if temperature values
# are retruned above 65000 which is about - 53,6 degree celsius
#MINUS_TEMPERATURE_OFFSET = 65000

INVERTER_STATUS = {
	'AC_input' : { 
		'voltage_of_AC_In1' : {
			'value' : -1.000,
			'text' : ""
		},
		'frequency_of_AC_In1' : {
			'value' : -1.000,
			'text' : ""
		},
		'current_of_AC_In1' : {
			'value' : -1.000,
			'text' : ""
		},
		'power_of_AC_In1' : {
			'value' : -1.000,
			'text' : ""
		},
		'input_current_limit_of_AC_In1' : {
			'value' : -1.000,
			'text'  : ""
		},
		'minimum_allowed_current_limit' : {
			'value' : -1.000,
			'text' : ""
		},
		'maximum_allowed_current_limit' : {
			'value' : -1.000,
			'text'  : ""
		},
		'current_limit_is_adjustable' : {
			'value' : -1,
			'text'  : ""
		},
		'AC_in_type' : {
			'value' : -1,
			'text'  : ""
		}
	},
	'AC_output' : { 
		'voltage_of_AC_out' : {
			'value' : -1.000,
			'text' : ""
		},
		'frequency_of_AC_out' : {
			'value' : -1.000,
			'text' : ""
		},
		'current_of_AC_out' : {
			'value' : -1.000,
			'text' : ""
		},
		'real_power_of_AC_out' : {
			'value' : -1.000,
			'text' : ""
		}
	},
	'other_AC' : {
		'active_input' : {
			'value' : -1,
			'text'  : ""
		},
		'number_of_phases' : {
			'value' : -1,
			'text'  : ""
		},
		'number_of_AC_inputs' : {
			'value' : -1,
			'text'  : ""
		}
		
	},
	'alarms' : {
		'low_SOC' : {
			'value' : -1,
			'text'  : ""
		},
		'low_battery_voltage' : {
			'value' : -1,
			'text'  : ""
		},
		'high_battery_voltage' : {
			'value' : -1,
			'text'  : ""
		},
		'low_AC_out_voltage' : {
			'value' : -1,
			'text'  : ""
		},
		'high_AC_out_voltage' : {
			'value' : -1,
			'text'  : ""
		},
		'high_device_temperature' : {
			'value' : -1,
			'text'  : ""
		},
		'inverter_overload' : {
			'value' : -1,
			'text'  : ""
		},
		'high_DC_ripple' : {
			'value' : -1,
			'text'  : ""
		}
		
	},
	'DC_input' : {
		'battery_voltage' : {
			'value' : -1,
			'text'  : ""
		},
		'battery_current' : {
			'value' : -1,
			'text'  : ""
		},
		'battery_temperature' : {
			'value' : -1,
			'text'  : ""
		}
		
	},
	'inverter_mode' : {
		'switch_position' : {
			'value' : -1,
			'text'  : ""
		},
		'charger_state' : {
			'value' : -1,
			'text'  : ""
		},
		'timestamp' : {
			'value' : -1,
			'text'  : ""
		}
	}
}


def reset_ACinput_values():

	INVERTER_STATUS['AC_input']['voltage_of_AC_In1']['value'] = -1
	INVERTER_STATUS['AC_input']['voltage_of_AC_In1']['text']  = ""
	INVERTER_STATUS['AC_input']['frequency_of_AC_In1']['value'] = -1
	INVERTER_STATUS['AC_input']['frequency_of_AC_In1']['text']  = ""
	INVERTER_STATUS['AC_input']['current_of_AC_In1']['value'] = -1
	INVERTER_STATUS['AC_input']['current_of_AC_In1']['text']  = ""
	INVERTER_STATUS['AC_input']['power_of_AC_In1']['value'] = -1
	INVERTER_STATUS['AC_input']['power_of_AC_In1']['text']  = ""
	INVERTER_STATUS['AC_input']['input_current_limit_of_AC_In1']['value'] = -1
	INVERTER_STATUS['AC_input']['input_current_limit_of_AC_In1']['text']  = ""
	INVERTER_STATUS['AC_input']['minimum_allowed_current_limit']['value'] = -1
	INVERTER_STATUS['AC_input']['minimum_allowed_current_limit']['text']  = ""
	INVERTER_STATUS['AC_input']['maximum_allowed_current_limit']['value'] = -1
	INVERTER_STATUS['AC_input']['maximum_allowed_current_limit']['text']  = ""
	INVERTER_STATUS['AC_input']['current_limit_is_adjustable']['value'] = -1
	INVERTER_STATUS['AC_input']['current_limit_is_adjustable']['text']  = ""
	INVERTER_STATUS['AC_input']['AC_in_type']['value'] = -1
	INVERTER_STATUS['AC_input']['AC_in_type']['text']  = ""

def reset_ACoutput_values():

	INVERTER_STATUS['AC_output']['voltage_of_AC_out']['value'] = -1
	INVERTER_STATUS['AC_output']['voltage_of_AC_out']['text']  = ""
	INVERTER_STATUS['AC_output']['frequency_of_AC_out']['value'] = -1
	INVERTER_STATUS['AC_output']['frequency_of_AC_out']['text']  = ""
	INVERTER_STATUS['AC_output']['current_of_AC_out']['value'] = -1
	INVERTER_STATUS['AC_output']['current_of_AC_out']['text']  = ""
	INVERTER_STATUS['AC_output']['real_power_of_AC_out']['value'] = -1
	INVERTER_STATUS['AC_output']['real_power_of_AC_out']['text']  = ""

def reset_otherAC_values():

	INVERTER_STATUS['other_AC']['active_input']['value'] = -1
	INVERTER_STATUS['other_AC']['active_input']['text']  = ""
	INVERTER_STATUS['other_AC']['number_of_phases']['value'] = -1
	INVERTER_STATUS['other_AC']['number_of_phases']['text']  = ""
	INVERTER_STATUS['other_AC']['number_of_AC_inputs']['value'] = -1
	INVERTER_STATUS['other_AC']['number_of_AC_inputs']['text']  = ""

def reset_alarms_values():
	
	INVERTER_STATUS['alarms']['low_SOC']['value'] = -1
	INVERTER_STATUS['alarms']['low_SOC']['text']  = ""
	INVERTER_STATUS['alarms']['low_battery_voltage']['value'] = -1
	INVERTER_STATUS['alarms']['low_battery_voltage']['text']  = ""
	INVERTER_STATUS['alarms']['high_battery_voltage']['value'] = -1
	INVERTER_STATUS['alarms']['high_battery_voltage']['text']  = ""
	INVERTER_STATUS['alarms']['low_AC_out_voltage']['value'] = -1
	INVERTER_STATUS['alarms']['low_AC_out_voltage']['text']  = ""
	INVERTER_STATUS['alarms']['high_AC_out_voltage']['value'] = -1
	INVERTER_STATUS['alarms']['high_AC_out_voltage']['text']  = ""
	INVERTER_STATUS['alarms']['high_device_temperature']['value'] = -1
	INVERTER_STATUS['alarms']['high_device_temperature']['text']  = ""
	INVERTER_STATUS['alarms']['inverter_overload']['value'] = -1
	INVERTER_STATUS['alarms']['inverter_overload']['text']  = ""
	INVERTER_STATUS['alarms']['high_DC_ripple']['value'] = -1
	INVERTER_STATUS['alarms']['high_DC_ripple']['text']  = ""

def reset_ACinput_values():
	
	INVERTER_STATUS['DC_input']['battery_voltage']['value'] = -1
	INVERTER_STATUS['DC_input']['battery_voltage']['text']  = ""
	INVERTER_STATUS['DC_input']['battery_current']['value'] = -1
	INVERTER_STATUS['DC_input']['battery_current']['text']  = ""
	INVERTER_STATUS['DC_input']['battery_temperature']['value'] = -1
	INVERTER_STATUS['DC_input']['battery_temperature']['text']  = ""

def reset_mode_values():

	INVERTER_STATUS['inverter_mode']['switch_position']['value'] = -1
	INVERTER_STATUS['inverter_mode']['switch_position']['text']  = ""
	INVERTER_STATUS['inverter_mode']['charger_state']['value'] = -1
	INVERTER_STATUS['inverter_mode']['charger_state']['text']  = ""
	INVERTER_STATUS['inverter_mode']['timestamp']['value'] = -1
	INVERTER_STATUS['inverter_mode']['timestamp']['text']  = ""

def debug_packet(packet):

	string_output = ""
	for packet_byte in packet:
		byte_string = str(packet_byte) + " [" + hex(packet_byte) + "] "
		string_output = string_output + byte_string
	logging.debug(string_output);


def get_header_position(packet):

	# detect header position
	previous_packet_byte = "0"
	pos_iterator = -1
	for packet_byte in packet:
		pos_iterator += 1
		if ((previous_packet_byte == PACKET_HEADER) and (packet_byte == PACKET_HEADER)):
			break
		previous_packet_byte = packet_byte

	return pos_iterator


def get_voltage_value(byte1, byte2):
	return float((float(byte1 * 256) + float(byte2)) / 1000)

def get_frequency_value(byte1, byte2):
	return float((float(byte1) + float(byte2 * 256)) / 100)

def get_current_value(byte1, byte2):
	return float((float(byte1 * 256) + float(byte2)) / 100)


def get_current1_value(byte1, byte2):
	return float((float(byte1) + float(byte2 * 256)) / 100)

def get_power_value(byte1, byte2):
	return float((float(byte1) + float(byte2 * 256)) / 100)

def get_temperature_value(byte1, byte2):
	if (((byte1 * 256) + byte2) >= 0): # temperature below 0 degree celsius
		return (-1) * float(((256 * 256) - (float(byte1 * 256) + float(byte2))) / 10)
	else:
		return float((float(byte1 * 256) + float(byte2)) / 10)
	
#def get_battery_capacity(byte1, byte2, byte3, byte4):
#	return float((float(byte1) + float(byte2 * 256) + float(byte3 * 256 * 256) + float(byte4 * 256 * 256 * 256)) / 1000)


#def get_cell_impedance(byte1, byte2):
#	return float((float(byte1) + float(byte2 * 256)) / 10)



def parse_packet(packet):
	logging.debug("Parse Packet [" + str(len(packet)) + "] bytes")
	debug_packet(packet)

	while (len(packet) >= PACKET_LENGTH): 
		header_position = get_header_position(packet)

		# now parse the packet	
		if ((header_position == -1) or (header_position == len(packet) - 1)):
			logging.debug("Packet Invalid")
			packet = ""
		else:
			# strip packet
			packet = packet[(header_position - 1):]
			
			if (len(packet) >= 4): 
				if ((packet[0] == PACKET_HEADER) and (packet[1] == PACKET_HEADER)):
					packet_length = packet[3]
					logging.debug("Packet Length [" + str (packet_length) + " bytes]")
					debug_packet(packet)
		
					if (packet[2] == PACKET_STATUS_INV):
					
						if (len(packet) < PACKET_LENGTH_STATUS_INV[0]):
							logging.debug("Packet Status BMS too short, skip")
							packet = ""
						else:
							# delete old data
							reset_status_values()

							# checksum value
							checksum = packet[packet_length-1]
							checksum_check = 0

							# calculate checksum
							for i in range(packet_length-1):
								checksum_check = checksum_check + packet[i]
							checksum_check = checksum_check % 256
							logging.debug("Packet Checksum : " + str(checksum) + "|" + str(checksum_check))
							
							# data integrity does match
							if (checksum == checksum_check):

								# AC charging voltage
								INVERTER_STATUS['AC_input']['voltage_of_AC_In1']['value'] = get_voltage_value(packet[4], packet[5])
								INVERTER_STATUS['AC_input']['voltage_of_AC_In1']['text'] = "{:.2f}".format(INVERTER_STATUS['AC_input']['voltage_of_AC_In1']['value']) + "V"
								if args.victron:
									dbusservice["/Ac/In/1/L1/V"] = INVERTER_STATUS['AC_input']['voltage_of_AC_In1']['text']
									dbusservice["/Raw/Ac/In/1/L1/V"] = INVERTER_STATUS['AC_input']['voltage_of_AC_In1']['value']

								# AC charging frequency
								INVERTER_STATUS['AC_input']['frequency_of_AC_In1']['value'] = get_frequency_value(packet[6], packet[7])
								INVERTER_STATUS['AC_input']['frequency_of_AC_In1']['text'] = "{:.2f}".format(INVERTER_STATUS['AC_input']['frequency_of_AC_In1']['value']) + "Hz"
								if args.victron:
									dbusservice["/Ac/In/1/L1/F"] = INVERTER_STATUS['AC_input']['frequency_of_AC_In1']['text']
									dbusservice["/Raw/Ac/In/1/L1/F"] = INVERTER_STATUS['AC_input']['frequency_of_AC_In1']['value']

								# AC charging current
								INVERTER_STATUS['AC_input']['current_of_AC_In1']['value'] = get_current_value(packet[8], packet[9])
								INVERTER_STATUS['AC_input']['current_of_AC_In1']['text'] = "{:.2f}".format(INVERTER_STATUS['AC_input']['current_of_AC_In1']['value']) + "A"
								if args.victron:
									dbusservice["/Ac/In/1/L1/I"] = INVERTER_STATUS['AC_input']['current_of_AC_In1']['text']
									dbusservice["/Raw/Ac/In/1/L1/I"] = INVERTER_STATUS['AC_input']['current_of_AC_In1']['value']

								# AC charging power
								INVERTER_STATUS['AC_input']['power_of_AC_In1']['value'] = get_power_value(packet[10], packet[11])
								INVERTER_STATUS['AC_input']['power_of_AC_In1']['text'] = "{:.2f}".format(INVERTER_STATUS['AC_input']['power_of_AC_In1']['value']) + "W"
								if args.victron:
									dbusservice["/Ac/In/1/L1/P"] = INVERTER_STATUS['AC_input']['power_of_AC_In1']['text']
									dbusservice["/Raw/Ac/In/1/L1/P"] = INVERTER_STATUS['AC_input']['power_of_AC_In1']['value']

								# actual current
								#BMS_STATUS['bms']['current']['value'] = get_current_value(packet[7], packet[8])

								# charge mode
								#bms_current_mode = packet[6]
								#if (bms_current_mode == 0x00):
								#	BMS_STATUS['bms']['current_mode']['value'] = 0
								#	BMS_STATUS['bms']['current_mode']['text']  = "Discharge"
								#	BMS_STATUS['bms']['current']['text'] = "-" + str(BMS_STATUS['bms']['current']['value']) + "A"
								#	BMS_STATUS['bms']['current']['value'] = -1 * BMS_STATUS['bms']['current']['value']
								#elif (bms_current_mode == 0x01):
								#	BMS_STATUS['bms']['current_mode']['value'] = 1
								#	BMS_STATUS['bms']['current_mode']['text']  = "Charge"
								#	BMS_STATUS['bms']['current']['text'] = str(BMS_STATUS['bms']['current']['value']) + "A"
								#elif (bms_current_mode == 0x02):
								#	BMS_STATUS['bms']['current_mode']['value'] = 2
								#	BMS_STATUS['bms']['current_mode']['text']  = "Storage"
								#	BMS_STATUS['bms']['current']['text'] = str(BMS_STATUS['bms']['current']['value']) + "A"
								#else:
								#	BMS_STATUS['bms']['current_mode']['value'] = -1
								#	BMS_STATUS['bms']['current_mode']['text']  = ""
								#	BMS_STATUS['bms']['current']['text'] = ""
								
								#if args.victron:
								#	dbusservice["/Info/CurrentMode"] = BMS_STATUS['bms']['current_mode']['text']
								#	dbusservice["/Info/Current"]     = BMS_STATUS['bms']['current']['text']
								#	dbusservice["/Raw/Info/CurrentMode"] = BMS_STATUS['bms']['current_mode']['value']
								#	dbusservice["/Raw/Info/Current"]     = BMS_STATUS['bms']['current']['value']

								# current temperatures
								#BMS_STATUS['bms']['temperature']['sensor_t1']['value'] = get_temperature_value(packet[9], packet[10])
								#BMS_STATUS['bms']['temperature']['sensor_t1']['text'] = str(BMS_STATUS['bms']['temperature']['sensor_t1']['value']) + "C"
								#BMS_STATUS['bms']['temperature']['sensor_t2']['value'] = get_temperature_value(packet[11], packet[12])
								#BMS_STATUS['bms']['temperature']['sensor_t2']['text'] = str(BMS_STATUS['bms']['temperature']['sensor_t2']['value']) + "C"

								#if args.victron:
								#	dbusservice["/Info/Temp/Sensor1"] = BMS_STATUS['bms']['temperature']['sensor_t1']['text']
								#	dbusservice["/Info/Temp/Sensor2"] = BMS_STATUS['bms']['temperature']['sensor_t2']['text']
								#	dbusservice["/Raw/Info/Temp/Sensor1"] = BMS_STATUS['bms']['temperature']['sensor_t1']['value']
								#	dbusservice["/Raw/Info/Temp/Sensor2"] = BMS_STATUS['bms']['temperature']['sensor_t2']['value']

								# soc value
								#BMS_STATUS['bms']['soc']['value'] = packet[13]
								#BMS_STATUS['bms']['soc']['text'] = str(packet[13]) + "%"
								#if args.victron:
								#	dbusservice["/Info/Soc"] = BMS_STATUS['bms']['soc']['text']
								#	dbusservice["/Raw/Info/Soc"] = BMS_STATUS['bms']['soc']['value']

								# discharge end voltage
								#BMS_STATUS['bms']['discharged_end_voltage']['value'] = get_voltage_value(packet[14], packet[15])
								#BMS_STATUS['bms']['discharged_end_voltage']['text'] = "{:.2f}".format(BMS_STATUS['bms']['discharged_end_voltage']['value']) + "V"
								#if args.victron:
								#	dbusservice["/Info/DischargeEndVoltage"] = BMS_STATUS['bms']['discharged_end_voltage']['text']
								#	dbusservice["/Raw/Info/DischargeEndVoltage"] = BMS_STATUS['bms']['discharged_end_voltage']['value']

								# charge relay status
								#bms_charge_relay_status = packet[16]
								#if (bms_charge_relay_status == 0x00):
								#	BMS_STATUS['bms']['charge_relay_status']['value'] = 0
								#	BMS_STATUS['bms']['charge_relay_status']['text']  = "On"
								#elif (bms_charge_relay_status == 0x01):
								#	BMS_STATUS['bms']['charge_relay_status']['value'] = 1
								#	BMS_STATUS['bms']['charge_relay_status']['text']  = "Off"
								#else:
								#	BMS_STATUS['bms']['charge_relay_status']['value'] = -1
								#	BMS_STATUS['bms']['charge_relay_status']['text']  = ""

								#if args.victron:
								#	dbusservice["/Info/ChargeRelayStatus"] = BMS_STATUS['bms']['charge_relay_status']['text']
								#	dbusservice["/Raw/Info/ChargeRelayStatus"] = BMS_STATUS['bms']['charge_relay_status']['value']


								# discharge relay status
								#bms_discharge_relay_status = packet[17]
								#if (bms_discharge_relay_status == 0x00):
								#	BMS_STATUS['bms']['discharge_relay_status']['value'] = 0
								#	BMS_STATUS['bms']['discharge_relay_status']['text']  = "On"
								#elif (bms_discharge_relay_status == 0x01):
								#	BMS_STATUS['bms']['discharge_relay_status']['value'] = 1
								#	BMS_STATUS['bms']['discharge_relay_status']['text']  = "Off"
								#else:
								#	BMS_STATUS['bms']['discharge_relay_status']['value'] = -1
								#	BMS_STATUS['bms']['discharge_relay_status']['text']  = ""

								#if args.victron:
								#	dbusservice["/Info/DischargeRelayStatus"] = BMS_STATUS['bms']['discharge_relay_status']['text']
								#	dbusservice["/Raw/Info/DischargeRelayStatus"] = BMS_STATUS['bms']['discharge_relay_status']['value']

								
								# update timestamp
								current_date = datetime.datetime.now()
								INVERTER_STATUS['inverter_mode']['timestamp']['value'] = time.time()
								INVERTER_STATUS['inverter_mode']['timestamp']['text']  = current_date.strftime('%a %d.%m.%Y %H:%M:%S')
								if args.victron:
									dbusservice["/Info/UpdateTimestamp"] = INVERTER_STATUS['inverter_mode']['timestamp']['text']
									dbusservice["/Raw/Info/UpdateTimestamp"] = INVERTER_STATUS['inverter_mode']['timestamp']['value']

								# print (INVERTER_STATUS)
								logging.info("Inverter Status [AC_voltage_in|" + INVERTER_STATUS['AC_input']['voltage_of_AC_In1']['text'] +
									"][AC_frequency_in|" + INVERTER_STATUS['AC_input']['frequency_of_AC_In1']['text'] + 
									"][AC_current_in|" + INVERTER_STATUS['AC_input']['current_of_AC_In1']['text'] + 
									"][AC_power_in|" + INVERTER_STATUS['AC_input']['power_of_AC_In1']['text'] + "]") 

							else:
								logging.info("Packet Checksum wrong, skip packet")

							# strip packet
							packet = packet[packet_length:]
			
					#elif (packet[2] == PACKET_STATUS_CELLS):

						#if (len(packet) < PACKET_LENGTH_STATUS_CELLS[0]):
						#	logging.debug("Packet Status Cells too short, skip")
						#	packet = ""
						#else:
							# delete old data
						#	reset_voltages_values()

							# checksum value
						#	checksum = -1
						#	checksum_check = 0

						#	if (packet_length == PACKET_LENGTH_STATUS_CELLS[0]): # packet from BMS8
						#		logging.debug("Packet Status Cells BMS8")

						#		if (len(packet) < PACKET_LENGTH_STATUS_CELLS[0]):
						#			logging.debug("Packet Status Cells too short, skip")
						#			packet = ""
						#		else:
						#			checksum = packet[packet_length-1]

									# calculate checksum
						#			for i in range(packet_length-1):
						#				checksum_check = checksum_check + packet[i]
						#			checksum_check = checksum_check % 256
						#			logging.debug("Packet Checksum BMS8: " + str(checksum) + "|" + str(checksum_check))

						#	elif (packet_length == PACKET_LENGTH_STATUS_CELLS[1]): # packet from BMS16
						#		logging.debug("Packet Status Cells BMS16")

						#		if (len(packet) < PACKET_LENGTH_STATUS_CELLS[1]):
						#			logging.debug("Packet Status Cells too short, skip")
						#			packet = ""
						#		else:
						#			checksum = packet[packet_length-1]

									# calculate checksum
						#			for i in range(packet_length-1):
						#				checksum_check = checksum_check + packet[i]
						#			checksum_check = checksum_check % 256
						#			logging.debug("Packet Checksum BMS16: " + str(checksum) + "|" + str(checksum_check))
							
						#	elif (packet_length == PACKET_LENGTH_STATUS_CELLS[2]): # packet from BMS24 
						#		logging.debug("Packet Status Cells BMS24")

						#		if (len(packet) < PACKET_LENGTH_STATUS_CELLS[2]):
						#			logging.debug("Packet Status Cells too short, skip")
						#			packet = ""
						#		else:
						#			checksum = packet[packet_length-1]

									# calculate checksum
						#			for i in range(packet_length-1):
						#				checksum_check = checksum_check + packet[i]
						#			checksum_check = checksum_check % 256
						#			logging.debug("Packet Checksum BMS24: " + str(checksum) + "|" + str(checksum_check))


							# data integrity does match
						#	if (checksum == checksum_check):

								# cell voltages BMS8/BMS16/BMS24
						#		BMS_STATUS['voltages']['cell1_voltage']['value'] = get_voltage_value(packet[4], packet[5])
						#		BMS_STATUS['voltages']['cell1_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell1_voltage']['value']) + "V"
						#		if args.victron:
						#			dbusservice["/Voltages/Cell1"] = BMS_STATUS['voltages']['cell1_voltage']['text']
						#			dbusservice["/Raw/Voltages/Cell1"] = BMS_STATUS['voltages']['cell1_voltage']['value']

						#		BMS_STATUS['voltages']['cell2_voltage']['value'] = get_voltage_value(packet[6], packet[7])
						#		BMS_STATUS['voltages']['cell2_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell2_voltage']['value']) + "V"
						#		if args.victron:
						#			dbusservice["/Voltages/Cell2"] = BMS_STATUS['voltages']['cell2_voltage']['text']
						#			dbusservice["/Raw/Voltages/Cell2"] = BMS_STATUS['voltages']['cell2_voltage']['value']

						#		BMS_STATUS['voltages']['cell3_voltage']['value'] = get_voltage_value(packet[8], packet[9])
						#		BMS_STATUS['voltages']['cell3_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell3_voltage']['value']) + "V"
						#		if args.victron:
						#			dbusservice["/Voltages/Cell3"] = BMS_STATUS['voltages']['cell3_voltage']['text']
						#			dbusservice["/Raw/Voltages/Cell3"] = BMS_STATUS['voltages']['cell3_voltage']['value']

						#		BMS_STATUS['voltages']['cell4_voltage']['value'] = get_voltage_value(packet[10], packet[11])
						#		BMS_STATUS['voltages']['cell4_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell4_voltage']['value']) + "V"
						#		if args.victron:
						#			dbusservice["/Voltages/Cell4"] = BMS_STATUS['voltages']['cell4_voltage']['text']
						#			dbusservice["/Raw/Voltages/Cell4"] = BMS_STATUS['voltages']['cell4_voltage']['value']

						#		BMS_STATUS['voltages']['cell5_voltage']['value'] = get_voltage_value(packet[12], packet[13])
						#		BMS_STATUS['voltages']['cell5_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell5_voltage']['value']) + "V"
						#		if args.victron:
						#			dbusservice["/Voltages/Cell5"] = BMS_STATUS['voltages']['cell5_voltage']['text']
						#			dbusservice["/Raw/Voltages/Cell5"] = BMS_STATUS['voltages']['cell5_voltage']['value']

						#		BMS_STATUS['voltages']['cell6_voltage']['value'] = get_voltage_value(packet[14], packet[15])
						#		BMS_STATUS['voltages']['cell6_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell6_voltage']['value']) + "V"
						#		if args.victron:
						#			dbusservice["/Voltages/Cell6"] = BMS_STATUS['voltages']['cell6_voltage']['text']
						#			dbusservice["/Raw/Voltages/Cell6"] = BMS_STATUS['voltages']['cell6_voltage']['value']

						#		BMS_STATUS['voltages']['cell7_voltage']['value'] = get_voltage_value(packet[16], packet[17])
						#		BMS_STATUS['voltages']['cell7_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell7_voltage']['value']) + "V"
						#		if args.victron:
						#			dbusservice["/Voltages/Cell7"] = BMS_STATUS['voltages']['cell7_voltage']['text']
						#			dbusservice["/Raw/Voltages/Cell7"] = BMS_STATUS['voltages']['cell7_voltage']['value']

						#		BMS_STATUS['voltages']['cell8_voltage']['value'] = get_voltage_value(packet[18], packet[19])
						#		BMS_STATUS['voltages']['cell8_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell8_voltage']['value']) + "V"
						#		if args.victron:
						#			dbusservice["/Voltages/Cell8"] = BMS_STATUS['voltages']['cell8_voltage']['text']
						#			dbusservice["/Raw/Voltages/Cell8"] = BMS_STATUS['voltages']['cell8_voltage']['value']

						#		if ((packet_length == PACKET_LENGTH_STATUS_CELLS[1]) or (packet_length == PACKET_LENGTH_STATUS_CELLS[2])): # packet from BMS16/BMS24

						#			BMS_STATUS['voltages']['cell9_voltage']['value'] = get_voltage_value(packet[20], packet[21])
						#			BMS_STATUS['voltages']['cell9_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell9_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell9"] = BMS_STATUS['voltages']['cell9_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell9"] = BMS_STATUS['voltages']['cell9_voltage']['value']

						#			BMS_STATUS['voltages']['cell10_voltage']['value'] = get_voltage_value(packet[22], packet[23])
						#			BMS_STATUS['voltages']['cell10_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell10_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell10"] = BMS_STATUS['voltages']['cell10_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell10"] = BMS_STATUS['voltages']['cell10_voltage']['value']

						#			BMS_STATUS['voltages']['cell11_voltage']['value'] = get_voltage_value(packet[24], packet[25])
						#			BMS_STATUS['voltages']['cell11_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell11_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell11"] = BMS_STATUS['voltages']['cell11_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell11"] = BMS_STATUS['voltages']['cell11_voltage']['value']

						#			BMS_STATUS['voltages']['cell12_voltage']['value'] = get_voltage_value(packet[26], packet[27])
						#			BMS_STATUS['voltages']['cell12_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell12_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell12"] = BMS_STATUS['voltages']['cell12_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell12"] = BMS_STATUS['voltages']['cell12_voltage']['value']

						#			BMS_STATUS['voltages']['cell13_voltage']['value'] = get_voltage_value(packet[28], packet[29])
						#			BMS_STATUS['voltages']['cell13_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell13_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell13"] = BMS_STATUS['voltages']['cell13_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell13"] = BMS_STATUS['voltages']['cell13_voltage']['value']

						#			BMS_STATUS['voltages']['cell14_voltage']['value'] = get_voltage_value(packet[30], packet[31])
						#			BMS_STATUS['voltages']['cell14_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell14_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell14"] = BMS_STATUS['voltages']['cell14_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell14"] = BMS_STATUS['voltages']['cell14_voltage']['value']

						#			BMS_STATUS['voltages']['cell15_voltage']['value'] = get_voltage_value(packet[32], packet[33])
						#			BMS_STATUS['voltages']['cell15_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell15_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell15"] = BMS_STATUS['voltages']['cell15_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell15"] = BMS_STATUS['voltages']['cell15_voltage']['value']

						#			BMS_STATUS['voltages']['cell16_voltage']['value'] = get_voltage_value(packet[34], packet[35])
						#			BMS_STATUS['voltages']['cell16_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell16_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell16"] = BMS_STATUS['voltages']['cell16_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell16"] = BMS_STATUS['voltages']['cell16_voltage']['value']


						#		if (packet_length == PACKET_LENGTH_STATUS_CELLS[2]): # packet from BMS24

						#			BMS_STATUS['voltages']['cell17_voltage']['value'] = get_voltage_value(packet[36], packet[37])
						#			BMS_STATUS['voltages']['cell17_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell17_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell17"] = BMS_STATUS['voltages']['cell17_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell17"] = BMS_STATUS['voltages']['cell17_voltage']['value']

						#			BMS_STATUS['voltages']['cell18_voltage']['value'] = get_voltage_value(packet[38], packet[39])
						#			BMS_STATUS['voltages']['cell18_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell18_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell18"] = BMS_STATUS['voltages']['cell18_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell18"] = BMS_STATUS['voltages']['cell18_voltage']['value']

						#			BMS_STATUS['voltages']['cell19_voltage']['value'] = get_voltage_value(packet[40], packet[41])
						#			BMS_STATUS['voltages']['cell19_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell19_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell19"] = BMS_STATUS['voltages']['cell19_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell19"] = BMS_STATUS['voltages']['cell19_voltage']['value']

						#			BMS_STATUS['voltages']['cell20_voltage']['value'] = get_voltage_value(packet[42], packet[43])
						#			BMS_STATUS['voltages']['cell20_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell20_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell20"] = BMS_STATUS['voltages']['cell20_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell20"] = BMS_STATUS['voltages']['cell20_voltage']['value']

						#			BMS_STATUS['voltages']['cell21_voltage']['value'] = get_voltage_value(packet[44], packet[45])
						#			BMS_STATUS['voltages']['cell21_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell21_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell21"] = BMS_STATUS['voltages']['cell21_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell21"] = BMS_STATUS['voltages']['cell21_voltage']['value']

						#			BMS_STATUS['voltages']['cell22_voltage']['value'] = get_voltage_value(packet[46], packet[47])
						#			BMS_STATUS['voltages']['cell22_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell22_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell22"] = BMS_STATUS['voltages']['cell22_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell22"] = BMS_STATUS['voltages']['cell22_voltage']['value']

						#			BMS_STATUS['voltages']['cell23_voltage']['value'] = get_voltage_value(packet[48], packet[49])
						#			BMS_STATUS['voltages']['cell23_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell23_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell23"] = BMS_STATUS['voltages']['cell23_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell23"] = BMS_STATUS['voltages']['cell23_voltage']['value']

						#			BMS_STATUS['voltages']['cell24_voltage']['value'] = get_voltage_value(packet[50], packet[51])
						#			BMS_STATUS['voltages']['cell24_voltage']['text'] = "{:.3f}".format(BMS_STATUS['voltages']['cell24_voltage']['value']) + "V"
						#			if args.victron:
						#				dbusservice["/Voltages/Cell24"] = BMS_STATUS['voltages']['cell24_voltage']['text']
						#				dbusservice["/Raw/Voltages/Cell24"] = BMS_STATUS['voltages']['cell24_voltage']['value']
								
									

								# get min/max voltages to calculate the diff
						#		cell_voltages = []

						#		if (BMS_STATUS['voltages']['cell1_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell1_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell2_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell2_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell3_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell3_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell4_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell4_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell5_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell5_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell6_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell6_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell7_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell7_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell8_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell8_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell9_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell9_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell10_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell10_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell11_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell11_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell12_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell12_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell13_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell13_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell14_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell14_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell15_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell15_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell16_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell16_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell17_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell17_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell18_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell18_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell19_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell19_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell20_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell20_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell21_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell21_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell22_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell22_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell23_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell23_voltage']['value'])
						#		if (BMS_STATUS['voltages']['cell24_voltage']['value'] >= MIN_CELL_VOLTAGE):
						#			cell_voltages.append(BMS_STATUS['voltages']['cell24_voltage']['value'])
									
						#		BMS_STATUS['voltages']['agg_voltages']['sum']['value']      = sum(cell_voltages)
						#		BMS_STATUS['voltages']['agg_voltages']['sum']['text']       = "{:.2f}".format(BMS_STATUS['voltages']['agg_voltages']['sum']['value']) + "V" 
						#		BMS_STATUS['voltages']['agg_voltages']['max']['value']      = max(cell_voltages)
						#		BMS_STATUS['voltages']['agg_voltages']['max']['text']       = "{:.3f}".format(BMS_STATUS['voltages']['agg_voltages']['max']['value']) + "V" 
						#		BMS_STATUS['voltages']['agg_voltages']['min']['value']      = min(cell_voltages)
						#		BMS_STATUS['voltages']['agg_voltages']['min']['text']       = "{:.3f}".format(BMS_STATUS['voltages']['agg_voltages']['min']['value']) + "V" 
						#		BMS_STATUS['voltages']['agg_voltages']['diff']['value']     = BMS_STATUS['voltages']['agg_voltages']['max']['value'] - BMS_STATUS['voltages']['agg_voltages']['min']['value']
						#		BMS_STATUS['voltages']['agg_voltages']['diff']['text']      = "{:.0f}".format(BMS_STATUS['voltages']['agg_voltages']['diff']['value'] * 1000) + "mV"
						#		BMS_STATUS['voltages']['agg_voltages']['average']['value']  = float("{:.3f}".format(sum(cell_voltages)/len(cell_voltages)))
						#		BMS_STATUS['voltages']['agg_voltages']['average']['text']   = "{:.3f}".format(BMS_STATUS['voltages']['agg_voltages']['average']['value']) + "V" 

						#		if args.victron:
						#			dbusservice["/Voltages/Sum"]      = BMS_STATUS['voltages']['agg_voltages']['sum']['text']
						#			dbusservice["/Raw/Voltages/Sum"]  = BMS_STATUS['voltages']['agg_voltages']['sum']['value']
						#			dbusservice["/Voltages/Max"]      = BMS_STATUS['voltages']['agg_voltages']['max']['text']
						#			dbusservice["/Raw/Voltages/Max"]  = BMS_STATUS['voltages']['agg_voltages']['max']['value']
						#			dbusservice["/Voltages/Min"]      = BMS_STATUS['voltages']['agg_voltages']['min']['text']
						#			dbusservice["/Raw/Voltages/Min"]  = BMS_STATUS['voltages']['agg_voltages']['min']['value']
						#			dbusservice["/Voltages/Diff"]     = BMS_STATUS['voltages']['agg_voltages']['diff']['text']
						#			dbusservice["/Raw/Voltages/Diff"] = BMS_STATUS['voltages']['agg_voltages']['diff']['value']
						#			dbusservice["/Voltages/Avg"]      = BMS_STATUS['voltages']['agg_voltages']['average']['text']
						#			dbusservice["/Raw/Voltages/Avg"]  = BMS_STATUS['voltages']['agg_voltages']['average']['value']


						#		if (packet_length == PACKET_LENGTH_STATUS_CELLS[0]): # packet from BMS8

									# get battery capacity
						#			BMS_STATUS['voltages']['battery_capacity_wh']['value'] = get_battery_capacity(packet[20], packet[21], packet[22], packet[23])
						#			BMS_STATUS['voltages']['battery_capacity_wh']['text'] = "{:.0f}".format(BMS_STATUS['voltages']['battery_capacity_wh']['value']) + "Wh"
						#			if args.victron:
						#				dbusservice["/Voltages/BatteryCapacityWH"] = BMS_STATUS['voltages']['battery_capacity_wh']['text']
						#				dbusservice["/Raw/Voltages/BatteryCapacityWH"] = BMS_STATUS['voltages']['battery_capacity_wh']['value']

						#			BMS_STATUS['voltages']['battery_capacity_ah']['value'] = get_battery_capacity(packet[24], packet[25], packet[26], packet[27])
						#			BMS_STATUS['voltages']['battery_capacity_ah']['text'] = "{:.0f}".format(BMS_STATUS['voltages']['battery_capacity_ah']['value']) + "Ah"
						#			if args.victron:
						#				dbusservice["/Voltages/BatteryCapacityAH"] = BMS_STATUS['voltages']['battery_capacity_ah']['text']
						#				dbusservice["/Raw/Voltages/BatteryCapacityAH"] = BMS_STATUS['voltages']['battery_capacity_ah']['value']


						#		elif (packet_length == PACKET_LENGTH_STATUS_CELLS[1]): # packet from BMS16

									# get battery capacity
						#			BMS_STATUS['voltages']['battery_capacity_wh']['value'] = get_battery_capacity(packet[36], packet[37], packet[38], packet[39])
						#			BMS_STATUS['voltages']['battery_capacity_wh']['text'] = "{:.0f}".format(BMS_STATUS['voltages']['battery_capacity_wh']['value']) + "Wh"
						#			if args.victron:
						#				dbusservice["/Voltages/BatteryCapacityWH"] = BMS_STATUS['voltages']['battery_capacity_wh']['text']
						#				dbusservice["/Raw/Voltages/BatteryCapacityWH"] = BMS_STATUS['voltages']['battery_capacity_wh']['value']

						#			BMS_STATUS['voltages']['battery_capacity_ah']['value'] = get_battery_capacity(packet[40], packet[41], packet[42], packet[43])
						#			BMS_STATUS['voltages']['battery_capacity_ah']['text'] = "{:.0f}".format(BMS_STATUS['voltages']['battery_capacity_ah']['value']) + "Ah"
						#			if args.victron:
						#				dbusservice["/Voltages/BatteryCapacityAH"] = BMS_STATUS['voltages']['battery_capacity_ah']['text']
						#				dbusservice["/Raw/Voltages/BatteryCapacityAH"] = BMS_STATUS['voltages']['battery_capacity_ah']['value']


						#		elif (packet_length == PACKET_LENGTH_STATUS_CELLS[2]): # packet from BMS24

									# get battery capacity
						#			BMS_STATUS['voltages']['battery_capacity_wh']['value'] = get_battery_capacity(packet[52], packet[53], packet[54], packet[55])
						#			BMS_STATUS['voltages']['battery_capacity_wh']['text'] = "{:.0f}".format(BMS_STATUS['voltages']['battery_capacity_wh']['value']) + "Wh"
						#			if args.victron:									
						#				dbusservice["/Voltages/BatteryCapacityWH"] = BMS_STATUS['voltages']['battery_capacity_wh']['text']
						#				dbusservice["/Raw/Voltages/BatteryCapacityWH"] = BMS_STATUS['voltages']['battery_capacity_wh']['value']

						#			BMS_STATUS['voltages']['battery_capacity_ah']['value'] = get_battery_capacity(packet[56], packet[57], packet[58], packet[59])
						#			BMS_STATUS['voltages']['battery_capacity_ah']['text'] = "{:.0f}".format(BMS_STATUS['voltages']['battery_capacity_ah']['value']) + "Ah"
						#			if args.victron:
						#				dbusservice["/Voltages/BatteryCapacityAH"] = BMS_STATUS['voltages']['battery_capacity_ah']['text']
						#				dbusservice["/Raw/Voltages/BatteryCapacityAH"] = BMS_STATUS['voltages']['battery_capacity_ah']['value']


								
								# update timestamp
								#current_date = datetime.datetime.now()
								#INVERTER_STATUS['inverter_mode']['timestamp']['value'] = time.time()
								#INVERTER_STATUS['inverter_mode']['timestamp']['text']  = current_date.strftime('%a %d.%m.%Y %H:%M:%S')
								#if args.victron:
								#	dbusservice["/Info/UpdateTimestamp"] = INVERTER_STATUS['inverter_mode']['timestamp']['text']
								#	dbusservice["/Raw/Info/UpdateTimestamp"] = INVERTER_STATUS['inverter_mode']['timestamp']['value']
									

								# print (BMS_STATUS)
								#if (packet_length == PACKET_LENGTH_STATUS_CELLS[0]): # packet from BMS8
								#
								#	logging.info("BMS Voltages " +
								#		"[CAPACITYAH|" + BMS_STATUS['voltages']['battery_capacity_ah']['text'] +
								#		"][CAPACITYWH|" + BMS_STATUS['voltages']['battery_capacity_wh']['text'] +
								#		"][DIFF|" + BMS_STATUS['voltages']['agg_voltages']['diff']['text'] +
								#		"][SUM|" + BMS_STATUS['voltages']['agg_voltages']['sum']['text'] +
								#		"][#1|"  + BMS_STATUS['voltages']['cell1_voltage']['text'] +
								#		"][#2|"  + BMS_STATUS['voltages']['cell2_voltage']['text'] + 
								#		"][#3|"  + BMS_STATUS['voltages']['cell3_voltage']['text'] + 
								#		"][#4|"  + BMS_STATUS['voltages']['cell4_voltage']['text'] +
								#		"][#5|"  + BMS_STATUS['voltages']['cell5_voltage']['text'] +
								#		"][#6|"  + BMS_STATUS['voltages']['cell6_voltage']['text'] +
								#		"][#7|"  + BMS_STATUS['voltages']['cell7_voltage']['text'] +
								#		"][#8|"  + BMS_STATUS['voltages']['cell8_voltage']['text'] + "]")

								#elif (packet_length == PACKET_LENGTH_STATUS_CELLS[1]): # packet from BMS16

								#	logging.info("BMS Voltages " +
								#		"[CAPACITYAH|" + BMS_STATUS['voltages']['battery_capacity_ah']['text'] +
								#		"][CAPACITYWH|" + BMS_STATUS['voltages']['battery_capacity_wh']['text'] +
								#		"][DIFF|" + BMS_STATUS['voltages']['agg_voltages']['diff']['text'] +
								#		"][SUM|"  + BMS_STATUS['voltages']['agg_voltages']['sum']['text'] +
								#		"][#1|"   + BMS_STATUS['voltages']['cell1_voltage']['text'] +
								#		"][#2|"   + BMS_STATUS['voltages']['cell2_voltage']['text'] + 
								#		"][#3|"   + BMS_STATUS['voltages']['cell3_voltage']['text'] + 
								#		"][#4|"   + BMS_STATUS['voltages']['cell4_voltage']['text'] +
								#		"][#5|"   + BMS_STATUS['voltages']['cell5_voltage']['text'] +
								#		"][#6|"   + BMS_STATUS['voltages']['cell6_voltage']['text'] +
								#		"][#7|"   + BMS_STATUS['voltages']['cell7_voltage']['text'] +
								#		"][#8|"   + BMS_STATUS['voltages']['cell8_voltage']['text'] +
								#		"][#9|"   + BMS_STATUS['voltages']['cell9_voltage']['text'] + 
								#		"][#10|"  + BMS_STATUS['voltages']['cell10_voltage']['text'] + 
								#		"][#11|"  + BMS_STATUS['voltages']['cell11_voltage']['text'] +
								#		"][#12|"  + BMS_STATUS['voltages']['cell12_voltage']['text'] +
								#		"][#13|"  + BMS_STATUS['voltages']['cell13_voltage']['text'] +
								#		"][#14|"  + BMS_STATUS['voltages']['cell14_voltage']['text'] +
								#		"][#15|"  + BMS_STATUS['voltages']['cell15_voltage']['text'] +
								#		"][#16|"  + BMS_STATUS['voltages']['cell16_voltage']['text'] + "]")
								

								#elif (packet_length == PACKET_LENGTH_STATUS_CELLS[2]): # packet from BMS24

								#	logging.info("BMS Voltages " +
								#		"[CAPACITYAH|" + BMS_STATUS['voltages']['battery_capacity_ah']['text'] +
								#		"][CAPACITYWH|" + BMS_STATUS['voltages']['battery_capacity_wh']['text'] +
								#		"][DIFF|" + BMS_STATUS['voltages']['agg_voltages']['diff']['text'] +
								#		"][SUM|"  + BMS_STATUS['voltages']['agg_voltages']['sum']['text'] +
								#		"][#1|"   + BMS_STATUS['voltages']['cell1_voltage']['text'] +
								#		"][#2|"   + BMS_STATUS['voltages']['cell2_voltage']['text'] + 
								#		"][#3|"   + BMS_STATUS['voltages']['cell3_voltage']['text'] + 
								#		"][#4|"   + BMS_STATUS['voltages']['cell4_voltage']['text'] +
								#		"][#5|"   + BMS_STATUS['voltages']['cell5_voltage']['text'] +
								#		"][#6|"   + BMS_STATUS['voltages']['cell6_voltage']['text'] +
								#		"][#7|"   + BMS_STATUS['voltages']['cell7_voltage']['text'] +
								#		"][#8|"   + BMS_STATUS['voltages']['cell8_voltage']['text'] +
								#		"][#9|"   + BMS_STATUS['voltages']['cell9_voltage']['text'] + 
								#		"][#10|"  + BMS_STATUS['voltages']['cell10_voltage']['text'] + 
								#		"][#11|"  + BMS_STATUS['voltages']['cell11_voltage']['text'] +
								#		"][#12|"  + BMS_STATUS['voltages']['cell12_voltage']['text'] +
								#		"][#13|"  + BMS_STATUS['voltages']['cell13_voltage']['text'] +
								#		"][#14|"  + BMS_STATUS['voltages']['cell14_voltage']['text'] +
								#		"][#15|"  + BMS_STATUS['voltages']['cell15_voltage']['text'] +
								#		"][#16|"  + BMS_STATUS['voltages']['cell16_voltage']['text'] + 
								#		"][#17|"  + BMS_STATUS['voltages']['cell17_voltage']['text'] +
								#		"][#18|"  + BMS_STATUS['voltages']['cell18_voltage']['text'] +
								#		"][#19|"  + BMS_STATUS['voltages']['cell19_voltage']['text'] +
								#		"][#20|"  + BMS_STATUS['voltages']['cell20_voltage']['text'] +
								#		"][#21|"  + BMS_STATUS['voltages']['cell21_voltage']['text'] +
								#		"][#22|"  + BMS_STATUS['voltages']['cell22_voltage']['text'] +
								#		"][#23|"  + BMS_STATUS['voltages']['cell23_voltage']['text'] +
								#		"][#24|"  + BMS_STATUS['voltages']['cell24_voltage']['text'] + "]")

							#else:
							#	logging.debug("Packet Checksum wrong, skip packet")

							# strip packet
							#packet = packet[packet_length:]

					#elif (packet[2] == PACKET_STATUS_IMPEDANCES):

					#	if (len(packet) < PACKET_LENGTH_STATUS_IMPEDANCES):
					#		logging.debug("Packet Impedances Cells too short, skip")
					#		packet = ""
					#	else:
							# delete old data
					#		reset_impedances_values()

					#		cell_count = int((packet_length - 8) / 2);
					#		logging.debug("Packet Impedances, detected cells: #" + str(cell_count))

							# checksum value
					#		checksum = packet[packet_length-1]
					#		checksum_check = 0

							# calculate checksum
					#		for i in range(packet_length-1):
					#			checksum_check = checksum_check + packet[i]
					#		checksum_check = checksum_check % 256
					#		logging.debug("Packet Checksum BMS: " + str(checksum) + "|" + str(checksum_check))


							# data integrity does match
					#		if (checksum == checksum_check):

								# Chargery protocol manual:
								# Current 1 (A), It is instant current when measure cell impedance								
					#			BMS_STATUS['impedances']['current1']['value'] = get_current1_value(packet[5], packet[6])

								# Chargery protocol manual:
								# Current mode 1 means battery is in charging or discharging when cell impedance is measured
					#			bms_current_mode1 = packet[4]
					#			if (bms_current_mode1 == 0x00):
					#				BMS_STATUS['impedances']['current_mode1']['value'] = 0
					#				BMS_STATUS['impedances']['current_mode1']['text']  = "Discharge"
					#				BMS_STATUS['impedances']['current1']['text'] = "-" + str(BMS_STATUS['impedances']['current1']['value']) + "A"
					#			elif (bms_current_mode1 == 0x01):
					#				BMS_STATUS['impedances']['current_mode1']['value'] = 1
					#				BMS_STATUS['impedances']['current_mode1']['text']  = "Charge"
					#				BMS_STATUS['impedances']['current1']['text'] = str(BMS_STATUS['impedances']['current1']['value']) + "A"
					#			else:
					#				BMS_STATUS['impedances']['current_mode1']['value'] = -1
					#				BMS_STATUS['impedances']['current_mode1']['text']  = ""
					#				BMS_STATUS['impedances']['current1']['text'] = ""
					#			if args.victron:
					#				dbusservice["/Impedances/CurrentMode1"] = BMS_STATUS['impedances']['current_mode1']['text']
					#				dbusservice["/Raw/Impedances/CurrentMode1"] = BMS_STATUS['impedances']['current_mode1']['value']
					#				dbusservice["/Impedances/Current1"] = BMS_STATUS['impedances']['current1']['text']
					#				dbusservice["/Raw/Impedances/Current1"] = BMS_STATUS['impedances']['current1']['value']

					#			for i in range(1, cell_count+1):
					#				BMS_STATUS['impedances']['cell'+str(i)+'_impedance']['value'] = get_cell_impedance(packet[7+(2*(i-1))], packet[8+(2*(i-1))])
					#				BMS_STATUS['impedances']['cell'+str(i)+'_impedance']['text'] = "{:.1f}".format(BMS_STATUS['impedances']['cell'+str(i)+'_impedance']['value']) + "mOhm"

					#				if args.victron:
					#					dbusservice["/Impedances/Cell"+str(i)] = BMS_STATUS['impedances']['cell'+str(i)+'_impedance']['text']
					#					dbusservice["/Raw/Impedances/Cell"+str(i)] = BMS_STATUS['impedances']['cell'+str(i)+'_impedance']['value']


								
								# get min/max impedances to calculate the diff
					#			cell_impedances = []

					#			if (BMS_STATUS['impedances']['cell1_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell1_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell2_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell2_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell3_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell3_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell4_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell4_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell5_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell5_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell6_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell6_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell7_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell7_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell8_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell8_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell9_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell9_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell10_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell10_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell11_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell11_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell12_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell12_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell13_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell13_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell14_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell14_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell15_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell15_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell16_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell16_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell17_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell17_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell18_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell18_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell19_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell19_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell20_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell20_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell21_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell21_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell22_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell22_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell23_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell23_impedance']['value'])
					#			if (BMS_STATUS['impedances']['cell24_impedance']['value'] >= MIN_CELL_IMPEDANCE):
					#				cell_impedances.append(BMS_STATUS['impedances']['cell24_impedance']['value'])
									
					#			BMS_STATUS['impedances']['agg_impedances']['sum']['value']      = sum(cell_impedances)
					#			BMS_STATUS['impedances']['agg_impedances']['sum']['text']       = "{:.1f}".format(BMS_STATUS['impedances']['agg_impedances']['sum']['value']) + "mOhm" 
					#			BMS_STATUS['impedances']['agg_impedances']['max']['value']      = max(cell_impedances)
					#			BMS_STATUS['impedances']['agg_impedances']['max']['text']       = "{:.1f}".format(BMS_STATUS['impedances']['agg_impedances']['max']['value']) + "mOhm" 
					#			BMS_STATUS['impedances']['agg_impedances']['min']['value']      = min(cell_impedances)
					#			BMS_STATUS['impedances']['agg_impedances']['min']['text']       = "{:.1f}".format(BMS_STATUS['impedances']['agg_impedances']['min']['value']) + "mOhm" 
					#			BMS_STATUS['impedances']['agg_impedances']['diff']['value']     = BMS_STATUS['impedances']['agg_impedances']['max']['value'] - BMS_STATUS['impedances']['agg_impedances']['min']['value']
					#			BMS_STATUS['impedances']['agg_impedances']['diff']['text']      = "{:.1f}".format(BMS_STATUS['impedances']['agg_impedances']['diff']['value']) + "mOhm"
					#			BMS_STATUS['impedances']['agg_impedances']['average']['value']  = float("{:.3f}".format(sum(cell_impedances)/len(cell_impedances))) 
					#			BMS_STATUS['impedances']['agg_impedances']['average']['text']   = "{:.1f}".format(BMS_STATUS['impedances']['agg_impedances']['average']['value']) + "mOhm" 

					#			if args.victron:
					#				dbusservice["/Impedances/Sum"]      = BMS_STATUS['impedances']['agg_impedances']['sum']['text']
					#				dbusservice["/Raw/Impedances/Sum"]  = BMS_STATUS['impedances']['agg_impedances']['sum']['value']
					#				dbusservice["/Impedances/Max"]      = BMS_STATUS['impedances']['agg_impedances']['max']['text']
					#				dbusservice["/Raw/Impedances/Max"]  = BMS_STATUS['impedances']['agg_impedances']['max']['value']
					#				dbusservice["/Impedances/Min"]      = BMS_STATUS['impedances']['agg_impedances']['min']['text']
					#				dbusservice["/Raw/Impedances/Min"]  = BMS_STATUS['impedances']['agg_impedances']['min']['value']
					#				dbusservice["/Impedances/Diff"]     = BMS_STATUS['impedances']['agg_impedances']['diff']['text']
					#				dbusservice["/Raw/Impedances/Diff"] = BMS_STATUS['impedances']['agg_impedances']['diff']['value']
					#				dbusservice["/Impedances/Avg"]      = BMS_STATUS['impedances']['agg_impedances']['average']['text']
					#				dbusservice["/Raw/Impedances/Avg"]  = BMS_STATUS['impedances']['agg_impedances']['average']['value']


								# update timestamp
					#			current_date = datetime.datetime.now()
					#			BMS_STATUS['impedances']['timestamp']['value'] = time.time()
					#			BMS_STATUS['impedances']['timestamp']['text']  = current_date.strftime('%a %d.%m.%Y %H:%M:%S')
					#			if args.victron:
					#				dbusservice["/Impedances/UpdateTimestamp"] = BMS_STATUS['impedances']['timestamp']['text']
					#				dbusservice["/Raw/Impedances/UpdateTimestamp"] = BMS_STATUS['impedances']['timestamp']['value']

					#			logging.info("BMS Impedances " +
					#				"][MODE1|" + BMS_STATUS['impedances']['current_mode1']['text'] +
					#				"][CURRENT1|" + BMS_STATUS['impedances']['current1']['text'] +
					#				"][SUM|"  + BMS_STATUS['impedances']['agg_impedances']['sum']['text'] +
					#				"][#1|"   + BMS_STATUS['impedances']['cell1_impedance']['text'] +
					#				"][#2|"   + BMS_STATUS['impedances']['cell2_impedance']['text'] +
					#				"][#3|"   + BMS_STATUS['impedances']['cell3_impedance']['text'] +
					#				"][#4|"   + BMS_STATUS['impedances']['cell4_impedance']['text'] +
					#				"][#5|"   + BMS_STATUS['impedances']['cell5_impedance']['text'] +
					#				"][#6|"   + BMS_STATUS['impedances']['cell6_impedance']['text'] +
					#				"][#7|"   + BMS_STATUS['impedances']['cell7_impedance']['text'] +
					#				"][#8|"   + BMS_STATUS['impedances']['cell8_impedance']['text'] +
					#				"][#9|"   + BMS_STATUS['impedances']['cell9_impedance']['text'] +
					#				"][#10|"  + BMS_STATUS['impedances']['cell10_impedance']['text'] +
					#				"][#11|"  + BMS_STATUS['impedances']['cell11_impedance']['text'] +
					#				"][#12|"  + BMS_STATUS['impedances']['cell12_impedance']['text'] +
					#				"][#13|"  + BMS_STATUS['impedances']['cell13_impedance']['text'] +
					#				"][#14|"  + BMS_STATUS['impedances']['cell14_impedance']['text'] +
					#				"][#15|"  + BMS_STATUS['impedances']['cell15_impedance']['text'] +
					#				"][#16|"  + BMS_STATUS['impedances']['cell16_impedance']['text'] +
					#				"][#17|"  + BMS_STATUS['impedances']['cell17_impedance']['text'] +
					#				"][#18|"  + BMS_STATUS['impedances']['cell18_impedance']['text'] +
					#				"][#19|"  + BMS_STATUS['impedances']['cell19_impedance']['text'] +
					#				"][#20|"  + BMS_STATUS['impedances']['cell20_impedance']['text'] +
					#				"][#21|"  + BMS_STATUS['impedances']['cell21_impedance']['text'] +
					#				"][#22|"  + BMS_STATUS['impedances']['cell22_impedance']['text'] +
					#				"][#23|"  + BMS_STATUS['impedances']['cell23_impedance']['text'] +
					#				"][#24|"  + BMS_STATUS['impedances']['cell24_impedance']['text'] + "]")

					#		else:
					#			logging.debug("Packet Checksum wrong, skip packet")

							# strip packet
					#		packet = packet[packet_length:]
						
					else:
						# debug_packet(packet)
						logging.debug("Packet Unknown [1]")
						packet = ""
				
				else:
					logging.debug("Packet Unknown [2]")
					packet = ""
			else:
				logging.debug("Packet too short, skip")
				packet = ""



def handle_serial_data():
	try:
		serial_packet = bytearray()

		if (serial_port.in_waiting > 0):
			logging.debug("Data Waiting [" + str(serial_port.in_waiting) + " bytes]")

		if (serial_port.in_waiting >= (PACKET_LENGTH * 2)):
			data_buffer_array = serial_port.read(serial_port.in_waiting)
			logging.debug("Data Received [" + str(len(data_buffer_array)) + " bytes]")
			for data_buffer in data_buffer_array:
				serial_packet.append(data_buffer)
				
			if (len(serial_packet) > 0):
				parse_packet(serial_packet)
				
			data_buffer_array = bytearray()
			serial_packet = bytearray()

		if args.victron:	
			# recheck every second
			gobject.timeout_add(1000, handle_serial_data)
		

	except KeyboardInterrupt:
		if not args.victron:
			raise

	except Exception as e:
		print(e);
		print(traceback.format_exc())

		if args.victron:
			dbusservice['/Alarms/InternalFailure'] = 1

		serial_port.close()
		quit()


if args.victron:
	gobject.timeout_add(1000, handle_serial_data)
	mainloop = gobject.MainLoop()
	mainloop.run()
else:
	while True:
		handle_serial_data()
		time.sleep(1)
