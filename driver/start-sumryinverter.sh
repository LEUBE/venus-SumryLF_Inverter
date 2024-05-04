#!/bin/bash
#
# Start script for Sumry Inverter
#	First parameter: tty device to use
#
# Keep this script running with daemon tools. If it exits because the
# connection crashes, or whatever, daemon tools will start a new one.
#

. /opt/victronenergy/serial-starter/run-service.sh

ln -s /dev/$tty /dev/ttySMRYINV01
app="/usr/bin/python /opt/victronenergy/dbus-sumry-inverter/sumryinverter.py"
start -d /dev/$tty --victron
