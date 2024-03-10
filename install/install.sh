#!/bin/bash

read -p "Install Sumry Inverter on Venus OS at your own risk? [Y to proceed]" -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
	echo "Download driver and library"

	wget https://github.com/LEUBE/venus-sumryinverter/archive/master.zip
	unzip master.zip
	rm master.zip

	wget https://github.com/victronenergy/velib_python/archive/master.zip
	unzip master.zip
	rm master.zip

	mkdir -p venus-sumryinverter-master/ext/velib_python
	cp -R velib_python-master/* venus-sumryinverter-master/ext/velib_python

	echo "Add Sumry entries to serial-starter"
	sed -i  '$aAction=="add", ENV{ID_BUS}=="usb", ENV{ID_SERIAL}=="FTDI_FT232R_USB_UART_A100LZBC",          ENV{VE_SERVICE}="sumryinverter"' /etc/udev/rules.d/serial-starter.rules
	sed -i  '/service.*imt.*dbus-imt-si-rs485tc/a service sumryinverter	dbus-sumry-inverter' /etc/venus/serial-starter.conf

	echo "Install Sumry driver"
	mkdir -p /var/log/dbus-sumry-inverter
	mkdir -p /opt/victronenergy/dbus-sumry-inverter
	cp -R venus-sumryinverter-master/ext /opt/victronenergy/dbus-sumry-inverter
	cp -R venus-sumryinverter-master/driver/* /opt/victronenergy/dbus-sumry-inverter

	chmod +x /opt/victronenergy/dbus-sumry-inverter/start-sumryinverter.sh
	chmod +x /opt/victronenergy/dbus-sumry-inverter/sumryinverter.py
	chmod +x /opt/victronenergy/dbus-sumry-inverter/service/run
	chmod +x /opt/victronenergy/dbus-sumry-inverter/service/log/run

	ln -s /opt/victronenergy/dbus-sumry-inverter/service /opt/victronenergy/service/dbus-sumry-inverter
	ln -s /opt/victronenergy/dbus-sumry-inverter/service /opt/victronenergy/service-templates/dbus-sumry-inverter

	#echo "Copy gui files" This should not be necessary as the inverter will use the standard GUI

	#cp venus-sumryinverter-master/gui/qml/MbItemRowTOBO.qml /opt/victronenergy/gui/qml
	#cp venus-sumryinverter-master/gui/qml/MbTextDescriptionTOBO.qml /opt/victronenergy/gui/qml
	#cp venus-sumryinverter-master/gui/qml/PageBatteryChargeryBMS.qml /opt/victronenergy/gui/qml
	#cp venus-sumryinverter-master/gui/qml/PageBatteryChargeryBMSImpedances.qml /opt/victronenergy/gui/qml
	#cp venus-sumryinverter-master/gui/qml/PageBatteryChargeryBMSVoltages.qml /opt/victronenergy/gui/qml
	#cp venus-sumryinverter-master/gui/qml/PageMain.qml /opt/victronenergy/gui/qml

	#read -p "Setup new gui overview? [Y to proceed]" -n 1 -r
	#echo    # (optional) move to a new line
	#if [[ $REPLY =~ ^[Yy]$ ]]
	#then
	#	echo "Setup new overview"
	#	cp venus-chargerybms-master/gui/qml/OverviewTiles.qml /opt/victronenergy/gui/qml
	#fi

	echo "To finish, reboot the Venus OS device"
fi
