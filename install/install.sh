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
	sed -i  '$aAction=="add", ENV{ID_BUS}=="usb", ENV{ID_MODEL}="USB_Serial",          ENV{VE_SERVICE}="rs485:default:sumryinverter"' /etc/udev/rules.d/serial-starter.rules
	sed -i  '/service.*imt.*dbus-imt-si-rs485tc/a service sumryinverter	dbus-sumry-inverter' /etc/venus/serial-starter.conf

	echo "Install Sumry driver"
	mkdir -p /var/log/sumryinverter
	mkdir -p /opt/victronenergy/sumryinverter
	cp -R venus-sumryinverter-master/ext /opt/victronenergy/sumryinverter
	cp -R venus-sumryinverter-master/driver/* /opt/victronenergy/sumryinverter

	chmod +x /opt/victronenergy/sumryinverter/start-sumryinverter.sh
	chmod +x /opt/victronenergy/sumryinverter/sumryinverter.py
	chmod +x /opt/victronenergy/sumryinverter/service/run
	chmod +x /opt/victronenergy/sumryinverter/service/log/run

	ln -s /opt/victronenergy/sumryinverter/service /opt/victronenergy/service/sumryinverter
	ln -s /opt/victronenergy/sumryinverter/service /opt/victronenergy/service-templates/sumryinverter

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
