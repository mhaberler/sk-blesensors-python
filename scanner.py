from bleak.backends.scanner import AdvertisementData
from bleak.backends.device import BLEDevice
from bleak import BleakScanner
import asyncio
import logging
import sys
import time
import struct

logger = logging.getLogger(__name__)

dev = "hci1"

senso4s_offset = 1940

def BatteryPercent(voltage: float) -> int:
    """Battery Percentage based on 3 volt CR2032 battery"""
    percent = ((voltage - 2.2) / 0.65) * 100
    if percent > 100.0:
        return 100
    if percent < 0.0:
        return 0
    return int(round(percent, 1))

def to_mac(self, data):
    return ''.join('{:02x}'.format(x) for x in data)

def decodev5(adv):

    try:
        data = struct.unpack('>BhHHhhhHBH6B', adv)
        result = {
            'format': 5,
            'movements': data[8],
            'sequence': data[9],
        }
        if (data[4] != -32768 and data[5] != -32768 and data[6] != -32768):
            result['acc_x'] = data[4]
            result['acc_y'] = data[5]
            result['acc_z'] = data[6]
        if data[2] != 65535:
            result['humidity'] = round(data[2] / 400, 2)
        if data[1] != -32768:
            result['temperature'] = round(data[1] / 200, 2)
        if data[3] != 0xFFFF:
            result['pressure'] = round((data[3] + 50000) / 100, 2)

        battery_voltage = data[7] >> 5
        if battery_voltage != 0b11111111111:
            mV = round(data[1] / 200.0, 2) + 1600.0

            result['battery'] = BatteryPercent(mV * 1000.0)

        tx_power = data[7] & 0x001F
        if tx_power != 0b11111:
            result['tx_power'] = -40 + (tx_power * 2)
        return result

    except Exception:
        logger.exception('Value: %s not valid', data)
        return None


# Mopeka:
# converting sensor value to height - contact Mopeka for other fluids/gases
MOPEKA_TANK_LEVEL_COEFFICIENTS_PROPANE = (0.573045, -0.002822, -0.00000535)


def TankLevelInMM(level: float, temp: float) -> int:
    """ The tank level/depth in mm for propane gas"""
    return int(
        level
        * (
            MOPEKA_TANK_LEVEL_COEFFICIENTS_PROPANE[0]
            + (MOPEKA_TANK_LEVEL_COEFFICIENTS_PROPANE[1] * temp)
            + (
                MOPEKA_TANK_LEVEL_COEFFICIENTS_PROPANE[2]
                * temp
                * temp
            )
        )
    )





def decode_ruuvi(device: BLEDevice, advertisement_data: AdvertisementData):
    data = advertisement_data.manufacturer_data[0x0499]
    l = len(data)

    if data[0] == 5:
        result = decodev5(data)
        logger.info(
            f"ruuvi {device.address} RSSI: {device.rssi} {result}")
        return

    logger.info(
            f"OLD RUUVI {device.address} RSSI: {device.rssi}, version={version} {device.metadata}")
    return None



def decode_tpms(device: BLEDevice, advertisement_data: AdvertisementData):
    data = None
    # several different "manufacturer codes" in the wild:
    # the hijacked TomTom 0x0100:
    if 256 in advertisement_data.manufacturer_data:
        data = advertisement_data.manufacturer_data[256]
    if 172 in advertisement_data.manufacturer_data:
        data = advertisement_data.manufacturer_data[172]
    if not data:
        return

    fmt = '<6sIIBB'
    address, pressure, temperature, battery, alarm = struct.unpack(fmt, data)
    loc = address[0] & 0x7f
    p = pressure / 100000.0
    t = temperature / 100.0
    print(f"tpms: {device.address} {device.name} rssi={device.rssi} loc={loc}"
          f" pressure={p:.2f}"
          f" temperature={t:.2f}"
          f" battery={battery}% alarm={alarm}")


def decode_mopeka(device: BLEDevice, advertisement_data: AdvertisementData):

    data = advertisement_data.manufacturer_data[0x0059]
    l = len(data)
    # print(f"mopeka len={l} {advertisement_data}!")

    if l != 10:
        return

    if data[0] != 3:
        logger.error(f"mopeka: invalid hwid {data[2]}")
        return

    # print(f"mopeka len={l} {advertisement_data}!")

    battery = (data[1] & 0x7f) / 32.0
    syncPressed = (data[2] & 0x80) > 0
    raw_temp = (data[2] & 0x7f)
    temperature = raw_temp - 40.0
    qualityStars = (data[4] >> 6)
    raw_level = ((int(data[4]) << 8) + data[3]) & 0x3fff
    level_mm = TankLevelInMM(raw_level, temperature)
    acceloX = data[8]
    acceloY = data[9]

    b = BatteryPercent(battery)
    print(f"mopeka: {device.address} {device.name} rssi={device.rssi}"
          f" raw_level={raw_level:.1f}"
          f" level_mm={level_mm:.1f}"
          f" qualityStars={qualityStars}"
          f" temperature={temperature:.1f}"
          f" acceloX={acceloX} acceloY={acceloY}"
          f" battery={b}% syncPressed={syncPressed}")


def decode_senso4s(device: BLEDevice, advertisement_data: AdvertisementData):
    data = advertisement_data.manufacturer_data[0x09CC]
    weight, status, battery, address = struct.unpack('<HBB6s', data)
    w = (weight - senso4s_offset) / 100.0
    print(
        f"senso4s:  {device.address} {device.name} rssi={device.rssi}  {w:.2f}Kg status={status} battery={battery}%")


ruuvi_svc = '6e400001-b5a3-f393-e0a9-e50e24dcca9e'
tpms_svc = '0000fbb0-0000-1000-8000-00805f9b34fb'
mopeka_svc = '0000fee5-0000-1000-8000-00805f9b34fb'


senso4s_svc = '00007081-0000-1000-8000-00805f9b34fb'
# other senso4s service UUID's:
# 00001881-0000-1000-8000-00805f9b34fb
# 00001081-0000-1000-8000-00805f9b34fb

svcuuid_map = {
    ruuvi_svc: decode_ruuvi,
    tpms_svc: decode_tpms,
    mopeka_svc: decode_mopeka,
    senso4s_svc: decode_senso4s,
}
# ruuvi_svc_uuid = '6e400001-b5a3-f393-e0a9-e50e24dcca9e'
# D0:88:3A:3A:80:15 RSSI: -71, AdvertisementData(local_name='Ruuvi 8015', manufacturer_data={1177: b'\x05\x0f\xa2qx\xb4o\x00\x80\xfc0\xff0\xae\xf6\x82\xc4\xc0\xd0\x88::\x80\x15'}, service_uuids=['6e400001-b5a3-f393-e0a9-e50e24dcca9e']) {'uuids': ['6e400001-b5a3-f393-e0a9-e50e24dcca9e'], 'manufacturer_data': {1177: b'\x05\x0f\xa2qx\xb4o\x00\x80\xfc0\xff0\xae\xf6\x82\xc4\xc0\xd0\x88::\x80\x15'}}

# // TPMS BLE ESP32
# // 2020 RA6070
# // v0.2 06/08/20
# //
# // TPMS BLE "manufacturer data" format
# // "000180eaca108a78e36d0000e60a00005b00"
# //  0001                                    Manufacturer (0001: TomTom)
# //      80                                  Sensor Number (80:1, 81:2, 82:3, 83:4, ..)
# //      80eaca108a78                        Sensor Address
# //                  e36d0000                Pressure
# //                          e60a0000        Temperature
# //                                  5b      Battery percentage
# //                                    00    Alarm Flag (00: OK, 01: No Pressure Alarm)
# //
# // How calculate Sensor Address:            (Sensor number):EA:CA:(Code binding reported in the leaflet) - i.e. 80:EA:CA:10:8A:78
#
#  TPMS 80:EA:CA:11:79:6F RSSI: -83, AdvertisementData(local_name='TPMS1_11796F', manufacturer_data={256: b'\x80\xea\xca\x11yo\xc6\x02\x00\x00f\n\x00\x00]\x00'}, service_uuids=['0000fbb0-0000-1000-8000-00805f9b34fb']) {'uuids': ['0000fbb0-0000-1000-8000-00805f9b34fb'], 'manufacturer_data': {256: b'\x80\xea\xca\x11yo\xc6\x02\x00\x00f\n\x00\x00]\x00'}}
#
#  TPMS 83:EA:CA:41:DA:FA RSSI: -74, AdvertisementData(local_name='TPMS4_41DAFA', manufacturer_data={256: b'\x83\xea\xcaA\xda\xfa\x00\x00\x00\x00\xe0\t\x00\x00d\x01'}, service_uuids=['0000fbb0-0000-1000-8000-00805f9b34fb']) {'uuids': ['0000fbb0-0000-1000-8000-00805f9b34fb'], 'manufacturer_data': {256: b'\x83\xea\xcaA\xda\xfa\x00\x00\x00\x00\xe0\t\x00\x00d\x01'}}

# Mopeka Pro:
#   C3:03:89:6E:8D:17 RSSI: -81, AdvertisementData(manufacturer_data={89: b'\x03`B\x00\x00n\x8d\x17\x18\xfd'}, service_uuids=['0000fee5-0000-1000-8000-00805f9b34fb']) {'uuids': ['0000fee5-0000-1000-8000-00805f9b34fb'], 'manufacturer_data': {89: b'\x03`B\x00\x00n\x8d\x17\x18\xfd'}}


def simple_callback(device: BLEDevice, advertisement_data: AdvertisementData):
    for u in advertisement_data.service_uuids:
        # print(u)
        if u in svcuuid_map.keys():
            # print(f"details: {device.details}")
            try:
                svcuuid_map.get(u)(device, advertisement_data)
            except:
                print(
                    f"------> EXCEPTION: {device.address} {device.name} rssi={device.rssi} adv={advertisement_data}")
    # if ruuvi_svc in advertisement_data.service_uuids:
    #     logger.info(f"RUUVI {device.address} RSSI: {device.rssi}, {advertisement_data} {device.metadata}")
    #     #print(device.address[3:8])
    # if tpms_svc in advertisement_data.service_uuids: #device.address[3:8] == 'EA:CA':
    #     logger.info(f"TPMS {device.address} RSSI: {device.rssi}, {advertisement_data} {device.metadata}")
    # if mopeka_svc in advertisement_data.service_uuids: #device.address[3:8] == 'EA:CA':
    #     logger.info(f"MOPEKA {device.address} RSSI: {device.rssi}, {advertisement_data} {device.metadata}")


async def scan():
    scanner = BleakScanner(adapter=dev, timeout=0)  # , timeout=3.0)
    scanner.register_detection_callback(simple_callback)
    while True:
        await scanner.start()
        await asyncio.sleep(30.0)
        await scanner.stop()


async def blink():
    while True:
        print("------->on")
        await asyncio.sleep(1.0)


async def main():
    await asyncio.gather(scan())  # , blink())


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        # format="%(asctime)-15s %(name)-8s %(levelname)s: %(message)s",
        format=" %(message)s",
    )
    asyncio.run(main())
    # while True:
    #     time.sleep(1.0)

    # await asyncio.gather(main())
