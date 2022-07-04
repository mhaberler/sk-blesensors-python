from bleak.backends.scanner import AdvertisementData
from bleak.backends.device import BLEDevice
from bleak import BleakScanner
import asyncio
import logging
import struct

logger = logging.getLogger(__name__)


class CustomException(Exception):
    pass


dev = "hci1"
scanmode = "passive"
senso4s_offset = 1940
# Mopeka:
# converting sensor value to height - contact Mopeka for other fluids/gases
MOPEKA_TANK_LEVEL_COEFFICIENTS_PROPANE = (0.573045, -0.002822, -0.00000535)


def battery_percent(voltage: float) -> int:
    """Battery Percentage based on 3 volt CR2032 battery"""
    percent = ((voltage - 2.2) / 0.65) * 100
    if percent > 100.0:
        return 100
    if percent < 0.0:
        return 0
    return int(round(percent, 1))


def decodev5(adv):
    try:
        data = struct.unpack('>BhHHhhhHBH6B', adv)
        result = {
            'type': 'ruuvi',
        }
        if data[1] != -32768:
            result['temperature'] = round(data[1] / 200, 2)
        if data[2] != 65535:
            result['humidity'] = round(data[2] / 400, 2)
        if data[3] != 0xFFFF:
            result['pressure'] = round((data[3] + 50000) / 100, 2)
        if (data[4] != -32768 and data[5] != -32768 and data[6] != -32768):
            result['accel_x'] = data[4]
            result['accel_y'] = data[5]
            result['accel_z'] = data[6]
        battery_voltage = data[7] >> 5
        if battery_voltage != 0b11111111111:
            mV = round(data[1] / 200.0, 2) + 1600.0
            result['battery'] = battery_percent(mV * 1000.0)

        tx_power = data[7] & 0x001F
        if tx_power != 0b11111:
            result['tx_power'] = -40 + (tx_power * 2)

        result['movements'] = data[8]
        result['sequence'] = data[9]
        return result

    except Exception:
        logger.exception('Value: %s not valid', data)
        return None


def propane_level(level: float, temp: float) -> int:
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
        return decodev5(data)
    raise CustomException(f"unsupported Ruuvi format: {data[0]}")


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
def decode_tpms(device: BLEDevice, advertisement_data: AdvertisementData):
    data = None
    # several different "manufacturer codes" in the wild:
    # the hijacked TomTom 0x0100:
    if 256 in advertisement_data.manufacturer_data:
        data = advertisement_data.manufacturer_data[256]
    if 172 in advertisement_data.manufacturer_data:
        data = advertisement_data.manufacturer_data[172]
    if not data:
        raise CustomException(f"tpms: unknown manufacturer code:"
                              f" {advertisement_data.manufacturer_data}")

    if len(data) != 16:
        raise CustomException(f"tpms: invalid MFD lengt: expect 16, got {len(data)} "
                              f" {advertisement_data.manufacturer_data}")

    address, pressure, temperature, battery, status = struct.unpack(
        '<6sIIBB', data)
    return {
        'type': 'tpms',
        'pressure': pressure / 100000.0,
        'temperature': temperature / 100.0,
        'location': address[0] & 0x7f,
        'battery': battery,
        'status': status
    }


def decode_mopeka(device: BLEDevice, advertisement_data: AdvertisementData):
    data = advertisement_data.manufacturer_data[0x0059]
    l = len(data)
    if l != 10:
        raise CustomException(
            f"invalid Moepka message length: expected 10 got {l}")
    if data[0] != 3:
        raise CustomException(f"unsupported Moepka hardware ID: {data[2]}")

    raw_temp = (data[2] & 0x7f)
    temperature = raw_temp - 40.0
    raw_level = ((int(data[4]) << 8) + data[3]) & 0x3fff
    level_mm = propane_level(raw_level, temperature)
    result = {
        'type': 'mopeka',
        'raw_level': raw_level,
        'propane_level': level_mm,
        'temperature': temperature,
        'quality': (data[4] >> 6),
        'accel_x': data[8],
        'accel_y': data[9],
        'battery':  battery_percent((data[1] & 0x7f) / 32.0),
        'sync':  (data[2] & 0x80) > 0
    }
    return result


def decode_senso4s(device: BLEDevice, advertisement_data: AdvertisementData):
    data = advertisement_data.manufacturer_data[0x09CC]
    if len(data) != 10:
        raise CustomException(f"senso4s: invalid MFD lengt: expect 16, got {len(data)} "
                              f" {advertisement_data.manufacturer_data}")
    weight, status, battery, address = struct.unpack('<HBB6s', data)
    w = (weight - senso4s_offset) / 100.0
    result = {
        'type': 'senso4s',
        'weight': w,
        'rawweight': weight,
        'battery':  battery,
        'status':  status
    }
    return result


ruuvi_svc = '6e400001-b5a3-f393-e0a9-e50e24dcca9e'
tpms_svc = '0000fbb0-0000-1000-8000-00805f9b34fb'
mopeka_svc = '0000fee5-0000-1000-8000-00805f9b34fb'
senso4s_svc = '00007081-0000-1000-8000-00805f9b34fb'
# other senso4s service UUID's:
# 00001881-0000-1000-8000-00805f9b34fb
# 00001081-0000-1000-8000-00805f9b34fb

use_whitelist = True
use_whitelist = False
whitelist = {
    "E6:91:DF:7B:E5:4D": "env",
    "D6:39:AE:4F:CD:0C": "mopeka1",
    "80:EA:CA:12:24:30": "tpms_tank1",
    "E7:3F:13:9C:2B:E1": "mopeka_tank1",
}

svcuuid_map = {
    ruuvi_svc: decode_ruuvi,
    tpms_svc: decode_tpms,
    mopeka_svc: decode_mopeka,
    senso4s_svc: decode_senso4s,
}


def simple_callback(device: BLEDevice, advertisement_data: AdvertisementData):
    if use_whitelist and not device.address in whitelist.keys():
        #logger.info(f"skipping {device.address} - not in whitelist")
        return
    for u in advertisement_data.service_uuids:
        if u in svcuuid_map.keys():
            try:
                result = svcuuid_map.get(u)(device, advertisement_data)
                if result:
                    print(result)
                logger.debug(
                    f"{device.address} '{device.name}' RSSI: {device.rssi}:  {result}")
            except CustomException as e:
                logger.error(f"{device.details}:  {e}")

            except Exception as e:
                logger.exception(f"EXCEPTION {device.details}:  {e}")


async def scan():
    scanner = BleakScanner(adapter=dev, timeout=0,
                           scanning_mode=scanmode)  # , timeout=3.0)
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
    await asyncio.gather(scan()) #, blink())


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format=" %(message)s",
    )
    asyncio.run(main())

