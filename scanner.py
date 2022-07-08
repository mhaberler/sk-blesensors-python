from bleak.backends.scanner import AdvertisementData
from bleak.backends.device import BLEDevice
from bleak import BleakScanner
import asyncio
import aioconsole

import logging
import logging.handlers

import struct
import json
import sys
import binascii


class CustomException(Exception):
    pass


# key = '03:B3:EC:C4:2F:9F' value = 'environment.oat'
knownmacs = {}
global whitelist, rounding
whitelist = True
rounding = 4

dev = "hci1"
scanmode = "passive"
senso4s_offset = 1940

# Mopeka:
# converting sensor value to height - contact Mopeka for other fluids/gases
MOPEKA_TANK_LEVEL_COEFFICIENTS_PROPANE = (0.573045, -0.002822, -0.00000535)


def prettify_mac(buffer, hexstring=False):
    if hexstring:
        b = buffer.replace(":", "")
        if len(b) != 12:
            raise CustomException(f"invalid length: expected 12, got"
                                  f" {len(buffer)}:  {b}")
        return ':'.join(format(s, '02x') for s in bytes.fromhex(b)).upper()
    else:
        if len(buffer) != 6:
            raise CustomException(f"invalid length: expected 6, got"
                                  f" {len(buffer)}:"
                                  f" {binascii.hexlify(bytearray(buffer,encoding='utf8'))}")
        return buffer.hex(":").upper()


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

#
# Manufacturer 172 (0x00ac)
#
#  b'af 49 4d 00 12 57 47 1f 0a 9a 33 c4 ec b3 03'
#                               ...BLE address...
def decode_tpms(device: BLEDevice, advertisement_data: AdvertisementData):
    data = None

    # several different "manufacturer codes" in the wild:
    # the hijacked TomTom 0x0100:
    if 256 in advertisement_data.manufacturer_data:
        data = advertisement_data.manufacturer_data[256]
        if len(data) != 16:
            hs = binascii.hexlify(bytearray(data))
            raise CustomException(f"tpms: invalid MFD length: expect 16, got {len(data)} "
                                  f" {advertisement_data.manufacturer_data} {hs}")

        address, pressure, temperature, battery, status = struct.unpack(
            '<6sIIBB', data)
        return {
            'type': 'tpms',
            'pressure': pressure,
            'temperature': temperature / 100.0,
            'location': address[0] & 0x7f,
            'battery': battery,
            'status': status
        }

    # this one has a different format - length 15:
#     mah@oe-sox:~$ ts|grep 'tpms MFC 172'
# Jul  5 20:33:07 oe-sox signalk-server[26090]: blescanner: tpms MFC 172: {'path': '/org/bluez/hci1/dev_03_B3_EC_C4_2F_9F', 'props': {'Address': '03:B3:EC:C4:2F:9F', 'AddressType': 'public', 'Name': 'TPMS_C42F9F', 'Alias': 'TPMS_C42F9F', 'Paired': False, 'Trusted': False, 'Blocked': False, 'LegacyPairing': False, 'RSSI': -86, 'Connected': False, 'UUIDs': ['0000fbb0-0000-1000-8000-00805f9b34fb'], 'Adapter': '/org/bluez/hci1', 'ManufacturerData': {172: b'\xaeLI\x00\x12UG\x1f\n\x9f/\xc4\xec\xb3\x03'}, 'ServicesResolved': False, 'AdvertisingFlags': b'\x06'}} {'type': 'tpms', 'pressure': 0.004803758, 'temperature': 0.52476853, 'battery': 10}

    if 172 in advertisement_data.manufacturer_data:
        data = advertisement_data.manufacturer_data[172]
        if len(data) != 15:
            hs = binascii.hexlify(bytearray(data))
            raise CustomException(f"tpms: invalid MFD length: expect 15 got {len(data)} "
                                  f" {advertisement_data.manufacturer_data} {hs}")

        pressure, temperature, battery, address = struct.unpack(
            '<IIB6s', data)
        result = {
            'type': 'tpms',
            'pressure': pressure / 1000000.0,
            'temperature': temperature / 1000000.0,
            'battery': battery
        }

        logger.info(f"tpms MFC 172: {device.details} adv={hs} {result}")
        return result

    raise CustomException(f"tpms: unknown manufacturer code:"
                          f" {advertisement_data.manufacturer_data}")

# Jul  5 17:39:15 oe-sox signalk-server[489]:  {'path': '/org/bluez/hci1/dev_03_B3_EC_C4_33_9A', 'props': {'Address': '03:B3:EC:C4:33:9A', 'AddressType': 'public', 'Name': 'TPMS_C4339A', 'Alias': 'TPMS_C4339A', 'Paired': False, 'Trusted': False, 'Blocked': False, 'LegacyPairing': False, 'RSSI': -85, 'Connected': False, 'UUIDs': ['0000fbb0-0000-1000-8000-00805f9b34fb'], 'Adapter': '/org/bluez/hci1', 'ManufacturerData': {172: b'\xafIM\x00\x12WG\x1f\n\x9a3\xc4\xec\xb3\x03'}, 'ServicesResolved': False, 'AdvertisingFlags': b'\x06'}}:  tpms: invalid MFD lengt: expect 16, got 15  {172: b'\xafIM\x00\x12WG\x1f\n\x9a3\xc4\xec\xb3\x03'} b'af494d001257471f0a9a33c4ecb303'
#
#
# >>> 0xae4f4c00/1000000000
# 2.924432384
# >>> 0x1257471f/100
# 3077097.27
# >>> 0x1257471f/10000000
# 30.7709727
#
#
# Jul  5 17:39:16 oe-sox signalk-server[489]:  {'path': '/org/bluez/hci1/dev_03_B3_EC_C4_33_9A', 'props': {'Address': '03:B3:EC:C4:33:9A', 'AddressType': 'public', 'Name': 'TPMS_C4339A', 'Alias': 'TPMS_C4339A', 'Paired': False, 'Trusted': False, 'Blocked': False, 'LegacyPairing': False, 'RSSI': -90, 'Connected': False, 'UUIDs': ['0000fbb0-0000-1000-8000-00805f9b34fb'], 'Adapter': '/org/bluez/hci1', 'ManufacturerData': {172: b'\xafIM\x00\x12WG\x1f\n\x9a3\xc4\xec\xb3\x03'}, 'ServicesResolved': False, 'AdvertisingFlags': b'\x00'}}:  tpms: invalid MFD lengt: expect 16, got 15  {172: b'\xafIM\x00\x12WG\x1f\n\x9a3\xc4\xec\xb3\x03'} b'af494d001257471f0a9a33c4ecb303'
# Jul  5 17:39:16 oe-sox signalk-server[489]:  {'path': '/org/bluez/hci1/dev_03_B3_EC_C4_33_9A', 'props': {'Address': '03:B3:EC:C4:33:9A', 'AddressType': 'public', 'Name': 'TPMS_C4339A', 'Alias': 'TPMS_C4339A', 'Paired': False, 'Trusted': False, 'Blocked': False, 'LegacyPairing': False, 'RSSI': -81, 'Connected': False, 'UUIDs': ['0000fbb0-0000-1000-8000-00805f9b34fb'], 'Adapter': '/org/bluez/hci1', 'ManufacturerData': {172: b'\xafIM\x00\x12WG\x1f\n\x9a3\xc4\xec\xb3\x03'}, 'ServicesResolved': False, 'AdvertisingFlags': b'\x06'}}:  tpms: invalid MFD lengt: expect 16, got 15  {172: b'\xafIM\x00\x12WG\x1f\n\x9a3\xc4\xec\xb3\x03'} b'af494d001257471f0a9a33c4ecb303'
# Jul  5 17:39:22 oe-sox signalk-server[489]:  {'path': '/org/bluez/hci1/dev_03_B3_EC_C4_2F_9F', 'props': {'Address': '03:B3:EC:C4:2F:9F', 'AddressType': 'public', 'Name': 'TPMS_C42F9F', 'Alias': 'TPMS_C42F9F', 'Paired': False, 'Trusted': False, 'Blocked': False, 'LegacyPairing': False, 'RSSI': -91, 'Connected': False, 'UUIDs': ['0000fbb0-0000-1000-8000-00805f9b34fb'], 'Adapter': '/org/bluez/hci1', 'ManufacturerData': {172: b'\xafOM\x00\x12]G\x1f\n\x9f/\xc4\xec\xb3\x03'}, 'ServicesResolved': False, 'AdvertisingFlags': b'\x06'}}:  tpms: invalid MFD lengt: expect 16, got 15  {172: b'\xafOM\x00\x12]G\x1f\n\x9f/\xc4\xec\xb3\x03'} b'af4f4d00125d471f0a9f2fc4ecb303'
# Jul  5 17:39:23 oe-sox signalk-server[489]:  {'path': '/org/bluez/hci1/dev_03_B3_EC_C4_2F_9F', 'props': {'Address': '03:B3:EC:C4:2F:9F', 'AddressType': 'public', 'Name': 'TPMS_C42F9F', 'Alias': 'TPMS_C42F9F', 'Paired': False, 'Trusted': False, 'Blocked': False, 'LegacyPairing': False, 'RSSI': -89, 'Connected': False, 'UUIDs': ['0000fbb0-0000-1000-8000-00805f9b34fb'], 'Adapter': '/org/bluez/hci1', 'ManufacturerData': {172: b'\xafOM\x00\x12]G\x1f\n\x9f/\xc4\xec\xb3\x03'}, 'ServicesResolved': False, 'AdvertisingFlags': b'\x00'}}:  tpms: invalid MFD lengt: expect 16, got 15  {172: b'\xafOM\x00\x12]G\x1f\n\x9f/\xc4\xec\xb3\x03'} b'af4f4d00125d471f0a9f2fc4ecb303'
# Jul  5 17:39:24 oe-sox signalk-server[489]:  {'path': '/org/bluez/hci1/dev_03_B3_EC_C4_2F_9F', 'props': {'Address': '03:B3:EC:C4:2F:9F', 'AddressType': 'public', 'Name': 'TPMS_C42F9F', 'Alias': 'TPMS_C42F9F', 'Paired': False, 'Trusted': False, 'Blocked': False, 'LegacyPairing': False, 'RSSI': -90, 'Connected': False, 'UUIDs': ['0000fbb0-0000-1000-8000-00805f9b34fb'], 'Adapter': '/org/bluez/hci1', 'ManufacturerData': {172: b'\xafOM\x00\x12]G\x1f\n\x9f/\xc4\xec\xb3\x03'}, 'ServicesResolved': False, 'AdvertisingFlags': b'\x06'}}:  tpms: invalid MFD lengt: expect 16, got 15  {172: b'\xafOM\x00\x12]G\x1f\n\x9f/\xc4\xec\xb3\x03'} b'af4f4d00125d471f0a9f2fc4ecb303'

    # if len(data) != 16:
    #     hs = binascii.hexlify(bytearray(data))
    #     raise CustomException(f"tpms: invalid MFD length: expect 16, got {len(data)} "
    #                           f" {advertisement_data.manufacturer_data} {hs}")

    # address, pressure, temperature, battery, status = struct.unpack(
    #     '<6sIIBB', data)
    # return {
    #     'type': 'tpms',
    #     'pressure': pressure / 100000.0,
    #     'temperature': temperature / 100.0,
    #     'location': address[0] & 0x7f,
    #     'battery': battery,
    #     'status': status
    # }


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

# use_whitelist = True
# use_whitelist = False
# whitelist = {
#     "E6:91:DF:7B:E5:4D": "env",
#     "D6:39:AE:4F:CD:0C": "mopeka1",
#     "80:EA:CA:12:24:30": "tpms_tank1",
#     "E7:3F:13:9C:2B:E1": "mopeka_tank1",
# }

svcuuid_map = {
    ruuvi_svc: decode_ruuvi,
    tpms_svc: decode_tpms,
    mopeka_svc: decode_mopeka,
    senso4s_svc: decode_senso4s,
}

skipkeys = ["type", "tx_power", "location"]


def outputSk(device: BLEDevice, devcfg: dict, result: dict):
    values = []
    if devcfg:
        prefix = devcfg['path'] + "."
    else:
        prefix = result['type'] + "." + \
            device.address.replace(":", "").lower() + "."

    for k, v in result.items():
        if k in skipkeys:
            continue
        values.append({"path": prefix + k, "value": v})

    # record signal strength
    values.append({"path": prefix + "rssi", "value": device.rssi})

    skData = {
        "updates": [
            {
                "values": values
            }
        ]
    }
    logger.debug(f"--> {skData=}")

    sys.stdout.write(json.dumps(skData))
    sys.stdout.write("\n")
    sys.stdout.flush()


def simple_callback(device: BLEDevice, advertisement_data: AdvertisementData):
    devcfg = knownmacs.get(device.address, None)
    if whitelist and devcfg is None:
        #logger.debug(f"skipping {device.address} - not in whitelist")
        return
    for u in advertisement_data.service_uuids:
        if u in svcuuid_map.keys():
            try:
                result = svcuuid_map.get(u)(device, advertisement_data)
                if result:
                    outputSk(device, devcfg, result)
                    logger.debug(
                        f"{device.address} '{device.name}' "
                        f"RSSI: {device.rssi}:  {result}")
            except CustomException as e:
                logger.error(f"{device.details}:  {e}")

            except Exception as e:
                logger.exception(
                    f"EXCEPTION {device.details}:  {advertisement_data} {e}")


async def scan(stdout):
    scanner = BleakScanner(adapter=dev, timeout=0,
                           scanning_mode=scanmode)  # , timeout=3.0)
    scanner.register_detection_callback(simple_callback)
    while True:
        await scanner.start()
        await asyncio.sleep(30.0)
        await scanner.stop()


def process(data: dict):
    global whitelist, rounding, knownmacs
    bledevs = data.get("multipleParametersArray", [])
    for dev in bledevs:
        cleaned = prettify_mac(dev['macaddress'], hexstring=True)
        dev.pop('macaddress')
        knownmacs[cleaned] = dev
    whitelist = data['whitelist']
    rounding = data['rounding']
    logger.info(f" ----> {knownmacs=} {whitelist=}")


async def read_input(stdin):

    while True:
        line = await stdin.readline()
        if not line:
            continue
        if len(line) == 0:
            continue
        if line.isspace():
            continue
        try:
            data = json.loads(line)
            #logger.info(f"-- from SignalK: ----> {json.dumps(data)}")
            process(data)
        except json.JSONDecodeError as je:
            logger.error(f"JSONDecodeError: {je}: {line}\n")


async def main():
    stdin, stdout = await aioconsole.get_standard_streams()
    await asyncio.gather(scan(stdout), read_input(stdin))


if __name__ == "__main__":
    logger = logging.getLogger("blescanner:")
    #logger.setLevel(logging.DEBUG)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(name)s: %(levelname)s %(message)s')
    handler = logging.handlers.SysLogHandler(address='/dev/log')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info('startup')
    asyncio.run(main())
