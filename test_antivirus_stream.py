import ast,asyncio,io,os,struct,time
from pathlib import Path
from unittest.mock import AsyncMock,patch
f=next(n for n in ast.parse(Path(__file__).with_name('main.py').read_text()).body if isinstance(n,ast.AsyncFunctionDef) and n.name=='scan_antivirus');ns=dict(asyncio=asyncio,os=os,struct=struct,time=time,MAX_UPLOAD_BYTES=100000);exec(compile(ast.Module(body=[f],type_ignores=[]),'scan','exec'),ns)
class Writer:
 def __init__(self):self.data=b''
 def write(self,b):self.data+=b
 async def drain(self):pass
 def close(self):pass
 async def wait_closed(self):pass
async def test():
 os.environ.pop('CLAMAV_SOCKET',None);assert (await ns['scan_antivirus'](io.BytesIO(b'x')))['status']=='disabled'
 os.environ['CLAMAV_SOCKET']='/run/clamav/clamd.ctl'
 with patch.object(asyncio,'open_unix_connection',AsyncMock(side_effect=OSError())):assert (await ns['scan_antivirus'](io.BytesIO(b'x')))['status']=='unavailable'
 for expected,reply in [('clean',b'stream: OK\0'),('infected',b'stream: Test FOUND\0'),('limit',b'stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0'),('unavailable',b'stream: ERROR\0')]:
  vr=AsyncMock();vr.readuntil.return_value=('ClamAV 1.4/123/'+time.strftime('%a %b %d %H:%M:%S %Y')+'\0').encode();r=AsyncMock();r.readuntil.return_value=reply;w=Writer()
  with patch.object(asyncio,'open_unix_connection',AsyncMock(side_effect=[(vr,Writer()),(r,w)])):
   s=io.BytesIO(b'sample');s.seek(2);assert (await ns['scan_antivirus'](s))['status']==expected;assert s.tell()==2;assert w.data==b'zINSTREAM\0'+struct.pack('!I',6)+b'sample'+b'\0'*4
 print('PASS: disabled, unavailable, clean, infected, scan limits, error, protocol bytes, file position')
asyncio.run(test())
