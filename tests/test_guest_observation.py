"""Kernel-counter/serial parser units only; fixtures are not actual VM evidence."""
import base64
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import guest_resource_probe
import inspect_reference_guest


class GuestObservation(unittest.TestCase):
    def test_streamed_external_identity_keeps_every_byte_and_enforces_bound(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'image'
            path.write_bytes(b'abcdefghi')
            observed=inspect_reference_guest.bounded_identity(path,9)
            self.assertEqual(observed,{'path':str(path),'bytes':9,
                'sha256':'19cc02f26df43cc571bc9ed7b0c4d29224a3ec229529221725ef76d021c8326f'})
            with self.assertRaisesRegex(ValueError,'bound'):
                inspect_reference_guest.bounded_identity(path,8)

    def test_live_console_overflow_retains_only_the_bounded_prefix(self):
        with tempfile.TemporaryDirectory() as folder:
            reader,writer=os.pipe()
            with os.fdopen(reader,'rb',buffering=0) as source:
                capture=inspect_reference_guest.BoundedCapture(source,Path(folder)/'serial',4)
                try:
                    os.write(writer,b'abcde')
                    with self.assertRaisesRegex(ValueError,'capture exceeds bound'):
                        capture.drain()
                    self.assertTrue(capture.exceeded)
                finally:
                    os.close(writer);capture.close()
            self.assertEqual((Path(folder)/'serial').read_bytes(),b'abcd')

    def test_live_console_exact_bound_and_eof_are_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            reader,writer=os.pipe()
            with os.fdopen(reader,'rb',buffering=0) as source:
                capture=inspect_reference_guest.BoundedCapture(source,Path(folder)/'serial',4)
                try:
                    os.write(writer,b'abcd');os.close(writer)
                    capture.drain()
                    self.assertTrue(capture.eof)
                    self.assertFalse(capture.exceeded)
                finally: capture.close()
            self.assertEqual((Path(folder)/'serial').read_bytes(),b'abcd')

    def test_final_console_read_rejects_bytes_over_bound(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'serial';path.write_bytes(b'abcd')
            self.assertEqual(inspect_reference_guest.bounded_text(path,4),'abcd')
            path.write_bytes(b'abcde')
            with self.assertRaisesRegex(ValueError,'capture exceeds bound'):
                inspect_reference_guest.bounded_text(path,4)

    def test_kernel_counters_require_real_complete_nonnegative_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'counters'
            path.write_text('pswpin 3\npswpout 7\npgmajfault 11\nother 999\n')
            self.assertEqual(guest_resource_probe.kernel_counters(path),
                {'status':'MEASURED','values':{'pswpin':3,'pswpout':7,'pgmajfault':11}})
            for content in ('pswpin 3\npswpout 7\n','pswpin -3\npswpout 7\npgmajfault 11\n',
                            'pswpin 3\npswpin 4\npswpout 7\npgmajfault 11\n',
                            'pswpin nope\npswpout 7\npgmajfault 11\n'):
                path.write_text(content)
                observed=guest_resource_probe.kernel_counters(path)
                self.assertEqual((observed['status'],observed['values']),('NOT MEASURED',None))
            path.unlink()
            self.assertEqual(guest_resource_probe.kernel_counters(path)['status'],'NOT MEASURED')

    def fixture(self,phase,number):
        return {'phase':phase,'environment':{},'boot_id':'12345678-1234-1234-1234-123456789abc',
                'utc_ns':number,'monotonic_ns':number,'clock_source':'fixture',
                'clock_properties':{},'online_cpus':'0-3','cpu_stat':'cpu 0','vmstat':{},
                'swaps':'','pressure':{},'virtio_devices':[],'reference_qualified':False,'scope':'unit fixture'}

    def serial(self,rows):
        return '\n'.join(inspect_reference_guest.PREFIX+base64.b64encode(json.dumps(row).encode()).decode() for row in rows)

    def test_complete_typed_serial_sequence_preserves_explicit_unqualified_status(self):
        rows=[self.fixture('guest-start',1),self.fixture('guest-end',2)]
        self.assertEqual(inspect_reference_guest.parse_guest(self.serial(rows)),rows)
        self.assertFalse(any(row['reference_qualified'] for row in rows))

    def test_missing_duplicate_changed_boot_and_invalid_clocks_cannot_qualify(self):
        start=self.fixture('guest-start',1);end=self.fixture('guest-end',2)
        cases=([start],[start,start,end],[start,dict(end,boot_id='87654321-1234-1234-1234-123456789abc')],
               [start,dict(end,monotonic_ns=1)],[dict(start,utc_ns=True),end],
               [start,dict(end,reference_qualified=True)],[start,dict(end,extra='closed')])
        for rows in cases:
            with self.subTest(rows=rows),self.assertRaises(ValueError):
                inspect_reference_guest.parse_guest(self.serial(rows))
        with self.assertRaises(ValueError): inspect_reference_guest.parse_guest(inspect_reference_guest.PREFIX+'!invalid!')


if __name__=='__main__': unittest.main()
