"""Synthetic clock/stop controls; no actual grant, VM or capture qualification."""
import ast
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/"scripts"),str(ROOT/"benchmarks")]
import canonical_reference_channel as channel


class CanonicalChannelStopCause(unittest.TestCase):
    def owner(self):
        owner=channel.CanonicalChannel.__new__(channel.CanonicalChannel)
        owner.stop=threading.Event();owner.deadline_ns=100
        owner.done=threading.Event();owner.stop_lock=threading.Lock()
        owner.stop_closed=False
        owner.report={};owner.connection=None
        owner.upstream_failure={"error":"ValueError","reason":"actual canonical guest retained a failed attempt"}
        return owner

    def check(self,owner,now):
        method=getattr(owner,"check_lifetime",None)
        self.assertTrue(callable(method),"channel must record cancellation separately from its original cutoff")
        with patch.object(channel.time,"monotonic_ns",return_value=now):
            return method("capture")

    def test_stop_before_original_cutoff_records_controller_and_upstream_cause(self):
        owner=self.owner()
        with patch.object(channel.time,"monotonic_ns",return_value=20):owner.request_stop()
        with self.assertRaisesRegex(ValueError,"cancelled by controller"):self.check(owner,30)
        self.assertEqual(owner.report["lifetime_failure"],{
            "phase":"capture","cause":"controller-cancelled","observed_monotonic_ns":30,
            "vm_deadline_monotonic_ns":100,"stop_requested":True,"deadline_exhausted":False,
            "stop_request":{"requested_monotonic_ns":20,"upstream_failure":owner.upstream_failure}})

    def test_expiry_without_stop_keeps_exact_original_deadline(self):
        owner=self.owner()
        with self.assertRaisesRegex(ValueError,"lifetime exhausted"):self.check(owner,100)
        row=owner.report["lifetime_failure"]
        self.assertEqual(row["cause"],"absolute-deadline")
        self.assertEqual(row["observed_monotonic_ns"],100)
        self.assertEqual(row["vm_deadline_monotonic_ns"],100)
        self.assertIs(row["deadline_exhausted"],True)
        self.assertIs(row["stop_requested"],False)
        self.assertIsNone(row["stop_request"])

    def test_simultaneous_expiry_and_stop_preserves_both_observations(self):
        owner=self.owner();owner.stop.set()
        with self.assertRaisesRegex(ValueError,"lifetime exhausted"):self.check(owner,101)
        row=owner.report["lifetime_failure"]
        self.assertEqual(row["cause"],"absolute-deadline")
        self.assertIs(row["stop_requested"],True)
        self.assertIs(row["deadline_exhausted"],True)

    def test_live_wait_does_not_create_failure_or_reset_clock(self):
        owner=self.owner()
        self.assertEqual(self.check(owner,99),99)
        self.assertEqual(owner.report,{})
        self.assertEqual(owner.deadline_ns,100)

    def test_repeated_stop_does_not_replace_first_upstream_request(self):
        owner=self.owner()
        with patch.object(channel.time,"monotonic_ns",return_value=20):owner.request_stop()
        first=getattr(owner,"stop_request",None)
        self.assertIsNotNone(first,"first cancellation clock and upstream failure must be retained")
        owner.upstream_failure={"error":"later","reason":"later cleanup"}
        with patch.object(channel.time,"monotonic_ns",return_value=40):owner.request_stop()
        self.assertEqual(owner.stop_request,first)
        self.assertEqual(owner.stop_request["requested_monotonic_ns"],20)

    def test_original_request_and_capture_loops_both_use_checked_lifetime(self):
        tree=ast.parse((ROOT/"scripts/canonical_reference_channel.py").read_text())
        cls=next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=="CanonicalChannel")
        run=next(node for node in cls.body if isinstance(node,ast.FunctionDef) and node.name=="run")
        phases={node.args[0].value for node in ast.walk(run) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Attribute) and node.func.attr=="check_lifetime"
            and node.args and isinstance(node.args[0],ast.Constant)}
        self.assertEqual(phases,{"allocation-request","capture"})


if __name__=="__main__":unittest.main()
