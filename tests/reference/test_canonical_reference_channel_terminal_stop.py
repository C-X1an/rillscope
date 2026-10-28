"""Synthetic terminal stop call order; no Linux socket, process, grant or VM."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'benchmarks')]
import canonical_reference_channel as channel


class CanonicalChannelTerminalStop(unittest.TestCase):
    def setUp(self):
        parent=ROOT/'.local-runs';parent.mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(prefix='terminal-stop-',dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.owner=channel.CanonicalChannel.__new__(channel.CanonicalChannel)
        owner=self.owner
        owner.controller_pid=os.getpid();owner.connection=None;owner.receiver_process=None
        owner.receiver_captures=[];owner.exchange_record=None
        owner.stop=threading.Event();owner.done=threading.Event();owner.stop_request=None
        owner.stop_lock=threading.Lock()
        owner.stop_closed=False
        owner.deadline_ns=100;owner.path=Path(self.temp.name)/'unused-socket';owner.out=Path(self.temp.name)
        owner.commit='a'*40;owner.source_sha256='b'*64;owner.report={'status':'RUNNING'}
        owner.upstream_failure={'error':'ValueError','reason':'original synthetic controller failure'}
        self.persisted=[];owner.persist=lambda:self.persisted.append(copy.deepcopy(owner.report))
        self.connection=Mock()

    def stop_at(self,now):
        with patch.object(channel.time,'monotonic_ns',return_value=now):self.owner.request_stop()

    def run_owner(self,*,select_action=None,exchange_action=None,connect_action=None):
        if connect_action is not None:self.connection.connect.side_effect=connect_action
        select_action=select_action or (lambda *_:([self.connection],[],[]))
        original_exchange=channel.exchange
        with patch.object(channel.socket,'AF_UNIX',1,create=True),patch.object(channel.socket,'socket',return_value=self.connection),patch.object(channel.select,'select',side_effect=select_action),patch.object(channel,'exchange',side_effect=exchange_action or original_exchange),patch.object(channel.time,'monotonic_ns',return_value=30),patch.object(channel.reservation,'fsync_directory'):
            self.owner.run()
        self.assertTrue(self.owner.done.is_set())
        self.assertEqual(self.owner.report['status'],'FAIL')
        self.assertEqual(self.owner.report['finished_monotonic_ns'],30)
        self.connection.close.assert_called_once_with()

    def assert_stop_retained(self,now):
        expected={'requested_monotonic_ns':now,'upstream_failure':{'error':'ValueError','reason':'original synthetic controller failure'}}
        self.assertEqual(self.owner.stop_request,expected)
        self.assertEqual(self.persisted[-1].get('stop_request'),expected)
        self.assertEqual(self.owner.report.get('stop_request'),expected)
        self.assertNotIn('lifetime_failure',self.owner.report)
        self.assertLess(now,self.owner.deadline_ns)

    def test_stop_after_readiness_before_real_exchange_retains_first_cause(self):
        def ready_then_stop(*_):
            self.stop_at(20)
            return [self.connection],[],[]
        self.run_owner(select_action=ready_then_stop)
        self.assertEqual(self.owner.report['reason'],'original allocation exchange cancelled')
        self.assert_stop_retained(20)

    def test_stop_inside_exchange_retains_first_cause_and_original_exception(self):
        def stopped_exchange(*_,**kwargs):
            self.stop_at(21)
            channel.AllocationDeadline(kwargs['deadline_ns'],kwargs['cancelled'])
            self.fail('real allocation budget must reject the stopped exchange')
        self.run_owner(exchange_action=stopped_exchange)
        self.assertEqual(self.owner.report['reason'],'original allocation exchange cancelled')
        self.assert_stop_retained(21)

    def test_stop_during_connect_failure_retains_original_failure(self):
        def stopped_connect(*_):
            self.stop_at(22)
            raise OSError('synthetic connect interrupted')
        self.run_owner(connect_action=stopped_connect)
        self.assertEqual(self.owner.report['error'],'OSError')
        self.assertEqual(self.owner.report['reason'],'synthetic connect interrupted')
        self.assert_stop_retained(22)

    def test_repeated_stop_keeps_first_upstream_failure_in_terminal_record(self):
        def stopped_exchange(*_,**kwargs):
            self.stop_at(20)
            self.owner.upstream_failure={'error':'later','reason':'later cleanup'}
            self.stop_at(25)
            channel.AllocationDeadline(kwargs['deadline_ns'],kwargs['cancelled'])
            self.fail('real allocation budget must reject the stopped exchange')
        self.run_owner(exchange_action=stopped_exchange)
        self.assertEqual(self.owner.report['reason'],'original allocation exchange cancelled')
        self.assert_stop_retained(20)

    def test_unrelated_failure_does_not_invent_a_stop_or_expiry(self):
        self.run_owner(connect_action=OSError('synthetic unrelated connect failure'))
        self.assertEqual(self.owner.report['reason'],'synthetic unrelated connect failure')
        self.assertFalse(self.owner.stop.is_set())
        self.assertIsNone(self.owner.stop_request)
        self.assertNotIn('stop_request',self.owner.report)
        self.assertNotIn('lifetime_failure',self.owner.report)

    def test_stop_after_terminal_done_keeps_final_record_immutable(self):
        self.run_owner(connect_action=OSError('synthetic terminal connect failure'))
        terminal=copy.deepcopy(self.owner.report);retained=copy.deepcopy(self.persisted)
        self.stop_at(40)
        self.assertFalse(self.owner.stop.is_set())
        self.assertIsNone(self.owner.stop_request)
        self.assertEqual(self.owner.report,terminal)
        self.assertEqual(self.persisted,retained)

    def test_committed_report_disk_persistence_cannot_block_stop_request(self):
        entered=threading.Event();release=threading.Event();returned=threading.Event()
        errors=[]
        def persist():
            if 'finished_monotonic_ns' in self.owner.report:
                entered.set()
                if not release.wait(2):raise RuntimeError('synthetic persistence not released')
            self.persisted.append(copy.deepcopy(self.owner.report))
        self.owner.persist=persist
        self.connection.connect.side_effect=OSError('synthetic terminal connect failure')
        def request_stop():
            try:self.owner.request_stop()
            except BaseException as error:errors.append(error)
            finally:returned.set()
        with patch.object(channel.socket,'AF_UNIX',1,create=True),patch.object(channel.socket,'socket',return_value=self.connection),patch.object(channel.time,'monotonic_ns',return_value=30),patch.object(channel.reservation,'fsync_directory'):
            runner=threading.Thread(target=self.owner.run)
            stopper=threading.Thread(target=request_stop)
            runner.start()
            try:
                self.assertTrue(entered.wait(2),'terminal disk write must be reached')
                stopper.start()
                self.assertTrue(returned.wait(.5),'stop request must not wait for terminal disk I/O')
                self.assertFalse(self.owner.done.is_set(),'disk write is still in progress')
            finally:
                release.set();runner.join(2)
                if stopper.ident is not None:stopper.join(2)
        self.assertFalse(runner.is_alive())
        self.assertFalse(stopper.is_alive())
        self.assertEqual(errors,[])
        self.assertTrue(self.owner.done.is_set())
        self.assertFalse(self.owner.stop.is_set())
        self.assertIsNone(self.owner.stop_request)
        self.assertEqual(self.owner.report['reason'],'synthetic terminal connect failure')
        self.assertNotIn('stop_request',self.persisted[-1])
        self.assertNotIn('retention_error',self.owner.report)


if __name__=='__main__':unittest.main()
