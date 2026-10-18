"""Filesystem fixtures for delegation rules; never actual allocation evidence."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'benchmarks'))
import run


class CgroupResources(unittest.TestCase):
    def hierarchy(self,folder):
        root=Path(folder).resolve()/'cgroup';parent=root/'system.slice';leaf=parent/'job';leaf.mkdir(parents=True)
        membership=Path(folder)/'membership';membership.write_text('0::/system.slice/job\n')
        for path in (root,parent,leaf):
            (path/'cgroup.controllers').write_text('cpu memory pids\n')
            (path/'cgroup.subtree_control').write_text('cpu memory\n' if path!=leaf else '')
            if path!=root: (path/'cgroup.type').write_text('domain\n')
        for path in (parent,leaf):
            for name,text in (('cpu.max','max 100000\n'),('memory.max','max\n'),('memory.high','max\n')):
                (path/name).write_text(text)
        return root,parent,leaf,membership

    def inspect(self,root,membership):
        with patch.object(os,'sched_getaffinity',return_value={0,1,2,3},create=True):
            return run.effective_linux_resources(root,membership)

    def disable_child_cpu(self,parent,leaf):
        (parent/'cgroup.subtree_control').write_text('memory\n')
        (leaf/'cgroup.controllers').write_text('memory\n');(leaf/'cpu.max').unlink()

    def test_complete_enabled_interfaces_retain_four_cpu_capacity(self):
        with tempfile.TemporaryDirectory() as folder:
            root,parent,leaf,membership=self.hierarchy(folder)
            value=self.inspect(root,membership)
            self.assertEqual(value['resource_inspection_status'],'MEASURED')
            self.assertEqual(value['effective_cpu_capacity'],4)
            self.assertEqual(value['cgroup_v2_ancestor_levels'],3)

    def test_proven_disabled_child_cpu_keeps_parent_quota(self):
        with tempfile.TemporaryDirectory() as folder:
            root,parent,leaf,membership=self.hierarchy(folder)
            self.disable_child_cpu(parent,leaf);(parent/'cpu.max').write_text('200000 100000\n')
            value=self.inspect(root,membership)
            self.assertEqual(value['resource_inspection_status'],'MEASURED')
            self.assertEqual(value['effective_cpu_capacity'],2)
            self.assertEqual(value['process_affinity_cpu_count'],4)

    def test_observed_guest_delegation_shape_has_no_local_cpu_quota(self):
        with tempfile.TemporaryDirectory() as folder:
            root,parent,leaf,membership=self.hierarchy(folder)
            self.disable_child_cpu(parent,leaf)
            (root/'cgroup.subtree_control').write_text('memory pids\n')
            (parent/'cgroup.controllers').write_text('memory pids\n');(parent/'cpu.max').unlink()
            value=self.inspect(root,membership)
            self.assertEqual(value['resource_inspection_status'],'MEASURED')
            self.assertEqual(value['effective_cpu_capacity'],4)
            self.assertIsNone(value['cgroup_memory_limit_bytes'])

    def test_disabled_memory_preserves_ancestor_limit_and_throttle(self):
        with tempfile.TemporaryDirectory() as folder:
            root,parent,leaf,membership=self.hierarchy(folder)
            (parent/'cgroup.subtree_control').write_text('cpu\n');(leaf/'cgroup.controllers').write_text('cpu\n')
            (leaf/'memory.max').unlink();(leaf/'memory.high').unlink()
            (parent/'memory.max').write_text(str(64*1024**2));(parent/'memory.high').write_text(str(32*1024**2))
            value=self.inspect(root,membership)
            self.assertEqual(value['resource_inspection_status'],'MEASURED')
            self.assertEqual(value['cgroup_memory_limit_bytes'],64*1024**2)
            self.assertEqual(value['cgroup_memory_high_bytes'],32*1024**2)

    def test_missing_enabled_cpu_interface_remains_unmeasured(self):
        with tempfile.TemporaryDirectory() as folder:
            root,parent,leaf,membership=self.hierarchy(folder);(leaf/'cpu.max').unlink()
            self.assertEqual(self.inspect(root,membership)['resource_inspection_status'],'NOT MEASURED')

    def test_missing_delegation_proof_remains_unmeasured(self):
        with tempfile.TemporaryDirectory() as folder:
            root,parent,leaf,membership=self.hierarchy(folder);self.disable_child_cpu(parent,leaf)
            (parent/'cgroup.subtree_control').unlink()
            self.assertEqual(self.inspect(root,membership)['resource_inspection_status'],'NOT MEASURED')

    def test_absent_root_controller_cannot_hide_an_uninspected_hierarchy(self):
        with tempfile.TemporaryDirectory() as folder:
            root,parent,leaf,membership=self.hierarchy(folder);(root/'cgroup.controllers').write_text('memory\n')
            self.assertEqual(self.inspect(root,membership)['resource_inspection_status'],'NOT MEASURED')

    def test_inconsistent_child_availability_cannot_authorize_missing_cpu(self):
        with tempfile.TemporaryDirectory() as folder:
            root,parent,leaf,membership=self.hierarchy(folder)
            (parent/'cgroup.subtree_control').write_text('memory\n');(leaf/'cpu.max').unlink()
            self.assertEqual(self.inspect(root,membership)['resource_inspection_status'],'NOT MEASURED')

    def test_ambiguous_group_type_cannot_authorize_missing_interface(self):
        with tempfile.TemporaryDirectory() as folder:
            root,parent,leaf,membership=self.hierarchy(folder);self.disable_child_cpu(parent,leaf)
            for value in ('threaded','domain threaded','domain invalid'):
                (leaf/'cgroup.type').write_text(value)
                self.assertEqual(self.inspect(root,membership)['resource_inspection_status'],'NOT MEASURED')

    def test_missing_child_controller_proof_remains_unmeasured(self):
        with tempfile.TemporaryDirectory() as folder:
            root,parent,leaf,membership=self.hierarchy(folder);self.disable_child_cpu(parent,leaf)
            (leaf/'cgroup.controllers').unlink()
            self.assertEqual(self.inspect(root,membership)['resource_inspection_status'],'NOT MEASURED')

    def test_permission_error_is_not_a_disabled_controller(self):
        with tempfile.TemporaryDirectory() as folder:
            root,parent,leaf,membership=self.hierarchy(folder);self.disable_child_cpu(parent,leaf)
            original=Path.read_text
            def guarded(path,*args,**kwargs):
                if path==parent/'cgroup.subtree_control': raise PermissionError('unit filesystem denial')
                return original(path,*args,**kwargs)
            with patch.object(Path,'read_text',guarded):
                observed=self.inspect(root,membership)
                self.assertEqual(observed['resource_inspection_status'],'NOT MEASURED')
                self.assertEqual(observed['resource_inspection_problem'],'PermissionError')

    def test_duplicate_root_controller_metadata_is_not_a_measurement(self):
        with tempfile.TemporaryDirectory() as folder:
            root,parent,leaf,membership=self.hierarchy(folder);(root/'cgroup.controllers').write_text('cpu cpu memory\n')
            self.assertEqual(self.inspect(root,membership)['resource_inspection_status'],'NOT MEASURED')


if __name__=='__main__': unittest.main()
