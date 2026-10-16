"""Compile GUI delivery applets; exercise shell-argument boundaries without installing anything."""
from pathlib import Path
import subprocess, tempfile, shlex, unittest
root=Path(__file__).resolve().parent.parent
class DeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='guard-delivery-tests-')
        cls.path=Path(cls.temp.name)
        for name in ('Installer','Uninstaller'):
            subprocess.run(['/usr/bin/osacompile','-o',str(cls.path/(name+'.scpt')),str(root/'Resources/Delivery'/(name+'.applescript'))],check=True)
        cls.driver=cls.path/'driver.applescript'
        cls.driver.write_text('''on run argv
set component to load script POSIX file (item 1 of argv)
return component's installationCommand(item 2 of argv, item 3 of argv, item 4 of argv, item 5 of argv)
end run
''')
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()
    def command(self,resource,uid,core='',config=''):
        return subprocess.run(['/usr/bin/osascript',str(self.driver),str(self.path/'Installer.scpt'),resource,uid,core,config],text=True,capture_output=True)
    def test_default_and_selected_paths_are_single_arguments(self):
        resource="/Volumes/Claude Guard's $(unused)/payload"
        core="/Applications/Example's app/core; echo unsafe"
        config='/Users/example/a `quoted` $(unused) config.yaml'
        result=self.command(resource,'501',core,config)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(shlex.split(result.stdout),['SUDO_UID=501','/bin/bash',resource+'/scripts/install.sh',core,config])
        result=self.command(resource,'501')
        self.assertEqual(shlex.split(result.stdout),['SUDO_UID=501','/bin/bash',resource+'/scripts/install.sh'])
    def test_invalid_owner_or_partial_registration_rejected(self):
        for args in [('/tmp/payload','0'),('/tmp/payload','501; bad'),('relative','501'),('/tmp/payload','501','/tmp/core','')]:
            self.assertNotEqual(self.command(*args).returncode,0)
if __name__=='__main__': unittest.main()
