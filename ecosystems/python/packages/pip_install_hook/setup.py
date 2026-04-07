from setuptools import setup
from setuptools.command.install import install


class _Install(install):
    def run(self):
        print("[oss-risks-findings] pip install hook executed")
        super().run()


setup(
    name="local-pip-install-hook",
    version="0.0.1",
    py_modules=["local_pip_install_hook"],
    cmdclass={"install": _Install},
)
