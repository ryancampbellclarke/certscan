from distutils.core import setup
import py2exe

setup(console = [
    {
        "script": "main.py",
        #"icon_resources": [(0, "favicon.ico")], ### Icon to embed into the PE file.
        "dest_base" : "certscan"
    }],
    data_files=[("dist",["config.ini",])]
)