from distutils.core import setup
import py2exe

setup(console = [
    {
        "script": "certscan.py",
        "dest_base" : "certscan"
    }],

    data_files=[
        ("conf",["conf/config.ini","conf/database.ini"]),
        ]
)