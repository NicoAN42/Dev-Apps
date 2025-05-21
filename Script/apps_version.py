# version_info.py
from PyInstaller.utils.win32.versioninfo import (
    VSVersionInfo,
    FixedFileInfo,
    StringFileInfo,
    StringTable,
    VarFileInfo,
    VarStruct,
)

version_info = VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=(1, 0, 0, 0),
        prodvers=(1, 0, 0, 0),
        mask=0x3F,
        flags=0x0,
        OS=0x40004,  # NT and Windows
        fileType=0x1,  # App
        subtype=0x0,
        date=(0, 0),
    ),
    kids=[
        StringFileInfo(
            [
                StringTable(
                    '040904B0',
                    [
                        ('CompanyName', 'SOW 7'),
                        ('FileDescription', 'Device Scanner by Nico Ardian'),
                        ('FileVersion', '1.0.0.0'),
                        ('InternalName', 'SOW7'),
                        ('LegalCopyright', '© Created by Nico Ardian SOW 7 - 2025'),
                        ('OriginalFilename', 'Device Sacnner.exe'),
                        ('ProductName', 'Device Scanner App'),
                        ('ProductVersion', '1.0.0.0'),
                        ('Comments', 'Publisher Information for Windows Defender mitigation'),
                    ],
                )
            ]
        ),
        VarFileInfo([VarStruct('Translation', [1033, 1200])]),
    ],
)