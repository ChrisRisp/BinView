## Purpose

This project aims to create an easy to use navigable front end for binary analysis tools such as binwalk to index artifact characteristics. Currently this tool is in CLI form which will later be replaced by a GUI following the format of a multi pane hexeditor. 
TLDR: This is a lightweight binary profiling interface with tracking / flagging and visualization.

## Features

* Offset Tracking / Flagging
* Layout Visualization
* Generate Report

## Use of Tool

Launch main.py to interact with menu
```
[0] Analyze File
[1] Show Results
[2] Build Profile
[3] Exit
(binview)$ 
```
The three options shown on the main menu allow you to either start analysis, show artifact results or build a profile for report generation.

After initial analysis the "Show results" sub menu will display all the identified file types and their count. You can select the file type to list offsets individually by executing the command shown below; dump all will display all offsets at once. Additionally, you are able to flag a filetype for display in the report generated at the main menu.

```
   Count        Type   
------------------------------
[0]       36        LZMA compressed data
[1]        1        End of Zip archive
[2]       508       Zip archive data
[3]        1        Certificate in DER format (x509 v3)


[0] List Offsets [idx,#]
[1] Flag Filetype [#]
[1] Dump All
[2] Exit
(binview)$ 0,2
```

The offsets will then be displayed like so after selecting a file type from the show results sub menu
```
(binview)$ 0,0
[0] Offset: 0xab0f4 
Squashfs filesystem  little endian  version 2.0  
size: 2654572 bytes  502 inodes  
blocksize: 65536 bytes  
created: 2012-02-08 03:43:28 

[0] Inspect [#, bytes]
[1] Flag Filetype [#]
[2] DD Extract [#]
[3] Extract All
[4] Exit
```
[Identified Headers]
Squashfs filesystem
BIN-Header
gzip compressed data
TRX firmware header

[Binary Graph]

File Size: 3363840
File End: 0x335400
Row Count: 16
Size Per Row: 210240.0
Memory Occupied: (Lzma_loader): 0.0%
Memory Occupied: (Kernel/FS): 99.9695585997%
Memory Occupied: (Firmware_header): 0.0%
Memory Occupied: (Filesystem): 78.9149305556%

|------------------------|
|########################| <-- Addr: 0x0 <-- Flag: Lzma_loader Avg: 0x0
|########################| <-- Addr: 0x0 <-- Flag: Kernel/FS Avg: 0x10
|########################| <-- Addr: 0x0 <-- Flag: Firmware_header Avg: 0xa
|########################| <-- Addr: 0x0 <-- Flag: Filesystem Avg: 0x2ac45
|########################| <-- Addr: 0x33540
|########################| <-- Addr: 0x66a80
|########################| <-- Addr: 0x99fc0
..........
|########################| <-- Addr: 0x335400


After review, you may generate a report like the one below from the main menu using [2] build profile. 
```

# Goals

* Improve Static Analysis Workflow
* Complete GUI
* Add Aditional Report Configuration

## Dependencies

* Python2.7
* Binwalk

Refer to Installation of Binwalk for python
[Here](https://github.com/ReFirmLabs/binwalk/blob/master/INSTALL.md)

## Authors

[ChrisRisp](https://github.com/ChrisRisp/)
Email: cgr5364@rit.edu

## Contributors
[Fdrozenski](https://github.com/Fdrozenski/)
Email: frd3436@rit.edu
