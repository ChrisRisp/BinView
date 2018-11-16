## Purpose

This project aims to create an easy to use navigable front end for binary analysis tools such as binwalk to index artifact characteristics. Currently this tool is in CLI form which will later be replaced by a GUI following the format of a multi pane hexeditor. 
TLDR: This is a lightweight binary profiling interface with tracking / flagging and reporting.

## Features

* Offset Tracking / Flagging
* (TODO) Layout Visualization
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
0x20e786L Size: 271B
0x20e8feL Size: 376B
0x20ea31L Size: 307B
0x20eccdL Size: 668B
0x2142fbL Size: 22062B
0x219df4L Size: 23289B
[0] List Offsets [#]
[1] Dump All
[2] Exit
(binview)$ 
```

## Goals

* Improve Static Analysis Workflow
* Complete GUI

## Dependencies

Refer to Installation of Binwalk for python
[Here](https://github.com/ReFirmLabs/binwalk/blob/master/INSTALL.md)
