#########################
# File: Main.py
# Author: ChrisRisp
# Project: Binview
# Version 0.1
#########################

import os
import sys
import binwalk
from collections import defaultdict

header = "\
__________.__            .__           \n\
\______   \__| _______  _|__| ______  _  __\n\
 |    |  _/  |/    \  \/ /  |/ __ \ \/ \/ /\\\n\
 |    |   \  |   |  \   /|  \  ___/\     /\n\
 |______  /__|___|  /\_/ |__|\___  >\/\_/  \n\
        \/        \/             \/         \n"

colors = {
    'blue': '\033[94m',
    'pink': '\033[95m',
    'green': '\033[92m',
    'red' : '\33[31m'
}

# Artifact Count/Offset Dicts
header_count = dict()
header_offsets = defaultdict(list)
header_flagged = []

def colorize(string, color):
    if not color in colors: return string
    return colors[color] + string + '\033[0m'


def analyze():

    for module in binwalk.scan(sys.argv[1],
                               signature=True,
                               quiet=True):

        for result in module.results:
            key = result.description.split(',')[0]
            offset = result.offset
            try:
                val = header_count[key]
                header_count[key] = val+1
                header_offsets[key].append(offset)

            except:
               # print ("No such entry yet")
                header_count[key] = 1
                header_offsets[key].append(offset)

    raw_input("Analyzed: Press [Enter] to continue...")


def show_results():
    sub = True
    while sub:
        submenuItems1 = [
            {"List Offsets [idx,#]": show_offsets},
            {"Flag Filetype [#]": flag_header},
            {"Dump All": show_offsets},
            {"Exit": exit},
        ]

        os.system('clear')

        # Print Table
        print(" {0:^10}  {1:^10}".format("Count", "Type"))
        print("-"*30)
        idx = 0

        # Get Header occurences
        for k, v in header_count.items():
            print ("[" + str(idx) + "] {0:^15} {1}".format(v, k))
            idx+=1
        print '\n'

        for item in submenuItems1:
            print colorize("[" + str(submenuItems1.index(item)) + "] ", 'blue') + item.keys()[0]
        choice = raw_input("(binview)$ ")
        selection = choice.split(',')
        try:
            if int(selection[0]) < 0: raise ValueError
            if int(selection[0]) == 3: sub = False
            # Call the matching function

            submenuItems1[int(selection[0])].values()[0](int(selection[1]))
        except (ValueError, IndexError):
            pass

def show_offsets(selection):
    submenuItems2 = [
        {"List Offsets [#]": analyze},
        {"Dump All": show_offsets},
        {"Exit": exit},
    ]

    prev_offset = 0
    for offset in header_offsets[header_offsets.keys()[selection]]:
        print hex(offset) + " Size: " + str(int(offset-prev_offset)) + "B"
        prev_offset = offset
    os.system('clear')

    for item in submenuItems2:
        print colorize("[" + str(submenuItems2.index(item)) + "] ", 'blue') + item.keys()[0]
    choice = raw_input("(binview)$ ")
    try:
        if int(choice) < 0: raise ValueError
        # Call the matching function
        submenuItems2[int(choice)].values()[0]()
    except (ValueError, IndexError):
        pass

def flag_header(selection):
    header_flagged.append(header_count.keys()[selection])
    print colorize("Header Flagged!", 'red')

def build_profile():
    # Get Density Report: Print range of memory frequent headers
    rp = open(sys.argv[1] + "_report.txt", "w")

    # Write heading
    rp.write("BinView v0.1 Report\n"
            "File: " + sys.argv[1] + "\n\n")

    # Write Flagged Headers
    rp.write("[Flagged Headers]\n\n")
    for entry in header_flagged:
            rp.write("*" + entry + "\n")

    # Write total identified headers
    rp.write("\n\n[Identified Headers]\n\n")
    for entry in header_count.keys():
            rp.write(entry + "\n")

menuItems = [
    {"Analyze File": analyze},
    {"Show Results": show_results},
    {"Build Profile": build_profile},
    {"Exit": exit},
]


def main():
    while True:
        os.system('clear')
        print colorize(header, 'blue')
        print colorize('version 0.1\n', 'green')
        for item in menuItems:
            print colorize("[" + str(menuItems.index(item)) + "] ", 'blue') + item.keys()[0]
        choice = raw_input("(binview)$ ")
        try:
            if int(choice) < 0: raise ValueError
            # Call the matching function
            menuItems[int(choice)].values()[0]()
        except (ValueError, IndexError):
            pass


if __name__ == "__main__":
    main()