#!/usr/bin/env python2.7
import os
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
}

# Artifact Count/Offset Dicts
header_count = dict()
header_offsets = defaultdict(list)


def colorize(string, color):
    if not color in colors: return string
    return colors[color] + string + '\033[0m'


def analyze():

    for module in binwalk.scan('firmware.apk',
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
    submenuItems1 = [
        {"List Offsets [#]": show_offsets},
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



#def build_profile():
    # Get Density Report: Print range of memory frequent headers


menuItems = [
    {"Analyze File": analyze},
    {"Show Results": show_results},
    {"Build Profile": show_results},#build_profile},
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