#!/usr/bin/env python2.7
import os
import binwalk
import tabulate

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

# Offset Genre Dict
offsets = dict()


def colorize(string, color):
    if not color in colors: return string
    return colors[color] + string + '\033[0m'


def analyze():

    for module in binwalk.scan('firmware.apk',
                               signature=True,
                               quiet=True):

        print("%s Results:" % module.name)


        for result in module.results:
            key = result.description.split(',')[0]
            try:
                val = offsets[key]
                offsets[key] = val+1
            except:
               # print ("No such entry yet")
                offsets[key] = 1

            #print ("\t%s    0x%.8X    %s" % (result.file.name,
            #                                 result.offset,
             #                                result.description))

    raw_input("Press [Enter] to continue...")


def show_results():
    submenuItems1 = [
        {"List Offsets [#]": show_offsets},
        {"Dump All": show_offsets},
        {"Exit": exit},
    ]

    print(" {0:^10}  {1:^10}".format("Count", "Type"))
    print("-"*30)
    for k, v in offsets.items():
        print ("{0:^15} {1}".format(v, k))

    for item in submenuItems1:
        print colorize("[" + str(submenuItems1.index(item)) + "] ", 'blue') + item.keys()[0]
    choice = raw_input("(binview)$ ")
    try:
        if int(choice) < 0: raise ValueError
        # Call the matching function
        submenuItems1[int(choice)].values()[0]()
    except (ValueError, IndexError):
        pass

    #raw_input("Press [Enter] to continue...")



def show_offsets():
    submenuItems2 = [
        {"List Offsets [#]": analyze},
        {"Dump All": show_offsets},
        {"Exit": exit},
    ]

    for item in submenuItems2:
        print colorize("[" + str(submenuItems1.index(item)) + "] ", 'blue') + item.keys()[0]
    choice = raw_input("(binview)$ ")
    try:
        if int(choice) < 0: raise ValueError
        # Call the matching function
        submenuItems1[int(choice)].values()[0]()
    except (ValueError, IndexError):
        pass



menuItems = [
    {"Analyze File": analyze},
    {"Show Results": show_results},
    {"Build Profile": show_offsets},
    {"Exit": exit},
]


def main():
    while True:
        os.system('clear')
        # Print some badass ascii art header here !
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