/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

//  Progress render

#ifndef PROGRESS_DISPLAY_H
#define PROGRESS_DISPLAY_H

#include <iostream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

class ProgressDisplay {
public:
    explicit ProgressDisplay(std::string label, int width = 45)
        : label_(std::move(label)), width_(width) {
        enable_virtual_terminal();
        std::cout << "\n";
        redraw_bar();
    }

    ProgressDisplay(const ProgressDisplay&) = delete;
    ProgressDisplay& operator=(const ProgressDisplay&) = delete;

    void set_file(const std::string& filename) {
        std::cout << "\033[1A\r\033[K" << filename << "\n";
        redraw_bar();
    }

    void set_progress(int percent) {
        last_percent_ = percent;
        redraw_bar();
    }

    void reset() {
        last_percent_ = 0;
        redraw_bar();
    }

    void finish() {
        std::cout << "\n";
    }

private:
    void redraw_bar() {
        int filled = last_percent_ * width_ / 100;
        if (filled > width_) filled = width_;

        std::cout << "\r\033[K" << label_ << ": ["
                   << std::string(static_cast<size_t>(filled), '#')
                   << std::string(static_cast<size_t>(width_ - filled), ' ')
                   << "] " << last_percent_ << "%" << std::flush;
    }

    static void enable_virtual_terminal() {
#ifdef _WIN32
        HANDLE h_out = GetStdHandle(STD_OUTPUT_HANDLE);
        if (h_out == INVALID_HANDLE_VALUE) return;

        DWORD mode = 0;
        if (!GetConsoleMode(h_out, &mode)) return;

        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(h_out, mode);
#endif
    }

    std::string label_;
    int width_;
    int last_percent_ = 0;
};

#endif // PROGRESS_DISPLAY_H