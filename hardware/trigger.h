/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

#ifndef TRIGGER_H
#define TRIGGER_H

#include <iostream>
#include <windows.h>
#include <dbt.h>
#include <initguid.h>
#include <usbiodef.h>

typedef std::wstring cap_device;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
void start_usb_tracker();

#endif