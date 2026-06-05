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