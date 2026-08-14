/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

// Implementation of the USB trigger concept 

#include "trigger.h"
#include "../shell/log/logs.h"

cap_device device;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch(msg) {
        case WM_DEVICECHANGE:
            switch(wp) {
                case DBT_DEVICEARRIVAL: {
                    if(!device.empty()) break;

                    DEV_BROADCAST_DEVICEINTERFACE_W* info = (DEV_BROADCAST_DEVICEINTERFACE_W*)lp;
                    if (info->dbcc_devicetype != DBT_DEVTYP_DEVICEINTERFACE) break;
                    device = info->dbcc_name;
                    log_w.success(L"Captured: " + device);
                    log_w.info(L"Listening...");
                    break;
                }
                case DBT_DEVICEREMOVECOMPLETE: {
                    DEV_BROADCAST_DEVICEINTERFACE_W* info = (DEV_BROADCAST_DEVICEINTERFACE_W*)lp;
                    if (info->dbcc_devicetype != DBT_DEVTYP_DEVICEINTERFACE) break;
                    
                    if (device == info->dbcc_name) {
                        device.clear();
                        log_w.info(L"Device removed: " + device);
                        system("shutdown /s /t 0");
                    }
                    break;
                }
            }
            break;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

void start_usb_tracker() {
    WNDCLASSW wc = {};
    HINSTANCE hInstance = GetModuleHandle(NULL);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"BitmaskHidden";
    RegisterClassW(&wc);
    
    HWND hwnd = CreateWindowW(L"BitmaskHidden", L"", 0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);
    DEV_BROADCAST_DEVICEINTERFACE_W dbdi = {};
    dbdi.dbcc_size = sizeof(dbdi);
    dbdi.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    dbdi.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;

    HDEVNOTIFY notify = RegisterDeviceNotificationW(hwnd, &dbdi, DEVICE_NOTIFY_WINDOW_HANDLE | DEVICE_NOTIFY_ALL_INTERFACE_CLASSES);
    
    if (notify == NULL) {
        log_w.error(L"Failed: " + GetLastError());
        return;
    }
    
    log_w.info(L"Connect USB Device...");
    
    MSG msg;
    while(GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

int main() {
    start_usb_tracker();
    return 0;
}