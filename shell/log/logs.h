#ifndef LOGS_H
#define LOGS_H

#include <iostream>

typedef const std::wstring c_wstr;
typedef const std::string c_str;

enum class LogLevel { DEBUG, INFO, SUCCESS, WARNING, ERR };

struct Logger_W {
private:
    const wchar_t* prefix(LogLevel level){
        switch (level) {
            case LogLevel::DEBUG: return L"[DEBUG] ";
            case LogLevel::INFO: return L"[INFO] ";
            case LogLevel::SUCCESS: return L"[SUCCESS] ";
            case LogLevel::WARNING: return L"[WARNING] ";
            case LogLevel::ERR: return L"[ERROR] ";
            default: return L"[?] ";
        }
    }

    void log(LogLevel lvl, const c_wstr& msg) {
        std::wcout << prefix(lvl) << msg << L"\n";
    }
public:
    void debug(c_wstr& msg) { log(LogLevel::DEBUG,msg); }
    void info(c_wstr& msg) { log(LogLevel::INFO,msg); }
    void success(c_wstr& msg) { log(LogLevel::SUCCESS,msg); }
    void warning(c_wstr& msg) { log(LogLevel::WARNING,msg); }
    void error(c_wstr& msg) { log(LogLevel::ERR,msg); }
};

struct Logger {
private:
    const char* prefix(LogLevel lvl) {
        switch(lvl) {
            case LogLevel::DEBUG: return "[DEBUG] ";
            case LogLevel::INFO: return "[INFO] ";
            case LogLevel::SUCCESS: return "[SUCCESS] ";
            case LogLevel::WARNING: return "[WARNING] ";
            case LogLevel::ERR: return "[ERROR] ";
            default: return "[?] ";
        }
    }
    void log(LogLevel lvl, c_str msg){
        std::cout<<prefix(lvl) << msg <<"\n";
    }
public:
    void debug(c_str& msg) { log(LogLevel::DEBUG, msg); }
    void info(c_str& msg) { log(LogLevel::INFO, msg); }
    void success(c_str& msg) { log(LogLevel::SUCCESS, msg); }
    void warning(c_str& msg) { log(LogLevel::WARNING, msg); }
    void error(c_str& msg) { log(LogLevel::ERR, msg); }
};

inline Logger_W log_w;
inline Logger logg;

#endif