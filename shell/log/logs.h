#ifndef LOGS_H
#define LOGS_H

#include <iostream>
#include <chrono>

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

class CryptoBenchmark {
private:
    std::chrono::high_resolution_clock::time_point session_start;
    std::chrono::high_resolution_clock::time_point region_start;

    std::chrono::duration<double> total_encrypt_time{0};
    uint64_t total_encrypted_bytes = 0;

public:
    CryptoBenchmark() {
        session_start = std::chrono::high_resolution_clock::now();
    }

    void start_crypt_region() {
        region_start = std::chrono::high_resolution_clock::now();
    }

    void end_crypt_region(size_t bytes_processed) {
        auto now = std::chrono::high_resolution_clock::now();
        total_encrypt_time += (now - region_start);
        total_encrypted_bytes += bytes_processed;
    }

    void print_session_report() const {
        auto session_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> total_session_time = session_end - session_start;

        double mb_per_sec = 0.0;
        if (total_encrypt_time.count() > 0.0) {
            mb_per_sec = (static_cast<double>(total_encrypted_bytes) / (1024.0 * 1024.0))
                         / total_encrypt_time.count();
        }

        std::cout << "\n" << "Total program time (s):     " << total_session_time.count() << "\n"
                   << "Time spent encrypting (s): " << total_encrypt_time.count() << "\n"
                   << "Cryption speed (MB/s):   " << mb_per_sec << "\n"
                   << "Bytes processed:         " << total_encrypted_bytes << "\n";
    }

    double session_seconds() const {
        return std::chrono::duration<double>(
            std::chrono::high_resolution_clock::now() - session_start).count();
    }
    double encrypt_seconds() const { return total_encrypt_time.count(); }
    uint64_t bytes_encrypted() const { return total_encrypted_bytes; }
};

inline Logger_W log_w;
inline Logger logg;

#endif