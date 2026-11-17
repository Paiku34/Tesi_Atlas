#include "serial_port.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <poll.h>
#include <iostream>
#include <chrono>
#include <cstring>

namespace radio {

SerialPort::SerialPort() : fd_(-1) {}

SerialPort::~SerialPort() {
    close_device();
}

bool SerialPort::open_device(const std::string& device, int baudrate) {
    close_device();

    // Apertura non-bloccante, no controllo tty
    fd_ = open(device.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd_ < 0) {
        std::cerr << "[SerialPort] Errore apertura dispositivo " << device << ": " << strerror(errno) << std::endl;
        return false;
    }

    struct termios tty;
    std::memset(&tty, 0, sizeof(tty));
    if (tcgetattr(fd_, &tty) != 0) {
        std::cerr << "[SerialPort] Errore tcgetattr: " << strerror(errno) << std::endl;
        close_device();
        return false;
    }

    // Configura baud rate
    speed_t speed = B57600;
    switch (baudrate) {
        case 9600:   speed = B9600; break;
        case 19200:  speed = B19200; break;
        case 38400:  speed = B38400; break;
        case 57600:  speed = B57600; break;
        case 115200: speed = B115200; break;
        default:
            std::cerr << "[SerialPort] Baudrate non standard " << baudrate << ", uso 57600" << std::endl;
            speed = B57600;
            break;
    }
    cfsetospeed(&tty, speed);
    cfsetispeed(&tty, speed);

    // Modalità Raw a 8-N-1 (8 data bits, no parity, 1 stop bit)
    tty.c_cflag &= ~PARENB;        // No parità
    tty.c_cflag &= ~CSTOPB;        // 1 Stop bit
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;            // 8 bit
    tty.c_cflag &= ~CRTSCTS;       // No hardware flow control (RFD868+ in standard usa 3-wire RX/TX/GND)
    tty.c_cflag |= CREAD | CLOCAL; // Abilita ricevitore, ignora linee di controllo modem

    // Disabilita processing input/output (RAW byte stream)
    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~(IXON | IXOFF | IXANY); // No software flow control
    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);
    tty.c_oflag &= ~OPOST; // No output processing

    // Timeout e lettura non bloccante nativa (gestito da poll)
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 0;

    if (tcsetattr(fd_, TCSANOW, &tty) != 0) {
        std::cerr << "[SerialPort] Errore tcsetattr: " << strerror(errno) << std::endl;
        close_device();
        return false;
    }

    // Rimuove flag O_NONBLOCK per usare poll() in modo controllato
    int flags = fcntl(fd_, F_GETFL, 0);
    fcntl(fd_, F_SETFL, flags & ~O_NONBLOCK);

    flush();
    return true;
}

void SerialPort::close_device() {
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
}

bool SerialPort::is_open() const {
    return fd_ >= 0;
}

void SerialPort::flush() {
    if (fd_ >= 0) {
        tcflush(fd_, TCIOFLUSH);
    }
}

bool SerialPort::write_exact(const uint8_t* data, size_t length) {
    if (fd_ < 0) return false;

    size_t total_written = 0;
    while (total_written < length) {
        ssize_t written = write(fd_, data + total_written, length - total_written);
        if (written < 0) {
            if (errno == EINTR) continue;
            std::cerr << "[SerialPort] Errore write: " << strerror(errno) << std::endl;
            return false;
        }
        total_written += written;
    }
    return true;
}

bool SerialPort::read_exact(uint8_t* buffer, size_t length, int timeout_ms) {
    if (fd_ < 0) return false;

    size_t total_read = 0;
    auto start_time = std::chrono::steady_clock::now();

    while (total_read < length) {
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time).count();
        int remaining_ms = timeout_ms - static_cast<int>(elapsed_ms);
        if (remaining_ms <= 0) {
            return false; // Timeout scaduto prima di leggere tutti i byte
        }

        struct pollfd pfd;
        pfd.fd = fd_;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, remaining_ms);
        if (ret < 0) {
            if (errno == EINTR) continue;
            return false;
        } else if (ret == 0) {
            return false; // Timeout
        }

        if (pfd.revents & POLLIN) {
            ssize_t bytes_read = read(fd_, buffer + total_read, length - total_read);
            if (bytes_read < 0) {
                if (errno == EINTR) continue;
                return false;
            } else if (bytes_read == 0) {
                return false; // EOF inatteso
            }
            total_read += bytes_read;
        }
    }
    return true;
}

bool SerialPort::read_byte(uint8_t& byte, int timeout_ms) {
    return read_exact(&byte, 1, timeout_ms);
}

} // namespace radio
