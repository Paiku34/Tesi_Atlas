#pragma once

#include <string>
#include <cstdint>
#include <cstddef>

namespace radio {

class SerialPort {
public:
    SerialPort();
    ~SerialPort();

    // Disabilita copia
    SerialPort(const SerialPort&) = delete;
    SerialPort& operator=(const SerialPort&) = delete;

    /**
     * @brief Apre la porta seriale configurando baud rate raw (default 57600 per RFD868+)
     * @param device Percorso del device, es. "/dev/ttyUSB0"
     * @param baudrate Velocità UART (default 57600)
     * @return true se apertura e configurazione hanno successo
     */
    bool open_device(const std::string& device, int baudrate = 57600);

    void close_device();
    bool is_open() const;

    /**
     * @brief Scrive un buffer di byte sulla seriale
     */
    bool write_exact(const uint8_t* data, size_t length);

    /**
     * @brief Legge esattamente `length` byte attendendo fino al timeout specificato
     * @param buffer Destinazione dati
     * @param length Numero di byte da leggere
     * @param timeout_ms Timeout massimo in millisecondi
     * @return true se tutti i byte richiesti sono stati letti entro il timeout
     */
    bool read_exact(uint8_t* buffer, size_t length, int timeout_ms);

    /**
     * @brief Legge 1 singolo byte con timeout (usato per cercare il Magic Byte)
     */
    bool read_byte(uint8_t& byte, int timeout_ms);

    /**
     * @brief Svuota i buffer FIFO della porta seriale (flush RX/TX)
     */
    void flush();

private:
    int fd_;
};

} // namespace radio
