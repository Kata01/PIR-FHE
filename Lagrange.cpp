#include <openfhe.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <stdexcept>
#include <algorithm>
#include <windows.h>
#include <psapi.h>
#include <complex>
#include <cmath>
#include <iomanip>
#include <sstream>

using namespace lbcrypto;

// Función para obtener uso memoria
size_t getMemoryUsage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024;
    }
    return 0;
}

// CLASE CLIENTE
class LagrangeClient {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    KeyPair<DCRTPoly> keyPair;
    
public:
    void initialize() {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(24);
        parameters.SetScalingModSize(50);
        parameters.SetRingDim(1<<18);
        parameters.SetBatchSize(64);
        parameters.SetScalingTechnique(FLEXIBLEAUTO);
        parameters.SetSecurityLevel(HEStd_128_classic);
        parameters.SetNumLargeDigits(3);

        cryptoContext = GenCryptoContext(parameters);
        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);
    }
    
    void generateKeys() {
        keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    }
    
    Ciphertext<DCRTPoly> encryptTimestamp(double timestamp) const {
        std::vector<double> timestampVec = {timestamp};
        Plaintext ptTimestamp = cryptoContext->MakeCKKSPackedPlaintext(timestampVec);
        return cryptoContext->Encrypt(keyPair.publicKey, ptTimestamp);
    }
    
    double decryptResult(const Ciphertext<DCRTPoly>& encryptedResult) const {
        Plaintext decryptedResult;
        cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &decryptedResult);
        decryptedResult->SetLength(1);
        return decryptedResult->GetRealPackedValue()[0];
    }
    
    CryptoContext<DCRTPoly> getCryptoContext() const { return cryptoContext; }
    PublicKey<DCRTPoly> getPublicKey() const { return keyPair.publicKey; }
    
    static double timeStringToHours(const std::string& timeStr) {
        int hours, minutes, seconds;
        char colon;
        std::istringstream iss(timeStr);
        
        if (!(iss >> hours >> colon >> minutes >> colon >> seconds) || colon != ':') {
            throw std::runtime_error("Formato de tiempo inválido. Use HH:MM:SS");
        }
        
        if (hours < 0 || hours > 23 || minutes < 0 || minutes > 59 || seconds < 0 || seconds > 59) {
            throw std::runtime_error("Tiempo fuera de rango. Use HH:00-23:MM:00-59:SS:00-59");
        }
        
        return hours + (minutes / 60.0) + (seconds / 3600.0);
    }
    
    static std::string hoursToTimeString(double hours) {
        int totalSeconds = static_cast<int>(hours * 3600);
        int h = totalSeconds / 3600;
        int m = (totalSeconds % 3600) / 60;
        int s = totalSeconds % 60;
        
        std::ostringstream oss;
        oss << std::setfill('0') << std::setw(2) << h << ":"
            << std::setfill('0') << std::setw(2) << m << ":"
            << std::setfill('0') << std::setw(2) << s;
        return oss.str();
    }
};

// CLASE SERVIDOR
class LagrangeServer {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    std::vector<double> temperatures;
    std::vector<double> timestamps;
    std::vector<std::string> timestampStrings;
    
public:
    LagrangeServer(CryptoContext<DCRTPoly> cc, size_t dataPoints) : cryptoContext(cc) {
        // Generar datos de ejemplo (hora por hora)
        temperatures.resize(dataPoints);
        timestamps.resize(dataPoints);
        timestampStrings.resize(dataPoints);
        
        for (size_t i = 0; i < dataPoints; i++) {
            int totalSeconds = i * 3600;
            int h = totalSeconds / 3600;
            int m = (totalSeconds % 3600) / 60;
            int s = totalSeconds % 60;
            
            std::ostringstream oss;
            oss << std::setfill('0') << std::setw(2) << h << ":"
                << std::setfill('0') << std::setw(2) << m << ":"
                << std::setfill('0') << std::setw(2) << s;
            
            timestampStrings[i] = oss.str();
            timestamps[i] = h + (m / 60.0) + (s / 3600.0);
            temperatures[i] = 20.0 + 10.0 * sin(i * 0.5);
        }
    }
    
    Ciphertext<DCRTPoly> computeInterpolation(const Ciphertext<DCRTPoly>& encryptedTimestamp, 
                                            const PublicKey<DCRTPoly>& publicKey) const {
        // Precalcular denominadores
        std::vector<double> denominators(timestamps.size(), 1.0);
        for (size_t j = 0; j < timestamps.size(); j++) {
            for (size_t i = 0; i < timestamps.size(); i++) {
                if (i != j) denominators[j] *= (timestamps[j] - timestamps[i]);
            }
        }

        auto encryptedResult = cryptoContext->Encrypt(publicKey, 
            cryptoContext->MakeCKKSPackedPlaintext(std::vector<double>{0.0}));
        
        for (size_t j = 0; j < temperatures.size(); j++) {
            try {
                // Calcular numerador
                auto numerator = cryptoContext->Encrypt(publicKey, 
                    cryptoContext->MakeCKKSPackedPlaintext(std::vector<double>{1.0}));
                
                for (size_t i = 0; i < timestamps.size(); i++) {
                    if (i == j) continue;
                    auto term = cryptoContext->EvalSub(
                        encryptedTimestamp,
                        cryptoContext->MakeCKKSPackedPlaintext(std::vector<double>{timestamps[i]})
                    );
                    numerator = cryptoContext->EvalMultAndRelinearize(numerator, term);
                }
                
                numerator = cryptoContext->Rescale(numerator);
                
                // Calcular coeficiente
                double coeff = temperatures[j] / denominators[j];
                auto plainCoeff = cryptoContext->MakeCKKSPackedPlaintext(std::vector<double>{coeff});
                
                // Multiplicar y sumar
                auto term = cryptoContext->EvalMult(numerator, plainCoeff);
                term = cryptoContext->Rescale(term);
                encryptedResult = cryptoContext->EvalAdd(encryptedResult, term);
                
            } catch (const std::exception& e) {
                std::cerr << "Error en timestamp " << timestamps[j] << ": " << e.what() << std::endl;
                throw;
            }
        }
        
        return encryptedResult;
    }
    
    void displayData() const {
        std::cout << "\nDatos de temperatura (primeros 10 puntos):" << std::endl;
        std::cout << "Timestamp\tTemperatura (C)" << std::endl;
        for (size_t i = 0; i < std::min<size_t>(10, temperatures.size()); i++) {
            std::cout << timestampStrings[i] << "\t" << temperatures[i] << std::endl;
        }
    }
    
    bool validateTimestamp(double timestamp) const {
        return timestamp >= timestamps.front() && timestamp <= timestamps.back();
    }
    
    double computeExpectedResult(double timestamp) const {
        double expectedTemp = 0.0;
        for (size_t j = 0; j < temperatures.size(); j++) {
            double term = temperatures[j];
            for (size_t i = 0; i < timestamps.size(); i++) {
                if (i != j) {
                    term *= (timestamp - timestamps[i]) / (timestamps[j] - timestamps[i]);
                }
            }
            expectedTemp += term;
        }
        return expectedTemp;
    }
};

// PROGRAMA PRINCIPAL
int main() {
    std::cout << "Uso de memoria inicial: " << getMemoryUsage() << " KB" << std::endl;

    // CONFIGURACIÓN CLIENTE
    std::cout << "\n[CLIENTE] Inicializando..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    LagrangeClient client;
    client.initialize();
    client.generateKeys();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "[CLIENTE] Configuración completada. Tiempo: " << elapsed.count() 
              << " segundos. Memoria: " << getMemoryUsage() << " KB" << std::endl;

    // CONFIGURACIÓN SERVIDOR
    size_t dataPoints;
    std::cout << "\n[SERVIDOR] Número de puntos de datos de temperatura (Entre 1 y 24): ";
    std::cin >> dataPoints;
    
    std::cout << "[SERVIDOR] Inicializando base de datos..." << std::endl;
    start = std::chrono::high_resolution_clock::now();
    LagrangeServer server(client.getCryptoContext(), dataPoints);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "[SERVIDOR] Base de datos creada. Tiempo: " << elapsed.count() 
              << " segundos. Memoria: " << getMemoryUsage() << " KB" << std::endl;
    
    server.displayData();

    // CONSULTA CLIENTE
    std::string queryTimeStr;
    std::cout << "\n[CLIENTE] Timestamp para consulta (formato HH:MM:SS): ";
    std::cin >> queryTimeStr;

    double queryTimestamp;
    try {
        queryTimestamp = LagrangeClient::timeStringToHours(queryTimeStr);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    if (!server.validateTimestamp(queryTimestamp)) {
        std::cerr << "Error: El timestamp está fuera del rango de datos" << std::endl;
        return 1;
    }

    // PROCESAMIENTO SERVIDOR
    std::cout << "\n[CLIENTE] Cifrando timestamp..." << std::endl;
    start = std::chrono::high_resolution_clock::now();
    auto encryptedTimestamp = client.encryptTimestamp(queryTimestamp);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "[CLIENTE] Timestamp cifrado. Tiempo: " << elapsed.count() 
              << " segundos. Memoria: " << getMemoryUsage() << " KB" << std::endl;

    std::cout << "\n[SERVIDOR] Computando interpolación..." << std::endl;
    start = std::chrono::high_resolution_clock::now();
    auto encryptedResult = server.computeInterpolation(encryptedTimestamp, client.getPublicKey());
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "[SERVIDOR] Interpolación completada. Tiempo: " << elapsed.count() 
              << " segundos. Memoria: " << getMemoryUsage() << " KB" << std::endl;

    std::cout << "\n[CLIENTE] Descifrando resultado..." << std::endl;
    start = std::chrono::high_resolution_clock::now();
    double result = client.decryptResult(encryptedResult);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "[CLIENTE] Resultado descifrado. Tiempo: " << elapsed.count() 
              << " segundos. Memoria: " << getMemoryUsage() << " KB" << std::endl;

    // Resultados
    double expectedTemp = server.computeExpectedResult(queryTimestamp);
    
    std::cout << "\nResultados:" << std::endl;
    std::cout << "Timestamp consultado: " << queryTimeStr 
              << " (" << queryTimestamp << " horas)" << std::endl;
    std::cout << "Temperatura estimada (HE): " << result << " °C" << std::endl;
    std::cout << "Temperatura esperada: " << expectedTemp << " °C" << std::endl;
    std::cout << "Diferencia: " << std::abs(result - expectedTemp) << " °C" << std::endl;
    std::cout << "Uso de memoria final: " << getMemoryUsage() << " KB" << std::endl;

    return 0;
}