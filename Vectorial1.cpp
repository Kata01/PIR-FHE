#include <openfhe.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <windows.h>
#include <psapi.h>
#include <cmath>

using namespace lbcrypto;

// Función para estimar tamaño de cifrado
size_t estimateCiphertextSize(const Ciphertext<DCRTPoly>& ciphertext) {
    size_t ringDim = ciphertext->GetCryptoContext()->GetRingDimension();
    return ringDim * sizeof(uint64_t) * 2; // Estimación conservadora
}

size_t getMemoryUsage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024;
    }
    return 0;
}

class Server {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    PublicKey<DCRTPoly> publicKey;
    std::vector<int64_t> database;  // Base de datos en texto claro
    size_t dbSize;

public:
    Server(size_t size, CryptoContext<DCRTPoly> cc, const PublicKey<DCRTPoly>& pk) 
        : cryptoContext(cc), publicKey(pk), dbSize(size) {
        
        // Inicializar la base de datos con valores simples (10, 20, 30...)
        database.resize(dbSize);
        for (size_t i = 0; i < dbSize; ++i) {
            database[i] = static_cast<int64_t>((i + 1) * 10);
        }
    }

    std::pair<Ciphertext<DCRTPoly>, size_t> processQuery(
        const std::vector<Ciphertext<DCRTPoly>>& query, 
        size_t& querySize) {
        
        // Calcular tamaño total de la consulta
        querySize = 0;
        for (const auto& ct : query) {
            querySize += estimateCiphertextSize(ct);
        }

        // Inicializar resultado con un ciphertext de cero
        auto zeroPlaintext = cryptoContext->MakePackedPlaintext({0});
        Ciphertext<DCRTPoly> result = cryptoContext->Encrypt(publicKey, zeroPlaintext);

        // Procesar la consulta: multiplicación punto a punto y suma
        for (size_t i = 0; i < dbSize; ++i) {
            // Convertir el valor de la base de datos a plaintext
            auto dbPlaintext = cryptoContext->MakePackedPlaintext({database[i]});
            // Multiplicar el elemento de la consulta cifrado con el plaintext de la base de datos
            auto product = cryptoContext->EvalMult(query[i], dbPlaintext);
            // Acumular el resultado
            result = cryptoContext->EvalAdd(result, product);
        }

        return {result, estimateCiphertextSize(result)};
    }

    void displayDatabaseInfo() const {
        std::cout << "[SERVIDOR] Base de datos con " << dbSize << " elementos (en claro)\n";
        std::cout << "  - Primeros valores: ";
        for (size_t i = 0; i < std::min(dbSize, size_t(5)); ++i) {
            std::cout << database[i] << " ";
        }
        if (dbSize > 5) std::cout << "...";
        std::cout << "\n";
    }

    int64_t getExpectedValue(size_t index) const {
        if (index >= dbSize) return 0;
        return database[index];
    }
};

class Client {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    KeyPair<DCRTPoly> keyPair;

public:
    Client() {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetMultiplicativeDepth(1);
        parameters.SetPlaintextModulus(4293918721);
        parameters.SetRingDim(1<<14);
        parameters.SetSecurityLevel(HEStd_128_classic);
        
        cryptoContext = GenCryptoContext(parameters);
        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);
    }

    void generateKeys() {
        keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    }

    std::pair<std::vector<Ciphertext<DCRTPoly>>, size_t> createQuery(size_t queryIndex, size_t dbSize) {
        if (queryIndex >= dbSize) {
            throw std::out_of_range("Índice fuera de rango");
        }

        std::vector<Ciphertext<DCRTPoly>> query;
        query.reserve(dbSize);

        // Crear vector de consulta con un 1 en la posición deseada
        for (size_t i = 0; i < dbSize; ++i) {
            int64_t value = (i == queryIndex) ? 1 : 0;
            auto plaintext = cryptoContext->MakePackedPlaintext({value});
            query.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
        }

        // Calcular tamaño total de la consulta
        size_t querySize = 0;
        for (const auto& ct : query) {
            querySize += estimateCiphertextSize(ct);
        }

        return {query, querySize};
    }

    int64_t decryptResult(const Ciphertext<DCRTPoly>& encryptedResult) {
        Plaintext decrypted;
        cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &decrypted);
        decrypted->SetLength(1);
        return decrypted->GetPackedValue()[0];
    }

    CryptoContext<DCRTPoly> getCryptoContext() const { return cryptoContext; }
    PublicKey<DCRTPoly> getPublicKey() const { return keyPair.publicKey; }
};

int main() {
    size_t dbSize;
    std::cout << "Tamaño de la base de datos: ";
    std::cin >> dbSize;

    if (dbSize == 0) {
        std::cerr << "Error: tamaño inválido" << std::endl;
        return 1;
    }

    // Variables para medición
    size_t querySizeBytes = 0;
    size_t responseSizeBytes = 0;

    // CLIENTE
    std::cout << "\n[CLIENTE] Configurando contexto criptográfico..." << std::endl;
    auto clientStart = std::chrono::high_resolution_clock::now();
    
    Client client;
    client.generateKeys();
    
    auto clientEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Configuración completada en " 
              << std::chrono::duration<double>(clientEnd - clientStart).count() << " segundos" << std::endl;

    // SERVIDOR
    std::cout << "\n[SERVIDOR] Inicializando base de datos..." << std::endl;
    auto serverStart = std::chrono::high_resolution_clock::now();
    
    Server server(dbSize, client.getCryptoContext(), client.getPublicKey());
    server.displayDatabaseInfo();
    
    auto serverEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[SERVIDOR] Base de datos inicializada en "
              << std::chrono::duration<double>(serverEnd - serverStart).count() << " segundos" << std::endl;

    // CONSULTA
    size_t queryIndex;
    std::cout << "\n[CLIENTE] Índice a recuperar (0 - " << dbSize - 1 << "): ";
    std::cin >> queryIndex;

    if (queryIndex >= dbSize) {
        std::cerr << "Error: índice fuera de rango\n";
        return 1;
    }

    auto queryStart = std::chrono::high_resolution_clock::now();
    auto [queryVector, querySize] = client.createQuery(queryIndex, dbSize);
    querySizeBytes = querySize;
    auto queryEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Consulta creada en " 
              << std::chrono::duration<double>(queryEnd - queryStart).count() << " segundos" << std::endl;

    // PROCESAMIENTO
    std::cout << "\n[SERVIDOR] Procesando consulta..." << std::endl;
    auto processStart = std::chrono::high_resolution_clock::now();
    
    auto [encryptedResult, responseSize] = server.processQuery(queryVector, querySizeBytes);
    responseSizeBytes = responseSize;
    
    auto processEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[SERVIDOR] Consulta procesada en " 
              << std::chrono::duration<double>(processEnd - processStart).count() << " segundos" << std::endl;

    // RESULTADO
    std::cout << "\n[CLIENTE] Desencriptando resultado..." << std::endl;
    auto decryptStart = std::chrono::high_resolution_clock::now();
    
    int64_t result = client.decryptResult(encryptedResult);
    int64_t expected = server.getExpectedValue(queryIndex);
    
    auto decryptEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Resultado desencriptado en " 
              << std::chrono::duration<double>(decryptEnd - decryptStart).count() << " segundos" << std::endl;

    // RESULTADOS
    std::cout << "\n=== Resultados ===" << std::endl;
    std::cout << "Índice solicitado: " << queryIndex << std::endl;
    std::cout << "Valor recuperado: " << result << std::endl;
    std::cout << "Valor esperado: " << expected << std::endl;
    std::cout << (result == expected ? "ÉXITO: Coincide" : "FALLO: No coincide") << std::endl;

    std::cout << "\n=== Estadísticas ===" << std::endl;
    std::cout << "Comunicación:" << std::endl;
    std::cout << "  - Consulta (Cliente→Servidor): " << querySizeBytes << " bytes (" 
              << dbSize << " cifrados)" << std::endl;
    std::cout << "  - Respuesta (Servidor→Cliente): " << responseSizeBytes << " bytes" << std::endl;
    std::cout << "  - Total: " << (querySizeBytes + responseSizeBytes) << " bytes" << std::endl;

    std::cout << "\nUso de memoria actual: " << getMemoryUsage() << " KB" << std::endl;

    return 0;
}