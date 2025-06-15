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
    return ringDim * sizeof(uint64_t) * 2; // Estimación para esquema BGV
}

size_t getMemoryUsage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024;
    }
    return 0;
}


// CLASE SERVIDOR
class Server {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    PublicKey<DCRTPoly> publicKey;
    std::vector<std::vector<int64_t>> databaseMatrix;
    size_t originalSize;
    size_t paddedSize;
    size_t sqrtN;

    size_t calculatePaddedSize(size_t dbSize) {
        size_t s = static_cast<size_t>(std::ceil(std::sqrt(dbSize)));
        return s * s;
    }

public:
    Server(size_t dbSize, CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk) 
        : cryptoContext(cc), publicKey(pk), originalSize(dbSize) {
        
        paddedSize = calculatePaddedSize(dbSize);
        sqrtN = static_cast<size_t>(std::sqrt(paddedSize));

        databaseMatrix.resize(sqrtN, std::vector<int64_t>(sqrtN, 0));
        
        for (size_t i = 0; i < dbSize; ++i) {
            size_t row = i / sqrtN;
            size_t col = i % sqrtN;
            databaseMatrix[row][col] = static_cast<int64_t>((i + 1) * 10);
        }
    }

    std::pair<Ciphertext<DCRTPoly>, size_t> processQuery(
        const std::vector<Ciphertext<DCRTPoly>>& rowSelector,
        const std::vector<Ciphertext<DCRTPoly>>& colSelector,
        size_t& querySize) {
        
        querySize = 0;
        for (const auto& ct : rowSelector) querySize += estimateCiphertextSize(ct);
        for (const auto& ct : colSelector) querySize += estimateCiphertextSize(ct);

        auto zeroPlain = cryptoContext->MakePackedPlaintext({0});
        auto result = cryptoContext->Encrypt(publicKey, zeroPlain);
        
        for (size_t i = 0; i < sqrtN; ++i) {
            for (size_t j = 0; j < sqrtN; ++j) {
                auto selectorProduct = cryptoContext->EvalMult(rowSelector[i], colSelector[j]);
                auto dbValuePlain = cryptoContext->MakePackedPlaintext({databaseMatrix[i][j]});
                auto term = cryptoContext->EvalMult(selectorProduct, dbValuePlain);
                result = cryptoContext->EvalAdd(result, term);
            }
        }

        return {result, estimateCiphertextSize(result)};
    }

    void displayDatabaseInfo() const {
        std::cout << "[SERVIDOR] Base de datos (" << sqrtN << "x" << sqrtN << ")\n";
        std::cout << "  - Tamaño original: " << originalSize << "\n";
        std::cout << "  - Tamaño con padding: " << paddedSize << "\n";
        std::cout << "  - Primeros valores: ";
        for (size_t i = 0; i < std::min(originalSize, size_t(5)); ++i) {
            std::cout << databaseMatrix[i/sqrtN][i%sqrtN] << " ";
        }
        if (originalSize > 5) std::cout << "...";
        std::cout << "\n";
    }

    int64_t getExpectedValue(size_t index) const {
        if (index >= originalSize) return 0;
        size_t i = index / sqrtN;
        size_t j = index % sqrtN;
        return databaseMatrix[i][j];
    }
};

// CLASE CLIENTE
class Client {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    KeyPair<DCRTPoly> keyPair;
    size_t originalSize;
    size_t paddedSize;
    size_t sqrtN;

    size_t calculatePaddedSize(size_t dbSize) {
        size_t s = static_cast<size_t>(std::ceil(std::sqrt(dbSize)));
        return s * s;
    }

public:
    Client(size_t dbSize) : originalSize(dbSize) {
        paddedSize = calculatePaddedSize(dbSize);
        sqrtN = static_cast<size_t>(std::sqrt(paddedSize));

        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetMultiplicativeDepth(2);
        parameters.SetPlaintextModulus(4293918721);
        parameters.SetRingDim(1<<14); 
        parameters.SetSecurityLevel(HEStd_128_classic);
        
        cryptoContext = GenCryptoContext(parameters);
        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);
        cryptoContext->Enable(ADVANCEDSHE);
    }

    void generateKeys() {
        keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeyGen(keyPair.secretKey);
        
        std::vector<int32_t> indices;
        for (int32_t i = 1; i <= static_cast<int32_t>(sqrtN); i <<= 1) {
            indices.push_back(i);
        }
        cryptoContext->EvalRotateKeyGen(keyPair.secretKey, indices);
    }

    std::pair<std::vector<Ciphertext<DCRTPoly>>, std::vector<Ciphertext<DCRTPoly>>> 
    createQuery(size_t index, size_t& querySize) {
        if (index >= originalSize) {
            throw std::out_of_range("Índice fuera del rango de datos originales");
        }

        size_t rowIdx = index / sqrtN;
        size_t colIdx = index % sqrtN;

        std::vector<Ciphertext<DCRTPoly>> encryptedRowSelector;
        std::vector<Ciphertext<DCRTPoly>> encryptedColSelector;

        // Selector de fila
        for (size_t i = 0; i < sqrtN; ++i) {
            int64_t value = (i == rowIdx) ? 1 : 0;
            auto plaintext = cryptoContext->MakePackedPlaintext({value});
            encryptedRowSelector.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
        }

        // Selector de columna
        for (size_t j = 0; j < sqrtN; ++j) {
            int64_t value = (j == colIdx) ? 1 : 0;
            auto plaintext = cryptoContext->MakePackedPlaintext({value});
            encryptedColSelector.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
        }

        querySize = 0;
        for (const auto& ct : encryptedRowSelector) querySize += estimateCiphertextSize(ct);
        for (const auto& ct : encryptedColSelector) querySize += estimateCiphertextSize(ct);

        return {encryptedRowSelector, encryptedColSelector};
    }

    int64_t decryptResult(const Ciphertext<DCRTPoly>& encryptedResult) {
        Plaintext decrypted;
        cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &decrypted);
        decrypted->SetLength(1);
        return decrypted->GetPackedValue()[0];
    }

    CryptoContext<DCRTPoly> getCryptoContext() const { return cryptoContext; }
    PublicKey<DCRTPoly> getPublicKey() const { return keyPair.publicKey; }
    size_t getOriginalSize() const { return originalSize; }
};

// PROGRAMA PRINCIPAL
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
    
    Client client(dbSize);
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
    std::cout << "\n[CLIENTE] Índice a recuperar (0 - " << client.getOriginalSize() - 1 << "): ";
    std::cin >> queryIndex;

    if (queryIndex >= client.getOriginalSize()) {
        std::cerr << "Error: índice fuera de rango\n";
        return 1;
    }

    auto queryStart = std::chrono::high_resolution_clock::now();
    auto [rowSelectors, colSelectors] = client.createQuery(queryIndex, querySizeBytes);
    auto queryEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Consulta creada en " 
              << std::chrono::duration<double>(queryEnd - queryStart).count() << " segundos" << std::endl;

    // PROCESAMIENTO
    std::cout << "\n[SERVIDOR] Procesando consulta..." << std::endl;
    auto processStart = std::chrono::high_resolution_clock::now();
    
    auto [encryptedResult, responseSize] = server.processQuery(rowSelectors, colSelectors, querySizeBytes);
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
    std::cout << "  - Consulta (Cliente→Servidor): " << querySizeBytes << " bytes" << std::endl;
    std::cout << "  - Respuesta (Servidor→Cliente): " << responseSizeBytes << " bytes" << std::endl;
    std::cout << "  - Total: " << (querySizeBytes + responseSizeBytes) << " bytes" << std::endl;
    std::cout << "  - Bytes por elemento: " 
              << (querySizeBytes + responseSizeBytes) / client.getOriginalSize() << " bytes/elem" << std::endl;

    std::cout << "\nUso de memoria actual: " << getMemoryUsage() << " KB" << std::endl;

    return 0;
}