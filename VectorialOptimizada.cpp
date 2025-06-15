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
    return ringDim * sizeof(uint64_t) * 2; 

size_t getMemoryUsage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024;
    }
    return 0;
}

// SERVIDOR
class Server {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    std::vector<int64_t> database;
    Plaintext packedDatabase;

public:
    Server(size_t dbSize, CryptoContext<DCRTPoly> cc) : cryptoContext(cc) {
        database.resize(dbSize);
        for (size_t i = 0; i < dbSize; ++i) {
            database[i] = static_cast<int64_t>((i + 1) * 10);
        }
        packedDatabase = cryptoContext->MakePackedPlaintext(database);
    }

    std::pair<Ciphertext<DCRTPoly>, size_t> processQuery(const Ciphertext<DCRTPoly>& encryptedSelector, size_t querySize) {
        querySize = estimateCiphertextSize(encryptedSelector);
        auto encryptedProduct = cryptoContext->EvalMult(encryptedSelector, packedDatabase);
        auto result = cryptoContext->EvalSum(encryptedProduct, database.size());
        return {result, estimateCiphertextSize(result)};
    }

    void displayDatabasePreview() const {
        std::cout << "[SERVIDOR] Base de datos (primeros valores): ";
        for (size_t i = 0; i < std::min(database.size(), size_t(10)); ++i) {
            std::cout << database[i] << " ";
        }
        if (database.size() > 10) std::cout << "...";
        std::cout << std::endl;
    }

    int64_t getExpectedValue(size_t index) const {
        return database[index];
    }
};

// CLIENTE
class Client {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    KeyPair<DCRTPoly> keyPair;

public:
    Client() {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetMultiplicativeDepth(1);
        parameters.SetPlaintextModulus(4293918721);
        parameters.SetRingDim(1<<19);
        parameters.SetSecurityLevel(HEStd_128_classic);
        
        cryptoContext = GenCryptoContext(parameters);
        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);
        cryptoContext->Enable(ADVANCEDSHE);
    }

    void generateKeys(size_t dbSize) {
        keyPair = cryptoContext->KeyGen();
        std::vector<int32_t> rotationIndices;
        for (size_t i = 1; i < dbSize; i <<= 1) { 
            rotationIndices.push_back(static_cast<int32_t>(i));
        }
        cryptoContext->EvalAtIndexKeyGen(keyPair.secretKey, rotationIndices);
    }

    std::pair<Ciphertext<DCRTPoly>, size_t> createQuery(size_t queryIndex, size_t dbSize) {
        if (queryIndex >= dbSize) {
            throw std::out_of_range("Índice fuera de rango");
        }

        std::vector<int64_t> selector(dbSize, 0);
        selector[queryIndex] = 1;
        
        Plaintext ptSelector = cryptoContext->MakePackedPlaintext(selector);
        auto ciphertext = cryptoContext->Encrypt(keyPair.publicKey, ptSelector);
        return {ciphertext, estimateCiphertextSize(ciphertext)};
    }

    int64_t decryptResult(const Ciphertext<DCRTPoly>& encryptedResult) {
        Plaintext decryptedResult;
        cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &decryptedResult);
        decryptedResult->SetLength(1);
        return decryptedResult->GetPackedValue()[0];
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

    // Variables para medición de comunicación
    size_t querySizeBytes = 0;
    size_t responseSizeBytes = 0;

    // CLIENTE
    std::cout << "\n[CLIENTE] Configurando contexto criptográfico..." << std::endl;
    auto clientStart = std::chrono::high_resolution_clock::now();
    
    Client client;
    client.generateKeys(dbSize);
    
    auto clientEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Configuración completada en " 
              << std::chrono::duration<double>(clientEnd - clientStart).count() << " segundos" << std::endl;

    // SERVIDOR
    std::cout << "\n[SERVIDOR] Inicializando base de datos..." << std::endl;
    Server server(dbSize, client.getCryptoContext());
    server.displayDatabasePreview();

    // CONSULTA CLIENTE
    size_t queryIndex;
    std::cout << "\n[CLIENTE] Índice a recuperar (0 - " << dbSize - 1 << "): ";
    std::cin >> queryIndex;

    if (queryIndex >= dbSize) {
        std::cerr << "Error: índice fuera de rango\n";
        return 1;
    }

    auto queryStart = std::chrono::high_resolution_clock::now();
    auto [encryptedSelector, querySize] = client.createQuery(queryIndex, dbSize);
    querySizeBytes = querySize;
    auto queryEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Consulta creada en " 
              << std::chrono::duration<double>(queryEnd - queryStart).count() << " segundos" << std::endl;

    // PROCESAMIENTO SERVIDOR
    std::cout << "\n[SERVIDOR] Procesando consulta PIR..." << std::endl;
    auto serverStart = std::chrono::high_resolution_clock::now();
    
    auto [encryptedResult, responseSize] = server.processQuery(encryptedSelector, querySizeBytes);
    responseSizeBytes = responseSize;
    
    auto serverEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[SERVIDOR] Consulta procesada en " 
              << std::chrono::duration<double>(serverEnd - serverStart).count() << " segundos" << std::endl;

    // RESULTADO CLIENTE
    std::cout << "\n[CLIENTE] Desencriptando resultado..." << std::endl;
    auto decryptStart = std::chrono::high_resolution_clock::now();
    
    int64_t recovered = client.decryptResult(encryptedResult);
    int64_t expected = server.getExpectedValue(queryIndex);
    
    auto decryptEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Resultado desencriptado en " 
              << std::chrono::duration<double>(decryptEnd - decryptStart).count() << " segundos" << std::endl;

    // Mostrar resultados
    std::cout << "\n=== Resultados ===" << std::endl;
    std::cout << "Índice solicitado: " << queryIndex << std::endl;
    std::cout << "Valor recuperado: " << recovered << std::endl;
    std::cout << "Valor esperado: " << expected << std::endl;
    std::cout << (recovered == expected ? "ÉXITO: Resultado correcto" : "ERROR: Resultado incorrecto") << std::endl;

    std::cout << "\n=== Estadísticas de Comunicación ===" << std::endl;
    std::cout << "Consulta (Cliente→Servidor): " << querySizeBytes << " bytes" << std::endl;
    std::cout << "Respuesta (Servidor→Cliente): " << responseSizeBytes << " bytes" << std::endl;
    std::cout << "Total transmitido: " << (querySizeBytes + responseSizeBytes) << " bytes" << std::endl;

    std::cout << "\nUso de memoria: " << getMemoryUsage() << " KB" << std::endl;

    return 0;
}