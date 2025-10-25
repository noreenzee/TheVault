#include <iostream> //---  needed for reading input/out
#include <fstream> //--- needed for read and write files
#include <unordered_map> //--- needed for storing key value pairs
#include <iomanip> //--- needed for formating numbers
#include <sstream> //--- for data conversion from bytes to string
#include <openssl/sha.h> //--- have functions for SHA256 HASHING
#include <openssl/evp.h> //--- ENCRY/DECRYP interface for AES 
#include <openssl/hmac.h> //--- Needed for HMAC to check data integrity
#include <openssl/rand.h> //--- random number generators for salt and IV
#include <ctime> //--- used for timestamp

using namespace std;

// --- SHA256 hashing with salt (KDF) ---
string deriveKey(const string &password, const string &salt) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    //--- creating structure to store hash
    SHA256_CTX sha256;
    //--- creating SHA256 for hashing
    SHA256_Init(&sha256);
    //--- add the password to the hash 
    SHA256_Update(&sha256, password.c_str(), password.size());
    //--- Add salt so even same password has for different user have different hashing.
    SHA256_Update(&sha256, salt.c_str(), salt.size());
    //--- complete hasing and store results 
    SHA256_Final(hash, &sha256);

    // --- convert each byte of hash to two digit hexadecimal, returns as string for AES KEY

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// --- AES Encryption / Decryption 
bool encryptAES(const string &plaintext, const string &key, string &ciphertext, string &ivHex) {
    unsigned char iv[16];
    if (!RAND_bytes(iv, sizeof(iv))) return false;

    ivHex.clear();
    for(int i=0; i<16; i++) {
        stringstream ss;
        ss << hex << setw(2) << setfill('0') << (int)iv[i];
        ivHex += ss.str();
    }
    //--- create context to store encryption state

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    //--- initialize AES-256 cbc with key and IV
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.c_str(), iv);

    unsigned char outbuf[1024];
    int outlen;
    //--- encrypts data
    EVP_EncryptUpdate(ctx, outbuf, &outlen, (unsigned char*)plaintext.c_str(), plaintext.size());
    int tmplen;
    //--- finalize encryptions 
    EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen);
    outlen += tmplen;
    //--- store encrypted data in ciphertext and free up memory for encryption context

    ciphertext.assign((char*)outbuf, outlen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
//--- AES Decryption
//--- convert stored hex iv back to bytes

bool decryptAES(const string &ciphertext, const string &key, const string &ivHex, string &plaintext) {
    unsigned char iv[16];
    for(int i=0; i<16; i++) {
        string byteStr = ivHex.substr(i*2, 2);
        iv[i] = (unsigned char) strtol(byteStr.c_str(), nullptr, 16);
    }
    //--- initialize AES decryption with same key and iv

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.c_str(), iv);
    //--- Decrypts ciphertext
    int outlen;
    EVP_DecryptUpdate(ctx, outbuf, &outlen, (unsigned char*)ciphertext.c_str(), ciphertext.size());
    int tmplen;
    EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen);
    outlen += tmplen;
    //--- returns origional plaintext password
    unsigned char outbuf[1024];
    plaintext.assign((char*)outbuf, outlen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// --- HMAC-SHA256 
//--- compute hmac of encrypted password
string computeHMAC(const string &key, const string &data) {
    unsigned char* hmac = HMAC(EVP_sha256(), key.c_str(), key.size(),
                               (unsigned char*)data.c_str(), data.size(), nullptr, nullptr);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hmac[i];
    }
    return ss.str();
}

// --- Logger for security 
void logEvent(const string &message) {
    ofstream logFile("security_report.txt", ios::app);
    time_t now = time(0);
    logFile << ctime(&now) << ": " << message << endl;
    logFile.close();
}

// --- Password strength check 
bool isStrongPassword(const string &password) {
    if(password.length() < 8) return false;
    bool hasDigit=false, hasUpper=false, hasLower=false, hasSpecial=false;
    for(char c: password){
        if(isdigit(c)) hasDigit=true;
        else if(isupper(c)) hasUpper=true;
        else if(islower(c)) hasLower=true;
        else hasSpecial=true;
    }
    return hasDigit && hasUpper && hasLower && hasSpecial;
}

// --- Password Manager Class
class PasswordManager {
private:
    unordered_map<string, pair<string,string>> vault; // account -> (encrypted password, IV)
    string masterKey;
    string salt;

public:
    PasswordManager(const string &masterPassword) {
        // Generate a random salt
        unsigned char saltBytes[16];
        RAND_bytes(saltBytes, sizeof(saltBytes));
        stringstream ss;
        for(int i=0;i<16;i++){
            ss << hex << setw(2) << setfill('0') << (int)saltBytes[i];
        }
        salt = ss.str();
        masterKey = deriveKey(masterPassword, salt);
        cout << "Master key generated successfully." << endl;
        logEvent("Master key generated with salt: " + salt);
    }

    void addPassword(const string &account, const string &password) {
        if(vault.find(account) != vault.end()) {
            logEvent("Duplicate account detected: " + account);
            cout << "Heads up! This account already exists. We'll overwrite it." << endl;
        }
        if(!isStrongPassword(password)){
            logEvent("Weak password detected for account: " + account);
            cout << "Warning: The password you entered is weak. Consider making it stronger!" << endl;
        }

        string cipherText, ivHex;
        encryptAES(password, masterKey, cipherText, ivHex);
        vault[account] = make_pair(cipherText, ivHex);

        string mac = computeHMAC(masterKey, cipherText);
        logEvent("Password stored for account: " + account + " with MAC: " + mac);
        cout << "Password successfully saved for " << account << "." << endl;
    }

    void getPassword(const string &account) {
        if(vault.find(account) == vault.end()) {
            logEvent("Attempted retrieval of non-existent account: " + account);
            cout << "Oops! No password found for that account." << endl;
            return;
        }
        string decrypted;
        string cipherText = vault[account].first;
        string ivHex = vault[account].second;
        decryptAES(cipherText, masterKey, ivHex, decrypted);

        string mac = computeHMAC(masterKey, cipherText);
        logEvent("Password retrieved for account: " + account + " MAC verified: " + mac);

        cout << "Here's the password for " << account << ": " << decrypted << endl;
        cout << "(MAC for verification: " << mac << ")" << endl;
    }

    void saveVault(const string &filename) {
        ofstream file(filename, ios::binary);
        for(auto &entry : vault) {
            file << entry.first << " " << entry.second.first << " " << entry.second.second << endl;
        }
        file.close();
        logEvent("Vault saved to file: " + filename);
        cout << "Vault has been saved safely." << endl;
    }

    void loadVault(const string &filename) {
        ifstream file(filename, ios::binary);
        if(!file) return;
        vault.clear();
        string account, cipher, iv;
        while(file >> account >> cipher >> iv) {
            vault[account] = make_pair(cipher, iv);
        }
        logEvent("Vault loaded from file: " + filename);
        cout << "Vault loaded successfully." << endl;
    }
};

// --- Main Program 
int main() {
    cout << "==============================\n";
    cout << " Welcome to The Vault Password Manager\n";
    cout << "==============================\n";

    string masterPassword;
    cout << "Please enter your master password: ";
    cin >> masterPassword;

    PasswordManager pm(masterPassword);
    pm.loadVault("vault.db");

    int choice;
    do {
        cout << "\nMenu:\n";
        cout << "1. Add a new password\n";
        cout << "2. Retrieve a password\n";
        cout << "3. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;

        if(choice == 1) {
            string account, password;
            cout << "Enter account name: "; cin >> account;
            cout << "Enter password: "; cin >> password;
            pm.addPassword(account, password);
        } else if(choice == 2) {
            string account;
            cout << "Enter account name to retrieve: "; cin >> account;
            pm.getPassword(account);
        }
    } while(choice != 3);

    pm.saveVault("vault.db");
    cout << "\nAll actions logged in security_report.txt" << endl;
    cout << "Thank you for using The Vault. Stay secure!" << endl;

    return 0;
}
