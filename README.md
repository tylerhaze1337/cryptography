### Introduction à la cryptographie
La cryptographie est la science de protéger l'information en la transformant de manière à ce qu'elle ne soit lisible que par ceux qui disposent d'une clé secrète. Les algorithmes de cryptographie sont largement utilisés dans des applications comme la sécurisation des communications, le stockage des mots de passe, et la protection des données sensibles.

#### Principaux types de cryptographie

1. **Cryptographie symétrique** : Utilise la même clé pour chiffrer et déchiffrer les données. Exemple : AES (Advanced Encryption Standard).
2. **Cryptographie asymétrique** : Utilise une paire de clés, une clé publique pour chiffrer et une clé privée pour déchiffrer. Exemple : RSA.
3. **Hachage cryptographique** : Utilisé pour générer un résumé (empreinte) d'un message, qui est unique pour un message donné. Exemple : SHA-256.

### Cryptographie symétrique avec AES
L'AES est un algorithme de chiffrement symétrique qui fonctionne avec des tailles de clé de 128, 192 ou 256 bits. C'est l'un des algorithmes les plus utilisés dans la cryptographie moderne pour sécuriser les données sensibles.

#### Exemple en Python avec `pycryptodome`
Pour AES, nous allons utiliser la bibliothèque `pycryptodome`, qui fournit une implémentation d'AES.

1. **Installation de `pycryptodome`** :
   ```bash
   pip install pycryptodome
   ```

2. **Chiffrement et déchiffrement d'un fichier avec AES** :
   
   ```python
   from Crypto.Cipher import AES
   from Crypto.Util.Padding import pad, unpad
   from Crypto.Random import get_random_bytes
   import os

   def encrypt_file(file_name, key):
       # Lecture du fichier à chiffrer
       with open(file_name, 'rb') as file:
           data = file.read()

       # Initialisation du chiffreur AES
       cipher = AES.new(key, AES.MODE_CBC)
       ct_bytes = cipher.encrypt(pad(data, AES.block_size))

       # Sauvegarde du fichier chiffré
       with open(file_name + ".enc", 'wb') as file:
           file.write(cipher.iv)  # On écrit le vecteur d'initialisation
           file.write(ct_bytes)

   def decrypt_file(file_name, key):
       with open(file_name, 'rb') as file:
           iv = file.read(16)  # On lit le vecteur d'initialisation
           ct = file.read()

       # Déchiffrement
       cipher = AES.new(key, AES.MODE_CBC, iv)
       decrypted_data = unpad(cipher.decrypt(ct), AES.block_size)

       with open(file_name + ".dec", 'wb') as file:
           file.write(decrypted_data)

   # Exemple d'utilisation
   key = get_random_bytes(16)  # Clé AES de 128 bits
   encrypt_file('test.txt', key)
   decrypt_file('test.txt.enc', key)
   ```

**Explication** :
- `AES.MODE_CBC` : Utilisation du mode CBC (Cipher Block Chaining).
- `get_random_bytes(16)` : Génère une clé AES de 128 bits.
- `pad` et `unpad` : Assure que le message soit un multiple de la taille du bloc AES.

### Cryptographie asymétrique avec RSA
RSA est un algorithme de cryptographie asymétrique qui utilise une paire de clés : une clé publique pour chiffrer et une clé privée pour déchiffrer. RSA est couramment utilisé pour sécuriser les communications en ligne.

#### Exemple en Python avec `pycryptodome`
1. **Générer une paire de clés RSA** :
   
   ```python
   from Crypto.PublicKey import RSA
   from Crypto.Cipher import PKCS1_OAEP
   from Crypto.Random import get_random_bytes

   # Générer une paire de clés RSA
   def generate_rsa_keys():
       key = RSA.generate(2048)
       private_key = key.export_key()
       public_key = key.publickey().export_key()
       return private_key, public_key

   # Chiffrement avec la clé publique RSA
   def encrypt_with_rsa(public_key, data):
       rsa_key = RSA.import_key(public_key)
       cipher = PKCS1_OAEP.new(rsa_key)
       encrypted_data = cipher.encrypt(data)
       return encrypted_data

   # Déchiffrement avec la clé privée RSA
   def decrypt_with_rsa(private_key, encrypted_data):
       rsa_key = RSA.import_key(private_key)
       cipher = PKCS1_OAEP.new(rsa_key)
       decrypted_data = cipher.decrypt(encrypted_data)
       return decrypted_data

   # Exemple d'utilisation
   private_key, public_key = generate_rsa_keys()

   message = b"Hello, this is a secret message!"
   encrypted_msg = encrypt_with_rsa(public_key, message)
   decrypted_msg = decrypt_with_rsa(private_key, encrypted_msg)

   print(f"Message original : {message}")
   print(f"Message décrypté : {decrypted_msg}")
   ```

**Explication** :
- `PKCS1_OAEP` : Un schéma de remplissage utilisé pour le chiffrement RSA, qui est plus sécurisé que les anciens schémas comme PKCS1 v1.5.
- `RSA.generate(2048)` : Génère une clé RSA de 2048 bits.

### Comparaison AES vs RSA
- **AES** est plus rapide que **RSA**, surtout pour de grandes quantités de données, c'est pourquoi il est souvent utilisé pour chiffrer des fichiers ou des flux de données.
- **RSA** est généralement utilisé pour échanger des clés de session de manière sécurisée, après quoi l'AES est utilisé pour le chiffrement réel des données.

### Utilisation combinée d'AES et RSA (Chiffrement hybride)
Dans les systèmes réels, on utilise souvent **AES** pour chiffrer les données (car il est plus rapide) et **RSA** pour échanger en toute sécurité la clé AES.

#### Exemple de chiffrement hybride (AES + RSA)

1. **Générer une clé AES aléatoire** pour chiffrer les données.
2. **Chiffrer la clé AES** avec RSA pour pouvoir la partager en toute sécurité.

```python
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Générer une paire de clés RSA
private_key, public_key = generate_rsa_keys()

# Générer une clé AES
aes_key = get_random_bytes(16)

# Chiffrer un fichier avec AES
def encrypt_data_with_aes(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes

# Chiffrer la clé AES avec RSA
def encrypt_aes_key_with_rsa(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key

# Déchiffrement
def decrypt_data_with_aes(ciphertext, aes_key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted_data

def decrypt_aes_key_with_rsa(encrypted_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key

# Exemple de chiffrement hybride
message = b"Confidential information that needs to be encrypted!"
encrypted_data = encrypt_data_with_aes(message, aes_key)
encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

# Déchiffrement
decrypted_aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)
decrypted_message = decrypt_data_with_aes(encrypted_data, decrypted_aes_key)

print(f"Message original: {message}")
print(f"Message déchiffré: {decrypted_message}")
```

**Explication** :
- La clé AES est générée pour chaque session (par exemple, pour chaque fichier ou flux de données).
- La clé AES est ensuite chiffrée avec RSA, ce qui permet de la transmettre en toute sécurité, même si la clé publique RSA est partagée ouvertement.

### Conclusion
La cryptographie moderne repose sur une combinaison d'algorithmes symétriques et asymétriques pour offrir à la fois sécurité et performance. Le chiffrement de fichiers peut être réalisé efficacement en utilisant AES pour le chiffrement des données, tout en utilisant RSA pour sécuriser la clé AES. Ces pratiques sont couramment utilisées dans des protocoles tels que SSL/TLS, PGP, et autres.

### Introduction à la cryptographie en C++

La cryptographie est utilisée pour protéger les données sensibles, que ce soit dans des communications ou pour le stockage. En C++, il existe plusieurs bibliothèques populaires pour implémenter la cryptographie, telles que OpenSSL et Crypto++.

Dans ce cours, nous allons utiliser la bibliothèque **Crypto++**, qui est une bibliothèque de cryptographie open-source populaire en C++. Nous allons aborder deux algorithmes principaux : **AES (Advanced Encryption Standard)** pour le chiffrement symétrique, et **RSA** pour le chiffrement asymétrique.

### Installation de Crypto++

Avant de commencer, il faut installer **Crypto++**. Voici comment faire cela sur un système Linux (vous pouvez adapter selon votre système d'exploitation) :

```bash
sudo apt-get update
sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils
```

Sur macOS, vous pouvez l'installer via **Homebrew** :

```bash
brew install cryptopp
```

### 1. Chiffrement avec AES en C++

L'algorithme **AES** est un algorithme de chiffrement symétrique largement utilisé. Nous allons l'utiliser pour chiffrer et déchiffrer un fichier en mode CBC (Cipher Block Chaining).

#### Exemple de chiffrement AES avec Crypto++

Voici un exemple en C++ pour chiffrer et déchiffrer un fichier en utilisant **AES en mode CBC**.

```cpp
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/osrng.h>
#include <crypto++/hex.h>
#include <crypto++/filters.h>

using namespace std;
using namespace CryptoPP;

// Fonction pour générer une clé AES et un vecteur d'initialisation aléatoire
void generate_key_and_iv(byte key[AES::DEFAULT_KEYLENGTH], byte iv[AES::BLOCKSIZE]) {
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(iv, AES::BLOCKSIZE);
}

// Fonction pour chiffrer un fichier avec AES en mode CBC
void encrypt_file(const string& input_filename, const string& output_filename, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE]) {
    // Lecture du fichier en entrée
    ifstream input(input_filename, ios::binary);
    if (!input) {
        cerr << "Erreur lors de l'ouverture du fichier d'entrée !" << endl;
        return;
    }

    // Lecture du contenu du fichier
    vector<byte> plaintext((istreambuf_iterator<char>(input)), istreambuf_iterator<char>());
    
    // Initialisation du chiffreur AES
    CBC_Mode<AES>::Encryption encryptor(key, AES::DEFAULT_KEYLENGTH, iv);

    // Chiffrement du fichier
    string ciphertext;
    StringSource(plaintext.data(), plaintext.size(), true,
        new StreamTransformationFilter(encryptor,
            new StringSink(ciphertext)
        )
    );

    // Sauvegarde du fichier chiffré
    ofstream output(output_filename, ios::binary);
    output.write(reinterpret_cast<const char*>(iv), AES::BLOCKSIZE); // Sauvegarde du vecteur d'initialisation
    output.write(ciphertext.c_str(), ciphertext.size());

    cout << "Fichier chiffré sauvegardé sous : " << output_filename << endl;
}

// Fonction pour déchiffrer un fichier avec AES en mode CBC
void decrypt_file(const string& input_filename, const string& output_filename, const byte key[AES::DEFAULT_KEYLENGTH]) {
    // Lecture du fichier chiffré
    ifstream input(input_filename, ios::binary);
    if (!input) {
        cerr << "Erreur lors de l'ouverture du fichier d'entrée !" << endl;
        return;
    }

    // Lecture du vecteur d'initialisation
    byte iv[AES::BLOCKSIZE];
    input.read(reinterpret_cast<char*>(iv), AES::BLOCKSIZE);

    // Lecture du reste du fichier chiffré
    string ciphertext((istreambuf_iterator<char>(input)), istreambuf_iterator<char>());
    
    // Initialisation du déchiffreur AES
    CBC_Mode<AES>::Decryption decryptor(key, AES::DEFAULT_KEYLENGTH, iv);

    // Déchiffrement du fichier
    string plaintext;
    StringSource(ciphertext, true,
        new StreamTransformationFilter(decryptor,
            new StringSink(plaintext)
        )
    );

    // Sauvegarde du fichier déchiffré
    ofstream output(output_filename, ios::binary);
    output.write(plaintext.c_str(), plaintext.size());

    cout << "Fichier déchiffré sauvegardé sous : " << output_filename << endl;
}

int main() {
    byte key[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];

    // Générer une clé et un IV aléatoires
    generate_key_and_iv(key, iv);

    // Nom du fichier à chiffrer
    string input_filename = "test.txt";
    string encrypted_filename = "test_encrypted.bin";
    string decrypted_filename = "test_decrypted.txt";

    // Chiffrement du fichier
    encrypt_file(input_filename, encrypted_filename, key, iv);

    // Déchiffrement du fichier
    decrypt_file(encrypted_filename, decrypted_filename, key);

    return 0;
}
```

**Explication** :
1. **Génération de la clé AES et du vecteur d'initialisation (IV)** : La fonction `generate_key_and_iv()` génère une clé AES aléatoire et un IV à l'aide d'un générateur de nombres aléatoires sécurisé.
2. **Chiffrement avec AES en mode CBC** : Le fichier est chiffré en mode CBC, un mode qui lie chaque bloc chiffré au bloc précédent avec un vecteur d'initialisation.
3. **Déchiffrement du fichier** : Le processus inverse est effectué pour récupérer le texte clair du fichier chiffré.

### 2. Chiffrement avec RSA en C++

Le chiffrement **RSA** est un algorithme asymétrique qui utilise une paire de clés publique/privée. Il est souvent utilisé pour échanger des clés secrètes (par exemple, AES) ou pour signer des données.

#### Exemple de chiffrement RSA avec Crypto++

Voici un exemple en C++ pour générer une paire de clés RSA, chiffrer et déchiffrer des données avec ces clés.

```cpp
#include <iostream>
#include <string>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/hex.h>
#include <crypto++/cryptlib.h>
#include <crypto++/pkcs1.h>
#include <crypto++/filters.h>

using namespace std;
using namespace CryptoPP;

// Générer une paire de clés RSA
void generate_rsa_keys(RSA::PrivateKey& privateKey, RSA::PublicKey& publicKey) {
    AutoSeededRandomPool prng;
    RSA::KeyPair keyPair;
    privateKey.GenerateRandomWithKeySize(prng, 2048);
    publicKey = privateKey.GetPublicKey();
}

// Chiffrement avec la clé publique RSA
string encrypt_with_rsa(const RSA::PublicKey& publicKey, const string& message) {
    AutoSeededRandomPool prng;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    string cipher;
    StringSource(message, true, new PK_EncryptorFilter(prng, encryptor, new StringSink(cipher)));
    return cipher;
}

// Déchiffrement avec la clé privée RSA
string decrypt_with_rsa(const RSA::PrivateKey& privateKey, const string& cipher) {
    AutoSeededRandomPool prng;
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    string recovered;
    StringSource(cipher, true, new PK_DecryptorFilter(prng, decryptor, new StringSink(recovered)));
    return recovered;
}

int main() {
    // Générer les clés RSA
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    generate_rsa_keys(privateKey, publicKey);

    // Message à chiffrer
    string message = "Hello, this is a secret message!";
    
    // Chiffrement avec la clé publique
    string encrypted_message = encrypt_with_rsa(publicKey, message);
    cout << "Message chiffré : " << encrypted_message << endl;

    // Déchiffrement avec la clé privée
    string decrypted_message = decrypt_with_rsa(privateKey, encrypted_message);
    cout << "Message déchiffré : " << decrypted_message << endl;

    return 0;
}
```

**Explication** :
1. **Génération de la paire de clés RSA** : La fonction `generate_rsa_keys()` génère une paire de clés RSA de 2048 bits.
2. **Chiffrement avec la clé publique RSA** : Le message est chiffré à l'aide de la clé publique.
3. **Déchiffrement avec la clé privée RSA** : Le message chiffré est déchiffré à l'aide de la clé privée.

### Conclusion

Dans ce cours, nous avons exploré l'utilisation des algorithmes de chiffrement **AES** (symétrique) et **RSA** (asymétrique) en C++ à l'aide de la bibliothèque **Crypto++**. Nous avons vu comment :
- Chiffrer et déchiffrer des fichiers avec AES en mode CBC.
- Utiliser RSA pour chiffrer et déchiffrer des données avec une paire de clés publique/privée.

Ces exemples couvrent les bases de la cryptographie en C++ et montrent comment sécuriser des données à l'aide de ces algorithmes largement utilisés. Si tu veux approfondir, il existe de nombreux autres algorithmes et techniques de cryptographie à explorer avec **Crypto++**.
