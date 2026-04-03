#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <chrono>
using namespace std;
using namespace std::chrono;

typedef uint64_t u64;

// =========================
// BIT OPS
// =========================
inline u64 rotl(u64 x, int r){ return (x<<r)|(x>>(64-r)); }
inline u64 rotr(u64 x, int r){ return (x>>r)|(x<<(64-r)); }

// =========================
// MIX (MoE)
// =========================
inline u64 mix(u64 v){
    v ^= rotl(v,17);
    v ^= rotr(v,13);
    v ^= (v >> 32);
    v *= 0xd6e8feb86659fd93ULL;
    v ^= (v >> 29);
    v ^= rotl(v,23);
    v *= 0x9e3779b185ebca87ULL;
    return v;
}

// =========================
// PERMUTE
// =========================
vector<u64> permute(vector<u64> state, int rounds){
    for(int r=0;r<rounds;r++){
        for(int i=0;i<8;i++) state[i] = mix(state[i]);
        for(int i=0;i<8;i++) state[i] ^= state[(i+3)%8];
        for(int i=0;i<8;i++) state[i] = rotl(state[i], (i*7 + r)%64);
        swap(state[1], state[5]);
        swap(state[2], state[6]);
        state[0] ^= r;
    }
    return state;
}

// =========================
// RUDRA-512 HASH FUNCTION
// =========================
string rudra_512(const vector<uint8_t>& msg, int rounds=32){
    vector<u64> state(8,0);
    for(size_t i=0;i<msg.size();i++)
        state[i%8] ^= ((u64)msg[i] << ((i%8)*8));
    state = permute(state, rounds);

    stringstream ss;
    for(auto v:state) ss<<hex<<setw(16)<<setfill('0')<<v;
    return ss.str();
}

// =========================
// SHA-512
// =========================
string sha512_hash(const vector<uint8_t>& msg){
    unsigned char h[64];
    SHA512(msg.data(), msg.size(), h);
    stringstream ss;
    for(int i=0;i<64;i++) ss<<hex<<setw(2)<<setfill('0')<<(int)h[i];
    return ss.str();
}

// =========================
// SHA3-512
// =========================
string sha3_512_hash(const vector<uint8_t>& msg){
    unsigned char h[64];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr);
    EVP_DigestUpdate(ctx, msg.data(), msg.size());
    EVP_DigestFinal_ex(ctx, h, nullptr);
    EVP_MD_CTX_free(ctx);

    stringstream ss;
    for(int i=0;i<64;i++) ss<<hex<<setw(2)<<setfill('0')<<(int)h[i];
    return ss.str();
}

// =========================
// HEX → BITS
// =========================
vector<int> hex_to_bits(const string &hex){
    vector<int> bits;
    for(char c:hex){
        int v = (c<='9')?c-'0':tolower(c)-'a'+10;
        for(int i=3;i>=0;i--) bits.push_back((v>>i)&1);
    }
    return bits;
}

// =========================
// Statistical tests
// =========================
double frequency(const vector<int>& bits){
    int ones = accumulate(bits.begin(),bits.end(),0);
    return ones/(double)bits.size()*100;
}

double runs(const vector<int>& bits){
    int r=1;
    for(size_t i=1;i<bits.size();i++)
        if(bits[i]!=bits[i-1]) r++;
    return r/(double)bits.size();
}

double entropy(const vector<int>& bits){
    int ones = accumulate(bits.begin(),bits.end(),0);
    double p = ones/(double)bits.size();
    if(p==0||p==1) return 0;
    return -p*log2(p)-(1-p)*log2(1-p);
}

double avalanche(function<string(vector<uint8_t>)> H){
    vector<uint8_t> msg(32,'A');
    string base = H(msg);
    auto base_bits = hex_to_bits(base);

    double total=0;
    for(int i=0;i<64;i++){
        auto m = msg;
        m[i/8] ^= (1<<(i%8));
        auto bits = hex_to_bits(H(m));

        int diff=0;
        for(size_t j=0;j<bits.size();j++)
            if(bits[j]!=base_bits[j]) diff++;
        total += diff/(double)bits.size()*100;
    }

    return total/64;
}

void collision(function<string(vector<uint8_t>)> H){
    unordered_set<string> s;
    for(int i=0;i<50000;i++){
        vector<uint8_t> m(32);
        for(auto &x:m) x = rand()%256;

        string h = H(m);
        if(s.count(h)){
            cout<<"Collision Found!\n";
            return;
        }
        s.insert(h);
    }
    cout<<"No Collision\n";
}

double speed(function<string(vector<uint8_t>)> H){
    vector<uint8_t> m(32,123);
    int N=20000;
    auto start = high_resolution_clock::now();
    for(int i=0;i<N;i++) H(m);
    auto end = high_resolution_clock::now();
    return N / duration<double>(end-start).count();
}

void run_all(function<string(vector<uint8_t>)> H, string name){
    cout<<"\n===== "<<name<<" =====\n";

    vector<int> bits;
    for(int i=0;i<200;i++){
        vector<uint8_t> m(32);
        for(auto &x:m) x = rand()%256;

        auto b = hex_to_bits(H(m));
        bits.insert(bits.end(),b.begin(),b.end());
    }

    cout<<"Frequency: "<<frequency(bits)<<"%\n";
    cout<<"Runs: "<<runs(bits)<<"\n";
    cout<<"Entropy: "<<entropy(bits)<<"\n";
    cout<<"Avalanche: "<<avalanche(H)<<"%\n";
    cout<<"Speed: "<<speed(H)<<" hashes/sec\n";

    collision(H);
}

// =========================
// MAIN
// =========================
int main(){
    auto rudra = [](vector<uint8_t> m){ return rudra_512(m); };
    auto sha512 = [](vector<uint8_t> m){ return sha512_hash(m); };
    auto sha3 = [](vector<uint8_t> m){ return sha3_512_hash(m); };

    run_all(rudra,"Rudra-512");
    run_all(sha512,"SHA-512");
    run_all(sha3,"SHA3-512");

    return 0;
}
