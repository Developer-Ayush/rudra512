#include <bits/stdc++.h>
using namespace std;

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
// MAIN EXAMPLE
// =========================
int main(){
    string input;
    cout << "Enter message: ";
    getline(cin,input);

    vector<uint8_t> msg(input.begin(), input.end());
    string h = rudra_512(msg);

    cout << "Rudra512: " << h << "\n";
    return 0;
}
