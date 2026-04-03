#include <napi.h>
#include "rudra512.h"

Napi::String Hash(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsString()) {
        throw Napi::TypeError::New(env, "Expected string");
    }

    std::string input = info[0].As<Napi::String>();

    int rounds = 32;
    if (info.Length() > 1 && info[1].IsNumber()) {
        rounds = info[1].As<Napi::Number>().Int32Value();
    }

    std::string result = rudra::hash_string(input, rounds);

    return Napi::String::New(env, result);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("hash", Napi::Function::New(env, Hash));
    return exports;
}

NODE_API_MODULE(rudra512, Init)
