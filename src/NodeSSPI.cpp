#include "NodeSSPI.h"

using namespace v8;
using namespace std;

Handle<Value> Method(const Arguments& args) {
	HandleScope scope;
	TryCatch trycatch;
	if (args[0]->IsObject()){
		auto req = args[0]->ToObject();
		req->Set(String::New("user"), String::New("Fred"));
	}
	return scope.Close(Undefined());
}

void init(Handle<Object> exports) {
	exports->Set(String::NewSymbol("authenticate"),
		FunctionTemplate::New(Method)->GetFunction());
}

NODE_MODULE(nodeSSPI, init)