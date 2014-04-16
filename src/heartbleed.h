#include "node.h"
#include "node_object_wrap.h"
#include "v8.h"
#include "openssl/ssl.h"

namespace heartbleed {

typedef const SSL_METHOD* (*MethodFunction)(void);
typedef long (*CtrlFunction)(SSL*, int, long, void*);
typedef int (*DispatchAlertFunction)(SSL*);

template <MethodFunction M>
class MethodWrap {
 public:
  MethodWrap();

 protected:
  static long Ctrl(SSL* s, int cmd, long larg, void* parg);
  static int DispatchAlert(SSL* s);

  static void ProcessHeartbeat(SSL* ssl, SSL3_RECORD* rr);

  static CtrlFunction ssl_ctrl_;
  static DispatchAlertFunction ssl_alert_;
};

class SSLWrap : public node::ObjectWrap {
 public:
  void WrapSSL(SSL* ssl);

  static void Initialize(v8::Handle<v8::Object> target);
  static SSLWrap* UnwrapSSL(SSL* ssl);

  inline int get_heartbeat_length() { return heartbeat_length_; }

 protected:
  SSLWrap() : heartbeat_length_(0) {
  }

  static v8::Handle<v8::Value> New(const v8::Arguments& args);
  static v8::Handle<v8::Value> SetHeartbeatLength(const v8::Arguments& args);

  int heartbeat_length_;
};

}  // namespace heartbleed
