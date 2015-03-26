/* Init vbox clipboard code */
void uxen_clipboard_connect();
int uxen_clipboard_init();

/* Process clipboard rpc request */
int uxen_clipboard_process_request(uint8_t *req, int reqsize,
    uint8_t **respbuf, int *respsize);

/* Send a message from host to guest */
void uxen_clipboard_notify_guest(int type, char * data, int len);

/* set clipboard access policy (retrieved from json config) */
void uxen_clipboard_set_policy(const char *policy);

/* lift access restrictions (temporarily) */
void uxen_clipboard_allow_copy_access();

/* Check if both channels are opened, if so, init vbox code */ 
void ns_uclip_try_init();

