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
void uxen_clipboard_allow_paste_access();

/* block clipboard rendering from remote end / test for blocked render */
void uxen_clipboard_block_remote_render(int);
int  uxen_clipboard_remote_render_blocked(void);

/* Check if both channels are opened, if so, init vbox code */ 
void ns_uclip_try_init();

void uxen_clipboard_resume(void);

void uxen_clipboard_reannounce(void);
