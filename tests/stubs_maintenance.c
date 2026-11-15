/* Test stub: maintenance work runs inline, no worker threads. */
#include "internal.h"

int hadc_maint_start(hadc_ctx_t *ctx) { (void)ctx; return 0; }
void hadc_maint_stop(void) {}
int hadc_maint_post_tick(hadc_ctx_t *ctx) { (void)ctx; return 0; }
int hadc_maint_post_fn(hadc_maint_fn_t fn, void *arg) { if (fn) fn(arg); return 0; }
void hadc_maint_lock(void) {}
void hadc_maint_unlock(void) {}
bool hadc_maint_running(void) { return false; }
